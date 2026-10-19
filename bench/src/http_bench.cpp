// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The HTTP API under load: the server in-process, on a ledger in a real
// directory, and a load generator holding many keep-alive connections that
// read, submit, or only ask for /healthz (the server's own overhead).

#include <algorithm>
#include <array>
#include <asio.hpp>
#include <atomic>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <stdexcept>
#include <sys/resource.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "bench.hpp"
#include "fixture.hpp"

namespace cexchain::bench {

namespace {

using asio::ip::tcp;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

/// Requests to send, shared by every connection: each takes the next.
struct Load {
    std::vector<std::string> requests;
    std::atomic<std::size_t> next = 0;
    /// With a duration, requests repeat until it is over; else each goes once.
    std::optional<Clock::time_point> until;
};

/// What one connection saw.
struct Tally {
    std::vector<std::uint32_t> latencies_us;
    /// Connects refused at first (a full listen backlog), then retried.
    std::uint64_t reconnects = 0;
    std::uint64_t failed_connects = 0;
    std::uint64_t io_errors = 0;
    std::uint64_t bad_statuses = 0;
    std::string first_error;
};

/// Status and total length of the response at the start of `buffer`, once
/// its headers are in.
std::optional<std::pair<int, std::size_t>> response_head(const std::string& buffer) {
    const std::size_t end = buffer.find("\r\n\r\n");
    if (end == std::string::npos || buffer.size() < 12) {
        return std::nullopt;
    }
    int status = 0;
    std::from_chars(buffer.data() + 9, buffer.data() + 12, status);
    std::string head = buffer.substr(0, end);
    std::ranges::transform(head, head.begin(),
                           [](char c) { return static_cast<char>(std::tolower(c)); });
    std::size_t length = 0;
    if (const std::size_t at = head.find("content-length:"); at != std::string::npos) {
        std::size_t from = at + 15;
        while (from < head.size() && head[from] == ' ') {
            ++from;
        }
        std::from_chars(head.data() + from, head.data() + head.size(), length);
    }
    return std::pair(status, end + 4 + length);
}

/// One keep-alive connection, sending requests one after another until the
/// load is done.
asio::awaitable<void> connection(tcp::endpoint server, Load& load, Tally& tally,
                                 std::chrono::milliseconds ramp) {
    auto executor = co_await asio::this_coro::executor;
    tcp::socket socket(executor);
    asio::steady_timer pause(executor);
    // Connections open over a short ramp: a burst of thousands of SYNs
    // overflows the kernel's listen queue (128 on macOS), which then resets
    // connections it had already accepted.
    pause.expires_after(ramp);
    co_await pause.async_wait(use_tuple);
    for (int attempt = 0;; ++attempt) {
        auto [ec] = co_await socket.async_connect(server, use_tuple);
        if (!ec) {
            break;
        }
        if (attempt == 50) {
            ++tally.failed_connects;
            co_return;
        }
        ++tally.reconnects;
        socket = tcp::socket(executor);
        pause.expires_after(std::chrono::milliseconds(10 + 10 * attempt));
        co_await pause.async_wait(use_tuple);
    }
    socket.set_option(tcp::no_delay(true));
    std::string buffer;
    std::array<char, 16 * 1024> chunk{};
    for (;;) {
        const std::size_t i = load.next.fetch_add(1, std::memory_order_relaxed);
        if (load.until ? Clock::now() >= *load.until : i >= load.requests.size()) {
            co_return;
        }
        const std::string& request = load.requests[i % load.requests.size()];
        const auto started = Clock::now();
        if (auto [ec, n] = co_await asio::async_write(socket, asio::buffer(request), use_tuple);
            ec) {
            ++tally.io_errors;
            tally.first_error = std::format("{} (writing, after {} answers)", ec.message(),
                                            tally.latencies_us.size());
            co_return;
        }
        std::optional<std::pair<int, std::size_t>> head;
        while (!(head = response_head(buffer)) || buffer.size() < head->second) {
            auto [ec, n] = co_await socket.async_read_some(asio::buffer(chunk), use_tuple);
            if (ec) {
                ++tally.io_errors;
                tally.first_error = std::format("{} (reading, after {} answers)", ec.message(),
                                                tally.latencies_us.size());
                co_return;
            }
            buffer.append(chunk.data(), n);
        }
        buffer.erase(0, head->second);
        const auto us =
            std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started);
        tally.latencies_us.push_back(static_cast<std::uint32_t>(us.count()));
        if (head->first < 200 || head->first >= 300) {
            ++tally.bad_statuses;
        }
    }
}

void raise_descriptor_limit(std::uint64_t wanted) {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur < wanted) {
        limit.rlim_cur = std::min<rlim_t>(limit.rlim_max, static_cast<rlim_t>(wanted));
        static_cast<void>(::setrlimit(RLIMIT_NOFILE, &limit));
    }
}

std::string get_request(std::string_view target, std::string_view token) {
    return std::format("GET {} HTTP/1.1\r\nHost: bench\r\nAuthorization: Bearer {}\r\n\r\n", target,
                       token);
}

std::string post_request(std::string_view target, std::string_view token, ByteView body) {
    std::string out = std::format("POST {} HTTP/1.1\r\nHost: bench\r\nAuthorization: Bearer {}\r\n"
                                  "Content-Type: application/cose\r\nContent-Length: {}\r\n\r\n",
                                  target, token, body.size());
    out.append(reinterpret_cast<const char*>(body.data()), body.size());
    return out;
}

} // namespace

int http_bench(const Options& options) {
    const std::string mode = options.text("mode", "read");
    const bool contracts = mode == "create" || mode == "call";
    if (mode != "read" && mode != "submit" && mode != "health" && !contracts) {
        throw std::invalid_argument("--mode is read, submit, health, create, or call");
    }
    const std::uint64_t connections = std::max<std::uint64_t>(1, options.number("connections", 64));
    const std::uint64_t hardware = std::max(1U, std::thread::hardware_concurrency());
    const std::uint64_t server_threads =
        options.number("server-threads", std::max<std::uint64_t>(1, hardware / 2));
    const std::uint64_t client_threads =
        options.number("client-threads", std::max<std::uint64_t>(1, hardware / 2));
    const std::uint64_t prefill = options.number("prefill", mode == "read" ? 10000 : 0);
    const std::uint64_t requests = options.number("requests", 20000);
    const std::uint64_t seconds = options.number("seconds", mode == "submit" || contracts ? 0 : 5);
    // Contract calls come in rounds, one call on each instance per round:
    // each call names its instance's head, known once the round before is in.
    const std::uint64_t instances = options.number("instances", 4096);
    const std::uint64_t calls = options.number("calls", 4);
    std::optional<Workload> workload;
    if (contracts) {
        workload = make_workload(options.text("contract", "small"), options);
    }
    const std::filesystem::path dir =
        options.text("dir", (std::filesystem::temp_directory_path() /
                             std::format("cexchain-bench-http-{}", ::getpid()))
                                .string());
    Results results;
    raise_descriptor_limit(connections * 2 + 256);

    // A ledger with `prefill` records, and tokens to read and submit with.
    const crypto::openssl::Provider provider;
    auto org = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto log = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    ledger::SystemClock clock;
    ledger::SystemEntropy entropy;
    std::filesystem::remove_all(dir);
    std::vector<protocol::Id> ids;
    protocol::Id ledger_id;
    protocol::Id contract;
    auto sign_body = [&](protocol::Body body) {
        protocol::Statement s;
        s.ledger_id = ledger_id;
        s.actor_id = ledger_id;
        s.issued_at = clock.now();
        s.nonce = entropy.bytes<16>();
        s.body = std::move(body);
        return must(protocol::sign_statement(org, provider, crypto::HashAlg::sha256, s), "sign")
            .encoded;
    };
    auto sign_record = [&] {
        protocol::Statement s;
        s.ledger_id = ledger_id;
        s.actor_id = ledger_id;
        s.issued_at = clock.now();
        s.nonce = entropy.bytes<16>();
        s.body =
            protocol::RecordRegisterBody{"example.document/1", Bytes(32, 7), 3, {}, std::nullopt};
        return must(protocol::sign_statement(org, provider, crypto::HashAlg::sha256, s), "sign")
            .encoded;
    };
    {
        auto fs = must(ledger::PosixFileSystem::open_directory(dir), "directory");
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Benchmark", org.public_key(),
                                             log.public_key()};
        auto ledger =
            must(ledger::Ledger::create(
                     fs, clock, provider,
                     must(protocol::sign_statement(org, provider, crypto::HashAlg::sha256, genesis),
                          "sign")
                         .encoded),
                 "create");
        ledger_id = ledger.id();
        for (std::uint64_t done = 0; done < prefill;) {
            const std::uint64_t n = std::min<std::uint64_t>(1000, prefill - done);
            std::vector<Bytes> batch;
            for (std::uint64_t i = 0; i < n; ++i) {
                batch.push_back(sign_record());
            }
            const std::vector<ByteView> views(batch.begin(), batch.end());
            for (auto& r : ledger.submit_batch(views)) {
                ids.push_back(must(std::move(r), "prefill").statement_id);
            }
            done += n;
        }
        if (workload) {
            // The contract, and for calls the instances (registered here,
            // before the server opens the ledger).
            protocol::Statement s;
            s.ledger_id = ledger_id;
            s.actor_id = ledger_id;
            s.issued_at = clock.now();
            s.nonce = entropy.bytes<16>();
            s.body = workload->deploy;
            contract = must(ledger.submit(must(protocol::sign_statement(org, provider,
                                                                        crypto::HashAlg::sha256, s),
                                               "sign")
                                              .encoded),
                            "deploy")
                           .statement_id;
            for (std::uint64_t done = 0; mode == "call" && done < instances;) {
                const std::uint64_t n = std::min<std::uint64_t>(1000, instances - done);
                std::vector<Bytes> batch;
                for (std::uint64_t i = 0; i < n; ++i) {
                    batch.push_back(sign_body(workload->create(contract, ledger_id)));
                }
                const std::vector<ByteView> views(batch.begin(), batch.end());
                for (auto& r : ledger.submit_batch(views)) {
                    ids.push_back(must(std::move(r), "create").statement_id);
                }
                done += n;
            }
        }
    }
    const std::string read_token = node::generate_token(entropy);
    const std::string submit_token = node::generate_token(entropy);
    must(node::save_tokens(dir, {{"reader", static_cast<node::Scopes>(node::Scope::read),
                                  node::token_hash(provider, read_token), clock.now()},
                                 {"app", static_cast<node::Scopes>(node::Scope::submit),
                                  node::token_hash(provider, submit_token), clock.now()}}),
         "tokens");

    // The requests, built (and for submits, signed) before timing starts.
    Load load;
    if (mode == "health") {
        load.requests.push_back(get_request("/healthz", read_token));
    } else if (mode == "read") {
        if (ids.empty()) {
            throw std::invalid_argument("--mode read needs --prefill > 0");
        }
        for (const protocol::Id& id : ids) {
            load.requests.push_back(
                get_request("/v1/statements/" + to_hex(id.bytes()), read_token));
        }
    } else if (mode == "submit" || mode == "create") {
        const auto t = Clock::now();
        for (std::uint64_t i = 0; i < requests; ++i) {
            load.requests.push_back(
                post_request("/v1/statements", submit_token,
                             mode == "submit" ? sign_record()
                                              : sign_body(workload->create(contract, ledger_id))));
        }
        results.add("sign (client side)", elapsed_ms(t) * 1000 / static_cast<double>(requests),
                    "us/statement");
    }

    node::ApiOptions api_options;
    api_options.directory = dir;
    auto api = must(node::LedgerApi::open(api_options, provider), "api");
    node::ServerOptions server_options;
    server_options.port = 0;
    server_options.threads = server_threads;
    server_options.max_connections = connections + 16;
    node::Server server(*api, server_options);
    must(server.listen(), "listen");
    std::thread serving([&] { server.run(); });

    // Like the server: one event loop per client thread, connections dealt
    // to them in turn.
    std::vector<std::unique_ptr<asio::io_context>> loops;
    for (std::uint64_t i = 0; i < client_threads; ++i) {
        loops.push_back(std::make_unique<asio::io_context>(1));
    }
    std::vector<Tally> tallies(connections);
    const tcp::endpoint endpoint(asio::ip::make_address("127.0.0.1"), server.port());
    double wall_ms = 0;
    auto run_load = [&](Load& l) {
        const auto started = Clock::now();
        for (std::uint64_t c = 0; c < connections; ++c) {
            asio::co_spawn(*loops[c % loops.size()],
                           connection(endpoint, l, tallies[c], std::chrono::milliseconds(c / 8)),
                           asio::detached);
        }
        std::vector<std::thread> clients;
        for (const auto& loop : loops) {
            clients.emplace_back([&lp = *loop] {
                lp.restart();
                lp.run();
            });
        }
        for (std::thread& t : clients) {
            t.join();
        }
        wall_ms += elapsed_ms(started);
    };
    if (mode == "call") {
        double signing_ms = 0;
        std::uint64_t signed_calls = 0;
        for (std::uint64_t round = 0; round < calls; ++round) {
            Load calls_load;
            const auto t = Clock::now();
            api->ledger().read_state([&](const protocol::LedgerState& state) {
                for (const protocol::Id& id : ids) {
                    const protocol::InstanceState* instance = state.instance(id);
                    if (instance == nullptr || instance->final) {
                        continue;
                    }
                    calls_load.requests.push_back(post_request(
                        "/v1/statements", submit_token,
                        sign_body(workload->call(id, instance->head, ledger_id, round))));
                }
            });
            signing_ms += elapsed_ms(t);
            signed_calls += calls_load.requests.size();
            if (calls_load.requests.empty()) {
                break;
            }
            run_load(calls_load);
        }
        results.add("sign (client side)",
                    signing_ms * 1000 /
                        static_cast<double>(std::max<std::uint64_t>(signed_calls, 1)),
                    "us/statement");
    } else {
        if (mode != "submit" && mode != "create" && seconds > 0) {
            load.until = Clock::now() + std::chrono::seconds(seconds);
        }
        run_load(load);
    }
    server.stop();
    serving.join();

    std::vector<std::uint32_t> latencies;
    Tally total;
    for (const Tally& t : tallies) {
        latencies.insert(latencies.end(), t.latencies_us.begin(), t.latencies_us.end());
        total.reconnects += t.reconnects;
        total.failed_connects += t.failed_connects;
        total.io_errors += t.io_errors;
        total.bad_statuses += t.bad_statuses;
        if (total.first_error.empty()) {
            total.first_error = t.first_error;
        }
    }
    if (!total.first_error.empty()) {
        std::println(stderr, "first error: {}", total.first_error);
    }
    const std::uint64_t errors = total.failed_connects + total.io_errors + total.bad_statuses;
    std::ranges::sort(latencies);
    auto percentile = [&](double p) {
        if (latencies.empty()) {
            return 0.0;
        }
        const auto at = static_cast<std::size_t>(p * static_cast<double>(latencies.size() - 1));
        return static_cast<double>(latencies[at]);
    };
    results.add("server threads", static_cast<double>(server_threads), "");
    results.add("client threads", static_cast<double>(client_threads), "");
    results.add("connections", static_cast<double>(connections), "");
    results.add("requests", static_cast<double>(latencies.size()), "");
    results.add("errors", static_cast<double>(errors), "");
    results.add("  failed connects", static_cast<double>(total.failed_connects), "");
    results.add("  broken connections", static_cast<double>(total.io_errors), "");
    results.add("  non-2xx answers", static_cast<double>(total.bad_statuses), "");
    results.add("reconnects (listen backlog full)", static_cast<double>(total.reconnects), "");
    results.add("throughput", static_cast<double>(latencies.size()) / wall_ms * 1000, "requests/s");
    results.add("latency p50", percentile(0.50), "us");
    results.add("latency p99", percentile(0.99), "us");
    results.add("latency p99.9", percentile(0.999), "us");
    results.add("ledger entries", static_cast<double>(api->ledger().size()), "");
    results.print(options.flag("json"));
    api.reset();
    if (!options.flag("keep")) {
        std::filesystem::remove_all(dir);
    }
    return errors == 0 ? 0 : 1;
}

} // namespace cexchain::bench
