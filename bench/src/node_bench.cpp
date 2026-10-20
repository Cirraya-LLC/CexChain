// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The node's contract services against an in-process server (D-056):
//   executor   an executor answering open requests through the command
//              connector (a child process running a program per request),
//              with where each request's time goes, from its events;
//   registrar  calls that need a party's consent: proposed to the home's
//              registrar, then the party's consent posted, after which the
//              registrar records the call.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <print>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/connectors.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/executor.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "bench.hpp"
#include "fixture.hpp"

namespace cexchain::bench {

namespace {

using json = nlohmann::json;
using namespace std::chrono_literals;
constexpr protocol::Timestamp hour = 3'600'000;

std::filesystem::path scratch(const Options& options, const std::string& name) {
    const std::filesystem::path dir =
        options.text("dir", (std::filesystem::temp_directory_path() /
                             std::format("cexchain-bench-{}-{}", name, ::getpid()))
                                .string());
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

class Serving {
public:
    Serving(node::Application& app, std::uint64_t threads)
        : server_(app, [threads] {
              node::ServerOptions o;
              o.port = 0;
              o.threads = threads;
              o.max_connections = 4096;
              return o;
          }()) {
        must(server_.listen(), "listen");
        thread_ = std::thread([this] { server_.run(); });
    }
    Serving(const Serving&) = delete;
    Serving& operator=(const Serving&) = delete;
    ~Serving() {
        server_.stop();
        thread_.join();
    }
    [[nodiscard]] std::string url() const {
        return std::format("http://127.0.0.1:{}", server_.port());
    }

private:
    node::Server server_;
    std::thread thread_;
};

node::Scopes scopes(std::initializer_list<node::Scope> list) {
    node::Scopes out = 0;
    for (const node::Scope s : list) {
        out |= static_cast<node::Scopes>(s);
    }
    return out;
}

protocol::Timestamp system_now() {
    return ledger::SystemClock{}.now();
}

} // namespace

// --- executor ---

namespace {

/// A webhook receiver: takes every POST, done, with a result.
class Receiver final : public node::Application {
public:
    void handle(node::http::Request, std::string, Respond respond) override {
        node::http::Response r;
        const std::string body = R"({"result":{"ref":"R-1"}})";
        r.body.assign(body.begin(), body.end());
        respond(std::move(r));
    }
};

} // namespace

int executor_bench(const Options& options) {
    const std::uint64_t n = options.number("requests", 200);
    const std::filesystem::path dir = scratch(options, "executor");
    const std::filesystem::path ledger_dir = dir / "ledger";
    // The executor's state: beside the ledger, or elsewhere (--state: another
    // volume, as when the executor runs on a machine of its own).
    const std::filesystem::path state_dir =
        options.text("state", (dir / "state").string()) + "/executor-bench-state";
    std::filesystem::remove_all(state_dir);
    std::filesystem::create_directories(state_dir);
    const std::string type = options.text("connector", "command");
    if (type != "command" && type != "webhook") {
        throw std::runtime_error("--connector is command or webhook");
    }
    Results results;

    // The home: the requesting test contract (testvectors/test-contracts.json,
    // which needs no Bo), an executor device answering "notify" requests,
    // and `n` instances, each with one open request.
    Home home("executor home", ledger_dir, system_now() - 600'000);
    const json vectors = json::parse(
        read_text(std::filesystem::path(CEXCHAIN_BENCH_TESTVECTORS_DIR) / "test-contracts.json"));
    protocol::ContractDeployBody deploy;
    deploy.code = must(from_hex(vectors["request"].get<std::string>()), "hex");
    for (const auto& [name, kind] : vectors["request_interface"].items()) {
        deploy.interface.emplace(name, static_cast<protocol::FunctionKind>(kind.get<int>()));
    }
    deploy.language = "wasm";
    deploy.compiler = "test_contracts.py 1";
    deploy.name = "Requesting";
    const protocol::Id contract = home.submit(deploy).statement_id;
    const crypto::openssl::KeyPair device = named_key("executor device");
    const protocol::Id actor =
        home.submit(protocol::ActorRegisterBody{
                        protocol::ActorKind::device, "Notifier", device.public_key(), {}, {}})
            .statement_id;
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::contract_call};
    scope.contracts = std::vector<protocol::Id>{contract};
    scope.functions = std::vector<std::string>{"result"};
    scope.request_kinds = std::vector<std::string>{"notify"};
    const protocol::Id delegation =
        home.submit(protocol::DelegationGrantBody{actor, scope}).statement_id;
    std::vector<Bytes> creations;
    for (std::uint64_t i = 0; i < n; ++i) {
        protocol::ContractCallBody b;
        b.contract = contract;
        b.function = "open";
        b.arguments = cbor::Value::array(
            {cbor::Value::array({text("notify"), object({{"n", number(i)}}), number(hour)})});
        creations.push_back(home.sign(std::move(b)).encoded);
    }
    home.submit_all(creations, 512, nullptr);
    must(home.ledger().checkpoint(home.log_key()), "checkpoint");
    const std::string token = "executor-token-0123456789";
    must(node::save_tokens(ledger_dir, {{"notifier", scopes({node::Scope::executor}),
                                         node::token_hash(provider(), token), t0}}),
         "tokens");
    home.close();

    node::ApiOptions api_options;
    api_options.directory = ledger_dir;
    api_options.log_keys = {
        std::make_shared<const crypto::openssl::KeyPair>(named_key("executor home log"))};
    auto api = must(node::LedgerApi::open(api_options, provider()), "api");
    auto serving = std::make_unique<Serving>(*api, options.number("server-threads", 2));
    Receiver receiver;
    std::unique_ptr<Serving> hooks;

    node::executor::Config config;
    config.ledger = home.id();
    config.actor = actor;
    config.delegation = delegation;
    node::executor::ConnectorConfig connector;
    connector.name = "notices";
    connector.type = type;
    connector.kinds = {"notify"};
    node::executor::RunOptions o;
    if (type == "command") {
        connector.config = json{{"program", options.text("program", "/usr/bin/true")}}.dump();
    } else {
        hooks = std::make_unique<Serving>(receiver, options.number("hook-threads", 2));
        connector.config = json{{"url", hooks->url() + "/hook"}, {"secret", "hook-key"}}.dump();
        connector.secrets = {"hook-key"};
        const std::string secret = "bench-hook-secret";
        o.secrets.emplace("hook-key", SecureBytes(Bytes(secret.begin(), secret.end())));
    }
    config.connectors.push_back(connector);

    const std::string cli = options.text("cexchain", CEXCHAIN_BENCH_CLI);
    const bool in_process = options.flag("in-process") || !std::filesystem::exists(cli);
    o.server = serving->url();
    o.client.bearer_token = token;
    o.state = state_dir;
    o.channels = in_process ? node::executor::local_channels(type == "command"
                                                                 ? node::connector::make_command
                                                                 : node::connector::make_webhook)
                            : node::executor::process_channels(cli);
    o.signer = &device;
    o.provider = &provider();
    o.once = true;
    o.wait = 0s;
    o.concurrency = options.number("concurrency", 0);
    // Each event with the thread it came from: a worker works its requests
    // one after another, so a request's time runs from that worker's last
    // event (or, for its first, from when the request was listed).
    struct Event {
        Clock::time_point at;
        std::string name;
        std::string request;
        std::thread::id thread;
    };
    std::vector<Event> events;
    std::uint64_t concurrency = 0;
    o.on_event = [&](std::string_view line) {
        const json e = json::parse(line);
        events.push_back({Clock::now(), e.value("event", ""), e.value("request", ""),
                          std::this_thread::get_id()});
        if (e.value("event", "") == "started") {
            concurrency = e.value("concurrency", std::uint64_t{0});
        }
    };
    const auto started = Clock::now();
    const auto ran = node::executor::run(config, o);
    const double wall_ms = elapsed_ms(started);
    if (!ran) {
        throw std::runtime_error("the executor stopped: " + ran.error());
    }

    // Each request's time, from its worker's previous event to its
    // "answered", and its parts.
    Latencies total;
    Latencies verify;
    Latencies prepare;
    Latencies connector_run;
    Latencies answer;
    std::map<std::string, Clock::time_point> seen;
    std::map<std::string, Clock::time_point> verified;
    std::map<std::string, Clock::time_point> acting;
    std::map<std::string, Clock::time_point> outcome;
    std::map<std::string, Clock::time_point> since;
    std::map<std::thread::id, Clock::time_point> last;
    std::optional<Clock::time_point> first_verified;
    std::optional<Clock::time_point> last_answered;
    auto us = [](Clock::time_point a, Clock::time_point b) {
        return std::chrono::duration<double, std::micro>(b - a).count();
    };
    for (const Event& e : events) {
        if (e.name == "seen") {
            seen[e.request] = e.at;
        } else if (e.name == "verified") {
            const auto previous = last.find(e.thread);
            since[e.request] = previous != last.end()     ? previous->second
                               : seen.contains(e.request) ? seen[e.request]
                                                          : e.at;
            verified[e.request] = e.at;
            verify.add(us(since[e.request], e.at));
            first_verified = first_verified.value_or(e.at);
        } else if (e.name == "acting" && verified.contains(e.request)) {
            acting[e.request] = e.at;
            prepare.add(us(verified[e.request], e.at));
        } else if (e.name == "outcome" && acting.contains(e.request)) {
            outcome[e.request] = e.at;
            connector_run.add(us(acting[e.request], e.at));
        } else if (e.name == "answered" && outcome.contains(e.request)) {
            answer.add(us(outcome[e.request], e.at));
            total.add(us(since[e.request], e.at));
            last_answered = e.at;
        }
        last[e.thread] = e.at;
    }
    auto mean = [](const Latencies& l) {
        return l.total_us() / static_cast<double>(std::max<std::size_t>(l.size(), 1));
    };
    results.add("connector", in_process ? 0 : 1, "(1: a child process, 0: in this process)");
    results.add(type == "command" ? "connector type: command" : "connector type: webhook", 1, "");
    results.add("concurrency", static_cast<double>(concurrency), "requests at once");
    results.add("requests", static_cast<double>(n), "");
    results.add("answered", static_cast<double>(total.size()), "");
    results.add("wall", wall_ms, "ms");
    results.add("throughput", static_cast<double>(total.size()) * 1000 / wall_ms, "answers/s");
    if (first_verified && last_answered && *last_answered > *first_verified) {
        results.add("throughput, first verified to last answered",
                    static_cast<double>(total.size()) * 1e6 / us(*first_verified, *last_answered),
                    "answers/s");
    }
    total.report(results, "request", "");
    results.add("verify the request (evidence fetched and checked)", mean(verify), "us");
    results.add("journal before acting", mean(prepare), "us");
    results.add(type == "command" ? "connector (the program run)" : "connector (the webhook)",
                mean(connector_run), "us");
    results.add("answer (sign, submit durably)", mean(answer), "us");
    serving.reset();
    hooks.reset();
    api.reset();
    results.print(options.flag("json"));
    if (!options.flag("keep")) {
        std::filesystem::remove_all(state_dir);
        std::filesystem::remove_all(dir);
    }
    return total.size() == n ? 0 : 1;
}

// --- registrar ---

int registrar_bench(const Options& options) {
    const std::uint64_t n = options.number("instances", 200);
    const std::uint64_t k = options.number("calls", 2);
    const std::uint64_t threads = std::max<std::uint64_t>(1, options.number("client-threads", 8));
    const std::filesystem::path dir = scratch(options, "registrar");
    Results results;

    // The home lends n things; the party (another organization's ledger)
    // borrows each and brings it back: every call needs its consent.
    const protocol::Timestamp start = system_now() - 600'000;
    Home home("registrar home", dir / "home", start);
    Home party("registrar party", {}, start);
    const Workload small = make_workload("small", options);
    const protocol::Id contract = home.submit(small.deploy).statement_id;
    const crypto::openssl::KeyPair registrar_key = named_key("registrar device");
    const protocol::Id device =
        home
            .submit(protocol::ActorRegisterBody{
                protocol::ActorKind::device, "Registrar", registrar_key.public_key(), {}, {}})
            .statement_id;
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::contract_call};
    scope.contracts = std::vector<protocol::Id>{contract};
    home.submit(protocol::DelegationGrantBody{device, scope});
    std::vector<protocol::Id> instances;
    std::vector<Bytes> creations;
    for (std::uint64_t i = 0; i < n; ++i) {
        protocol::SignedStatement s = home.sign(small.create(contract, home.id()));
        instances.push_back(s.id);
        creations.push_back(std::move(s.encoded));
    }
    home.submit_all(creations, 512, nullptr);
    must(home.ledger().checkpoint(home.log_key()), "checkpoint");
    const std::string staff = "staff-token-0123456789";
    const std::string peer = "party-token-0123456789";
    must(node::save_tokens(
             home.directory(),
             {{"staff", scopes({node::Scope::read, node::Scope::submit}),
               node::token_hash(provider(), staff), t0},
              {"party", scopes({node::Scope::peer}), node::token_hash(provider(), peer), t0}}),
         "tokens");
    node::Peer p;
    p.name = "party";
    p.ledger_id = party.id();
    must(node::save_peers(home.directory(), {p}), "peers");
    const protocol::Id home_id = home.id();
    home.close();

    node::ApiOptions api_options;
    api_options.directory = dir / "home";
    api_options.log_keys = {
        std::make_shared<const crypto::openssl::KeyPair>(named_key("registrar home log"))};
    api_options.registrar =
        std::make_shared<const crypto::openssl::KeyPair>(named_key("registrar device"));
    auto api = must(node::LedgerApi::open(api_options, provider()), "api");
    auto serving = std::make_unique<Serving>(*api, options.number("server-threads", 2));
    const node::Url url = must(node::Url::parse(serving->url()), "url");

    // Posts bodies from `threads` threads, each with its own client.
    auto post = [&](const std::string& path, const std::string& token,
                    const std::vector<Bytes>& bodies, Latencies& latencies, int expected) {
        std::atomic<std::size_t> next = 0;
        std::atomic<std::size_t> failures = 0;
        std::vector<std::vector<double>> times(threads);
        std::mutex first_mutex;
        std::string first;
        const auto started = Clock::now();
        std::vector<std::thread> workers;
        for (std::uint64_t t = 0; t < threads; ++t) {
            workers.emplace_back([&, t] {
                node::ClientOptions co;
                co.bearer_token = token;
                const node::Client client(url, co);
                for (std::size_t i; (i = next.fetch_add(1)) < bodies.size();) {
                    const auto at = Clock::now();
                    auto r = client.request("POST", path, bodies[i], "application/cbor");
                    times[t].push_back(elapsed_us(at));
                    if (!r || r->status != expected) {
                        ++failures;
                        const std::scoped_lock lock(first_mutex);
                        if (first.empty()) {
                            first = r ? std::format("{} {}", r->status,
                                                    std::string(r->body.begin(), r->body.end()))
                                      : std::string(r.error().detail);
                        }
                    }
                }
            });
        }
        for (std::thread& w : workers) {
            w.join();
        }
        for (const auto& per : times) {
            for (const double us : per) {
                latencies.add(us);
            }
        }
        if (failures > 0) {
            throw std::runtime_error(
                std::format("{}: {} failed, the first: {}", path, failures.load(), first));
        }
        return elapsed_ms(started);
    };

    Latencies proposed;
    Latencies consented;
    double propose_ms = 0;
    double consent_ms = 0;
    double party_ms = 0;
    std::uint64_t made = 0;
    for (std::uint64_t round = 0; round < k; ++round) {
        // What each instance's call is: lend to the party, or bring back.
        std::vector<node::PendingCall> pending;
        api->ledger().read_state([&](const protocol::LedgerState& state) {
            for (const protocol::Id& id : instances) {
                node::PendingCall c;
                c.instance = id;
                c.head = state.instance(id)->head;
                const protocol::ContractCallBody b = small.call(id, c.head, party.id(), round);
                c.function = b.function;
                c.arguments = b.arguments;
                pending.push_back(std::move(c));
            }
        });
        std::vector<Bytes> proposals;
        for (const node::PendingCall& c : pending) {
            proposals.push_back(must(node::encode_call_proposal(c), "proposal"));
        }
        propose_ms += post("/v1/contracts/calls", staff, proposals, proposed, 202);

        // The party consents on its own ledger: one record each, one
        // checkpoint, one bundle each.
        const auto t = Clock::now();
        party.clock().set(std::max(party.clock().now(), system_now() - 1000));
        std::vector<protocol::Id> records;
        std::vector<Bytes> statements;
        for (const node::PendingCall& c : pending) {
            const protocol::Id digest = must(protocol::contract_arguments_digest(
                                                 provider(), crypto::HashAlg::sha256, c.arguments),
                                             "digest");
            auto metadata = must(
                protocol::encode_contract_consent({home_id, c.instance, c.function, digest, c.head,
                                                   system_now() + 30 * day, std::nullopt}),
                "consent");
            const auto commitment =
                must(protocol::commit_fields(provider(), crypto::HashAlg::sha256,
                                             {{"terms", protocol::Nonce{}, text("agreed")}}),
                     "commit");
            protocol::SignedStatement s = party.sign(protocol::RecordRegisterBody{
                std::string(protocol::contract_consent_type),
                Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end()),
                1,
                {},
                std::move(metadata)});
            records.push_back(s.id);
            statements.push_back(std::move(s.encoded));
        }
        party.submit_all(statements, 512, nullptr);
        must(party.ledger().checkpoint(party.log_key()), "party checkpoint");
        std::vector<Bytes> bundles;
        for (const protocol::Id& record : records) {
            bundles.push_back(
                must(protocol::encode_bundle(
                         must(party.ledger().export_evidence(party.log_key(), record), "export")),
                     "bundle"));
        }
        party_ms += elapsed_ms(t);
        consent_ms += post("/v1/contracts/consents", peer, bundles, consented, 201);
        made += pending.size();
    }
    results.add("client threads", static_cast<double>(threads), "");
    results.add("consent-bearing calls", static_cast<double>(made), "");
    results.add("propose throughput", static_cast<double>(made) * 1000 / propose_ms, "proposals/s");
    proposed.report(results, "propose", "");
    results.add("consent throughput (recorded calls)",
                static_cast<double>(made) * 1000 / consent_ms, "calls/s");
    consented.report(results, "consent", "");
    results.add("party side per consent (record, checkpoint, export)",
                party_ms * 1000 / static_cast<double>(made), "us");
    results.add("ledger entries", static_cast<double>(api->ledger().size()), "");
    serving.reset();
    api.reset();
    results.print(options.flag("json"));
    if (!options.flag("keep")) {
        std::filesystem::remove_all(dir);
    }
    return 0;
}

} // namespace cexchain::bench
