// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Serving a ledger's HTTP API, with what an application serves beside it.

#include "serve.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <print>
#include <stop_token>
#include <sys/resource.h>
#include <thread>

#include <cexchain/client/backups.hpp>
#include <cexchain/client/network_witnesses.hpp>
#include <cexchain/client/public_witness.hpp>
#include <cexchain/client/public_witnesses.hpp>
#include <cexchain/client/relay_client.hpp>
#include <cexchain/client/relay_server.hpp>
#include <cexchain/client/witness.hpp>
#include <cexchain/ledger/backup.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/record_files.hpp>
#include <cexchain/node/replica.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

void require_ledger_directory(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir / "statements")) {
        throw CommandError{"no ledger at " + dir.string()};
    }
}

/// HOST:PORT, with [v6]:PORT for IPv6.
std::pair<std::string, std::uint16_t> parse_listen(const std::string& text) {
    std::string host;
    std::string port;
    if (text.starts_with('[')) {
        const std::size_t close = text.find("]:");
        if (close == std::string::npos) {
            throw UsageError{"--listen takes HOST:PORT, e.g. 127.0.0.1:8080 or [::1]:8080"};
        }
        host = text.substr(1, close - 1);
        port = text.substr(close + 2);
    } else {
        const std::size_t colon = text.rfind(':');
        if (colon == std::string::npos) {
            throw UsageError{"--listen takes HOST:PORT, e.g. 127.0.0.1:8080 or [::1]:8080"};
        }
        host = text.substr(0, colon);
        port = text.substr(colon + 1);
    }
    const std::uint64_t number = parse_number(port, "port");
    if (number > 65535) {
        throw UsageError{"the port must be at most 65535"};
    }
    return {host, static_cast<std::uint16_t>(number)};
}

namespace {

/// Each connection takes a file descriptor: lift the soft limit (often 256
/// or 1024) toward what the connections need, as far as the hard limit lets.
void raise_descriptor_limit(std::uint64_t wanted) {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur >= wanted) {
        return;
    }
    limit.rlim_cur = std::min<rlim_t>(limit.rlim_max, static_cast<rlim_t>(wanted));
    static_cast<void>(::setrlimit(RLIMIT_NOFILE, &limit));
}

} // namespace

namespace {

/// Asks the ledger's public witnesses every `every` until `stop`, keeping
/// their cosignatures through the API's writer; says what changed, unless
/// quiet.
void ask_witnesses_until(const std::stop_token& stop, node::LedgerApi& api,
                         const std::filesystem::path& dir, std::chrono::seconds every, bool quiet) {
    std::map<std::string, std::string> problems;
    std::mutex mutex;
    std::condition_variable_any wake;
    while (!stop.stop_requested()) {
        const auto asked = client::ask_used_witnesses(api.ledger(), dir, [&api](Bytes body) {
            auto kept = std::make_shared<std::promise<int>>();
            auto status = kept->get_future();
            api.add_cosignature(std::move(body),
                                [kept](node::http::Response r) { kept->set_value(r.status); });
            return status.wait_for(std::chrono::seconds(30)) == std::future_status::ready
                       ? status.get()
                       : 504;
        });
        for (const client::WitnessAsked& a : asked) {
            if (!quiet && a.cosigned) {
                std::println(stderr, "witness {} cosigned the checkpoint at size {}", a.name,
                             *a.cosigned);
            }
            if (std::string& was = problems[a.name]; was != a.problem) {
                if (!quiet && !a.problem.empty()) {
                    std::println(stderr, "witness {}: {}", a.name.empty() ? "list" : a.name,
                                 a.problem);
                }
                was = a.problem;
            }
        }
        std::unique_lock lock(mutex);
        wake.wait_for(lock, stop, every, [] { return false; });
    }
}

} // namespace

int serve(const Args& args, const ServeDefaults& defaults) {
    // A server stamps every write with its clock, so one run ahead
    // ($CEXCHAIN_CLOCK_OFFSET) records later times for everyone who writes
    // through it, and keeps them: it takes an explicit flag, so that a
    // variable left in an environment does not move a ledger's clock.
    if (ledger::SystemClock::offset() != 0 && !args.has("allow-clock-offset")) {
        throw UsageError{std::format(
            "CEXCHAIN_CLOCK_OFFSET runs the clock {} s ahead, and a server would record the later "
            "times for good: unset it, or pass --allow-clock-offset (demonstrations and tests "
            "only)",
            ledger::SystemClock::offset() / 1000)};
    }
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    node::ApiOptions options;
    options.directory = dir;
    for (const std::string& key : args.all("log-key")) {
        options.log_keys.push_back(std::shared_ptr<const crypto::Signer>(load_signer(key, args)));
    }
    options.read_only = args.has("read-only");
    options.cluster = args.has("cluster");
    options.public_read = args.has("public-read");
    const std::uint64_t interval = args.has("checkpoint-interval")
                                       ? parse_number(*args.get("checkpoint-interval"), "interval")
                                   : !options.log_keys.empty() ? 60
                                                               : 0;
    if (interval > 0 && options.log_keys.empty()) {
        throw UsageError{"--checkpoint-interval needs --log-key"};
    }
    options.checkpoint_interval = std::chrono::seconds(interval);
    if (const auto tsa = args.get("tsa")) {
        options.timestamp_authority = *tsa;
        if (const auto every = args.get("timestamp-interval")) {
            options.timestamp_interval =
                std::chrono::seconds(parse_number(*every, "--timestamp-interval"));
            if (options.timestamp_interval.count() == 0) {
                throw UsageError{"--timestamp-interval must be at least one second"};
            }
        }
    } else if (args.has("timestamp-interval")) {
        throw UsageError{"--timestamp-interval needs --tsa"};
    }
    if (const auto note = args.get("note-key")) {
        auto key = load_signer(*note, args);
        if (key->algorithm() != crypto::SigAlg::ed25519) {
            throw UsageError{"--note-key takes an Ed25519 key"};
        }
        options.note_key = std::shared_ptr<const crypto::Signer>(std::move(key));
        for (const client::UsedNetworkWitness& w :
             client::load_network_witnesses(dir, shared_provider())) {
            options.network_witnesses.push_back(w.witness);
        }
        if (const auto every = args.get("network-interval")) {
            options.network_interval =
                std::chrono::seconds(parse_number(*every, "--network-interval"));
            if (options.network_interval.count() == 0) {
                throw UsageError{"--network-interval must be at least one second"};
            }
        }
    } else if (args.has("network-interval")) {
        throw UsageError{"--network-interval needs --note-key"};
    }
    if (const auto every = args.get("snapshot-interval")) {
        options.snapshot_interval = parse_number(*every, "--snapshot-interval");
    }
    options.version = CEXCHAIN_VERSION;
    options.event_log = &std::cerr;
    if (args.has("witness-dir") != args.has("witness-key")) {
        throw UsageError{"--witness-dir and --witness-key go together"};
    }
    const bool witness_public = args.has("witness-public");
    if (witness_public && !args.has("witness-dir")) {
        throw UsageError{"--witness-public needs --witness-dir and --witness-key"};
    }
    for (const char* option : {"witness-name", "witness-max-ledgers",
                               "witness-registrations-per-day", "witness-cosign-interval"}) {
        if (args.has(option) && !witness_public) {
            throw UsageError{std::format("--{} goes with --witness-public", option)};
        }
    }
    if (const auto witness_dir = args.get("witness-dir")) {
        if (!witness_public && !std::filesystem::is_directory(*witness_dir)) {
            throw CommandError{"no witness directory at " + *witness_dir +
                               " (cexchain witness add-log)"};
        }
        std::shared_ptr<const crypto::Signer> witness_key =
            load_signer(args.need("witness-key"), args);
        options.witness = [dir = std::filesystem::path(*witness_dir),
                           witness_key](ByteView request) {
            return client::witness_cosign(dir, *witness_key, request, ledger::SystemClock{}.now());
        };
        if (witness_public) {
            // Any ledger registers and asks, with no token, within quotas.
            client::PublicWitnessLimits limits;
            if (const auto n = args.get("witness-max-ledgers")) {
                limits.max_ledgers = parse_number(*n, "--witness-max-ledgers");
            }
            if (const auto n = args.get("witness-registrations-per-day")) {
                limits.registrations_per_day = parse_number(*n, "--witness-registrations-per-day");
            }
            if (const auto n = args.get("witness-cosign-interval")) {
                limits.cosign_interval = parse_number(*n, "--witness-cosign-interval") * 1000;
            }
            auto witness = std::make_shared<client::PublicWitness>(
                *witness_dir, witness_key, args.get("witness-name").value_or(""), limits);
            options.public_witness = [witness](const node::http::Request& r,
                                               std::string_view address) {
                return witness->handle(r, address, ledger::SystemClock{}.now());
            };
        }
    }
    if (const auto relay_dir = args.get("relay-dir")) {
        if (!witness_public) {
            throw UsageError{"--relay-dir needs --witness-public: a relay serves the ledgers its "
                             "witness follows"};
        }
        auto relay = std::make_shared<client::Relay>(*relay_dir, *args.get("witness-dir"),
                                                     client::RelayLimits{});
        options.extensions.push_back({.handle =
                                          [relay](const node::http::Request& r, std::string_view,
                                                  node::Application::Respond respond) {
                                              return relay->handle(r, ledger::SystemClock{}.now(),
                                                                   std::move(respond));
                                          },
                                      .tick = [relay] { relay->tick(ledger::SystemClock{}.now()); },
                                      .stopping = [relay] { relay->stopping(); }});
    }
    if (const auto registrar = args.get("registrar-key")) {
        if (options.log_keys.empty()) {
            throw UsageError{"--registrar-key needs --log-key (to serve instances' evidence)"};
        }
        options.registrar = load_signer(*registrar, args);
    }
    if (const auto keeper = args.get("keeper-key")) {
        if (options.read_only) {
            throw UsageError{"--keeper-key writes: not with --read-only"};
        }
        options.keeper = load_signer(*keeper, args);
    } else if (args.has("keeper-interval") || args.has("expiry-grace")) {
        throw UsageError{"--keeper-interval and --expiry-grace go with --keeper-key"};
    }
    if (const auto every = args.get("keeper-interval")) {
        const std::uint64_t seconds = parse_number(*every, "--keeper-interval");
        if (seconds == 0 || seconds > 86'400) {
            throw UsageError{"--keeper-interval is 1 to 86400 seconds"};
        }
        options.keeper_interval = std::chrono::seconds(seconds);
    }
    if (const auto grace = args.get("expiry-grace")) {
        const std::uint64_t seconds = parse_number(*grace, "--expiry-grace");
        if (seconds > 31'622'400) {
            throw UsageError{"--expiry-grace is 0 to 31622400 seconds (366 days)"};
        }
        options.expiry_grace = std::chrono::seconds(seconds);
    }
    // An application served beside the API (the console, the index) adds
    // its parts to the options.
    if (defaults.before_open) {
        defaults.before_open(options);
    }
    auto api = unwrap(node::LedgerApi::open(options, shared_provider()), "opening the ledger");
    if (defaults.after_open) {
        defaults.after_open(*api);
    }

    node::ServerOptions server_options;
    const auto [host, port] =
        parse_listen(args.get("listen").value_or(defaults.listen.value_or("127.0.0.1:8080")));
    server_options.host = host;
    server_options.port = port;
    if (defaults.check_listen) {
        const bool loopback = host == "127.0.0.1" || host == "::1" || host.starts_with("127.");
        defaults.check_listen(loopback, args.has("tls-cert"));
    }
    if (const auto cert = args.get("tls-cert")) {
        server_options.tls_certificate = *cert;
    }
    if (const auto key = args.get("tls-key")) {
        server_options.tls_private_key = *key;
    }
    if (const auto n = args.get("threads")) {
        server_options.threads = parse_number(*n, "threads");
        if (server_options.threads == 0 || server_options.threads > 1024) {
            throw UsageError{"--threads is 1 to 1024"};
        }
    }
    if (const auto n = args.get("max-connections")) {
        server_options.max_connections = parse_number(*n, "connections");
    }
    if (const auto n = args.get("max-connections-per-ip")) {
        server_options.max_connections_per_peer = parse_number(*n, "connections per address");
    }
    raise_descriptor_limit(server_options.max_connections + 64);
    keep_keys_out_of_dumps();
    if (const auto n = args.get("max-body")) {
        server_options.limits.max_body = parse_number(*n, "body size");
    } else if (defaults.max_body) {
        server_options.limits.max_body = *defaults.max_body;
    }
    server_options.access_log = args.has("quiet") ? nullptr : &std::cerr;
    const bool tls = server_options.tls_certificate.has_value();

    // With a fallback, the next ports are tried when this one is taken.
    std::optional<node::Server> listening;
    for (unsigned tried = 0;; ++tried) {
        listening.emplace(*api, server_options);
        auto status = listening->listen();
        if (status) {
            break;
        }
        if (tried + 1 >= defaults.port_fallback) {
            unwrap(std::move(status), "starting the server");
        }
        listening.reset();
        ++server_options.port;
    }
    node::Server& server = *listening;
    const std::string url =
        std::format("{}://{}:{}", tls ? "https" : "http",
                    host.find(':') != std::string::npos ? "[" + host + "]" : host, server.port());
    // Where people reach the application served beside the API, if any.
    const auto served_too =
        defaults.on_address ? std::optional(defaults.on_address(server.port())) : std::nullopt;
    const std::string role = api->is_replica() ? "replica" : "primary";
    if (args.json()) {
        Json started{{"url", url},
                     {"port", server.port()},
                     {"ledger_id", id_json(api->ledger().id())},
                     {"role", role},
                     {"read_only", options.read_only || api->is_replica()},
                     {"log_key", !options.log_keys.empty()},
                     {"checkpoint_interval", interval},
                     {"timestamp_authority", options.timestamp_authority.empty()
                                                 ? Json(nullptr)
                                                 : Json(options.timestamp_authority)},
                     {"keeper", options.keeper != nullptr},
                     {"network_witnesses",
                      options.note_key ? Json(options.network_witnesses.size()) : Json(nullptr)},
                     {"clock_offset_ms", ledger::SystemClock::offset()}};
        if (served_too) {
            started[served_too->first] = served_too->second;
        }
        print_json(started);
    } else {
        std::println("serving ledger {} ({}) at {}", hex_id(api->ledger().id()), role, url);
        if (served_too) {
            std::println("{}: {}", served_too->first, served_too->second);
        }
        if (options.log_keys.empty()) {
            std::println("no --log-key: receipts, evidence, and checkpoints are not served");
        }
        if (options.keeper) {
            std::println(
                "keeper: every {} s, expiring requests {} s after their deadline",
                options.keeper_interval.count(),
                std::chrono::duration_cast<std::chrono::seconds>(options.expiry_grace).count());
        }
    }
    if (const protocol::Timestamp offset = ledger::SystemClock::offset(); offset != 0) {
        std::println(stderr,
                     "warning: the ledger's clock runs {} s ahead of this computer's "
                     "($CEXCHAIN_CLOCK_OFFSET): for demonstrations and tests only; what it "
                     "records keeps the later times",
                     offset / 1000);
    }
    std::fflush(stdout);
    if (defaults.on_listening) {
        defaults.on_listening(server.port());
    }
    // Reached through a relay (relay use): the requests that wait there for
    // this ledger, answered with its own API.
    std::jthread relaying;
    if (const auto relay_key = args.get("relay-key")) {
        const auto own = client::load_own_relay(dir);
        if (!own) {
            throw UsageError{"--relay-key: this ledger is not reached through a relay (relay use)"};
        }
        if (options.log_keys.empty()) {
            throw UsageError{
                "--relay-key needs --log-key, which signs what goes through the relay"};
        }
        auto key =
            std::make_shared<const crypto::openssl::HpkeKey>(load_hpke_key(*relay_key, args));
        if (!std::ranges::equal(key->public_key(), own->key)) {
            throw UsageError{"--relay-key is not the key this ledger's relay seals to (relay use)"};
        }
        std::shared_ptr<const crypto::Signer> log_key = options.log_keys.back();
        auto agent = std::make_shared<client::RelayAgent>(
            *own, key, api->ledger().id(), [log_key] { return log_key; },
            [api = api.get()](node::http::Request r,
                              std::function<void(node::http::Response)> done) {
                api->handle(std::move(r), "relay", std::move(done));
            });
        relaying = std::jthread([agent, quiet = args.has("quiet")](const std::stop_token& stop) {
            agent->run(stop, [quiet](const std::string& problem) {
                if (!quiet) {
                    std::println(stderr, "relay: {}", problem.empty() ? "reached" : problem);
                }
            });
        });
    }
    // The public witnesses this ledger registered with (witness register),
    // asked after each new checkpoint; the list is read each time.
    std::jthread asking;
    if (!api->is_replica() && !options.read_only && !options.log_keys.empty()) {
        // As often as checkpoints come, at most every 15 seconds.
        const auto every =
            std::chrono::seconds(interval == 0 ? 15 : std::clamp<std::uint64_t>(interval, 1, 15));
        asking = std::jthread(
            [api = api.get(), dir, every, quiet = args.has("quiet")](const std::stop_token& stop) {
                ask_witnesses_until(stop, *api, dir, every, quiet);
            });
    }
    server.run();
    return exit_ok;
}

} // namespace cexchain::cli
