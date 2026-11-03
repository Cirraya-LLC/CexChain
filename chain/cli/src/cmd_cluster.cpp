// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Clusters: several nodes keep one ledger with Raft, and a new
// leader takes over within seconds if the leader fails.
//
//   cexchain cluster init     the first member (on a fully checkpointed ledger)
//   cexchain cluster join     copy the cluster's ledger, ready to be added
//   cexchain serve --cluster  run a member
//   cexchain cluster add      the leader adds a running node
//   cexchain cluster status | remove | step-down

#include <array>
#include <charconv>
#include <cstdlib>
#include <print>

#include <cexchain/node/api.hpp>
#include <cexchain/node/cluster.hpp>
#include <cexchain/node/replica.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

int parse_id(const Args& args) {
    const std::uint64_t id = parse_number(args.need("id"), "--id");
    if (id < 1 || id > 1000) {
        throw UsageError{"--id is 1 to 1000"};
    }
    return static_cast<int>(id);
}

/// --raft HOST:PORT, and the port to listen on.
std::pair<std::string, std::uint16_t> raft_address(const Args& args) {
    const std::string endpoint = args.need("raft");
    const std::size_t colon = endpoint.rfind(':');
    std::uint64_t port = 0;
    if (colon == std::string::npos || colon == 0) {
        throw UsageError{"--raft is HOST:PORT"};
    }
    port = parse_number(endpoint.substr(colon + 1), "the --raft port");
    if (const auto listen = args.get("raft-port")) {
        port = parse_number(*listen, "--raft-port");
    }
    if (port == 0 || port > 65535) {
        throw UsageError{"a Raft port is 1 to 65535"};
    }
    return {endpoint, static_cast<std::uint16_t>(port)};
}

std::string api_url(const Args& args) {
    std::string url = args.need("api");
    while (url.ends_with('/')) {
        url.pop_back();
    }
    unwrap(node::Url::parse(url), "reading --api");
    return url;
}

node::Client cluster_client(const Args& args) {
    std::optional<std::string> url = args.get("server");
    if (!url) {
        if (const char* env = std::getenv("CEXCHAIN_SERVER"); env != nullptr && *env != '\0') {
            url = env;
        }
    }
    if (!url) {
        throw UsageError{"name a member's API: --server URL (or $CEXCHAIN_SERVER)"};
    }
    return client_for(*url, args, args.get("ca-file"));
}

Json call(const node::Client& client, std::string_view method, std::string_view path,
          const Json& body = nullptr) {
    const std::string text = body.is_null() ? std::string() : body.dump();
    const auto response = unwrap(
        client.request(method, path, as_bytes(text), body.is_null() ? "" : "application/json"),
        "reaching " + client.base().to_string());
    const Json answer = Json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (response.status != 200) {
        const std::string message = answer.is_object() && answer.contains("error")
                                        ? answer["error"].value("message", std::string())
                                        : "HTTP " + std::to_string(response.status);
        throw CommandError{"the cluster refused: " + message};
    }
    return answer;
}

Bytes read_secret(const std::filesystem::path& path) {
    Bytes secret = read_file(path);
    if (secret.size() != node::cluster_secret_size) {
        throw CommandError{path.string() + " is not a cluster secret (32 bytes)"};
    }
    return secret;
}

} // namespace

int cmd_cluster_init(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    const node::ClusterNode self{parse_id(args), raft_address(args).first,
                                 raft_address(args).second, api_url(args), true};
    {
        Session session(dir);
        session.require_primary();
        if (node::is_cluster_member(dir)) {
            throw CommandError{"this ledger is a cluster member already"};
        }
        // Members that join copy the ledger up to its latest checkpoint; Raft
        // brings them the rest. So the cluster starts from a checkpoint.
        const auto latest = session.ledger().latest_checkpoint();
        if (!latest || latest->checkpoint.tree_size != session.ledger().size()) {
            throw CommandError{"checkpoint the whole log first (cexchain checkpoint create)"};
        }
    }
    Bytes secret;
    if (const auto file = args.get("secret-file")) {
        secret = read_secret(*file);
    } else {
        std::array<std::uint8_t, node::cluster_secret_size> fresh{};
        unwrap(crypto::openssl::random_bytes(fresh), "generating the cluster secret");
        secret.assign(fresh.begin(), fresh.end());
    }
    unwrap(node::init_cluster(dir, self, secret), "starting the cluster");
    const std::filesystem::path secret_path = dir / node::cluster_directory / "secret";
    if (args.json()) {
        print_json({{"id", self.id},
                    {"raft", self.raft_endpoint},
                    {"api", self.api_url},
                    {"secret_file", secret_path.string()}});
        return exit_ok;
    }
    std::println("this ledger founds a cluster as member {} (Raft at {})", self.id,
                 self.raft_endpoint);
    std::println("Run it with: cexchain serve --cluster --ledger {} ...", dir.string());
    std::println("Copy {} to every other member, privately: it authenticates the members.",
                 secret_path.string());
    return exit_ok;
}

int cmd_cluster_join(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    if (std::filesystem::exists(dir / "statements")) {
        throw CommandError{"a ledger already exists at " + dir.string()};
    }
    const node::ClusterNode self{parse_id(args), raft_address(args).first,
                                 raft_address(args).second, api_url(args), false};
    const Bytes secret = read_secret(args.need("secret-file"));
    const std::string url = args.need("from");
    const node::Client client = client_for(url, args, args.get("ca-file"));
    std::optional<protocol::Id> expected;
    if (const auto text = args.get("ledger-id")) {
        const auto bytes = from_hex(*text);
        if (!bytes || bytes->size() != protocol::id_size) {
            throw UsageError{"--ledger-id must be the full hex ledger id"};
        }
        expected = unwrap(protocol::to_id(*bytes), "ledger id");
    } else if (!client.base().tls) {
        throw UsageError{"an http:// member needs --ledger-id, to pin the ledger copied"};
    }
    // The ledger up to the latest checkpoint, re-validated as a replica
    // would; Raft brings the rest once the leader adds this node.
    std::filesystem::create_directories(dir);
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    ledger::SystemClock clock;
    std::uint64_t size = 0;
    auto copied = [&]() -> Status {
        const auto lock = ledger::DirectoryLock::acquire(dir);
        if (!lock) {
            return std::unexpected(lock.error());
        }
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        if (!fs) {
            return std::unexpected(fs.error());
        }
        auto copy = node::create_replica(client, *fs, clock, shared_provider(), expected);
        if (!copy) {
            return std::unexpected(copy.error());
        }
        auto report = node::sync_replica(client, *copy, dir);
        if (!report) {
            return std::unexpected(report.error());
        }
        size = copy->size();
        return node::init_cluster(dir, self, secret);
    }();
    if (!copied) {
        std::filesystem::remove_all(dir);
        unwrap(copied, "copying the cluster's ledger from " + url);
    }
    if (args.json()) {
        print_json(
            {{"id", self.id}, {"raft", self.raft_endpoint}, {"api", self.api_url}, {"size", size}});
        return exit_ok;
    }
    std::println("copied the cluster's ledger ({} entries) to {}", size, dir.string());
    std::println("Run it with: cexchain serve --cluster --ledger {} ...", dir.string());
    std::println("then add it: cexchain cluster add --server {} --id {} --raft {} --api {}", url,
                 self.id, self.raft_endpoint, self.api_url);
    return exit_ok;
}

int cmd_cluster_add(const Args& args) {
    const node::Client client = cluster_client(args);
    const int id = parse_id(args);
    const std::string raft = raft_address(args).first;
    const std::string api = api_url(args);
    call(client, "POST", "/v1/cluster/members", {{"id", id}, {"raft", raft}, {"api", api}});
    if (args.json()) {
        print_json({{"added", id}});
    } else {
        std::println("member {} is being added; it catches up from the leader", id);
    }
    return exit_ok;
}

int cmd_cluster_remove(const Args& args) {
    const node::Client client = cluster_client(args);
    const int id = parse_id(args);
    call(client, "POST", "/v1/cluster/members/remove", {{"id", id}});
    if (args.json()) {
        print_json({{"removed", id}});
    } else {
        std::println("member {} is being removed", id);
    }
    return exit_ok;
}

int cmd_cluster_step_down(const Args& args) {
    const node::Client client = cluster_client(args);
    call(client, "POST", "/v1/cluster/step-down");
    if (args.json()) {
        print_json({{"stepped_down", true}});
    } else {
        std::println("the leader is handing leadership to another member");
    }
    return exit_ok;
}

int cmd_cluster_status(const Args& args) {
    const node::Client client = cluster_client(args);
    const Json status = call(client, "GET", "/v1/cluster");
    if (args.json()) {
        print_json(status);
        return exit_ok;
    }
    std::println("member {} of {}; term {}; committed {}, applied {}", status.value("id", 0),
                 status["members"].size(), status.value("term", 0),
                 status.value("committed", std::uint64_t{0}),
                 status.value("applied", std::uint64_t{0}));
    for (const Json& m : status["members"]) {
        std::println("  {:>4}  {:<24} {:<36} {}", m.value("id", 0), m.value("raft", ""),
                     m.value("api", ""), m.value("leader", false) ? "leader" : "");
    }
    if (status["leader"].is_null()) {
        std::println("no leader yet");
    }
    return exit_ok;
}

} // namespace cexchain::cli
