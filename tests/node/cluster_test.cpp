// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Clusters (D-051), in one process: three nodes on loopback, each with its
// own ledger directory and Raft port.

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/node/assets.hpp>
#include <cexchain/node/cluster.hpp>

#include "cluster_parts.hpp"
#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using namespace std::chrono_literals;
namespace node = cexchain::node;

std::uint16_t free_port() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof address;
    REQUIRE(::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0);
    REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    ::close(fd);
    return ntohs(address.sin_port);
}

bool eventually(const std::function<bool()>& condition, std::chrono::milliseconds limit = 60s) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline) {
        if (condition()) {
            return true;
        }
        std::this_thread::sleep_for(50ms);
    }
    return condition();
}

/// One node: a ledger directory and, while it runs, its Raft server.
struct Node {
    std::filesystem::path dir;
    node::ClusterNode config;
    std::optional<ledger::PosixFileSystem> fs;
    ledger::ManualClock clock{t0};
    std::optional<ledger::Ledger> ledger;
    std::unique_ptr<node::Cluster> cluster;
    node::ClusterTuning tuning;

    void start() {
        fs.emplace(*ledger::PosixFileSystem::open_directory(dir));
        auto opened = ledger::Ledger::open(*fs, clock, provider());
        REQUIRE(opened);
        ledger.emplace(std::move(*opened));
        auto started = node::Cluster::start(
            dir, *ledger,
            [id = config.id](std::string_view what, std::string_view detail) {
                if (std::getenv("CEXCHAIN_CLUSTER_DEBUG") != nullptr) {
                    std::fprintf(stderr, "node %d: %.*s %.*s\n", id, static_cast<int>(what.size()),
                                 what.data(), static_cast<int>(detail.size()), detail.data());
                }
            },
            tuning);
        INFO((started ? std::string() : std::string(started.error().detail)));
        REQUIRE(started);
        cluster = std::move(*started);
    }

    void stop() {
        cluster.reset();
        ledger.reset();
        fs.reset();
    }
};

/// Three nodes of one ledger; node 1 founded the cluster.
struct Trio {
    World w;
    std::vector<std::unique_ptr<Node>> nodes;
    Bytes secret = Bytes(node::cluster_secret_size, 0x5c);

    /// Starts and adds the first `members` nodes; the others are prepared
    /// (with `secrets[i]`, if given) but not started.
    explicit Trio(int members = 3, node::ClusterTuning tuning = {},
                  std::vector<Bytes> secrets = {}) {
        static int counter = 0;
        const auto base = std::filesystem::temp_directory_path() /
                          ("cexchain-cluster-test-" + std::to_string(::getpid()) + "-" +
                           std::to_string(counter++));
        std::filesystem::remove_all(base);
        const Bytes genesis = *w.ledger().entry(0);
        for (int id = 1; id <= 3; ++id) {
            auto n = std::make_unique<Node>();
            n->dir = base / std::to_string(id);
            std::filesystem::create_directories(n->dir);
            auto fs = ledger::PosixFileSystem::open_directory(n->dir);
            REQUIRE(fs);
            REQUIRE(ledger::Ledger::create_replica(*fs, n->clock, provider(), genesis));
            const std::uint16_t port = free_port();
            n->config = {id, "127.0.0.1:" + std::to_string(port), port,
                         "http://127.0.0.1:" + std::to_string(9000 + id), id == 1};
            const auto i = static_cast<std::size_t>(id - 1);
            REQUIRE(
                node::init_cluster(n->dir, n->config, i < secrets.size() ? secrets[i] : secret));
            // A vault, so records may carry private data.
            std::filesystem::create_directories(n->dir / "vault" / "records");
            REQUIRE(
                node::detail::write_file(n->dir / "vault" / "vault.pub", Bytes{1, 2, 3}, false));
            n->tuning = tuning;
            if (id <= members) {
                n->start();
            }
            nodes.push_back(std::move(n));
        }
        REQUIRE(eventually([&] { return nodes[0]->cluster->leads(); }));
        for (int id = 2; id <= members; ++id) {
            add(id);
        }
    }

    /// The leader adds node `id`, which then catches up.
    void add(int id) {
        const auto& c = nodes[static_cast<std::size_t>(id - 1)]->config;
        REQUIRE(eventually([&] {
            return leader() != nullptr &&
                   leader()->cluster->add_member({id, c.raft_endpoint, c.api_url}).has_value();
        }));
        REQUIRE(eventually([&] {
            return leader()->cluster->status().members.size() >= static_cast<std::size_t>(id);
        }));
    }

    /// The leader commits `count` records in one batch, the first with
    /// private data.
    void write(int count, protocol::Timestamp at) {
        std::vector<Bytes> statements;
        for (int i = 0; i < count; ++i) {
            statements.push_back(record(at + static_cast<protocol::Timestamp>(i)));
        }
        const std::vector<ByteView> views(statements.begin(), statements.end());
        std::vector<std::optional<node::Sidecar>> vaults(statements.size());
        vaults[0] = node::Sidecar{node::Sidecar::Kind::vault,
                                  Bytes{0xa0, static_cast<std::uint8_t>(at & 0xffU)}};
        cexchain::Result<node::BatchResult> results = std::unexpected(cexchain::Error{});
        REQUIRE(eventually([&] {
            Node* now = leader();
            results = now != nullptr ? now->cluster->submit(views, vaults, at)
                                     : cexchain::Result<node::BatchResult>(std::unexpected(
                                           cexchain::Error{Errc::unavailable, "no leader"}));
            return results.has_value();
        }));
        for (const auto& r : *results) {
            REQUIRE(r);
        }
    }

    ~Trio() {
        for (auto& n : nodes) {
            n->stop();
        }
        std::filesystem::remove_all(nodes.front()->dir.parent_path());
    }

    Node* leader() {
        for (auto& n : nodes) {
            if (n->cluster && n->cluster->leads()) {
                return n.get();
            }
        }
        return nullptr;
    }

    /// Registers a receivable held by `party`, which consents to cancel it;
    /// the cancellation goes in with the consent. Returns its id.
    protocol::Id cancel_asset(World& party, protocol::Timestamp at) {
        auto commit = [&](std::string type, cbor::Value metadata) {
            return protocol::RecordRegisterBody{
                std::move(type), Bytes(32, 0x42), 1, {}, std::move(metadata)};
        };
        auto submit = [&](const Bytes& statement, std::optional<node::Sidecar> sidecar) {
            const ByteView view = statement;
            cexchain::Result<node::BatchResult> results = std::unexpected(cexchain::Error{});
            REQUIRE(eventually([&] {
                Node* now = leader();
                results =
                    now != nullptr
                        ? now->cluster->submit(std::span(&view, 1), std::span(&sidecar, 1), at)
                        : cexchain::Result<node::BatchResult>(
                              std::unexpected(cexchain::Error{Errc::unavailable, "no leader"}));
                return results.has_value();
            }));
            REQUIRE(results->front());
            return results->front()->index;
        };
        auto metadata = protocol::encode_asset_metadata(
            protocol::AssetKind::receivable, {party.ledger().id(), 100, "CNY", t0 + day});
        REQUIRE(metadata);
        auto s = w.statement(w.org_id(), std::nullopt,
                             commit(std::string(protocol::receivable_type), std::move(*metadata)));
        s.issued_at = at;
        const Bytes registration = w.sign(w.org(), s);
        const std::uint64_t head = submit(registration, std::nullopt);
        const protocol::Id asset =
            protocol::parse_statement(provider(), registration, w.hash())->id;

        protocol::AssetActionBody cancel;
        cancel.asset = asset;
        cancel.action = protocol::AssetAction::cancel;
        cancel.head = head;
        auto consent_metadata = protocol::encode_asset_consent(
            {protocol::terms_of(cancel, w.org_id()), t0 + 30 * day, std::nullopt});
        REQUIRE(consent_metadata);
        const protocol::Id consent =
            party.ok(party.org(), party.statement(party.org_id(), std::nullopt,
                                                  commit(std::string(protocol::asset_consent_type),
                                                         std::move(*consent_metadata))));
        REQUIRE(party.ledger().checkpoint(party.log_key()));
        const Bytes bundle =
            *protocol::encode_bundle(*party.ledger().export_evidence(party.log_key(), consent));
        cancel.consents.push_back(
            {party.ledger().id(), consent, *provider().digest(w.hash(), bundle)});
        auto a = w.statement(w.org_id(), std::nullopt, cancel);
        a.issued_at = at + 1;
        const Bytes signed_action = w.sign(w.org(), a);
        const Bytes bundles = *node::encode_consent_bundles(std::vector<Bytes>{bundle});
        submit(signed_action, node::Sidecar{node::Sidecar::Kind::consents, bundles});
        REQUIRE(eventually([&] { return agree(); }));
        return protocol::parse_statement(provider(), signed_action, w.hash())->id;
    }

    Bytes record(protocol::Timestamp at) {
        auto s = w.statement(w.org_id(), std::nullopt, w.record_body("other/1"));
        s.issued_at = at;
        return w.sign(w.org(), s);
    }

    /// Every running node's ledger has the same entries.
    bool agree() {
        std::optional<cexchain::crypto::Digest> root;
        std::uint64_t size = 0;
        for (auto& n : nodes) {
            if (!n->ledger) {
                continue;
            }
            const auto here = n->ledger->root(n->ledger->size());
            if (!root) {
                root = *here;
                size = n->ledger->size();
            } else if (n->ledger->size() != size || *here != *root) {
                return false;
            }
        }
        return true;
    }
};

} // namespace

TEST_CASE("a cluster replicates writes and survives its leader", "[node][cluster]") {
    // Nothing here assumes which member leads: under load (sanitizers,
    // parallel tests) an election may come at any time.
    Trio trio;
    REQUIRE(trio.leader() != nullptr);

    // A batch: two records and a forged copy; the outcome is the leader's,
    // and every node applies the same.
    Bytes forged = trio.record(t0 + 2);
    forged[forged.size() - 2] ^= 1;
    const std::vector<Bytes> batch{trio.record(t0 + 1), trio.record(t0 + 2), forged};
    const std::vector<ByteView> views(batch.begin(), batch.end());
    const std::vector<std::optional<node::Sidecar>> vaults(batch.size());
    cexchain::Result<node::BatchResult> results = std::unexpected(cexchain::Error{});
    REQUIRE(eventually([&] {
        results = trio.leader()->cluster->submit(views, vaults, t0 + 5000);
        return results.has_value();
    }));
    REQUIRE(results->size() == 3);
    CHECK((*results)[0]);
    CHECK((*results)[1]);
    CHECK_FALSE((*results)[2]);
    CHECK((*results)[0]->registered_at == t0 + 5000);
    CHECK(eventually([&] { return trio.agree() && trio.nodes[2]->ledger->size() == 3; }));

    // A checkpoint, signed by the leader, the same everywhere.
    const crypto::Signer* keys[] = {&trio.w.log_key()};
    cexchain::Result<protocol::SignedCheckpoint> checkpoint = std::unexpected(cexchain::Error{});
    REQUIRE(eventually([&] {
        checkpoint = trio.leader()->cluster->checkpoint(ledger::LogKeys(keys));
        return checkpoint.has_value();
    }));
    CHECK(eventually([&] {
        for (auto& n : trio.nodes) {
            const auto latest = n->ledger->latest_checkpoint();
            if (!latest || latest->encoded != checkpoint->encoded) {
                return false;
            }
        }
        return true;
    }));

    // Followers do not take writes, and know where the leader is.
    CHECK(eventually([&] {
        Node* leader = trio.leader();
        for (auto& n : trio.nodes) {
            if (leader != nullptr && n.get() != leader) {
                auto refused = n->cluster->submit(views, vaults, t0 + 6000);
                return !refused && refused.error().code == Errc::unavailable &&
                       n->cluster->leader_api_url() == leader->config.api_url;
            }
        }
        return false;
    }));

    // The leader goes away: the others elect one of them and carry on.
    Node* gone = trio.leader();
    REQUIRE(gone != nullptr);
    gone->stop();
    const std::vector<Bytes> more{trio.record(t0 + 10)};
    const std::vector<ByteView> more_views(more.begin(), more.end());
    const std::vector<std::optional<node::Sidecar>> no_vaults(1);
    REQUIRE(eventually([&] {
        Node* leader = trio.leader();
        return leader != nullptr && leader != gone &&
               leader->cluster->submit(more_views, no_vaults, t0 + 20000).has_value();
    }));
    CHECK(eventually([&] { return trio.agree(); }));

    // The old leader comes back and catches up.
    gone->start();
    CHECK(eventually([&] {
        Node* leader = trio.leader();
        return leader != nullptr && gone->ledger->size() == leader->ledger->size() && trio.agree();
    }));
}

TEST_CASE("a node far behind gets the ledger itself as a snapshot", "[node][cluster]") {
    // Snapshots every few entries, and little kept after: by the time the
    // third node starts, the Raft log no longer reaches back to its start.
    node::ClusterTuning tuning;
    tuning.snapshot_distance = 3;
    tuning.reserved_log_items = 1;
    Trio trio(2, tuning);
    for (int i = 0; i < 8; ++i) {
        trio.write(3, t0 + 1000 * static_cast<protocol::Timestamp>(i + 1));
    }
    const crypto::Signer* keys[] = {&trio.w.log_key()};
    REQUIRE(eventually([&] {
        return trio.leader() != nullptr &&
               trio.leader()->cluster->checkpoint(ledger::LogKeys(keys)).has_value();
    }));
    trio.write(2, t0 + 20000);
    REQUIRE(eventually([&] { return trio.agree(); }));

    // An asset action, with the consent it pins kept on every node (D-052).
    World party{crypto::HashAlg::sha256, "Party"};
    const protocol::Id action = trio.cancel_asset(party, t0 + 25000);
    for (int n = 0; n < 2; ++n) {
        CHECK(std::filesystem::exists(
            node::consents_path(trio.nodes[static_cast<std::size_t>(n)]->dir, action)));
    }

    trio.nodes[2]->start();
    trio.add(3);
    auto& late = *trio.nodes[2];
    REQUIRE(eventually(
        [&] { return late.ledger->size() == trio.leader()->ledger->size() && trio.agree(); }));
    // Checkpoints and private data come along (after the entries).
    CHECK(eventually([&] { return late.ledger->latest_checkpoint().has_value(); }));
    CHECK(eventually([&] {
        std::size_t files = 0;
        for (const auto& f : std::filesystem::directory_iterator(late.dir / "vault" / "records")) {
            files += f.path().extension() == ".cbor" ? 1U : 0U;
        }
        return files == 9;
    }));
    CHECK(
        eventually([&] { return std::filesystem::exists(node::consents_path(late.dir, action)); }));
    // And it takes part from then on.
    trio.write(1, t0 + 30000);
    CHECK(eventually([&] { return trio.agree(); }));
}

TEST_CASE("a node without the cluster's secret gets nothing", "[node][cluster][security]") {
    const Bytes right(node::cluster_secret_size, 0x5c);
    Trio trio(1, {}, {right, right, Bytes(node::cluster_secret_size, 0x77)});
    trio.nodes[2]->start();
    const auto& c = trio.nodes[2]->config;
    static_cast<void>(trio.leader()->cluster->add_member({3, c.raft_endpoint, c.api_url}));
    trio.write(2, t0 + 1000);
    std::this_thread::sleep_for(3s);
    // Every message to or from it fails authentication: it never hears of
    // the leader, and the leader goes on alone.
    CHECK(trio.nodes[2]->ledger->size() == 1);
    CHECK_FALSE(trio.nodes[2]->cluster->leader_api_url());
    CHECK(trio.nodes[0]->ledger->size() == 3);
}

TEST_CASE("the Raft log keeps exactly what was written", "[node][cluster][storage]") {
    namespace cd = node::cluster_detail;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("cexchain-raft-log-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const auto path = dir / "raft-log";
    auto entry = [](nuraft::ulong term, std::uint8_t fill) {
        auto e = nuraft::cs_new<nuraft::log_entry>(term, cd::to_buffer(Bytes(5, fill)));
        return e;
    };
    {
        auto log = cd::RaftLog::open(path);
        REQUIRE(log);
        CHECK((*log)->next_slot() == 1);
        CHECK((*log)->last_entry()->get_term() == 0);
        for (std::uint8_t i = 1; i <= 4; ++i) {
            auto e = entry(i, i);
            CHECK((*log)->append(e) == i);
        }
        // write_at replaces the suffix.
        auto e = entry(9, 9);
        (*log)->write_at(3, e);
        CHECK((*log)->next_slot() == 4);
        CHECK((*log)->term_at(3) == 9);
    }
    {
        auto log = cd::RaftLog::open(path);
        REQUIRE(log);
        CHECK((*log)->next_slot() == 4);
        CHECK((*log)->entry_at(2)->get_term() == 2);
        CHECK(cd::to_bytes((*log)->entry_at(3)->get_buf()) == Bytes(5, 9));
        CHECK((*log)->compact(1));
        CHECK((*log)->start_index() == 2);
        CHECK((*log)->term_at(1) == 0);
        CHECK((*log)->entry_at(2)->get_term() == 2);
        // A pack of entries, applied elsewhere, reads the same.
        auto pack = (*log)->pack(2, 2);
        auto other = cd::RaftLog::open(dir / "copy");
        REQUIRE(other);
        (*other)->apply_pack(2, *pack);
        CHECK((*other)->start_index() == 2);
        CHECK((*other)->term_at(3) == 9);
    }
    // A torn record at the end (a crash mid-append) is dropped; the rest stays.
    {
        FILE* f = std::fopen(path.c_str(), "ab");
        REQUIRE(f != nullptr);
        const std::array<std::uint8_t, 7> torn{0, 0, 0, 40, 1, 2, 3};
        std::fwrite(torn.data(), 1, torn.size(), f);
        std::fclose(f);
        auto log = cd::RaftLog::open(path);
        REQUIRE(log);
        CHECK((*log)->start_index() == 2);
        CHECK((*log)->next_slot() == 4);
        auto e = entry(10, 10);
        CHECK((*log)->append(e) == 4);
    }
    // A damaged last record is dropped too.
    {
        const auto size = std::filesystem::file_size(path);
        FILE* f = std::fopen(path.c_str(), "r+b");
        REQUIRE(f != nullptr);
        std::fseek(f, static_cast<long>(size) - 2, SEEK_SET);
        std::fputc(0xff, f);
        std::fclose(f);
        auto log = cd::RaftLog::open(path);
        REQUIRE(log);
        CHECK((*log)->next_slot() == 4);
    }
    std::filesystem::remove_all(dir);
}
