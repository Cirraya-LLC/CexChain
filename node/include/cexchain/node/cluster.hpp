// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/node/contracts.hpp>

/// Clusters: a ledger kept by several nodes, with automatic failover (D-051).
///
/// The nodes run Raft (NuRaft). The leader takes the writes: a group of
/// statements becomes one Raft entry, {time, statements, sealed vault files},
/// and once a majority holds it durably, every node applies it to its own
/// ledger at that time. Validation is deterministic, so every node keeps the
/// same entries and the leader answers with its own outcome; no node writes
/// anything uncommitted. Checkpoints are signed by the leader and replicated
/// as bytes; cosignatures are replicated too. If the leader fails, the others
/// elect a new one within seconds, and no acknowledged write is lost.
///
/// Files under <ledger>/cluster: node.json (this node), secret (the
/// cluster's shared secret, which authenticates every Raft message), state
/// and config (Raft's), raft-log, applied, snapshot. A batch entry carries
/// the files kept with its statements: [i, bytes] for a vault file,
/// [i, bytes, 3] for a contract call's consents (kind 2, the consents of
/// D-052's actions, is reserved: spec v0.9 removed them, and a node ignores
/// it as any unknown kind). The calls a registrar holds until their consents
/// are in (D-053) are replicated too, so a new leader carries on with them.
namespace cexchain::node {

inline constexpr std::string_view cluster_directory = "cluster";

/// This node's place in its cluster.
struct ClusterNode {
    /// 1 to 1000, unique in the cluster.
    int id = 0;
    /// host:port the other members reach this node's Raft port at.
    std::string raft_endpoint;
    /// The port this node's Raft listens on.
    std::uint16_t raft_port = 0;
    /// This node's HTTP API, where the other members send writers.
    std::string api_url;
    /// The node that started the cluster. The others wait to be added, and
    /// never lead before.
    bool founder = false;
};

/// The shared secret's size.
inline constexpr std::size_t cluster_secret_size = 32;

/// Makes `ledger_directory` a cluster member: writes node.json and the
/// shared secret (the founder generates it; the others get a copy).
[[nodiscard]] Status init_cluster(const std::filesystem::path& ledger_directory,
                                  const ClusterNode& node, ByteView secret);
[[nodiscard]] Result<ClusterNode> read_cluster_node(const std::filesystem::path& ledger_directory);
[[nodiscard]] bool is_cluster_member(const std::filesystem::path& ledger_directory);

struct ClusterMember {
    int id = 0;
    std::string raft_endpoint;
    std::string api_url;
};

struct ClusterStatus {
    int id = 0;
    std::optional<int> leader;
    bool leads = false;
    std::uint64_t term = 0;
    /// Raft log indices.
    std::uint64_t committed = 0;
    std::uint64_t applied = 0;
    std::uint64_t ledger_size = 0;
    std::vector<ClusterMember> members;
};

/// Raft's timing and log compaction; the defaults suit nodes on one network.
struct ClusterTuning {
    int heartbeat_ms = 250;
    /// A follower that hears nothing from the leader for a random time in
    /// this range starts an election.
    int election_min_ms = 1000;
    int election_max_ms = 2000;
    /// After this many entries, a snapshot (the ledger's size at that
    /// point) lets the Raft log be compacted; a node further behind gets
    /// the ledger itself.
    int snapshot_distance = 10000;
    /// Entries kept in the Raft log after compacting.
    int reserved_log_items = 20000;
};

/// Each statement's outcome in a replicated batch, in order.
using BatchResult = std::vector<Result<ledger::Registration>>;

/// A file kept with a replicated statement: a record's sealed private data
/// (stored once it is registered), or the consent bundles a contract call
/// cites (stored before, so a registered call always has them).
struct Sidecar {
    /// 2 is reserved (D-052's consents, removed in spec v0.9).
    enum class Kind : std::uint8_t { vault = 1, contract_consents = 3 };
    Kind kind = Kind::vault;
    Bytes bytes;
};

class Cluster {
public:
    /// Starts this node's Raft server over `ledger`, opened from
    /// `ledger_directory`, which it then applies committed entries to. Nothing
    /// else may write to the ledger. `on_event` gets notable events (leader
    /// changes, apply failures).
    [[nodiscard]] static Result<std::unique_ptr<Cluster>>
    start(const std::filesystem::path& ledger_directory, ledger::Ledger& ledger,
          std::function<void(std::string_view event, std::string_view detail)> on_event = {},
          const ClusterTuning& tuning = {});

    ~Cluster();
    Cluster(const Cluster&) = delete;
    Cluster& operator=(const Cluster&) = delete;

    /// True if this node leads and may take writes.
    [[nodiscard]] bool leads() const;
    /// The leader's API URL, if a leader is known.
    [[nodiscard]] std::optional<std::string> leader_api_url() const;
    [[nodiscard]] ClusterStatus status() const;

    // On the leader. Each blocks until its entry is committed and applied
    // here. Errc::unavailable means the outcome is unknown (leadership was
    // lost on the way): a client may retry, since every write is idempotent.

    [[nodiscard]] Result<BatchResult> submit(std::span<const ByteView> statements,
                                             std::span<const std::optional<Sidecar>> sidecars,
                                             protocol::Timestamp at);
    /// Signs a checkpoint (and the state commitment before it) and
    /// replicates it; refused while an entry is still on its way.
    [[nodiscard]] Result<protocol::SignedCheckpoint> checkpoint(ledger::LogKeys log_keys);
    [[nodiscard]] Status add_cosignature(ByteView cosignature, const crypto::PublicKey& witness);
    /// Writes or removes the registrar's pending calls on every node.
    [[nodiscard]] Status change_pending(std::span<const PendingChange> changes);
    [[nodiscard]] Status add_member(const ClusterMember& member);
    [[nodiscard]] Status remove_member(int id);
    /// Hands leadership to another member.
    [[nodiscard]] Status step_down();

    struct Impl;

private:
    explicit Cluster(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::node
