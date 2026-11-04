// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/keys.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/core/protocol/witness.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/record_log.hpp>
#include <cexchain/ledger/storage.hpp>

/// A single-organization ledger: registers signed statements, keeps the log
/// and its Merkle tree, and issues checkpoints and receipts.
///
/// Files in the ledger's file system:
///   statements[.synced]   the log: one encoded log entry per record
///   checkpoints[.synced]  every signed checkpoint, in order
///
/// Opening a ledger replays and re-validates the whole log, then checks the
/// result against the latest signed checkpoint, so a log that was rolled back
/// or altered on disk is refused.
///
/// Threads: any number may call the const methods at once, alongside one
/// thread that calls the rest (submitting, checkpointing, refreshing, ...).
/// Readers never wait for the disk and only ever see durable entries: a
/// statement counts once it is synced. `state()` is the exception: it hands
/// out the state itself, for code that is single-threaded or is the writer;
/// concurrent readers use `read_state` and `statement_index`.
namespace cexchain::ledger {

struct Registration {
    protocol::Id statement_id;
    std::uint64_t index = 0;
    protocol::Timestamp registered_at = 0;
    /// False if the statement was already registered; submission is
    /// idempotent, so clients may safely retry.
    bool newly_registered = false;
};

/// A witness cosignature held by the ledger, with the witness's key.
struct StoredCosignature {
    Bytes encoded;
    protocol::SignedCheckpoint cosignature;
    crypto::PublicKey witness;
};

/// A time-stamp authority's RFC 3161 token held by the ledger (v0.11), with
/// the checkpoint it stamps.
struct StoredTimestamp {
    Bytes token;
    protocol::SignedCheckpoint checkpoint;
};

/// How to open a ledger.
struct OpenOptions {
    /// Start from the newest snapshot of the state that checks against the
    /// log (see `Ledger::write_snapshot`), replaying only what follows it;
    /// otherwise, or without one that checks, replay the whole log.
    bool use_snapshot = true;
};

/// A snapshot of the state kept beside the log: a local cache, never sent
/// anywhere (not part of the protocol).
struct SnapshotInfo {
    /// The log size it holds the state at; its last entry is a state
    /// commitment.
    std::uint64_t size = 0;
    /// When it was written (the ledger's clock), and its file's size.
    protocol::Timestamp written_at = 0;
    std::uint64_t bytes = 0;

    friend bool operator==(const SnapshotInfo&, const SnapshotInfo&) = default;
};

/// What a refresh picked up.
struct RefreshReport {
    std::uint64_t entries = 0;
    std::uint64_t checkpoints = 0;
    std::uint64_t cosignatures = 0;
    std::uint64_t timestamps = 0;
};

/// The log keys an operator holds. Across a rotation an operator holds the
/// old key and the new one, and the ledger signs with whichever is in effect
/// for what it signs (spec v0.4).
using LogKeys = std::span<const crypto::Signer* const>;

struct AuditReport {
    std::uint64_t entries = 0;
    std::uint64_t checkpoints = 0;
    std::uint64_t cosignatures = 0;
    std::uint64_t timestamps = 0;
    std::uint64_t actors = 0;
    std::uint64_t delegations = 0;
    std::uint64_t records = 0;
    /// Entries registered after the latest checkpoint.
    std::uint64_t unchecked_entries = 0;
};

class Ledger {
public:
    /// Creates a new ledger whose first entry is `genesis`, a statement
    /// signed by the organization root key. Fails if the file system already
    /// holds a ledger.
    [[nodiscard]] static Result<Ledger> create(FileSystem& fs, Clock& clock,
                                               const crypto::Provider& provider, ByteView genesis);

    /// Opens an existing ledger, replaying and re-validating its log, or
    /// only what follows its newest snapshot (OpenOptions).
    [[nodiscard]] static Result<Ledger> open(FileSystem& fs, Clock& clock,
                                             const crypto::Provider& provider);
    [[nodiscard]] static Result<Ledger> open(FileSystem& fs, Clock& clock,
                                             const crypto::Provider& provider,
                                             const OpenOptions& options);

    /// Writes a snapshot of the state, for later opens to start from: the
    /// state, written whole, the log's leaf hashes, and their roots, in the
    /// older of two files (`snapshot-a`, `snapshot-b`), so the newer one
    /// stays whole while it is written. Only right after a checkpoint whose
    /// state commitment ends the log, so that the state is the committed one.
    /// For the ledger's writer, under its lock. A snapshot is a cache: one
    /// that fails its checks is ignored, and the log is replayed instead.
    [[nodiscard]] Status write_snapshot();
    /// The newest snapshot on disk that checks, and the one this ledger
    /// opened from, if any.
    [[nodiscard]] std::optional<SnapshotInfo> snapshot() const;
    [[nodiscard]] std::optional<SnapshotInfo> opened_from_snapshot() const;
    /// Empties both snapshot files: later opens replay the whole log.
    [[nodiscard]] Status remove_snapshots();
    /// The integrity check an open from a snapshot skipped: replays the log
    /// afresh, from files opened in `fs` to read only, up to the snapshot's
    /// size, and requires the same state and root. Nothing to do for a
    /// ledger opened without one. Takes as long as an open without it, with
    /// a second state in memory; safe beside the writer. Once `stop` turns
    /// true it gives up (Errc::unavailable).
    [[nodiscard]] Status verify_snapshot(FileSystem& fs,
                                         const std::atomic<bool>* stop = nullptr) const;
    /// After each checkpoint, a snapshot is written once the log has grown
    /// this many entries since the last (0: never).
    void set_snapshot_interval(std::uint64_t entries) noexcept;
    static constexpr std::uint64_t default_snapshot_interval = 100'000;

    /// Creates a copy of another ledger (a replica, or a restore from a
    /// backup) from its first log entry, kept exactly as the original logged
    /// it. Later entries come through `append_entries`.
    [[nodiscard]] static Result<Ledger> create_replica(FileSystem& fs, Clock& clock,
                                                       const crypto::Provider& provider,
                                                       ByteView genesis_entry);

    Ledger(Ledger&&) noexcept;
    Ledger& operator=(Ledger&&) noexcept;
    ~Ledger();

    [[nodiscard]] const protocol::LedgerState& state() const noexcept;
    [[nodiscard]] const protocol::Id& id() const noexcept;
    [[nodiscard]] crypto::HashAlg hash() const noexcept;
    [[nodiscard]] const crypto::Provider& provider() const noexcept;
    [[nodiscard]] std::uint64_t size() const noexcept;
    /// False once a write failed after memory moved ahead of the files, or
    /// the files were found not to validate: the ledger must be reopened.
    [[nodiscard]] bool usable() const noexcept;

    /// Contract calls run ahead of their validation, in parallel,
    /// and how many of those runs validation took: the rest ran again,
    /// their input having changed (an earlier statement of the batch moved
    /// what they read).
    struct RunsAhead {
        std::uint64_t made = 0;
        std::uint64_t taken = 0;
    };
    [[nodiscard]] RunsAhead runs_ahead() const noexcept;

    /// The log index of a durable statement.
    [[nodiscard]] std::optional<std::uint64_t> statement_index(const protocol::Id& id) const;
    /// Calls `read` with the state, safe alongside the writer.
    void read_state(const std::function<void(const protocol::LedgerState&)>& read) const;

    /// Validates and registers a signed statement.
    [[nodiscard]] Result<Registration> submit(ByteView signed_statement);

    /// Registers many signed statements with one sync (group commit):
    /// signatures are checked on all cores, then each statement is validated
    /// in order against the state the ones before it left. One result per
    /// statement, in order; refused ones do not stop the rest. If writing
    /// fails, every newly registered one fails and the ledger must be
    /// reopened.
    /// With `at`, the batch is registered at max(`at`, the last registration
    /// time) instead of the clock's time: a cluster's nodes apply one batch
    /// at the time its leader chose, so they all keep the same entries.
    ///
    /// `offers` (one slot per statement, or empty) are runs of the calls the
    /// caller made ahead, say dry runs on the state it read: validation
    /// takes one only if its input is the one built in turn (see
    /// protocol::Validation::offer). The ledger runs the other calls ahead
    /// itself, in parallel.
    using Offers = std::vector<std::optional<protocol::ContractRun>>;
    [[nodiscard]] std::vector<Result<Registration>>
    submit_batch(std::span<const ByteView> signed_statements,
                 std::optional<protocol::Timestamp> at = std::nullopt, Offers offers = {});

    /// What became of a pipelined batch, once its entries are durable (or
    /// writing them failed). Called on the ledger's commit thread, in the
    /// order the batches were submitted; it must not call the ledger's
    /// writing methods, and should be quick (the next sync waits for it).
    using Durable = std::function<void(std::vector<Result<Registration>>)>;

    /// submit_batch, pipelined: returns once the batch is
    /// validated and applied in memory; its entries are written and synced
    /// on the ledger's commit thread, together with any batches submitted
    /// meanwhile (one sync for all), and then `durable` gets the results.
    /// The next batch is validated while this one syncs. As with
    /// submit_batch, readers see the entries (and statement_index finds
    /// them) only once they are durable. Every other method that writes
    /// waits for the batches in flight first.
    void submit_batch_pipelined(std::span<const ByteView> signed_statements, Durable durable,
                                std::optional<protocol::Timestamp> at = std::nullopt,
                                Offers offers = {});

    /// Waits until every pipelined batch is durable or has failed, and its
    /// `durable` has returned.
    void wait_durable();

    /// Holds pipelined batches back from the commit thread (a write already
    /// under way finishes), so that several batches submitted in a row are
    /// written with one sync: until release_commits, or until anything
    /// waits for the batches in flight (wait_durable, submit_batch, every
    /// other writing method), which releases them first.
    void hold_commits();
    void release_commits();

    /// Appends log entries copied from the original ledger, in order from
    /// index `size()`. Each must pass the checks a replay applies: time
    /// order, statements valid under the ledger's rules when they were
    /// registered, state commitments signed by the log key and true. Fails
    /// with Errc::verification_failed on the first entry that does not; the
    /// ones before it are kept. If writing fails, the ledger must be
    /// reopened.
    [[nodiscard]] Status append_entries(std::span<const Bytes> entries);

    /// Stores a checkpoint copied from the original ledger, after checking
    /// that the log key signed it and that it agrees with this log. Storing
    /// the latest checkpoint again changes nothing.
    [[nodiscard]] Status store_checkpoint(ByteView signed_checkpoint);

    /// Checks a checkpoint before the entries it covers are here: signed by
    /// the log key, for this ledger, and not before the latest stored (in
    /// size or time). With `compact_range`, a replica checks that entries
    /// lead to its root before taking any of them. The key is the one in
    /// effect at the checkpoint's size as far as this log knows, or
    /// `log_key`: what a replica that followed key rotations among entries it
    /// has not taken yet learned (see protocol::follow_key_rotation).
    [[nodiscard]] Result<protocol::SignedCheckpoint>
    verify_checkpoint(ByteView signed_checkpoint, const crypto::PublicKey* log_key = nullptr) const;

    /// The organization's keys as of the log's end, for following rotations
    /// in entries beyond it.
    [[nodiscard]] protocol::LedgerKeys keys() const;

    /// The right edge of the log's Merkle tree, to grow a copy of.
    [[nodiscard]] merkle::CompactRange compact_range() const;

    /// Picks up entries, checkpoints, and cosignatures that another process
    /// appended to `fs` (the file system this ledger was opened from), up to
    /// what that process made durable, re-validating every new entry. Call it
    /// with `recover` only while holding the ledger's lock, before writing:
    /// it then also cuts off what a crashed writer left half-written.
    [[nodiscard]] Result<RefreshReport> refresh(FileSystem& fs, bool recover);

    /// Whether another process has made entries, checkpoints, or
    /// cosignatures durable since this ledger last wrote or refreshed, so
    /// that `refresh` would pick something up. Costs three fstat calls.
    [[nodiscard]] bool outdated() const;

    /// The encoded log entry at `index` (the bytes the tree commits to).
    [[nodiscard]] Result<Bytes> entry(std::uint64_t index) const;
    /// The same without copying it: `visit` sees the bytes in place, under
    /// the readers' lock, and must not keep the view or call back into the
    /// ledger at all (the lock is not reentrant).
    [[nodiscard]] Status visit_entry(std::uint64_t index,
                                     const std::function<void(ByteView)>& visit) const;

    [[nodiscard]] Result<crypto::Digest> root(std::uint64_t tree_size) const;
    [[nodiscard]] Result<std::vector<crypto::Digest>>
    inclusion_proof(std::uint64_t index, std::uint64_t tree_size) const;
    [[nodiscard]] Result<std::vector<crypto::Digest>>
    consistency_proof(std::uint64_t old_size, std::uint64_t new_size) const;

    /// Appends a state commitment to the log (unless the last entry is one),
    /// then signs and stores a checkpoint of the tree, with the newest log
    /// key: `log_key` must be it, or `log_keys` must hold it.
    [[nodiscard]] Result<protocol::SignedCheckpoint> checkpoint(const crypto::Signer& log_key);
    [[nodiscard]] Result<protocol::SignedCheckpoint> checkpoint(LogKeys log_keys);

    /// What `checkpoint` appends and stores, signed but not written: for a
    /// cluster's leader, which replicates it before any node applies it.
    struct PreparedCheckpoint {
        /// The state commitment log entry to append first, unless the log
        /// already ends with one.
        std::optional<Bytes> commitment;
        protocol::SignedCheckpoint checkpoint;
    };
    [[nodiscard]] Result<PreparedCheckpoint> prepare_checkpoint(LogKeys log_keys);
    /// Applies a prepared checkpoint: appends the commitment (re-validated)
    /// unless the log holds it at its index already, then stores the
    /// checkpoint unless it is stored. Applying it again changes nothing.
    [[nodiscard]] Status apply_checkpoint(const std::optional<Bytes>& commitment,
                                          ByteView checkpoint);

    /// A cosign request for the latest checkpoint, with a consistency proof
    /// from `old_size` and every key rotation below its size.
    [[nodiscard]] Result<protocol::CosignRequest> cosign_request(std::uint64_t old_size) const;

    /// Every stored checkpoint, oldest first (for backups and audits; the
    /// API pages through them).
    [[nodiscard]] Result<std::vector<protocol::SignedCheckpoint>> checkpoints() const;
    [[nodiscard]] std::uint64_t checkpoint_count() const;
    /// Checkpoints [start, start + count), at most 1000, read from disk.
    [[nodiscard]] Result<std::vector<protocol::SignedCheckpoint>>
    checkpoints(std::uint64_t start, std::uint64_t count) const;
    /// The checkpoints of tree size `size`, oldest first (a binary search:
    /// they are stored in order of size).
    [[nodiscard]] Result<std::vector<protocol::SignedCheckpoint>>
    checkpoints_of_size(std::uint64_t size) const;

    /// Stores a witness's cosignature of one of the ledger's checkpoints,
    /// after verifying it with the witness's key. Storing the same
    /// cosignature again changes nothing.
    [[nodiscard]] Status add_cosignature(ByteView cosignature, const crypto::PublicKey& witness);

    /// Every stored cosignature, oldest first.
    [[nodiscard]] Result<std::vector<StoredCosignature>> cosignatures() const;
    [[nodiscard]] std::uint64_t cosignature_count() const;
    /// Cosignatures [start, start + count), at most 1000.
    [[nodiscard]] Result<std::vector<StoredCosignature>> cosignatures(std::uint64_t start,
                                                                      std::uint64_t count) const;

    /// Stores a time-stamp authority's token (RFC 3161, DER) over the payload
    /// of a stored checkpoint of tree size `size`, once it verifies with its
    /// signing certificate and the ledger's clock agrees with it: neither
    /// the checkpoint nor the last entry it covers is dated more than the
    /// slack after the authority's time (spec v0.11). Which authorities to
    /// trust is each verifier's choice; the ledger keeps any token that
    /// verifies. Storing the same token again changes nothing.
    [[nodiscard]] Status add_timestamp(ByteView token, std::uint64_t size);

    /// Every stored time-stamp token, oldest first.
    [[nodiscard]] Result<std::vector<StoredTimestamp>> timestamps() const;
    [[nodiscard]] std::uint64_t timestamp_count() const;
    /// Tokens [start, start + count), at most 1000.
    [[nodiscard]] Result<std::vector<StoredTimestamp>> timestamps(std::uint64_t start,
                                                                  std::uint64_t count) const;

    /// The newest checkpoint `witness` has cosigned, if any.
    [[nodiscard]] Result<std::optional<protocol::Checkpoint>>
    last_cosigned(const crypto::PublicKey& witness) const;

    /// Re-checks every stored checkpoint against the log: signed by the log
    /// key, for this ledger, sizes never decreasing, and each root equal to
    /// the tree's root at that size; every stored cosignature against its
    /// witness's key and a stored checkpoint; and every stored time-stamp
    /// token against its signing certificate and the checkpoint it stamps.
    /// (Opening the ledger has already replayed and re-validated every
    /// statement.)
    [[nodiscard]] Result<AuditReport> audit() const;

    /// The latest stored checkpoint, if any.
    [[nodiscard]] std::optional<protocol::SignedCheckpoint> latest_checkpoint() const;

    /// Builds an evidence bundle for `record`, a record or a contract
    /// instance: genesis, its statements, and every statement they depend on
    /// (signers' registrations and key rotations, delegation chains,
    /// referenced actors, a contract's deploy), each with a receipt anchored
    /// to the latest checkpoint, which
    /// must cover them all, plus the stored witness cosignatures of that
    /// checkpoint, and anchors (v0.11): the earliest time-stamped checkpoint
    /// covering the record's first event, and the latest at or before the
    /// bundle's. The caller adds field disclosures and attachment openings,
    /// since only it holds the record's private data.
    /// The receipts are signed with the log key in effect for the latest
    /// checkpoint, which `log_key` must be, or `log_keys` must hold. Every
    /// rotation of the organization's keys below its size is included.
    [[nodiscard]] Result<protocol::EvidenceBundle>
    export_evidence(const crypto::Signer& log_key, const protocol::Id& record) const;
    [[nodiscard]] Result<protocol::EvidenceBundle>
    export_evidence(LogKeys log_keys, const protocol::Id& record) const;

    /// The state commitment the latest checkpoint ends with, if it has one.
    [[nodiscard]] std::optional<protocol::StateCommitment> state_commitment() const;

    /// A proof of the complete history of an actor, delegation, or record, as
    /// of the latest checkpoint, against its state commitment.
    [[nodiscard]] Result<protocol::StateProof> state_proof(const protocol::Id& id) const;

    /// A state proof together with the commitment it is against, read at
    /// once: with a writer running, a checkpoint may come between two calls.
    struct CommittedProof {
        protocol::StateProof proof;
        protocol::StateCommitment commitment;
    };
    [[nodiscard]] Result<CommittedProof> committed_state_proof(const protocol::Id& id) const;

    /// An RFC 9942 receipt for the entry at `index`, anchored to the latest
    /// checkpoint, signed with the log key in effect for it. Fails if no
    /// checkpoint covers the entry yet.
    [[nodiscard]] Result<Bytes> receipt(const crypto::Signer& log_key, std::uint64_t index) const;
    [[nodiscard]] Result<Bytes> receipt(LogKeys log_keys, std::uint64_t index) const;

    struct Impl; // opaque

private:
    explicit Ledger(std::unique_ptr<Impl> impl) noexcept;
    /// What checkpoint() and store_checkpoint() do before a snapshot.
    [[nodiscard]] Result<protocol::SignedCheckpoint> checkpoint_now(LogKeys log_keys);
    [[nodiscard]] Status store_checkpoint_now(ByteView encoded);
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::ledger
