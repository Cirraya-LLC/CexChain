// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

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

/// What a refresh picked up.
struct RefreshReport {
    std::uint64_t entries = 0;
    std::uint64_t checkpoints = 0;
    std::uint64_t cosignatures = 0;
};

/// The log keys an operator holds. Across a rotation an operator holds the
/// old key and the new one, and the ledger signs with whichever is in effect
/// for what it signs (spec v0.4).
using LogKeys = std::span<const crypto::Signer* const>;

struct AuditReport {
    std::uint64_t entries = 0;
    std::uint64_t checkpoints = 0;
    std::uint64_t cosignatures = 0;
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

    /// Opens an existing ledger, replaying and re-validating its log.
    [[nodiscard]] static Result<Ledger> open(FileSystem& fs, Clock& clock,
                                             const crypto::Provider& provider);

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
    [[nodiscard]] std::vector<Result<Registration>>
    submit_batch(std::span<const ByteView> signed_statements,
                 std::optional<protocol::Timestamp> at = std::nullopt);

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

    /// The newest checkpoint `witness` has cosigned, if any.
    [[nodiscard]] Result<std::optional<protocol::Checkpoint>>
    last_cosigned(const crypto::PublicKey& witness) const;

    /// Re-checks every stored checkpoint against the log: signed by the log
    /// key, for this ledger, sizes never decreasing, and each root equal to
    /// the tree's root at that size; and every stored cosignature against its
    /// witness's key and a stored checkpoint. (Opening the ledger has already
    /// replayed and re-validated every statement.)
    [[nodiscard]] Result<AuditReport> audit() const;

    /// The latest stored checkpoint, if any.
    [[nodiscard]] std::optional<protocol::SignedCheckpoint> latest_checkpoint() const;

    /// Builds an evidence bundle for `record`: genesis, the record's
    /// statements, and every statement they depend on (signers'
    /// registrations and key rotations, delegation chains, referenced
    /// actors), each with a receipt anchored to the latest checkpoint, which
    /// must cover them all, plus the stored witness cosignatures of that
    /// checkpoint. The caller adds field disclosures and attachment openings,
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
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::ledger
