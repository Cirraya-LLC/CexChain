// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>
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
namespace cexchain::ledger {

struct Registration {
    protocol::Id statement_id;
    std::uint64_t index = 0;
    protocol::Timestamp registered_at = 0;
    /// False if the statement was already registered; submission is
    /// idempotent, so clients may safely retry.
    bool newly_registered = false;
};

struct AuditReport {
    std::uint64_t entries = 0;
    std::uint64_t checkpoints = 0;
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

    Ledger(Ledger&&) noexcept;
    Ledger& operator=(Ledger&&) noexcept;
    ~Ledger();

    [[nodiscard]] const protocol::LedgerState& state() const noexcept;
    [[nodiscard]] const protocol::Id& id() const noexcept;
    [[nodiscard]] crypto::HashAlg hash() const noexcept;
    [[nodiscard]] std::uint64_t size() const noexcept;

    /// Validates and registers a signed statement.
    [[nodiscard]] Result<Registration> submit(ByteView signed_statement);

    /// The encoded log entry at `index` (the bytes the tree commits to).
    [[nodiscard]] Result<Bytes> entry(std::uint64_t index) const;

    [[nodiscard]] Result<crypto::Digest> root(std::uint64_t tree_size) const;
    [[nodiscard]] Result<std::vector<crypto::Digest>>
    inclusion_proof(std::uint64_t index, std::uint64_t tree_size) const;
    [[nodiscard]] Result<std::vector<crypto::Digest>>
    consistency_proof(std::uint64_t old_size, std::uint64_t new_size) const;

    /// Signs and stores a checkpoint of the current tree. `log_key` must be the
    /// key named in genesis.
    [[nodiscard]] Result<protocol::SignedCheckpoint> checkpoint(const crypto::Signer& log_key);

    /// Every stored checkpoint, oldest first.
    [[nodiscard]] Result<std::vector<protocol::SignedCheckpoint>> checkpoints() const;

    /// Re-checks every stored checkpoint against the log: signed by the log
    /// key, for this ledger, sizes never decreasing, and each root equal to
    /// the tree's root at that size. (Opening the ledger has already replayed
    /// and re-validated every statement.)
    [[nodiscard]] Result<AuditReport> audit() const;

    /// The latest stored checkpoint, if any.
    [[nodiscard]] const std::optional<protocol::SignedCheckpoint>&
    latest_checkpoint() const noexcept;

    /// Builds an evidence bundle for `record`: genesis, the record's
    /// statements, and every statement they depend on (signers'
    /// registrations and key rotations, delegation chains, referenced
    /// actors), each with a receipt anchored to the latest checkpoint, which
    /// must cover them all. The caller adds field disclosures and attachment
    /// openings, since only it holds the record's private data.
    [[nodiscard]] Result<protocol::EvidenceBundle>
    export_evidence(const crypto::Signer& log_key, const protocol::Id& record) const;

    /// An RFC 9942 receipt for the entry at `index`, anchored to the latest
    /// checkpoint. Fails if no checkpoint covers the entry yet.
    [[nodiscard]] Result<Bytes> receipt(const crypto::Signer& log_key, std::uint64_t index) const;

private:
    struct Impl;
    explicit Ledger(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::ledger
