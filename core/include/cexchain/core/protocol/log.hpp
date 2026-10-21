// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cose.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/common.hpp>

/// Log entries, checkpoints, witness cosignatures, and receipts.
/// See spec/cexchain.cddl.
namespace cexchain::protocol {

/// One log entry, as committed by the ledger's Merkle tree: a registered
/// statement, or a state commitment the ledger made when checkpointing.
struct LogEntry {
    /// HASH(Sig_structure) of the statement or of the state commitment.
    Id statement_id;
    /// Ledger clock at registration.
    Timestamp registered_at = 0;
    /// The signed statement (COSE_Sign1) as submitted; empty for a state
    /// commitment.
    Bytes statement = {};
    /// The signed state commitment; empty for a statement.
    Bytes state_commitment = {};

    [[nodiscard]] bool is_state_commitment() const noexcept { return !state_commitment.empty(); }

    friend bool operator==(const LogEntry&, const LogEntry&) = default;
};

[[nodiscard]] Result<Bytes> encode_log_entry(const LogEntry& entry);
[[nodiscard]] Result<LogEntry> decode_log_entry(ByteView encoded);

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

/// A signed statement of the ledger's tree size and root. The size and root
/// are signed together (D-023).
struct Checkpoint {
    Id ledger_id;
    crypto::HashAlg tree_hash = crypto::HashAlg::sha256;
    std::uint64_t tree_size = 0;
    crypto::Digest root;
    Timestamp timestamp = 0;

    friend bool operator==(const Checkpoint&, const Checkpoint&) = default;
};

[[nodiscard]] Result<Bytes> encode_checkpoint(const Checkpoint& checkpoint);
[[nodiscard]] Result<Checkpoint> decode_checkpoint(ByteView encoded);

/// A checkpoint signed by the log key, or a cosignature by a witness. Both
/// sign the same payload bytes, under different content types.
struct SignedCheckpoint {
    Bytes encoded;
    cose::Sign1 envelope;
    Checkpoint checkpoint;
    Id kid;
};

/// Signs a checkpoint with the ledger's log key.
[[nodiscard]] Result<SignedCheckpoint> sign_checkpoint(const crypto::Signer& log_key,
                                                       const crypto::Provider& provider,
                                                       const Checkpoint& checkpoint);
[[nodiscard]] Result<SignedCheckpoint> parse_checkpoint(ByteView encoded);
[[nodiscard]] Status verify_checkpoint(const crypto::Provider& provider,
                                       const SignedCheckpoint& checkpoint,
                                       const crypto::PublicKey& log_key);

/// A witness's cosignature over a checkpoint. A witness must only cosign
/// after verifying consistency with the last checkpoint it cosigned.
[[nodiscard]] Result<SignedCheckpoint> cosign_checkpoint(const crypto::Signer& witness_key,
                                                         const crypto::Provider& provider,
                                                         const Checkpoint& checkpoint);
[[nodiscard]] Result<SignedCheckpoint> parse_cosignature(ByteView encoded);
[[nodiscard]] Status verify_cosignature(const crypto::Provider& provider,
                                        const SignedCheckpoint& cosignature,
                                        const crypto::PublicKey& witness_key);

// ---------------------------------------------------------------------------
// State commitments
// ---------------------------------------------------------------------------

inline constexpr std::string_view state_commitment_content_type = "application/cexchain-state+cbor";

/// The ledger's commitment, signed with the log key and appended to the log
/// when it checkpoints, to the state after the entries before it (see
/// state_tree.hpp). Being in the log, it is covered by every later checkpoint
/// and witnessed like any entry: a false commitment cannot be withdrawn, and
/// anyone replaying the log finds it.
struct StateCommitment {
    Id ledger_id;
    crypto::HashAlg tree_hash = crypto::HashAlg::sha256;
    /// The number of entries before the commitment: its own log index.
    std::uint64_t tree_size = 0;
    crypto::Digest state_root;
    Timestamp timestamp = 0;

    friend bool operator==(const StateCommitment&, const StateCommitment&) = default;
};

struct SignedStateCommitment {
    Bytes encoded;
    cose::Sign1 envelope;
    StateCommitment commitment;
    /// HASH(Sig_structure) under the tree hash: the log entry's id.
    Id id;
    Id kid;
};

[[nodiscard]] Result<Bytes> encode_state_commitment(const StateCommitment& commitment);
[[nodiscard]] Result<StateCommitment> decode_state_commitment(ByteView encoded);
[[nodiscard]] Result<SignedStateCommitment>
sign_state_commitment(const crypto::Signer& log_key, const crypto::Provider& provider,
                      const StateCommitment& commitment);
[[nodiscard]] Result<SignedStateCommitment> parse_state_commitment(const crypto::Provider& provider,
                                                                   ByteView encoded);
[[nodiscard]] Status verify_state_commitment(const crypto::Provider& provider,
                                             const SignedStateCommitment& commitment,
                                             const crypto::PublicKey& log_key);

// ---------------------------------------------------------------------------
// Receipts (RFC 9942)
// ---------------------------------------------------------------------------

/// COSE header labels registered by RFC 9942.
inline constexpr std::int64_t label_receipts = 394;
inline constexpr std::int64_t label_vds = 395;
inline constexpr std::int64_t label_vdp = 396;
inline constexpr std::int64_t vdp_inclusion_proofs = -1;

/// Verifiable data structure identifiers: RFC9162_SHA256 (registered) and an
/// RFC 9162 tree with SM3 (CexChain private use).
inline constexpr std::int64_t vds_rfc9162_sha256 = 1;
inline constexpr std::int64_t vds_rfc9162_sm3 = -65537;

struct InclusionProof {
    std::uint64_t tree_size = 0;
    std::uint64_t leaf_index = 0;
    std::vector<crypto::Digest> path;

    friend bool operator==(const InclusionProof&, const InclusionProof&) = default;
};

/// An RFC 9942 inclusion receipt: the log key's signature over the Merkle
/// root (detached payload) plus an inclusion proof for one entry.
struct Receipt {
    Bytes encoded;
    cose::Sign1 envelope;
    crypto::HashAlg tree_hash = crypto::HashAlg::sha256;
    InclusionProof proof;
    Id kid;
};

[[nodiscard]] Result<Bytes> issue_receipt(const crypto::Signer& log_key,
                                          const crypto::Provider& provider,
                                          crypto::HashAlg tree_hash, const crypto::Digest& root,
                                          const InclusionProof& proof);

/// What every receipt against one root shares: the protected header and the
/// log key's signature over it and the root. The inclusion proof sits in
/// the unprotected header, so one signature serves every entry the root
/// covers.
struct ReceiptSeal {
    Bytes protected_bytes;
    Bytes signature;
};

/// Signs `root` once, for any number of receipts.
[[nodiscard]] Result<ReceiptSeal> seal_receipts(const crypto::Signer& log_key,
                                                const crypto::Provider& provider,
                                                crypto::HashAlg tree_hash,
                                                const crypto::Digest& root);
/// A receipt from a seal, without signing again.
[[nodiscard]] Result<Bytes> issue_receipt(const ReceiptSeal& seal, const InclusionProof& proof);

[[nodiscard]] Result<Receipt> parse_receipt(ByteView encoded);

/// Applies the receipt's proof to `entry` (the encoded log entry), then
/// verifies the log key's signature over the resulting root. Returns that
/// root, so the caller can match it against a checkpoint of the same size.
[[nodiscard]] Result<crypto::Digest> verify_receipt(const crypto::Provider& provider,
                                                    const Receipt& receipt, ByteView entry,
                                                    const crypto::PublicKey& log_key);

/// The two halves of verify_receipt, for a verifier that learns the log key
/// in effect only later (from rotations among the entries): the root the
/// receipt's proof leads to, and the log key's signature over that root.
/// Receipts into one tree may share a `memo` (see merkle::InclusionMemo);
/// their proofs must outlive it.
[[nodiscard]] Result<crypto::Digest> receipt_root(const crypto::Provider& provider,
                                                  const Receipt& receipt, ByteView entry,
                                                  merkle::InclusionMemo* memo = nullptr);
[[nodiscard]] Status verify_receipt_signature(const crypto::Provider& provider,
                                              const Receipt& receipt, const crypto::Digest& root,
                                              const crypto::PublicKey& log_key);

} // namespace cexchain::protocol
