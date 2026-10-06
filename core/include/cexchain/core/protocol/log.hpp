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
#include <cexchain/core/protocol/common.hpp>

/// Log entries, checkpoints, witness cosignatures, and receipts.
/// See spec/cexchain-v0.1.cddl.
namespace cexchain::protocol {

/// One registered statement, as committed by the ledger's Merkle tree.
struct LogEntry {
    Id statement_id;
    /// Ledger clock at registration.
    Timestamp registered_at = 0;
    /// The signed statement (COSE_Sign1) as submitted.
    Bytes statement;

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
    /// The state commitment at this size (see state_tree.hpp). Absent only in
    /// checkpoints written before it existed.
    std::optional<crypto::Digest> state_root;

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

[[nodiscard]] Result<Receipt> parse_receipt(ByteView encoded);

/// Applies the receipt's proof to `entry` (the encoded log entry), then
/// verifies the log key's signature over the resulting root. Returns that
/// root, so the caller can match it against a checkpoint of the same size.
[[nodiscard]] Result<crypto::Digest> verify_receipt(const crypto::Provider& provider,
                                                    const Receipt& receipt, ByteView entry,
                                                    const crypto::PublicKey& log_key);

} // namespace cexchain::protocol
