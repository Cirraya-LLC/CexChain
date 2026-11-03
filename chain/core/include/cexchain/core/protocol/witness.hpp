// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/keys.hpp>
#include <cexchain/core/protocol/log.hpp>

/// Witnessing, after the C2SP tlog-witness model. A witness is an independent
/// party that remembers the last checkpoint it cosigned for each ledger, and
/// cosigns a new one only if a consistency proof shows that the new history
/// extends the old. A ledger that rewrites its past, or shows different
/// histories to different parties, cannot get both histories cosigned.
/// See `cosign-request` in spec/cexchain.cddl.
namespace cexchain::protocol {

/// A log entry that rotates the organization's root or log key, with its
/// inclusion proof against the checkpoint of a cosign request.
struct KeyRotationProof {
    std::uint64_t index = 0;
    /// The encoded log entry.
    Bytes entry;
    std::vector<crypto::Digest> path;

    friend bool operator==(const KeyRotationProof&, const KeyRotationProof&) = default;
};

/// At most this many key rotations in one cosign request.
inline constexpr std::size_t max_key_rotations = 4096;

/// What a ledger operator sends a witness: a signed checkpoint and a
/// consistency proof from the size the witness last cosigned.
struct CosignRequest {
    /// The signed checkpoint (COSE_Sign1).
    Bytes checkpoint;
    /// The tree size the witness last cosigned; 0 if it never has.
    std::uint64_t old_size = 0;
    /// RFC 9162 consistency proof from `old_size` to the checkpoint's size.
    std::vector<crypto::Digest> proof;
    /// Every key rotation below the checkpoint's size, ascending (spec v0.4):
    /// the witness follows those it has not seen, so it knows the log key
    /// that signs the checkpoint.
    std::vector<KeyRotationProof> rotations;

    friend bool operator==(const CosignRequest&, const CosignRequest&) = default;
};

[[nodiscard]] Result<Bytes> encode_cosign_request(const CosignRequest& request);
[[nodiscard]] Result<CosignRequest> decode_cosign_request(ByteView encoded);

/// What a witness knows about one ledger.
struct WitnessedLog {
    Id ledger_id;
    /// The log key in effect for the size last cosigned: from the ledger's
    /// genesis (or out of band), then followed through rotations.
    crypto::PublicKey log_key;
    /// The organization's root key, which signs key rotations; absent for a
    /// log added with only its log key, which cannot follow a rotation.
    std::optional<crypto::PublicKey> root_key;
    /// The index of the last key rotation followed; 0 if none.
    std::uint64_t last_rotation = 0;
    /// Fixed by the first checkpoint the witness cosigns.
    std::optional<crypto::HashAlg> tree_hash;
    /// The last cosigned tree size and root; 0 and empty before the first.
    std::uint64_t size = 0;
    crypto::Digest root;

    friend bool operator==(const WitnessedLog&, const WitnessedLog&) = default;
};

/// A checkpoint a witness may cosign, and what the witness knows once it has.
struct CosignApproval {
    SignedCheckpoint checkpoint;
    WitnessedLog log;
};

/// Checks a cosign request against what the witness knows: first any key
/// rotations it has not followed (each in the checkpoint's log, signed by the
/// root key in effect), then the checkpoint's signature with the log key that
/// results, then consistency. Fails with:
///   Errc::rejected             if `old_size` is not the size the witness last
///                              cosigned (the operator should send a proof
///                              from `log.size` instead);
///   Errc::verification_failed  if the checkpoint is not the ledger's, is not
///                              signed by its log key, or does not extend the
///                              history the witness has seen, or a key
///                              rotation does not check.
[[nodiscard]] Result<CosignApproval> check_cosign_request(const crypto::Provider& provider,
                                                          const WitnessedLog& log,
                                                          const CosignRequest& request);

/// `log` after cosigning `checkpoint`.
[[nodiscard]] WitnessedLog advance(WitnessedLog log, const Checkpoint& checkpoint);

} // namespace cexchain::protocol
