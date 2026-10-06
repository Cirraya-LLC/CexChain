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
#include <cexchain/core/protocol/log.hpp>

/// Witnessing, after the C2SP tlog-witness model. A witness is an independent
/// party that remembers the last checkpoint it cosigned for each ledger, and
/// cosigns a new one only if a consistency proof shows that the new history
/// extends the old. A ledger that rewrites its past, or shows different
/// histories to different parties, cannot get both histories cosigned.
/// See `cosign-request` in spec/cexchain.cddl.
namespace cexchain::protocol {

/// What a ledger operator sends a witness: a signed checkpoint and a
/// consistency proof from the size the witness last cosigned.
struct CosignRequest {
    /// The signed checkpoint (COSE_Sign1).
    Bytes checkpoint;
    /// The tree size the witness last cosigned; 0 if it never has.
    std::uint64_t old_size = 0;
    /// RFC 9162 consistency proof from `old_size` to the checkpoint's size.
    std::vector<crypto::Digest> proof;

    friend bool operator==(const CosignRequest&, const CosignRequest&) = default;
};

[[nodiscard]] Result<Bytes> encode_cosign_request(const CosignRequest& request);
[[nodiscard]] Result<CosignRequest> decode_cosign_request(ByteView encoded);

/// What a witness knows about one ledger.
struct WitnessedLog {
    Id ledger_id;
    /// Learned out of band from the ledger's operator.
    crypto::PublicKey log_key;
    /// Fixed by the first checkpoint the witness cosigns.
    std::optional<crypto::HashAlg> tree_hash;
    /// The last cosigned tree size and root; 0 and empty before the first.
    std::uint64_t size = 0;
    crypto::Digest root;
    /// The state root of the last cosigned checkpoint, if it had one.
    std::optional<crypto::Digest> state_root = std::nullopt;
};

/// Checks a cosign request against what the witness knows. Returns the
/// checkpoint the witness may cosign. Fails with:
///   Errc::rejected             if `old_size` is not the size the witness last
///                              cosigned (the operator should send a proof
///                              from `log.size` instead);
///   Errc::verification_failed  if the checkpoint is not the ledger's, is not
///                              signed by its log key, or does not extend the
///                              history the witness has seen; or if it
///                              commits to a different state than the one
///                              cosigned at the same size, or stops
///                              committing to the state at all.
[[nodiscard]] Result<SignedCheckpoint> check_cosign_request(const crypto::Provider& provider,
                                                            const WitnessedLog& log,
                                                            const CosignRequest& request);

/// `log` after cosigning `checkpoint`.
[[nodiscard]] WitnessedLog advance(WitnessedLog log, const Checkpoint& checkpoint);

} // namespace cexchain::protocol
