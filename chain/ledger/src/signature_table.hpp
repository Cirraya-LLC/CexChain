// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <compare>
#include <span>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/ledger/verify.hpp>

// Internal to the ledger library (and its tests).
namespace cexchain::ledger::detail {

/// A signature check, as `crypto::Provider::verify` was asked it, and the
/// outcome.
struct CheckedSignature {
    crypto::PublicKey key;
    Bytes message;
    Bytes signature;
    Status outcome;
};

/// Orders checks by their bytes: signature, algorithm, key, then message.
[[nodiscard]] std::strong_ordering compare(const crypto::PublicKey& a_key, ByteView a_message,
                                           ByteView a_signature, const crypto::PublicKey& b_key,
                                           ByteView b_message, ByteView b_signature) noexcept;

/// The signatures checked ahead for one verification, outcomes as they came
/// (failures too: a check's outcome stands either way), found only by
/// exactly the same algorithm, key, message, and signature.
class SignatureTable final : public protocol::SignatureChecks {
public:
    explicit SignatureTable(std::vector<CheckedSignature> checks);

    [[nodiscard]] std::optional<Status> find(const crypto::PublicKey& key, ByteView message,
                                             ByteView signature) override;
    void checked(const crypto::PublicKey& /*key*/, ByteView /*message*/, ByteView /*signature*/,
                 const Status& /*outcome*/) override {}

    [[nodiscard]] std::size_t size() const noexcept { return checks_.size(); }

private:
    std::vector<CheckedSignature> checks_;
};

/// Checks, on all cores, the signatures that verifying `encoded` (contract
/// evidence if `contract_evidence`, else a bundle) will check: each
/// statement's with the key its kid names in the bundle, the checkpoint's,
/// each receipt seal's, and each state commitment's with the log key in
/// effect, and the cosignatures of `trusted_witnesses`. Whatever cannot be
/// read or predicted is left to the verification itself. Successes found in
/// `cache` are not checked again; new ones are told to it.
[[nodiscard]] std::vector<CheckedSignature>
check_ahead(const crypto::Provider& provider, ByteView encoded, bool contract_evidence,
            std::span<const crypto::PublicKey> trusted_witnesses, SignatureCache* cache);

} // namespace cexchain::ledger::detail
