// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/evidence.hpp>

/// Contract evidence (D-053, spec section 15): an instance's evidence bundle
/// from its home ledger, with the consent bundles from other ledgers that its
/// calls cite. Verified offline, it shows every call, what the contract made
/// of it, and who consented on their own ledger. See `contract-evidence` in
/// spec/cexchain.cddl.
namespace cexchain::protocol {

inline constexpr std::uint64_t contract_evidence_version = 1;
/// Contract evidence carries at most this many consent bundles.
inline constexpr std::size_t max_consent_bundles = 4096;

struct ContractEvidence {
    /// The instance's evidence bundle, from its home.
    Bytes instance_bundle;
    /// Every consent bundle the instance's calls cite, each once.
    std::vector<Bytes> consent_bundles;

    friend bool operator==(const ContractEvidence&, const ContractEvidence&) = default;
};

[[nodiscard]] Result<Bytes> encode_contract_evidence(const ContractEvidence& evidence);
[[nodiscard]] Result<ContractEvidence> decode_contract_evidence(ByteView encoded);

/// Who signed a record's registration (an evidence report's first event), as
/// contracts see it: what a call citing a consent to the record must claim.
[[nodiscard]] ContractSigner registration_signer(const RecordEvent& registration);

/// A consent checked against the call that cites it.
struct ContractConsentCheck {
    ContractConsentRef ref;
    ContractConsent consent;
    /// The consent record's evidence, verified for the party's ledger.
    EvidenceReport report;
};

/// Checks a party's consent to `call`, registered (or to be registered) at
/// `at` on the ledger `home` with hash `home_hash`: `bundle` hashes to
/// `ref.bundle`, verifies for `ref.ledger` completely, and is about
/// `ref.record`, a live contract consent with the call's terms that lapses
/// no earlier than `at`, registered by the signer `ref.signer` claims.
/// Cosignatures count as trusted only by `trusted_witnesses`.
[[nodiscard]] Result<ContractConsentCheck>
check_contract_consent(const crypto::Provider& provider, const ContractConsentRef& ref,
                       ByteView bundle, const ContractCallBody& call, const Id& home,
                       crypto::HashAlg home_hash, Timestamp at,
                       std::span<const crypto::PublicKey> trusted_witnesses = {});

/// The same checks for a bundle verified already: `report` must be what
/// `verify_bundle` reports for exactly `bundle` with `expected_ledger` set to
/// `ref.ledger` and no trusted witnesses (a registrar verifies a consent once,
/// on another thread, before it checks the consent against a call).
[[nodiscard]] Result<ContractConsentCheck>
check_verified_contract_consent(const crypto::Provider& provider, const ContractConsentRef& ref,
                                ByteView bundle, EvidenceReport report,
                                const ContractCallBody& call, const Id& home,
                                crypto::HashAlg home_hash, Timestamp at);

/// One call on the instance (for a child, or on one of its ancestors), with
/// its consents.
struct ContractStep {
    /// The call's event in the instance report's `events`.
    std::size_t event = 0;
    std::vector<ContractConsentCheck> consents;
};

struct ContractReport {
    /// The instance's own report: complete, with the instance in `instance`.
    EvidenceReport instance;
    /// Its calls, oldest first; for a child, its ancestors' calls up to each
    /// one that created the next generation come first (v0.7).
    std::vector<ContractStep> steps;
};

/// Verifies contract evidence: the instance bundle for the home ledger
/// (`options.expected_ledger`, if set), completely; and every consent its
/// calls cite, against the bundle each pins. For a child, its ancestors'
/// calls are its calls here, consents and all (v0.7). A bundle that no call
/// pins, or a call whose consent is missing, fails it.
[[nodiscard]] Result<ContractReport> verify_contract_evidence(const crypto::Provider& provider,
                                                              ByteView encoded,
                                                              const VerifyOptions& options = {});

} // namespace cexchain::protocol
