// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/core/protocol/evidence.hpp>

/// Asset evidence (D-052, spec section 13): an asset's evidence bundle from
/// its home ledger, with the consent bundles from other ledgers that its
/// actions pin. Verified offline, it shows the asset's chain of title: each
/// action, and who consented to it on their own ledger. See
/// `asset-evidence` in spec/cexchain.cddl.
namespace cexchain::protocol {

inline constexpr std::uint64_t asset_evidence_version = 1;
inline constexpr std::size_t max_consent_bundles = 4096;

struct AssetEvidence {
    /// The asset's evidence bundle, from its home.
    Bytes asset_bundle;
    /// Every consent bundle the asset's actions pin, each once.
    std::vector<Bytes> consent_bundles;

    friend bool operator==(const AssetEvidence&, const AssetEvidence&) = default;
};

[[nodiscard]] Result<Bytes> encode_asset_evidence(const AssetEvidence& evidence);
[[nodiscard]] Result<AssetEvidence> decode_asset_evidence(ByteView encoded);

/// A consent checked against the action that cites it.
struct ConsentCheck {
    ConsentRef ref;
    AssetConsent consent;
    /// The consent record's evidence, verified for the party's ledger.
    EvidenceReport report;
};

/// Checks a party's consent for an action with `terms` registered (or to be
/// registered) at `at` on a ledger with hash `home_hash`: `bundle` hashes
/// to `ref.bundle`, verifies for `ref.ledger` completely, and is about
/// `ref.record`, a live consent record with these terms that lapses no
/// earlier than `at`. Cosignatures count as trusted only by
/// `trusted_witnesses`.
[[nodiscard]] Result<ConsentCheck>
check_consent(const crypto::Provider& provider, const ConsentRef& ref, ByteView bundle,
              const AssetTerms& terms, Timestamp at, crypto::HashAlg home_hash,
              std::span<const crypto::PublicKey> trusted_witnesses = {});

/// One action in an asset's chain of title.
struct AssetStep {
    /// The action's event in the asset report's `events`.
    std::size_t event = 0;
    std::vector<ConsentCheck> consents;
};

struct AssetReport {
    /// The asset's own report: complete, with its state in `asset`.
    EvidenceReport asset;
    /// Its actions, oldest first.
    std::vector<AssetStep> steps;
};

/// Verifies asset evidence: the asset bundle for the home ledger
/// (`options.expected_ledger`, if set), completely; and every consent its
/// actions cite, against the bundle each pins. A bundle that no action pins,
/// or an action whose consent is missing, fails it.
[[nodiscard]] Result<AssetReport> verify_asset_evidence(const crypto::Provider& provider,
                                                        ByteView encoded,
                                                        const VerifyOptions& options = {});

} // namespace cexchain::protocol
