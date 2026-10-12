// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/asset_evidence.hpp>
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/ledger.hpp>

/// A home ledger's side of ownership assets (D-052): it records an asset
/// action only with the consent bundles the action pins, keeps them, and
/// serves them with the asset's evidence. A registrar collects consents
/// from the parties until every one an action needs is in.
///
/// Files under <ledger>/assets:
///   consents/<action id>.cbor   the consent bundles an action pins,
///                               [* bstr] in its order; written once
///   pending/<asset>/<head>-<terms>/<party>.cbor
///                               consents a registrar holds until the rest
///                               arrive (dropped once the asset moves on)
namespace cexchain::node {

[[nodiscard]] std::filesystem::path
consents_directory(const std::filesystem::path& ledger_directory);
[[nodiscard]] std::filesystem::path consents_path(const std::filesystem::path& ledger_directory,
                                                  const protocol::Id& action);

[[nodiscard]] Result<Bytes> encode_consent_bundles(std::span<const Bytes> bundles);
/// At most `max` bundles: an asset action cites up to 4 consents, a contract
/// call up to 16.
[[nodiscard]] Result<std::vector<Bytes>>
decode_consent_bundles(ByteView encoded, std::size_t max = protocol::max_consents);

/// Checks the bundles an asset action pins, one per consent, in its order:
/// what a home does before recording the action at `now` on the ledger
/// `home` (hash `hash`). Actions without consents need none.
[[nodiscard]] Status check_action_consents(const crypto::Provider& provider,
                                           const protocol::Id& home, crypto::HashAlg hash,
                                           const protocol::AssetActionBody& action,
                                           std::span<const Bytes> bundles, protocol::Timestamp now);

/// Keeps an action's consent bundles (encoded), once: the same bytes again
/// are fine, other bytes are refused (Errc::rejected).
[[nodiscard]] Status store_consents(const std::filesystem::path& ledger_directory,
                                    const protocol::Id& action, ByteView encoded);
/// The same, for any statement's consents kept at `path`.
[[nodiscard]] Status store_consents_file(const std::filesystem::path& path, ByteView encoded);

/// True if the signed statement is an asset action that cites consents.
[[nodiscard]] bool cites_consents(const protocol::Statement& statement);

/// The asset evidence for `asset_bundle` (an asset's evidence bundle from
/// this ledger, disclosures included or not): the bundle and the consent
/// bundles its actions pin, read from `ledger_directory`.
[[nodiscard]] Result<Bytes> asset_evidence(const crypto::Provider& provider,
                                           const std::filesystem::path& ledger_directory,
                                           const protocol::EvidenceBundle& asset_bundle);

/// The newest valid delegation of `actor` for `type`, on records of
/// `record_type` and on `contract` if given, at `now`.
[[nodiscard]] std::optional<protocol::Id>
choose_delegation(const protocol::LedgerState& state, const protocol::Id& actor,
                  protocol::StatementType type, const std::optional<std::string>& record_type,
                  protocol::Timestamp now,
                  const std::optional<protocol::Id>& contract = std::nullopt);

/// Signs an asset action as the registrar `signer` (an actor of the ledger),
/// under its newest delegation that covers it.
[[nodiscard]] Result<protocol::SignedStatement>
sign_asset_action(const crypto::Provider& provider, const protocol::LedgerState& state,
                  const crypto::Signer& signer, const protocol::AssetActionBody& action,
                  protocol::Timestamp now, ledger::Entropy& entropy);

/// What a registrar holds after taking a consent.
struct ConsentProgress {
    protocol::AssetTerms terms;
    /// Parties whose consent is still to come.
    std::vector<protocol::Id> missing;
    /// Once none is missing: the action to record, and the bundles it pins.
    std::optional<protocol::AssetActionBody> action;
    std::vector<Bytes> bundles;
};

/// The consents a registrar holds. Not thread-safe: one writer.
class ConsentPool {
public:
    explicit ConsentPool(std::filesystem::path ledger_directory);

    /// Takes `bundle`, the evidence of a consent on `party`'s ledger (checked
    /// here, against this ledger's state at `now`): the asset must exist and
    /// allow the action at the consent's head, and `party` must be one of
    /// those it needs. Errc::rejected for a consent this ledger cannot use
    /// (a moved head among them), Errc::invalid_argument for a party the
    /// action does not need.
    [[nodiscard]] Result<ConsentProgress> add(const crypto::Provider& provider,
                                              const protocol::LedgerState& state,
                                              const protocol::Id& party, ByteView bundle,
                                              protocol::Timestamp now);

    /// Drops what is held for these terms (once recorded).
    void forget(const protocol::AssetTerms& terms);

private:
    std::filesystem::path root_;
};

} // namespace cexchain::node
