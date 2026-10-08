// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/id_map.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Ownership assets (D-052, spec section 13): receivables and warehouse
/// receipts. An asset is a record of an asset type on its home ledger, its
/// issuer's, and changes only through asset actions, which the home records
/// once every party the action needs has consented on its own ledger. These
/// are the rules every replay applies, and the metadata of assets and
/// consents. See `asset-action-body`, `receivable`, `warehouse-receipt`, and
/// `asset-consent` in spec/cexchain.cddl.
namespace cexchain::protocol {

inline constexpr std::string_view receivable_type = "cexchain.receivable/1";
inline constexpr std::string_view warehouse_receipt_type = "cexchain.warehouse-receipt/1";
/// A party's consent, on its own ledger: "given", which may become
/// "withdrawn".
inline constexpr std::string_view asset_consent_type = "cexchain.asset-consent/1";
inline constexpr std::string_view consent_given = "given";
inline constexpr std::string_view consent_withdrawn = "withdrawn";

enum class AssetKind : std::uint8_t {
    receivable,
    warehouse_receipt,
};

/// The asset kind of a record type, if it is an asset type.
[[nodiscard]] std::optional<AssetKind> asset_kind_of(std::string_view record_type) noexcept;
[[nodiscard]] std::string_view record_type_of(AssetKind kind) noexcept;

/// An asset's states. Settled, redeemed, and cancelled are final.
namespace asset_status {
inline constexpr std::string_view active = "active";
inline constexpr std::string_view pledged = "pledged";
inline constexpr std::string_view frozen = "frozen";
inline constexpr std::string_view paid = "paid";
inline constexpr std::string_view disputed = "disputed";
inline constexpr std::string_view settled = "settled";
inline constexpr std::string_view redeemed = "redeemed";
inline constexpr std::string_view cancelled = "cancelled";
} // namespace asset_status

[[nodiscard]] bool is_final_asset_status(std::string_view status) noexcept;

/// The part of an asset's metadata the rules check. Other metadata keys are
/// allowed and kept as they are.
struct AssetMetadata {
    /// The first holder's ledger.
    Id holder;
    /// Receivables: the amount, in the currency's minor unit. Warehouse
    /// receipts: the quantity.
    std::uint64_t units = 0;
    /// Receivables: the ISO 4217 currency. Warehouse receipts: the unit of
    /// measure.
    std::string unit;
    /// Receivables: when it falls due (ms).
    std::optional<Timestamp> due;

    friend bool operator==(const AssetMetadata&, const AssetMetadata&) = default;
};

/// Decodes and checks an asset's metadata (a map with text keys).
[[nodiscard]] Result<AssetMetadata> decode_asset_metadata(AssetKind kind,
                                                          const cbor::Value& metadata);
/// Encodes an asset's metadata, with `extra` text-keyed entries (a title,
/// say) besides the checked ones.
[[nodiscard]] Result<cbor::Value>
encode_asset_metadata(AssetKind kind, const AssetMetadata& metadata, const cbor::Map& extra = {});

/// An asset as the ledger keeps it, besides its record (whose `state` is the
/// asset's status).
struct AssetState {
    CompactId id;
    AssetKind kind = AssetKind::receivable;
    Id holder;
    std::optional<Id> pledgee;
    /// Set by pay: whom the debtor says it paid.
    std::optional<Id> payee;
    /// Receivables: the amount. Warehouse receipts: the quantity remaining.
    std::uint64_t units = 0;
    /// The log index of its registration or latest asset action.
    std::uint64_t head = 0;
    /// While frozen: the status to return to.
    std::string frozen_from;
};

/// Checks an asset's registration on the ledger `home`, and returns the
/// asset it creates at log index `index`.
[[nodiscard]] Result<AssetState> register_asset(AssetKind kind,
                                                const std::optional<cbor::Value>& metadata,
                                                const Id& home, const Id& id, std::uint64_t index);

/// The parties whose consent `action` needs on `asset` in `status`,
/// ascending (none for pay, freeze, and unfreeze). Assumes the action is
/// otherwise allowed.
[[nodiscard]] std::vector<Id> consenting_parties(const AssetState& asset, std::string_view status,
                                                 const AssetActionBody& action);

/// Checks an asset action against the asset's state, on the ledger `home`
/// (spec section 13).
[[nodiscard]] Status check_asset_action(const AssetState& asset, std::string_view status,
                                        const AssetActionBody& action, const Id& home);

/// Applies an action that `check_asset_action` accepted, registered at log
/// index `index`, and returns the asset's new status.
[[nodiscard]] std::string apply_asset_action(AssetState& asset, std::string_view status,
                                             const AssetActionBody& action, std::uint64_t index);

/// What a party consents to: these must equal the action's.
struct AssetTerms {
    /// The asset's home ledger.
    Id ledger;
    Id asset;
    AssetAction action = AssetAction::transfer;
    std::uint64_t head = 0;
    std::optional<Id> to;
    std::optional<std::uint64_t> quantity;

    friend bool operator==(const AssetTerms&, const AssetTerms&) = default;
};

/// The terms of an action recorded on the ledger `home`.
[[nodiscard]] AssetTerms terms_of(const AssetActionBody& action, const Id& home);

/// Metadata of a consent record, on the consenting party's ledger.
struct AssetConsent {
    AssetTerms terms;
    /// The consent lapses at this time (ms).
    Timestamp until = 0;
    /// A financing contract, a registry filing: 1 to 1024 bytes.
    std::optional<std::string> reference;

    friend bool operator==(const AssetConsent&, const AssetConsent&) = default;
};

[[nodiscard]] Result<cbor::Value> encode_asset_consent(const AssetConsent& consent);
/// Decodes a consent's metadata. Unknown keys are refused.
[[nodiscard]] Result<AssetConsent> decode_asset_consent(const cbor::Value& metadata);

} // namespace cexchain::protocol
