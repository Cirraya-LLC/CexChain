// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Asset evidence and consents come from other organizations (D-052).
// Decoding must never crash, whatever decodes must encode back to the same
// bytes, and verifying arbitrary evidence must fail cleanly.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/asset_evidence.hpp>
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace protocol = cexchain::protocol;
namespace cbor = cexchain::cbor;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

/// Asset metadata keeps keys it does not check: re-encoding the checked
/// part with the rest must give the input back.
void round_trip_metadata(protocol::AssetKind kind, const cbor::Value& value,
                         cexchain::ByteView input) {
    const auto metadata = protocol::decode_asset_metadata(kind, value);
    if (!metadata) {
        return;
    }
    static constexpr std::array<std::string_view, 4> receivable{"holder", "amount", "currency",
                                                                "due"};
    static constexpr std::array<std::string_view, 3> receipt{"holder", "quantity", "unit"};
    const std::span<const std::string_view> checked =
        kind == protocol::AssetKind::receivable ? std::span<const std::string_view>(receivable)
                                                : std::span<const std::string_view>(receipt);
    cbor::Map extra;
    for (const cbor::MapEntry& e : *value.as_map()) {
        if (std::ranges::find(checked, *e.key.as_text()) == checked.end()) {
            extra.push_back(e);
        }
    }
    const auto again = protocol::encode_asset_metadata(kind, *metadata, extra);
    const auto encoded = again ? cbor::encode(*again)
                               : cexchain::Result<cexchain::Bytes>(std::unexpected(again.error()));
    require(encoded && std::ranges::equal(*encoded, input));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    const cexchain::ByteView input(data, size);
    if (const auto evidence = protocol::decode_asset_evidence(input)) {
        const auto again = protocol::encode_asset_evidence(*evidence);
        require(again && std::ranges::equal(*again, input));
        // Verification replays bundles: it must refuse anything not genuine
        // without crashing, and accept only complete evidence.
        if (const auto report = protocol::verify_asset_evidence(provider, input)) {
            require(report->asset.complete && report->asset.asset.has_value());
        }
    }
    if (const auto value = cbor::decode(input)) {
        if (const auto consent = protocol::decode_asset_consent(*value)) {
            const auto again = protocol::encode_asset_consent(*consent);
            const auto encoded =
                again ? cbor::encode(*again)
                      : cexchain::Result<cexchain::Bytes>(std::unexpected(again.error()));
            require(encoded && std::ranges::equal(*encoded, input));
        }
        round_trip_metadata(protocol::AssetKind::receivable, *value, input);
        round_trip_metadata(protocol::AssetKind::warehouse_receipt, *value, input);
    }
    return 0;
}
