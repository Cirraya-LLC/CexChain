// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Deliveries and access metadata come from other organizations. Decoding
// must never crash, and whatever decodes must encode back to the same bytes
// (one encoding per value).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>

namespace protocol = cexchain::protocol;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const cexchain::ByteView input(data, size);
    if (const auto delivery = protocol::decode_delivery(input)) {
        const auto again = protocol::encode_delivery(*delivery);
        if (!again || !std::ranges::equal(*again, input)) {
            std::abort();
        }
    }
    if (const auto contents = protocol::decode_delivery_contents(input)) {
        const auto again = protocol::encode_delivery_contents(*contents);
        if (!again || !std::ranges::equal(*again, input)) {
            std::abort();
        }
    }
    // Metadata: canonical input re-encodes to exactly the input.
    auto same = [&](const cexchain::Result<cexchain::cbor::Value>& value) {
        const auto encoded =
            value ? cexchain::cbor::encode(*value)
                  : cexchain::Result<cexchain::Bytes>(std::unexpected(value.error()));
        return encoded && std::ranges::equal(*encoded, input);
    };
    if (const auto value = cexchain::cbor::decode(input)) {
        if (const auto request = protocol::decode_access_request(*value)) {
            if (!same(protocol::encode_access_request(*request))) {
                std::abort();
            }
        }
        if (const auto grant = protocol::decode_access_grant(*value)) {
            if (!same(protocol::encode_access_grant(*grant))) {
                std::abort();
            }
        }
        if (const auto receipt = protocol::decode_access_receipt(*value)) {
            if (!same(protocol::encode_access_receipt(*receipt))) {
                std::abort();
            }
        }
    }
    return 0;
}
