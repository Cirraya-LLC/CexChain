// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Deliveries and access metadata come from other organizations. Decoding
// must never crash, and whatever decodes must encode back to the same bytes
// (one encoding per value).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/access.hpp>

namespace protocol = kanhe::protocol;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const kanhe::ByteView input(data, size);
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
    auto same = [&](const kanhe::Result<kanhe::cbor::Value>& value) {
        const auto encoded = value ? kanhe::cbor::encode(*value)
                                   : kanhe::Result<kanhe::Bytes>(std::unexpected(value.error()));
        return encoded && std::ranges::equal(*encoded, input);
    };
    if (const auto value = kanhe::cbor::decode(input)) {
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
