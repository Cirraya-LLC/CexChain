// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A claim's metadata (spec v0.14) comes from whoever registers a record:
// reading it must refuse what is not one, never crash, and what it accepts
// must encode back to metadata that reads the same, and be put in words.

#include <cstddef>
#include <cstdint>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/claims.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto value = kanhe::cbor::decode({data, size});
    if (!value) {
        return 0;
    }
    const auto claim = kanhe::protocol::decode_claim(*value);
    if (!claim) {
        return 0;
    }
    const auto again = kanhe::protocol::encode_claim(*claim);
    if (!again || kanhe::protocol::decode_claim(*again) != claim) {
        __builtin_trap();
    }
    if (kanhe::protocol::claim_text(*claim).empty()) {
        __builtin_trap();
    }
    return 0;
}
