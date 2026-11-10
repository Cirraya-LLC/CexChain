// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A claim's metadata (spec v0.14) comes from whoever registers a record:
// reading it must refuse what is not one, never crash, and what it accepts
// must encode back to metadata that reads the same, and be put in words.

#include <cstddef>
#include <cstdint>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/claims.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto value = cexchain::cbor::decode({data, size});
    if (!value) {
        return 0;
    }
    const auto claim = cexchain::protocol::decode_claim(*value);
    if (!claim) {
        return 0;
    }
    const auto again = cexchain::protocol::encode_claim(*claim);
    if (!again || cexchain::protocol::decode_claim(*again) != claim) {
        __builtin_trap();
    }
    if (cexchain::protocol::claim_text(*claim).empty()) {
        __builtin_trap();
    }
    return 0;
}
