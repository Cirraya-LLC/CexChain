// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Strict decoding accepts only canonical input, so every accepted input must
// re-encode to exactly the same bytes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/cbor.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const cexchain::ByteView input(data, size);
    const auto decoded = cexchain::cbor::decode(input);
    if (!decoded) {
        return 0;
    }
    const auto encoded = cexchain::cbor::encode(*decoded);
    if (!encoded || !std::ranges::equal(*encoded, input)) {
        std::abort();
    }
    static_cast<void>(cexchain::cbor::diagnostic(*decoded));
    return 0;
}
