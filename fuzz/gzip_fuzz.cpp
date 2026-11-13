// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// GZIP data, as a status list's encodedList carries it (a credential's
// issuer's, anyone's). Whatever arrives, decompressing must not crash nor
// pass its limit; what decompresses compresses again to what decompresses
// to the same.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <kanhe/verifier/gzip.hpp>

namespace verifier = kanhe::verifier;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

constexpr std::size_t limit = 1 << 20;

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto out = verifier::gzip_decompress({data, size}, limit);
    if (out) {
        require(out->size() <= limit);
        const auto again = verifier::gzip_decompress(verifier::gzip_compress(*out), limit);
        require(again && *again == *out);
    }
    return 0;
}
