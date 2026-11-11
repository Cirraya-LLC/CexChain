// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Feeds arbitrary bytes to what reads time-stamp authorities' output (RFC
// 3161): tokens in evidence, an authority's answer, and certificate files.
// Each must refuse or accept without crashing, hanging, or invoking
// undefined behavior. The first byte chooses which.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <kanhe/crypto/openssl.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace openssl = kanhe::crypto::openssl;
    static const openssl::Provider provider;
    if (size == 0) {
        return 0;
    }
    const kanhe::ByteView input(data + 1, size - 1);
    switch (data[0] % 3) {
    case 0:
        static_cast<void>(provider.read_timestamp(input, {}));
        break;
    case 1: {
        static constexpr std::array<std::uint8_t, 32> imprint{};
        static_cast<void>(
            openssl::timestamp_from_response(input, kanhe::crypto::HashAlg::sha256, imprint, 1));
        break;
    }
    default:
        static_cast<void>(openssl::read_certificates(input));
        break;
    }
    return 0;
}
