// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// PKCS #11 URIs arrive on command lines and in configuration. Parsing must
// never crash, and a URI it accepts must name a module and a key.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <cexchain/crypto/pkcs11.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const auto uri = cexchain::crypto::pkcs11::parse_uri(text);
    if (uri && (uri->module_path.empty() || (!uri->object && !uri->id))) {
        std::abort();
    }
    return 0;
}
