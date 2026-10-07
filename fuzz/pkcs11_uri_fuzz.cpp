// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// PKCS #11 URIs arrive on command lines and in configuration. Parsing must
// never crash, and a URI it accepts must name a module by an absolute path
// (once, with no NUL to cut it short), and a key.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <cexchain/crypto/pkcs11.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const auto uri = cexchain::crypto::pkcs11::parse_uri(text);
    if (uri && (uri->module_path.empty() || uri->module_path.front() != '/' ||
                (!uri->object && !uri->id))) {
        std::abort();
    }
    if (!uri) {
        return 0;
    }
    // Nothing twice: count the query's module-path attributes independently.
    std::size_t paths = 0;
    if (const std::size_t question = text.find('?'); question != std::string_view::npos) {
        std::string_view query = text.substr(question + 1);
        while (true) {
            const std::size_t amp = query.find('&');
            paths += query.substr(0, amp).starts_with("module-path=") ? 1 : 0;
            if (amp == std::string_view::npos) {
                break;
            }
            query.remove_prefix(amp + 1);
        }
    }
    if (paths != 1 || uri->module_path.contains('\0')) {
        std::abort();
    }
    return 0;
}
