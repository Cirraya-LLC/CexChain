// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A credential (a compact JWS), its parts, and what a verifier reads from
// one before it trusts anything: the JSON (which must be canonical), the
// addresses it names, a status list's encodedList, a base URL, an
// endorsement role. Whatever arrives must not crash; what is accepted holds
// up when written again.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include <kanhe/verifier/credentials.hpp>
#include <kanhe/verifier/jcs.hpp>

namespace verifier = kanhe::verifier;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    if (const auto jws = verifier::parse_jws(text)) {
        require(jws->signature.size() == 64);
        require(verifier::jcs(jws->payload).has_value());
        if (const auto addresses = verifier::credential_addresses(text)) {
            require(addresses->evidence.find("/c/") != std::string::npos);
        }
    }
    if (const auto json = verifier::parse_jcs(text)) {
        const auto again = verifier::jcs(*json);
        require(again && *again == text);
    }
    if (const auto bits = verifier::decode_status_list(text)) {
        require(bits->size() == verifier::status_list_bytes);
    }
    if (const auto base = verifier::parse_base_url(text)) {
        const auto again = verifier::parse_base_url(base->url);
        require(again && *again == *base);
        require(base->did.starts_with("did:web:"));
    }
    if (const auto entry = verifier::parse_credential_role(text)) {
        require(entry->list >= 1 && entry->index < verifier::status_list_size);
        require(verifier::credential_role(*entry) == text);
    }
    return 0;
}
