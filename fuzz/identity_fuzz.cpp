// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// What identity providers send the console: ID tokens, key sets, discovery
// documents, and CAS answers, all from the network. Properties: reading never
// crashes; a token never verifies against keys it was not signed with (here,
// a fixed key set and random input: only shapes and refusals); a CAS answer
// that reads names a user of 1 to 255 bytes.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <nlohmann/json.hpp>

#include <cexchain/console/identity.hpp>

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace cexchain;
    const std::string_view input(reinterpret_cast<const char*>(data), size);

    if (const auto jwt = console::decode_jwt(input)) {
        require(jwt->header.is_object() && jwt->claims.is_object());
    }
    const auto doc = nlohmann::json::parse(input, nullptr, false);
    const auto keys = console::parse_jwks(doc);
    require(keys.size() <= 64);
    static_cast<void>(console::parse_discovery(doc, "https://login.example"));

    // Random keys from the input, a token from the input: whatever the
    // token says, it is checked, never trusted.
    const console::IdTokenCheck check{"https://login.example", "console", "n", 1'793'491'200'000};
    const auto who = console::check_id_token(input, keys, check);
    if (std::holds_alternative<console::Identity>(who)) {
        // Only possible if the input carried a key and a token it signed:
        // the token's claims then passed every check.
        require(std::get<console::Identity>(who).issuer == check.issuer);
    }

    const auto cas = console::parse_cas_validation(input, "https://cas.example");
    if (const auto* id = std::get_if<console::Identity>(&cas)) {
        require(!id->subject.empty() && id->subject.size() <= 255);
    }
    return 0;
}
