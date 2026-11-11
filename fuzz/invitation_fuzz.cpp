// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Invitation codes (khp_...) are pasted from other organizations. Properties:
// reading never crashes; a code that reads keeps the limits (a name of 1 to
// 128 bytes, a URL and a token of printable ASCII); and writing what it read
// gives a code that reads to the same invitation.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <kanhe/client/peers.hpp>

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace kanhe;
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    const auto invitation = client::decode_invitation(input);
    if (!invitation) {
        return 0;
    }
    require(!invitation->organization.empty() && invitation->organization.size() <= 128);
    require(!invitation->url || (!invitation->url->empty() && invitation->url->size() <= 2048));
    require(!invitation->token ||
            (!invitation->token->empty() && invitation->token->size() <= 256));
    const auto again = client::decode_invitation(client::encode_invitation(*invitation));
    require(again.has_value() && *again == *invitation);
    return 0;
}
