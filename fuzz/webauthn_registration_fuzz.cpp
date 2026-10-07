// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A passkey registration comes from a browser, and from whatever page runs
// in it: the attestation object (CBOR, authenticator data, a COSE key) and
// the client data JSON. Parsing must never crash, and a registration it
// accepts must give a credential that encodes and decodes the same.
//
// Input: [attestation length: u16 big-endian][attestation object][client
// data], against the challenge 32 x 0x5a and the relying party "localhost".

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace protocol = cexchain::protocol;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    static const cexchain::Bytes challenge(32, 0x5a);
    if (size < 2) {
        return 0;
    }
    const std::size_t length =
        std::min<std::size_t>((std::size_t{data[0]} << 8U) | data[1], size - 2);
    const cexchain::ByteView attestation(data + 2, length);
    const cexchain::ByteView client_data(data + 2 + length, size - 2 - length);
    if (const auto credential = protocol::credential_from_registration(
            provider, attestation, client_data, challenge, "localhost", std::nullopt)) {
        const auto encoded = protocol::encode_presence_credential(*credential);
        if (!encoded || credential->credential_id.empty() ||
            credential->key.bytes.size() !=
                cexchain::crypto::public_key_size(credential->key.algorithm) ||
            protocol::decode_presence_credential(*encoded) != *credential) {
            std::abort();
        }
    }
    // The origin check on its own, with the client data as an origin.
    const std::string_view origin(reinterpret_cast<const char*>(client_data.data()),
                                  client_data.size());
    static_cast<void>(protocol::origin_matches_rp_id(origin, "localhost"));
    static_cast<void>(protocol::origin_matches_rp_id(origin, "example.com"));
    return 0;
}
