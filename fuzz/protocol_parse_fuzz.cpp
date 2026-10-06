// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Feeds arbitrary bytes to every protocol object parser. Whatever a decoder
// accepts, the matching encoder must reproduce byte for byte, so decoding and
// encoding can never disagree about what a structure means.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/core/protocol/witness.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace protocol = cexchain::protocol;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

template <class Encoded>
void require_same(const Encoded& encoded, cexchain::ByteView input) {
    require(encoded.has_value() && std::ranges::equal(*encoded, input));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    const cexchain::ByteView input(data, size);

    if (const auto statement = protocol::decode_payload(input)) {
        require_same(protocol::encode_payload(*statement), input);
        // Run any proof of presence through the WebAuthn checks (DER, client
        // data, flags) against a credential with the same id.
        if (statement->presence) {
            const protocol::PresenceCredential credential{
                "localhost",
                statement->presence->credential_id,
                {cexchain::crypto::SigAlg::esp256, cexchain::Bytes(65, 0x04)},
                std::nullopt};
            static_cast<void>(protocol::verify_presence(provider, cexchain::crypto::HashAlg::sha256,
                                                        *statement, std::span(&credential, 1)));
        }
    }
    if (const auto credential = protocol::decode_presence_credential(input)) {
        require_same(protocol::encode_presence_credential(*credential), input);
    }
    if (const auto entry = protocol::decode_log_entry(input)) {
        require_same(protocol::encode_log_entry(*entry), input);
    }
    if (const auto checkpoint = protocol::decode_checkpoint(input)) {
        require_same(protocol::encode_checkpoint(*checkpoint), input);
    }
    if (const auto field = protocol::decode_field(input)) {
        require_same(protocol::encode_field(*field), input);
    }
    for (const auto hash : {cexchain::crypto::HashAlg::sha256, cexchain::crypto::HashAlg::sm3}) {
        if (const auto statement = protocol::parse_statement(provider, input, hash)) {
            require_same(protocol::encode_payload(statement->statement),
                         *statement->envelope.payload);
        }
    }
    if (const auto bundle = protocol::decode_bundle(input)) {
        require_same(protocol::encode_bundle(*bundle), input);
        static_cast<void>(protocol::verify_bundle(provider, input));
    }
    if (const auto request = protocol::decode_cosign_request(input)) {
        require_same(protocol::encode_cosign_request(*request), input);
        // A witness that has seen nothing yet, for whichever ledger the
        // request names, checks the request without crashing.
        protocol::WitnessedLog log;
        if (const auto checkpoint = protocol::parse_checkpoint(request->checkpoint)) {
            log.ledger_id = checkpoint->checkpoint.ledger_id;
        }
        log.log_key = {cexchain::crypto::SigAlg::ed25519, cexchain::Bytes(32, 0x11)};
        static_cast<void>(protocol::check_cosign_request(provider, log, *request));
    }
    static_cast<void>(protocol::parse_checkpoint(input));
    static_cast<void>(protocol::parse_cosignature(input));
    static_cast<void>(protocol::parse_receipt(input));
    return 0;
}
