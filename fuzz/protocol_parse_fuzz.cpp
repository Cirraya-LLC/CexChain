// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Feeds arbitrary bytes to every protocol object parser. Whatever a decoder
// accepts, the matching encoder must reproduce byte for byte, so decoding and
// encoding can never disagree about what a structure means.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <kanhe/core/protocol/access.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/core/protocol/witness.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/ledger/verify.hpp>

namespace protocol = kanhe::protocol;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

template <class Encoded>
void require_same(const Encoded& encoded, kanhe::ByteView input) {
    require(encoded.has_value() && std::ranges::equal(*encoded, input));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const kanhe::crypto::openssl::Provider provider;
    const kanhe::ByteView input(data, size);

    if (const auto statement = protocol::decode_payload(input)) {
        require_same(protocol::encode_payload(*statement), input);
        // Run any proof of presence through the WebAuthn checks (DER, client
        // data, flags) against a credential with the same id.
        if (statement->presence) {
            const protocol::PresenceCredential credential{
                "localhost",
                statement->presence->credential_id,
                {kanhe::crypto::SigAlg::esp256, kanhe::Bytes(65, 0x04)},
                std::nullopt};
            const auto kid = *kanhe::crypto::Digest::from_bytes(kanhe::Bytes(32, 0x22));
            static_cast<void>(protocol::verify_presence(provider, kanhe::crypto::HashAlg::sha256,
                                                        *statement, kid,
                                                        std::span(&credential, 1)));
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
    if (const auto commitment = protocol::decode_state_commitment(input)) {
        require_same(protocol::encode_state_commitment(*commitment), input);
    }
    static_cast<void>(protocol::parse_state_commitment(provider, input));
    if (const auto field = protocol::decode_field(input)) {
        require_same(protocol::encode_field(*field), input);
    }
    for (const auto hash : {kanhe::crypto::HashAlg::sha256, kanhe::crypto::HashAlg::sm3}) {
        if (const auto statement = protocol::parse_statement(provider, input, hash)) {
            require_same(protocol::encode_payload(statement->statement),
                         *statement->envelope.payload);
        }
    }
    if (const auto bundle = protocol::decode_bundle(input)) {
        require_same(protocol::encode_bundle(*bundle), input);
        static_cast<void>(protocol::verify_bundle(provider, input));
        // The option paths too: a pinned ledger, a trusted witness, and
        // attachment contents to check.
        const auto ledger = protocol::bundle_ledger_id(input);
        protocol::VerifyOptions options;
        if (ledger) {
            options.expected_ledger = *ledger;
        }
        options.trusted_witnesses.push_back(
            {kanhe::crypto::SigAlg::ed25519, kanhe::Bytes(32, 0x33)});
        for (const auto& opening : bundle->attachments) {
            options.attachment_contents.emplace(
                opening.name, kanhe::Bytes(opening.name.begin(), opening.name.end()));
        }
        const auto report = protocol::verify_bundle(provider, input, options);
        if (report) {
            require(report->complete || !report->state_commitment);
        }
        // On all cores, with signatures remembered across inputs:
        // exactly core's outcome.
        static kanhe::ledger::SignatureCache remembered;
        const auto on_cores =
            kanhe::ledger::verify_bundle(provider, input, options, {true, &remembered});
        require(report.has_value() == on_cores.has_value());
        require(report ? *report == *on_cores : report.error() == on_cores.error());
        // The access checks, as each side would run them.
        if (ledger) {
            const auto other = *kanhe::crypto::Digest::from_bytes(kanhe::Bytes(32, 0x44));
            constexpr protocol::Timestamp now = 1'791'244'800'000;
            static_cast<void>(protocol::check_access_request(provider, input, *ledger, other, now));
            protocol::AccessRequest asked{
                *ledger,      other,        "fuzz",      now + 1, kanhe::Bytes(32, 7),
                std::nullopt, std::nullopt, std::nullopt};
            if (const auto grant = protocol::check_access_grant(provider, input, *ledger, other,
                                                                other, asked, now)) {
                static_cast<void>(protocol::check_delivered_record(
                    provider,
                    protocol::DeliveryContents{kanhe::Bytes(input.begin(), input.end()), {}},
                    *ledger, *grant));
            }
            static_cast<void>(protocol::check_access_receipt(provider, input, *ledger, other, other,
                                                             other, kanhe::Bytes(32)));
            // A claim answering a question (spec v0.15), as the asker checks it.
            protocol::AccessRequest question = asked;
            question.recipient = {};
            question.condition = std::vector<protocol::ClaimTerm>{
                {"result", "=", "text", kanhe::cbor::Value::text("pass")}};
            static_cast<void>(protocol::check_claim_answer(provider, input, *ledger, other, other,
                                                           question, now));
        }
    }
    if (const auto request = protocol::decode_cosign_request(input)) {
        require_same(protocol::encode_cosign_request(*request), input);
        // A witness that has seen nothing yet, for whichever ledger the
        // request names, checks the request without crashing.
        protocol::WitnessedLog log;
        if (const auto checkpoint = protocol::parse_checkpoint(request->checkpoint)) {
            log.ledger_id = checkpoint->checkpoint.ledger_id;
        }
        log.log_key = {kanhe::crypto::SigAlg::ed25519, kanhe::Bytes(32, 0x11)};
        static_cast<void>(protocol::check_cosign_request(provider, log, *request));
        // One that can follow key rotations (spec v0.4).
        log.root_key = {kanhe::crypto::SigAlg::ed25519, kanhe::Bytes(32, 0x22)};
        static_cast<void>(protocol::check_cosign_request(provider, log, *request));
    }
    // A log entry as a genesis, and as a key rotation to follow.
    if (const auto keys = protocol::keys_from_genesis(provider, input)) {
        require(keys->log_keys.size() == 1 && keys->last_rotation == 0);
    }
    protocol::LedgerKeys keys{*kanhe::crypto::Digest::from_bytes(kanhe::Bytes(32, 0x44)),
                              kanhe::crypto::HashAlg::sha256,
                              {kanhe::crypto::SigAlg::ed25519, kanhe::Bytes(32, 0x22)},
                              {{0, {kanhe::crypto::SigAlg::ed25519, kanhe::Bytes(32, 0x11)}}},
                              0};
    if (protocol::follow_key_rotation(provider, keys, 1, input)) {
        require(keys.log_keys.size() <= 2);
    }
    static_cast<void>(protocol::parse_checkpoint(input));
    static_cast<void>(protocol::parse_cosignature(input));
    static_cast<void>(protocol::parse_receipt(input));
    return 0;
}
