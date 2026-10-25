// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's own checks, in the browser: before a person's passkey
// approves a statement, the page decodes the bytes it will approve with the
// core (not the console's description of them) and computes their presence
// challenge itself, so a tampered answer cannot obtain a tap for something
// else. Exported as plain C functions; strings are JSON, freed with
// cexchain_free.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <emscripten/emscripten.h>
#include <optional>
#include <string>
#include <variant>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/verifier/report.hpp>

namespace {

using namespace cexchain;
using verifier::Json;

const crypto::openssl::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

char* to_c_string(const Json& value) {
    const std::string text = value.dump(-1, ' ', false, Json::error_handler_t::replace);
    char* out = static_cast<char*>(std::malloc(text.size() + 1));
    if (out != nullptr) {
        std::memcpy(out, text.c_str(), text.size() + 1);
    }
    return out;
}

Json hex_or_null(const std::optional<protocol::Id>& id) {
    return id ? Json(to_hex(id->bytes())) : Json();
}

/// What a statement says, for the person about to approve it: its type and
/// signer, and the fields of the actions the console prepares.
Json describe(const protocol::Statement& s) {
    Json out{{"ok", true},
             {"type", std::string(protocol::name(protocol::type_of(s.body)))},
             {"ledger", hex_or_null(s.ledger_id)},
             {"actor", hex_or_null(s.actor_id)},
             {"delegation", hex_or_null(s.delegation_id)},
             {"issued_at", s.issued_at}};
    if (const auto* e = std::get_if<protocol::RecordEndorseBody>(&s.body)) {
        out["record"] = to_hex(e->record.bytes());
        out["role"] = e->role;
    } else if (const auto* r = std::get_if<protocol::RecordRevokeBody>(&s.body)) {
        out["record"] = to_hex(r->record.bytes());
        out["reason"] = r->reason ? Json(*r->reason) : Json();
    }
    return out;
}

} // namespace

extern "C" {

EMSCRIPTEN_KEEPALIVE char* cexchain_describe_payload(const std::uint8_t* payload,
                                                     std::size_t size) {
    const auto statement = protocol::decode_payload(ByteView(payload, size));
    if (!statement) {
        return to_c_string({{"ok", false}, {"error", statement.error().detail}});
    }
    return to_c_string(describe(*statement));
}

/// The presence challenge of a payload signed with the key `kid` on a ledger
/// whose hash is `hash` (its COSE id), as base64url.
EMSCRIPTEN_KEEPALIVE char* cexchain_presence_challenge(const std::uint8_t* payload,
                                                       std::size_t size, const std::uint8_t* kid,
                                                       std::size_t kid_size, int hash) {
    const auto statement = protocol::decode_payload(ByteView(payload, size));
    const auto alg = crypto::hash_alg_from_cose(hash);
    const auto id = protocol::to_id(ByteView(kid, kid_size));
    if (!statement || !alg || !id) {
        return to_c_string({{"ok", false}, {"error", "not a payload, a key id, or a hash"}});
    }
    const auto challenge = protocol::presence_challenge(provider(), *alg, *statement, *id);
    if (!challenge) {
        return to_c_string({{"ok", false}, {"error", challenge.error().detail}});
    }
    return to_c_string({{"ok", true}, {"challenge", to_base64url(*challenge)}});
}

EMSCRIPTEN_KEEPALIVE void cexchain_free(char* text) {
    std::free(text);
}

} // extern "C"
