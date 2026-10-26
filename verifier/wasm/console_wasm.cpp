// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's own checks, in the browser: before a person's passkey
// approves a statement, the page decodes the bytes it will approve with the
// core (not the console's description of them) and computes their presence
// challenge itself, so a tampered answer cannot obtain a tap for something
// else. A registration's fields and files are recomputed from what the
// person typed and chose. Exported as plain C functions; strings are JSON,
// freed with cexchain_free.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <emscripten/emscripten.h>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/record.hpp>
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
    } else if (const auto* g = std::get_if<protocol::RecordRegisterBody>(&s.body)) {
        out["record_type"] = g->record_type;
        out["field_count"] = g->field_count;
        out["field_root"] = to_hex(g->field_root);
        Json attachments = Json::array();
        for (const protocol::Attachment& a : g->attachments) {
            attachments.push_back({{"name", a.name},
                                   {"media_type", a.media_type},
                                   {"size", a.size},
                                   {"commitment", to_hex(a.commitment)}});
        }
        out["attachments"] = attachments;
        // Public metadata as the console writes it: text names and values.
        Json metadata = Json::object();
        if (g->metadata) {
            const cbor::Map* map = g->metadata->as_map();
            if (map == nullptr) {
                metadata = Json();
            } else {
                for (const auto& entry : *map) {
                    const std::string* key = entry.key.as_text();
                    const std::string* value = entry.value.as_text();
                    if (key == nullptr || value == nullptr) {
                        metadata = Json();
                        break;
                    }
                    metadata[*key] = *value;
                }
            }
        }
        out["metadata"] = metadata;
    }
    return out;
}

std::optional<protocol::Nonce> salt_of(const std::string& text) {
    const auto bytes = from_base64url(text);
    protocol::Nonce salt{};
    if (!bytes || bytes->size() != salt.size()) {
        return std::nullopt;
    }
    std::copy(bytes->begin(), bytes->end(), salt.begin());
    return salt;
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

/// The root of a record's fields, from what the person typed and the salts
/// the console chose: {"hash": COSE id, "fields": [{"name", "value",
/// "salt"}]}, values as text. So the page knows the registration commits to
/// exactly what it shows.
EMSCRIPTEN_KEEPALIVE char* cexchain_field_root(const char* request, std::size_t size) {
    const auto j = Json::parse(request, request + size, nullptr, false);
    const auto alg = j.is_object() && j.contains("hash") && j["hash"].is_number_integer()
                         ? crypto::hash_alg_from_cose(j["hash"].get<int>())
                         : std::nullopt;
    if (!alg || !j.contains("fields") || !j["fields"].is_array()) {
        return to_c_string({{"ok", false}, {"error", "send {hash, fields}"}});
    }
    std::vector<protocol::RecordField> fields;
    for (const auto& f : j["fields"]) {
        if (!f.is_object() || !f.contains("name") || !f["name"].is_string() ||
            !f.contains("value") || !f["value"].is_string() || !f.contains("salt") ||
            !f["salt"].is_string()) {
            return to_c_string({{"ok", false}, {"error", "a field is {name, value, salt}"}});
        }
        const auto salt = salt_of(f["salt"].get<std::string>());
        if (!salt) {
            return to_c_string({{"ok", false}, {"error", "a salt is 16 bytes, base64url"}});
        }
        fields.push_back({f["name"].get<std::string>(), *salt,
                          cbor::Value::text(f["value"].get<std::string>())});
    }
    const auto commitment = protocol::commit_fields(provider(), *alg, std::move(fields));
    if (!commitment) {
        return to_c_string({{"ok", false}, {"error", commitment.error().detail}});
    }
    return to_c_string({{"ok", true},
                        {"root", to_hex(commitment->root.bytes())},
                        {"count", commitment->leaves.size()}});
}

/// An attachment's commitment over the file's bytes and its salt.
EMSCRIPTEN_KEEPALIVE char* cexchain_attachment_commitment(const std::uint8_t* content,
                                                          std::size_t size,
                                                          const std::uint8_t* salt,
                                                          std::size_t salt_size, int hash) {
    const auto alg = crypto::hash_alg_from_cose(hash);
    protocol::Nonce nonce{};
    if (!alg || salt_size != nonce.size()) {
        return to_c_string({{"ok", false}, {"error", "not a salt or a hash"}});
    }
    std::copy(salt, salt + salt_size, nonce.begin());
    const auto digest =
        protocol::attachment_commitment(provider(), *alg, nonce, ByteView(content, size));
    if (!digest) {
        return to_c_string({{"ok", false}, {"error", digest.error().detail}});
    }
    return to_c_string({{"ok", true}, {"commitment", to_hex(digest->bytes())}});
}

EMSCRIPTEN_KEEPALIVE void cexchain_free(char* text) {
    std::free(text);
}

} // extern "C"
