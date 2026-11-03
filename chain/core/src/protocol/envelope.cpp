// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "envelope.hpp"

#include <string>

namespace cexchain::protocol::detail {

Result<Bytes> sign_envelope(const crypto::Signer& signer, const crypto::Provider& provider,
                            crypto::HashAlg hash, ByteView payload, std::string_view content_type) {
    auto kid = key_id(provider, hash, signer.public_key());
    if (!kid) {
        return std::unexpected(kid.error());
    }
    cose::SignOptions options;
    options.protected_header = {
        {cbor::Value::integer(cose::label_content_type),
         cbor::Value::text(std::string(content_type))},
        {cbor::Value::integer(cose::label_kid), cbor::Value::bytes(kid->bytes())},
    };
    return cose::sign(signer, payload, options);
}

Result<Envelope> parse_envelope(ByteView encoded, std::string_view content_type) {
    auto message = cose::parse(encoded);
    if (!message) {
        return std::unexpected(message.error());
    }
    const cbor::Map* protected_map = message->protected_header.as_map();
    if (protected_map == nullptr || protected_map->size() != 3) {
        return fail(Errc::malformed, "protected header must be exactly {alg, content type, kid}");
    }
    const cbor::Value* type = message->protected_header.find(cose::label_content_type);
    const cbor::Value* kid = message->protected_header.find(cose::label_kid);
    if (type == nullptr || kid == nullptr) {
        return fail(Errc::malformed, "protected header must be exactly {alg, content type, kid}");
    }
    const std::string* type_text = type->as_text();
    if (type_text == nullptr || *type_text != content_type) {
        return fail(Errc::malformed, "unexpected content type");
    }
    const Bytes* kid_bytes = kid->as_bytes();
    if (kid_bytes == nullptr) {
        return fail(Errc::malformed, "kid must be a byte string");
    }
    auto kid_id = to_id(*kid_bytes);
    if (!kid_id) {
        return std::unexpected(kid_id.error());
    }
    const cbor::Map* unprotected = message->unprotected_header.as_map();
    if (unprotected == nullptr || !unprotected->empty()) {
        return fail(Errc::malformed, "unprotected header must be empty");
    }
    if (!message->payload) {
        return fail(Errc::malformed, "payload must be attached");
    }
    return Envelope{std::move(*message), *kid_id};
}

Status verify_envelope(const crypto::Provider& provider, crypto::HashAlg hash,
                       const Envelope& envelope, const crypto::PublicKey& key) {
    auto expected = key_id(provider, hash, key);
    if (!expected) {
        return std::unexpected(expected.error());
    }
    if (*expected != envelope.kid) {
        return fail(Errc::verification_failed, "key does not match the kid in the header");
    }
    return cose::verify(provider, envelope.message, key);
}

} // namespace cexchain::protocol::detail
