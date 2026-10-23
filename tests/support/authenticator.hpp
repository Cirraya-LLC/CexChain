// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/statement.hpp>

// A software stand-in for a passkey authenticator, for tests: it registers
// (navigator.credentials.create) and signs in (navigator.credentials.get)
// as a browser on `origin` would report it.
namespace cexchain::test {

struct SoftPasskey {
    std::shared_ptr<const crypto::Signer> key;
    crypto::PublicKey public_key;
    Bytes credential_id;
    std::string rp_id = "localhost";
    std::string origin = "http://localhost:7470";
    /// User present and user verified.
    std::uint8_t flags = 0x05;

    [[nodiscard]] static Bytes sha256(const crypto::Provider& provider, ByteView data) {
        const auto digest = provider.digest(crypto::HashAlg::sha256, data);
        return Bytes(digest->bytes().begin(), digest->bytes().end());
    }

    [[nodiscard]] Bytes client_data(std::string_view type, ByteView challenge) const {
        const std::string text = "{\"type\":\"" + std::string(type) + "\",\"challenge\":\"" +
                                 to_base64url(challenge) + "\",\"origin\":\"" + origin +
                                 "\",\"crossOrigin\":false}";
        return Bytes(text.begin(), text.end());
    }

    /// The attestation object of a registration ("none" attestation), with
    /// the public key as an EC2 COSE key.
    [[nodiscard]] Bytes attestation(const crypto::Provider& provider) const {
        Bytes data = sha256(provider, as_bytes(rp_id));
        data.push_back(static_cast<std::uint8_t>(flags | 0x40)); // attested credential data
        data.insert(data.end(), {0, 0, 0, 0});
        data.insert(data.end(), 16, 0); // AAGUID
        data.push_back(0);
        data.push_back(static_cast<std::uint8_t>(credential_id.size()));
        data.insert(data.end(), credential_id.begin(), credential_id.end());
        const ByteView point = public_key.bytes;
        const auto cose_key = cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::integer(2)},
             {cbor::Value::integer(3), cbor::Value::integer(-7)},
             {cbor::Value::integer(-1), cbor::Value::integer(1)},
             {cbor::Value::integer(-2), cbor::Value::bytes(point.subspan(1, 32))},
             {cbor::Value::integer(-3), cbor::Value::bytes(point.subspan(33, 32))}});
        const Bytes encoded_key = *cbor::encode(cose_key);
        data.insert(data.end(), encoded_key.begin(), encoded_key.end());
        return *cbor::encode(
            cbor::Value::map({{cbor::Value::text("fmt"), cbor::Value::text("none")},
                              {cbor::Value::text("attStmt"), cbor::Value::map({})},
                              {cbor::Value::text("authData"), cbor::Value::bytes(data)}}));
    }

    /// An assertion over `challenge`: authenticator data, client data, and
    /// the signature in DER, as authenticators send it.
    [[nodiscard]] protocol::PresenceProof sign(const crypto::Provider& provider,
                                               ByteView challenge) const {
        Bytes data = sha256(provider, as_bytes(rp_id));
        data.push_back(flags);
        data.insert(data.end(), {0, 0, 0, 9});
        const Bytes client = client_data("webauthn.get", challenge);
        Bytes message = data;
        const Bytes client_hash = sha256(provider, client);
        message.insert(message.end(), client_hash.begin(), client_hash.end());
        const Bytes raw = *key->sign(message);
        return {credential_id, data, client, der_signature(raw)};
    }

private:
    [[nodiscard]] static Bytes der_integer(ByteView value) {
        std::size_t start = 0;
        while (start + 1 < value.size() && value[start] == 0) {
            ++start;
        }
        Bytes body(value.begin() + static_cast<std::ptrdiff_t>(start), value.end());
        if ((body[0] & 0x80U) != 0) {
            body.insert(body.begin(), 0x00);
        }
        Bytes out{0x02, static_cast<std::uint8_t>(body.size())};
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }

    [[nodiscard]] static Bytes der_signature(ByteView raw) {
        Bytes inner = der_integer(raw.first(32));
        const Bytes s = der_integer(raw.subspan(32));
        inner.insert(inner.end(), s.begin(), s.end());
        Bytes out{0x30, static_cast<std::uint8_t>(inner.size())};
        out.insert(out.end(), inner.begin(), inner.end());
        return out;
    }
};

} // namespace cexchain::test
