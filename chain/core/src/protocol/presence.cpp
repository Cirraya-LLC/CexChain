// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/presence.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

constexpr std::size_t rp_id_hash_size = 32;
constexpr std::size_t authenticator_data_header = 37; // rpIdHash, flags, signCount
constexpr std::size_t aaguid_size = 16;
constexpr std::uint8_t flag_user_present = 0x01;
constexpr std::uint8_t flag_user_verified = 0x04;
constexpr std::uint8_t flag_attested = 0x40;
constexpr std::uint8_t flag_extensions = 0x80;
constexpr std::size_t p256_scalar = 32;

// COSE key parameters (RFC 9053).
constexpr std::int64_t cose_kty = 1;
constexpr std::int64_t cose_alg = 3;
constexpr std::int64_t cose_crv = -1;
constexpr std::int64_t cose_x = -2;
constexpr std::int64_t cose_y = -3;
constexpr std::int64_t kty_okp = 1;
constexpr std::int64_t kty_ec2 = 2;
constexpr std::int64_t alg_es256 = -7;
constexpr std::int64_t alg_eddsa = -8;
constexpr std::int64_t crv_p256 = 1;
constexpr std::int64_t crv_ed25519 = 6;

std::string_view as_text_view(ByteView bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

/// DER ECDSA-Sig-Value (SEQUENCE of two INTEGERs) to raw r || s for P-256.
/// Strict DER: definite minimal lengths, minimal positive integers.
Result<Bytes> der_ecdsa_to_raw(ByteView der) {
    auto bad = [] {
        return fail(Errc::malformed, "the presence signature is not DER-encoded ECDSA");
    };
    if (der.size() < 8 || der[0] != 0x30) {
        return bad();
    }
    std::size_t length = der[1];
    std::size_t i = 2;
    if (length == 0x81) {
        if (der[2] < 0x80) {
            return bad();
        }
        length = der[2];
        i = 3;
    } else if (length > 0x7F) {
        return bad();
    }
    if (i + length != der.size()) {
        return bad();
    }
    Bytes raw(2 * p256_scalar, 0);
    for (std::size_t k = 0; k < 2; ++k) {
        if (i + 2 > der.size() || der[i] != 0x02) {
            return bad();
        }
        const std::size_t n = der[i + 1];
        i += 2;
        if (n == 0 || n > p256_scalar + 1 || i + n > der.size()) {
            return bad();
        }
        ByteView value = der.subspan(i, n);
        if ((value[0] & 0x80U) != 0 || (n > 1 && value[0] == 0 && (value[1] & 0x80U) == 0)) {
            return bad();
        }
        if (value[0] == 0) {
            value = value.subspan(1);
        }
        if (value.size() > p256_scalar) {
            return bad();
        }
        std::ranges::copy(
            value, raw.begin() + static_cast<std::ptrdiff_t>((k + 1) * p256_scalar - value.size()));
        i += n;
    }
    if (i != der.size()) {
        return bad();
    }
    return raw;
}

bool valid_port(std::string_view rest) {
    if (rest.size() < 2 || rest.size() > 6 || rest[0] != ':') {
        return false;
    }
    return std::ranges::all_of(rest.substr(1), [](char c) { return c >= '0' && c <= '9'; });
}

/// Checks WebAuthn client data with the limited verification algorithm
/// (WebAuthn Level 3, 5.8.1.2) and returns the origin.
Result<std::string> check_client_data(ByteView json, std::string_view type, ByteView challenge,
                                      std::string_view rp_id) {
    const std::string_view text = as_text_view(json);
    const std::string prefix = "{\"type\":\"" + std::string(type) + "\",\"challenge\":\"" +
                               to_base64url(challenge) + "\",\"origin\":\"";
    if (!text.starts_with(prefix) || !text.ends_with("}")) {
        return fail(Errc::verification_failed,
                    "the WebAuthn client data is not for this statement");
    }
    const std::string_view rest = text.substr(prefix.size());
    const std::size_t end = rest.find('"');
    if (end == std::string_view::npos) {
        return fail(Errc::verification_failed, "the WebAuthn client data is malformed");
    }
    const std::string_view origin = rest.substr(0, end);
    if (std::ranges::any_of(
            origin, [](char c) { return c == '\\' || static_cast<unsigned char>(c) < 0x20; })) {
        return fail(Errc::verification_failed, "the WebAuthn client data is malformed");
    }
    const std::string_view after = rest.substr(end + 1);
    if (after != "}" && !after.starts_with(",\"crossOrigin\":false}") &&
        !after.starts_with(",\"crossOrigin\":false,")) {
        return fail(Errc::verification_failed, "the WebAuthn ceremony ran in a cross-origin frame");
    }
    if (!origin_matches_rp_id(origin, rp_id)) {
        return fail(Errc::verification_failed,
                    "the WebAuthn origin does not belong to the credential's site");
    }
    return std::string(origin);
}

Status check_rp_id_hash(const crypto::Provider& provider, ByteView authenticator_data,
                        std::string_view rp_id) {
    CEXCHAIN_TRY(crypto::Digest expected,
                 provider.digest(crypto::HashAlg::sha256, as_bytes(rp_id)));
    if (!std::ranges::equal(expected.bytes(), authenticator_data.first(rp_id_hash_size))) {
        return fail(Errc::verification_failed, "the WebAuthn response is for another site");
    }
    return {};
}

Result<crypto::PublicKey> public_key_from_cose(const cbor::Value& value) {
    auto need_int = [&](std::int64_t key) -> Result<std::int64_t> {
        const cbor::Value* v = value.find(key);
        if (v == nullptr || !v->as_int64()) {
            return fail(Errc::malformed, "the credential's COSE key is malformed");
        }
        return *v->as_int64();
    };
    auto need_bytes = [&](std::int64_t key, std::size_t size) -> Result<Bytes> {
        const cbor::Value* v = value.find(key);
        if (v == nullptr || v->as_bytes() == nullptr || v->as_bytes()->size() != size) {
            return fail(Errc::malformed, "the credential's COSE key is malformed");
        }
        return *v->as_bytes();
    };
    CEXCHAIN_TRY(std::int64_t kty, need_int(cose_kty));
    CEXCHAIN_TRY(std::int64_t alg, need_int(cose_alg));
    CEXCHAIN_TRY(std::int64_t crv, need_int(cose_crv));
    if (kty == kty_ec2 && alg == alg_es256 && crv == crv_p256) {
        CEXCHAIN_TRY(Bytes x, need_bytes(cose_x, p256_scalar));
        CEXCHAIN_TRY(Bytes y, need_bytes(cose_y, p256_scalar));
        Bytes point{0x04};
        point.insert(point.end(), x.begin(), x.end());
        point.insert(point.end(), y.begin(), y.end());
        return crypto::PublicKey{crypto::SigAlg::esp256, std::move(point)};
    }
    if (kty == kty_okp && alg == alg_eddsa && crv == crv_ed25519) {
        CEXCHAIN_TRY(Bytes x, need_bytes(cose_x, 32));
        return crypto::PublicKey{crypto::SigAlg::ed25519, std::move(x)};
    }
    return fail(Errc::unsupported, "the passkey uses an algorithm other than ES256 or EdDSA");
}

Result<PresenceCheck> verify_webauthn(const crypto::Provider& provider,
                                      const PresenceCredential& credential,
                                      const PresenceProof& proof, ByteView challenge);

} // namespace

bool origin_matches_rp_id(std::string_view origin, std::string_view rp_id) {
    if (rp_id.empty()) {
        return false;
    }
    if (rp_id == "localhost") {
        for (const std::string_view scheme : {"http://localhost", "https://localhost"}) {
            if (origin.starts_with(scheme)) {
                const std::string_view rest = origin.substr(scheme.size());
                return rest.empty() || valid_port(rest);
            }
        }
        return false;
    }
    if (!origin.starts_with("https://")) {
        return false;
    }
    std::string_view host = origin.substr(8);
    if (const std::size_t colon = host.find(':'); colon != std::string_view::npos) {
        if (!valid_port(host.substr(colon))) {
            return false;
        }
        host = host.substr(0, colon);
    }
    return host == rp_id || (host.size() > rp_id.size() + 1 && host.ends_with(rp_id) &&
                             host[host.size() - rp_id.size() - 1] == '.');
}

Result<Bytes> presence_challenge(const crypto::Provider& provider, crypto::HashAlg ledger_hash,
                                 const Statement& statement, const Id& kid) {
    if (kid.size() != id_size) {
        return fail(Errc::invalid_argument, "a key id is 32 bytes");
    }
    Statement bare = statement;
    bare.presence.reset();
    CEXCHAIN_TRY(Bytes payload, encode_payload(bare));
    CEXCHAIN_TRY(crypto::Digest digest,
                 provider.digest(ledger_hash, {as_bytes(presence_context), kid.bytes(), payload}));
    return Bytes(digest.bytes().begin(), digest.bytes().end());
}

Result<PresenceCheck> verify_presence(const crypto::Provider& provider, crypto::HashAlg ledger_hash,
                                      const Statement& statement, const Id& kid,
                                      std::span<const PresenceCredential> credentials) {
    if (!statement.presence) {
        return fail(Errc::invalid_argument, "the statement carries no proof of presence");
    }
    const PresenceProof& proof = *statement.presence;
    const auto credential =
        std::ranges::find(credentials, proof.credential_id, &PresenceCredential::credential_id);
    if (credential == credentials.end()) {
        return fail(Errc::verification_failed, "the passkey is not registered for the signer");
    }
    if (credential->method == PresenceMethod::hardware_key) {
        // The token signs the challenge itself, after its PIN was entered.
        if (!proof.authenticator_data.empty() || !proof.client_data_json.empty()) {
            return fail(Errc::verification_failed,
                        "a hardware key's proof carries no WebAuthn data");
        }
        CEXCHAIN_TRY(Bytes challenge, presence_challenge(provider, ledger_hash, statement, kid));
        if (auto s = provider.verify(credential->key, challenge, proof.signature); !s) {
            return fail(Errc::verification_failed, "the hardware key's signature does not verify");
        }
        return PresenceCheck{false, {}, {}, credential->label, PresenceMethod::hardware_key};
    }
    CEXCHAIN_TRY(Bytes challenge, presence_challenge(provider, ledger_hash, statement, kid));
    return verify_webauthn(provider, *credential, proof, challenge);
}

Result<PresenceCheck> verify_assertion(const crypto::Provider& provider, ByteView challenge,
                                       const PresenceProof& proof,
                                       std::span<const PresenceCredential> credentials) {
    const auto credential =
        std::ranges::find(credentials, proof.credential_id, &PresenceCredential::credential_id);
    if (credential == credentials.end()) {
        return fail(Errc::verification_failed, "the passkey is not registered");
    }
    if (credential->method != PresenceMethod::webauthn) {
        return fail(Errc::verification_failed, "a hardware key cannot sign in");
    }
    return verify_webauthn(provider, *credential, proof, challenge);
}

namespace {

/// A passkey's assertion over `challenge`, for `credential`.
Result<PresenceCheck> verify_webauthn(const crypto::Provider& provider,
                                      const PresenceCredential& credential,
                                      const PresenceProof& proof, ByteView challenge) {
    if (proof.authenticator_data.empty()) {
        return fail(Errc::verification_failed, "a passkey's proof needs its WebAuthn data");
    }
    const ByteView data = proof.authenticator_data;
    if (data.size() < authenticator_data_header) {
        return fail(Errc::malformed, "the WebAuthn authenticator data is too short");
    }
    CEXCHAIN_CHECK(check_rp_id_hash(provider, data, credential.rp_id));
    const std::uint8_t flags = data[rp_id_hash_size];
    if ((flags & flag_user_present) == 0) {
        return fail(Errc::verification_failed,
                    "the authenticator did not confirm that a person was present");
    }
    CEXCHAIN_TRY(std::string origin, check_client_data(proof.client_data_json, "webauthn.get",
                                                       challenge, credential.rp_id));
    CEXCHAIN_TRY(crypto::Digest client_hash,
                 provider.digest(crypto::HashAlg::sha256, proof.client_data_json));
    Bytes message(data.begin(), data.end());
    message.insert(message.end(), client_hash.bytes().begin(), client_hash.bytes().end());
    Bytes signature = proof.signature;
    if (credential.key.algorithm == crypto::SigAlg::esp256) {
        // Authenticators sign in DER and need not use low-S.
        CEXCHAIN_TRY(signature, der_ecdsa_to_raw(proof.signature));
        crypto::canonicalize_signature(crypto::SigAlg::esp256, signature);
    }
    if (auto s = provider.verify(credential.key, message, signature); !s) {
        return fail(Errc::verification_failed, "the passkey signature does not verify");
    }
    return PresenceCheck{(flags & flag_user_verified) != 0, std::move(origin), credential.rp_id,
                         credential.label, PresenceMethod::webauthn};
}

} // namespace

Result<PresenceCredential> credential_from_registration(const crypto::Provider& provider,
                                                        ByteView attestation_object,
                                                        ByteView client_data_json,
                                                        ByteView challenge, std::string_view rp_id,
                                                        std::optional<std::string> label) {
    CEXCHAIN_TRY(std::string origin,
                 check_client_data(client_data_json, "webauthn.create", challenge, rp_id));
    static_cast<void>(origin);
    CEXCHAIN_TRY(cbor::Value object, cbor::decode(attestation_object));
    const cbor::Value* auth_data_value = object.find(std::string_view("authData"));
    if (auth_data_value == nullptr || auth_data_value->as_bytes() == nullptr) {
        return fail(Errc::malformed, "the attestation object has no authenticator data");
    }
    const ByteView data = *auth_data_value->as_bytes();
    if (data.size() < authenticator_data_header + aaguid_size + 2) {
        return fail(Errc::malformed, "the authenticator data is too short");
    }
    CEXCHAIN_CHECK(check_rp_id_hash(provider, data, rp_id));
    const std::uint8_t flags = data[rp_id_hash_size];
    if ((flags & flag_user_present) == 0) {
        return fail(Errc::verification_failed,
                    "the authenticator did not confirm that a person was present");
    }
    if ((flags & flag_attested) == 0) {
        return fail(Errc::malformed, "the registration carries no credential");
    }
    if ((flags & flag_extensions) != 0) {
        return fail(Errc::unsupported, "authenticator extensions are not supported");
    }
    std::size_t i = authenticator_data_header + aaguid_size;
    const std::size_t id_length = (std::size_t{data[i]} << 8U) | data[i + 1];
    i += 2;
    if (id_length == 0 || i + id_length > data.size()) {
        return fail(Errc::malformed, "the credential id does not fit the authenticator data");
    }
    PresenceCredential credential;
    credential.rp_id = std::string(rp_id);
    credential.credential_id.assign(data.begin() + static_cast<std::ptrdiff_t>(i),
                                    data.begin() + static_cast<std::ptrdiff_t>(i + id_length));
    i += id_length;
    CEXCHAIN_TRY(cbor::Value cose_key, cbor::decode(data.subspan(i)));
    CEXCHAIN_TRY(credential.key, public_key_from_cose(cose_key));
    if (crypto::is_weak_public_key(credential.key.algorithm, credential.key.bytes)) {
        return fail(Errc::rejected, "the passkey's public key is weak");
    }
    credential.label = std::move(label);
    // Round-trips through the statement encoding, which checks every limit.
    CEXCHAIN_TRY(Bytes encoded, encode_presence_credential(credential));
    return decode_presence_credential(encoded);
}

} // namespace cexchain::protocol
