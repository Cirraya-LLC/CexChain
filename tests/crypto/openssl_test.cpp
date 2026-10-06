// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_all.hpp>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>

#include <cexchain/core/crypto.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace crypto = cexchain::crypto;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::Errc;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::hex_field;
using cexchain::test::load_vectors;
using crypto::HashAlg;
using crypto::SigAlg;

namespace {
Bytes to_bytes(std::string_view text) {
    const auto view = as_bytes(text);
    return Bytes(view.begin(), view.end());
}
} // namespace
using crypto::openssl::KeyPair;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

Errc expected_error(const nlohmann::json& vector) {
    const std::string name = vector.value("expected_error", "verification_failed");
    if (name == "invalid_argument") {
        return Errc::invalid_argument;
    }
    REQUIRE(name == "verification_failed");
    return Errc::verification_failed;
}

} // namespace

TEST_CASE("OpenSSL provider supports every CexChain algorithm", "[crypto][openssl]") {
    for (const auto alg : crypto::all_hash_algs) {
        INFO(crypto::name(alg));
        CHECK(provider().supports(alg));
    }
    for (const auto alg : crypto::all_sig_algs) {
        INFO(crypto::name(alg));
        CHECK(provider().supports(alg));
    }
}

TEST_CASE("hash outputs match independent vectors", "[crypto][openssl][vectors]") {
    const auto document = load_vectors("hashes.json");
    for (const auto& vector : document["vectors"]) {
        const auto alg = crypto::hash_alg_from_cose(vector["algorithm"].get<std::int64_t>());
        REQUIRE(alg);
        const auto digest = provider().digest(*alg, hex_field(vector["message"]));
        REQUIRE(digest);
        CHECK(digest->size() == crypto::digest_size(*alg));
        CHECK(to_hex(digest->bytes()) == vector["digest"].get<std::string>());
    }
}

TEST_CASE("multi-part digest equals the digest of the concatenation", "[crypto][openssl]") {
    for (const auto alg : crypto::all_hash_algs) {
        const auto whole = provider().digest(alg, as_bytes("hello world"));
        const auto parts =
            provider().digest(alg, {as_bytes("hello"), as_bytes(""), as_bytes(" world")});
        REQUIRE(whole);
        REQUIRE(parts);
        CHECK(*whole == *parts);
    }
}

TEST_CASE("signatures from independent implementations verify", "[crypto][openssl][vectors]") {
    const auto document = load_vectors("signatures.json");
    int valid = 0;
    int invalid = 0;
    for (const auto& vector : document["vectors"]) {
        const auto alg = crypto::sig_alg_from_cose(vector["algorithm"].get<std::int64_t>());
        REQUIRE(alg);
        INFO(vector["name"].get<std::string>() << " from " << vector["source"].get<std::string>());
        const crypto::PublicKey key{*alg, hex_field(vector["public_key"])};
        const auto status =
            provider().verify(key, hex_field(vector["message"]), hex_field(vector["signature"]));
        if (vector["valid"].get<bool>()) {
            CHECK(status);
            ++valid;
        } else {
            REQUIRE_FALSE(status);
            CHECK(status.error().code == expected_error(vector));
            ++invalid;
        }
    }
    CHECK(valid == 16);
    CHECK(invalid == 48);
}

TEST_CASE("PKCS #8 vectors: valid keys load, malformed and mismatched keys do not",
          "[crypto][openssl][vectors]") {
    const auto document = load_vectors("pkcs8.json");
    for (const auto& vector : document["vectors"]) {
        INFO(vector["name"].get<std::string>());
        const auto key = KeyPair::from_pkcs8(hex_field(vector["der"]));
        if (vector["valid"].get<bool>()) {
            REQUIRE(key);
            CHECK(crypto::cose_id(key->algorithm()) == vector["algorithm"].get<std::int64_t>());
            CHECK(key->public_key().bytes == hex_field(vector["public_key"]));
        } else {
            REQUIRE_FALSE(key);
            CHECK(key.error().code == expected_error(vector));
        }
    }
}

TEST_CASE("ESP256 signatures are always produced in low-S form", "[crypto][openssl]") {
    const auto key = KeyPair::generate(SigAlg::esp256);
    REQUIRE(key);
    // Each signature has a one-in-two chance of being high-S before
    // normalization, so 64 signatures exercise both paths.
    for (int i = 0; i < 64; ++i) {
        const std::string message = "message " + std::to_string(i);
        const auto signature = key->sign(as_bytes(message));
        REQUIRE(signature);
        CHECK(crypto::is_canonical_signature(SigAlg::esp256, *signature));
        CHECK(provider().verify(key->public_key(), as_bytes(message), *signature));
    }
}

TEST_CASE("a moved-from key pair refuses to sign", "[crypto][openssl]") {
    auto key = KeyPair::generate(SigAlg::ed25519);
    REQUIRE(key);
    const KeyPair moved = std::move(*key);
    CHECK(moved.sign(as_bytes("x")));
    // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from state is under test.
    CHECK(key->sign(as_bytes("x")).error().code == Errc::invalid_argument);
    CHECK(key->to_pkcs8().error().code == Errc::invalid_argument);
    CHECK(key->public_key().bytes.empty());
}

TEST_CASE("generated keys sign and verify", "[crypto][openssl]") {
    const SigAlg alg = GENERATE(from_range(crypto::all_sig_algs));
    INFO(crypto::name(alg));

    auto key = KeyPair::generate(alg);
    REQUIRE(key);
    CHECK(key->algorithm() == alg);
    CHECK(key->public_key().algorithm == alg);
    CHECK(key->public_key().bytes.size() == crypto::public_key_size(alg));

    const auto message = as_bytes("CexChain");
    const auto signature = key->sign(message);
    REQUIRE(signature);
    CHECK(signature->size() == crypto::signature_size(alg));
    CHECK(provider().verify(key->public_key(), message, *signature));
    CHECK(provider().verify(key->public_key(), as_bytes("CexChaim"), *signature).error().code ==
          Errc::verification_failed);

    const auto other = KeyPair::generate(alg);
    REQUIRE(other);
    CHECK(provider().verify(other->public_key(), message, *signature).error().code ==
          Errc::verification_failed);

    const auto empty_signature = key->sign({});
    REQUIRE(empty_signature);
    CHECK(provider().verify(key->public_key(), {}, *empty_signature));
}

TEST_CASE("PKCS #8 export and import preserve the key", "[crypto][openssl]") {
    const SigAlg alg = GENERATE(from_range(crypto::all_sig_algs));
    INFO(crypto::name(alg));

    auto key = KeyPair::generate(alg);
    REQUIRE(key);
    const auto der = key->to_pkcs8();
    REQUIRE(der);
    CHECK_FALSE(der->empty());

    auto loaded = KeyPair::from_pkcs8(der->view());
    REQUIRE(loaded);
    CHECK(loaded->algorithm() == alg);
    CHECK(loaded->public_key() == key->public_key());

    const auto signature = loaded->sign(as_bytes("x"));
    REQUIRE(signature);
    CHECK(provider().verify(key->public_key(), as_bytes("x"), *signature));
}

TEST_CASE("Ed25519 seed import reproduces RFC 8032 test 2", "[crypto][openssl]") {
    auto key = KeyPair::from_ed25519_seed(
        hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    REQUIRE(key);
    CHECK(to_hex(key->public_key().bytes) ==
          "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    const auto signature = key->sign(hex("72"));
    REQUIRE(signature);
    CHECK(to_hex(*signature) == "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    CHECK(KeyPair::from_ed25519_seed(Bytes(31, 0)).error().code == Errc::invalid_argument);
}

TEST_CASE("verify rejects malformed keys and signatures", "[crypto][openssl]") {
    const auto key = KeyPair::generate(SigAlg::esp256);
    REQUIRE(key);
    const auto message = as_bytes("m");
    const auto signature = key->sign(message);
    REQUIRE(signature);

    const crypto::PublicKey short_key{SigAlg::esp256, Bytes(64, 0x04)};
    CHECK(provider().verify(short_key, message, *signature).error().code == Errc::invalid_argument);

    crypto::PublicKey compressed = key->public_key();
    compressed.bytes.front() = 0x02;
    CHECK(provider().verify(compressed, message, *signature).error().code ==
          Errc::invalid_argument);

    Bytes off_curve(65, 0x01);
    off_curve.front() = 0x04;
    CHECK(provider().verify({SigAlg::esp256, off_curve}, message, *signature).error().code ==
          Errc::invalid_argument);
    CHECK(provider().verify({SigAlg::sm2_sm3, off_curve}, message, *signature).error().code ==
          Errc::invalid_argument);

    CHECK(provider().verify(key->public_key(), message, Bytes(63, 0)).error().code ==
          Errc::verification_failed);
    CHECK(provider().verify(key->public_key(), message, Bytes(64, 0)).error().code ==
          Errc::verification_failed);
    CHECK(provider().verify(key->public_key(), message, Bytes(64, 0xff)).error().code ==
          Errc::verification_failed);
}

TEST_CASE("from_pkcs8 rejects input that is not a private key", "[crypto][openssl]") {
    CHECK(KeyPair::from_pkcs8(Bytes{}).error().code == Errc::invalid_argument);
    CHECK(KeyPair::from_pkcs8(hex("3000")).error().code == Errc::invalid_argument);
    CHECK(KeyPair::from_pkcs8(Bytes(100, 0x30)).error().code == Errc::invalid_argument);
}

TEST_CASE("passphrase-protected PKCS #8 round trip", "[crypto][openssl]") {
    const SigAlg alg = GENERATE(SigAlg::ed25519, SigAlg::sm2_sm3, SigAlg::ml_dsa_44);
    INFO(crypto::name(alg));
    const auto key = KeyPair::generate(alg);
    REQUIRE(key);
    const auto encrypted = key->to_encrypted_pkcs8("correct horse battery staple");
    REQUIRE(encrypted);
    CHECK(crypto::openssl::is_encrypted_pkcs8(*encrypted));
    CHECK_FALSE(crypto::openssl::is_encrypted_pkcs8(key->to_pkcs8()->view()));

    const auto loaded = KeyPair::from_encrypted_pkcs8(*encrypted, "correct horse battery staple");
    REQUIRE(loaded);
    CHECK(loaded->public_key() == key->public_key());
    CHECK(KeyPair::from_encrypted_pkcs8(*encrypted, "wrong").error().code ==
          Errc::verification_failed);
    CHECK(KeyPair::from_pkcs8(*encrypted).error().code == Errc::invalid_argument);
    CHECK(key->to_encrypted_pkcs8("").error().code == Errc::invalid_argument);
}

TEST_CASE("encrypted keys decode through OpenSSL's generic decoder", "[crypto][openssl]") {
    // The path other tools take (the openssl command line among them): format
    // detection, then decryption with the passphrase. The key files are
    // standard PKCS #8, not readable only by CexChain.
    const SigAlg alg =
        GENERATE(SigAlg::ed25519, SigAlg::esp256, SigAlg::sm2_sm3, SigAlg::ml_dsa_65);
    INFO(crypto::name(alg));
    const auto key = KeyPair::generate(alg);
    REQUIRE(key);
    const std::string secret = "correct horse battery staple";
    const auto encrypted = key->to_encrypted_pkcs8(secret);
    REQUIRE(encrypted);

    EVP_PKEY* pkey = nullptr;
    OSSL_DECODER_CTX* decoder = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", nullptr, nullptr,
                                                              EVP_PKEY_KEYPAIR, nullptr, nullptr);
    REQUIRE(decoder != nullptr);
    CHECK(OSSL_DECODER_CTX_set_passphrase(
              decoder, reinterpret_cast<const unsigned char*>(secret.data()), secret.size()) == 1);
    const unsigned char* data = encrypted->data();
    std::size_t length = encrypted->size();
    const int decoded = OSSL_DECODER_from_data(decoder, &data, &length);
    OSSL_DECODER_CTX_free(decoder);
    REQUIRE(decoded == 1);
    REQUIRE(pkey != nullptr);

    OSSL_ENCODER_CTX* encoder =
        OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, "DER", "PrivateKeyInfo", nullptr);
    unsigned char* plain = nullptr;
    std::size_t plain_length = 0;
    const int encoded =
        encoder != nullptr ? OSSL_ENCODER_to_data(encoder, &plain, &plain_length) : 0;
    OSSL_ENCODER_CTX_free(encoder);
    EVP_PKEY_free(pkey);
    REQUIRE(encoded == 1);
    const auto reloaded = KeyPair::from_pkcs8(cexchain::ByteView(plain, plain_length));
    OPENSSL_free(plain);
    REQUIRE(reloaded);
    CHECK(reloaded->public_key() == key->public_key());
}

TEST_CASE("HPKE seals to a public key and opens only with its private key",
          "[crypto][openssl][hpke]") {
    using crypto::openssl::HpkeKey;
    const auto key = HpkeKey::generate();
    REQUIRE(key);
    REQUIRE(key->public_key().size() == crypto::openssl::hpke_public_key_size);
    const Bytes info = to_bytes("CexChain test");
    const Bytes aad = to_bytes("record 1");
    const Bytes message = to_bytes("result = pass");

    const auto sealed = crypto::openssl::hpke_seal(key->public_key(), info, aad, message);
    REQUIRE(sealed);
    CHECK(sealed->encapsulated_key.size() == 32);
    CHECK(sealed->ciphertext.size() == message.size() + 16);

    const auto opened = key->open(*sealed, info, aad);
    REQUIRE(opened);
    CHECK(Bytes(opened->view().begin(), opened->view().end()) == message);

    // Each seal uses a fresh ephemeral key.
    const auto again = crypto::openssl::hpke_seal(key->public_key(), info, aad, message);
    REQUIRE(again);
    CHECK(again->encapsulated_key != sealed->encapsulated_key);

    // Wrong key, context, associated data, or altered ciphertext all fail.
    const auto other = HpkeKey::generate();
    REQUIRE(other);
    CHECK(other->open(*sealed, info, aad).error().code == Errc::verification_failed);
    CHECK(key->open(*sealed, to_bytes("other"), aad).error().code == Errc::verification_failed);
    CHECK(key->open(*sealed, info, to_bytes("record 2")).error().code == Errc::verification_failed);
    auto altered = *sealed;
    altered.ciphertext[0] ^= 1;
    CHECK(key->open(altered, info, aad).error().code == Errc::verification_failed);
    altered = *sealed;
    altered.ciphertext.pop_back();
    CHECK(key->open(altered, info, aad).error().code == Errc::verification_failed);

    CHECK(crypto::openssl::hpke_seal(Bytes(31, 1), info, aad, message).error().code ==
          Errc::invalid_argument);
    // A low-order point gives an all-zero shared secret, which must be refused.
    CHECK_FALSE(crypto::openssl::hpke_seal(Bytes(32, 0), info, aad, message));
}

TEST_CASE("HPKE keys round-trip through plain and encrypted PKCS #8", "[crypto][openssl][hpke]") {
    using crypto::openssl::HpkeKey;
    const auto key = HpkeKey::generate();
    REQUIRE(key);
    const auto plain = key->to_pkcs8();
    REQUIRE(plain);
    const auto reloaded = HpkeKey::from_pkcs8(plain->view());
    REQUIRE(reloaded);
    CHECK(Bytes(reloaded->public_key().begin(), reloaded->public_key().end()) ==
          Bytes(key->public_key().begin(), key->public_key().end()));

    const auto encrypted = key->to_encrypted_pkcs8("vault passphrase");
    REQUIRE(encrypted);
    CHECK(crypto::openssl::is_encrypted_pkcs8(*encrypted));
    const auto decrypted = HpkeKey::from_encrypted_pkcs8(*encrypted, "vault passphrase");
    REQUIRE(decrypted);
    const auto sealed = crypto::openssl::hpke_seal(key->public_key(), {}, {}, to_bytes("x"));
    REQUIRE(sealed);
    CHECK(decrypted->open(*sealed, {}, {}));
    CHECK(HpkeKey::from_encrypted_pkcs8(*encrypted, "wrong").error().code ==
          Errc::verification_failed);

    // Signing keys are not HPKE keys, and vice versa.
    const auto signing = KeyPair::generate(SigAlg::ed25519);
    REQUIRE(signing);
    CHECK(HpkeKey::from_pkcs8(signing->to_pkcs8()->view()).error().code == Errc::unsupported);
    CHECK_FALSE(KeyPair::from_pkcs8(plain->view()));
}
