// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_all.hpp>

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
using crypto::openssl::KeyPair;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
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
            CHECK(status.error().code == Errc::verification_failed);
            ++invalid;
        }
    }
    CHECK(valid == 16);
    CHECK(invalid == 32);
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
