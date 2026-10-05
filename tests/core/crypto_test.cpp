// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/crypto.hpp>

namespace crypto = cexchain::crypto;
using cexchain::Bytes;
using cexchain::Errc;

TEST_CASE("COSE identifiers map to algorithms and back", "[core][crypto]") {
    for (const auto alg : crypto::all_hash_algs) {
        CHECK(crypto::hash_alg_from_cose(crypto::cose_id(alg)) == alg);
        CHECK(crypto::digest_size(alg) > 0);
    }
    for (const auto alg : crypto::all_sig_algs) {
        CHECK(crypto::sig_alg_from_cose(crypto::cose_id(alg)) == alg);
        CHECK(crypto::public_key_size(alg) > 0);
        CHECK(crypto::signature_size(alg) > 0);
    }
    CHECK_FALSE(crypto::sig_alg_from_cose(-7)); // ES256 is deprecated; CexChain uses ESP256.
    CHECK_FALSE(crypto::sig_alg_from_cose(-8)); // Polymorphic EdDSA; CexChain uses Ed25519.
    CHECK_FALSE(crypto::hash_alg_from_cose(0));
}

TEST_CASE("registered identifiers match the IANA COSE registry", "[core][crypto]") {
    CHECK(crypto::cose_id(crypto::SigAlg::esp256) == -9);
    CHECK(crypto::cose_id(crypto::SigAlg::ed25519) == -19);
    CHECK(crypto::cose_id(crypto::SigAlg::ml_dsa_44) == -48);
    CHECK(crypto::cose_id(crypto::SigAlg::ml_dsa_65) == -49);
    CHECK(crypto::cose_id(crypto::SigAlg::ml_dsa_87) == -50);
    CHECK(crypto::cose_id(crypto::HashAlg::sha256) == -16);
    CHECK(crypto::cose_id(crypto::HashAlg::sha384) == -43);
    CHECK(crypto::cose_id(crypto::HashAlg::sha512) == -44);
    // Private-use identifiers must lie below -65536.
    CHECK(crypto::cose_id(crypto::SigAlg::sm2_sm3) < -65536);
    CHECK(crypto::cose_id(crypto::HashAlg::sm3) < -65536);
}

TEST_CASE("Digest holds 1 to 64 bytes", "[core][crypto]") {
    CHECK(crypto::Digest::from_bytes(Bytes{}).error().code == Errc::invalid_argument);
    CHECK(crypto::Digest::from_bytes(Bytes(65, 0)).error().code == Errc::invalid_argument);
    const auto a = crypto::Digest::from_bytes(Bytes(32, 0xab));
    const auto b = crypto::Digest::from_bytes(Bytes(32, 0xab));
    const auto c = crypto::Digest::from_bytes(Bytes(31, 0xab));
    REQUIRE(a);
    REQUIRE(b);
    REQUIRE(c);
    CHECK(*a == *b);
    CHECK_FALSE(*a == *c);
    CHECK(a->size() == 32);
    CHECK(crypto::Digest{}.empty());
}
