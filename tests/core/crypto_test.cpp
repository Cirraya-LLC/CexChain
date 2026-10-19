// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

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

TEST_CASE("ESP256 low-S boundary and canonicalization", "[core][crypto]") {
    // n/2 and n for P-256, big-endian (see tools/crypto/derive_constants.py).
    const auto half =
        *cexchain::from_hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");
    const auto order =
        *cexchain::from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    // r || s, each 32 bytes, written in place (GCC 16.2 reports a false
    // -Warray-bounds on growing a vector here, in release builds).
    Bytes at_half(64, 0x11);
    std::ranges::copy(half, at_half.begin() + 32);
    CHECK(crypto::is_canonical_signature(crypto::SigAlg::esp256, at_half));

    Bytes above_half = at_half;
    above_half.back() = 0xa9; // n/2 + 1
    CHECK_FALSE(crypto::is_canonical_signature(crypto::SigAlg::esp256, above_half));

    // Canonicalizing s = n/2 + 1 gives n - (n/2 + 1) = n/2 (n is odd).
    Bytes normalized = above_half;
    crypto::canonicalize_signature(crypto::SigAlg::esp256, normalized);
    CHECK(normalized == at_half);
    crypto::canonicalize_signature(crypto::SigAlg::esp256, normalized);
    CHECK(normalized == at_half); // idempotent

    // s = n - 1 becomes 1.
    Bytes near_order(64, 0x22);
    std::ranges::copy(order, near_order.begin() + 32);
    near_order.back() = 0x50;
    crypto::canonicalize_signature(crypto::SigAlg::esp256, near_order);
    Bytes one(32, 0);
    one.back() = 1;
    CHECK(Bytes(near_order.begin() + 32, near_order.end()) == one);

    // Other algorithms are left alone.
    Bytes sm2 = above_half;
    crypto::canonicalize_signature(crypto::SigAlg::sm2_sm3, sm2);
    CHECK(sm2 == above_half);
    CHECK(crypto::is_canonical_signature(crypto::SigAlg::sm2_sm3, above_half));
    CHECK(crypto::is_canonical_signature(crypto::SigAlg::ml_dsa_65, Bytes(3309, 0xff)));
}

TEST_CASE("Ed25519 signature scalar must be reduced", "[core][crypto]") {
    const auto order =
        *cexchain::from_hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    Bytes signature(32, 0x33);
    signature.insert(signature.end(), order.begin(), order.end()); // S = L
    CHECK_FALSE(crypto::is_canonical_signature(crypto::SigAlg::ed25519, signature));
    signature[32] = 0xec; // S = L - 1
    CHECK(crypto::is_canonical_signature(crypto::SigAlg::ed25519, signature));
}

TEST_CASE("weak Ed25519 public keys are recognized", "[core][crypto]") {
    for (const char* weak : {
             "0000000000000000000000000000000000000000000000000000000000000000",
             "0000000000000000000000000000000000000000000000000000000000000080",
             "0100000000000000000000000000000000000000000000000000000000000000",
             "0100000000000000000000000000000000000000000000000000000000000080",
             "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
             "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
             "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
             "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
             "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
         }) {
        INFO(weak);
        CHECK(crypto::is_weak_public_key(crypto::SigAlg::ed25519, *cexchain::from_hex(weak)));
    }
    // The RFC 8032 test 1 key and the largest canonical y (p - 1 with high bits
    // varied) are fine.
    CHECK_FALSE(crypto::is_weak_public_key(
        crypto::SigAlg::ed25519,
        *cexchain::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")));
    CHECK_FALSE(crypto::is_weak_public_key(
        crypto::SigAlg::ed25519,
        *cexchain::from_hex("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")));
    // Only Ed25519 has this notion.
    CHECK_FALSE(crypto::is_weak_public_key(crypto::SigAlg::esp256, Bytes(65, 0)));
}
