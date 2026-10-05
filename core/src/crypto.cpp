// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <compare>

#include <cexchain/core/crypto.hpp>

namespace cexchain::crypto {

namespace {

constexpr std::uint8_t sec1_uncompressed_prefix = 0x04;

bool uses_sec1_point(SigAlg alg) noexcept {
    return alg == SigAlg::esp256 || alg == SigAlg::sm2_sm3;
}

using Scalar = std::array<std::uint8_t, 32>;

// Constants below are re-derived by tools/crypto/derive_constants.py.

/// P-256 group order n and floor(n / 2), big-endian.
constexpr Scalar p256_order = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
                               0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
constexpr Scalar p256_half_order = {
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8};

/// Ed25519 group order L, little-endian.
constexpr Scalar ed25519_order = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                  0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/// The distinct y-coordinates (little-endian) of Ed25519's eight torsion
/// points: orders 4, 1, 8, 8, and 2.
constexpr std::array<Scalar, 5> ed25519_small_order_y = {{
    {},
    {0x01},
    {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
     0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
     0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
    {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
     0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
     0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
    {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}};

/// Compares two little-endian numbers of equal length.
std::strong_ordering compare_le(ByteView a, ByteView b) noexcept {
    for (std::size_t i = a.size(); i-- > 0;) {
        if (a[i] != b[i]) {
            return a[i] <=> b[i];
        }
    }
    return std::strong_ordering::equal;
}

/// Compares two big-endian numbers of equal length.
std::strong_ordering compare_be(ByteView a, ByteView b) noexcept {
    return std::lexicographical_compare_three_way(a.begin(), a.end(), b.begin(), b.end());
}

} // namespace

std::optional<HashAlg> hash_alg_from_cose(std::int64_t id) noexcept {
    for (const HashAlg alg : all_hash_algs) {
        if (cose_id(alg) == id) {
            return alg;
        }
    }
    return std::nullopt;
}

std::optional<SigAlg> sig_alg_from_cose(std::int64_t id) noexcept {
    for (const SigAlg alg : all_sig_algs) {
        if (cose_id(alg) == id) {
            return alg;
        }
    }
    return std::nullopt;
}

std::string_view name(HashAlg alg) noexcept {
    switch (alg) {
    case HashAlg::sha256:
        return "SHA-256";
    case HashAlg::sha384:
        return "SHA-384";
    case HashAlg::sha512:
        return "SHA-512";
    case HashAlg::sm3:
        return "SM3";
    }
    return "unknown";
}

std::string_view name(SigAlg alg) noexcept {
    switch (alg) {
    case SigAlg::esp256:
        return "ESP256";
    case SigAlg::ed25519:
        return "Ed25519";
    case SigAlg::ml_dsa_44:
        return "ML-DSA-44";
    case SigAlg::ml_dsa_65:
        return "ML-DSA-65";
    case SigAlg::ml_dsa_87:
        return "ML-DSA-87";
    case SigAlg::sm2_sm3:
        return "SM2-SM3";
    }
    return "unknown";
}

std::size_t digest_size(HashAlg alg) noexcept {
    switch (alg) {
    case HashAlg::sha256:
    case HashAlg::sm3:
        return 32;
    case HashAlg::sha384:
        return 48;
    case HashAlg::sha512:
        return 64;
    }
    return 0;
}

std::size_t public_key_size(SigAlg alg) noexcept {
    switch (alg) {
    case SigAlg::esp256:
    case SigAlg::sm2_sm3:
        return 65;
    case SigAlg::ed25519:
        return 32;
    case SigAlg::ml_dsa_44:
        return 1312;
    case SigAlg::ml_dsa_65:
        return 1952;
    case SigAlg::ml_dsa_87:
        return 2592;
    }
    return 0;
}

std::size_t signature_size(SigAlg alg) noexcept {
    switch (alg) {
    case SigAlg::esp256:
    case SigAlg::sm2_sm3:
    case SigAlg::ed25519:
        return 64;
    case SigAlg::ml_dsa_44:
        return 2420;
    case SigAlg::ml_dsa_65:
        return 3309;
    case SigAlg::ml_dsa_87:
        return 4627;
    }
    return 0;
}

bool is_weak_public_key(SigAlg alg, ByteView key) noexcept {
    if (alg != SigAlg::ed25519 || key.size() != 32) {
        return false;
    }
    Scalar y{};
    std::ranges::copy(key, y.begin());
    y[31] &= 0x7f; // Drop the sign bit of x.

    // Non-canonical: y >= p = 2^255 - 19, i.e. 0x7fff...ffed in little-endian.
    const bool middle_all_ones =
        std::ranges::all_of(ByteView(y).subspan(1, 30), [](std::uint8_t b) { return b == 0xff; });
    if (y[31] == 0x7f && middle_all_ones && y[0] >= 0xed) {
        return true;
    }
    return std::ranges::find(ed25519_small_order_y, y) != ed25519_small_order_y.end();
}

bool is_canonical_signature(SigAlg alg, ByteView signature) noexcept {
    switch (alg) {
    case SigAlg::esp256:
        return signature.size() == 64 &&
               compare_be(signature.subspan(32), p256_half_order) != std::strong_ordering::greater;
    case SigAlg::ed25519:
        return signature.size() == 64 &&
               compare_le(signature.subspan(32), ed25519_order) == std::strong_ordering::less;
    default:
        return true;
    }
}

void canonicalize_signature(SigAlg alg, std::span<std::uint8_t> signature) noexcept {
    if (alg != SigAlg::esp256 || signature.size() != 64 || is_canonical_signature(alg, signature)) {
        return;
    }
    // s := n - s, big-endian subtraction with borrow.
    const std::span<std::uint8_t> s = signature.subspan(32);
    int borrow = 0;
    for (std::size_t i = s.size(); i-- > 0;) {
        const int difference = int{p256_order[i]} - int{s[i]} - borrow;
        borrow = difference < 0 ? 1 : 0;
        s[i] = static_cast<std::uint8_t>(difference + (borrow << 8));
    }
}

Result<Digest> Digest::from_bytes(ByteView bytes) noexcept {
    if (bytes.empty() || bytes.size() > max_size) {
        return fail(Errc::invalid_argument, "digest must be 1 to 64 bytes");
    }
    Digest digest;
    std::ranges::copy(bytes, digest.data_.begin());
    digest.size_ = bytes.size();
    return digest;
}

bool operator==(const Digest& a, const Digest& b) noexcept {
    return std::ranges::equal(a.bytes(), b.bytes());
}

Result<Digest> Provider::digest(HashAlg alg, ByteView data) const {
    return digest(alg, std::span<const ByteView>(&data, 1));
}

Result<Digest> Provider::digest(HashAlg alg, std::span<const ByteView> parts) const {
    if (!supports(alg)) {
        return fail(Errc::unsupported, "hash algorithm is not supported by this provider");
    }
    return do_digest(alg, parts);
}

Result<Digest> Provider::digest(HashAlg alg, std::initializer_list<ByteView> parts) const {
    return digest(alg, std::span<const ByteView>(parts.begin(), parts.size()));
}

Status Provider::verify(const PublicKey& key, ByteView message, ByteView signature) const {
    if (!supports(key.algorithm)) {
        return fail(Errc::unsupported, "signature algorithm is not supported by this provider");
    }
    if (key.bytes.size() != public_key_size(key.algorithm)) {
        return fail(Errc::invalid_argument, "public key has the wrong length for its algorithm");
    }
    if (uses_sec1_point(key.algorithm) && key.bytes.front() != sec1_uncompressed_prefix) {
        return fail(Errc::invalid_argument, "EC public key is not an uncompressed SEC 1 point");
    }
    if (is_weak_public_key(key.algorithm, key.bytes)) {
        return fail(Errc::invalid_argument,
                    "public key has small order or a non-canonical encoding");
    }
    if (signature.size() != signature_size(key.algorithm)) {
        return fail(Errc::verification_failed, "signature has the wrong length for its algorithm");
    }
    if (!is_canonical_signature(key.algorithm, signature)) {
        return fail(Errc::verification_failed, "signature is not in canonical form");
    }
    return do_verify(key, message, signature);
}

} // namespace cexchain::crypto
