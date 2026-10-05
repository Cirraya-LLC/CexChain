// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

#include <cexchain/core/crypto.hpp>

namespace cexchain::crypto {

namespace {

constexpr std::uint8_t sec1_uncompressed_prefix = 0x04;

bool uses_sec1_point(SigAlg alg) noexcept {
    return alg == SigAlg::esp256 || alg == SigAlg::sm2_sm3;
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
    if (signature.size() != signature_size(key.algorithm)) {
        return fail(Errc::verification_failed, "signature has the wrong length for its algorithm");
    }
    return do_verify(key, message, signature);
}

} // namespace cexchain::crypto
