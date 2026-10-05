// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>

/// Algorithm identifiers and the interfaces that cryptographic backends
/// implement. The core library performs no cryptography itself.
///
/// Identifiers are COSE algorithm values from the IANA "COSE Algorithms"
/// registry. Algorithms without a registered value use identifiers from the
/// private-use range (values below -65536).
///
/// Wire encodings:
///   - Ed25519 public keys are 32 bytes and signatures 64 bytes (RFC 8032).
///   - ESP256 and SM2 public keys are uncompressed SEC 1 points (0x04 || X || Y,
///     65 bytes). Their signatures are the fixed-size concatenation r || s
///     (64 bytes), as COSE specifies for ECDSA, not DER.
///   - ML-DSA public keys and signatures use the FIPS 204 encodings, with an
///     empty context string.
///   - SM2 uses SM3 and the GM/T 0009 default distinguishing identifier
///     "1234567812345678".
namespace cexchain::crypto {

enum class HashAlg : std::int32_t {
    sha256 = -16,
    sha384 = -43,
    sha512 = -44,
    sm3 = -65538, ///< Private use; SM3 has no registered COSE value.
};

enum class SigAlg : std::int32_t {
    esp256 = -9,      ///< ECDSA with P-256 and SHA-256.
    ed25519 = -19,    ///< EdDSA with Ed25519.
    ml_dsa_44 = -48,  ///< ML-DSA-44 (FIPS 204).
    ml_dsa_65 = -49,  ///< ML-DSA-65 (FIPS 204).
    ml_dsa_87 = -50,  ///< ML-DSA-87 (FIPS 204).
    sm2_sm3 = -65537, ///< Private use; SM2 with SM3 (GB/T 32918, GM/T 0009).
};

inline constexpr std::string_view sm2_distinguishing_id = "1234567812345678";

inline constexpr std::array all_hash_algs{HashAlg::sha256, HashAlg::sha384, HashAlg::sha512,
                                          HashAlg::sm3};

inline constexpr std::array all_sig_algs{SigAlg::esp256,    SigAlg::ed25519,   SigAlg::ml_dsa_44,
                                         SigAlg::ml_dsa_65, SigAlg::ml_dsa_87, SigAlg::sm2_sm3};

[[nodiscard]] constexpr std::int64_t cose_id(HashAlg alg) noexcept {
    return static_cast<std::int64_t>(alg);
}

[[nodiscard]] constexpr std::int64_t cose_id(SigAlg alg) noexcept {
    return static_cast<std::int64_t>(alg);
}

[[nodiscard]] std::optional<HashAlg> hash_alg_from_cose(std::int64_t id) noexcept;
[[nodiscard]] std::optional<SigAlg> sig_alg_from_cose(std::int64_t id) noexcept;

[[nodiscard]] std::string_view name(HashAlg alg) noexcept;
[[nodiscard]] std::string_view name(SigAlg alg) noexcept;

[[nodiscard]] std::size_t digest_size(HashAlg alg) noexcept;
[[nodiscard]] std::size_t public_key_size(SigAlg alg) noexcept;
[[nodiscard]] std::size_t signature_size(SigAlg alg) noexcept;

/// A hash output of up to 64 bytes, stored inline.
class Digest {
public:
    static constexpr std::size_t max_size = 64;

    Digest() noexcept = default;

    /// Fails if `bytes` is empty or longer than `max_size`.
    [[nodiscard]] static Result<Digest> from_bytes(ByteView bytes) noexcept;

    [[nodiscard]] ByteView bytes() const noexcept { return {data_.data(), size_}; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    friend bool operator==(const Digest& a, const Digest& b) noexcept;

private:
    std::array<std::uint8_t, max_size> data_{};
    std::size_t size_ = 0;
};

struct PublicKey {
    SigAlg algorithm;
    Bytes bytes;

    friend bool operator==(const PublicKey&, const PublicKey&) = default;
};

/// Holds a private key and produces signatures. Implementations may keep the
/// key in software, an HSM, or another device.
class Signer {
public:
    virtual ~Signer() = default;

    [[nodiscard]] virtual SigAlg algorithm() const noexcept = 0;
    [[nodiscard]] virtual const PublicKey& public_key() const noexcept = 0;

    /// Signs `message` (not a digest of it) and returns the signature in the
    /// algorithm's wire encoding.
    [[nodiscard]] virtual Result<Bytes> sign(ByteView message) const = 0;

protected:
    Signer() = default;
    Signer(const Signer&) = default;
    Signer(Signer&&) = default;
    Signer& operator=(const Signer&) = default;
    Signer& operator=(Signer&&) = default;
};

/// Hashing and signature verification. Implementations must be safe to call
/// concurrently from multiple threads.
class Provider {
public:
    virtual ~Provider() = default;

    [[nodiscard]] virtual bool supports(HashAlg alg) const noexcept = 0;
    [[nodiscard]] virtual bool supports(SigAlg alg) const noexcept = 0;

    /// Hashes `data`.
    [[nodiscard]] Result<Digest> digest(HashAlg alg, ByteView data) const;

    /// Hashes the concatenation of `parts` without materializing it.
    [[nodiscard]] Result<Digest> digest(HashAlg alg, std::span<const ByteView> parts) const;
    [[nodiscard]] Result<Digest> digest(HashAlg alg, std::initializer_list<ByteView> parts) const;

    /// Verifies `signature` over `message`.
    ///
    /// Returns `Errc::invalid_argument` if the key is malformed,
    /// `Errc::unsupported` if the algorithm is unavailable, and
    /// `Errc::verification_failed` if the signature is not valid.
    [[nodiscard]] Status verify(const PublicKey& key, ByteView message, ByteView signature) const;

protected:
    Provider() = default;
    Provider(const Provider&) = default;
    Provider(Provider&&) = default;
    Provider& operator=(const Provider&) = default;
    Provider& operator=(Provider&&) = default;

private:
    /// Called only for supported algorithms.
    [[nodiscard]] virtual Result<Digest> do_digest(HashAlg alg,
                                                   std::span<const ByteView> parts) const = 0;

    /// Called only for supported algorithms, with a key and signature whose
    /// sizes (and, for EC keys, point format prefix) have been checked.
    [[nodiscard]] virtual Status do_verify(const PublicKey& key, ByteView message,
                                           ByteView signature) const = 0;
};

} // namespace cexchain::crypto
