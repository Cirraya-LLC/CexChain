// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <memory>
#include <span>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Cryptographic backend built on OpenSSL 3.5 or later.
///
/// Key generation and signing draw randomness from OpenSSL's CSPRNG, which is
/// seeded by the operating system. This is intentional: the determinism rules
/// that govern protocol logic do not apply inside cryptographic primitives.
namespace cexchain::crypto::openssl {

class Provider final : public crypto::Provider {
public:
    /// Probes which algorithms the loaded libcrypto offers.
    Provider();
    ~Provider() override;

    Provider(const Provider&) = delete;
    Provider& operator=(const Provider&) = delete;
    Provider(Provider&&) = delete;
    Provider& operator=(Provider&&) = delete;

    [[nodiscard]] bool supports(HashAlg alg) const noexcept override;
    [[nodiscard]] bool supports(SigAlg alg) const noexcept override;

private:
    [[nodiscard]] Result<Digest> do_digest(HashAlg alg,
                                           std::span<const ByteView> parts) const override;
    [[nodiscard]] Status do_verify(const PublicKey& key, ByteView message,
                                   ByteView signature) const override;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Fills `out` from OpenSSL's CSPRNG (seeded by the operating system).
[[nodiscard]] Status random_bytes(std::span<std::uint8_t> out);

/// A software key pair held in OpenSSL. ESP256 signatures are returned in
/// low-S form. A moved-from KeyPair reports an empty public key and refuses to
/// sign or export.
class KeyPair final : public crypto::Signer {
public:
    /// Generates a new key pair.
    [[nodiscard]] static Result<KeyPair> generate(SigAlg alg);

    /// Loads an unencrypted PKCS #8 PrivateKeyInfo (DER). Other formats are
    /// rejected, as is a key whose embedded public key does not match its
    /// private key.
    [[nodiscard]] static Result<KeyPair> from_pkcs8(ByteView der);

    /// Imports an Ed25519 private key from its 32-byte seed (RFC 8032).
    [[nodiscard]] static Result<KeyPair> from_ed25519_seed(ByteView seed);

    KeyPair(KeyPair&&) noexcept;
    KeyPair& operator=(KeyPair&&) noexcept;
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
    ~KeyPair() override;

    [[nodiscard]] SigAlg algorithm() const noexcept override;
    [[nodiscard]] const PublicKey& public_key() const noexcept override;
    [[nodiscard]] Result<Bytes> sign(ByteView message) const override;

    /// Exports the private key as an unencrypted PKCS #8 PrivateKeyInfo (DER).
    [[nodiscard]] Result<SecureBytes> to_pkcs8() const;

private:
    struct Impl;
    explicit KeyPair(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::crypto::openssl
