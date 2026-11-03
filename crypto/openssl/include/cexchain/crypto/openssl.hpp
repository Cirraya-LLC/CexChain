// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

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

/// The loaded libcrypto's version, e.g. "OpenSSL 3.6.0 1 Oct 2025".
[[nodiscard]] std::string_view library_version() noexcept;

/// True if `der` is a PKCS #8 EncryptedPrivateKeyInfo.
[[nodiscard]] bool is_encrypted_pkcs8(ByteView der);

/// Fills `out` from OpenSSL's CSPRNG (seeded by the operating system).
[[nodiscard]] Status random_bytes(std::span<std::uint8_t> out);

/// HMAC (RFC 2104) of `message` under `key` with the hash `alg` (SHA-256 or
/// SM3, for example), as OpenSSL's EVP_MAC computes it. Not part of the
/// protocol: executors sign the requests they send to webhooks with it.
[[nodiscard]] Result<Digest> hmac(HashAlg alg, ByteView key, ByteView message);

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

    /// Loads a passphrase-protected PKCS #8 EncryptedPrivateKeyInfo (DER).
    /// Fails with `Errc::verification_failed` if the passphrase is wrong.
    [[nodiscard]] static Result<KeyPair> from_encrypted_pkcs8(ByteView der,
                                                              std::string_view passphrase);

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

    /// Exports the private key as a PKCS #8 EncryptedPrivateKeyInfo (DER):
    /// PBES2 with scrypt (N = 2^14, r = 8, p = 1, the OpenSSL CLI default,
    /// within OpenSSL's default scrypt memory limit) and AES-256-CBC.
    [[nodiscard]] Result<Bytes> to_encrypted_pkcs8(std::string_view passphrase) const;

private:
    struct Impl;
    explicit KeyPair(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Public-key encryption (HPKE, RFC 9180)
// ---------------------------------------------------------------------------

/// The one HPKE suite CexChain uses, in base mode: DHKEM(X25519, HKDF-SHA256),
/// HKDF-SHA256, and AES-256-GCM. The identifiers are those of RFC 9180 and
/// are stored with sealed data, so other suites can be added later.
struct HpkeSuite {
    std::uint16_t kem = 0x0020;
    std::uint16_t kdf = 0x0001;
    std::uint16_t aead = 0x0002;

    friend bool operator==(const HpkeSuite&, const HpkeSuite&) = default;
};

inline constexpr HpkeSuite hpke_suite{};
inline constexpr std::size_t hpke_public_key_size = 32;

/// Data sealed to a recipient's public key.
struct HpkeSealed {
    /// The encapsulated (ephemeral) key.
    Bytes encapsulated_key;
    Bytes ciphertext;
};

/// Encrypts `plaintext` to `recipient`, an X25519 public key. `info` binds
/// the key schedule to an application context and `aad` is authenticated
/// with the ciphertext; the recipient must supply both unchanged.
[[nodiscard]] Result<HpkeSealed> hpke_seal(ByteView recipient, ByteView info, ByteView aad,
                                           ByteView plaintext);

/// An X25519 private key for HPKE. Stored as PKCS #8, like signing keys.
class HpkeKey {
public:
    [[nodiscard]] static Result<HpkeKey> generate();
    /// Loads an X25519 PKCS #8 PrivateKeyInfo (DER).
    [[nodiscard]] static Result<HpkeKey> from_pkcs8(ByteView der);
    /// Loads a passphrase-protected X25519 PKCS #8 key. Fails with
    /// `Errc::verification_failed` if the passphrase is wrong.
    [[nodiscard]] static Result<HpkeKey> from_encrypted_pkcs8(ByteView der,
                                                              std::string_view passphrase);

    HpkeKey(HpkeKey&&) noexcept;
    HpkeKey& operator=(HpkeKey&&) noexcept;
    HpkeKey(const HpkeKey&) = delete;
    HpkeKey& operator=(const HpkeKey&) = delete;
    ~HpkeKey();

    /// The 32-byte X25519 public key; empty if moved from.
    [[nodiscard]] ByteView public_key() const noexcept;

    /// Decrypts data sealed to this key. Fails with
    /// `Errc::verification_failed` if it was sealed to another key, or if the
    /// ciphertext, `info`, or `aad` differ from what was sealed.
    [[nodiscard]] Result<SecureBytes> open(const HpkeSealed& sealed, ByteView info,
                                           ByteView aad) const;

    [[nodiscard]] Result<SecureBytes> to_pkcs8() const;
    /// Same scheme as KeyPair::to_encrypted_pkcs8.
    [[nodiscard]] Result<Bytes> to_encrypted_pkcs8(std::string_view passphrase) const;

private:
    struct Impl;
    explicit HpkeKey(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::crypto::openssl
