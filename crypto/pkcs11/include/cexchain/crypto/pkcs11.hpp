// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Keys held on PKCS #11 tokens: USB keys (UKey), smart cards, and HSMs. The
/// private key never leaves the token; signing needs the token and its PIN.
namespace cexchain::crypto::pkcs11 {

/// A key named by an RFC 7512 PKCS #11 URI, e.g.
///   pkcs11:token=CexChain;object=alice?module-path=/usr/lib/softhsm/libsofthsm2.so
/// Path attributes: token (label), serial, object (label), id (percent-encoded
/// bytes). Query attributes: module-path (required), pin-value, pin-source
/// (a file, "file:PATH" or a path), and x-sm2-mechanism: the vendor's
/// SM2-with-SM3 signing mechanism, in hex (SM2 is not in PKCS #11 itself).
struct KeyUri {
    std::string module_path;
    std::optional<std::string> token;
    std::optional<std::string> serial;
    std::optional<std::string> object;
    std::optional<Bytes> id;
    std::optional<std::string> pin_value;
    std::optional<std::string> pin_source;
    std::optional<unsigned long> sm2_mechanism;
};

/// True if `text` is a PKCS #11 URI.
[[nodiscard]] bool is_uri(std::string_view text) noexcept;
[[nodiscard]] Result<KeyUri> parse_uri(std::string_view text);

/// A signing key on a token. Signatures come back in CexChain's wire format
/// (ESP256 in low-S form) and are checked against the public key before they
/// are returned, so a token whose mechanism does something unexpected fails
/// loudly instead of producing unusable signatures.
class Key final : public crypto::Signer {
public:
    /// Opens the token, logs in with `pin`, and finds the key pair. `provider`
    /// must outlive the key.
    [[nodiscard]] static Result<Key> open(const KeyUri& uri, std::string_view pin,
                                          const crypto::Provider& provider);
    /// Generates a key pair on the token (sensitive, never extractable),
    /// labelled with the URI's object (and id, or a random one).
    [[nodiscard]] static Result<Key> generate(const KeyUri& uri, std::string_view pin, SigAlg alg,
                                              const crypto::Provider& provider);

    Key(Key&&) noexcept;
    Key& operator=(Key&&) noexcept;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key() override;

    [[nodiscard]] SigAlg algorithm() const noexcept override;
    [[nodiscard]] const PublicKey& public_key() const noexcept override;
    [[nodiscard]] Result<Bytes> sign(ByteView message) const override;

    /// The token's label.
    [[nodiscard]] const std::string& token_label() const noexcept;

private:
    struct Impl;
    explicit Key(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::crypto::pkcs11
