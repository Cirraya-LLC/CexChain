// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// COSE_Sign1 (RFC 9052 §4.2) in the CexChain profile.
///
/// The profile is stricter than RFC 9052:
///   - messages are always tagged (CBOR tag 18);
///   - the whole message, including the protected header, uses deterministic
///     CBOR, so every message has exactly one encoding;
///   - the protected header must carry the algorithm (label 1), and the
///     unprotected header must not;
///   - no parameter may appear in both headers;
///   - labels are integers or text strings, at most `max_header_parameters`
///     per header;
///   - the critical-parameters header (label 2) is rejected, since this
///     implementation defines no critical extensions.
namespace cexchain::cose {

inline constexpr std::uint64_t tag_sign1 = 18;

/// Maximum number of parameters in each header. This bounds parsing cost;
/// real headers carry only a handful of parameters.
inline constexpr std::size_t max_header_parameters = 64;

/// Common header parameter labels (RFC 9052 §3.1).
inline constexpr std::int64_t label_alg = 1;
inline constexpr std::int64_t label_crit = 2;
inline constexpr std::int64_t label_content_type = 3;
inline constexpr std::int64_t label_kid = 4;

/// A parsed COSE_Sign1 message.
struct Sign1 {
    /// The protected header exactly as serialized and signed.
    Bytes protected_bytes;
    /// The decoded protected header map.
    cbor::Value protected_header;
    /// The unprotected header map.
    cbor::Value unprotected_header;
    /// The payload, or nullopt if it is detached.
    std::optional<Bytes> payload;
    Bytes signature;
    /// The algorithm declared in the protected header.
    crypto::SigAlg algorithm;
};

struct SignOptions {
    /// Additional protected header parameters. Must not include alg or crit;
    /// alg is added from the signer.
    cbor::Map protected_header;
    /// Unprotected header parameters. Must not include alg or crit.
    cbor::Map unprotected_header;
    /// Externally supplied data bound into the signature but not transmitted.
    ByteView external_aad;
    /// Omit the payload from the message. The signature still covers it.
    bool detached = false;
};

/// Builds the Sig_structure that a COSE_Sign1 signature covers:
/// ["Signature1", body_protected, external_aad, payload].
[[nodiscard]] Result<Bytes> sig_structure(ByteView protected_bytes, ByteView external_aad,
                                          ByteView payload);

/// Signs `payload` and returns the encoded, tagged COSE_Sign1 message.
[[nodiscard]] Result<Bytes> sign(const crypto::Signer& signer, ByteView payload,
                                 const SignOptions& options = {});

/// Parses a tagged COSE_Sign1 message and checks it against the profile. Does
/// not verify the signature.
[[nodiscard]] Result<Sign1> parse(ByteView message);

/// Verifies `message` with `key`. The key's algorithm must match the
/// algorithm in the protected header. Pass `detached_payload` exactly when the
/// message omits its payload.
[[nodiscard]] Status verify(const crypto::Provider& provider, const Sign1& message,
                            const crypto::PublicKey& key, ByteView external_aad = {},
                            std::optional<ByteView> detached_payload = std::nullopt);

} // namespace cexchain::cose
