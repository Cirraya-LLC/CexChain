// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string_view>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cose.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>

namespace kanhe::protocol::detail {

/// A Kanhe signed object: a COSE_Sign1 whose protected header is exactly
/// {alg, content type, kid}, whose unprotected header is empty, and whose
/// payload is attached.
struct Envelope {
    cose::Sign1 message;
    Id kid;
};

/// Signs `payload` with the protected header {alg, content type, kid}, where
/// kid identifies the signer's key under `hash`.
[[nodiscard]] Result<Bytes> sign_envelope(const crypto::Signer& signer,
                                          const crypto::Provider& provider, crypto::HashAlg hash,
                                          ByteView payload, std::string_view content_type);

/// Parses a signed object and checks its header shape and content type.
[[nodiscard]] Result<Envelope> parse_envelope(ByteView encoded, std::string_view content_type);

/// Verifies an envelope's signature with `key`, which must be the key that
/// `kid` names under `hash`.
[[nodiscard]] Status verify_envelope(const crypto::Provider& provider, crypto::HashAlg hash,
                                     const Envelope& envelope, const crypto::PublicKey& key);

} // namespace kanhe::protocol::detail
