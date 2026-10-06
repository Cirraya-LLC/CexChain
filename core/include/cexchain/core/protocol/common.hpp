// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Types shared by the CexChain v0.1 protocol objects. The normative
/// definition of every structure is spec/cexchain-v0.1.cddl.
namespace cexchain::protocol {

inline constexpr std::uint64_t protocol_version = 1;

/// Identifiers (statement, ledger, actor, key) are digests under the ledger's
/// hash algorithm. v0.1 ledgers use SHA-256 or SM3, so identifiers are 32
/// bytes.
inline constexpr std::size_t id_size = 32;
using Id = crypto::Digest;

/// Unix time in milliseconds.
using Timestamp = std::uint64_t;

using Nonce = std::array<std::uint8_t, 16>;

inline constexpr std::string_view statement_content_type = "application/cexchain-statement+cbor";
inline constexpr std::string_view checkpoint_content_type = "application/cexchain-checkpoint+cbor";
inline constexpr std::string_view cosignature_content_type =
    "application/cexchain-cosignature+cbor";

/// True for the hash algorithms a v0.1 ledger may use: SHA-256 and SM3.
[[nodiscard]] bool is_ledger_hash(crypto::HashAlg alg) noexcept;

/// Encodes a public key as [alg, key].
[[nodiscard]] cbor::Value encode_public_key(const crypto::PublicKey& key);

/// Decodes [alg, key], checking that the algorithm is known and the key has
/// the algorithm's size.
[[nodiscard]] Result<crypto::PublicKey> decode_public_key(const cbor::Value& value);

/// The key identifier used as COSE kid: HASH(deterministic-CBOR([alg, key])).
[[nodiscard]] Result<Id> key_id(const crypto::Provider& provider, crypto::HashAlg alg,
                                const crypto::PublicKey& key);

/// Checks that `bytes` has the identifier size and wraps it.
[[nodiscard]] Result<Id> to_id(ByteView bytes);

} // namespace cexchain::protocol
