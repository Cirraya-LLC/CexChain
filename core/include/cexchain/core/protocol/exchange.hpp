// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

/// Proposal and consent files (`exchange-file` in spec/cexchain.cddl,
/// extension .cexchain): consents carried between ledgers that do not reach
/// each other's APIs, by any channel. Nothing in a file is relied on
/// unchecked: a proposal's terms are checked against the instance's contract
/// evidence it carries, and a consent's bundle as the home checks any
/// consent (spec section 15). This only reads and writes the envelope.
namespace cexchain::protocol {

inline constexpr std::uint64_t exchange_format = 1;
/// A file is at most this large; its note at most this many bytes; a
/// proposal waits for at most this many ledgers.
inline constexpr std::size_t max_exchange_file = std::size_t{16} << 20;
inline constexpr std::size_t max_exchange_note = 1000;
inline constexpr std::size_t max_exchange_needs = 16;

enum class ExchangeKind : std::uint8_t {
    /// The home asks for consents to one call.
    proposal,
    /// A party's consent to that call.
    consent,
};

struct ExchangeFile {
    ExchangeKind kind = ExchangeKind::proposal;
    /// The instance's home ledger, the instance, and its head.
    Id home;
    Id instance;
    std::uint64_t head = 0;
    std::string function;
    cbor::Value arguments;
    /// The home's hash, which the consent's terms hash the arguments with.
    crypto::HashAlg hash = crypto::HashAlg::sha256;
    /// A proposal: the instance's contract evidence. A consent: the consent
    /// record's evidence bundle, from the consenting ledger.
    Bytes evidence;
    /// A proposal: the ledgers whose consents the call waits for (1 to 16).
    std::vector<Id> needs;
    /// For people, 1 to 1000 bytes.
    std::optional<std::string> note;

    friend bool operator==(const ExchangeFile&, const ExchangeFile&) = default;
};

/// "proposal" or "consent".
[[nodiscard]] std::string_view name(ExchangeKind kind) noexcept;

/// Encodes a file; fails if it breaks the shape or the limits above.
[[nodiscard]] Result<Bytes> encode_exchange_file(const ExchangeFile& file);
/// Decodes a file: deterministic CBOR in the shape above, within its
/// limits, every key known.
[[nodiscard]] Result<ExchangeFile> decode_exchange_file(ByteView encoded);

} // namespace cexchain::protocol
