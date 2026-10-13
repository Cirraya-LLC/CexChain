// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Part of cexchain::bo, the compiler proper: C++26 with static reflection
/// (GCC 16). The names of the front end's enumerations come from the
/// enumerators themselves, and the front end's own name tables, which it
/// keeps because it builds without reflection, are checked against them at
/// compile time.
namespace cexchain::bo {

[[nodiscard]] std::string_view name_of(Category value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(Severity value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(Separation value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(MeaningKind value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(TokenKind value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(Piece value) noexcept BO_POST(r, !r.empty());

/// What `bo packs list` shows of a pack.
struct PackFacts {
    std::string id;
    std::uint64_t version = 0;
    std::string language;
    std::string name;
    bool official = false;
    std::uint64_t edition = 0;
    std::string separation;
    /// Keywords and vocabulary concepts spelled.
    std::uint64_t keywords = 0;
    std::uint64_t words = 0;
    /// Every spelling, alternatives and forms included.
    std::uint64_t spellings = 0;
    std::uint64_t messages = 0;
    std::uint64_t sentences = 0;
    /// Bytes of canonical CBOR.
    std::uint64_t size = 0;
    std::string hash;
    std::string digest;
};

[[nodiscard]] Result<PackFacts> facts(const Pack& pack, const crypto::Provider& provider,
                                      crypto::HashAlg alg);

/// A CBOR map with one entry per member of PackFacts, keyed by the member's
/// name, in declaration order (written by reflection, so a new member shows
/// up without more code).
[[nodiscard]] cbor::Value to_cbor(const PackFacts& facts)
    BO_POST(r, r.as_map() != nullptr && !r.as_map()->empty());

} // namespace cexchain::bo
