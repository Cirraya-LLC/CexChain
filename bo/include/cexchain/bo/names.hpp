// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/model.hpp>
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
[[nodiscard]] std::string_view name_of(ast::ExprKind value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(ast::LiteralKind value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(ast::Operator value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(model::TypeKind value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(model::Dimension value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(model::Refers value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(model::Binding value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(model::FieldKind value) noexcept BO_POST(r, !r.empty());
[[nodiscard]] std::string_view name_of(model::DueKind value) noexcept BO_POST(r, !r.empty());

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

/// A parsed tree as CBOR (`bo check --stage parse --json`): each clause and
/// statement a map with "node" (its tag) and one entry per member, keyed by
/// the member's name, in declaration order, written by reflection, so a new
/// member or node shows up without more code. Expressions are maps of the
/// members their kind uses; places are maps of line, column, offset, and
/// length; concepts are their ids.
[[nodiscard]] cbor::Value to_cbor(const ast::File& file) BO_POST(r, r.as_map() != nullptr);

/// A checked model as CBOR (`bo check --stage model --json`): each struct of
/// model.hpp a map with one entry per member, keyed by the member's name, in
/// declaration order, written by reflection (statements also carry "node",
/// their tag). Types are their encoded text ("money cur.HKD"), enumerations
/// their enumerators' names, concepts their ids, places maps of line,
/// column, offset, and length; an expression has the members its kind uses,
/// with what it refers to and the rule that inferred it, when it has them.
[[nodiscard]] cbor::Value to_cbor(const model::Model& model) BO_POST(r, r.as_map() != nullptr);

} // namespace cexchain::bo
