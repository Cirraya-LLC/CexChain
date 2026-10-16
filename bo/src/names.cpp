// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Names by static reflection (C++26, P2996): the compiler proper may use it;
// the front end, which Clang must build for fuzzing, may not. So the front
// end keeps hand-written name tables, and this file proves them right at
// compile time.

#include <array>
#include <cstddef>
#include <cstdint>
#include <meta>
#include <string>
#include <string_view>
#include <type_traits>

#include <cexchain/bo/names.hpp>
#include <cexchain/core/bytes.hpp>

#include "reflection.hpp"

namespace cexchain::bo {

namespace {

using detail::enumerator_name;
using detail::table_matches;

static_assert(table_matches<Category>(category_names), "category_names is out of date");
static_assert(table_matches<Vocab>(vocab_names), "vocab_names is out of date");
static_assert(table_matches<Severity>(severity_names), "severity_names is out of date");
static_assert(table_matches<Separation>(separation_names), "separation_names is out of date");
static_assert(table_matches<MeaningKind>(meaning_kind_names), "meaning_kind_names is out of date");
static_assert(table_matches<TokenKind>(token_kind_names), "token_kind_names is out of date");
static_assert(table_matches<Piece>(piece_names), "piece_names is out of date");
static_assert(table_matches<ast::ExprKind>(ast::expr_kind_names), "expr_kind_names is out of date");
static_assert(table_matches<ast::LiteralKind>(ast::literal_kind_names),
              "literal_kind_names is out of date");
static_assert(table_matches<ast::Operator>(ast::operator_names), "operator_names is out of date");
static_assert(table_matches<model::TypeKind>(model::type_kind_names),
              "type_kind_names is out of date");
static_assert(table_matches<model::Dimension>(model::dimension_names),
              "dimension_names is out of date");
static_assert(table_matches<model::Refers>(model::refers_names), "refers_names is out of date");
static_assert(table_matches<model::Binding>(model::binding_names), "binding_names is out of date");
static_assert(table_matches<model::FieldKind>(model::field_kind_names),
              "field_kind_names is out of date");
static_assert(table_matches<model::DueKind>(model::due_kind_names),
              "due_kind_names is out of date");
static_assert(table_matches<model::Expectation>(model::expectation_names),
              "expectation_names is out of date");
// operator_texts holds how each operator is written: one per enumerator.
static_assert(detail::enumerator_count<ast::Operator>() == ast::operator_texts.size(),
              "operator_texts is out of date");
// symbol_texts holds what each symbol looks like, not its name: one per
// enumerator.
static_assert(std::meta::enumerators_of(^^Symbol).size() == symbol_texts.size(),
              "symbol_texts is out of date");

static_assert(enumerator_name(Category::expression) == "expression");
static_assert(enumerator_name(MeaningKind::punctuation) == "punctuation");

cbor::Value value_of(const std::string& text) {
    return cbor::Value::text(text);
}

cbor::Value value_of(const std::uint64_t number) {
    return cbor::Value::unsigned_integer(number);
}

cbor::Value value_of(const bool flag) {
    return cbor::Value::boolean(flag);
}

/// A struct as a CBOR map of its members, keyed by their names, in
/// declaration order. (A template: GCC 16's -Wshadow takes each expansion of
/// a `template for` in an ordinary function for a new local shadowing the
/// last.)
template <class T>
cbor::Value members_to_cbor(const T& value) {
    cbor::Map map;
    constexpr auto context = std::meta::access_context::current();
    template for (constexpr auto member :
                  std::define_static_array(std::meta::nonstatic_data_members_of(^^T, context))) {
        map.push_back({cbor::Value::text(std::string(std::meta::identifier_of(member))),
                       value_of(value.[:member:])});
    }
    return cbor::Value::map(std::move(map));
}

} // namespace

std::string_view name_of(const Category value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const Severity value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const Separation value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const MeaningKind value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const TokenKind value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const Piece value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const ast::ExprKind value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const ast::LiteralKind value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const ast::Operator value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const model::TypeKind value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const model::Dimension value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const model::Refers value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const model::Binding value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const model::FieldKind value) noexcept {
    return enumerator_name(value);
}

std::string_view name_of(const model::DueKind value) noexcept {
    return enumerator_name(value);
}

Result<PackFacts> facts(const Pack& pack, const crypto::Provider& provider,
                        const crypto::HashAlg alg) {
    const auto hashed = digest(pack, provider, alg);
    if (!hashed) {
        return std::unexpected(hashed.error());
    }
    PackFacts out;
    out.id = pack.id;
    out.version = pack.version;
    out.language = pack.language;
    out.name = pack.name;
    out.official = pack.official;
    out.edition = pack.edition;
    out.separation = std::string(name_of(pack.reading.separation));
    out.keywords = pack.keywords.size();
    out.words = pack.vocabulary.size();
    for (const auto* words : {&pack.keywords, &pack.vocabulary}) {
        for (const auto& [id, word] : *words) {
            out.spellings += word.spellings.size() + word.forms.size();
        }
    }
    out.messages = pack.messages.size();
    out.sentences = pack.sentences.size();
    out.size = pack.canonical.size();
    out.hash = std::string(crypto::name(alg));
    out.digest = to_hex(hashed->bytes());
    return out;
}

cbor::Value to_cbor(const PackFacts& facts) {
    return members_to_cbor(facts);
}

} // namespace cexchain::bo
