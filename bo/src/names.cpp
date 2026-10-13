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

namespace cexchain::bo {

namespace {

/// True if `table` lists E's enumerators' identifiers, in order, and the
/// enumerators are 0, 1, 2, ...
template <class E, std::size_t N>
consteval bool table_matches(const std::array<std::string_view, N>& table) {
    const auto enumerators = std::meta::enumerators_of(^^E);
    if (enumerators.size() != N) {
        return false;
    }
    for (std::size_t i = 0; i < N; ++i) {
        if (std::meta::identifier_of(enumerators[i]) != table[i] ||
            static_cast<std::size_t>(std::meta::extract<E>(enumerators[i])) != i) {
            return false;
        }
    }
    return true;
}

static_assert(table_matches<Category>(category_names), "category_names is out of date");
static_assert(table_matches<Severity>(severity_names), "severity_names is out of date");
static_assert(table_matches<Separation>(separation_names), "separation_names is out of date");
static_assert(table_matches<MeaningKind>(meaning_kind_names), "meaning_kind_names is out of date");

template <class E>
constexpr std::string_view enumerator_name(const E value) noexcept {
    template for (constexpr auto e : std::define_static_array(std::meta::enumerators_of(^^E))) {
        if (value == [:e:]) {
            return std::meta::identifier_of(e);
        }
    }
    return {};
}

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
