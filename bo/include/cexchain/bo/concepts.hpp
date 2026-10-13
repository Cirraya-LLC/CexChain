// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <cexchain/bo/contracts.hpp>

/// What the Bo compiler knows, whatever the language: the concepts of an
/// edition, the codes of its messages, and the sentences `explain` writes.
/// Language packs (pack.hpp) give these spellings and texts; the compiler
/// works on the ids alone, so a contract compiles to the same code through
/// any pack.
namespace cexchain::bo {

/// The edition this compiler reads (`bo 1`). Later editions only add.
inline constexpr std::uint64_t edition = 1;

/// A concept's category, which decides where it may stand. Packs name
/// categories by these identifiers ("unit", "currency"), for example in their
/// attaching rules.
enum class Category : std::uint8_t {
    keyword,    ///< kw.*: the syntax; every pack spells all of them
    kind,       ///< kind.*: what a block declares (asset, service, ...)
    action,     ///< act.*: business actions (pledge, renew, ...)
    condition,  ///< cond.*: conditions (over, in person, overdue, ...)
    pricing,    ///< price.*: prices and usage
    charge,     ///< charge.*: taxes, fees, and other charges
    time,       ///< time.*: durations, recurrences, and the current time
    unit,       ///< unit.*: units of quantities
    currency,   ///< cur.*: currencies
    rounding,   ///< round.*: rounding modes
    document,   ///< doc.*: business documents
    type,       ///< type.*: value types
    value,      ///< val.*: literal values
    field,      ///< field.*: common fields
    state,      ///< state.*: common states
    actor,      ///< actor.*: who acts (a person, an AI agent, a device)
    role,       ///< role.*: common roles
    expression, ///< expr.*: built-in expressions
};

/// Category names, in enumerator order. The front end reads and writes packs
/// without reflection; cexchain::bo checks this table against the
/// enumerators' identifiers at compile time.
inline constexpr std::array<std::string_view, 18> category_names{
    "keyword", "kind",  "action",   "condition", "pricing",  "charge",
    "time",    "unit",  "currency", "rounding",  "document", "type",
    "value",   "field", "state",    "actor",     "role",     "expression"};

[[nodiscard]] constexpr std::string_view category_name(Category category) noexcept {
    return category_names[static_cast<std::size_t>(category)];
}

[[nodiscard]] std::optional<Category> category_from_name(std::string_view name) noexcept;

/// A concept of the edition: a keyword, a vocabulary word, a unit, a
/// currency. `arity` is 1 for a concept that takes an argument, whose
/// spellings mark the argument's place with "…" ("consent of …",
/// "經 … 同意"), since languages put it in different places.
struct Concept {
    std::string_view id;
    Category category;
    std::uint8_t arity;
};

/// Every concept of the edition, sorted by id.
[[nodiscard]] std::span<const Concept> concepts() noexcept;
[[nodiscard]] const Concept* find_concept(std::string_view id) noexcept;
/// The number of keywords (every pack spells them all).
[[nodiscard]] std::size_t keyword_count() noexcept;

enum class Severity : std::uint8_t { error, warning };

inline constexpr std::array<std::string_view, 2> severity_names{"error", "warning"};

/// A message the compiler can report: its code, its severity, and the names
/// of its parameters (space-separated), which packs' texts use as
/// placeholders: "{path} must be a map".
struct MessageSpec {
    std::string_view code;
    Severity severity;
    std::string_view params;
};

[[nodiscard]] std::span<const MessageSpec> message_specs() noexcept;
[[nodiscard]] const MessageSpec* find_message(std::string_view code) noexcept;

/// A sentence `explain` writes, with the names of its parameters. A
/// placeholder may ask for a word's form: "{action.third}".
struct SentenceSpec {
    std::string_view id;
    std::string_view params;
};

[[nodiscard]] std::span<const SentenceSpec> sentence_specs() noexcept;
[[nodiscard]] const SentenceSpec* find_sentence(std::string_view id) noexcept;

/// True if `name` is one of the space-separated names in `params`.
[[nodiscard]] bool has_param(std::string_view params, std::string_view name) noexcept;

} // namespace cexchain::bo
