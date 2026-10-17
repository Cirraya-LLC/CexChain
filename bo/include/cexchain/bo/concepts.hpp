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

struct VocabularyPack;

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

/// Where a concept belongs (D-054): Bo's core, which every source reads, or
/// one of the official vocabulary packs, whose words a source uses only after
/// declaring the pack (`use finance`), or a user's vocabulary pack (G6;
/// vocab.hpp). Official pack words are reserved even where their pack is not
/// used: Bo never reads `pledge` as a name of the contract's own.
enum class Vocab : std::uint8_t {
    core,
    finance,  ///< assets, pledges, payments, splits, freezes
    commerce, ///< prices, charges (taxes among them), bills, refunds
    services, ///< services, resources, and their allocation
    user,     ///< a user's pack, which Concept::owner names
};

/// Vocabulary pack ids, in enumerator order ("core" is no pack; "user"
/// stands for any user's pack, whose own id names it).
inline constexpr std::array<std::string_view, 5> vocab_names{"core", "finance", "commerce",
                                                             "services", "user"};

[[nodiscard]] constexpr std::string_view vocab_name(Vocab vocab) noexcept {
    return vocab_names[static_cast<std::size_t>(vocab)];
}

/// What a field's word fixes about the field (R1, R20, R31), as its
/// vocabulary pack states it.
enum FieldFlag : std::uint8_t {
    /// R20: a field the standard terms may add to an instance, holding no
    /// party until an action sets it (pledgee, payee).
    field_added = 1,
    /// R31: a counterparty an action puts into this field consents at every
    /// call (holder, pledgee, payee).
    field_taking = 2,
};

/// A concept of the edition: a keyword, a vocabulary word, a unit, a
/// currency. `arity` is 1 for a concept that takes an argument, whose
/// spellings mark the argument's place with "…" ("consent of …",
/// "經 … 同意"), since languages put it in different places.
struct Concept {
    std::string_view id;
    Category category;
    std::uint8_t arity;
    /// The core or the vocabulary pack the concept belongs to.
    Vocab pack = Vocab::core;
    /// A field's type, as R1 reads it: "party", "date", "number", "text",
    /// "duration", "parties" (a list of at most 16 parties), each fixed by
    /// the word; or what the word accepts once a type is given: "quantity",
    /// "list", "offset" (a constant text), "amount" (money or a quantity),
    /// "portion" (a quantity or money). Empty for other concepts.
    std::string_view type = {};
    /// FieldFlag bits.
    std::uint8_t flags = 0;
    /// No longer in the vocabulary: only the language packs of before
    /// vocabulary packs (version 1 of the official ones) spell it, so that
    /// their deploys rebuild (kind.record, now kind.thing; act.merge, which
    /// never had a meaning).
    bool retired = false;
    /// The vocabulary pack that defines it (vocab.hpp): an official pack's
    /// current version, or a user's pack; nullptr for the core.
    const VocabularyPack* owner = nullptr;
};

/// Every concept of the edition, the core's and the official vocabulary
/// packs' (whose files define theirs: bo/vocab/), sorted by id. A user's
/// pack's concepts are its own (VocabularyPack::concepts).
[[nodiscard]] std::span<const Concept* const> concepts() noexcept;

/// The symbol a unit is written as in every language, or empty: "°C" for
/// unit.celsius (G5b), which sources may also write ℃, and which the packs
/// also spell in words ("degrees Celsius", 攝氏度). Tools write the symbol.
[[nodiscard]] std::string_view unit_symbol(const Concept* c) noexcept;
/// A concept of the edition (the core's or an official pack's), or nullptr.
[[nodiscard]] const Concept* find_concept(std::string_view id) noexcept;
/// A concept of the core alone (the official packs' files are read with it).
[[nodiscard]] const Concept* find_core_concept(std::string_view id) noexcept;
/// The core's concepts (retired ones too), sorted by id.
[[nodiscard]] std::span<const Concept> core_concepts() noexcept;
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
    /// No longer written: only the official packs of earlier releases have
    /// it (the official vocabulary packs' names, which their files give
    /// since G6: vocabulary_name in vocab.hpp).
    bool retired = false;
};

[[nodiscard]] std::span<const SentenceSpec> sentence_specs() noexcept;
[[nodiscard]] const SentenceSpec* find_sentence(std::string_view id) noexcept;

/// A recognition rule of the edition: something Bo infers from a source by a
/// fixed, published rule, never by a guess (a field's type from the
/// vocabulary, the state an instance starts in, a consent an action needs).
/// The checked model tags everything it infers with its rule's id, and
/// `explain` spells it out; each pack gives its text as the sentence
/// "rule-ID". Ids are R1, R2, ... in the order the rules were added; once an
/// edition is released, a rule never changes meaning.
struct RuleSpec {
    std::string_view id;
    std::string_view name;
    /// The vocabulary pack whose words alone reach the rule, which then
    /// applies only in a source that uses the pack; the core for the others.
    Vocab pack = Vocab::core;
};

/// The edition's rules, in the order of their ids (R1, R2, ...).
[[nodiscard]] std::span<const RuleSpec> rule_specs() noexcept;
[[nodiscard]] const RuleSpec* find_rule(std::string_view id) noexcept;

/// True if `name` is one of the space-separated names in `params`.
[[nodiscard]] bool has_param(std::string_view params, std::string_view name) noexcept;

} // namespace cexchain::bo
