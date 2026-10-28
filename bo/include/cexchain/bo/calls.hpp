// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/core/cbor.hpp>

/// The calls a person makes on a contract, for forms (`bo calls`, `bo args`,
/// and the console's things with rules): what each function takes, and its
/// arguments (spec/bo.md 12.4) built from what a person fills in.
///
/// Values are typed by the model, never guessed from what is written: a
/// text is taken as typed, yes or no as a choice, a party as its ledger id
/// (64 hexadecimal digits), a list item by item, and a number, an amount of
/// money, a quantity, a rate, a date, or a duration as Bo writes it, in any
/// official language (`HKD 100.50`, `500萬`, `2027年1月6日`, `30日`), read by
/// Bo's lexer and checked against the declared type. A plain number is
/// taken in the field's currency for money, in the declared unit for a
/// quantity that names one, and in percent for a rate: the form shows each.
///
/// Problems are codes (Problem::code), worded by whoever shows them: the
/// official packs, whose digests deploys record, are not changed by forms.
namespace cexchain::bo::calls {

/// Where a value goes in the arguments.
enum class Place : std::uint8_t {
    field, ///< a field given at creation: under "fields"
    role,  ///< a role bound to a ledger: at creation under "parties", by an action by its name
    input, ///< an action's input (R21's counterparty included)
};

inline constexpr std::array<std::string_view, 3> place_names{"field", "role", "input"};

/// A value a call takes from whoever makes it.
struct Input {
    /// As compiled code names it (12.1): its key in the arguments.
    std::string name;
    /// For people: the word in the reader's language, or the name as written.
    std::string label;
    /// The checker's encoded type ("money cur.HKD", "party", "list 3 text").
    std::string type;
    /// The type in the reader's language.
    std::string type_text;
    Place place = Place::input;
    /// It may be left out: a field with a default; a role an action binds,
    /// once bound (unless the action binds it again on every call).
    bool optional = false;
    /// A role an action binds again on every call (R23).
    bool each_call = false;
    /// A field's default as written in the source, or empty.
    std::string initial;
};

enum class Kind : std::uint8_t {
    create,  ///< the function that creates an instance
    action,  ///< a `can`
    rule,    ///< a time rule's function, which a keeper (or a person) calls with no arguments
    approve, ///< approves an AI agent's proposal
    reply,   ///< every answer to a request calls it
};

inline constexpr std::array<std::string_view, 5> kind_names{"create", "action", "rule", "approve",
                                                            "reply"};

struct Call {
    Kind kind = Kind::action;
    std::string function;
    /// The action's word in the reader's language, or its name as written.
    std::string label;
    std::vector<Input> inputs;
    /// What the contract text says of it, clause by clause, in the reader's
    /// language (without rule marks).
    std::vector<std::string> clauses;
    /// `AI agent can propose`: an agent's call waits for a person.
    bool agents_propose = false;
};

struct Description {
    /// The contract's name.
    std::string contract;
    std::vector<Call> calls;
};

/// A contract's calls, in the order of its interface: the creation, the
/// actions, approve, the time rules, the reply. `source` is the text the
/// model was checked from (defaults are quoted from it); `language` the
/// reader's pack (English if null). Meant for a model without errors.
[[nodiscard]] Description describe(const model::Model& model, std::string_view source,
                                   const Pack* language);

/// A value as a form gives it: a text (what was typed), yes or no, or a list.
struct Value {
    std::variant<std::string, bool, std::vector<Value>> value;
};

using Values = std::vector<std::pair<std::string, Value>>;

/// Why a value cannot go into the call.
struct Problem {
    /// The input, or empty for the call itself.
    std::string name;
    /// function: no such function takes arguments from a person;
    /// unknown: no such input; missing: required and not given;
    /// type: not a value of its type (the wrong kind of value, currency,
    /// dimension, or time unit); literal: does not read as one value (or a
    /// text not in UTF-8);
    /// exact: finer than its smallest unit, or too large;
    /// ledger: not a ledger id; bound: more items than its list holds;
    /// size: a text too long; twice: given twice.
    std::string_view code;
    /// The encoded type expected, if any.
    std::string type;
    /// In English, for logs and the command line.
    std::string detail;
};

struct Arguments {
    /// The call's arguments (canonical CBOR), if there is no problem.
    std::optional<cbor::Value> value;
    std::vector<Problem> problems;
};

/// The arguments of a call of `function` with `values` (by input name, as
/// `describe` lists them). Values are read with `lexicon`, the pack set's.
[[nodiscard]] Arguments arguments(const model::Model& model, const Lexicon& lexicon,
                                  std::string_view function, const Values& values);

/// Values from JSON (`{"NAME": VALUE, ...}`: a string, true or false, or an
/// array of them), at most 64 KiB and 256 values; an error message if the
/// text is not such an object.
[[nodiscard]] std::variant<Values, std::string> parse_values(std::string_view json);

/// The most values a call takes from a form, and the most bytes of JSON.
inline constexpr std::size_t max_values = 256;
inline constexpr std::size_t max_values_json = 64 * 1024;

} // namespace cexchain::bo::calls
