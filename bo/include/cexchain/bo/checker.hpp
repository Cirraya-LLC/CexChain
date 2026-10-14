// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>

/// The checker (passes 4 and 5 of the plan): a parsed tree, with the
/// standard library's terms of its built-in actions (stdlib.hpp), to the
/// checked model of model.hpp, and every problem found.
///
/// What it reads:
///   - the contract's name (a file without one is a fragment: a warning),
///     its parties, the one kind of instance and its fields, its charges;
///   - fields: a type (amount HKD, due date) makes a field each instance
///     holds, set at creation; a value (IP 1 item, price monthly HKD 120)
///     makes a constant; a party (holder supplier) makes a field that starts
///     with that party and may change (R2). A vocabulary field has the
///     vocabulary's type (R1);
///   - states, collected from the state changes (R5); the first state (R4);
///   - actions (`can`): the vocabulary's, which get the standard library's
///     terms (R19) after the lines the contract writes under them, with the
///     contract's counterparty (`to`) or one each call names (R21), and the
///     fields the terms use (R20); and the contract's own, which need `by`;
///     their inputs; their blocks, typed;
///   - time rules (`when`): an event that is a time, and duties (R9).
/// What it checks (spec section 9):
///   - names: every name declared once and used where declared;
///   - types and units: money only with money of the same currency,
///     quantities only within a dimension, months never with days, rates,
///     dates, durations, texts, yes or no, parties, bounded lists; exact
///     values only (no amount finer than its smallest unit; no overflow);
///   - termination: `each` only over bounded lists, and no recursion;
///   - consents: changing a field that holds a party needs its consent (R8);
///   - every state reachable from the first (a state the standard terms
///     name but no instance reaches is none of the contract's), and every
///     built-in action able to start;
///   - built-in actions: their starter and counterparty, their state
///     changes, and the fields their terms set are the terms'; the fields
///     their terms need are the instance's;
///   - thresholds (R6), presence (R13), agents (R14), and the places of
///     each (`in person` never in a time rule).
/// Executor clauses (R10) are accepted with a warning: they come in 6b.
/// `test` blocks: their steps, parties, values, and expectations (a state of
/// the contract, a refusal, a wait, or an AI agent's proposal).
namespace cexchain::bo {

struct Checked {
    model::Model model;
    /// The checker's problems (check.* codes), in the order found.
    std::vector<Diagnostic> diagnostics;
};

/// Checks a tree. `source` is the text it was parsed from: messages quote
/// what was written. Meant for trees without errors (the lexer's and the
/// parser's); any tree is safe to check.
[[nodiscard]] Checked check(std::string_view source, const ast::File& file);

/// A type as a short, language-neutral text: "money cur.HKD",
/// "quantity data", "list 16 money cur.HKD", "recurring time.monthly money
/// cur.HKD". Messages carry types this way (parameters named `type` or
/// `..._type`), and render() describes them in the reader's language.
[[nodiscard]] std::string encode(const model::Type& type);

/// An encoded type in words, from the pack's sentences "type-*" (English if
/// the pack lacks one): "money in HKD", "港元金額".
[[nodiscard]] std::string describe_type(std::string_view encoded, const Pack* language);

/// The model as canonical text: one declaration or statement per line,
/// expressions as in the tree's dump, and `{R3}` after whatever a rule
/// inferred. No places and no spellings, so every language gives the same
/// text.
[[nodiscard]] std::string dump(const model::Model& model);

/// The model, then the checker's diagnostics with their places (messages in
/// `language`, English if null): what `bo check --stage model` prints, and
/// the checker's goldens.
[[nodiscard]] std::string dump(const Checked& checked, const Pack* language);

} // namespace cexchain::bo
