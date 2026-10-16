// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>

/// The contract text (pass 8 of the plan, `bo explain`): a checked model
/// written out in one language, from the sentences of that language's pack.
/// This is the text the parties read and confirm before they sign, so it
/// says what the compiled contract does, and nothing else:
///   - the parties, and when each is bound to a ledger;
///   - what each instance records: its kind, its fields (given at creation,
///     a party it starts with, or a constant), and how one is created;
///   - charges;
///   - the states: the first, all of them, the final ones (from which no
///     action can start, as compiled code decides), and the events;
///   - each action: who starts it, its counterparty, its inputs, the
///     consents it needs, its requirements numbered as compiled code numbers
///     them (a refusal "bo:requires sign 2" names requirement 2 of sign), its
///     choices, refusals, field changes, and state changes, and what AI
///     agents may do;
///   - the time rules, with what is due and when, duties, and executors;
///   - the rules Bo applied, with their texts.
/// Whatever Bo inferred instead of reading it (model.hpp's rule ids) is
/// spelled out in the clause and marked with its rule ("[R3]"), and every
/// rule used is explained at the end.
///
/// The text depends on the model and the pack only, never on the language
/// the source was written in, its layout, or its places: one contract gives
/// the same text, byte for byte, through any spelling of it. A pack without
/// a sentence falls back to English for it.
namespace cexchain::bo {

/// One clause of the contract text.
struct ExplainedClause {
    /// Its place: "4.1.3" (section 4, its first item, that item's third).
    std::string number;
    /// What it states: party, kind, field, creation, first-state, states,
    /// final-state, events, action, standard, by, to, inputs, consent,
    /// requirement, if, otherwise, reject, set, transition, each, do,
    /// agents, executor, due, when, charge, charge-line.
    std::string_view kind;
    /// The clause, in the pack's language, without its rule marks.
    std::string text;
    /// The rules that inferred what it states, in the order of their ids.
    std::vector<std::string_view> rules;
    /// An action's clauses: the function compiled code gives the action.
    std::string function;
    /// A requirement: its number within its action, from 1.
    std::uint32_t requirement = 0;
};

struct ExplainedSection {
    /// "1", "2", ...
    std::string number;
    /// parties, instance, charges, states, actions, time.
    std::string_view kind;
    std::string title;
    /// A sentence under the title, or empty.
    std::string note;
    std::vector<ExplainedClause> clauses;
};

struct Explained {
    /// The pack's id.
    std::string language;
    /// "Contract SupplyAgreement", or the fragment's title.
    std::string title;
    std::string intro;
    /// The vocabulary packs the contract uses, as a sentence ("Besides Bo's
    /// core words, the contract uses the finance vocabulary pack (version
    /// 1)."), or empty if it uses none.
    std::string packs;
    std::vector<ExplainedSection> sections;
    /// The rules the text uses, in the order of their ids, with their texts
    /// (the pack's sentences rule-R1 ...).
    std::vector<std::pair<std::string_view, std::string>> rules;
    /// The rules' section: its number and title.
    std::string rules_number;
    std::string rules_title;
    /// Everything above as one text: what tools print and parties confirm.
    std::string text;
};

/// The contract text of a model in a pack's language (English if null).
/// Meant for a model the checker found no errors in; any model is safe.
[[nodiscard]] Explained explain(const model::Model& model, const Pack* language);

/// One field of an instance, as the contract text writes it.
struct ExplainedValue {
    /// The field, in the pack's language (a name as written).
    std::string field;
    /// Its value in words: "HKD 250,000.00", "1 January 2030", "「steel」".
    std::string value;
};

/// What an instance holds, in the pack's language: its state, and each of
/// its fields the state carries.
struct ExplainedState {
    /// The state's word (or name); empty if the state names none of the
    /// model's.
    std::string state;
    std::vector<ExplainedValue> fields;
};

/// Names a party's ledger (its 32-byte id) for people.
using LedgerLabel = std::function<std::string(ByteView ledger)>;

/// An instance's state, as compiled code keeps it (`{"state": NAME,
/// "fields": {...}}`: money in its smallest unit, rates in millionths, dates
/// in milliseconds at the contract's UTC offset, parties as ledger ids), read
/// by the model's types and written in the pack's language. A value that is
/// not of its field's type is shown in CBOR diagnostic notation.
[[nodiscard]] ExplainedState explain_state(const model::Model& model, const cbor::Value& state,
                                           const Pack* language, const LedgerLabel& ledger);

/// A text value as the contract text shows it: in the pack's quotation
/// marks ("中国内地" in English, 「中國內地」 in zh-Hant-HK). Every text in
/// the contract text goes through here, written ones and those Bo read as
/// text by rule R18 (an undeclared name compared with a text), so the
/// parties see what was read as text.
[[nodiscard]] std::string quoted_text(std::string_view text, const Pack* language);

} // namespace cexchain::bo
