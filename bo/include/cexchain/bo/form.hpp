// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/pack.hpp>

/// The form that writes Bo (`bo form`, and the console's rules editor). A
/// *rules sheet* (JSON) describes a contract with the constructs a form can
/// hold: its parties, its kind and fields, its actions (who starts each,
/// with whom, their inputs, requirements, consents, presence, what AI agents
/// may do, the state change, the fields set, the requests), its time rules,
/// its rules for answers, and its tests. The generator writes the source;
/// the compiler then checks it, so the sheet is never a second language.
///
/// Bo never guesses, and neither does the form. Everything that is not a
/// choice among the form's widgets is a piece of Bo text, kept as written:
/// names in any language, types (`HKD`, `date`, `list text at most 3`),
/// values (`"Camera X100"`, `HKD 100`), conditions, events (`overdue 30
/// days`). The generator adds the keywords, in English, around them, and
/// nothing else: no state, action, consent, or field the sheet does not
/// name. `bo form --language` then writes the whole source in one language
/// through the formatter.
///
/// Back from text: a source whose every construct fits the form is read
/// back into a sheet through its parse tree, its pieces taken from the
/// source as written. Generating that sheet again gives the same tree. A
/// source with anything else (a choice, a loop, a refusal, lines in another
/// order) stays text, and `read_sheet` says where.
///
/// An action's block is written in one order: plain requirements, consents,
/// presence (always, then above a threshold), what AI agents may do, the
/// state change, the fields set, the requests. A rule's and a rule for
/// answers' block: the state change, the fields set, the requests.
namespace cexchain::bo::form {

inline constexpr std::uint64_t sheet_version = 1;

/// A piece of Bo source as written, on one line.
using Text = std::string;

/// `NAME = VALUE`: a field set, a step's or a request's value.
struct Assign {
    Text name;
    Text value;

    friend bool operator==(const Assign&, const Assign&) = default;
};

/// A kind block's line (`amount HKD`, `count number = 0`, `holder owner`)
/// or an action's input (`fee HKD`).
struct Line {
    Text name;
    Text type;
    std::optional<Text> initial;

    friend bool operator==(const Line&, const Line&) = default;
};

/// `request KIND [to PARTY] [with NAME = VALUE, ...] WITHIN`.
struct Request {
    Text kind;
    std::optional<Text> to;
    std::vector<Assign> with;
    /// The deadline as written, its word included: `within 1 day`, `1日內`.
    Text within;

    friend bool operator==(const Request&, const Request&) = default;
};

/// What a block does after its requirements: its state change (from the
/// states `from`, or from any if empty, to `to_state`), fields, requests.
struct Effects {
    std::vector<Text> from;
    std::optional<Text> to_state;
    std::vector<Assign> set;
    std::vector<Request> requests;

    friend bool operator==(const Effects&, const Effects&) = default;
};

struct Action {
    Text action;
    std::optional<Text> by;
    std::optional<Text> to;
    std::vector<Line> inputs;
    /// `requires COND`, each a condition as written.
    std::vector<Text> requires_;
    /// `requires consent of X`, each X as written.
    std::vector<Text> consent_of;
    bool in_person = false;
    /// `GUARD requires in person`: the guard as written (`over 5_000_000`).
    std::optional<Text> in_person_over;
    /// `AI agent can propose`.
    bool agents_propose = false;
    Effects effects;

    friend bool operator==(const Action&, const Action&) = default;
};

/// `when EVENT [ACTION and ...]` and its block.
struct Rule {
    Text when;
    std::vector<Text> act;
    Effects effects;

    friend bool operator==(const Rule&, const Rule&) = default;
};

enum class Outcome : std::uint8_t { done, fails, expires };

/// `when KIND done|fails|expires [ACTION and ...]` and its block.
struct Answer {
    Text kind;
    Outcome outcome = Outcome::done;
    std::vector<Text> act;
    Effects effects;

    friend bool operator==(const Answer&, const Answer&) = default;
};

/// A test's step: `PARTY ACTION [OUTCOME] [ARG ...] [to P] [by B] [with
/// N = V, ...] [-> EXPECT]`. Its arguments are as written (a holder, `at
/// 2027-01-05`, `in person`), and so is its expectation, after `->`.
struct Step {
    Text party;
    Text action;
    std::optional<Outcome> outcome;
    std::vector<Text> args;
    std::optional<Text> to;
    std::optional<Text> by;
    std::vector<Assign> with;
    std::optional<Text> expect;

    friend bool operator==(const Step&, const Step&) = default;
};

struct Test {
    /// As written: a text in quotes, or a name.
    std::optional<Text> name;
    std::vector<Step> steps;

    friend bool operator==(const Test&, const Test&) = default;
};

struct Sheet {
    Text contract;
    /// Vocabulary packs (`use` lines), by id.
    std::vector<std::string> packs;
    std::vector<Text> parties;
    /// The kind word (`thing`, or with its pack `asset`, `service`,
    /// `resource`) and the kind's name.
    Text kind_word = "thing";
    Text kind_name;
    std::vector<Line> fields;
    std::vector<Action> actions;
    std::vector<Rule> rules;
    std::vector<Answer> answers;
    std::vector<Test> tests;

    friend bool operator==(const Sheet&, const Sheet&) = default;
};

/// Where a sheet is wrong: a JSON pointer (`/actions/0/set/1/value`) and
/// what is wrong there.
struct SheetError {
    std::string path;
    std::string message;
};

/// Reads a sheet (JSON). Every key is known, every piece of text is one line
/// without a comment or a tab: a sheet cannot write a line the form does
/// not.
[[nodiscard]] std::variant<Sheet, SheetError> parse_sheet(std::string_view json);
/// The sheet as JSON, every key written in one order (two-space indents,
/// a final newline): the same sheet gives the same bytes.
[[nodiscard]] std::string sheet_json(const Sheet& sheet);

struct Generated {
    /// The source: English keywords around the sheet's pieces, laid out as
    /// `bo fmt` lays it out.
    std::string source;
    /// For each line of the source (line N at index N - 1), the JSON
    /// pointer of the part of the sheet it comes from; empty for a blank
    /// line. So a diagnostic's line names its place in the form.
    std::vector<std::string> paths;
};

[[nodiscard]] Generated generate(const Sheet& sheet);

/// Why a source does not fit the form: what, and where.
struct Unfit {
    std::string reason;
    Span span;
};

/// The sheet a source's tree fits (pieces taken from `source`, as
/// written), or why it does not. The tree must come from `source`.
[[nodiscard]] std::variant<Sheet, Unfit> read_sheet(std::string_view source, const ast::File& file);

} // namespace cexchain::bo::form
