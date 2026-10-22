// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>

/// The tree a Bo source parses to. It holds concepts and names, never
/// spellings: a contract written in English, in Chinese, or in both gives the
/// same tree (word forms such as `pays` are gone too). Every node keeps its
/// place in the source, for the messages of later passes.
///
/// Expressions are one node type (Expr), told apart by `kind`. Statements
/// and clauses are one struct each, in variants; each struct names itself
/// with a static `tag`, which the canonical dump and the JSON use.
namespace cexchain::bo::ast {

enum class ExprKind : std::uint8_t {
    literal, ///< a number, money, quantity, duration, rate, date, or text: `literal`
    name,    ///< a name the contract gives: `name`
    word,    ///< a vocabulary word: `concept_entry`
    apply,   ///< a word with an argument (consent of bank): `concept_entry`, `operands[0]`
    phrase,  ///< words side by side (monthly HKD 120): `operands`, two or more
    list,    ///< (a, b, c): `operands`
    unary,   ///< `op` (logical_not) and `operands[0]`
    binary,  ///< `op` and `operands[0]`, `operands[1]`
};

inline constexpr std::array<std::string_view, 8> expr_kind_names{
    "literal", "name", "word", "apply", "phrase", "list", "unary", "binary"};

enum class LiteralKind : std::uint8_t { number, money, quantity, duration, rate, date, text };

inline constexpr std::array<std::string_view, 7> literal_kind_names{
    "number", "money", "quantity", "duration", "rate", "date", "text"};

/// Operators, loosest first: or, and, not, the comparisons and membership,
/// + and -, then * and /.
enum class Operator : std::uint8_t {
    none,
    logical_or,
    logical_and,
    logical_not,
    equals,
    less,
    less_equal,
    greater,
    greater_equal,
    member, ///< `in`
    plus,
    minus,
    times,
    divide,
};

/// Operator's enumerator names, in order (checked by reflection).
inline constexpr std::array<std::string_view, 14> operator_names{
    "none",    "logical_or",    "logical_and", "logical_not", "equals", "less",  "less_equal",
    "greater", "greater_equal", "member",      "plus",        "minus",  "times", "divide"};

/// How each operator is written in the canonical dump, in enumerator order.
inline constexpr std::array<std::string_view, 14> operator_texts{
    "", "or", "and", "not", "=", "<", "<=", ">", ">=", "in", "+", "-", "*", "/"};

struct Literal {
    LiteralKind kind = LiteralKind::number;
    /// number, money, quantity, duration, rate (in percent).
    Decimal number;
    /// money: the currency; quantity: the unit; duration: the time unit.
    const Concept* unit = nullptr;
    Date date;
    /// text: as written, without the quotes.
    std::string text;
};

struct Expr {
    ExprKind kind = ExprKind::literal;
    Span span;
    Literal literal;
    std::string name;
    const Concept* concept_entry = nullptr;
    Operator op = Operator::none;
    std::vector<Expr> operands;
};

// ---------------------------------------------------------------------------
// Lines in blocks.

/// A line of a kind's or a charge's block (`amount HKD`, `traffic monthly
/// 2TB, overage per GB HKD 0.10`), or one input after `with`: the field, and
/// its type or value, one expression per comma-separated part; in a block,
/// the value after `=` at the end of the line, an instance field's default
/// (`count number = 0`).
struct Field {
    static constexpr std::string_view tag = "field";
    Span span;
    Expr head;
    std::vector<Expr> values;
    std::optional<Expr> initial;
};

/// `FIELD = VALUE` at the start of an action's line, or after `with` in a
/// step: sets the field (inside a condition, `=` compares instead).
struct Set {
    static constexpr std::string_view tag = "set";
    Span span;
    Expr target;
    Expr value;
};

/// An action done: `notify customer`, `issuer pays`, a test's step
/// `supplier pledge to bank at 2027-01-06 in person`.
struct Do {
    static constexpr std::string_view tag = "do";
    Span span;
    /// The party that acts, where the line names one before the action.
    std::optional<Expr> subject;
    /// A word of category action, or a name the contract declares.
    Expr action;
    std::vector<Expr> args;
    std::optional<Expr> to;
    std::optional<Expr> by;
    std::vector<Set> with;
    /// A test's step that answers a request , `executor notify done`:
    /// the outcome's keyword (kw.done, kw.fails, or kw.expires) after the
    /// request's kind, which `action` holds; null for any other step.
    const Concept* outcome = nullptr;
};

/// `request KIND [to PARTY] [with NAME = VALUE, ...] within DURATION` :
/// asks an executor to act outside the ledger. The kind is a name or an
/// action's word; `within` is the word `within` and its duration.
struct Request {
    static constexpr std::string_view tag = "request";
    Span span;
    Expr kind;
    std::optional<Expr> to;
    std::vector<Set> with;
    std::optional<Expr> within;
};

/// `requires CONDITION`, or `GUARD requires CONDITION` (`over 5_000_000
/// requires in person`: the condition holds when the guard does).
struct Requires {
    static constexpr std::string_view tag = "requires";
    Span span;
    Expr condition;
    std::optional<Expr> guard;
};

/// `AI agent can propose`: who may start the action, and how.
struct Permit {
    static constexpr std::string_view tag = "permit";
    Span span;
    Expr who;
    Expr action;
};

struct Reject {
    static constexpr std::string_view tag = "reject";
    Span span;
    std::string message;
};

/// `active -> suspended`, or `-> pledged` from any state.
struct Transition {
    static constexpr std::string_view tag = "transition";
    Span span;
    std::vector<Expr> from;
    Expr to;
};

/// A test's expectation: `-> pledged`, `-> refused "reason"`, and the values
/// of fields after it (`-> delivered, fee = HKD 4_000`, or `-> fee = HKD 0`
/// with no outcome: accepted).
struct Expect {
    static constexpr std::string_view tag = "expect";
    Span span;
    std::optional<Expr> outcome;
    std::optional<std::string> reason;
    std::vector<Set> fields;
};

struct Statement;

/// `if CONDITION` with its block, and `otherwise` with its own (`otherwise
/// if` nests another If there).
struct If {
    static constexpr std::string_view tag = "if";
    Span span;
    Expr condition;
    std::vector<Statement> then;
    std::vector<Statement> otherwise;
};

/// `each NAME in LIST` with its block.
struct Each {
    static constexpr std::string_view tag = "each";
    Span span;
    Expr name;
    Expr list;
    std::vector<Statement> body;
};

struct Statement {
    std::variant<Requires, Permit, If, Each, Reject, Set, Transition, Do, Expect, Request> node;
};

// ---------------------------------------------------------------------------
// Clauses: the lines outside any block.

struct Contract {
    static constexpr std::string_view tag = "contract";
    Span span;
    Expr name;
};

struct Parties {
    static constexpr std::string_view tag = "parties";
    Span span;
    std::vector<Expr> parties;
};

/// `asset Receivable` (a kind word, then a name; the kind word is required)
/// or `charge 增值税`, with its fields.
struct Block {
    static constexpr std::string_view tag = "block";
    Span span;
    const Concept* kind = nullptr;
    Expr name;
    std::vector<Field> fields;
};

/// `can ACTION [by PARTY] [to PARTY] [with INPUTS]` and its block.
struct Can {
    static constexpr std::string_view tag = "can";
    Span span;
    Expr action;
    std::optional<Expr> by;
    std::optional<Expr> to;
    std::vector<Field> inputs;
    std::vector<Statement> body;
};

/// `when EVENT [ACTIONS]` and its block.
struct When {
    static constexpr std::string_view tag = "when";
    Span span;
    Expr event;
    std::vector<Do> actions;
    std::vector<Statement> body;
};

/// `when KIND done`, `when KIND fails`, `when KIND expires` : a rule
/// for the answers to the contract's requests of a kind (a name or an
/// action's word), its outcome the keyword after it, then the actions on its
/// line and its block, as for a time rule.
struct AnswerRule {
    static constexpr std::string_view tag = "answer";
    Span span;
    Expr kind;
    const Concept* outcome = nullptr;
    std::vector<Do> actions;
    std::vector<Statement> body;
};

/// `test [NAME | "TEXT"]` and its steps (Do) and expectations (Expect).
struct Test {
    static constexpr std::string_view tag = "test";
    Span span;
    std::optional<Expr> name;
    std::vector<Statement> steps;
};

using Clause = std::variant<Contract, Parties, Block, Can, When, Test, AnswerRule>;

/// `use finance`: the source uses a vocabulary pack. Pack ids are
/// ASCII and stay as written in every language (`使用 finance`).
struct Use {
    static constexpr std::string_view tag = "use";
    Span span;
    std::string pack;
};

/// The first word of a vocabulary pack in a source (outside `use` lines):
/// where the checker says the pack is not used, if it is not.
struct PackWord {
    const Concept* concept_entry = nullptr;
    Span span;
};

struct File {
    /// From `bo N`; 1 without it.
    std::uint64_t edition = 1;
    /// The `use` lines, in source order.
    std::vector<Use> uses;
    std::vector<Clause> clauses;
    /// The first word of each vocabulary pack the source has, in source
    /// order (one for each pack).
    std::vector<PackWord> pack_words;
    /// Read with the official packs of before vocabulary packs: every
    /// vocabulary pack is used without `use` (pack.hpp, Officials).
    bool implicit_vocabulary = false;
    /// The vocabulary packs it was read with (PackSet::vocabularies): those
    /// its `use` lines may name, and the users' packs' terms.
    std::shared_ptr<const Vocabularies> vocabularies;
};

} // namespace cexchain::bo::ast
