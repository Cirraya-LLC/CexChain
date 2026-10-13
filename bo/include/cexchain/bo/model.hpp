// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>

/// The checked model of a contract (checker.hpp builds it from a tree): its
/// parties, the one kind of instance it describes and that kind's fields, its
/// charges, its states, its actions, and its time rules, with every name
/// resolved and every expression typed. Like the tree, it holds concepts and
/// names, never spellings, so every language gives the same model.
///
/// Whatever Bo infers rather than reads (a field's type from the vocabulary,
/// the state an instance starts in, a consent an action needs, a threshold's
/// unit) carries the id of the rule that inferred it (`rule`, an id of
/// rule_specs(): "R1", ...), so that `explain` can spell it out. Recognition
/// never guesses: a rule is fixed by the edition, and where none applies the
/// checker reports an error instead.
namespace cexchain::bo::model {

enum class TypeKind : std::uint8_t {
    unknown,    ///< after an error: no further message about it
    number,     ///< a whole number
    money,      ///< an amount in `currency`, kept in its smallest unit
    quantity,   ///< a quantity of `dimension`, kept in the base unit
    rate,       ///< a percentage, kept in millionths
    date,       ///< a calendar date (the contract's UTC offset applies)
    duration,   ///< days and weeks, or months and years (`calendar`)
    text,       ///< a text
    yes_no,     ///< yes or no: conditions
    party,      ///< one of the contract's parties
    state,      ///< a state of the instance
    list,       ///< at most `bound` items of `element[0]`
    unit_price, ///< money in `currency` per unit of `dimension` (6 decimals)
    recurring,  ///< `element[0]` each `period` (monthly HKD 120)
    basis,      ///< what a charge depends on (according to customer location)
};

/// TypeKind's names, in enumerator order (checked by reflection).
inline constexpr std::array<std::string_view, 15> type_kind_names{
    "unknown", "number", "money", "quantity", "rate",       "date",      "duration", "text",
    "yes_no",  "party",  "state", "list",     "unit_price", "recurring", "basis"};

/// What a quantity measures. Units of one dimension convert exactly (TB is
/// 1,000 GB, TiB 1,024 GiB); units of two never mix.
enum class Dimension : std::uint8_t {
    none,
    data,      ///< bytes: MB, GB, TB, MiB, GiB, TiB
    bandwidth, ///< bits per second: Mbps, Gbps
    count,     ///< items
    mass,      ///< grams: kg, tonnes
};

inline constexpr std::array<std::string_view, 5> dimension_names{"none", "data", "bandwidth",
                                                                 "count", "mass"};

struct Type {
    TypeKind kind = TypeKind::unknown;
    /// money, unit_price: a cur.* concept.
    const Concept* currency = nullptr;
    /// quantity, unit_price.
    Dimension dimension = Dimension::none;
    /// duration: months or years, which have no fixed length.
    bool calendar = false;
    /// recurring: time.daily, weekly, monthly, or yearly.
    const Concept* period = nullptr;
    /// quantity: the unit it was declared or written with (a bare threshold
    /// takes it), if any. Not part of the type: units of a dimension convert.
    const Concept* unit = nullptr;
    /// list: the most items it holds (0: any list, in messages only).
    std::uint32_t bound = 0;
    /// list, recurring: the item's type (one element).
    std::vector<Type> element;
};

/// What a name or a vocabulary word in an expression stands for.
enum class Refers : std::uint8_t {
    none,
    party,  ///< a role of `parties`
    field,  ///< a field of the instance
    input,  ///< an input of the action (`with`)
    item,   ///< the name an `each` gives
    state,  ///< a state of the instance
    action, ///< an action (in `do`)
};

inline constexpr std::array<std::string_view, 7> refers_names{"none", "party", "field", "input",
                                                              "item", "state", "action"};

/// A typed expression: the tree's expression (ast::Expr), with what it
/// means. A rule is set where the meaning was inferred: a bare threshold
/// given the amount's unit (R6), a state read as a condition (R7), a name
/// read as a text (R18), presence asked of the starter (R13).
struct Expr {
    ast::ExprKind kind = ast::ExprKind::literal;
    Span span;
    Type type;
    ast::Literal literal;
    std::string name;
    const Concept* concept_entry = nullptr;
    ast::Operator op = ast::Operator::none;
    Refers refers = Refers::none;
    std::string_view rule;
    std::vector<Expr> operands;
};

// ---------------------------------------------------------------------------
// Statements in an action's or a time rule's block (as in the tree; a
// permit line becomes the action's `agents_propose`).

struct Statement;

struct Requires {
    static constexpr std::string_view tag = "requires";
    Span span;
    Expr condition;
    std::optional<Expr> guard;
};

struct If {
    static constexpr std::string_view tag = "if";
    Span span;
    Expr condition;
    std::vector<Statement> then;
    std::vector<Statement> otherwise;
};

struct Each {
    static constexpr std::string_view tag = "each";
    Span span;
    std::string name;
    Expr list;
    std::vector<Statement> body;
};

struct Reject {
    static constexpr std::string_view tag = "reject";
    Span span;
    std::string message;
};

/// `FIELD = VALUE`: the target refers to a field (or, in `do ... with`, to
/// an input of the action done).
struct Set {
    static constexpr std::string_view tag = "set";
    Span span;
    Expr target;
    Expr value;
};

/// `FROM, ... -> TO`: states (no FROM: from any state).
struct Transition {
    static constexpr std::string_view tag = "transition";
    Span span;
    std::vector<Expr> from;
    Expr to;
};

/// An action done. In a time rule, an action with a subject is a duty of
/// that party (R9: `when due issuer pays`), never a call. `executor` marks an
/// action that asks an executor to act outside the ledger (R10), which comes
/// in step 6b: checked and explained, but not built yet.
struct Do {
    static constexpr std::string_view tag = "do";
    Span span;
    std::optional<Expr> subject;
    Expr action;
    std::vector<Expr> args;
    std::optional<Expr> to;
    std::optional<Expr> by;
    std::vector<Set> with;
    bool obligation = false;
    bool executor = false;
    std::string_view rule;
};

struct Statement {
    std::variant<Requires, If, Each, Reject, Set, Transition, Do> node;
};

// ---------------------------------------------------------------------------
// Declarations.

enum class Binding : std::uint8_t {
    creation, ///< bound to a ledger when an instance is created
    action,   ///< bound by the action that first names it after `to` (U4)
};

inline constexpr std::array<std::string_view, 2> binding_names{"creation", "action"};

/// A role of `parties`: a role word (role.bank) or a name of the contract's.
struct Party {
    Span span;
    const Concept* role = nullptr;
    std::string name;
    Binding binding = Binding::creation;
    /// Binding::action: the action's key (act.pledge, or a name).
    std::string bound_by;
    std::string_view rule;
};

enum class FieldKind : std::uint8_t {
    constant, ///< given its value in the block: the same for every instance
    instance, ///< each instance's own: set at creation, and by actions
};

inline constexpr std::array<std::string_view, 2> field_kind_names{"constant", "instance"};

/// A field of the instance, or an input of an action: a vocabulary word
/// (field.amount, price.price) or a name.
struct Field {
    Span span;
    const Concept* word = nullptr;
    std::string name;
    FieldKind kind = FieldKind::instance;
    Type type;
    /// A constant's value, or the party a party field starts with (R2).
    std::optional<Expr> value;
    /// Further parts after commas: labelled prices (overage per GB HKD 0.10).
    std::vector<Expr> more;
    std::string_view rule;
};

/// A line of a charge's block (`rate 6%`, `applies to ...`, `added`,
/// `from 2027-01-01 on rate 9%`): its head word, the head's argument, and
/// its values, typed. Charges are computed in milestone 13.
struct ChargeLine {
    Span span;
    const Concept* head = nullptr;
    std::optional<Expr> argument;
    std::vector<Expr> values;
};

struct Charge {
    Span span;
    /// charge.charge or charge.tax.
    const Concept* kind = nullptr;
    std::string name;
    std::vector<ChargeLine> lines;
};

/// A state of the instance: a state word or a name, collected from the state
/// changes (R5). The first state is where every instance starts (R4).
struct State {
    Span span;
    const Concept* word = nullptr;
    std::string name;
    bool first = false;
    std::string_view rule;
};

/// A consent an action needs that no line states: changing a field that
/// holds a party takes something from that party (R8).
struct Consent {
    Span span;
    Expr party;
    std::string_view rule;
};

/// `can ACTION`: a vocabulary action (its template comes from the standard
/// library, milestone 11, and adds to what is written here) or the
/// contract's own.
struct Action {
    Span span;
    const Concept* word = nullptr;
    std::string name;
    std::optional<Expr> by;
    std::optional<Expr> to;
    std::vector<Field> inputs;
    std::vector<Statement> body;
    std::vector<Consent> consents;
    /// `AI agent can propose`: an agent's call waits for a person's approval.
    /// Otherwise agents act within their delegation (R14, in `agents_rule`).
    bool agents_propose = false;
    std::string_view agents_rule;
    /// R10: the action asks an executor to act outside the ledger.
    bool executor = false;
    std::string_view executor_rule;
};

/// `when EVENT`: a time rule. The event is a date (`due`) or a condition on
/// time (`7 days before due`, `overdue 3 days`).
struct TimeRule {
    Span span;
    Expr event;
    std::vector<Do> actions;
    std::vector<Statement> body;
    /// As for an action (R8): the keeper's call waits for them.
    std::vector<Consent> consents;
};

enum class DueKind : std::uint8_t {
    none,   ///< nothing is due
    field,  ///< the instance's `due` date field
    period, ///< a service with a recurring price: the end of each period (R11)
};

inline constexpr std::array<std::string_view, 3> due_kind_names{"none", "field", "period"};

struct Model {
    std::uint64_t edition = 1;
    /// From `contract NAME`; empty for a fragment.
    std::string name;
    std::vector<Party> parties;
    /// The kind of instance (kind.asset, ...) and its name, if the contract
    /// has a block for one.
    const Concept* kind = nullptr;
    std::string kind_name;
    /// The kind's fields, and those a rule adds (R12).
    std::vector<Field> fields;
    std::vector<Charge> charges;
    /// The first state first.
    std::vector<State> states;
    std::vector<Action> actions;
    std::vector<TimeRule> rules;
    DueKind due = DueKind::none;
    std::string_view due_rule;
};

/// The key of something with a concept or a name: the concept's id, or the
/// name (names never hold a dot, ids always do).
[[nodiscard]] inline std::string key(const Concept* word, const std::string& name) {
    return word != nullptr ? std::string(word->id) : name;
}

} // namespace cexchain::bo::model
