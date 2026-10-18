// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <set>
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
    data,        ///< bytes: MB, GB, TB, MiB, GiB, TiB
    bandwidth,   ///< bits per second: Mbps, Gbps
    count,       ///< items
    mass,        ///< grams: kg, tonnes
    temperature, ///< hundredths of a degree Celsius: °C (G5b)
};

inline constexpr std::array<std::string_view, 6> dimension_names{"none",  "data", "bandwidth",
                                                                 "count", "mass", "temperature"};

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
    charge, ///< a charge: its amount on the instance's bill (R26)
};

inline constexpr std::array<std::string_view, 8> refers_names{"none", "party", "field",  "input",
                                                              "item", "state", "action", "charge"};

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
///
/// `parts` marks the creation word in an action's own block (R30): `issue
/// PARTS to RECIPIENTS [with FIELD = VALUE, ...]` issues parts, each an
/// instance of its own created by the call (spec section 15): `args[0]` the
/// list of amounts, `to` the list of parties, `with` the fields each part
/// gets (their targets refer to fields, their values read this instance).
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
    bool parts = false;
    std::string_view rule;
};

/// `request KIND [to PARTY] [with NAME = VALUE, ...] within DURATION` (E8):
/// the call asks an executor to act outside the ledger. Compiled code adds
/// the request to the call's accept (key 7): its kind, its params (a map of
/// `to` and each value by name), its deadline (the time of the call plus the
/// duration), and the function an answer calls (reply_function).
struct Request {
    static constexpr std::string_view tag = "request";
    Span span;
    /// The kind, as compiled code names it: a name as written, or an action
    /// word's name (act.notify: notify).
    std::string kind;
    /// The action word it is spelled as, if any (for the contract text).
    const Concept* word = nullptr;
    /// The party it concerns: params key "to".
    std::optional<Expr> to;
    /// The values it carries, by name: each target holds the name (or a
    /// word), its value typed.
    std::vector<Set> with;
    /// Within how long it is to be answered: a duration literal.
    Expr within;
    /// R34 (E9): counted from the due date (paid until) rather than from
    /// the call, and kept at least a day and at most 366 days after the call
    /// (a service's collection: by the latest overdue rule's time).
    bool from_due = false;
    /// The rule that made it, if Bo added it rather than reading it: R10
    /// (an action that asks an executor, notify PARTY), R34 and R35 (a
    /// service's bills and payments).
    std::string_view rule;
};

struct Statement {
    std::variant<Requires, If, Each, Reject, Set, Transition, Do, Request> node;
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
    /// R23: bound again by each call of the action that binds it (a
    /// resource's allocate), not only by the first.
    bool each_call = false;
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
    /// An instance field's default (`count number = 0`): a literal of its
    /// type, which an instance holds when its creation does not give the
    /// field.
    std::optional<Expr> initial;
    /// Further parts after commas: labelled prices (overage per GB HKD 0.10).
    std::vector<Expr> more;
    std::string_view rule;
    /// A party field that may hold no party (`none`): one an action sets to
    /// none, or one the standard terms add (R20).
    bool optional = false;
    /// R20: added by the standard terms; each instance starts with none, so
    /// it is not given at creation.
    bool empty_at_start = false;
};

/// A line of a charge's block (`rate 6%`, `applies to ...`, `added`,
/// `from 2027-01-01 on rate 9%`): its head word, the head's argument, and
/// its values, typed.
struct ChargeLine {
    Span span;
    const Concept* head = nullptr;
    std::optional<Expr> argument;
    std::vector<Expr> values;
};

/// `from DATE on rate R`: a rate in force from a day on (R28).
struct DatedRate {
    /// A date literal: its local midnight at the contract's offset.
    Expr date;
    Expr rate;
};

/// A charge (tax, fee, commission): what its lines say, read once by the
/// checker, so that compiled code and the contract text agree. Charges are
/// computed on the contract's bill (R26), in the order written (R27).
struct Charge {
    Span span;
    /// charge.charge or charge.tax.
    const Concept* kind = nullptr;
    std::string name;
    std::vector<ChargeLine> lines;
    /// Included in the price (taken out of it), or added to it.
    bool included = false;
    /// A rate (its plain one, and those from a date on, by date), or a fixed
    /// amount of money.
    std::optional<Expr> rate;
    std::vector<DatedRate> dated;
    std::optional<Expr> amount;
    /// `applies to`: it applies only when this holds (on the whole bill).
    std::optional<Expr> condition;
    /// Rounded (or, for a fixed amount, charged) once per bill rather than
    /// on each line; `document` is the document `according to` names.
    bool per_document = false;
    const Concept* document = nullptr;
    /// The rounding mode (round.*); null: half up (R17).
    const Concept* rounding = nullptr;
    /// What it is computed on (`according to price, OTHER`): the price (the
    /// lines), and charges written before it, by index (R27).
    bool on_price = true;
    std::vector<std::uint64_t> on;
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

/// `can ACTION`: a vocabulary action (the standard library's terms for it, if
/// it has some, follow the contract's own lines: R19) or the contract's own.
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
    /// R19: a vocabulary action with the standard library's terms. Its body
    /// is the contract's own lines, then, from `terms_from` on, the terms'.
    bool terms = false;
    std::uint64_t terms_from = 0;
    /// A built-in action that only the contract's time rules do (no `can`
    /// declares it): compiled code has no function of its own for it.
    bool rule_only = false;
};

/// How a request went, as a rule for its answers names it (E8): done, or
/// failed, or expired (no answer by the deadline).
enum class Outcome : std::uint8_t { done, fails, expires };

inline constexpr std::array<std::string_view, 3> outcome_names{"done", "fails", "expires"};

/// `when KIND done`, `when KIND fails`, `when KIND expires` (E8): what the
/// contract does when an answer to one of its requests of that kind comes.
/// Compiled code runs it in the reply function (reply_function), which takes
/// every answer: it never refuses one, so its block asks no consent and
/// refuses nothing.
struct AnswerRule {
    Span span;
    std::string kind;
    const Concept* word = nullptr;
    Outcome outcome = Outcome::done;
    std::vector<Statement> body;
    /// R33: a rule for failures that also takes the kind's expired answers,
    /// as the contract has no rule for them.
    bool expired = false;
    std::string_view rule;
};

/// `when EVENT`: a time rule. The event is a date (`due`) or a condition on
/// time (`7 days before due`, `overdue 3 days`, `suspended 30 days`), with
/// other conditions joined by `and` (trigger_of finds its time). Unless it
/// only states duties (R9), compiled code gives it a function that a keeper
/// calls once its time has come (R24; rule_functions names them).
struct TimeRule {
    Span span;
    Expr event;
    std::vector<Do> actions;
    std::vector<Statement> body;
    /// As for an action (R8): the keeper's call waits for them.
    std::vector<Consent> consents;
};

// ---------------------------------------------------------------------------
// Tests (`test` blocks, U8): scenarios `bo test` runs on the compiled
// contract as a ledger would. They are no part of the code.

/// What a step expects.
enum class Expectation : std::uint8_t {
    accepted, ///< nothing written: the call is accepted, into any state
    state,    ///< `-> STATE`: accepted, and the instance is then in STATE
    refused,  ///< `-> refused ["REASON"]`: refused (with that reason)
    waits,    ///< `-> consent of PARTY`: the call waits for those parties' consent
    proposed, ///< `-> pending approval`: an AI agent's call, kept as a proposal
};

inline constexpr std::array<std::string_view, 5> expectation_names{"accepted", "state", "refused",
                                                                   "waits", "proposed"};

/// A party a test names: one of the contract's roles (a role word or a
/// name of `parties`), or a ledger only the test names (`bank1`). Each is a
/// test ledger of its own, keyed by `key(word, name)`; a role an action
/// binds stands, once bound, for the ledger it was bound to.
struct TestParty {
    Span span;
    const Concept* word = nullptr;
    std::string name;
    /// One of the contract's parties; otherwise a ledger only tests name.
    bool role = false;
};

/// A step: `SUBJECT ACTION [to PARTY] [by AI agent] [with INPUT = VALUE,
/// ...] [at DATE] [in person] [-> EXPECTATION]`. The first step of a test
/// creates its instance (`issue` for an asset, `create` otherwise), and its
/// subject is the home, whose ledger runs the contract.
struct Step {
    Span span;
    /// The party that acts.
    TestParty subject;
    /// The action, by its concept or its name; the creation's concept.
    const Concept* word = nullptr;
    std::string name;
    bool creation = false;
    /// `PARTY approve`: approves the first proposal the instance keeps.
    bool approve = false;
    /// `keeper ACTION`: the keeper calls the time rule `rule` (an index of
    /// Model::rules), the one whose function does ACTION.
    bool keeper = false;
    std::uint64_t rule = 0;
    std::optional<TestParty> to;
    /// The party holding the instance the step acts on (`issuer pay
    /// smith1`), once a split has made parts; without it, the instance the
    /// subject holds, is pledgee or payee of (scenario.hpp).
    std::optional<TestParty> part;
    /// The values given, typed: the action's inputs, or at creation the
    /// fields given at creation. Each is a literal (or yes, no, a list).
    std::vector<Set> with;
    /// `at DATE`: the day the step happens (a date literal).
    std::optional<Expr> at;
    /// `in person`: the subject is a person who proves presence.
    bool in_person = false;
    /// `by AI agent`: the subject's signer is an AI agent.
    bool agent = false;
    /// An answer to a request (E8): `executor notify done`, `keeper notify
    /// expires`: the oldest open request of the kind is answered, with the
    /// values `with` gives (result, reason). The subject signs it.
    bool answer = false;
    std::string request_kind;
    Outcome outcome = Outcome::done;
    Expectation expect = Expectation::accepted;
    Span expect_span;
    /// Expectation::state: the state, a word or a name.
    const Concept* state_word = nullptr;
    std::string state_name;
    /// Expectation::refused: the reason, as the contract gives it.
    std::optional<std::string> reason;
    /// Expectation::waits: the parties whose consent the call waits for.
    std::vector<TestParty> waits;
    /// Expectation::accepted or state: the values of instance fields the
    /// step expects after the call (`-> delivered, fee = HKD 4_000`), each
    /// a value written out, a test's party, or none.
    std::vector<Set> fields;
};

struct Test {
    Span span;
    /// As written (a text or a name); empty if the test has none.
    std::string name;
    std::vector<Step> steps;
};

enum class DueKind : std::uint8_t {
    none,   ///< nothing is due
    field,  ///< the instance's `due` date field
    period, ///< a service with a recurring price: the end of each period (R11)
};

inline constexpr std::array<std::string_view, 3> due_kind_names{"none", "field", "period"};

struct Model {
    std::uint64_t edition = 1;
    /// The vocabulary packs the source uses (`use`), by ascending id.
    std::vector<std::string> packs;
    /// Those packs, as read (vocab.hpp): an official one at its release's
    /// version, or a user's.
    std::vector<const VocabularyPack*> vocabularies;
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
    /// The rules for the answers to requests (E8), in source order.
    std::vector<AnswerRule> answers;
    DueKind due = DueKind::none;
    std::string_view due_rule;
    /// The contract's offset from UTC, in milliseconds east (U6): its `UTC
    /// offset`, else +08:00 (R25, `offset_rule`).
    std::int64_t utc_offset_ms = 8 * 3'600'000;
    std::string_view offset_rule;
    /// The `test` blocks, in source order.
    std::vector<Test> tests;
};

/// The key of something with a concept or a name: the concept's id, or the
/// name (names never hold a dot, ids always do).
[[nodiscard]] inline std::string key(const Concept* word, const std::string& name) {
    return word != nullptr ? std::string(word->id) : name;
}

// ---------------------------------------------------------------------------
// What compiled code makes of a model, shared by lowering (which writes it
// into the code) and `explain` (which writes it into the contract text), so
// that the text says what the code does.

/// The states an action can start from, by its top-level lines before
/// anything that may change the state: the FROM states of its first state
/// change, narrowed by `requires STATE` (or `requires STATE or STATE`)
/// before it. Nullopt: any state.
[[nodiscard]] std::optional<std::set<std::string>> entry_states(const Action& action);

/// For each of the model's states, in order: true if it is final, that is,
/// no action can start from it (none is final while some action can start
/// from any state). A final instance takes no more calls.
[[nodiscard]] std::vector<bool> final_states(const Model& model);

/// The key of the action's one amount, which `over N` compares (R6): its
/// one input of money or a quantity, or, with none, the instance's
/// `amount` if that is money or a quantity. Nullopt if there is no such
/// amount (several inputs, or none and no amount).
[[nodiscard]] std::optional<std::string> action_amount(const Model& model, const Action& action);

/// The name of the function that creates an instance: `issue` for an
/// asset, `create` otherwise.
[[nodiscard]] std::string_view creation_function(const Model& model) noexcept;

/// True if some action lets AI agents only propose it, so that compiled code
/// keeps proposals and has a function `approve`.
[[nodiscard]] bool has_proposals(const Model& model) noexcept;

/// True if a transition goes back to the state before (`previous state`),
/// so that compiled code keeps that state.
[[nodiscard]] bool uses_previous(const Model& model) noexcept;

/// The field that holds the contract's bill (R26): the one named by a
/// document (invoice, credit note, receipt), a list of money. Null if none.
[[nodiscard]] const Field* bill_field(const Model& model) noexcept;

/// The statement by which an action issues parts (R30), if it has one: the
/// creation word in its own block (never nested).
[[nodiscard]] const Do* issued_parts(const Action& action) noexcept;

/// True if some action issues parts.
[[nodiscard]] bool issues_parts(const Model& model) noexcept;

/// R31: the field (holder, pledgee, or payee) that an action's block sets
/// to its counterparty (`to`, a role or a party field), the first such line
/// depth first; null if it sets none of them to it.
[[nodiscard]] const Concept* role_taken(const Action& action);

/// The deepest a part may be (spec section 15): an instance at this depth
/// creates no parts.
inline constexpr std::uint64_t max_part_depth = 8;
/// The most items a list may hold: `at most N` with N at most this (R16).
inline constexpr std::uint64_t max_list_bound = 1'000;

/// The name of the function that approves a proposal.
inline constexpr std::string_view approve_function = "approve";

// ---------------------------------------------------------------------------
// Time rules (milestone 12).

enum class TriggerKind : std::uint8_t {
    date,       ///< a date: `when due`, `when start + 3 days`
    before_due, ///< `when 7 days before due`: the due date less N
    overdue,    ///< `when overdue` (the day after the due date) or `overdue N` (due + N)
    held,       ///< `when suspended 30 days`: N after the instance entered the state
};

inline constexpr std::array<std::string_view, 4> trigger_kind_names{"date", "before_due", "overdue",
                                                                    "held"};

/// The time a rule's event names, as pointers into the event.
struct Trigger {
    TriggerKind kind = TriggerKind::date;
    /// date: the date; before_due, held, and overdue N: the duration (null
    /// for a bare `overdue`).
    const Expr* value = nullptr;
    /// held: the state.
    const Expr* state = nullptr;
    /// The event's other conditions: the other operands of the `and`s that
    /// join the trigger to them, in order.
    std::vector<const Expr*> conditions;
};

/// The one time an event names: a date (without now or today), or one of
/// the forms above, alone or joined to other conditions by `and`. Nullopt if
/// it names none, more than one, or one inside `or` or `not`.
[[nodiscard]] std::optional<Trigger> trigger_of(const Expr& event);

/// True if a yes-or-no expression is one of the trigger forms (not a date).
[[nodiscard]] bool is_trigger(const Expr& e) noexcept;

/// True if a rule does something besides stating duties (R9): an action, or
/// a block. Only such a rule has a function.
[[nodiscard]] bool rule_runs(const TimeRule& rule) noexcept;

/// The function compiled code gives each time rule, in the model's order
/// (empty for a rule that only states duties): "when." and the first action
/// it does, else the kind of the first request it makes (E8), else the state
/// its first state change leads to, else "rule";
/// ".2", ".3", ... when that name is taken by an earlier rule.
[[nodiscard]] std::vector<std::string> rule_functions(const Model& model);

/// The actions a rule does, in order (its line's, then its block's, depth
/// first): each a Do that states no duty and asks no executor.
[[nodiscard]] std::vector<const Do*> rule_actions(const TimeRule& rule);

/// The model's action a rule's Do names, if any.
[[nodiscard]] const Action* action_of(const Model& model, const Do& d) noexcept;

/// True if compiled code keeps the time the instance last changed state
/// (`since`): some expression asks `within N`, or how long a state is held.
[[nodiscard]] bool uses_since(const Model& model) noexcept;

// ---------------------------------------------------------------------------
// Requests (E8).

/// The function every request names as its reply: answers call it.
inline constexpr std::string_view reply_function = "result";
/// The most requests one call makes, and the most bytes a request's params
/// take (spec section 15).
inline constexpr std::uint64_t max_call_requests = 16;
inline constexpr std::uint64_t max_request_params = 4'096;
/// A request's deadline is at most this long after its call (366 days).
inline constexpr std::int64_t max_request_ms = 31'622'400'000;

/// The requests in a block, depth first, in order (those of actions it does
/// not included).
[[nodiscard]] std::vector<const Request*> requests_in(const std::vector<Statement>& list);

/// True if the contract makes requests: compiled code then has the reply
/// function.
[[nodiscard]] bool makes_requests(const Model& model);

/// The rule that takes an answer of `status` (1 done, 2 failed, 3 expired)
/// to a request of `kind`, if the contract has one: a rule for failures
/// takes expired answers too unless one is for expiry (R33).
[[nodiscard]] const AnswerRule* answer_rule(const Model& model, std::string_view kind,
                                            int status) noexcept;

} // namespace cexchain::bo::model
