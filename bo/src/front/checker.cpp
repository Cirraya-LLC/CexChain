// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The checker (milestone 4 of the Bo compiler): a parsed tree to the checked
// model of model.hpp. What it reads and checks is listed in checker.hpp. It
// works in passes over the tree: the declarations (parties, the kind and its
// fields, the actions and their inputs, the states the state changes name),
// then what the rules infer from them (the first state, how roles are bound,
// what is due), then each action and time rule, typed, and last what needs
// the whole contract (reachable states, recursion). Values are exact: no
// floating point, and every amount, quantity, rate, and duration is checked
// to fit its smallest unit in 64 bits. Nothing depends on addresses or on
// unordered iteration.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <format>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/stdlib.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/bo/vocab.hpp>

#include "internal.hpp"

namespace cexchain::bo {

namespace {

namespace m = model;
using ast::ExprKind;
using ast::Operator;
using m::Dimension;
using m::Refers;
using m::Type;
using m::TypeKind;

template <class... F>
struct Overloaded : F... {
    using F::operator()...;
};

// The recognition rules (concepts.cpp lists them; packs give their texts).
constexpr std::string_view rule_field_meaning = "R1";
constexpr std::string_view rule_party_field = "R2";
constexpr std::string_view rule_role_binding = "R3";
constexpr std::string_view rule_first_state = "R4";
constexpr std::string_view rule_states = "R5";
constexpr std::string_view rule_threshold = "R6";
constexpr std::string_view rule_state_condition = "R7";
constexpr std::string_view rule_consent_taken = "R8";
constexpr std::string_view rule_obligation = "R9";
constexpr std::string_view rule_executor = "R10";
constexpr std::string_view rule_service_due = "R11";
constexpr std::string_view rule_customer_location = "R12";
constexpr std::string_view rule_presence = "R13";
constexpr std::string_view rule_agents = "R14";
constexpr std::string_view rule_parts = "R15";
constexpr std::string_view rule_list_bound = "R16";
constexpr std::string_view rule_rounding = "R17";
constexpr std::string_view rule_bare_text = "R18";
constexpr std::string_view rule_standard_terms = "R19";
constexpr std::string_view rule_standard_fields = "R20";
constexpr std::string_view rule_counterparty = "R21";
constexpr std::string_view rule_zero = "R22";
constexpr std::string_view rule_utc_offset = "R25";
constexpr std::string_view rule_bill = "R26";
// R27 (how a charge computes) is marked where the model states it (dump).
constexpr std::string_view rule_rate_in_force = "R28";
constexpr std::string_view rule_one_item = "R29";
constexpr std::string_view rule_issue_parts = "R30";
constexpr std::string_view rule_role_taking = "R31";
constexpr std::string_view rule_whole_times = "R32";
constexpr std::string_view rule_expired = "R33";
constexpr std::string_view rule_service_bill = "R34";
constexpr std::string_view rule_service_paid = "R35";

/// The fields the standard terms may add to an instance (R20), in the order
/// R20 adds them: those their packs mark as added (Concept::flags; parties
/// that hold the thing in some way, none until an action sets them), and a
/// resource's holder (it has none while in the pool). The order is the
/// model's, which compiled code follows; vocab_test.cpp checks the list
/// against the packs.
/// Then a service's periods (E9): the dates it is paid until and billed
/// until, which hold no date until it is subscribed to (R11, R34).
constexpr std::string_view standard_fields[] = {"field.pledgee", "field.payee", "field.holder",
                                                "field.paid_until", "field.billed_until"};

bool is(const Concept* c, std::string_view id) noexcept {
    return c != nullptr && c->id == id;
}

bool word_is(const ast::Expr& e, std::string_view id) noexcept {
    return e.kind == ExprKind::word && is(e.concept_entry, id);
}

bool word_in(const ast::Expr& e, Category category) noexcept {
    return e.kind == ExprKind::word && e.concept_entry != nullptr &&
           e.concept_entry->category == category;
}

// ---------------------------------------------------------------------------
// Units and exact values (values.hpp).

constexpr std::uint32_t default_list_bound = 16;
using model::max_list_bound;

// ---------------------------------------------------------------------------
// Types.

Type of(TypeKind kind) {
    Type t;
    t.kind = kind;
    return t;
}

Type money(const Concept* currency) {
    Type t = of(TypeKind::money);
    t.currency = currency;
    return t;
}

Type quantity(Dimension dimension, const Concept* unit) {
    Type t = of(TypeKind::quantity);
    t.dimension = dimension;
    t.unit = unit;
    return t;
}

Type duration(bool calendar) {
    Type t = of(TypeKind::duration);
    t.calendar = calendar;
    return t;
}

Type list_of(Type element, std::uint32_t bound) {
    Type t = of(TypeKind::list);
    t.bound = bound;
    t.element.push_back(std::move(element));
    return t;
}

Type recurring(const Concept* period, Type element) {
    Type t = of(TypeKind::recurring);
    t.period = period;
    t.element.push_back(std::move(element));
    return t;
}

Type unit_price(const Concept* currency, Dimension dimension) {
    Type t = of(TypeKind::unit_price);
    t.currency = currency;
    t.dimension = dimension;
    return t;
}

bool known(const Type& t) noexcept {
    if (t.kind == TypeKind::unknown) {
        return false;
    }
    return std::ranges::all_of(t.element, [](const Type& e) { return known(e); });
}

/// The same type: units within a dimension, and lists of any bound, are.
bool same(const Type& a, const Type& b) noexcept {
    if (a.kind != b.kind || a.element.size() != b.element.size()) {
        return false;
    }
    switch (a.kind) {
    case TypeKind::money:
        if (a.currency != b.currency) {
            return false;
        }
        break;
    case TypeKind::quantity:
        if (a.dimension != b.dimension) {
            return false;
        }
        break;
    case TypeKind::unit_price:
        if (a.currency != b.currency || a.dimension != b.dimension) {
            return false;
        }
        break;
    case TypeKind::duration:
        if (a.calendar != b.calendar) {
            return false;
        }
        break;
    case TypeKind::recurring:
        if (a.period != b.period) {
            return false;
        }
        break;
    default:
        break;
    }
    for (std::size_t i = 0; i < a.element.size(); ++i) {
        if (!same(a.element[i], b.element[i])) {
            return false;
        }
    }
    return true;
}

bool additive(TypeKind kind) noexcept {
    return kind == TypeKind::number || kind == TypeKind::money || kind == TypeKind::quantity ||
           kind == TypeKind::rate || kind == TypeKind::duration;
}

bool ordered(TypeKind kind) noexcept {
    return additive(kind) || kind == TypeKind::date;
}

/// The vocabulary's fields whose type the vocabulary fixes (R1): the type
/// each field's pack gives it (Concept::type).
std::optional<Type> vocabulary_type(const Concept* word) {
    const std::string_view type = word != nullptr ? word->type : std::string_view();
    if (type == "party") {
        return of(TypeKind::party);
    }
    if (type == "date") {
        return of(TypeKind::date);
    }
    if (type == "number") {
        return of(TypeKind::number);
    }
    if (type == "text") {
        return of(TypeKind::text);
    }
    if (type == "duration") {
        return duration(false);
    }
    if (type == "parties") {
        // A split's recipients: at most 16, as a call creates at most 16
        // instances (spec section 15).
        return list_of(of(TypeKind::party), 16);
    }
    return std::nullopt;
}

/// What a vocabulary field may hold, for messages.
Type vocabulary_expected(const Concept* word) {
    if (std::optional<Type> fixed = vocabulary_type(word)) {
        return *fixed;
    }
    const std::string_view type = word != nullptr ? word->type : std::string_view();
    if (type == "quantity" || type == "portion") {
        return of(TypeKind::quantity);
    }
    if (type == "list") {
        return of(TypeKind::list);
    }
    if (type == "offset") {
        return of(TypeKind::text);
    }
    return of(TypeKind::money);
}

bool vocabulary_accepts(const Concept* word, const Type& t) {
    const std::string_view type = word != nullptr ? word->type : std::string_view();
    if (type == "amount" || type == "portion") {
        return t.kind == TypeKind::money || t.kind == TypeKind::quantity;
    }
    if (type == "duration") {
        return t.kind == TypeKind::duration;
    }
    if (type == "parties") {
        return t.kind == TypeKind::list && t.element.size() == 1 &&
               t.element[0].kind == TypeKind::party;
    }
    return t.kind == vocabulary_expected(word).kind;
}

/// What a price word holds: price and setup fee money, traffic and usage a
/// quantity (each recurring, or not), overage a unit price.
bool pricing_accepts(const Concept* word, const Type& t) {
    const Type& inner = t.kind == TypeKind::recurring && !t.element.empty() ? t.element[0] : t;
    if (is(word, "price.price")) {
        return inner.kind == TypeKind::money;
    }
    if (is(word, "price.setup_fee")) {
        return t.kind == TypeKind::money;
    }
    if (is(word, "price.traffic") || is(word, "price.usage")) {
        return inner.kind == TypeKind::quantity;
    }
    if (is(word, "price.overage")) {
        return t.kind == TypeKind::unit_price;
    }
    return false;
}

Type pricing_expected(const Concept* word) {
    if (is(word, "price.traffic") || is(word, "price.usage")) {
        return of(TypeKind::quantity);
    }
    if (is(word, "price.overage")) {
        return of(TypeKind::unit_price);
    }
    return of(TypeKind::money);
}

/// A price word that labels a part of a field (overage per GB HKD 0.10).
bool is_label(const ast::Expr& e) noexcept {
    return word_in(e, Category::pricing) && !word_is(e, "price.per");
}

/// R10: the actions that ask an executor to act outside the ledger: notify,
/// and on a service the changes of its subscription. Each makes a request
/// of its own kind after its clauses (E9).
bool executor_action(const Concept* word, const Concept* kind) {
    if (word == nullptr) {
        return false;
    }
    if (word->id == "act.notify") {
        return true;
    }
    static constexpr std::string_view service_changes[] = {
        "act.subscribe", "act.upgrade", "act.downgrade",
        "act.suspend",   "act.resume",  "act.terminate",
    };
    return is(kind, "kind.service") && std::ranges::contains(service_changes, word->id);
}

// ---------------------------------------------------------------------------
// Lines Bo adds to a contract (E9): written as the tree would hold them, at
// the place of the clause they belong to, then checked as the contract's own.

ast::Expr word_node(std::string_view id, const Span& span) {
    ast::Expr e;
    e.kind = ExprKind::word;
    e.span = span;
    e.concept_entry = find_concept(id);
    return e;
}

ast::Expr duration_node(std::uint64_t count, std::string_view unit, const Span& span) {
    ast::Expr e;
    e.kind = ExprKind::literal;
    e.span = span;
    e.literal.kind = ast::LiteralKind::duration;
    e.literal.number.digits = count;
    e.literal.unit = find_concept(unit);
    return e;
}

ast::Expr binary_node(Operator op, ast::Expr left, ast::Expr right, const Span& span) {
    ast::Expr e;
    e.kind = ExprKind::binary;
    e.span = span;
    e.op = op;
    e.operands.push_back(std::move(left));
    e.operands.push_back(std::move(right));
    return e;
}

ast::Expr apply_node(std::string_view id, ast::Expr operand, const Span& span) {
    ast::Expr e = word_node(id, span);
    e.kind = ExprKind::apply;
    e.operands.push_back(std::move(operand));
    return e;
}

ast::Statement set_node(ast::Expr target, ast::Expr value, const Span& span) {
    return ast::Statement{ast::Set{span, std::move(target), std::move(value)}};
}

/// One period of a recurring price: a day, a week, a month, or a year.
ast::Expr period_node(const Concept* period, const Span& span) {
    const std::string_view id = period != nullptr ? period->id : std::string_view();
    return id == "time.daily"    ? duration_node(1, "time.day", span)
           : id == "time.weekly" ? duration_node(1, "time.week", span)
           : id == "time.yearly" ? duration_node(1, "time.year", span)
                                 : duration_node(1, "time.month", span);
}

// ---------------------------------------------------------------------------
// The tree's statements and expressions, walked (for the standard terms).

/// The key of a word or a name.
std::string expr_key(const ast::Expr& e) {
    return m::key(e.kind == ExprKind::word ? e.concept_entry : nullptr, e.name);
}

/// Calls `f` on every statement of `list`, nested ones included, in order.
template <class List, class F>
void each_statement(List& list, const F& f) {
    for (auto& s : list) {
        f(s);
        std::visit(
            [&](auto& node) {
                using N = std::remove_cvref_t<decltype(node)>;
                if constexpr (std::is_same_v<N, ast::If> || std::is_same_v<N, m::If>) {
                    each_statement(node.then, f);
                    each_statement(node.otherwise, f);
                } else if constexpr (std::is_same_v<N, ast::Each> || std::is_same_v<N, m::Each>) {
                    each_statement(node.body, f);
                }
            },
            s.node);
    }
}

/// Calls `f` on each expression a statement holds itself (not its nested
/// statements'), and on every expression within them.
template <class Statement, class F>
void each_expression(Statement& s, const F& f) {
    const auto all = [&](auto& e, const auto& self) -> void {
        f(e);
        for (auto& o : e.operands) {
            self(o, self);
        }
    };
    const auto one = [&](auto& e) {
        all(e, all);
    };
    std::visit(
        [&](auto& node) {
            using N = std::remove_cvref_t<decltype(node)>;
            if constexpr (std::is_same_v<N, ast::Requires>) {
                one(node.condition);
                if (node.guard) {
                    one(*node.guard);
                }
            } else if constexpr (std::is_same_v<N, ast::Permit>) {
                one(node.who);
                one(node.action);
            } else if constexpr (std::is_same_v<N, ast::If>) {
                one(node.condition);
            } else if constexpr (std::is_same_v<N, ast::Each>) {
                one(node.list);
            } else if constexpr (std::is_same_v<N, ast::Set>) {
                one(node.target);
                one(node.value);
            } else if constexpr (std::is_same_v<N, ast::Transition>) {
                for (auto& from : node.from) {
                    one(from);
                }
                one(node.to);
            } else if constexpr (std::is_same_v<N, ast::Do>) {
                if (node.subject) {
                    one(*node.subject);
                }
                one(node.action);
                for (auto& a : node.args) {
                    one(a);
                }
                if (node.to) {
                    one(*node.to);
                }
                if (node.by) {
                    one(*node.by);
                }
                for (auto& w : node.with) {
                    one(w.target);
                    one(w.value);
                }
            } else if constexpr (std::is_same_v<N, ast::Request>) {
                if (node.to) {
                    one(*node.to);
                }
                for (auto& w : node.with) {
                    one(w.value);
                }
            } else if constexpr (std::is_same_v<N, ast::Expect>) {
                if (node.outcome) {
                    one(*node.outcome);
                }
                for (auto& w : node.fields) {
                    one(w.target);
                    one(w.value);
                }
            }
        },
        s.node);
}

/// Calls `f` on every expression of a `can` clause (its action, by, to,
/// inputs, and body), nested ones included.
template <class F>
void each_can_expression(const ast::Can& c, const F& f) {
    const auto all = [&](const ast::Expr& e, const auto& self) -> void {
        f(e);
        for (const ast::Expr& o : e.operands) {
            self(o, self);
        }
    };
    if (c.by) {
        all(*c.by, all);
    }
    if (c.to) {
        all(*c.to, all);
    }
    for (const ast::Field& input : c.inputs) {
        all(input.head, all);
        for (const ast::Expr& v : input.values) {
            all(v, all);
        }
    }
    each_statement(c.body, [&](const ast::Statement& s) { each_expression(s, f); });
}

/// The states an action of the tree can start from, by its top-level lines,
/// as model::entry_states reads them: nullopt for any state.
std::optional<std::set<std::string>> tree_entry_states(const std::vector<ast::Statement>& list) {
    std::optional<std::set<std::string>> allowed;
    const auto narrow = [&](std::set<std::string> states) {
        if (!allowed) {
            allowed = std::move(states);
            return;
        }
        std::set<std::string> both;
        std::ranges::set_intersection(*allowed, states, std::inserter(both, both.begin()));
        allowed = std::move(both);
    };
    const auto states_of = [](const ast::Expr& e, std::set<std::string>& out, const auto& self) {
        if (word_in(e, Category::state)) {
            out.insert(std::string(e.concept_entry->id));
            return true;
        }
        if (e.kind == ExprKind::binary && e.op == Operator::logical_or && e.operands.size() == 2) {
            return self(e.operands[0], out, self) && self(e.operands[1], out, self);
        }
        return false;
    };
    for (const ast::Statement& s : list) {
        if (const auto* t = std::get_if<ast::Transition>(&s.node)) {
            if (!t->from.empty()) {
                std::set<std::string> from;
                for (const ast::Expr& f : t->from) {
                    if (word_in(f, Category::state)) {
                        from.insert(std::string(f.concept_entry->id));
                    }
                }
                narrow(std::move(from));
            }
            break;
        }
        if (const auto* r = std::get_if<ast::Requires>(&s.node); r != nullptr && !r->guard) {
            std::set<std::string> states;
            if (states_of(r->condition, states, states_of)) {
                narrow(std::move(states));
            }
            continue;
        }
        bool changes = false;
        const std::vector<ast::Statement> one{s};
        each_statement(one, [&](const ast::Statement& n) {
            changes = changes || std::holds_alternative<ast::Transition>(n.node);
        });
        if (changes) {
            break;
        }
    }
    return allowed;
}

/// Places a model's expressions and statements at one place: the standard
/// terms' are the library's source, so the model puts them at the contract's
/// `can` line.
void respan(m::Expr& e, const Span& at) {
    e.span = at;
    for (m::Expr& o : e.operands) {
        respan(o, at);
    }
}

void respan(std::vector<m::Statement>& list, const Span& at) {
    for (m::Statement& s : list) {
        std::visit(
            [&](auto& node) {
                using N = std::remove_cvref_t<decltype(node)>;
                node.span = at;
                if constexpr (std::is_same_v<N, m::Requires>) {
                    respan(node.condition, at);
                    if (node.guard) {
                        respan(*node.guard, at);
                    }
                } else if constexpr (std::is_same_v<N, m::If>) {
                    respan(node.condition, at);
                    respan(node.then, at);
                    respan(node.otherwise, at);
                } else if constexpr (std::is_same_v<N, m::Each>) {
                    respan(node.list, at);
                    respan(node.body, at);
                } else if constexpr (std::is_same_v<N, m::Set>) {
                    respan(node.target, at);
                    respan(node.value, at);
                } else if constexpr (std::is_same_v<N, m::Transition>) {
                    for (m::Expr& f : node.from) {
                        respan(f, at);
                    }
                    respan(node.to, at);
                } else if constexpr (std::is_same_v<N, m::Do>) {
                    if (node.subject) {
                        respan(*node.subject, at);
                    }
                    respan(node.action, at);
                    for (m::Expr& a : node.args) {
                        respan(a, at);
                    }
                    if (node.to) {
                        respan(*node.to, at);
                    }
                    if (node.by) {
                        respan(*node.by, at);
                    }
                    for (m::Set& w : node.with) {
                        w.span = at;
                        respan(w.target, at);
                        respan(w.value, at);
                    }
                }
            },
            s.node);
    }
}

/// R22: a bare 0 beside money, a quantity, a rate, or a duration is zero of
/// it.
void zero_of(m::Expr& zero, const m::Expr& other) {
    const TypeKind kind = other.type.kind;
    if (zero.kind == ExprKind::literal && zero.literal.kind == ast::LiteralKind::number &&
        zero.literal.number.digits == 0 && zero.type.kind == TypeKind::number &&
        (kind == TypeKind::money || kind == TypeKind::quantity || kind == TypeKind::rate ||
         kind == TypeKind::duration)) {
        zero.type = other.type;
        zero.rule = rule_zero;
    }
}

/// Where an expression stands, which decides the words it may use.
enum class Place : std::uint8_t {
    declaration, ///< a field's value, an input's type
    charge,      ///< a line of a charge
    action,      ///< a `can` block (a call someone starts)
    rule,        ///< a `when` block (the keeper fires it)
    event,       ///< a `when`'s event
    answer,      ///< a rule for answers (E8): `when notify done`
};

struct Decl {
    Refers refers = Refers::none;
    std::size_t index = 0;
};

struct Local {
    Refers refers = Refers::none;
    Type type;
};

/// A type written in a declaration, and the rule that completed it (R16, a
/// list's default bound).
struct Declared {
    Type type;
    std::string_view rule;
};

class Checker {
public:
    Checker(std::string_view source, detail::Diagnostics& diagnostics)
        : source_(source), diagnostics_(diagnostics) {}

    m::Model run(const ast::File& file);

private:
    // --- Problems. While the standard terms of an action are checked (they
    // are the library's source, not the contract's), a problem is placed at
    // the contract's `can` line.
    void error(const Span& span, std::string_view code, detail::Args args) {
        if (in_terms_) {
            // Once per problem: the terms may repeat a word of the contract's.
            std::string key = std::string(code);
            for (const auto& [name, value] : args) {
                key += "\n" + std::string(name) + "=" + std::string(value);
            }
            if (!terms_problems_.insert(std::to_string(terms_site_.offset) + key).second) {
                return;
            }
        }
        diagnostics_.add(in_terms_ ? terms_site_ : span, code, args);
    }
    [[nodiscard]] std::string written(const Span& span) const {
        const std::string_view text = in_terms_ ? terms_text_ : source_;
        const std::size_t from = std::min<std::size_t>(span.offset, text.size());
        return detail::quote(text.substr(from, span.length));
    }

    // --- Declarations.
    bool declare(const std::string& key, Refers refers, std::size_t index, const Span& span);
    [[nodiscard]] const Decl* global(std::string_view key) const;
    [[nodiscard]] const Local* local(std::string_view key) const;
    [[nodiscard]] bool declared(std::string_view key) const;
    void declare_parties();
    void read_kind();
    std::optional<m::Field> read_field(const ast::Field& f, bool input);
    void read_default(const ast::Field& f, m::Field& field);
    std::optional<Declared> as_type(const ast::Expr& e);
    void complete_parts(m::Field& field);
    void read_utc_offset(const ast::Field& f);
    [[nodiscard]] bool added_field(std::string_view id) const;
    /// True if `e` reads a date field that may hold no date (R20: a
    /// service's paid until and billed until).
    [[nodiscard]] bool optional_date(const m::Expr& e) const;
    /// A concept by id: the edition's, or a user's vocabulary pack's the
    /// file was read with.
    [[nodiscard]] const Concept* concept_of(std::string_view id) const;
    void add_rule_actions();
    void prepare_terms();
    void declare_actions();
    void collect_states(const std::vector<ast::Statement>& list);
    void collect_terms_states(const std::vector<ast::Statement>& list);
    void reach_terms();
    void finish_terms();
    std::optional<std::string> state_key(const ast::Expr& e);
    void choose_first_state();
    void bind_roles();
    void mentions(const ast::Expr& e, std::vector<std::string>& out) const;
    void mentions(const std::vector<ast::Statement>& list, std::vector<std::string>& out) const;
    void find_due();
    /// What the lines of a charge said so far, and what they may name.
    struct ChargeReading {
        bool rate = false;
        bool amount = false;
        bool applies = false;
        bool rounding = false;
        bool mode = false;
        bool base = false;
        int inclusion = 0;
        std::set<std::string> dates;
        std::string first_base;
        /// Every charge's name, and those written before this one.
        std::set<std::string, std::less<>> all;
        std::map<std::string, std::uint64_t, std::less<>> earlier;
        /// The bill's lines' type (money), if the contract has a bill.
        std::optional<Type> bill;
    };
    void read_charges();
    m::ChargeLine charge_line(const ast::Field& f, m::Charge& charge, ChargeReading& r);

    // --- Actions and rules.
    void check_can(const ast::Can& c, std::size_t index);
    void check_to(const ast::Expr& to, m::Action& a, const std::string& action);
    void check_when(const ast::When& w);
    void check_answer(const ast::AnswerRule& r);
    m::Request request_statement(const ast::Request& r);
    // E9: notify PARTY, a request (R10); the requests and the bills Bo adds
    // to a service (R10, R34, R35).
    m::Request notify_request(const ast::Do& d);
    [[nodiscard]] bool is_notify(const ast::Do& d) const;
    m::Request added_request(std::string_view kind, std::optional<ast::Expr> to,
                             std::vector<ast::Set> with, ast::Expr within, const Span& span,
                             std::string_view rule);
    void add_billing(m::Action& a, const Span& span);
    void add_billing_answers();
    void mark(std::vector<m::Statement>& list, std::string_view rule);
    [[nodiscard]] std::optional<ast::Expr> customer_node(const Span& span) const;
    [[nodiscard]] ast::Expr period_amount(const Span& span) const;
    [[nodiscard]] const m::Field* recurring_price() const;
    void check_requests();
    std::vector<m::Statement> statements(const std::vector<ast::Statement>& list);
    m::Set set_statement(const ast::Set& s);
    m::Do do_action(const ast::Do& d);
    m::Do parts_statement(const ast::Do& d);
    void check_states();
    void check_recursion();

    // --- Tests.
    void check_tests();
    m::Step test_step(const ast::Do& d, bool first, std::optional<std::int64_t>& clock);
    m::Step answer_step(const ast::Do& d, bool first, std::optional<std::int64_t>& clock);
    void test_with(const ast::Do& d, m::Step& step, const m::Action* action,
                   const std::string& action_key);
    void test_expect(const ast::Expect& e, m::Step& step);
    void test_outcome(const ast::Expect& e, m::Step& step);
    void test_fields(const ast::Expect& e, m::Step& step);
    std::optional<m::TestParty> test_party(const ast::Expr& e);
    m::Expr test_parties(const ast::Expr& e, const Type& type);
    [[nodiscard]] std::string creation_word() const {
        return is(model_.kind, "kind.asset") ? "act.issue" : "act.create";
    }
    bool reaches(const std::string& from, const std::string& target,
                 std::set<std::string>& seen) const;

    // --- Expressions.
    m::Expr value(const ast::Expr& e);
    m::Expr condition(const ast::Expr& e);
    void expect(m::Expr& e, const Type& want);
    void expect_kind(m::Expr& e, TypeKind kind);
    m::Expr plain(const ast::Expr& e) const;
    m::Expr as_text(const ast::Expr& e) const;
    [[nodiscard]] bool undeclared_name(const ast::Expr& e) const;
    Type literal_type(const ast::Expr& e);
    void name_value(const ast::Expr& e, m::Expr& out);
    void word_value(const ast::Expr& e, m::Expr& out);
    void apply_value(const ast::Expr& e, m::Expr& out);
    void phrase_value(const ast::Expr& e, m::Expr& out);
    void list_value(const ast::Expr& e, m::Expr& out, bool text_items);
    void binary_value(const ast::Expr& e, m::Expr& out);
    Type arithmetic(const ast::Expr& e, m::Expr& out);
    Type compare(const ast::Expr& e, const m::Expr& left, const m::Expr& right);
    void mismatch(const ast::Expr& e, const Type& left, const Type& right);
    void threshold(const ast::Expr& e, m::Expr& out);
    void needs_due(const ast::Expr& e);
    void not_a_value(const ast::Expr& e, m::Expr& out);
    [[nodiscard]] bool in_call() const noexcept {
        return place_ == Place::action || place_ == Place::rule || place_ == Place::event ||
               place_ == Place::answer;
    }

    std::string_view source_;
    detail::Diagnostics& diagnostics_;
    m::Model model_;

    // The tree's clauses, by kind. The `can`s include one for each built-in
    // action only time rules do (`rule_only_`, their indices), kept in
    // `synthetic_`.
    const ast::Contract* contract_ = nullptr;
    const ast::Parties* parties_ = nullptr;
    const ast::Block* kind_ = nullptr;
    std::vector<const ast::Block*> charges_;
    std::vector<const ast::Can*> cans_;
    std::vector<const ast::When*> whens_;
    std::vector<const ast::AnswerRule*> answers_;
    /// The kinds of the requests the contract makes (E8), as compiled code
    /// names them.
    std::set<std::string, std::less<>> requested_;
    /// A service's period bill (R34): made by some action, and where.
    bool billing_ = false;
    Span billing_span_;
    std::vector<const ast::Test*> tests_;
    std::vector<const ast::Clause*> clauses_;
    std::deque<ast::Can> synthetic_;
    std::set<std::size_t> rule_only_;
    bool offset_read_ = false;

    // Names: parties, fields, actions, and states by key; inputs and each
    // names in frames.
    std::map<std::string, Decl, std::less<>> globals_;
    std::vector<std::map<std::string, Local, std::less<>>> frames_;
    // Each action's inputs, by the action's key (read before any block, so
    // that `do X with ...` can name them); actions declared twice.
    std::map<std::string, std::vector<m::Field>, std::less<>> inputs_;
    std::set<std::size_t> duplicate_actions_;
    /// A vocabulary action without the standard library's terms: its states
    /// are unknown, so vocabulary states are not reported unreachable.
    bool any_unterms_ = false;

    // The standard library's terms of the contract's built-in actions (R19),
    // by the index of their `can`: copies of the library's clause, with the
    // contract's counterparty in place of `counterparty`.
    struct Terms {
        const ast::Can* source = nullptr;
        std::optional<ast::Expr> by;
        /// The counterparty, if the terms have one: the contract's `to`, or
        /// `counterparty` itself (named by each call, R21).
        std::optional<ast::Expr> to;
        std::vector<ast::Field> inputs;
        std::vector<ast::Statement> body;
        /// The fields the terms set.
        std::set<std::string> sets;
    };
    std::map<std::size_t, Terms> terms_;
    /// While the terms are checked: problems go to the `can` line, once.
    bool in_terms_ = false;
    /// The library file the terms being checked come from.
    std::string_view terms_text_;
    Span terms_site_;
    std::set<std::string> terms_problems_;

    // States: the state changes, as keys; vocabulary states named elsewhere.
    // A state change of the standard terms (`standard`) adds its states only
    // if an instance can reach them.
    struct Edge {
        std::vector<std::string> from;
        std::string to;
        bool standard = false;
    };
    std::vector<Edge> edges_;
    std::map<std::string, Span, std::less<>> state_mentions_;
    /// The candidates for the first state, when there are several.
    std::set<std::string> unclear_;

    // Calls between the contract's own actions.
    std::map<std::string, std::vector<std::string>, std::less<>> calls_;

    // The vocabulary packs the file was read with (ast::File::vocabularies).
    const Vocabularies* vocabularies_ = nullptr;

    // While checking a block.
    Place place_ = Place::declaration;
    m::Action* action_ = nullptr;
    std::string action_key_;
    std::vector<m::Consent>* consents_ = nullptr;
    /// The action's amount, for thresholds: how many there are, and the type.
    std::size_t amounts_ = 0;
    Type amount_;
};

// --- Declarations.

bool Checker::declare(const std::string& key, Refers refers, std::size_t index, const Span& span) {
    if (globals_.contains(key)) {
        error(span, "check.duplicate", {{"name", key}});
        return false;
    }
    globals_.emplace(key, Decl{refers, index});
    return true;
}

const Decl* Checker::global(std::string_view key) const {
    const auto it = globals_.find(key);
    return it == globals_.end() ? nullptr : &it->second;
}

const Local* Checker::local(std::string_view key) const {
    for (auto frame = frames_.rbegin(); frame != frames_.rend(); ++frame) {
        if (const auto it = frame->find(key); it != frame->end()) {
            return &it->second;
        }
    }
    return nullptr;
}

bool Checker::declared(std::string_view key) const {
    return local(key) != nullptr || global(key) != nullptr;
}

void Checker::declare_parties() {
    if (parties_ == nullptr) {
        return;
    }
    for (const ast::Expr& p : parties_->parties) {
        m::Party party;
        party.span = p.span;
        if (p.kind == ExprKind::word) {
            party.role = p.concept_entry;
        } else {
            party.name = p.name;
        }
        party.rule = rule_role_binding;
        if (declare(m::key(party.role, party.name), Refers::party, model_.parties.size(), p.span)) {
            model_.parties.push_back(std::move(party));
        }
    }
}

std::optional<Declared> Checker::as_type(const ast::Expr& e) {
    if (e.kind == ExprKind::word && e.concept_entry != nullptr) {
        const Concept* c = e.concept_entry;
        if (is(c, "type.date")) {
            return Declared{of(TypeKind::date), {}};
        }
        if (is(c, "type.text")) {
            return Declared{of(TypeKind::text), {}};
        }
        if (is(c, "type.number")) {
            return Declared{of(TypeKind::number), {}};
        }
        if (is(c, "type.yes_no")) {
            return Declared{of(TypeKind::yes_no), {}};
        }
        if (c->category == Category::currency) {
            return Declared{money(c), {}};
        }
        if (const UnitInfo* unit = unit_info(c)) {
            return Declared{quantity(unit->dimension, c), {}};
        }
        if (is(c, "time.day") || is(c, "time.week")) {
            return Declared{duration(false), {}};
        }
        if (is(c, "time.month") || is(c, "time.year")) {
            return Declared{duration(true), {}};
        }
        return std::nullopt;
    }
    if (e.kind != ExprKind::phrase || std::ranges::none_of(e.operands, [](const ast::Expr& o) {
            return word_is(o, "type.list");
        })) {
        return std::nullopt;
    }
    // A list: `list HKD`, `HKD list`, with `at most N` anywhere.
    std::optional<Type> element;
    std::uint32_t bound = 0;
    bool shaped = true;
    for (const ast::Expr& o : e.operands) {
        if (word_is(o, "type.list")) {
            continue;
        }
        if (o.kind == ExprKind::apply && is(o.concept_entry, "expr.at_most") && bound == 0 &&
            o.operands.size() == 1 && o.operands[0].kind == ExprKind::literal &&
            o.operands[0].literal.kind == ast::LiteralKind::number) {
            const Exact n = exact(o.operands[0].literal.number, 1);
            if (!n.whole || n.value == 0 || n.value > max_list_bound ||
                o.operands[0].literal.number.negative) {
                error(o.span, "check.list-bound",
                      {{"text", written(o.span)}, {"limit", std::to_string(max_list_bound)}});
                bound = default_list_bound;
            } else {
                bound = static_cast<std::uint32_t>(n.value);
            }
            continue;
        }
        std::optional<Declared> inner = element ? std::nullopt : as_type(o);
        if (!inner || inner->type.kind == TypeKind::list) {
            shaped = false;
            break;
        }
        element = inner->type;
    }
    if (!shaped || !element) {
        return std::nullopt;
    }
    if (bound == 0) {
        return Declared{list_of(*element, default_list_bound), rule_list_bound};
    }
    return Declared{list_of(*element, bound), {}};
}

std::optional<m::Field> Checker::read_field(const ast::Field& f, const bool input) {
    m::Field out;
    out.span = f.span;
    const ast::Expr& head = f.head;
    enum class What : std::uint8_t { own, vocabulary, pricing, charge, document };
    What what = What::own;
    if (head.kind == ExprKind::name) {
        out.name = head.name;
    } else if (word_in(head, Category::field)) {
        out.word = head.concept_entry;
        what = What::vocabulary;
    } else if (word_in(head, Category::document)) {
        // R26: a bill's lines; only the instance holds one.
        if (input) {
            error(head.span, "check.document", {{"field", std::string(head.concept_entry->id)}});
            return std::nullopt;
        }
        out.word = head.concept_entry;
        what = What::document;
    } else if (!input && is_label(head)) {
        out.word = head.concept_entry;
        what = What::pricing;
    } else if (!input && (word_is(head, "charge.tax") || word_is(head, "charge.charge"))) {
        out.word = head.concept_entry;
        what = What::charge;
    } else {
        error(head.span, "check.field-head", {{"text", written(head.span)}});
        return std::nullopt;
    }
    const std::string field_key = m::key(out.word, out.name);

    if (what == What::charge) {
        // `tax according to customer location`: what the charge depends on.
        out.kind = m::FieldKind::constant;
        if (f.values.size() != 1) {
            error(f.span, "check.charge-field", {{"text", written(f.span)}});
            return out;
        }
        out.value = value(f.values[0]);
        out.type = out.value->type;
        if (known(out.type) && out.type.kind != TypeKind::basis) {
            error(f.span, "check.charge-field", {{"text", written(f.span)}});
            out.type = of(TypeKind::unknown);
        }
        return out;
    }

    if (f.values.empty()) {
        if (what == What::vocabulary) {
            if (std::optional<Type> fixed = vocabulary_type(out.word)) {
                out.type = *fixed;
                out.rule = rule_field_meaning;
                return out;
            }
            if (is(out.word, "field.parts")) {
                out.type = list_of(of(TypeKind::unknown), default_list_bound);
                out.rule = rule_parts;
                complete_parts(out);
                return out;
            }
        }
        error(f.span, "check.field-needs-type", {{"field", field_key}});
        return out;
    }

    const ast::Expr& first = f.values[0];
    const bool party = (word_in(first, Category::role) && first.concept_entry != nullptr) ||
                       (first.kind == ExprKind::name && global(first.name) != nullptr &&
                        global(first.name)->refers == Refers::party);
    const Decl* like = word_in(first, Category::field) ? global(first.concept_entry->id)
                       : first.kind == ExprKind::name  ? global(first.name)
                                                       : nullptr;
    if (std::optional<Declared> declared_type = as_type(first)) {
        out.type = declared_type->type;
        out.rule = declared_type->rule;
    } else if (input && f.values.size() == 1 && like != nullptr && like->refers == Refers::field &&
               model_.fields[like->index].kind == m::FieldKind::instance) {
        // An input of an instance field's type: with portion quantity.
        out.type = model_.fields[like->index].type;
    } else if (input) {
        error(f.span, "check.field-needs-type", {{"field", field_key}});
        return out;
    } else if (party) {
        out.value = value(first);
        out.type = of(TypeKind::party);
        out.rule = rule_party_field;
    } else {
        out.kind = m::FieldKind::constant;
        out.value = value(first);
        out.type = out.value->type;
    }

    if (known(out.type)) {
        if (what == What::vocabulary && !vocabulary_accepts(out.word, out.type)) {
            error(first.span, "check.field-type",
                  {{"field", field_key},
                   {"type", encode(out.type)},
                   {"expected_type", encode(vocabulary_expected(out.word))}});
            out.type = of(TypeKind::unknown);
        } else if (what == What::pricing && !pricing_accepts(out.word, out.type)) {
            error(first.span, "check.field-type",
                  {{"field", field_key},
                   {"type", encode(out.type)},
                   {"expected_type", encode(pricing_expected(out.word))}});
            out.type = of(TypeKind::unknown);
        } else if (what == What::vocabulary && is(out.word, "field.parts") &&
                   out.type.kind == TypeKind::list) {
            // parts: amounts, in the amount's unit.
            const Type written_type = out.type;
            complete_parts(out);
            if (known(out.type) && !same(out.type, written_type)) {
                error(first.span, "check.field-type",
                      {{"field", field_key},
                       {"type", encode(written_type)},
                       {"expected_type", encode(out.type)}});
            }
        }
    }

    if (what == What::document) {
        // R26: the lines of a bill, amounts of money in one currency.
        const bool lines = out.kind == m::FieldKind::instance && out.type.kind == TypeKind::list &&
                           out.type.element.size() == 1 &&
                           out.type.element[0].kind == TypeKind::money &&
                           out.type.element[0].currency != nullptr;
        if (known(out.type) && (!lines || f.values.size() != 1)) {
            error(f.span, "check.document", {{"field", field_key}});
            out.type = of(TypeKind::unknown);
        } else if (lines) {
            out.rule = rule_bill;
        }
        return out;
    }

    // Further parts: labelled prices, in the field's own dimension.
    for (std::size_t i = 1; i < f.values.size(); ++i) {
        const ast::Expr& part = f.values[i];
        if (input || part.kind != ExprKind::phrase || part.operands.empty() ||
            !is_label(part.operands[0])) {
            error(part.span, "check.field-values", {{"field", field_key}});
            continue;
        }
        m::Expr more = value(part);
        const Type& base = out.type.kind == TypeKind::recurring && !out.type.element.empty()
                               ? out.type.element[0]
                               : out.type;
        if (known(more.type) && known(base) && more.type.kind == TypeKind::unit_price &&
            base.kind == TypeKind::quantity && more.type.dimension != base.dimension) {
            error(part.span, "check.mixed-units",
                  {{"left_type", encode(base)}, {"right_type", encode(more.type)}});
        }
        out.more.push_back(std::move(more));
    }
    return out;
}

void Checker::complete_parts(m::Field& field) {
    // R15: parts are amounts, in the unit of the instance's amount.
    const Decl* amount = global("field.amount");
    if (amount == nullptr || amount->refers != Refers::field ||
        !known(model_.fields[amount->index].type)) {
        field.type = of(TypeKind::unknown);
        error(field.span, "check.field-needs-type", {{"field", std::string("field.parts")}});
        return;
    }
    const std::uint32_t bound = field.type.bound == 0 ? default_list_bound : field.type.bound;
    field.type = list_of(model_.fields[amount->index].type, bound);
    if (field.rule.empty()) {
        field.rule = rule_parts;
    }
}

void Checker::read_kind() {
    if (kind_ == nullptr) {
        return;
    }
    model_.kind = kind_->kind;
    model_.kind_name = kind_->name.name;
    place_ = Place::declaration;
    for (const ast::Field& f : kind_->fields) {
        if (word_is(f.head, "field.utc_offset")) {
            read_utc_offset(f);
            continue;
        }
        std::optional<m::Field> field = read_field(f, false);
        if (!field) {
            continue;
        }
        if (f.initial) {
            read_default(f, *field);
        }
        // R26: one bill per instance.
        if (field->word != nullptr && field->word->category == Category::document &&
            field->rule == rule_bill && m::bill_field(model_) != nullptr) {
            error(f.span, "check.document", {{"field", std::string(field->word->id)}});
            field->type = of(TypeKind::unknown);
            field->rule = {};
        }
        if (declare(m::key(field->word, field->name), Refers::field, model_.fields.size(),
                    f.head.span)) {
            model_.fields.push_back(std::move(*field));
        }
    }
}

/// A value written out (a test's, a default): a literal, yes or no,
/// or a list of them.
bool test_value(const ast::Expr& e) {
    if (e.kind == ExprKind::literal || word_is(e, "val.yes") || word_is(e, "val.no")) {
        return true;
    }
    return e.kind == ExprKind::list &&
           std::ranges::all_of(e.operands, [](const ast::Expr& o) { return test_value(o); });
}

void Checker::read_default(const ast::Field& f, m::Field& field) {
    // `count number = 0`: an instance field given at creation, or else its
    // default, a literal of its type. A constant has its value, a party
    // field starts with its party (R2), and a bill is made from its lines.
    const std::string key = m::key(field.word, field.name);
    const bool parties = field.type.kind == TypeKind::party ||
                         (field.type.kind == TypeKind::list && field.type.element.size() == 1 &&
                          field.type.element[0].kind == TypeKind::party);
    if (field.kind != m::FieldKind::instance || field.value || parties || field.rule == rule_bill) {
        error(f.initial->span, "check.default-field", {{"field", key}});
        return;
    }
    if (!test_value(*f.initial)) {
        error(f.initial->span, "check.default-value", {{"text", written(f.initial->span)}});
        return;
    }
    m::Expr initial = value(*f.initial);
    expect(initial, field.type);
    field.initial = std::move(initial);
}

void Checker::read_utc_offset(const ast::Field& f) {
    // U6: `UTC offset "+08:00"`, a fixed offset, with no daylight saving.
    if (offset_read_) {
        error(f.head.span, "check.duplicate", {{"name", std::string("field.utc_offset")}});
        return;
    }
    offset_read_ = true;
    const auto offset = [&]() -> std::optional<std::int64_t> {
        if (f.values.size() != 1 || f.values[0].kind != ExprKind::literal ||
            f.values[0].literal.kind != ast::LiteralKind::text) {
            return std::nullopt;
        }
        const std::string& t = f.values[0].literal.text;
        const auto digit = [&](std::size_t i) {
            return t[i] >= '0' && t[i] <= '9';
        };
        if (t.size() != 6 || (t[0] != '+' && t[0] != '-') || !digit(1) || !digit(2) ||
            t[3] != ':' || !digit(4) || !digit(5)) {
            return std::nullopt;
        }
        const std::int64_t hours = (t[1] - '0') * 10 + (t[2] - '0');
        const std::int64_t minutes = (t[4] - '0') * 10 + (t[5] - '0');
        if (minutes > 59 || hours * 60 + minutes > 14 * 60) {
            return std::nullopt;
        }
        return (t[0] == '-' ? -1 : 1) * (hours * 60 + minutes) * 60'000;
    }();
    if (!offset) {
        error(f.span, "check.utc-offset", {{"text", written(f.span)}});
        return;
    }
    model_.utc_offset_ms = *offset;
    model_.offset_rule = {};
}

bool Checker::added_field(std::string_view id) const {
    if (id == "field.holder") {
        return is(model_.kind, "kind.resource");
    }
    const Concept* c = concept_of(id);
    return c != nullptr && (c->flags & field_added) != 0;
}

bool Checker::optional_date(const m::Expr& e) const {
    if (e.refers != Refers::field || (e.kind != ExprKind::word && e.kind != ExprKind::name)) {
        return false;
    }
    const Decl* d = global(m::key(e.concept_entry, e.name));
    return d != nullptr && d->refers == Refers::field && model_.fields[d->index].optional &&
           model_.fields[d->index].type.kind == TypeKind::date;
}

const Concept* Checker::concept_of(std::string_view id) const {
    if (const Concept* c = find_concept(id)) {
        return c;
    }
    return vocabularies_ != nullptr ? vocabularies_->find_concept(id) : nullptr;
}

void Checker::add_rule_actions() {
    // A built-in action with standard terms that a time rule does but no
    // `can` declares: the rule does it under its terms (R24), and nothing
    // else can (rule_only).
    std::set<std::string> declared;
    for (const ast::Can* c : cans_) {
        if (c->action.kind == ExprKind::word && c->action.concept_entry != nullptr) {
            declared.insert(std::string(c->action.concept_entry->id));
        }
    }
    const auto consider = [&](const ast::Do& d) {
        if (d.subject || !word_in(d.action, Category::action)) {
            return;
        }
        const Concept* word = d.action.concept_entry;
        if (find_terms(word, vocabularies_) == nullptr ||
            !declared.insert(std::string(word->id)).second) {
            return;
        }
        ast::Can& c = synthetic_.emplace_back();
        c.span = d.span;
        c.action = d.action;
        rule_only_.insert(cans_.size());
        cans_.push_back(&c);
    };
    for (const ast::When* w : whens_) {
        for (const ast::Do& d : w->actions) {
            consider(d);
        }
        each_statement(w->body, [&](const ast::Statement& s) {
            if (const auto* d = std::get_if<ast::Do>(&s.node)) {
                consider(*d);
            }
        });
    }
}

void Checker::prepare_terms() {
    // R19: each built-in action with terms in the standard library (or in a
    // user's vocabulary pack) gets a copy of them, the contract's
    // counterparty in place of `counterparty`.
    std::set<std::string> seen;
    for (std::size_t i = 0; i < cans_.size(); ++i) {
        const ast::Can& c = *cans_[i];
        const Concept* word = c.action.kind == ExprKind::word ? c.action.concept_entry : nullptr;
        // A second `can` of an action is reported as declared twice.
        if (word == nullptr || !seen.insert(std::string(word->id)).second) {
            continue;
        }
        const ast::Can* source = find_terms(word, vocabularies_);
        if (source == nullptr) {
            any_unterms_ = true;
            continue;
        }
        const std::string action(word->id);
        Terms terms;
        terms.source = source;
        terms.inputs = source->inputs;
        terms.body = source->body;
        if (source->by) {
            terms.by = *source->by;
            if (c.by && expr_key(*c.by) != expr_key(*source->by)) {
                error(c.by->span, "check.standard-by",
                      {{"action", action}, {"party", expr_key(*source->by)}});
            }
        }
        if (c.to && !source->to) {
            error(c.to->span, "check.standard-to", {{"action", action}});
        }
        if (c.to && !word_is(*c.to, "role.counterparty")) {
            // The counterparty must be one of the contract's parties (else
            // the `to` reports it, and the terms are left out).
            const Decl* d = global(expr_key(*c.to));
            if (d == nullptr || d->refers != Refers::party) {
                any_unterms_ = true;
                continue;
            }
        }
        if (source->to) {
            terms.to = c.to ? *c.to : *source->to;
            if (c.to) {
                each_statement(terms.body, [&](ast::Statement& s) {
                    each_expression(s, [&](ast::Expr& e) {
                        if (word_is(e, "role.counterparty")) {
                            const Span span = e.span;
                            e = *c.to;
                            e.span = span;
                        }
                    });
                });
            }
        }
        // The fields the terms set, and those an instance must hold for them
        // (other than their inputs, and the fields R20 adds).
        each_statement(source->body, [&](const ast::Statement& s) {
            if (const auto* set = std::get_if<ast::Set>(&s.node)) {
                terms.sets.insert(expr_key(set->target));
            }
        });
        std::set<std::string> inputs;
        for (const ast::Field& f : source->inputs) {
            inputs.insert(expr_key(f.head));
        }
        std::vector<std::string> needed;
        each_can_expression(*source, [&](const ast::Expr& e) {
            if (!word_in(e, Category::field)) {
                return;
            }
            const std::string id(e.concept_entry->id);
            if (!inputs.contains(id) && !added_field(id) && !std::ranges::contains(needed, id)) {
                needed.push_back(id);
            }
        });
        bool usable = true;
        for (const std::string& f : needed) {
            // A field the terms only read may be the same for every instance
            // (a resource's cooling period).
            const Decl* d = global(f);
            if (d == nullptr || d->refers != Refers::field ||
                (terms.sets.contains(f) &&
                 model_.fields[d->index].kind != m::FieldKind::instance)) {
                error(c.action.span, "check.standard-field", {{"action", action}, {"field", f}});
                usable = false;
                break;
            }
        }
        // The contract's own lines add to the terms: they change neither the
        // state nor a field the terms set.
        each_statement(c.body, [&](const ast::Statement& s) {
            const Span* span = nullptr;
            if (const auto* t = std::get_if<ast::Transition>(&s.node)) {
                span = &t->span;
            } else if (const auto* set = std::get_if<ast::Set>(&s.node);
                       set != nullptr && terms.sets.contains(expr_key(set->target))) {
                span = &set->span;
            }
            if (span != nullptr) {
                error(*span, "check.standard-change",
                      {{"action", action}, {"text", written(*span)}});
            }
        });
        if (!usable) {
            any_unterms_ = true;
            continue;
        }
        terms_.emplace(i, std::move(terms));
    }
    // R20: the pledgee and the payee (and a resource's holder), used by the
    // terms or by an action of the contract's (a copy of the terms, say) but
    // not declared, none at first.
    // Then those of users' vocabulary packs, by id.
    std::vector<std::string_view> addable(std::begin(standard_fields), std::end(standard_fields));
    if (vocabularies_ != nullptr) {
        for (const VocabularyHandle& pack : vocabularies_->users) {
            for (const Concept* c : pack->concepts) {
                if (c->category == Category::field && (c->flags & field_added) != 0) {
                    addable.push_back(c->id);
                }
            }
        }
    }
    for (const std::string_view id : addable) {
        if (global(id) != nullptr || !added_field(id)) {
            continue;
        }
        bool used = false;
        const auto mentions = [&](const ast::Expr& e) {
            used = used || word_is(e, id);
        };
        for (const auto& [i, terms] : terms_) {
            each_statement(terms.body,
                           [&](const ast::Statement& s) { each_expression(s, mentions); });
            if (terms.by) {
                mentions(*terms.by);
            }
        }
        for (const ast::Can* c : cans_) {
            each_can_expression(*c, mentions);
        }
        // R11: a service with a recurring price is due on the date it is
        // paid until, which a rule or a condition on its due date reads.
        if (!used && id == "field.paid_until" && recurring_price() != nullptr) {
            const auto due_word = [&](const ast::Expr& e) {
                used = used || word_is(e, "cond.overdue") || word_is(e, "cond.before_due") ||
                       word_is(e, "field.due");
            };
            const auto in = [&](const ast::Expr& e, const auto& self) -> void {
                due_word(e);
                for (const ast::Expr& o : e.operands) {
                    self(o, self);
                }
            };
            for (const ast::When* w : whens_) {
                in(w->event, in);
                each_statement(w->body,
                               [&](const ast::Statement& st) { each_expression(st, due_word); });
            }
            for (const ast::Can* c : cans_) {
                each_can_expression(*c, due_word);
            }
            for (const ast::AnswerRule* r : answers_) {
                each_statement(r->body,
                               [&](const ast::Statement& st) { each_expression(st, due_word); });
            }
        }
        if (!used) {
            continue;
        }
        m::Field f;
        f.word = concept_of(id);
        f.type = vocabulary_type(f.word).value_or(of(TypeKind::party));
        f.rule = rule_standard_fields;
        f.optional = true;
        f.empty_at_start = true;
        globals_.emplace(std::string(id), Decl{Refers::field, model_.fields.size()});
        model_.fields.push_back(std::move(f));
    }
}

void Checker::declare_actions() {
    place_ = Place::declaration;
    for (std::size_t i = 0; i < cans_.size(); ++i) {
        const ast::Can& c = *cans_[i];
        const Concept* word = c.action.kind == ExprKind::word ? c.action.concept_entry : nullptr;
        const std::string action = m::key(word, c.action.name);
        if (!declare(action, Refers::action, i, c.action.span)) {
            duplicate_actions_.insert(i);
            continue;
        }
        std::vector<m::Field> inputs;
        std::set<std::string> seen;
        const auto add = [&](const ast::Field& f) {
            std::optional<m::Field> input = read_field(f, true);
            if (!input) {
                return;
            }
            if (in_terms_) {
                if (input->rule.empty()) {
                    input->rule = rule_standard_terms;
                }
                input->span = c.action.span;
                if (input->value) {
                    respan(*input->value, c.action.span);
                }
                for (m::Expr& more : input->more) {
                    respan(more, c.action.span);
                }
            }
            const std::string input_key = m::key(input->word, input->name);
            if (in_terms_ && seen.contains(input_key)) {
                // The contract may restate an input of the terms (`can split
                // with parts`), with the same type.
                const auto own = std::ranges::find_if(inputs, [&](const m::Field& written_input) {
                    return m::key(written_input.word, written_input.name) == input_key;
                });
                if (own != inputs.end() &&
                    (same(own->type, input->type) || !known(own->type) || !known(input->type))) {
                    return;
                }
            }
            if (global(input_key) != nullptr || !seen.insert(input_key).second) {
                error(f.head.span, "check.duplicate", {{"name", input_key}});
                return;
            }
            inputs.push_back(std::move(*input));
        };
        for (const ast::Field& f : c.inputs) {
            add(f);
        }
        const auto terms = terms_.find(i);
        if (terms != terms_.end()) {
            in_terms_ = true;
            terms_site_ = c.action.span;
            terms_text_ = terms_source(c.action.concept_entry, vocabularies_);
            for (const ast::Field& f : terms->second.inputs) {
                add(f);
            }
            in_terms_ = false;
        }
        // R21: a counterparty the contract does not declare is named by each
        // call, as an input.
        const ast::Expr* to = c.to ? &*c.to
                              : terms != terms_.end() && terms->second.to.has_value()
                                  ? &*terms->second.to
                                  : nullptr;
        if (to != nullptr && word_is(*to, "role.counterparty") &&
            global("role.counterparty") == nullptr && seen.insert("role.counterparty").second) {
            m::Field input;
            input.span = c.to ? to->span : c.action.span;
            input.word = to->concept_entry;
            input.type = of(TypeKind::party);
            input.rule = rule_counterparty;
            inputs.push_back(std::move(input));
        }
        inputs_.emplace(action, std::move(inputs));
    }
}

std::optional<std::string> Checker::state_key(const ast::Expr& e) {
    if (word_in(e, Category::state)) {
        const std::string id(e.concept_entry->id);
        if (global(id) == nullptr) {
            globals_.emplace(id, Decl{Refers::state, model_.states.size()});
            model_.states.push_back(m::State{e.span, e.concept_entry, {}, false, rule_states});
        }
        return id;
    }
    if (e.kind != ExprKind::name) {
        return std::nullopt;
    }
    if (const Decl* d = global(e.name)) {
        return d->refers == Refers::state ? std::optional<std::string>(e.name) : std::nullopt;
    }
    globals_.emplace(e.name, Decl{Refers::state, model_.states.size()});
    model_.states.push_back(m::State{e.span, nullptr, e.name, false, rule_states});
    return e.name;
}

void Checker::collect_states(const std::vector<ast::Statement>& list) {
    for (const ast::Statement& s : list) {
        if (const auto* t = std::get_if<ast::Transition>(&s.node)) {
            Edge edge;
            for (const ast::Expr& from : t->from) {
                if (std::optional<std::string> k = state_key(from)) {
                    edge.from.push_back(*k);
                }
            }
            if (std::optional<std::string> k = state_key(t->to)) {
                edge.to = *k;
                edges_.push_back(std::move(edge));
            }
        } else if (const auto* i = std::get_if<ast::If>(&s.node)) {
            collect_states(i->then);
            collect_states(i->otherwise);
        } else if (const auto* e = std::get_if<ast::Each>(&s.node)) {
            collect_states(e->body);
        }
    }
}

void Checker::collect_terms_states(const std::vector<ast::Statement>& list) {
    // The terms name vocabulary states only. A state change without FROM
    // starts from the states the action can start from.
    const std::optional<std::set<std::string>> entry = tree_entry_states(list);
    each_statement(list, [&](const ast::Statement& s) {
        const auto* t = std::get_if<ast::Transition>(&s.node);
        if (t == nullptr || !word_in(t->to, Category::state)) {
            return; // `previous state` leads back where an instance has been
        }
        Edge edge;
        edge.standard = true;
        for (const ast::Expr& from : t->from) {
            if (word_in(from, Category::state)) {
                edge.from.emplace_back(from.concept_entry->id);
            }
        }
        if (t->from.empty() && entry) {
            edge.from.assign(entry->begin(), entry->end());
        }
        edge.to = std::string(t->to.concept_entry->id);
        edges_.push_back(std::move(edge));
    });
}

void Checker::reach_terms() {
    // The states the terms can reach from the first state become states of
    // the contract (R19); the others are none of its states.
    if (terms_.empty()) {
        return;
    }
    std::set<std::string> reached;
    for (const m::State& s : model_.states) {
        if (s.first) {
            reached.insert(m::key(s.word, s.name));
        }
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (const Edge& edge : edges_) {
            const bool from = edge.from.empty()
                                  ? !reached.empty()
                                  : std::ranges::any_of(edge.from, [&](const std::string& k) {
                                        return reached.contains(k);
                                    });
            if (from && reached.insert(edge.to).second) {
                changed = true;
            }
        }
    }
    for (const Edge& edge : edges_) {
        if (!edge.standard) {
            continue;
        }
        std::vector<std::string> keys = edge.from;
        keys.push_back(edge.to);
        for (const std::string& k : keys) {
            if (reached.contains(k) && global(k) == nullptr) {
                globals_.emplace(k, Decl{Refers::state, model_.states.size()});
                model_.states.push_back(
                    m::State{Span{}, concept_of(k), {}, false, rule_standard_terms});
            }
        }
    }
    // An action whose terms start only from states no instance reaches can
    // never start.
    for (const auto& [i, terms] : terms_) {
        const std::optional<std::set<std::string>> entry = tree_entry_states(terms.body);
        if (!entry || entry->empty() || std::ranges::any_of(*entry, [&](const std::string& k) {
                return reached.contains(k);
            })) {
            continue;
        }
        std::string states;
        for (const std::string& k : *entry) {
            states += (states.empty() ? "" : ", ") + k;
        }
        const ast::Can& c = *cans_[i];
        error(c.action.span, "check.standard-unreachable",
              {{"action", expr_key(c.action)}, {"states", states}});
    }
}

void Checker::choose_first_state() {
    // R4: the one state no state change leads to; with none, active. The
    // standard terms' state changes start from no first state of their own:
    // they assume an asset starts active.
    std::set<std::string> targets;
    std::set<std::string> sources;
    for (const Edge& edge : edges_) {
        targets.insert(edge.to);
        if (!edge.standard) {
            sources.insert(edge.from.begin(), edge.from.end());
        }
    }
    std::vector<std::size_t> candidates;
    for (std::size_t i = 0; i < model_.states.size(); ++i) {
        const std::string k = m::key(model_.states[i].word, model_.states[i].name);
        if (sources.contains(k) && !targets.contains(k)) {
            candidates.push_back(i);
        }
    }
    std::size_t first = 0;
    if (candidates.size() > 1) {
        std::string names;
        for (const std::size_t i : candidates) {
            names +=
                (names.empty() ? "" : ", ") + m::key(model_.states[i].word, model_.states[i].name);
            // Reported once: not again as unreachable.
            unclear_.insert(m::key(model_.states[i].word, model_.states[i].name));
        }
        error(model_.states[candidates[1]].span, "check.initial-state", {{"states", names}});
    }
    if (!candidates.empty()) {
        first = candidates.front();
    } else if (const Decl* active = global("state.active");
               active != nullptr && active->refers == Refers::state) {
        first = active->index;
    } else {
        model_.states.push_back(
            m::State{Span{}, find_concept("state.active"), {}, false, rule_first_state});
        first = model_.states.size() - 1;
        if (global("state.active") == nullptr) {
            globals_.emplace("state.active", Decl{Refers::state, first});
        }
    }
    model_.states[first].first = true;
    model_.states[first].rule = rule_first_state;
    // The first state first; the others in the order they were named.
    std::rotate(model_.states.begin(), model_.states.begin() + static_cast<std::ptrdiff_t>(first),
                model_.states.begin() + static_cast<std::ptrdiff_t>(first) + 1);
    for (std::size_t i = 0; i < model_.states.size(); ++i) {
        auto it = globals_.find(m::key(model_.states[i].word, model_.states[i].name));
        if (it != globals_.end() && it->second.refers == Refers::state) {
            it->second.index = i;
        }
    }
}

void Checker::mentions(const ast::Expr& e, std::vector<std::string>& out) const {
    if (word_in(e, Category::role)) {
        out.emplace_back(e.concept_entry->id);
    } else if (e.kind == ExprKind::name) {
        if (const Decl* d = global(e.name); d != nullptr && d->refers == Refers::party) {
            out.push_back(e.name);
        }
    }
    for (const ast::Expr& o : e.operands) {
        mentions(o, out);
    }
}

void Checker::mentions(const std::vector<ast::Statement>& list,
                       std::vector<std::string>& out) const {
    const auto do_mentions = [&](const ast::Do& d) {
        if (d.subject) {
            mentions(*d.subject, out);
        }
        for (const ast::Expr& a : d.args) {
            mentions(a, out);
        }
        if (d.to) {
            mentions(*d.to, out);
        }
        if (d.by) {
            mentions(*d.by, out);
        }
        for (const ast::Set& s : d.with) {
            mentions(s.value, out);
        }
    };
    for (const ast::Statement& s : list) {
        std::visit(Overloaded{
                       [&](const ast::Requires& r) {
                           if (r.guard) {
                               mentions(*r.guard, out);
                           }
                           mentions(r.condition, out);
                       },
                       [&](const ast::Permit& p) { mentions(p.who, out); },
                       [&](const ast::If& i) {
                           mentions(i.condition, out);
                           mentions(i.then, out);
                           mentions(i.otherwise, out);
                       },
                       [&](const ast::Each& e) {
                           mentions(e.list, out);
                           mentions(e.body, out);
                       },
                       [&](const ast::Reject&) {},
                       [&](const ast::Set& st) { mentions(st.value, out); },
                       [&](const ast::Transition&) {},
                       [&](const ast::Do& d) { do_mentions(d); },
                       [&](const ast::Expect&) {},
                       [&](const ast::Request& r) {
                           if (r.to) {
                               mentions(*r.to, out);
                           }
                           for (const ast::Set& w : r.with) {
                               mentions(w.value, out);
                           }
                       },
                   },
                   s.node);
    }
}

void Checker::bind_roles() {
    // R3 (U4): a role first named after a `can`'s `to` is bound by that
    // action; every other role when an instance is created.
    std::set<std::string> seen;
    for (const ast::Clause* clause : clauses_) {
        std::vector<std::string> named;
        const ast::Can* can = std::get_if<ast::Can>(clause);
        if (const auto* b = std::get_if<ast::Block>(clause)) {
            for (const ast::Field& f : b->fields) {
                mentions(f.head, named);
                for (const ast::Expr& v : f.values) {
                    mentions(v, named);
                }
            }
        } else if (can != nullptr) {
            // The counterparty: the contract's `to`, or its terms' (R19).
            const ast::Expr* counterparty = can->to ? &*can->to : nullptr;
            if (counterparty == nullptr) {
                const auto at =
                    static_cast<std::size_t>(std::ranges::find(cans_, can) - cans_.begin());
                if (const auto t = terms_.find(at); t != terms_.end() && t->second.to) {
                    counterparty = &*t->second.to;
                }
            }
            if (counterparty != nullptr) {
                std::vector<std::string> to;
                mentions(*counterparty, to);
                if (to.size() == 1 && !seen.contains(to[0])) {
                    if (const Decl* d = global(to[0]); d != nullptr && d->refers == Refers::party) {
                        m::Party& party = model_.parties[d->index];
                        party.binding = m::Binding::action;
                        party.bound_by =
                            m::key(can->action.kind == ExprKind::word ? can->action.concept_entry
                                                                      : nullptr,
                                   can->action.name);
                    }
                }
                named.insert(named.end(), to.begin(), to.end());
            }
            if (can->by) {
                mentions(*can->by, named);
            }
            mentions(can->body, named);
        } else if (const auto* w = std::get_if<ast::When>(clause)) {
            mentions(w->event, named);
            mentions(w->body, named);
            for (const ast::Do& d : w->actions) {
                std::vector<ast::Statement> one{ast::Statement{d}};
                mentions(one, named);
            }
        } else if (const auto* a = std::get_if<ast::AnswerRule>(clause)) {
            mentions(a->body, named);
        }
        seen.insert(named.begin(), named.end());
    }
    // R23: a resource goes to one holder at a time, so the role a built-in
    // allocate binds is bound again by each allocation.
    for (std::size_t i = 0; i < cans_.size(); ++i) {
        if (!terms_.contains(i) || !word_is(cans_[i]->action, "act.allocate")) {
            continue;
        }
        for (m::Party& p : model_.parties) {
            if (p.binding == m::Binding::action && p.bound_by == "act.allocate") {
                p.each_call = true;
            }
        }
    }
}

const m::Field* Checker::recurring_price() const {
    // R11: a service with a recurring price in money.
    if (!is(model_.kind, "kind.service")) {
        return nullptr;
    }
    for (const m::Field& f : model_.fields) {
        if (f.type.kind == TypeKind::recurring && !f.type.element.empty() &&
            f.type.element[0].kind == TypeKind::money && f.value) {
            return &f;
        }
    }
    return nullptr;
}

void Checker::find_due() {
    if (const Decl* due = global("field.due"); due != nullptr && due->refers == Refers::field) {
        if (model_.fields[due->index].type.kind == TypeKind::date) {
            model_.due = m::DueKind::field;
        }
        return;
    }
    if (recurring_price() != nullptr) {
        model_.due = m::DueKind::period;
        model_.due_rule = rule_service_due;
    }
}

m::ChargeLine Checker::charge_line(const ast::Field& f, m::Charge& charge, ChargeReading& r) {
    m::ChargeLine line;
    line.span = f.span;
    const ast::Expr& head = f.head;
    const auto refuse = [&] {
        error(f.span, "check.charge-field", {{"text", written(f.span)}});
    };
    // Each kind of line once.
    const auto once = [&](bool& seen) {
        if (seen) {
            error(f.span, "check.charge-twice", {{"name", charge.name}, {"text", written(f.span)}});
        }
        seen = true;
    };
    const Concept* word =
        head.kind == ExprKind::word || head.kind == ExprKind::apply ? head.concept_entry : nullptr;
    line.head = word;
    if (word == nullptr) {
        line.head = find_concept("charge.charge");
        refuse();
        return line;
    }
    const std::size_t values = f.values.size();
    if (head.kind == ExprKind::word && is(word, "charge.rate") && values == 1) {
        m::Expr v = value(f.values[0]);
        expect_kind(v, TypeKind::rate);
        line.values.push_back(v);
        once(r.rate);
        charge.rate = std::move(v);
    } else if (head.kind == ExprKind::word && is(word, "field.amount") && values == 1) {
        m::Expr v = value(f.values[0]);
        expect_kind(v, TypeKind::money);
        if (r.bill && known(v.type)) {
            expect(v, *r.bill);
        }
        line.values.push_back(v);
        once(r.amount);
        charge.amount = std::move(v);
    } else if (head.kind == ExprKind::apply && is(word, "charge.applies_to") && values == 0) {
        line.argument = condition(head.operands[0]);
        once(r.applies);
        charge.condition = line.argument;
    } else if (head.kind == ExprKind::word &&
               (is(word, "charge.included") || is(word, "charge.added")) && values == 0) {
        ++r.inclusion;
        charge.included = is(word, "charge.included");
    } else if (head.kind == ExprKind::word &&
               (is(word, "charge.per_line") || is(word, "charge.per_document")) &&
               (values == 0 || (values == 1 && word_in(f.values[0], Category::rounding)))) {
        if (values == 1) {
            line.values.push_back(plain(f.values[0]));
            charge.rounding = f.values[0].concept_entry;
            r.mode = true;
        }
        once(r.rounding);
        charge.per_document = is(word, "charge.per_document");
    } else if (head.kind == ExprKind::word && is(word, "charge.by") && values >= 1) {
        const ast::Expr& v = f.values[0];
        const bool document = word_in(v, Category::document);
        const bool with_mode = v.kind == ExprKind::phrase && v.operands.size() == 2 &&
                               word_in(v.operands[0], Category::document) &&
                               word_in(v.operands[1], Category::rounding);
        if (values == 1 && (document || with_mode)) {
            // according to invoice [half up]: once per document of that kind.
            line.values.push_back(plain(v));
            once(r.rounding);
            charge.per_document = true;
            charge.document = document ? v.concept_entry : v.operands[0].concept_entry;
            if (with_mode) {
                charge.rounding = v.operands[1].concept_entry;
                r.mode = true;
            }
        } else if (std::ranges::all_of(f.values, [](const ast::Expr& o) {
                       return word_is(o, "price.price") || o.kind == ExprKind::name;
                   })) {
            // according to price, OTHER: what it is computed on (R27).
            once(r.base);
            charge.on_price = false;
            for (const ast::Expr& o : f.values) {
                m::Expr item = plain(o);
                if (word_is(o, "price.price")) {
                    charge.on_price = true;
                } else if (const auto it = r.earlier.find(o.name); it != r.earlier.end()) {
                    item.refers = Refers::charge;
                    charge.on.push_back(it->second);
                } else if (r.all.contains(o.name)) {
                    error(o.span, "check.charge-on", {{"name", charge.name}, {"other", o.name}});
                } else {
                    error(o.span, "check.unknown-name", {{"name", o.name}});
                }
                if (r.first_base.empty()) {
                    r.first_base = word_is(o, "price.price") ? std::string("price.price") : o.name;
                }
                line.values.push_back(std::move(item));
            }
        } else {
            refuse();
        }
    } else if (head.kind == ExprKind::word && word->category == Category::rounding && values == 0) {
        // A rounding mode alone: per line.
        once(r.rounding);
        charge.rounding = word;
        r.mode = true;
    } else if (head.kind == ExprKind::apply && is(word, "charge.from") && values == 1) {
        // from DATE on rate 9%: a rate from that date on (R28).
        const ast::Expr& when = head.operands[0];
        m::Expr date = value(when);
        expect_kind(date, TypeKind::date);
        line.argument = date;
        const ast::Expr& v = f.values[0];
        const ast::Expr* rate_value = &v;
        if (v.kind == ExprKind::phrase && v.operands.size() == 2 &&
            word_is(v.operands[0], "charge.rate")) {
            rate_value = &v.operands[1];
        }
        m::Expr rate = value(*rate_value);
        expect_kind(rate, TypeKind::rate);
        line.values.push_back(rate);
        date.rule = rule_rate_in_force;
        line.argument->rule = rule_rate_in_force;
        if (when.kind != ExprKind::literal || when.literal.kind != ast::LiteralKind::date) {
            // Rates and their dates are written in the contract (U9).
            refuse();
        } else {
            const Date& d = when.literal.date;
            bool seen =
                !r.dates.insert(std::format("{}-{}-{}", int{d.year}, int{d.month}, int{d.day}))
                     .second;
            once(seen);
            charge.dated.push_back(m::DatedRate{std::move(date), std::move(rate)});
        }
    } else {
        refuse();
    }
    return line;
}

void Checker::read_charges() {
    // R26: charges are computed on the instance's bill; R27: in the order
    // written, each on the price and on charges written before it.
    std::set<std::string> names;
    ChargeReading shared;
    for (const ast::Block* block : charges_) {
        shared.all.insert(block->name.name);
    }
    const m::Field* bill = m::bill_field(model_);
    if (bill != nullptr && bill->rule == rule_bill) {
        shared.bill = bill->type.element[0];
    }
    const Concept* document = bill != nullptr ? bill->word : nullptr;
    place_ = Place::charge;
    for (const ast::Block* block : charges_) {
        m::Charge charge;
        charge.span = block->span;
        charge.kind = block->kind;
        charge.name = block->name.name;
        if (!names.insert(charge.name).second) {
            error(block->name.span, "check.duplicate", {{"name", charge.name}});
            continue;
        }
        ChargeReading r;
        r.all = shared.all;
        r.earlier = shared.earlier;
        r.bill = shared.bill;
        for (const ast::Field& f : block->fields) {
            if (f.initial) {
                // Defaults are an instance field's (`count number = 0`).
                error(f.initial->span, "check.default-field",
                      {{"field", f.head.kind == ExprKind::word && f.head.concept_entry != nullptr
                                     ? std::string(f.head.concept_entry->id)
                                     : f.head.name}});
            }
            charge.lines.push_back(charge_line(f, charge, r));
        }
        const Span& at = block->name.span;
        if (charge.amount && !r.rounding) {
            // R27: a fixed amount is charged once per bill unless per line.
            charge.per_document = true;
        }
        const bool rated = charge.rate || !charge.dated.empty();
        if (rated == charge.amount.has_value()) {
            error(at, "check.charge-rate", {{"name", charge.name}});
        }
        if (r.inclusion != 1) {
            error(at, "check.charge-included", {{"name", charge.name}});
        }
        if (charge.amount && r.mode) {
            // A fixed amount is never rounded.
            error(at, "check.charge-rounding", {{"name", charge.name}});
        }
        if (r.base && charge.amount) {
            // A fixed amount has no base.
            error(at, "check.charge-on", {{"name", charge.name}, {"other", r.first_base}});
        } else if (charge.included && !charge.on.empty()) {
            // An included charge is taken out of the price only.
            error(at, "check.charge-on",
                  {{"name", charge.name}, {"other", model_.charges[charge.on.front()].name}});
        } else if (!charge.per_document) {
            // On each line: only on charges with an amount on each line.
            for (const std::uint64_t j : charge.on) {
                if (model_.charges[j].per_document) {
                    error(at, "check.charge-on",
                          {{"name", charge.name}, {"other", model_.charges[j].name}});
                }
            }
        }
        if (document == nullptr) {
            error(at, "check.charge-document", {{"name", charge.name}});
        } else if (charge.document != nullptr && charge.document != document) {
            error(at, "check.charge-bill",
                  {{"name", charge.name}, {"document", std::string(charge.document->id)}});
        }
        std::ranges::stable_sort(charge.dated, [](const m::DatedRate& x, const m::DatedRate& y) {
            const Date& a = x.date.literal.date;
            const Date& b = y.date.literal.date;
            return std::tuple{a.year, a.month, a.day} < std::tuple{b.year, b.month, b.day};
        });
        shared.earlier.emplace(charge.name, model_.charges.size());
        if (declare(charge.name, Refers::charge, model_.charges.size(), at)) {
            model_.charges.push_back(std::move(charge));
        } else {
            shared.earlier.erase(charge.name);
        }
    }
    place_ = Place::declaration;
}

// --- Actions and rules.

void Checker::check_can(const ast::Can& c, std::size_t index) {
    m::Action a;
    a.span = c.span;
    if (c.action.kind == ExprKind::word) {
        a.word = c.action.concept_entry;
    } else {
        a.name = c.action.name;
    }
    const std::string action = m::key(a.word, a.name);
    const bool duplicate = duplicate_actions_.contains(index);
    if (!duplicate) {
        if (const auto it = inputs_.find(action); it != inputs_.end()) {
            a.inputs = it->second;
        }
    }
    frames_.emplace_back();
    for (const m::Field& input : a.inputs) {
        frames_.back().emplace(m::key(input.word, input.name), Local{Refers::input, input.type});
    }
    // The action's amount, for thresholds (R6): its one input of money or
    // a quantity; with none, the instance's amount.
    amounts_ = 0;
    amount_ = of(TypeKind::unknown);
    for (const m::Field& input : a.inputs) {
        if (input.type.kind == TypeKind::money || input.type.kind == TypeKind::quantity) {
            ++amounts_;
            amount_ = input.type;
        }
    }
    if (amounts_ == 0) {
        if (const Decl* d = global("field.amount"); d != nullptr && d->refers == Refers::field) {
            const Type& t = model_.fields[d->index].type;
            if (t.kind == TypeKind::money || t.kind == TypeKind::quantity) {
                amounts_ = 1;
                amount_ = t;
            }
        }
    }

    place_ = Place::action;
    action_ = &a;
    action_key_ = action;
    consents_ = &a.consents;
    // R19: a built-in action's terms from the standard library.
    const auto terms = duplicate ? terms_.end() : terms_.find(index);
    a.terms = terms != terms_.end();
    a.rule_only = rule_only_.contains(index);
    const auto in_terms = [&](bool on) {
        in_terms_ = on;
        terms_site_ = c.action.span;
        terms_text_ = terms_source(c.action.concept_entry, vocabularies_);
    };
    if (c.by) {
        a.by = value(*c.by);
        expect_kind(*a.by, TypeKind::party);
    } else if (a.terms && terms->second.by) {
        in_terms(true);
        a.by = value(*terms->second.by);
        expect_kind(*a.by, TypeKind::party);
        a.by->rule = rule_standard_terms;
        respan(*a.by, c.action.span);
        in_terms(false);
    }
    // Where the counterparty's consents go (R3, R21; R31 once the block is
    // read).
    const Span to_span = c.to ? c.to->span : c.action.span;
    if (c.to) {
        check_to(*c.to, a, action);
    } else if (a.terms && terms->second.to) {
        in_terms(true);
        const std::size_t before = a.consents.size();
        check_to(*terms->second.to, a, action);
        respan(*a.to, c.action.span);
        for (std::size_t k = before; k < a.consents.size(); ++k) {
            a.consents[k].span = c.action.span;
            respan(a.consents[k].party, c.action.span);
        }
        in_terms(false);
    }
    const std::size_t to_consents = a.consents.size();
    if (!c.by && a.word == nullptr) {
        error(c.action.span, "check.needs-by", {{"action", action}});
    }
    a.body = statements(c.body);
    if (a.terms) {
        // The contract's own lines first, then the terms (R8 adds no
        // consent to them). A state change from states no instance reaches
        // leaves them out.
        a.terms_from = a.body.size();
        in_terms(true);
        consents_ = nullptr;
        std::vector<m::Statement> more = statements(terms->second.body);
        respan(more, c.action.span);
        consents_ = &a.consents;
        in_terms(false);
        const auto prune = [&](std::vector<m::Statement>& list, const auto& self) -> void {
            for (m::Statement& st : list) {
                if (auto* t = std::get_if<m::Transition>(&st.node)) {
                    const auto unreached = [&](const m::Expr& f) {
                        const Decl* d = global(m::key(f.concept_entry, f.name));
                        return d == nullptr || d->refers != Refers::state;
                    };
                    if (!std::ranges::all_of(t->from, unreached)) {
                        std::erase_if(t->from, unreached);
                    }
                } else if (auto* i = std::get_if<m::If>(&st.node)) {
                    self(i->then, self);
                    self(i->otherwise, self);
                } else if (auto* e = std::get_if<m::Each>(&st.node)) {
                    self(e->body, self);
                }
            }
        };
        prune(more, prune);
        for (m::Statement& st : more) {
            a.body.push_back(std::move(st));
        }
    }
    // R30: an action issues parts once, in its own block.
    {
        bool issued = false;
        for (const m::Statement& st : a.body) {
            if (const auto* d = std::get_if<m::Do>(&st.node); d != nullptr && d->parts) {
                if (issued) {
                    error(d->span, "check.parts-place", {{"text", written(d->span)}});
                }
                issued = true;
            } else if (const auto* i = std::get_if<m::If>(&st.node)) {
                const auto nested = [&](const std::vector<m::Statement>& list,
                                        const auto& self) -> void {
                    for (const m::Statement& inner : list) {
                        if (const auto* nd = std::get_if<m::Do>(&inner.node);
                            nd != nullptr && nd->parts) {
                            error(nd->span, "check.parts-place", {{"text", written(nd->span)}});
                        } else if (const auto* ni = std::get_if<m::If>(&inner.node)) {
                            self(ni->then, self);
                            self(ni->otherwise, self);
                        }
                    }
                };
                nested(i->then, nested);
                nested(i->otherwise, nested);
            }
        }
    }
    // R31: a counterparty the action makes the holder, the pledgee, or the
    // payee consents at every call, even when its role was bound before
    // (at creation, or by another action). R3 and R21 ask it already when
    // the action binds it or each call names it, and R8 when it is a field
    // the action's own lines set.
    if (m::role_taken(a) != nullptr) {
        const std::string party = m::key(a.to->concept_entry, a.to->name);
        const bool asked = std::ranges::any_of(a.consents, [&](const m::Consent& k) {
            return k.party.refers == a.to->refers &&
                   m::key(k.party.concept_entry, k.party.name) == party;
        });
        if (!asked) {
            a.consents.insert(a.consents.begin() + static_cast<std::ptrdiff_t>(to_consents),
                              m::Consent{to_span, *a.to, rule_role_taking});
        }
    }
    if (!a.agents_propose) {
        a.agents_rule = rule_agents;
    }
    // R34: subscribing to a service, or renewing it, bills one period.
    if (a.terms && (is(a.word, "act.subscribe") || is(a.word, "act.renew"))) {
        add_billing(a, c.action.span);
    }
    // R10: it asks an executor to do the same, after its clauses, within a
    // day (notify has no terms: `notify PARTY` is a request of its own).
    if (executor_action(a.word, model_.kind)) {
        a.executor = true;
        a.executor_rule = rule_executor;
        if (!a.terms) {
            // `can notify`: notify is a request, written in a block.
            error(c.action.span, "check.needs-executor", {{"action", action}});
        } else {
            a.body.push_back(m::Statement{added_request(wire_name(a.word, {}), std::nullopt, {},
                                                        duration_node(1, "time.day", c.action.span),
                                                        c.action.span, rule_executor)});
        }
    }
    frames_.pop_back();
    action_ = nullptr;
    consents_ = nullptr;
    action_key_.clear();
    place_ = Place::declaration;
    if (!duplicate) {
        model_.actions.push_back(std::move(a));
    }
}

void Checker::check_to(const ast::Expr& to, m::Action& a, const std::string& action) {
    a.to = value(to);
    expect_kind(*a.to, TypeKind::party);
    if (a.to->refers == Refers::input) {
        // R21: each call names the counterparty, which consents.
        a.consents.push_back(m::Consent{to.span, *a.to, rule_counterparty});
        a.to->rule = rule_counterparty;
        return;
    }
    // R3: the role this action binds consents to being bound.
    const std::string party = m::key(a.to->concept_entry, a.to->name);
    if (const Decl* d = global(party);
        d != nullptr && d->refers == Refers::party && model_.parties[d->index].bound_by == action) {
        a.consents.push_back(m::Consent{to.span, *a.to, rule_role_binding});
    }
}

/// True if a statement of an action's asks a person to prove presence.
bool asks_presence(const std::vector<m::Statement>& list) {
    const auto in = [](const m::Expr& e, const auto& self) -> bool {
        return (e.kind == ExprKind::word && is(e.concept_entry, "cond.in_person")) ||
               std::ranges::any_of(e.operands, [&](const m::Expr& o) { return self(o, self); });
    };
    return std::ranges::any_of(list, [&](const m::Statement& s) {
        if (const auto* r = std::get_if<m::Requires>(&s.node)) {
            return in(r->condition, in) || (r->guard && in(*r->guard, in));
        }
        if (const auto* i = std::get_if<m::If>(&s.node)) {
            return in(i->condition, in) || asks_presence(i->then) || asks_presence(i->otherwise);
        }
        if (const auto* e = std::get_if<m::Each>(&s.node)) {
            return asks_presence(e->body);
        }
        return false;
    });
}

void Checker::check_when(const ast::When& w) {
    m::TimeRule r;
    r.span = w.span;
    frames_.emplace_back();
    place_ = Place::event;
    r.event = value(w.event);
    if (r.event.type.kind == TypeKind::state) {
        r.event.type = of(TypeKind::yes_no);
        r.event.rule = rule_state_condition;
    }
    // The one time the rule fires at (a date, N before due, overdue, a state
    // held N), with any other conditions joined by `and`.
    if (known(r.event.type) && !m::trigger_of(r.event)) {
        error(w.event.span, "check.when-event", {{"text", written(w.event.span)}});
    }
    place_ = Place::rule;
    consents_ = &r.consents;
    if (std::ranges::any_of(w.actions, [&](const ast::Do& d) { return is_notify(d); })) {
        // R10: notify PARTY is a request; with it, the line's actions are
        // the block's first lines, in order.
        for (const ast::Do& d : w.actions) {
            r.body.push_back(is_notify(d) ? m::Statement{notify_request(d)}
                                          : m::Statement{do_action(d)});
        }
    } else {
        for (const ast::Do& d : w.actions) {
            r.actions.push_back(do_action(d));
        }
    }
    for (m::Statement& st : statements(w.body)) {
        r.body.push_back(std::move(st));
    }
    // The actions the rule does: the keeper's call gives no arguments, and
    // nobody proves presence in it.
    for (const m::Do* d : m::rule_actions(r)) {
        const m::Action* a = m::action_of(model_, *d);
        if (a == nullptr) {
            continue;
        }
        if (a->to || !a->inputs.empty() || !d->args.empty() || !d->with.empty() || d->to || d->by) {
            error(d->span, "check.when-action", {{"action", m::key(a->word, a->name)}});
        } else if (asks_presence(a->body)) {
            error(d->span, "check.when-person", {{"text", written(d->span)}});
        }
    }
    frames_.pop_back();
    consents_ = nullptr;
    place_ = Place::declaration;
    model_.rules.push_back(std::move(r));
}

/// A request's kind as the ledger takes it: 1 to 64 bytes, a lowercase
/// ASCII letter, then lowercase letters, digits, `.`, `_`, or `-`.
bool request_kind(std::string_view kind) noexcept {
    if (kind.empty() || kind.size() > 64 || kind[0] < 'a' || kind[0] > 'z') {
        return false;
    }
    return std::ranges::all_of(kind, [](const char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    });
}

/// A type a request's value may have: one with a JSON form (numbers,
/// texts, yes or no, parties as their ledger ids), or a list of them.
bool request_value(const Type& t) {
    switch (t.kind) {
    case TypeKind::number:
    case TypeKind::money:
    case TypeKind::quantity:
    case TypeKind::rate:
    case TypeKind::date:
    case TypeKind::duration:
    case TypeKind::text:
    case TypeKind::yes_no:
    case TypeKind::party:
        return true;
    case TypeKind::list:
        return t.element.size() == 1 && t.element[0].kind != TypeKind::list &&
               request_value(t.element[0]);
    default:
        return false;
    }
}

m::Request Checker::request_statement(const ast::Request& r) {
    m::Request out;
    out.span = r.span;
    if (r.kind.kind == ExprKind::word) {
        out.word = r.kind.concept_entry;
        out.kind = wire_name(out.word, {});
    } else {
        out.kind = r.kind.name;
    }
    if (!request_kind(out.kind)) {
        error(r.kind.span, "check.request-kind", {{"text", written(r.kind.span)}});
    } else {
        requested_.insert(out.kind);
    }
    if (r.to) {
        out.to = value(*r.to);
        expect_kind(*out.to, TypeKind::party);
    }
    std::set<std::string> names;
    for (const ast::Set& w : r.with) {
        m::Set item;
        item.span = w.span;
        item.target = plain(w.target);
        const std::string name = wire_name(
            w.target.kind == ExprKind::word ? w.target.concept_entry : nullptr, w.target.name);
        if (!names.insert(name).second || (name == "to" && r.to)) {
            error(w.target.span, "check.duplicate", {{"name", name}});
        }
        item.value = value(w.value);
        if (known(item.value.type) && !request_value(item.value.type)) {
            error(w.value.span, "check.request-value",
                  {{"name", name}, {"type", encode(item.value.type)}});
        }
        item.target.type = item.value.type;
        out.with.push_back(std::move(item));
    }
    // Within a duration written out: more than nothing, at most 366 days
    // (12 months), the ledger's limit.
    const ast::Expr* duration =
        r.within && r.within->operands.size() == 1 ? &r.within->operands[0] : nullptr;
    std::optional<std::int64_t> amount;
    if (duration != nullptr && duration->kind == ExprKind::literal &&
        duration->literal.kind == ast::LiteralKind::duration) {
        amount = literal_value(duration->literal, model_.utc_offset_ms);
    }
    if (!amount) {
        error(r.within ? r.within->span : r.span, "check.request-within",
              {{"text", written(r.within ? r.within->span : r.span)}});
    } else {
        out.within = value(*duration);
        const bool calendar = out.within.type.calendar;
        if (*amount <= 0 || *amount > (calendar ? 12 : m::max_request_ms)) {
            error(r.within->span, "check.request-within", {{"text", written(r.within->span)}});
        }
    }
    return out;
}

void Checker::check_answer(const ast::AnswerRule& r) {
    m::AnswerRule out;
    out.span = r.span;
    if (r.kind.kind == ExprKind::word) {
        out.word = r.kind.concept_entry;
        out.kind = wire_name(out.word, {});
    } else {
        out.kind = r.kind.name;
    }
    if (!request_kind(out.kind)) {
        error(r.kind.span, "check.request-kind", {{"text", written(r.kind.span)}});
    }
    out.outcome = is(r.outcome, "kw.done")    ? m::Outcome::done
                  : is(r.outcome, "kw.fails") ? m::Outcome::fails
                                              : m::Outcome::expires;
    for (const m::AnswerRule& other : model_.answers) {
        if (other.kind == out.kind && other.outcome == out.outcome) {
            error(r.kind.span, "check.answer-twice", {{"text", written(r.kind.span)}});
        }
    }
    frames_.emplace_back();
    place_ = Place::answer;
    // An answer is never refused and cites no consent: its rule does no
    // action, refuses nothing, and sets no party's field.
    std::vector<m::Consent> consents;
    consents_ = &consents;
    for (const ast::Do& d : r.actions) {
        if (is_notify(d)) {
            out.body.push_back(m::Statement{notify_request(d)});
        } else {
            error(d.span, "check.answer-line", {{"text", written(d.span)}});
        }
    }
    for (m::Statement& st : statements(r.body)) {
        out.body.push_back(std::move(st));
    }
    each_statement(out.body, [&](const m::Statement& st) {
        const Span* at = nullptr;
        if (const auto* q = std::get_if<m::Requires>(&st.node)) {
            at = &q->span;
        } else if (const auto* j = std::get_if<m::Reject>(&st.node)) {
            at = &j->span;
        } else if (const auto* d = std::get_if<m::Do>(&st.node)) {
            at = &d->span;
        } else if (const auto* t = std::get_if<m::Transition>(&st.node); t && !t->from.empty()) {
            at = &t->span;
        }
        if (at != nullptr) {
            error(*at, "check.answer-line", {{"text", written(*at)}});
        }
    });
    for (const m::Consent& c : consents) {
        error(c.span, "check.answer-line", {{"text", written(c.span)}});
    }
    frames_.pop_back();
    consents_ = nullptr;
    place_ = Place::declaration;
    model_.answers.push_back(std::move(out));
}

bool Checker::is_notify(const ast::Do& d) const {
    return !d.subject && !d.outcome && word_is(d.action, "act.notify");
}

m::Request Checker::notify_request(const ast::Do& d) {
    // R10: `notify PARTY` asks an executor to notify that party, within a
    // day: `request notify to PARTY within 1 day`.
    std::optional<ast::Expr> to;
    if (d.args.size() == 1 && !d.to && !d.by && d.with.empty()) {
        to = d.args[0];
    } else {
        error(d.span, "check.notify", {{"text", written(d.span)}});
    }
    m::Request out = added_request("notify", std::move(to), {},
                                   duration_node(1, "time.day", d.span), d.span, rule_executor);
    out.word = d.action.concept_entry;
    return out;
}

m::Request Checker::added_request(std::string_view kind, std::optional<ast::Expr> to,
                                  std::vector<ast::Set> with, ast::Expr within, const Span& span,
                                  std::string_view rule) {
    ast::Request r;
    r.span = span;
    const Concept* word =
        find_concept(kind == "invoice" ? "doc.invoice" : "act." + std::string(kind));
    r.kind = word != nullptr ? word_node(word->id, span) : ast::Expr{};
    if (word == nullptr) {
        r.kind.kind = ExprKind::name;
        r.kind.span = span;
        r.kind.name = std::string(kind);
    }
    r.to = std::move(to);
    r.with = std::move(with);
    r.within = apply_node("cond.within", std::move(within), span);
    m::Request out = request_statement(r);
    out.rule = rule;
    return out;
}

std::optional<ast::Expr> Checker::customer_node(const Span& span) const {
    // The party a service's bills are for: its customer, if the contract
    // names one.
    const Decl* d = global("role.customer");
    if (d == nullptr || d->refers != Refers::party) {
        return std::nullopt;
    }
    return word_node("role.customer", span);
}

ast::Expr Checker::period_amount(const Span& span) const {
    // The recurring price's amount for one period (HKD 120 of monthly HKD
    // 120), as written.
    const m::Field* price = recurring_price();
    BO_ASSERT(price != nullptr);
    const m::Expr* amount = &*price->value;
    while (amount->kind == ExprKind::phrase && !amount->operands.empty()) {
        amount = &amount->operands.back();
    }
    ast::Expr e;
    e.kind = ExprKind::literal;
    e.span = span;
    e.literal = amount->literal;
    return e;
}

void Checker::mark(std::vector<m::Statement>& list, std::string_view rule) {
    // The lines Bo adds carry the rule that adds them (in the contract text).
    for (m::Statement& st : list) {
        std::visit(Overloaded{
                       [&](m::Set& set) { set.value.rule = rule; },
                       [&](m::If& i) {
                           i.condition.rule = rule;
                           mark(i.then, rule);
                           mark(i.otherwise, rule);
                       },
                       [&](m::Transition& t) { t.to.rule = rule; },
                       [&](m::Request& r) {
                           if (r.rule.empty()) {
                               r.rule = rule;
                           }
                       },
                       [&](auto&) {},
                   },
                   st.node);
    }
}

void Checker::add_billing(m::Action& a, const Span& span) {
    // R34: on a service with a recurring price, billed until moves one
    // period on, and an executor is asked to invoice the customer for the
    // period's price, from the date it is paid until to the date it is now
    // billed until.
    const m::Field* price = recurring_price();
    const Decl* billed = global("field.billed_until");
    const Decl* paid = global("field.paid_until");
    // Only where the service is due on the date it is paid until (R11):
    // not with a due date of its own.
    if (price == nullptr || billed == nullptr || paid == nullptr || !known(price->type) ||
        model_.due != m::DueKind::period) {
        return;
    }
    if (m::bill_field(model_) != nullptr) {
        // Charges on a service's period bills come later: its invoices carry
        // the period's price.
        error(span, "check.service-bill", {{"text", written(span)}});
        return;
    }
    billing_ = true;
    billing_span_ = span;
    const ast::Expr period = period_node(price->type.period, span);
    std::vector<ast::Statement> lines;
    lines.push_back(set_node(
        word_node("field.billed_until", span),
        binary_node(Operator::plus, word_node("field.billed_until", span), period, span), span));
    std::vector<m::Statement> checked = statements(lines);
    std::vector<ast::Set> with;
    with.push_back(ast::Set{span, word_node("field.amount", span), period_amount(span)});
    with.push_back(
        ast::Set{span, word_node("field.paid_until", span), word_node("field.paid_until", span)});
    with.push_back(ast::Set{span, word_node("field.billed_until", span),
                            word_node("field.billed_until", span)});
    checked.push_back(
        m::Statement{added_request("invoice", customer_node(span), std::move(with),
                                   duration_node(7, "time.day", span), span, rule_service_bill)});
    mark(checked, rule_service_bill);
    for (m::Statement& st : checked) {
        a.body.push_back(std::move(st));
    }
}

void Checker::add_billing_answers() {
    // R34, R35: the answers to a service's invoices and collections. The
    // lines go after those of the contract's own rule for the same answer,
    // if it has one.
    if (!billing_) {
        return;
    }
    const Span span = billing_span_;
    const m::Field* price = recurring_price();
    // The collection is due by the latest overdue rule's time, counted from
    // the due date; without one, 30 days after it.
    ast::Expr latest = duration_node(30, "time.day", span);
    std::optional<std::int64_t> longest;
    for (const m::TimeRule& r : model_.rules) {
        const std::optional<m::Trigger> t = m::trigger_of(r.event);
        if (!t || t->kind != m::TriggerKind::overdue || !m::rule_runs(r)) {
            continue;
        }
        ast::Expr n = duration_node(1, "time.day", span);
        std::int64_t ms = 86'400'000;
        if (t->value != nullptr && t->value->kind == ExprKind::literal) {
            n.literal = t->value->literal;
            const std::optional<std::int64_t> v = literal_value(n.literal, model_.utc_offset_ms);
            // A month counts as 31 days here, only to find the latest.
            ms = !v ? 0 : t->value->type.calendar ? *v * 31 * 86'400'000 : *v;
            if (t->value->type.calendar && v && *v > 12) {
                n.literal.number.digits = 12;
                n.literal.number.scale = 0;
            } else if (!t->value->type.calendar && ms > m::max_request_ms) {
                n = duration_node(366, "time.day", span);
            }
        }
        if (!longest || ms > *longest) {
            longest = ms;
            latest = std::move(n);
        }
    }
    const auto add = [&](std::string_view kind, m::Outcome outcome,
                         std::vector<m::Statement> lines) {
        for (m::AnswerRule& r : model_.answers) {
            if (r.kind == kind && r.outcome == outcome) {
                for (m::Statement& st : lines) {
                    r.body.push_back(std::move(st));
                }
                return;
            }
        }
        m::AnswerRule r;
        r.span = span;
        r.kind = std::string(kind);
        r.word = find_concept(kind == "invoice" ? "doc.invoice" : "act." + std::string(kind));
        r.outcome = outcome;
        r.body = std::move(lines);
        model_.answers.push_back(std::move(r));
    };
    frames_.emplace_back();
    place_ = Place::answer;
    std::vector<m::Consent> consents;
    consents_ = &consents;
    // A failed (or expired) invoice or collection closes the bill: billed
    // until goes back to paid until.
    const auto close = [&] {
        std::vector<ast::Statement> lines;
        lines.push_back(set_node(word_node("field.billed_until", span),
                                 word_node("field.paid_until", span), span));
        std::vector<m::Statement> out = statements(lines);
        mark(out, rule_service_bill);
        return out;
    };
    // The invoice done: the collection, carrying the invoice's result.
    {
        std::vector<ast::Set> with;
        with.push_back(ast::Set{span, word_node("field.amount", span), period_amount(span)});
        with.push_back(
            ast::Set{span, word_node("doc.invoice", span), word_node("expr.result", span)});
        m::Request collect = added_request("collect", customer_node(span), std::move(with),
                                           std::move(latest), span, rule_service_bill);
        collect.from_due = true;
        std::vector<m::Statement> lines;
        lines.push_back(m::Statement{std::move(collect)});
        add("invoice", m::Outcome::done, std::move(lines));
    }
    add("invoice", m::Outcome::fails, close());
    // The collection done: one more period paid; a suspended service no
    // longer overdue resumes (R35).
    {
        std::vector<ast::Statement> lines;
        lines.push_back(set_node(word_node("field.paid_until", span),
                                 binary_node(Operator::plus, word_node("field.paid_until", span),
                                             period_node(price->type.period, span), span),
                                 span));
        const Decl* suspended = global("state.suspended");
        const Decl* active = global("state.active");
        std::vector<m::Statement> out = statements(lines);
        if (suspended != nullptr && suspended->refers == Refers::state && active != nullptr &&
            active->refers == Refers::state) {
            ast::If resume;
            resume.span = span;
            ast::Expr not_overdue;
            not_overdue.kind = ExprKind::unary;
            not_overdue.span = span;
            not_overdue.op = Operator::logical_not;
            not_overdue.operands.push_back(word_node("cond.overdue", span));
            resume.condition =
                binary_node(Operator::logical_and, word_node("state.suspended", span),
                            std::move(not_overdue), span);
            resume.then.push_back(
                ast::Statement{ast::Transition{span, {}, word_node("state.active", span)}});
            std::vector<ast::Statement> wrapped;
            wrapped.push_back(ast::Statement{std::move(resume)});
            std::vector<m::Statement> checked = statements(wrapped);
            auto& branch = std::get<m::If>(checked.back().node).then;
            branch.push_back(m::Statement{added_request("resume", std::nullopt, {},
                                                        duration_node(1, "time.day", span), span,
                                                        rule_service_paid)});
            for (m::Statement& st : checked) {
                out.push_back(std::move(st));
            }
        }
        mark(out, rule_service_paid);
        add("collect", m::Outcome::done, std::move(out));
    }
    add("collect", m::Outcome::fails, close());
    // A contract's own rule for an expiry takes it from the rule for
    // failures (R33): it closes the bill too.
    for (const std::string_view kind : {std::string_view("invoice"), std::string_view("collect")}) {
        for (m::AnswerRule& r : model_.answers) {
            if (r.kind == kind && r.outcome == m::Outcome::expires) {
                for (m::Statement& st : close()) {
                    r.body.push_back(std::move(st));
                }
            }
        }
    }
    frames_.pop_back();
    consents_ = nullptr;
    place_ = Place::declaration;
}

/// What the whole contract's requests need: a reply function, at most 16
/// requests in any one call, and rules for kinds it requests.
void Checker::check_requests() {
    // R33: a rule for failures takes a kind's expired answers too, unless
    // a rule for its expiry does.
    for (m::AnswerRule& r : model_.answers) {
        if (r.outcome == m::Outcome::fails && m::answer_rule(model_, r.kind, 3) == &r) {
            r.expired = true;
            r.rule = rule_expired;
        }
        if (!requested_.contains(r.kind) && request_kind(r.kind)) {
            error(r.span, "check.answer-unasked", {{"kind", r.kind}});
        }
    }
    const auto count = [](const std::vector<m::Statement>& list) {
        return static_cast<std::uint64_t>(m::requests_in(list).size());
    };
    const auto too_many = [&](const Span& span, std::string_view function, std::uint64_t n) {
        if (n > m::max_call_requests) {
            error(span, "check.request-count",
                  {{"function", std::string(function)}, {"count", std::to_string(n)}});
        }
    };
    std::uint64_t proposals = 0;
    for (const m::Action& a : model_.actions) {
        too_many(a.span, wire_name(a.word, a.name), count(a.body));
        if (a.agents_propose) {
            proposals = std::max(proposals, count(a.body));
        }
    }
    too_many(model_.actions.empty() ? Span{} : model_.actions.front().span, m::approve_function,
             proposals);
    const std::vector<std::string> functions = m::rule_functions(model_);
    for (std::size_t i = 0; i < model_.rules.size(); ++i) {
        const m::TimeRule& r = model_.rules[i];
        std::uint64_t n = count(r.body);
        for (const m::Do* d : m::rule_actions(r)) {
            if (const m::Action* a = m::action_of(model_, *d)) {
                n += count(a->body);
            }
        }
        too_many(r.span, functions[i], n);
    }
    for (const m::AnswerRule& r : model_.answers) {
        too_many(r.span, m::reply_function, count(r.body));
    }
}

std::vector<m::Statement> Checker::statements(const std::vector<ast::Statement>& list) {
    std::vector<m::Statement> out;
    for (const ast::Statement& s : list) {
        std::visit(
            Overloaded{
                [&](const ast::Requires& r) {
                    m::Requires req;
                    req.span = r.span;
                    if (r.guard) {
                        req.guard = condition(*r.guard);
                    }
                    req.condition = condition(r.condition);
                    out.push_back(m::Statement{std::move(req)});
                },
                [&](const ast::Permit& p) {
                    if (place_ != Place::action || action_ == nullptr) {
                        error(p.span, "check.when-person", {{"text", written(p.span)}});
                    } else if (word_is(p.who, "actor.ai_agent") &&
                               word_is(p.action, "act.propose")) {
                        action_->agents_propose = true;
                    } else {
                        error(p.span, "check.permit", {{"text", written(p.span)}});
                    }
                },
                [&](const ast::If& i) {
                    m::If node;
                    node.span = i.span;
                    node.condition = condition(i.condition);
                    node.then = statements(i.then);
                    node.otherwise = statements(i.otherwise);
                    out.push_back(m::Statement{std::move(node)});
                },
                [&](const ast::Each& e) {
                    m::Each node;
                    node.span = e.span;
                    node.name = e.name.name;
                    node.list = value(e.list);
                    Type item = of(TypeKind::unknown);
                    if (node.list.type.kind == TypeKind::list && !node.list.type.element.empty()) {
                        item = node.list.type.element[0];
                    } else if (known(node.list.type)) {
                        error(e.list.span, "check.type",
                              {{"text", written(e.list.span)},
                               {"type", encode(node.list.type)},
                               {"expected_type", encode(of(TypeKind::list))}});
                    }
                    if (declared(node.name)) {
                        error(e.name.span, "check.duplicate", {{"name", node.name}});
                    }
                    frames_.emplace_back();
                    frames_.back().emplace(node.name, Local{Refers::item, item});
                    node.body = statements(e.body);
                    frames_.pop_back();
                    // Once per item: no state change, no action done,
                    // no request (a call makes at most 16).
                    each_statement(node.body, [&](const m::Statement& st) {
                        const Span* at = nullptr;
                        if (const auto* t = std::get_if<m::Transition>(&st.node)) {
                            at = &t->span;
                        } else if (const auto* d = std::get_if<m::Do>(&st.node)) {
                            at = &d->span;
                        } else if (const auto* r = std::get_if<m::Request>(&st.node)) {
                            at = &r->span;
                        }
                        if (at != nullptr) {
                            error(*at, "check.each-body", {{"text", written(*at)}});
                        }
                    });
                    out.push_back(m::Statement{std::move(node)});
                },
                [&](const ast::Reject& r) {
                    out.push_back(m::Statement{m::Reject{r.span, r.message}});
                },
                [&](const ast::Set& st) { out.push_back(m::Statement{set_statement(st)}); },
                [&](const ast::Transition& t) {
                    m::Transition node;
                    node.span = t.span;
                    for (const ast::Expr& from : t.from) {
                        node.from.push_back(value(from));
                        expect_kind(node.from.back(), TypeKind::state);
                    }
                    if (word_is(t.to, "expr.previous_state")) {
                        // Back to the state before the current one.
                        node.to = plain(t.to);
                        node.to.type = of(TypeKind::state);
                    } else {
                        node.to = value(t.to);
                        expect_kind(node.to, TypeKind::state);
                    }
                    out.push_back(m::Statement{std::move(node)});
                },
                [&](const ast::Do& d) {
                    out.push_back(is_notify(d) ? m::Statement{notify_request(d)}
                                               : m::Statement{do_action(d)});
                },
                [&](const ast::Expect&) {},
                [&](const ast::Request& r) { out.push_back(m::Statement{request_statement(r)}); },
            },
            s.node);
    }
    return out;
}

m::Set Checker::set_statement(const ast::Set& s) {
    m::Set out;
    out.span = s.span;
    out.target = value(s.target);
    if (word_is(s.value, "val.none")) {
        // No party: a party field may be set to none.
        out.value = plain(s.value);
        out.value.type = of(TypeKind::party);
    } else {
        out.value = value(s.value);
    }
    if (out.target.refers != Refers::field) {
        if (known(out.target.type)) {
            error(s.target.span, "check.set-target", {{"text", written(s.target.span)}});
        }
        return out;
    }
    const std::string field = m::key(out.target.concept_entry, out.target.name);
    const Decl* d = global(field);
    if (d == nullptr || d->refers != Refers::field) {
        return out;
    }
    const m::Field& declared_field = model_.fields[d->index];
    if (declared_field.kind == m::FieldKind::constant) {
        error(s.target.span, "check.set-constant", {{"field", field}});
        return out;
    }
    expect(out.value, declared_field.type);
    // R8: changing a field that holds a party takes it from that party.
    if (declared_field.type.kind == TypeKind::party && consents_ != nullptr) {
        const bool starter = action_ != nullptr && action_->by &&
                             action_->by->refers == Refers::field &&
                             m::key(action_->by->concept_entry, action_->by->name) == field;
        const bool listed = std::ranges::any_of(*consents_, [&](const m::Consent& c) {
            return c.party.refers == Refers::field &&
                   m::key(c.party.concept_entry, c.party.name) == field;
        });
        if (!starter && !listed) {
            consents_->push_back(m::Consent{s.span, out.target, rule_consent_taken});
        }
    }
    return out;
}

m::Do Checker::do_action(const ast::Do& d) {
    const Concept* word = d.action.kind == ExprKind::word ? d.action.concept_entry : nullptr;
    // R30: the creation word in an action's own block issues parts.
    if ((is(word, "act.issue") || is(word, "act.create")) && !d.subject) {
        if (place_ == Place::action) {
            return parts_statement(d);
        }
        error(d.span, "check.parts-place", {{"text", written(d.span)}});
    }
    m::Do out;
    out.span = d.span;
    out.action = plain(d.action);
    const std::string action = m::key(word, d.action.name);
    if (word == nullptr) {
        out.action.refers = Refers::action;
    }
    if (d.subject) {
        out.subject = value(*d.subject);
        expect_kind(*out.subject, TypeKind::party);
        if (place_ == Place::action) {
            error(d.span, "check.subject", {{"text", written(d.span)}});
        } else {
            // R9 (U7): a party's duty, which sets what is due; no call.
            out.obligation = true;
            out.rule = rule_obligation;
        }
    }
    for (const ast::Expr& a : d.args) {
        out.args.push_back(value(a));
    }
    if (d.to) {
        out.to = value(*d.to);
        expect_kind(*out.to, TypeKind::party);
    }
    if (d.by) {
        out.by = value(*d.by);
        expect_kind(*out.by, TypeKind::party);
    }
    const auto inputs = inputs_.find(action);
    for (const ast::Set& s : d.with) {
        m::Set item;
        item.span = s.span;
        item.target = plain(s.target);
        item.target.refers = Refers::input;
        item.value = value(s.value);
        if (word == nullptr) {
            const std::string input = m::key(
                s.target.kind == ExprKind::word ? s.target.concept_entry : nullptr, s.target.name);
            const m::Field* found = nullptr;
            if (inputs != inputs_.end()) {
                for (const m::Field& f : inputs->second) {
                    if (m::key(f.word, f.name) == input) {
                        found = &f;
                    }
                }
            }
            if (found == nullptr) {
                error(s.target.span, "check.unknown-input", {{"name", input}, {"action", action}});
            } else {
                expect(item.value, found->type);
            }
        }
        out.with.push_back(std::move(item));
    }
    if (word == nullptr && place_ == Place::action && !action_key_.empty()) {
        calls_[action_key_].push_back(action);
    }
    return out;
}

m::Do Checker::parts_statement(const ast::Do& d) {
    // issue PARTS to RECIPIENTS [with FIELD = VALUE, ...] (R30): each part an
    // instance of its own, its amount the part and its holder the recipient
    // in the same place; the instance that issues them ends.
    m::Do out;
    out.span = d.span;
    out.action = plain(d.action);
    out.parts = true;
    out.rule = rule_issue_parts;
    bool shaped =
        expr_key(d.action) == creation_word() && !d.by && d.args.size() == 1 && d.to.has_value();
    // The instance's amount and holder, which each part gets; no bill.
    const Decl* amount = global("field.amount");
    const Decl* holder = global("field.holder");
    const m::Field* amount_field = amount != nullptr && amount->refers == Refers::field
                                       ? &model_.fields[amount->index]
                                       : nullptr;
    const m::Field* holder_field = holder != nullptr && holder->refers == Refers::field
                                       ? &model_.fields[holder->index]
                                       : nullptr;
    const bool instance = amount_field != nullptr && amount_field->kind == m::FieldKind::instance &&
                          (amount_field->type.kind == TypeKind::money ||
                           amount_field->type.kind == TypeKind::quantity) &&
                          holder_field != nullptr && holder_field->kind == m::FieldKind::instance &&
                          holder_field->type.kind == TypeKind::party &&
                          m::bill_field(model_) == nullptr;
    if (!instance) {
        error(d.span, "check.parts-instance", {{"action", action_key_}});
    }
    // A list by its name: an input, or a field of the instance.
    const auto named_list = [&](const m::Expr& e, const Type& item) {
        if (!known(e.type)) {
            return true;
        }
        const bool by_name = (e.kind == ExprKind::name || e.kind == ExprKind::word) &&
                             (e.refers == Refers::input || e.refers == Refers::field);
        return by_name && e.type.kind == TypeKind::list && e.type.element.size() == 1 &&
               e.type.bound <= 16 && (!known(item) || same(e.type.element[0], item));
    };
    for (const ast::Expr& a : d.args) {
        out.args.push_back(value(a));
    }
    if (d.to) {
        out.to = value(*d.to);
    }
    if (!out.args.empty() && amount_field != nullptr &&
        !named_list(out.args[0], amount_field->type)) {
        shaped = false;
    }
    if (out.to && !named_list(*out.to, of(TypeKind::party))) {
        shaped = false;
    }
    std::set<std::string> given;
    for (const ast::Set& s : d.with) {
        m::Set item;
        item.span = s.span;
        item.target = value(s.target);
        const std::string field = m::key(item.target.concept_entry, item.target.name);
        const Decl* decl = global(field);
        const bool settable = item.target.refers == Refers::field && decl != nullptr &&
                              decl->refers == Refers::field &&
                              model_.fields[decl->index].kind == m::FieldKind::instance &&
                              field != "field.amount" && field != "field.holder" &&
                              m::bill_field(model_) == nullptr;
        if (word_is(s.value, "val.none")) {
            item.value = plain(s.value);
            item.value.type = of(TypeKind::party);
        } else {
            item.value = value(s.value);
        }
        if (!settable) {
            if (known(item.target.type)) {
                shaped = false;
            }
        } else if (!given.insert(field).second) {
            error(s.target.span, "check.duplicate", {{"name", field}});
        } else {
            const m::Field& target = model_.fields[decl->index];
            if (item.value.type.kind == TypeKind::party && word_is(s.value, "val.none") &&
                target.type.kind == TypeKind::party) {
                // No party: the field may hold none.
                model_.fields[decl->index].optional = true;
            } else {
                expect(item.value, target.type);
            }
        }
        out.with.push_back(std::move(item));
    }
    if (!shaped) {
        error(d.span, "check.parts-shape", {{"text", written(d.span)}});
    }
    return out;
}

void Checker::check_states() {
    std::set<std::string> reached;
    for (const m::State& s : model_.states) {
        if (s.first) {
            reached.insert(m::key(s.word, s.name));
        }
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (const Edge& edge : edges_) {
            const bool from = edge.from.empty()
                                  ? !reached.empty()
                                  : std::ranges::any_of(edge.from, [&](const std::string& k) {
                                        return reached.contains(k);
                                    });
            if (from && reached.insert(edge.to).second) {
                changed = true;
            }
        }
    }
    for (const m::State& s : model_.states) {
        const std::string k = m::key(s.word, s.name);
        // A vocabulary state may be reached by a vocabulary action whose
        // standard terms come later.
        if (reached.contains(k) || unclear_.contains(k) || (s.word != nullptr && any_unterms_)) {
            continue;
        }
        error(s.span, "check.unreachable-state", {{"state", k}});
    }
    if (!any_unterms_) {
        for (const auto& [k, span] : state_mentions_) {
            if (global(k) == nullptr) {
                error(span, "check.unreachable-state", {{"state", k}});
            }
        }
    }
}

void Checker::finish_terms() {
    // A party field some action sets to none may hold no party.
    const auto mark = [&](const std::vector<m::Statement>& list, const auto& self) -> void {
        for (const m::Statement& st : list) {
            if (const auto* set = std::get_if<m::Set>(&st.node)) {
                const Decl* d = global(m::key(set->target.concept_entry, set->target.name));
                if (set->value.kind == ExprKind::word && is(set->value.concept_entry, "val.none") &&
                    set->target.refers == Refers::field && d != nullptr &&
                    d->refers == Refers::field &&
                    model_.fields[d->index].type.kind == TypeKind::party) {
                    model_.fields[d->index].optional = true;
                }
            } else if (const auto* i = std::get_if<m::If>(&st.node)) {
                self(i->then, self);
                self(i->otherwise, self);
            } else if (const auto* e = std::get_if<m::Each>(&st.node)) {
                self(e->body, self);
            }
        }
    };
    for (const m::Action& a : model_.actions) {
        mark(a.body, mark);
    }
    for (const m::TimeRule& r : model_.rules) {
        mark(r.body, mark);
    }
}

bool Checker::reaches(const std::string& from, const std::string& target,
                      std::set<std::string>& seen) const {
    const auto it = calls_.find(from);
    if (it == calls_.end()) {
        return false;
    }
    for (const std::string& next : it->second) {
        if (next == target) {
            return true;
        }
        if (seen.insert(next).second && reaches(next, target, seen)) {
            return true;
        }
    }
    return false;
}

void Checker::check_recursion() {
    for (std::size_t i = 0; i < cans_.size(); ++i) {
        const ast::Can& c = *cans_[i];
        if (c.action.kind != ExprKind::name || duplicate_actions_.contains(i)) {
            continue;
        }
        std::set<std::string> seen;
        if (reaches(c.action.name, c.action.name, seen)) {
            error(c.action.span, "check.recursion", {{"action", c.action.name}});
        }
    }
}

// --- Tests (U8).

std::optional<m::TestParty> Checker::test_party(const ast::Expr& e) {
    m::TestParty p;
    p.span = e.span;
    if (word_in(e, Category::role)) {
        p.word = e.concept_entry;
        const Decl* d = global(e.concept_entry->id);
        if (d == nullptr || d->refers != Refers::party) {
            error(e.span, "check.unknown-party", {{"party", std::string(e.concept_entry->id)}});
            return std::nullopt;
        }
        p.role = true;
        return p;
    }
    if (e.kind == ExprKind::name) {
        // A name nothing declares is a ledger only the test names.
        p.name = e.name;
        if (const Decl* d = global(e.name)) {
            if (d->refers != Refers::party) {
                error(e.span, "check.test-party", {{"text", written(e.span)}});
                return std::nullopt;
            }
            p.role = true;
        }
        return p;
    }
    error(e.span, "check.test-party", {{"text", written(e.span)}});
    return std::nullopt;
}

m::Expr Checker::test_parties(const ast::Expr& e, const Type& type) {
    // A party (a role, or a ledger only tests name), or a list of them: each
    // item keeps its word or name, and refers to a party if it is a role.
    const auto one = [&](const ast::Expr& item) {
        m::Expr out = plain(item);
        out.type = of(TypeKind::party);
        if (std::optional<m::TestParty> p = test_party(item)) {
            out.refers = p->role ? Refers::party : Refers::none;
        } else {
            out.type = of(TypeKind::unknown);
        }
        return out;
    };
    if (type.kind == TypeKind::party) {
        return one(e);
    }
    m::Expr out = plain(e);
    out.kind = ExprKind::list;
    out.operands.clear();
    const std::vector<ast::Expr> single{e};
    // R29: one party where a list is needed is a list of one.
    for (const ast::Expr& item : e.kind == ExprKind::list ? e.operands : single) {
        out.operands.push_back(one(item));
    }
    out.type = type;
    if (out.operands.size() > type.bound) {
        error(e.span, "check.test-value", {{"text", written(e.span)}});
    }
    return out;
}

void Checker::check_tests() {
    place_ = Place::declaration;
    std::set<std::string> names;
    for (const ast::Test* t : tests_) {
        m::Test test;
        test.span = t->span;
        if (t->name) {
            test.name = t->name->kind == ExprKind::literal ? t->name->literal.text : t->name->name;
            if (!names.insert(test.name).second) {
                error(t->name->span, "check.duplicate", {{"name", test.name}});
            }
        }
        // The time of the steps so far: `at` never goes back.
        std::optional<std::int64_t> clock;
        // A step without an expectation yet, which a `->` line may give.
        bool open = false;
        for (const ast::Statement& s : t->steps) {
            if (const auto* e = std::get_if<ast::Expect>(&s.node)) {
                if (!open) {
                    error(e->span, "check.test-expect-step", {});
                    continue;
                }
                test_expect(*e, test.steps.back());
                open = false;
            } else if (const auto* d = std::get_if<ast::Do>(&s.node)) {
                test.steps.push_back(test_step(*d, test.steps.empty(), clock));
                open = true;
            }
        }
        if (test.steps.empty()) {
            error(t->span, "check.test-start", {{"action", creation_word()}});
        }
        model_.tests.push_back(std::move(test));
    }
}

m::Step Checker::answer_step(const ast::Do& d, const bool first,
                             std::optional<std::int64_t>& clock) {
    // `executor notify done [with result = TEXT, reason = TEXT] [at DATE]
    // [in person]`: the oldest open request of the kind is answered.
    m::Step step;
    step.span = d.span;
    step.answer = true;
    const Concept* word = d.action.kind == ExprKind::word ? d.action.concept_entry : nullptr;
    step.word = word;
    if (word == nullptr) {
        step.name = d.action.name;
    }
    step.request_kind = wire_name(word, step.name);
    step.outcome = is(d.outcome, "kw.done")    ? m::Outcome::done
                   : is(d.outcome, "kw.fails") ? m::Outcome::fails
                                               : m::Outcome::expires;
    if (first) {
        error(d.span, "check.test-start", {{"action", creation_word()}});
    }
    if (!requested_.contains(step.request_kind)) {
        error(d.action.span, "check.test-answer", {{"text", written(d.span)}});
    }
    // Who answers: the executor or the keeper (the home's devices), or a
    // party of the test (by hand).
    if (d.subject &&
        (word_is(*d.subject, "actor.executor") || word_is(*d.subject, "actor.keeper"))) {
        step.subject.span = d.subject->span;
        step.subject.word = d.subject->concept_entry;
    } else if (d.subject) {
        if (std::optional<m::TestParty> p = test_party(*d.subject)) {
            step.subject = std::move(*p);
        }
    }
    if (d.to || d.by) {
        error(d.span, "check.test-answer", {{"text", written(d.span)}});
    }
    for (const ast::Expr& a : d.args) {
        if (a.kind == ExprKind::apply && is(a.concept_entry, "time.at") && !step.at) {
            const ast::Expr* date = a.operands.empty() ? nullptr : &a.operands[0];
            const std::optional<std::int64_t> when =
                date != nullptr && date->kind == ExprKind::literal &&
                        date->literal.kind == ast::LiteralKind::date
                    ? literal_value(date->literal, model_.utc_offset_ms)
                    : std::nullopt;
            if (!when || *when < 0) {
                error(a.span, "check.test-time", {{"text", written(a.span)}});
                continue;
            }
            step.at = value(*date);
            if (clock && *when < *clock) {
                error(a.span, "check.test-time-back", {{"text", written(a.span)}});
            } else {
                clock = when;
            }
        } else if (word_is(a, "cond.in_person") && !step.in_person &&
                   !(step.subject.word != nullptr &&
                     step.subject.word->category == Category::actor)) {
            step.in_person = true;
        } else {
            error(a.span, "check.test-step", {{"text", written(a.span)}});
        }
    }
    // The answer's values: its result and its reason, texts.
    std::set<std::string> given;
    for (const ast::Set& w : d.with) {
        m::Set item;
        item.span = w.span;
        item.target = plain(w.target);
        if (!word_is(w.target, "expr.result") && !word_is(w.target, "expr.reason")) {
            error(w.target.span, "check.test-answer", {{"text", written(w.span)}});
        } else if (!given.insert(std::string(w.target.concept_entry->id)).second) {
            error(w.target.span, "check.duplicate", {{"name", written(w.target.span)}});
        }
        item.target.type = of(TypeKind::text);
        if (w.value.kind != ExprKind::literal || w.value.literal.kind != ast::LiteralKind::text) {
            error(w.value.span, "check.test-value", {{"text", written(w.value.span)}});
            item.value = plain(w.value);
        } else {
            item.value = value(w.value);
        }
        step.with.push_back(std::move(item));
    }
    return step;
}

m::Step Checker::test_step(const ast::Do& d, const bool first, std::optional<std::int64_t>& clock) {
    if (d.outcome != nullptr) {
        return answer_step(d, first, clock);
    }
    m::Step step;
    step.span = d.span;
    const Concept* word = d.action.kind == ExprKind::word ? d.action.concept_entry : nullptr;
    step.word = word;
    if (word == nullptr) {
        step.name = d.action.name;
    }
    const std::string action = m::key(word, step.name);
    const std::string creation = creation_word();
    // `keeper ACTION`: the keeper calls the time rule that does ACTION.
    step.keeper = d.subject && word_is(*d.subject, "actor.keeper");
    const m::Action* declared = nullptr;
    for (const m::Action& a : model_.actions) {
        // An action only time rules do is no step's.
        if (m::key(a.word, a.name) == action && !step.keeper && !a.rule_only) {
            declared = &a;
        }
    }
    step.creation = !step.keeper && action == creation;
    // `PARTY approve`: a person approves the first proposal an AI agent made.
    step.approve =
        !step.keeper && declared == nullptr && is(word, "act.approve") && m::has_proposals(model_);
    if (step.keeper) {
        const std::vector<std::string> functions = m::rule_functions(model_);
        const auto rule = std::ranges::find(functions, "when." + wire_name(word, step.name));
        if (rule == functions.end()) {
            error(d.action.span, "check.test-rule", {{"action", action}});
        } else {
            step.rule = static_cast<std::uint64_t>(rule - functions.begin());
        }
        if (d.to || d.by || !d.with.empty()) {
            error(d.span, "check.test-keeper", {{"text", written(d.span)}});
        }
    } else if (!step.creation && !step.approve && declared == nullptr) {
        if (is(word, "act.issue") || is(word, "act.create")) {
            error(d.action.span, "check.test-creation",
                  {{"text", written(d.action.span)}, {"action", creation}});
        } else {
            error(d.action.span, "check.test-action", {{"action", action}});
        }
    }
    if (step.creation && !first) {
        error(d.action.span, "check.test-again", {{"action", creation}});
    } else if (!step.creation && first) {
        error(d.span, "check.test-start", {{"action", creation}});
    }

    // Who acts: at creation, the home; `we`, if the contract has it. The
    // keeper is the home's device.
    if (step.keeper) {
        step.subject.span = d.subject->span;
        step.subject.word = d.subject->concept_entry;
    } else if (d.subject) {
        if (std::optional<m::TestParty> p = test_party(*d.subject)) {
            step.subject = std::move(*p);
            const Decl* we = global("role.we");
            if (step.creation && we != nullptr && we->refers == Refers::party &&
                !is(step.subject.word, "role.we")) {
                error(d.subject->span, "check.test-home", {{"party", std::string("role.we")}});
            }
        }
    }

    // The counterparty: a role bound at creation is that role's ledger; one
    // each call names (R21) must be given.
    if (!d.to && declared != nullptr && declared->to && declared->to->refers == Refers::input) {
        error(d.action.span, "check.test-needs-to", {{"action", action}});
    }
    if (d.to && (step.creation || step.approve || declared != nullptr)) {
        const m::Expr* role = declared != nullptr && declared->to ? &*declared->to : nullptr;
        if (role == nullptr) {
            error(d.to->span, "check.test-to", {{"action", step.creation ? creation : action}});
        } else if (std::optional<m::TestParty> p = test_party(*d.to)) {
            const std::string key = m::key(role->concept_entry, role->name);
            const Decl* bound = global(key);
            if (bound != nullptr && bound->refers == Refers::party &&
                model_.parties[bound->index].binding == m::Binding::creation &&
                m::key(p->word, p->name) != key) {
                error(d.to->span, "check.test-counterparty", {{"action", action}, {"party", key}});
            }
            step.to = std::move(*p);
        }
    }

    // Who signs: by AI agent, or in person; and when.
    if (d.by && !step.keeper) {
        if (word_is(*d.by, "actor.ai_agent")) {
            step.agent = true;
        } else {
            error(d.by->span, "check.test-signer", {{"text", written(d.by->span)}});
        }
    }
    for (const ast::Expr& a : d.args) {
        if (a.kind == ExprKind::apply && is(a.concept_entry, "time.at") && !step.at) {
            const ast::Expr* date = a.operands.empty() ? nullptr : &a.operands[0];
            // A ledger's times start at 1970-01-01T00:00Z.
            const std::optional<std::int64_t> when =
                date != nullptr && date->kind == ExprKind::literal &&
                        date->literal.kind == ast::LiteralKind::date
                    ? literal_value(date->literal, model_.utc_offset_ms)
                    : std::nullopt;
            if (!when || *when < 0) {
                error(a.span, "check.test-time", {{"text", written(a.span)}});
                continue;
            }
            step.at = value(*date);
            if (clock && *when < *clock) {
                error(a.span, "check.test-time-back", {{"text", written(a.span)}});
            } else {
                clock = when;
            }
        } else if (word_is(a, "cond.in_person") && !step.in_person && !step.keeper) {
            step.in_person = true;
        } else if ((a.kind == ExprKind::name || word_in(a, Category::role)) && !step.part &&
                   !step.creation) {
            // The instance the step acts on, by the party holding it.
            const Decl* holder = global("field.holder");
            if (holder == nullptr || holder->refers != Refers::field ||
                model_.fields[holder->index].type.kind != TypeKind::party) {
                error(a.span, "check.test-part", {{"text", written(a.span)}});
            } else if (std::optional<m::TestParty> p = test_party(a)) {
                step.part = std::move(*p);
            }
        } else if (step.keeper) {
            error(d.span, "check.test-keeper", {{"text", written(d.span)}});
        } else {
            error(a.span, "check.test-step", {{"text", written(a.span)}});
        }
    }
    if (step.in_person && step.agent) {
        error(d.span, "check.test-signer", {{"text", written(d.span)}});
    }
    if (!step.keeper) {
        test_with(d, step, declared, step.creation ? creation : action);
    }
    return step;
}

void Checker::test_with(const ast::Do& d, m::Step& step, const m::Action* action,
                        const std::string& action_key) {
    // What the step must give: the action's inputs, or at creation every
    // field given at creation (not a party field, which starts with its
    // role, R2).
    const bool known_action = step.creation || step.approve || action != nullptr;
    std::vector<const m::Field*> expected;
    if (step.creation) {
        for (const m::Field& f : model_.fields) {
            if (f.kind == m::FieldKind::instance && !(f.type.kind == TypeKind::party && f.value) &&
                !f.empty_at_start) {
                expected.push_back(&f);
            }
        }
    } else if (action != nullptr) {
        for (const m::Field& f : action->inputs) {
            // A counterparty each call names (R21) is the step's `to`.
            if (f.rule != rule_counterparty) {
                expected.push_back(&f);
            }
        }
    }
    std::set<std::string> given;
    for (const ast::Set& s : d.with) {
        m::Set item;
        item.span = s.span;
        item.target = plain(s.target);
        item.target.refers = step.creation ? Refers::field : Refers::input;
        const std::string target = m::key(
            s.target.kind == ExprKind::word ? s.target.concept_entry : nullptr, s.target.name);
        const m::Field* field = nullptr;
        for (const m::Field* f : expected) {
            if (m::key(f->word, f->name) == target) {
                field = f;
            }
        }
        if (known_action && field == nullptr) {
            error(s.target.span, "check.unknown-input", {{"name", target}, {"action", action_key}});
        } else if (!given.insert(target).second) {
            error(s.target.span, "check.duplicate", {{"name", target}});
        }
        const bool parties = field != nullptr && (field->type.kind == TypeKind::party ||
                                                  (field->type.kind == TypeKind::list &&
                                                   field->type.element.size() == 1 &&
                                                   field->type.element[0].kind == TypeKind::party));
        if (parties) {
            // Parties (a split's recipients): the test's ledgers, by name.
            item.target.type = field->type;
            item.value = test_parties(s.value, field->type);
        } else if (!test_value(s.value)) {
            error(s.value.span, "check.test-value", {{"text", written(s.value.span)}});
            item.value = plain(s.value);
        } else {
            item.value = value(s.value);
            if (field != nullptr) {
                item.target.type = field->type;
                expect(item.value, field->type);
                // A test's value is no clause of the contract: R29 says what
                // it is, but the contract text never states it.
                if (item.value.rule == rule_one_item) {
                    item.value.rule = {};
                }
            }
        }
        step.with.push_back(std::move(item));
    }
    if (!known_action) {
        return;
    }
    for (const m::Field* f : expected) {
        const std::string name = m::key(f->word, f->name);
        // A field with a default may be left out at creation.
        if (!given.contains(name) && !f->initial) {
            error(d.action.span, "check.test-missing", {{"action", action_key}, {"name", name}});
        }
    }
}

void Checker::test_expect(const ast::Expect& e, m::Step& step) {
    step.expect_span = e.span;
    if (!e.outcome) {
        // Values of fields only: the call is accepted.
        step.expect = m::Expectation::accepted;
        test_fields(e, step);
        return;
    }
    test_outcome(e, step);
    if (!e.fields.empty() && step.expect != m::Expectation::accepted &&
        step.expect != m::Expectation::state) {
        error(e.fields.front().span, "check.test-fields", {{"text", written(e.span)}});
        return;
    }
    test_fields(e, step);
}

void Checker::test_fields(const ast::Expect& e, m::Step& step) {
    // `fee = HKD 4_000`: an instance field, and its value after the call.
    std::set<std::string> seen;
    for (const ast::Set& s : e.fields) {
        const std::string key = m::key(
            s.target.kind == ExprKind::word ? s.target.concept_entry : nullptr, s.target.name);
        const Decl* d = global(key);
        if (d == nullptr || d->refers != Refers::field ||
            model_.fields[d->index].kind != m::FieldKind::instance) {
            error(s.target.span, "check.test-field", {{"name", key}});
            continue;
        }
        if (!seen.insert(key).second) {
            error(s.target.span, "check.duplicate", {{"name", key}});
            continue;
        }
        const m::Field& field = model_.fields[d->index];
        m::Set item;
        item.span = s.span;
        item.target = plain(s.target);
        item.target.refers = Refers::field;
        item.target.type = field.type;
        const bool parties = field.type.kind == TypeKind::party ||
                             (field.type.kind == TypeKind::list && field.type.element.size() == 1 &&
                              field.type.element[0].kind == TypeKind::party);
        if (field.type.kind == TypeKind::party && word_is(s.value, "val.none")) {
            // A party field that holds no party.
            item.value = plain(s.value);
            item.value.type = field.type;
        } else if (parties) {
            item.value = test_parties(s.value, field.type);
        } else if (!test_value(s.value)) {
            error(s.value.span, "check.test-value", {{"text", written(s.value.span)}});
            continue;
        } else {
            item.value = value(s.value);
            expect(item.value, field.type);
            // A test's value is no clause of the contract (R29, as in with).
            if (item.value.rule == rule_one_item) {
                item.value.rule = {};
            }
        }
        step.fields.push_back(std::move(item));
    }
}

void Checker::test_outcome(const ast::Expect& e, m::Step& step) {
    const ast::Expr& o = *e.outcome;
    if (word_is(o, "val.refused")) {
        step.expect = m::Expectation::refused;
        step.reason = e.reason;
        return;
    }
    if (e.reason) {
        error(e.span, "check.test-reason", {{"text", written(e.span)}});
    }
    if (word_is(o, "val.pending_approval")) {
        // An AI agent's call to an action it may only propose.
        const m::Action* proposed = nullptr;
        for (const m::Action& a : model_.actions) {
            if (m::key(a.word, a.name) == m::key(step.word, step.name)) {
                proposed = &a;
            }
        }
        step.expect = m::Expectation::proposed;
        if (proposed == nullptr || !proposed->agents_propose || !step.agent) {
            error(e.span, "check.test-proposal", {{"action", m::key(step.word, step.name)}});
        }
        return;
    }
    if (word_in(o, Category::state)) {
        // Only a state of the contract: one an instance can reach.
        const Decl* d = global(o.concept_entry->id);
        if (d != nullptr && d->refers == Refers::state) {
            step.expect = m::Expectation::state;
            step.state_word = o.concept_entry;
            return;
        }
    } else if (o.kind == ExprKind::name) {
        if (const Decl* d = global(o.name); d != nullptr && d->refers == Refers::state) {
            step.expect = m::Expectation::state;
            step.state_name = o.name;
            return;
        }
    } else if (o.kind == ExprKind::apply && is(o.concept_entry, "cond.consent_of") &&
               !o.operands.empty()) {
        step.expect = m::Expectation::waits;
        const ast::Expr& who = o.operands[0];
        const std::vector<ast::Expr> one{who};
        for (const ast::Expr& p : who.kind == ExprKind::list ? who.operands : one) {
            if (std::optional<m::TestParty> party = test_party(p)) {
                step.waits.push_back(std::move(*party));
            }
        }
        return;
    }
    error(o.span, "check.test-expect", {{"text", written(o.span)}});
}

// --- Expressions.

m::Expr Checker::plain(const ast::Expr& e) const {
    m::Expr out;
    out.kind = e.kind;
    out.span = e.span;
    out.literal = e.literal;
    out.name = e.name;
    out.concept_entry = e.concept_entry;
    out.op = e.op;
    for (const ast::Expr& o : e.operands) {
        out.operands.push_back(plain(o));
    }
    return out;
}

m::Expr Checker::as_text(const ast::Expr& e) const {
    // R18: a name compared with a text is that text.
    m::Expr out;
    out.kind = ExprKind::literal;
    out.span = e.span;
    out.literal.kind = ast::LiteralKind::text;
    out.literal.text = e.name;
    out.type = of(TypeKind::text);
    out.rule = rule_bare_text;
    return out;
}

bool Checker::undeclared_name(const ast::Expr& e) const {
    return e.kind == ExprKind::name && !declared(e.name);
}

void Checker::not_a_value(const ast::Expr& e, m::Expr& out) {
    error(e.span, "check.not-a-value", {{"text", written(e.span)}});
    out.type = of(TypeKind::unknown);
}

m::Expr Checker::condition(const ast::Expr& e) {
    m::Expr out = value(e);
    if (out.type.kind == TypeKind::state) {
        // R7: a state as a condition: the instance is in that state.
        out.type = of(TypeKind::yes_no);
        out.rule = rule_state_condition;
    } else if (known(out.type) && out.type.kind != TypeKind::yes_no) {
        error(e.span, "check.type",
              {{"text", written(e.span)},
               {"type", encode(out.type)},
               {"expected_type", encode(of(TypeKind::yes_no))}});
        out.type = of(TypeKind::unknown);
    }
    return out;
}

void Checker::expect_kind(m::Expr& e, const TypeKind kind) {
    if (known(e.type) && e.type.kind != kind) {
        error(e.span, "check.type",
              {{"text", written(e.span)},
               {"type", encode(e.type)},
               {"expected_type", encode(of(kind))}});
        e.type = of(TypeKind::unknown);
    }
}

void Checker::expect(m::Expr& e, const Type& want) {
    if (!known(e.type) || !known(want)) {
        return;
    }
    if (want.kind == TypeKind::list && e.type.kind != TypeKind::list && want.element.size() == 1 &&
        same(e.type, want.element[0])) {
        // R29: one value where a list is needed is a list of that one item.
        m::Expr list;
        list.kind = ExprKind::list;
        list.span = e.span;
        list.type = list_of(e.type, 1);
        list.rule = rule_one_item;
        list.operands.push_back(std::move(e));
        e = std::move(list);
        return;
    }
    if (want.kind == TypeKind::list && e.type.kind == TypeKind::list && !e.type.element.empty() &&
        same(want.element[0], e.type.element[0])) {
        if (e.type.bound > want.bound) {
            error(e.span, "check.list-bound",
                  {{"text", written(e.span)}, {"limit", std::to_string(want.bound)}});
        }
        return;
    }
    if (same(e.type, want)) {
        return;
    }
    if (e.type.kind == TypeKind::duration && want.kind == TypeKind::duration) {
        error(e.span, "check.calendar", {{"text", written(e.span)}});
        return;
    }
    if (e.type.kind == TypeKind::money && want.kind == TypeKind::money) {
        error(e.span, "check.mixed-currencies",
              {{"left_type", encode(e.type)}, {"right_type", encode(want)}});
    } else if (e.type.kind == TypeKind::quantity && want.kind == TypeKind::quantity) {
        error(e.span, "check.mixed-units",
              {{"left_type", encode(e.type)}, {"right_type", encode(want)}});
    } else {
        error(
            e.span, "check.type",
            {{"text", written(e.span)}, {"type", encode(e.type)}, {"expected_type", encode(want)}});
    }
}

Type Checker::literal_type(const ast::Expr& e) {
    const ast::Literal& l = e.literal;
    const auto check = [&](const Exact& x, std::string_view not_whole) {
        if (!x.whole) {
            error(e.span, not_whole, {{"text", written(e.span)}});
            return false;
        }
        if (!x.fits) {
            error(e.span, "check.overflow", {{"text", written(e.span)}});
            return false;
        }
        return true;
    };
    switch (l.kind) {
    case ast::LiteralKind::number:
        return check(exact(l.number, 1), "check.whole-number") ? of(TypeKind::number)
                                                               : of(TypeKind::unknown);
    case ast::LiteralKind::money:
        return check(exact(l.number, money_factor), "check.precision") ? money(l.unit)
                                                                       : of(TypeKind::unknown);
    case ast::LiteralKind::quantity: {
        const UnitInfo* unit = unit_info(l.unit);
        if (unit == nullptr) {
            return of(TypeKind::unknown);
        }
        return check(exact(l.number, unit->factor), "check.precision")
                   ? quantity(unit->dimension, l.unit)
                   : of(TypeKind::unknown);
    }
    case ast::LiteralKind::duration: {
        const bool calendar = is(l.unit, "time.month") || is(l.unit, "time.year");
        const Exact count = exact(l.number, 1);
        if (!check(count, "check.whole-number")) {
            return of(TypeKind::unknown);
        }
        const std::uint64_t factor = is(l.unit, "time.week")   ? 7 * day_ms
                                     : is(l.unit, "time.day")  ? day_ms
                                     : is(l.unit, "time.year") ? 12
                                                               : 1;
        const Exact scaled = exact(l.number, factor);
        if (!scaled.fits || (calendar && scaled.value > max_months)) {
            error(e.span, "check.overflow", {{"text", written(e.span)}});
            return of(TypeKind::unknown);
        }
        return duration(calendar);
    }
    case ast::LiteralKind::rate:
        return check(exact(l.number, rate_factor), "check.precision") ? of(TypeKind::rate)
                                                                      : of(TypeKind::unknown);
    case ast::LiteralKind::date:
        return of(TypeKind::date);
    case ast::LiteralKind::text:
        return of(TypeKind::text);
    }
    return of(TypeKind::unknown);
}

m::Expr Checker::value(const ast::Expr& e) {
    m::Expr out;
    out.kind = e.kind;
    out.span = e.span;
    out.literal = e.literal;
    out.name = e.name;
    out.concept_entry = e.concept_entry;
    out.op = e.op;
    switch (e.kind) {
    case ExprKind::literal:
        out.type = literal_type(e);
        break;
    case ExprKind::name:
        name_value(e, out);
        break;
    case ExprKind::word:
        word_value(e, out);
        break;
    case ExprKind::apply:
        apply_value(e, out);
        break;
    case ExprKind::phrase:
        phrase_value(e, out);
        break;
    case ExprKind::list:
        list_value(e, out, false);
        break;
    case ExprKind::unary:
        if (!e.operands.empty()) {
            out.operands.push_back(condition(e.operands[0]));
        }
        out.type = of(TypeKind::yes_no);
        break;
    case ExprKind::binary:
        binary_value(e, out);
        break;
    }
    return out;
}

void Checker::name_value(const ast::Expr& e, m::Expr& out) {
    if (const Local* l = local(e.name)) {
        out.refers = l->refers;
        out.type = l->type;
        return;
    }
    const Decl* d = global(e.name);
    if (d == nullptr) {
        error(e.span, "check.unknown-name", {{"name", e.name}});
        return;
    }
    out.refers = d->refers;
    switch (d->refers) {
    case Refers::party:
        out.type = of(TypeKind::party);
        break;
    case Refers::field:
        out.type = model_.fields[d->index].type;
        break;
    case Refers::state:
        out.type = of(TypeKind::state);
        break;
    case Refers::charge:
        // R26: the charge's amount on the instance's bill.
        if (const m::Field* bill = m::bill_field(model_);
            bill != nullptr && known(bill->type) && in_call()) {
            out.type = bill->type.element[0];
            out.rule = rule_bill;
        } else {
            out.refers = Refers::none;
            not_a_value(e, out);
        }
        break;
    case Refers::action:
    case Refers::none:
    case Refers::input:
    case Refers::item:
        out.refers = Refers::none;
        not_a_value(e, out);
        break;
    }
}

void Checker::needs_due(const ast::Expr& e) {
    if (model_.due == m::DueKind::none) {
        error(e.span, "check.needs-due", {{"text", written(e.span)}});
    }
}

void Checker::word_value(const ast::Expr& e, m::Expr& out) {
    const Concept* c = e.concept_entry;
    if (c == nullptr) {
        not_a_value(e, out);
        return;
    }
    const std::string id(c->id);
    switch (c->category) {
    case Category::role:
        out.type = of(TypeKind::party);
        if (const Local* l = local(id)) {
            // R21: a counterparty each call names, as an input.
            out.refers = l->refers;
            out.type = l->type;
            return;
        }
        if (const Decl* d = global(id); d != nullptr && d->refers == Refers::party) {
            out.refers = Refers::party;
        } else if (parties_ != nullptr) {
            error(e.span, "check.unknown-party", {{"party", id}});
            out.type = of(TypeKind::unknown);
        } else {
            out.type = of(TypeKind::unknown);
        }
        return;
    case Category::field:
    case Category::pricing:
        if (const Local* l = local(id)) {
            out.refers = l->refers;
            out.type = l->type;
            return;
        }
        if (const Decl* d = global(id); d != nullptr && d->refers == Refers::field) {
            out.refers = Refers::field;
            out.type = model_.fields[d->index].type;
            return;
        }
        if (id == "field.customer_location") {
            // R12: text each instance holds, given at creation.
            m::Field location;
            location.span = e.span;
            location.word = c;
            location.type = of(TypeKind::text);
            location.rule = rule_customer_location;
            globals_.emplace(id, Decl{Refers::field, model_.fields.size()});
            model_.fields.push_back(std::move(location));
            out.refers = Refers::field;
            out.type = of(TypeKind::text);
            return;
        }
        if (c->category == Category::field) {
            error(e.span, "check.unknown-field", {{"field", id}});
            return;
        }
        not_a_value(e, out);
        return;
    case Category::document:
        // The field that holds the bill (R26).
        if (const Decl* d = global(id); d != nullptr && d->refers == Refers::field) {
            out.refers = Refers::field;
            out.type = model_.fields[d->index].type;
            return;
        }
        break;
    case Category::state:
        out.refers = Refers::state;
        out.type = of(TypeKind::state);
        // A state the terms name but no instance reaches is never the
        // instance's: not a problem of the contract's.
        if (!in_terms_ && global(id) == nullptr && !state_mentions_.contains(id)) {
            state_mentions_.emplace(id, e.span);
        }
        return;
    case Category::value:
        if (id == "val.yes" || id == "val.no") {
            out.type = of(TypeKind::yes_no);
            return;
        }
        break;
    case Category::time:
        if (id == "time.now" || id == "time.today") {
            out.type = of(TypeKind::date);
            return;
        }
        break;
    case Category::expression:
        // An answer's result and reason (E8): texts, in its rule only.
        if ((id == "expr.result" || id == "expr.reason") && place_ == Place::answer) {
            out.type = of(TypeKind::text);
            return;
        }
        break;
    case Category::condition:
        if (id == "cond.in_person") {
            if (place_ == Place::action) {
                out.type = of(TypeKind::yes_no);
                out.rule = rule_presence;
                return;
            }
            if (place_ == Place::rule || place_ == Place::event || place_ == Place::answer) {
                error(e.span, "check.when-person", {{"text", written(e.span)}});
                return;
            }
        } else if (id == "cond.overdue" && in_call()) {
            needs_due(e);
            out.type = of(TypeKind::yes_no);
            return;
        }
        break;
    default:
        break;
    }
    not_a_value(e, out);
}

void Checker::threshold(const ast::Expr& e, m::Expr& out) {
    // R6: over N compares the action's one amount; a bare N takes its unit.
    const ast::Expr& operand = e.operands[0];
    const std::string action = action_key_;
    const bool bare =
        operand.kind == ExprKind::literal && operand.literal.kind == ast::LiteralKind::number;
    out.type = of(TypeKind::yes_no);
    if (bare && amounts_ == 1 && (amount_.currency != nullptr || amount_.unit != nullptr)) {
        m::Expr n = plain(operand);
        n.literal.unit = amount_.kind == TypeKind::money ? amount_.currency : amount_.unit;
        n.literal.kind =
            amount_.kind == TypeKind::money ? ast::LiteralKind::money : ast::LiteralKind::quantity;
        ast::Expr typed = operand;
        typed.literal = n.literal;
        n.type = literal_type(typed);
        n.rule = rule_threshold;
        out.operands.push_back(std::move(n));
        return;
    }
    m::Expr n = value(operand);
    if (amounts_ == 1 && !bare) {
        expect(n, amount_);
        out.operands.push_back(std::move(n));
        return;
    }
    const bool standard = action_ != nullptr && action_->word != nullptr && !action_->terms;
    if (!bare && standard && amounts_ == 0 &&
        (n.type.kind == TypeKind::money || n.type.kind == TypeKind::quantity || !known(n.type))) {
        // The amount of a vocabulary action without standard terms yet comes
        // with its terms, which must agree.
        out.rule = rule_threshold;
        out.operands.push_back(std::move(n));
        return;
    }
    out.operands.push_back(std::move(n));
    error(e.span, "check.threshold-amount", {{"text", written(e.span)}, {"action", action}});
}

void Checker::apply_value(const ast::Expr& e, m::Expr& out) {
    if (e.concept_entry == nullptr || e.operands.empty()) {
        not_a_value(e, out);
        return;
    }
    const std::string id(e.concept_entry->id);
    const ast::Expr& operand = e.operands[0];
    if (id == "cond.over") {
        if (place_ != Place::action) {
            not_a_value(e, out);
            return;
        }
        threshold(e, out);
        return;
    }
    if (id == "cond.consent_of" && (place_ == Place::action || place_ == Place::rule)) {
        out.operands.push_back(value(operand));
        // A party, or a list of parties (a split's recipients): each consents.
        const Type& who = out.operands.back().type;
        if (who.kind != TypeKind::list || who.element.size() != 1 ||
            who.element[0].kind != TypeKind::party) {
            expect_kind(out.operands.back(), TypeKind::party);
        }
        out.type = of(TypeKind::yes_no);
        return;
    }
    if ((id == "cond.before_due" || id == "cond.within") && in_call()) {
        if (id == "cond.before_due") {
            needs_due(e);
        }
        out.operands.push_back(value(operand));
        expect_kind(out.operands.back(), TypeKind::duration);
        out.type = of(TypeKind::yes_no);
        return;
    }
    if (id == "expr.sum_of" || id == "expr.count_of") {
        out.operands.push_back(value(operand));
        const Type& list = out.operands.back().type;
        if (!known(list)) {
            return;
        }
        if (list.kind != TypeKind::list || list.element.empty()) {
            error(operand.span, "check.type",
                  {{"text", written(operand.span)},
                   {"type", encode(list)},
                   {"expected_type", encode(of(TypeKind::list))}});
            return;
        }
        if (id == "expr.count_of") {
            out.type = of(TypeKind::number);
        } else if (additive(list.element[0].kind)) {
            out.type = list.element[0];
        } else {
            error(operand.span, "check.operands",
                  {{"operator", "+"},
                   {"left_type", encode(list.element[0])},
                   {"right_type", encode(list.element[0])}});
        }
        return;
    }
    not_a_value(e, out);
}

void Checker::phrase_value(const ast::Expr& e, m::Expr& out) {
    const std::vector<ast::Expr>& ops = e.operands;
    const auto phrase_error = [&] {
        error(e.span, "check.phrase", {{"text", written(e.span)}});
        out.type = of(TypeKind::unknown);
    };
    if (ops.size() < 2) {
        phrase_error();
        return;
    }
    const ast::Expr& head = ops[0];
    // monthly HKD 120, monthly 2TB: a recurring amount.
    if (word_is(head, "time.daily") || word_is(head, "time.weekly") ||
        word_is(head, "time.monthly") || word_is(head, "time.yearly")) {
        if (ops.size() != 2) {
            phrase_error();
            return;
        }
        out.operands.push_back(plain(head));
        out.operands.push_back(value(ops[1]));
        const Type& inner = out.operands.back().type;
        if (!known(inner)) {
            return;
        }
        if (inner.kind != TypeKind::money && inner.kind != TypeKind::quantity) {
            phrase_error();
            return;
        }
        out.type = recurring(head.concept_entry, inner);
        return;
    }
    // per GB HKD 0.10: a unit price, to six decimal places (U5).
    if (word_is(head, "price.per")) {
        if (ops.size() != 3 || unit_info(ops[1].concept_entry) == nullptr ||
            ops[1].kind != ExprKind::word || ops[2].kind != ExprKind::literal ||
            ops[2].literal.kind != ast::LiteralKind::money) {
            phrase_error();
            return;
        }
        for (const ast::Expr& o : ops) {
            out.operands.push_back(plain(o));
        }
        const Exact x = exact(ops[2].literal.number, unit_price_factor);
        if (!x.whole) {
            error(ops[2].span, "check.precision", {{"text", written(ops[2].span)}});
            return;
        }
        if (!x.fits) {
            error(ops[2].span, "check.overflow", {{"text", written(ops[2].span)}});
            return;
        }
        out.operands[2].type = money(ops[2].literal.unit);
        out.type = unit_price(ops[2].literal.unit, unit_info(ops[1].concept_entry)->dimension);
        return;
    }
    // overage per GB HKD 0.10, setup fee HKD 500: a labelled price.
    if (is_label(head)) {
        out.operands.push_back(plain(head));
        ast::Expr rest;
        if (ops.size() == 2) {
            rest = ops[1];
        } else {
            rest.kind = ExprKind::phrase;
            rest.span = Span{ops[1].span.line, ops[1].span.column, ops[1].span.offset,
                             e.span.offset + e.span.length - ops[1].span.offset};
            rest.operands.assign(ops.begin() + 1, ops.end());
        }
        m::Expr inner = value(rest);
        out.type = inner.type;
        if (ops.size() == 2) {
            out.operands.push_back(std::move(inner));
        } else {
            for (m::Expr& o : inner.operands) {
                out.operands.push_back(std::move(o));
            }
        }
        return;
    }
    // overdue 3 days: overdue by at least that long.
    if (word_is(head, "cond.overdue") && in_call()) {
        if (ops.size() != 2) {
            phrase_error();
            return;
        }
        needs_due(head);
        out.operands.push_back(plain(head));
        out.operands.push_back(value(ops[1]));
        expect_kind(out.operands.back(), TypeKind::duration);
        out.type = of(TypeKind::yes_no);
        return;
    }
    // suspended 30 days: the instance has been in the state that long.
    if (in_call() && ops.size() == 2 &&
        (word_in(head, Category::state) || head.kind == ExprKind::name)) {
        if (const Decl* d = global(expr_key(head)); d != nullptr && d->refers == Refers::state) {
            m::Expr state = plain(head);
            state.refers = Refers::state;
            state.type = of(TypeKind::state);
            out.operands.push_back(std::move(state));
            out.operands.push_back(value(ops[1]));
            expect_kind(out.operands.back(), TypeKind::duration);
            out.type = of(TypeKind::yes_no);
            return;
        }
    }
    // according to customer location: what a charge depends on.
    if (word_is(head, "charge.by") && (place_ == Place::declaration || place_ == Place::charge)) {
        if (ops.size() != 2) {
            phrase_error();
            return;
        }
        out.operands.push_back(plain(head));
        if (word_in(ops[1], Category::document)) {
            out.operands.push_back(plain(ops[1]));
        } else {
            out.operands.push_back(value(ops[1]));
            const m::Expr& basis = out.operands.back();
            if (basis.refers != Refers::field) {
                if (known(basis.type)) {
                    phrase_error();
                }
                return;
            }
        }
        out.type = of(TypeKind::basis);
        return;
    }
    phrase_error();
}

void Checker::list_value(const ast::Expr& e, m::Expr& out, const bool text_items) {
    Type element = of(TypeKind::unknown);
    bool mixed = false;
    for (const ast::Expr& o : e.operands) {
        m::Expr item = text_items && undeclared_name(o) ? as_text(o) : value(o);
        if (known(item.type)) {
            if (!known(element)) {
                element = item.type;
            } else if (!same(element, item.type)) {
                mixed = true;
            }
        }
        out.operands.push_back(std::move(item));
    }
    if (mixed) {
        error(e.span, "check.list-items", {{"text", written(e.span)}});
        out.type = of(TypeKind::unknown);
        return;
    }
    if (e.operands.size() > max_list_bound) {
        error(e.span, "check.list-bound",
              {{"text", written(e.span)}, {"limit", std::to_string(max_list_bound)}});
        out.type = of(TypeKind::unknown);
        return;
    }
    out.type = known(element) ? list_of(element, static_cast<std::uint32_t>(e.operands.size()))
                              : of(TypeKind::unknown);
}

void Checker::mismatch(const ast::Expr& e, const Type& left, const Type& right) {
    if (left.kind == TypeKind::money && right.kind == TypeKind::money &&
        left.currency != right.currency) {
        error(e.span, "check.mixed-currencies",
              {{"left_type", encode(left)}, {"right_type", encode(right)}});
    } else if ((left.kind == TypeKind::quantity || left.kind == TypeKind::unit_price) &&
               (right.kind == TypeKind::quantity || right.kind == TypeKind::unit_price) &&
               left.dimension != right.dimension) {
        error(e.span, "check.mixed-units",
              {{"left_type", encode(left)}, {"right_type", encode(right)}});
    } else if (left.kind == TypeKind::duration && right.kind == TypeKind::duration &&
               left.calendar != right.calendar) {
        error(e.span, "check.calendar", {{"text", written(e.span)}});
    } else {
        const std::string op =
            e.op == Operator::member
                ? std::string("kw.in")
                : std::string(ast::operator_texts[static_cast<std::size_t>(e.op)]);
        error(e.span, "check.operands",
              {{"operator", op}, {"left_type", encode(left)}, {"right_type", encode(right)}});
    }
}

Type Checker::compare(const ast::Expr& e, const m::Expr& left, const m::Expr& right) {
    const Type& l = left.type;
    const Type& r = right.type;
    if (!known(l) || !known(r)) {
        return of(TypeKind::yes_no);
    }
    if (e.op == Operator::member) {
        if (r.kind != TypeKind::list || r.element.empty()) {
            error(e.operands[1].span, "check.type",
                  {{"text", written(e.operands[1].span)},
                   {"type", encode(r)},
                   {"expected_type", encode(of(TypeKind::list))}});
        } else if (!same(l, r.element[0])) {
            mismatch(e, l, r.element[0]);
        }
        return of(TypeKind::yes_no);
    }
    if (!same(l, r)) {
        mismatch(e, l, r);
    } else if (e.op != Operator::equals && !ordered(l.kind)) {
        mismatch(e, l, r);
    }
    return of(TypeKind::yes_no);
}

Type Checker::arithmetic(const ast::Expr& e, m::Expr& out) {
    const Type& l = out.operands[0].type;
    const Type& r = out.operands[1].type;
    if (!known(l) || !known(r)) {
        return of(TypeKind::unknown);
    }
    const auto fail = [&] {
        mismatch(e, l, r);
        return of(TypeKind::unknown);
    };
    const auto rounds = [&](Type t) {
        // R17: rounded to the smallest unit, half up.
        out.rule = rule_rounding;
        return t;
    };
    const TypeKind lk = l.kind;
    const TypeKind rk = r.kind;
    switch (e.op) {
    case Operator::plus:
    case Operator::minus:
        if (same(l, r) && additive(lk)) {
            return l;
        }
        if (lk == TypeKind::date && rk == TypeKind::duration) {
            return l;
        }
        if (e.op == Operator::plus && lk == TypeKind::duration && rk == TypeKind::date) {
            return r;
        }
        if (e.op == Operator::minus && lk == TypeKind::date && rk == TypeKind::date) {
            return duration(false);
        }
        return fail();
    case Operator::times:
        if (lk == TypeKind::number && additive(rk)) {
            return r;
        }
        if (rk == TypeKind::number && additive(lk)) {
            return l;
        }
        if (lk == TypeKind::rate &&
            (rk == TypeKind::money || rk == TypeKind::quantity || rk == TypeKind::rate)) {
            return rounds(r);
        }
        if (rk == TypeKind::rate && (lk == TypeKind::money || lk == TypeKind::quantity)) {
            return rounds(l);
        }
        if ((lk == TypeKind::unit_price && rk == TypeKind::quantity) ||
            (lk == TypeKind::quantity && rk == TypeKind::unit_price)) {
            const Type& price = lk == TypeKind::unit_price ? l : r;
            const Type& amount = lk == TypeKind::unit_price ? r : l;
            if (price.dimension != amount.dimension) {
                return fail();
            }
            return rounds(money(price.currency));
        }
        return fail();
    case Operator::divide: {
        const ast::Expr& divisor = e.operands[1];
        if (divisor.kind == ExprKind::literal && divisor.literal.number.digits == 0 &&
            divisor.literal.kind != ast::LiteralKind::date &&
            divisor.literal.kind != ast::LiteralKind::text) {
            error(e.span, "check.zero-division", {{"text", written(e.span)}});
            return of(TypeKind::unknown);
        }
        if (rk == TypeKind::number && additive(lk) && !(lk == TypeKind::duration && l.calendar)) {
            return rounds(l);
        }
        if (same(l, r) && (lk == TypeKind::money || lk == TypeKind::quantity)) {
            return rounds(of(TypeKind::rate));
        }
        if (same(l, r) && lk == TypeKind::duration) {
            // R32: how many whole times the divisor fits, the rest dropped
            // (days late: (now - due) / 1 day).
            out.rule = rule_whole_times;
            return of(TypeKind::number);
        }
        return fail();
    }
    default:
        return fail();
    }
}

void Checker::binary_value(const ast::Expr& e, m::Expr& out) {
    if (e.operands.size() != 2) {
        out.type = of(TypeKind::unknown);
        return;
    }
    const ast::Expr& a = e.operands[0];
    const ast::Expr& b = e.operands[1];
    switch (e.op) {
    case Operator::logical_and:
        if (place_ == Place::event) {
            // when due + 1 month and active: a rule's date (the time it
            // fires at) joined to conditions; trigger_of takes one date.
            for (const ast::Expr* o : {&a, &b}) {
                m::Expr v = value(*o);
                if (v.type.kind == TypeKind::state) {
                    v.type = of(TypeKind::yes_no);
                    v.rule = rule_state_condition;
                } else if (known(v.type) && v.type.kind != TypeKind::yes_no &&
                           v.type.kind != TypeKind::date) {
                    error(o->span, "check.type",
                          {{"text", written(o->span)},
                           {"type", encode(v.type)},
                           {"expected_type", encode(of(TypeKind::yes_no))}});
                    v.type = of(TypeKind::unknown);
                }
                out.operands.push_back(std::move(v));
            }
            out.type = of(TypeKind::yes_no);
            return;
        }
        [[fallthrough]];
    case Operator::logical_or:
        out.operands.push_back(condition(a));
        out.operands.push_back(condition(b));
        out.type = of(TypeKind::yes_no);
        return;
    case Operator::equals:
    case Operator::less:
    case Operator::less_equal:
    case Operator::greater:
    case Operator::greater_equal:
    case Operator::member: {
        if (e.op == Operator::equals && (word_is(a, "val.none") || word_is(b, "val.none"))) {
            // A party field that holds no party: pledgee = none; a date
            // field Bo adds that holds no date: paid until = none (R20).
            const bool left_none = word_is(a, "val.none");
            m::Expr other = value(left_none ? b : a);
            m::Expr none = plain(left_none ? a : b);
            none.type = of(TypeKind::party);
            if (other.type.kind == TypeKind::date && optional_date(other)) {
                none.type = other.type;
            } else if (known(other.type) && other.type.kind != TypeKind::party) {
                mismatch(e, left_none ? none.type : other.type, left_none ? other.type : none.type);
            }
            out.type = of(TypeKind::yes_no);
            out.operands.push_back(left_none ? std::move(none) : std::move(other));
            out.operands.push_back(left_none ? std::move(other) : std::move(none));
            return;
        }
        // R18: an undeclared name compared with a text is that text.
        m::Expr left;
        m::Expr right;
        if (e.op != Operator::member && undeclared_name(a) && !undeclared_name(b)) {
            right = value(b);
            left = right.type.kind == TypeKind::text ? as_text(a) : value(a);
        } else {
            left = value(a);
            const bool text = left.type.kind == TypeKind::text;
            if (text && e.op != Operator::member && undeclared_name(b)) {
                right = as_text(b);
            } else if (text && e.op == Operator::member && b.kind == ExprKind::list) {
                right.kind = b.kind;
                right.span = b.span;
                list_value(b, right, true);
            } else {
                right = value(b);
            }
        }
        if (e.op != Operator::member) {
            zero_of(left, right);
            zero_of(right, left);
        }
        out.type = compare(e, left, right);
        out.operands.push_back(std::move(left));
        out.operands.push_back(std::move(right));
        return;
    }
    case Operator::plus:
    case Operator::minus:
    case Operator::times:
    case Operator::divide:
        out.operands.push_back(value(a));
        out.operands.push_back(value(b));
        if (e.op == Operator::plus || e.op == Operator::minus) {
            zero_of(out.operands[0], out.operands[1]);
            zero_of(out.operands[1], out.operands[0]);
        }
        out.type = arithmetic(e, out);
        return;
    case Operator::none:
    case Operator::logical_not:
        break;
    }
    out.type = of(TypeKind::unknown);
}

// --- The passes.

m::Model Checker::run(const ast::File& file) {
    model_.edition = file.edition;
    // The vocabulary packs (D-054): each `use` names one, and each pack's
    // words need its `use` (all of them, read with the official packs of
    // before vocabulary packs).
    vocabularies_ = file.vocabularies.get();
    std::vector<std::pair<std::string, const VocabularyPack*>> used;
    for (const ast::Use& u : file.uses) {
        // A pack the set reads: an official one of its release, or a
        // user's (vocab.hpp); without the set's packs, an official one.
        const VocabularyPack* pack =
            vocabularies_ != nullptr ? vocabularies_->find(u.pack) : find_vocabulary_pack(u.pack);
        if (pack == nullptr) {
            error(u.span, "check.unknown-pack", {{"pack", detail::quote(u.pack)}});
        } else {
            used.emplace_back(u.pack, pack);
        }
    }
    std::ranges::sort(used);
    for (const auto& [id, pack] : used) {
        model_.packs.push_back(id);
        model_.vocabularies.push_back(pack);
    }
    // A pack's required packs are used too.
    for (const ast::Use& u : file.uses) {
        const auto it =
            std::ranges::find(used, u.pack, &std::pair<std::string, const VocabularyPack*>::first);
        if (it == used.end()) {
            continue;
        }
        for (const std::string& other : it->second->required) {
            if (!std::ranges::contains(model_.packs, other)) {
                error(u.span, "check.pack-requires", {{"pack", u.pack}, {"other", other}});
            }
        }
    }
    for (const ast::PackWord& w : file.pack_words) {
        const std::string_view pack = pack_of(*w.concept_entry);
        if (!file.implicit_vocabulary && !std::ranges::contains(model_.packs, pack)) {
            error(w.span, "check.pack-not-used",
                  {{"word", written(w.span)}, {"pack", std::string(pack)}});
        }
    }
    for (const ast::Clause& clause : file.clauses) {
        clauses_.push_back(&clause);
        std::visit(Overloaded{
                       [&](const ast::Contract& c) {
                           if (contract_ == nullptr) {
                               contract_ = &c;
                           }
                       },
                       [&](const ast::Parties& p) {
                           if (parties_ == nullptr) {
                               parties_ = &p;
                           }
                       },
                       [&](const ast::Block& b) {
                           if (b.kind->category != Category::kind) {
                               charges_.push_back(&b);
                           } else if (kind_ == nullptr) {
                               kind_ = &b;
                           } else {
                               error(b.name.span, "check.one-kind", {{"name", b.name.name}});
                           }
                       },
                       [&](const ast::Can& c) { cans_.push_back(&c); },
                       [&](const ast::When& w) { whens_.push_back(&w); },
                       [&](const ast::Test& t) { tests_.push_back(&t); },
                       [&](const ast::AnswerRule& r) { answers_.push_back(&r); },
                   },
                   clause);
    }
    if (contract_ != nullptr) {
        model_.name = contract_->name.name;
    } else {
        error(Span{}, "check.fragment", {});
    }
    if (parties_ == nullptr && (!cans_.empty() || !whens_.empty())) {
        error(!cans_.empty() ? cans_.front()->span : whens_.front()->span, "check.no-parties", {});
    }

    model_.offset_rule = rule_utc_offset;
    declare_parties();
    read_kind();
    add_rule_actions();
    prepare_terms();
    declare_actions();
    for (const ast::Can* c : cans_) {
        collect_states(c->body);
    }
    for (const ast::When* w : whens_) {
        collect_states(w->body);
    }
    for (const ast::AnswerRule* r : answers_) {
        collect_states(r->body);
    }
    for (const auto& [i, terms] : terms_) {
        collect_terms_states(terms.body);
    }
    choose_first_state();
    reach_terms();
    bind_roles();
    find_due();
    read_charges();
    for (std::size_t i = 0; i < cans_.size(); ++i) {
        check_can(*cans_[i], i);
    }
    for (const ast::When* w : whens_) {
        check_when(*w);
    }
    for (const ast::AnswerRule* r : answers_) {
        check_answer(*r);
    }
    add_billing_answers();
    finish_terms();
    check_states();
    check_recursion();
    check_requests();
    check_tests();
    return std::move(model_);
}

} // namespace

Checked check(std::string_view source, const ast::File& file) {
    detail::Diagnostics diagnostics;
    Checked out;
    out.model = Checker(source, diagnostics).run(file);
    out.diagnostics = diagnostics.take();
    // In source order; problems without a place last.
    std::ranges::stable_sort(out.diagnostics, {}, [](const Diagnostic& d) {
        return d.span.line == 0 ? std::numeric_limits<std::uint64_t>::max()
                                : std::uint64_t{d.span.offset};
    });
    return out;
}

} // namespace cexchain::bo
