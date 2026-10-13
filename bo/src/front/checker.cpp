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
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/values.hpp>

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
constexpr std::uint64_t max_list_bound = 1'000;

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

/// The vocabulary's fields whose type the vocabulary fixes (R1).
std::optional<Type> vocabulary_type(const Concept* word) {
    if (is(word, "field.holder") || is(word, "field.pledgee")) {
        return of(TypeKind::party);
    }
    if (is(word, "field.due")) {
        return of(TypeKind::date);
    }
    if (is(word, "field.tier")) {
        return of(TypeKind::number);
    }
    if (is(word, "field.customer_location")) {
        return of(TypeKind::text);
    }
    if (is(word, "field.cooling_period")) {
        return duration(false);
    }
    return std::nullopt;
}

/// What a vocabulary field may hold, for messages.
Type vocabulary_expected(const Concept* word) {
    if (std::optional<Type> fixed = vocabulary_type(word)) {
        return *fixed;
    }
    if (is(word, "field.quantity")) {
        return of(TypeKind::quantity);
    }
    if (is(word, "field.parts")) {
        return of(TypeKind::list);
    }
    return of(TypeKind::money);
}

bool vocabulary_accepts(const Concept* word, const Type& t) {
    if (is(word, "field.amount")) {
        return t.kind == TypeKind::money || t.kind == TypeKind::quantity;
    }
    if (is(word, "field.cooling_period")) {
        return t.kind == TypeKind::duration;
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

/// R10: the actions that ask an executor to act outside the ledger.
bool executor_action(const Concept* word, const Concept* kind) {
    if (word == nullptr) {
        return false;
    }
    if (word->id == "act.notify") {
        return true;
    }
    static constexpr std::string_view service_changes[] = {
        "act.subscribe", "act.upgrade",   "act.downgrade", "act.suspend",
        "act.resume",    "act.terminate", "act.allocate",  "act.reclaim",
    };
    return is(kind, "kind.service") && std::ranges::contains(service_changes, word->id);
}

/// Where an expression stands, which decides the words it may use.
enum class Place : std::uint8_t {
    declaration, ///< a field's value, an input's type
    charge,      ///< a line of a charge
    action,      ///< a `can` block (a call someone starts)
    rule,        ///< a `when` block (the keeper fires it)
    event,       ///< a `when`'s event
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
    // --- Problems.
    void error(const Span& span, std::string_view code, detail::Args args) {
        diagnostics_.add(span, code, args);
    }
    [[nodiscard]] std::string written(const Span& span) const {
        const std::size_t from = std::min<std::size_t>(span.offset, source_.size());
        return detail::quote(source_.substr(from, span.length));
    }

    // --- Declarations.
    bool declare(const std::string& key, Refers refers, std::size_t index, const Span& span);
    [[nodiscard]] const Decl* global(std::string_view key) const;
    [[nodiscard]] const Local* local(std::string_view key) const;
    [[nodiscard]] bool declared(std::string_view key) const;
    void declare_parties();
    void read_kind();
    std::optional<m::Field> read_field(const ast::Field& f, bool input);
    std::optional<Declared> as_type(const ast::Expr& e);
    void complete_parts(m::Field& field);
    void declare_actions();
    void collect_states(const std::vector<ast::Statement>& list);
    std::optional<std::string> state_key(const ast::Expr& e);
    void choose_first_state();
    void bind_roles();
    void mentions(const ast::Expr& e, std::vector<std::string>& out) const;
    void mentions(const std::vector<ast::Statement>& list, std::vector<std::string>& out) const;
    void find_due();
    void read_charges();
    m::ChargeLine charge_line(const ast::Field& f, bool& rate, bool& amount, int& inclusion);

    // --- Actions and rules.
    void check_can(const ast::Can& c, std::size_t index);
    void check_when(const ast::When& w);
    std::vector<m::Statement> statements(const std::vector<ast::Statement>& list);
    m::Set set_statement(const ast::Set& s);
    m::Do do_action(const ast::Do& d);
    void check_states();
    void check_recursion();
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
        return place_ == Place::action || place_ == Place::rule || place_ == Place::event;
    }

    std::string_view source_;
    detail::Diagnostics& diagnostics_;
    m::Model model_;

    // The tree's clauses, by kind.
    const ast::Contract* contract_ = nullptr;
    const ast::Parties* parties_ = nullptr;
    const ast::Block* kind_ = nullptr;
    std::vector<const ast::Block*> charges_;
    std::vector<const ast::Can*> cans_;
    std::vector<const ast::When*> whens_;
    std::vector<const ast::Clause*> clauses_;

    // Names: parties, fields, actions, and states by key; inputs and each
    // names in frames.
    std::map<std::string, Decl, std::less<>> globals_;
    std::vector<std::map<std::string, Local, std::less<>>> frames_;
    // Each action's inputs, by the action's key (read before any block, so
    // that `do X with ...` can name them); actions declared twice.
    std::map<std::string, std::vector<m::Field>, std::less<>> inputs_;
    std::set<std::size_t> duplicate_actions_;
    bool any_standard_ = false;

    // States: the state changes, as keys; vocabulary states named elsewhere.
    struct Edge {
        std::vector<std::string> from;
        std::string to;
    };
    std::vector<Edge> edges_;
    std::map<std::string, Span, std::less<>> state_mentions_;
    /// The candidates for the first state, when there are several.
    std::set<std::string> unclear_;

    // Calls between the contract's own actions.
    std::map<std::string, std::vector<std::string>, std::less<>> calls_;

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
            if (!n.whole || n.value == 0 || n.value > max_list_bound) {
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
    enum class What : std::uint8_t { own, vocabulary, pricing, charge };
    What what = What::own;
    if (head.kind == ExprKind::name) {
        out.name = head.name;
    } else if (word_in(head, Category::field)) {
        out.word = head.concept_entry;
        what = What::vocabulary;
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
    if (std::optional<Declared> declared_type = as_type(first)) {
        out.type = declared_type->type;
        out.rule = declared_type->rule;
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
        std::optional<m::Field> field = read_field(f, false);
        if (!field) {
            continue;
        }
        if (declare(m::key(field->word, field->name), Refers::field, model_.fields.size(),
                    f.head.span)) {
            model_.fields.push_back(std::move(*field));
        }
    }
}

void Checker::declare_actions() {
    place_ = Place::declaration;
    for (std::size_t i = 0; i < cans_.size(); ++i) {
        const ast::Can& c = *cans_[i];
        const Concept* word = c.action.kind == ExprKind::word ? c.action.concept_entry : nullptr;
        const std::string action = m::key(word, c.action.name);
        any_standard_ = any_standard_ || word != nullptr;
        if (!declare(action, Refers::action, i, c.action.span)) {
            duplicate_actions_.insert(i);
            continue;
        }
        std::vector<m::Field> inputs;
        std::set<std::string> seen;
        for (const ast::Field& f : c.inputs) {
            std::optional<m::Field> input = read_field(f, true);
            if (!input) {
                continue;
            }
            const std::string input_key = m::key(input->word, input->name);
            if (global(input_key) != nullptr || !seen.insert(input_key).second) {
                error(f.head.span, "check.duplicate", {{"name", input_key}});
                continue;
            }
            inputs.push_back(std::move(*input));
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

void Checker::choose_first_state() {
    // R4: the one state no state change leads to; with none, active.
    std::set<std::string> targets;
    std::set<std::string> sources;
    for (const Edge& edge : edges_) {
        targets.insert(edge.to);
        sources.insert(edge.from.begin(), edge.from.end());
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
            if (can->to) {
                std::vector<std::string> to;
                mentions(*can->to, to);
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
        }
        seen.insert(named.begin(), named.end());
    }
}

void Checker::find_due() {
    if (const Decl* due = global("field.due"); due != nullptr && due->refers == Refers::field) {
        if (model_.fields[due->index].type.kind == TypeKind::date) {
            model_.due = m::DueKind::field;
        }
        return;
    }
    if (!is(model_.kind, "kind.service")) {
        return;
    }
    for (const m::Field& f : model_.fields) {
        if (f.type.kind == TypeKind::recurring && !f.type.element.empty() &&
            f.type.element[0].kind == TypeKind::money) {
            model_.due = m::DueKind::period;
            model_.due_rule = rule_service_due;
            return;
        }
    }
}

m::ChargeLine Checker::charge_line(const ast::Field& f, bool& rate, bool& amount, int& inclusion) {
    m::ChargeLine line;
    line.span = f.span;
    const ast::Expr& head = f.head;
    const auto refuse = [&] {
        error(f.span, "check.charge-field", {{"text", written(f.span)}});
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
        line.values.push_back(std::move(v));
        rate = true;
    } else if (head.kind == ExprKind::word && is(word, "field.amount") && values == 1) {
        m::Expr v = value(f.values[0]);
        expect_kind(v, TypeKind::money);
        line.values.push_back(std::move(v));
        amount = true;
    } else if (head.kind == ExprKind::apply && is(word, "charge.applies_to") && values == 0) {
        line.argument = condition(head.operands[0]);
    } else if (head.kind == ExprKind::word &&
               (is(word, "charge.included") || is(word, "charge.added")) && values == 0) {
        ++inclusion;
    } else if (head.kind == ExprKind::word &&
               (is(word, "charge.per_line") || is(word, "charge.per_document")) &&
               (values == 0 || (values == 1 && word_in(f.values[0], Category::rounding)))) {
        if (values == 1) {
            line.values.push_back(plain(f.values[0]));
        }
    } else if (head.kind == ExprKind::word && is(word, "charge.by") && values == 1) {
        // according to invoice [half up]: per document of that kind.
        const ast::Expr& v = f.values[0];
        const bool document = word_in(v, Category::document);
        const bool with_mode = v.kind == ExprKind::phrase && v.operands.size() == 2 &&
                               word_in(v.operands[0], Category::document) &&
                               word_in(v.operands[1], Category::rounding);
        if (!document && !with_mode) {
            refuse();
        } else {
            line.values.push_back(plain(v));
        }
    } else if (head.kind == ExprKind::word && word->category == Category::rounding && values == 0) {
        // A rounding mode alone: per line.
    } else if (head.kind == ExprKind::apply && is(word, "charge.from") && values == 1) {
        // from DATE on rate 9%: a rate from that date.
        m::Expr date = value(head.operands[0]);
        expect_kind(date, TypeKind::date);
        line.argument = std::move(date);
        const ast::Expr& v = f.values[0];
        const ast::Expr* rate_value = &v;
        if (v.kind == ExprKind::phrase && v.operands.size() == 2 &&
            word_is(v.operands[0], "charge.rate")) {
            rate_value = &v.operands[1];
        }
        m::Expr r = value(*rate_value);
        expect_kind(r, TypeKind::rate);
        line.values.push_back(std::move(r));
        rate = true;
    } else {
        refuse();
    }
    return line;
}

void Checker::read_charges() {
    std::set<std::string> names;
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
        bool rate = false;
        bool amount = false;
        int inclusion = 0;
        for (const ast::Field& f : block->fields) {
            charge.lines.push_back(charge_line(f, rate, amount, inclusion));
        }
        if (!rate && !amount) {
            error(block->name.span, "check.charge-rate", {{"name", charge.name}});
        }
        if (inclusion != 1) {
            error(block->name.span, "check.charge-included", {{"name", charge.name}});
        }
        model_.charges.push_back(std::move(charge));
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
    if (c.by) {
        a.by = value(*c.by);
        expect_kind(*a.by, TypeKind::party);
    }
    if (c.to) {
        a.to = value(*c.to);
        expect_kind(*a.to, TypeKind::party);
        // R3: the role this action binds consents to being bound.
        const std::string party = m::key(a.to->concept_entry, a.to->name);
        if (const Decl* d = global(party); d != nullptr && d->refers == Refers::party &&
                                           model_.parties[d->index].bound_by == action) {
            a.consents.push_back(m::Consent{c.to->span, *a.to, rule_role_binding});
        }
    }
    if (!c.by && a.word == nullptr) {
        error(c.action.span, "check.needs-by", {{"action", action}});
    }
    a.body = statements(c.body);
    if (!a.agents_propose) {
        a.agents_rule = rule_agents;
    }
    if (executor_action(a.word, model_.kind)) {
        a.executor = true;
        a.executor_rule = rule_executor;
        error(c.action.span, "check.needs-executor", {{"action", action}});
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

/// True if an event is a time: it names due, overdue, a time before due,
/// within, now, or today, or it is a date.
bool timed(const m::Expr& e) {
    if (e.type.kind == TypeKind::date) {
        return true;
    }
    const Concept* c = e.concept_entry;
    if (is(c, "cond.overdue") || is(c, "cond.before_due") || is(c, "cond.within") ||
        is(c, "time.now") || is(c, "time.today")) {
        return true;
    }
    return std::ranges::any_of(e.operands, [](const m::Expr& o) { return timed(o); });
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
    if (known(r.event.type) && !(r.event.type.kind == TypeKind::date ||
                                 (r.event.type.kind == TypeKind::yes_no && timed(r.event)))) {
        error(w.event.span, "check.when-event", {{"text", written(w.event.span)}});
    }
    place_ = Place::rule;
    consents_ = &r.consents;
    for (const ast::Do& d : w.actions) {
        r.actions.push_back(do_action(d));
    }
    r.body = statements(w.body);
    frames_.pop_back();
    consents_ = nullptr;
    place_ = Place::declaration;
    model_.rules.push_back(std::move(r));
}

std::vector<m::Statement> Checker::statements(const std::vector<ast::Statement>& list) {
    std::vector<m::Statement> out;
    for (const ast::Statement& s : list) {
        std::visit(Overloaded{
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
                           if (node.list.type.kind == TypeKind::list &&
                               !node.list.type.element.empty()) {
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
                           node.to = value(t.to);
                           expect_kind(node.to, TypeKind::state);
                           out.push_back(m::Statement{std::move(node)});
                       },
                       [&](const ast::Do& d) { out.push_back(m::Statement{do_action(d)}); },
                       [&](const ast::Expect&) {},
                   },
                   s.node);
    }
    return out;
}

m::Set Checker::set_statement(const ast::Set& s) {
    m::Set out;
    out.span = s.span;
    out.target = value(s.target);
    out.value = value(s.value);
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
    m::Do out;
    out.span = d.span;
    out.action = plain(d.action);
    const Concept* word = d.action.kind == ExprKind::word ? d.action.concept_entry : nullptr;
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
    if (!out.obligation && executor_action(word, model_.kind)) {
        out.executor = true;
        out.rule = rule_executor;
        error(d.action.span, "check.needs-executor", {{"action", action}});
    }
    if (word == nullptr && place_ == Place::action && !action_key_.empty()) {
        calls_[action_key_].push_back(action);
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
        // A vocabulary state may be reached by a vocabulary action's
        // template (milestone 11).
        if (reached.contains(k) || unclear_.contains(k) || (s.word != nullptr && any_standard_)) {
            continue;
        }
        error(s.span, "check.unreachable-state", {{"state", k}});
    }
    if (!any_standard_) {
        for (const auto& [k, span] : state_mentions_) {
            if (global(k) == nullptr) {
                error(span, "check.unreachable-state", {{"state", k}});
            }
        }
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
    case Category::state:
        out.refers = Refers::state;
        out.type = of(TypeKind::state);
        if (global(id) == nullptr && !state_mentions_.contains(id)) {
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
    case Category::condition:
        if (id == "cond.in_person") {
            if (place_ == Place::action) {
                out.type = of(TypeKind::yes_no);
                out.rule = rule_presence;
                return;
            }
            if (place_ == Place::rule || place_ == Place::event) {
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
    const bool standard = action_ != nullptr && action_->word != nullptr;
    if (!bare && standard && amounts_ == 0 &&
        (n.type.kind == TypeKind::money || n.type.kind == TypeKind::quantity || !known(n.type))) {
        // The amount of a vocabulary action comes from its template
        // (milestone 11), which must agree.
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
        expect_kind(out.operands.back(), TypeKind::party);
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
                       [&](const ast::Test&) {},
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

    declare_parties();
    read_kind();
    declare_actions();
    for (const ast::Can* c : cans_) {
        collect_states(c->body);
    }
    for (const ast::When* w : whens_) {
        collect_states(w->body);
    }
    choose_first_state();
    bind_roles();
    find_due();
    read_charges();
    for (std::size_t i = 0; i < cans_.size(); ++i) {
        check_can(*cans_[i], i);
    }
    for (const ast::When* w : whens_) {
        check_when(*w);
    }
    check_states();
    check_recursion();
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
