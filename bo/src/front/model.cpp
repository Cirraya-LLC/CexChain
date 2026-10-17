// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The checked model as text: types in their neutral form and in words, and
// the canonical dump the checker's goldens keep.

#include <algorithm>
#include <cstddef>
#include <format>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/values.hpp>

namespace cexchain::bo {

namespace {

using model::Dimension;
using model::TypeKind;

template <class... F>
struct Overloaded : F... {
    using F::operator()...;
};

/// The sentence that describes a dimension's quantities.
std::string_view dimension_sentence(Dimension dimension) noexcept {
    switch (dimension) {
    case Dimension::data:
        return "type-data";
    case Dimension::bandwidth:
        return "type-bandwidth";
    case Dimension::count:
        return "type-count";
    case Dimension::mass:
        return "type-mass";
    case Dimension::temperature:
        return "type-temperature";
    case Dimension::none:
        break;
    }
    return "type-any-quantity";
}

/// The unit a unit price is per, in words.
std::string_view display_unit(Dimension dimension) noexcept {
    switch (dimension) {
    case Dimension::data:
        return "unit.GB";
    case Dimension::bandwidth:
        return "unit.Mbps";
    case Dimension::count:
        return "unit.item";
    case Dimension::mass:
        return "unit.kg";
    case Dimension::temperature:
        return "unit.celsius";
    case Dimension::none:
        break;
    }
    return {};
}

Dimension dimension_from(std::string_view name) noexcept {
    for (std::size_t i = 1; i < model::dimension_names.size(); ++i) {
        if (model::dimension_names[i] == name) {
            return static_cast<Dimension>(i);
        }
    }
    return Dimension::none;
}

/// Reads one encoded type from `tokens`, from `at`, in words.
std::string describe_tokens(const std::vector<std::string_view>& tokens, std::size_t& at,
                            const Pack* language, std::size_t depth) {
    if (at >= tokens.size() || depth > 16) {
        return sentence("type-unknown", {}, language);
    }
    const std::string_view head = tokens[at++];
    const auto next = [&]() -> std::string_view {
        return at < tokens.size() ? tokens[at] : std::string_view{};
    };
    using V = std::pair<std::string_view, std::string>;
    if (head == "money") {
        if (next().starts_with("cur.")) {
            const V values[] = {{"currency", spell(tokens[at++], language)}};
            return sentence("type-money", values, language);
        }
        return sentence("type-any-money", {}, language);
    }
    if (head == "quantity") {
        const Dimension d = dimension_from(next());
        if (d != Dimension::none) {
            ++at;
        }
        return sentence(dimension_sentence(d), {}, language);
    }
    if (head == "duration") {
        if (next() == "calendar") {
            ++at;
        }
        return sentence("type-duration", {}, language);
    }
    if (head == "list") {
        const std::string_view bound = next();
        if (!bound.empty() && bound.find_first_not_of("0123456789") == std::string_view::npos) {
            ++at;
            const std::string element = describe_tokens(tokens, at, language, depth + 1);
            const V values[] = {{"element", element}, {"limit", std::string(bound)}};
            return sentence("type-list", values, language);
        }
        return sentence("type-any-list", {}, language);
    }
    if (head == "unit_price") {
        std::string currency = std::string(hole);
        if (next().starts_with("cur.")) {
            currency = spell(tokens[at++], language);
        }
        std::string unit = std::string(hole);
        if (const Dimension d = dimension_from(next()); d != Dimension::none) {
            ++at;
            unit = spell(display_unit(d), language);
        }
        const V values[] = {{"currency", currency}, {"unit", unit}};
        return sentence("type-unit-price", values, language);
    }
    if (head == "recurring") {
        std::string period = std::string(hole);
        if (next().starts_with("time.")) {
            period = spell(tokens[at++], language);
        }
        const std::string value = describe_tokens(tokens, at, language, depth + 1);
        const V values[] = {{"value", value}, {"period", period}};
        return sentence("type-recurring", values, language);
    }
    static constexpr std::pair<std::string_view, std::string_view> simple[] = {
        {"?", "type-unknown"},   {"number", "type-number"}, {"rate", "type-rate"},
        {"date", "type-date"},   {"text", "type-text"},     {"yes_no", "type-yes-no"},
        {"party", "type-party"}, {"state", "type-state"},   {"basis", "type-basis"},
    };
    for (const auto& [token, id] : simple) {
        if (head == token) {
            return sentence(id, {}, language);
        }
    }
    return std::string(head);
}

// --- The dump.

void add_line(std::string& out, std::size_t depth, std::string_view text) {
    out.append(2 * depth, ' ');
    out += text;
    out += '\n';
}

std::string ruled(std::string text, std::string_view rule) {
    if (!rule.empty()) {
        text += "{" + std::string(rule) + "}";
    }
    return text;
}

std::string literal_text(const ast::Literal& l) {
    switch (l.kind) {
    case ast::LiteralKind::number:
        return to_string(l.number);
    case ast::LiteralKind::money:
        return "(money " + std::string(l.unit->id) + " " + to_string(l.number) + ")";
    case ast::LiteralKind::quantity:
        return "(quantity " + std::string(l.unit->id) + " " + to_string(l.number) + ")";
    case ast::LiteralKind::duration:
        return "(duration " + std::string(l.unit->id) + " " + to_string(l.number) + ")";
    case ast::LiteralKind::rate:
        return to_string(l.number) + "%";
    case ast::LiteralKind::date:
        return std::format("{:04}-{:02}-{:02}", l.date.year, l.date.month, l.date.day);
    case ast::LiteralKind::text:
        return "\"" + l.text + "\"";
    }
    return {};
}

std::string text(const model::Expr& e) {
    std::string out;
    switch (e.kind) {
    case ast::ExprKind::literal:
        out = literal_text(e.literal);
        break;
    case ast::ExprKind::name:
        out = e.name;
        break;
    case ast::ExprKind::word:
        out = std::string(e.concept_entry->id);
        break;
    case ast::ExprKind::apply:
    case ast::ExprKind::phrase:
    case ast::ExprKind::list:
    case ast::ExprKind::unary:
    case ast::ExprKind::binary:
        out = "(";
        if (e.kind == ast::ExprKind::apply) {
            out += e.concept_entry->id;
        } else if (e.kind == ast::ExprKind::phrase) {
            out += "phrase";
        } else if (e.kind == ast::ExprKind::list) {
            out += "list";
        } else {
            out += ast::operator_texts[static_cast<std::size_t>(e.op)];
        }
        for (const model::Expr& o : e.operands) {
            out += " " + text(o);
        }
        out += ")";
        break;
    }
    return ruled(std::move(out), e.rule);
}

void statements(std::string& out, const std::vector<model::Statement>& list, std::size_t depth);

void set_line(std::string& out, const model::Set& s, std::size_t depth) {
    add_line(out, depth, "set " + text(s.target) + " " + text(s.value));
}

void do_lines(std::string& out, const model::Do& d, std::size_t depth) {
    std::string line = "do";
    if (d.subject) {
        line += " subject=" + text(*d.subject);
    }
    line += " " + text(d.action);
    for (const model::Expr& arg : d.args) {
        line += " " + text(arg);
    }
    if (d.to) {
        line += " to=" + text(*d.to);
    }
    if (d.by) {
        line += " by=" + text(*d.by);
    }
    if (d.obligation) {
        line += " " + ruled("obligation", d.rule);
    }
    if (d.executor) {
        line += " " + ruled("executor", d.rule);
    }
    if (d.parts) {
        line += " " + ruled("parts", d.rule);
    }
    add_line(out, depth, line);
    for (const model::Set& s : d.with) {
        set_line(out, s, depth + 1);
    }
}

void statements(std::string& out, const std::vector<model::Statement>& list, std::size_t depth) {
    for (const model::Statement& statement : list) {
        std::visit(Overloaded{
                       [&](const model::Requires& r) {
                           std::string line = "requires " + text(r.condition);
                           if (r.guard) {
                               line += " guard=" + text(*r.guard);
                           }
                           add_line(out, depth, line);
                       },
                       [&](const model::If& i) {
                           add_line(out, depth, "if " + text(i.condition));
                           statements(out, i.then, depth + 1);
                           if (!i.otherwise.empty()) {
                               add_line(out, depth, "otherwise");
                               statements(out, i.otherwise, depth + 1);
                           }
                       },
                       [&](const model::Each& e) {
                           add_line(out, depth, "each " + e.name + " in=" + text(e.list));
                           statements(out, e.body, depth + 1);
                       },
                       [&](const model::Reject& r) {
                           add_line(out, depth, "reject \"" + r.message + "\"");
                       },
                       [&](const model::Set& s) { set_line(out, s, depth); },
                       [&](const model::Transition& t) {
                           std::string line = "transition";
                           for (const model::Expr& from : t.from) {
                               line += " " + text(from);
                           }
                           add_line(out, depth, line + " -> " + text(t.to));
                       },
                       [&](const model::Do& d) { do_lines(out, d, depth); },
                   },
                   statement.node);
    }
}

void field_line(std::string& out, std::string_view label, const model::Field& f,
                std::size_t depth) {
    std::string line = std::string(label) + " " + model::key(f.word, f.name) + " " +
                       std::string(model::field_kind_names[static_cast<std::size_t>(f.kind)]) +
                       " " + encode(f.type);
    if (f.value) {
        line += " = " + text(*f.value);
    }
    if (f.initial) {
        line += " default " + text(*f.initial);
    }
    if (f.optional) {
        line += " optional";
    }
    if (f.empty_at_start) {
        line += " empty";
    }
    add_line(out, depth, ruled(std::move(line), f.rule));
    for (const model::Expr& more : f.more) {
        add_line(out, depth + 1, "more " + text(more) + " : " + encode(more.type));
    }
}

void consent_lines(std::string& out, const std::vector<model::Consent>& consents,
                   std::size_t depth) {
    for (const model::Consent& c : consents) {
        add_line(out, depth, ruled("consent " + text(c.party), c.rule));
    }
}

std::string party_text(const model::TestParty& p) {
    if (p.word != nullptr) {
        return std::string(p.word->id);
    }
    return p.role ? p.name : "ledger:" + p.name;
}

void test_lines(std::string& out, const model::Test& t) {
    add_line(out, 0, t.name.empty() ? std::string("test") : "test \"" + t.name + "\"");
    for (const model::Step& s : t.steps) {
        std::string line = "step " + party_text(s.subject) + " " + model::key(s.word, s.name);
        if (s.creation) {
            line += " creation";
        }
        if (s.keeper) {
            line += std::format(" rule={}", s.rule + 1);
        }
        if (s.to) {
            line += " to=" + party_text(*s.to);
        }
        if (s.part) {
            line += " part=" + party_text(*s.part);
        }
        if (s.at) {
            line += " at=" + text(*s.at);
        }
        if (s.in_person) {
            line += " in_person";
        }
        if (s.agent) {
            line += " agent";
        }
        line +=
            " expect=" + std::string(model::expectation_names[static_cast<std::size_t>(s.expect)]);
        switch (s.expect) {
        case model::Expectation::state:
            line += " " + model::key(s.state_word, s.state_name);
            break;
        case model::Expectation::refused:
            if (s.reason) {
                line += " \"" + *s.reason + "\"";
            }
            break;
        case model::Expectation::waits:
            for (const model::TestParty& p : s.waits) {
                line += " " + party_text(p);
            }
            break;
        case model::Expectation::accepted:
        case model::Expectation::proposed:
            break;
        }
        add_line(out, 1, line);
        for (const model::Set& w : s.with) {
            set_line(out, w, 2);
        }
    }
}

} // namespace

namespace model {

std::optional<std::set<std::string>> entry_states(const Action& action) {
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
    // The states a condition names when it is only states joined by `or`.
    const auto states_of = [](const Expr& e, std::set<std::string>& out, const auto& self) {
        if ((e.kind == ast::ExprKind::word || e.kind == ast::ExprKind::name) &&
            e.refers == Refers::state) {
            out.insert(key(e.concept_entry, e.name));
            return true;
        }
        if (e.kind == ast::ExprKind::binary && e.op == ast::Operator::logical_or &&
            e.operands.size() == 2) {
            return self(e.operands[0], out, self) && self(e.operands[1], out, self);
        }
        return false;
    };
    const auto changes = [](const std::vector<Statement>& list, const auto& self) -> bool {
        return std::ranges::any_of(list, [&](const Statement& s) {
            if (std::holds_alternative<Transition>(s.node)) {
                return true;
            }
            if (const auto* i = std::get_if<If>(&s.node)) {
                return self(i->then, self) || self(i->otherwise, self);
            }
            if (const auto* e = std::get_if<Each>(&s.node)) {
                return self(e->body, self);
            }
            return false;
        });
    };
    for (const Statement& s : action.body) {
        if (const auto* t = std::get_if<Transition>(&s.node)) {
            if (!t->from.empty()) {
                std::set<std::string> from;
                for (const Expr& f : t->from) {
                    from.insert(key(f.concept_entry, f.name));
                }
                narrow(std::move(from));
            }
            break;
        }
        if (const auto* r = std::get_if<Requires>(&s.node); r != nullptr && !r->guard) {
            std::set<std::string> states;
            if (states_of(r->condition, states, states_of)) {
                narrow(std::move(states));
            }
            continue;
        }
        if (changes(std::vector<Statement>{s}, changes)) {
            break;
        }
    }
    return allowed;
}

namespace {

/// The states a time rule can fire from (nullopt: any): the state a held
/// trigger names, narrowed by what the rule does first.
std::optional<std::set<std::string>> rule_entry_states(const Model& model, const TimeRule& rule) {
    std::optional<std::set<std::string>> allowed;
    if (const std::optional<Trigger> t = trigger_of(rule.event);
        t && t->kind == TriggerKind::held && t->state != nullptr) {
        allowed = std::set<std::string>{key(t->state->concept_entry, t->state->name)};
    }
    std::optional<std::set<std::string>> first;
    const auto line = std::ranges::find_if(
        rule.actions, [](const Do& d) { return !d.obligation && !d.executor; });
    if (line != rule.actions.end()) {
        if (const Action* a = action_of(model, *line)) {
            first = entry_states(*a);
        }
    } else {
        Action body;
        body.body = rule.body;
        first = entry_states(body);
    }
    if (!first) {
        return allowed;
    }
    if (!allowed) {
        return first;
    }
    std::set<std::string> both;
    std::ranges::set_intersection(*allowed, *first, std::inserter(both, both.begin()));
    return both;
}

} // namespace

std::vector<bool> final_states(const Model& model) {
    std::set<std::string> open;
    bool any = false;
    for (const Action& a : model.actions) {
        const auto allowed = entry_states(a);
        if (!allowed) {
            any = true;
            break;
        }
        open.insert(allowed->begin(), allowed->end());
    }
    // A state a time rule can fire from takes the keeper's calls.
    for (const TimeRule& r : model.rules) {
        if (any || !rule_runs(r)) {
            continue;
        }
        const auto allowed = rule_entry_states(model, r);
        if (!allowed) {
            any = true;
            break;
        }
        open.insert(allowed->begin(), allowed->end());
    }
    std::vector<bool> out;
    out.reserve(model.states.size());
    for (const State& s : model.states) {
        out.push_back(!any && !open.contains(key(s.word, s.name)));
    }
    return out;
}

std::optional<std::string> action_amount(const Model& model, const Action& action) {
    const auto amount = [](const Type& t) {
        return t.kind == TypeKind::money || t.kind == TypeKind::quantity;
    };
    std::optional<std::string> found;
    int amounts = 0;
    for (const Field& input : action.inputs) {
        if (amount(input.type)) {
            ++amounts;
            found = key(input.word, input.name);
        }
    }
    if (amounts == 1) {
        return found;
    }
    if (amounts == 0) {
        for (const Field& f : model.fields) {
            if (f.word != nullptr && f.word->id == "field.amount" && amount(f.type)) {
                return std::string("field.amount");
            }
        }
    }
    return std::nullopt;
}

std::string_view creation_function(const Model& model) noexcept {
    return model.kind != nullptr && model.kind->id == "kind.asset" ? "issue" : "create";
}

bool has_proposals(const Model& model) noexcept {
    return std::ranges::any_of(model.actions, [](const Action& a) { return a.agents_propose; });
}

const Do* issued_parts(const Action& action) noexcept {
    for (const Statement& s : action.body) {
        if (const auto* d = std::get_if<Do>(&s.node); d != nullptr && d->parts) {
            return d;
        }
    }
    return nullptr;
}

bool issues_parts(const Model& model) noexcept {
    return std::ranges::any_of(model.actions,
                               [](const Action& a) { return issued_parts(a) != nullptr; });
}

namespace {

const Concept* taken(const std::vector<Statement>& list, const Expr& party) {
    for (const Statement& s : list) {
        const Concept* found = nullptr;
        if (const auto* set = std::get_if<Set>(&s.node)) {
            const Concept* field = set->target.concept_entry;
            if (set->target.refers == Refers::field && field != nullptr &&
                (field->flags & field_taking) != 0 && set->value.refers == party.refers &&
                key(set->value.concept_entry, set->value.name) ==
                    key(party.concept_entry, party.name)) {
                found = field;
            }
        } else if (const auto* i = std::get_if<If>(&s.node)) {
            found = taken(i->then, party);
            if (found == nullptr) {
                found = taken(i->otherwise, party);
            }
        } else if (const auto* e = std::get_if<Each>(&s.node)) {
            found = taken(e->body, party);
        }
        if (found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

} // namespace

const Concept* role_taken(const Action& action) {
    if (!action.to || (action.to->refers != Refers::party && action.to->refers != Refers::field)) {
        return nullptr;
    }
    return taken(action.body, *action.to);
}

namespace {

bool goes_back(const std::vector<Statement>& list) {
    return std::ranges::any_of(list, [](const Statement& s) {
        if (const auto* t = std::get_if<Transition>(&s.node)) {
            return t->to.kind == ast::ExprKind::word && t->to.concept_entry != nullptr &&
                   t->to.concept_entry->id == "expr.previous_state";
        }
        if (const auto* i = std::get_if<If>(&s.node)) {
            return goes_back(i->then) || goes_back(i->otherwise);
        }
        if (const auto* e = std::get_if<Each>(&s.node)) {
            return goes_back(e->body);
        }
        return false;
    });
}

} // namespace

bool uses_previous(const Model& model) noexcept {
    return std::ranges::any_of(model.actions, [](const Action& a) { return goes_back(a.body); }) ||
           std::ranges::any_of(model.rules, [](const TimeRule& r) { return goes_back(r.body); });
}

const Field* bill_field(const Model& model) noexcept {
    for (const Field& f : model.fields) {
        if (f.word != nullptr && f.word->category == Category::document &&
            f.kind == FieldKind::instance) {
            return &f;
        }
    }
    return nullptr;
}

namespace {

bool word_is(const Expr& e, std::string_view id) noexcept {
    return e.kind == ast::ExprKind::word && e.concept_entry != nullptr && e.concept_entry->id == id;
}

bool mentions_now(const Expr& e) noexcept {
    return word_is(e, "time.now") || word_is(e, "time.today") ||
           std::ranges::any_of(e.operands, [](const Expr& o) { return mentions_now(o); });
}

bool holds_trigger(const Expr& e) noexcept {
    return is_trigger(e) ||
           std::ranges::any_of(e.operands, [](const Expr& o) { return holds_trigger(o); });
}

void and_operands(const Expr& e, std::vector<const Expr*>& out) {
    if (e.kind == ast::ExprKind::binary && e.op == ast::Operator::logical_and &&
        e.operands.size() == 2) {
        and_operands(e.operands[0], out);
        and_operands(e.operands[1], out);
        return;
    }
    out.push_back(&e);
}

/// Calls `f` on every Do of a list, nested ones included, in order.
template <class F>
void each_do(const std::vector<Statement>& list, const F& f) {
    for (const Statement& s : list) {
        if (const auto* d = std::get_if<Do>(&s.node)) {
            f(*d);
        } else if (const auto* i = std::get_if<If>(&s.node)) {
            each_do(i->then, f);
            each_do(i->otherwise, f);
        } else if (const auto* e = std::get_if<Each>(&s.node)) {
            each_do(e->body, f);
        }
    }
}

/// The first state change of a list, nested ones included.
const Transition* first_transition(const std::vector<Statement>& list) {
    for (const Statement& s : list) {
        if (const auto* t = std::get_if<Transition>(&s.node)) {
            return t;
        }
        if (const auto* i = std::get_if<If>(&s.node)) {
            if (const Transition* t = first_transition(i->then)) {
                return t;
            }
            if (const Transition* t = first_transition(i->otherwise)) {
                return t;
            }
        } else if (const auto* e = std::get_if<Each>(&s.node)) {
            if (const Transition* t = first_transition(e->body)) {
                return t;
            }
        }
    }
    return nullptr;
}

/// Calls `f` on every expression of a list of statements, nested ones
/// included; returns true as soon as `f` does.
template <class F>
bool any_expression(const std::vector<Statement>& list, const F& f) {
    const auto in = [&](const Expr& e, const auto& self) -> bool {
        return f(e) ||
               std::ranges::any_of(e.operands, [&](const Expr& o) { return self(o, self); });
    };
    const auto walk = [&](const Expr& e) {
        return in(e, in);
    };
    for (const Statement& s : list) {
        const bool found = std::visit(
            Overloaded{
                [&](const Requires& r) { return walk(r.condition) || (r.guard && walk(*r.guard)); },
                [&](const If& i) {
                    return walk(i.condition) || any_expression(i.then, f) ||
                           any_expression(i.otherwise, f);
                },
                [&](const Each& e) { return walk(e.list) || any_expression(e.body, f); },
                [&](const Reject&) { return false; },
                [&](const Set& st) { return walk(st.value); },
                [&](const Transition&) { return false; },
                [&](const Do& d) {
                    return std::ranges::any_of(d.args, walk) ||
                           std::ranges::any_of(d.with, [&](const Set& w) { return walk(w.value); });
                },
            },
            s.node);
        if (found) {
            return true;
        }
    }
    return false;
}

} // namespace

bool is_trigger(const Expr& e) noexcept {
    if (e.type.kind != TypeKind::yes_no) {
        return false;
    }
    if (word_is(e, "cond.overdue")) {
        return true;
    }
    if (e.kind == ast::ExprKind::apply && e.concept_entry != nullptr &&
        e.concept_entry->id == "cond.before_due" && e.operands.size() == 1) {
        return true;
    }
    if (e.kind == ast::ExprKind::phrase && e.operands.size() == 2) {
        return word_is(e.operands[0], "cond.overdue") ||
               (e.operands[0].refers == Refers::state &&
                e.operands[1].type.kind == TypeKind::duration);
    }
    return false;
}

std::optional<Trigger> trigger_of(const Expr& event) {
    if (event.type.kind == TypeKind::date) {
        if (mentions_now(event)) {
            return std::nullopt;
        }
        return Trigger{TriggerKind::date, &event, nullptr, {}};
    }
    std::vector<const Expr*> operands;
    and_operands(event, operands);
    std::optional<Trigger> out;
    std::vector<const Expr*> conditions;
    for (const Expr* e : operands) {
        if (e->type.kind == TypeKind::date) {
            // A date joined to conditions: the time the rule fires at.
            if (out || mentions_now(*e)) {
                return std::nullopt;
            }
            out = Trigger{TriggerKind::date, e, nullptr, {}};
            continue;
        }
        if (!is_trigger(*e)) {
            if (holds_trigger(*e)) {
                return std::nullopt;
            }
            conditions.push_back(e);
            continue;
        }
        if (out) {
            return std::nullopt;
        }
        if (word_is(*e, "cond.overdue")) {
            out = Trigger{TriggerKind::overdue, nullptr, nullptr, {}};
        } else if (e->kind == ast::ExprKind::apply) {
            out = Trigger{TriggerKind::before_due, &e->operands[0], nullptr, {}};
        } else if (word_is(e->operands[0], "cond.overdue")) {
            out = Trigger{TriggerKind::overdue, &e->operands[1], nullptr, {}};
        } else {
            out = Trigger{TriggerKind::held, &e->operands[1], &e->operands[0], {}};
        }
    }
    if (out) {
        out->conditions = std::move(conditions);
    }
    return out;
}

bool rule_runs(const TimeRule& rule) noexcept {
    return !rule.body.empty() || !rule.consents.empty() ||
           std::ranges::any_of(rule.actions, [](const Do& d) { return !d.obligation; });
}

std::vector<const Do*> rule_actions(const TimeRule& rule) {
    std::vector<const Do*> out;
    for (const Do& d : rule.actions) {
        if (!d.obligation && !d.executor) {
            out.push_back(&d);
        }
    }
    each_do(rule.body, [&](const Do& d) {
        if (!d.obligation && !d.executor) {
            out.push_back(&d);
        }
    });
    return out;
}

const Action* action_of(const Model& model, const Do& d) noexcept {
    const std::string k =
        key(d.action.kind == ast::ExprKind::word ? d.action.concept_entry : nullptr, d.action.name);
    for (const Action& a : model.actions) {
        if (key(a.word, a.name) == k) {
            return &a;
        }
    }
    return nullptr;
}

std::vector<std::string> rule_functions(const Model& model) {
    std::vector<std::string> out;
    std::set<std::string> used;
    for (const TimeRule& r : model.rules) {
        if (!rule_runs(r)) {
            out.emplace_back();
            continue;
        }
        std::optional<std::string> what;
        const auto name_of = [&](const Do& d) {
            if (!what && !d.obligation) {
                what = wire_name(d.action.kind == ast::ExprKind::word ? d.action.concept_entry
                                                                      : nullptr,
                                 d.action.name);
            }
        };
        for (const Do& d : r.actions) {
            name_of(d);
        }
        each_do(r.body, name_of);
        if (!what) {
            if (const Transition* t = first_transition(r.body)) {
                what = word_is(t->to, "expr.previous_state")
                           ? std::string("previous")
                           : wire_name(t->to.concept_entry, t->to.name);
            }
        }
        const std::string base = "when." + what.value_or("rule");
        std::string name = base;
        for (int n = 2; !used.insert(name).second; ++n) {
            name = base + "." + std::to_string(n);
        }
        out.push_back(std::move(name));
    }
    return out;
}

bool uses_since(const Model& model) noexcept {
    const auto asks = [](const Expr& e) {
        return (e.kind == ast::ExprKind::apply && e.concept_entry != nullptr &&
                e.concept_entry->id == "cond.within") ||
               (is_trigger(e) && e.kind == ast::ExprKind::phrase &&
                e.operands[0].refers == Refers::state);
    };
    const auto in = [&](const Expr& e, const auto& self) -> bool {
        return asks(e) ||
               std::ranges::any_of(e.operands, [&](const Expr& o) { return self(o, self); });
    };
    return std::ranges::any_of(model.actions,
                               [&](const Action& a) { return any_expression(a.body, asks); }) ||
           std::ranges::any_of(model.rules, [&](const TimeRule& r) {
               return rule_runs(r) && (in(r.event, in) || any_expression(r.body, asks));
           });
}

} // namespace model

std::string encode(const model::Type& type) {
    switch (type.kind) {
    case TypeKind::unknown:
        return "?";
    case TypeKind::money:
        return type.currency == nullptr ? "money" : "money " + std::string(type.currency->id);
    case TypeKind::quantity:
        return type.dimension == Dimension::none
                   ? "quantity"
                   : "quantity " +
                         std::string(
                             model::dimension_names[static_cast<std::size_t>(type.dimension)]);
    case TypeKind::duration:
        return type.calendar ? "duration calendar" : "duration";
    case TypeKind::list:
        if (type.element.empty()) {
            return "list";
        }
        return std::format("list {} {}", type.bound, encode(type.element.front()));
    case TypeKind::unit_price: {
        std::string out = "unit_price";
        out += type.currency == nullptr ? " ?" : " " + std::string(type.currency->id);
        out += " ";
        out += model::dimension_names[static_cast<std::size_t>(type.dimension)];
        return out;
    }
    case TypeKind::recurring:
        return std::format("recurring {} {}",
                           type.period == nullptr ? std::string_view("?") : type.period->id,
                           type.element.empty() ? std::string("?") : encode(type.element.front()));
    case TypeKind::number:
    case TypeKind::rate:
    case TypeKind::date:
    case TypeKind::text:
    case TypeKind::yes_no:
    case TypeKind::party:
    case TypeKind::state:
    case TypeKind::basis:
        break;
    }
    return std::string(model::type_kind_names[static_cast<std::size_t>(type.kind)]);
}

std::string describe_type(std::string_view encoded, const Pack* language) {
    std::vector<std::string_view> tokens;
    while (!encoded.empty()) {
        const std::size_t space = encoded.find(' ');
        if (space != 0) {
            tokens.push_back(encoded.substr(0, space));
        }
        if (space == std::string_view::npos) {
            break;
        }
        encoded.remove_prefix(space + 1);
    }
    std::size_t at = 0;
    std::string out = describe_tokens(tokens, at, language, 0);
    // Anything left over (not an encoded type): kept as written.
    while (at < tokens.size()) {
        out += " " + std::string(tokens[at++]);
    }
    return out;
}

std::string dump(const model::Model& m) {
    std::string out = std::format("edition {}\n", m.edition);
    if (!m.packs.empty()) {
        std::string line = "packs";
        for (const std::string& pack : m.packs) {
            line += " " + pack;
        }
        add_line(out, 0, line);
    }
    add_line(out, 0, m.name.empty() ? std::string("fragment") : "contract " + m.name);
    for (const model::Party& p : m.parties) {
        std::string binding =
            p.binding == model::Binding::creation ? std::string("creation") : p.bound_by;
        std::string line =
            "party " + model::key(p.role, p.name) + " " + ruled("bound=" + binding, p.rule);
        if (p.each_call) {
            line += " each_call{R23}";
        }
        add_line(out, 0, line);
    }
    if (m.offset_rule.empty() || !m.rules.empty()) {
        // U6: written, or the default (R25) for a contract with time rules.
        const std::int64_t minutes = m.utc_offset_ms / 60'000;
        const std::int64_t whole = minutes < 0 ? -minutes : minutes;
        add_line(out, 0,
                 ruled(std::format("utc_offset {}{:02}:{:02}", minutes < 0 ? '-' : '+', whole / 60,
                                   whole % 60),
                       m.offset_rule));
    }
    if (m.kind != nullptr) {
        add_line(out, 0, "kind " + std::string(m.kind->id) + " " + m.kind_name);
    }
    for (const model::Field& f : m.fields) {
        field_line(out, "field", f, 0);
    }
    for (const model::Charge& c : m.charges) {
        add_line(out, 0, "charge " + std::string(c.kind->id) + " " + c.name);
        for (const model::ChargeLine& line : c.lines) {
            std::string head = std::string(line.head->id);
            if (line.argument) {
                head = "(" + head + " " + text(*line.argument) + ")";
            }
            for (const model::Expr& v : line.values) {
                head += " " + text(v);
            }
            add_line(out, 1, "line " + head);
        }
        // What compiled code computes (R27): how, on what, and how rounded.
        std::string how = std::string(c.included ? "computes included" : "computes added") +
                          (c.amount ? " amount" : " rate") +
                          (c.per_document ? " per_document" : " per_line");
        if (c.document != nullptr) {
            how += " " + std::string(c.document->id);
        }
        if (!c.amount) {
            how +=
                c.rounding != nullptr ? " " + std::string(c.rounding->id) : " round.half_up{R17}";
        }
        std::string on;
        if (c.on_price) {
            on = "price.price";
        }
        for (const std::uint64_t j : c.on) {
            if (j < m.charges.size()) {
                on += (on.empty() ? "" : ",") + m.charges[j].name;
            }
        }
        add_line(out, 1, how + " on=" + on + "{R27}");
    }
    if (m.due != model::DueKind::none) {
        add_line(out, 0,
                 ruled("due " + std::string(model::due_kind_names[static_cast<std::size_t>(m.due)]),
                       m.due_rule));
    }
    for (const model::State& s : m.states) {
        std::string line = "state " + model::key(s.word, s.name);
        if (s.first) {
            line += " first";
        }
        add_line(out, 0, ruled(std::move(line), s.rule));
    }
    for (const model::Action& a : m.actions) {
        std::string line = "can " + model::key(a.word, a.name);
        line += a.word != nullptr ? " standard" : " own";
        if (a.by) {
            line += " by=" + text(*a.by);
        }
        if (a.to) {
            line += " to=" + text(*a.to);
        }
        line += " " + (a.agents_propose ? std::string("agents=propose")
                                        : ruled("agents=delegation", a.agents_rule));
        if (a.executor) {
            line += " " + ruled("executor", a.executor_rule);
        }
        if (a.rule_only) {
            line += " rule_only";
        }
        add_line(out, 0, line);
        for (const model::Field& f : a.inputs) {
            field_line(out, "input", f, 1);
        }
        consent_lines(out, a.consents, 1);
        if (!a.terms) {
            statements(out, a.body, 1);
            continue;
        }
        const auto split = a.body.begin() + static_cast<std::ptrdiff_t>(a.terms_from);
        statements(out, std::vector<model::Statement>(a.body.begin(), split), 1);
        add_line(out, 1, "terms{R19}");
        statements(out, std::vector<model::Statement>(split, a.body.end()), 2);
    }
    const std::vector<std::string> functions = model::rule_functions(m);
    for (std::size_t i = 0; i < m.rules.size(); ++i) {
        const model::TimeRule& r = m.rules[i];
        std::string line = "when " + text(r.event);
        if (const auto t = model::trigger_of(r.event); t && !functions[i].empty()) {
            line += " trigger=" +
                    std::string(model::trigger_kind_names[static_cast<std::size_t>(t->kind)]) +
                    " function=" + functions[i] + "{R24}";
        }
        add_line(out, 0, line);
        consent_lines(out, r.consents, 1);
        for (const model::Do& d : r.actions) {
            do_lines(out, d, 1);
        }
        statements(out, r.body, 1);
    }
    for (const model::Test& t : m.tests) {
        test_lines(out, t);
    }
    return out;
}

std::string dump(const Checked& checked, const Pack* language) {
    std::string out = dump(checked.model);
    for (const Diagnostic& d : checked.diagnostics) {
        const std::string place =
            d.span.line == 0 ? std::string("-") : std::format("{}:{}", d.span.line, d.span.column);
        out += place + " " + std::string(severity_names[static_cast<std::size_t>(d.severity())]) +
               " " + std::string(d.code) + ": " + render(d, language) + "\n";
    }
    return out;
}

} // namespace cexchain::bo
