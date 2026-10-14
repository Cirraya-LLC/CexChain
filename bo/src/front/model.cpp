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
        if (s.to) {
            line += " to=" + party_text(*s.to);
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
    add_line(out, 0, m.name.empty() ? std::string("fragment") : "contract " + m.name);
    for (const model::Party& p : m.parties) {
        std::string binding =
            p.binding == model::Binding::creation ? std::string("creation") : p.bound_by;
        add_line(out, 0,
                 "party " + model::key(p.role, p.name) + " " + ruled("bound=" + binding, p.rule));
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
    for (const model::TimeRule& r : m.rules) {
        add_line(out, 0, "when " + text(r.event));
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
