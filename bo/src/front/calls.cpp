// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/bo/calls.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/core/bytes.hpp>

namespace cexchain::bo::calls {

namespace {

namespace m = model;

std::string label_of(const Concept* word, const std::string& name, const Pack* language) {
    return word != nullptr ? spell(word->id, language) : name;
}

/// The fields a creation gives: every instance field but a party field
/// that starts with a party (R2) and the fields Bo adds (R20).
bool given_at_creation(const m::Field& f) {
    return f.kind == m::FieldKind::instance && !(f.type.kind == m::TypeKind::party && f.value) &&
           !f.empty_at_start;
}

Input input_of(const m::Field& f, Place place, std::string_view source, const Pack* language) {
    Input in;
    in.name = wire_name(f.word, f.name);
    in.label = label_of(f.word, f.name, language);
    in.type = encode(f.type);
    in.type_text = describe_type(in.type, language);
    in.place = place;
    if (f.initial) {
        in.optional = true;
        const Span& s = f.initial->span;
        if (s.offset <= source.size() && s.length <= source.size() - s.offset) {
            in.initial = std::string(source.substr(s.offset, s.length));
        }
    }
    return in;
}

Input role_input(const m::Party& p, const Pack* language) {
    m::Type party;
    party.kind = m::TypeKind::party;
    Input in;
    in.name = wire_name(p.role, p.name);
    in.label = label_of(p.role, p.name, language);
    in.type = encode(party);
    in.type_text = describe_type(in.type, language);
    in.place = Place::role;
    return in;
}

/// The roles an action binds (R3), each to the ledger a call names.
std::vector<const m::Party*> bound_by(const m::Model& model, const m::Action& a) {
    std::vector<const m::Party*> out;
    const std::string action = m::key(a.word, a.name);
    for (const m::Party& p : model.parties) {
        if (p.binding == m::Binding::action && p.bound_by == action) {
            out.push_back(&p);
        }
    }
    return out;
}

std::vector<std::string> clauses_of(const Explained& text, std::string_view function,
                                    std::string_view kind = {}) {
    std::vector<std::string> out;
    for (const ExplainedSection& s : text.sections) {
        for (const ExplainedClause& c : s.clauses) {
            if (kind.empty() ? c.function == function : c.kind == kind) {
                out.push_back(c.number + " " + c.text);
            }
        }
    }
    return out;
}

// --- Values -----------------------------------------------------------------

/// A map in canonical order: its keys sorted by their encodings.
cbor::Value canonical(cbor::Map entries) {
    std::vector<std::pair<Bytes, cbor::MapEntry>> keyed;
    keyed.reserve(entries.size());
    for (cbor::MapEntry& e : entries) {
        Bytes key = cbor::encode(e.key).value_or(Bytes{});
        keyed.emplace_back(std::move(key), std::move(e));
    }
    std::ranges::sort(keyed, [](const auto& a, const auto& b) { return a.first < b.first; });
    cbor::Map out;
    out.reserve(keyed.size());
    for (auto& [key, entry] : keyed) {
        out.push_back(std::move(entry));
    }
    return cbor::Value::map(std::move(out));
}

struct Reader {
    const m::Model& model;
    const Lexicon& lexicon;
    std::vector<Problem>& problems;

    void problem(const std::string& name, std::string_view code, const m::Type& type,
                 std::string detail) {
        problems.push_back(Problem{name, code, encode(type), std::move(detail)});
    }

    std::optional<cbor::Value> read(const std::string& name, const m::Type& type, const Value& v) {
        switch (type.kind) {
        case m::TypeKind::text: {
            const auto* text = std::get_if<std::string>(&v.value);
            if (text == nullptr) {
                problem(name, "type", type, "a text, as typed");
                return std::nullopt;
            }
            if (text->size() > max_text_bytes) {
                problem(name, "size", type, "a text is at most 1000 bytes");
                return std::nullopt;
            }
            if (!cbor::is_valid_utf8(*text)) {
                problem(name, "literal", type, "a text in UTF-8");
                return std::nullopt;
            }
            return cbor::Value::text(*text);
        }
        case m::TypeKind::yes_no: {
            const auto* yes = std::get_if<bool>(&v.value);
            if (yes == nullptr) {
                problem(name, "type", type, "yes or no (true or false)");
                return std::nullopt;
            }
            return cbor::Value::boolean(*yes);
        }
        case m::TypeKind::party: {
            const auto* text = std::get_if<std::string>(&v.value);
            std::optional<Bytes> bytes;
            if (text != nullptr) {
                if (auto decoded = from_hex(*text)) {
                    bytes = std::move(*decoded);
                }
            }
            if (!bytes || bytes->size() != 32) {
                problem(name, "ledger", type, "a ledger id: 64 hexadecimal digits");
                return std::nullopt;
            }
            return cbor::Value::bytes(*bytes);
        }
        case m::TypeKind::list: {
            const auto* items = std::get_if<std::vector<Value>>(&v.value);
            if (items == nullptr || type.element.size() != 1) {
                problem(name, "type", type, "a list");
                return std::nullopt;
            }
            if (type.bound > 0 && items->size() > type.bound) {
                problem(name, "bound", type,
                        "at most " + std::to_string(type.bound) + " items in this list");
                return std::nullopt;
            }
            cbor::Array out;
            bool ok = true;
            for (std::size_t i = 0; i < items->size(); ++i) {
                auto item = read(name + "/" + std::to_string(i), type.element[0], (*items)[i]);
                ok = ok && item.has_value();
                if (item) {
                    out.push_back(std::move(*item));
                }
            }
            if (!ok) {
                return std::nullopt;
            }
            return cbor::Value::array(std::move(out));
        }
        case m::TypeKind::number:
        case m::TypeKind::money:
        case m::TypeKind::quantity:
        case m::TypeKind::rate:
        case m::TypeKind::date:
        case m::TypeKind::duration:
            return literal(name, type, v);
        default:
            problem(name, "type", type, "a form cannot give a value of this type");
            return std::nullopt;
        }
    }

    /// A number, money, a quantity, a rate, a date, or a duration, written
    /// as Bo writes it.
    std::optional<cbor::Value> literal(const std::string& name, const m::Type& type,
                                       const Value& v) {
        const auto* text = std::get_if<std::string>(&v.value);
        if (text == nullptr) {
            problem(name, "type", type, "a value written as Bo writes it, such as 100 or HKD 100");
            return std::nullopt;
        }
        if (text->empty() || text->size() > 256 ||
            std::ranges::any_of(*text, [](unsigned char c) { return c < 0x20 || c == 0x7f; })) {
            problem(name, "literal", type, "one value, on one line");
            return std::nullopt;
        }
        const Lexed lexed = lex(*text, lexicon);
        std::vector<const Token*> tokens;
        for (const Token& t : lexed.tokens) {
            if (t.kind != TokenKind::newline && t.kind != TokenKind::end) {
                tokens.push_back(&t);
            }
        }
        const auto is_value = [](const Token* t) {
            switch (t->kind) {
            case TokenKind::number:
            case TokenKind::money:
            case TokenKind::quantity:
            case TokenKind::duration:
            case TokenKind::rate:
            case TokenKind::date:
            case TokenKind::text:
                return true;
            default:
                return false;
            }
        };
        if (!lexed.diagnostics.empty() || tokens.size() != 1 || !is_value(tokens.front())) {
            problem(name, "literal", type, "one value, written as Bo writes it");
            return std::nullopt;
        }
        const Token& t = *tokens.front();
        ast::Literal l;
        l.number = t.number;
        l.date = t.date;
        bool fits = false;
        switch (type.kind) {
        case m::TypeKind::number:
            l.kind = ast::LiteralKind::number;
            fits = t.kind == TokenKind::number;
            break;
        case m::TypeKind::money:
            l.kind = ast::LiteralKind::money;
            l.unit = type.currency;
            // A plain number is in the field's currency.
            fits = t.kind == TokenKind::number ||
                   (t.kind == TokenKind::money && t.concept_entry == type.currency);
            break;
        case m::TypeKind::quantity: {
            l.kind = ast::LiteralKind::quantity;
            if (t.kind == TokenKind::quantity) {
                l.unit = t.concept_entry;
                const UnitInfo* unit = unit_info(l.unit);
                fits = unit != nullptr && unit->dimension == type.dimension;
            } else if (t.kind == TokenKind::number && type.unit != nullptr) {
                // A plain number is in the unit the field was declared with.
                l.unit = type.unit;
                fits = true;
            }
            break;
        }
        case m::TypeKind::rate:
            l.kind = ast::LiteralKind::rate;
            // A plain number is a percent, as the form shows it.
            fits = t.kind == TokenKind::rate || t.kind == TokenKind::number;
            break;
        case m::TypeKind::date:
            l.kind = ast::LiteralKind::date;
            fits = t.kind == TokenKind::date;
            break;
        case m::TypeKind::duration: {
            l.kind = ast::LiteralKind::duration;
            l.unit = t.concept_entry;
            const bool calendar =
                l.unit != nullptr && (l.unit->id == "time.month" || l.unit->id == "time.year");
            fits = t.kind == TokenKind::duration && calendar == type.calendar;
            break;
        }
        default:
            break;
        }
        if (!fits) {
            problem(name, "type", type, "not a value of this type");
            return std::nullopt;
        }
        const std::optional<std::int64_t> value = literal_value(l, model.utc_offset_ms);
        if (!value) {
            problem(name, "exact", type, "finer than its smallest unit, or too large");
            return std::nullopt;
        }
        return cbor::Value::integer(*value);
    }
};

struct Expected {
    std::string name;
    m::Type type;
    Place place = Place::input;
    bool optional = false;
};

m::Type party_type() {
    m::Type t;
    t.kind = m::TypeKind::party;
    return t;
}

} // namespace

Description describe(const m::Model& model, std::string_view source, const Pack* language) {
    const Explained text = explain(model, language);
    Description out;
    out.contract = model.name;

    Call creation;
    creation.kind = Kind::create;
    creation.function = std::string(m::creation_function(model));
    creation.label = creation.function;
    for (const m::Field& f : model.fields) {
        if (given_at_creation(f)) {
            creation.inputs.push_back(input_of(f, Place::field, source, language));
        }
    }
    for (const m::Party& p : model.parties) {
        if (p.binding == m::Binding::creation) {
            creation.inputs.push_back(role_input(p, language));
        }
    }
    creation.clauses = clauses_of(text, {}, "creation");
    out.calls.push_back(std::move(creation));

    for (const m::Action& a : model.actions) {
        if (a.rule_only) {
            continue;
        }
        Call call;
        call.kind = Kind::action;
        call.function = wire_name(a.word, a.name);
        call.label = label_of(a.word, a.name, language);
        call.agents_propose = a.agents_propose;
        for (const m::Field& f : a.inputs) {
            call.inputs.push_back(input_of(f, Place::input, source, language));
        }
        for (const m::Party* p : bound_by(model, a)) {
            Input role = role_input(*p, language);
            role.optional = !p->each_call;
            role.each_call = p->each_call;
            call.inputs.push_back(std::move(role));
        }
        call.clauses = clauses_of(text, call.function);
        out.calls.push_back(std::move(call));
    }
    if (m::has_proposals(model)) {
        Call approve;
        approve.kind = Kind::approve;
        approve.function = std::string(m::approve_function);
        approve.label = approve.function;
        approve.clauses = clauses_of(text, approve.function);
        out.calls.push_back(std::move(approve));
    }
    for (const std::string& function : m::rule_functions(model)) {
        if (function.empty()) {
            continue;
        }
        Call rule;
        rule.kind = Kind::rule;
        rule.function = function;
        rule.label = function;
        rule.clauses = clauses_of(text, function);
        out.calls.push_back(std::move(rule));
    }
    if (m::makes_requests(model)) {
        Call reply;
        reply.kind = Kind::reply;
        reply.function = std::string(m::reply_function);
        reply.label = reply.function;
        reply.clauses = clauses_of(text, reply.function);
        out.calls.push_back(std::move(reply));
    }
    return out;
}

Arguments arguments(const m::Model& model, const Lexicon& lexicon, std::string_view function,
                    const Values& values) {
    Arguments out;
    std::vector<Expected> expected;
    const bool creation = function == m::creation_function(model);
    const m::Action* action = nullptr;
    if (creation) {
        for (const m::Field& f : model.fields) {
            if (given_at_creation(f)) {
                expected.push_back(
                    {wire_name(f.word, f.name), f.type, Place::field, f.initial.has_value()});
            }
        }
        for (const m::Party& p : model.parties) {
            if (p.binding == m::Binding::creation) {
                expected.push_back({wire_name(p.role, p.name), party_type(), Place::role, false});
            }
        }
    } else {
        for (const m::Action& a : model.actions) {
            if (!a.rule_only && wire_name(a.word, a.name) == function) {
                action = &a;
            }
        }
        if (action == nullptr) {
            const auto rules = m::rule_functions(model);
            if (!function.empty() && std::ranges::contains(rules, function)) {
                // A time rule's function takes no arguments.
                if (!values.empty()) {
                    out.problems.push_back(
                        {"", "unknown", "", "a time rule's call takes no values"});
                    return out;
                }
                out.value = cbor::Value::null();
                return out;
            }
            out.problems.push_back({"", "function", "",
                                    "the contract has no function " + std::string(function) +
                                        " that takes values from a person"});
            return out;
        }
        for (const m::Field& f : action->inputs) {
            expected.push_back({wire_name(f.word, f.name), f.type, Place::input, false});
        }
        for (const m::Party* p : bound_by(model, *action)) {
            expected.push_back({wire_name(p->role, p->name), party_type(), Place::role, true});
        }
    }

    Reader reader{model, lexicon, out.problems};
    cbor::Map fields;
    cbor::Map parties;
    cbor::Map inputs;
    std::vector<std::string> seen;
    for (const auto& [name, value] : values) {
        if (std::ranges::contains(seen, name)) {
            out.problems.push_back({name, "twice", "", "given twice"});
            continue;
        }
        seen.push_back(name);
        const auto it = std::ranges::find(expected, name, &Expected::name);
        if (it == expected.end()) {
            out.problems.push_back({name, "unknown", "", "the call takes no value " + name});
            continue;
        }
        auto encoded = reader.read(name, it->type, value);
        if (!encoded) {
            continue;
        }
        cbor::Map& into = !creation ? inputs : it->place == Place::field ? fields : parties;
        into.push_back({cbor::Value::text(name), std::move(*encoded)});
    }
    for (const Expected& e : expected) {
        if (!e.optional && !std::ranges::contains(seen, e.name)) {
            out.problems.push_back(Problem{e.name, "missing", encode(e.type), "required"});
        }
    }
    if (!out.problems.empty()) {
        return out;
    }
    if (!creation) {
        out.value = inputs.empty() ? cbor::Value::null() : canonical(std::move(inputs));
        return out;
    }
    // {"fields": {...}} whenever some field is given at creation, even if
    // every one left out has a default; {"parties": {...}} with the roles.
    const bool has_fields =
        std::ranges::any_of(expected, [](const Expected& e) { return e.place == Place::field; });
    const bool has_roles =
        std::ranges::any_of(expected, [](const Expected& e) { return e.place == Place::role; });
    cbor::Map map;
    if (has_fields) {
        map.push_back({cbor::Value::text("fields"), canonical(std::move(fields))});
    }
    if (has_roles) {
        map.push_back({cbor::Value::text("parties"), canonical(std::move(parties))});
    }
    out.value = map.empty() ? cbor::Value::null() : canonical(std::move(map));
    return out;
}

namespace {

std::optional<Value> value_of(const nlohmann::json& j, int depth) {
    if (j.is_string()) {
        return Value{j.get<std::string>()};
    }
    if (j.is_boolean()) {
        return Value{j.get<bool>()};
    }
    if (j.is_array() && depth < 2 && j.size() <= max_values) {
        std::vector<Value> items;
        for (const nlohmann::json& item : j) {
            auto v = value_of(item, depth + 1);
            if (!v) {
                return std::nullopt;
            }
            items.push_back(std::move(*v));
        }
        return Value{std::move(items)};
    }
    return std::nullopt;
}

} // namespace

std::variant<Values, std::string> parse_values(std::string_view json) {
    if (json.size() > max_values_json) {
        return std::string("the values are at most 64 KiB of JSON");
    }
    const auto j = nlohmann::json::parse(json, nullptr, false);
    if (!j.is_object()) {
        return std::string("the values are a JSON object: {\"NAME\": VALUE, ...}");
    }
    if (j.size() > max_values) {
        return std::string("a call takes at most 256 values");
    }
    Values out;
    for (const auto& [name, value] : j.items()) {
        if (name.empty() || name.size() > max_name_bytes) {
            return std::string("a value's name is 1 to 128 bytes");
        }
        auto v = value_of(value, 0);
        if (!v) {
            return "the value " + name + " is not a string, true or false, or a list of them";
        }
        out.emplace_back(name, std::move(*v));
    }
    return out;
}

} // namespace cexchain::bo::calls
