// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/form.hpp>

namespace cexchain::bo::form {

namespace {

using Json = nlohmann::ordered_json;

// ---------------------------------------------------------------------------
// Reading a sheet.

struct Failure {
    std::string path;
    std::string message;
};

[[noreturn]] void fail(const std::string& path, std::string message) {
    throw Failure{path, std::move(message)};
}

std::string at(const std::string& path, std::string_view key) {
    return path + "/" + std::string(key);
}

std::string at(const std::string& path, std::size_t index) {
    return path + "/" + std::to_string(index);
}

/// A piece of Bo text: one line, without tabs or other control characters.
Text piece(const Json& value, const std::string& path) {
    if (!value.is_string()) {
        fail(path, "a piece of Bo text, in quotes");
    }
    Text text = value.get<std::string>();
    const bool blank = std::ranges::all_of(text, [](char c) { return c == ' '; });
    if (blank) {
        fail(path, "this may not be empty");
    }
    if (std::ranges::any_of(text, [](unsigned char c) { return c < 0x20 || c == 0x7f; })) {
        fail(path, "one line, without tabs or control characters");
    }
    if (text.front() == ' ' || text.back() == ' ') {
        fail(path, "no spaces at either end");
    }
    return text;
}

void known_keys(const Json& object, const std::string& path,
                std::initializer_list<std::string_view> keys) {
    if (!object.is_object()) {
        fail(path, "an object");
    }
    for (const auto& [key, value] : object.items()) {
        if (std::ranges::find(keys, key) == keys.end()) {
            fail(at(path, key), "the sheet has no such key");
        }
    }
}

const Json* member(const Json& object, std::string_view key) {
    const auto it = object.find(key);
    return it == object.end() || it->is_null() ? nullptr : &*it;
}

Text required_piece(const Json& object, std::string_view key, const std::string& path) {
    const Json* value = member(object, key);
    if (value == nullptr) {
        fail(at(path, key), "this is required");
    }
    return piece(*value, at(path, key));
}

std::optional<Text> optional_piece(const Json& object, std::string_view key,
                                   const std::string& path) {
    const Json* value = member(object, key);
    return value == nullptr ? std::nullopt : std::optional(piece(*value, at(path, key)));
}

bool flag(const Json& object, std::string_view key, const std::string& path) {
    const Json* value = member(object, key);
    if (value == nullptr) {
        return false;
    }
    if (!value->is_boolean()) {
        fail(at(path, key), "true or false");
    }
    return value->get<bool>();
}

template <class Read>
auto list(const Json& object, std::string_view key, const std::string& path, Read read) {
    using Item = decltype(read(Json(), std::string()));
    std::vector<Item> out;
    const Json* value = member(object, key);
    if (value == nullptr) {
        return out;
    }
    if (!value->is_array()) {
        fail(at(path, key), "a list");
    }
    if (value->size() > 1000) {
        fail(at(path, key), "at most 1000 items");
    }
    for (std::size_t i = 0; i < value->size(); ++i) {
        out.push_back(read((*value)[i], at(at(path, key), i)));
    }
    return out;
}

std::vector<Text> pieces(const Json& object, std::string_view key, const std::string& path) {
    return list(object, key, path, [](const Json& v, const std::string& p) { return piece(v, p); });
}

Assign read_assign(const Json& value, const std::string& path) {
    known_keys(value, path, {"name", "value"});
    return {required_piece(value, "name", path), required_piece(value, "value", path)};
}

Line read_line(const Json& value, const std::string& path) {
    known_keys(value, path, {"name", "type", "default"});
    return {required_piece(value, "name", path),
            optional_piece(value, "type", path).value_or(Text()),
            optional_piece(value, "default", path)};
}

Request read_request(const Json& value, const std::string& path) {
    known_keys(value, path, {"kind", "to", "with", "within"});
    return {required_piece(value, "kind", path), optional_piece(value, "to", path),
            list(value, "with", path, read_assign), required_piece(value, "within", path)};
}

Effects read_effects(const Json& value, const std::string& path) {
    Effects e{pieces(value, "from", path), optional_piece(value, "to_state", path),
              list(value, "set", path, read_assign), list(value, "requests", path, read_request)};
    if (!e.from.empty() && !e.to_state) {
        fail(at(path, "to_state"), "a state change from some states needs the state it leads to");
    }
    return e;
}

std::optional<Outcome> outcome_of(std::string_view text) {
    if (text == "done") {
        return Outcome::done;
    }
    if (text == "fails") {
        return Outcome::fails;
    }
    if (text == "expires") {
        return Outcome::expires;
    }
    return std::nullopt;
}

Outcome read_outcome(const Json& value, const std::string& path) {
    const auto outcome = value.is_string() ? outcome_of(value.get<std::string>()) : std::nullopt;
    if (!outcome) {
        fail(path, "done, fails, or expires");
    }
    return *outcome;
}

Action read_action(const Json& value, const std::string& path) {
    known_keys(value, path,
               {"action", "by", "to", "inputs", "requires", "consent_of", "in_person",
                "in_person_over", "agents_propose", "from", "to_state", "set", "requests"});
    Action a;
    a.action = required_piece(value, "action", path);
    a.by = optional_piece(value, "by", path);
    a.to = optional_piece(value, "to", path);
    a.inputs = list(value, "inputs", path, read_line);
    a.requires_ = pieces(value, "requires", path);
    a.consent_of = pieces(value, "consent_of", path);
    a.in_person = flag(value, "in_person", path);
    a.in_person_over = optional_piece(value, "in_person_over", path);
    a.agents_propose = flag(value, "agents_propose", path);
    a.effects = read_effects(value, path);
    return a;
}

Rule read_rule(const Json& value, const std::string& path) {
    known_keys(value, path, {"when", "do", "from", "to_state", "set", "requests"});
    return {required_piece(value, "when", path), pieces(value, "do", path),
            read_effects(value, path)};
}

Answer read_answer(const Json& value, const std::string& path) {
    known_keys(value, path, {"kind", "outcome", "do", "from", "to_state", "set", "requests"});
    const Json* outcome = member(value, "outcome");
    if (outcome == nullptr) {
        fail(at(path, "outcome"), "this is required");
    }
    return {required_piece(value, "kind", path), read_outcome(*outcome, at(path, "outcome")),
            pieces(value, "do", path), read_effects(value, path)};
}

Step read_step(const Json& value, const std::string& path) {
    known_keys(value, path, {"party", "action", "outcome", "args", "to", "by", "with", "expect"});
    Step s;
    s.party = required_piece(value, "party", path);
    s.action = required_piece(value, "action", path);
    if (const Json* outcome = member(value, "outcome")) {
        s.outcome = read_outcome(*outcome, at(path, "outcome"));
    }
    s.args = pieces(value, "args", path);
    s.to = optional_piece(value, "to", path);
    s.by = optional_piece(value, "by", path);
    s.with = list(value, "with", path, read_assign);
    s.expect = optional_piece(value, "expect", path);
    return s;
}

Test read_test(const Json& value, const std::string& path) {
    known_keys(value, path, {"name", "steps"});
    Test t{optional_piece(value, "name", path), list(value, "steps", path, read_step)};
    if (t.steps.empty()) {
        fail(at(path, "steps"), "a test has steps");
    }
    return t;
}

Sheet read(const Json& j) {
    const std::string root;
    known_keys(j, root,
               {"sheet", "kind", "contract", "packs", "parties", "thing", "actions", "rules",
                "answers", "tests"});
    if (const Json* version = member(j, "sheet"); version == nullptr ||
                                                  !version->is_number_unsigned() ||
                                                  version->get<std::uint64_t>() != sheet_version) {
        fail("/sheet", "this is a rules sheet of version 1 (\"sheet\": 1)");
    }
    if (const Json* kind = member(j, "kind"); kind == nullptr || *kind != "rules") {
        fail("/kind", "a rules sheet says \"kind\": \"rules\"");
    }
    Sheet s;
    s.contract = required_piece(j, "contract", root);
    s.packs = list(j, "packs", root, [](const Json& v, const std::string& p) {
        const Text id = piece(v, p);
        if (!std::ranges::all_of(id, [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                       c == '.';
            })) {
            fail(p, "a pack's id: lowercase letters, digits, '.', '-', '_'");
        }
        return id;
    });
    s.parties = pieces(j, "parties", root);
    if (const Json* thing = member(j, "thing")) {
        known_keys(*thing, "/thing", {"word", "name", "fields"});
        s.kind_word = optional_piece(*thing, "word", "/thing").value_or("thing");
        s.kind_name = required_piece(*thing, "name", "/thing");
        s.fields = list(*thing, "fields", "/thing", read_line);
    }
    s.actions = list(j, "actions", root, read_action);
    s.rules = list(j, "rules", root, read_rule);
    s.answers = list(j, "answers", root, read_answer);
    s.tests = list(j, "tests", root, read_test);
    return s;
}

// ---------------------------------------------------------------------------
// Writing a sheet.

Json optional_json(const std::optional<Text>& text) {
    return text ? Json(*text) : Json();
}

Json assigns_json(const std::vector<Assign>& items) {
    Json out = Json::array();
    for (const Assign& a : items) {
        out.push_back({{"name", a.name}, {"value", a.value}});
    }
    return out;
}

Json lines_json(const std::vector<Line>& items) {
    Json out = Json::array();
    for (const Line& l : items) {
        out.push_back({{"name", l.name},
                       {"type", l.type.empty() ? Json() : Json(l.type)},
                       {"default", optional_json(l.initial)}});
    }
    return out;
}

Json requests_json(const std::vector<Request>& items) {
    Json out = Json::array();
    for (const Request& r : items) {
        out.push_back({{"kind", r.kind},
                       {"to", optional_json(r.to)},
                       {"with", assigns_json(r.with)},
                       {"within", r.within}});
    }
    return out;
}

void effects_json(Json& out, const Effects& e) {
    out["from"] = e.from;
    out["to_state"] = optional_json(e.to_state);
    out["set"] = assigns_json(e.set);
    out["requests"] = requests_json(e.requests);
}

std::string_view outcome_text(Outcome o) {
    switch (o) {
    case Outcome::done:
        return "done";
    case Outcome::fails:
        return "fails";
    case Outcome::expires:
        return "expires";
    }
    return "done";
}

// ---------------------------------------------------------------------------
// Generating the source.

struct Writer {
    std::string source;
    std::vector<std::string> paths;

    void line(std::size_t depth, const std::string& text, std::string path) {
        source.append(depth * 2, ' ');
        source += text;
        source += '\n';
        paths.push_back(std::move(path));
    }
    void blank() {
        if (!paths.empty() && !paths.back().empty()) {
            source += '\n';
            paths.emplace_back();
        }
    }
};

std::string joined(const std::vector<Text>& items, std::string_view separator) {
    std::string out;
    for (const Text& t : items) {
        out += (out.empty() ? "" : std::string(separator)) + t;
    }
    return out;
}

std::string assigns_text(const std::vector<Assign>& items) {
    std::string out;
    for (const Assign& a : items) {
        out += (out.empty() ? "" : ", ") + a.name + " = " + a.value;
    }
    return out;
}

std::string line_text(const Line& l) {
    std::string out = l.name;
    if (!l.type.empty()) {
        out += " " + l.type;
    }
    if (l.initial) {
        out += " = " + *l.initial;
    }
    return out;
}

void effects_lines(Writer& w, const Effects& e, const std::string& path) {
    if (e.to_state) {
        w.line(1,
               (e.from.empty() ? std::string() : joined(e.from, ", ") + " ") + "-> " + *e.to_state,
               at(path, "to_state"));
    }
    for (std::size_t i = 0; i < e.set.size(); ++i) {
        w.line(1, e.set[i].name + " = " + e.set[i].value, at(at(path, "set"), i));
    }
    for (std::size_t i = 0; i < e.requests.size(); ++i) {
        const Request& r = e.requests[i];
        std::string text = "request " + r.kind;
        if (r.to) {
            text += " to " + *r.to;
        }
        if (!r.with.empty()) {
            text += " with " + assigns_text(r.with);
        }
        text += " " + r.within;
        w.line(1, text, at(at(path, "requests"), i));
    }
}

// ---------------------------------------------------------------------------
// Reading a tree back.

struct Misfit {
    std::string reason;
    Span span;
};

[[noreturn]] void misfit(std::string reason, const Span& span) {
    throw Misfit{std::move(reason), span};
}

struct Back {
    std::string_view source;

    [[nodiscard]] Text text(const Span& span) const {
        return Text(source.substr(span.offset, span.length));
    }
    /// An expression's text: its span, widened to the parentheses it opens
    /// or closes (`(monthly 5) = 0` spans from `monthly`).
    [[nodiscard]] Text text(const ast::Expr& e) const {
        std::size_t begin = e.span.offset;
        std::size_t end = static_cast<std::size_t>(e.span.offset) + e.span.length;
        constexpr std::string_view open_wide = "\uFF08";
        constexpr std::string_view close_wide = "\uFF09";
        for (int guard = 0; guard < 256; ++guard) {
            int depth = 0;
            int lowest = 0;
            bool quoted = false;
            for (std::size_t i = begin; i < end; ++i) {
                const std::string_view rest = source.substr(i);
                if (source[i] == '"') {
                    quoted = !quoted;
                } else if (!quoted && (source[i] == '(' || rest.starts_with(open_wide))) {
                    ++depth;
                } else if (!quoted && (source[i] == ')' || rest.starts_with(close_wide))) {
                    lowest = std::min(lowest, --depth);
                }
            }
            if (lowest < 0) {
                // A parenthesis closes one opened before: take the opening.
                std::size_t i = begin;
                while (i > 0 && source[i - 1] == ' ') {
                    --i;
                }
                if (i > 0 && source[i - 1] == '(') {
                    begin = i - 1;
                } else if (i >= open_wide.size() &&
                           source.substr(i - open_wide.size(), open_wide.size()) == open_wide) {
                    begin = i - open_wide.size();
                } else {
                    break;
                }
            } else if (depth > lowest) {
                // One opened and not closed: take the closing.
                std::size_t i = end;
                while (i < source.size() && source[i] == ' ') {
                    ++i;
                }
                if (i < source.size() && source[i] == ')') {
                    end = i + 1;
                } else if (source.substr(i).starts_with(close_wide)) {
                    end = i + close_wide.size();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        return Text(source.substr(begin, end - begin));
    }
    [[nodiscard]] std::optional<Text> text(const std::optional<ast::Expr>& e) const {
        return e ? std::optional(text(*e)) : std::nullopt;
    }
    /// The words before `name` on its clause's line (a kind's word).
    [[nodiscard]] Text before(const Span& clause, const Span& name) const {
        std::string_view t = source.substr(clause.offset, name.offset - clause.offset);
        while (!t.empty() && t.back() == ' ') {
            t.remove_suffix(1);
        }
        return Text(t);
    }
    /// An expectation's text after its arrow.
    [[nodiscard]] Text after_arrow(const Span& span) const {
        std::string_view t = source.substr(span.offset, span.length);
        if (t.starts_with("->")) {
            t.remove_prefix(2);
        } else if (t.starts_with("→")) {
            t.remove_prefix(std::string_view("→").size());
        }
        while (!t.empty() && t.front() == ' ') {
            t.remove_prefix(1);
        }
        return Text(t);
    }

    [[nodiscard]] Line line(const ast::Field& f) const {
        if (f.values.size() > 1) {
            misfit("a line with several parts (labelled prices) does not fit the form", f.span);
        }
        return {text(f.head), f.values.empty() ? Text() : text(f.values.front()),
                f.initial ? std::optional(text(*f.initial)) : std::nullopt};
    }
    [[nodiscard]] std::vector<Assign> assigns(const std::vector<ast::Set>& sets) const {
        std::vector<Assign> out;
        for (const ast::Set& s : sets) {
            out.push_back({text(s.target), text(s.value)});
        }
        return out;
    }
    [[nodiscard]] Request request(const ast::Request& r) const {
        if (!r.within) {
            misfit("a request without its deadline", r.span);
        }
        return {text(r.kind), text(r.to), assigns(r.with), text(*r.within)};
    }
    [[nodiscard]] std::vector<Text> actions(const std::vector<ast::Do>& done) const {
        std::vector<Text> out;
        for (const ast::Do& d : done) {
            if (d.subject || !d.args.empty() || d.to || d.by || !d.with.empty()) {
                misfit("an action done with a party, arguments, or values does not fit the form",
                       d.span);
            }
            out.push_back(text(d.action));
        }
        return out;
    }

    /// A block of effects only: the state change, the fields set, the
    /// requests, in that order.
    [[nodiscard]] Effects effects(const std::vector<ast::Statement>& body, int phase) const {
        Effects e;
        for (const ast::Statement& s : body) {
            if (const auto* t = std::get_if<ast::Transition>(&s.node)) {
                if (phase > 0) {
                    misfit("the state change comes first, before the fields set and the requests",
                           t->span);
                }
                for (const ast::Expr& from : t->from) {
                    e.from.push_back(text(from));
                }
                e.to_state = text(t->to);
                phase = 1;
            } else if (const auto* set = std::get_if<ast::Set>(&s.node)) {
                if (phase > 1) {
                    misfit("fields are set before the requests", set->span);
                }
                e.set.push_back({text(set->target), text(set->value)});
                phase = 1;
            } else if (const auto* r = std::get_if<ast::Request>(&s.node)) {
                e.requests.push_back(request(*r));
                phase = 2;
            } else {
                std::visit(
                    [](const auto& node) {
                        misfit("a choice, a loop, a refusal, or an action done here does not fit "
                               "the form",
                               node.span);
                    },
                    s.node);
            }
        }
        return e;
    }
};

const Concept* concept_named(std::string_view id) {
    return find_concept(id);
}

bool is_word(const ast::Expr& e, const Concept* c) {
    return e.kind == ast::ExprKind::word && e.concept_entry == c;
}

std::optional<Outcome> outcome_concept(const Concept* c) {
    if (c == concept_named("kw.done")) {
        return Outcome::done;
    }
    if (c == concept_named("kw.fails")) {
        return Outcome::fails;
    }
    if (c == concept_named("kw.expires")) {
        return Outcome::expires;
    }
    return std::nullopt;
}

Action read_can(const Back& back, const ast::Can& can) {
    Action a;
    a.action = back.text(can.action);
    a.by = back.text(can.by);
    a.to = back.text(can.to);
    for (const ast::Field& f : can.inputs) {
        if (f.initial) {
            misfit("an input has no default", f.span);
        }
        a.inputs.push_back(back.line(f));
    }
    const Concept* consent = concept_named("cond.consent_of");
    const Concept* in_person = concept_named("cond.in_person");
    const Concept* ai_agent = concept_named("actor.ai_agent");
    const Concept* propose = concept_named("act.propose");
    // The requirements' order: plain, consents, presence, then a threshold's
    // presence, then what AI agents may do; then the effects.
    int phase = 0;
    std::size_t effects_from = can.body.size();
    for (std::size_t i = 0; i < can.body.size(); ++i) {
        const ast::Statement& s = can.body[i];
        auto order = [&](int next, const Span& span) {
            if (next < phase) {
                misfit("requirements come in the form's order: conditions, consents, presence, "
                       "what AI agents may do",
                       span);
            }
            phase = next;
        };
        if (const auto* r = std::get_if<ast::Requires>(&s.node)) {
            const bool consent_line = r->condition.kind == ast::ExprKind::apply &&
                                      r->condition.concept_entry == consent &&
                                      r->condition.operands.size() == 1;
            const bool person = is_word(r->condition, in_person);
            if (r->guard) {
                if (!person || a.in_person_over) {
                    misfit("a requirement with a guard fits the form only as a threshold for "
                           "presence, once",
                           r->span);
                }
                order(3, r->span);
                a.in_person_over = back.text(*r->guard);
            } else if (person) {
                if (a.in_person) {
                    misfit("presence is required once", r->span);
                }
                order(2, r->span);
                a.in_person = true;
            } else if (consent_line) {
                order(1, r->span);
                a.consent_of.push_back(back.text(r->condition.operands.front()));
            } else {
                order(0, r->span);
                a.requires_.push_back(back.text(r->condition));
            }
        } else if (const auto* p = std::get_if<ast::Permit>(&s.node)) {
            if (!is_word(p->who, ai_agent) || !is_word(p->action, propose) || a.agents_propose) {
                misfit("of who may do what, the form holds only: AI agent can propose", p->span);
            }
            order(4, p->span);
            a.agents_propose = true;
        } else {
            effects_from = i;
            break;
        }
    }
    a.effects = back.effects(
        std::vector<ast::Statement>(can.body.begin() + static_cast<std::ptrdiff_t>(effects_from),
                                    can.body.end()),
        0);
    return a;
}

Test read_test(const Back& back, const ast::Test& test) {
    Test t;
    t.name = back.text(test.name);
    for (const ast::Statement& s : test.steps) {
        if (const auto* d = std::get_if<ast::Do>(&s.node)) {
            Step step;
            if (!d->subject) {
                misfit("a step names its party", d->span);
            }
            step.party = back.text(*d->subject);
            step.action = back.text(d->action);
            if (d->outcome != nullptr) {
                step.outcome = outcome_concept(d->outcome);
            }
            for (const ast::Expr& arg : d->args) {
                step.args.push_back(back.text(arg));
            }
            step.to = back.text(d->to);
            step.by = back.text(d->by);
            step.with = back.assigns(d->with);
            t.steps.push_back(std::move(step));
        } else if (const auto* e = std::get_if<ast::Expect>(&s.node)) {
            if (t.steps.empty() || t.steps.back().expect) {
                misfit("an expectation follows its step", e->span);
            }
            t.steps.back().expect = back.after_arrow(e->span);
        } else {
            std::visit([](const auto& node) { misfit("a test holds steps only", node.span); },
                       s.node);
        }
    }
    return t;
}

} // namespace

std::variant<Sheet, SheetError> parse_sheet(std::string_view json) {
    const Json j = Json::parse(json.begin(), json.end(), nullptr, false);
    if (j.is_discarded()) {
        return SheetError{"", "the sheet is not JSON"};
    }
    try {
        return read(j);
    } catch (const Failure& f) {
        return SheetError{f.path.empty() ? "/" : f.path, f.message};
    }
}

std::string sheet_json(const Sheet& sheet) {
    Json out;
    out["sheet"] = sheet_version;
    out["kind"] = "rules";
    out["contract"] = sheet.contract;
    out["packs"] = sheet.packs;
    out["parties"] = sheet.parties;
    if (!sheet.kind_name.empty()) {
        out["thing"] = {{"word", sheet.kind_word},
                        {"name", sheet.kind_name},
                        {"fields", lines_json(sheet.fields)}};
    } else {
        out["thing"] = nullptr;
    }
    Json actions = Json::array();
    for (const Action& a : sheet.actions) {
        Json item{{"action", a.action},
                  {"by", optional_json(a.by)},
                  {"to", optional_json(a.to)},
                  {"inputs", lines_json(a.inputs)},
                  {"requires", a.requires_},
                  {"consent_of", a.consent_of},
                  {"in_person", a.in_person},
                  {"in_person_over", optional_json(a.in_person_over)},
                  {"agents_propose", a.agents_propose}};
        effects_json(item, a.effects);
        actions.push_back(std::move(item));
    }
    out["actions"] = std::move(actions);
    Json rules = Json::array();
    for (const Rule& r : sheet.rules) {
        Json item{{"when", r.when}, {"do", r.act}};
        effects_json(item, r.effects);
        rules.push_back(std::move(item));
    }
    out["rules"] = std::move(rules);
    Json answers = Json::array();
    for (const Answer& a : sheet.answers) {
        Json item{{"kind", a.kind}, {"outcome", outcome_text(a.outcome)}, {"do", a.act}};
        effects_json(item, a.effects);
        answers.push_back(std::move(item));
    }
    out["answers"] = std::move(answers);
    Json tests = Json::array();
    for (const Test& t : sheet.tests) {
        Json steps = Json::array();
        for (const Step& s : t.steps) {
            steps.push_back({{"party", s.party},
                             {"action", s.action},
                             {"outcome", s.outcome ? Json(outcome_text(*s.outcome)) : Json()},
                             {"args", s.args},
                             {"to", optional_json(s.to)},
                             {"by", optional_json(s.by)},
                             {"with", assigns_json(s.with)},
                             {"expect", optional_json(s.expect)}});
        }
        tests.push_back({{"name", optional_json(t.name)}, {"steps", std::move(steps)}});
    }
    out["tests"] = std::move(tests);
    return out.dump(2) + "\n";
}

Generated generate(const Sheet& sheet) {
    Writer w;
    for (std::size_t i = 0; i < sheet.packs.size(); ++i) {
        w.line(0, "use " + sheet.packs[i], at("/packs", i));
    }
    w.line(0, "contract " + sheet.contract, "/contract");
    if (!sheet.parties.empty()) {
        w.line(0, "parties " + joined(sheet.parties, ", "), "/parties");
    }
    if (!sheet.kind_name.empty()) {
        w.blank();
        w.line(0, sheet.kind_word + " " + sheet.kind_name, "/thing");
        for (std::size_t i = 0; i < sheet.fields.size(); ++i) {
            w.line(1, line_text(sheet.fields[i]), at("/thing/fields", i));
        }
    }
    if (!sheet.actions.empty()) {
        w.blank();
    }
    for (std::size_t i = 0; i < sheet.actions.size(); ++i) {
        const Action& a = sheet.actions[i];
        const std::string path = at("/actions", i);
        std::string head = "can " + a.action;
        if (a.by) {
            head += " by " + *a.by;
        }
        if (a.to) {
            head += " to " + *a.to;
        }
        if (!a.inputs.empty()) {
            std::string inputs;
            for (const Line& l : a.inputs) {
                inputs += (inputs.empty() ? "" : ", ") + line_text(l);
            }
            head += " with " + inputs;
        }
        w.line(0, head, path);
        for (std::size_t k = 0; k < a.requires_.size(); ++k) {
            w.line(1, "requires " + a.requires_[k], at(at(path, "requires"), k));
        }
        for (std::size_t k = 0; k < a.consent_of.size(); ++k) {
            w.line(1, "requires consent of " + a.consent_of[k], at(at(path, "consent_of"), k));
        }
        if (a.in_person) {
            w.line(1, "requires in person", at(path, "in_person"));
        }
        if (a.in_person_over) {
            w.line(1, *a.in_person_over + " requires in person", at(path, "in_person_over"));
        }
        if (a.agents_propose) {
            w.line(1, "AI agent can propose", at(path, "agents_propose"));
        }
        effects_lines(w, a.effects, path);
    }
    if (!sheet.rules.empty() || !sheet.answers.empty()) {
        w.blank();
    }
    for (std::size_t i = 0; i < sheet.rules.size(); ++i) {
        const Rule& r = sheet.rules[i];
        const std::string path = at("/rules", i);
        w.line(0, "when " + r.when + (r.act.empty() ? "" : " " + joined(r.act, " and ")), path);
        effects_lines(w, r.effects, path);
    }
    for (std::size_t i = 0; i < sheet.answers.size(); ++i) {
        const Answer& a = sheet.answers[i];
        const std::string path = at("/answers", i);
        w.line(0,
               "when " + a.kind + " " + std::string(outcome_text(a.outcome)) +
                   (a.act.empty() ? "" : " " + joined(a.act, " and ")),
               path);
        effects_lines(w, a.effects, path);
    }
    for (std::size_t i = 0; i < sheet.tests.size(); ++i) {
        const Test& t = sheet.tests[i];
        const std::string path = at("/tests", i);
        w.blank();
        w.line(0, "test" + (t.name ? " " + *t.name : std::string()), path);
        for (std::size_t k = 0; k < t.steps.size(); ++k) {
            const Step& s = t.steps[k];
            std::string text = s.party + " " + s.action;
            if (s.outcome) {
                text += " " + std::string(outcome_text(*s.outcome));
            }
            for (const Text& arg : s.args) {
                text += " " + arg;
            }
            if (s.to) {
                text += " to " + *s.to;
            }
            if (s.by) {
                text += " by " + *s.by;
            }
            if (!s.with.empty()) {
                text += " with " + assigns_text(s.with);
            }
            if (s.expect) {
                text += " -> " + *s.expect;
            }
            w.line(1, text, at(at(path, "steps"), k));
        }
    }
    return {std::move(w.source), std::move(w.paths)};
}

std::variant<Sheet, Unfit> read_sheet(std::string_view source, const ast::File& file) {
    const Back back{source};
    Sheet sheet;
    try {
        if (file.edition != 1) {
            misfit("the form writes edition 1", Span{});
        }
        for (const ast::Use& u : file.uses) {
            sheet.packs.push_back(u.pack);
        }
        // The clauses in the form's order: the contract, the parties, the
        // kind, the actions, the time rules, the rules for answers, tests.
        int order = 0;
        auto next = [&](int clause, const Span& span) {
            if (clause < order) {
                misfit("the clauses come in the form's order: contract, parties, the kind, "
                       "actions, time rules, rules for answers, tests",
                       span);
            }
            order = clause;
        };
        bool named = false;
        for (const ast::Clause& clause : file.clauses) {
            if (const auto* c = std::get_if<ast::Contract>(&clause)) {
                next(0, c->span);
                sheet.contract = back.text(c->name);
                named = true;
            } else if (const auto* p = std::get_if<ast::Parties>(&clause)) {
                next(1, p->span);
                for (const ast::Expr& party : p->parties) {
                    sheet.parties.push_back(back.text(party));
                }
            } else if (const auto* b = std::get_if<ast::Block>(&clause)) {
                next(2, b->span);
                if (!sheet.kind_name.empty()) {
                    misfit("charges and taxes do not fit the form", b->span);
                }
                sheet.kind_word = back.before(b->span, b->name.span);
                sheet.kind_name = back.text(b->name);
                for (const ast::Field& f : b->fields) {
                    sheet.fields.push_back(back.line(f));
                }
            } else if (const auto* can = std::get_if<ast::Can>(&clause)) {
                next(3, can->span);
                sheet.actions.push_back(read_can(back, *can));
            } else if (const auto* when = std::get_if<ast::When>(&clause)) {
                next(4, when->span);
                sheet.rules.push_back({back.text(when->event), back.actions(when->actions),
                                       back.effects(when->body, 0)});
            } else if (const auto* answer = std::get_if<ast::AnswerRule>(&clause)) {
                next(5, answer->span);
                const auto outcome = outcome_concept(answer->outcome);
                if (!outcome) {
                    misfit("a rule for answers says done, fails, or expires", answer->span);
                }
                sheet.answers.push_back({back.text(answer->kind), *outcome,
                                         back.actions(answer->actions),
                                         back.effects(answer->body, 0)});
            } else if (const auto* test = std::get_if<ast::Test>(&clause)) {
                next(6, test->span);
                sheet.tests.push_back(read_test(back, *test));
            }
        }
        if (!named) {
            misfit("a fragment (no contract line) does not fit the form", Span{});
        }
    } catch (const Misfit& m) {
        return Unfit{m.reason, m.span};
    }
    return sheet;
}

} // namespace cexchain::bo::form
