// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Bo source is untrusted: a counterparty may send a contract to check, and a
// deploy carries its source for anyone to rebuild. The checker runs on
// whatever the parser accepts; here it runs on every tree, with errors or
// without (the command line checks only trees without errors), so nothing
// the parser builds can upset it. Properties:
//   - every diagnostic is a known check.* code (or the truncation note), has
//     a place in the source (but the fragment's note), and renders in each
//     official language, its types described in words;
//   - the model's places lie in the source; its first state, exactly one, is
//     its first; its states, fields, and parties have distinct keys; every
//     rule it names is a rule of the edition; every type it holds encodes
//     and describes;
//   - checking again gives the same model and the same diagnostics;
//   - the contract text (explain, milestone 8) is written for every model, in
//     each official language: valid UTF-8, every clause in the text, every
//     rule it marks a rule of the edition and explained in its last section,
//     and the same text twice;
//   - test blocks (milestone 10): every step's places lie in the source; a
//     party is a role word, or a name; what a step expects carries what that
//     expectation needs (a state, a reason only with refused); `at` is a
//     date; only the creation word creates; and in a model without errors,
//     every test begins by creating its instance, once.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/core/cbor.hpp>

namespace {

using namespace cexchain;
namespace m = bo::model;

const bo::Lexicon& lexicon() {
    static const bo::Lexicon instance = [] {
        const bo::PackSetRead set = bo::make_pack_set({});
        if (!set.set) {
            std::abort();
        }
        return bo::Lexicon(*set.set);
    }();
    return instance;
}

template <class... F>
struct Overloaded : F... {
    using F::operator()...;
};

class Walker {
public:
    explicit Walker(std::string_view source) : source_(source) {}

    void place(const bo::Span& span) const {
        if (span.line != 0 && std::size_t{span.offset} + span.length > source_.size()) {
            std::abort();
        }
    }

    void rule(std::string_view id) const {
        if (!id.empty() && bo::find_rule(id) == nullptr) {
            std::abort();
        }
    }

    void type(const m::Type& t) const {
        const std::string encoded = bo::encode(t);
        for (const bo::Pack& pack : bo::official_packs()) {
            if (bo::describe_type(encoded, &pack).empty()) {
                std::abort();
            }
        }
    }

    void expr(const m::Expr& e, std::size_t depth) const {
        if (depth > 2 * bo::max_parse_depth + 8) {
            std::abort();
        }
        place(e.span);
        rule(e.rule);
        type(e.type);
        for (const m::Expr& o : e.operands) {
            expr(o, depth + 1);
        }
    }

    void action(const m::Do& d) const {
        place(d.span);
        rule(d.rule);
        if (d.obligation && d.executor) {
            std::abort();
        }
        if (d.subject) {
            expr(*d.subject, 1);
        }
        expr(d.action, 1);
        for (const m::Expr& a : d.args) {
            expr(a, 1);
        }
        for (const m::Set& s : d.with) {
            expr(s.target, 1);
            expr(s.value, 1);
        }
    }

    void statements(const std::vector<m::Statement>& list, std::size_t depth) const {
        if (depth > bo::max_block_depth + bo::max_parse_depth) {
            std::abort();
        }
        for (const m::Statement& s : list) {
            std::visit(Overloaded{
                           [&](const m::Requires& r) {
                               place(r.span);
                               expr(r.condition, 1);
                               if (r.guard) {
                                   expr(*r.guard, 1);
                               }
                           },
                           [&](const m::If& i) {
                               place(i.span);
                               expr(i.condition, 1);
                               statements(i.then, depth + 1);
                               statements(i.otherwise, depth + 1);
                           },
                           [&](const m::Each& e) {
                               place(e.span);
                               expr(e.list, 1);
                               statements(e.body, depth + 1);
                           },
                           [&](const m::Reject& r) { place(r.span); },
                           [&](const m::Set& st) {
                               place(st.span);
                               expr(st.target, 1);
                               expr(st.value, 1);
                           },
                           [&](const m::Transition& t) {
                               place(t.span);
                               for (const m::Expr& f : t.from) {
                                   expr(f, 1);
                               }
                               expr(t.to, 1);
                           },
                           [&](const m::Do& d) { action(d); },
                           [&](const m::Request& r) {
                               place(r.span);
                               // A kind the ledger takes, or an error said so.
                               if (r.kind.empty()) {
                                   std::abort();
                               }
                               if (r.to) {
                                   expr(*r.to, 1);
                               }
                               for (const m::Set& w : r.with) {
                                   expr(w.target, 1);
                                   expr(w.value, 1);
                               }
                               expr(r.within, 1);
                           },
                       },
                       s.node);
        }
    }

    void field(const m::Field& f) const {
        place(f.span);
        rule(f.rule);
        type(f.type);
        if (f.value) {
            expr(*f.value, 1);
        }
        for (const m::Expr& e : f.more) {
            expr(e, 1);
        }
    }

    void model(const m::Model& model) const {
        std::set<std::string> keys;
        for (const m::Party& p : model.parties) {
            place(p.span);
            rule(p.rule);
            if (!keys.insert(m::key(p.role, p.name)).second) {
                std::abort();
            }
        }
        keys.clear();
        for (const m::Field& f : model.fields) {
            field(f);
            if (!keys.insert(m::key(f.word, f.name)).second) {
                std::abort();
            }
        }
        for (const m::Charge& c : model.charges) {
            place(c.span);
            for (const m::ChargeLine& line : c.lines) {
                place(line.span);
                if (line.head == nullptr) {
                    std::abort();
                }
                if (line.argument) {
                    expr(*line.argument, 1);
                }
                for (const m::Expr& v : line.values) {
                    expr(v, 1);
                }
            }
        }
        // One first state, and it comes first.
        keys.clear();
        std::size_t first = 0;
        for (const m::State& s : model.states) {
            place(s.span);
            rule(s.rule);
            first += s.first ? 1U : 0U;
            if (!keys.insert(m::key(s.word, s.name)).second) {
                std::abort();
            }
        }
        if (first != 1 || !model.states.front().first) {
            std::abort();
        }
        for (const m::Action& a : model.actions) {
            place(a.span);
            rule(a.agents_rule);
            rule(a.executor_rule);
            if (a.agents_propose == !a.agents_rule.empty()) {
                std::abort();
            }
            for (const m::Field& f : a.inputs) {
                field(f);
            }
            for (const m::Consent& c : a.consents) {
                rule(c.rule);
                expr(c.party, 1);
            }
            statements(a.body, 1);
        }
        for (const m::TimeRule& r : model.rules) {
            place(r.span);
            expr(r.event, 1);
            for (const m::Do& d : r.actions) {
                action(d);
            }
            statements(r.body, 1);
        }
        for (const m::AnswerRule& r : model.answers) {
            place(r.span);
            rule(r.rule);
            if (r.expired != (r.outcome == m::Outcome::fails && !r.rule.empty())) {
                std::abort();
            }
            statements(r.body, 1);
        }
        rule(model.due_rule);
        for (const m::Test& t : model.tests) {
            test(t);
        }
    }

    /// A party a step names (none, after an error).
    void party(const m::TestParty& p) const {
        place(p.span);
        if (p.word != nullptr && (p.word->category != bo::Category::role || !p.name.empty())) {
            std::abort();
        }
    }

    void test(const m::Test& t) const {
        place(t.span);
        for (const m::Step& s : t.steps) {
            place(s.span);
            place(s.expect_span);
            // The keeper (a device of the home) calls a time rule.
            if (s.keeper) {
                place(s.subject.span);
                if (s.subject.word == nullptr || s.subject.word->id != "actor.keeper" ||
                    s.creation || s.approve) {
                    std::abort();
                }
            } else if (s.answer && s.subject.word != nullptr &&
                       s.subject.word->category == bo::Category::actor) {
                // E8: an answer by the executor or the keeper (the home's
                // devices), of a kind the ledger would take.
                place(s.subject.span);
                if ((s.subject.word->id != "actor.executor" &&
                     s.subject.word->id != "actor.keeper") ||
                    s.creation || s.approve || s.keeper || s.request_kind.empty()) {
                    std::abort();
                }
            } else {
                party(s.subject);
            }
            if (s.to) {
                party(*s.to);
            }
            for (const m::TestParty& p : s.waits) {
                party(p);
            }
            for (const m::Set& w : s.with) {
                expr(w.target, 1);
                expr(w.value, 1);
            }
            if (s.at) {
                expr(*s.at, 1);
                if (s.at->kind != bo::ast::ExprKind::literal ||
                    s.at->literal.kind != bo::ast::LiteralKind::date) {
                    std::abort();
                }
            }
            const bool state = s.expect == m::Expectation::state;
            if (state != (s.state_word != nullptr || !s.state_name.empty()) ||
                (s.state_word != nullptr && !s.state_name.empty()) ||
                (s.reason && s.expect != m::Expectation::refused) ||
                (!s.waits.empty() && s.expect != m::Expectation::waits)) {
                std::abort();
            }
            if (s.creation &&
                (s.word == nullptr || (s.word->id != "act.issue" && s.word->id != "act.create"))) {
                std::abort();
            }
        }
    }

private:
    std::string_view source_;
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view source(reinterpret_cast<const char*>(data), size);
    const bo::Lexed lexed = bo::lex(source, lexicon());
    const bo::Parsed parsed = bo::parse(source, lexed);
    const bo::Checked checked = bo::check(source, parsed.file);

    const Walker walker(source);
    walker.model(checked.model);
    for (const bo::Diagnostic& d : checked.diagnostics) {
        if (bo::find_message(d.code) == nullptr ||
            !(d.code.starts_with("check.") || d.code == "bo.truncated")) {
            std::abort();
        }
        if (d.code != "bo.truncated" && d.code != "check.fragment") {
            if (d.span.line == 0) {
                std::abort();
            }
            walker.place(d.span);
        }
        for (const bo::Pack& language : bo::official_packs()) {
            if (bo::render(d, &language).empty()) {
                std::abort();
            }
        }
    }
    const std::string text = bo::dump(checked, nullptr);
    if (bo::dump(bo::check(source, parsed.file), nullptr) != text) {
        std::abort();
    }
    // A model without errors: every test creates its instance first, once.
    if (!bo::has_errors(lexed.diagnostics) && parsed.diagnostics.empty() &&
        !bo::has_errors(checked.diagnostics)) {
        for (const m::Test& t : checked.model.tests) {
            if (t.steps.empty() || !t.steps.front().creation ||
                std::count_if(t.steps.begin(), t.steps.end(),
                              [](const m::Step& s) { return s.creation; }) != 1) {
                std::abort();
            }
            for (const m::Step& s : t.steps) {
                if (s.subject.word == nullptr && s.subject.name.empty()) {
                    std::abort();
                }
            }
        }
    }
    for (const bo::Pack& language : bo::official_packs()) {
        const bo::Explained e = bo::explain(checked.model, &language);
        if (e.text.empty() || !cbor::is_valid_utf8(e.text) ||
            bo::explain(checked.model, &language).text != e.text) {
            std::abort();
        }
        std::set<std::string_view> marked;
        for (const bo::ExplainedSection& section : e.sections) {
            for (const bo::ExplainedClause& c : section.clauses) {
                if (e.text.find(c.text) == std::string::npos) {
                    std::abort();
                }
                for (const std::string_view r : c.rules) {
                    walker.rule(r);
                    marked.insert(r);
                }
            }
        }
        if (marked.size() != e.rules.size()) {
            std::abort();
        }
        for (const auto& [rule, explanation] : e.rules) {
            if (!marked.contains(rule) || explanation.empty()) {
                std::abort();
            }
        }
    }
    return 0;
}
