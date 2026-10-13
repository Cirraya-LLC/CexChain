// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Bo source is untrusted: a counterparty may send a contract to check, and a
// deploy carries its source for anyone to rebuild. The input is lexed with
// the official packs and parsed. Properties:
//   - every place in the tree lies in the source, and every expression's
//     node has the operands its kind needs (an argument for a word with an
//     argument, two for a binary operator, two or more for a phrase);
//   - every diagnostic is a known parse.* code (or the truncation note), has
//     a place in the source, is not on a line where the lexer found a
//     problem, and renders in each official language;
//   - parsing again gives the same dump, and the tree's dump has no more
//     lines than the source has tokens (nothing is invented);
//   - the formatter (bo fmt): a source with problems is not formatted; one
//     without is, as written and in an official language chosen by the
//     input's size, unless (in a language) words would read together
//     (fmt.unstable); what it writes reads without problems, parses to the
//     same tree with the same comments, and formats to itself.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>

namespace {

using namespace cexchain;

const bo::PackSet& packs() {
    static const bo::PackSet instance = [] {
        bo::PackSetRead set = bo::make_pack_set({});
        if (!set.set) {
            std::abort();
        }
        return std::move(*set.set);
    }();
    return instance;
}

const bo::Lexicon& lexicon() {
    static const bo::Lexicon instance(packs());
    return instance;
}

/// Formats a source that reads without problems, and checks what it
/// writes.
void format_round_trip(std::string_view source, const bo::Lexed& lexed, const bo::Parsed& parsed,
                       const bo::Pack* language) {
    const bo::Formatted f = bo::format_source(source, packs(), lexicon(), language);
    if (!f.source) {
        // Only words that would read together in a language stop it.
        if (language == nullptr || f.diagnostics.empty()) {
            std::abort();
        }
        for (const bo::Diagnostic& d : f.diagnostics) {
            if (d.code != "fmt.unstable") {
                std::abort();
            }
        }
        return;
    }
    const bo::Lexed again = bo::lex(*f.source, lexicon());
    const bo::Parsed reparsed = bo::parse(*f.source, again);
    if (bo::has_errors(again.diagnostics) || !reparsed.diagnostics.empty() ||
        bo::dump(reparsed.file) != bo::dump(parsed.file) ||
        again.comments.size() != lexed.comments.size()) {
        std::abort();
    }
    const bo::Formatted twice = bo::format_source(*f.source, packs(), lexicon(), language);
    if (twice.source != f.source) {
        std::abort();
    }
}

template <class... F>
struct Overloaded : F... {
    using F::operator()...;
};

class Checker {
public:
    explicit Checker(std::string_view source) : source_(source) {}

    void place(const bo::Span& span) const {
        if (span.line == 0 || std::size_t{span.offset} + span.length > source_.size()) {
            std::abort();
        }
    }

    void expr(const bo::ast::Expr& e, std::size_t depth) const {
        // Nesting is bounded by the parser; twice the limit leaves room for
        // statements around an expression.
        if (depth > 2 * bo::max_parse_depth + 8) {
            std::abort();
        }
        place(e.span);
        const std::size_t n = e.operands.size();
        bool shaped = true;
        switch (e.kind) {
        case bo::ast::ExprKind::literal:
        case bo::ast::ExprKind::name:
            shaped = n == 0;
            break;
        case bo::ast::ExprKind::word:
            shaped = n == 0 && e.concept_entry != nullptr;
            break;
        case bo::ast::ExprKind::apply:
            shaped = n == 1 && e.concept_entry != nullptr && e.concept_entry->arity == 1;
            break;
        case bo::ast::ExprKind::phrase:
        case bo::ast::ExprKind::list:
            shaped = n >= 2;
            break;
        case bo::ast::ExprKind::unary:
            shaped = n == 1 && e.op == bo::ast::Operator::logical_not;
            break;
        case bo::ast::ExprKind::binary:
            shaped =
                n == 2 && e.op != bo::ast::Operator::none && e.op != bo::ast::Operator::logical_not;
            break;
        }
        if (!shaped) {
            std::abort();
        }
        for (const bo::ast::Expr& o : e.operands) {
            expr(o, depth + 1);
        }
    }

    void action(const bo::ast::Do& d, std::size_t depth) const {
        place(d.span);
        if (d.subject) {
            expr(*d.subject, depth + 1);
        }
        expr(d.action, depth + 1);
        for (const bo::ast::Expr& a : d.args) {
            expr(a, depth + 1);
        }
        if (d.to) {
            expr(*d.to, depth + 1);
        }
        if (d.by) {
            expr(*d.by, depth + 1);
        }
        for (const bo::ast::Set& s : d.with) {
            place(s.span);
            expr(s.target, depth + 1);
            expr(s.value, depth + 1);
        }
    }

    void statements(const std::vector<bo::ast::Statement>& list, std::size_t depth) const {
        for (const bo::ast::Statement& s : list) {
            statement(s, depth);
        }
    }

    void statement(const bo::ast::Statement& s, std::size_t depth) const {
        std::visit(Overloaded{
                       [&](const bo::ast::Requires& r) {
                           place(r.span);
                           expr(r.condition, depth + 1);
                           if (r.guard) {
                               expr(*r.guard, depth + 1);
                           }
                       },
                       [&](const bo::ast::Permit& p) {
                           place(p.span);
                           expr(p.who, depth + 1);
                           expr(p.action, depth + 1);
                       },
                       [&](const bo::ast::If& i) {
                           place(i.span);
                           expr(i.condition, depth + 1);
                           statements(i.then, depth + 1);
                           statements(i.otherwise, depth + 1);
                       },
                       [&](const bo::ast::Each& e) {
                           place(e.span);
                           expr(e.name, depth + 1);
                           expr(e.list, depth + 1);
                           statements(e.body, depth + 1);
                       },
                       [&](const bo::ast::Reject& r) { place(r.span); },
                       [&](const bo::ast::Set& st) {
                           place(st.span);
                           expr(st.target, depth + 1);
                           expr(st.value, depth + 1);
                       },
                       [&](const bo::ast::Transition& t) {
                           place(t.span);
                           for (const bo::ast::Expr& f : t.from) {
                               expr(f, depth + 1);
                           }
                           expr(t.to, depth + 1);
                       },
                       [&](const bo::ast::Do& d) { action(d, depth); },
                       [&](const bo::ast::Expect& e) {
                           place(e.span);
                           expr(e.outcome, depth + 1);
                       },
                   },
                   s.node);
    }

    void clause(const bo::ast::Clause& c) const {
        std::visit(Overloaded{
                       [&](const bo::ast::Contract& k) {
                           place(k.span);
                           expr(k.name, 1);
                       },
                       [&](const bo::ast::Parties& p) {
                           place(p.span);
                           for (const bo::ast::Expr& e : p.parties) {
                               expr(e, 1);
                           }
                       },
                       [&](const bo::ast::Block& b) {
                           place(b.span);
                           expr(b.name, 1);
                           for (const bo::ast::Field& f : b.fields) {
                               place(f.span);
                               expr(f.head, 2);
                               for (const bo::ast::Expr& v : f.values) {
                                   expr(v, 2);
                               }
                           }
                       },
                       [&](const bo::ast::Can& k) {
                           place(k.span);
                           expr(k.action, 1);
                           if (k.by) {
                               expr(*k.by, 1);
                           }
                           if (k.to) {
                               expr(*k.to, 1);
                           }
                           for (const bo::ast::Field& f : k.inputs) {
                               place(f.span);
                               expr(f.head, 2);
                               for (const bo::ast::Expr& v : f.values) {
                                   expr(v, 2);
                               }
                           }
                           statements(k.body, 1);
                       },
                       [&](const bo::ast::When& w) {
                           place(w.span);
                           expr(w.event, 1);
                           for (const bo::ast::Do& d : w.actions) {
                               action(d, 1);
                           }
                           statements(w.body, 1);
                       },
                       [&](const bo::ast::Test& t) {
                           place(t.span);
                           statements(t.steps, 1);
                       },
                   },
                   c);
    }

private:
    std::string_view source_;
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const bo::Lexicon& lx = lexicon();
    const std::string_view source(reinterpret_cast<const char*>(data), size);
    const bo::Lexed lexed = bo::lex(source, lx);
    const bo::Parsed parsed = bo::parse(source, lexed);

    const Checker checker(source);
    for (const bo::ast::Clause& c : parsed.file.clauses) {
        checker.clause(c);
    }
    std::set<std::uint32_t> lexer_lines;
    for (const bo::Diagnostic& d : lexed.diagnostics) {
        lexer_lines.insert(d.span.line);
    }
    for (const bo::Diagnostic& d : parsed.diagnostics) {
        if (bo::find_message(d.code) == nullptr ||
            !(d.code.starts_with("parse.") || d.code == "bo.truncated")) {
            std::abort();
        }
        if (d.code != "bo.truncated") {
            checker.place(d.span);
            if (lexer_lines.contains(d.span.line)) {
                std::abort();
            }
        }
        for (const bo::Pack& language : bo::official_packs()) {
            if (bo::render(d, &language).empty()) {
                std::abort();
            }
        }
    }
    const std::string text = bo::dump(parsed, nullptr);
    if (bo::dump(bo::parse(source, lexed), nullptr) != text) {
        std::abort();
    }
    const std::string tree = bo::dump(parsed.file);
    if (static_cast<std::size_t>(std::ranges::count(tree, '\n')) > lexed.tokens.size() + 1) {
        std::abort();
    }
    if (bo::has_errors(lexed.diagnostics) || !parsed.diagnostics.empty()) {
        if (bo::format_source(source, packs(), lx, nullptr).source.has_value()) {
            std::abort();
        }
        return 0;
    }
    format_round_trip(source, lexed, parsed, nullptr);
    static const bo::Pack* const languages[] = {packs().find("en"), packs().find("zh-Hant-HK"),
                                                packs().find("zh-Hans-CN")};
    format_round_trip(source, lexed, parsed, languages[size % 3]);
    return 0;
}
