// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The standard library of edition 1, compiled in from bo/stdlib/ with #embed
// and read once with the official packs. Like the official packs, it is
// part of the compiler and of edition 1: once released, a template's terms
// never change what an action means; a later edition may add actions.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/stdlib.hpp>
#include <cexchain/bo/values.hpp>

namespace cexchain::bo {

namespace {

#if defined(__clang__)
#pragma clang diagnostic push
// Clang 23 accepts #embed in C++ as an extension of C23's.
#pragma clang diagnostic ignored "-Wc23-extensions"
#endif

constexpr unsigned char edition1_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../stdlib/edition1.bo"
#else
#include "edition1.bo.inc"
#endif
};

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

/// The official packs, together, and their lexicon (which reads the packs
/// in place): read once.
struct Reading {
    explicit Reading(PackSet set) : packs(std::move(set)), lexicon(packs) {}
    PackSet packs;
    Lexicon lexicon;
};

PackSet official_set() {
    PackSetRead set = make_pack_set({});
    if (!set.set) {
        std::fprintf(stderr, "bo: the official packs do not read together\n");
        std::abort();
    }
    return std::move(*set.set);
}

const Reading& official_reading() {
    static const Reading reading(official_set());
    return reading;
}

[[noreturn]] void defect(const char* what) {
    std::fprintf(stderr, "bo: the standard library does not read: %s\n", what);
    std::abort();
}

StandardLibrary read_library() {
    StandardLibrary out;
    out.source =
        std::string_view(reinterpret_cast<const char*>(edition1_bytes), sizeof edition1_bytes);
    const Lexed lexed = lex(out.source, official_reading().lexicon);
    if (has_errors(lexed.diagnostics) || lexed.edition != out.edition) {
        defect("a lexer error");
    }
    out.parsed = parse(out.source, lexed);
    if (has_errors(out.parsed.diagnostics)) {
        defect("a parser error");
    }
    for (const ast::Clause& clause : out.parsed.file.clauses) {
        const auto* can = std::get_if<ast::Can>(&clause);
        if (can == nullptr || can->action.kind != ast::ExprKind::word ||
            can->action.concept_entry == nullptr ||
            can->action.concept_entry->category != Category::action) {
            defect("a clause that is not a built-in action's terms");
        }
        out.templates.push_back(can);
    }
    return out;
}

} // namespace

const ast::Can* StandardLibrary::find(std::string_view action) const noexcept {
    for (const ast::Can* can : templates) {
        if (can->action.concept_entry->id == action) {
            return can;
        }
    }
    return nullptr;
}

const StandardLibrary& standard_library() noexcept {
    // The templates point into `parsed`, whose clauses keep their place when
    // the library is moved into place.
    static const StandardLibrary library = read_library();
    return library;
}

std::string_view standard_showcase() {
    static const std::string showcase = [] {
        std::string out = "contract StandardLibrary\n"
                          "parties we, supplier\n"
                          "\n"
                          "asset Asset\n"
                          "  holder supplier\n"
                          "  quantity item\n"
                          "  cooling period 30 days\n"
                          "\n";
        for (const ast::Can* can : standard_library().templates) {
            const Pack& english = english_pack();
            const Word* word = english.word(can->action.concept_entry->id);
            out += "can " +
                   (word != nullptr && !word->spellings.empty()
                        ? word->spellings.front()
                        : std::string(can->action.concept_entry->id)) +
                   "\n";
        }
        return out;
    }();
    return showcase;
}

const model::Model& standard_model() {
    static const model::Model model = [] {
        const std::string_view source = standard_showcase();
        const Lexed lexed = lex(source, official_reading().lexicon);
        const Parsed parsed = parse(source, lexed);
        Checked checked = check(source, parsed.file);
        if (has_errors(lexed.diagnostics) || has_errors(parsed.diagnostics) ||
            !checked.diagnostics.empty()) {
            defect("the showcase of its actions does not check");
        }
        return std::move(checked.model);
    }();
    return model;
}

std::vector<StandardAction> standard_actions() {
    std::vector<StandardAction> out;
    for (const model::Action& a : standard_model().actions) {
        StandardAction s;
        s.action = a.word;
        s.function = wire_name(a.word, a.name);
        s.starter = a.by ? a.by->concept_entry : nullptr;
        s.counterparty = a.to.has_value();
        if (const auto entry = model::entry_states(a)) {
            // In the order the terms name them.
            std::set<std::string> left = *entry;
            const auto name = [&](const model::Expr& e) {
                const std::string k = model::key(e.concept_entry, e.name);
                if (left.erase(k) > 0) {
                    s.from.push_back(find_concept(k));
                }
            };
            for (const model::Statement& st : a.body) {
                if (const auto* t = std::get_if<model::Transition>(&st.node)) {
                    std::ranges::for_each(t->from, name);
                    break;
                }
                if (const auto* r = std::get_if<model::Requires>(&st.node)) {
                    const auto states = [&](const model::Expr& e, const auto& self) -> void {
                        if (e.refers == model::Refers::state) {
                            name(e);
                        }
                        for (const model::Expr& o : e.operands) {
                            self(o, self);
                        }
                    };
                    states(r->condition, states);
                }
            }
            for (const std::string& k : left) {
                s.from.push_back(find_concept(k));
            }
        }
        std::set<std::string> seen;
        const auto targets = [&](const std::vector<model::Statement>& list,
                                 const auto& self) -> void {
            for (const model::Statement& st : list) {
                if (const auto* t = std::get_if<model::Transition>(&st.node)) {
                    if (t->to.concept_entry != nullptr &&
                        seen.insert(std::string(t->to.concept_entry->id)).second) {
                        s.to.push_back(t->to.concept_entry);
                    }
                } else if (const auto* i = std::get_if<model::If>(&st.node)) {
                    self(i->then, self);
                    self(i->otherwise, self);
                }
            }
        };
        targets(a.body, targets);
        out.push_back(std::move(s));
    }
    return out;
}

const Concept* standard_action(std::string_view word, const PackSet& packs) {
    const StandardLibrary& library = standard_library();
    for (const ast::Can* can : library.templates) {
        if (wire_name(can->action.concept_entry, {}) == word) {
            return can->action.concept_entry;
        }
    }
    const Meaning* meaning = packs.lookup(word);
    if (meaning == nullptr || meaning->concept_entry == nullptr ||
        library.find(meaning->concept_entry->id) == nullptr) {
        return nullptr;
    }
    return meaning->concept_entry;
}

std::optional<std::string> standard_terms_source(const Concept* action, const Pack* language) {
    const StandardLibrary& library = standard_library();
    if (action == nullptr || library.find(action->id) == nullptr) {
        return std::nullopt;
    }
    const Reading& reading = official_reading();
    const Formatted formatted =
        format_source(library.source, reading.packs, reading.lexicon, language);
    if (!formatted.source) {
        return std::nullopt;
    }
    // The clause's line, and the lines of its block after it.
    const std::string& text = *formatted.source;
    const Parsed parsed = parse(text, lex(text, reading.lexicon));
    std::uint32_t first = 0;
    for (const ast::Clause& clause : parsed.file.clauses) {
        if (const auto* can = std::get_if<ast::Can>(&clause);
            can != nullptr && can->action.concept_entry == action) {
            first = can->span.line;
        }
    }
    std::string out;
    std::uint32_t line = 1;
    bool inside = false;
    for (std::size_t at = 0; at < text.size();) {
        const std::size_t end = std::min(text.find('\n', at), text.size());
        const std::string_view row = std::string_view(text).substr(at, end - at);
        if (line == first) {
            inside = true;
        } else if (inside && !row.starts_with(' ')) {
            break;
        }
        if (inside) {
            out += std::string(row) + "\n";
        }
        at = end + 1;
        ++line;
    }
    return out.empty() ? std::nullopt : std::optional<std::string>(out);
}

std::vector<ExplainedClause> standard_terms_text(const Concept* action, const Pack* language) {
    std::vector<ExplainedClause> out;
    if (action == nullptr) {
        return out;
    }
    const std::string function = wire_name(action, {});
    const Explained text = explain(standard_model(), language);
    for (const ExplainedSection& section : text.sections) {
        for (const ExplainedClause& c : section.clauses) {
            // The action's own clauses, not its heading nor the note on
            // its standard terms.
            if (c.function == function && c.kind != "action" && c.kind != "standard") {
                out.push_back(c);
            }
        }
    }
    return out;
}

} // namespace cexchain::bo
