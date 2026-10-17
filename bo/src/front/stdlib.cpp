// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The standard library of edition 1: the core's terms, compiled in from
// bo/stdlib/core.bo with #embed, then the official vocabulary packs' (D-054),
// from their files (bo/vocab/) and read once with the
// official packs. Like the official packs, it is
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
#include <cexchain/bo/vocab.hpp>

#include "internal.hpp"

namespace cexchain::bo {

namespace {

#if defined(__clang__)
#pragma clang diagnostic push
// Clang 23 accepts #embed in C++ as an extension of C23's.
#pragma clang diagnostic ignored "-Wc23-extensions"
#endif

constexpr unsigned char core_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../stdlib/core.bo"
#else
#include "core.bo.inc"
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

std::string_view as_text(std::span<const unsigned char> bytes) noexcept {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

StandardLibrary read_library() {
    StandardLibrary out;
    for (const Vocab pack : {Vocab::core, Vocab::finance, Vocab::services}) {
        StandardFile& file = out.files.emplace_back();
        file.pack = pack;
        file.source = standard_source(pack);
        const Lexed lexed = lex(file.source, official_reading().lexicon);
        if (has_errors(lexed.diagnostics) || lexed.edition != out.edition) {
            defect("a lexer error");
        }
        file.parsed = parse(file.source, lexed);
        if (has_errors(file.parsed.diagnostics)) {
            defect("a parser error");
        }
        // A pack's file uses its pack, the core's none.
        const bool uses = pack == Vocab::core
                              ? file.parsed.file.uses.empty()
                              : file.parsed.file.uses.size() == 1 &&
                                    file.parsed.file.uses[0].pack == vocab_name(pack);
        if (!uses) {
            defect("a file that does not use its own pack");
        }
    }
    // The templates point into the files' trees, which keep their place now
    // that every file is read.
    for (const StandardFile& file : out.files) {
        for (const ast::Clause& clause : file.parsed.file.clauses) {
            const auto* can = std::get_if<ast::Can>(&clause);
            if (can == nullptr || can->action.kind != ast::ExprKind::word ||
                can->action.concept_entry == nullptr ||
                can->action.concept_entry->category != Category::action ||
                can->action.concept_entry->pack != file.pack) {
                defect("a clause that is not the terms of one of its own pack's actions");
            }
            out.templates.push_back(can);
        }
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

std::string_view StandardLibrary::source_of(const Concept* action) const noexcept {
    if (action == nullptr) {
        return {};
    }
    for (const StandardFile& file : files) {
        if (file.pack == action->pack) {
            return file.source;
        }
    }
    return {};
}

std::string_view standard_source(const Vocab pack) noexcept {
    if (pack == Vocab::core) {
        return as_text(core_bytes);
    }
    // A vocabulary pack's terms are in its file (bo/vocab/).
    const VocabularyPack* vocabulary = vocabulary_pack(pack);
    return vocabulary == nullptr ? std::string_view() : std::string_view(vocabulary->terms);
}

const StandardLibrary& standard_library() noexcept {
    // The templates point into `parsed`, whose clauses keep their place when
    // the library is moved into place.
    static const StandardLibrary library = read_library();
    return library;
}

const ast::Can* UserTerms::find(std::string_view action) const noexcept {
    for (const ast::Can* can : templates) {
        if (can->action.concept_entry->id == action) {
            return can;
        }
    }
    return nullptr;
}

std::string_view UserTerms::source_of(const Concept* action) const noexcept {
    if (action == nullptr) {
        return {};
    }
    for (const StandardFile& file : files) {
        if (file.owner == action->owner) {
            return file.source;
        }
    }
    return {};
}

const ast::Can* find_terms(const Concept* action, const Vocabularies* vocabularies) {
    if (action == nullptr) {
        return nullptr;
    }
    if (action->pack == Vocab::user) {
        return vocabularies != nullptr && vocabularies->terms != nullptr
                   ? vocabularies->terms->find(action->id)
                   : nullptr;
    }
    return standard_library().find(action->id);
}

std::string_view terms_source(const Concept* action, const Vocabularies* vocabularies) {
    if (action != nullptr && action->pack == Vocab::user) {
        return vocabularies != nullptr && vocabularies->terms != nullptr
                   ? vocabularies->terms->source_of(action)
                   : std::string_view();
    }
    return standard_library().source_of(action);
}

namespace detail {

std::shared_ptr<const UserTerms> read_user_terms(const PackSet& set,
                                                 std::span<const VocabularyHandle> users,
                                                 Diagnostics& diagnostics) {
    auto out = std::make_shared<UserTerms>();
    out->packs.assign(users.begin(), users.end());
    const Lexicon lexicon(set);
    for (const VocabularyHandle& pack : users) {
        if (pack->terms.empty()) {
            continue;
        }
        const auto problem = [&](std::uint32_t line, std::string_view code) {
            diagnostics.add(
                "vocab.terms",
                {{"pack", pack->id}, {"line", std::to_string(line)}, {"code", std::string(code)}});
        };
        StandardFile file;
        file.pack = Vocab::user;
        file.owner = pack.get();
        file.source = pack->terms;
        const Lexed lexed = lex(file.source, lexicon);
        const auto first_error = [](const std::vector<Diagnostic>& list) -> const Diagnostic* {
            const auto it = std::ranges::find_if(
                list, [](const Diagnostic& d) { return d.severity() == Severity::error; });
            return it == list.end() ? nullptr : &*it;
        };
        if (const Diagnostic* d = first_error(lexed.diagnostics)) {
            problem(d->span.line, d->code);
            continue;
        }
        file.parsed = parse(file.source, lexed);
        if (const Diagnostic* d = first_error(file.parsed.diagnostics)) {
            problem(d->span.line, d->code);
            continue;
        }
        // The terms use the pack, and only the packs it requires besides;
        // their words are the core's, the pack's, and those packs'.
        bool ok = true;
        const auto allowed = [&](std::string_view id) {
            return id == pack->id || std::ranges::contains(pack->required, id);
        };
        bool own = false;
        for (const ast::Use& u : file.parsed.file.uses) {
            own = own || u.pack == pack->id;
            if (!allowed(u.pack)) {
                problem(u.span.line, "check.unknown-pack");
                ok = false;
            }
        }
        for (const ast::PackWord& w : file.parsed.file.pack_words) {
            if (!allowed(pack_of(*w.concept_entry)) ||
                (pack_of(*w.concept_entry) == pack->id && !own)) {
                problem(w.span.line, "check.pack-not-used");
                ok = false;
            }
        }
        // Each clause the terms of one of the pack's actions, once.
        std::set<const Concept*> seen;
        for (const ast::Clause& clause : file.parsed.file.clauses) {
            const auto* can = std::get_if<ast::Can>(&clause);
            const Concept* action = can != nullptr && can->action.kind == ast::ExprKind::word
                                        ? can->action.concept_entry
                                        : nullptr;
            if (action == nullptr || action->category != Category::action ||
                action->owner != pack.get() || !seen.insert(action).second) {
                const std::uint32_t line =
                    std::visit([](const auto& node) { return node.span.line; }, clause);
                diagnostics.add("vocab.terms-clause",
                                {{"pack", pack->id}, {"line", std::to_string(line)}});
                ok = false;
            }
        }
        if (ok) {
            out->files.push_back(std::move(file));
        }
    }
    // The templates point into the files' trees, which keep their place now
    // that every file is read.
    for (const StandardFile& file : out->files) {
        for (const ast::Clause& clause : file.parsed.file.clauses) {
            out->templates.push_back(&std::get<ast::Can>(clause));
        }
    }
    return out;
}

} // namespace detail

std::string_view standard_showcase() {
    static const std::string showcase = [] {
        std::string out = "use finance\n"
                          "use services\n"
                          "contract StandardLibrary\n"
                          "parties we, supplier\n"
                          "\n"
                          "asset Asset\n"
                          "  holder supplier\n"
                          "  amount HKD\n"
                          "  tier number\n"
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

std::vector<StandardAction> user_actions(const PackSet& set) {
    std::vector<StandardAction> out;
    const auto& terms = set.vocabularies().terms;
    if (terms == nullptr) {
        return out;
    }
    for (const ast::Can* can : terms->templates) {
        StandardAction s;
        s.action = can->action.concept_entry;
        s.function = wire_name(s.action, {});
        s.starter =
            can->by && can->by->kind == ast::ExprKind::word ? can->by->concept_entry : nullptr;
        s.counterparty = can->to.has_value();
        bool first = true;
        const auto walk = [&](const std::vector<ast::Statement>& list, const auto& self) -> void {
            for (const ast::Statement& st : list) {
                if (const auto* t = std::get_if<ast::Transition>(&st.node)) {
                    if (first) {
                        for (const ast::Expr& e : t->from) {
                            if (e.concept_entry != nullptr) {
                                s.from.push_back(e.concept_entry);
                            }
                        }
                        first = false;
                    }
                    if (t->to.concept_entry != nullptr &&
                        !std::ranges::contains(s.to, t->to.concept_entry)) {
                        s.to.push_back(t->to.concept_entry);
                    }
                } else if (const auto* i = std::get_if<ast::If>(&st.node)) {
                    self(i->then, self);
                    self(i->otherwise, self);
                }
            }
        };
        walk(can->body, walk);
        out.push_back(std::move(s));
    }
    return out;
}

std::optional<std::string> user_terms_source(const Concept* action, const PackSet& set,
                                             const Pack* language) {
    const auto& terms = set.vocabularies().terms;
    if (action == nullptr || terms == nullptr || terms->find(action->id) == nullptr) {
        return std::nullopt;
    }
    const Lexicon lexicon(set);
    const Formatted formatted = format_source(terms->source_of(action), set, lexicon, language);
    if (!formatted.source) {
        return std::nullopt;
    }
    const std::string& text = *formatted.source;
    const Parsed parsed = parse(text, lex(text, lexicon));
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

const Concept* standard_action(std::string_view word, const PackSet& packs) {
    const StandardLibrary& library = standard_library();
    for (const ast::Can* can : library.templates) {
        if (wire_name(can->action.concept_entry, {}) == word) {
            return can->action.concept_entry;
        }
    }
    // A user's pack's action, by its function or its word.
    const Vocabularies* vocabularies = &packs.vocabularies();
    if (vocabularies->terms != nullptr) {
        for (const ast::Can* can : vocabularies->terms->templates) {
            if (wire_name(can->action.concept_entry, {}) == word) {
                return can->action.concept_entry;
            }
        }
    }
    const Meaning* meaning = packs.lookup(word);
    if (meaning == nullptr || meaning->concept_entry == nullptr ||
        find_terms(meaning->concept_entry, vocabularies) == nullptr) {
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
        format_source(library.source_of(action), reading.packs, reading.lexicon, language);
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
