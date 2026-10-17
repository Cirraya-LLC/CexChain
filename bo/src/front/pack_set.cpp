// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Pack sets: the packs one source is read with, and the never-guess checks
// across them (one spelling, one meaning; no word an attaching rule could
// split).

#include <algorithm>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/vocab.hpp>

#include "internal.hpp"

namespace cexchain::bo {

namespace detail {

namespace {

bool same_meaning(const Meaning& a, const Meaning& b) noexcept {
    if (a.kind != b.kind) {
        return false;
    }
    switch (a.kind) {
    case MeaningKind::word:
        return a.concept_entry == b.concept_entry;
    case MeaningKind::multiplier:
        return a.multiplier == b.multiplier;
    case MeaningKind::punctuation:
        return a.punctuation == b.punctuation;
    }
    return false;
}

void add(std::map<std::string, Meaning, std::less<>>& index, const std::string& spelling,
         Meaning meaning, Diagnostics& diagnostics) {
    const auto [it, inserted] = index.try_emplace(spelling, meaning);
    if (inserted || same_meaning(it->second, meaning)) {
        return;
    }
    if (it->second.pack == meaning.pack) {
        diagnostics.add("pack.duplicate-spelling", {{"pack", meaning.pack},
                                                    {"spelling", quote(spelling)},
                                                    {"concept", describe(it->second)},
                                                    {"other", describe(meaning)}});
        return;
    }
    diagnostics.add("pack.conflict", {{"spelling", quote(spelling)},
                                      {"pack", it->second.pack},
                                      {"meaning", describe(it->second)},
                                      {"other_pack", meaning.pack},
                                      {"other", describe(meaning)}});
}

/// A word that attaches to its neighbour: before words of `before`, after
/// words of `after`.
struct Rule {
    std::string piece;
    std::vector<Category> before;
    std::vector<Category> after;
};

bool operator==(const Rule& a, const Rule& b) noexcept {
    return a.piece == b.piece && a.before == b.before && a.after == b.after;
}

/// Adds a rule unless the same one is there (two packs may share it: 可).
void add_rule(std::vector<Rule>& rules, Rule rule) {
    if (std::ranges::find(rules, rule) == rules.end()) {
        rules.push_back(std::move(rule));
    }
}

std::vector<Rule> attaching_rules(std::span<const Pack* const> packs) {
    std::vector<Category> vocabulary;
    for (std::size_t i = 0; i < category_names.size(); ++i) {
        if (static_cast<Category>(i) != Category::keyword) {
            vocabulary.push_back(static_cast<Category>(i));
        }
    }
    std::vector<Rule> rules;
    for (const Pack* pack : packs) {
        // Prefixes attach to any vocabulary word (and, as the lexer will
        // check, to names the contract declares).
        for (const std::string& id : pack->reading.prefixes) {
            if (const Word* word = pack->word(id)) {
                for (const std::string& spelling : word->spellings) {
                    add_rule(rules, {spelling, vocabulary, {}});
                }
            }
        }
        for (const Attachment& attachment : pack->reading.attach) {
            if (const Word* word = pack->word(attachment.word)) {
                for (const std::string& spelling : word->spellings) {
                    for (const std::string_view part : split_words(spelling)) {
                        if (part != hole) {
                            add_rule(rules,
                                     {std::string(part), attachment.before, attachment.after});
                        }
                    }
                }
            }
        }
    }
    return rules;
}

} // namespace

void index_spellings(std::span<const Pack* const> packs,
                     std::map<std::string, Meaning, std::less<>>& index, Diagnostics& diagnostics,
                     const Vocabularies* users) {
    for (const Pack* pack : packs) {
        for (const auto* words : {&pack->keywords, &pack->vocabulary}) {
            for (const auto& [id, word] : *words) {
                const Concept* entry = find_concept(id);
                if (entry == nullptr && users != nullptr) {
                    entry = users->find_concept(id);
                }
                BO_ASSERT(entry != nullptr);
                for (const std::string& spelling : word.spellings) {
                    add(index, spelling, Meaning{MeaningKind::word, entry, {}, 0, 0, pack->id},
                        diagnostics);
                }
                for (const auto& [form, spelling] : word.forms) {
                    add(index, spelling, Meaning{MeaningKind::word, entry, form, 0, 0, pack->id},
                        diagnostics);
                }
            }
        }
        for (const auto& [spelling, value] : pack->reading.multipliers) {
            add(index, spelling, Meaning{MeaningKind::multiplier, nullptr, {}, value, 0, pack->id},
                diagnostics);
        }
        for (const auto& [character, ascii] : pack->reading.punctuation) {
            add(index, character,
                Meaning{MeaningKind::punctuation, nullptr, {}, 0, ascii, pack->id}, diagnostics);
        }
    }

    // A word that is also an attaching word joined to another word could be
    // read two ways: refuse it here, once, rather than in every source.
    const std::vector<Rule> rules = attaching_rules(packs);
    for (const auto& [spelling, meaning] : index) {
        if (meaning.kind != MeaningKind::word || spelling.find(' ') != std::string::npos) {
            continue;
        }
        for (const Rule& rule : rules) {
            if (spelling.size() <= rule.piece.size()) {
                continue;
            }
            const auto check = [&](std::string_view rest, const std::vector<Category>& allowed,
                                   bool piece_first) {
                const auto other = index.find(rest);
                if (other == index.end() || other->second.kind != MeaningKind::word ||
                    std::ranges::find(allowed, other->second.concept_entry->category) ==
                        allowed.end()) {
                    return;
                }
                diagnostics.add("pack.ambiguous-attachment",
                                {{"spelling", quote(spelling)},
                                 {"meaning", describe(meaning)},
                                 {"first", piece_first ? rule.piece : std::string(rest)},
                                 {"second", piece_first ? std::string(rest) : rule.piece}});
            };
            const std::string_view word = spelling;
            if (!rule.before.empty() && word.starts_with(rule.piece)) {
                check(word.substr(rule.piece.size()), rule.before, true);
            }
            if (!rule.after.empty() && word.ends_with(rule.piece)) {
                check(word.substr(0, word.size() - rule.piece.size()), rule.after, false);
            }
        }
    }
}

} // namespace detail

/// Fills a PackSet's private parts.
struct PackSetBuilder {
    static PackSet make(std::vector<Pack> packs, std::map<std::string, Meaning, std::less<>> index,
                        Officials officials, std::shared_ptr<const Vocabularies> vocabularies) {
        PackSet set;
        set.packs_ = std::move(packs);
        set.spellings_ = std::move(index);
        set.officials_ = officials;
        set.vocabularies_ = std::move(vocabularies);
        return set;
    }
    static void set_vocabularies(PackSet& set, std::shared_ptr<const Vocabularies> vocabularies) {
        set.vocabularies_ = std::move(vocabularies);
    }
};

namespace {

/// Every spelling of a vocabulary pack's word in one language: its
/// spellings and forms.
std::vector<std::string> all_spellings(const Word& word) {
    std::vector<std::string> out = word.spellings;
    for (const auto& [form, spelling] : word.forms) {
        out.push_back(spelling);
    }
    return out;
}

/// The users' packs, checked together with the set's packs: ids, required
/// packs, and spellings new to the set. Adds each pack's words to the
/// language packs of its languages.
void add_users(std::vector<Pack>& packs, std::vector<VocabularyHandle>& users,
               detail::Diagnostics& diagnostics) {
    std::ranges::sort(users, {}, [](const VocabularyHandle& v) { return v->id; });
    for (std::size_t i = 1; i < users.size(); ++i) {
        if (users[i]->id == users[i - 1]->id) {
            diagnostics.add("vocab.duplicate-id", {{"pack", users[i]->id}});
        }
    }
    const auto user = [&](std::string_view id) -> const VocabularyPack* {
        const auto it =
            std::ranges::find_if(users, [&](const VocabularyHandle& v) { return v->id == id; });
        return it == users.end() ? nullptr : it->get();
    };
    for (const VocabularyHandle& pack : users) {
        for (const std::string& other : pack->required) {
            if (find_vocabulary_pack(other) == nullptr && user(other) == nullptr) {
                diagnostics.add("vocab.unknown-requires", {{"pack", pack->id}, {"other", other}});
            }
        }
        // A pack that requires itself, through the users' packs it requires.
        std::vector<const VocabularyPack*> stack{pack.get()};
        std::set<const VocabularyPack*> seen;
        bool cycle = false;
        while (!stack.empty() && !cycle) {
            const VocabularyPack* at = stack.back();
            stack.pop_back();
            for (const std::string& other : at->required) {
                const VocabularyPack* next = user(other);
                if (next == pack.get()) {
                    cycle = true;
                } else if (next != nullptr && seen.insert(next).second) {
                    stack.push_back(next);
                }
            }
        }
        if (cycle) {
            diagnostics.add("vocab.cycle", {{"pack", pack->id}});
        }
    }
    // Each spelling new to the set: the set's packs first, then the users'
    // in the order of their ids.
    std::vector<const Pack*> pointers;
    for (const Pack& pack : packs) {
        pointers.push_back(&pack);
    }
    std::map<std::string, Meaning, std::less<>> index;
    detail::Diagnostics ignored;
    detail::index_spellings(pointers, index, ignored);
    for (const VocabularyHandle& pack : users) {
        for (const auto& [language, words] : pack->languages) {
            Pack* target = nullptr;
            for (Pack& p : packs) {
                if (p.id == language) {
                    target = &p;
                }
            }
            if (target == nullptr) {
                diagnostics.add("vocab.no-language", {{"pack", pack->id}, {"language", language}});
                continue;
            }
            for (const auto& [id, word] : words.words) {
                const Concept* entry = pack->find(id);
                for (const std::string& spelling : all_spellings(word)) {
                    const auto it = index.find(spelling);
                    if (it != index.end() && !(it->second.kind == MeaningKind::word &&
                                               it->second.concept_entry == entry)) {
                        diagnostics.add("vocab.conflict",
                                        {{"pack", pack->id},
                                         {"spelling", detail::quote(spelling)},
                                         {"meaning", detail::describe(it->second)}});
                        continue;
                    }
                    index.try_emplace(spelling,
                                      Meaning{MeaningKind::word, entry, {}, 0, 0, pack->id});
                }
            }
            detail::merge_vocabulary(*target, *pack);
        }
    }
}

} // namespace

const Vocabularies& PackSet::vocabularies() const noexcept {
    static const Vocabularies none;
    return vocabularies_ != nullptr ? *vocabularies_ : none;
}

const Pack* PackSet::find(std::string_view id) const noexcept {
    const auto it = std::ranges::find(packs_, id, &Pack::id);
    return it == packs_.end() ? nullptr : &*it;
}

const Meaning* PackSet::lookup(std::string_view spelling) const noexcept {
    const auto it = spellings_.find(spelling);
    return it == spellings_.end() ? nullptr : &it->second;
}

PackSetRead make_pack_set(std::vector<Pack> extra, const Officials officials,
                          std::vector<VocabularyHandle> users) {
    detail::Diagnostics diagnostics;
    const std::span<const Pack> carried_packs = official_packs(officials);
    std::vector<Pack> packs(carried_packs.begin(), carried_packs.end());
    for (Pack& pack : extra) {
        if (pack.official) {
            const auto it = std::ranges::find(carried_packs, pack.id, &Pack::id);
            const Pack* carried = it == carried_packs.end() ? nullptr : &*it;
            if (carried == nullptr || carried->canonical != pack.canonical) {
                diagnostics.add("pack.false-official", {{"pack", pack.id}});
            }
            // The same pack as one carried: it is in the set already.
            continue;
        }
        if (std::ranges::find(packs, pack.id, &Pack::id) != packs.end()) {
            diagnostics.add("pack.duplicate-id", {{"pack", pack.id}});
            continue;
        }
        packs.push_back(std::move(pack));
    }
    auto vocabularies = std::make_shared<Vocabularies>();
    for (const VocabularyPack* pack : vocabulary_packs(officials)) {
        vocabularies->packs.push_back(pack);
    }
    if (!users.empty()) {
        add_users(packs, users, diagnostics);
        for (const VocabularyHandle& pack : users) {
            vocabularies->packs.push_back(pack.get());
        }
        vocabularies->users = users;
    }
    std::vector<const Pack*> pointers;
    pointers.reserve(packs.size());
    for (const Pack& pack : packs) {
        pointers.push_back(&pack);
    }
    std::map<std::string, Meaning, std::less<>> index;
    detail::index_spellings(pointers, index, diagnostics, vocabularies.get());
    PackSetRead out;
    if (!diagnostics.has_errors()) {
        out.set = PackSetBuilder::make(std::move(packs), std::move(index), officials, vocabularies);
        // The users' terms, read with the set: their words and all.
        if (!users.empty()) {
            std::shared_ptr<const UserTerms> terms =
                detail::read_user_terms(*out.set, users, diagnostics);
            auto complete = std::make_shared<Vocabularies>(*vocabularies);
            complete->terms = std::move(terms);
            PackSetBuilder::set_vocabularies(*out.set, std::move(complete));
        }
    }
    const bool ok = !diagnostics.has_errors();
    out.diagnostics = diagnostics.take();
    if (!ok) {
        out.set.reset();
    }
    return out;
}

namespace {

bool equal_ignoring_case(std::string_view a, std::string_view b) noexcept {
    return std::ranges::equal(a, b, [](char x, char y) {
        const auto lower = [](char c) {
            return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c;
        };
        return lower(x) == lower(y);
    });
}

} // namespace

const Pack* find_language(std::span<const Pack> packs, std::string_view want) noexcept {
    for (const Pack& pack : packs) {
        if (pack.id == want) {
            return &pack;
        }
    }
    for (const Pack& pack : packs) {
        if (equal_ignoring_case(pack.language, want)) {
            return &pack;
        }
    }
    // A tag's prefix, at a subtag boundary: zh-Hant finds zh-Hant-HK, if no
    // other pack is zh-Hant-something.
    const Pack* found = nullptr;
    for (const Pack& pack : packs) {
        if (pack.language.size() > want.size() && pack.language[want.size()] == '-' &&
            equal_ignoring_case(std::string_view(pack.language).substr(0, want.size()), want)) {
            if (found != nullptr) {
                return nullptr;
            }
            found = &pack;
        }
    }
    return found;
}

} // namespace cexchain::bo
