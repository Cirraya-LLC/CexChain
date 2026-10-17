// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Vocabulary packs of users' are untrusted (G6 of D-054): anyone may share a
// pack file, and a deploy's source bundle embeds the packs it uses as CBOR
// (key 7), which every verifier reads. The input is read as a pack file
// (diagnostic notation) and as CBOR. Properties:
//   - a pack is returned exactly when no error is reported;
//   - every diagnostic renders in each official language;
//   - a pack that reads, read again from its canonical CBOR, is the same
//     pack (same bytes, concepts, terms, and languages), none of its
//     concepts an official or core word's, each carrying the pack;
//   - it joins the official packs, or says why not (never both); joined,
//     every spelling of its words means its concept in the set, its terms
//     read as templates of its own actions, and a source using it lexes,
//     parses, and checks.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/stdlib.hpp>
#include <cexchain/bo/vocab.hpp>
#include <cexchain/core/cbor.hpp>

namespace {

using namespace cexchain;

/// A source that uses the pack and writes each of its actions.
std::string source_using(const bo::VocabularyPack& pack, const bo::PackSet& set) {
    std::string out = "use " + pack.id + "\n";
    for (const std::string& other : pack.required) {
        out += "use " + other + "\n";
    }
    out += "contract Fuzz\nparties we\nthing T\n  holder we\n";
    const bo::Pack* english = set.find("en");
    for (const bo::Concept* c : pack.concepts) {
        const bo::Word* word = bo::concept_word(c, english);
        if (c->category == bo::Category::action && word != nullptr) {
            out += "can " + word->spellings.front() + "\n";
        }
    }
    return out;
}

void check(const bo::VocabularyRead& read) {
    if ((read.pack != nullptr) == bo::has_errors(read.diagnostics)) {
        std::abort();
    }
    for (const bo::Diagnostic& diagnostic : read.diagnostics) {
        for (const bo::Pack& language : bo::official_packs()) {
            if (bo::render(diagnostic, &language).empty()) {
                std::abort();
            }
        }
    }
    if (read.pack == nullptr) {
        return;
    }
    const bo::VocabularyPack& pack = *read.pack;
    const auto value = cbor::decode(pack.canonical);
    if (!value) {
        std::abort();
    }
    const bo::VocabularyRead again = bo::read_vocabulary_pack(*value);
    if (again.pack == nullptr || again.pack->canonical != pack.canonical ||
        again.pack->concepts.size() != pack.concepts.size() || again.pack->terms != pack.terms ||
        again.pack->languages.size() != pack.languages.size() || pack.official()) {
        std::abort();
    }
    for (const bo::Concept* c : pack.concepts) {
        if (c->owner != &pack || bo::find_concept(c->id) != nullptr || bo::pack_of(*c) != pack.id ||
            pack.find(c->id) != c) {
            std::abort();
        }
    }
    const bo::PackSetRead set = bo::make_pack_set({}, bo::Officials::current, {read.pack});
    if (set.set.has_value() == bo::has_errors(set.diagnostics)) {
        std::abort();
    }
    if (!set.set) {
        return;
    }
    const bo::Vocabularies& vocabularies = set.set->vocabularies();
    if (vocabularies.find(pack.id) != &pack ||
        (!pack.terms.empty() && vocabularies.terms == nullptr)) {
        std::abort();
    }
    if (vocabularies.terms != nullptr) {
        for (const bo::ast::Can* can : vocabularies.terms->templates) {
            if (can->action.concept_entry == nullptr || can->action.concept_entry->owner != &pack) {
                std::abort();
            }
        }
    }
    // Every spelling of the pack's words, in the languages the set has,
    // means its concept.
    for (const auto& [language, words] : pack.languages) {
        if (set.set->find(language) == nullptr) {
            continue;
        }
        for (const auto& [id, word] : words.words) {
            for (const std::string& spelling : word.spellings) {
                const bo::Meaning* meaning = set.set->lookup(spelling);
                if (meaning == nullptr || meaning->concept_entry != pack.find(id)) {
                    std::abort();
                }
            }
        }
    }
    const std::string source = source_using(pack, *set.set);
    const bo::Lexicon lexicon(*set.set);
    const bo::Lexed lexed = bo::lex(source, lexicon);
    const bo::Parsed parsed = bo::parse(source, lexed);
    if (!bo::has_errors(lexed.diagnostics) && !bo::has_errors(parsed.diagnostics)) {
        static_cast<void>(bo::check(source, parsed.file));
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Read once before timing anything: the official packs and the
    // standard library.
    static const bool ready = !cexchain::bo::official_packs().empty() &&
                              !cexchain::bo::standard_library().templates.empty();
    if (!ready) {
        std::abort();
    }
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    check(cexchain::bo::read_vocabulary_pack(text));
    cexchain::cbor::DecodeOptions options;
    options.max_depth = cexchain::cbor::max_nesting_depth;
    if (const auto value = cexchain::cbor::decode(cexchain::ByteView(data, size), options)) {
        check(cexchain::bo::read_vocabulary_pack(*value));
    }
    return 0;
}
