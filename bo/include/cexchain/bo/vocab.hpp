// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Bo's vocabulary packs (D-054): Bo's core words (holder, transfer, money,
/// ...) are in every source; a pack's words are read only in a source that
/// declares the pack (`use finance`). Unlike a language pack, which spells
/// concepts in one language, a vocabulary pack says which concepts exist,
/// their categories and field types, how each language spells them, and the
/// standard terms of its actions, so it changes what runs: a deploy pins each
/// pack it uses by version and digest (bo-source key 6, source.hpp), and
/// embeds those that are not official in full (key 7).
///
/// A pack is a file (`.vocab`) in CBOR diagnostic notation, like a language
/// pack, and its digest covers its canonical CBOR (comments and layout do
/// not count):
///
///   {"format": 1, "id": "events", "version": 1, "edition": 1,
///    "requires": ["commerce"],                     # optional
///    "concepts": {"act.book": {"category": "action"},
///                 "field.guest": {"category": "field", "type": "party",
///                                 "added": true, "taking": true},
///                 "unit.dozen": {"category": "unit", "dimension": "count",
///                                "scale": 12}, ...},
///    "terms": ["bo 1", "use events", "", "can book to counterparty", ...],
///    "languages": {"en": {"name": "events",
///                         "words": {"act.book": "book", ...},
///                         "attach": [...]}, ...}}
///
/// "terms" is a Bo source (a text, or its lines), the standard terms of the
/// pack's actions; "languages" spells every concept in each language (keyed
/// by language pack id) as a language pack's "vocabulary" does, with the
/// pack's name and, for languages written without spaces, the reading
/// rules of its own words. "argument", "added", and "taking" are written
/// only when true.
///
/// The official packs (commerce, finance, services) are such files, compiled
/// in (bo/vocab/), and only they may bind the compiler's mechanisms: kinds,
/// prices, charges, documents, and a concept with an argument. A user's pack
/// adds actions (with or without terms), fields (party, date, number, text,
/// duration, parties, quantity, list, amount), states, roles, and units of
/// the core's dimensions. Its concepts' ids carry its id (`events:act.book`);
/// compiled code names them by their plain names (`book`), which may not be
/// those of a core or official word of the same category. Versions of the
/// official packs from before pack files (version 1) carry no "languages":
/// the language packs of their release spell them.
namespace cexchain::bo {

/// The vocabulary pack format.
inline constexpr std::uint64_t vocab_format = 1;

/// A pack file is at most this many bytes, like a language pack.
inline constexpr std::size_t max_vocab_size = max_pack_size;

/// Concepts one pack defines.
inline constexpr std::size_t max_vocab_concepts = 256;

/// A pack's terms are at most this many bytes.
inline constexpr std::size_t max_vocab_terms = std::size_t{64} * 1024;

/// One language's words of a vocabulary pack.
struct VocabularyLanguage {
    /// The pack's name in this language ("events", "活動").
    std::string name;
    /// The spellings of each of the pack's concepts, by concept id.
    std::map<std::string, Word, std::less<>> words;
    /// How its words attach to others, in a language written without
    /// spaces (as a language pack's reading rules).
    std::vector<Attachment> attach;
};

struct VocabularyPack {
    std::string id;
    std::uint64_t version = 0;
    std::uint64_t edition = 0;
    /// The official pack it is, or Vocab::user.
    Vocab vocab = Vocab::user;
    /// The packs a source using this one must use too, by ascending id.
    std::vector<std::string> required;
    /// Its concepts, by ascending id.
    std::vector<const Concept*> concepts;
    /// The standard terms of its actions, a Bo source; or empty.
    std::string terms;
    /// Its words in each language, by language pack id; empty for an
    /// official version spelled by its release's language packs.
    std::map<std::string, VocabularyLanguage, std::less<>> languages;
    /// The canonical CBOR of the file: what digests cover.
    Bytes canonical;

    VocabularyPack() = default;
    VocabularyPack(const VocabularyPack&) = delete;
    VocabularyPack& operator=(const VocabularyPack&) = delete;

    [[nodiscard]] bool official() const noexcept { return vocab != Vocab::user; }
    /// Its words in this language (a language pack id), or nullptr.
    [[nodiscard]] const VocabularyLanguage* language(std::string_view language_id) const noexcept;
    /// One of its concepts, by id (`events:act.book`), or nullptr.
    [[nodiscard]] const Concept* find(std::string_view concept_id) const noexcept;
    /// Its unit's entry, or nullptr.
    [[nodiscard]] const UnitInfo* unit(const Concept* c) const noexcept;

    /// What its concepts point into: a user pack's own concepts and texts
    /// (an official pack's are the compiler's table).
    std::deque<Concept> owned;
    std::deque<std::string> texts;
    std::deque<UnitInfo> units;
};

using VocabularyHandle = std::shared_ptr<const VocabularyPack>;

/// The vocabulary packs a pack set reads (PackSet::vocabularies), as the
/// lexer hands them to the parser and the checker: the official ones of its
/// release and the users' (given with --vocab, or embedded in a bundle),
/// with the users' terms read. It keeps the users' packs, whose concepts
/// tokens, trees, and models point at, alive.
struct Vocabularies {
    /// The official packs of the set's release, then the users', each by
    /// ascending id.
    std::vector<const VocabularyPack*> packs;
    /// The users' packs (a subset of `packs`).
    std::vector<VocabularyHandle> users;
    /// The users' packs' terms, read with the set (stdlib.hpp); nullptr
    /// without users' packs.
    std::shared_ptr<const UserTerms> terms;

    /// The pack a `use` line names, or nullptr.
    [[nodiscard]] const VocabularyPack* find(std::string_view id) const noexcept;
    /// A concept of a user's pack, by id (`events:act.book`), or nullptr.
    [[nodiscard]] const Concept* find_concept(std::string_view id) const noexcept;
};

struct VocabularyRead {
    /// Set if the pack reads.
    VocabularyHandle pack;
    std::vector<Diagnostic> diagnostics;
};

/// Reads a user's vocabulary pack file (CBOR diagnostic notation): its
/// shape, ids, concepts, terms (as text; a pack set reads them as Bo), and
/// spellings, every problem reported. An official pack's id is refused
/// (official packs are the compiler's; a bundle names them); so is a
/// concept whose plain name is a core or official word's in its category.
[[nodiscard]] VocabularyRead read_vocabulary_pack(std::string_view text)
    BO_POST(r, (r.pack != nullptr) != has_errors(r.diagnostics));
/// The same, from CBOR (a pack a bundle embeds).
[[nodiscard]] VocabularyRead read_vocabulary_pack(const cbor::Value& value)
    BO_POST(r, (r.pack != nullptr) != has_errors(r.diagnostics));

/// The official vocabulary packs this compiler carries in their current
/// versions, by ascending id (commerce, finance, services).
[[nodiscard]] std::span<const VocabularyPack* const> vocabulary_packs() noexcept;
/// The current version of the official vocabulary pack with this id, or
/// nullptr ("core" is none).
[[nodiscard]] const VocabularyPack* find_vocabulary_pack(std::string_view id) noexcept;
/// The official pack with this id at this version (current or carried), or
/// nullptr.
[[nodiscard]] const VocabularyPack* find_vocabulary_pack(std::string_view id,
                                                         std::uint64_t version) noexcept;
/// The current version of the official pack a concept belongs to, or nullptr
/// for a core word (or a user's).
[[nodiscard]] const VocabularyPack* vocabulary_pack(Vocab vocab) noexcept;
/// The official vocabulary packs a release of the official language packs
/// reads with (pack.hpp, Officials), by ascending id: their versions spelled
/// by those language packs, or, for the current release, spelled by
/// themselves; none before vocabulary packs.
[[nodiscard]] std::span<const VocabularyPack* const> vocabulary_packs(Officials officials) noexcept;
/// The texts of the official pack files (current, then carried versions).
struct VocabularyText {
    std::string_view id;
    std::uint64_t version = 0;
    std::string_view text;
};
[[nodiscard]] std::span<const VocabularyText> official_vocabulary_texts() noexcept;

/// The id of the pack a concept belongs to: "core", an official pack's, or a
/// user's.
[[nodiscard]] std::string_view pack_of(const Concept& c) noexcept;

/// The pack's name in a language (a language pack id): its own, else in
/// English, else in its first language; else the language pack's sentence
/// "vocab-ID" (the official versions of before pack files); else its id.
[[nodiscard]] std::string vocabulary_name(const VocabularyPack& pack, const Pack* language);

/// The home's hash of the pack's canonical CBOR (SHA-256 or SM3).
[[nodiscard]] Result<crypto::Digest> digest(const VocabularyPack& pack,
                                            const crypto::Provider& provider, crypto::HashAlg alg);

} // namespace cexchain::bo
