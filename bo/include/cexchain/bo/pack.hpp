// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Language packs: how Bo source is read and how its text is written, for
/// one language. A pack maps the edition's concepts to spellings; it never
/// changes what runs.
///
/// A pack is a file in CBOR diagnostic notation (RFC 8949 section 8, with
/// "/ ... /" and "#" comments), read by cbor::parse_diagnostic. Its digest is
/// the hash of its canonical CBOR, so comments and layout do not change it:
///
///   {
///     "format": 1,                  # the pack format
///     "id": "zh-Hant-HK",           # letters, digits, hyphens
///     "version": 1,                 # raised on any change
///     "language": "zh-Hant-HK",     # a BCP 47 tag
///     "name": "繁體中文（香港）",
///     "official": true,             # only the packs the compiler carries
///     "edition": 1,                 # the Bo edition it spells
///     "reading": {
///       "separation": "none",       # "spaces" or "none": how the language
///                                   # separates words in running text
///       "prefixes": ["kw.can"],     # keywords whose spellings may attach to
///                                   # the start of the next word (可質押)
///       "attach": [                 # words that attach to their neighbour,
///         {"word": "price.per", "before": ["unit", "currency"]},  # 每GB
///         {"word": "cond.within", "after": ["time", "unit"]}      # 30日內
///       ],
///       "punctuation": {"，": ","}, # characters read as ASCII punctuation
///       "multipliers": {"萬": 10000},
///       "dates": {"read": ["{Y}年{M}月{D}日"], "write": "{Y}年{M}月{D}日"}
///     },
///     "keywords": {"kw.can": "可", ...},          # every keyword
///     "vocabulary": {                              # any of the rest
///       "act.pledge": "質押",
///       "cond.consent_of": "經 … 同意",            # … marks the argument
///       "time.day": {"word": "日"},
///       "act.pay": {"word": "pay", "forms": {"third": "pays"}}
///     },
///     "messages": {"pack.missing-key": "{path} 須有 {key}"},
///     "sentences": {"can": "{party}可{action}。"}
///   }
///
/// A spelling is one to four words separated by single spaces, plus the
/// argument's place "…" for concepts that take one; alternatives are given
/// as a list, the first being the one tools write. Words are exact UTF-8:
/// letters, marks, and digits (not first), never punctuation, symbols,
/// spaces, invisible characters, compatibility forms (full-width letters,
/// CJK compatibility ideographs), or anything else Unicode normalization
/// would change, so two words that look alike are never different. Where
/// spellings share a beginning, the longest is read.
///
/// Never guess: one spelling with two meanings, in one pack or across the
/// packs a file is read with, is an error, and so is a word an attaching rule
/// could split into two others (每日 as 每 + 日, if 每 attached to time
/// words). A pack spells every keyword; missing vocabulary is read and shown
/// in English.
namespace cexchain::bo {

struct VocabularyPack;
struct Vocabularies;
struct UserTerms;

/// Where something is in a source: its line and column, counted from 1
/// (columns in characters, that is code points), and its bytes. Line 0 means
/// no place: a pack's diagnostics name a path in their arguments instead.
struct Span {
    std::uint32_t line = 0;
    std::uint32_t column = 0;
    std::uint32_t offset = 0;
    std::uint32_t length = 0;

    friend bool operator==(const Span&, const Span&) = default;
};

/// One problem found, with its message's parameters (MessageSpec::params)
/// as values, and its place in a source, if it has one. Packs give the
/// texts; see messages.hpp.
struct Diagnostic {
    std::string_view code;
    std::vector<std::pair<std::string_view, std::string>> args;
    Span span;

    [[nodiscard]] Severity severity() const noexcept;
    /// The value of a parameter, or empty.
    [[nodiscard]] std::string_view arg(std::string_view name) const noexcept;
};

[[nodiscard]] bool has_errors(std::span<const Diagnostic> diagnostics) noexcept;

/// The most diagnostics one reading reports; a last warning says more were
/// found.
inline constexpr std::size_t max_diagnostics = 100;
/// The largest pack, as text or as CBOR.
inline constexpr std::size_t max_pack_size = std::size_t{1} << 20;
/// The pack format this compiler reads.
inline constexpr std::uint64_t pack_format = 1;
/// The argument's place in a spelling: U+2026 HORIZONTAL ELLIPSIS.
inline constexpr std::string_view hole = "\u2026";

enum class Separation : std::uint8_t { spaces, none };

inline constexpr std::array<std::string_view, 2> separation_names{"spaces", "none"};

/// A word that attaches to its neighbour without a space: `before` lists
/// the categories of words it may precede (每GB), `after` those it may
/// follow (30日內).
struct Attachment {
    std::string word;
    std::vector<Category> before;
    std::vector<Category> after;
};

/// Dates beyond ISO 8601 (2027-01-06), which every pack reads. Patterns use
/// {Y}, {M}, {D}, and, to write, {MONTH} for a month's name.
struct DateForms {
    std::vector<std::string> read;
    std::string write;
    std::vector<std::string> months;
};

struct ReadingRules {
    Separation separation = Separation::spaces;
    std::vector<std::string> prefixes;
    std::vector<Attachment> attach;
    /// One character to the ASCII character it stands for.
    std::map<std::string, char, std::less<>> punctuation;
    std::map<std::string, std::uint64_t, std::less<>> multipliers;
    DateForms dates;
};

/// A concept's spellings in one pack: the first is canonical. Forms are
/// further spellings with a grammatical name ("third": "pays"), which
/// sentences may ask for; they read as the concept too.
struct Word {
    std::vector<std::string> spellings;
    std::map<std::string, std::string, std::less<>> forms;
};

struct Pack {
    std::string id;
    std::uint64_t version = 0;
    std::string language;
    std::string name;
    bool official = false;
    std::uint64_t edition = 0;
    ReadingRules reading;
    /// By concept id.
    std::map<std::string, Word, std::less<>> keywords;
    std::map<std::string, Word, std::less<>> vocabulary;
    /// By message code and sentence id.
    std::map<std::string, std::string, std::less<>> messages;
    std::map<std::string, std::string, std::less<>> sentences;
    /// The pack's canonical CBOR: what digests cover, and what a source
    /// bundle embeds.
    Bytes canonical;

    /// The spellings of a concept (keyword or vocabulary), or nullptr.
    [[nodiscard]] const Word* word(std::string_view concept_id) const noexcept;
};

/// A pack, if it is valid (no errors), and everything found.
struct PackRead {
    std::optional<Pack> pack;
    std::vector<Diagnostic> diagnostics;
};

/// Reads and checks a pack file (diagnostic notation).
[[nodiscard]] PackRead read_pack(std::string_view text)
    BO_POST(r, r.pack.has_value() != has_errors(r.diagnostics));
/// Reads and checks a pack given as CBOR (a source bundle embeds them).
[[nodiscard]] PackRead read_pack(const cbor::Value& value)
    BO_POST(r, r.pack.has_value() != has_errors(r.diagnostics));

/// The home's hash of the pack's canonical CBOR (SHA-256 or SM3).
[[nodiscard]] Result<crypto::Digest> digest(const Pack& pack, const crypto::Provider& provider,
                                            crypto::HashAlg alg);

/// What a spelling means in a pack set.
enum class MeaningKind : std::uint8_t {
    word,        ///< a concept: a keyword or a vocabulary word, or one of its forms
    multiplier,  ///< a number multiplier (萬)
    punctuation, ///< a character read as ASCII punctuation (，)
};

inline constexpr std::array<std::string_view, 3> meaning_kind_names{"word", "multiplier",
                                                                    "punctuation"};

struct Meaning {
    MeaningKind kind = MeaningKind::word;
    /// For a word: the concept (from the edition's table).
    const Concept* concept_entry = nullptr;
    /// For a word: the form's name, or empty for a spelling.
    std::string form;
    std::uint64_t multiplier = 0;
    char punctuation = 0;
    /// The first pack that gives it.
    std::string pack;
};

/// Which release of the official language packs a set is built on: the
/// current one, or an earlier one, which a compiler carries so that the
/// deploys made with it rebuild (bo/packs/history/). Releases:
///   - before_vocabulary: version 1 of each, from before vocabulary packs
///     (D-054). A source read with them uses every vocabulary pack without
///     declaring it (they had no `use`), and its kind word `record`
///     (kind.record) is today's `thing`;
///   - before_temperature: version 2 of each, with vocabulary packs, from
///     before temperatures and field defaults (G5b): it reads like the
///     current release, but spells no word for a temperature;
///   - before_pack_files: version 3 of each, from before vocabulary pack
///     files (G6): they spell the official vocabulary packs' words too,
///     whose versions of this release (version 1) carry no spellings;
///   - current: version 4 of each, which spell the core's words alone; the
///     official vocabulary packs (version 2) spell theirs (vocab.hpp), and
///     the release's packs hold them as their own.
enum class Officials : std::uint8_t {
    current,
    before_vocabulary,
    before_temperature,
    before_pack_files,
};

/// The packs a source is read with: the official packs, always, and any
/// others given. No spelling has two meanings in it.
class PackSet {
public:
    [[nodiscard]] Officials officials() const noexcept { return officials_; }
    /// True if every vocabulary pack is used without `use` (Officials).
    [[nodiscard]] bool implicit_vocabulary() const noexcept {
        return officials_ == Officials::before_vocabulary;
    }
    [[nodiscard]] const std::vector<Pack>& packs() const noexcept { return packs_; }
    [[nodiscard]] const Pack* find(std::string_view id) const noexcept;
    /// What a spelling (words separated by single spaces, the argument's
    /// place as "…") means, or nullptr.
    [[nodiscard]] const Meaning* lookup(std::string_view spelling) const noexcept;
    /// Every spelling, multiplier, and punctuation alias, in byte order.
    [[nodiscard]] const std::map<std::string, Meaning, std::less<>>& spellings() const noexcept {
        return spellings_;
    }
    /// The vocabulary packs it reads (vocab.hpp): the official ones of its
    /// release and the users' given to make_pack_set, whose words its
    /// language packs hold as their own (each in the languages it spells).
    [[nodiscard]] const Vocabularies& vocabularies() const noexcept;
    [[nodiscard]] const std::shared_ptr<const Vocabularies>& vocabularies_handle() const noexcept {
        return vocabularies_;
    }

private:
    friend struct PackSetBuilder;
    std::vector<Pack> packs_;
    std::map<std::string, Meaning, std::less<>> spellings_;
    Officials officials_ = Officials::current;
    std::shared_ptr<const Vocabularies> vocabularies_;
};

struct PackSetRead {
    std::optional<PackSet> set;
    std::vector<Diagnostic> diagnostics;
};

/// The official packs plus `extra` (each already read without errors). A
/// pack that calls itself official must be byte for byte one the compiler
/// carries (it is then the same pack, and taken once).
///
/// A user's vocabulary pack (vocab.hpp) adds its words to the language
/// packs of the languages it spells (a language no pack of the set has is
/// warned of, vocab.no-language), each spelling new to the set (else
/// vocab.conflict); the packs it requires are official or given too
/// (vocab.unknown-requires, vocab.cycle); and its terms read as Bo, a `can`
/// of one of its actions each, with words of the core, the pack, and the
/// packs it requires (vocab.terms, vocab.terms-clause).
[[nodiscard]] PackSetRead
make_pack_set(std::vector<Pack> extra, Officials officials = Officials::current,
              std::vector<std::shared_ptr<const VocabularyPack>> vocabularies = {})
    BO_POST(r, r.set.has_value() != has_errors(r.diagnostics));

/// The packs this compiler carries (the latest version of each), read once.
[[nodiscard]] std::span<const Pack> official_packs() noexcept;
/// Every release of the official packs this compiler carries, the current
/// one first, then the earlier ones, newest first.
[[nodiscard]] std::span<const Officials> official_releases() noexcept;
/// The official packs of a release (Officials), read once.
[[nodiscard]] std::span<const Pack> official_packs(Officials officials) noexcept;
/// The official pack with this id, or nullptr.
[[nodiscard]] const Pack* official_pack(std::string_view id) noexcept;
/// The official pack with this id and version, current or earlier, and
/// which officials it is one of; nullptr if this compiler carries none.
[[nodiscard]] const Pack* official_pack(std::string_view id, std::uint64_t version,
                                        Officials* officials = nullptr) noexcept;
/// The English pack, where missing words and messages fall back to.
[[nodiscard]] const Pack& english_pack() noexcept;

/// How a concept is spelled in a language: the language pack's word, or
/// the word of the vocabulary pack that defines the concept in that
/// language (vocab.hpp); else in English; else, for a user's pack, in its
/// first language. Nullptr if nothing spells it.
[[nodiscard]] const Word* concept_word(const Concept* c, const Pack* language) noexcept;

/// An official pack's file, as compiled in.
struct PackText {
    std::string_view id;
    std::string_view text;
};

/// The current official packs' files.
[[nodiscard]] std::span<const PackText> official_pack_texts() noexcept;
/// The files of a release's official packs (earlier ones in
/// bo/packs/history/).
[[nodiscard]] std::span<const PackText> official_pack_texts(Officials officials) noexcept;

/// The pack for a language: by pack id, by language tag, or by a tag's
/// unique prefix ("zh-Hant" finds zh-Hant-HK). Nullptr if none or several.
[[nodiscard]] const Pack* find_language(std::span<const Pack> packs,
                                        std::string_view want) noexcept;

} // namespace cexchain::bo
