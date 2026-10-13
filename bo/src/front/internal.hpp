// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The front end's shared internals: collecting diagnostics, and the rules
// for words and spellings.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/pack.hpp>

namespace cexchain::bo::detail {

using Args = std::initializer_list<std::pair<std::string_view, std::string>>;

/// True if `code` is a known message and every argument one of its
/// parameters.
[[nodiscard]] bool well_formed(std::string_view code, Args args) noexcept;

/// Diagnostics as they are found, up to max_diagnostics.
class Diagnostics {
public:
    void add(std::string_view code, Args args) BO_PRE(well_formed(code, args));
    [[nodiscard]] bool has_errors() const noexcept { return errors_; }
    /// The diagnostics, plus a last warning if some were dropped.
    [[nodiscard]] std::vector<Diagnostic> take();

private:
    std::vector<Diagnostic> list_;
    std::size_t dropped_ = 0;
    bool errors_ = false;
};

/// Code points of valid UTF-8, or nullopt.
[[nodiscard]] std::optional<std::u32string> code_points(std::string_view text);
[[nodiscard]] std::string utf8(char32_t code_point);
/// True if a word may contain the code point: letters, marks, and digits;
/// not punctuation, symbols, spaces, invisible or format characters, private
/// use, or compatibility forms that Unicode normalization would change.
[[nodiscard]] bool is_word_char(char32_t c) noexcept;
/// True for spaces and characters that show nothing (format characters,
/// variation selectors, fillers).
[[nodiscard]] bool is_invisible(char32_t c) noexcept;
/// "U+3001 (、)", or just "U+200B" for an invisible character.
[[nodiscard]] std::string describe_char(char32_t c);
/// At most `max` bytes of `text` (whole characters), "…" marking a cut, for
/// diagnostics that quote what they read.
[[nodiscard]] std::string quote(std::string_view text, std::size_t max = 80);

/// The most words a spelling has, besides the argument's place.
inline constexpr std::size_t max_spelling_words = 4;
/// The longest word, in bytes.
inline constexpr std::size_t max_word_bytes = 64;

enum class SpellingProblem : std::uint8_t {
    none,
    malformed,     ///< empty, bad spacing, too many or too long words, a leading digit
    bad_character, ///< a character no word may contain (see `character`)
};

struct SpellingCheck {
    SpellingProblem problem = SpellingProblem::none;
    char32_t character = 0;
    /// How many words are the argument's place.
    std::size_t holes = 0;
    std::size_t words = 0;
};

/// Checks a spelling: one to four words separated by single spaces, plus
/// any number of "…" words (the caller checks how many there may be).
[[nodiscard]] SpellingCheck check_spelling(std::string_view spelling);
/// The words of a spelling.
[[nodiscard]] std::vector<std::string_view> split_words(std::string_view spelling);

/// A spelling's meaning, for diagnostics: "act.pay", "act.pay (third)",
/// "×10000", or "','".
[[nodiscard]] std::string describe(const Meaning& meaning);

/// Indexes the spellings of `packs`, in order, reporting a spelling with two
/// meanings and a word that an attaching rule could split into two (never
/// guess). Used for one pack as it is read, and for a pack set.
void index_spellings(std::span<const Pack* const> packs,
                     std::map<std::string, Meaning, std::less<>>& index, Diagnostics& diagnostics);

} // namespace cexchain::bo::detail
