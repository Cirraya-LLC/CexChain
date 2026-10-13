// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Words and spellings: which characters a word may hold, and the shape of a
// spelling. Also the diagnostics collector the front end shares.

#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "internal.hpp"

namespace cexchain::bo::detail {

namespace {

struct Range {
    char32_t first;
    char32_t last;
};

// Characters no word may hold, beyond ASCII (where only letters and digits
// may appear). Sorted, not overlapping. They are separators, punctuation,
// symbols, invisible and format characters, private use, and compatibility
// forms that NFKC would fold into other characters, so that two words that
// look alike are never different words.
constexpr Range refused[] = {
    {0x0080, 0x00BF},    // C1 controls, no-break space, soft hyphen, Latin-1 symbols
    {0x00D7, 0x00D7},    // ×, an operator
    {0x00F7, 0x00F7},    // ÷, an operator
    {0x02B0, 0x02FF},    // spacing modifier letters
    {0x034F, 0x034F},    // combining grapheme joiner
    {0x061C, 0x061C},    // Arabic letter mark
    {0x115F, 0x1160},    // Hangul fillers
    {0x1680, 0x1680},    // Ogham space mark
    {0x17B4, 0x17B5},    // Khmer inherent vowels (invisible)
    {0x180B, 0x180F},    // Mongolian variation selectors and vowel separator
    {0x1D2C, 0x1D6A},    // phonetic modifier letters
    {0x1D78, 0x1D78},    // modifier letter Cyrillic en
    {0x1D9B, 0x1DBF},    // phonetic modifier letters
    {0x2000, 0x2BFF},    // spaces, invisible and format characters, punctuation,
                         // super- and subscripts, symbols, letterlike forms,
                         // number forms, arrows, operators, shapes, braille
    {0x2E00, 0x2FFF},    // supplemental punctuation, CJK and Kangxi radicals
    {0x3000, 0x3004},    // ideographic space, CJK punctuation
    {0x3008, 0x3030},    // CJK brackets and marks
    {0x3036, 0x303A},    // CJK symbols
    {0x303D, 0x303F},    // CJK symbols
    {0x309B, 0x309C},    // spacing kana voicing marks
    {0x30A0, 0x30A0},    // katakana double hyphen
    {0x30FB, 0x30FB},    // katakana middle dot
    {0x3130, 0x319F},    // Hangul compatibility jamo, kanbun
    {0x31C0, 0x31EF},    // CJK strokes
    {0x3200, 0x33FF},    // enclosed CJK letters and months, CJK compatibility
    {0x4DC0, 0x4DFF},    // hexagram symbols
    {0xD800, 0xF8FF},    // surrogates, private use
    {0xF900, 0xFAFF},    // CJK compatibility ideographs
    {0xFB00, 0xFDFF},    // ligatures, Arabic presentation forms
    {0xFE00, 0xFE6F},    // variation selectors, vertical and small forms
    {0xFE70, 0xFFFF},    // presentation forms, byte order mark, full- and
                         // half-width forms, specials
    {0x1D100, 0x1D1FF},  // musical symbols (with invisible format characters)
    {0x1D400, 0x1D7FF},  // mathematical letters and digits
    {0x1F000, 0x1FFFF},  // symbols, emoji, enclosed alphanumerics
    {0x2F800, 0x2FA1F},  // CJK compatibility ideographs supplement
    {0xE0000, 0x10FFFF}, // tags, variation selectors, private use
};

} // namespace

bool is_invisible(char32_t c) noexcept {
    return c < 0x21 || (c >= 0x7F && c <= 0xA0) || c == 0xAD || (c >= 0x2000 && c <= 0x200F) ||
           (c >= 0x2028 && c <= 0x202F) || (c >= 0x205F && c <= 0x206F) || c == 0x3000 ||
           c == 0xFEFF || (c >= 0xFE00 && c <= 0xFE0F) || c == 0x034F || c == 0x061C ||
           c == 0x115F || c == 0x1160 || c == 0x3164 || c == 0xFFA0 || c == 0x1680 ||
           (c >= 0x180B && c <= 0x180F) || (c >= 0x17B4 && c <= 0x17B5) ||
           (c >= 0x1D173 && c <= 0x1D17A) || c >= 0xE0000;
}

namespace {

bool is_ascii_digit(char32_t c) noexcept {
    return c >= U'0' && c <= U'9';
}

} // namespace

bool well_formed(std::string_view code, Args args) noexcept {
    const MessageSpec* spec = find_message(code);
    if (spec == nullptr) {
        return false;
    }
    for (const auto& [name, value] : args) {
        if (!has_param(spec->params, name)) {
            return false;
        }
    }
    return true;
}

void Diagnostics::add(std::string_view code, Args args) {
    add(Span{}, code, args);
}

void Diagnostics::add(const Span& span, std::string_view code, Args args) {
    const MessageSpec* spec = find_message(code);
    if (spec != nullptr && spec->severity == Severity::error) {
        errors_ = true;
    }
    if (list_.size() >= max_diagnostics) {
        ++dropped_;
        return;
    }
    list_.push_back(Diagnostic{code, {args.begin(), args.end()}, span});
}

std::vector<Diagnostic> Diagnostics::take() {
    if (dropped_ > 0) {
        list_.push_back(
            Diagnostic{"bo.truncated", {{"limit", std::to_string(max_diagnostics)}}, Span{}});
        dropped_ = 0;
    }
    return std::move(list_);
}

std::optional<std::u32string> code_points(std::string_view text) {
    if (!cbor::is_valid_utf8(text)) {
        return std::nullopt;
    }
    std::u32string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size();) {
        const auto lead = static_cast<unsigned char>(text[i]);
        std::size_t length = 1;
        char32_t c = lead;
        if (lead >= 0xF0) {
            length = 4;
            c = lead & 0x07U;
        } else if (lead >= 0xE0) {
            length = 3;
            c = lead & 0x0FU;
        } else if (lead >= 0xC0) {
            length = 2;
            c = lead & 0x1FU;
        }
        for (std::size_t k = 1; k < length; ++k) {
            c = (c << 6U) | (static_cast<unsigned char>(text[i + k]) & 0x3FU);
        }
        out.push_back(c);
        i += length;
    }
    return out;
}

std::string utf8(char32_t c) {
    std::string out;
    if (c < 0x80) {
        out.push_back(static_cast<char>(c));
    } else if (c < 0x800) {
        out.push_back(static_cast<char>(0xC0U | (c >> 6U)));
        out.push_back(static_cast<char>(0x80U | (c & 0x3FU)));
    } else if (c < 0x10000) {
        out.push_back(static_cast<char>(0xE0U | (c >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((c >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (c & 0x3FU)));
    } else {
        out.push_back(static_cast<char>(0xF0U | (c >> 18U)));
        out.push_back(static_cast<char>(0x80U | ((c >> 12U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | ((c >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (c & 0x3FU)));
    }
    return out;
}

bool is_word_char(char32_t c) noexcept {
    if (c < 0x80) {
        return (c >= U'a' && c <= U'z') || (c >= U'A' && c <= U'Z') || is_ascii_digit(c);
    }
    // Noncharacters.
    if ((c & 0xFFFEU) == 0xFFFEU || (c >= 0xFDD0 && c <= 0xFDEF)) {
        return false;
    }
    // Ranges are sorted: find the last one starting at or below c.
    std::size_t low = 0;
    std::size_t high = std::size(refused);
    while (low < high) {
        const std::size_t mid = low + (high - low) / 2;
        if (refused[mid].first <= c) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    return low == 0 || c > refused[low - 1].last;
}

std::string describe_char(char32_t c) {
    const std::string code = std::format("U+{:04X}", static_cast<std::uint32_t>(c));
    // Combining marks would sit on the parenthesis.
    const bool combining = (c >= 0x0300 && c <= 0x036F) || (c >= 0x1AB0 && c <= 0x1AFF) ||
                           (c >= 0x1DC0 && c <= 0x1DFF) || (c >= 0x20D0 && c <= 0x20FF) ||
                           (c >= 0xFE20 && c <= 0xFE2F) || c == 0x3099 || c == 0x309A;
    if (is_invisible(c) || combining) {
        return code;
    }
    return code + " (" + utf8(c) + ")";
}

std::string quote(std::string_view text, std::size_t max) {
    if (text.size() <= max) {
        return std::string(text);
    }
    std::size_t end = max;
    // Back up to the start of a character.
    while (end > 0 && (static_cast<unsigned char>(text[end]) & 0xC0U) == 0x80U) {
        --end;
    }
    return std::string(text.substr(0, end)) + std::string(hole);
}

std::vector<std::string_view> split_words(std::string_view spelling) {
    std::vector<std::string_view> out;
    while (true) {
        const std::size_t space = spelling.find(' ');
        out.push_back(spelling.substr(0, space));
        if (space == std::string_view::npos) {
            return out;
        }
        spelling.remove_prefix(space + 1);
    }
}

SpellingCheck check_spelling(std::string_view spelling) {
    SpellingCheck out;
    if (spelling.empty()) {
        out.problem = SpellingProblem::malformed;
        return out;
    }
    for (const std::string_view word : split_words(spelling)) {
        if (word == hole) {
            ++out.holes;
            continue;
        }
        ++out.words;
        // Empty words come from leading, trailing, or double spaces.
        if (word.empty() || word.size() > max_word_bytes || out.words > max_spelling_words) {
            out.problem = SpellingProblem::malformed;
            return out;
        }
        const auto points = code_points(word);
        if (!points) {
            out.problem = SpellingProblem::malformed;
            return out;
        }
        if (is_ascii_digit(points->front())) {
            out.problem = SpellingProblem::malformed;
            return out;
        }
        for (const char32_t c : *points) {
            if (!is_word_char(c)) {
                out.problem = SpellingProblem::bad_character;
                out.character = c;
                return out;
            }
        }
    }
    if (out.words == 0) {
        out.problem = SpellingProblem::malformed;
    }
    return out;
}

std::string describe(const Meaning& meaning) {
    switch (meaning.kind) {
    case MeaningKind::word:
        if (meaning.concept_entry == nullptr) {
            return "?";
        }
        if (meaning.form.empty()) {
            return std::string(meaning.concept_entry->id);
        }
        return std::string(meaning.concept_entry->id) + " (" + meaning.form + ")";
    case MeaningKind::multiplier:
        return "\u00D7" + std::to_string(meaning.multiplier);
    case MeaningKind::punctuation:
        return std::string("'") + meaning.punctuation + "'";
    }
    return "?";
}

} // namespace cexchain::bo::detail
