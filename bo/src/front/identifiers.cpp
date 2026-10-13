// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Names: the characters a name may hold, and when two names look alike.
// Bo reads source as exact UTF-8 and never normalizes it (that would need
// Unicode's tables, a dependency). Instead it refuses what normalization
// would change, so a name has one spelling in bytes, and it refuses names
// that mix the scripts whose letters look alike.

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>

#include "internal.hpp"

namespace cexchain::bo::detail {

namespace {

struct Range {
    char32_t first;
    char32_t last;
};

// Characters that NFC changes (or may change with their neighbour) and that
// is_word_char does not refuse already. Sorted, not overlapping.
constexpr Range
    not_normalized[] =
        {
            {0x0300, 0x036F}, // combining diacritical marks: é is U+00E9, not e + U+0301
            {0x0374, 0x0374}, // Greek numeral sign (a singleton)
            {0x037E, 0x037E}, // Greek question mark (a singleton)
            {0x0387, 0x0387}, // Greek ano teleia (a singleton)
            {0x0653, 0x0655}, // Arabic madda and hamza, which compose with alef
            {0x0958, 0x095F}, // Devanagari composition exclusions
            {0x09DC, 0x09DD}, // Bengali composition exclusions
            {0x09DF, 0x09DF}, {0x0A33, 0x0A33}, // Gurmukhi composition exclusions
            {0x0A36, 0x0A36}, {0x0A59, 0x0A5B}, {0x0A5E, 0x0A5E},
            {0x0B5C, 0x0B5D}, // Oriya composition exclusions
            {0x0F43, 0x0F43}, // Tibetan composition exclusions
            {0x0F4D, 0x0F4D}, {0x0F52, 0x0F52}, {0x0F57, 0x0F57},
            {0x0F5C, 0x0F5C}, {0x0F69, 0x0F69}, {0x0F73, 0x0F73},
            {0x0F75, 0x0F76}, {0x0F78, 0x0F78}, {0x0F81, 0x0F81},
            {0x0F93, 0x0F93}, {0x0F9D, 0x0F9D}, {0x0FA2, 0x0FA2},
            {0x0FA7, 0x0FA7}, {0x0FAC, 0x0FAC}, {0x0FB9, 0x0FB9},
            {0x1100, 0x11FF}, // conjoining Hangul jamo: syllables are written whole
            {0x1AB0, 0x1AFF}, // combining diacritical marks extended
            {0x1DC0, 0x1DFF}, // combining diacritical marks supplement
            {0x1F71, 0x1F71}, // Greek letters with oxia, which NFC writes with tonos
            {0x1F73, 0x1F73}, {0x1F75, 0x1F75}, {0x1F77, 0x1F77},
            {0x1F79, 0x1F79}, {0x1F7B, 0x1F7B}, {0x1F7D, 0x1F7D},
            {0x1FBB, 0x1FBB}, {0x1FBE, 0x1FBE}, {0x1FC9, 0x1FC9},
            {0x1FCB, 0x1FCB}, {0x1FD3, 0x1FD3}, {0x1FDB, 0x1FDB},
            {0x1FE3, 0x1FE3}, {0x1FEB, 0x1FEB}, {0x1FEE, 0x1FEF},
            {0x1FF9, 0x1FF9}, {0x1FFB, 0x1FFB}, {0x1FFD, 0x1FFD},
            {0x3099, 0x309A}, // combining kana voicing marks: が is U+304C
};

constexpr bool sorted_ranges(const auto& ranges) {
    for (std::size_t i = 0; i < std::size(ranges); ++i) {
        if (ranges[i].first > ranges[i].last || (i > 0 && ranges[i - 1].last >= ranges[i].first)) {
            return false;
        }
    }
    return true;
}

static_assert(sorted_ranges(not_normalized));

constexpr bool in(const Range* begin, const Range* end, char32_t c) noexcept {
    const Range* it =
        std::upper_bound(begin, end, c, [](char32_t x, const Range& r) { return x < r.first; });
    return it != begin && c <= (it - 1)->last;
}

enum class Script : unsigned { none = 0, latin = 1, greek = 2, cyrillic = 4 };

constexpr Range latin[] = {
    {U'A', U'Z'},     {U'a', U'z'},     {0x00C0, 0x024F}, {0x0250, 0x02AF},
    {0x1E00, 0x1EFF}, {0x2C60, 0x2C7F}, {0xA720, 0xA7FF}, {0xAB30, 0xAB6F},
};
constexpr Range greek[] = {{0x0370, 0x03FF}, {0x1F00, 0x1FFF}};
constexpr Range cyrillic[] = {{0x0400, 0x052F}, {0x1C80, 0x1C8F}, {0xA640, 0xA69F}};

static_assert(sorted_ranges(latin) && sorted_ranges(greek) && sorted_ranges(cyrillic));

Script script_of(char32_t c) noexcept {
    if (in(std::begin(latin), std::end(latin), c)) {
        return Script::latin;
    }
    if (in(std::begin(greek), std::end(greek), c)) {
        return Script::greek;
    }
    if (in(std::begin(cyrillic), std::end(cyrillic), c)) {
        return Script::cyrillic;
    }
    return Script::none;
}

struct LookAlike {
    char32_t letter;
    char32_t latin;
};

// Greek and Cyrillic letters that look like Latin ones, in common fonts.
constexpr LookAlike look_alikes[] = {
    {0x037F, U'J'}, {0x0391, U'A'}, {0x0392, U'B'}, {0x0395, U'E'}, {0x0396, U'Z'}, {0x0397, U'H'},
    {0x0399, U'I'}, {0x039A, U'K'}, {0x039C, U'M'}, {0x039D, U'N'}, {0x039F, U'O'}, {0x03A1, U'P'},
    {0x03A4, U'T'}, {0x03A5, U'Y'}, {0x03A7, U'X'}, {0x03B1, U'a'}, {0x03B9, U'i'}, {0x03BA, U'k'},
    {0x03BD, U'v'}, {0x03BF, U'o'}, {0x03C1, U'p'}, {0x03C5, U'u'}, {0x03C7, U'x'}, {0x03F2, U'c'},
    {0x03F3, U'j'}, {0x03F9, U'C'}, {0x0405, U'S'}, {0x0406, U'I'}, {0x0408, U'J'}, {0x0410, U'A'},
    {0x0412, U'B'}, {0x0415, U'E'}, {0x041A, U'K'}, {0x041C, U'M'}, {0x041D, U'H'}, {0x041E, U'O'},
    {0x0420, U'P'}, {0x0421, U'C'}, {0x0422, U'T'}, {0x0423, U'Y'}, {0x0425, U'X'}, {0x0430, U'a'},
    {0x0435, U'e'}, {0x043E, U'o'}, {0x0440, U'p'}, {0x0441, U'c'}, {0x0443, U'y'}, {0x0445, U'x'},
    {0x0455, U's'}, {0x0456, U'i'}, {0x0458, U'j'}, {0x0474, U'V'}, {0x0475, U'v'}, {0x04AE, U'Y'},
    {0x04AF, U'y'}, {0x04BB, U'h'}, {0x04C0, U'I'}, {0x04CF, U'l'}, {0x0501, U'd'}, {0x051A, U'Q'},
    {0x051B, U'q'}, {0x051C, U'W'}, {0x051D, U'w'},
};

static_assert(std::ranges::is_sorted(look_alikes, {}, &LookAlike::letter));

} // namespace

NameCheck check_name(std::u32string_view name) noexcept {
    if (!name.empty() && name.front() == U'_') {
        return {NameProblem::bad_start, U'_'};
    }
    unsigned scripts = 0;
    for (const char32_t c : name) {
        if (c != U'_' && !is_word_char(c)) {
            return {NameProblem::bad_character, c};
        }
        if (in(std::begin(not_normalized), std::end(not_normalized), c)) {
            return {NameProblem::not_normalized, c};
        }
        scripts |= static_cast<unsigned>(script_of(c));
    }
    // More than one bit: two of the three scripts.
    if ((scripts & (scripts - 1)) != 0) {
        return {NameProblem::mixed_script, 0};
    }
    return {};
}

std::u32string skeleton(std::u32string_view text) {
    std::u32string out(text);
    for (char32_t& c : out) {
        const auto it = std::ranges::lower_bound(look_alikes, c, {}, &LookAlike::letter);
        if (it != std::end(look_alikes) && it->letter == c) {
            c = it->latin;
        }
    }
    return out;
}

} // namespace cexchain::bo::detail
