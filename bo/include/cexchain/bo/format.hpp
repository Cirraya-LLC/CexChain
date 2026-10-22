// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>

/// The formatter (`bo fmt`): a source in canonical layout and, on request,
/// with every keyword and word written in one language. It works on the
/// tokens, line by line, so every clause stays on its line and every comment
/// in its place; the tree, the checked model, the compiled code, and the
/// contract text of the result are those of the source (languages are
/// shells over one core).
///
/// Layout:
///   - each line is indented by two spaces per block, whatever the source
///     used; a comment on a line of its own is indented as the block it
///     sits in (by its column, between the lines around it); a comment after
///     code follows it after two spaces; comments keep their text (trailing
///     spaces go);
///   - runs of blank lines become one, and there are none at the start or
///     the end; lines end with LF, and the file with one;
///   - tokens are separated by one space, except: none before `,` `:` `)`
///     and none after `(`; and where two words written in Chinese (or any
///     script written without spaces) meet and the packs' reading rules join
///     them, they are joined as Chinese is written: a prefix keyword and the
///     word after it (可質押, 須親身確認, 須經), an attaching word and its
///     neighbour (按發票, 30日內). Latin words and numbers stand apart from
///     Chinese by a space (每 GB, 可 subscribe), except that a number takes
///     its multiplier and a Chinese unit or currency after it directly
///     (500萬港元, 30日, 1個);
///   - punctuation stays as written: ASCII, × and ÷, or the full-width
///     marks a pack reads (，、：（）), with no space on either side of
///     those; translated into a language that does not read a full-width
///     mark, it becomes ASCII. Numbers keep their digits and `_` as
///     written, in ASCII (５ is 5).
///
/// Languages. Without a language, every word keeps its spelling. With one,
/// a word already spelled in that language (any of its spellings or forms:
/// `pays`, 費率) keeps it; any other is written in that language's first
/// spelling, a unit or time unit after a number other than 1 in its plural
/// form if the language has one (30 days, 3 tonnes). A word with an
/// argument is arranged as the language spells it (`consent of bank`,
/// `經 銀行 同意`), with parentheses where its new place would otherwise
/// take a different argument. Names the contract gives, texts in quotes,
/// and comments stay as written. A multiplier the language lacks is written
/// out (500萬 is 5_000_000 in English); a date in a pack's form the language
/// cannot read is written in its own form, else ISO (2027-01-06).
///
/// What does not round-trip: the formatted text, not the source as written.
/// Writing a file in another language and back gives the same tree, model,
/// code, and contract text, but not the same characters: forms and other
/// spellings become the first spelling (`pays` → 支付 → `pay`), multipliers
/// are written out, dates in a pack's form become ISO in English, and the
/// layout is canonical. Comments are never translated.
///
/// Safety: the result is lexed and parsed again before it is returned; it
/// must give the same tree and the same comments (without a language, the
/// same tokens too). If joining words would change that, the line is
/// written with spaces instead; if it still differs (a name the contract
/// gives reads together with the words of the new language), nothing is
/// returned and `fmt.unstable` says where.
namespace cexchain::bo {

/// Spaces per block level.
inline constexpr std::size_t format_indent = 2;

struct Formatted {
    /// The formatted source, if the source reads without errors and could be
    /// written as asked.
    std::optional<std::string> source;
    /// The lexer's and the parser's problems (nothing is formatted then), or
    /// why it could not be written (fmt.unstable, fmt.internal), in source
    /// order.
    std::vector<Diagnostic> diagnostics;
};

/// Formats a source read with `packs` (and `lexicon`, built from them), its
/// words in `language`'s spellings, or as written if `language` is null.
/// `language` is one of the set's packs (a word it does not spell is written
/// in English, as packs fall back to English).
///
/// (Not `format`: with a string argument, argument-dependent lookup would
/// find std::format too.)
[[nodiscard]] Formatted format_source(std::string_view source, const PackSet& packs,
                                      const Lexicon& lexicon, const Pack* language)
    BO_POST(r, r.source.has_value() != has_errors(r.diagnostics));

} // namespace cexchain::bo
