// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/pack.hpp>

/// The lexer: Bo source (UTF-8) to tokens, under the reading rules of a pack
/// set. A token is a concept (a keyword, a vocabulary word, or one part of a
/// word with an argument's place), a name, a literal, or a symbol, with its
/// span; comments are kept beside the tokens, for the formatter.
///
/// Lines and blocks. One clause per line; blocks by indentation with spaces
/// (a tab is an error), as indent and dedent tokens; blank lines and
/// comment-only lines do not count. `#` starts a comment, except in a text.
///
/// Words. A run of letters, marks, digits, and `_` is read as:
///   - a spelling of the pack set, the longest first where several words
///     form one (`in person`, `AI 代理`);
///   - a prefix keyword joined to such a word (`可質押`, `須親身確認`);
///   - an attaching word joined to a word of the categories it accepts
///     (`每GB`, `按發票`, `個月內`);
///   - otherwise a name. A name that starts with a prefix keyword followed
///     by a valid name (`可提款`) records that split: whether it applies
///     depends on the names the contract declares, which the parser knows.
/// Any run with two readings is an error asking for a space: Bo never
/// guesses (`可用率` has one reading, a name, unless the vocabulary had 用率).
///
/// Literals. Numbers with `_` between digits and an optional decimal part
/// (`5_000_000`, `0.10`; `5,000` is an error), full-width digits, and a
/// multiplier (`500萬`, `1.5萬`, `500 萬`); a number joined to, or followed
/// by, a unit, a time unit, or a currency (`2TB`, `100 Mbps`, `30日`,
/// `3 個月`, `500萬港元`); money with its currency on either side
/// (`HKD 0.10`, `120 HKD`; a currency between two numbers is an error);
/// percentages (`5%`); ISO dates (`2027-01-06`) and the packs' date forms
/// (`2027年1月6日`); texts in double quotes, on one line, without escapes.
/// `bo 1` as the first line names the edition.
///
/// Characters. Exact UTF-8, never normalized: invisible and format
/// characters (bidirectional controls included) are refused everywhere, and
/// in names, compatibility forms and anything else Unicode normalization
/// would change; names that mix Latin, Greek, and Cyrillic letters, or that
/// look like another name or word, are refused, so that two names that look
/// alike are never different.
namespace cexchain::bo {

enum class TokenKind : std::uint8_t {
    edition_line, ///< `bo N` on the first line: the edition, in `number`
    word,         ///< a concept: a keyword or a vocabulary word, or a part of one
    name,         ///< a name the contract gives
    number,       ///< a plain number
    money,        ///< a number with a currency (`unit` is a cur.* concept)
    quantity,     ///< a number with a unit (`unit` is a unit.* concept)
    duration,     ///< a number with a time unit (time.day, week, month, year)
    rate,         ///< a percentage: `number` is in percent
    date,         ///< a calendar date
    text,         ///< a quoted text: `text` holds it, without the quotes
    symbol,       ///< punctuation or an operator
    newline,      ///< the end of a line that has tokens
    indent,       ///< a block begins
    dedent,       ///< a block ends
    end,          ///< the end of the source: always the last token
};

/// TokenKind's names, in enumerator order (checked by reflection in
/// cexchain::bo).
inline constexpr std::array<std::string_view, 15> token_kind_names{
    "edition_line", "word", "name",   "number",  "money",  "quantity", "duration", "rate",
    "date",         "text", "symbol", "newline", "indent", "dedent",   "end"};

/// Which part of a spelling a word token is. A concept that takes an
/// argument marks its place with "…" in each spelling, and the words on
/// either side are read as separate tokens: `consent of` (head) in
/// `consent of bank`, `before due` (tail) in `7 days before due`, and 經
/// (open) and 同意 (close) in `經 銀行 同意`. The parser joins them.
enum class Piece : std::uint8_t {
    whole, ///< a spelling without an argument's place
    head,  ///< the words before the argument, in a spelling with none after it
    tail,  ///< the words after the argument, in a spelling with none before it
    open,  ///< the words before the argument, in a spelling with words after it too
    close, ///< the words after the argument, in a spelling with words before it too
};

inline constexpr std::array<std::string_view, 5> piece_names{"whole", "head", "tail", "open",
                                                             "close"};

/// Punctuation and operators. `×` is `*`, `÷` is `/`, and the packs'
/// punctuation aliases (`，`, `（`) are their ASCII characters.
enum class Symbol : std::uint8_t {
    comma,
    colon,
    open,
    close,
    equals,
    less,
    less_equal,
    greater,
    greater_equal,
    plus,
    minus,
    times,
    divide,
    arrow,
};

/// Each symbol as it is written in ASCII, in enumerator order.
inline constexpr std::array<std::string_view, 14> symbol_texts{
    ",", ":", "(", ")", "=", "<", "<=", ">", ">=", "+", "-", "*", "/", "->"};

/// An exact decimal: `digits` / 10^`scale`. "0.10" is {10, 2}: the scale is
/// as written, and multipliers fold into the digits (1.5萬 is {15000, 0}).
struct Decimal {
    std::uint64_t digits = 0;
    std::uint8_t scale = 0;

    friend bool operator==(const Decimal&, const Decimal&) = default;
};

/// The decimal as written: "0.10", "5000000".
[[nodiscard]] std::string to_string(const Decimal& value);

/// A date in the proleptic Gregorian calendar; the contract's UTC offset
/// applies later.
struct Date {
    std::uint16_t year = 0;
    std::uint8_t month = 0;
    std::uint8_t day = 0;

    friend bool operator==(const Date&, const Date&) = default;
};

/// A name that could also be read as a prefix keyword followed by a
/// declared name: 可提款 as 可 + 提款, if the contract declares 提款.
struct NameSplit {
    const Concept* prefix = nullptr;
    /// Bytes of the name the prefix takes.
    std::uint32_t length = 0;

    friend bool operator==(const NameSplit&, const NameSplit&) = default;
};

/// How a number was written, for the formatter: `500萬港元`, `HKD 0.10`,
/// `30 days`. The value is in Token::number either way.
struct Written {
    /// The digits, `_`, and the decimal point as written (full-width digits
    /// as ASCII), before any multiplier.
    std::string digits;
    /// The multiplier as written (萬), or empty.
    std::string multiplier;
    /// The unit, time unit, or currency as written (a form included: `days`),
    /// its words separated by single spaces; empty for a plain number.
    std::string measure;
    /// The currency before the number (HKD 0.10).
    bool measure_first = false;
};

struct Token {
    TokenKind kind = TokenKind::end;
    Span span;
    /// word: its concept. money, quantity, duration: the currency or unit.
    const Concept* concept_entry = nullptr;
    /// word: which part of the spelling.
    Piece piece = Piece::whole;
    /// word: the form written ("third" for `pays`), or empty.
    std::string form;
    /// name: the name as written. text: the text between the quotes.
    std::string text;
    /// edition_line, number, money, quantity, duration, rate.
    Decimal number;
    Date date;
    Symbol symbol = Symbol::comma;
    /// name: the prefix splits it allows, if a declaration says so.
    std::vector<NameSplit> splits;
    /// number, money, quantity, duration, rate: how it was written.
    Written written;
};

struct Comment {
    Span span;
    /// From the `#` to the end of the line.
    std::string text;
};

struct Lexed {
    /// Ends with an `end` token.
    std::vector<Token> tokens;
    std::vector<Comment> comments;
    std::vector<Diagnostic> diagnostics;
    /// From `bo N`; 1 without it (a file without `bo 1` is edition 1).
    std::uint64_t edition = 1;
};

/// The largest source, in bytes.
inline constexpr std::size_t max_source_size = std::size_t{256} * 1024;
/// The deepest nesting of blocks.
inline constexpr std::size_t max_block_depth = 32;
/// The longest name and the longest text, in bytes.
inline constexpr std::size_t max_name_bytes = 128;
inline constexpr std::size_t max_text_bytes = 1000;

/// A pack set's reading rules, indexed for the lexer. Build it once per pack
/// set and lex any number of sources with it; it keeps its own copies, so
/// it may outlive the set.
class Lexicon {
public:
    explicit Lexicon(const PackSet& packs);
    Lexicon(Lexicon&&) noexcept;
    Lexicon& operator=(Lexicon&&) noexcept;
    Lexicon(const Lexicon&) = delete;
    Lexicon& operator=(const Lexicon&) = delete;
    ~Lexicon();

    struct Impl;
    [[nodiscard]] const Impl& impl() const noexcept { return *impl_; }

private:
    std::unique_ptr<Impl> impl_;
};

/// The tokens of a source, and every problem found (up to max_diagnostics).
/// Lexing goes on after an error, so one run reports as much as it can.
[[nodiscard]] Lexed lex(std::string_view source, const Lexicon& lexicon)
    BO_POST(r, !r.tokens.empty() && r.tokens.back().kind == TokenKind::end);

/// A token as one line of text, without its place: "word kw.can",
/// "word cond.consent_of piece=head", "money cur.HKD 0.10", "name 可用率
/// split=kw.can/用率". The same in every language for the same concepts,
/// except for forms (`form=third`) and names, which stay as written.
[[nodiscard]] std::string describe(const Token& token);

/// The tokens, the comments, and the diagnostics (messages in `language`,
/// English if null), one per line with their places: what
/// `bo check --stage lex` prints, and the lexer's goldens.
[[nodiscard]] std::string dump(std::string_view source, const Lexed& lexed, const Pack* language);

} // namespace cexchain::bo
