// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The lexer (milestone 2 of the Bo compiler): source to tokens, under the
// reading rules of a pack set. Each line is read in three steps:
//   1. characters to raw items: runs of word characters, numbers (with any
//      suffix joined to them), dates, texts, and symbols;
//   2. runs to words or names: a spelling (the longest of several words
//      first), a prefix or an attaching word joined to one, else a name; two
//      readings are an error;
//   3. numbers joined with the words after or around them: a multiplier,
//      a unit, a currency on either side.
// Nothing depends on addresses, the locale, or unordered iteration.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>

#include "internal.hpp"

namespace cexchain::bo {

struct Lexicon::Impl {
    /// The set's official packs are those of before vocabulary packs.
    bool implicit_vocabulary = false;
    std::shared_ptr<const Vocabularies> vocabularies;
    /// The unit a degree symbol (°C, ℃) reads as, where the set spells it
    /// (G5b; version 2 of the official packs did not).
    const Concept* celsius = nullptr;
    /// A spelling's words: all of them, or those on one side of the
    /// argument's place.
    struct Entry {
        std::vector<std::string> words;
        const Concept* concept_entry = nullptr;
        std::string form;
        Piece piece = Piece::whole;
    };
    struct Prefix {
        std::string spelling;
        const Concept* keyword = nullptr;
    };
    struct Attach {
        std::string word;
        const Concept* concept_entry = nullptr;
        Piece piece = Piece::whole;
        std::vector<Category> before;
        std::vector<Category> after;
    };
    /// A date form's parts: a field ('Y', 'M', 'D'), or literal text.
    struct DatePart {
        char field = 0;
        std::u32string literal;

        friend bool operator==(const DatePart&, const DatePart&) = default;
    };

    /// Entries by their first word, longest first.
    std::map<std::string, std::vector<Entry>, std::less<>> by_first;
    /// One-word spellings of units, time units, and currencies: what may
    /// follow a number directly (2TB, 30日, 500萬港元).
    std::vector<const Entry*> measures;
    std::map<std::string, std::uint64_t, std::less<>> multipliers;
    std::map<char32_t, char> punctuation;
    std::vector<Prefix> prefixes;
    std::vector<Attach> attach;
    std::vector<std::vector<DatePart>> dates;
    /// Every word of every spelling, by its skeleton (look-alike names).
    std::map<std::u32string, std::string> skeletons;
};

namespace {

using Entry = Lexicon::Impl::Entry;
using Attach = Lexicon::Impl::Attach;

constexpr std::size_t npos = std::string_view::npos;

bool is_measure(const Concept* c) noexcept {
    if (c->category == Category::unit || c->category == Category::currency) {
        return true;
    }
    return c->id == "time.day" || c->id == "time.week" || c->id == "time.month" ||
           c->id == "time.year";
}

TokenKind measure_kind(const Concept* c) noexcept {
    switch (c->category) {
    case Category::currency:
        return TokenKind::money;
    case Category::time:
        return TokenKind::duration;
    default:
        return TokenKind::quantity;
    }
}

bool accepts(const std::vector<Category>& categories, const Concept* c) noexcept {
    return std::ranges::find(categories, c->category) != categories.end();
}

void add_entry(Lexicon::Impl& lx, Entry entry) {
    std::vector<Entry>& list = lx.by_first[entry.words.front()];
    const bool known = std::ranges::any_of(list, [&](const Entry& e) {
        return e.words == entry.words && e.concept_entry == entry.concept_entry &&
               e.piece == entry.piece;
    });
    if (!known) {
        list.push_back(std::move(entry));
    }
}

/// The entries of one spelling: the whole of it, or its head and tail
/// around the argument's place.
void add_spelling(Lexicon::Impl& lx, std::string_view spelling, const Meaning& meaning) {
    std::vector<std::string> words;
    std::size_t place = npos;
    for (const std::string_view word : detail::split_words(spelling)) {
        if (word == hole) {
            place = words.size();
        } else {
            words.emplace_back(word);
        }
    }
    if (words.empty()) {
        return;
    }
    if (place == npos) {
        add_entry(lx, {words, meaning.concept_entry, meaning.form, Piece::whole});
        return;
    }
    // Words on both sides of the place: the first part opens, the second
    // closes, so the parser knows to expect the second.
    const bool both = place > 0 && place < words.size();
    if (place > 0) {
        add_entry(lx, {std::vector<std::string>(words.begin(),
                                                words.begin() + static_cast<std::ptrdiff_t>(place)),
                       meaning.concept_entry, meaning.form, both ? Piece::open : Piece::head});
    }
    if (place < words.size()) {
        add_entry(lx, {std::vector<std::string>(words.begin() + static_cast<std::ptrdiff_t>(place),
                                                words.end()),
                       meaning.concept_entry, meaning.form, both ? Piece::close : Piece::tail});
    }
}

std::vector<Lexicon::Impl::DatePart> date_parts(std::string_view pattern) {
    std::vector<Lexicon::Impl::DatePart> parts;
    const auto points = detail::code_points(pattern);
    if (!points) {
        return parts;
    }
    for (std::size_t i = 0; i < points->size(); ++i) {
        const char32_t c = (*points)[i];
        if (c == U'{' && i + 2 < points->size() && (*points)[i + 2] == U'}') {
            parts.push_back({static_cast<char>((*points)[i + 1]), {}});
            i += 2;
            continue;
        }
        if (parts.empty() || parts.back().field != 0) {
            parts.push_back({0, {}});
        }
        parts.back().literal.push_back(c);
    }
    return parts;
}

} // namespace

Lexicon::Lexicon(const PackSet& packs) : impl_(std::make_unique<Impl>()) {
    Impl& lx = *impl_;
    lx.implicit_vocabulary = packs.implicit_vocabulary();
    lx.vocabularies = packs.vocabularies_handle();
    for (const auto& [spelling, meaning] : packs.spellings()) {
        switch (meaning.kind) {
        case MeaningKind::word:
            add_spelling(lx, spelling, meaning);
            if (!unit_symbol(meaning.concept_entry).empty()) {
                lx.celsius = meaning.concept_entry;
            }
            break;
        case MeaningKind::multiplier:
            lx.multipliers.emplace(spelling, meaning.multiplier);
            break;
        case MeaningKind::punctuation:
            if (const auto points = detail::code_points(spelling); points && points->size() == 1) {
                lx.punctuation.emplace(points->front(), meaning.punctuation);
            }
            break;
        }
    }
    for (auto& [first, list] : lx.by_first) {
        // Longest first; then by words and concept, so the order is fixed.
        std::ranges::sort(list, [](const Entry& a, const Entry& b) {
            if (a.words.size() != b.words.size()) {
                return a.words.size() > b.words.size();
            }
            if (a.words != b.words) {
                return a.words < b.words;
            }
            if (a.concept_entry->id != b.concept_entry->id) {
                return a.concept_entry->id < b.concept_entry->id;
            }
            return a.piece < b.piece;
        });
        for (const Entry& entry : list) {
            if (entry.words.size() == 1 && entry.piece == Piece::whole &&
                is_measure(entry.concept_entry)) {
                lx.measures.push_back(&entry);
            }
            for (const std::string& word : entry.words) {
                if (const auto points = detail::code_points(word)) {
                    lx.skeletons.try_emplace(detail::skeleton(*points), word);
                }
            }
        }
    }
    for (const Pack& pack : packs.packs()) {
        for (const std::string& id : pack.reading.prefixes) {
            const Word* word = pack.word(id);
            const Concept* keyword = find_concept(id);
            if (word == nullptr || keyword == nullptr) {
                continue;
            }
            for (const std::string& spelling : word->spellings) {
                if (std::ranges::none_of(lx.prefixes, [&](const Impl::Prefix& p) {
                        return p.spelling == spelling && p.keyword == keyword;
                    })) {
                    lx.prefixes.push_back({spelling, keyword});
                }
            }
        }
        for (const Attachment& attachment : pack.reading.attach) {
            const Word* word = pack.word(attachment.word);
            const Concept* entry = find_concept(attachment.word);
            if (word == nullptr || entry == nullptr) {
                continue;
            }
            for (const std::string& spelling : word->spellings) {
                const auto parts = detail::split_words(spelling);
                Attach a{std::string(parts.front()), entry, Piece::whole, attachment.before,
                         attachment.after};
                if (parts.size() == 2) {
                    a.piece = parts.front() == hole ? Piece::tail : Piece::head;
                    a.word = std::string(parts.front() == hole ? parts.back() : parts.front());
                }
                if (std::ranges::none_of(lx.attach, [&](const Attach& b) {
                        return b.word == a.word && b.concept_entry == a.concept_entry &&
                               b.piece == a.piece && b.before == a.before && b.after == a.after;
                    })) {
                    lx.attach.push_back(std::move(a));
                }
            }
        }
        for (const std::string& pattern : pack.reading.dates.read) {
            auto parts = date_parts(pattern);
            if (!parts.empty() && std::ranges::find(lx.dates, parts) == lx.dates.end()) {
                lx.dates.push_back(std::move(parts));
            }
        }
    }
}

Lexicon::Lexicon(Lexicon&&) noexcept = default;
Lexicon& Lexicon::operator=(Lexicon&&) noexcept = default;
Lexicon::~Lexicon() = default;

namespace {

struct Cp {
    char32_t c;
    std::uint32_t offset;
};

/// The offset of the first byte that is not valid UTF-8, or npos.
std::size_t invalid_utf8(std::string_view s) noexcept {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto lead = static_cast<unsigned char>(s[i]);
        if (lead < 0x80) {
            ++i;
            continue;
        }
        std::size_t extra = 0;
        char32_t c = 0;
        char32_t least = 0;
        if (lead >= 0xC2 && lead <= 0xDF) {
            extra = 1;
            c = lead & 0x1FU;
            least = 0x80;
        } else if (lead >= 0xE0 && lead <= 0xEF) {
            extra = 2;
            c = lead & 0x0FU;
            least = 0x800;
        } else if (lead >= 0xF0 && lead <= 0xF4) {
            extra = 3;
            c = lead & 0x07U;
            least = 0x10000;
        } else {
            return i;
        }
        if (s.size() - i <= extra) {
            return i;
        }
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto next = static_cast<unsigned char>(s[i + k]);
            if ((next & 0xC0U) != 0x80U) {
                return i;
            }
            c = (c << 6U) | (next & 0x3FU);
        }
        if (c < least || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) {
            return i;
        }
        i += extra + 1;
    }
    return npos;
}

/// Room for a decimal's digits after multiplying by `factor` (a power of
/// ten): decimal places absorb it first (1.5萬 is 15000).
bool multiply(Decimal& value, std::uint64_t factor) noexcept {
    while (factor > 1 && value.scale > 0) {
        factor /= 10;
        --value.scale;
    }
    if (factor > 1 && value.digits > std::numeric_limits<std::uint64_t>::max() / factor) {
        return false;
    }
    value.digits *= factor;
    return true;
}

Span join(const Span& a, const Span& b) noexcept {
    Span out = a;
    out.length = b.offset + b.length - a.offset;
    return out;
}

bool is_ascii_digit(char c) noexcept {
    return c >= '0' && c <= '9';
}

class Lexer {
public:
    Lexer(std::string_view source, const Lexicon::Impl& lexicon) : source_(source), lx_(lexicon) {}

    Lexed run();

private:
    /// A step-1 item: a run still to read, or a token.
    struct Raw {
        bool run = false;
        std::size_t from = 0;
        std::size_t to = 0;
        Token token;
        bool multiplied = false;
    };
    /// A step-2 item: a token, or a multiplier waiting for its number.
    struct Item {
        Token token;
        std::uint64_t multiplier = 0;
        bool multiplied = false;
    };
    /// One way to read a run (and any runs after it that a spelling takes).
    struct Reading {
        std::vector<Token> tokens;
        std::size_t runs = 1;
        std::string text;
    };
    /// One way to read a number's suffix.
    struct Segment {
        std::uint64_t multiplier = 0;
        std::size_t multiplier_bytes = 0;
        const Entry* measure = nullptr;
        const Attach* attach = nullptr;
    };

    // Characters.
    [[nodiscard]] char mapped(std::size_t i) const noexcept;
    [[nodiscard]] bool is_digit(std::size_t i) const noexcept { return is_ascii_digit(mapped(i)); }
    [[nodiscard]] bool is_run_char(std::size_t i) const noexcept;
    [[nodiscard]] std::string_view slice(std::size_t from, std::size_t to) const noexcept;
    [[nodiscard]] Span span(std::size_t from, std::size_t to) const noexcept;
    [[nodiscard]] std::size_t after_bytes(std::size_t from, std::size_t bytes) const noexcept;
    [[nodiscard]] Span place_of_byte(std::size_t offset) const noexcept;
    [[nodiscard]] std::string spelled(const Span& s) const;
    [[nodiscard]] std::string character(std::size_t i) const {
        return detail::describe_char(cps_[i].c);
    }

    void decode();
    void lex_line();
    void blocks(std::uint32_t width, std::size_t first, std::size_t indent_end);
    void edition(const std::vector<Raw>& raws);

    // Step 1.
    void scan(std::size_t i, std::vector<Raw>& raws);
    std::size_t comment(std::size_t i);
    std::size_t text(std::size_t i, std::vector<Raw>& raws);
    std::size_t number(std::size_t i, std::vector<Raw>& raws, std::size_t sign = npos);
    [[nodiscard]] bool sign_at(std::size_t i, std::size_t start) const noexcept;
    std::size_t date(std::size_t i, std::vector<Raw>& raws);
    std::size_t symbol(std::size_t i, std::vector<Raw>& raws);
    [[nodiscard]] std::size_t degree(std::size_t i) const noexcept;
    [[nodiscard]] std::vector<Segment> segments(std::string_view suffix) const;

    // Step 2.
    std::vector<Item> read_runs(const std::vector<Raw>& raws);
    std::size_t read_run(const std::vector<Raw>& raws, std::size_t k, std::vector<Item>& items);
    [[nodiscard]] std::vector<const Entry*>
    longest(std::string_view first, std::span<const std::string_view> next, bool vocabulary) const;
    [[nodiscard]] Token word(const Concept* entry, Piece piece, std::string form, std::size_t from,
                             std::size_t to) const;
    Token name(std::size_t from, std::size_t to);

    // Step 3.
    void merge(std::vector<Item>& items);

    void confusables();

    std::string_view source_;
    const Lexicon::Impl& lx_;
    std::vector<Cp> cps_;
    detail::Diagnostics diagnostics_;
    Lexed out_;
    std::vector<std::uint32_t> indents_{0};
    bool seen_tokens_ = false;
    /// Names already refused for their characters: not also look-alikes.
    std::set<std::string, std::less<>> refused_;

    std::uint32_t line_ = 0;
    std::size_t line_begin_ = 0;
    /// The end of the line's text: its line feed, its CRLF, or the end.
    std::size_t content_end_ = 0;
};

char Lexer::mapped(std::size_t i) const noexcept {
    if (i >= content_end_) {
        return 0;
    }
    const char32_t c = cps_[i].c;
    if (c < 0x80) {
        return static_cast<char>(c);
    }
    const auto it = lx_.punctuation.find(c);
    return it == lx_.punctuation.end() ? '\0' : it->second;
}

bool Lexer::is_run_char(std::size_t i) const noexcept {
    if (i >= content_end_) {
        return false;
    }
    const char32_t c = cps_[i].c;
    return detail::is_word_char(c) || c == U'_' || is_digit(i);
}

std::string_view Lexer::slice(std::size_t from, std::size_t to) const noexcept {
    return source_.substr(cps_[from].offset, cps_[to].offset - cps_[from].offset);
}

Span Lexer::span(std::size_t from, std::size_t to) const noexcept {
    return Span{line_, static_cast<std::uint32_t>(from - line_begin_ + 1), cps_[from].offset,
                cps_[to].offset - cps_[from].offset};
}

std::size_t Lexer::after_bytes(std::size_t from, std::size_t bytes) const noexcept {
    const std::uint64_t target = std::uint64_t{cps_[from].offset} + bytes;
    std::size_t j = from;
    while (j + 1 < cps_.size() && cps_[j].offset < target) {
        ++j;
    }
    return j;
}

/// What a span of the current line says, separators (spaces and what packs
/// read as one) as single spaces: `30 days`, `AI 代理`.
std::string Lexer::spelled(const Span& s) const {
    std::string out;
    bool gap = false;
    auto it = std::ranges::lower_bound(cps_, s.offset, {}, &Cp::offset);
    for (; it != cps_.end() && it->offset < std::uint64_t{s.offset} + s.length; ++it) {
        if (mapped(static_cast<std::size_t>(it - cps_.begin())) == ' ') {
            gap = true;
            continue;
        }
        if (gap && !out.empty()) {
            out += ' ';
        }
        gap = false;
        out += detail::utf8(it->c);
    }
    return out;
}

Span Lexer::place_of_byte(std::size_t offset) const noexcept {
    std::uint32_t line = 1;
    std::uint32_t column = 1;
    for (std::size_t i = 0; i < offset; ++i) {
        const auto byte = static_cast<unsigned char>(source_[i]);
        if (byte == '\n') {
            ++line;
            column = 1;
        } else if ((byte & 0xC0U) != 0x80U) {
            ++column;
        }
    }
    return Span{line, column, static_cast<std::uint32_t>(offset), 1};
}

void Lexer::decode() {
    cps_.reserve(source_.size() + 1);
    for (std::size_t i = 0; i < source_.size();) {
        const auto lead = static_cast<unsigned char>(source_[i]);
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
            c = (c << 6U) | (static_cast<unsigned char>(source_[i + k]) & 0x3FU);
        }
        cps_.push_back({c, static_cast<std::uint32_t>(i)});
        i += length;
    }
    // A sentinel: the end of the source.
    cps_.push_back({0, static_cast<std::uint32_t>(source_.size())});
}

Lexed Lexer::run() {
    const auto finish = [&] {
        std::vector<Diagnostic> list = diagnostics_.take();
        // In source order; anything without a place (a truncation) last.
        std::ranges::stable_sort(list, {}, [](const Diagnostic& d) {
            return d.span.line == 0 ? std::numeric_limits<std::uint64_t>::max()
                                    : std::uint64_t{d.span.offset};
        });
        out_.diagnostics = std::move(list);
        return std::move(out_);
    };
    const auto nothing = [&](Span at) {
        Token end;
        end.kind = TokenKind::end;
        end.span = at;
        end.span.length = 0;
        out_.tokens.push_back(std::move(end));
        return finish();
    };
    if (source_.size() > max_source_size) {
        diagnostics_.add(
            Span{1, 1, 0, 0}, "lex.too-large",
            {{"size", std::to_string(source_.size())}, {"limit", std::to_string(max_source_size)}});
        return nothing(Span{1, 1, 0, 0});
    }
    if (const std::size_t bad = invalid_utf8(source_); bad != npos) {
        const Span at = place_of_byte(bad);
        diagnostics_.add(at, "lex.utf8", {});
        return nothing(at);
    }
    decode();
    const std::size_t last = cps_.size() - 1;
    std::size_t begin = 0;
    while (true) {
        ++line_;
        line_begin_ = begin;
        std::size_t end = begin;
        while (end < last && cps_[end].c != U'\n') {
            ++end;
        }
        // CRLF ends a line as LF does; a lone CR is an invisible character.
        content_end_ = end;
        if (end < last && end > begin && cps_[end - 1].c == U'\r') {
            content_end_ = end - 1;
        }
        lex_line();
        if (end == last) {
            break;
        }
        begin = end + 1;
    }
    content_end_ = last;
    const Span at = span(last, last);
    while (indents_.size() > 1) {
        indents_.pop_back();
        Token dedent;
        dedent.kind = TokenKind::dedent;
        dedent.span = at;
        out_.tokens.push_back(std::move(dedent));
    }
    Token end;
    end.kind = TokenKind::end;
    end.span = at;
    out_.tokens.push_back(std::move(end));
    confusables();
    return finish();
}

void Lexer::lex_line() {
    std::size_t i = line_begin_;
    bool tab = false;
    while (i < content_end_) {
        const char32_t c = cps_[i].c;
        if (c == U' ') {
            ++i;
        } else if (c == U'\t') {
            if (!tab) {
                diagnostics_.add(span(i, i + 1), "lex.tab", {});
                tab = true;
            }
            ++i;
        } else if (mapped(i) == ' ') {
            diagnostics_.add(span(i, i + 1), "lex.indent-character", {{"character", character(i)}});
            ++i;
        } else {
            break;
        }
    }
    const std::size_t indent_end = i;
    std::vector<Raw> raws;
    scan(i, raws);
    if (raws.empty()) {
        return;
    }
    const auto width = static_cast<std::uint32_t>(indent_end - line_begin_);
    if (!seen_tokens_ && width == 0 && raws.front().run &&
        slice(raws.front().from, raws.front().to) == "bo") {
        seen_tokens_ = true;
        edition(raws);
        return;
    }
    seen_tokens_ = true;
    blocks(width, raws.front().from, indent_end);
    std::vector<Item> items = read_runs(raws);
    merge(items);
    for (Item& item : items) {
        out_.tokens.push_back(std::move(item.token));
    }
    Token newline;
    newline.kind = TokenKind::newline;
    newline.span = span(content_end_, content_end_);
    out_.tokens.push_back(std::move(newline));
}

void Lexer::blocks(std::uint32_t width, std::size_t first, std::size_t indent_end) {
    if (width > indents_.back()) {
        if (indents_.size() - 1 >= max_block_depth) {
            diagnostics_.add(span(line_begin_, indent_end), "lex.too-deep",
                             {{"limit", std::to_string(max_block_depth)}});
            return;
        }
        indents_.push_back(width);
        Token indent;
        indent.kind = TokenKind::indent;
        indent.span = span(line_begin_, indent_end);
        out_.tokens.push_back(std::move(indent));
        return;
    }
    while (width < indents_.back()) {
        indents_.pop_back();
        Token dedent;
        dedent.kind = TokenKind::dedent;
        dedent.span = span(first, first);
        out_.tokens.push_back(std::move(dedent));
    }
    if (width != indents_.back()) {
        // The line stays in the block it fell back to.
        diagnostics_.add(span(line_begin_, indent_end), "lex.dedent", {});
    }
}

void Lexer::edition(const std::vector<Raw>& raws) {
    const Span whole =
        join(span(raws.front().from, raws.front().to),
             raws.back().run ? span(raws.back().from, raws.back().to) : raws.back().token.span);
    const bool shaped =
        raws.size() == 2 && !raws[1].run && raws[1].token.kind == TokenKind::number &&
        raws[1].token.number.scale == 0 && !raws[1].token.number.negative && !raws[1].multiplied;
    if (!shaped) {
        diagnostics_.add(whole, "lex.bad-edition", {});
        return;
    }
    const std::uint64_t value = raws[1].token.number.digits;
    out_.edition = value;
    if (value != bo::edition) {
        diagnostics_.add(whole, "lex.edition", {{"value", std::to_string(value)}});
    }
    Token token;
    token.kind = TokenKind::edition_line;
    token.span = whole;
    token.number = Decimal{value, 0};
    out_.tokens.push_back(std::move(token));
    Token newline;
    newline.kind = TokenKind::newline;
    newline.span = span(content_end_, content_end_);
    out_.tokens.push_back(std::move(newline));
}

// ---------------------------------------------------------------------------
// Step 1: characters to raw items.

void Lexer::scan(std::size_t i, std::vector<Raw>& raws) {
    const std::size_t start = i;
    while (i < content_end_) {
        const char32_t c = cps_[i].c;
        const char m = mapped(i);
        if (m == '-' && is_digit(i + 1) && sign_at(i, start)) {
            // -18 °C, HKD -5: a negative number where a value begins (G5b).
            i = number(i + 1, raws, i);
        } else if (m == ' ') {
            ++i;
        } else if (c == U'\t') {
            diagnostics_.add(span(i, i + 1), "lex.tab", {});
            ++i;
        } else if (c == U'#') {
            i = comment(i);
        } else if (m == '"') {
            i = text(i, raws);
        } else if (is_digit(i)) {
            i = number(i, raws);
        } else if (detail::is_word_char(c) || c == U'_') {
            const std::size_t from = i;
            while (is_run_char(i)) {
                ++i;
            }
            raws.push_back(Raw{true, from, i, {}, false});
        } else if (const std::size_t degrees = degree(i); degrees != i) {
            // °C or ℃: the unit of temperature, in every language (G5b).
            raws.push_back(
                Raw{false, i, degrees, word(lx_.celsius, Piece::whole, {}, i, degrees), false});
            i = degrees;
        } else if (const std::size_t next = symbol(i, raws); next != npos) {
            i = next;
        } else {
            if (m == '%') {
                diagnostics_.add(span(i, i + 1), "lex.percent", {});
            } else if (detail::is_invisible(c)) {
                diagnostics_.add(span(i, i + 1), "lex.invisible", {{"character", character(i)}});
            } else {
                diagnostics_.add(span(i, i + 1), "lex.bad-character",
                                 {{"character", character(i)}});
            }
            ++i;
        }
    }
}

bool Lexer::sign_at(const std::size_t i, const std::size_t start) const noexcept {
    // A minus directly before a digit makes the number negative where a
    // value begins: at the start of the line's code, after a space, or
    // directly after a symbol that ends no value. After a word, a number, a
    // text, a percent sign, or `)`, it subtracts: 10-3, x-3.
    if (i == start) {
        return true;
    }
    const char32_t c = cps_[i - 1].c;
    const char p = mapped(i - 1);
    return p == ' ' || p == '(' || p == ',' || p == '=' || p == '<' || p == '>' || p == '+' ||
           p == '-' || p == '*' || p == '/' || p == ':' || c == U'\u00D7' || c == U'\u00F7';
}

std::size_t Lexer::degree(const std::size_t i) const noexcept {
    // °C (U+00B0, then C ending the run) or ℃ (U+2103), where the pack set
    // spells the unit; otherwise no symbol, and i.
    if (lx_.celsius == nullptr || i >= content_end_) {
        return i;
    }
    if (cps_[i].c == U'\u2103') {
        return i + 1;
    }
    if (cps_[i].c == U'\u00B0' && i + 1 < content_end_ && cps_[i + 1].c == U'C' &&
        (i + 2 >= content_end_ || !is_run_char(i + 2))) {
        return i + 2;
    }
    return i;
}

std::size_t Lexer::comment(std::size_t i) {
    for (std::size_t j = i; j < content_end_; ++j) {
        const char32_t c = cps_[j].c;
        if (c != U'\t' && mapped(j) != ' ' && detail::is_invisible(c)) {
            diagnostics_.add(span(j, j + 1), "lex.invisible", {{"character", character(j)}});
        }
    }
    out_.comments.push_back(Comment{span(i, content_end_), std::string(slice(i, content_end_))});
    return content_end_;
}

std::size_t Lexer::text(std::size_t i, std::vector<Raw>& raws) {
    std::size_t j = i + 1;
    while (j < content_end_ && mapped(j) != '"') {
        const char32_t c = cps_[j].c;
        if (c == U'\t') {
            diagnostics_.add(span(j, j + 1), "lex.tab", {});
        } else if (mapped(j) != ' ' && detail::is_invisible(c)) {
            diagnostics_.add(span(j, j + 1), "lex.invisible", {{"character", character(j)}});
        }
        ++j;
    }
    Token token;
    token.kind = TokenKind::text;
    token.text = std::string(slice(i + 1, j));
    if (j == content_end_) {
        diagnostics_.add(span(i, j), "lex.unterminated-text", {});
        token.span = span(i, j);
    } else {
        token.span = span(i, j + 1);
        ++j;
    }
    if (token.text.size() > max_text_bytes) {
        diagnostics_.add(token.span, "lex.text-too-long",
                         {{"limit", std::to_string(max_text_bytes)}});
    }
    raws.push_back(Raw{false, i, j, std::move(token), false});
    return j;
}

std::size_t Lexer::symbol(std::size_t i, std::vector<Raw>& raws) {
    const char32_t c = cps_[i].c;
    const char m = mapped(i);
    const char next = mapped(i + 1);
    std::size_t length = 1;
    Symbol s{};
    if (c == char32_t{0x00D7}) { // ×
        s = Symbol::times;
    } else if (c == char32_t{0x00F7}) { // ÷
        s = Symbol::divide;
    } else {
        switch (m) {
        case ',':
            s = Symbol::comma;
            break;
        case ':':
            s = Symbol::colon;
            break;
        case '(':
            s = Symbol::open;
            break;
        case ')':
            s = Symbol::close;
            break;
        case '=':
            s = Symbol::equals;
            break;
        case '<':
            s = next == '=' ? Symbol::less_equal : Symbol::less;
            length = next == '=' ? 2 : 1;
            break;
        case '>':
            s = next == '=' ? Symbol::greater_equal : Symbol::greater;
            length = next == '=' ? 2 : 1;
            break;
        case '+':
            s = Symbol::plus;
            break;
        case '-':
            s = next == '>' ? Symbol::arrow : Symbol::minus;
            length = next == '>' ? 2 : 1;
            break;
        case '*':
            s = Symbol::times;
            break;
        case '/':
            s = Symbol::divide;
            break;
        default:
            return npos;
        }
    }
    Token token;
    token.kind = TokenKind::symbol;
    token.symbol = s;
    token.span = span(i, i + length);
    raws.push_back(Raw{false, i, i + length, std::move(token), false});
    return i + length;
}

std::size_t Lexer::date(std::size_t i, std::vector<Raw>& raws) {
    const auto digits_end = [&](std::size_t j) {
        while (j < content_end_ && is_digit(j)) {
            ++j;
        }
        return j;
    };
    // Digits joined by "-", twice or more: a date, whatever else it is not
    // (2027-1-6 never reads as a subtraction).
    std::vector<std::size_t> ends{digits_end(i)};
    while (ends.back() < content_end_ && mapped(ends.back()) == '-' && is_digit(ends.back() + 1)) {
        ends.push_back(digits_end(ends.back() + 1));
    }
    const auto valid = [](std::uint64_t y, std::uint64_t m, std::uint64_t d) {
        if (y < 1 || y > 9999 || m < 1 || m > 12 || d < 1) {
            return false;
        }
        constexpr std::uint64_t days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        return d <= days[m - 1] + (m == 2 && leap ? 1 : 0);
    };
    const auto value = [&](std::size_t from, std::size_t to) {
        std::uint64_t v = 0;
        for (std::size_t j = from; j < to && v < 100000; ++j) {
            v = v * 10 + static_cast<std::uint64_t>(mapped(j) - '0');
        }
        return v;
    };
    const auto make = [&](std::size_t to, std::uint64_t y, std::uint64_t m, std::uint64_t d) {
        if (!valid(y, m, d)) {
            diagnostics_.add(span(i, to), "lex.bad-date", {{"text", detail::quote(slice(i, to))}});
            return to;
        }
        Token token;
        token.kind = TokenKind::date;
        token.span = span(i, to);
        token.date = Date{static_cast<std::uint16_t>(y), static_cast<std::uint8_t>(m),
                          static_cast<std::uint8_t>(d)};
        raws.push_back(Raw{false, i, to, std::move(token), false});
        return to;
    };
    if (ends.size() >= 3) {
        std::size_t to = ends.back();
        while (to < content_end_ && (is_run_char(to) || mapped(to) == '.')) {
            ++to;
        }
        const bool iso = ends.size() == 3 && to == ends.back() && ends[0] - i == 4 &&
                         ends[1] - ends[0] == 3 && ends[2] - ends[1] == 3;
        if (!iso) {
            diagnostics_.add(span(i, to), "lex.bad-date", {{"text", detail::quote(slice(i, to))}});
            return to;
        }
        return make(to, value(i, ends[0]), value(ends[0] + 1, ends[1]),
                    value(ends[1] + 1, ends[2]));
    }
    // The packs' forms: 2027年1月6日.
    for (const auto& parts : lx_.dates) {
        std::size_t j = i;
        std::array<std::uint64_t, 3> fields{};
        bool ok = true;
        for (const auto& part : parts) {
            if (part.field != 0) {
                const std::size_t most = part.field == 'Y' ? 4 : 2;
                const std::size_t end = digits_end(j);
                if (end == j || end - j > most) {
                    ok = false;
                    break;
                }
                const std::size_t field = part.field == 'Y' ? 0 : part.field == 'M' ? 1 : 2;
                fields[field] = value(j, end);
                j = end;
                continue;
            }
            for (const char32_t c : part.literal) {
                if (j >= content_end_ || cps_[j].c != c) {
                    ok = false;
                    break;
                }
                ++j;
            }
            if (!ok) {
                break;
            }
        }
        if (ok && !is_run_char(j)) {
            return make(j, fields[0], fields[1], fields[2]);
        }
    }
    return npos;
}

std::vector<Lexer::Segment> Lexer::segments(std::string_view suffix) const {
    std::vector<Segment> out;
    std::vector<std::pair<std::uint64_t, std::size_t>> multipliers{{0, 0}};
    for (const auto& [spelling, value] : lx_.multipliers) {
        if (suffix.starts_with(spelling)) {
            multipliers.emplace_back(value, spelling.size());
        }
    }
    for (const auto& [value, bytes] : multipliers) {
        const std::string_view rest = suffix.substr(bytes);
        if (rest.empty()) {
            out.push_back({value, bytes, nullptr, nullptr});
            continue;
        }
        for (const Entry* measure : lx_.measures) {
            const std::string& word = measure->words.front();
            if (!rest.starts_with(word)) {
                continue;
            }
            const std::string_view tail = rest.substr(word.size());
            if (tail.empty()) {
                out.push_back({value, bytes, measure, nullptr});
                continue;
            }
            for (const Attach& a : lx_.attach) {
                if (tail == a.word && accepts(a.after, measure->concept_entry)) {
                    out.push_back({value, bytes, measure, &a});
                }
            }
        }
    }
    return out;
}

std::size_t Lexer::number(std::size_t i, std::vector<Raw>& raws, const std::size_t sign) {
    // A negative number begins at its sign; a date has none.
    const std::size_t from = sign != npos ? sign : i;
    if (sign == npos) {
        if (const std::size_t end = date(i, raws); end != npos) {
            return end;
        }
    }
    std::size_t k = i;
    while (k < content_end_ && (is_digit(k) || mapped(k) == '_' || mapped(k) == '.')) {
        ++k;
    }
    if (mapped(k) == ',' && is_digit(k + 1)) {
        while (k < content_end_ &&
               (is_digit(k) || mapped(k) == '_' || mapped(k) == '.' || mapped(k) == ',')) {
            ++k;
        }
        std::string suggestion = sign != npos ? "-" : "";
        for (std::size_t j = i; j < k; ++j) {
            suggestion.push_back(mapped(j) == ',' ? '_' : mapped(j));
        }
        diagnostics_.add(span(from, k), "lex.digit-comma",
                         {{"text", detail::quote(slice(from, k))}, {"suggestion", suggestion}});
        return k;
    }
    // digit+ ("_" digit+)* ("." digit+ ("_" digit+)*)?
    Decimal value;
    bool ok = true;
    bool point = false;
    bool large = false;
    char previous = 0;
    for (std::size_t j = i; j < k; ++j) {
        const char m = mapped(j);
        if (is_ascii_digit(m)) {
            const auto d = static_cast<std::uint64_t>(m - '0');
            if (value.digits > (std::numeric_limits<std::uint64_t>::max() - d) / 10) {
                large = true;
            } else {
                value.digits = value.digits * 10 + d;
            }
            if (point) {
                if (value.scale == 18) {
                    large = true;
                } else {
                    ++value.scale;
                }
            }
            previous = '0';
            continue;
        }
        if (previous != '0' || !(j + 1 < k && is_digit(j + 1)) || (m == '.' && point)) {
            ok = false;
        }
        point = point || m == '.';
        previous = m;
    }
    if (!ok) {
        diagnostics_.add(span(from, k), "lex.bad-number",
                         {{"text", detail::quote(slice(from, k))}});
        return k;
    }
    value.negative = sign != npos;
    Token token;
    token.kind = TokenKind::number;
    token.number = value;
    token.span = span(from, k);
    if (value.negative) {
        token.written.digits.push_back('-');
    }
    for (std::size_t j = i; j < k; ++j) {
        token.written.digits.push_back(mapped(j));
    }
    if (mapped(k) == '%') {
        token.kind = TokenKind::rate;
        token.span = span(from, k + 1);
        ++k;
    }
    std::size_t end = k;
    Segment segment;
    if (token.kind == TokenKind::number && is_run_char(k)) {
        while (is_run_char(end)) {
            ++end;
        }
        const std::string_view suffix = slice(k, end);
        const std::vector<Segment> found = segments(suffix);
        if (found.empty()) {
            diagnostics_.add(
                span(from, end), "lex.number-suffix",
                {{"text", detail::quote(slice(from, end))}, {"suffix", detail::quote(suffix)}});
            return end;
        }
        const auto reading = [&](const Segment& s) {
            std::string out(slice(from, k));
            std::string_view rest = suffix;
            if (s.multiplier != 0) {
                out += " + " + std::string(rest.substr(0, s.multiplier_bytes));
                rest.remove_prefix(s.multiplier_bytes);
            }
            if (s.measure != nullptr) {
                out += " + " + s.measure->words.front();
                rest.remove_prefix(s.measure->words.front().size());
            }
            if (!rest.empty()) {
                out += " + " + std::string(rest);
            }
            return out;
        };
        if (found.size() > 1) {
            diagnostics_.add(span(from, end), "lex.ambiguous",
                             {{"text", detail::quote(slice(from, end))},
                              {"first", reading(found[0])},
                              {"second", reading(found[1])}});
        }
        segment = found.front();
        token.written.multiplier = std::string(suffix.substr(0, segment.multiplier_bytes));
        if (segment.measure != nullptr) {
            token.written.measure = segment.measure->words.front();
        }
    }
    if (large || (segment.multiplier != 0 && !multiply(token.number, segment.multiplier))) {
        diagnostics_.add(span(from, end), "lex.number-too-large",
                         {{"text", detail::quote(slice(from, end))}});
        return end;
    }
    std::size_t measured = after_bytes(k, segment.multiplier_bytes);
    if (segment.measure != nullptr) {
        measured = after_bytes(measured, segment.measure->words.front().size());
        token.kind = measure_kind(segment.measure->concept_entry);
        token.concept_entry = segment.measure->concept_entry;
    }
    if (token.kind != TokenKind::rate) {
        token.span = span(from, measured);
    }
    raws.push_back(Raw{false, from, measured, std::move(token), segment.multiplier != 0});
    if (segment.attach != nullptr) {
        raws.push_back(Raw{
            false, measured, end,
            word(segment.attach->concept_entry, segment.attach->piece, {}, measured, end), false});
    }
    return end;
}

// ---------------------------------------------------------------------------
// Step 2: runs to words and names.

std::vector<const Entry*> Lexer::longest(std::string_view first,
                                         std::span<const std::string_view> next,
                                         bool vocabulary) const {
    std::vector<const Entry*> out;
    const auto it = lx_.by_first.find(first);
    if (it == lx_.by_first.end()) {
        return out;
    }
    std::size_t best = 0;
    for (const Entry& entry : it->second) {
        if (best != 0 && entry.words.size() < best) {
            break;
        }
        if (entry.words.size() - 1 > next.size()) {
            continue;
        }
        if (vocabulary && (entry.concept_entry->category == Category::keyword ||
                           entry.piece == Piece::tail || entry.piece == Piece::close)) {
            continue;
        }
        if (!std::ranges::equal(std::span(entry.words).subspan(1),
                                next.first(entry.words.size() - 1))) {
            continue;
        }
        best = entry.words.size();
        out.push_back(&entry);
    }
    return out;
}

Token Lexer::word(const Concept* entry, Piece piece, std::string form, std::size_t from,
                  std::size_t to) const {
    Token token;
    token.kind = TokenKind::word;
    token.concept_entry = entry;
    token.piece = piece;
    token.form = std::move(form);
    token.span = span(from, to);
    return token;
}

std::vector<Lexer::Item> Lexer::read_runs(const std::vector<Raw>& raws) {
    std::vector<Item> items;
    for (std::size_t k = 0; k < raws.size();) {
        if (!raws[k].run) {
            items.push_back(Item{raws[k].token, 0, raws[k].multiplied});
            ++k;
            continue;
        }
        k += read_run(raws, k, items);
    }
    return items;
}

std::size_t Lexer::read_run(const std::vector<Raw>& raws, std::size_t k, std::vector<Item>& items) {
    const Raw& raw = raws[k];
    const std::string_view text = slice(raw.from, raw.to);
    if (const auto it = lx_.multipliers.find(text); it != lx_.multipliers.end()) {
        Item item;
        item.token.span = span(raw.from, raw.to);
        item.token.text = std::string(text);
        item.multiplier = it->second;
        items.push_back(std::move(item));
        return 1;
    }
    // The runs after this one, for spellings of several words.
    std::vector<std::string_view> next;
    for (std::size_t m = k + 1;
         m < raws.size() && raws[m].run && next.size() < detail::max_spelling_words - 1; ++m) {
        next.push_back(slice(raws[m].from, raws[m].to));
    }
    const auto described = [&](const std::vector<Token>& tokens) {
        std::string out;
        for (const Token& t : tokens) {
            out += (out.empty() ? "" : " + ") +
                   std::string(source_.substr(t.span.offset, t.span.length)) + " (" +
                   std::string(t.concept_entry->id) + ")";
        }
        return out;
    };
    std::vector<Reading> readings;
    const auto add = [&](std::vector<Token> tokens, std::size_t runs) {
        std::string description = described(tokens);
        readings.push_back(Reading{std::move(tokens), runs, std::move(description)});
    };
    const auto end_of = [&](std::size_t runs) {
        return raws[k + runs - 1].to;
    };
    // A spelling.
    for (const Entry* entry : longest(text, next, false)) {
        const std::size_t runs = entry->words.size();
        add({word(entry->concept_entry, entry->piece, entry->form, raw.from, end_of(runs))}, runs);
    }
    // A prefix keyword joined to a vocabulary word: 可質押, 須親身確認, 須經.
    for (const auto& prefix : lx_.prefixes) {
        if (text.size() <= prefix.spelling.size() || !text.starts_with(prefix.spelling)) {
            continue;
        }
        const std::size_t split = after_bytes(raw.from, prefix.spelling.size());
        for (const Entry* entry : longest(text.substr(prefix.spelling.size()), next, true)) {
            const std::size_t runs = entry->words.size();
            add({word(prefix.keyword, Piece::whole, {}, raw.from, split),
                 word(entry->concept_entry, entry->piece, entry->form, split, end_of(runs))},
                runs);
        }
    }
    // An attaching word joined to a word of a category it accepts: 每GB,
    // 按發票, 個月內.
    const auto single = [&](std::string_view spelling, const std::vector<Category>& categories) {
        std::vector<const Entry*> out;
        if (const auto it = lx_.by_first.find(spelling); it != lx_.by_first.end()) {
            for (const Entry& entry : it->second) {
                if (entry.words.size() == 1 && entry.piece == Piece::whole &&
                    accepts(categories, entry.concept_entry)) {
                    out.push_back(&entry);
                }
            }
        }
        return out;
    };
    for (const Attach& a : lx_.attach) {
        if (text.size() <= a.word.size()) {
            continue;
        }
        if (!a.before.empty() && text.starts_with(a.word)) {
            const std::size_t split = after_bytes(raw.from, a.word.size());
            for (const Entry* entry : single(text.substr(a.word.size()), a.before)) {
                add({word(a.concept_entry, a.piece, {}, raw.from, split),
                     word(entry->concept_entry, entry->piece, entry->form, split, raw.to)},
                    1);
            }
        }
        if (!a.after.empty() && text.ends_with(a.word)) {
            const std::size_t split = after_bytes(raw.from, text.size() - a.word.size());
            for (const Entry* entry :
                 single(text.substr(0, text.size() - a.word.size()), a.after)) {
                add({word(entry->concept_entry, entry->piece, entry->form, raw.from, split),
                     word(a.concept_entry, a.piece, {}, split, raw.to)},
                    1);
            }
        }
    }
    if (readings.empty()) {
        items.push_back(Item{name(raw.from, raw.to), 0, false});
        return 1;
    }
    if (readings.size() > 1) {
        diagnostics_.add(span(raw.from, raw.to), "lex.ambiguous",
                         {{"text", detail::quote(text)},
                          {"first", readings[0].text},
                          {"second", readings[1].text}});
    }
    for (Token& token : readings.front().tokens) {
        items.push_back(Item{std::move(token), 0, false});
    }
    return readings.front().runs;
}

Token Lexer::name(std::size_t from, std::size_t to) {
    Token token;
    token.kind = TokenKind::name;
    token.span = span(from, to);
    token.text = std::string(slice(from, to));
    const std::string_view text = token.text;
    // HKD100: a currency or unit run into its number.
    for (const Entry* measure : lx_.measures) {
        const std::string& word = measure->words.front();
        if (text.size() > word.size() && text.starts_with(word) &&
            is_digit(after_bytes(from, word.size()))) {
            diagnostics_.add(token.span, "lex.needs-space",
                             {{"text", detail::quote(text)},
                              {"first", word},
                              {"second", detail::quote(text.substr(word.size()))}});
            return token;
        }
    }
    std::u32string points;
    for (std::size_t i = from; i < to; ++i) {
        points.push_back(cps_[i].c);
    }
    const detail::NameCheck check = detail::check_name(points);
    const auto at = [&](char32_t c) {
        const std::size_t i = from + points.find(c);
        return span(i, i + 1);
    };
    if (check.problem != detail::NameProblem::none) {
        refused_.insert(token.text);
    }
    switch (check.problem) {
    case detail::NameProblem::none:
        break;
    case detail::NameProblem::bad_start:
        diagnostics_.add(token.span, "lex.bad-name", {{"name", detail::quote(text)}});
        break;
    case detail::NameProblem::bad_character:
        diagnostics_.add(at(check.character), "lex.bad-character",
                         {{"character", detail::describe_char(check.character)}});
        break;
    case detail::NameProblem::not_normalized:
        diagnostics_.add(at(check.character), "lex.not-normalized",
                         {{"character", detail::describe_char(check.character)}});
        break;
    case detail::NameProblem::mixed_script:
        diagnostics_.add(token.span, "lex.mixed-script", {{"name", detail::quote(text)}});
        break;
    }
    if (text.size() > max_name_bytes) {
        diagnostics_.add(
            token.span, "lex.name-too-long",
            {{"name", detail::quote(text)}, {"limit", std::to_string(max_name_bytes)}});
    }
    // 可提款: 可 + 提款, if the contract declares 提款 (the parser decides).
    for (const auto& prefix : lx_.prefixes) {
        if (text.size() <= prefix.spelling.size() || !text.starts_with(prefix.spelling) ||
            is_digit(after_bytes(from, prefix.spelling.size()))) {
            continue;
        }
        const std::u32string_view rest =
            std::u32string_view(points).substr(after_bytes(from, prefix.spelling.size()) - from);
        if (detail::check_name(rest).problem == detail::NameProblem::none) {
            token.splits.push_back(
                {prefix.keyword, static_cast<std::uint32_t>(prefix.spelling.size())});
        }
    }
    return token;
}

// ---------------------------------------------------------------------------
// Step 3: numbers with their multipliers, units, and currencies.

void Lexer::merge(std::vector<Item>& items) {
    const auto source_of = [&](const Span& s) {
        return detail::quote(source_.substr(s.offset, s.length));
    };
    // 500 萬: a multiplier after its number.
    std::vector<Item> out;
    for (Item& item : items) {
        if (item.multiplier == 0) {
            out.push_back(std::move(item));
            continue;
        }
        if (out.empty() || out.back().token.kind != TokenKind::number || out.back().multiplied) {
            diagnostics_.add(item.token.span, "lex.multiplier", {{"word", item.token.text}});
            continue;
        }
        Item& number = out.back();
        const Span joined = join(number.token.span, item.token.span);
        if (!multiply(number.token.number, item.multiplier)) {
            diagnostics_.add(joined, "lex.number-too-large", {{"text", source_of(joined)}});
        }
        number.token.span = joined;
        number.token.written.multiplier = item.token.text;
        number.multiplied = true;
    }
    items = std::move(out);
    out.clear();
    // 100 Mbps, 3 噸, 30 days: a unit after its number.
    for (Item& item : items) {
        const Token& t = item.token;
        if (!out.empty() && out.back().token.kind == TokenKind::number &&
            t.kind == TokenKind::word && t.piece == Piece::whole && is_measure(t.concept_entry) &&
            t.concept_entry->category != Category::currency) {
            Token& number = out.back().token;
            number.kind = measure_kind(t.concept_entry);
            number.concept_entry = t.concept_entry;
            number.span = join(number.span, t.span);
            number.written.measure = spelled(t.span);
            continue;
        }
        out.push_back(std::move(item));
    }
    items = std::move(out);
    out.clear();
    // HKD 0.10, 120 HKD: a currency beside its number, on either side, but
    // never between two numbers, nor a number between two currencies.
    const std::size_t n = items.size();
    const auto plain = [&](std::size_t j) {
        return j < n && items[j].token.kind == TokenKind::number;
    };
    const auto currency = [&](std::size_t j) {
        if (j >= n) {
            return false;
        }
        const Token& t = items[j].token;
        return t.kind == TokenKind::word && t.piece == Piece::whole &&
               t.concept_entry->category == Category::currency;
    };
    std::vector<bool> stuck(n, false);
    for (std::size_t j = 1; j + 1 < n; ++j) {
        const bool around_currency = currency(j) && plain(j - 1) && plain(j + 1);
        const bool around_number = plain(j) && currency(j - 1) && currency(j + 1);
        if (around_currency || around_number) {
            const Span joined = join(items[j - 1].token.span, items[j + 1].token.span);
            diagnostics_.add(joined, "lex.ambiguous-money", {{"text", source_of(joined)}});
            stuck[j - 1] = stuck[j] = stuck[j + 1] = true;
        }
    }
    for (std::size_t j = 0; j < n; ++j) {
        if (j + 1 < n && !stuck[j] && !stuck[j + 1] &&
            ((currency(j) && plain(j + 1)) || (plain(j) && currency(j + 1)))) {
            const std::size_t c = currency(j) ? j : j + 1;
            Item money = std::move(items[c == j ? j + 1 : j]);
            money.token.kind = TokenKind::money;
            money.token.concept_entry = items[c].token.concept_entry;
            money.token.span = join(items[j].token.span, items[j + 1].token.span);
            money.token.written.measure = spelled(items[c].token.span);
            money.token.written.measure_first = c == j;
            out.push_back(std::move(money));
            ++j;
            continue;
        }
        out.push_back(std::move(items[j]));
    }
    items = std::move(out);
}

void Lexer::confusables() {
    std::map<std::u32string, std::string> seen;
    std::set<std::string, std::less<>> reported;
    for (const Token& token : out_.tokens) {
        if (token.kind != TokenKind::name || reported.contains(token.text) ||
            refused_.contains(token.text)) {
            continue;
        }
        const auto points = detail::code_points(token.text);
        if (!points) {
            continue;
        }
        const std::u32string key = detail::skeleton(*points);
        const auto word = lx_.skeletons.find(key);
        if (word != lx_.skeletons.end() && word->second != token.text) {
            diagnostics_.add(token.span, "lex.confusable",
                             {{"name", detail::quote(token.text)}, {"other", word->second}});
            reported.insert(token.text);
            continue;
        }
        const auto [it, inserted] = seen.try_emplace(key, token.text);
        if (!inserted && it->second != token.text) {
            diagnostics_.add(
                token.span, "lex.confusable",
                {{"name", detail::quote(token.text)}, {"other", detail::quote(it->second)}});
            reported.insert(token.text);
        }
    }
}

} // namespace

namespace {

/// Text for a dump: invisible characters as their code points, except the
/// plain space.
std::string shown(std::string_view text) {
    const auto points = detail::code_points(text);
    if (!points) {
        return std::string(text);
    }
    std::string out;
    for (const char32_t c : *points) {
        out += c != U' ' && detail::is_invisible(c)
                   ? std::format("U+{:04X}", static_cast<std::uint32_t>(c))
                   : detail::utf8(c);
    }
    return out;
}

} // namespace

Lexed lex(std::string_view source, const Lexicon& lexicon) {
    Lexed out = Lexer(source, lexicon.impl()).run();
    out.implicit_vocabulary = lexicon.impl().implicit_vocabulary;
    out.vocabularies = lexicon.impl().vocabularies;
    return out;
}

std::string to_string(const Decimal& value) {
    std::string digits = std::to_string(value.digits);
    if (value.scale != 0) {
        if (digits.size() <= value.scale) {
            digits.insert(0, value.scale + 1 - digits.size(), '0');
        }
        digits.insert(digits.size() - value.scale, 1, '.');
    }
    return value.negative ? "-" + digits : digits;
}

std::string describe(const Token& token) {
    std::string out(token_kind_names[static_cast<std::size_t>(token.kind)]);
    const auto measured = [&] {
        return out + " " + std::string(token.concept_entry->id) + " " + to_string(token.number);
    };
    switch (token.kind) {
    case TokenKind::edition_line:
    case TokenKind::number:
        return out + " " + to_string(token.number);
    case TokenKind::word:
        out += " " + std::string(token.concept_entry->id);
        if (token.piece != Piece::whole) {
            out += " piece=" + std::string(piece_names[static_cast<std::size_t>(token.piece)]);
        }
        if (!token.form.empty()) {
            out += " form=" + token.form;
        }
        return out;
    case TokenKind::name:
        out += " " + shown(token.text);
        for (const NameSplit& split : token.splits) {
            out += " split=" + std::string(split.prefix->id) + "/" +
                   shown(std::string_view(token.text).substr(split.length));
        }
        return out;
    case TokenKind::money:
    case TokenKind::quantity:
    case TokenKind::duration:
        return measured();
    case TokenKind::rate:
        return out + " " + to_string(token.number) + "%";
    case TokenKind::date:
        return out +
               std::format(" {:04}-{:02}-{:02}", token.date.year, token.date.month, token.date.day);
    case TokenKind::text:
        return out + " \"" + shown(token.text) + "\"";
    case TokenKind::symbol:
        return out + " " + std::string(symbol_texts[static_cast<std::size_t>(token.symbol)]);
    case TokenKind::newline:
    case TokenKind::indent:
    case TokenKind::dedent:
    case TokenKind::end:
        return out;
    }
    return out;
}

std::string dump(std::string_view source, const Lexed& lexed, const Pack* language) {
    const auto place = [](const Span& s) {
        return s.line == 0 ? std::string("-") : std::format("{}:{}", s.line, s.column);
    };
    const auto written = [&](const Span& s) {
        return shown(source.substr(std::min<std::size_t>(s.offset, source.size()), s.length));
    };
    std::string out;
    std::size_t c = 0;
    const auto comments_before = [&](std::uint64_t offset) {
        while (c < lexed.comments.size() && lexed.comments[c].span.offset < offset) {
            const Comment& comment = lexed.comments[c++];
            out += place(comment.span) + " comment | " + written(comment.span) + "\n";
        }
    };
    for (const Token& token : lexed.tokens) {
        comments_before(token.span.offset);
        out += place(token.span) + " " + describe(token);
        if (token.span.length > 0 && token.kind != TokenKind::indent) {
            out += " | " + written(token.span);
        }
        out += "\n";
    }
    comments_before(std::numeric_limits<std::uint64_t>::max());
    for (const Diagnostic& d : lexed.diagnostics) {
        out += place(d.span) + " " +
               std::string(severity_names[static_cast<std::size_t>(d.severity())]) + " " +
               std::string(d.code) + ": " + render(d, language) + "\n";
    }
    return out;
}

} // namespace cexchain::bo
