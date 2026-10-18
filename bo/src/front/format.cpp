// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The formatter (milestone 9 of the Bo compiler): a source in canonical
// layout, and on request in one language. format.hpp states the rules. It
// writes the parser's tokens line by line; the one change of order is a word
// with an argument that another language spells on the other side of it
// (`7 days before due`, `到期前 7日`), which it rearranges by the operands
// the parser reads. Everything it writes is read again and must give the
// same tree.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/parser.hpp>

#include "internal.hpp"

namespace cexchain::bo {

namespace {

constexpr std::size_t npos = std::string_view::npos;

/// Scripts written without spaces between words (Chinese, and the rest of
/// East Asia): from the CJK radicals on.
bool east_asian(char32_t c) noexcept {
    return c >= 0x2E80;
}

char32_t first_point(std::string_view text) {
    const auto points = detail::code_points(text);
    return points && !points->empty() ? points->front() : 0;
}

char32_t last_point(std::string_view text) {
    const auto points = detail::code_points(text);
    return points && !points->empty() ? points->back() : 0;
}

std::string trimmed(std::string_view s) {
    while (!s.empty() && s.front() == ' ') {
        s.remove_prefix(1);
    }
    while (!s.empty() && s.back() == ' ') {
        s.remove_suffix(1);
    }
    return std::string(s);
}

/// A comment without what trails it (spaces, tabs, ideographic spaces).
std::string comment_text(std::string_view text) {
    while (true) {
        if (text.ends_with(' ') || text.ends_with('\t')) {
            text.remove_suffix(1);
        } else if (text.ends_with("　")) {
            text.remove_suffix(3);
        } else {
            return std::string(text);
        }
    }
}

/// The words of a spelling on either side of its argument's place:
/// "consent of …" is {"consent of", ""}, "經 … 同意" is {"經", "同意"}.
struct Shape {
    std::string before;
    std::string after;

    friend bool operator==(const Shape&, const Shape&) = default;
};

std::optional<Shape> shape_of(std::string_view spelling) {
    const std::size_t at = spelling.find(hole);
    if (at == npos) {
        return std::nullopt;
    }
    return Shape{trimmed(spelling.substr(0, at)), trimmed(spelling.substr(at + hole.size()))};
}

/// A word's spellings, then its forms.
std::vector<std::string_view> all_spellings(const Word& word) {
    std::vector<std::string_view> out(word.spellings.begin(), word.spellings.end());
    for (const auto& [form, spelling] : word.forms) {
        out.push_back(spelling);
    }
    return out;
}

bool spells(const Word& word, std::string_view text) {
    return std::ranges::any_of(
        all_spellings(word), [&](std::string_view s) { return s.find(hole) == npos && s == text; });
}

bool spells(const Word& word, const Shape& shape) {
    return std::ranges::any_of(all_spellings(word), [&](std::string_view s) {
        const std::optional<Shape> mine = shape_of(s);
        return mine && *mine == shape;
    });
}

/// "5000000" as "5_000_000": a number written out from a multiplier.
std::string grouped(const std::string& number) {
    const std::size_t point = number.find('.');
    const std::string whole = number.substr(0, point);
    if (whole.size() <= 4) {
        return number;
    }
    std::string out;
    for (std::size_t i = 0; i < whole.size(); ++i) {
        if (i != 0 && (whole.size() - i) % 3 == 0) {
            out += '_';
        }
        out += whole[i];
    }
    return point == npos ? out : out + number.substr(point);
}

/// A pack's date form ("{Y}年{M}月{D}日") read as the lexer reads it.
bool date_matches(std::string_view pattern, std::string_view text) {
    std::size_t p = 0;
    std::size_t t = 0;
    while (p < pattern.size()) {
        if (pattern[p] == '{') {
            const std::size_t close = pattern.find('}', p);
            if (close == npos) {
                return false;
            }
            const std::size_t most = pattern.substr(p + 1, close - p - 1) == "Y" ? 4 : 2;
            std::size_t end = t;
            while (end < text.size() && text[end] >= '0' && text[end] <= '9') {
                ++end;
            }
            if (end == t || end - t > most) {
                return false;
            }
            t = end;
            p = close + 1;
            continue;
        }
        if (t >= text.size() || text[t] != pattern[p]) {
            return false;
        }
        ++t;
        ++p;
    }
    return t == text.size();
}

std::string date_in(std::string_view pattern, const Date& date) {
    std::string out;
    for (std::size_t p = 0; p < pattern.size();) {
        if (pattern[p] == '{') {
            const std::size_t close = pattern.find('}', p);
            if (close != npos) {
                const std::string_view field = pattern.substr(p + 1, close - p - 1);
                out += field == "Y"   ? std::to_string(date.year)
                       : field == "M" ? std::to_string(date.month)
                                      : std::to_string(date.day);
                p = close + 1;
                continue;
            }
        }
        out += pattern[p++];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Lines.

/// A line with tokens: where it is, how deep, and its tokens.
struct CodeLine {
    std::uint32_t line = 0;
    std::size_t depth = 0;
    /// The indentation of each enclosing block, and of this line at [depth].
    std::vector<std::uint32_t> widths;
    /// Its tokens, [first, last), without newline, indent, and dedent.
    std::size_t first = 0;
    std::size_t last = 0;
};

std::vector<CodeLine> code_lines(const std::vector<Token>& tokens) {
    std::vector<CodeLine> out;
    std::vector<std::uint32_t> widths{0};
    std::size_t depth = 0;
    std::optional<CodeLine> current;
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const Token& t = tokens[i];
        switch (t.kind) {
        case TokenKind::indent:
            ++depth;
            break;
        case TokenKind::dedent:
            depth -= depth > 0 ? 1 : 0;
            break;
        case TokenKind::newline:
            if (current) {
                out.push_back(std::move(*current));
                current.reset();
            }
            break;
        case TokenKind::end:
            break;
        default:
            if (!current) {
                widths.resize(depth + 1);
                widths[depth] = t.span.column > 0 ? t.span.column - 1 : 0;
                current = CodeLine{t.span.line, depth, widths, i, i};
            }
            current->last = i + 1;
            break;
        }
    }
    if (current) {
        out.push_back(std::move(*current));
    }
    return out;
}

/// What a line says, whatever its order and spelling: for finding the
/// line a rewrite changed.
std::vector<std::string> meanings(const std::vector<Token>& tokens, const CodeLine& line) {
    std::vector<std::string> out;
    for (std::size_t i = line.first; i < line.last; ++i) {
        const Token& t = tokens[i];
        if (t.kind == TokenKind::word) {
            out.emplace_back(t.concept_entry->id);
        } else if (t.kind != TokenKind::symbol ||
                   (t.symbol != Symbol::open && t.symbol != Symbol::close)) {
            out.push_back(describe(t));
        }
    }
    std::ranges::sort(out);
    return out;
}

// ---------------------------------------------------------------------------
// Writing a line.

struct Atom {
    std::string text;
    bool symbol = false;
    Symbol which = Symbol::comma;
    /// A word that may stand in parentheses (a value, not an action).
    bool operand = false;
    /// A full-width mark (，、（）): it carries its own space.
    bool wide = false;
};

Atom symbol_atom(Symbol s) {
    return Atom{std::string(symbol_texts[static_cast<std::size_t>(s)]), true, s};
}

Atom word_atom(std::string text) {
    return Atom{std::move(text), false, Symbol::comma};
}

/// A line's tokens grouped as the parser reads operands, so that a word with
/// an argument can be written around its argument in any language's order.
struct Node {
    enum class Kind : std::uint8_t { token, group, apply };
    Kind kind = Kind::token;
    /// token: the token. group: `(`. apply: the head or open piece, or npos.
    std::size_t first = npos;
    /// group: `)`, or npos. apply: the tail or close piece, or npos.
    std::size_t last = npos;
    const Concept* concept_entry = nullptr;
    /// group: what the parentheses hold. apply: the argument (one operand,
    /// or a condition for `applies to`).
    std::vector<Node> items;
};

struct Number {
    std::string digits;
    std::string multiplier;
};

class Formatter {
public:
    Formatter(std::string_view source, const PackSet& packs, const Lexicon& lexicon,
              const Pack* language, const std::vector<Token>& tokens, bool compact)
        : source_(source), packs_(packs), lexicon_(lexicon), language_(language), tokens_(tokens),
          compact_(compact), applies_to_(find_concept("charge.applies_to")) {
        for (const Pack& pack : packs.packs()) {
            for (const auto& [character, ascii] : pack.reading.punctuation) {
                if (const auto points = detail::code_points(character);
                    points && points->size() == 1) {
                    punctuation_.try_emplace(points->front(), ascii);
                }
            }
        }
    }

    std::string line(const CodeLine& l) {
        first_ = l.first;
        at_ = l.first;
        end_ = l.last;
        const std::vector<Node> nodes = sequence(false);
        std::vector<Atom> atoms;
        for (const Node& node : nodes) {
            emit(node, atoms);
        }
        if (language_ != nullptr) {
            separate(atoms);
        }
        return join(atoms);
    }

private:
    // Reading the line's operands, as the parser does.

    [[nodiscard]] bool is_symbol(std::size_t i, Symbol s) const {
        return i < end_ && tokens_[i].kind == TokenKind::symbol && tokens_[i].symbol == s;
    }

    [[nodiscard]] bool is_piece(std::size_t i, Piece piece) const {
        return i < end_ && tokens_[i].kind == TokenKind::word && tokens_[i].piece == piece &&
               tokens_[i].concept_entry->category != Category::keyword;
    }

    [[nodiscard]] bool starts_operand(std::size_t i) const {
        const Token& t = tokens_[i];
        switch (t.kind) {
        case TokenKind::name:
        case TokenKind::number:
        case TokenKind::money:
        case TokenKind::quantity:
        case TokenKind::duration:
        case TokenKind::rate:
        case TokenKind::date:
        case TokenKind::text:
            return true;
        case TokenKind::word:
            return t.concept_entry->category != Category::keyword && t.piece != Piece::tail &&
                   t.piece != Piece::close;
        case TokenKind::symbol:
            return t.symbol == Symbol::open;
        default:
            return false;
        }
    }

    /// Where a condition (the argument of `applies to`) ends: a comma, a
    /// closing parenthesis, an arrow, or a keyword that is not part of one.
    [[nodiscard]] bool ends_condition(std::size_t i) const {
        const Token& t = tokens_[i];
        if (t.kind == TokenKind::symbol) {
            return t.symbol == Symbol::comma || t.symbol == Symbol::close ||
                   t.symbol == Symbol::arrow || t.symbol == Symbol::colon;
        }
        if (t.kind == TokenKind::word && t.concept_entry->category == Category::keyword) {
            const std::string_view id = t.concept_entry->id;
            return id != "kw.and" && id != "kw.or" && id != "kw.not" && id != "kw.in";
        }
        return false;
    }

    std::vector<Node> sequence(bool condition) {
        std::vector<Node> out;
        while (at_ < end_) {
            if ((depth_ > 0 && is_symbol(at_, Symbol::close)) ||
                (condition && ends_condition(at_))) {
                break;
            }
            if (starts_operand(at_)) {
                out.push_back(operand());
            } else {
                out.push_back(Node{Node::Kind::token, at_, npos, nullptr, {}});
                ++at_;
            }
        }
        return out;
    }

    Node operand() {
        Node n;
        if (is_piece(at_, Piece::head) || is_piece(at_, Piece::open)) {
            const Token& head = tokens_[at_];
            n.kind = Node::Kind::apply;
            n.first = at_++;
            n.concept_entry = head.concept_entry;
            if (head.concept_entry == applies_to_) {
                n.items = sequence(true);
            } else if (at_ < end_ && starts_operand(at_)) {
                n.items.push_back(operand());
            }
            if (head.piece == Piece::open && is_piece(at_, Piece::close) &&
                tokens_[at_].concept_entry == head.concept_entry) {
                n.last = at_++;
            }
        } else if (is_symbol(at_, Symbol::open)) {
            n.kind = Node::Kind::group;
            n.first = at_++;
            ++depth_;
            n.items = sequence(false);
            --depth_;
            if (is_symbol(at_, Symbol::close)) {
                n.last = at_++;
            }
        } else {
            n.first = at_++;
        }
        // Words after their argument: 7 days `before due`.
        while (is_piece(at_, Piece::tail)) {
            Node applied;
            applied.kind = Node::Kind::apply;
            applied.last = at_;
            applied.concept_entry = tokens_[at_].concept_entry;
            applied.items.push_back(std::move(n));
            n = std::move(applied);
            ++at_;
        }
        return n;
    }

    // Writing it.

    /// A span as written, with the packs' punctuation as ASCII and
    /// separators as single spaces.
    [[nodiscard]] std::string written(const Span& s) const {
        const auto points = detail::code_points(source_.substr(s.offset, s.length));
        std::string out;
        if (!points) {
            return out;
        }
        bool gap = false;
        for (const char32_t c : *points) {
            char ascii = c < 0x80 ? static_cast<char>(c) : '\0';
            if (const auto it = punctuation_.find(c); it != punctuation_.end()) {
                ascii = it->second;
            }
            if (ascii == ' ') {
                gap = true;
                continue;
            }
            if (gap && !out.empty()) {
                out += ' ';
            }
            gap = false;
            out += ascii != '\0' ? std::string(1, ascii) : detail::utf8(c);
        }
        return out;
    }

    /// The target language's words for a concept, else English's.
    [[nodiscard]] const Word* target(const Concept* c) const { return concept_word(c, language_); }

    /// How a word with an argument is written: as written, if the target
    /// language spells it so (or there is none), else the language's first
    /// spelling.
    [[nodiscard]] Shape shape(const Node& n) const {
        Shape as_written{n.first != npos ? written(tokens_[n.first].span) : std::string(),
                         n.last != npos ? written(tokens_[n.last].span) : std::string()};
        if (language_ == nullptr) {
            return as_written;
        }
        const Word* w = target(n.concept_entry);
        if (w == nullptr || spells(*w, as_written)) {
            return as_written;
        }
        return shape_of(w->spellings.front()).value_or(as_written);
    }

    /// True if a node is written starting with words that take the operand
    /// after them: before a word that follows its argument, it then needs
    /// parentheses (`(到期前 7日) 總和`), or that word would take the operand.
    [[nodiscard]] bool head_first(const Node& n) const {
        if (n.kind != Node::Kind::apply) {
            return false;
        }
        const Shape s = shape(n);
        return !s.before.empty() && s.after.empty();
    }

    void emit(const Node& n, std::vector<Atom>& out) const {
        switch (n.kind) {
        case Node::Kind::token: {
            const Token& t = tokens_[n.first];
            out.push_back(atom(t, glued(n.first)));
            out.back().operand = t.kind == TokenKind::word && t.piece == Piece::whole &&
                                 t.concept_entry->category != Category::keyword &&
                                 t.concept_entry->category != Category::action;
            return;
        }
        case Node::Kind::group:
            out.push_back(symbol(tokens_[n.first]));
            for (const Node& item : n.items) {
                emit(item, out);
            }
            if (n.last != npos) {
                out.push_back(symbol(tokens_[n.last]));
            }
            return;
        case Node::Kind::apply:
            break;
        }
        const Shape s = shape(n);
        if (!s.before.empty()) {
            out.push_back(word_atom(s.before));
        }
        const bool wrap = s.before.empty() && !s.after.empty() &&
                          (n.items.size() != 1 || head_first(n.items.front()));
        if (wrap) {
            out.push_back(symbol_atom(Symbol::open));
        }
        for (const Node& item : n.items) {
            emit(item, out);
        }
        if (wrap) {
            out.push_back(symbol_atom(Symbol::close));
        }
        if (!s.after.empty()) {
            out.push_back(word_atom(s.after));
        }
    }

    [[nodiscard]] Atom atom(const Token& t, bool glue) const {
        switch (t.kind) {
        case TokenKind::edition_line:
            return word_atom("bo " + to_string(t.number));
        case TokenKind::word: {
            std::string text = written(t.span);
            if (language_ != nullptr && t.piece == Piece::whole && !symbol_unit(t, text)) {
                if (const Word* w = target(t.concept_entry); w != nullptr && !spells(*w, text)) {
                    text = w->spellings.front();
                }
            }
            return word_atom(std::move(text));
        }
        case TokenKind::name:
            return word_atom(t.text);
        case TokenKind::number:
        case TokenKind::money:
        case TokenKind::quantity:
        case TokenKind::duration:
        case TokenKind::rate:
            return word_atom(literal(t, glue));
        case TokenKind::date:
            return word_atom(date(t));
        case TokenKind::text:
            return word_atom("\"" + t.text + "\"");
        case TokenKind::symbol:
            return symbol(t);
        case TokenKind::newline:
        case TokenKind::indent:
        case TokenKind::dedent:
        case TokenKind::end:
            break;
        }
        return word_atom({});
    }

    /// A symbol as written: ASCII, × and ÷, or a pack's full-width mark
    /// (，、：（）) where the target language reads it; else in ASCII.
    [[nodiscard]] Atom symbol(const Token& t) const {
        Atom out = symbol_atom(t.symbol);
        const std::string as_written(source_.substr(t.span.offset, t.span.length));
        const char32_t c = first_point(as_written);
        if (c < 0x80 || as_written == "\u00D7" || as_written == "\u00F7") {
            out.text = as_written;
        } else if (language_ == nullptr || language_->reading.punctuation.contains(as_written)) {
            out.text = as_written;
            out.wide = east_asian(c);
        }
        return out;
    }

    /// True if a unit is written as its symbol (°C, or ℃), which every
    /// language reads: it stays as written.
    [[nodiscard]] static bool symbol_unit(const Token& t, std::string_view as_written) {
        const std::string_view symbol = unit_symbol(t.concept_entry);
        return !symbol.empty() && (as_written == symbol || as_written == "\u2103");
    }

    /// A unit, time unit, or currency in the target language.
    [[nodiscard]] std::string measure(const Token& t) const {
        const std::string& as_written = t.written.measure;
        if (language_ == nullptr || symbol_unit(t, as_written)) {
            return as_written;
        }
        const Word* w = target(t.concept_entry);
        if (w == nullptr || spells(*w, as_written)) {
            return as_written;
        }
        if (t.kind != TokenKind::money && t.number != Decimal{1, 0}) {
            if (const auto it = w->forms.find("plural"); it != w->forms.end()) {
                return it->second;
            }
        }
        return w->spellings.front();
    }

    /// The number and its multiplier in the target language: the same
    /// multiplier if it has it, else one of the same value, else the
    /// number written out.
    [[nodiscard]] Number number(const Token& t) const {
        Number n{t.written.digits, t.written.multiplier};
        if (language_ == nullptr || n.multiplier.empty() ||
            language_->reading.multipliers.contains(n.multiplier)) {
            return n;
        }
        const Meaning* meaning = packs_.lookup(n.multiplier);
        const std::uint64_t value = meaning != nullptr && meaning->kind == MeaningKind::multiplier
                                        ? meaning->multiplier
                                        : 0;
        for (const auto& [spelling, factor] : language_->reading.multipliers) {
            if (factor == value) {
                n.multiplier = spelling;
                return n;
            }
        }
        return Number{grouped(to_string(t.number)), {}};
    }

    /// The number, its multiplier, and its measure: joined where Chinese
    /// joins them (compact), all joined (glued), or spaced.
    [[nodiscard]] static std::string compose(const Number& n, const std::string& measure,
                                             bool measure_first, bool compact, bool glued) {
        if (glued) {
            return n.digits + n.multiplier + measure;
        }
        const bool attached_multiplier =
            compact && !n.multiplier.empty() && east_asian(first_point(n.multiplier));
        std::string out = n.digits;
        if (!n.multiplier.empty()) {
            out += (attached_multiplier ? "" : " ") + n.multiplier;
        }
        if (measure.empty()) {
            return out;
        }
        if (measure_first) {
            return measure + " " + out;
        }
        const bool attached = compact && east_asian(first_point(measure)) &&
                              measure.find(' ') == npos &&
                              (n.multiplier.empty() || attached_multiplier);
        return out + (attached ? "" : " ") + measure;
    }

    /// An amount written number first whose currency must stay joined to it
    /// (0HKD 400): spaced, the currency would stand between two numbers, or
    /// the number between two currencies, which reads as neither.
    [[nodiscard]] bool glued(std::size_t i) const {
        const Token& t = tokens_[i];
        if (t.kind != TokenKind::money || t.written.measure_first) {
            return false;
        }
        const bool number_after = i + 1 < end_ && tokens_[i + 1].kind == TokenKind::number;
        const bool currency_before = i > first_ && tokens_[i - 1].kind == TokenKind::word &&
                                     tokens_[i - 1].piece == Piece::whole &&
                                     tokens_[i - 1].concept_entry->category == Category::currency;
        return number_after || currency_before;
    }

    [[nodiscard]] std::string literal(const Token& t, bool glue) const {
        if (t.kind == TokenKind::rate) {
            return t.written.digits + "%";
        }
        const Number n = number(t);
        const std::string unit = t.kind == TokenKind::number ? std::string() : measure(t);
        if (glue) {
            return compose(n, unit, false, true, true);
        }
        std::string spaced = compose(n, unit, t.written.measure_first, false, false);
        if (!compact_) {
            return spaced;
        }
        std::string joined = compose(n, unit, t.written.measure_first, true, false);
        if (joined == spaced) {
            return spaced;
        }
        const auto a = reading(joined);
        const auto b = reading(spaced);
        return a && b && *a == *b ? joined : spaced;
    }

    /// A date: ISO as it is; a pack's form if the target language reads it,
    /// else in the language's own form, else ISO.
    [[nodiscard]] std::string date(const Token& t) const {
        std::string as_written = written(t.span);
        if (language_ == nullptr || as_written.find('-') != npos) {
            return as_written;
        }
        const std::vector<std::string>& forms = language_->reading.dates.read;
        if (std::ranges::any_of(
                forms, [&](const std::string& f) { return date_matches(f, as_written); })) {
            return as_written;
        }
        if (!forms.empty()) {
            return date_in(forms.front(), t.date);
        }
        return std::format("{:04}-{:02}-{:02}", t.date.year, t.date.month, t.date.day);
    }

    /// The tokens a text reads as alone, or nullopt if it has problems.
    [[nodiscard]] std::optional<std::vector<std::string>> reading(std::string_view text) const {
        if (const auto it = readings_.find(text); it != readings_.end()) {
            return it->second;
        }
        std::optional<std::vector<std::string>> out;
        if (const Lexed lexed = lex(text, lexicon_); lexed.diagnostics.empty()) {
            out.emplace();
            for (const Token& t : lexed.tokens) {
                if (t.kind != TokenKind::newline && t.kind != TokenKind::end) {
                    out->push_back(describe(t));
                }
            }
        }
        readings_.emplace(std::string(text), out);
        return out;
    }

    /// Two words written without spaces between them join when the joined
    /// text reads as the same tokens (可質押 is 可 + 質押).
    [[nodiscard]] bool joins(const std::string& run, const std::string& next) const {
        const auto together = reading(run + next);
        if (!together) {
            return false;
        }
        auto expected = reading(run);
        const auto after = reading(next);
        if (!expected || !after) {
            return false;
        }
        expected->insert(expected->end(), after->begin(), after->end());
        return *together == *expected;
    }

    /// Words side by side that the new language reads as one longer word
    /// (於 真人, written in English, is `in person`): the first of them that
    /// may stand in parentheses gets them (`in (person)`), which the parser
    /// reads as the word alone.
    void separate(std::vector<Atom>& atoms) const {
        for (std::size_t j = 1; j < atoms.size(); ++j) {
            // The shortest run of words ending at j that reads as something
            // else than its words one by one.
            std::optional<std::vector<std::string>> expected = reading(atoms[j].text);
            std::string text = atoms[j].text;
            std::size_t merged = npos;
            for (std::size_t s = j; expected && s > 0 && j - s + 1 < detail::max_spelling_words;
                 --s) {
                const Atom& before = atoms[s - 1];
                if (before.symbol || atoms[j].symbol) {
                    break;
                }
                const auto alone = reading(before.text);
                if (!alone) {
                    break;
                }
                expected->insert(expected->begin(), alone->begin(), alone->end());
                text = before.text + " " + text;
                if (reading(text) != expected) {
                    merged = s - 1;
                    break;
                }
            }
            if (merged == npos) {
                continue;
            }
            for (std::size_t w = merged; w <= j; ++w) {
                if (atoms[w].operand) {
                    atoms[w].operand = false;
                    atoms.insert(atoms.begin() + static_cast<std::ptrdiff_t>(w) + 1,
                                 symbol_atom(Symbol::close));
                    atoms.insert(atoms.begin() + static_cast<std::ptrdiff_t>(w),
                                 symbol_atom(Symbol::open));
                    break;
                }
            }
        }
    }

    [[nodiscard]] std::string join(const std::vector<Atom>& atoms) const {
        std::string out;
        // The words written so far without a space or a symbol between them.
        std::string run;
        for (std::size_t k = 0; k < atoms.size(); ++k) {
            const Atom& a = atoms[k];
            if (k == 0) {
                out = a.text;
                run = a.symbol ? std::string() : a.text;
                continue;
            }
            const Atom& p = atoms[k - 1];
            // A full-width mark carries its own space, except that a comma
            // between digits would read as one number (5，6).
            const bool wide =
                compact_ &&
                (a.wide || (p.wide && !(p.which == Symbol::comma && !a.text.empty() &&
                                        a.text.front() >= '0' && a.text.front() <= '9')));
            bool space = !(p.symbol && p.which == Symbol::open) &&
                         !(a.symbol && (a.which == Symbol::close || a.which == Symbol::comma ||
                                        a.which == Symbol::colon)) &&
                         !wide;
            if (space && compact_ && !p.symbol && !a.symbol && east_asian(last_point(p.text)) &&
                east_asian(first_point(a.text)) && joins(run, a.text)) {
                space = false;
            }
            if (space) {
                out += ' ';
            }
            out += a.text;
            if (a.symbol) {
                run.clear();
            } else if (space || p.symbol) {
                run = a.text;
            } else {
                run += a.text;
            }
        }
        return out;
    }

    std::string_view source_;
    const PackSet& packs_;
    const Lexicon& lexicon_;
    const Pack* language_;
    const std::vector<Token>& tokens_;
    bool compact_;
    const Concept* applies_to_;
    std::map<char32_t, char> punctuation_;
    mutable std::map<std::string, std::optional<std::vector<std::string>>, std::less<>> readings_;
    std::size_t first_ = 0;
    std::size_t at_ = 0;
    std::size_t end_ = 0;
    std::size_t depth_ = 0;
};

// ---------------------------------------------------------------------------
// The file.

/// The block a comment on a line of its own belongs to: between the code
/// lines before and after it, the deepest whose indentation its column
/// reaches.
std::size_t comment_depth(std::uint32_t width, const CodeLine* before, const CodeLine* after) {
    if (before == nullptr) {
        return after != nullptr ? after->depth : 0;
    }
    const std::size_t low = after != nullptr ? std::min(before->depth, after->depth) : 0;
    const std::size_t high =
        after != nullptr ? std::max(before->depth, after->depth) : before->depth;
    for (std::size_t d = high;; --d) {
        const std::uint32_t at = d <= before->depth ? before->widths[d] : after->widths[d];
        if (at <= width || d == low) {
            return d;
        }
    }
}

/// A line of code or a comment, in the order the file is written.
struct Item {
    std::uint32_t line;
    bool code;
    std::size_t index;
    /// Written after a blank line whatever the lines say (after the `use`
    /// lines moved first).
    bool blank_before = false;
};

bool is_use_line(const std::vector<Token>& tokens, const CodeLine& line) {
    const Token& t = tokens[line.first];
    return t.kind == TokenKind::word && t.concept_entry != nullptr &&
           t.concept_entry->id == "kw.use";
}

std::string use_pack(const std::vector<Token>& tokens, const CodeLine& line) {
    return line.first + 1 < line.last ? tokens[line.first + 1].text : std::string();
}

/// `use` lines first (after `bo N`), sorted by pack id (D-054): if they are
/// not, they move there, each a line after the other, and the rest follows
/// after a blank line.
void first_uses(std::vector<Item>& items, const std::vector<CodeLine>& lines,
                const std::vector<Token>& tokens) {
    std::vector<Item> uses;
    std::vector<Item> rest;
    bool in_place = true;
    bool other_code = false;
    for (const Item& item : items) {
        const bool use = item.code && is_use_line(tokens, lines[item.index]);
        if (use) {
            in_place = in_place && !other_code &&
                       (uses.empty() || use_pack(tokens, lines[uses.back().index]) <
                                            use_pack(tokens, lines[item.index]));
            uses.push_back(item);
        } else {
            rest.push_back(item);
            const bool edition =
                item.code && tokens[lines[item.index].first].kind == TokenKind::edition_line;
            other_code = other_code || (item.code && !edition);
        }
    }
    if (in_place) {
        return;
    }
    std::ranges::stable_sort(uses, {},
                             [&](const Item& item) { return use_pack(tokens, lines[item.index]); });
    // After the edition line, if there is one; else first.
    const auto edition = std::ranges::find_if(rest, [&](const Item& item) {
        return item.code && tokens[lines[item.index].first].kind == TokenKind::edition_line;
    });
    const auto at = edition == rest.end() ? rest.begin() : edition + 1;
    items.assign(rest.begin(), at);
    const std::uint32_t top = items.empty() ? 0 : items.back().line;
    for (std::size_t i = 0; i < uses.size(); ++i) {
        Item item = uses[i];
        item.line = top + 1 + static_cast<std::uint32_t>(i);
        items.push_back(item);
    }
    // The rest after a blank line, its lines counted without the use lines
    // that left them, so that only its own blank lines separate it.
    for (auto it = at; it != rest.end(); ++it) {
        Item item = *it;
        const auto moved =
            std::ranges::count_if(uses, [&](const Item& u) { return u.line < it->line; });
        item.line -= static_cast<std::uint32_t>(moved);
        item.blank_before = it == at;
        items.push_back(item);
    }
}

std::string write(std::string_view source, const PackSet& packs, const Lexicon& lexicon,
                  const Pack* language, const Lexed& lexed, const Parsed& parsed, bool compact) {
    const std::vector<CodeLine> lines = code_lines(parsed.tokens);
    Formatter formatter(source, packs, lexicon, language, parsed.tokens, compact);

    // Comments after code, by line; the others on lines of their own.
    std::map<std::uint32_t, std::size_t> code_at;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        code_at.emplace(lines[i].line, i);
    }
    std::map<std::uint32_t, std::size_t> after_code;
    std::vector<Item> items;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        items.push_back({lines[i].line, true, i});
    }
    for (std::size_t c = 0; c < lexed.comments.size(); ++c) {
        const std::uint32_t at = lexed.comments[c].span.line;
        if (code_at.contains(at)) {
            after_code.emplace(at, c);
        } else {
            items.push_back({at, false, c});
        }
    }
    std::ranges::stable_sort(items, {}, &Item::line);
    first_uses(items, lines, parsed.tokens);

    std::string out;
    std::uint32_t previous = 0;
    const CodeLine* before = nullptr;
    std::size_t next_code = 0;
    for (const Item& item : items) {
        if (!out.empty() && (item.line > previous + 1 || item.blank_before)) {
            out += '\n';
        }
        previous = item.line;
        if (item.code) {
            const CodeLine& line = lines[item.index];
            out += std::string(format_indent * line.depth, ' ') + formatter.line(line);
            if (const auto it = after_code.find(line.line); it != after_code.end()) {
                out += "  " + comment_text(lexed.comments[it->second].text);
            }
            before = &line;
            next_code = item.index + 1;
        } else {
            const Comment& comment = lexed.comments[item.index];
            const CodeLine* after = next_code < lines.size() ? &lines[next_code] : nullptr;
            const std::uint32_t width = comment.span.column > 0 ? comment.span.column - 1 : 0;
            out += std::string(format_indent * comment_depth(width, before, after), ' ') +
                   comment_text(comment.text);
        }
        out += '\n';
    }
    return out;
}

/// Each token as describe() writes it, those of `use` lines (which the
/// formatter moves) left out.
std::vector<std::string> token_texts(const std::vector<Token>& tokens) {
    std::vector<std::string> out;
    std::set<std::uint32_t> uses;
    for (const CodeLine& line : code_lines(tokens)) {
        if (is_use_line(tokens, line)) {
            uses.insert(line.line);
        }
    }
    for (const Token& t : tokens) {
        if (!uses.contains(t.span.line) || t.kind == TokenKind::end) {
            out.push_back(describe(t));
        }
    }
    return out;
}

/// Where a rewrite reads differently from its source, if it does.
struct Difference {
    bool differs = false;
    Span where;
};

Difference compare(const Lexed& lexed, const Parsed& parsed, std::string_view text,
                   const Lexicon& lexicon, bool same_tokens) {
    const Lexed again = lex(text, lexicon);
    const Parsed reparsed = parse(text, again);
    bool same = !has_errors(again.diagnostics) && reparsed.diagnostics.empty() &&
                again.edition == lexed.edition && dump(reparsed.file) == dump(parsed.file) &&
                again.comments.size() == lexed.comments.size();
    if (same) {
        // The same comments; in another order where `use` lines moved with
        // the comments after them.
        std::vector<std::string> before;
        std::vector<std::string> after;
        for (std::size_t c = 0; c < lexed.comments.size(); ++c) {
            before.push_back(comment_text(lexed.comments[c].text));
            after.push_back(comment_text(again.comments[c].text));
        }
        std::ranges::sort(before);
        std::ranges::sort(after);
        same = before == after;
    }
    if (same && same_tokens) {
        // The same tokens, the `use` lines (which may move) aside.
        same = token_texts(reparsed.tokens) == token_texts(parsed.tokens);
    }
    if (same) {
        return {};
    }
    // The first line whose words differ, else the line of the first problem.
    const std::vector<CodeLine> mine = code_lines(parsed.tokens);
    const std::vector<CodeLine> theirs = code_lines(reparsed.tokens);
    for (std::size_t i = 0; i < mine.size(); ++i) {
        if (i >= theirs.size() ||
            meanings(parsed.tokens, mine[i]) != meanings(reparsed.tokens, theirs[i])) {
            return {true, parsed.tokens[mine[i].first].span};
        }
    }
    std::vector<Diagnostic> problems = again.diagnostics;
    problems.insert(problems.end(), reparsed.diagnostics.begin(), reparsed.diagnostics.end());
    for (const Diagnostic& d : problems) {
        for (std::size_t i = 0; i < theirs.size() && i < mine.size(); ++i) {
            if (theirs[i].line == d.span.line) {
                return {true, parsed.tokens[mine[i].first].span};
            }
        }
    }
    return {true, {}};
}

Formatted formatted(std::string_view source, const PackSet& packs, const Lexicon& lexicon,
                    const Pack* language) {
    Formatted out;
    const Lexed lexed = lex(source, lexicon);
    const Parsed parsed = parse(source, lexed);
    if (has_errors(lexed.diagnostics) || !parsed.diagnostics.empty()) {
        out.diagnostics = lexed.diagnostics;
        out.diagnostics.insert(out.diagnostics.end(), parsed.diagnostics.begin(),
                               parsed.diagnostics.end());
        std::ranges::stable_sort(out.diagnostics, {}, [](const Diagnostic& d) {
            return d.span.line == 0 ? std::numeric_limits<std::uint64_t>::max()
                                    : std::uint64_t{d.span.offset};
        });
        return out;
    }
    // Words joined as Chinese is written, then, if that reads differently
    // (packs could make a joined word read otherwise in its context), with
    // spaces between all of them.
    Difference difference;
    for (const bool compact : {true, false}) {
        std::string text = write(source, packs, lexicon, language, lexed, parsed, compact);
        difference = compare(lexed, parsed, text, lexicon, language == nullptr);
        if (!difference.differs) {
            out.source = std::move(text);
            return out;
        }
    }
    detail::Diagnostics problems;
    if (language != nullptr) {
        problems.add(difference.where, "fmt.unstable", {{"language", language->id}});
    } else {
        problems.add(difference.where, "fmt.internal", {});
    }
    out.diagnostics = problems.take();
    return out;
}

} // namespace

// With the body here, GCC 16.2 stops with an internal compiler error
// (gimple_add_tmp_var) on the declaration's postcondition; returning a call
// avoids it.
Formatted format_source(std::string_view source, const PackSet& packs, const Lexicon& lexicon,
                        const Pack* language) {
    return formatted(source, packs, lexicon, language);
}

} // namespace cexchain::bo
