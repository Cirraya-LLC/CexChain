// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The parser (milestone 3 of the Bo compiler): tokens to the tree of
// ast.hpp, by recursive descent, one line at a time. The grammar is in
// parser.hpp. Two passes: the first collects the names the contract
// declares, which decide the prefix splits the lexer left open (可提款) and
// which names are parties and actions; the second builds the tree.
// Nothing depends on addresses or unordered iteration.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/parser.hpp>

#include "internal.hpp"

namespace cexchain::bo {

namespace {

using ast::Expr;
using ast::ExprKind;
using ast::Operator;
using ast::Statement;

/// The concepts the grammar names.
struct Known {
    const Concept* contract;
    const Concept* parties;
    const Concept* can;
    const Concept* by;
    const Concept* to;
    const Concept* with;
    const Concept* requires_;
    const Concept* when;
    const Concept* if_;
    const Concept* otherwise;
    const Concept* and_;
    const Concept* or_;
    const Concept* not_;
    const Concept* each;
    const Concept* in;
    const Concept* reject;
    const Concept* test;
    const Concept* use;
    const Concept* charge;
    const Concept* tax;
    const Concept* applies_to;
    const Concept* at;
    const Concept* in_person;
};

const Concept* concept_of(std::string_view id) noexcept {
    const Concept* c = find_concept(id);
    BO_ASSERT(c != nullptr);
    return c;
}

const Known& known() {
    static const Known k{
        concept_of("kw.contract"),   concept_of("kw.parties"),     concept_of("kw.can"),
        concept_of("kw.by"),         concept_of("kw.to"),          concept_of("kw.with"),
        concept_of("kw.requires"),   concept_of("kw.when"),        concept_of("kw.if"),
        concept_of("kw.otherwise"),  concept_of("kw.and"),         concept_of("kw.or"),
        concept_of("kw.not"),        concept_of("kw.each"),        concept_of("kw.in"),
        concept_of("kw.reject"),     concept_of("kw.test"),        concept_of("kw.use"),
        concept_of("charge.charge"), concept_of("charge.tax"),     concept_of("charge.applies_to"),
        concept_of("time.at"),       concept_of("cond.in_person"),
    };
    return k;
}

/// The names a contract declares (see parser.hpp).
struct Declared {
    std::set<std::string, std::less<>> names;
    std::set<std::string, std::less<>> parties;
    std::set<std::string, std::less<>> actions;
};

Span join(const Span& a, const Span& b) noexcept {
    if (b.offset + b.length < a.offset) {
        return a;
    }
    return Span{a.line, a.column, a.offset, b.offset + b.length - a.offset};
}

bool is_literal(TokenKind kind) noexcept {
    switch (kind) {
    case TokenKind::number:
    case TokenKind::money:
    case TokenKind::quantity:
    case TokenKind::duration:
    case TokenKind::rate:
    case TokenKind::date:
    case TokenKind::text:
        return true;
    default:
        return false;
    }
}

ast::LiteralKind literal_kind(TokenKind kind) noexcept {
    switch (kind) {
    case TokenKind::money:
        return ast::LiteralKind::money;
    case TokenKind::quantity:
        return ast::LiteralKind::quantity;
    case TokenKind::duration:
        return ast::LiteralKind::duration;
    case TokenKind::rate:
        return ast::LiteralKind::rate;
    case TokenKind::date:
        return ast::LiteralKind::date;
    case TokenKind::text:
        return ast::LiteralKind::text;
    default:
        return ast::LiteralKind::number;
    }
}

std::optional<Operator> comparison_of(const Token& t) noexcept {
    if (t.kind == TokenKind::word && t.concept_entry == known().in) {
        return Operator::member;
    }
    if (t.kind != TokenKind::symbol) {
        return std::nullopt;
    }
    switch (t.symbol) {
    case Symbol::equals:
        return Operator::equals;
    case Symbol::less:
        return Operator::less;
    case Symbol::less_equal:
        return Operator::less_equal;
    case Symbol::greater:
        return Operator::greater;
    case Symbol::greater_equal:
        return Operator::greater_equal;
    default:
        return std::nullopt;
    }
}

/// The If that an `otherwise` line would join, with its depth; `broken`
/// when the if before it could not be read, so that its `otherwise` lines
/// are skipped quietly instead of each being an error.
struct OpenIf {
    ast::If* target = nullptr;
    std::size_t depth = 0;
    bool broken = false;
};

class Parser {
public:
    Parser(std::string_view source, const std::vector<Token>& tokens, const Declared& declared,
           const std::set<std::uint32_t>& quiet, detail::Diagnostics& diagnostics)
        : source_(source), tokens_(tokens), declared_(declared), quiet_(quiet),
          diagnostics_(diagnostics) {}

    ast::File run(std::uint64_t edition);
    [[nodiscard]] const Declared& found() const noexcept { return found_; }

private:
    // --- Tokens.
    [[nodiscard]] const Token& at(std::size_t i) const noexcept {
        return tokens_[std::min(i, tokens_.size() - 1)];
    }
    [[nodiscard]] const Token& peek(std::size_t ahead = 0) const noexcept {
        return at(pos_ + ahead);
    }
    const Token& take() noexcept {
        last_ = pos_;
        if (pos_ + 1 < tokens_.size()) {
            ++pos_;
        }
        return tokens_[last_];
    }
    [[nodiscard]] bool at_line_end() const noexcept {
        const TokenKind k = peek().kind;
        return k == TokenKind::newline || k == TokenKind::end;
    }
    [[nodiscard]] bool at_kind(TokenKind kind) const noexcept { return peek().kind == kind; }
    [[nodiscard]] static bool is_kw(const Token& t, const Concept* keyword) noexcept {
        return t.kind == TokenKind::word && t.concept_entry == keyword;
    }
    [[nodiscard]] bool at_kw(const Concept* keyword) const noexcept {
        return is_kw(peek(), keyword);
    }
    [[nodiscard]] static bool is_symbol(const Token& t, Symbol s) noexcept {
        return t.kind == TokenKind::symbol && t.symbol == s;
    }
    [[nodiscard]] bool at_symbol(Symbol s) const noexcept { return is_symbol(peek(), s); }
    [[nodiscard]] std::string written(const Token& t) const {
        const std::size_t from = std::min<std::size_t>(t.span.offset, source_.size());
        return std::string(source_.substr(from, t.span.length));
    }
    /// The span from token `first` to the last one taken.
    [[nodiscard]] Span span_from(std::size_t first) const noexcept {
        return join(at(first).span, at(std::max(first, last_)).span);
    }

    // --- What tokens are.
    [[nodiscard]] bool is_action(const Token& t) const {
        if (t.kind == TokenKind::word) {
            return t.piece == Piece::whole && t.concept_entry->category == Category::action;
        }
        return t.kind == TokenKind::name && declared_.actions.contains(t.text);
    }
    [[nodiscard]] bool is_party(const Token& t) const {
        if (t.kind == TokenKind::word) {
            return t.piece == Piece::whole && t.concept_entry->category == Category::role;
        }
        return t.kind == TokenKind::name && declared_.parties.contains(t.text);
    }
    /// An action begins at `i`: an action, or a party just before one.
    [[nodiscard]] bool starts_action(std::size_t i) const {
        return is_action(at(i)) || (is_party(at(i)) && is_action(at(i + 1)));
    }
    [[nodiscard]] static bool starts_operand(const Token& t) noexcept {
        if (is_literal(t.kind) || t.kind == TokenKind::name) {
            return true;
        }
        if (t.kind == TokenKind::word) {
            return t.concept_entry->category != Category::keyword &&
                   (t.piece == Piece::whole || t.piece == Piece::head || t.piece == Piece::open);
        }
        return is_symbol(t, Symbol::open);
    }
    /// An operand that is not the beginning of an action. In a test step's
    /// `with`, a value also ends before `at DATE` and `in person`, which
    /// belong to the step (`we create with amount = HKD 5 at 2027-01-06`).
    [[nodiscard]] bool starts_value() const {
        if (step_with_ && peek().kind == TokenKind::word &&
            (peek().concept_entry == known().at || peek().concept_entry == known().in_person)) {
            return false;
        }
        return starts_operand(peek()) && !starts_action(pos_);
    }
    [[nodiscard]] bool starts_condition() const { return at_kw(known().not_) || starts_value(); }
    /// A name or a word that `=` may set.
    [[nodiscard]] static bool is_target(const Token& t) noexcept {
        return t.kind == TokenKind::name || (t.kind == TokenKind::word && t.piece == Piece::whole &&
                                             t.concept_entry->category != Category::keyword);
    }

    // --- Problems.
    bool fail(const Span& where, std::string_view code, detail::Args args) {
        if (!failed_) {
            failed_ = true;
            if (!quiet_.contains(where.line)) {
                diagnostics_.add(where, code, args);
            }
        }
        return false;
    }
    /// A problem with the current token: a piece out of place, `use`, or
    /// `code` with the token as written.
    bool fail_found(std::string_view code) {
        const Token& t = peek();
        if (t.kind == TokenKind::word && t.piece == Piece::tail) {
            return fail(t.span, "parse.missing-argument",
                        {{"text", written(t)}, {"concept", std::string(t.concept_entry->id)}});
        }
        if (t.kind == TokenKind::word && t.piece == Piece::close) {
            return fail(t.span, "parse.missing-head",
                        {{"text", written(t)}, {"concept", std::string(t.concept_entry->id)}});
        }
        if (is_kw(t, known().use)) {
            return fail(t.span, "parse.reserved", {{"word", written(t)}});
        }
        return fail(t.span, code, {{"found", written(t)}});
    }
    /// Something must follow the last token taken: `code` names what.
    bool fail_expected(std::string_view code) {
        const Token& t = peek();
        if ((t.kind == TokenKind::word && t.piece != Piece::whole && t.piece != Piece::head &&
             t.piece != Piece::open) ||
            is_kw(t, known().use)) {
            return fail_found(code);
        }
        return fail(t.span, code, {{"after", written(at(last_))}});
    }

    // --- Lines and blocks.
    void skip_line() noexcept {
        // Lines end with a newline before any block token; stopping at one
        // anyway keeps blocks whole whatever the tokens.
        while (!at_line_end() && !at_kind(TokenKind::indent) && !at_kind(TokenKind::dedent)) {
            take();
        }
        if (at_kind(TokenKind::newline)) {
            take();
        }
    }
    void skip_block() noexcept {
        if (!at_kind(TokenKind::indent)) {
            return;
        }
        std::size_t depth = 0;
        while (!at_kind(TokenKind::end)) {
            const TokenKind k = take().kind;
            if (k == TokenKind::indent) {
                ++depth;
            } else if (k == TokenKind::dedent && --depth == 0) {
                return;
            }
        }
    }
    /// Ends a line whose clause or statement was read (`ok`), or not: the
    /// rest of the line is an error if anything is left.
    void end_line(bool ok) {
        if (ok && !failed_ && !at_line_end()) {
            fail_found("parse.trailing");
        }
        skip_line();
    }
    /// After a line that takes no block: one under it is an error.
    void no_block() {
        if (at_kind(TokenKind::indent)) {
            if (!failed_) {
                fail(peek().span, "parse.unexpected-block", {});
            }
            skip_block();
        }
    }
    /// The lines of the block under a header, if there is one, each read by
    /// `line` (which reads a whole line, its end, and any block under it).
    template <class F>
    bool block(F&& line) {
        if (!at_kind(TokenKind::indent)) {
            return false;
        }
        take();
        while (!at_kind(TokenKind::dedent) && !at_kind(TokenKind::end)) {
            if (at_kind(TokenKind::newline)) {
                take();
                continue;
            }
            if (at_kind(TokenKind::indent)) {
                failed_ = false;
                fail(peek().span, "parse.unexpected-block", {});
                skip_block();
                continue;
            }
            failed_ = false;
            expr_depth_ = 0;
            line();
        }
        if (at_kind(TokenKind::dedent)) {
            take();
        }
        return true;
    }

    // --- Expressions.
    /// Counts nesting while it lives; false once too deep.
    class Deeper {
    public:
        explicit Deeper(Parser& p) noexcept : p_(p) { ++p_.expr_depth_; }
        Deeper(const Deeper&) = delete;
        Deeper& operator=(const Deeper&) = delete;
        ~Deeper() { --p_.expr_depth_; }
        [[nodiscard]] bool ok() {
            if (p_.expr_depth_ <= max_parse_depth) {
                return true;
            }
            return p_.fail(p_.peek().span, "parse.too-deep",
                           {{"limit", std::to_string(max_parse_depth)}});
        }

    private:
        Parser& p_;
    };

    Expr token_expr(const Token& t) const;
    /// An expression, and whether it is words side by side outside
    /// parentheses (`monthly HKD 120`), which no operator may take.
    struct Term {
        Expr expr;
        bool bare = false;
    };
    std::optional<Expr> operand();
    std::optional<Term> phrase();
    std::optional<Term> product();
    std::optional<Term> sum();
    std::optional<Expr> comparison();
    std::optional<Expr> negation();
    std::optional<Expr> conjunction();
    std::optional<Expr> condition();
    /// A condition must come next.
    std::optional<Expr> required_condition() {
        if (!starts_condition()) {
            fail_expected("parse.expected-value");
            return std::nullopt;
        }
        return condition();
    }
    std::optional<Expr> required_operand(std::string_view code) {
        if (!starts_operand(peek())) {
            fail_expected(code);
            return std::nullopt;
        }
        return operand();
    }
    std::optional<Term> binary(Operator op, Term left, Term right, const Token& sign);
    static Expr logic(Operator op, Expr left, Expr right) {
        Expr e;
        e.kind = ExprKind::binary;
        e.op = op;
        e.span = join(left.span, right.span);
        e.operands.push_back(std::move(left));
        e.operands.push_back(std::move(right));
        return e;
    }

    // --- Clauses and statements.
    void clause(std::vector<ast::Clause>& out);
    void use_line(std::vector<ast::Use>& out);
    bool contract(std::vector<ast::Clause>& out);
    bool parties(std::vector<ast::Clause>& out);
    void block_clause(std::vector<ast::Clause>& out);
    void can(std::vector<ast::Clause>& out);
    void when(std::vector<ast::Clause>& out);
    void test(std::vector<ast::Clause>& out);
    std::optional<ast::Field> field(bool input);
    std::optional<ast::Set> set_item();
    std::optional<ast::Do> action(bool step);
    bool actions(std::vector<ast::Do>& out);
    std::optional<ast::Expect> expect();
    /// The block under a header, its lines read as statements at `depth`.
    bool body(std::vector<Statement>& out, std::size_t depth) {
        OpenIf open;
        return block([&] { statement_line(out, depth, open); });
    }
    void statement_line(std::vector<Statement>& out, std::size_t depth, OpenIf& open);
    bool simple(std::vector<Statement>& out);
    void if_statement(std::vector<Statement>& out, std::size_t depth);
    void each(std::vector<Statement>& out, std::size_t depth);
    OpenIf otherwise(OpenIf open);
    /// A line that begins with a name the lexer could split (可提款) and
    /// cannot be read: say that the split needs a declaration or a space.
    bool split_hint(const Token& t) {
        if (t.kind != TokenKind::name || t.splits.empty()) {
            return false;
        }
        const NameSplit& s = t.splits.front();
        fail(t.span, "parse.undeclared-split",
             {{"name", t.text},
              {"prefix", t.text.substr(0, s.length)},
              {"rest", t.text.substr(s.length)}});
        return true;
    }
    /// The first token of a line could not start it: say why.
    bool fail_line_start(std::string_view code) {
        if (split_hint(peek())) {
            return false;
        }
        return fail_found(code);
    }

    std::string_view source_;
    const std::vector<Token>& tokens_;
    const Declared& declared_;
    const std::set<std::uint32_t>& quiet_;
    detail::Diagnostics& diagnostics_;
    Declared found_;
    std::size_t pos_ = 0;
    std::size_t last_ = 0;
    std::size_t expr_depth_ = 0;
    bool failed_ = false;
    /// Reading the values of a test step's `with`.
    bool step_with_ = false;
    bool have_contract_ = false;
    bool have_parties_ = false;
};

Expr Parser::token_expr(const Token& t) const {
    Expr e;
    e.span = t.span;
    if (is_literal(t.kind)) {
        e.kind = ExprKind::literal;
        e.literal.kind = literal_kind(t.kind);
        e.literal.number = t.number;
        e.literal.date = t.date;
        e.literal.text = t.text;
        if (t.kind == TokenKind::money || t.kind == TokenKind::quantity ||
            t.kind == TokenKind::duration) {
            e.literal.unit = t.concept_entry;
        }
    } else if (t.kind == TokenKind::name) {
        e.kind = ExprKind::name;
        e.name = t.text;
    } else {
        e.kind = ExprKind::word;
        e.concept_entry = t.concept_entry;
    }
    return e;
}

std::optional<Expr> Parser::operand() {
    Deeper deeper(*this);
    if (!deeper.ok()) {
        return std::nullopt;
    }
    const Token& t = peek();
    Expr e;
    if (is_literal(t.kind) || t.kind == TokenKind::name ||
        (t.kind == TokenKind::word && t.piece == Piece::whole &&
         t.concept_entry->category != Category::keyword)) {
        e = token_expr(take());
    } else if (t.kind == TokenKind::word && t.concept_entry->category != Category::keyword &&
               (t.piece == Piece::head || t.piece == Piece::open)) {
        const Token& head = take();
        // `applies to` takes the rest of a condition; every other word one
        // operand, so that `consent of bank` and `經 銀行 同意` agree.
        std::optional<Expr> argument = head.concept_entry == known().applies_to
                                           ? required_condition()
                                           : required_operand("parse.expected-value");
        if (!argument) {
            return std::nullopt;
        }
        if (head.piece == Piece::open) {
            const Token& close = peek();
            if (close.kind != TokenKind::word || close.piece != Piece::close ||
                close.concept_entry != head.concept_entry) {
                fail(head.span, "parse.missing-tail",
                     {{"text", written(head)}, {"concept", std::string(head.concept_entry->id)}});
                return std::nullopt;
            }
            take();
        }
        e.kind = ExprKind::apply;
        e.concept_entry = head.concept_entry;
        e.span = join(head.span, at(last_).span);
        e.operands.push_back(std::move(*argument));
    } else if (is_symbol(t, Symbol::open)) {
        const Token& open = take();
        std::optional<Expr> first = required_condition();
        if (!first) {
            return std::nullopt;
        }
        if (at_symbol(Symbol::comma)) {
            Expr list;
            list.kind = ExprKind::list;
            list.operands.push_back(std::move(*first));
            while (at_symbol(Symbol::comma)) {
                take();
                std::optional<Expr> item = required_condition();
                if (!item) {
                    return std::nullopt;
                }
                list.operands.push_back(std::move(*item));
            }
            e = std::move(list);
        } else {
            e = std::move(*first);
        }
        if (!at_symbol(Symbol::close)) {
            if (at_line_end()) {
                fail(open.span, "parse.unclosed", {});
            } else {
                fail_found("parse.trailing");
            }
            return std::nullopt;
        }
        take();
        if (e.kind == ExprKind::list) {
            e.span = join(open.span, at(last_).span);
        }
    } else {
        fail_expected("parse.expected-value");
        return std::nullopt;
    }
    // Words after their argument: 7 days `before due`, 各部分 `總和`.
    while (peek().kind == TokenKind::word && peek().piece == Piece::tail) {
        const Token& tail = take();
        Expr applied;
        applied.kind = ExprKind::apply;
        applied.concept_entry = tail.concept_entry;
        applied.span = join(e.span, tail.span);
        applied.operands.push_back(std::move(e));
        e = std::move(applied);
    }
    return e;
}

std::optional<Parser::Term> Parser::phrase() {
    if (!starts_value()) {
        fail_expected("parse.expected-value");
        return std::nullopt;
    }
    std::optional<Expr> first = operand();
    if (!first) {
        return std::nullopt;
    }
    if (!starts_value()) {
        return Term{std::move(*first), false};
    }
    Expr p;
    p.kind = ExprKind::phrase;
    p.span = first->span;
    p.operands.push_back(std::move(*first));
    while (starts_value()) {
        std::optional<Expr> next = operand();
        if (!next) {
            return std::nullopt;
        }
        p.span = join(p.span, next->span);
        p.operands.push_back(std::move(*next));
    }
    return Term{std::move(p), true};
}

std::optional<Parser::Term> Parser::binary(Operator op, Term left, Term right, const Token& sign) {
    // `monthly HKD 120 * 12`: which words does * take? Never guess; in
    // parentheses, the phrase is one operand.
    if (left.bare || right.bare) {
        fail(sign.span, "parse.phrase-operator", {{"operator", written(sign)}});
        return std::nullopt;
    }
    Expr e;
    e.kind = ExprKind::binary;
    e.op = op;
    e.span = join(left.expr.span, right.expr.span);
    e.operands.push_back(std::move(left.expr));
    e.operands.push_back(std::move(right.expr));
    return Term{std::move(e), false};
}

std::optional<Parser::Term> Parser::product() {
    std::optional<Term> left = phrase();
    std::size_t added = 0;
    while (left && (at_symbol(Symbol::times) || at_symbol(Symbol::divide))) {
        const Token& sign = take();
        ++expr_depth_;
        ++added;
        if (expr_depth_ > max_parse_depth) {
            fail(sign.span, "parse.too-deep", {{"limit", std::to_string(max_parse_depth)}});
            left.reset();
            break;
        }
        std::optional<Term> right = phrase();
        if (!right) {
            left.reset();
            break;
        }
        left = binary(sign.symbol == Symbol::times ? Operator::times : Operator::divide,
                      std::move(*left), std::move(*right), sign);
    }
    expr_depth_ -= added;
    return left;
}

std::optional<Parser::Term> Parser::sum() {
    std::optional<Term> left = product();
    std::size_t added = 0;
    while (left && (at_symbol(Symbol::plus) || at_symbol(Symbol::minus))) {
        const Token& sign = take();
        ++expr_depth_;
        ++added;
        if (expr_depth_ > max_parse_depth) {
            fail(sign.span, "parse.too-deep", {{"limit", std::to_string(max_parse_depth)}});
            left.reset();
            break;
        }
        std::optional<Term> right = product();
        if (!right) {
            left.reset();
            break;
        }
        left = binary(sign.symbol == Symbol::plus ? Operator::plus : Operator::minus,
                      std::move(*left), std::move(*right), sign);
    }
    expr_depth_ -= added;
    return left;
}

std::optional<Expr> Parser::comparison() {
    std::optional<Term> left = sum();
    if (!left) {
        return std::nullopt;
    }
    const std::optional<Operator> op = comparison_of(peek());
    if (!op) {
        return std::move(left->expr);
    }
    const Token& sign = take();
    std::optional<Term> right = sum();
    if (!right) {
        return std::nullopt;
    }
    std::optional<Term> out = binary(*op, std::move(*left), std::move(*right), sign);
    if (!out) {
        return std::nullopt;
    }
    if (comparison_of(peek())) {
        fail(peek().span, "parse.chained-comparison", {{"operator", written(peek())}});
        return std::nullopt;
    }
    return std::move(out->expr);
}

std::optional<Expr> Parser::negation() {
    if (!at_kw(known().not_)) {
        return comparison();
    }
    Deeper deeper(*this);
    if (!deeper.ok()) {
        return std::nullopt;
    }
    const Token& sign = take();
    if (!starts_condition()) {
        fail_expected("parse.expected-value");
        return std::nullopt;
    }
    std::optional<Expr> inner = negation();
    if (!inner) {
        return inner;
    }
    Expr e;
    e.kind = ExprKind::unary;
    e.op = Operator::logical_not;
    e.span = join(sign.span, inner->span);
    e.operands.push_back(std::move(*inner));
    return e;
}

std::optional<Expr> Parser::conjunction() {
    std::optional<Expr> left = negation();
    std::size_t added = 0;
    while (left && at_kw(known().and_)) {
        const Token& sign = take();
        ++expr_depth_;
        ++added;
        if (expr_depth_ > max_parse_depth) {
            fail(sign.span, "parse.too-deep", {{"limit", std::to_string(max_parse_depth)}});
            left.reset();
            break;
        }
        if (!starts_condition()) {
            fail_expected("parse.expected-value");
            left.reset();
            break;
        }
        std::optional<Expr> right = negation();
        if (!right) {
            left.reset();
            break;
        }
        left = logic(Operator::logical_and, std::move(*left), std::move(*right));
    }
    expr_depth_ -= added;
    return left;
}

std::optional<Expr> Parser::condition() {
    Deeper deeper(*this);
    if (!deeper.ok()) {
        return std::nullopt;
    }
    std::optional<Expr> left = conjunction();
    std::size_t added = 0;
    while (left && at_kw(known().or_)) {
        const Token& sign = take();
        ++expr_depth_;
        ++added;
        if (expr_depth_ > max_parse_depth) {
            fail(sign.span, "parse.too-deep", {{"limit", std::to_string(max_parse_depth)}});
            left.reset();
            break;
        }
        if (!starts_condition()) {
            fail_expected("parse.expected-value");
            left.reset();
            break;
        }
        std::optional<Expr> right = conjunction();
        if (!right) {
            left.reset();
            break;
        }
        left = logic(Operator::logical_or, std::move(*left), std::move(*right));
    }
    expr_depth_ -= added;
    return left;
}

// --- Clauses.

ast::File Parser::run(std::uint64_t edition) {
    ast::File file;
    file.edition = edition;
    while (!at_kind(TokenKind::end)) {
        failed_ = false;
        expr_depth_ = 0;
        switch (peek().kind) {
        case TokenKind::newline:
        case TokenKind::edition_line:
        case TokenKind::dedent:
            take();
            continue;
        case TokenKind::indent:
            fail(peek().span, "parse.unexpected-block", {});
            skip_block();
            continue;
        default:
            if (is_kw(peek(), known().use)) {
                use_line(file.uses);
            } else {
                clause(file.clauses);
            }
        }
    }
    return file;
}

void Parser::use_line(std::vector<ast::Use>& out) {
    const Token& keyword = take();
    bool ok = false;
    // The pack's id as written, whatever it reads as: a name (finance), or a
    // word that some pack spells (services, a form of `service`).
    if (!at_line_end() && !at_kind(TokenKind::indent) && !at_kind(TokenKind::dedent)) {
        const Token& id = take();
        std::string pack = written(id);
        if (std::ranges::any_of(out, [&](const ast::Use& u) { return u.pack == pack; })) {
            fail(id.span, "parse.duplicate", {{"word", detail::quote(pack)}});
        } else {
            out.push_back(ast::Use{join(keyword.span, id.span), std::move(pack)});
            ok = true;
        }
    } else {
        fail(keyword.span, "parse.expected-name", {{"after", written(keyword)}});
    }
    end_line(ok);
    if (failed_ && ok) {
        // Something after the id: the line adds nothing.
        out.pop_back();
    }
    no_block();
}

void Parser::clause(std::vector<ast::Clause>& out) {
    const Known& k = known();
    const Token& t = peek();
    if (is_kw(t, k.contract) || is_kw(t, k.parties)) {
        const std::size_t before = out.size();
        end_line(is_kw(t, k.contract) ? contract(out) : parties(out));
        // A line with an error adds nothing to the tree.
        if (failed_) {
            out.resize(before);
        }
        no_block();
    } else if (t.kind == TokenKind::word && t.piece == Piece::whole &&
               (t.concept_entry->category == Category::kind || t.concept_entry == k.charge ||
                t.concept_entry == k.tax)) {
        block_clause(out);
    } else if (is_kw(t, k.can)) {
        can(out);
    } else if (is_kw(t, k.when)) {
        when(out);
    } else if (is_kw(t, k.test)) {
        test(out);
    } else {
        fail_line_start("parse.top-level");
        skip_line();
        skip_block();
    }
}

bool Parser::contract(std::vector<ast::Clause>& out) {
    const std::size_t first = pos_;
    const Token& keyword = take();
    if (peek().kind != TokenKind::name) {
        return fail_expected("parse.expected-name");
    }
    ast::Contract c;
    c.name = token_expr(take());
    c.span = span_from(first);
    found_.names.insert(c.name.name);
    if (have_contract_) {
        return fail(keyword.span, "parse.duplicate", {{"word", written(keyword)}});
    }
    have_contract_ = true;
    out.emplace_back(std::move(c));
    return true;
}

bool Parser::parties(std::vector<ast::Clause>& out) {
    const std::size_t first = pos_;
    const Token& keyword = take();
    ast::Parties p;
    while (true) {
        const Token& t = peek();
        const bool role = t.kind == TokenKind::word && t.piece == Piece::whole &&
                          t.concept_entry->category == Category::role;
        if (!role && t.kind != TokenKind::name) {
            return fail_expected("parse.expected-party");
        }
        p.parties.push_back(token_expr(take()));
        if (t.kind == TokenKind::name) {
            found_.names.insert(t.text);
            found_.parties.insert(t.text);
        }
        if (!at_symbol(Symbol::comma)) {
            break;
        }
        take();
    }
    p.span = span_from(first);
    if (have_parties_) {
        return fail(keyword.span, "parse.duplicate", {{"word", written(keyword)}});
    }
    have_parties_ = true;
    out.emplace_back(std::move(p));
    return true;
}

void Parser::block_clause(std::vector<ast::Clause>& out) {
    const std::size_t first = pos_;
    ast::Block b;
    b.kind = take().concept_entry;
    bool ok = true;
    if (peek().kind != TokenKind::name) {
        ok = fail_expected("parse.expected-name");
    } else {
        b.name = token_expr(take());
        found_.names.insert(b.name.name);
    }
    b.span = span_from(first);
    end_line(ok);
    if (failed_) {
        skip_block();
        return;
    }
    block([&] {
        std::optional<ast::Field> f = field(false);
        if (f) {
            b.fields.push_back(std::move(*f));
        }
        end_line(f.has_value());
        no_block();
    });
    out.emplace_back(std::move(b));
}

std::optional<ast::Field> Parser::field(bool input) {
    const std::size_t first = pos_;
    if (!starts_operand(peek())) {
        if (input) {
            fail_expected("parse.expected-value");
        } else {
            fail_line_start("parse.field");
        }
        return std::nullopt;
    }
    ast::Field f;
    std::optional<Expr> head = operand();
    if (!head) {
        return std::nullopt;
    }
    f.head = std::move(*head);
    if (f.head.kind == ExprKind::name) {
        found_.names.insert(f.head.name);
    }
    if (starts_value()) {
        std::optional<Term> value = sum();
        if (!value) {
            return std::nullopt;
        }
        f.values.push_back(std::move(value->expr));
    }
    // An input ends at a comma: the next input follows it.
    while (!input && at_symbol(Symbol::comma)) {
        take();
        if (!starts_value()) {
            fail_expected("parse.expected-value");
            return std::nullopt;
        }
        std::optional<Term> value = sum();
        if (!value) {
            return std::nullopt;
        }
        f.values.push_back(std::move(value->expr));
    }
    // A block's field may end with its default: `count number = 0`.
    if (!input && at_symbol(Symbol::equals)) {
        take();
        if (!starts_value()) {
            fail_expected("parse.expected-value");
            return std::nullopt;
        }
        std::optional<Term> initial = sum();
        if (!initial) {
            return std::nullopt;
        }
        f.initial = std::move(initial->expr);
    }
    if (!input && !at_line_end()) {
        fail_found("parse.field");
        return std::nullopt;
    }
    f.span = span_from(first);
    return f;
}

void Parser::can(std::vector<ast::Clause>& out) {
    const Known& k = known();
    const std::size_t first = pos_;
    take();
    ast::Can c;
    bool ok = true;
    if (const Token& a = peek(); is_action(a) || a.kind == TokenKind::name) {
        c.action = token_expr(take());
        if (a.kind == TokenKind::name) {
            found_.names.insert(a.text);
            found_.actions.insert(a.text);
        }
    } else {
        ok = fail_expected("parse.expected-action");
    }
    while (ok && !at_line_end()) {
        const Token& t = peek();
        if (is_kw(t, k.by) || is_kw(t, k.to)) {
            std::optional<Expr>& slot = is_kw(t, k.by) ? c.by : c.to;
            const Token& keyword = take();
            if (slot) {
                ok = fail(keyword.span, "parse.duplicate", {{"word", written(keyword)}});
                break;
            }
            slot = required_operand("parse.expected-party");
            ok = slot.has_value();
        } else if (is_kw(t, k.with)) {
            const Token& keyword = take();
            if (!c.inputs.empty()) {
                ok = fail(keyword.span, "parse.duplicate", {{"word", written(keyword)}});
                break;
            }
            while (true) {
                std::optional<ast::Field> input = field(true);
                if (!input) {
                    ok = false;
                    break;
                }
                c.inputs.push_back(std::move(*input));
                if (!at_symbol(Symbol::comma)) {
                    break;
                }
                take();
            }
        } else {
            ok = fail_found("parse.can");
        }
    }
    c.span = span_from(first);
    end_line(ok);
    if (failed_) {
        skip_block();
        return;
    }
    body(c.body, 1);
    out.emplace_back(std::move(c));
}

void Parser::when(std::vector<ast::Clause>& out) {
    const std::size_t first = pos_;
    const Token& keyword = take();
    ast::When w;
    bool ok = true;
    if (!starts_condition()) {
        ok = fail(at_line_end() ? keyword.span : peek().span, "parse.when", {});
    } else if (std::optional<Expr> event = condition(); event) {
        w.event = std::move(*event);
        if (!at_line_end()) {
            ok = starts_action(pos_) ? actions(w.actions) : fail_found("parse.trailing");
        }
    } else {
        ok = false;
    }
    w.span = span_from(first);
    end_line(ok);
    if (failed_) {
        skip_block();
        return;
    }
    const bool has_block = body(w.body, 1);
    if (!has_block && w.actions.empty()) {
        fail(keyword.span, "parse.empty-block", {{"word", written(keyword)}});
        return;
    }
    out.emplace_back(std::move(w));
}

void Parser::test(std::vector<ast::Clause>& out) {
    const std::size_t first = pos_;
    const Token& keyword = take();
    ast::Test t;
    if (peek().kind == TokenKind::name || peek().kind == TokenKind::text) {
        t.name = token_expr(take());
    }
    t.span = span_from(first);
    end_line(true);
    if (failed_) {
        skip_block();
        return;
    }
    const bool has_block = block([&] {
        if (at_symbol(Symbol::arrow)) {
            std::optional<ast::Expect> e = expect();
            end_line(e.has_value());
            if (e && !failed_) {
                t.steps.push_back(Statement{std::move(*e)});
            }
        } else if (starts_operand(peek()) && !is_action(peek())) {
            const std::size_t before = t.steps.size();
            std::optional<ast::Do> step = action(true);
            bool ok = step.has_value();
            if (step) {
                t.steps.push_back(Statement{std::move(*step)});
                if (at_symbol(Symbol::arrow)) {
                    std::optional<ast::Expect> e = expect();
                    ok = e.has_value();
                    if (e) {
                        t.steps.push_back(Statement{std::move(*e)});
                    }
                }
            }
            end_line(ok);
            if (failed_) {
                t.steps.resize(before);
            }
        } else {
            fail_line_start("parse.step");
            skip_line();
        }
        no_block();
    });
    if (!has_block) {
        fail(keyword.span, "parse.empty-block", {{"word", written(keyword)}});
        return;
    }
    out.emplace_back(std::move(t));
}

std::optional<ast::Expect> Parser::expect() {
    const std::size_t first = pos_;
    take();
    ast::Expect e;
    // `-> fee = HKD 0`: values of fields only, the call accepted.
    bool fields = is_target(peek()) && is_symbol(peek(1), Symbol::equals);
    if (!fields) {
        std::optional<Expr> outcome = required_operand("parse.expected-state");
        if (!outcome) {
            return std::nullopt;
        }
        e.outcome = std::move(*outcome);
        if (at_kind(TokenKind::text)) {
            e.reason = take().text;
        }
        // `-> delivered, fee = HKD 4_000`: and values of fields.
        if (at_symbol(Symbol::comma)) {
            take();
            fields = true;
        }
    }
    while (fields) {
        std::optional<ast::Set> s = set_item();
        if (!s) {
            return std::nullopt;
        }
        e.fields.push_back(std::move(*s));
        fields = at_symbol(Symbol::comma);
        if (fields) {
            take();
        }
    }
    e.span = span_from(first);
    return e;
}

std::optional<ast::Set> Parser::set_item() {
    const std::size_t first = pos_;
    if (!is_target(peek()) || !is_symbol(peek(1), Symbol::equals)) {
        fail_expected("parse.expected-set");
        return std::nullopt;
    }
    ast::Set s;
    s.target = token_expr(take());
    take();
    std::optional<Expr> value = required_condition();
    if (!value) {
        return std::nullopt;
    }
    s.value = std::move(*value);
    s.span = span_from(first);
    return s;
}

std::optional<ast::Do> Parser::action(bool step) {
    const Known& k = known();
    const std::size_t first = pos_;
    ast::Do d;
    if (step || (is_party(peek()) && is_action(peek(1)))) {
        std::optional<Expr> subject = operand();
        if (!subject) {
            return std::nullopt;
        }
        d.subject = std::move(*subject);
    }
    if (const Token& a = peek(); is_action(a) || (step && a.kind == TokenKind::name)) {
        d.action = token_expr(take());
    } else {
        fail_expected("parse.expected-action");
        return std::nullopt;
    }
    while (!at_line_end()) {
        const Token& t = peek();
        if (is_kw(t, k.to) || is_kw(t, k.by)) {
            std::optional<Expr>& slot = is_kw(t, k.to) ? d.to : d.by;
            const Token& keyword = take();
            if (slot) {
                fail(keyword.span, "parse.duplicate", {{"word", written(keyword)}});
                return std::nullopt;
            }
            slot = required_operand("parse.expected-party");
            if (!slot) {
                return std::nullopt;
            }
        } else if (is_kw(t, k.with)) {
            const Token& keyword = take();
            if (!d.with.empty()) {
                fail(keyword.span, "parse.duplicate", {{"word", written(keyword)}});
                return std::nullopt;
            }
            while (true) {
                step_with_ = step;
                std::optional<ast::Set> s = set_item();
                step_with_ = false;
                if (!s) {
                    return std::nullopt;
                }
                d.with.push_back(std::move(*s));
                if (!at_symbol(Symbol::comma)) {
                    break;
                }
                take();
            }
        } else if (starts_value()) {
            std::optional<Expr> arg = operand();
            if (!arg) {
                return std::nullopt;
            }
            d.args.push_back(std::move(*arg));
        } else {
            break;
        }
    }
    d.span = span_from(first);
    return d;
}

bool Parser::actions(std::vector<ast::Do>& out) {
    while (true) {
        std::optional<ast::Do> d = action(false);
        if (!d) {
            return false;
        }
        out.push_back(std::move(*d));
        if (!at_kw(known().and_)) {
            return true;
        }
        take();
    }
}

// --- Statements.

void Parser::statement_line(std::vector<Statement>& out, std::size_t depth, OpenIf& open) {
    const Known& k = known();
    if (depth > max_parse_depth) {
        fail(peek().span, "parse.too-deep", {{"limit", std::to_string(max_parse_depth)}});
        skip_line();
        skip_block();
        open = OpenIf{};
        return;
    }
    if (at_kw(k.otherwise)) {
        open = otherwise(open);
        return;
    }
    const std::size_t before = out.size();
    if (at_kw(k.if_)) {
        if_statement(out, depth);
        // Its address is stable until this block gains another statement.
        open = out.size() > before ? OpenIf{std::get_if<ast::If>(&out.back().node), depth, false}
                                   : OpenIf{nullptr, 0, true};
        return;
    }
    open = OpenIf{};
    if (at_kw(k.each)) {
        each(out, depth);
        return;
    }
    end_line(simple(out));
    // A line with an error adds nothing to the tree.
    if (failed_) {
        out.resize(before);
    }
    no_block();
}

bool Parser::simple(std::vector<Statement>& out) {
    const Known& k = known();
    const std::size_t first = pos_;
    const Token& t = peek();
    if (is_kw(t, k.requires_)) {
        take();
        std::optional<Expr> cond = required_condition();
        if (!cond) {
            return false;
        }
        ast::Requires r;
        r.condition = std::move(*cond);
        r.span = span_from(first);
        out.push_back(Statement{std::move(r)});
        return true;
    }
    if (is_kw(t, k.reject)) {
        take();
        if (!at_kind(TokenKind::text)) {
            return fail_expected("parse.expected-text");
        }
        ast::Reject r;
        r.message = take().text;
        r.span = span_from(first);
        out.push_back(Statement{std::move(r)});
        return true;
    }
    if (is_symbol(t, Symbol::arrow)) {
        take();
        std::optional<Expr> to = required_operand("parse.expected-state");
        if (!to) {
            return false;
        }
        ast::Transition tr;
        tr.to = std::move(*to);
        tr.span = span_from(first);
        out.push_back(Statement{std::move(tr)});
        return true;
    }
    if (starts_action(pos_)) {
        std::vector<ast::Do> list;
        if (!actions(list)) {
            return false;
        }
        for (ast::Do& d : list) {
            out.push_back(Statement{std::move(d)});
        }
        return true;
    }
    if (is_target(t) && is_symbol(peek(1), Symbol::equals)) {
        std::optional<ast::Set> s = set_item();
        if (!s) {
            return false;
        }
        out.push_back(Statement{std::move(*s)});
        return true;
    }
    if (!starts_condition()) {
        return fail_line_start("parse.statement");
    }
    std::optional<Expr> e = condition();
    if (!e) {
        return false;
    }
    if (at_kw(k.requires_)) {
        // GUARD requires CONDITION: over 5_000_000 requires in person.
        take();
        std::optional<Expr> cond = required_condition();
        if (!cond) {
            return false;
        }
        ast::Requires r;
        r.condition = std::move(*cond);
        r.guard = std::move(*e);
        r.span = span_from(first);
        out.push_back(Statement{std::move(r)});
        return true;
    }
    if (at_kw(k.can)) {
        // WHO can ACTION: AI agent can propose.
        take();
        if (!is_action(peek()) && peek().kind != TokenKind::name) {
            return fail_expected("parse.expected-action");
        }
        ast::Permit p;
        p.who = std::move(*e);
        p.action = token_expr(take());
        p.span = span_from(first);
        out.push_back(Statement{std::move(p)});
        return true;
    }
    if (at_symbol(Symbol::comma) || at_symbol(Symbol::arrow)) {
        // FROM, FROM -> TO.
        ast::Transition tr;
        tr.from.push_back(std::move(*e));
        while (at_symbol(Symbol::comma)) {
            take();
            std::optional<Expr> from = required_condition();
            if (!from) {
                return false;
            }
            tr.from.push_back(std::move(*from));
        }
        if (!at_symbol(Symbol::arrow)) {
            return fail_found("parse.trailing");
        }
        take();
        std::optional<Expr> to = required_operand("parse.expected-state");
        if (!to) {
            return false;
        }
        tr.to = std::move(*to);
        tr.span = span_from(first);
        out.push_back(Statement{std::move(tr)});
        return true;
    }
    if (at_line_end()) {
        if (split_hint(at(first))) {
            return false;
        }
        return fail(e->span, "parse.bare-condition", {});
    }
    return fail_found("parse.trailing");
}

void Parser::if_statement(std::vector<Statement>& out, std::size_t depth) {
    const std::size_t first = pos_;
    const Token& keyword = take();
    ast::If s;
    bool ok = true;
    if (std::optional<Expr> cond = required_condition(); cond) {
        s.condition = std::move(*cond);
        // One statement may follow on the same line: if not paid reject "...".
        const Known& k = known();
        if (at_kw(k.requires_) || at_kw(k.reject) || at_symbol(Symbol::arrow) ||
            starts_action(pos_)) {
            ok = simple(s.then);
        } else if (!at_line_end()) {
            ok = fail_found("parse.trailing");
        }
    } else {
        ok = false;
    }
    s.span = span_from(first);
    end_line(ok);
    if (failed_) {
        skip_block();
        return;
    }
    const bool has_block = body(s.then, depth + 1);
    if (!has_block && s.then.empty()) {
        fail(keyword.span, "parse.empty-block", {{"word", written(keyword)}});
        return;
    }
    out.push_back(Statement{std::move(s)});
}

OpenIf Parser::otherwise(const OpenIf open) {
    const Token& keyword = take();
    if (open.broken) {
        // The if (or otherwise if) before this one was an error already.
        skip_line();
        skip_block();
        return open;
    }
    ast::If* target = open.target;
    if (target == nullptr) {
        fail(keyword.span, "parse.otherwise", {{"word", written(keyword)}});
        skip_line();
        skip_block();
        return OpenIf{};
    }
    if (at_kw(known().if_)) {
        // otherwise if: the If nests in this branch, and the next otherwise
        // joins it.
        if (open.depth + 1 > max_parse_depth) {
            fail(peek().span, "parse.too-deep", {{"limit", std::to_string(max_parse_depth)}});
            skip_line();
            skip_block();
            return OpenIf{nullptr, 0, true};
        }
        if_statement(target->otherwise, open.depth + 1);
        if (target->otherwise.empty()) {
            return OpenIf{nullptr, 0, true};
        }
        return OpenIf{std::get_if<ast::If>(&target->otherwise.back().node), open.depth + 1, false};
    }
    bool ok = true;
    if (!at_line_end()) {
        ok = simple(target->otherwise);
    }
    end_line(ok);
    if (failed_) {
        skip_block();
        return OpenIf{};
    }
    const bool has_block = body(target->otherwise, open.depth + 1);
    if (!has_block && target->otherwise.empty()) {
        fail(keyword.span, "parse.empty-block", {{"word", written(keyword)}});
    }
    return OpenIf{};
}

void Parser::each(std::vector<Statement>& out, std::size_t depth) {
    const std::size_t first = pos_;
    const Token& keyword = take();
    ast::Each e;
    bool ok = true;
    if (peek().kind != TokenKind::name || !is_kw(peek(1), known().in)) {
        ok = fail(at_line_end() ? keyword.span : peek().span, "parse.each", {});
    } else {
        e.name = token_expr(take());
        found_.names.insert(e.name.name);
        take();
        if (std::optional<Expr> list = required_condition(); list) {
            e.list = std::move(*list);
        } else {
            ok = false;
        }
    }
    e.span = span_from(first);
    end_line(ok);
    if (failed_) {
        skip_block();
        return;
    }
    if (!body(e.body, depth + 1)) {
        fail(keyword.span, "parse.empty-block", {{"word", written(keyword)}});
        return;
    }
    out.push_back(Statement{std::move(e)});
}

// --- Prefix splits.

/// The tokens with each name split as the declarations decide: 可提款 is
/// 可 + 提款 when 提款 is declared and 可提款 is not.
std::vector<Token> resolve_splits(const std::vector<Token>& tokens, const Declared& declared,
                                  detail::Diagnostics& diagnostics,
                                  const std::set<std::uint32_t>& quiet,
                                  std::set<std::uint32_t>& ambiguous) {
    std::vector<Token> out;
    out.reserve(tokens.size());
    for (const Token& t : tokens) {
        if (t.kind != TokenKind::name || t.splits.empty()) {
            out.push_back(t);
            continue;
        }
        std::vector<const NameSplit*> declared_rest;
        for (const NameSplit& s : t.splits) {
            if (declared.names.contains(std::string_view(t.text).substr(s.length))) {
                declared_rest.push_back(&s);
            }
        }
        if (declared_rest.empty()) {
            out.push_back(t);
            continue;
        }
        if (declared.names.contains(t.text) || declared_rest.size() > 1) {
            const NameSplit& s = *declared_rest.front();
            if (!quiet.contains(t.span.line) && ambiguous.insert(t.span.line).second) {
                diagnostics.add(t.span, "parse.ambiguous-name",
                                {{"name", t.text},
                                 {"prefix", t.text.substr(0, s.length)},
                                 {"rest", t.text.substr(s.length)}});
            }
            Token kept = t;
            kept.splits.clear();
            out.push_back(std::move(kept));
            continue;
        }
        const NameSplit& s = *declared_rest.front();
        const auto points = detail::code_points(std::string_view(t.text).substr(0, s.length));
        const auto columns = static_cast<std::uint32_t>(points ? points->size() : 0);
        Token prefix;
        prefix.kind = TokenKind::word;
        prefix.concept_entry = s.prefix;
        prefix.span = Span{t.span.line, t.span.column, t.span.offset, s.length};
        Token rest;
        rest.kind = TokenKind::name;
        rest.text = t.text.substr(s.length);
        rest.span = Span{t.span.line, t.span.column + columns, t.span.offset + s.length,
                         t.span.length - s.length};
        out.push_back(std::move(prefix));
        out.push_back(std::move(rest));
    }
    return out;
}

// --- The dump.

template <class... F>
struct Overloaded : F... {
    using F::operator()...;
};

void add_line(std::string& out, std::size_t depth, std::string_view text) {
    out.append(2 * depth, ' ');
    out += text;
    out += '\n';
}

std::string literal_text(const ast::Literal& l) {
    switch (l.kind) {
    case ast::LiteralKind::number:
        return to_string(l.number);
    case ast::LiteralKind::money:
        return "(money " + std::string(l.unit->id) + " " + to_string(l.number) + ")";
    case ast::LiteralKind::quantity:
        return "(quantity " + std::string(l.unit->id) + " " + to_string(l.number) + ")";
    case ast::LiteralKind::duration:
        return "(duration " + std::string(l.unit->id) + " " + to_string(l.number) + ")";
    case ast::LiteralKind::rate:
        return to_string(l.number) + "%";
    case ast::LiteralKind::date:
        return std::format("{:04}-{:02}-{:02}", l.date.year, l.date.month, l.date.day);
    case ast::LiteralKind::text:
        return "\"" + l.text + "\"";
    }
    return {};
}

void statements(std::string& out, const std::vector<Statement>& list, std::size_t depth);

std::string do_text(const ast::Do& d) {
    std::string text = "do";
    if (d.subject) {
        text += " subject=" + dump(*d.subject);
    }
    text += " " + dump(d.action);
    for (const Expr& arg : d.args) {
        text += " " + dump(arg);
    }
    if (d.to) {
        text += " to=" + dump(*d.to);
    }
    if (d.by) {
        text += " by=" + dump(*d.by);
    }
    return text;
}

std::string set_text(const ast::Set& s) {
    return "set " + dump(s.target) + " " + dump(s.value);
}

std::string field_text(std::string_view tag, const ast::Field& f) {
    std::string text = std::string(tag) + " " + dump(f.head);
    for (const Expr& v : f.values) {
        text += " " + dump(v);
    }
    if (f.initial) {
        text += " = " + dump(*f.initial);
    }
    return text;
}

void do_lines(std::string& out, const ast::Do& d, std::size_t depth) {
    add_line(out, depth, do_text(d));
    for (const ast::Set& s : d.with) {
        add_line(out, depth + 1, set_text(s));
    }
}

void statement(std::string& out, const Statement& s, std::size_t depth) {
    std::visit(
        Overloaded{
            [&](const ast::Requires& r) {
                add_line(out, depth,
                         "requires " + dump(r.condition) +
                             (r.guard ? " guard=" + dump(*r.guard) : std::string()));
            },
            [&](const ast::Permit& p) {
                add_line(out, depth, "permit " + dump(p.who) + " " + dump(p.action));
            },
            [&](const ast::If& i) {
                add_line(out, depth, "if " + dump(i.condition));
                statements(out, i.then, depth + 1);
                if (!i.otherwise.empty()) {
                    add_line(out, depth, "otherwise");
                    statements(out, i.otherwise, depth + 1);
                }
            },
            [&](const ast::Each& e) {
                add_line(out, depth, "each " + dump(e.name) + " in=" + dump(e.list));
                statements(out, e.body, depth + 1);
            },
            [&](const ast::Reject& r) { add_line(out, depth, "reject \"" + r.message + "\""); },
            [&](const ast::Set& st) { add_line(out, depth, set_text(st)); },
            [&](const ast::Transition& t) {
                std::string text = "transition";
                for (const Expr& f : t.from) {
                    text += " " + dump(f);
                }
                add_line(out, depth, text + " -> " + dump(t.to));
            },
            [&](const ast::Do& d) { do_lines(out, d, depth); },
            [&](const ast::Expect& e) {
                std::string text = "expect";
                if (e.outcome) {
                    text += " " + dump(*e.outcome);
                }
                if (e.reason) {
                    text += " \"" + *e.reason + "\"";
                }
                add_line(out, depth, text);
                for (const ast::Set& f : e.fields) {
                    add_line(out, depth + 1, set_text(f));
                }
            },
        },
        s.node);
}

void statements(std::string& out, const std::vector<Statement>& list, std::size_t depth) {
    for (const Statement& s : list) {
        statement(out, s, depth);
    }
}

} // namespace

Parsed parse(std::string_view source, const Lexed& lexed) {
    // Lines where the lexer found a problem: the parser says nothing more
    // about them.
    std::set<std::uint32_t> quiet;
    for (const Diagnostic& d : lexed.diagnostics) {
        if (d.severity() == Severity::error && d.span.line != 0) {
            quiet.insert(d.span.line);
        }
    }
    const Declared none;
    detail::Diagnostics ignored;
    Parser first(source, lexed.tokens, none, quiet, ignored);
    static_cast<void>(first.run(lexed.edition));
    const Declared declared = first.found();

    detail::Diagnostics diagnostics;
    std::set<std::uint32_t> ambiguous;
    std::vector<Token> tokens =
        resolve_splits(lexed.tokens, declared, diagnostics, quiet, ambiguous);
    // A line with an ambiguous name has its error: the parser adds none.
    ambiguous.insert(quiet.begin(), quiet.end());
    Parser second(source, tokens, declared, ambiguous, diagnostics);
    Parsed out;
    out.file = second.run(lexed.edition);
    out.file.implicit_vocabulary = lexed.implicit_vocabulary;
    out.file.vocabularies = lexed.vocabularies;
    // A `use` line's pack id is a name, whatever it reads as elsewhere; the
    // other words of vocabulary packs are where the checker says a pack is
    // not used (the first of each pack).
    std::set<std::uint32_t> use_lines;
    for (const ast::Use& u : out.file.uses) {
        use_lines.insert(u.span.line);
    }
    for (Token& t : tokens) {
        if (use_lines.contains(t.span.line)) {
            if (t.kind != TokenKind::newline && t.kind != TokenKind::end &&
                !(t.kind == TokenKind::word && t.concept_entry == known().use)) {
                t.kind = TokenKind::name;
                t.text = std::string(source.substr(t.span.offset, t.span.length));
                t.concept_entry = nullptr;
                t.piece = Piece::whole;
                t.form.clear();
            }
            continue;
        }
        if (t.kind == TokenKind::word && t.concept_entry != nullptr &&
            t.concept_entry->owner != nullptr &&
            std::ranges::none_of(out.file.pack_words, [&](const ast::PackWord& w) {
                return w.concept_entry->owner == t.concept_entry->owner;
            })) {
            out.file.pack_words.push_back(ast::PackWord{t.concept_entry, t.span});
        }
    }
    // The parser held them by reference until here.
    out.tokens = std::move(tokens);
    std::vector<Diagnostic> list = diagnostics.take();
    // In source order; anything without a place (a truncation) last.
    std::ranges::stable_sort(list, {}, [](const Diagnostic& d) {
        return d.span.line == 0 ? std::numeric_limits<std::uint64_t>::max()
                                : std::uint64_t{d.span.offset};
    });
    out.diagnostics = std::move(list);
    return out;
}

std::string dump(const ast::Expr& e) {
    switch (e.kind) {
    case ExprKind::literal:
        return literal_text(e.literal);
    case ExprKind::name:
        return e.name;
    case ExprKind::word:
        return std::string(e.concept_entry->id);
    case ExprKind::apply:
    case ExprKind::phrase:
    case ExprKind::list:
    case ExprKind::unary:
    case ExprKind::binary: {
        std::string text = "(";
        if (e.kind == ExprKind::apply) {
            text += e.concept_entry->id;
        } else if (e.kind == ExprKind::phrase) {
            text += "phrase";
        } else if (e.kind == ExprKind::list) {
            text += "list";
        } else {
            text += ast::operator_texts[static_cast<std::size_t>(e.op)];
        }
        for (const Expr& o : e.operands) {
            text += " " + dump(o);
        }
        return text + ")";
    }
    }
    return {};
}

std::string dump(const ast::File& file) {
    std::string out = std::format("edition {}\n", file.edition);
    // By pack: the order of `use` lines means nothing.
    std::vector<std::string> uses;
    for (const ast::Use& u : file.uses) {
        uses.push_back(u.pack);
    }
    std::ranges::sort(uses);
    for (const std::string& pack : uses) {
        add_line(out, 0, "use " + pack);
    }
    for (const ast::Clause& clause : file.clauses) {
        std::visit(
            Overloaded{
                [&](const ast::Contract& c) { add_line(out, 0, "contract " + dump(c.name)); },
                [&](const ast::Parties& p) {
                    std::string text = "parties";
                    for (const Expr& party : p.parties) {
                        text += " " + dump(party);
                    }
                    add_line(out, 0, text);
                },
                [&](const ast::Block& b) {
                    add_line(out, 0, "block " + std::string(b.kind->id) + " " + dump(b.name));
                    for (const ast::Field& f : b.fields) {
                        add_line(out, 1, field_text("field", f));
                    }
                },
                [&](const ast::Can& c) {
                    std::string text = "can " + dump(c.action);
                    if (c.by) {
                        text += " by=" + dump(*c.by);
                    }
                    if (c.to) {
                        text += " to=" + dump(*c.to);
                    }
                    add_line(out, 0, text);
                    for (const ast::Field& f : c.inputs) {
                        add_line(out, 1, field_text("with", f));
                    }
                    statements(out, c.body, 1);
                },
                [&](const ast::When& w) {
                    add_line(out, 0, "when " + dump(w.event));
                    for (const ast::Do& d : w.actions) {
                        do_lines(out, d, 1);
                    }
                    statements(out, w.body, 1);
                },
                [&](const ast::Test& t) {
                    add_line(out, 0, t.name ? "test " + dump(*t.name) : "test");
                    statements(out, t.steps, 1);
                },
            },
            clause);
    }
    return out;
}

std::string dump(const Parsed& parsed, const Pack* language) {
    std::string out = dump(parsed.file);
    for (const Diagnostic& d : parsed.diagnostics) {
        const std::string place =
            d.span.line == 0 ? std::string("-") : std::format("{}:{}", d.span.line, d.span.column);
        out += place + " " + std::string(severity_names[static_cast<std::size_t>(d.severity())]) +
               " " + std::string(d.code) + ": " + render(d, language) + "\n";
    }
    return out;
}

} // namespace cexchain::bo
