// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The parser (milestone 3 of the Bo compiler): the goldens in
// tests/bo/golden/CASE/ast.txt (for the cases named example-*, parse-*, and
// error-parse-*, as `bo check --stage parse` prints the tree, followed by the
// parser's problems), the same tree for the same contract in every language,
// precedence, the `=` rule, words with arguments, prefix splits, and the
// messages. Set CEXCHAIN_UPDATE_GOLDENS=1 to rewrite the ast.txt files after
// a deliberate change.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>

using namespace cexchain::bo;

namespace {

const std::filesystem::path golden_dir = CEXCHAIN_BO_GOLDEN_DIR;

const Lexicon& official() {
    static const Lexicon lexicon = [] {
        const PackSetRead set = make_pack_set({});
        return Lexicon(*set.set);
    }();
    return lexicon;
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

Parsed parse_text(std::string_view source, const Lexicon& lexicon = official()) {
    return parse(source, lex(source, lexicon));
}

std::string codes(const Parsed& parsed) {
    std::string out;
    for (const Diagnostic& d : parsed.diagnostics) {
        out += (out.empty() ? "" : " ") + std::string(d.code);
    }
    return out;
}

/// The tree of a source that must parse without problems.
std::string tree(std::string_view source) {
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    INFO(source);
    INFO(dump(parsed, nullptr));
    CHECK(!has_errors(lexed.diagnostics));
    CHECK(parsed.diagnostics.empty());
    return dump(parsed.file);
}

/// The statements of `can pledge` whose block is `lines`, as dumped.
std::string body(std::string_view lines) {
    const std::string full = tree("can pledge\n" + std::string(lines));
    const std::string head = "edition 1\ncan act.pledge\n";
    REQUIRE(full.starts_with(head));
    return full.substr(head.size());
}

/// A condition, as dumped: the one `requires` of `can pledge`.
std::string condition(std::string_view text) {
    const Parsed parsed = parse_text("can pledge\n  requires " + std::string(text) + "\n");
    INFO(text);
    INFO(dump(parsed, nullptr));
    REQUIRE(parsed.diagnostics.empty());
    REQUIRE(parsed.file.clauses.size() == 1);
    const auto& can = std::get<ast::Can>(parsed.file.clauses[0]);
    REQUIRE(can.body.size() == 1);
    return dump(std::get<ast::Requires>(can.body[0].node).condition);
}

/// The error codes of `can pledge` whose block is `lines`.
std::string body_codes(std::string_view lines) {
    return codes(parse_text("can pledge\n" + std::string(lines)));
}

} // namespace

TEST_CASE("the parser's goldens", "[bo][parser]") {
    std::vector<std::filesystem::path> cases;
    for (const auto& entry : std::filesystem::directory_iterator(golden_dir)) {
        const std::string name = entry.path().filename().string();
        if (std::filesystem::exists(entry.path() / "source.bo") &&
            (name.starts_with("example-") || name.starts_with("parse-") ||
             name.starts_with("error-parse-"))) {
            cases.push_back(entry.path());
        }
    }
    std::ranges::sort(cases);
    CHECK(cases.size() >= 35);
    const bool update = std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr;
    for (const auto& path : cases) {
        const std::string name = path.filename().string();
        INFO(name);
        const std::string source = read_text(path / "source.bo");
        const Lexed lexed = lex(source, official());
        const Parsed parsed = parse(source, lexed);
        const std::string text = dump(parsed, nullptr);
        if (update) {
            std::ofstream(path / "ast.txt", std::ios::binary) << text;
        }
        CHECK(text == read_text(path / "ast.txt"));
        // The same every time.
        CHECK(dump(parse(source, lex(source, official())), nullptr) == text);
        // Every problem has a place in the source.
        for (const Diagnostic& d : parsed.diagnostics) {
            CHECK(d.span.line >= 1);
            CHECK(std::uint64_t{d.span.offset} + d.span.length <= source.size());
        }
        if (name.starts_with("parse-error-")) {
            CHECK(!has_errors(lexed.diagnostics));
            CHECK(has_errors(parsed.diagnostics));
        } else if (name.starts_with("error-parse-")) {
            // The lexer found problems; the parser says nothing more about
            // those lines.
            CHECK(has_errors(lexed.diagnostics));
            std::set<std::uint32_t> lines;
            for (const Diagnostic& d : lexed.diagnostics) {
                lines.insert(d.span.line);
            }
            for (const Diagnostic& d : parsed.diagnostics) {
                CHECK(!lines.contains(d.span.line));
            }
        } else {
            CHECK(!has_errors(lexed.diagnostics));
            CHECK(parsed.diagnostics.empty());
        }
    }
}

TEST_CASE("each example, in each language or mixed, gives the same tree", "[bo][parser]") {
    const std::vector<std::pair<std::string, std::vector<std::string>>> groups{
        {"example-receivable", {"en", "zh-hant", "zh-hans", "mixed"}},
        {"example-ip-pool", {"en", "zh-hant", "zh-hans", "mixed"}},
        {"example-vps", {"en", "zh-hant", "zh-hans", "mixed"}},
        {"example-split", {"en", "zh-hant", "zh-hans", "mixed"}},
        {"example-tax", {"en", "zh-hant", "zh-hans", "mixed"}},
        {"parse-statements", {"en", "zh-hant", "zh-hans"}},
        {"parse-test", {"en", "zh-hant", "zh-hans"}},
    };
    for (const auto& [group, languages] : groups) {
        const std::string first = tree(read_text(golden_dir / (group + "-en") / "source.bo"));
        CHECK(std::ranges::count(first, '\n') > 3);
        for (const std::string& language : languages) {
            INFO(group + "-" + language);
            CHECK(tree(read_text(golden_dir / (group + "-" + language) / "source.bo")) == first);
        }
    }
    // The receivable's tree, as the plan's milestone asks: an example
    // clause in English, Traditional and Simplified Chinese, and mixed.
    for (const std::string_view source :
         {"can pledge to bank\n  over 5_000_000 requires in person\n",
          "可質押 予 銀行\n  超過 5_000_000 須親身確認\n",
          "可质押 给 银行\n  超过 5_000_000 须本人确认\n",
          "可pledge 予 bank\n  over 5_000_000 須親身確認\n"}) {
        CHECK(tree(source) == "edition 1\ncan act.pledge to=role.bank\n"
                              "  requires cond.in_person guard=(cond.over 5000000)\n");
    }
}

TEST_CASE("precedence: * and / before + and -, then comparisons, not, and, or", "[bo][parser]") {
    CHECK(condition("a + b * c") == "(+ a (* b c))");
    CHECK(condition("a * b + c") == "(+ (* a b) c)");
    CHECK(condition("a - b - c") == "(- (- a b) c)");
    CHECK(condition("a / b * c") == "(* (/ a b) c)");
    CHECK(condition("a < b + c") == "(< a (+ b c))");
    CHECK(condition("not a = b") == "(not (= a b))");
    CHECK(condition("not a and b") == "(and (not a) b)");
    CHECK(condition("a or b and c") == "(or a (and b c))");
    CHECK(condition("a and b or c and d") == "(or (and a b) (and c d))");
    CHECK(condition("not not a") == "(not (not a))");
    CHECK(condition("(a or b) and c") == "(and (or a b) c)");
    CHECK(condition("(a)") == "a");
    CHECK(condition("x in (1, 2.5, \"three\")") == "(in x (list 1 2.5 \"three\"))");
    // × and ÷, and the Chinese keywords, are the same operators.
    CHECK(condition("a × b ÷ c") == "(/ (* a b) c)");
    CHECK(condition("a 及 b 或 非 c") == "(or (and a b) (not c))");
    CHECK(condition("a 且 b") == "(and a b)");
    // Comparisons never chain, and words side by side are never operands of
    // an operator: both would be guesses.
    CHECK(body_codes("  requires a < b < c\n") == "parse.chained-comparison");
    CHECK(body_codes("  requires a = b = c\n") == "parse.chained-comparison");
    CHECK(body_codes("  requires monthly HKD 120 * 12\n") == "parse.phrase-operator");
    CHECK(body_codes("  requires x = monthly HKD 120\n") == "parse.phrase-operator");
    CHECK(condition("(monthly HKD 120) * 12") ==
          "(* (phrase time.monthly (money cur.HKD 120)) 12)");
    // but logic may join them.
    CHECK(condition("overdue 3 days and not paid") ==
          "(and (phrase cond.overdue (duration time.day 3)) (not state.paid))");
}

TEST_CASE("= sets a field at the start of an action's line, and compares in a condition",
          "[bo][parser]") {
    CHECK(body("  holder = bank\n") == "  set field.holder role.bank\n");
    CHECK(body("  持有人 = 銀行\n") == "  set field.holder role.bank\n");
    CHECK(body("  requires holder = bank\n") == "  requires (= field.holder role.bank)\n");
    CHECK(body("  if holder = bank reject \"no\"\n") ==
          "  if (= field.holder role.bank)\n    reject \"no\"\n");
    // The value may be any condition: the first = sets.
    CHECK(body("  ok = tier = 2\n") == "  set ok (= field.tier 2)\n");
    // Not one field before =: a condition alone, which does nothing.
    CHECK(body_codes("  sum of parts = amount\n") == "parse.bare-condition");
    CHECK(body_codes("  tier + 1 = 2\n") == "parse.bare-condition");
    // In a block of fields, = has no place.
    CHECK(codes(parse_text("asset A\n  amount = HKD 1\n")) == "parse.field");
}

TEST_CASE("a word with an argument meets it on either side, in any language", "[bo][parser]") {
    const std::vector<std::pair<std::string, std::vector<std::string>>> same{
        {"(cond.consent_of role.bank)", {"consent of bank", "經 銀行 同意", "经 银行 同意"}},
        {"(cond.before_due (duration time.day 7))",
         {"7 days before due", "到期前 7日", "到期前 7天", "7日 before due"}},
        {"(cond.within (duration time.day 30))", {"within 30 days", "30日內", "30天内"}},
        {"(expr.sum_of field.parts)", {"sum of parts", "各部分 總和", "各部分 总和"}},
        {"(expr.count_of field.parts)", {"count of parts", "各部分 數目"}},
        {"(cond.over (money cur.HKD 100))", {"over HKD 100", "超過 港元 100", "超过 100 港元"}},
        {"(expr.at_most 16)", {"at most 16", "最多 16"}},
        {"(time.at 2027-01-06)", {"at 2027-01-06", "時間 2027-01-06", "时间 2027年1月6日"}},
    };
    for (const auto& [expected, spellings] : same) {
        for (const std::string& text : spellings) {
            INFO(text);
            CHECK(condition(text) == expected);
        }
    }
    // `from … on` and `從 … 起` have words on both sides.
    CHECK(tree("charge VAT\n  from 2027-01-01 on rate 9%\n") ==
          tree("charge VAT\n  從 2027-01-01 起 稅率 9%\n"));
    // An argument is one operand, so that the languages agree: the
    // consent of bank, and then a phrase, in each.
    CHECK(condition("consent of bank and consent of we") ==
          "(and (cond.consent_of role.bank) (cond.consent_of role.we))");
    CHECK(body_codes("  requires 經 銀行 及 本公司 同意\n") == "parse.missing-tail");
    // `applies to` takes a whole condition.
    CHECK(tree("charge VAT\n  applies to customer location = 中国内地\n") ==
          "edition 1\nblock charge.charge VAT\n"
          "  field (charge.applies_to (= field.customer_location 中国内地))\n");
    // A piece without its partner is an error naming the concept.
    CHECK(body_codes("  requires 經 銀行\n") == "parse.missing-tail");
    CHECK(body_codes("  requires 銀行 同意\n") == "parse.missing-head");
    CHECK(body_codes("  requires before due\n") == "parse.missing-argument");
    CHECK(body_codes("  requires consent of\n") == "parse.expected-value");
}

TEST_CASE("an action begins at its word, or at the party just before it", "[bo][parser]") {
    CHECK(tree("parties issuer\nwhen due issuer pays\n") ==
          "edition 1\nparties role.issuer\nwhen field.due\n  do subject=role.issuer act.pay\n");
    // A name is a party when `parties` declares it, and an action when a
    // `can` does.
    CHECK(tree("parties 甲方\ncan 停機\nwhen due 甲方 pays\nwhen overdue 3 days 停機\n") ==
          "edition 1\nparties 甲方\ncan 停機\nwhen field.due\n  do subject=甲方 act.pay\n"
          "when (phrase cond.overdue (duration time.day 3))\n  do 停機\n");
    // Otherwise a name is part of the event.
    CHECK(tree("asset A\n  結算日 date\nwhen 結算日 notify customer\n") ==
          "edition 1\nblock kind.asset A\n  field 結算日 type.date\nwhen 結算日\n"
          "  do act.notify role.customer\n");
    // `and` joins actions; a when without an event is an error.
    CHECK(tree("when overdue 30 days terminate and reclaim IP\n") ==
          "edition 1\nwhen (phrase cond.overdue (duration time.day 30))\n  do act.terminate\n"
          "  do act.reclaim IP\n");
    CHECK(codes(parse_text("when issuer pays\n")) == "parse.when");
    CHECK(codes(parse_text("when overdue 3 days suspend and\n")) == "parse.expected-action");
    CHECK(codes(parse_text("when overdue 3 days\n")) == "parse.empty-block");
}

TEST_CASE("a name the lexer could split is split as the declarations decide", "[bo][parser]") {
    // 提款 is declared by `可 提款`: then 可提款 is 可 + 提款.
    CHECK(tree("可 提款 由 客戶\n可提款 由 本公司\n") ==
          "edition 1\ncan 提款 by=role.customer\ncan 提款 by=role.we\n");
    // Nothing declares 用率: 可用率 is one name.
    CHECK(tree("asset A\n  可用率 number\n") ==
          "edition 1\nblock kind.asset A\n  field 可用率 type.number\n");
    // Both declared: an error asking for a space, once per line.
    const Parsed both = parse_text("asset A\n  可提款 number\ncan 提款\n可提款 by we\n");
    CHECK(codes(both) == "parse.ambiguous-name parse.ambiguous-name");
    CHECK(render(both.diagnostics[1], nullptr) ==
          "可提款 could be the name 可提款 or 可 followed by 提款, since both are declared; Bo "
          "never guesses: write 可 提款 with a space, or rename one of them");
    // Neither: the line cannot begin with a name, and the message says why.
    const Parsed neither = parse_text("可提款 由 客戶\n");
    CHECK(codes(neither) == "parse.undeclared-split");
    CHECK(render(neither.diagnostics[0], official_pack("zh-Hant-HK")) ==
          "可提款 在此是一個名稱，因為沒有任何地方宣告 提款；如要以 可 開始此行，請寫成 可 "
          "提款（中間加空格）");
    // The pieces of a split keep their places.
    const Parsed split = parse_text("can 提款\n可提款 by we\n");
    REQUIRE(split.file.clauses.size() == 2);
    const auto& second = std::get<ast::Can>(split.file.clauses[1]);
    CHECK(second.span == Span{2, 1, 11, 15});
    CHECK(second.action.span == Span{2, 2, 14, 6});
}

TEST_CASE("blocks: if, otherwise, each, and the lines that open none", "[bo][parser]") {
    CHECK(body("  if a\n    reject \"x\"\n  otherwise if b\n    reject \"y\"\n  otherwise\n"
               "    reject \"z\"\n") ==
          "  if a\n    reject \"x\"\n  otherwise\n    if b\n      reject \"y\"\n    otherwise\n"
          "      reject \"z\"\n");
    // An otherwise joins only the if just before it, at its indentation.
    CHECK(body_codes("  reject \"x\"\n  otherwise\n    reject \"y\"\n") == "parse.otherwise");
    CHECK(body_codes("  if a reject \"x\"\n  otherwise reject \"y\"\n  otherwise reject \"z\"\n") ==
          "parse.otherwise");
    // An if that fails takes its otherwise lines with it, quietly.
    CHECK(body_codes("  if a b *\n  otherwise if c\n  otherwise reject \"q\"\n") ==
          "parse.expected-value");
    CHECK(body("  each part in parts\n    requires part > 0\n") ==
          "  each part in=field.parts\n    requires (> part 0)\n");
    CHECK(body_codes("  each part\n") == "parse.each");
    CHECK(body_codes("  if a\n") == "parse.empty-block");
    CHECK(codes(parse_text("contract X\n  parties we\n")) == "parse.unexpected-block");
    CHECK(codes(parse_text("  contract X\n")) == "parse.unexpected-block");
    CHECK(codes(parse_text("test\n")) == "parse.empty-block");
    // `use` declares a vocabulary pack on a line of its own, outside any
    // block; the pack's id is the next token as written (checked later).
    CHECK(codes(parse_text("use modules\n")).empty());
    CHECK(dump(parse_text("use services\nuse finance\n").file) ==
          "edition 1\nuse finance\nuse services\n");
    CHECK(codes(parse_text("use finance\nuse finance\n")) == "parse.duplicate");
    CHECK(codes(parse_text("use\n")) == "parse.expected-name");
    CHECK(codes(parse_text("use finance services\n")) == "parse.trailing");
    CHECK(codes(parse_text("use finance\n  contract X\n")) == "parse.unexpected-block");
    CHECK(codes(parse_text("can x\n  requires use\n")) == "parse.reserved");
    CHECK(codes(parse_text("can x\n  use finance\n")) == "parse.reserved");
    // A line that fails adds nothing, and the parser goes on with the next.
    const Parsed recovered =
        parse_text("contract X Y\ncan pledge bank\n  requires z\ncan transfer\n");
    CHECK(codes(recovered) == "parse.trailing parse.can");
    CHECK(dump(recovered.file) == "edition 1\ncan act.transfer\n");
}

TEST_CASE("tests: steps and expectations (U8)", "[bo][parser]") {
    CHECK(tree("test\n  supplier pledge to bank1 at 2027-01-06 in person\n  -> pledged\n"
               "  supplier pledge to bank2 by AI agent -> refused \"already pledged\"\n") ==
          "edition 1\ntest\n"
          "  do subject=role.supplier act.pledge (time.at 2027-01-06) cond.in_person to=bank1\n"
          "  expect state.pledged\n"
          "  do subject=role.supplier act.pledge to=bank2 by=actor.ai_agent\n"
          "  expect val.refused \"already pledged\"\n");
    CHECK(codes(parse_text("test\n  pledge to bank\n")) == "parse.step");
    CHECK(codes(parse_text("test\n  supplier pledge ->\n")) == "parse.expected-state");
    CHECK(codes(parse_text("test\n  supplier split with parts\n")) == "parse.expected-set");
}

TEST_CASE("places, limits, and the empty source", "[bo][parser]") {
    const Parsed empty = parse_text("");
    CHECK(empty.file.clauses.empty());
    CHECK(empty.diagnostics.empty());
    CHECK(dump(empty.file) == "edition 1\n");
    // Places count characters, as the lexer's do.
    const Parsed placed = parse_text("可質押 予 銀行\n  超過 5_000_000 須親身確認\n");
    REQUIRE(placed.file.clauses.size() == 1);
    const auto& can = std::get<ast::Can>(placed.file.clauses[0]);
    CHECK(can.span == Span{1, 1, 0, 20});
    const auto& requires_ = std::get<ast::Requires>(can.body.at(0).node);
    CHECK(requires_.guard->span == Span{2, 3, 23, 16});
    CHECK(requires_.condition.span == Span{2, 17, 43, 12});
    // Nesting is bounded, so a hostile source cannot exhaust the stack.
    const std::string deep =
        "can x\n  requires " + std::string(200, '(') + "a" + std::string(200, ')') + "\n";
    CHECK(codes(parse_text(deep)) == "parse.too-deep");
    std::string chain = "can x\n  if a reject \"a\"\n";
    for (std::size_t i = 0; i < max_parse_depth + 10; ++i) {
        chain += "  otherwise if b reject \"b\"\n";
    }
    CHECK(codes(parse_text(chain)) == "parse.too-deep");
    // Many problems: the first 100, and a note.
    std::string many;
    for (int i = 0; i < 150; ++i) {
        many += "holder\n";
    }
    const Parsed truncated = parse_text(many);
    CHECK(truncated.diagnostics.size() == max_diagnostics + 1);
    CHECK(truncated.diagnostics.back().code == "bo.truncated");
}

TEST_CASE("a community pack's words parse as the official ones", "[bo][parser]") {
    std::string keywords;
    for (const Concept& c : concepts()) {
        if (c.category == Category::keyword) {
            keywords += (keywords.empty() ? "" : ", ") + std::string("\"") + std::string(c.id) +
                        "\": \"q" + std::string(c.id.substr(3)) + "\"";
        }
    }
    const std::string text =
        R"({"format": 1, "id": "test", "version": 1, "language": "qaa", "name": "Test", )"
        R"("official": false, "edition": 1, "reading": {"separation": "spaces"}, "keywords": {)" +
        keywords +
        R"(}, "vocabulary": {"act.pledge": "lodge", "cond.consent_of": "nod of … please"}})";
    const PackRead read = read_pack(text);
    REQUIRE(read.pack);
    const PackSetRead set = make_pack_set({*read.pack});
    REQUIRE(set.set);
    const Lexicon lexicon(*set.set);
    const Parsed parsed =
        parse_text("qcan lodge qto bank\n  qrequires nod of bank please\n", lexicon);
    CHECK(parsed.diagnostics.empty());
    CHECK(dump(parsed.file) == tree("can pledge to bank\n  requires consent of bank\n"));
}

TEST_CASE("the parser's messages are in every official pack", "[bo][parser]") {
    std::size_t parser_codes = 0;
    for (const MessageSpec& spec : message_specs()) {
        if (spec.code.starts_with("parse.")) {
            ++parser_codes;
            for (const Pack& pack : official_packs()) {
                INFO(pack.id + " " + std::string(spec.code));
                CHECK(pack.messages.contains(spec.code));
            }
        }
    }
    CHECK(parser_codes == 30);
    const Parsed parsed = parse_text("can x\n  requires a < b < c\n");
    REQUIRE(parsed.diagnostics.size() == 1);
    const Diagnostic& d = parsed.diagnostics[0];
    CHECK(render(d, nullptr) ==
          "comparisons do not chain: write a < b and b < c, not a < b < c (at <)");
    CHECK(render(d, official_pack("zh-Hant-HK")) ==
          "比較不可串連：請寫 a < b 及 b < c，而非 a < b < c（在 < 處）");
    CHECK(render(d, official_pack("zh-Hans-CN")) ==
          "比较不能串联：请写 a < b 且 b < c，而不是 a < b < c（在 < 处）");
}
