// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The lexer: the goldens in
// tests/bo/golden/CASE/ (source.bo, and tokens.txt as `bo check --stage lex`
// prints it), the same concepts in every language, the spec's cases, and the
// rules that keep a reading from being a guess. Set CEXCHAIN_UPDATE_GOLDENS=1
// to rewrite the tokens.txt files after a deliberate change.

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>

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

std::string codes(const Lexed& lexed) {
    std::string out;
    for (const Diagnostic& d : lexed.diagnostics) {
        out += (out.empty() ? "" : " ") + std::string(d.code);
    }
    return out;
}

/// The tokens of a source, described, without newlines and the end.
std::vector<std::string> tokens(std::string_view source, const Lexicon& lexicon = official()) {
    const Lexed lexed = lex(source, lexicon);
    INFO(dump(source, lexed, nullptr));
    CHECK(!has_errors(lexed.diagnostics));
    std::vector<std::string> out;
    for (const Token& token : lexed.tokens) {
        if (token.kind != TokenKind::newline && token.kind != TokenKind::end) {
            out.push_back(describe(token));
        }
    }
    return out;
}

/// The concepts of each token, line by line: describe() without forms
/// (pays and 支付 are the same act.pay).
std::vector<std::string> concepts_of(std::string_view source) {
    const Lexed lexed = lex(source, official());
    std::vector<std::string> out;
    for (const Token& token : lexed.tokens) {
        std::string text = describe(token);
        if (const std::size_t form = text.find(" form="); form != std::string::npos) {
            text.erase(form);
        }
        out.push_back(std::move(text));
    }
    return out;
}

/// A community pack in the test language "qaa": every keyword spelled q...,
/// plus `vocabulary`.
Lexicon with_pack(std::string_view vocabulary) {
    std::string keywords;
    for (const Concept* c_entry : concepts()) {
        const Concept& c = *c_entry;
        if (c.category == Category::keyword) {
            keywords += (keywords.empty() ? "" : ", ") + std::string("\"") + std::string(c.id) +
                        "\": \"q" + std::string(c.id.substr(3)) + "\"";
        }
    }
    const std::string text =
        R"({"format": 1, "id": "test", "version": 1, "language": "qaa", "name": "Test", )"
        R"("official": false, "edition": 1, "reading": {"separation": "none"}, "keywords": {)" +
        keywords + "}, \"vocabulary\": {" + std::string(vocabulary) + "}}";
    const PackRead read = read_pack(text);
    REQUIRE(read.pack);
    const PackSetRead set = make_pack_set({*read.pack});
    REQUIRE(set.set);
    return Lexicon(*set.set);
}

} // namespace

TEST_CASE("the lexer's goldens", "[bo][lexer]") {
    std::vector<std::filesystem::path> cases;
    for (const auto& entry : std::filesystem::directory_iterator(golden_dir)) {
        // The checker's own cases (check-*) keep only the model.
        if (std::filesystem::exists(entry.path() / "source.bo") &&
            !entry.path().filename().string().starts_with("check-")) {
            cases.push_back(entry.path());
        }
    }
    std::ranges::sort(cases);
    CHECK(cases.size() >= 60);
    const bool update = std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr;
    for (const auto& path : cases) {
        INFO(path.filename().string());
        const std::string source = read_text(path / "source.bo");
        const Lexed lexed = lex(source, official());
        const std::string text = dump(source, lexed, nullptr);
        if (update) {
            std::ofstream(path / "tokens.txt", std::ios::binary) << text;
        }
        CHECK(text == read_text(path / "tokens.txt"));
        // The same every time.
        CHECK(dump(source, lex(source, official()), nullptr) == text);
        // Blocks balance, places are in the source and in order.
        REQUIRE(!lexed.tokens.empty());
        CHECK(lexed.tokens.back().kind == TokenKind::end);
        CHECK(std::ranges::count(lexed.tokens, TokenKind::indent, &Token::kind) ==
              std::ranges::count(lexed.tokens, TokenKind::dedent, &Token::kind));
        std::uint64_t last = 0;
        for (const Token& token : lexed.tokens) {
            CHECK(std::uint64_t{token.span.offset} + token.span.length <= source.size());
            CHECK(token.span.offset >= last);
            CHECK(token.span.line >= 1);
            last = token.span.offset;
        }
        // A golden named error-* has errors; any other has none.
        CHECK(has_errors(lexed.diagnostics) == path.filename().string().starts_with("error-"));
    }
}

TEST_CASE("one line in each language, or mixed, gives the same concept tokens", "[bo][lexer]") {
    // Groups of goldens written in each language. Names stay as written, as
    // `bo fmt --language` will leave them. (Concepts whose argument goes on
    // different sides in different languages, `7 days before due` and
    // `到期前 7日`, give the same tree only once parsed.)
    const std::vector<std::pair<std::string, std::vector<std::string>>> groups{
        {"lines", {"en", "zh-hant", "zh-hans", "mixed"}},
        {"example-receivable", {"en", "zh-hant", "zh-hans", "mixed"}},
        {"example-ip-pool", {"en", "zh-hant", "zh-hans", "mixed"}},
        // The tax example's `sum of invoice` is `发票 总和` in Chinese: the
        // same tree, not the same tokens (parser_test checks its tree).
    };
    for (const auto& [group, languages] : groups) {
        const auto first = concepts_of(read_text(golden_dir / (group + "-en") / "source.bo"));
        CHECK(first.size() > 10);
        for (const std::string& language : languages) {
            INFO(group + "-" + language);
            const std::string source =
                read_text(golden_dir / (group + "-" + language) / "source.bo");
            CHECK(!has_errors(lex(source, official()).diagnostics));
            CHECK(concepts_of(source) == first);
        }
    }
    // And line by line.
    const std::vector<std::string> pledge{"word kw.can", "word act.pledge", "word kw.to",
                                          "word role.bank"};
    for (const std::string_view line : {"can pledge to bank", "可質押 予 銀行", "可质押 给 银行",
                                        "可pledge 予 bank", "可 pledge to 銀行"}) {
        INFO(line);
        CHECK(tokens(line) == pledge);
    }
    const std::vector<std::string> threshold{"word cond.over piece=head", "money cur.HKD 100",
                                             "word kw.requires", "word cond.in_person"};
    for (const std::string_view line :
         {"over HKD 100 requires in person", "超過 HKD 100 須親身確認", "超过 港元 100 须本人确认",
          "over 100 港元 須 in person"}) {
        INFO(line);
        CHECK(tokens(line) == threshold);
    }
}

TEST_CASE("the spec's cases lex as it says", "[bo][lexer]") {
    // Prefixes attach to vocabulary words.
    CHECK(tokens("可質押") == std::vector<std::string>{"word kw.can", "word act.pledge"});
    CHECK(tokens("須親身確認") ==
          std::vector<std::string>{"word kw.requires", "word cond.in_person"});
    // 用率 is no word: 可用率 is one name, and records the split a
    // declaration of 用率 would allow.
    CHECK(tokens("可用率") == std::vector<std::string>{"name 可用率 split=kw.can/用率"});
    // Multipliers, exact decimals, attaching words.
    CHECK(tokens("500萬") == std::vector<std::string>{"number 5000000"});
    CHECK(tokens("HKD 0.10") == std::vector<std::string>{"money cur.HKD 0.10"});
    CHECK(tokens("每GB") == std::vector<std::string>{"word price.per", "word unit.GB"});
    // 每 attaches before units and currencies only: 每日 stays daily.
    CHECK(tokens("每日") == std::vector<std::string>{"word time.daily"});
    CHECK(tokens("30日內") ==
          std::vector<std::string>{"duration time.day 30", "word cond.within piece=tail"});

    const Lexed lexed = lex("超過 HKD 100 須親身確認", official());
    REQUIRE(lexed.tokens.size() == 6);
    const Token& money = lexed.tokens[1];
    CHECK(money.kind == TokenKind::money);
    CHECK(money.concept_entry->id == "cur.HKD");
    CHECK(money.number == Decimal{100, 0});
    // 須 is a prefix in the middle of a line too.
    CHECK(lexed.tokens[2].concept_entry->id == "kw.requires");
}

TEST_CASE("places: lines and columns count characters, offsets count bytes", "[bo][lexer]") {
    const std::string source = "合約 X\n  可質押 予 銀行 # 註\n";
    const Lexed lexed = lex(source, official());
    REQUIRE(!has_errors(lexed.diagnostics));
    // contract, X, newline, indent, can, pledge, to, bank, newline, dedent, end
    REQUIRE(lexed.tokens.size() == 11);
    const Token& pledge = lexed.tokens[5];
    CHECK(pledge.span == Span{2, 4, 14, 6});
    CHECK(source.substr(pledge.span.offset, pledge.span.length) == "質押");
    CHECK(lexed.tokens[3].kind == TokenKind::indent);
    CHECK(lexed.tokens[3].span == Span{2, 1, 9, 2});
    REQUIRE(lexed.comments.size() == 1);
    CHECK(lexed.comments[0].text == "# 註");
    CHECK(lexed.comments[0].span.column == 12);
    // Diagnostics carry places too.
    const Lexed bad = lex("contract X\n  a\u200bb\n", official());
    REQUIRE(bad.diagnostics.size() == 1);
    CHECK(bad.diagnostics[0].code == "lex.invisible");
    CHECK(bad.diagnostics[0].span == Span{2, 4, 14, 3});
}

TEST_CASE("a run that reads two ways is an error, never a guess", "[bo][lexer]") {
    // 如果押: 如 + 果押 (pledge) or 如果 + 押 (transfer), with a pack whose
    // words allow both.
    const Lexicon lexicon = with_pack(R"("act.pledge": "果押", "act.transfer": "押")");
    const Lexed lexed = lex("如果押", lexicon);
    CHECK(codes(lexed) == "lex.ambiguous");
    REQUIRE(lexed.diagnostics.size() == 1);
    CHECK(render(lexed.diagnostics[0], nullptr) ==
          "如果押 can be read as 如 (kw.if) + 果押 (act.pledge) or as 如果 (kw.if) + 押 "
          "(act.transfer); Bo never guesses: add a space where the words divide");
    // With a space, one reading.
    CHECK(tokens("如 果押", lexicon) == std::vector<std::string>{"word kw.if", "word act.pledge"});
    CHECK(tokens("如果 押", lexicon) ==
          std::vector<std::string>{"word kw.if", "word act.transfer"});
    // A currency between two numbers belongs to neither.
    CHECK(codes(lex("100 HKD 200", official())) == "lex.ambiguous-money");
    CHECK(codes(lex("HKD 100 USD", official())) == "lex.ambiguous-money");
    CHECK(tokens("HKD 100, 200 USD") ==
          std::vector<std::string>{"money cur.HKD 100", "symbol ,", "money cur.USD 200"});
    // Dates are never subtractions.
    CHECK(codes(lex("2027-1-6", official())) == "lex.bad-date");
    CHECK(tokens("10-3") == std::vector<std::string>{"number 10", "symbol -", "number 3"});
}

TEST_CASE("a community pack's words and rules apply", "[bo][lexer]") {
    const Lexicon lexicon = with_pack(R"("act.pledge": "lodge", "role.bank": "lender")");
    CHECK(tokens("can lodge to lender", lexicon) == tokens("can pledge to bank"));
    CHECK(tokens("qcan lodge qto lender", lexicon) == tokens("can pledge to bank"));
    // The official packs' rules hold with it: 可 attaches to its words.
    CHECK(tokens("可lodge", lexicon) == std::vector<std::string>{"word kw.can", "word act.pledge"});
    // A Lexicon keeps its own copies, and moves.
    Lexicon moved = with_pack(R"("act.pledge": "lodge")");
    const Lexicon other = std::move(moved);
    CHECK(tokens("可lodge", other) == std::vector<std::string>{"word kw.can", "word act.pledge"});
}

TEST_CASE("names: exact, never two that look alike", "[bo][lexer]") {
    CHECK(tokens("late_fee VPS服務 第2期") ==
          std::vector<std::string>{"name late_fee", "name VPS服務", "name 第2期"});
    // Case is exact: Date is a name, date the type.
    CHECK(tokens("Date date") == std::vector<std::string>{"name Date", "word type.date"});
    CHECK(codes(lex("caf\u00e9 cafe\u0301", official())) == "lex.not-normalized");
    CHECK(codes(lex("\u0440\u0430\u0443", official())) == "lex.confusable"); // Cyrillic, like pay
    CHECK(codes(lex("Coco \u0421\u043e\u0441\u043e", official())) == "lex.confusable");
    CHECK(codes(lex("p\u0430y", official())) == "lex.mixed-script");
    CHECK(codes(lex("\uff27\uff22", official())) == "lex.bad-character lex.bad-character");
    CHECK(codes(lex("\uf900", official())) == "lex.bad-character");
    // Greek or Cyrillic alone is a name like any other.
    CHECK(tokens("\u041c\u043e\u0441\u043a\u0432\u0430 \u0394\u03ad\u03bb\u03c4\u03b1") ==
          std::vector<std::string>{"name \u041c\u043e\u0441\u043a\u0432\u0430",
                                   "name \u0394\u03ad\u03bb\u03c4\u03b1"});
}

TEST_CASE("limits", "[bo][lexer]") {
    CHECK(codes(lex(std::string(max_source_size + 1, 'a'), official())) == "lex.too-large");
    CHECK(lex(std::string(max_source_size + 1, 'a'), official()).tokens.size() == 1);
    CHECK(codes(lex(std::string(max_name_bytes + 1, 'a'), official())) == "lex.name-too-long");
    CHECK(!has_errors(lex(std::string(max_name_bytes, 'a'), official()).diagnostics));
    CHECK(codes(lex("reject \"" + std::string(max_text_bytes + 1, 'x') + "\"", official())) ==
          "lex.text-too-long");
    std::string deep;
    for (std::size_t i = 0; i <= max_block_depth; ++i) {
        deep += std::string(i, ' ') + "a\n";
    }
    CHECK(!has_errors(lex(deep, official()).diagnostics));
    deep += std::string(max_block_depth + 1, ' ') + "a\n";
    CHECK(codes(lex(deep, official())) == "lex.too-deep");
    // Many problems: the first 100, and a note.
    const Lexed many = lex(std::string(300, '@'), official());
    CHECK(many.diagnostics.size() == max_diagnostics + 1);
    CHECK(many.diagnostics.back().code == "bo.truncated");
    // Invalid UTF-8: one error at the first bad byte, nothing else.
    const Lexed bad = lex("ab\n c\xC3", official());
    CHECK(codes(bad) == "lex.utf8");
    CHECK(bad.diagnostics[0].span == Span{2, 3, 5, 1});
}

TEST_CASE("numbers are exact decimals", "[bo][lexer]") {
    CHECK(to_string(Decimal{10, 2}) == "0.10");
    CHECK(to_string(Decimal{1, 3}) == "0.001");
    CHECK(to_string(Decimal{15000, 0}) == "15000");
    CHECK(to_string(Decimal{125, 1}) == "12.5");
    CHECK(tokens("1.5萬 0.10萬 0.000_001 18446744073709551615") ==
          std::vector<std::string>{"number 15000", "number 1000", "number 0.000001",
                                   "number 18446744073709551615"});
    CHECK(codes(lex("18446744073709551616", official())) == "lex.number-too-large");
    CHECK(codes(lex("2億億", official())) == "lex.number-suffix");
    CHECK(tokens("2027年1月6日 \uff12\uff10\uff12\uff17-\uff10\uff11-\uff10\uff16") ==
          std::vector<std::string>{"date 2027-01-06", "date 2027-01-06"});
    // The edition: 1 unless `bo N` says otherwise.
    CHECK(lex("contract X", official()).edition == 1);
    const Lexed two = lex("bo 2\ncontract X", official());
    CHECK(two.edition == 2);
    CHECK(codes(two) == "lex.edition");
}

TEST_CASE("messages are in the reader's language", "[bo][lexer]") {
    const Lexed lexed = lex("over 5,000", official());
    REQUIRE(lexed.diagnostics.size() == 1);
    const Diagnostic& d = lexed.diagnostics[0];
    CHECK(render(d, nullptr) == "5,000: a comma never groups digits; write 5_000");
    CHECK(render(d, official_pack("zh-Hant-HK")) == "5,000：逗號不可用作數字分組；請寫 5_000");
    CHECK(render(d, official_pack("zh-Hans-CN")) == "5,000：逗号不能用于数字分组；请写成 5_000");
    // Every lexer code has a text in every official pack (the packs' own
    // test checks all codes; this one checks the lexer's are there).
    std::size_t lexer_codes = 0;
    for (const MessageSpec& spec : message_specs()) {
        if (spec.code.starts_with("lex.")) {
            ++lexer_codes;
            for (const Pack& pack : official_packs()) {
                CHECK(pack.messages.contains(spec.code));
            }
        }
    }
    CHECK(lexer_codes == 27);
}
