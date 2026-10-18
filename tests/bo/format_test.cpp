// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The formatter (milestone 9 of the Bo compiler): the goldens in
// tests/bo/golden/format/CASE/{keep,en,zh-hant,zh-hans}.bo; the language
// invariance property over every golden source and example (formatted as
// written or into each official language, a source parses to the same tree
// with the same comments, checks to the same model, and explains to the same
// text in every language; formatting again changes nothing); a source in one
// language formatted into that language changes only its layout; the layout
// rules; words the new language would read together; and source that cannot
// be formatted. That the formatted source builds to the same code is in
// build_test.cpp (it needs cexchain::bo). Set CEXCHAIN_UPDATE_GOLDENS=1 to
// rewrite the goldens after a deliberate change.

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>

using namespace cexchain::bo;

namespace {

const std::filesystem::path golden_dir = CEXCHAIN_BO_GOLDEN_DIR;
const std::filesystem::path source_dir = golden_dir.parent_path().parent_path().parent_path();

const PackSet& official_set() {
    static const PackSet set = [] {
        PackSetRead read = make_pack_set({});
        REQUIRE(read.set.has_value());
        return std::move(*read.set);
    }();
    return set;
}

const Lexicon& official() {
    static const Lexicon lexicon(official_set());
    return lexicon;
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

const Pack* pack(std::string_view id) {
    const Pack* p = official_set().find(id);
    REQUIRE(p != nullptr);
    return p;
}

/// The targets: as written, then each official language, with the goldens'
/// file names.
std::vector<std::pair<const Pack*, std::string>> targets() {
    return {{nullptr, "keep.bo"},
            {pack("en"), "en.bo"},
            {pack("zh-Hant-HK"), "zh-hant.bo"},
            {pack("zh-Hans-CN"), "zh-hans.bo"}};
}

std::string formatted(std::string_view source, const Pack* language) {
    const Formatted f = format_source(source, official_set(), official(), language);
    INFO((f.diagnostics.empty() ? std::string() : std::string(f.diagnostics.front().code)));
    REQUIRE(f.source.has_value());
    return *f.source;
}

/// Every source the tests have: the goldens of each pass, the compiled
/// agreement in four spellings, the formatter's own cases, the tests' own
/// cases, and the examples' contracts.
std::vector<std::filesystem::path> all_sources() {
    std::vector<std::filesystem::path> out;
    for (const std::filesystem::path& dir :
         {golden_dir, golden_dir / "build", golden_dir / "format", golden_dir / "test"}) {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (std::filesystem::exists(entry.path() / "source.bo")) {
                out.push_back(entry.path() / "source.bo");
            }
        }
    }
    // The examples library's contracts.
    for (const std::string_view example :
         {"lending", "supply-agreement", "receivable-financing", "multi-tier-split", "shipment"}) {
        const std::string name(example);
        out.push_back(source_dir / "examples" / name / (name + ".bo"));
    }
    std::ranges::sort(out);
    return out;
}

/// The text without spaces, ideographic spaces, and line ends: what a
/// change of layout leaves alone.
std::string without_layout(std::string_view text) {
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == ' ' || text[i] == '\n' || text[i] == '\r') {
            continue;
        }
        if (text.substr(i).starts_with("　")) {
            i += 2;
            continue;
        }
        out += text[i];
    }
    return out;
}

struct Read {
    std::string tree;
    std::vector<std::string> comments;
    bool clean = false;
};

Read read_source(std::string_view source) {
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    Read out;
    out.clean = !has_errors(lexed.diagnostics) && parsed.diagnostics.empty();
    out.tree = dump(parsed.file);
    for (const Comment& c : lexed.comments) {
        std::string text = c.text;
        while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
            text.pop_back();
        }
        out.comments.push_back(text);
    }
    return out;
}

/// The model's dump and its text in each official language, if it checks.
std::vector<std::string> meaning(std::string_view source) {
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    const Checked checked = check(source, parsed.file);
    if (has_errors(checked.diagnostics)) {
        return {};
    }
    std::vector<std::string> out{dump(checked.model)};
    for (const Pack& language : official_packs()) {
        out.push_back(explain(checked.model, &language).text);
    }
    return out;
}

} // namespace

TEST_CASE("the formatter's goldens", "[bo][format]") {
    const bool update = std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr;
    std::size_t files = 0;
    for (const auto& entry : std::filesystem::directory_iterator(golden_dir / "format")) {
        const std::string source = read_text(entry.path() / "source.bo");
        for (const auto& [language, file] : targets()) {
            INFO(entry.path().filename().string() + "/" + file);
            const std::string text = formatted(source, language);
            if (update) {
                std::ofstream(entry.path() / file, std::ios::binary) << text;
            } else {
                CHECK(text == read_text(entry.path() / file));
            }
            ++files;
        }
    }
    CHECK(files >= 12);
}

TEST_CASE("formatting keeps the tree, the model, and the text, in every language", "[bo][format]") {
    std::size_t sources = 0;
    std::size_t checked = 0;
    for (const std::filesystem::path& path : all_sources()) {
        const std::string source = read_text(path);
        const Read before = read_source(source);
        if (!before.clean) {
            // Source with errors is not formatted: it says why.
            const Formatted f = format_source(source, official_set(), official(), nullptr);
            CHECK(!f.source.has_value());
            CHECK(has_errors(f.diagnostics));
            continue;
        }
        ++sources;
        const std::vector<std::string> model = meaning(source);
        checked += model.empty() ? 0U : 1U;
        for (const auto& [language, file] : targets()) {
            INFO(path.string() + " as " + file);
            const std::string text = formatted(source, language);
            const Read after = read_source(text);
            CHECK(after.clean);
            CHECK(after.tree == before.tree);
            // The same comments; `use` lines that move take theirs along.
            std::vector<std::string> kept = after.comments;
            std::vector<std::string> given = before.comments;
            std::ranges::sort(kept);
            std::ranges::sort(given);
            CHECK(kept == given);
            CHECK(formatted(text, language) == text);
            CHECK(meaning(text) == model);
            // Into any other language and back: the same tree again.
            for (const auto& [other, ignored] : targets()) {
                CHECK(read_source(formatted(formatted(text, other), language)).tree == before.tree);
            }
        }
    }
    CHECK(sources >= 50);
    CHECK(checked >= 20);
}

TEST_CASE("formatting a source into its own language changes only its layout", "[bo][format]") {
    // Sources whose every word is spelled in one language.
    const std::pair<std::string, std::string_view> single[] = {
        {"example-receivable-en", "en"},
        {"example-receivable-zh-hant", "zh-Hant-HK"},
        {"example-receivable-zh-hans", "zh-Hans-CN"},
        {"example-ip-pool-en", "en"},
        {"example-ip-pool-zh-hant", "zh-Hant-HK"},
        {"example-ip-pool-zh-hans", "zh-Hans-CN"},
        {"example-split-en", "en"},
        {"example-split-zh-hant", "zh-Hant-HK"},
        {"example-split-zh-hans", "zh-Hans-CN"},
        {"example-tax-en", "en"},
        {"example-tax-zh-hant", "zh-Hant-HK"},
        {"example-tax-zh-hans", "zh-Hans-CN"},
        {"example-vps-en", "en"},
        {"build/agreement-en", "en"},
        {"build/agreement-zh-hant", "zh-Hant-HK"},
        {"build/agreement-zh-hans", "zh-Hans-CN"},
        {"format/pieces", "en"},
    };
    for (const auto& [name, id] : single) {
        INFO(name);
        const std::string source = read_text(golden_dir / name / "source.bo");
        const std::string kept = formatted(source, nullptr);
        CHECK(formatted(source, pack(id)) == kept);
        CHECK(without_layout(kept) == without_layout(source));
    }
    // Without a language, every source written in canonical spellings keeps
    // its characters, mixed ones included.
    for (const std::string_view name : {"example-vps-mixed", "example-receivable-mixed",
                                        "example-tax-mixed", "build/agreement-mixed"}) {
        INFO(name);
        const std::string source = read_text(golden_dir / name / "source.bo");
        CHECK(without_layout(formatted(source, nullptr)) == without_layout(source));
    }
    // The examples' contracts are kept in canonical layout, in English.
    for (const std::string_view example :
         {"lending", "supply-agreement", "receivable-financing", "multi-tier-split", "shipment"}) {
        INFO(example);
        const std::string name(example);
        const std::string demo = read_text(source_dir / "examples" / name / (name + ".bo"));
        CHECK(formatted(demo, nullptr) == demo);
        CHECK(formatted(demo, pack("en")) == demo);
    }
}

TEST_CASE("the layout rules", "[bo][format]") {
    // Indentation, spaces, punctuation, blank lines, line ends, comments.
    CHECK(formatted("use commerce\r\ncontract  A\r\n\r\n\r\nparties   we ,customer\r\nthing R\r\n  "
                    "    amount   "
                    "HKD   # money\t \r\n\r\n",
                    nullptr) ==
          "use commerce\ncontract A\n\nparties we, customer\nthing R\n  amount HKD  # money\n");
    CHECK(formatted("\n\n# only a comment\n\n", nullptr) == "# only a comment\n");
    CHECK(formatted("", nullptr).empty());
    CHECK(formatted("\n\n", nullptr).empty());
    // A comment on its own line sits in the block its column reaches.
    CHECK(formatted("can pay by we\n    requires now < due\n    # in the block\n# after it\ncan "
                    "transfer by we\n",
                    nullptr) == "can pay by we\n  requires now < due\n  # in the block\n# after "
                                "it\ncan transfer by we\n");
    // Full-width punctuation stays where the language reads it, without
    // spaces around it; digits become ASCII; ×, and spaces inside parentheses.
    const std::string wide =
        "訂約方 本公司， 客戶\n可 approve 由 本公司\n  須 （ 金額 × ２ ） > 港元 １_０００\n";
    CHECK(formatted(wide, nullptr) ==
          "訂約方 本公司，客戶\n可 approve 由 本公司\n  須（金額 × 2）> 港元 1_000\n");
    CHECK(formatted(wide, pack("zh-Hans-CN")) ==
          "参与方 本公司，客户\n可批准 由 本公司\n  须（金额 × 2）> 港元 1_000\n");
    CHECK(formatted(wide, pack("en")) ==
          "parties we, customer\ncan approve by we\n  requires (amount × 2) > HKD 1_000\n");
    // An amount joined to its currency stays joined where, spaced, the
    // currency would stand between two numbers.
    CHECK(formatted("thing R\n  amount (0HKD 400, HKD 5 6HKD, HKD 7HKD)\n", nullptr) ==
          "thing R\n  amount (0HKD 400, HKD 5 6 HKD, HKD 7HKD)\n");
    // A full-width comma before a digit keeps its space: 5，6 would be one
    // number written with a comma.
    CHECK(formatted("物件 R\n  數量 (5 ，6)\n", nullptr) == "物件 R\n  數量 (5， 6)\n");
    CHECK(formatted("parties we, customer\nthing R\n  amount HKD\n  limit 2 * 3\n", nullptr) ==
          "parties we, customer\nthing R\n  amount HKD\n  limit 2 * 3\n");
    // Chinese words join where the packs' rules join them; names do not
    // (可 提款 is two tokens only because 提款 is declared).
    CHECK(formatted("可 質押 予 銀行\n  須 親身確認\n  須 經 銀行 同意\n可 提款 由 客戶\n",
                    nullptr) ==
          "可質押 予 銀行\n  須親身確認\n  須經 銀行 同意\n可 提款 由 客戶\n");
    // Latin words and numbers stand apart from Chinese; numbers take their
    // multiplier and Chinese measure.
    CHECK(formatted("服務 S\n  流量 每月 2TB, 超出 每GB 港元 0.10\n  價格 500 萬 港元\n  "
                    "冷卻期 30 日 內\n",
                    nullptr) ==
          "服務 S\n  流量 每月 2 TB, 超出 每 GB 港元 0.10\n  價格 500萬港元\n  "
          "冷卻期 30日內\n");
    // Translation: multipliers written out, dates in the language's form,
    // plural units, arguments on their side.
    CHECK(formatted("服務 S\n  價格 500萬港元\n  冷卻期 30日內\n  到期日 2027年1月6日\n",
                    pack("en")) ==
          "service S\n  price 5_000_000 HKD\n  cooling period within 30 days\n  due 2027-01-06\n");
    CHECK(formatted("service S\n  due 2027-01-06\n  quantity 1 item\n", pack("zh-Hans-CN")) ==
          "服务 S\n  到期日 2027-01-06\n  数量 1个\n");
    // A word already in the language keeps its spelling or form.
    CHECK(formatted("when due issuer pays\n", pack("en")) == "when due issuer pays\n");
    CHECK(formatted("when due issuer pays\n", pack("zh-Hant-HK")) == "當到期日 發行人 支付\n");
    CHECK(formatted("當到期日 發行人 支付\n", pack("en")) == "when due issuer pay\n");
    // A `use` line right after a block moves first; the block's end, which
    // the lexer puts on that line, stays (found by bo_parse_fuzz in E11).
    CHECK(formatted("thing R\n  amount HKD\nuse commerce\n", nullptr) ==
          "use commerce\n\nthing R\n  amount HKD\n");
    CHECK(formatted("thing R\n  amount HKD\n\nuse services\ncan pay by we\n  requires now < due\n"
                    "use commerce\n",
                    nullptr) == "use commerce\nuse services\n\nthing R\n  amount HKD\n\ncan pay by "
                                "we\n  requires now < due\n");
}

TEST_CASE("words the new language would read together get parentheses", "[bo][format]") {
    // 於 真人 (in, a person) is `in person` in English, which reads as the
    // condition in person.
    const std::string source =
        "使用 commerce\n合約 C\n訂約方 本公司, 客戶\n\n可 approve 由 本公司\n  須 客戶 於 真人\n"
        "  須 flag = 是 或 否\n";
    const std::string english = formatted(source, pack("en"));
    CHECK(
        english ==
        "use commerce\ncontract C\nparties we, customer\n\ncan approve by we\n  requires customer "
        "in (person)\n  requires flag = (yes) or no\n");
    CHECK(read_source(english).tree == read_source(source).tree);
    CHECK(formatted(english, pack("en")) == english);
}

TEST_CASE("source that cannot be formatted says why", "[bo][format]") {
    // Errors: nothing is formatted; the lexer's and the parser's problems.
    Formatted f = format_source("contract A\n\tparties we\n", official_set(), official(), nullptr);
    REQUIRE(!f.source.has_value());
    CHECK(f.diagnostics.front().code == "lex.tab");
    f = format_source("contract\n", official_set(), official(), pack("en"));
    REQUIRE(!f.source.has_value());
    CHECK(f.diagnostics.front().code.starts_with("parse."));

    // A name the contract gives that the new language reads together with
    // the word after it: a company's pack spells act.release `lodge qto`, so
    // the action `lodge` before `to` would read as release.
    std::string keywords;
    for (const Concept* c_entry : concepts()) {
        const Concept& c = *c_entry;
        if (c.category == Category::keyword) {
            keywords += (keywords.empty() ? "" : ", ") + std::string("\"") + std::string(c.id) +
                        "\": \"q" + std::string(c.id.substr(3)) + "\"";
        }
    }
    const PackRead read = read_pack(
        R"({"format": 1, "id": "test", "version": 1, "language": "qaa", "name": "Test", )"
        R"("official": false, "edition": 1, "reading": {"separation": "spaces"}, "keywords": {)" +
        keywords + R"(}, "vocabulary": {"act.release": "lodge qto"}})");
    REQUIRE(read.pack);
    const PackSetRead set = make_pack_set({*read.pack});
    REQUIRE(set.set);
    const Lexicon lexicon(*set.set);
    const std::string source = "use finance\ncontract C\nparties we, bank\ncan lodge to bank\n";
    f = format_source(source, *set.set, lexicon, set.set->find("test"));
    REQUIRE(!f.source.has_value());
    REQUIRE(f.diagnostics.size() == 1);
    CHECK(f.diagnostics.front().code == "fmt.unstable");
    CHECK(f.diagnostics.front().span.line == 4);
    CHECK(f.diagnostics.front().arg("language") == "test");
    for (const Pack& language : official_packs()) {
        CHECK(!render(f.diagnostics.front(), &language).empty());
    }
    // Into any official language it formats.
    const Formatted chinese = format_source(source, *set.set, lexicon, set.set->find("zh-Hant-HK"));
    CHECK(chinese.source == std::optional<std::string>(
                                "使用 finance\n合約 C\n訂約方 我方, 銀行\n可 lodge 予 銀行\n"));
}

TEST_CASE("the parser gives the tokens it read, splits applied", "[bo][format]") {
    const std::string source = "contract C\nparties we\ncan 提款 by we\n可提款 由 本公司\n";
    const Parsed parsed = parse(source, lex(source, official()));
    std::vector<std::string> words;
    for (const Token& t : parsed.tokens) {
        if (t.kind == TokenKind::word || t.kind == TokenKind::name) {
            words.push_back(describe(t));
        }
    }
    CHECK(words == std::vector<std::string>{"word kw.contract", "name C", "word kw.parties",
                                            "word role.we", "word kw.can", "name 提款",
                                            "word kw.by", "word role.we", "word kw.can",
                                            "name 提款", "word kw.by", "word role.we"});
}
