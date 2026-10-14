// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The contract text (milestone 8 of the Bo compiler): the goldens in
// tests/bo/golden/explain/CASE/{en,zh-hant,zh-hans}.txt (the text of each
// example in each official language), the same text from every spelling of
// a contract (English, Traditional and Simplified Chinese, mixed), what
// compiled code decides (requirement numbers, final states, the creation
// function), every inferred clause marked and every rule used explained,
// texts in quotation marks (R18), spacing in Chinese, and a pack without
// sentences. Set CEXCHAIN_UPDATE_GOLDENS=1 to rewrite the goldens after a
// deliberate change.

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>

using namespace cexchain::bo;

namespace {

const std::filesystem::path golden_dir = CEXCHAIN_BO_GOLDEN_DIR;
/// The source tree: the demo's contract is one of the cases.
const std::filesystem::path source_dir = golden_dir.parent_path().parent_path().parent_path();

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

/// The checked model of a source that has no errors.
model::Model model_of(const std::filesystem::path& path) {
    const std::string source = read_text(path);
    INFO(path.string());
    REQUIRE(!source.empty());
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    REQUIRE(!has_errors(lexed.diagnostics));
    REQUIRE(parsed.diagnostics.empty());
    Checked checked = check(source, parsed.file);
    REQUIRE(!has_errors(checked.diagnostics));
    return std::move(checked.model);
}

const Pack* language(std::string_view id) {
    const Pack* pack = official_pack(id);
    REQUIRE(pack != nullptr);
    return pack;
}

/// The output languages, and the goldens' file names.
const std::pair<std::string_view, std::string_view> languages[] = {
    {"en", "en.txt"}, {"zh-Hant-HK", "zh-hant.txt"}, {"zh-Hans-CN", "zh-hans.txt"}};

struct Case {
    std::string name;
    /// One contract, in each spelling there is of it.
    std::vector<std::filesystem::path> sources;
};

std::vector<Case> cases() {
    std::vector<Case> out;
    const auto spellings = [](const std::filesystem::path& dir, std::string_view stem) {
        std::vector<std::filesystem::path> paths;
        for (const std::string_view s : {"en", "zh-hant", "zh-hans", "mixed"}) {
            paths.push_back(dir / (std::string(stem) + "-" + std::string(s)) / "source.bo");
        }
        return paths;
    };
    out.push_back({"agreement", spellings(golden_dir / "build", "agreement")});
    out.push_back({"supply-agreement", {source_dir / "deploy/demo/supply-agreement.bo"}});
    for (const std::string_view e : {"receivable", "vps", "ip-pool", "split", "tax"}) {
        out.push_back({std::string(e), spellings(golden_dir, "example-" + std::string(e))});
    }
    out.push_back({"check-agreement", {golden_dir / "check-agreement/source.bo"}});
    out.push_back({"recognized", {golden_dir / "check-recognized/source.bo"}});
    // The standard library's terms (milestone 11).
    out.push_back({"receivable-flow", {golden_dir / "test/receivable/source.bo"}});
    out.push_back({"warehouse-receipt", {golden_dir / "test/warehouse-receipt/source.bo"}});
    out.push_back({"standard", {golden_dir / "check-standard/source.bo"}});
    // Time rules and the keeper (milestone 12).
    out.push_back({"time", {golden_dir / "test/time/source.bo"}});
    out.push_back({"membership", {golden_dir / "check-time/source.bo"}});
    out.push_back({"ip-pool-tests", {golden_dir / "test/ip-pool/source.bo"}});
    // Lists and charges (milestone 13).
    out.push_back({"tax-tests", {golden_dir / "test/tax/source.bo"}});
    out.push_back({"charges", {golden_dir / "test/charges/source.bo"}});
    out.push_back({"lists", {golden_dir / "test/lists/source.bo"}});
    // Splitting (milestone 17): the demo's receivable, split down its chain.
    out.push_back({"multi-tier-split", {source_dir / "deploy/demo/multi-tier-split.bo"}});
    return out;
}

/// The rule ids a model's dump marks: "{R3}".
std::set<std::string> dumped_rules(const model::Model& m) {
    std::set<std::string> out;
    const std::string text = dump(m);
    const std::regex rule(R"(\{(R[0-9]+)\})");
    for (auto it = std::sregex_iterator(text.begin(), text.end(), rule);
         it != std::sregex_iterator(); ++it) {
        out.insert((*it)[1].str());
    }
    return out;
}

std::vector<const ExplainedClause*> clauses_of(const Explained& e, std::string_view kind) {
    std::vector<const ExplainedClause*> out;
    for (const ExplainedSection& s : e.sections) {
        for (const ExplainedClause& c : s.clauses) {
            if (c.kind == kind) {
                out.push_back(&c);
            }
        }
    }
    return out;
}

bool contains(std::string_view text, std::string_view part) {
    return text.find(part) != std::string_view::npos;
}

} // namespace

TEST_CASE("the contract text's goldens, the same from every spelling", "[bo][explain]") {
    const bool update = std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr;
    std::size_t texts = 0;
    for (const Case& c : cases()) {
        INFO(c.name);
        const std::filesystem::path dir = golden_dir / "explain" / c.name;
        if (update) {
            std::filesystem::create_directories(dir);
        }
        for (const auto& [id, file] : languages) {
            INFO(id);
            const std::string text = explain(model_of(c.sources.front()), language(id)).text;
            if (update) {
                std::ofstream(dir / file, std::ios::binary) << text;
            }
            CHECK(text == read_text(dir / file));
            ++texts;
            for (const auto& source : c.sources) {
                INFO(source.string());
                const model::Model m = model_of(source);
                CHECK(explain(m, language(id)).text == text);
                // The same every time.
                CHECK(explain(m, language(id)).text == text);
            }
        }
    }
    CHECK(texts == 57);
}

TEST_CASE("the contract text says what compiled code decides", "[bo][explain]") {
    const model::Model agreement = model_of(golden_dir / "build/agreement-en/source.bo");
    const Explained e = explain(agreement, nullptr);
    CHECK(e.language == "en");
    CHECK(e.title == "Contract Agreement");

    // Requirements, numbered as refusals name them (bo:requires amend 1,
    // bo:requires sign 2): every requires line, in order, by action.
    std::vector<std::pair<std::string, std::uint32_t>> numbers;
    for (const ExplainedClause* c : clauses_of(e, "requirement")) {
        numbers.emplace_back(c->function, c->requirement);
        CHECK(c->text.starts_with("Requirement " + std::to_string(c->requirement) + ": "));
    }
    CHECK(numbers ==
          std::vector<std::pair<std::string, std::uint32_t>>{
              {"amend", 1}, {"amend", 2}, {"amend", 3}, {"sign", 1}, {"sign", 2}, {"close", 1}});
    const ExplainedClause* sign2 = clauses_of(e, "requirement")[4];
    CHECK(sign2->text == "Requirement 2: the time of the call is before starts.");
    const ExplainedClause* amend1 = clauses_of(e, "requirement")[0];
    CHECK(amend1->text == "Requirement 1: the instance is proposed.");
    CHECK(amend1->rules == std::vector<std::string_view>{"R7"});

    // The final state is the one compiled code marks final.
    const std::vector<bool> finals = model::final_states(agreement);
    REQUIRE(finals.size() == 4);
    CHECK(finals == std::vector<bool>{false, false, false, true});
    const auto final_clauses = clauses_of(e, "final-state");
    REQUIRE(final_clauses.size() == 1);
    CHECK(final_clauses[0]->text ==
          "The state closed is final: no action can start from it, so an instance in it "
          "takes no more calls.");

    // The functions: create (issue for an asset), and one per action.
    CHECK(contains(clauses_of(e, "creation")[0]->text, "(function create)"));
    const Explained receivable =
        explain(model_of(golden_dir / "example-receivable-en/source.bo"), nullptr);
    CHECK(contains(clauses_of(receivable, "creation")[0]->text, "(function issue)"));
    std::vector<std::string> functions;
    for (const ExplainedClause* c : clauses_of(e, "action")) {
        functions.push_back(c->function);
    }
    CHECK(functions == std::vector<std::string>{"amend", "sign", "countersign", "close"});
    // In Chinese, a vocabulary action is named in the language, with its
    // function: what a refusal names.
    const Explained hant =
        explain(model_of(golden_dir / "example-receivable-en/source.bo"), language("zh-Hant-HK"));
    CHECK(clauses_of(hant, "action")[0]->text == "質押（函數 pledge）");

    // R6: the threshold compares the action's one amount.
    const ExplainedClause* in_person = clauses_of(e, "requirement")[3];
    CHECK(in_person->text ==
          "Requirement 1: if the amount is over HKD 1,000,000, the customer must prove presence "
          "in person, with a passkey or a hardware key.");
    CHECK(in_person->rules == std::vector<std::string_view>{"R6", "R13"});
    CHECK(model::action_amount(agreement, agreement.actions[1]) == "field.amount");
    CHECK(model::action_amount(agreement, agreement.actions[0]) == "new_amount");
}

TEST_CASE("every inferred clause is marked, and every rule used explained", "[bo][explain]") {
    for (const Case& c : cases()) {
        INFO(c.name);
        const model::Model m = model_of(c.sources.front());
        for (const auto& [id, file] : languages) {
            INFO(id);
            const Explained e = explain(m, language(id));
            std::set<std::string> marked;
            std::size_t clauses = 0;
            for (const ExplainedSection& s : e.sections) {
                for (const ExplainedClause& clause : s.clauses) {
                    ++clauses;
                    CHECK(!clause.text.empty());
                    CHECK(clause.number.starts_with(s.number + "."));
                    CHECK(contains(e.text, clause.text));
                    for (const std::string_view r : clause.rules) {
                        CHECK(find_rule(r) != nullptr);
                        marked.insert(std::string(r));
                    }
                }
            }
            CHECK(clauses > 4);
            // Whatever the model says a rule inferred is marked in the text.
            for (const std::string& r : dumped_rules(m)) {
                CHECK(marked.contains(r));
            }
            // The last section explains exactly the rules marked, in order.
            std::vector<std::string> explained;
            for (const auto& [rule, text] : e.rules) {
                explained.emplace_back(rule);
                CHECK(text == explain(m, language(id)).rules[explained.size() - 1].second);
                CHECK(!text.starts_with("rule-"));
            }
            CHECK(std::set<std::string>(explained.begin(), explained.end()) == marked);
            CHECK(std::ranges::is_sorted(
                explained, {}, [](const std::string& r) { return std::stoi(r.substr(1)); }));
        }
    }
}

TEST_CASE("texts are in quotation marks, those read by R18 too", "[bo][explain]") {
    CHECK(quoted_text("中国内地", nullptr) == "\"中国内地\"");
    CHECK(quoted_text("中国内地", language("zh-Hant-HK")) == "「中国内地」");
    CHECK(quoted_text("中国内地", language("zh-Hans-CN")) == "“中国内地”");
    const model::Model tax = model_of(golden_dir / "example-tax-zh-hans/source.bo");
    const auto applies = [&](std::string_view id) {
        for (const ExplainedClause* c : clauses_of(explain(tax, language(id)), "charge-line")) {
            if (!c->rules.empty() && c->rules.front() == "R18") {
                return c->text;
            }
        }
        return std::string();
    };
    CHECK(applies("en") == "It applies when the customer location is \"中国内地\".");
    CHECK(applies("zh-Hant-HK") == "適用條件：客戶所在地為「中国内地」。");
    CHECK(applies("zh-Hans-CN") == "适用条件：客户所在地为“中国内地”。");
    // A written text, too (a reject's reason).
    const Explained e =
        explain(model_of(golden_dir / "build/agreement-zh-hans/source.bo"), language("zh-Hans-CN"));
    CHECK(clauses_of(e, "reject")[0]->text ==
          "拒绝调用，原因为“an amendment may raise the amount by half at most”。");
}

TEST_CASE("Chinese text sets Latin words and numbers apart, never inside a name", "[bo][explain]") {
    const model::Model agreement = model_of(golden_dir / "build/agreement-en/source.bo");
    const Explained hant = explain(agreement, language("zh-Hant-HK"));
    CHECK(clauses_of(hant, "kind")[0]->text == "每個實例為一項紀錄，名為 Terms。");
    CHECK(clauses_of(hant, "requirement")[2]->text == "要求 3：new_amount 大於港元 0。");
    CHECK(clauses_of(hant, "states")[0]->text == "其狀態包括已提議、signed、effective 及 closed。");
    CHECK(contains(hant.text, "〔R6、R13〕"));
    // English: words, forms (us, the customer), and grouped numbers.
    const Explained en = explain(agreement, nullptr);
    CHECK(clauses_of(en, "by")[0]->text == "Started by us, whose agreement it needs.");
    CHECK(clauses_of(en, "by")[1]->text == "Started by the customer, whose agreement it needs.");
    CHECK(clauses_of(en, "states")[0]->text ==
          "Its states are proposed, signed, effective, and closed.");
    // A name with Han characters and Latin letters stays as written.
    const Explained pool =
        explain(model_of(golden_dir / "example-ip-pool-en/source.bo"), language("zh-Hans-CN"));
    CHECK(pool.title == "合约 IP地址池");
    CHECK(clauses_of(pool, "kind")[0]->text == "每个实例为一项资源，名为 IP地址。");
    CHECK(clauses_of(pool, "field")[1]->text == "冷却期：30 天，所有实例都相同。");
}

TEST_CASE("a pack without sentences writes them in English, with its own words", "[bo][explain]") {
    std::string keywords;
    for (const Concept& c : concepts()) {
        if (c.category == Category::keyword) {
            keywords += (keywords.empty() ? "" : ", ") + std::string("\"") + std::string(c.id) +
                        "\": \"q" + std::string(c.id.substr(3)) + "\"";
        }
    }
    const std::string text =
        R"({"format": 1, "id": "acme", "version": 1, "language": "en-x-acme", "name": "Acme",
            "official": false, "edition": 1, "reading": {"separation": "spaces"},
            "keywords": {)" +
        keywords + R"(},
            "vocabulary": {"role.customer": {"word": "client",
                "forms": {"subject": "the client", "object": "the client"}}}})";
    const PackRead read = read_pack(text);
    REQUIRE(read.pack);
    const model::Model agreement = model_of(golden_dir / "build/agreement-en/source.bo");
    const std::string english = explain(agreement, nullptr).text;
    const Explained own = explain(agreement, &*read.pack);
    CHECK(own.language == "acme");
    CHECK(own.text == std::regex_replace(english, std::regex("customer"), "client"));
}

TEST_CASE("any model explains, in every language", "[bo][explain]") {
    // Fragments, models with errors, and an empty model are safe.
    const model::Model empty;
    for (const auto& [id, file] : languages) {
        const Explained e = explain(empty, language(id));
        CHECK(!e.text.empty());
        CHECK(e.title == explain(empty, language(id)).title);
    }
    const std::string source = "contract X\nparties we\nasset A\n  amount HKD\n  holder nobody\n"
                               "can go by we\n  requires amount > HKD 1 and nothing\n";
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    const Checked checked = check(source, parsed.file);
    CHECK(has_errors(checked.diagnostics));
    for (const auto& [id, file] : languages) {
        CHECK(!explain(checked.model, language(id)).text.empty());
    }
}

TEST_CASE("an instance's state, in the text's words", "[bo][explain]") {
    const std::string source = "contract Values\nparties we, customer\nrecord Sheet\n"
                               "  label text\n  approved yes or no\n  total HKD\n  ends date\n"
                               "  size GB\n  count number\n  holder customer\n"
                               "can close by we\n  active -> closed\n";
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    const Checked checked = check(source, parsed.file);
    REQUIRE(!has_errors(checked.diagnostics));
    // 2030-01-01 13:30 at +08:00; money in cents; GB in bytes.
    const auto state = cexchain::cbor::parse_diagnostic(
        R"({"state": "active", "fields": {"label": "a", "approved": true, "total": -12345,
            "ends": 1893475800000, "size": 1500000000, "count": 1234567,
            "holder": h'1111111111111111111111111111111111111111111111111111111111111111',
            "other": 1}})");
    REQUIRE(state);
    const LedgerLabel label = [](cexchain::ByteView id) {
        return "ledger " + std::to_string(id.size()) + " bytes";
    };
    const auto values = [&](const Pack* pack) {
        const ExplainedState s = explain_state(checked.model, *state, pack, label);
        std::vector<std::string> out{s.state};
        for (const ExplainedValue& v : s.fields) {
            out.push_back(v.field + ": " + v.value);
        }
        return out;
    };
    CHECK(values(nullptr) ==
          std::vector<std::string>{"active", "label: \"a\"", "approved: yes", "total: HKD -123.45",
                                   "ends: 1 January 2030 13:30 (UTC+08:00)", "size: 1.5 GB",
                                   "count: 1,234,567", "holder: ledger 32 bytes"});
    CHECK(values(language("zh-Hant-HK")) ==
          std::vector<std::string>{"正常", "label: 「a」", "approved: 是", "total: 港元 -123.45",
                                   "ends: 2030年1月1日 13:30 (UTC+08:00)", "size: 1.5 GB",
                                   "count: 1,234,567", "持有人: ledger 32 bytes"});
    // A value not of its field's type is shown as it is.
    const auto odd =
        cexchain::cbor::parse_diagnostic(R"({"state": "gone", "fields": {"total": "x"}})");
    REQUIRE(odd);
    const ExplainedState s = explain_state(checked.model, *odd, nullptr, label);
    CHECK(s.state.empty());
    REQUIRE(s.fields.size() == 1);
    CHECK(s.fields[0].value == "\"x\"");
}
