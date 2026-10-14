// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Bo's standard library (milestone 11): bo/stdlib/edition1.bo, compiled in.
// It reads, is laid out canonically, and reads the same in every language;
// each clause is a built-in action's terms; a contract that declares them
// all checks without a problem; their contract text has goldens in three
// languages (tests/bo/golden/explain/stdlib/); and `bo stdlib` finds an
// action by any of its words and writes its terms in any language.
// Set CEXCHAIN_UPDATE_GOLDENS=1 to rewrite the goldens.

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/stdlib.hpp>

using namespace cexchain;
using namespace cexchain::bo;

namespace {

const std::filesystem::path golden_dir = CEXCHAIN_BO_GOLDEN_DIR;
const std::filesystem::path source_dir = golden_dir.parent_path().parent_path().parent_path();

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

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

std::string tree_of(std::string_view source) {
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    CHECK(!has_errors(lexed.diagnostics));
    CHECK(parsed.diagnostics.empty());
    return dump(parsed.file);
}

const std::vector<std::pair<std::string, std::string>> languages{
    {"en", "en.txt"}, {"zh-Hant-HK", "zh-hant.txt"}, {"zh-Hans-CN", "zh-hans.txt"}};

} // namespace

TEST_CASE("the standard library reads, as compiled in, in every language", "[bo][stdlib]") {
    const StandardLibrary& library = standard_library();
    // The file as compiled in, and laid out canonically.
    CHECK(library.source == read_text(source_dir / "bo/stdlib/edition1.bo"));
    const Formatted kept = format_source(library.source, official_set(), official(), nullptr);
    REQUIRE(kept.source.has_value());
    CHECK(*kept.source == library.source);
    // The same tree in each language.
    const std::string tree = dump(library.parsed.file);
    for (const auto& [id, file] : languages) {
        INFO(id);
        const Formatted other =
            format_source(library.source, official_set(), official(), official_pack(id));
        REQUIRE(other.source.has_value());
        CHECK(tree_of(*other.source) == tree);
    }
    // Every clause is a built-in action's terms, each action once.
    std::vector<std::string> actions;
    for (const ast::Can* can : library.templates) {
        actions.emplace_back(can->action.concept_entry->id);
        CHECK(library.find(can->action.concept_entry->id) == can);
    }
    CHECK(actions == std::vector<std::string>{"act.transfer", "act.pledge", "act.release",
                                              "act.enforce", "act.redeem", "act.pay",
                                              "act.confirm_payment", "act.dispute", "act.freeze",
                                              "act.unfreeze", "act.cancel"});
    CHECK(library.find("act.refund") == nullptr);
    CHECK(library.find("act.issue") == nullptr);
}

TEST_CASE("every built-in action's terms, in short", "[bo][stdlib]") {
    // A contract declaring them all checks, every action with its terms.
    const model::Model& m = standard_model();
    REQUIRE(m.actions.size() == 11);
    for (const model::Action& a : m.actions) {
        INFO(a.word->id);
        CHECK(a.terms);
        CHECK(a.terms_from == 0);
    }
    std::vector<std::string> lines;
    for (const StandardAction& a : standard_actions()) {
        std::string line = a.function + ":";
        line += a.starter != nullptr ? " " + std::string(a.starter->id) : " home";
        line += a.counterparty ? " to" : "";
        for (const Concept* c : a.from) {
            line += " " + std::string(c->id);
        }
        line += " ->";
        for (const Concept* c : a.to) {
            line += " " + std::string(c->id);
        }
        lines.push_back(line);
    }
    CHECK(lines == std::vector<std::string>{
                       "transfer: field.holder to state.active -> state.active",
                       "pledge: field.holder to state.active -> state.pledged",
                       "release: field.pledgee state.pledged -> state.active",
                       "enforce: field.pledgee state.pledged -> state.active",
                       "redeem: field.holder state.active state.pledged -> state.redeemed",
                       "pay: home state.active state.pledged state.disputed -> state.paid",
                       "confirm_payment: field.payee state.paid state.disputed -> state.settled",
                       "dispute: field.payee state.paid -> state.disputed",
                       "freeze: home state.active state.pledged state.paid state.disputed -> "
                       "state.frozen",
                       "unfreeze: home state.frozen -> expr.previous_state",
                       "cancel: field.holder state.active -> state.cancelled"});
}

namespace {

/// Every place a model holds is in its source (or is no place: line 0).
bool placed(const Span& span, std::string_view source) {
    return span.line == 0 || std::size_t{span.offset} + span.length <= source.size();
}

bool placed(const model::Expr& e, std::string_view source) {
    return placed(e.span, source) &&
           std::ranges::all_of(e.operands, [&](const model::Expr& o) { return placed(o, source); });
}

bool placed(const std::vector<model::Statement>& list, std::string_view source) {
    return std::ranges::all_of(list, [&](const model::Statement& s) {
        return std::visit(
            [&](const auto& node) {
                using N = std::remove_cvref_t<decltype(node)>;
                bool ok = placed(node.span, source);
                if constexpr (std::is_same_v<N, model::Requires>) {
                    ok = ok && placed(node.condition, source) &&
                         (!node.guard || placed(*node.guard, source));
                } else if constexpr (std::is_same_v<N, model::If>) {
                    ok = ok && placed(node.condition, source) && placed(node.then, source) &&
                         placed(node.otherwise, source);
                } else if constexpr (std::is_same_v<N, model::Set>) {
                    ok = ok && placed(node.target, source) && placed(node.value, source);
                } else if constexpr (std::is_same_v<N, model::Transition>) {
                    ok = ok && placed(node.to, source) &&
                         std::ranges::all_of(
                             node.from, [&](const model::Expr& f) { return placed(f, source); });
                }
                return ok;
            },
            s.node);
    });
}

} // namespace

TEST_CASE("the standard terms are placed in the contract, not in the library", "[bo][stdlib]") {
    // The terms are read from the library's source; the model places them at
    // the contract's `can` line, so every place is in the contract's source.
    const std::string_view source = standard_showcase();
    const model::Model& m = standard_model();
    for (const model::Action& a : m.actions) {
        INFO(a.word->id);
        CHECK(placed(a.span, source));
        CHECK(placed(a.body, source));
        CHECK((!a.by || placed(*a.by, source)));
        CHECK((!a.to || placed(*a.to, source)));
        for (const model::Field& input : a.inputs) {
            CHECK(placed(input.span, source));
        }
        for (const model::Consent& c : a.consents) {
            CHECK(placed(c.span, source));
            CHECK(placed(c.party, source));
        }
    }
}

TEST_CASE("the standard library's contract text, in three languages", "[bo][stdlib]") {
    const bool update = std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr;
    const std::filesystem::path dir = golden_dir / "explain" / "stdlib";
    for (const auto& [id, file] : languages) {
        INFO(id);
        const std::string text = explain(standard_model(), official_pack(id)).text;
        if (update) {
            std::filesystem::create_directories(dir);
            std::ofstream(dir / file, std::ios::binary) << text;
        }
        CHECK(text == read_text(dir / file));
    }
}

TEST_CASE("bo stdlib finds an action by any word, and writes its terms in any language",
          "[bo][stdlib]") {
    const Concept* pledge = find_concept("act.pledge");
    for (const std::string_view word : {"pledge", "質押", "质押"}) {
        CHECK(standard_action(word, official_set()) == pledge);
    }
    CHECK(standard_action("confirm_payment", official_set()) ==
          find_concept("act.confirm_payment"));
    CHECK(standard_action("確認收款", official_set()) == find_concept("act.confirm_payment"));
    CHECK(standard_action("refund", official_set()) == nullptr);
    CHECK(standard_action("lodge", official_set()) == nullptr);
    for (const StandardAction& a : standard_actions()) {
        INFO(a.function);
        const std::optional<std::string> english = standard_terms_source(a.action, nullptr);
        REQUIRE(english.has_value());
        CHECK(english->starts_with("can "));
        // No comments: what a contract copies.
        CHECK(english->find('#') == std::string::npos);
        const std::string tree = tree_of(*english);
        for (const auto& [id, file] : languages) {
            INFO(id);
            const std::optional<std::string> other =
                standard_terms_source(a.action, official_pack(id));
            REQUIRE(other.has_value());
            CHECK(tree_of(*other) == tree);
        }
        // Its contract text: the action's clauses, every one marked.
        const std::vector<ExplainedClause> text = standard_terms_text(a.action, nullptr);
        REQUIRE(!text.empty());
        for (const ExplainedClause& c : text) {
            CHECK(c.function == a.function);
            CHECK(!c.rules.empty());
        }
    }
    CHECK(standard_terms_source(find_concept("act.refund"), nullptr) == std::nullopt);
    CHECK(*standard_terms_source(pledge, official_pack("zh-Hant-HK")) ==
          "可質押 予 相對方 由 持有人\n  須 非 相對方 = 持有人\n  正常 -> 已質押\n  質權人 = "
          "相對方\n");
}
