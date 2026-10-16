// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// cexchain::bo, the part of the compiler built with C++26 reflection and
// contracts (GCC 16): names from the enumerators, and records (a pack's
// facts, a tree, a checked model) written member by member.

#include <cstddef>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/names.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;

TEST_CASE("names come from the enumerators", "[bo][names]") {
    for (std::size_t i = 0; i < category_names.size(); ++i) {
        CHECK(name_of(static_cast<Category>(i)) == category_names[i]);
    }
    CHECK(name_of(Category::unit) == "unit");
    CHECK(name_of(Severity::warning) == "warning");
    CHECK(name_of(Separation::none) == "none");
    CHECK(name_of(MeaningKind::multiplier) == "multiplier");
    CHECK(name_of(Piece::close) == "close");
    CHECK(name_of(ast::ExprKind::apply) == "apply");
    CHECK(name_of(ast::LiteralKind::duration) == "duration");
    CHECK(name_of(ast::Operator::member) == "member");
    CHECK(name_of(model::TypeKind::unit_price) == "unit_price");
    CHECK(name_of(model::Dimension::bandwidth) == "bandwidth");
    CHECK(name_of(model::Refers::item) == "item");
    CHECK(name_of(model::Binding::action) == "action");
    CHECK(name_of(model::FieldKind::constant) == "constant");
    CHECK(name_of(model::DueKind::period) == "period");
    // Contracts are on: this build checks BO_PRE, BO_POST, and BO_ASSERT.
    CHECK(BO_CONTRACTS == 1);
}

TEST_CASE("a pack's facts, written member by member", "[bo][names]") {
    const crypto::openssl::Provider provider;
    const Pack& pack = *official_pack("zh-Hant-HK");
    const auto facts_or = facts(pack, provider, crypto::HashAlg::sm3);
    REQUIRE(facts_or);
    const PackFacts& f = *facts_or;
    CHECK(f.id == "zh-Hant-HK");
    CHECK(f.official);
    CHECK(f.separation == "none");
    CHECK(f.keywords == 18);
    CHECK(f.words == pack.vocabulary.size());
    CHECK(f.size == pack.canonical.size());
    CHECK(f.hash == "SM3");
    const auto d = digest(pack, provider, crypto::HashAlg::sm3);
    REQUIRE(d);
    CHECK(f.digest == to_hex(d->bytes()));

    const cbor::Value value = to_cbor(f);
    const cbor::Map& map = *value.as_map();
    REQUIRE(map.size() == 15);
    // Declaration order, names as declared.
    CHECK(*map[0].key.as_text() == "id");
    CHECK(*map[0].value.as_text() == "zh-Hant-HK");
    CHECK(*map[4].key.as_text() == "official");
    CHECK(map[4].value.as_bool() == true);
    CHECK(*map[7].key.as_text() == "keywords");
    CHECK(map[7].value.as_uint64() == 18U);
    CHECK(*map[14].key.as_text() == "digest");
}

TEST_CASE("a tree, written node by node and member by member", "[bo][names]") {
    const std::string source =
        "use finance\ncontract X\ncan pledge to bank\n  over HKD 100 requires in person\n"
        "test\n  supplier pledge to bank -> refused \"no\"\n";
    const PackSetRead set = make_pack_set({});
    REQUIRE(set.set);
    const Lexicon lexicon(*set.set);
    const Parsed parsed = parse(source, lex(source, lexicon));
    REQUIRE(parsed.diagnostics.empty());
    const cbor::Value value = to_cbor(parsed.file);
    CHECK(value.find("edition")->as_uint64() == 1U);
    const cbor::Array& clauses = *value.find("clauses")->as_array();
    REQUIRE(clauses.size() == 3);
    // Each clause: "node" (its tag), then its members by name, in order.
    const cbor::Map& can = *clauses[1].as_map();
    REQUIRE(can.size() == 7);
    CHECK(*can[0].key.as_text() == "node");
    CHECK(*can[0].value.as_text() == "can");
    CHECK(*can[1].key.as_text() == "span");
    CHECK(clauses[1].find("span")->find("line")->as_uint64() == 3U);
    // The use line, and the first word of its pack.
    CHECK(*value.find("uses")->as_array()->at(0).find("pack")->as_text() == "finance");
    CHECK(*value.find("pack_words")->as_array()->at(0).find("concept")->as_text() == "act.pledge");
    CHECK(*can[2].key.as_text() == "action");
    CHECK(*clauses[1].find("action")->find("concept")->as_text() == "act.pledge");
    CHECK(clauses[1].find("by")->is_null());
    CHECK(*clauses[1].find("to")->find("concept")->as_text() == "role.bank");
    // Statements in a variant: their own tag and members.
    const cbor::Value& requires_ = clauses[1].find("body")->as_array()->at(0);
    CHECK(*requires_.find("node")->as_text() == "requires");
    const cbor::Value& guard = *requires_.find("guard");
    CHECK(*guard.find("kind")->as_text() == "apply");
    const cbor::Value& money = guard.find("operands")->as_array()->at(0);
    CHECK(*money.find("literal")->find("kind")->as_text() == "money");
    CHECK(*money.find("literal")->find("value")->as_text() == "100");
    CHECK(*money.find("literal")->find("unit")->as_text() == "cur.HKD");
    // An optional text, present.
    const cbor::Value& expect = clauses[2].find("steps")->as_array()->at(1);
    CHECK(*expect.find("node")->as_text() == "expect");
    CHECK(*expect.find("reason")->as_text() == "no");
}

TEST_CASE("a checked model, written member by member", "[bo][names]") {
    const std::string source =
        "use finance\ncontract ReceivableFinancing\nparties issuer, supplier, bank\n"
        "asset Receivable\n  amount HKD\n  due date\n  holder supplier\n"
        "can pledge to bank\n  over 5_000_000 requires in person\n"
        "when due issuer pays\n"
        "test \"pledged\"\n"
        "  issuer issue with amount = HKD 100, due = 2027-01-01\n"
        "  supplier pledge to bank1 at 2027-01-06 in person -> pledged\n";
    const PackSetRead set = make_pack_set({});
    REQUIRE(set.set);
    const Lexicon lexicon(*set.set);
    const Parsed parsed = parse(source, lex(source, lexicon));
    REQUIRE(parsed.diagnostics.empty());
    const Checked checked = check(source, parsed.file);
    REQUIRE(checked.diagnostics.empty());
    const cbor::Value value = to_cbor(checked.model);
    // Model's members by name, in declaration order.
    const cbor::Map& map = *value.as_map();
    REQUIRE(map.size() == 16);
    CHECK(*map[0].key.as_text() == "edition");
    CHECK(*map[1].key.as_text() == "packs");
    CHECK(*map[1].value.as_array()->at(0).as_text() == "finance");
    CHECK(*map[2].key.as_text() == "name");
    CHECK(*map[2].value.as_text() == "ReceivableFinancing");
    CHECK(*value.find("kind")->as_text() == "kind.asset");
    CHECK(*value.find("due")->as_text() == "field");
    // Enumerations by their enumerators' names; rules by their ids.
    const cbor::Value& bank = value.find("parties")->as_array()->at(2);
    CHECK(*bank.find("role")->as_text() == "role.bank");
    CHECK(*bank.find("binding")->as_text() == "action");
    CHECK(*bank.find("bound_by")->as_text() == "act.pledge");
    CHECK(*bank.find("rule")->as_text() == "R3");
    // Types as their text.
    const cbor::Value& holder = value.find("fields")->as_array()->at(2);
    CHECK(*holder.find("type")->as_text() == "party");
    CHECK(*holder.find("kind")->as_text() == "instance");
    CHECK(*holder.find("value")->find("concept")->as_text() == "role.supplier");
    CHECK(*holder.find("rule")->as_text() == "R2");
    // Statements: their tag, then their members; the threshold took the
    // amount's currency (R6).
    const cbor::Value& pledge = value.find("actions")->as_array()->at(0);
    const cbor::Value& requires_ = pledge.find("body")->as_array()->at(0);
    CHECK(*requires_.find("node")->as_text() == "requires");
    const cbor::Value& amount = requires_.find("guard")->find("operands")->as_array()->at(0);
    CHECK(*amount.find("type")->as_text() == "money cur.HKD");
    CHECK(*amount.find("rule")->as_text() == "R6");
    CHECK(*amount.find("literal")->find("value")->as_text() == "5000000");
    CHECK(*requires_.find("condition")->find("rule")->as_text() == "R13");
    CHECK(*pledge.find("consents")->as_array()->at(0).find("rule")->as_text() == "R3");
    CHECK(*pledge.find("agents_rule")->as_text() == "R14");
    // A duty in a time rule (R9).
    const cbor::Value& pays =
        value.find("rules")->as_array()->at(0).find("actions")->as_array()->at(0);
    CHECK(*pays.find("node")->as_text() == "do");
    CHECK(pays.find("obligation")->as_bool() == true);
    CHECK(*pays.find("rule")->as_text() == "R9");
    CHECK(*pays.find("subject")->find("refers")->as_text() == "party");
    // Tests: steps, with what they expect by its name.
    const cbor::Value& test = value.find("tests")->as_array()->at(0);
    CHECK(*test.find("name")->as_text() == "pledged");
    const cbor::Array& steps = *test.find("steps")->as_array();
    REQUIRE(steps.size() == 2);
    CHECK(steps[0].find("creation")->as_bool() == true);
    CHECK(*steps[0].find("with")->as_array()->at(0).find("node")->as_text() == "set");
    CHECK(*steps[1].find("expect")->as_text() == "state");
    CHECK(*steps[1].find("state_word")->as_text() == "state.pledged");
    CHECK(steps[1].find("in_person")->as_bool() == true);
    CHECK(*steps[1].find("to")->find("name")->as_text() == "bank1");
    CHECK(steps[1].find("to")->find("role")->as_bool() == false);
    CHECK(*steps[1].find("at")->find("type")->as_text() == "date");
}
