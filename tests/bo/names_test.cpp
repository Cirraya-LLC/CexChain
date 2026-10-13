// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// cexchain::bo, the part of the compiler built with C++26 reflection and
// contracts (GCC 16): names from the enumerators, and records written member
// by member.

#include <cstddef>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/ast.hpp>
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
    const std::string source = "contract X\ncan pledge to bank\n  over HKD 100 requires in person\n"
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
    CHECK(clauses[1].find("span")->find("line")->as_uint64() == 2U);
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
