// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Claims (spec v0.14): their metadata's shape, their words, the ledger's
// rules for their source, and their evidence, which carries the source and
// says when it was revoked or replaced since.

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/claims.hpp>
#include <kanhe/core/protocol/evidence.hpp>

#include "support/ledger_world.hpp"

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::Errc;
namespace cbor = kanhe::cbor;

namespace {

using V = cbor::Value;

cbor::Value money(std::int64_t amount, std::string currency, std::uint64_t scale) {
    return V::array({V::integer(amount), V::text(std::move(currency)), V::unsigned_integer(scale)});
}

/// "monthly_salary is above HKD 30,000.00 and ...", as of `as_of`, for 30
/// days.
protocol::Claim salary_claim(const protocol::Id& source,
                             protocol::Timestamp as_of = 1'791'244'800'000) {
    protocol::Claim c;
    c.source = source;
    c.condition = {{"monthly_salary", ">", "money", money(3000000, "HKD", 2)},
                   {"status", "in", "text", V::array({V::text("staff"), V::text("contractor")})}};
    c.as_of = as_of;
    c.until = as_of + 30 * 86'400'000ULL;
    c.subject = "Chan Tai Man";
    return c;
}

/// A claim's metadata with `key` set to `value` (or removed, if null and
/// `remove`).
cbor::Value with(const protocol::Claim& claim, std::string_view key, cbor::Value value) {
    cbor::Map map = *protocol::encode_claim(claim)->as_map();
    std::erase_if(map, [&](const cbor::MapEntry& e) { return *e.key.as_text() == key; });
    map.push_back({V::text(std::string(key)), std::move(value)});
    return V::map(std::move(map));
}

cbor::Value term(std::string field, std::string op, std::string type, cbor::Value value) {
    return V::array({V::text(std::move(field)), V::text(std::move(op)), V::text(std::move(type)),
                     std::move(value)});
}

bool refused(const protocol::Claim& claim, cbor::Value condition) {
    return !protocol::decode_claim(with(claim, "condition", V::array({std::move(condition)})));
}

} // namespace

TEST_CASE("a claim's metadata reads back, and its shape is checked", "[claims]") {
    const auto claim = salary_claim(*protocol::to_id(Bytes(32, 7)));
    const auto encoded = protocol::encode_claim(claim);
    REQUIRE(encoded);
    const auto back = protocol::decode_claim(*encoded);
    REQUIRE(back);
    CHECK(*back == claim);

    CHECK_FALSE(protocol::decode_claim(with(claim, "extra", V::boolean(true))));
    CHECK_FALSE(protocol::decode_claim(with(claim, "until", V::unsigned_integer(claim.as_of))));
    CHECK_FALSE(protocol::decode_claim(with(claim, "subject", V::text(std::string(257, 'a')))));
    CHECK_FALSE(protocol::decode_claim(with(claim, "holds", V::text("yes"))));
    CHECK_FALSE(protocol::decode_claim(with(claim, "source", V::bytes(Bytes(31, 7)))));
    CHECK_FALSE(protocol::decode_claim(with(claim, "condition", V::array({}))));
    CHECK_FALSE(protocol::decode_claim(
        with(claim, "condition",
             V::array(std::vector<V>(17, term("age", ">=", "number", V::integer(18)))))));

    // Each operator with its types and values.
    CHECK_FALSE(refused(claim, term("age", ">=", "number", V::integer(18))));
    CHECK_FALSE(refused(claim, term("score", "<", "number", V::text("-3.25"))));
    CHECK(refused(claim, term("score", "<", "number", V::text("3."))));
    CHECK(refused(claim, term("score", "<", "number", V::text(std::string(41, '1')))));
    CHECK(refused(claim, term("name", ">", "text", V::text("A"))));
    CHECK_FALSE(refused(claim, term("name", "!=", "text", V::text("A"))));
    CHECK(refused(claim, term("born", "<", "date", V::text("2026-02-30"))));
    CHECK_FALSE(refused(claim, term("born", "<", "date", V::text("2024-02-29"))));
    CHECK(refused(claim, term("pay", ">", "money", money(1, "hkd", 2))));
    CHECK(refused(claim, term("pay", ">", "money", money(1, "HKD", 5))));
    CHECK_FALSE(refused(claim, term("pay", "between", "money",
                                    V::array({money(100, "HKD", 0), money(10001, "HKD", 2)}))));
    CHECK(refused(claim, term("pay", "between", "money",
                              V::array({money(100, "HKD", 0), money(9999, "HKD", 2)}))));
    CHECK(refused(claim, term("pay", "between", "money",
                              V::array({money(1, "HKD", 0), money(2, "USD", 0)}))));
    CHECK(refused(claim, term("grade", "in", "text", V::array({V::text("A"), V::text("A")}))));
    CHECK(refused(claim, term("grade", "in", "text", V::array({}))));
    CHECK_FALSE(refused(claim, term("grade", "exists", "text", V::null())));
    CHECK(refused(claim, term("grade", "exists", "number", V::null())));
    CHECK(refused(claim, term("grade", "exists", "text", V::text("A"))));
    CHECK(refused(claim, term("", "=", "text", V::text("A"))));
    CHECK(refused(claim, term("grade", "~", "text", V::text("A"))));
}

TEST_CASE("a claim's condition in words", "[claims]") {
    auto claim = salary_claim(*protocol::to_id(Bytes(32, 7)));
    CHECK(protocol::claim_text(claim) ==
          "monthly_salary is above HKD 30,000.00 and status is one of \"staff\", \"contractor\"");
    claim.condition = {{"balance", "<=", "money", money(-123456789, "JPY", 0)},
                       {"rate", "between", "number", V::array({V::integer(-1), V::text("2.50")})},
                       {"born", "<", "date", V::text("2008-11-10")},
                       {"grade", "exists", "text", V::null()},
                       {"name", "=", "text", V::text("Chan Tai Man")},
                       {"left", "!=", "money", money(5, "USD", 2)},
                       {"age", ">=", "number", V::integer(18)}};
    CHECK(protocol::claim_text(claim) ==
          "balance is at most JPY -123,456,789 and rate is between -1 and 2.50 and born is below "
          "2008-11-10 and grade is given and name is \"Chan Tai Man\" and left is not USD 0.05 "
          "and age is at least 18");
}

TEST_CASE("the ledger takes a claim only on a live record of its own", "[claims][ledger]") {
    World w;
    const auto source = w.ok(
        w.org(), w.statement(w.org_id(), std::nullopt, w.record_body("example.org.payslip/1")));
    auto claim_of = [&](const protocol::Claim& claim) {
        auto body = w.record_body(std::string(protocol::claim_type));
        body.metadata = *protocol::encode_claim(claim);
        return w.statement(w.org_id(), std::nullopt, std::move(body));
    };
    const auto claim = salary_claim(source, w.clock().now());
    const auto made = w.ok(w.org(), claim_of(claim));
    CHECK(w.ledger().state().record(made)->state == "confirmed");

    // Not of this ledger, not generic, not yet evaluated, not live.
    CHECK(w.rejected(w.org(), claim_of(salary_claim(*protocol::to_id(Bytes(32, 9)),
                                                    w.clock().now()))) == Errc::not_found);
    CHECK(w.rejected(w.org(), claim_of(salary_claim(made, w.clock().now()))) == Errc::rejected);
    CHECK(w.rejected(w.org(), claim_of(salary_claim(source, w.clock().now() + 60'000))) ==
          Errc::rejected);
    auto unshaped = w.record_body(std::string(protocol::claim_type));
    unshaped.metadata = with(claim, "extra", V::boolean(true));
    CHECK(w.rejected(w.org(), w.statement(w.org_id(), std::nullopt, unshaped)) == Errc::malformed);
    // A claim takes no endorsement, and is not superseded.
    CHECK(w.rejected(w.org(), w.statement(w.org_id(), std::nullopt,
                                          protocol::RecordEndorseBody{made, "witness"})) ==
          Errc::rejected);
    w.ok(w.org(),
         w.statement(w.org_id(), std::nullopt, protocol::RecordRevokeBody{source, "reissued"}));
    CHECK(w.rejected(w.org(), claim_of(salary_claim(source, w.clock().now()))) == Errc::rejected);
}

TEST_CASE("a claim's evidence carries its source, and says when it was revoked",
          "[claims][evidence]") {
    World w;
    const auto source = w.ok(
        w.org(), w.statement(w.org_id(), std::nullopt, w.record_body("example.org.payslip/1")));
    auto body = w.record_body(std::string(protocol::claim_type));
    auto claim = salary_claim(source, w.clock().now());
    claim.until = claim.as_of + 3'600'000;
    body.metadata = *protocol::encode_claim(claim);
    const auto made = w.ok(w.org(), w.statement(w.org_id(), std::nullopt, std::move(body)));
    // An unrelated record, which the claim's bundle does not need.
    w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body("example.org.other/1")));
    REQUIRE(w.ledger().checkpoint(w.log_key()));

    protocol::VerifyOptions options;
    options.expected_ledger = w.ledger().id();
    auto verified = [&] {
        const auto exported = w.ledger().export_evidence(w.log_key(), made);
        REQUIRE(exported);
        return protocol::verify_bundle(provider(), *protocol::encode_bundle(*exported), options);
    };
    auto report = verified();
    REQUIRE(report);
    REQUIRE(report->complete);
    REQUIRE(report->claim);
    CHECK(report->claim->claim == claim);
    CHECK(report->claim->source_type == "example.org.payslip/1");
    CHECK(report->claim->source_status == "live");
    CHECK_FALSE(report->claim->lapsed);
    CHECK(report->claim->text.starts_with("monthly_salary is above HKD 30,000.00"));

    // Revoked since: the claim's evidence says so.
    w.ok(w.org(),
         w.statement(w.org_id(), std::nullopt, protocol::RecordRevokeBody{source, "reissued"}));
    w.clock().advance(3'600'000);
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    report = verified();
    REQUIRE(report);
    REQUIRE(report->complete);
    CHECK(report->claim->source_status == "revoked");
    CHECK(report->claim->lapsed);

    // The source's proof cannot be left out.
    auto exported = w.ledger().export_evidence(w.log_key(), made);
    REQUIRE(exported);
    std::erase_if(exported->state_proofs,
                  [&](const protocol::StateProof& p) { return p.leaf.id == source; });
    CHECK_FALSE(protocol::verify_bundle(provider(), *protocol::encode_bundle(*exported), options));
}
