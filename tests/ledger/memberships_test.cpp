// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Trust nodes (spec v0.16): the ledger's rules for memberships, and a
// member's evidence that carries them, verified with where each stood.

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/memberships.hpp>

#include "support/ledger_world.hpp"

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::Errc;
namespace cbor = kanhe::cbor;

namespace {

using S = protocol::Standing;

protocol::Membership membership_of(const protocol::Id& member) {
    protocol::Membership m;
    m.member = member;
    m.kind = protocol::MemberKind::organization;
    m.name = "Kowloon Example School";
    m.verified = true;
    m.registration = "12345678";
    m.jurisdiction = "HK";
    return m;
}

protocol::Statement membership_statement(World& node, const protocol::Membership& m) {
    auto body = node.record_body(std::string(protocol::membership_type));
    body.metadata = *protocol::encode_membership(m);
    return node.statement(node.org_id(), std::nullopt, std::move(body));
}

protocol::Statement transition(World& w, const protocol::Id& record, std::string from,
                               std::string to) {
    return w.statement(w.org_id(), std::nullopt,
                       protocol::RecordTransitionBody{record, std::move(from), std::move(to)});
}

/// A record's complete evidence, encoded, at a fresh checkpoint.
Bytes evidence(World& w, const protocol::Id& record, std::vector<Bytes> memberships = {}) {
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    auto exported = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(exported);
    exported->memberships = std::move(memberships);
    auto encoded = protocol::encode_bundle(*exported);
    REQUIRE(encoded);
    return std::move(*encoded);
}

} // namespace

TEST_CASE("a trust node's memberships: the ledger's rules", "[memberships][ledger]") {
    World node(kanhe::crypto::HashAlg::sha256, "Trust Node");
    World member(kanhe::crypto::HashAlg::sha256, "Kowloon Example School");
    const auto m = membership_of(member.ledger().id());
    const auto made = node.ok(node.org(), membership_statement(node, m));
    CHECK(node.ledger().state().record(made)->state == "active");

    // Its own ledger is no member; the metadata is the membership's shape.
    CHECK(node.rejected(node.org(), membership_statement(node, membership_of(node.org_id()))) ==
          Errc::rejected);
    auto bare = node.record_body(std::string(protocol::membership_type));
    CHECK(node.rejected(node.org(), node.statement(node.org_id(), std::nullopt, bare)) ==
          Errc::malformed);
    cbor::Map extra = *protocol::encode_membership(m)->as_map();
    extra.push_back({cbor::Value::text("extra"), cbor::Value::boolean(true)});
    bare.metadata = cbor::Value::map(std::move(extra));
    CHECK(node.rejected(node.org(), node.statement(node.org_id(), std::nullopt, bare)) ==
          Errc::malformed);

    // Suspended, resumed, ended; nothing after its end, no endorsement.
    node.ok(node.org(), transition(node, made, "active", "suspended"));
    node.ok(node.org(), transition(node, made, "suspended", "active"));
    node.ok(node.org(), transition(node, made, "active", "ended"));
    CHECK(node.ledger().state().record(made)->state == "ended");
    CHECK(node.rejected(node.org(), transition(node, made, "ended", "active")) == Errc::rejected);
    CHECK(node.rejected(node.org(), node.statement(node.org_id(), std::nullopt,
                                                   protocol::RecordEndorseBody{made, "checked"})) ==
          Errc::rejected);
}

TEST_CASE("a member's evidence carries its memberships, and says where they stood",
          "[memberships][evidence]") {
    World node(kanhe::crypto::HashAlg::sha256, "Trust Node");
    World member(kanhe::crypto::HashAlg::sha256, "Kowloon Example School");
    const auto m = membership_of(member.ledger().id());
    const auto made = node.ok(node.org(), membership_statement(node, m));
    const Bytes proof = evidence(node, made);

    // The member's record, registered after the membership was.
    member.clock().advance(60'000);
    const auto record =
        member.ok(member.org(), member.statement(member.org_id(), std::nullopt,
                                                 member.record_body("example.org.diploma/1")));
    protocol::VerifyOptions options;
    options.expected_ledger = member.ledger().id();
    options.trust_nodes = {{node.ledger().id(), "HK Trust"}};
    auto report = protocol::verify_bundle(provider(), evidence(member, record, {proof}), options);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    REQUIRE(report->memberships.size() == 1);
    const auto& p = report->memberships.front();
    CHECK(p.trust_node == node.ledger().id());
    CHECK(p.trusted);
    CHECK(p.trust_node_name == "HK Trust");
    CHECK(p.record == made);
    CHECK(p.membership == m);
    CHECK(p.at_record == S::active);
    CHECK(p.at_checkpoint == S::active);
    CHECK(p.record_time == report->events.front().registered_at);

    // A node off the verifier's list is reported, and named by nothing.
    options.trust_nodes = {{member.ledger().id(), "Look-alike"}};
    report = protocol::verify_bundle(provider(), evidence(member, record, {proof}), options);
    REQUIRE(report);
    CHECK_FALSE(report->memberships.front().trusted);
    CHECK(report->memberships.front().trust_node_name.empty());

    // Suspended after the record: active then, suspended at the checkpoint.
    node.clock().advance(120'000);
    node.ok(node.org(), transition(node, made, "active", "suspended"));
    const Bytes later = evidence(node, made);
    report = protocol::verify_bundle(provider(), evidence(member, record, {later}), options);
    REQUIRE(report);
    CHECK(report->memberships.front().at_record == S::active);
    CHECK(report->memberships.front().at_checkpoint == S::suspended);

    // A record older than the membership: not yet a member then.
    World early(kanhe::crypto::HashAlg::sha256, "Early School");
    const auto early_record =
        early.ok(early.org(), early.statement(early.org_id(), std::nullopt,
                                              early.record_body("example.org.diploma/1")));
    node.clock().advance(60'000);
    const auto early_membership =
        node.ok(node.org(), membership_statement(node, membership_of(early.ledger().id())));
    options.expected_ledger = early.ledger().id();
    report = protocol::verify_bundle(
        provider(), evidence(early, early_record, {evidence(node, early_membership)}), options);
    REQUIRE(report);
    CHECK(report->memberships.front().at_record == S::not_yet);
    CHECK(report->memberships.front().at_checkpoint == S::active);
    options.expected_ledger = member.ledger().id();

    // What fails: a proof naming another member, twice the same proof, a
    // proof carrying proofs, a damaged proof, a proof of no membership, and
    // more than 16.
    CHECK_FALSE(protocol::verify_bundle(
        provider(), evidence(member, record, {evidence(node, early_membership)}), options));
    CHECK_FALSE(
        protocol::verify_bundle(provider(), evidence(member, record, {proof, later}), options));
    CHECK_FALSE(
        protocol::verify_bundle(provider(), evidence(member, record, {proof, proof}), options));
    auto nested = protocol::decode_bundle(proof);
    REQUIRE(nested);
    nested->memberships = {proof};
    CHECK_FALSE(protocol::verify_bundle(
        provider(), evidence(member, record, {*protocol::encode_bundle(*nested)}), options));
    Bytes damaged = proof;
    damaged[damaged.size() - 20] ^= 1;
    CHECK_FALSE(protocol::verify_bundle(provider(), evidence(member, record, {damaged}), options));
    const auto other = node.ok(node.org(), node.statement(node.org_id(), std::nullopt,
                                                          node.record_body("example.org.note/1")));
    CHECK_FALSE(protocol::verify_bundle(
        provider(), evidence(member, record, {evidence(node, other)}), options));
    auto many = protocol::decode_bundle(evidence(member, record));
    REQUIRE(many);
    many->memberships = std::vector<Bytes>(17, proof);
    CHECK_FALSE(protocol::encode_bundle(*many));
}
