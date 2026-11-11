// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.16 vectors (testvectors/protocol-v0.16.json), made apart from this
// implementation: trust nodes' memberships, their metadata, where one stood
// at a time, a trust node's log replayed with every refusal, and members'
// evidence carrying membership proofs, verified or refused.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/memberships.hpp>
#include <kanhe/core/protocol/record_types.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/state_tree.hpp>
#include <kanhe/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = kanhe::protocol;
namespace crypto = kanhe::crypto;
namespace cbor = kanhe::cbor;
using kanhe::to_hex;
using kanhe::test::hex;
using kanhe::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.16.json");
    return document;
}

protocol::Id id_of(const nlohmann::json& value) {
    return *protocol::to_id(hex(text(value)));
}

std::optional<std::string> optional_text(const nlohmann::json& j, const char* key) {
    return j.contains(key) && !j[key].is_null() ? std::optional(text(j[key])) : std::nullopt;
}

std::optional<protocol::Timestamp> optional_time(const nlohmann::json& j, const char* key) {
    return j.contains(key) && !j[key].is_null() ? std::optional(j[key].get<protocol::Timestamp>())
                                                : std::nullopt;
}

protocol::Membership membership_of(const nlohmann::json& j) {
    protocol::Membership m;
    if (j.contains("member")) {
        m.member = id_of(j["member"]);
    }
    m.kind = text(j["kind"]) == "person" ? protocol::MemberKind::person
                                         : protocol::MemberKind::organization;
    m.name = text(j["name"]);
    m.verified = j["verified"].get<bool>();
    m.registration = optional_text(j, "registration");
    m.jurisdiction = optional_text(j, "jurisdiction");
    m.until = optional_time(j, "until");
    return m;
}

std::string standing_key(protocol::Standing s) {
    return s == protocol::Standing::not_yet ? "not_yet" : std::string(protocol::standing_name(s));
}

} // namespace

TEST_CASE("v0.16 memberships: the six mechanism types, and metadata read and written",
          "[protocol][vectors][v016]") {
    const auto& types = vectors()["mechanism_types"];
    REQUIRE(protocol::builtin_record_types().size() == types.size());
    for (std::size_t i = 0; i < types.size(); ++i) {
        INFO(text(types[i]["type"]));
        const protocol::RecordType* type = protocol::find_record_type(text(types[i]["type"]));
        REQUIRE(type != nullptr);
        CHECK(type->initial_state == text(types[i]["initial"]));
        std::vector<std::pair<std::string, std::string>> transitions;
        for (const protocol::Transition& t : type->transitions) {
            transitions.emplace_back(t.from, t.to);
        }
        auto expected =
            types[i]["transitions"].get<std::vector<std::pair<std::string, std::string>>>();
        std::ranges::sort(transitions);
        std::ranges::sort(expected);
        CHECK(transitions == expected);
        CHECK(type->roles.empty());
    }
    CHECK(protocol::builtin_record_types().back().name == protocol::membership_type);

    for (const auto& c : vectors()["membership_metadata"]["valid"]) {
        INFO(text(c["name"]));
        const auto value = cbor::decode(hex(text(c["metadata"])));
        REQUIRE(value);
        const auto m = protocol::decode_membership(*value);
        INFO((m ? std::string() : std::string(m.error().detail)));
        REQUIRE(m);
        CHECK(*m == membership_of(c["membership"]));
        const auto again = protocol::encode_membership(*m);
        REQUIRE(again);
        CHECK(to_hex(*cbor::encode(*again)) == text(c["metadata"]));
    }
    for (const auto& c : vectors()["membership_metadata"]["refused"]) {
        INFO(text(c["name"]) + " (" + text(c["why"]) + ")");
        const auto value = cbor::decode(hex(text(c["metadata"])));
        CHECK_FALSE((value && protocol::decode_membership(*value)));
    }
}

TEST_CASE("v0.16 memberships: where one stood at a time", "[protocol][vectors][v016]") {
    for (const auto& h : vectors()["standings"]) {
        INFO(text(h["name"]));
        protocol::Membership m;
        m.until = optional_time(h, "until");
        std::vector<protocol::MembershipChange> changes;
        for (const auto& c : h["changes"]) {
            changes.push_back({c["at"].get<protocol::Timestamp>(), text(c["to"])});
        }
        for (const auto& c : h["cases"]) {
            const auto t = c["t"].get<protocol::Timestamp>();
            INFO(t);
            CHECK(
                standing_key(protocol::standing_at(m, h["registered_at"].get<protocol::Timestamp>(),
                                                   changes, t)) == text(c["standing"]));
        }
    }
}

TEST_CASE("v0.16 memberships: a trust node's log replayed, with every refusal in place",
          "[protocol][vectors][v016]") {
    for (const auto& ledger : vectors()["replay"]["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        std::vector<protocol::SignedStatement> statements;
        for (const auto& st : ledger["statements"]) {
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            statements.push_back(std::move(*parsed));
        }
        std::multimap<std::size_t, const nlohmann::json*> refused;
        for (const auto& st : ledger["refused"]) {
            refused.emplace(st["after"].get<std::size_t>(), &st);
        }
        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        std::size_t checked = 0;
        auto refusals = [&](std::size_t after) {
            const auto [first, last] = refused.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const nlohmann::json& r = *it->second;
                INFO(text(r["name"]) + " (" + text(r["why"]) + ")");
                auto parsed = protocol::parse_statement(provider(), hex(text(r["encoded"])), hash);
                if (parsed) {
                    CHECK_FALSE(
                        state->validate(provider(), *parsed, r["at"].get<protocol::Timestamp>()));
                }
                ++checked;
            }
        };
        for (std::size_t i = 1; i < statements.size(); ++i) {
            refusals(i);
            const auto& st = ledger["statements"][i];
            INFO(text(st["name"]));
            const auto at = st["registered_at"].get<protocol::Timestamp>();
            const auto valid = state->validate(provider(), statements[i], at);
            INFO((valid ? std::string() : std::string(valid.error().detail)));
            REQUIRE(valid);
            REQUIRE(state->apply(provider(), statements[i], i, at));
        }
        refusals(statements.size());
        CHECK(checked == ledger["refused"].size());

        for (const auto& expected : ledger["records"]) {
            INFO(text(expected["id"]));
            const protocol::RecordState* record = state->record(id_of(expected["id"]));
            REQUIRE(record != nullptr);
            CHECK(record->record_type == text(expected["type"]));
            CHECK(record->state == text(expected["state"]));
            CHECK(record->revoked == expected["revoked"].get<bool>());
            CHECK(record->history.to_vector() ==
                  expected["history"].get<std::vector<std::uint64_t>>());
        }
        for (const auto& m : ledger["memberships"]) {
            const protocol::RecordState* record = state->record(id_of(m));
            REQUIRE(record != nullptr);
            CHECK(record->record_type == protocol::membership_type);
        }
        const auto leaves = protocol::state_leaves(*state);
        REQUIRE(leaves.size() == ledger["state_leaves"].size());
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));
    }
}

TEST_CASE("v0.16 memberships: evidence that carries proofs, verified or refused",
          "[protocol][vectors][v016]") {
    for (const auto& c : vectors()["bundles"]["valid"]) {
        INFO(text(c["name"]));
        protocol::VerifyOptions options;
        options.expected_ledger = id_of(c["ledger"]);
        for (const auto& n : c["trust_nodes"]) {
            options.trust_nodes.push_back({id_of(n["ledger"]), text(n["name"])});
        }
        const auto report = protocol::verify_bundle(provider(), hex(text(c["bundle"])), options);
        INFO((report ? std::string() : std::string(report.error().detail)));
        REQUIRE(report);
        const auto& expected = c["memberships"];
        REQUIRE(report->memberships.size() == expected.size());
        for (std::size_t i = 0; i < expected.size(); ++i) {
            INFO(i);
            const auto& got = report->memberships[i];
            const auto& want = expected[i];
            CHECK(to_hex(got.trust_node.bytes()) == text(want["trust_node"]));
            CHECK(got.trusted == want["trusted"].get<bool>());
            CHECK(got.trust_node_name ==
                  (want["trust_node_name"].is_null() ? "" : text(want["trust_node_name"])));
            CHECK(to_hex(got.record.bytes()) == text(want["membership"]));
            protocol::Membership m = membership_of(want);
            m.member = report->ledger_id;
            CHECK(got.membership == m);
            CHECK(got.registered_at == want["registered_at"].get<protocol::Timestamp>());
            CHECK(got.record_time == want["record_time"].get<protocol::Timestamp>());
            CHECK(standing_key(got.at_record) == text(want["at_record"]));
            CHECK(got.checkpoint_time == want["checkpoint_time"].get<protocol::Timestamp>());
            CHECK(standing_key(got.at_checkpoint) == text(want["at_checkpoint"]));
        }
    }
    for (const auto& c : vectors()["bundles"]["refused"]) {
        INFO(text(c["name"]) + " (" + text(c["why"]) + ")");
        protocol::VerifyOptions options;
        options.expected_ledger = id_of(c["ledger"]);
        CHECK_FALSE(protocol::verify_bundle(provider(), hex(text(c["bundle"])), options));
    }
}
