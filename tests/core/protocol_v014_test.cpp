// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.14 (claims) against objects built by an independent Python
// encoder (tools/testvectors/generate.py): the fifth mechanism type, claim
// metadata read, encoded byte for byte, and put in words, the refused
// shapes, and a log replayed under the rules with every refusal in place,
// to the state the independent encoder computed.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/claims.hpp>
#include <cexchain/core/protocol/record_types.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = cexchain::protocol;
namespace crypto = cexchain::crypto;
namespace cbor = cexchain::cbor;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.14.json");
    return document;
}

crypto::HashAlg ledger_hash(const nlohmann::json& ledger) {
    return *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
}

} // namespace

TEST_CASE("v0.14 claims: the type, and metadata read, written, and worded",
          "[protocol][vectors][v014]") {
    const protocol::RecordType* type = protocol::find_record_type(protocol::claim_type);
    REQUIRE(type != nullptr);
    CHECK(type->initial_state == text(vectors()["claim_type"]["initial"]));
    CHECK(type->transitions.empty());
    CHECK(type->roles.empty());
    REQUIRE(protocol::builtin_record_types().size() == vectors()["mechanism_types"].size());

    for (const auto& c : vectors()["claim_metadata"]["valid"]) {
        INFO(text(c["name"]));
        const auto bytes = hex(text(c["metadata"]));
        const auto value = cbor::decode(bytes);
        REQUIRE(value);
        const auto claim = protocol::decode_claim(*value);
        INFO((claim ? std::string() : std::string(claim.error().detail)));
        REQUIRE(claim);
        const auto again = protocol::encode_claim(*claim);
        REQUIRE(again);
        CHECK(to_hex(*cbor::encode(*again)) == text(c["metadata"]));
        CHECK(protocol::claim_text(*claim) == text(c["text"]));
    }
    for (const auto& c : vectors()["claim_metadata"]["refused"]) {
        INFO(text(c["name"]) + " (" + text(c["why"]) + ")");
        const auto value = cbor::decode(hex(text(c["metadata"])));
        CHECK((!value || !protocol::decode_claim(*value)));
    }
}

TEST_CASE("v0.14 claims: replay, with every refusal in place", "[protocol][vectors][v014]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const auto hash = ledger_hash(ledger);
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
                if (!parsed) {
                    ++checked; // refused as malformed
                    continue;
                }
                CHECK_FALSE(
                    state->validate(provider(), *parsed, r["at"].get<protocol::Timestamp>()));
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
            const protocol::RecordState* record =
                state->record(*protocol::to_id(hex(text(expected["id"]))));
            REQUIRE(record != nullptr);
            CHECK(record->record_type == text(expected["type"]));
            CHECK(record->state == text(expected["state"]));
            CHECK(record->revoked == expected["revoked"].get<bool>());
            CHECK(record->history.to_vector() ==
                  expected["history"].get<std::vector<std::uint64_t>>());
        }
        for (const auto& claim : ledger["claims"]) {
            const protocol::RecordState* record =
                state->record(*protocol::to_id(hex(text(claim.is_string() ? claim : claim["id"]))));
            REQUIRE(record != nullptr);
            CHECK(record->record_type == protocol::claim_type);
        }

        const auto leaves = protocol::state_leaves(*state);
        REQUIRE(leaves.size() == ledger["state_leaves"].size());
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));
    }
}
