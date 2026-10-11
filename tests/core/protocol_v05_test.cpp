// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.5 (ownership assets) against objects built by an independent
// Python encoder (tools/testvectors/generate.py).

#include <map>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/asset_evidence.hpp>
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = cexchain::protocol;
namespace crypto = cexchain::crypto;
namespace cbor = cexchain::cbor;
using cexchain::Bytes;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

constexpr protocol::Timestamp t0 = 1'791'244'800'000;

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

protocol::Id id(const nlohmann::json& value) {
    return *protocol::to_id(hex(text(value)));
}

} // namespace

TEST_CASE("v0.5 ownership assets from an independent encoder", "[protocol][vectors][assets]") {
    const auto document = load_vectors("protocol-v0.5.json");
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));

        std::vector<protocol::SignedStatement> statements;
        for (const auto& st : ledger["statements"]) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            CHECK(to_hex(parsed->id.bytes()) == text(st["statement_id"]));
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            statements.push_back(std::move(*parsed));
        }
        // Refused statements are well-formed; the rules refuse them at their
        // place in the log.
        std::multimap<std::size_t, protocol::SignedStatement> refused;
        for (const auto& st : ledger["refused"]) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            refused.emplace(st["after"].get<std::size_t>(), std::move(*parsed));
        }

        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        auto check_refused = [&](std::size_t after) {
            const auto [first, last] = refused.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const auto valid = state->validate(provider(), it->second, t0 + 1000 + after);
                INFO(protocol::name(it->second.statement.type()));
                CHECK_FALSE(valid);
            }
        };
        for (std::size_t i = 1; i < statements.size(); ++i) {
            check_refused(i);
            INFO(text(ledger["statements"][i]["name"]));
            const auto valid = state->validate(provider(), statements[i], t0 + 1000 + i);
            INFO((valid ? std::string() : std::string(valid.error().detail)));
            REQUIRE(valid);
            REQUIRE(state->apply(provider(), statements[i], i, t0 + 1000 + i));
        }
        check_refused(statements.size());

        // Every asset ends where the independent encoder says.
        for (const auto& expected : ledger["assets"]) {
            INFO(text(expected["name"]));
            const protocol::Id asset_id = id(expected["id"]);
            const protocol::RecordState* record = state->record(asset_id);
            const protocol::AssetState* asset = state->asset(asset_id);
            REQUIRE(record != nullptr);
            REQUIRE(asset != nullptr);
            CHECK(record->record_type == text(expected["type"]));
            CHECK(record->state == text(expected["state"]));
            CHECK(asset->holder == id(expected["holder"]));
            CHECK(asset->pledgee.has_value() == !expected["pledgee"].is_null());
            CHECK(asset->payee.has_value() == !expected["payee"].is_null());
            if (asset->payee) {
                CHECK(*asset->payee == id(expected["payee"]));
            }
            CHECK(asset->units == expected["quantity"].get<std::uint64_t>());
            CHECK(asset->head == expected["head"].get<std::uint64_t>());
        }

        // Consent metadata decodes, re-encodes byte for byte, and pins the
        // bundle by its hash under the home's hash.
        for (const auto& c : ledger["consents"]) {
            const Bytes metadata = hex(text(c["metadata"]));
            auto value = cbor::decode(metadata);
            REQUIRE(value);
            auto consent = protocol::decode_asset_consent(*value);
            REQUIRE(consent);
            CHECK(consent->terms.ledger == state->ledger_id());
            auto encoded = protocol::encode_asset_consent(*consent);
            REQUIRE(encoded);
            CHECK(*cbor::encode(*encoded) == metadata);
            CHECK(to_hex(provider().digest(hash, hex(text(c["bundle"])))->bytes()) ==
                  text(c["bundle_hash"]));
        }

        // Asset evidence round-trips; its bundles are the ones the
        // receivable's actions pin.
        const auto& e = ledger["asset_evidence"];
        const Bytes encoded = hex(text(e["encoded"]));
        auto evidence = protocol::decode_asset_evidence(encoded);
        REQUIRE(evidence);
        CHECK(*protocol::encode_asset_evidence(*evidence) == encoded);
        CHECK(evidence->asset_bundle == hex(text(e["asset_bundle"])));
        REQUIRE(evidence->consent_bundles.size() == e["pins"].size());
        for (std::size_t i = 0; i < evidence->consent_bundles.size(); ++i) {
            CHECK(to_hex(provider().digest(hash, evidence->consent_bundles[i])->bytes()) ==
                  text(e["pins"][i]));
        }
    }
}
