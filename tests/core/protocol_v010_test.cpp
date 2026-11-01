// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.10 (versions) against objects built by an independent Python
// encoder (tools/testvectors/generate.py).
//
// The first case checks the objects one by one: statements, the state tree,
// the log, the state commitment, and the checkpoint. The second replays the
// log under the rules, with every refusal in place, and checks the chain of
// versions and both histories of each superseding registration. The third
// checks that a bundle's replay, which may lack the superseded record, takes
// the registration that names it, and that a ledger's does not.

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = cexchain::protocol;
namespace crypto = cexchain::crypto;
using cexchain::Bytes;
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

protocol::Id id(const nlohmann::json& value) {
    return *protocol::to_id(hex(text(value)));
}

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.10.json");
    return document;
}

crypto::HashAlg ledger_hash(const nlohmann::json& ledger) {
    return *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
}

/// Words of the detail core gives for each rule the vectors name.
std::string refusal_words(const std::string& why) {
    static const std::map<std::string, std::string> words{
        {"superseded", "superseded already"},
        {"scope", "type of the record it supersedes"},
        {"no such record", "does not exist"},
        {"mechanism", "mechanism type"},
    };
    return words.at(why);
}

std::vector<protocol::SignedStatement> statements_of(const nlohmann::json& ledger) {
    std::vector<protocol::SignedStatement> out;
    for (const auto& st : ledger["statements"]) {
        auto parsed =
            protocol::parse_statement(provider(), hex(text(st["encoded"])), ledger_hash(ledger));
        REQUIRE(parsed);
        out.push_back(std::move(*parsed));
    }
    return out;
}

} // namespace

TEST_CASE("v0.10 versions: statements, the state, and the log", "[protocol][vectors][v010]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const auto hash = ledger_hash(ledger);
        INFO(crypto::name(hash));

        // Every statement parses and encodes back, refused ones too, except
        // the one that breaks the CDDL.
        auto check_statement = [&](const nlohmann::json& st) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            if (st.contains("statement_id")) {
                CHECK(to_hex(parsed->id.bytes()) == text(st["statement_id"]));
            }
        };
        std::size_t malformed = 0;
        for (const auto& st : ledger["statements"]) {
            check_statement(st);
        }
        for (const auto& st : ledger["refused"]) {
            if (!st["malformed"].get<bool>()) {
                check_statement(st);
                continue;
            }
            ++malformed;
            INFO(text(st["name"]));
            CHECK_FALSE(protocol::parse_statement(provider(), hex(text(st["encoded"])), hash));
            CHECK_FALSE(protocol::decode_payload(hex(text(st["payload"]))));
        }
        CHECK(malformed == 1);

        // Key 6 names the version before, oldest first.
        const auto statements = statements_of(ledger);
        const auto& versions = ledger["versions"];
        REQUIRE(versions.size() == 5);
        for (std::size_t v = 0; v < versions.size(); ++v) {
            const auto found = std::ranges::find_if(statements, [&](const auto& s) {
                return to_hex(s.id.bytes()) == text(versions[v]);
            });
            REQUIRE(found != statements.end());
            const auto& body = std::get<protocol::RecordRegisterBody>(found->statement.body);
            if (v == 0) {
                CHECK_FALSE(body.supersedes);
            } else {
                REQUIRE(body.supersedes);
                CHECK(to_hex(body.supersedes->bytes()) == text(versions[v - 1]));
            }
        }

        // The state tree over every object has the root the logged state
        // commitment signs.
        std::vector<protocol::StateLeaf> leaves;
        for (const auto& leaf : ledger["state_leaves"]) {
            leaves.push_back({static_cast<protocol::ObjectKind>(leaf["kind"].get<int>()),
                              id(leaf["id"]), leaf["history"].get<std::vector<std::uint64_t>>()});
        }
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));

        // The log, then the state commitment; the checkpoint covers it all.
        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        const auto& entries = ledger["log_entries"];
        const auto commitment_index = ledger["state_commitment"]["index"].get<std::size_t>();
        REQUIRE(commitment_index + 1 == entries.size());
        REQUIRE(commitment_index == ledger["statements"].size());
        cexchain::merkle::Tree tree(provider(), hash);
        for (std::size_t i = 0; i < entries.size(); ++i) {
            const Bytes encoded = hex(text(entries[i]));
            const auto entry = protocol::decode_log_entry(encoded);
            REQUIRE(entry);
            CHECK(*protocol::encode_log_entry(*entry) == encoded);
            if (i < commitment_index) {
                const auto& st = ledger["statements"][i];
                CHECK(to_hex(entry->statement_id.bytes()) == text(st["statement_id"]));
                CHECK(entry->registered_at == st["registered_at"].get<protocol::Timestamp>());
            }
            REQUIRE(tree.append(encoded));
        }
        const auto logged =
            protocol::decode_log_entry(hex(text(entries[commitment_index])))->state_commitment;
        const auto commitment = protocol::parse_state_commitment(provider(), logged);
        REQUIRE(commitment);
        CHECK(to_hex(commitment->id.bytes()) == text(ledger["state_commitment"]["id"]));
        CHECK(commitment->commitment.state_root == *root);
        CHECK(protocol::verify_state_commitment(provider(), *commitment, state->log_key()));
        const auto checkpoint = protocol::parse_checkpoint(hex(text(ledger["checkpoint"])));
        REQUIRE(checkpoint);
        CHECK(protocol::verify_checkpoint(provider(), *checkpoint, state->log_key()));
        CHECK(checkpoint->checkpoint.tree_size == entries.size());
        CHECK(*tree.root() == checkpoint->checkpoint.root);
    }
}

TEST_CASE("v0.10 versions: replay, the chain, and the refusals in place",
          "[protocol][vectors][v010]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const auto hash = ledger_hash(ledger);
        INFO(crypto::name(hash));
        const auto statements = statements_of(ledger);
        std::multimap<std::size_t, const nlohmann::json*> refused;
        for (const auto& st : ledger["refused"]) {
            if (!st["malformed"].get<bool>()) {
                refused.emplace(st["after"].get<std::size_t>(), &st);
            }
        }
        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        std::size_t checked = 0;
        auto refusals = [&](std::size_t after) {
            const auto [first, last] = refused.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const nlohmann::json& r = *it->second;
                INFO(text(r["name"]));
                auto parsed = protocol::parse_statement(provider(), hex(text(r["encoded"])), hash);
                REQUIRE(parsed);
                const auto valid =
                    state->validate(provider(), *parsed, r["at"].get<protocol::Timestamp>());
                REQUIRE_FALSE(valid);
                INFO(std::string(valid.error().detail));
                CHECK(std::string(valid.error().detail).find(refusal_words(text(r["why"]))) !=
                      std::string::npos);
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
        CHECK(checked == 6);

        // Records end where the independent encoder says, with their links.
        CHECK(state->records().size() == ledger["records"].size());
        for (const auto& expected : ledger["records"]) {
            INFO(text(expected["id"]));
            const protocol::RecordState* record = state->record(id(expected["id"]));
            REQUIRE(record != nullptr);
            CHECK(record->record_type == text(expected["type"]));
            CHECK(record->state == text(expected["state"]));
            CHECK(record->revoked == expected["revoked"].get<bool>());
            CHECK(record->history.to_vector() ==
                  expected["history"].get<std::vector<std::uint64_t>>());
            CHECK(record->endorsements.size() == expected["endorsements"].size());
            CHECK(record->supersedes.has_value() == !expected["supersedes"].is_null());
            if (record->supersedes) {
                CHECK(to_hex(record->supersedes->bytes()) == text(expected["supersedes"]));
            }
            CHECK(record->superseded_by.has_value() == !expected["superseded_by"].is_null());
            if (record->superseded_by) {
                CHECK(to_hex(record->superseded_by->bytes()) == text(expected["superseded_by"]));
                // The superseding registration is the last of its history
                // here, at its log index.
                CHECK(std::ranges::contains(record->history.to_vector(),
                                            record->superseded_at_index));
                CHECK(to_hex(statements[record->superseded_at_index].id.bytes()) ==
                      text(expected["superseded_by"]));
            }
        }

        // The replayed state has the leaves, and the root, the log commits to.
        const auto leaves = protocol::state_leaves(*state);
        REQUIRE(leaves.size() == ledger["state_leaves"].size());
        for (std::size_t i = 0; i < leaves.size(); ++i) {
            const auto& expected = ledger["state_leaves"][i];
            CHECK(to_hex(leaves[i].id.bytes()) == text(expected["id"]));
            CHECK(leaves[i].history == expected["history"].get<std::vector<std::uint64_t>>());
        }
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));
    }
}

TEST_CASE("v0.10 versions: a bundle's replay may lack the superseded record",
          "[protocol][vectors][v010]") {
    const auto& ledger = vectors()["ledgers"][0];
    const auto statements = statements_of(ledger);
    // The statements up to and with version 1, then version 2's
    // registration without version 1's: as a bundle about version 2 holds
    // them (its signer's registration and delegation, not version 1).
    const auto& versions = ledger["versions"];
    std::size_t v1 = 0;
    std::size_t v2 = 0;
    for (std::size_t i = 0; i < statements.size(); ++i) {
        if (to_hex(statements[i].id.bytes()) == text(versions[0])) {
            v1 = i;
        } else if (to_hex(statements[i].id.bytes()) == text(versions[1])) {
            v2 = i;
        }
    }
    REQUIRE(v1 > 0);
    REQUIRE(v2 == v1 + 1);
    auto build = [&](bool bundle) {
        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        if (bundle) {
            state->replay_bundle();
        }
        for (std::size_t i = 1; i < v1; ++i) {
            const auto at = ledger["statements"][i]["registered_at"].get<protocol::Timestamp>();
            REQUIRE(state->validate(provider(), statements[i], at));
            REQUIRE(state->apply(provider(), statements[i], i, at));
        }
        return std::move(*state);
    };
    const auto at = ledger["statements"][v2]["registered_at"].get<protocol::Timestamp>();

    // A ledger refuses a registration that names a record it does not have.
    protocol::LedgerState full = build(false);
    const auto refused = full.validate(provider(), statements[v2], at);
    REQUIRE_FALSE(refused);
    CHECK(std::string(refused.error().detail).find("does not exist") != std::string::npos);

    // A bundle's replay takes it, and links only the record it holds.
    protocol::LedgerState partial = build(true);
    REQUIRE(partial.validate(provider(), statements[v2], at));
    REQUIRE(partial.apply(provider(), statements[v2], v2, at));
    const protocol::RecordState* record = partial.record(statements[v2].id);
    REQUIRE(record != nullptr);
    REQUIRE(record->supersedes);
    CHECK(to_hex(record->supersedes->bytes()) == text(versions[0]));
    CHECK(record->history.to_vector() == std::vector<std::uint64_t>{v2});
    CHECK(partial.record(id(versions[0])) == nullptr);
}
