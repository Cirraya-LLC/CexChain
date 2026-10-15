// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.9 (the generic core) against objects built by an independent
// Python encoder (tools/testvectors/generate.py).
//
// The first case checks the objects one by one: statements, the state tree,
// the log, the state commitment, and the checkpoint. The second replays the
// log under the rules, with every refusal of the generic lifecycle and of the
// mechanism types in place. The third covers what v0.9 removed: statement
// type 20, and the record types under the reserved "cexchain." prefix.

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
#include <cexchain/core/protocol/record_types.hpp>
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
    static const nlohmann::json document = load_vectors("protocol-v0.9.json");
    return document;
}

crypto::HashAlg ledger_hash(const nlohmann::json& ledger) {
    return *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
}

/// Words of the detail core gives for each rule the vectors name.
std::string refusal_words(const std::string& why) {
    static const std::map<std::string, std::string> words{
        {"transition", "does not allow this transition"},
        {"state", "not in the stated state"},
        {"role", "role is not defined"},
        {"repeated", "already endorsed"},
        {"revoked", "has been revoked"},
        {"reserved type", "reserved"},
        {"unknown type", "unknown statement type"},
    };
    return words.at(why);
}

/// Refusals for what v0.9 removed, which the third case checks.
bool removed_in_v09(const std::string& why) {
    return why == "reserved type" || why == "unknown type";
}

struct Refusal {
    std::string name;
    protocol::SignedStatement statement;
    protocol::Timestamp at = 0;
    std::string why;
};

/// Replays the ledger's statements at their registration times, calling
/// `refusals` with the state after each prefix of the log (from genesis on)
/// and the number of statements in it. Returns the final state.
template <typename Check>
protocol::LedgerState replay(const nlohmann::json& ledger, Check&& refusals) {
    const auto hash = ledger_hash(ledger);
    std::vector<protocol::SignedStatement> statements;
    for (const auto& st : ledger["statements"]) {
        auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
        REQUIRE(parsed);
        statements.push_back(std::move(*parsed));
    }
    auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
    REQUIRE(state);
    for (std::size_t i = 1; i < statements.size(); ++i) {
        refusals(*state, i);
        const auto& st = ledger["statements"][i];
        INFO(text(st["name"]));
        const auto at = st["registered_at"].get<protocol::Timestamp>();
        const auto valid = state->validate(provider(), statements[i], at);
        INFO((valid ? std::string() : std::string(valid.error().detail)));
        REQUIRE(valid);
        REQUIRE(state->apply(provider(), statements[i], i, at));
    }
    refusals(*state, statements.size());
    return std::move(*state);
}

/// The refusals that parse, by the number of statements before them.
std::multimap<std::size_t, Refusal> parsed_refusals(const nlohmann::json& ledger) {
    std::multimap<std::size_t, Refusal> out;
    for (const auto& st : ledger["refused"]) {
        if (st["malformed"].get<bool>()) {
            continue;
        }
        INFO(text(st["name"]));
        auto parsed =
            protocol::parse_statement(provider(), hex(text(st["encoded"])), ledger_hash(ledger));
        REQUIRE(parsed);
        out.emplace(st["after"].get<std::size_t>(),
                    Refusal{text(st["name"]), std::move(*parsed),
                            st["at"].get<protocol::Timestamp>(), text(st["why"])});
    }
    return out;
}

} // namespace

TEST_CASE("v0.9 generic core: statements, the state, and the log", "[protocol][vectors][v09]") {
    // The mechanism types keep their lifecycles, and take no endorsement.
    for (const auto& expected : vectors()["mechanism_types"]) {
        INFO(text(expected["type"]));
        const protocol::RecordType* type = protocol::find_record_type(text(expected["type"]));
        REQUIRE(type != nullptr);
        CHECK(type->initial_state == text(expected["initial"]));
        CHECK(type->roles.empty());
        CHECK(type->transitions.size() == expected["transitions"].size());
        for (const auto& t : expected["transitions"]) {
            CHECK(type->allows(text(t[0]), text(t[1])));
        }
    }
    // A user's types have the generic lifecycle.
    CHECK(protocol::find_record_type("example.document/1") == nullptr);
    CHECK(protocol::find_record_type("cexchain-example.note/1") == nullptr);

    for (const auto& ledger : vectors()["ledgers"]) {
        const auto hash = ledger_hash(ledger);
        INFO(crypto::name(hash));

        // Every statement parses and encodes back, refused ones too, except
        // those that break the CDDL (the third case).
        auto check_statement = [&](const nlohmann::json& st) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            if (st.contains("statement_id")) {
                CHECK(to_hex(parsed->id.bytes()) == text(st["statement_id"]));
            }
        };
        for (const auto& st : ledger["statements"]) {
            check_statement(st);
        }
        for (const auto& st : ledger["refused"]) {
            if (!st["malformed"].get<bool>()) {
                check_statement(st);
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

        // The log: each entry with its statement and registration time, then
        // the state commitment; the checkpoint covers it all.
        auto genesis = protocol::parse_statement(
            provider(), hex(text(ledger["statements"][0]["encoded"])), hash);
        REQUIRE(genesis);
        CHECK(to_hex(genesis->id.bytes()) == text(ledger["ledger_id"]));
        auto state = protocol::LedgerState::from_genesis(provider(), *genesis);
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
                CHECK(to_hex(entry->statement) == text(st["encoded"]));
            }
            REQUIRE(tree.append(encoded));
        }
        const auto logged =
            protocol::decode_log_entry(hex(text(entries[commitment_index])))->state_commitment;
        const auto commitment = protocol::parse_state_commitment(provider(), logged);
        REQUIRE(commitment);
        CHECK(to_hex(commitment->id.bytes()) == text(ledger["state_commitment"]["id"]));
        CHECK(commitment->commitment.state_root == *root);
        CHECK(commitment->commitment.tree_size == commitment_index);
        CHECK(protocol::verify_state_commitment(provider(), *commitment, state->log_key()));
        const auto checkpoint = protocol::parse_checkpoint(hex(text(ledger["checkpoint"])));
        REQUIRE(checkpoint);
        CHECK(protocol::verify_checkpoint(provider(), *checkpoint, state->log_key()));
        CHECK(checkpoint->checkpoint.tree_size == entries.size());
        CHECK(checkpoint->checkpoint.timestamp ==
              ledger["checkpoint_time"].get<protocol::Timestamp>());
        CHECK(*tree.root() == checkpoint->checkpoint.root);
    }
}

TEST_CASE("v0.9 generic core: replay, and the lifecycles' refusals in place",
          "[protocol][vectors][v09]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const auto hash = ledger_hash(ledger);
        INFO(crypto::name(hash));
        const auto refused = parsed_refusals(ledger);
        std::size_t checked = 0;
        std::size_t lifecycle = 0;
        const protocol::LedgerState state =
            replay(ledger, [&](const protocol::LedgerState& now, std::size_t after) {
                const auto [first, last] = refused.equal_range(after);
                for (auto it = first; it != last; ++it) {
                    const Refusal& r = it->second;
                    ++checked;
                    if (removed_in_v09(r.why)) {
                        continue;
                    }
                    ++lifecycle;
                    INFO(r.name);
                    const auto valid = now.validate(provider(), r.statement, r.at);
                    REQUIRE_FALSE(valid);
                    INFO(std::string(valid.error().detail));
                    CHECK(std::string(valid.error().detail).find(refusal_words(r.why)) !=
                          std::string::npos);
                }
            });
        CHECK(checked == refused.size());
        CHECK(lifecycle == 8);

        // Records end where the independent encoder says: a user's type with
        // endorsements in any role, the mechanism types through their
        // lifecycles.
        CHECK(state.records().size() == ledger["records"].size());
        for (const auto& expected : ledger["records"]) {
            INFO(text(expected["id"]));
            const protocol::RecordState* record = state.record(id(expected["id"]));
            REQUIRE(record != nullptr);
            CHECK(record->record_type == text(expected["type"]));
            CHECK(record->state == text(expected["state"]));
            CHECK(record->revoked == expected["revoked"].get<bool>());
            CHECK(to_hex(record->registrant.bytes()) == text(expected["registrant"]));
            CHECK(record->history.to_vector() ==
                  expected["history"].get<std::vector<std::uint64_t>>());
            REQUIRE(record->endorsements.size() == expected["endorsements"].size());
            for (std::size_t i = 0; i < record->endorsements.size(); ++i) {
                const auto& e = expected["endorsements"][i];
                CHECK(record->endorsements[i].role == text(e["role"]));
                CHECK(to_hex(record->endorsements[i].actor.bytes()) == text(e["actor"]));
                CHECK(record->endorsements[i].index == e["index"].get<std::uint64_t>());
            }
        }

        // The replayed state has the leaves, and the root, the log commits to.
        const auto leaves = protocol::state_leaves(state);
        REQUIRE(leaves.size() == ledger["state_leaves"].size());
        for (std::size_t i = 0; i < leaves.size(); ++i) {
            const auto& expected = ledger["state_leaves"][i];
            CHECK(static_cast<int>(leaves[i].kind) == expected["kind"].get<int>());
            CHECK(to_hex(leaves[i].id.bytes()) == text(expected["id"]));
            CHECK(leaves[i].history == expected["history"].get<std::vector<std::uint64_t>>());
        }
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));
    }
}

TEST_CASE("v0.9 generic core: statement type 20 and the reserved prefix",
          "[protocol][vectors][v09]") {
    // The removed types are no longer built in; only the four mechanism
    // types are, and only types under the prefix that are not one of them
    // are reserved.
    for (const auto& removed : vectors()["removed_types"]) {
        INFO(text(removed));
        CHECK(protocol::find_record_type(text(removed)) == nullptr);
        CHECK(protocol::is_reserved_record_type(text(removed)));
    }
    // Each mechanism type with its lifecycle, as the independent encoder
    // states it; none takes endorsements.
    REQUIRE(protocol::builtin_record_types().size() == vectors()["mechanism_types"].size());
    for (const auto& mechanism : vectors()["mechanism_types"]) {
        const std::string name = text(mechanism["type"]);
        INFO(name);
        const protocol::RecordType* type = protocol::find_record_type(name);
        REQUIRE(type != nullptr);
        CHECK_FALSE(protocol::is_reserved_record_type(name));
        CHECK(type->initial_state == text(mechanism["initial"]));
        std::vector<std::pair<std::string, std::string>> transitions;
        for (const protocol::Transition& t : type->transitions) {
            transitions.emplace_back(t.from, t.to);
        }
        CHECK(transitions ==
              mechanism["transitions"].get<std::vector<std::pair<std::string, std::string>>>());
        CHECK(type->roles.empty());
    }
    CHECK(text(vectors()["generic_lifecycle"]["initial"]) == protocol::generic_initial_state);
    CHECK(text(vectors()["reserved_prefix"]) == protocol::reserved_type_prefix);

    for (const auto& ledger : vectors()["ledgers"]) {
        const auto hash = ledger_hash(ledger);
        INFO(crypto::name(hash));

        // Statement type 20, and a scope that names it, break the CDDL.
        std::size_t malformed = 0;
        for (const auto& st : ledger["refused"]) {
            if (!st["malformed"].get<bool>()) {
                continue;
            }
            ++malformed;
            INFO(text(st["name"]));
            CHECK(text(st["why"]) == "unknown type");
            const auto parsed =
                protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            const auto decoded = protocol::decode_payload(hex(text(st["payload"])));
            REQUIRE_FALSE(parsed);
            REQUIRE_FALSE(decoded);
            CHECK(std::string(parsed.error().detail).find(refusal_words("unknown type")) !=
                  std::string::npos);
            CHECK(std::string(decoded.error().detail).find(refusal_words("unknown type")) !=
                  std::string::npos);
        }
        CHECK(malformed == 3);

        // Registrations under the reserved prefix are refused at their place
        // in the log.
        const auto refused = parsed_refusals(ledger);
        std::size_t reserved = 0;
        static_cast<void>(replay(ledger, [&](const protocol::LedgerState& now, std::size_t after) {
            const auto [first, last] = refused.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const Refusal& r = it->second;
                if (r.why != "reserved type") {
                    continue;
                }
                ++reserved;
                INFO(r.name);
                const auto valid = now.validate(provider(), r.statement, r.at);
                REQUIRE_FALSE(valid);
                INFO(std::string(valid.error().detail));
                CHECK(std::string(valid.error().detail).find(refusal_words(r.why)) !=
                      std::string::npos);
            }
        }));
        CHECK(reserved == 8);
    }
}
