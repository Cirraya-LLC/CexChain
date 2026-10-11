// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.4 (key rotation) against objects built by an independent Python
// encoder (tools/testvectors/generate.py).

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/keys.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/core/protocol/witness.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = cexchain::protocol;
namespace crypto = cexchain::crypto;
namespace merkle = cexchain::merkle;
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

crypto::PublicKey ed25519(const nlohmann::json& key) {
    return {crypto::SigAlg::ed25519, hex(text(key))};
}

} // namespace

TEST_CASE("v0.4 key rotation from an independent encoder", "[protocol][vectors][rotation]") {
    const auto document = load_vectors("protocol-v0.4.json");
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
        CHECK(statements[2].statement.type() == protocol::StatementType::ledger_rotate_log_key);

        // Replayed under the rules: both rotations, then a statement that only
        // the new root key may sign.
        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        for (std::size_t i = 1; i < statements.size(); ++i) {
            INFO(text(ledger["statements"][i]["name"]));
            const auto valid = state->validate(provider(), statements[i], t0 + 1000 + i);
            INFO((valid ? std::string() : std::string(valid.error().detail)));
            REQUIRE(valid);
            REQUIRE(state->apply(provider(), statements[i], i, t0 + 1000 + i));
        }
        std::vector<protocol::KeyEpoch> log_keys;
        for (const auto& k : ledger["log_keys"]) {
            log_keys.push_back({k["index"].get<std::uint64_t>(), ed25519(k["key"])});
        }
        std::vector<protocol::KeyEpoch> root_keys;
        for (const auto& k : ledger["root_keys"]) {
            root_keys.push_back({k["index"].get<std::uint64_t>(), ed25519(k["key"])});
        }
        CHECK(std::ranges::equal(state->log_keys(), log_keys));
        CHECK(std::ranges::equal(state->root_keys(), root_keys));

        // The same state root and proofs (the organization's leaf lists both
        // rotations).
        const auto leaves = protocol::state_leaves(*state);
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));
        for (const auto& expected : ledger["state_proofs"]) {
            const auto proof = protocol::prove_state(provider(), hash, leaves,
                                                     *protocol::to_id(hex(text(expected["id"]))));
            REQUIRE(proof);
            CHECK(proof->leaf.history == expected["history"].get<std::vector<std::uint64_t>>());
        }

        // The commitment is the new log key's.
        const auto& c = ledger["state_commitment"];
        const auto commitment =
            protocol::parse_state_commitment(provider(), hex(text(c["encoded"])));
        REQUIRE(commitment);
        CHECK(to_hex(commitment->id.bytes()) == text(c["id"]));
        CHECK(protocol::check_state_commitment(provider(), *state, *commitment,
                                               c["index"].get<std::uint64_t>(), *root));

        // The log, its checkpoints, each under the key in effect at its size.
        merkle::Tree tree(provider(), hash);
        for (const auto& entry : ledger["log_entries"]) {
            REQUIRE(tree.append(hex(text(entry))));
        }
        const auto before = protocol::parse_checkpoint(hex(text(ledger["checkpoint_before"])));
        const auto after = protocol::parse_checkpoint(hex(text(ledger["checkpoint"])));
        REQUIRE(before);
        REQUIRE(after);
        CHECK(*tree.root(before->checkpoint.tree_size) == before->checkpoint.root);
        CHECK(*tree.root() == after->checkpoint.root);
        CHECK(protocol::verify_checkpoint(provider(), *before,
                                          state->log_key_for(before->checkpoint.tree_size)));
        CHECK(protocol::verify_checkpoint(provider(), *after,
                                          state->log_key_for(after->checkpoint.tree_size)));
        CHECK(state->log_key_for(before->checkpoint.tree_size) == log_keys.front().key);
        CHECK_FALSE(protocol::verify_checkpoint(provider(), *after, log_keys.front().key));

        // The cosign request round-trips, and a witness that cosigned size 2
        // from the genesis keys follows both rotations to cosign it.
        const Bytes encoded = hex(text(ledger["cosign_request"]["encoded"]));
        const auto request = protocol::decode_cosign_request(encoded);
        REQUIRE(request);
        CHECK(*protocol::encode_cosign_request(*request) == encoded);
        REQUIRE(request->rotations.size() == 2);
        const auto keys =
            protocol::keys_from_genesis(provider(), hex(text(ledger["log_entries"][0])));
        REQUIRE(keys);
        protocol::WitnessedLog witness;
        witness.ledger_id = keys->ledger_id;
        witness.log_key = keys->log_key();
        witness.root_key = keys->root_key;
        witness.tree_hash = hash;
        witness.size = ledger["cosign_request"]["old_size"].get<std::uint64_t>();
        witness.root = *crypto::Digest::from_bytes(hex(text(ledger["cosign_request"]["old_root"])));
        const auto approved = protocol::check_cosign_request(provider(), witness, *request);
        INFO((approved ? std::string() : std::string(approved.error().detail)));
        REQUIRE(approved);
        CHECK(approved->log.log_key == log_keys.back().key);
        CHECK(approved->log.root_key == root_keys.back().key);
        CHECK(approved->log.last_rotation == root_keys.back().index);
        CHECK(approved->log.size == after->checkpoint.tree_size);
    }
}
