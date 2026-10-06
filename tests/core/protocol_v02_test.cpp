// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The objects of specification revision v0.2, as built by an independent
// Python encoder (tools/testvectors/generate.py), must be read, checked, and
// reproduced byte for byte.

#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/core/protocol/witness.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace {

namespace crypto = cexchain::crypto;
namespace protocol = cexchain::protocol;
using cexchain::Bytes;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::load_vectors;

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

constexpr protocol::Timestamp t0 = 1'791'244'800'000;

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

} // namespace

TEST_CASE("v0.2 objects from an independent encoder", "[protocol][vectors]") {
    const auto document = load_vectors("protocol-v0.2.json");
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));

        // Every statement parses, has the expected id, and re-encodes exactly.
        std::vector<protocol::SignedStatement> statements;
        for (const auto& st : ledger["statements"]) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            CHECK(to_hex(parsed->id.bytes()) == text(st["statement_id"]));
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            statements.push_back(std::move(*parsed));
        }

        // Replayed under the rules, which verify the proof of presence and the
        // delegation's requirement for it.
        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        for (std::size_t i = 1; i < statements.size(); ++i) {
            INFO(text(ledger["statements"][i]["name"]));
            const auto at = t0 + 1000 + i;
            const auto valid = state->validate(provider(), statements[i], at);
            INFO((valid ? std::string() : std::string(valid.error().detail)));
            REQUIRE(valid);
            REQUIRE(state->apply(provider(), statements[i], i));
        }

        // Proof of presence.
        const auto& presence = ledger["presence"];
        const protocol::Statement& endorsement =
            statements[presence["statement_index"].get<std::size_t>()].statement;
        REQUIRE(endorsement.presence);
        CHECK(to_hex(*protocol::presence_challenge(provider(), hash, endorsement)) == text(presence["challenge"]));
        const auto credential = protocol::decode_presence_credential(hex(text(presence["credential"])));
        REQUIRE(credential);
        CHECK(*protocol::encode_presence_credential(*credential) == hex(text(presence["credential"])));
        const auto check = protocol::verify_presence(provider(), hash, endorsement, std::vector{*credential});
        REQUIRE(check);
        CHECK(check->user_verified);
        CHECK(check->origin == "http://localhost:43210");

        // The state commitment: the same root and the same proofs.
        const auto leaves = protocol::state_leaves(*state);
        REQUIRE(leaves.size() == ledger["state_proofs"].size());
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));
        for (const auto& expected : ledger["state_proofs"]) {
            const auto id = *protocol::to_id(hex(text(expected["id"])));
            const auto proof = protocol::prove_state(provider(), hash, leaves, id);
            REQUIRE(proof);
            CHECK(static_cast<int>(proof->leaf.kind) == expected["kind"].get<int>());
            CHECK(proof->leaf.history == expected["history"].get<std::vector<std::uint64_t>>());
            std::vector<std::string> siblings;
            for (const auto& s : proof->siblings) {
                siblings.push_back(to_hex(s.bytes()));
            }
            CHECK(siblings == expected["siblings"].get<std::vector<std::string>>());
            CHECK(protocol::verify_state_proof(provider(), hash, *proof, *root));
        }

        // A checkpoint carrying the state root.
        const auto checkpoint = protocol::parse_checkpoint(hex(text(ledger["checkpoint"])));
        REQUIRE(checkpoint);
        CHECK(protocol::verify_checkpoint(provider(), *checkpoint, state->log_key()));
        REQUIRE(checkpoint->checkpoint.state_root);
        CHECK(*checkpoint->checkpoint.state_root == *root);
        CHECK(*protocol::encode_checkpoint(checkpoint->checkpoint) == *checkpoint->envelope.payload);
        cexchain::merkle::Tree tree(provider(), hash);
        for (const auto& entry : ledger["log_entries"]) {
            REQUIRE(tree.append(hex(text(entry))));
        }
        CHECK(*tree.root() == checkpoint->checkpoint.root);

        // A cosign request, accepted by a witness that last cosigned size 4.
        const Bytes encoded_request = hex(text(ledger["cosign_request"]));
        const auto request = protocol::decode_cosign_request(encoded_request);
        REQUIRE(request);
        CHECK(*protocol::encode_cosign_request(*request) == encoded_request);
        const protocol::WitnessedLog witness{state->ledger_id(), state->log_key(), hash, 4, *tree.root(4)};
        CHECK(protocol::check_cosign_request(provider(), witness, *request));
    }
}
