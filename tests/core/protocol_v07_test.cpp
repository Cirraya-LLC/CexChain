// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.7 (instances created by a call) against objects built by an
// independent Python encoder and run by the reference interpreter
// (tools/testvectors/).
//
// Core does not create children yet (milestone M15 of the Bo compiler plan):
// this file checks everything the code of v0.6 can check, which is most of
// the vectors' bytes, and leaves the replay of children to M15 (the last test
// case below).

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = cexchain::protocol;
namespace crypto = cexchain::crypto;
namespace cbor = cexchain::cbor;
namespace vm = cexchain::vm;
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

} // namespace

TEST_CASE("v0.7 children: statements, runs, ids, the state, and the log",
          "[protocol][vectors][contracts][children]") {
    const auto document = load_vectors("protocol-v0.7.json");
    std::map<std::string, vm::Module> modules;
    for (const auto& [name, code] : document["contracts"].items()) {
        auto module = vm::load(hex(text(code)));
        REQUIRE(module);
        modules.emplace(name, std::move(*module));
    }
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));

        // Every statement parses and re-encodes; the refused ones parse
        // unless they break the CDDL. (Replaying them under the rules of v0.7
        // is M15's.)
        std::vector<protocol::SignedStatement> statements;
        for (const auto& st : ledger["statements"]) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            CHECK(to_hex(parsed->id.bytes()) == text(st["statement_id"]));
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            statements.push_back(std::move(*parsed));
        }
        for (const auto& st : ledger["refused"]) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            if (st["malformed"].get<bool>()) {
                CHECK_FALSE(parsed);
                continue;
            }
            REQUIRE(parsed);
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
        }

        // The deploys carry the two contracts, and every run, the inputs of
        // calls on children included, gives the same outcome, output, and
        // fuel here as in the reference interpreter.
        std::map<std::string, std::string> contract_names;
        for (const auto& st : statements) {
            if (const auto* deploy =
                    std::get_if<protocol::ContractDeployBody>(&st.statement.body)) {
                for (const auto& [name, code] : document["contracts"].items()) {
                    if (to_hex(deploy->code) == text(code)) {
                        contract_names.emplace(to_hex(st.id.bytes()), name);
                    }
                }
            }
        }
        REQUIRE(contract_names.size() == 2);
        for (const auto& run : ledger["runs"]) {
            INFO(text(run["name"]));
            const auto outcome = vm::run(modules.at(contract_names.at(text(run["contract"]))),
                                         hex(text(run["input"])), provider(), hash);
            REQUIRE(outcome);
            CHECK((outcome->trap ? std::string(vm::name(*outcome->trap)) : std::string("ok")) ==
                  text(run["outcome"]));
            CHECK(to_hex(outcome->output) == text(run["output"]));
            CHECK(outcome->fuel_used == run["fuel"].get<std::uint64_t>());
        }

        // A child's id is HASH([call, position]).
        for (const auto& child : ledger["children"]) {
            const auto encoded = cbor::encode(cbor::Value::array(
                {cbor::Value::bytes(hex(text(child["call"]))),
                 cbor::Value::unsigned_integer(child["position"].get<std::uint64_t>())}));
            REQUIRE(encoded);
            CHECK(to_hex(provider().digest(hash, *encoded)->bytes()) == text(child["id"]));
        }

        // The state tree over every object, children included, has the root
        // the logged state commitment signs, and the checkpoint covers the
        // whole log.
        std::vector<protocol::StateLeaf> leaves;
        for (const auto& leaf : ledger["state_leaves"]) {
            leaves.push_back({static_cast<protocol::ObjectKind>(leaf["kind"].get<int>()),
                              id(leaf["id"]), leaf["history"].get<std::vector<std::uint64_t>>()});
        }
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));
        for (const auto& instance : ledger["instances"]) {
            const auto proof = protocol::prove_state(provider(), hash, leaves, id(instance["id"]));
            REQUIRE(proof);
            CHECK(proof->leaf.kind == protocol::ObjectKind::instance);
            CHECK(proof->leaf.history == instance["history"].get<std::vector<std::uint64_t>>());
            CHECK(proof->leaf.history.back() == instance["head"].get<std::uint64_t>());
        }

        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        const auto& entries = ledger["log_entries"];
        const auto commitment_index = ledger["state_commitment"]["index"].get<std::size_t>();
        REQUIRE(commitment_index + 1 == entries.size());
        cexchain::merkle::Tree tree(provider(), hash);
        for (std::size_t i = 0; i < entries.size(); ++i) {
            const Bytes encoded = hex(text(entries[i]));
            const auto entry = protocol::decode_log_entry(encoded);
            REQUIRE(entry);
            CHECK(*protocol::encode_log_entry(*entry) == encoded);
            if (i < commitment_index) {
                CHECK(entry->statement_id == statements[i].id);
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
        CHECK(*tree.root() == checkpoint->checkpoint.root);
    }
}

TEST_CASE("v0.7 children: evidence bundles and consents",
          "[protocol][vectors][contracts][children]") {
    const auto document = load_vectors("protocol-v0.7.json");
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        const protocol::Id home = id(ledger["ledger_id"]);
        const auto checkpoint = protocol::parse_checkpoint(hex(text(ledger["checkpoint"])));
        REQUIRE(checkpoint);
        const auto commitment = protocol::parse_state_commitment(
            provider(),
            protocol::decode_log_entry(hex(text(ledger["log_entries"].back())))->state_commitment);
        REQUIRE(commitment);

        std::map<std::uint64_t, protocol::SignedStatement> by_index;
        for (std::size_t i = 0; i < ledger["statements"].size(); ++i) {
            by_index.emplace(
                i, *protocol::parse_statement(provider(),
                                              hex(text(ledger["statements"][i]["encoded"])), hash));
        }

        // Every consent comes from a real party ledger: its bundle verifies
        // there, completely, and carries the terms of the call that cites it.
        std::size_t cited = 0;
        for (const auto& [index, signed_call] : by_index) {
            const auto* call = std::get_if<protocol::ContractCallBody>(&signed_call.statement.body);
            if (call == nullptr) {
                continue;
            }
            for (const auto& ref : call->consents) {
                const auto& all = ledger["consents"];
                const auto c = std::find_if(all.begin(), all.end(), [&](const auto& v) {
                    return text(v["record"]) == to_hex(ref.record.bytes());
                });
                REQUIRE(c != all.end());
                const auto value = cbor::decode(hex(text((*c)["metadata"])));
                REQUIRE(value);
                const auto consent = protocol::decode_contract_consent(*value);
                REQUIRE(consent);
                const auto digest =
                    protocol::contract_arguments_digest(provider(), hash, call->arguments);
                REQUIRE(digest);
                CHECK(protocol::consent_matches(*consent, home, *call, *digest));
                const auto check = protocol::check_contract_consent(
                    provider(), ref, hex(text((*c)["bundle"])), *call, home, hash,
                    document["t0"].get<protocol::Timestamp>() + 1000 + index);
                INFO((check ? std::string() : std::string(check.error().detail)));
                CHECK(check);
                ++cited;
            }
        }
        CHECK(cited == ledger["consents"].size() - 1); // one consent's call was refused

        for (const auto& [what, expected] : ledger["evidence"].items()) {
            INFO(what);
            const Bytes encoded = hex(text(expected["contract_evidence"]));
            const auto evidence = protocol::decode_contract_evidence(encoded);
            REQUIRE(evidence);
            CHECK(*protocol::encode_contract_evidence(*evidence) == encoded);
            CHECK(evidence->consent_bundles.size() == expected["pins"].size());
            const auto bundle = protocol::decode_bundle(evidence->instance_bundle);
            REQUIRE(bundle);
            CHECK(*protocol::encode_bundle(*bundle) == evidence->instance_bundle);
            CHECK(bundle->record == id(expected["subject"]));

            // The entries the generator chose, each proven against the
            // checkpoint; the last is the state commitment.
            const auto indices = expected["entries"].get<std::vector<std::uint64_t>>();
            REQUIRE(bundle->entries.size() == indices.size());
            for (std::size_t i = 0; i < indices.size(); ++i) {
                const auto receipt = protocol::parse_receipt(bundle->entries[i].receipt);
                REQUIRE(receipt);
                CHECK(receipt->proof.leaf_index == indices[i]);
                CHECK(*protocol::receipt_root(provider(), *receipt, bundle->entries[i].entry) ==
                      checkpoint->checkpoint.root);
                CHECK(to_hex(bundle->entries[i].entry) == text(ledger["log_entries"][indices[i]]));
            }
            CHECK(indices.back() + 1 == checkpoint->checkpoint.tree_size);

            // A proof for the instance, its contract, and everyone involved
            // in its events (its ancestors' calls included), in that order;
            // none for the ancestors.
            std::vector<std::string> proven;
            for (const auto& proof : bundle->state_proofs) {
                CHECK(protocol::verify_state_proof(provider(), hash, proof,
                                                   commitment->commitment.state_root));
                proven.push_back(to_hex(proof.leaf.id.bytes()));
            }
            CHECK(proven == expected["involved"].get<std::vector<std::string>>());
            for (const auto& ancestor : expected["ancestors"]) {
                CHECK_FALSE(std::ranges::contains(proven, text(ancestor["id"])));
            }

            // Without ancestors, the code of v0.6 verifies it in full.
            if (expected["ancestors"].empty()) {
                protocol::VerifyOptions options;
                options.expected_ledger = home;
                const auto report =
                    protocol::verify_contract_evidence(provider(), encoded, options);
                INFO((report ? std::string() : std::string(report.error().detail)));
                REQUIRE(report);
                CHECK(report->instance.complete);
                CHECK(report->steps.size() == expected["events"].size());
            }
        }
    }
}

TEST_CASE("v0.7 children: replay and evidence of children (M15)",
          "[protocol][vectors][contracts][children]") {
    // M15 replaces this with the v0.6 pattern (protocol_v06_test.cpp) on
    // protocol-v0.7.json: replay `statements` under the rules, with each run
    // and each refused statement at its place (`after`); every instance's
    // state, status, parties, head, finality, depth, parent, and history; and
    // `verify_contract_evidence` on the evidence of the tier-3 part and of the
    // child whose parent carried on.
    SKIP("core creates no children yet: milestone M15 of the Bo compiler plan");
}
