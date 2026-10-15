// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.8 (requests and answers) against objects built by an independent
// Python encoder and run by the reference interpreter (tools/testvectors/).
//
// Core does not implement requests and answers yet: that is milestone E2 of
// Phase 6b. The first two cases check what the code of v0.7 can, and keep
// passing once E2 lands: every statement parses and re-encodes unless it
// carries an answer or scope key 8 or 9; every contract run gives the same
// outcome, output, and fuel here as in the reference interpreter; outputs
// decode unless they make requests; request ids and the digests of outside
// responses; the state tree, the log, the state commitment, and the
// checkpoint; the consent; and each evidence bundle's receipts and state
// proofs. The last case, replaying the log under the rules of v0.8 and
// verifying the contract evidence, is E2's.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
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

/// Whether an encoded statement payload uses what v0.8 adds to statements:
/// an answer (contract-call key 8), or scope key 8 or 9 in a delegation.
bool uses_v08(const Bytes& payload) {
    const auto value = cbor::decode(payload);
    REQUIRE(value);
    const cbor::Value* type = value->find(1);
    const cbor::Value* body = value->find(7);
    REQUIRE(type != nullptr);
    REQUIRE(body != nullptr);
    if (type->as_uint64() == 22U) {
        return body->find(8) != nullptr;
    }
    if (type->as_uint64() == 5U) {
        const cbor::Value* scope = body->find(2);
        return scope != nullptr && (scope->find(8) != nullptr || scope->find(9) != nullptr);
    }
    return false;
}

/// Whether an encoded contract output is an accept that makes requests (key 7).
bool makes_requests(const Bytes& output) {
    const auto value = cbor::decode(output);
    REQUIRE(value);
    const cbor::Array* outcome = value->as_array();
    REQUIRE(outcome != nullptr);
    REQUIRE(outcome->size() == 2);
    return (*outcome)[0].as_uint64() == 1U && (*outcome)[1].find(7) != nullptr;
}

} // namespace

TEST_CASE("v0.8 requests: statements, runs, ids, the state, and the log",
          "[protocol][vectors][contracts][requests]") {
    const auto document = load_vectors("protocol-v0.8.json");
    auto module = vm::load(hex(text(document["contract"])));
    REQUIRE(module);
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        const protocol::Id home = id(ledger["ledger_id"]);

        // Every statement parses and re-encodes, except those that carry an
        // answer or scope key 8 or 9, which need E2. The malformed refused
        // ones never parse.
        std::size_t pending = 0;
        auto check_statement = [&](const nlohmann::json& st) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            if (!parsed) {
                CHECK(uses_v08(hex(text(st["payload"]))));
                ++pending;
                return;
            }
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            if (st.contains("statement_id")) {
                CHECK(to_hex(parsed->id.bytes()) == text(st["statement_id"]));
            }
        };
        for (const auto& st : ledger["statements"]) {
            check_statement(st);
        }
        for (const auto& st : ledger["refused"]) {
            if (st["malformed"].get<bool>()) {
                INFO(text(st["name"]));
                CHECK_FALSE(protocol::parse_statement(provider(), hex(text(st["encoded"])), hash));
                continue;
            }
            check_statement(st);
        }
        CHECK(pending > 0);

        // Every run, answers' inputs (key 9) included, gives the same outcome,
        // output, and fuel here as in the reference interpreter. An output
        // decodes and encodes back unless it makes requests (E2), and a
        // malformed one never decodes.
        for (const auto& run : ledger["runs"]) {
            INFO(text(run["name"]));
            const auto outcome = vm::run(*module, hex(text(run["input"])), provider(), hash);
            REQUIRE(outcome);
            CHECK((outcome->trap ? std::string(vm::name(*outcome->trap)) : std::string("ok")) ==
                  text(run["outcome"]));
            CHECK(to_hex(outcome->output) == text(run["output"]));
            CHECK(outcome->fuel_used == run["fuel"].get<std::uint64_t>());
            const std::string verdict = text(run["verdict"]);
            if (verdict == "malformed") {
                CHECK_FALSE(protocol::decode_contract_output(outcome->output, home));
            } else if (verdict == "accept" || verdict == "needs") {
                const auto output = protocol::decode_contract_output(outcome->output, home);
                if (output) {
                    CHECK(*protocol::encode_contract_output(*output) == outcome->output);
                } else {
                    CHECK(makes_requests(outcome->output));
                }
            }
        }

        // A request's id is HASH(["request", call, position]), its call being
        // the statement that made it.
        for (const auto& request : ledger["requests"]) {
            const auto& call = ledger["statements"][request["call"].get<std::size_t>()];
            CHECK(text(call["statement_id"]) == text(request["call_id"]));
            CHECK(call["registered_at"] == request["asked_at"]);
            const auto encoded = cbor::encode(cbor::Value::array(
                {cbor::Value::text("request"), cbor::Value::bytes(hex(text(request["call_id"]))),
                 cbor::Value::unsigned_integer(request["position"].get<std::uint64_t>())}));
            REQUIRE(encoded);
            CHECK(to_hex(provider().digest(hash, *encoded)->bytes()) == text(request["id"]));
        }

        // An outside response is committed as HASH(salt || response), which
        // the answer's arguments carry.
        for (const auto& disclosure : ledger["disclosures"]) {
            INFO(text(disclosure["name"]));
            Bytes salted = hex(text(disclosure["salt"]));
            REQUIRE(salted.size() == 16);
            const Bytes response = hex(text(disclosure["response"]));
            salted.insert(salted.end(), response.begin(), response.end());
            const Bytes digest = hex(text(disclosure["digest"]));
            CHECK(to_hex(provider().digest(hash, salted)->bytes()) == text(disclosure["digest"]));
            const auto& all = ledger["statements"];
            CHECK(std::ranges::any_of(all, [&](const auto& st) {
                const Bytes payload = hex(text(st["payload"]));
                return !std::ranges::search(payload, digest).empty();
            }));
        }

        // The state tree over every object has the root the logged state
        // commitment signs; no object is a request (they have no leaves).
        std::vector<protocol::StateLeaf> leaves;
        for (const auto& leaf : ledger["state_leaves"]) {
            leaves.push_back({static_cast<protocol::ObjectKind>(leaf["kind"].get<int>()),
                              id(leaf["id"]), leaf["history"].get<std::vector<std::uint64_t>>()});
            for (const auto& request : ledger["requests"]) {
                CHECK(text(leaf["id"]) != text(request["id"]));
            }
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

        // The log: each entry with its statement and registration time, then
        // the state commitment; the checkpoint covers it all.
        auto genesis = protocol::parse_statement(
            provider(), hex(text(ledger["statements"][0]["encoded"])), hash);
        REQUIRE(genesis);
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
                if (i > 0) {
                    const auto& before = ledger["statements"][i - 1];
                    CHECK(entry->registered_at >
                          before["registered_at"].get<protocol::Timestamp>());
                }
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

        // Overdue means open with the checkpoint's time at or past the
        // deadline.
        for (const auto& request : ledger["requests"]) {
            const bool open = request["status"].is_null();
            CHECK(request["overdue"].get<bool>() ==
                  (open && checkpoint->checkpoint.timestamp >=
                               request["deadline"].get<protocol::Timestamp>()));
            CHECK(request["answered_by"].is_null() == open);
        }
    }
}

TEST_CASE("v0.8 requests: evidence bundles and consents",
          "[protocol][vectors][contracts][requests]") {
    const auto document = load_vectors("protocol-v0.8.json");
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

        // The consent comes from a real party ledger: its bundle verifies
        // there, completely, and carries the terms of the call that cites it.
        std::size_t cited = 0;
        for (const auto& st : ledger["statements"]) {
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            if (!parsed) {
                continue; // an answer or a scope of v0.8, which cites none
            }
            const auto* call = std::get_if<protocol::ContractCallBody>(&parsed->statement.body);
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
                    st["registered_at"].get<protocol::Timestamp>());
                INFO((check ? std::string() : std::string(check.error().detail)));
                CHECK(check);
                ++cited;
            }
        }
        CHECK(cited == ledger["consents"].size());

        for (const auto& [what, expected] : ledger["evidence"].items()) {
            INFO(what);
            const Bytes encoded = hex(text(expected["contract_evidence"]));
            const auto evidence = protocol::decode_contract_evidence(encoded);
            REQUIRE(evidence);
            CHECK(*protocol::encode_contract_evidence(*evidence) == encoded);
            REQUIRE(evidence->consent_bundles.size() == expected["pins"].size());
            for (std::size_t i = 0; i < evidence->consent_bundles.size(); ++i) {
                CHECK(to_hex(provider().digest(hash, evidence->consent_bundles[i])->bytes()) ==
                      text(expected["pins"][i]));
            }
            const auto bundle = protocol::decode_bundle(evidence->instance_bundle);
            REQUIRE(bundle);
            CHECK(*protocol::encode_bundle(*bundle) == evidence->instance_bundle);
            CHECK(bundle->record == id(expected["subject"]));

            // The entries the generator chose, each proven against the
            // checkpoint; the last is the state commitment. Every call the
            // report shows is among them.
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
            for (const auto& call : expected["calls"]) {
                CHECK(std::ranges::contains(indices, call["index"].get<std::uint64_t>()));
            }

            // A proof for the instance, its contract, and everyone involved
            // in its calls (an agent's responsible person and every link of a
            // delegation chain included), in that order.
            std::vector<std::string> proven;
            for (const auto& proof : bundle->state_proofs) {
                CHECK(protocol::verify_state_proof(provider(), hash, proof,
                                                   commitment->commitment.state_root));
                proven.push_back(to_hex(proof.leaf.id.bytes()));
            }
            CHECK(proven == expected["involved"].get<std::vector<std::string>>());

            // The instance's own requests, open or answered, are those its
            // calls made; the open ones are as the ledger leaves them.
            std::vector<std::string> own;
            for (const auto& request : ledger["requests"]) {
                if (text(request["instance"]) == text(expected["subject"])) {
                    own.push_back(text(request["id"]));
                    CHECK(
                        std::ranges::contains(expected["events"].get<std::vector<std::uint64_t>>(),
                                              request["call"].get<std::uint64_t>()));
                }
            }
            CHECK(own == expected["requests"].get<std::vector<std::string>>());
            for (const auto& instance : ledger["instances"]) {
                if (text(instance["id"]) == text(expected["subject"])) {
                    CHECK(instance["open"] == expected["open"]);
                }
            }
        }
    }
}

TEST_CASE("v0.8 requests: replay, refusals in place, and reports (E2)",
          "[protocol][vectors][contracts][requests]") {
    // E2 replaces this with the v0.7 pattern (protocol_v07_test.cpp): replay
    // every statement at its registration time, each refused one at `at` for
    // the rule `why` names, each run's input byte for byte (key 9 for an
    // answer), the open and answered requests of every instance, and the
    // contract evidence's report (each call's requests and answer, open and
    // overdue requests), with tampered bundles failing.
    SKIP("core does not implement requests and answers yet: milestone E2 of Phase 6b");
}
