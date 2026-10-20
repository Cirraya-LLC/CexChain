// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.8 (requests and answers) against objects built by an independent
// Python encoder and run by the reference interpreter (tools/testvectors/).
//
// The first two cases check the objects one by one: statements (answers and
// scope keys 8 and 9 included), contract runs and outputs (requests
// included), request ids, the digests of outside responses, the state tree,
// the log, the consent, and each evidence bundle's receipts and proofs. The
// third replays the log under the rules of v0.8, every refusal in place and
// every run's input byte for byte; the fourth verifies the contract evidence
// and its reports (each call's requests and answer, open and overdue
// requests). The last covers what the vectors cannot reach.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
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
#include <cexchain/verifier/report.hpp>

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

std::vector<std::string> hex_ids(const std::vector<protocol::Id>& ids) {
    std::vector<std::string> out;
    for (const protocol::Id& i : ids) {
        out.push_back(to_hex(i.bytes()));
    }
    return out;
}

} // namespace

TEST_CASE("v0.8 requests: statements, runs, ids, the state, and the log",
          "[protocol][vectors][contracts][requests]") {
    const auto document = load_vectors("protocol-v0.8.json");
    const auto& limits = document["limits"];
    CHECK(limits["requests"].get<std::size_t>() == protocol::max_contract_requests);
    CHECK(limits["open"].get<std::size_t>() == protocol::max_open_requests);
    CHECK(limits["params"].get<std::size_t>() == protocol::max_request_params);
    CHECK(limits["deadline"].get<protocol::Timestamp>() == protocol::max_request_deadline);
    auto module = vm::load(hex(text(document["contract"])));
    REQUIRE(module);
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        const protocol::Id home = id(ledger["ledger_id"]);

        // Every statement parses and re-encodes, answers and scope keys 8
        // and 9 included; the malformed refused ones never parse.
        std::size_t answers = 0;
        std::size_t narrowed = 0;
        auto check_statement = [&](const nlohmann::json& st) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            if (st.contains("statement_id")) {
                CHECK(to_hex(parsed->id.bytes()) == text(st["statement_id"]));
            }
            if (const auto* call =
                    std::get_if<protocol::ContractCallBody>(&parsed->statement.body)) {
                answers += call->answer ? 1U : 0U;
                CHECK((!call->answer || call->instance));
            }
            if (const auto* grant =
                    std::get_if<protocol::DelegationGrantBody>(&parsed->statement.body)) {
                narrowed += grant->scope.functions || grant->scope.request_kinds ? 1U : 0U;
            }
        };
        for (const auto& st : ledger["statements"]) {
            check_statement(st);
        }
        for (const auto& st : ledger["refused"]) {
            if (st["malformed"].get<bool>()) {
                INFO(text(st["name"]));
                CHECK_FALSE(protocol::parse_statement(provider(), hex(text(st["encoded"])), hash));
                CHECK_FALSE(protocol::decode_payload(hex(text(st["payload"]))));
                continue;
            }
            check_statement(st);
        }
        CHECK(answers > 0);
        CHECK(narrowed > 0);

        // Every run, answers' inputs (key 9) included, gives the same outcome,
        // output, and fuel here as in the reference interpreter. An output
        // decodes, requests and all, and encodes back; a malformed one never
        // decodes.
        std::size_t asking = 0;
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
                const auto output = protocol::decode_contract_output(outcome->output, home);
                REQUIRE_FALSE(output);
                CHECK(output.error().code == cexchain::Errc::malformed);
            } else if (verdict == "accept" || verdict == "needs") {
                const auto output = protocol::decode_contract_output(outcome->output, home);
                REQUIRE(output);
                CHECK(*protocol::encode_contract_output(*output) == outcome->output);
                CHECK(std::holds_alternative<protocol::ContractAccept>(*output) ==
                      (verdict == "accept"));
                if (const auto* accept = std::get_if<protocol::ContractAccept>(&*output)) {
                    asking += accept->requests.empty() ? 0U : 1U;
                }
            }
        }
        CHECK(asking > 0);

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
            const auto rid = protocol::request_id(provider(), hash, id(request["call_id"]),
                                                  request["position"].get<std::uint64_t>());
            REQUIRE(rid);
            CHECK(to_hex(rid->bytes()) == text(request["id"]));
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
            REQUIRE(parsed);
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
                const Bytes bundle = hex(text((*c)["bundle"]));
                const auto at = st["registered_at"].get<protocol::Timestamp>();
                const auto check = protocol::check_contract_consent(provider(), ref, bundle, *call,
                                                                    home, hash, at);
                INFO((check ? std::string() : std::string(check.error().detail)));
                CHECK(check);
                // The same checks on a bundle verified ahead (a registrar's
                // consent, verified before its writer takes it): the same
                // answer, and the same refusal for other terms.
                protocol::VerifyOptions party;
                party.expected_ledger = ref.ledger;
                const auto report = protocol::verify_bundle(provider(), bundle, party);
                REQUIRE(report);
                const auto ahead = protocol::check_verified_contract_consent(
                    provider(), ref, bundle, *report, *call, home, hash, at);
                REQUIRE(ahead);
                CHECK(ahead->ref == check->ref);
                CHECK(ahead->consent == check->consent);
                CHECK(ahead->report.record == check->report.record);
                protocol::ContractCallBody other = *call;
                other.function = "other";
                CHECK(protocol::check_verified_contract_consent(provider(), ref, bundle, *report,
                                                                other, home, hash, at)
                          .error() == protocol::check_contract_consent(provider(), ref, bundle,
                                                                       other, home, hash, at)
                                          .error());
                CHECK(protocol::check_verified_contract_consent(provider(), ref, bundle, *report,
                                                                *call, home, hash,
                                                                at + 400 * 86'400'000ULL)
                          .error() == protocol::check_contract_consent(provider(), ref, bundle,
                                                                       *call, home, hash,
                                                                       at + 400 * 86'400'000ULL)
                                          .error());
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

namespace {

/// The verdict a run's vector names: accept, needs, malformed, or the trap.
std::string verdict(const protocol::ContractRun& run) {
    if (run.outcome.trap) {
        return std::string(vm::name(*run.outcome.trap));
    }
    if (run.malformed) {
        return "malformed";
    }
    return run.accepted() != nullptr ? "accept" : "needs";
}

/// Words the refusal's detail holds, for each rule the vectors name.
std::string refusal_words(const std::string& why) {
    static const std::map<std::string, std::string> words{
        {"narrowing", "exceed the grantor's scope"},
        {"answer function", "calls its request's reply"},
        {"consents", "cites no consents"},
        {"early", "expires only once its deadline"},
        {"no such request", "request does not exist"},
        {"other instance", "another instance"},
        {"answered", "already answered"},
        {"authority", "delegation"},
        {"head", "head"},
        {"final", "final"},
        {"open", "64 open requests"},
        {"deadline", "deadline is after the call"},
        {"reply", "reply is a function"},
        {"contract", "contract"},
    };
    return words.at(why);
}

/// The encoded signer a contract would see for an event's statement.
std::string signer_hex(const protocol::RecordEvent& event) {
    protocol::ContractSigner signer;
    signer.kind = event.actor.kind ? static_cast<std::uint8_t>(*event.actor.kind) : 0;
    if (event.presence) {
        signer.presence = event.presence->method;
    }
    if (event.provenance) {
        signer.model = event.provenance->model;
    }
    return to_hex(*cbor::encode(protocol::encode_contract_signer(signer)));
}

} // namespace

TEST_CASE("v0.8 requests: replay, refusals in place, and every request",
          "[protocol][vectors][contracts][requests]") {
    const auto document = load_vectors("protocol-v0.8.json");
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));

        std::vector<protocol::SignedStatement> statements;
        std::vector<protocol::Timestamp> times;
        std::map<std::string, protocol::SignedStatement> by_name;
        for (const auto& st : ledger["statements"]) {
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            REQUIRE(by_name.emplace(text(st["name"]), *parsed).second);
            statements.push_back(std::move(*parsed));
            times.push_back(st["registered_at"].get<protocol::Timestamp>());
        }
        // The rules refuse each statement that parses at its place in the
        // log and its time, for the one rule the vectors name.
        struct Refusal {
            protocol::SignedStatement statement;
            protocol::Timestamp at = 0;
            std::string why;
        };
        std::multimap<std::size_t, Refusal> refused;
        std::map<std::string, std::size_t> reasons;
        for (const auto& st : ledger["refused"]) {
            INFO(text(st["name"]));
            ++reasons[text(st["why"])];
            if (st["malformed"].get<bool>()) {
                continue;
            }
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            REQUIRE(by_name.emplace(text(st["name"]), *parsed).second);
            refused.emplace(
                st["after"].get<std::size_t>(),
                Refusal{std::move(*parsed), st["at"].get<protocol::Timestamp>(), text(st["why"])});
        }
        CHECK(reasons.size() == 15);
        std::multimap<std::size_t, nlohmann::json> runs;
        for (const auto& run : ledger["runs"]) {
            runs.emplace(run["after"].get<std::size_t>(), run);
        }

        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        // Every run at this point of the log and its time: the same input,
        // byte for byte (key 9 for an answer), outcome, output, fuel, and
        // verdict; the output, requests included, encodes back.
        auto check_runs = [&](std::size_t after) {
            const auto [first, last] = runs.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const auto& expected = it->second;
                INFO(text(expected["name"]));
                auto run = state->run_contract(provider(), by_name.at(text(expected["name"])),
                                               expected["at"].get<protocol::Timestamp>());
                REQUIRE(run);
                CHECK(to_hex(run->input) == text(expected["input"]));
                CHECK((run->outcome.trap ? std::string(vm::name(*run->outcome.trap))
                                         : std::string("ok")) == text(expected["outcome"]));
                CHECK(to_hex(run->outcome.output) == text(expected["output"]));
                CHECK(run->outcome.fuel_used == expected["fuel"].get<std::uint64_t>());
                CHECK(verdict(*run) == text(expected["verdict"]));
                if (run->output) {
                    CHECK(*protocol::encode_contract_output(*run->output) == run->outcome.output);
                }
            }
        };
        std::size_t checked = 0;
        auto check_refused = [&](std::size_t after) {
            const auto [first, last] = refused.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const Refusal& r = it->second;
                INFO(r.why);
                const auto valid = state->validate(provider(), r.statement, r.at);
                REQUIRE_FALSE(valid);
                INFO(std::string(valid.error().detail));
                CHECK(std::string(valid.error().detail).find(refusal_words(r.why)) !=
                      std::string::npos);
                ++checked;
            }
        };
        for (std::size_t i = 1; i < statements.size(); ++i) {
            check_runs(i);
            check_refused(i);
            INFO(text(ledger["statements"][i]["name"]));
            const auto valid = state->validate(provider(), statements[i], times[i]);
            INFO((valid ? std::string() : std::string(valid.error().detail)));
            REQUIRE(valid);
            REQUIRE(state->apply(provider(), statements[i], i, times[i]));
        }
        check_runs(statements.size());
        check_refused(statements.size());
        CHECK(checked == refused.size());

        // Instances end where the independent encoder says, each with its
        // open requests in the order they were made.
        CHECK(state->instances().size() == ledger["instances"].size());
        for (const auto& expected : ledger["instances"]) {
            INFO(text(expected["id"]));
            const protocol::InstanceState* instance = state->instance(id(expected["id"]));
            REQUIRE(instance != nullptr);
            CHECK(instance->contract == id(expected["contract"]));
            CHECK(instance->head == expected["head"].get<std::uint64_t>());
            CHECK(instance->history.to_vector() ==
                  expected["history"].get<std::vector<std::uint64_t>>());
            CHECK(to_hex(instance->state.bytes()) == text(expected["state"]));
            CHECK(instance->status.has_value() == !expected["status"].is_null());
            if (instance->status) {
                CHECK(*instance->status == text(expected["status"]));
            }
            CHECK(instance->parties.size() == expected["parties"].size());
            CHECK(instance->final == expected["final"].get<bool>());
            CHECK(instance->depth == expected["depth"].get<std::uint32_t>());
            std::vector<std::string> open;
            for (const protocol::CompactId& r : instance->open_requests) {
                open.push_back(to_hex(r.bytes()));
            }
            CHECK(open == expected["open"].get<std::vector<std::string>>());
            CHECK(open.size() <= protocol::max_open_requests);
        }

        // Every request, made by its call at its position, open or answered
        // once, by the answer the vectors name.
        CHECK(state->requests().size() == ledger["requests"].size());
        std::size_t position = 0;
        for (const auto& [key, request] : state->requests()) {
            const auto& expected = ledger["requests"][position++];
            INFO(text(expected["id"]));
            CHECK(to_hex(request.id.bytes()) == text(expected["id"]));
            CHECK(to_hex(request.instance.bytes()) == text(expected["instance"]));
            CHECK(request.call == expected["call"].get<std::uint64_t>());
            CHECK(statements[request.call].id == id(expected["call_id"]));
            CHECK(request.position == expected["position"].get<std::uint32_t>());
            CHECK(request.kind == text(expected["kind"]));
            CHECK(to_hex(*cbor::encode(request.params)) == text(expected["params"]));
            CHECK(request.deadline == expected["deadline"].get<protocol::Timestamp>());
            CHECK(request.reply == text(expected["reply"]));
            CHECK(request.asked_at == expected["asked_at"].get<protocol::Timestamp>());
            REQUIRE(request.open() == expected["status"].is_null());
            if (!request.open()) {
                CHECK(static_cast<int>(*request.status) == expected["status"].get<int>());
                CHECK(request.answered_by == expected["answered_by"].get<std::uint64_t>());
                CHECK(request.answered_at == expected["answered_at"].get<protocol::Timestamp>());
                CHECK(request.late_by() == expected["late_by"].get<protocol::Timestamp>());
                const auto* answer = std::get_if<protocol::ContractCallBody>(
                    &statements[*request.answered_by].statement.body);
                REQUIRE(answer != nullptr);
                REQUIRE(answer->answer);
                CHECK(answer->answer->request == request.id);
                CHECK(answer->function == request.reply);
            }
            CHECK(state->request(request.id) == &request);
        }

        // The replayed state has the leaves, and the root, the log commits
        // to: requests add none.
        const auto leaves = protocol::state_leaves(*state);
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

namespace {

/// The bundle of `encoded` contract evidence, changed by `change`, encoded
/// again into contract evidence with the same consents.
Bytes tampered(const Bytes& encoded, const std::function<void(protocol::EvidenceBundle&)>& change) {
    auto evidence = protocol::decode_contract_evidence(encoded);
    REQUIRE(evidence);
    auto bundle = protocol::decode_bundle(evidence->instance_bundle);
    REQUIRE(bundle);
    change(*bundle);
    auto again = protocol::encode_bundle(*bundle);
    REQUIRE(again);
    evidence->instance_bundle = std::move(*again);
    auto out = protocol::encode_contract_evidence(*evidence);
    REQUIRE(out);
    return *out;
}

std::uint64_t leaf_index(const protocol::EvidenceEntry& e) {
    const auto receipt = protocol::parse_receipt(e.receipt);
    REQUIRE(receipt);
    return receipt->proof.leaf_index;
}

} // namespace

TEST_CASE("v0.8 requests: contract evidence shows every request and answer",
          "[protocol][vectors][contracts][requests]") {
    const auto document = load_vectors("protocol-v0.8.json");
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        protocol::VerifyOptions options;
        options.expected_ledger = id(ledger["ledger_id"]);
        for (const auto& [what, expected] : ledger["evidence"].items()) {
            INFO(what);
            const Bytes encoded = hex(text(expected["contract_evidence"]));
            const auto report = protocol::verify_contract_evidence(provider(), encoded, options);
            INFO((report ? std::string() : std::string(report.error().detail)));
            REQUIRE(report);
            const protocol::EvidenceReport& e = report->instance;
            CHECK(e.complete);
            CHECK(e.record == id(expected["subject"]));
            REQUIRE(e.instance);
            const protocol::InstanceReport& i = *e.instance;
            CHECK(i.depth == expected["depth"].get<std::uint32_t>());
            CHECK(i.ancestors.size() == expected["ancestors"].size());
            REQUIRE(e.events.size() == expected["calls"].size());
            REQUIRE(report->steps.size() == e.events.size());
            const auto bundle = protocol::decode_bundle(
                protocol::decode_contract_evidence(encoded)->instance_bundle);
            REQUIRE(bundle);

            // Each call: the requests it made, and the answer it gave, with
            // the request's status, how late it was, and who gave it under
            // which delegation.
            for (std::size_t n = 0; n < e.events.size(); ++n) {
                const protocol::RecordEvent& event = e.events[n];
                const auto& call = expected["calls"][n];
                INFO(event.index);
                CHECK(event.index == call["index"].get<std::uint64_t>());
                CHECK(hex_ids(event.requests) == call["requests"].get<std::vector<std::string>>());
                REQUIRE(event.outcome);
                CHECK(event.requests.size() == event.outcome->requests.size());
                REQUIRE(event.contract_call);
                const auto& answer = call["answer"];
                REQUIRE(event.contract_call->answer.has_value() == !answer.is_null());
                REQUIRE(event.answered.has_value() == !answer.is_null());
                if (answer.is_null()) {
                    continue;
                }
                const protocol::RequestReport& r = *event.answered;
                CHECK(to_hex(r.id.bytes()) == text(answer["request"]));
                CHECK(static_cast<int>(*r.status) == answer["status"].get<int>());
                CHECK(static_cast<int>(event.contract_call->answer->status) ==
                      answer["status"].get<int>());
                CHECK(r.answered_by == event.index);
                CHECK(r.answered_at == event.registered_at);
                CHECK(r.late_by == answer["late_by"].get<protocol::Timestamp>());
                CHECK(to_hex(event.actor.id.bytes()) == text(answer["actor"]));
                CHECK(signer_hex(event) == text(answer["signer"]));
                const auto entry = std::ranges::find_if(
                    bundle->entries, [&](const auto& x) { return leaf_index(x) == event.index; });
                REQUIRE(entry != bundle->entries.end());
                const auto statement = protocol::parse_statement(
                    provider(), protocol::decode_log_entry(entry->entry)->statement, hash);
                REQUIRE(statement);
                CHECK(statement->statement.delegation_id.has_value() ==
                      !answer["delegation"].is_null());
                if (statement->statement.delegation_id) {
                    CHECK(to_hex(statement->statement.delegation_id->bytes()) ==
                          text(answer["delegation"]));
                }
            }

            // The instance's own requests, the open ones, and those overdue
            // at the checkpoint's time.
            std::vector<protocol::Id> own;
            std::vector<protocol::Id> open;
            std::vector<protocol::Id> overdue;
            for (const protocol::RequestReport& r : i.requests) {
                own.push_back(r.id);
                CHECK(r.instance == e.record);
                CHECK(r.overdue == (!r.status && e.checkpoint.timestamp >= r.deadline));
            }
            for (const std::size_t n : i.open_requests()) {
                open.push_back(i.requests[n].id);
            }
            for (const std::size_t n : i.overdue_requests()) {
                overdue.push_back(i.requests[n].id);
            }
            CHECK(hex_ids(own) == expected["requests"].get<std::vector<std::string>>());
            CHECK(hex_ids(open) == expected["open"].get<std::vector<std::string>>());
            CHECK(hex_ids(overdue) == expected["overdue"].get<std::vector<std::string>>());

            // Every verifier front end reports the same (the command line and
            // the browser share these reports).
            const auto json = cexchain::verifier::contract_report_json(*report, true);
            REQUIRE(json["calls"].size() == expected["calls"].size());
            for (std::size_t n = 0; n < e.events.size(); ++n) {
                const auto& call = expected["calls"][n];
                const auto& shown = json["calls"][n];
                std::vector<std::string> made;
                if (shown["outcome"].contains("requests")) {
                    for (const auto& r : shown["outcome"]["requests"]) {
                        made.push_back(r["id"].get<std::string>());
                    }
                }
                CHECK(made == call["requests"].get<std::vector<std::string>>());
                if (call["answer"].is_null()) {
                    CHECK(shown["answer"].is_null());
                } else {
                    CHECK(shown["answer"]["request"] == call["answer"]["request"]);
                    CHECK(shown["answer"]["status"] ==
                          std::string(protocol::name(static_cast<protocol::AnswerStatus>(
                              call["answer"]["status"].get<int>()))));
                    CHECK(shown["answer"]["late_by_ms"] == call["answer"]["late_by"]);
                }
            }
            CHECK(json["instance"]["open_requests"] == expected["open"]);
            CHECK(json["instance"]["overdue_requests"] == expected["overdue"]);
            CHECK(json["instance"]["requests"].size() == expected["requests"].size());
            const std::string shown = cexchain::verifier::contract_report_text(*report, true);
            CHECK(shown.contains("OVERDUE") == !expected["overdue"].empty());
            CHECK(shown.contains("answers    "));
            const bool late = std::ranges::any_of(expected["calls"], [](const auto& c) {
                return !c["answer"].is_null() && c["answer"]["late_by"].template get<int>() > 0;
            });
            CHECK(shown.contains("LATE by") == late);
            CHECK(shown.contains("whether they were answered") == !expected["ancestors"].empty());

            // Every answer is needed: without one, the calls after it no
            // longer follow their heads, and the instance's history is not
            // what its home commits to.
            for (const protocol::RecordEvent& event : e.events) {
                if (event.contract_call->answer) {
                    CHECK_FALSE(protocol::verify_contract_evidence(
                        provider(),
                        tampered(encoded,
                                 [&](protocol::EvidenceBundle& b) {
                                     std::erase_if(b.entries, [&](const auto& x) {
                                         return leaf_index(x) == event.index;
                                     });
                                 }),
                        options));
                    break;
                }
            }
        }
    }
}

namespace {

const protocol::Id home_ledger = *protocol::to_id(Bytes(32, 0x5A));

cbor::MapEntry field(std::uint64_t key, cbor::Value value) {
    return {cbor::Value::unsigned_integer(key), std::move(value)};
}

/// An accept of null with `requests`, as a contract writes it.
Bytes accept_with(std::vector<cbor::Value> requests) {
    cbor::Map accept{field(1, cbor::Value::null())};
    accept.push_back(field(7, cbor::Value::array(std::move(requests))));
    auto encoded = cbor::encode(cbor::Value::array(
        {cbor::Value::unsigned_integer(1), cbor::Value::map(std::move(accept))}));
    REQUIRE(encoded);
    return *encoded;
}

cbor::Value request_map(std::string kind, cbor::Value params, protocol::Timestamp deadline,
                        std::string reply = "result") {
    return cbor::Value::map({field(1, cbor::Value::text(std::move(kind))),
                             field(2, std::move(params)),
                             field(3, cbor::Value::unsigned_integer(deadline)),
                             field(4, cbor::Value::text(std::move(reply)))});
}

} // namespace

TEST_CASE("v0.8 requests: what the vectors cannot reach", "[protocol][contracts][requests]") {
    // Kinds: [a-z][a-z0-9._-]{0,63}, written out.
    for (const std::string& kind :
         std::vector<std::string>{"a", "invoice", "panel.suspend-2_b", std::string(64, 'k')}) {
        CHECK(protocol::is_request_kind(kind));
    }
    for (const std::string& kind : std::vector<std::string>{
             "", "Invoice", "1st", "_a", ".a", "a b", "a/b", "caf\xc3\xa9", std::string(65, 'k')}) {
        CHECK_FALSE(protocol::is_request_kind(kind));
    }
    for (const std::uint64_t status : {1U, 2U, 3U}) {
        CHECK(protocol::answer_status_from(status));
    }
    CHECK_FALSE(protocol::answer_status_from(0));
    CHECK_FALSE(protocol::answer_status_from(4));
    CHECK(protocol::name(protocol::AnswerStatus::expired) == "expired");

    // An output at the limits encodes back; the deadline is any uint, even
    // the largest (its window is a ledger rule).
    std::vector<cbor::Value> sixteen;
    for (std::uint64_t n = 0; n < protocol::max_contract_requests; ++n) {
        sixteen.push_back(request_map(
            std::string(64, static_cast<char>('a' + n)), cbor::Value::bytes(Bytes(4093, 0x11)),
            std::numeric_limits<std::uint64_t>::max(), std::string(64, 'r')));
    }
    const Bytes full = accept_with(sixteen);
    const auto decoded = protocol::decode_contract_output(full, home_ledger);
    REQUIRE(decoded);
    const auto& accept = std::get<protocol::ContractAccept>(*decoded);
    REQUIRE(accept.requests.size() == 16);
    CHECK(accept.requests[15].deadline == std::numeric_limits<std::uint64_t>::max());
    CHECK(*protocol::encode_contract_output(*decoded) == full);
    // Params of 4,097 bytes, a reply that is not text, a map key that is
    // text, or a request beside a child's keys do not decode.
    CHECK_FALSE(protocol::decode_contract_output(
        accept_with({request_map("a", cbor::Value::bytes(Bytes(4094, 0)), 1)}), home_ledger));
    CHECK_FALSE(protocol::decode_contract_output(
        accept_with(
            {cbor::Value::map({field(1, cbor::Value::text("a")), field(2, cbor::Value::null()),
                               field(3, cbor::Value::unsigned_integer(1)),
                               field(4, cbor::Value::unsigned_integer(2))})}),
        home_ledger));
    CHECK_FALSE(protocol::decode_contract_output(
        accept_with({cbor::Value::map({field(1, cbor::Value::text("a")),
                                       field(2, cbor::Value::null()),
                                       field(3, cbor::Value::unsigned_integer(1)),
                                       field(4, cbor::Value::text("r")),
                                       {cbor::Value::text("x"), cbor::Value::null()}})}),
        home_ledger));

    // A request's id is never a child's id or the call's, and positions
    // differ.
    const protocol::Id call = *protocol::to_id(Bytes(32, 0x22));
    for (const auto hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
        std::set<std::string> ids{to_hex(call.bytes())};
        for (std::uint64_t position = 0; position < protocol::max_contract_requests; ++position) {
            CHECK(
                ids.insert(to_hex(protocol::request_id(provider(), hash, call, position)->bytes()))
                    .second);
            CHECK(ids
                      .insert(to_hex(
                          protocol::child_instance_id(provider(), hash, call, position)->bytes()))
                      .second);
        }
    }

    // The input shows an answer its request (key 9), after the consents.
    protocol::ContractInput input;
    input.function = "result";
    input.arguments = cbor::Value::null();
    input.home = home_ledger;
    input.contract = call;
    input.caller = call;
    input.instance =
        protocol::ContractInstanceView{call, 7, cbor::Encoded(), std::nullopt, {}, {}, 0};
    const auto without = cbor::decode(*protocol::encode_contract_input(input));
    REQUIRE(without);
    CHECK(without->find(9) == nullptr);
    input.request = protocol::ContractRequestView{call, "invoice", cbor::Value::text("p"),
                                                  20,   10,        protocol::AnswerStatus::failed};
    const auto with = cbor::decode(*protocol::encode_contract_input(input));
    REQUIRE(with);
    REQUIRE(with->find(9) != nullptr);
    CHECK(*cbor::encode(*with->find(9)) ==
          *cbor::encode(cbor::Value::map(
              {field(1, cbor::Value::bytes(call.bytes())), field(2, cbor::Value::text("invoice")),
               field(3, cbor::Value::text("p")), field(4, cbor::Value::unsigned_integer(20)),
               field(5, cbor::Value::unsigned_integer(10)),
               field(6, cbor::Value::unsigned_integer(2))})));

    // Scope keys 8 and 9 encode sorted by UTF-8 bytes, each once, and decode
    // only so.
    protocol::Statement grant;
    grant.ledger_id = home_ledger;
    grant.actor_id = home_ledger;
    grant.issued_at = 1;
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::contract_call};
    scope.functions = std::vector<std::string>{"\xe7\xb5\x90\xe6\x9e\x9c", "result", "ask"};
    scope.request_kinds = std::vector<std::string>{"notify", "invoice"};
    grant.body = protocol::DelegationGrantBody{call, scope};
    const auto payload = protocol::encode_payload(grant);
    REQUIRE(payload);
    const auto back = protocol::decode_payload(*payload);
    REQUIRE(back);
    const auto& got = std::get<protocol::DelegationGrantBody>(back->body).scope;
    CHECK(*got.functions == std::vector<std::string>{"ask", "result", "\xe7\xb5\x90\xe6\x9e\x9c"});
    CHECK(*got.request_kinds == std::vector<std::string>{"invoice", "notify"});
    // What the structural rules refuse, an encoder refuses as an invalid
    // argument.
    auto refused = [&](std::string_view words) {
        const auto encoded = protocol::encode_payload(grant);
        REQUIRE_FALSE(encoded);
        CHECK(encoded.error().code == cexchain::Errc::invalid_argument);
        CHECK(encoded.error().detail.contains(words));
    };
    scope.request_kinds->push_back("invoice");
    grant.body = protocol::DelegationGrantBody{call, scope};
    refused("request kind twice");
    scope.request_kinds = std::vector<std::string>{"Invoice"};
    grant.body = protocol::DelegationGrantBody{call, scope};
    refused("starting with a letter");
    scope.request_kinds = std::nullopt;
    scope.functions = std::vector<std::string>{std::string(65, 'f')};
    grant.body = protocol::DelegationGrantBody{call, scope};
    refused("1 to 64 bytes");
    scope.functions = std::vector<std::string>{};
    grant.body = protocol::DelegationGrantBody{call, scope};
    refused("must not be empty");

    // An answer names an instance: a creation never answers.
    protocol::ContractCallBody create;
    create.contract = call;
    create.function = "open";
    create.arguments = cbor::Value::null();
    create.answer = protocol::ContractAnswer{call, protocol::AnswerStatus::done};
    grant.body = create;
    refused("an answer names an instance");
    create.contract.reset();
    create.instance = call;
    create.head = 3;
    grant.body = create;
    const auto answer = protocol::encode_payload(grant);
    REQUIRE(answer);
    CHECK(std::get<protocol::ContractCallBody>(protocol::decode_payload(*answer)->body).answer ==
          create.answer);
}
