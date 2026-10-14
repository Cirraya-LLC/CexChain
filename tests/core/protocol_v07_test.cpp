// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.7 (instances created by a call) against objects built by an
// independent Python encoder and run by the reference interpreter
// (tools/testvectors/).
//
// The first two cases check what needs no children in core (statements,
// runs, ids, the log, consents, and the evidence of an instance never split);
// the last two replay the log under the rules of v0.7 and verify the
// contract evidence of children, ancestors included.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
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

            // An instance never split verifies as in v0.6 (children are the
            // last test case's).
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

/// Words the refusal's detail holds, for each reason the vectors name.
std::string refusal_words(const std::string& why) {
    static const std::map<std::string, std::string> words{
        {"final", "final"},          {"head", "head"},
        {"authority", "delegation"}, {"no such instance", "does not exist"},
        {"depth", "depth 8"},        {"retired", "retired"},
        {"contract", "contract"},
    };
    return words.at(why);
}

} // namespace

TEST_CASE("v0.7 children: replay, refusals in place, and every instance",
          "[protocol][vectors][contracts][children]") {
    const auto document = load_vectors("protocol-v0.7.json");
    const auto t0 = document["t0"].get<protocol::Timestamp>();
    CHECK(document["max_depth"].get<std::uint32_t>() == protocol::max_instance_depth);
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));

        std::vector<protocol::SignedStatement> statements;
        std::map<std::string, protocol::SignedStatement> by_name;
        for (const auto& st : ledger["statements"]) {
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            by_name.emplace(text(st["name"]), *parsed);
            statements.push_back(std::move(*parsed));
        }
        // No refused statement breaks the CDDL: the rules refuse each at its
        // place in the log, for the reason the vectors name.
        std::multimap<std::size_t, std::pair<protocol::SignedStatement, std::string>> refused;
        for (const auto& st : ledger["refused"]) {
            INFO(text(st["name"]));
            REQUIRE_FALSE(st["malformed"].get<bool>());
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            by_name.emplace(text(st["name"]), *parsed);
            refused.emplace(st["after"].get<std::size_t>(),
                            std::pair(std::move(*parsed), text(st["why"])));
        }
        std::multimap<std::size_t, nlohmann::json> runs;
        for (const auto& run : ledger["runs"]) {
            runs.emplace(run["after"].get<std::size_t>(), run);
        }

        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        // Every run at this point of the log: the same input, byte for byte
        // (key 6 of the instance view for a child), outcome, output, fuel,
        // and verdict; the output, children included, encodes back.
        auto check_runs = [&](std::size_t after) {
            const auto [first, last] = runs.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const auto& expected = it->second;
                INFO(text(expected["name"]));
                auto run = state->run_contract(provider(), by_name.at(text(expected["name"])),
                                               t0 + 1000 + after);
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
        auto check_refused = [&](std::size_t after) {
            const auto [first, last] = refused.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const auto& [statement, why] = it->second;
                INFO(why);
                const auto valid = state->validate(provider(), statement, t0 + 1000 + after);
                REQUIRE_FALSE(valid);
                CHECK(std::string(valid.error().detail).find(refusal_words(why)) !=
                      std::string::npos);
            }
        };
        for (std::size_t i = 1; i < statements.size(); ++i) {
            check_runs(i);
            check_refused(i);
            INFO(text(ledger["statements"][i]["name"]));
            const auto valid = state->validate(provider(), statements[i], t0 + 1000 + i);
            INFO((valid ? std::string() : std::string(valid.error().detail)));
            REQUIRE(valid);
            REQUIRE(state->apply(provider(), statements[i], i, t0 + 1000 + i));
        }
        check_runs(statements.size());
        check_refused(statements.size());

        // Contracts and instances, children and all, end where the
        // independent encoder says.
        for (const auto& expected : ledger["contracts"]) {
            const protocol::ContractState* contract = state->contract(id(expected["id"]));
            REQUIRE(contract != nullptr);
            CHECK(contract->retired == expected["retired"].get<bool>());
        }
        CHECK(state->instances().size() == ledger["instances"].size());
        for (const auto& expected : ledger["instances"]) {
            INFO(text(expected["id"]));
            const protocol::InstanceState* instance = state->instance(id(expected["id"]));
            REQUIRE(instance != nullptr);
            CHECK(instance->contract == id(expected["contract"]));
            CHECK(instance->head == expected["head"].get<std::uint64_t>());
            CHECK(instance->history.to_vector() ==
                  expected["history"].get<std::vector<std::uint64_t>>());
            CHECK(to_hex(*cbor::encode(instance->state)) == text(expected["state"]));
            CHECK(instance->status.has_value() == !expected["status"].is_null());
            if (instance->status) {
                CHECK(*instance->status == text(expected["status"]));
            }
            CHECK(instance->parties.size() == expected["parties"].size());
            for (const auto& [role, ledger_id] : expected["parties"].items()) {
                REQUIRE(instance->parties.contains(role));
                CHECK(instance->parties.at(role) == id(ledger_id));
            }
            CHECK(instance->final == expected["final"].get<bool>());
            CHECK(instance->depth == expected["depth"].get<std::uint32_t>());
            CHECK(instance->created_by == instance->history.front());
            if (expected["parent"].is_null()) {
                CHECK_FALSE(instance->parent);
                // Its id is its creation's statement id; a child's is not.
                CHECK(state->statement_index(id(expected["id"])) == instance->created_by);
            } else {
                REQUIRE(instance->parent);
                CHECK(instance->parent->id() == id(expected["parent"]));
                CHECK(instance->created_by == expected["created_by"].get<std::uint64_t>());
                CHECK(instance->position == expected["position"].get<std::uint32_t>());
                CHECK_FALSE(state->statement_index(id(expected["id"])));
                const auto child_id = protocol::child_instance_id(
                    provider(), hash, statements[instance->created_by].id, instance->position);
                REQUIRE(child_id);
                CHECK(*child_id == id(expected["id"]));
            }
        }

        // The replayed state has the leaves, and the root, the log commits to.
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
/// again into contract evidence with `consents` (all of them by default).
Bytes tampered(const Bytes& encoded, const std::function<void(protocol::EvidenceBundle&)>& change,
               std::optional<std::vector<Bytes>> consents = std::nullopt) {
    auto evidence = protocol::decode_contract_evidence(encoded);
    REQUIRE(evidence);
    auto bundle = protocol::decode_bundle(evidence->instance_bundle);
    REQUIRE(bundle);
    change(*bundle);
    auto again = protocol::encode_bundle(*bundle);
    REQUIRE(again);
    evidence->instance_bundle = std::move(*again);
    if (consents) {
        evidence->consent_bundles = std::move(*consents);
    }
    auto out = protocol::encode_contract_evidence(*evidence);
    REQUIRE(out);
    return *out;
}

/// Drops the bundle's entry at log index `index`.
std::function<void(protocol::EvidenceBundle&)> without_entry(std::uint64_t index) {
    return [index](protocol::EvidenceBundle& bundle) {
        const auto before = bundle.entries.size();
        std::erase_if(bundle.entries, [&](const protocol::EvidenceEntry& e) {
            return protocol::parse_receipt(e.receipt)->proof.leaf_index == index;
        });
        REQUIRE(bundle.entries.size() + 1 == before);
    };
}

} // namespace

TEST_CASE("v0.7 children: a child's contract evidence verifies, ancestors and consents included",
          "[protocol][vectors][contracts][children]") {
    const auto document = load_vectors("protocol-v0.7.json");
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

            // The calls: the ancestors' up to each creating call, then the
            // child's own, each run again, with what the contract made of it.
            std::vector<std::uint64_t> events;
            for (const auto& event : e.events) {
                events.push_back(event.index);
                CHECK(event.contract_call);
                CHECK(event.outcome);
            }
            CHECK(events == expected["events"].get<std::vector<std::uint64_t>>());
            REQUIRE(report->steps.size() == events.size());

            // The chain of ancestors, oldest first.
            CHECK(i.depth == expected["depth"].get<std::uint32_t>());
            const auto& ancestors = expected["ancestors"];
            REQUIRE(i.ancestors.size() == ancestors.size());
            CHECK(i.parent.has_value() == !ancestors.empty());
            for (std::size_t a = 0; a < ancestors.size(); ++a) {
                const protocol::AncestorReport& ancestor = i.ancestors[a];
                CHECK(ancestor.id == id(ancestors[a]["id"]));
                CHECK(ancestor.depth == a);
                CHECK(ancestor.until == ancestors[a]["until"].get<std::uint64_t>());
                REQUIRE_FALSE(ancestor.events.empty());
                CHECK(e.events[ancestor.events.front()].index == ancestor.created_by);
                CHECK(e.events[ancestor.events.back()].index == ancestor.until);
                // The next generation was created by the call that ends it.
                const auto next_created_by =
                    a + 1 < ancestors.size() ? i.ancestors[a + 1].created_by : i.created_by;
                CHECK(ancestor.until == next_created_by);
                CHECK(ancestor.parent.has_value() == (a > 0));
            }
            if (!ancestors.empty()) {
                CHECK(*i.parent == i.ancestors.back().id);
            }
            REQUIRE(i.first_own_event < e.events.size());
            CHECK(e.events[i.first_own_event].index == i.created_by);

            // Every pinned consent is checked against the call citing it, an
            // ancestor's call included.
            std::size_t consents = 0;
            for (const auto& step : report->steps) {
                consents += step.consents.size();
                for (const auto& c : step.consents) {
                    CHECK(c.report.complete);
                    CHECK(c.consent.instance == *e.events[step.event].contract_call->instance);
                }
            }
            CHECK(consents == expected["pins"].size());
            if (ancestors.empty()) {
                continue;
            }

            // A missing ancestor call breaks the chain of heads: the call
            // that follows it, or the one that created the next generation,
            // no longer replays. So does a missing creation of an ancestor.
            const auto first_call = i.ancestors.front().until;
            CHECK_FALSE(protocol::verify_contract_evidence(
                provider(), tampered(encoded, without_entry(first_call)), options));
            CHECK_FALSE(protocol::verify_contract_evidence(
                provider(), tampered(encoded, without_entry(i.ancestors.front().created_by)),
                options));
            // Without its state proofs it proves no state.
            CHECK_FALSE(protocol::verify_contract_evidence(
                provider(),
                tampered(encoded, [](protocol::EvidenceBundle& b) { b.state_proofs.clear(); }),
                options));
            // A sibling, or the parent, is not what this evidence proves:
            // their complete histories are not in it.
            for (const auto& other : ledger["instances"]) {
                const bool sibling = !other["parent"].is_null() &&
                                     id(other["parent"]) == *i.parent &&
                                     id(other["id"]) != e.record;
                if (sibling || id(other["id"]) == *i.parent) {
                    INFO(text(other["id"]));
                    CHECK_FALSE(protocol::verify_contract_evidence(
                        provider(),
                        tampered(encoded,
                                 [&](protocol::EvidenceBundle& b) { b.record = id(other["id"]); }),
                        options));
                }
            }
            // A consent an ancestor's call cites is needed, and pinned by it.
            const auto evidence = protocol::decode_contract_evidence(encoded);
            REQUIRE(evidence);
            for (std::size_t drop = 0; drop < evidence->consent_bundles.size(); ++drop) {
                std::vector<Bytes> fewer = evidence->consent_bundles;
                fewer.erase(fewer.begin() + static_cast<std::ptrdiff_t>(drop));
                CHECK_FALSE(protocol::verify_contract_evidence(
                    provider(),
                    tampered(encoded, [](protocol::EvidenceBundle&) {}, fewer), options));
            }
            CHECK(protocol::verify_contract_evidence(
                provider(), tampered(encoded, [](protocol::EvidenceBundle&) {}), options));
        }
    }
}

namespace {

const protocol::Id home_ledger = *protocol::to_id(Bytes(32, 0x5A));

/// An accept output of `state` with `children`, as a contract writes it.
Bytes accept_with(cbor::Value state, std::vector<cbor::Value> children) {
    cbor::Map accept{{cbor::Value::unsigned_integer(1), std::move(state)}};
    if (!children.empty()) {
        accept.push_back(
            {cbor::Value::unsigned_integer(6), cbor::Value::array(std::move(children))});
    }
    auto encoded = cbor::encode(cbor::Value::array(
        {cbor::Value::unsigned_integer(1), cbor::Value::map(std::move(accept))}));
    REQUIRE(encoded);
    return *encoded;
}

cbor::Value child_map(cbor::Map fields) {
    return cbor::Value::map(std::move(fields));
}

cbor::MapEntry field(std::uint64_t key, cbor::Value value) {
    return {cbor::Value::unsigned_integer(key), std::move(value)};
}

/// A byte string of `size` bytes encoded (head included).
cbor::Value state_of_size(std::size_t size) {
    REQUIRE(size > 3);
    REQUIRE(size - 3 < 65'536);
    return cbor::Value::bytes(Bytes(size - 3, 0xAB));
}

} // namespace

TEST_CASE("v0.7 children: the limits of an output, which the vectors' contracts cannot reach",
          "[protocol][contracts][children]") {
    // The vectors' contracts write what their arguments hold, which are at
    // most 65,536 bytes encoded: a child's state cannot reach its own limit.
    REQUIRE(cbor::encode(state_of_size(65'536))->size() == 65'536);
    const auto decoded = protocol::decode_contract_output(
        accept_with(cbor::Value::null(), {child_map({field(1, state_of_size(65'536))})}),
        home_ledger);
    REQUIRE(decoded);
    const auto& accept = std::get<protocol::ContractAccept>(*decoded);
    REQUIRE(accept.children.size() == 1);
    CHECK(accept.children[0].state == state_of_size(65'536));
    CHECK_FALSE(accept.children[0].status);
    CHECK(accept.children[0].parties.empty());
    const auto over = protocol::decode_contract_output(
        accept_with(cbor::Value::null(), {child_map({field(1, state_of_size(65'537))})}),
        home_ledger);
    REQUIRE_FALSE(over);
    CHECK(over.error().code == cexchain::Errc::malformed);
    // The parent's state has the same limit, children or not.
    CHECK_FALSE(protocol::decode_contract_output(
        accept_with(state_of_size(65'537), {child_map({field(1, cbor::Value::null())})}),
        home_ledger));

    // Sixteen children at their limits of status and parties encode back to
    // the same bytes; a 17th, a 65th party, or a 65-byte status does not
    // decode.
    // 64 roles of 64 bytes each (encode sorts them).
    cbor::Map parties;
    for (std::uint8_t n = 0; n < 64; ++n) {
        std::string role(62, 'r');
        role += static_cast<char>('a' + n / 26);
        role += static_cast<char>('a' + n % 26);
        parties.push_back({cbor::Value::text(role), cbor::Value::bytes(Bytes(32, n))});
    }
    auto child = [&](std::size_t status_size, std::size_t party_count) {
        cbor::Map these = parties;
        these.resize(std::min(party_count, parties.size()));
        if (party_count > parties.size()) {
            these.push_back({cbor::Value::text("zz"), cbor::Value::bytes(Bytes(32, 0xFF))});
        }
        return child_map({field(1, cbor::Value::unsigned_integer(status_size)),
                          field(2, cbor::Value::text(std::string(status_size, 's'))),
                          field(3, cbor::Value::map(std::move(these)))});
    };
    std::vector<cbor::Value> sixteen(16, child(64, 64));
    const Bytes full = accept_with(cbor::Value::null(), sixteen);
    const auto sixteen_decoded = protocol::decode_contract_output(full, home_ledger);
    REQUIRE(sixteen_decoded);
    CHECK(std::get<protocol::ContractAccept>(*sixteen_decoded).children.size() == 16);
    CHECK(std::get<protocol::ContractAccept>(*sixteen_decoded).children[15].parties.size() == 64);
    CHECK(*protocol::encode_contract_output(*sixteen_decoded) == full);
    std::vector<cbor::Value> seventeen(17, child(64, 64));
    CHECK_FALSE(
        protocol::decode_contract_output(accept_with(cbor::Value::null(), seventeen), home_ledger));
    CHECK_FALSE(protocol::decode_contract_output(accept_with(cbor::Value::null(), {child(65, 1)}),
                                                 home_ledger));
    CHECK_FALSE(protocol::decode_contract_output(accept_with(cbor::Value::null(), {child(0, 1)}),
                                                 home_ledger));
    CHECK_FALSE(protocol::decode_contract_output(accept_with(cbor::Value::null(), {child(1, 65)}),
                                                 home_ledger));
    // A child holds only keys 1 to 3: no events, no finality, no other key.
    for (const std::uint64_t extra : {0U, 4U, 5U, 7U}) {
        cbor::Map fields{field(1, cbor::Value::null()), field(extra, cbor::Value::boolean(true))};
        CHECK_FALSE(protocol::decode_contract_output(
            accept_with(cbor::Value::null(), {child_map(std::move(fields))}), home_ledger));
    }
    CHECK_FALSE(protocol::decode_contract_output(
        accept_with(cbor::Value::null(),
                    {child_map({field(1, cbor::Value::null()),
                                {cbor::Value::text("a"), cbor::Value::null()}})}),
        home_ledger));

    // A child's id is HASH([call, position]) under the home's hash: one per
    // position, never the call's own id.
    const protocol::Id call = *protocol::to_id(Bytes(32, 0x22));
    for (const auto hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
        std::vector<protocol::Id> ids;
        for (std::uint64_t position = 0; position < protocol::max_contract_children; ++position) {
            const auto child_id = protocol::child_instance_id(provider(), hash, call, position);
            REQUIRE(child_id);
            CHECK_FALSE(*child_id == call);
            CHECK_FALSE(std::ranges::contains(ids, *child_id));
            ids.push_back(*child_id);
        }
        CHECK(*protocol::child_instance_id(provider(), hash, call, 0) ==
              *provider().digest(hash, hex("825820" + to_hex(call.bytes()) + "00")));
    }

    // The input shows a child its parent and depth (view key 6), and other
    // instances nothing new.
    protocol::ContractInput input;
    input.function = "f";
    input.arguments = cbor::Value::null();
    input.home = home_ledger;
    input.contract = call;
    input.caller = call;
    input.instance =
        protocol::ContractInstanceView{call, 7, cbor::Value::null(), std::nullopt, {}, {}, 0};
    const auto without = cbor::decode(*protocol::encode_contract_input(input));
    REQUIRE(without);
    input.instance->parent = home_ledger;
    input.instance->depth = 8;
    const auto with = cbor::decode(*protocol::encode_contract_input(input));
    REQUIRE(with);
    auto view = [](const cbor::Value& value) -> const cbor::Map& {
        for (const auto& e : *value.as_map()) {
            if (e.key.as_uint64() == 5U) {
                return *e.value.as_map();
            }
        }
        FAIL("no instance view");
        throw std::logic_error("unreachable");
    };
    CHECK(view(*without).size() == 3);
    REQUIRE(view(*with).size() == 4);
    CHECK(*cbor::encode(view(*with).back().value) ==
          *cbor::encode(cbor::Value::array(
              {cbor::Value::bytes(home_ledger.bytes()), cbor::Value::unsigned_integer(8)})));
}
