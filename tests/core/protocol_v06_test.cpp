// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.6 (contracts) against objects built by an independent Python
// encoder and run by the reference interpreter (tools/testvectors/).

#include <map>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contracts.hpp>
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

} // namespace

TEST_CASE("v0.6 contracts from an independent encoder and interpreter",
          "[protocol][vectors][contracts]") {
    const auto document = load_vectors("protocol-v0.6.json");
    const auto t0 = document["t0"].get<protocol::Timestamp>();
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));

        std::vector<protocol::SignedStatement> statements;
        std::map<std::string, protocol::SignedStatement> by_name;
        for (const auto& st : ledger["statements"]) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            CHECK(to_hex(parsed->id.bytes()) == text(st["statement_id"]));
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            by_name.emplace(text(st["name"]), *parsed);
            statements.push_back(std::move(*parsed));
        }
        // Refused statements either break the CDDL, and do not parse, or the
        // rules refuse them at their place in the log.
        std::multimap<std::size_t, protocol::SignedStatement> refused;
        for (const auto& st : ledger["refused"]) {
            INFO(text(st["name"]));
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            if (st["malformed"].get<bool>()) {
                CHECK_FALSE(parsed);
                continue;
            }
            REQUIRE(parsed);
            CHECK(*protocol::encode_payload(parsed->statement) == hex(text(st["payload"])));
            by_name.emplace(text(st["name"]), *parsed);
            refused.emplace(st["after"].get<std::size_t>(), std::move(*parsed));
        }
        std::multimap<std::size_t, nlohmann::json> runs;
        for (const auto& run : ledger["runs"]) {
            runs.emplace(run["after"].get<std::size_t>(), run);
        }

        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        // Every contract run at this point of the log: the same input, byte
        // for byte, the same outcome, output, and fuel, and the same verdict.
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
                const auto valid = state->validate(provider(), it->second, t0 + 1000 + after);
                INFO(protocol::name(it->second.statement.type()));
                CHECK_FALSE(valid);
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

        // Contracts and instances end where the independent encoder says,
        // and the state tree holds them.
        for (const auto& expected : ledger["contracts"]) {
            const protocol::ContractState* contract = state->contract(id(expected["id"]));
            REQUIRE(contract != nullptr);
            CHECK(contract->retired == expected["retired"].get<bool>());
            const auto leaf = protocol::state_leaf(*state, id(expected["id"]));
            REQUIRE(leaf);
            CHECK(leaf->kind == protocol::ObjectKind::contract);
        }
        for (const auto& expected : ledger["instances"]) {
            const protocol::InstanceState* instance = state->instance(id(expected["id"]));
            REQUIRE(instance != nullptr);
            CHECK(instance->contract == id(expected["contract"]));
            CHECK(instance->head == expected["head"].get<std::uint64_t>());
            CHECK(to_hex(instance->state.bytes()) == text(expected["state"]));
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
            const auto leaf = protocol::state_leaf(*state, id(expected["id"]));
            REQUIRE(leaf);
            CHECK(leaf->kind == protocol::ObjectKind::instance);
            CHECK(leaf->history.back() == instance->head);
        }

        // Consent metadata decodes and re-encodes byte for byte; the calls
        // that cite a consent carry its terms and claim its signer.
        for (const auto& c : ledger["consents"]) {
            const Bytes metadata = hex(text(c["metadata"]));
            auto value = cbor::decode(metadata);
            REQUIRE(value);
            auto consent = protocol::decode_contract_consent(*value);
            REQUIRE(consent);
            CHECK(consent->ledger == state->ledger_id());
            CHECK(*cbor::encode(*protocol::encode_contract_consent(*consent)) == metadata);
            CHECK(to_hex(provider().digest(hash, hex(text(c["bundle"])))->bytes()) ==
                  text(c["bundle_hash"]));
            for (const auto& st : statements) {
                const auto* call = std::get_if<protocol::ContractCallBody>(&st.statement.body);
                if (call == nullptr) {
                    continue;
                }
                for (const auto& ref : call->consents) {
                    if (to_hex(ref.record.bytes()) != text(c["record"])) {
                        continue;
                    }
                    const auto digest =
                        protocol::contract_arguments_digest(provider(), hash, call->arguments);
                    REQUIRE(digest);
                    CHECK(protocol::consent_matches(*consent, state->ledger_id(), *call, *digest));
                    CHECK(to_hex(*cbor::encode(protocol::encode_contract_signer(ref.signer))) ==
                          text(c["signer"]));
                }
            }
        }
    }
}

TEST_CASE("v0.6 contracts: a call runs once, its validation reused only where it holds",
          "[protocol][vectors][contracts]") {
    // validate() keeps a call's accepted run for apply(), which takes it only
    // for the same statement, at the same time, on the same state (a copy
    // counts; any change since does not); otherwise the call runs again.
    const auto document = load_vectors("protocol-v0.6.json");
    const auto t0 = document["t0"].get<protocol::Timestamp>();
    const auto same_run = [](const protocol::ContractRun& a, const protocol::ContractRun& b) {
        return a.input == b.input && a.outcome.trap == b.outcome.trap &&
               a.outcome.output == b.outcome.output && a.outcome.fuel_used == b.outcome.fuel_used;
    };
    std::size_t calls = 0;
    for (const auto& ledger : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        std::vector<protocol::SignedStatement> statements;
        for (const auto& st : ledger["statements"]) {
            statements.push_back(
                *protocol::parse_statement(provider(), hex(text(st["encoded"])), hash));
        }
        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        auto plain = *state; // replayed without validations, for comparison
        for (std::size_t i = 1; i < statements.size(); ++i) {
            INFO(i);
            const protocol::SignedStatement& s = statements[i];
            const protocol::Timestamp at = t0 + 1000 + i;
            const bool is_call =
                std::holds_alternative<protocol::ContractCallBody>(s.statement.body);
            protocol::Validation validation;
            REQUIRE(state->validate(provider(), s, at, nullptr, &validation));
            REQUIRE((validation.run() != nullptr) == is_call);
            if (is_call) {
                ++calls;
                CHECK(same_run(*validation.run(), *state->run_contract(provider(), s, at)));

                // Another time, another statement id, or a state changed
                // since: run again. A copy of the state: reused.
                auto other = *state;
                protocol::Validation v;
                REQUIRE(state->validate(provider(), s, at, nullptr, &v));
                (void)other.apply(provider(), s, i, at + 1, &v);
                CHECK_FALSE(v.reused());
                CHECK(v.run() == nullptr);

                other = *state;
                REQUIRE(state->validate(provider(), s, at, nullptr, &v));
                protocol::SignedStatement renamed = s;
                renamed.id = statements.front().id;
                (void)other.apply(provider(), renamed, i, at, &v);
                CHECK_FALSE(v.reused());

                other = *state;
                REQUIRE(other.validate(provider(), s, at, nullptr, &v));
                REQUIRE(other.apply(provider(), s, i, at));
                (void)other.apply(provider(), s, i, at, &v);
                CHECK_FALSE(v.reused());

                other = *state;
                REQUIRE(state->validate(provider(), s, at, nullptr, &v));
                auto moved = std::move(other);
                CHECK(moved.apply(provider(), s, i, at, &v));
                CHECK(v.reused());
            }
            REQUIRE(state->apply(provider(), s, i, at, &validation));
            CHECK(validation.reused() == is_call);
            CHECK(validation.run() == nullptr);
            REQUIRE(plain.validate(provider(), s, at));
            REQUIRE(plain.apply(provider(), s, i, at));
        }
        for (const auto& [key, instance] : state->instances()) {
            const protocol::InstanceState* expected = plain.instance(instance.id);
            REQUIRE(expected != nullptr);
            CHECK(instance.head == expected->head);
            CHECK(instance.state == expected->state);
        }
    }
    CHECK(calls > 0);
}
