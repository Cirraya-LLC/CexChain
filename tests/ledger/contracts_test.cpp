// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Contracts across three ledgers (spec section 15): a home deploys a
// contract, proposes an agreement, and records it as effective once the
// supplier and the bank consent on their own ledgers; anyone then verifies
// the instance offline, the contract run again included.

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>

#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

/// The vectors' test contract: it outputs the content of byte-string
/// arguments, aborts with text arguments, and otherwise accepts with
/// HASH(input) as the state.
Bytes oracle() {
    return hex(load_vectors("protocol-v0.6.json")["contract"].get<std::string>());
}

/// Arguments that make the oracle write `output`.
cbor::Value arguments_for(const protocol::ContractOutput& output) {
    auto encoded = protocol::encode_contract_output(output);
    REQUIRE(encoded);
    return cbor::Value::bytes(*encoded);
}

protocol::ContractAccept accept(std::string status, std::optional<protocol::Parties> parties = {}) {
    return {*cbor::Encoded::encode(cbor::Value::text("state: " + status)),
            status,
            std::move(parties),
            {},
            false,
            {},
            {}};
}

const protocol::Nonce salt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

struct Deal {
    World home{crypto::HashAlg::sha256, "Core Enterprise"};
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    protocol::Id contract;
    protocol::Id instance;

    Deal() {
        protocol::ContractDeployBody deploy;
        deploy.code = oracle();
        deploy.interface = {{"propose", protocol::FunctionKind::create},
                            {"sign", protocol::FunctionKind::call},
                            {"close", protocol::FunctionKind::call}};
        deploy.language = "wasm";
        deploy.compiler = "hand-assembled 1";
        deploy.name = "Supply agreement";
        contract = home.ok(home.org(), home.statement(home.org_id(), std::nullopt, deploy));
        instance =
            home.ok(home.org(),
                    home.statement(home.org_id(), std::nullopt,
                                   create(arguments_for(accept(
                                       "proposed", protocol::Parties{{"supplier", supplier_id()},
                                                                     {"bank", bank_id()}})))));
    }

    const protocol::Id& supplier_id() { return supplier.ledger().id(); }
    const protocol::Id& bank_id() { return bank.ledger().id(); }
    const protocol::InstanceState& state() {
        const auto* i = home.ledger().state().instance(instance);
        REQUIRE(i != nullptr);
        return *i;
    }

    protocol::ContractCallBody create(cbor::Value arguments) {
        protocol::ContractCallBody b;
        b.contract = contract;
        b.function = "propose";
        b.arguments = std::move(arguments);
        return b;
    }

    protocol::ContractCallBody call(std::string function, cbor::Value arguments) {
        protocol::ContractCallBody b;
        b.instance = instance;
        b.function = std::move(function);
        b.arguments = std::move(arguments);
        b.head = state().head;
        return b;
    }

    /// `party`'s organization consents to `b` on its own ledger; the
    /// citation claims `signer`. Returns the bundle.
    Bytes consent(World& party, protocol::ContractCallBody& b, const std::string& function,
                  protocol::ContractSigner signer = {}) {
        auto digest = protocol::contract_arguments_digest(provider(), home.hash(), b.arguments);
        REQUIRE(digest);
        auto metadata =
            protocol::encode_contract_consent({home.ledger().id(), instance, function, *digest,
                                               *b.head, t0 + 30 * day, std::nullopt});
        REQUIRE(metadata);
        auto commitment = protocol::commit_fields(provider(), party.hash(),
                                                  {{"terms", salt, cbor::Value::text("ok")}});
        REQUIRE(commitment);
        const protocol::Id record =
            party.ok(party.org(), party.statement(party.org_id(), std::nullopt,
                                                  protocol::RecordRegisterBody{
                                                      std::string(protocol::contract_consent_type),
                                                      Bytes(commitment->root.bytes().begin(),
                                                            commitment->root.bytes().end()),
                                                      1,
                                                      {},
                                                      std::move(*metadata)}));
        REQUIRE(party.ledger().checkpoint(party.log_key()));
        auto bundle = party.ledger().export_evidence(party.log_key(), record);
        REQUIRE(bundle);
        auto encoded = protocol::encode_bundle(*bundle);
        REQUIRE(encoded);
        auto pin = provider().digest(home.hash(), *encoded);
        REQUIRE(pin);
        b.consents.push_back({party.ledger().id(), record, *pin, signer});
        std::ranges::sort(b.consents, [](const auto& x, const auto& y) {
            return std::ranges::lexicographical_compare(x.ledger.bytes(), y.ledger.bytes());
        });
        return *encoded;
    }

    cexchain::Result<ledger::Registration> submit(const protocol::ContractCallBody& b) {
        auto r = home.submit(home.org(), home.statement(home.org_id(), std::nullopt, b));
        home.clock().advance(1000);
        return r;
    }

    Bytes evidence(std::vector<Bytes> consents, bool complete = true) {
        REQUIRE(home.ledger().checkpoint(home.log_key()));
        auto bundle = home.ledger().export_evidence(home.log_key(), instance);
        REQUIRE(bundle);
        if (!complete) {
            bundle->state_proofs.clear();
        }
        auto instance_bundle = protocol::encode_bundle(*bundle);
        REQUIRE(instance_bundle);
        auto encoded = protocol::encode_contract_evidence({*instance_bundle, std::move(consents)});
        REQUIRE(encoded);
        return *encoded;
    }

    cexchain::Result<protocol::ContractReport> verify(const Bytes& evidence) {
        protocol::VerifyOptions options;
        options.expected_ledger = home.ledger().id();
        return protocol::verify_contract_evidence(provider(), evidence, options);
    }
};

} // namespace

TEST_CASE("an agreement takes effect with both parties' consents and verifies offline",
          "[contracts]") {
    Deal d;
    CHECK(d.state().status == "proposed");
    CHECK(d.state().parties.size() == 2);

    // Asked first without consents, the contract names whose it needs.
    protocol::ContractNeeds needs{{d.supplier_id(), d.bank_id()}};
    std::ranges::sort(needs.ledgers, [](const auto& x, const auto& y) {
        return std::ranges::lexicographical_compare(x.bytes(), y.bytes());
    });
    auto ask = d.call("sign", arguments_for(needs));
    auto signed_ask =
        protocol::sign_statement(d.home.org(), provider(), d.home.hash(),
                                 d.home.statement(d.home.org_id(), std::nullopt, ask));
    REQUIRE(signed_ask);
    auto run = d.home.ledger().state().run_contract(provider(), *signed_ask, d.home.clock().now());
    REQUIRE(run);
    REQUIRE(run->output);
    CHECK(std::get<protocol::ContractNeeds>(*run->output) == needs);
    CHECK(d.home.rejected(d.home.org(), d.home.statement(d.home.org_id(), std::nullopt, ask)) ==
          Errc::rejected);

    // Both consent; the call is recorded, and the agreement is effective.
    auto sign = d.call("sign", arguments_for(accept("effective")));
    std::vector<Bytes> bundles{d.consent(d.supplier, sign, "sign"),
                               d.consent(d.bank, sign, "sign")};
    REQUIRE(d.submit(sign));
    CHECK(d.state().status == "effective");
    CHECK(d.state().parties.size() == 2);

    auto report = d.verify(d.evidence(bundles));
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    CHECK(report->instance.complete);
    REQUIRE(report->instance.instance);
    CHECK(report->instance.instance->status == "effective");
    CHECK(report->instance.instance->contract == d.contract);
    CHECK(report->instance.instance->contract_name == "Supply agreement");
    REQUIRE(report->instance.events.size() == 2);
    REQUIRE(report->instance.events[0].outcome);
    CHECK(report->instance.events[0].outcome->status == "proposed");
    CHECK(report->instance.events[1].detail == "sign");
    REQUIRE(report->steps.size() == 2);
    REQUIRE(report->steps[1].consents.size() == 2);
    for (const auto& c : report->steps[1].consents) {
        CHECK(c.report.complete);
    }

    // Without both consent bundles, or with an extra one, it fails.
    CHECK_FALSE(d.verify(d.evidence({bundles[0]})));
    CHECK_FALSE(d.verify(d.evidence({bundles[0], bundles[1], bundles[0]})));
    // Incomplete instance evidence proves no state.
    CHECK_FALSE(d.verify(d.evidence(bundles, false)));
}

TEST_CASE("a call that misstates a consent's signer fails verification", "[contracts]") {
    Deal d;
    auto sign = d.call("sign", arguments_for(accept("effective")));
    // The supplier's organization signed its consent, but the call claims a
    // person who proved presence with a passkey.
    const Bytes bundle = d.consent(d.supplier, sign, "sign",
                                   {static_cast<std::uint8_t>(protocol::ActorKind::person),
                                    protocol::PresenceMethod::webauthn, std::nullopt});
    // The home's ledger cannot tell (the bundle is not in its log)...
    REQUIRE(d.submit(sign));
    // ...but every verifier holding the evidence can.
    auto report = d.verify(d.evidence({bundle}));
    REQUIRE_FALSE(report);
    CHECK(report.error().code == Errc::verification_failed);
}

TEST_CASE("a consent to other terms fails verification", "[contracts]") {
    Deal d;
    auto sign = d.call("sign", arguments_for(accept("effective")));
    // The supplier consented to closing, not signing.
    const Bytes bundle = d.consent(d.supplier, sign, "close");
    REQUIRE(d.submit(sign));
    CHECK_FALSE(d.verify(d.evidence({bundle})));
}

TEST_CASE("contracts are retired, instances become final, and a reopened ledger agrees",
          "[contracts]") {
    Deal d;
    // A delegation limited to another contract does not cover this one.
    const auto clerk_key = key("clerk");
    const protocol::Id clerk = d.home.register_actor(d.home.org(), d.home.org_id(), std::nullopt,
                                                     protocol::ActorKind::person, clerk_key);
    auto limited = scope({StatementType::contract_call, StatementType::contract_retire});
    limited.contracts = std::vector<protocol::Id>{d.instance}; // not a contract
    const protocol::Id grant =
        d.home.grant(d.home.org(), d.home.org_id(), std::nullopt, clerk, limited);
    auto close = d.call("close", arguments_for(protocol::ContractAccept{
                                     cbor::Encoded(), "closed", std::nullopt, {}, true, {}, {}}));
    CHECK(d.home.rejected(clerk_key, d.home.statement(clerk, grant, close)) == Errc::rejected);

    // The organization retires the contract: no new instances, but the
    // agreement carries on, and closes.
    d.home.ok(d.home.org(), d.home.statement(d.home.org_id(), std::nullopt,
                                             protocol::ContractRetireBody{d.contract, "v2"}));
    CHECK(d.home.rejected(d.home.org(), d.home.statement(d.home.org_id(), std::nullopt,
                                                         d.create(cbor::Value::null()))) ==
          Errc::rejected);
    REQUIRE(d.submit(close));
    CHECK(d.state().final);
    CHECK(d.home.rejected(d.home.org(), d.home.statement(d.home.org_id(), std::nullopt,
                                                         d.call("close", cbor::Value::null()))) ==
          Errc::rejected);

    auto report = d.verify(d.evidence({}));
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    CHECK(report->instance.instance->final);
    CHECK(report->instance.instance->contract_retired);
    CHECK(report->instance.state == "closed");

    // Replayed from storage, the contract runs again to the same instance.
    const protocol::InstanceState before = d.state();
    auto reopened = ledger::Ledger::open(d.home.fs(), d.home.clock(), provider());
    REQUIRE(reopened);
    const auto* after = reopened->state().instance(d.instance);
    REQUIRE(after != nullptr);
    CHECK(after->state == before.state);
    CHECK(after->status == before.status);
    CHECK(after->final);
    CHECK(after->head == before.head);
}
