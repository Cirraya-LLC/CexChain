// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Instances created by a call (spec v0.7) on real ledgers: a receivable split
// across three ledgers, its holders consenting on their own, and a tier-3
// part verified offline with its ancestors' calls and consents; and the
// home's evidence for a child, exported from a copy of the vectors' log,
// equal byte for byte to the independent encoder's.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>

#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

protocol::Id id_of(const nlohmann::json& value) {
    return *protocol::to_id(hex_field(value));
}

const nlohmann::json& test_contracts() {
    static const nlohmann::json document = load_vectors("test-contracts.json");
    return document;
}

cbor::Value ledger_value(const protocol::Id& ledger) {
    return cbor::Value::bytes(ledger.bytes());
}

/// The splitting contract's arguments for `split`: [[ledger, amount], ...].
cbor::Value parts(const std::vector<std::pair<protocol::Id, std::uint64_t>>& list) {
    cbor::Array items;
    for (const auto& [ledger, amount] : list) {
        items.push_back(
            cbor::Value::array({ledger_value(ledger), cbor::Value::unsigned_integer(amount)}));
    }
    return cbor::Value::array(std::move(items));
}

const protocol::Nonce salt{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};

/// A home that deploys the splitting contract of testvectors/test-contracts.json
/// (a receivable [amount, tier] held by {holder}; issue, split, transfer; the
/// holder consents to splits and transfers unless it is the home), and two
/// parties: a supplier (SHA-256) and a bank (SM3).
struct Chain {
    World home;
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    protocol::Id contract;

    explicit Chain(crypto::HashAlg home_hash) : home(home_hash, "Core Enterprise") {
        protocol::ContractDeployBody deploy;
        deploy.code = hex_field(test_contracts()["split"]);
        for (const auto& [name, kind] : test_contracts()["split_interface"].items()) {
            deploy.interface.emplace(name, static_cast<protocol::FunctionKind>(kind.get<int>()));
        }
        deploy.language = "wasm";
        deploy.compiler = "hand-assembled 1";
        deploy.name = "Receivable";
        contract = home.ok(home.org(), home.statement(home.org_id(), std::nullopt, deploy));
    }

    const protocol::InstanceState& instance(const protocol::Id& id) {
        const auto* i = home.ledger().state().instance(id);
        REQUIRE(i != nullptr);
        return *i;
    }

    protocol::Id issue(const protocol::Id& holder, std::uint64_t amount) {
        protocol::ContractCallBody b;
        b.contract = contract;
        b.function = "issue";
        b.arguments =
            cbor::Value::array({ledger_value(holder), cbor::Value::unsigned_integer(amount)});
        return submit(b);
    }

    protocol::ContractCallBody call(const protocol::Id& id, std::string function,
                                    cbor::Value arguments) {
        protocol::ContractCallBody b;
        b.instance = id;
        b.function = std::move(function);
        b.arguments = std::move(arguments);
        b.head = instance(id).head;
        return b;
    }

    /// `party`'s organization consents to `b` on its own ledger; returns the
    /// consent's evidence bundle, which `b` now cites.
    Bytes consent(World& party, protocol::ContractCallBody& b) {
        auto digest = protocol::contract_arguments_digest(provider(), home.hash(), b.arguments);
        REQUIRE(digest);
        auto metadata = protocol::encode_contract_consent(
            {home.ledger().id(), *b.instance, b.function, *digest, *b.head, t0 + 30 * day,
             std::string("tier ") + std::to_string(instance(*b.instance).depth + 1)});
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
        b.consents.push_back({party.ledger().id(), record, *pin, {}});
        std::ranges::sort(b.consents, [](const auto& x, const auto& y) {
            return std::ranges::lexicographical_compare(x.ledger.bytes(), y.ledger.bytes());
        });
        return *encoded;
    }

    protocol::Id submit(const protocol::ContractCallBody& b) {
        return home.ok(home.org(), home.statement(home.org_id(), std::nullopt, b));
    }

    protocol::Id child(const protocol::Id& call, std::uint64_t position) {
        auto id = protocol::child_instance_id(provider(), home.hash(), call, position);
        REQUIRE(id);
        return *id;
    }

    Bytes evidence(const protocol::Id& id, std::vector<Bytes> consents) {
        REQUIRE(home.ledger().checkpoint(home.log_key()));
        auto bundle = home.ledger().export_evidence(home.log_key(), id);
        REQUIRE(bundle);
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

/// `evidence` with its instance bundle changed by `change`, and `consents`.
Bytes rebuilt(const Bytes& evidence, const std::function<void(protocol::EvidenceBundle&)>& change,
              std::vector<Bytes> consents) {
    auto decoded = protocol::decode_contract_evidence(evidence);
    REQUIRE(decoded);
    auto bundle = protocol::decode_bundle(decoded->instance_bundle);
    REQUIRE(bundle);
    change(*bundle);
    auto encoded_bundle = protocol::encode_bundle(*bundle);
    REQUIRE(encoded_bundle);
    auto encoded = protocol::encode_contract_evidence({*encoded_bundle, std::move(consents)});
    REQUIRE(encoded);
    return *encoded;
}

std::uint64_t leaf_index(const protocol::EvidenceEntry& e) {
    auto receipt = protocol::parse_receipt(e.receipt);
    REQUIRE(receipt);
    return receipt->proof.leaf_index;
}

} // namespace

TEST_CASE("a receivable splits across three ledgers, and a tier-3 part verifies offline",
          "[contracts][children]") {
    const auto home_hash = GENERATE(crypto::HashAlg::sha256, crypto::HashAlg::sm3);
    INFO(crypto::name(home_hash));
    Chain c(home_hash);
    const protocol::Id& supplier = c.supplier.ledger().id();
    const protocol::Id& bank = c.bank.ledger().id();

    // The home issues a receivable to itself and transfers it to the
    // supplier (the home holds it: no consent).
    const protocol::Id r = c.issue(c.home.org_id(), 1000);
    const protocol::Id transfer_r = c.submit(c.call(r, "transfer", ledger_value(supplier)));
    CHECK(c.instance(r).parties.at("holder") == supplier);

    // Splitting needs the holder's consent; with it, the receivable ends and
    // its parts are children at depth 1, tier 2.
    auto split_r = c.call(r, "split", parts({{supplier, 600}, {bank, 400}}));
    CHECK(c.home.rejected(c.home.org(), c.home.statement(c.home.org_id(), std::nullopt, split_r)) ==
          Errc::rejected);
    const Bytes supplier_splits_r = c.consent(c.supplier, split_r);
    const protocol::Id split_r_id = c.submit(split_r);
    const protocol::Id a = c.child(split_r_id, 0);
    const protocol::Id b = c.child(split_r_id, 1);
    CHECK(c.instance(r).final);
    CHECK(c.instance(r).status == "split");
    CHECK(c.instance(a).depth == 1);
    CHECK(c.instance(b).position == 1);
    CHECK(c.instance(b).parties.at("holder") == bank);
    CHECK(c.instance(a).parent->id() == r);
    CHECK_FALSE(c.home.ledger().state().statement_index(a));
    const std::uint64_t split_r_index = c.instance(a).created_by;
    CHECK(c.instance(r).head == split_r_index);
    CHECK(c.instance(a).history.to_vector() == std::vector<std::uint64_t>{split_r_index});
    CHECK(c.instance(a).state ==
          *cbor::Encoded::encode(cbor::Value::array(
              {cbor::Value::unsigned_integer(600), cbor::Value::unsigned_integer(2)})));
    // A final parent takes no more calls.
    CHECK(c.home.rejected(c.home.org(),
                          c.home.statement(c.home.org_id(), std::nullopt,
                                           c.call(r, "transfer", ledger_value(bank)))) ==
          Errc::rejected);

    // The contract sees a child's parent and depth (instance view key 6).
    auto split_a = c.call(a, "split", parts({{supplier, 450}, {bank, 150}}));
    {
        auto signed_call =
            protocol::sign_statement(c.home.org(), provider(), c.home.hash(),
                                     c.home.statement(c.home.org_id(), std::nullopt, split_a));
        REQUIRE(signed_call);
        auto run =
            c.home.ledger().state().run_contract(provider(), *signed_call, c.home.clock().now());
        REQUIRE(run);
        auto input = cbor::decode(run->input);
        REQUIRE(input);
        const cbor::Value* view = nullptr;
        for (const auto& e : *input->as_map()) {
            if (e.key.as_uint64() == 5U) {
                view = &e.value;
            }
        }
        REQUIRE(view != nullptr);
        CHECK(
            *cbor::encode(view->as_map()->back().value) ==
            *cbor::encode(cbor::Value::array({ledger_value(r), cbor::Value::unsigned_integer(1)})));
    }
    // A part splits again: tier 3, depth 2.
    const Bytes supplier_splits_a = c.consent(c.supplier, split_a);
    const protocol::Id split_a_id = c.submit(split_a);
    const protocol::Id a0 = c.child(split_a_id, 0);
    const protocol::Id a1 = c.child(split_a_id, 1);
    CHECK(c.instance(a1).depth == 2);
    CHECK(c.instance(a1).parent->id() == a);

    // The bank, on SM3, consents to transferring its tier-3 part.
    auto transfer_a1 = c.call(a1, "transfer", ledger_value(supplier));
    const Bytes bank_transfers_a1 = c.consent(c.bank, transfer_a1);
    c.submit(transfer_a1);
    CHECK(c.instance(a1).parties.at("holder") == supplier);

    // Its evidence verifies offline: the receivable's calls up to its split,
    // the part's up to its split, then its own, with every consent.
    const std::vector<Bytes> consents{supplier_splits_r, supplier_splits_a, bank_transfers_a1};
    const Bytes evidence = c.evidence(a1, consents);
    auto report = c.verify(evidence);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    const protocol::EvidenceReport& e = report->instance;
    CHECK(e.complete);
    REQUIRE(e.instance);
    const protocol::InstanceReport& i = *e.instance;
    CHECK(i.depth == 2);
    CHECK(i.parent == a);
    CHECK(i.position == 1);
    CHECK(i.parties.at("holder") == supplier);
    CHECK(i.state == *cbor::Encoded::encode(cbor::Value::array(
                         {cbor::Value::unsigned_integer(150), cbor::Value::unsigned_integer(3)})));
    REQUIRE(i.ancestors.size() == 2);
    CHECK(i.ancestors[0].id == r);
    CHECK(i.ancestors[0].depth == 0);
    CHECK(i.ancestors[0].events.size() == 3); // issue, transfer, split
    CHECK(i.ancestors[1].id == a);
    CHECK(i.ancestors[1].parent == r);
    CHECK(i.ancestors[1].events.size() == 2); // created by the split, split
    REQUIRE(e.events.size() == 5);
    CHECK(e.events[0].detail == "issue");
    CHECK(e.events[1].detail == "transfer");
    CHECK(e.events[2].outcome->children.size() == 2);
    CHECK(e.events[i.first_own_event].index == i.created_by);
    CHECK(e.events.back().detail == "transfer");
    REQUIRE(report->steps.size() == 5);
    CHECK(report->steps[2].consents.size() == 1);
    CHECK(report->steps[2].consents[0].report.hash == crypto::HashAlg::sha256);
    CHECK(report->steps[4].consents[0].report.hash == crypto::HashAlg::sm3);

    // Its sibling's evidence needs only the consents to the splits.
    CHECK(c.verify(c.evidence(a0, {supplier_splits_r, supplier_splits_a})));
    CHECK_FALSE(c.verify(c.evidence(a0, consents)));

    // Every consent is needed, the ancestors' too; and every ancestor call:
    // without the receivable's transfer, its split no longer follows its
    // head.
    for (std::size_t drop = 0; drop < consents.size(); ++drop) {
        std::vector<Bytes> fewer = consents;
        fewer.erase(fewer.begin() + static_cast<std::ptrdiff_t>(drop));
        CHECK_FALSE(c.verify(rebuilt(evidence, [](protocol::EvidenceBundle&) {}, fewer)));
    }
    const std::uint64_t transfer_index = *c.home.ledger().statement_index(transfer_r);
    const Bytes gap = rebuilt(
        evidence,
        [&](protocol::EvidenceBundle& bundle) {
            std::erase_if(bundle.entries, [&](const protocol::EvidenceEntry& entry) {
                return leaf_index(entry) == transfer_index;
            });
        },
        consents);
    CHECK_FALSE(c.verify(gap));
    // Its parent's evidence is its own: the part's later calls are not in it.
    CHECK_FALSE(c.verify(
        rebuilt(evidence, [&](protocol::EvidenceBundle& bundle) { bundle.record = a; }, consents)));
    auto parent = c.verify(c.evidence(a, {supplier_splits_r, supplier_splits_a}));
    REQUIRE(parent);
    CHECK(parent->instance.instance->final);
    CHECK(parent->instance.instance->ancestors.size() == 1);

    // A retired contract creates no more instances, children included; its
    // parts carry on.
    c.home.ok(c.home.org(), c.home.statement(c.home.org_id(), std::nullopt,
                                             protocol::ContractRetireBody{c.contract, "v2"}));
    auto split_a0 = c.call(a0, "split", parts({{supplier, 400}, {bank, 50}}));
    (void)c.consent(c.supplier, split_a0);
    CHECK(c.home.rejected(c.home.org(), c.home.statement(c.home.org_id(), std::nullopt,
                                                         split_a0)) == Errc::rejected);
    auto transfer_a0 = c.call(a0, "transfer", ledger_value(bank));
    const Bytes supplier_transfers_a0 = c.consent(c.supplier, transfer_a0);
    c.submit(transfer_a0);
    CHECK(c.verify(c.evidence(a0, {supplier_splits_r, supplier_splits_a, supplier_transfers_a0})));

    // Replayed from storage, the children come back as they were.
    auto reopened = ledger::Ledger::open(c.home.fs(), c.home.clock(), provider());
    REQUIRE(reopened);
    for (const protocol::Id& id : {r, a, b, a0, a1}) {
        const auto* before = c.home.ledger().state().instance(id);
        const auto* after = reopened->state().instance(id);
        REQUIRE(after != nullptr);
        CHECK(after->state == before->state);
        CHECK(after->parties == before->parties);
        CHECK(after->history == before->history);
        CHECK(after->parent == before->parent);
        CHECK(after->depth == before->depth);
        CHECK(after->position == before->position);
        CHECK(after->created_by == before->created_by);
    }
}

TEST_CASE("the home's evidence for a child is the independent encoder's, byte for byte",
          "[contracts][children][vectors]") {
    const auto document = load_vectors("protocol-v0.7.json");
    auto log_key = KeyPair::from_ed25519_seed(hex_field(document["seeds"]["log"]));
    REQUIRE(log_key);
    for (const auto& vectors : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(vectors["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        // A copy of the vectors' log and checkpoint, every entry replayed
        // under the rules, children included.
        std::vector<Bytes> entries;
        for (const auto& entry : vectors["log_entries"]) {
            entries.push_back(hex_field(entry));
        }
        ledger::MemoryFileSystem fs;
        ledger::ManualClock clock(document["t0"].get<protocol::Timestamp>());
        auto copy = ledger::Ledger::create_replica(fs, clock, provider(), entries.front());
        REQUIRE(copy);
        const auto appended = copy->append_entries(std::span<const Bytes>(entries).subspan(1));
        INFO((appended ? std::string() : std::string(appended.error().detail)));
        REQUIRE(appended);
        REQUIRE(copy->store_checkpoint(hex_field(vectors["checkpoint"])));

        for (const auto& [what, expected] : vectors["evidence"].items()) {
            INFO(what);
            const auto evidence =
                protocol::decode_contract_evidence(hex_field(expected["contract_evidence"]));
            REQUIRE(evidence);
            auto bundle = copy->export_evidence(*log_key, id_of(expected["subject"]));
            REQUIRE(bundle);
            auto encoded = protocol::encode_bundle(*bundle);
            REQUIRE(encoded);
            CHECK(*encoded == evidence->instance_bundle);
        }
    }
}
