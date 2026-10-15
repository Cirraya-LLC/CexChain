// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Requests and answers (spec v0.8) on real ledgers: a service whose contract
// asks a device executor and a person for work, with a customer's consent
// from a ledger on the other hash, answers on time, late, and at the
// deadline, refusals for whatever a delegation or the rules do not allow,
// and the instance's evidence verified offline with every request and
// answer; and the home's evidence for the vectors' instances, exported from
// a copy of their log, equal byte for byte to the independent encoder's.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
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
#include <cexchain/verifier/report.hpp>

#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.8.json");
    return document;
}

protocol::Id id_of(const nlohmann::json& value) {
    return *protocol::to_id(hex_field(value));
}

cbor::Value text(std::string value) {
    return cbor::Value::text(std::move(value));
}

/// The requesting contract's arguments that make requests: [[kind, params,
/// after], ...], each due `after` ms after the call.
cbor::Value asks(const std::vector<std::pair<std::string, protocol::Timestamp>>& specs) {
    cbor::Array items;
    for (const auto& [kind, after] : specs) {
        items.push_back(
            cbor::Value::array({text(kind), cbor::Value::map({{text("plan"), text("vps-2c4g")}}),
                                cbor::Value::unsigned_integer(after)}));
    }
    return cbor::Value::array(std::move(items));
}

const protocol::Nonce salt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

/// A home that deploys the vectors' requesting contract, a clerk (a person)
/// who runs it, a panel executor (a device) that may only answer provision
/// and suspend requests with `result`, and a customer on the other hash.
struct Service {
    World home;
    World customer;
    protocol::Id contract;
    KeyPair clerk_key = key("clerk");
    KeyPair panel_key = key("panel");
    protocol::Id clerk;
    protocol::Id panel;
    protocol::Id d_clerk;
    protocol::Id d_panel;

    explicit Service(crypto::HashAlg hash)
        : home(hash, "IDC Home"),
          customer(hash == crypto::HashAlg::sha256 ? crypto::HashAlg::sm3 : crypto::HashAlg::sha256,
                   "Customer") {
        protocol::ContractDeployBody deploy;
        deploy.code = hex_field(vectors()["contract"]);
        for (const auto& [name, kind] : vectors()["interface"].items()) {
            deploy.interface.emplace(name, static_cast<protocol::FunctionKind>(kind.get<int>()));
        }
        deploy.language = "wasm";
        deploy.compiler = "hand-assembled 1";
        deploy.name = "Service";
        contract = home.ok(home.org(), home.statement(home.org_id(), std::nullopt, deploy));
        clerk = home.register_actor(home.org(), home.org_id(), std::nullopt,
                                    protocol::ActorKind::person, clerk_key);
        panel = home.register_actor(home.org(), home.org_id(), std::nullopt,
                                    protocol::ActorKind::device, panel_key);
        auto clerk_scope = scope({StatementType::contract_call});
        clerk_scope.contracts = std::vector<protocol::Id>{contract};
        d_clerk = home.grant(home.org(), home.org_id(), std::nullopt, clerk, clerk_scope);
        auto panel_scope = clerk_scope;
        panel_scope.functions = std::vector<std::string>{"result"};
        panel_scope.request_kinds = std::vector<std::string>{"provision", "suspend"};
        d_panel = home.grant(home.org(), home.org_id(), std::nullopt, panel, panel_scope);
    }

    const protocol::InstanceState& instance(const protocol::Id& id) {
        const auto* i = home.ledger().state().instance(id);
        REQUIRE(i != nullptr);
        return *i;
    }

    const protocol::RequestState& request(const protocol::Id& id) {
        const auto* r = home.ledger().state().request(id);
        REQUIRE(r != nullptr);
        return *r;
    }

    protocol::Id request_id(const protocol::Id& call, std::uint64_t position) {
        auto id = protocol::request_id(provider(), home.hash(), call, position);
        REQUIRE(id);
        return *id;
    }

    protocol::ContractCallBody call(const protocol::Id& instance_id, std::string function,
                                    cbor::Value arguments) {
        protocol::ContractCallBody b;
        b.instance = instance_id;
        b.function = std::move(function);
        b.arguments = std::move(arguments);
        b.head = instance(instance_id).head;
        return b;
    }

    protocol::ContractCallBody answer(const protocol::Id& instance_id, const protocol::Id& request,
                                      protocol::AnswerStatus status, cbor::Value result) {
        auto b = call(instance_id, "result", std::move(result));
        b.answer = protocol::ContractAnswer{request, status};
        return b;
    }

    protocol::Statement by_clerk(protocol::Body body) {
        return home.statement(clerk, d_clerk, std::move(body));
    }

    protocol::Statement by_panel(protocol::Body body) {
        return home.statement(panel, d_panel, std::move(body));
    }

    /// The customer consents to `b` on its own ledger; returns the
    /// consent's evidence bundle, which `b` now cites.
    Bytes consent(protocol::ContractCallBody& b) {
        auto digest = protocol::contract_arguments_digest(provider(), home.hash(), b.arguments);
        REQUIRE(digest);
        auto metadata =
            protocol::encode_contract_consent({home.ledger().id(), *b.instance, b.function, *digest,
                                               *b.head, home.clock().now() + 7 * day, "terms"});
        REQUIRE(metadata);
        auto commitment =
            protocol::commit_fields(provider(), customer.hash(), {{"terms", salt, text("ok")}});
        REQUIRE(commitment);
        const protocol::Id record = customer.ok(
            customer.org(), customer.statement(customer.org_id(), std::nullopt,
                                               protocol::RecordRegisterBody{
                                                   std::string(protocol::contract_consent_type),
                                                   Bytes(commitment->root.bytes().begin(),
                                                         commitment->root.bytes().end()),
                                                   1,
                                                   {},
                                                   std::move(*metadata)}));
        REQUIRE(customer.ledger().checkpoint(customer.log_key()));
        auto bundle = customer.ledger().export_evidence(customer.log_key(), record);
        REQUIRE(bundle);
        auto encoded = protocol::encode_bundle(*bundle);
        REQUIRE(encoded);
        auto pin = provider().digest(home.hash(), *encoded);
        REQUIRE(pin);
        b.consents.push_back({customer.ledger().id(), record, *pin, {}});
        return *encoded;
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
};

std::string detail(const cexchain::Result<ledger::Registration>& r) {
    return r ? std::string() : std::string(r.error().detail);
}

} // namespace

TEST_CASE("a device and a person answer a service's requests, and its evidence shows them",
          "[contracts][requests]") {
    const auto home_hash = GENERATE(crypto::HashAlg::sha256, crypto::HashAlg::sm3);
    INFO(crypto::name(home_hash));
    Service s(home_hash);
    auto& home = s.home;

    // The clerk opens a service, asking for it to be provisioned within a
    // day: the request is the new instance's, open.
    protocol::ContractCallBody open;
    open.contract = s.contract;
    open.function = "open";
    open.arguments = asks({{"provision", day}});
    const protocol::Timestamp opened_at = home.clock().now();
    const protocol::Id service = home.ok(s.clerk_key, s.by_clerk(open));
    const protocol::Id provision = s.request_id(service, 0);
    CHECK(s.request(provision).instance == service);
    CHECK(s.request(provision).kind == "provision");
    CHECK(s.request(provision).deadline == opened_at + day);
    CHECK(s.request(provision).asked_at == opened_at);
    CHECK(s.request(provision).reply == "result");
    CHECK(s.request(provision).open());
    CHECK(s.instance(service).open_requests == std::vector<protocol::CompactId>{provision});

    // The panel executor sees the request (input key 9) when it answers.
    auto provisioned = s.answer(service, provision, protocol::AnswerStatus::done,
                                cbor::Value::map({{text("ref"), text("vm-4711")}}));
    {
        auto signed_answer =
            protocol::sign_statement(s.panel_key, provider(), home.hash(), s.by_panel(provisioned));
        REQUIRE(signed_answer);
        auto run =
            home.ledger().state().run_contract(provider(), *signed_answer, home.clock().now());
        REQUIRE(run);
        const auto input = cbor::decode(run->input);
        REQUIRE(input);
        const cbor::Value* view = input->find(9);
        REQUIRE(view != nullptr);
        CHECK(view->find(1)->as_bytes() != nullptr);
        CHECK(*view->find(2)->as_text() == "provision");
        CHECK(view->find(4)->as_uint64() == opened_at + day);
        CHECK(view->find(5)->as_uint64() == opened_at);
        CHECK(view->find(6)->as_uint64() == 1U);
    }
    home.ok(s.panel_key, s.by_panel(provisioned));
    CHECK(s.request(provision).status == protocol::AnswerStatus::done);
    CHECK(s.request(provision).late_by() == 0);
    CHECK(s.instance(service).open_requests.empty());
    // At most once.
    CHECK(home.rejected(s.panel_key,
                        s.by_panel(s.answer(service, provision, protocol::AnswerStatus::done,
                                            cbor::Value::null()))) == Errc::rejected);

    // With the customer's consent from its own ledger, the clerk asks for an
    // invoice within three days and a suspension within an hour.
    auto ask = s.call(service, "ask", asks({{"invoice", 3 * day}, {"suspend", 3'600'000}}));
    const Bytes consent = s.consent(ask);
    const protocol::Timestamp asked_at = home.clock().now();
    const protocol::Id asked = home.ok(s.clerk_key, s.by_clerk(ask));
    const protocol::Id invoice = s.request_id(asked, 0);
    const protocol::Id suspend = s.request_id(asked, 1);
    CHECK(s.instance(service).open_requests == std::vector<protocol::CompactId>{invoice, suspend});

    // The panel executor serves provision and suspend with `result`, and
    // nothing else: not an invoice, not `ask`, not a call that answers
    // nothing.
    auto refused = home.submit(
        s.panel_key,
        s.by_panel(s.answer(service, invoice, protocol::AnswerStatus::done, cbor::Value::null())));
    REQUIRE_FALSE(refused);
    CHECK(detail(refused).contains("delegation"));
    CHECK(home.rejected(s.panel_key, s.by_panel(s.call(service, "ask", asks({})))) ==
          Errc::rejected);
    CHECK(home.rejected(s.panel_key, s.by_panel(s.call(service, "result", cbor::Value::null()))) ==
          Errc::rejected);
    // Nobody expires a request before its deadline.
    refused = home.submit(s.clerk_key,
                          s.by_clerk(s.answer(service, suspend, protocol::AnswerStatus::expired,
                                              cbor::Value::null())));
    REQUIRE_FALSE(refused);
    CHECK(detail(refused).contains("deadline"));

    // At the suspension's deadline itself, both a done and an expiry are
    // valid: the first registered wins.
    home.clock().set(asked_at + 3'600'000);
    const auto expire =
        s.answer(service, suspend, protocol::AnswerStatus::expired, cbor::Value::null());
    const auto suspended = s.answer(service, suspend, protocol::AnswerStatus::done,
                                    cbor::Value::map({{text("ref"), text("vm-4711")}}));
    {
        auto signed_done =
            protocol::sign_statement(s.panel_key, provider(), home.hash(), s.by_panel(suspended));
        REQUIRE(signed_done);
        CHECK(home.ledger().state().validate(provider(), *signed_done, home.clock().now()));
    }
    home.ok(s.panel_key, s.by_panel(expire));
    CHECK(s.request(suspend).status == protocol::AnswerStatus::expired);
    CHECK(s.request(suspend).late_by() == 0);
    refused = home.submit(
        s.panel_key,
        s.by_panel(s.answer(service, suspend, protocol::AnswerStatus::done, cbor::Value::null())));
    REQUIRE_FALSE(refused);
    CHECK(detail(refused).contains("already answered"));

    // Four days later the clerk records by hand that the invoice was
    // issued: late, and recorded all the same.
    home.clock().set(asked_at + 4 * day);
    const protocol::Timestamp invoiced_at = home.clock().now();
    home.ok(s.clerk_key,
            s.by_clerk(s.answer(service, invoice, protocol::AnswerStatus::done,
                                cbor::Value::map({{text("ref"), text("INV-2026-0001")}}))));
    CHECK(s.request(invoice).late_by() == invoiced_at - (asked_at + 3 * day));

    // A reclaim due within the hour stays open, and is overdue when the
    // home checkpoints two hours later.
    const protocol::Id last =
        home.ok(s.clerk_key, s.by_clerk(s.call(service, "ask", asks({{"reclaim", 3'600'000}}))));
    const protocol::Id reclaim = s.request_id(last, 0);
    // A deadline of 366 days and a millisecond, or one at the call, is
    // refused; so is a 65th open request (none here: the limit is the
    // vectors').
    CHECK(home.rejected(s.clerk_key,
                        s.by_clerk(s.call(service, "ask",
                                          asks({{"x", protocol::max_request_deadline + 1}})))) ==
          Errc::rejected);
    CHECK(home.rejected(s.clerk_key, s.by_clerk(s.call(service, "ask", asks({{"x", 0}})))) ==
          Errc::rejected);
    // The contract adds modulo 2^64: a deadline that wraps around, or the
    // largest, is refused too.
    for (const std::uint64_t after :
         {std::numeric_limits<std::uint64_t>::max(),
          std::numeric_limits<std::uint64_t>::max() - home.clock().now()}) {
        CHECK(
            home.rejected(s.clerk_key, s.by_clerk(s.call(service, "ask", asks({{"x", after}})))) ==
            Errc::rejected);
    }
    home.clock().advance(2 * 3'600'000);

    // The evidence verifies offline: each call's requests, each answer with
    // its status, its lateness, and who gave it; the reclaim open and
    // overdue at the checkpoint's time.
    const Bytes evidence = s.evidence(service, {consent});
    protocol::VerifyOptions options;
    options.expected_ledger = home.ledger().id();
    auto report = protocol::verify_contract_evidence(provider(), evidence, options);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    const protocol::EvidenceReport& e = report->instance;
    CHECK(e.complete);
    const protocol::InstanceReport& i = *e.instance;
    REQUIRE(e.events.size() == 6);
    CHECK(e.events[0].requests == std::vector<protocol::Id>{provision});
    CHECK(e.events[2].requests == std::vector<protocol::Id>{invoice, suspend});
    CHECK(e.events[5].requests == std::vector<protocol::Id>{reclaim});
    REQUIRE(e.events[1].answered);
    CHECK(e.events[1].answered->id == provision);
    CHECK(e.events[1].actor.kind == protocol::ActorKind::device);
    REQUIRE(e.events[3].answered);
    CHECK(e.events[3].answered->status == protocol::AnswerStatus::expired);
    CHECK(e.events[3].answered->late_by == 0);
    REQUIRE(e.events[4].answered);
    CHECK(e.events[4].answered->id == invoice);
    CHECK(e.events[4].actor.kind == protocol::ActorKind::person);
    CHECK(e.events[4].answered->late_by == day);
    REQUIRE(report->steps[2].consents.size() == 1);
    CHECK(report->steps[2].consents[0].report.hash == s.customer.hash());
    REQUIRE(i.requests.size() == 4);
    CHECK(i.open_requests() == std::vector<std::size_t>{3});
    CHECK(i.overdue_requests() == std::vector<std::size_t>{3});
    CHECK(i.requests[3].id == reclaim);
    CHECK(i.requests[3].overdue);
    const auto json = cexchain::verifier::contract_report_json(*report, true);
    CHECK(json["instance"]["overdue_requests"] ==
          nlohmann::ordered_json::array({cexchain::to_hex(reclaim.bytes())}));
    CHECK(json["calls"][4]["answer"]["late"] == true);
    CHECK(json["calls"][1]["called_by"]["kind"] == "device");
    const std::string shown = cexchain::verifier::contract_report_text(*report, true);
    CHECK(shown.contains("LATE by 1 d 0 h 0 min"));
    CHECK(shown.contains("1 OVERDUE at the checkpoint"));
    // Every consent is needed.
    CHECK_FALSE(protocol::verify_contract_evidence(provider(), s.evidence(service, {}), options));

    // Replayed from storage, the requests come back as they were.
    auto reopened = ledger::Ledger::open(home.fs(), home.clock(), provider());
    REQUIRE(reopened);
    for (const protocol::Id& r : {provision, invoice, suspend, reclaim}) {
        const auto* before = home.ledger().state().request(r);
        const auto* after = reopened->state().request(r);
        REQUIRE(after != nullptr);
        CHECK(after->status == before->status);
        CHECK(after->answered_by == before->answered_by);
        CHECK(after->answered_at == before->answered_at);
        CHECK(after->deadline == before->deadline);
        CHECK(after->call == before->call);
    }
    CHECK(reopened->state().instance(service)->open_requests ==
          std::vector<protocol::CompactId>{reclaim});
}

TEST_CASE("scope key 8 restricts creations too", "[contracts][requests]") {
    Service s(crypto::HashAlg::sm3);
    auto& home = s.home;
    // A device that may only open services (key 8) and nothing else.
    const KeyPair opener_key = key("opener");
    const protocol::Id opener = home.register_actor(home.org(), home.org_id(), std::nullopt,
                                                    protocol::ActorKind::device, opener_key);
    auto only_open = scope({StatementType::contract_call});
    only_open.functions = std::vector<std::string>{"open"};
    const protocol::Id d_opener =
        home.grant(home.org(), home.org_id(), std::nullopt, opener, only_open);
    protocol::ContractCallBody open;
    open.contract = s.contract;
    open.function = "open";
    open.arguments = asks({{"provision", day}});
    const protocol::Id service = home.ok(opener_key, home.statement(opener, d_opener, open));
    const protocol::Id provision = s.request_id(service, 0);
    auto refused = home.submit(
        opener_key, home.statement(opener, d_opener,
                                   s.answer(service, provision, protocol::AnswerStatus::done,
                                            cbor::Value::null())));
    REQUIRE_FALSE(refused);
    CHECK(detail(refused).contains("function"));
    // Under key 9 alone, a creation answers nothing, so it is refused.
    auto answers_only = scope({StatementType::contract_call});
    answers_only.request_kinds = std::vector<std::string>{"provision"};
    const protocol::Id d_answers =
        home.grant(home.org(), home.org_id(), std::nullopt, opener, answers_only);
    refused = home.submit(opener_key, home.statement(opener, d_answers, open));
    REQUIRE_FALSE(refused);
    CHECK(detail(refused).contains("answers to requests"));
    home.ok(opener_key, home.statement(opener, d_answers,
                                       s.answer(service, provision, protocol::AnswerStatus::done,
                                                cbor::Value::null())));
    CHECK(s.request(provision).status == protocol::AnswerStatus::done);
}

TEST_CASE("a final instance takes answers to its open requests, and stays final",
          "[contracts][requests]") {
    Service s(crypto::HashAlg::sha256);
    auto& home = s.home;
    protocol::ContractCallBody open;
    open.contract = s.contract;
    open.function = "open";
    open.arguments = cbor::Value::null();
    const protocol::Id service = home.ok(s.clerk_key, s.by_clerk(open));

    // The clerk ends the service, asking for a suspension: the contract's
    // accept is final and makes the request.
    const auto now = home.clock().now();
    cbor::Map accept{
        {cbor::Value::unsigned_integer(1), text("ended")},
        {cbor::Value::unsigned_integer(5), cbor::Value::boolean(true)},
        {cbor::Value::unsigned_integer(7),
         cbor::Value::array({cbor::Value::map(
             {{cbor::Value::unsigned_integer(1), text("suspend")},
              {cbor::Value::unsigned_integer(2), cbor::Value::null()},
              {cbor::Value::unsigned_integer(3), cbor::Value::unsigned_integer(now + day)},
              {cbor::Value::unsigned_integer(4), text("result")}})})}};
    const auto output = cbor::encode(cbor::Value::array(
        {cbor::Value::unsigned_integer(1), cbor::Value::map(std::move(accept))}));
    REQUIRE(output);
    const protocol::Id end =
        home.ok(s.clerk_key, s.by_clerk(s.call(service, "ask", cbor::Value::bytes(*output))));
    CHECK(s.instance(service).final);
    const protocol::Id suspend = s.request_id(end, 0);

    // Only answers to its open requests reach it, making no requests.
    CHECK(home.rejected(s.clerk_key, s.by_clerk(s.call(service, "ask", cbor::Value::null()))) ==
          Errc::rejected);
    auto again =
        s.answer(service, suspend, protocol::AnswerStatus::failed, asks({{"suspend", day}}));
    auto refused = home.submit(s.panel_key, s.by_panel(again));
    REQUIRE_FALSE(refused);
    CHECK(detail(refused).contains("final"));
    home.ok(s.panel_key, s.by_panel(s.answer(service, suspend, protocol::AnswerStatus::done,
                                             cbor::Value::null())));
    CHECK(s.instance(service).final);
    CHECK(s.instance(service).open_requests.empty());
    CHECK(s.request(suspend).answered_by == s.instance(service).head);
}

TEST_CASE("the home's evidence for requests is the independent encoder's, byte for byte",
          "[contracts][requests][vectors]") {
    const auto& document = vectors();
    auto log_key = KeyPair::from_ed25519_seed(hex_field(document["seeds"]["log"]));
    REQUIRE(log_key);
    for (const auto& ledger_vectors : document["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger_vectors["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        // A copy of the vectors' log and checkpoint, every entry replayed
        // under the rules, answers and requests included.
        std::vector<Bytes> entries;
        for (const auto& entry : ledger_vectors["log_entries"]) {
            entries.push_back(hex_field(entry));
        }
        ledger::MemoryFileSystem fs;
        ledger::ManualClock clock(document["t0"].get<protocol::Timestamp>());
        auto copy = ledger::Ledger::create_replica(fs, clock, provider(), entries.front());
        REQUIRE(copy);
        const auto appended = copy->append_entries(std::span<const Bytes>(entries).subspan(1));
        INFO((appended ? std::string() : std::string(appended.error().detail)));
        REQUIRE(appended);
        REQUIRE(copy->store_checkpoint(hex_field(ledger_vectors["checkpoint"])));
        CHECK(copy->state().requests().size() == ledger_vectors["requests"].size());

        for (const auto& [what, expected] : ledger_vectors["evidence"].items()) {
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
