// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A home ledger's server takes the parties' consents to a pledge, records it
// once both are in, and serves the asset's evidence to its parties (D-052).

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/asset_evidence.hpp>
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/assets.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
namespace node = cexchain::node;
using cexchain::Bytes;
using json = nlohmann::json;

std::filesystem::path fresh_directory() {
    static int counter = 0;
    const auto dir =
        std::filesystem::temp_directory_path() /
        ("cexchain-assets-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

class Running {
public:
    explicit Running(node::Application& app) : server_(app, options()) {
        REQUIRE(server_.listen());
        thread_ = std::thread([this] { server_.run(); });
    }
    Running(const Running&) = delete;
    Running& operator=(const Running&) = delete;
    ~Running() {
        server_.stop();
        thread_.join();
    }
    [[nodiscard]] node::Client client(const std::string& token) const {
        node::ClientOptions o;
        o.bearer_token = token;
        o.timeout = std::chrono::seconds(10);
        return node::Client(*node::Url::parse("http://127.0.0.1:" + std::to_string(server_.port())),
                            o);
    }

private:
    static node::ServerOptions options() {
        node::ServerOptions o;
        o.port = 0;
        o.request_timeout = std::chrono::seconds(5);
        return o;
    }
    node::Server server_;
    std::thread thread_;
};

const protocol::Nonce salt{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};

protocol::RecordRegisterBody body_with(const std::string& type, cbor::Value metadata) {
    auto commitment = protocol::commit_fields(provider(), crypto::HashAlg::sha256,
                                              {{"invoice", salt, cbor::Value::text("INV-77")}});
    REQUIRE(commitment);
    return {type,
            Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end()),
            1,
            {},
            std::move(metadata)};
}

/// A consent on `party`'s ledger to `terms`, and its evidence.
Bytes consent(World& party, const protocol::AssetTerms& terms) {
    auto metadata = protocol::encode_asset_consent({terms, t0 + 30 * day, std::nullopt});
    REQUIRE(metadata);
    const protocol::Id record =
        party.ok(party.org(), party.statement(party.org_id(), std::nullopt,
                                              body_with(std::string(protocol::asset_consent_type),
                                                        std::move(*metadata))));
    REQUIRE(party.ledger().checkpoint(party.log_key()));
    auto bundle = party.ledger().export_evidence(party.log_key(), record);
    REQUIRE(bundle);
    return *protocol::encode_bundle(*bundle);
}

/// The home: a debtor's ledger in a directory, with a registrar (a device
/// with a delegation for asset actions on receivables) and tokens for its
/// staff and two peers.
struct Home {
    std::filesystem::path dir = fresh_directory();
    ledger::ManualClock clock{t0};
    ledger::SeededEntropy entropy{21};
    KeyPair org = key("home org");
    std::shared_ptr<const KeyPair> log_key = std::make_shared<const KeyPair>(key("home log"));
    std::shared_ptr<const KeyPair> registrar = std::make_shared<const KeyPair>(key("registrar"));
    protocol::Id id;
    protocol::Id receivable;
    std::string staff = "staff-token-0123456789";
    std::string supplier_token = "supplier-token-0123456789";
    std::string bank_token = "bank-token-0123456789";
    std::string buyer_token = "buyer-token-0123456789";

    Home(World& supplier, World& bank, World& buyer) {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        auto sign = [&](protocol::Body body) {
            protocol::Statement s;
            s.ledger_id = id;
            s.actor_id = id;
            s.issued_at = t0;
            s.nonce = entropy.bytes<16>();
            s.body = std::move(body);
            auto signed_statement =
                protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, s);
            REQUIRE(signed_statement);
            return signed_statement->encoded;
        };
        protocol::Statement genesis;
        genesis.issued_at = t0;
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Debtor", org.public_key(),
                                             log_key->public_key()};
        auto signed_genesis =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, genesis);
        REQUIRE(signed_genesis);
        auto ledger = ledger::Ledger::create(*fs, clock, provider(), signed_genesis->encoded);
        REQUIRE(ledger);
        id = ledger->id();
        auto device = ledger->submit(sign(protocol::ActorRegisterBody{
            protocol::ActorKind::device, "Registrar", registrar->public_key(), {}, {}}));
        REQUIRE(device);
        REQUIRE(ledger->submit(sign(protocol::DelegationGrantBody{
            device->statement_id,
            scope({StatementType::asset_action},
                  std::vector<std::string>{std::string(protocol::receivable_type)})})));
        auto metadata = protocol::encode_asset_metadata(
            protocol::AssetKind::receivable, {supplier.ledger().id(), 500'000, "CNY", t0 + day});
        REQUIRE(metadata);
        auto registered = ledger->submit(
            sign(body_with(std::string(protocol::receivable_type), std::move(*metadata))));
        REQUIRE(registered);
        receivable = registered->statement_id;
        REQUIRE(ledger->checkpoint(*log_key));

        auto scopes = [](node::Scope s) {
            return static_cast<node::Scopes>(s);
        };
        REQUIRE(node::save_tokens(
            dir,
            {{"staff",
              static_cast<node::Scopes>(scopes(node::Scope::read) | scopes(node::Scope::submit) |
                                        scopes(node::Scope::admin)),
              node::token_hash(provider(), staff), t0},
             {"supplier", scopes(node::Scope::peer), node::token_hash(provider(), supplier_token),
              t0},
             {"bank", scopes(node::Scope::peer), node::token_hash(provider(), bank_token), t0},
             {"buyer", scopes(node::Scope::peer), node::token_hash(provider(), buyer_token), t0}}));
        node::Peer p1;
        p1.name = "supplier";
        p1.ledger_id = supplier.ledger().id();
        node::Peer p2;
        p2.name = "bank";
        p2.ledger_id = bank.ledger().id();
        node::Peer p3;
        p3.name = "buyer";
        p3.ledger_id = buyer.ledger().id();
        REQUIRE(node::save_peers(dir, {p1, p2, p3}));
    }
    Home(const Home&) = delete;
    Home& operator=(const Home&) = delete;
    ~Home() { std::filesystem::remove_all(dir); }

    std::unique_ptr<node::LedgerApi> api(bool with_registrar = true) const {
        node::ApiOptions o;
        o.directory = dir;
        o.log_keys = {log_key};
        if (with_registrar) {
            o.registrar = registrar;
        }
        auto opened = node::LedgerApi::open(o, provider());
        REQUIRE(opened);
        return std::move(*opened);
    }
};

node::http::ClientResponse send(const node::Client& c, std::string_view method,
                                const std::string& path, const Bytes& body = {},
                                std::string_view type = "application/cbor") {
    auto r = c.request(method, path, body, type);
    REQUIRE(r);
    return std::move(*r);
}

json body_json(const node::http::ClientResponse& r) {
    return json::parse(r.body.begin(), r.body.end());
}

} // namespace

TEST_CASE("a registrar records a pledge once both parties consented", "[node][assets]") {
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sha256, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    Home home(supplier, bank, buyer);
    auto api = home.api();
    Running server(*api);
    const auto staff = server.client(home.staff);
    const std::string asset_path = "/v1/assets/" + cexchain::to_hex(home.receivable.bytes());

    protocol::AssetActionBody pledge;
    pledge.asset = home.receivable;
    pledge.action = protocol::AssetAction::pledge;
    pledge.head = api->ledger().state().asset(home.receivable)->head;
    pledge.to = bank.ledger().id();
    const auto terms = protocol::terms_of(pledge, home.id);

    // Only the parties: the buyer is not one.
    CHECK(
        send(server.client(home.buyer_token), "POST", "/v1/assets/consents", consent(buyer, terms))
            .status == 403);
    // A consent must come from the token's own ledger.
    CHECK(send(server.client(home.bank_token), "POST", "/v1/assets/consents",
               consent(supplier, terms))
              .status == 403);

    const auto first = send(server.client(home.supplier_token), "POST", "/v1/assets/consents",
                            consent(supplier, terms));
    REQUIRE(first.status == 202);
    CHECK(body_json(first)["status"] == "waiting");
    CHECK(body_json(first)["missing"] ==
          json::array({cexchain::to_hex(bank.ledger().id().bytes())}));

    const auto second =
        send(server.client(home.bank_token), "POST", "/v1/assets/consents", consent(bank, terms));
    INFO(std::string(second.body.begin(), second.body.end()));
    REQUIRE(second.status == 201);
    CHECK(body_json(second)["status"] == "recorded");
    CHECK(api->ledger().state().record(home.receivable)->state == "pledged");

    // A consent to the head before the pledge can no longer be used.
    CHECK(send(server.client(home.supplier_token), "POST", "/v1/assets/consents",
               consent(supplier, terms))
              .status == 409);

    // The evidence: for the staff and the asset's parties, verified offline.
    REQUIRE(send(staff, "POST", "/v1/checkpoint").status == 200);
    const auto for_bank = send(server.client(home.bank_token), "GET", asset_path);
    REQUIRE(for_bank.status == 200);
    protocol::VerifyOptions options;
    options.expected_ledger = home.id;
    auto report = protocol::verify_asset_evidence(provider(), for_bank.body, options);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    CHECK(report->asset.state == "pledged");
    REQUIRE(report->steps.size() == 1);
    CHECK(report->steps.front().consents.size() == 2);
    CHECK(send(staff, "GET", asset_path).status == 200);
    CHECK(send(server.client(home.supplier_token), "GET", asset_path).status == 200);
    CHECK(send(server.client(home.buyer_token), "GET", asset_path).status == 404);
}

TEST_CASE("an asset action arrives with its consents, and only so", "[node][assets]") {
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sha256, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    Home home(supplier, bank, buyer);
    auto api = home.api(false);
    Running server(*api);
    const auto staff = server.client(home.staff);

    // Without a registrar, consents are not taken.
    protocol::AssetActionBody cancel;
    cancel.asset = home.receivable;
    cancel.action = protocol::AssetAction::cancel;
    cancel.head = api->ledger().state().asset(home.receivable)->head;
    const Bytes bundle = consent(supplier, protocol::terms_of(cancel, home.id));
    CHECK(send(server.client(home.supplier_token), "POST", "/v1/assets/consents", bundle).status ==
          501);

    // The home's people send the action with the consent's evidence.
    cancel.consents.push_back({supplier.ledger().id(), protocol::decode_bundle(bundle)->record,
                               *provider().digest(crypto::HashAlg::sha256, bundle)});
    protocol::Statement s;
    s.ledger_id = home.id;
    s.actor_id = home.id;
    s.issued_at = t0;
    s.nonce = home.entropy.bytes<16>();
    s.body = cancel;
    auto action = protocol::sign_statement(home.org, provider(), crypto::HashAlg::sha256, s);
    REQUIRE(action);
    // Alone, it is refused: the home would not hold the consent it cites.
    CHECK(send(staff, "POST", "/v1/statements", action->encoded, "application/cose").status == 400);
    auto submission = [&](const Bytes& consent_bundle) {
        return *cbor::encode(cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::bytes(action->encoded)},
             {cbor::Value::integer(3), cbor::Value::array({cbor::Value::bytes(consent_bundle)})}}));
    };
    // Another bundle than the one it pins is refused.
    const Bytes other = consent(supplier, protocol::terms_of(cancel, home.id));
    CHECK(send(staff, "POST", "/v1/statements", submission(other), node::submission_content_type)
              .status == 422);
    const auto done =
        send(staff, "POST", "/v1/statements", submission(bundle), node::submission_content_type);
    INFO(std::string(done.body.begin(), done.body.end()));
    REQUIRE(done.status == 201);
    CHECK(api->ledger().state().record(home.receivable)->state == "cancelled");
    CHECK(std::filesystem::exists(node::consents_path(home.dir, action->id)));
}
