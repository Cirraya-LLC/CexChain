// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A home ledger's server as a contract registrar (D-053): it takes a proposed
// call, asks the parties the contract names for their consents, records the
// call once the contract accepts it, and serves the instance's evidence to
// its parties. The supplier keeps a SHA-256 ledger, the bank an SM3 one.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/cluster.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "support/ledger_world.hpp"
#include "support/ports.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
namespace node = cexchain::node;
using cexchain::Bytes;
using json = nlohmann::json;
using namespace std::chrono_literals;

std::filesystem::path fresh_directory() {
    static int counter = 0;
    const auto dir =
        std::filesystem::temp_directory_path() /
        ("cexchain-contracts-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

class Running {
public:
    explicit Running(node::Application& app, std::uint16_t port = 0) : server_(app, options(port)) {
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
    static node::ServerOptions options(std::uint16_t port) {
        node::ServerOptions o;
        o.port = port;
        o.request_timeout = std::chrono::seconds(5);
        return o;
    }
    node::Server server_;
    std::thread thread_;
};

/// The counting contract (testvectors/test-contracts.json): with arguments
/// [out_0, ..., out_k], it writes out_min(n, k) for a call citing n consents.
Bytes counting() {
    return hex(load_vectors("test-contracts.json")["counting"].get<std::string>());
}

cbor::Value outputs(const std::vector<protocol::ContractOutput>& list) {
    cbor::Array items;
    for (const auto& o : list) {
        auto encoded = protocol::encode_contract_output(o);
        REQUIRE(encoded);
        items.push_back(cbor::Value::bytes(*encoded));
    }
    return cbor::Value::array(std::move(items));
}

protocol::ContractAccept accept(std::string status, std::optional<protocol::Parties> parties = {},
                                bool final = false) {
    return {*cbor::Encoded::encode(cbor::Value::text("state: " + status)),
            status,
            std::move(parties),
            {},
            final,
            {},
            {}};
}

protocol::ContractNeeds needs(std::vector<protocol::Id> ledgers) {
    std::ranges::sort(ledgers, [](const auto& a, const auto& b) {
        return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
    });
    return {std::move(ledgers)};
}

protocol::Timestamp now() {
    return ledger::SystemClock{}.now();
}

const protocol::Nonce salt{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5};

/// `party`'s organization consents, on its own ledger, to `function` with
/// `arguments` on the home's instance at `head`, until `until`. Returns the
/// consent's evidence.
Bytes consent(World& party, const protocol::Id& home, crypto::HashAlg home_hash,
              const protocol::Id& instance, std::uint64_t head, const std::string& function,
              const cbor::Value& arguments, protocol::Timestamp until) {
    auto digest = protocol::contract_arguments_digest(provider(), home_hash, arguments);
    REQUIRE(digest);
    auto metadata = protocol::encode_contract_consent(
        {home, instance, function, *digest, head, until, std::nullopt});
    REQUIRE(metadata);
    auto commitment = protocol::commit_fields(provider(), party.hash(),
                                              {{"terms", salt, cbor::Value::text("agreed")}});
    REQUIRE(commitment);
    const protocol::Id record = party.ok(
        party.org(),
        party.statement(party.org_id(), std::nullopt,
                        protocol::RecordRegisterBody{
                            std::string(protocol::contract_consent_type),
                            Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end()),
                            1,
                            {},
                            std::move(*metadata)}));
    REQUIRE(party.ledger().checkpoint(party.log_key()));
    auto bundle = party.ledger().export_evidence(party.log_key(), record);
    REQUIRE(bundle);
    auto encoded = protocol::encode_bundle(*bundle);
    REQUIRE(encoded);
    return *encoded;
}

/// The home: a core enterprise's ledger in a directory, with the counting
/// contract deployed, an agreement proposed to a supplier and a bank, a
/// registrar (a device with a delegation for calls on that contract), and
/// tokens for its staff and three peers (the buyer is no party).
struct Home {
    std::filesystem::path dir = fresh_directory();
    ledger::ManualClock clock{t0};
    ledger::SeededEntropy entropy{31};
    KeyPair org = key("contract home org");
    std::shared_ptr<const KeyPair> log_key =
        std::make_shared<const KeyPair>(key("contract home log"));
    std::shared_ptr<const KeyPair> registrar =
        std::make_shared<const KeyPair>(key("contract registrar"));
    protocol::Id id;
    protocol::Id contract;
    protocol::Id agreement;
    std::string staff = "staff-token-0123456789";
    std::string supplier_token = "supplier-token-0123456789";
    std::string bank_token = "bank-token-0123456789";
    std::string buyer_token = "buyer-token-0123456789";

    Home(World& supplier, World& bank, World& buyer) {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        protocol::Statement genesis;
        genesis.issued_at = t0;
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Core Enterprise",
                                             org.public_key(), log_key->public_key()};
        auto signed_genesis =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, genesis);
        REQUIRE(signed_genesis);
        auto ledger = ledger::Ledger::create(*fs, clock, provider(), signed_genesis->encoded);
        REQUIRE(ledger);
        id = ledger->id();
        auto submit = [&](protocol::Body body) {
            auto registered = ledger->submit(sign(std::move(body)));
            INFO((registered ? std::string() : std::string(registered.error().detail)));
            REQUIRE(registered);
            clock.advance(1000);
            return registered->statement_id;
        };
        protocol::ContractDeployBody deploy;
        deploy.code = counting();
        deploy.interface = {{"propose", protocol::FunctionKind::create},
                            {"sign", protocol::FunctionKind::call},
                            {"close", protocol::FunctionKind::call}};
        deploy.language = "wasm";
        deploy.compiler = "test_contracts.py 1";
        deploy.source = Bytes{'(', ')'};
        deploy.name = "Supply agreement";
        contract = submit(deploy);
        protocol::ContractCallBody create;
        create.contract = contract;
        create.function = "propose";
        create.arguments =
            outputs({accept("proposed", protocol::Parties{{"supplier", supplier.ledger().id()},
                                                          {"bank", bank.ledger().id()}})});
        agreement = submit(create);
        const protocol::Id device = submit(protocol::ActorRegisterBody{
            protocol::ActorKind::device, "Registrar", registrar->public_key(), {}, {}});
        auto calls = scope({StatementType::contract_call});
        calls.contracts = std::vector<protocol::Id>{contract};
        submit(protocol::DelegationGrantBody{device, calls});
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
        std::vector<node::Peer> peers(3);
        peers[0].name = "supplier";
        peers[0].ledger_id = supplier.ledger().id();
        peers[1].name = "bank";
        peers[1].ledger_id = bank.ledger().id();
        peers[2].name = "buyer";
        peers[2].ledger_id = buyer.ledger().id();
        REQUIRE(node::save_peers(dir, peers));
    }
    Home(const Home&) = delete;
    Home& operator=(const Home&) = delete;
    ~Home() { std::filesystem::remove_all(dir); }

    Bytes sign(protocol::Body body) {
        protocol::Statement s;
        s.ledger_id = id;
        s.actor_id = id;
        s.issued_at = clock.now();
        s.nonce = entropy.bytes<16>();
        s.body = std::move(body);
        auto signed_statement =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, s);
        REQUIRE(signed_statement);
        return signed_statement->encoded;
    }

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

std::string text(const node::http::ClientResponse& r) {
    return {r.body.begin(), r.body.end()};
}

std::string hex_id(const protocol::Id& id) {
    return cexchain::to_hex(id.bytes());
}

bool eventually(const std::function<bool()>& condition, std::chrono::milliseconds limit = 60s) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline) {
        if (condition()) {
            return true;
        }
        std::this_thread::sleep_for(50ms);
    }
    return condition();
}

/// A proposal to call `function` with `arguments` on the agreement at its head.
Bytes proposal(const node::LedgerApi& api, const Home& home, const std::string& function,
               const cbor::Value& arguments, std::optional<protocol::Timestamp> until = {}) {
    node::PendingCall p;
    p.instance = home.agreement;
    p.head = api.ledger().state().instance(home.agreement)->head;
    p.function = function;
    p.arguments = arguments;
    p.until = until.value_or(0);
    auto encoded = node::encode_call_proposal(p);
    REQUIRE(encoded);
    return *encoded;
}

/// A proposal to call `function` with `arguments` on any instance (a part
/// too) at its head.
Bytes proposal_on(const node::LedgerApi& api, const protocol::Id& instance,
                  const std::string& function, const cbor::Value& arguments) {
    node::PendingCall p;
    p.instance = instance;
    p.head = api.ledger().state().instance(instance)->head;
    p.function = function;
    p.arguments = arguments;
    auto encoded = node::encode_call_proposal(p);
    REQUIRE(encoded);
    return *encoded;
}

/// An accept that ends the instance and creates a part held by each ledger
/// (v0.7).
protocol::ContractAccept split_among(const std::vector<protocol::Id>& holders) {
    protocol::ContractAccept a = accept("split", {}, true);
    for (std::size_t n = 0; n < holders.size(); ++n) {
        a.children.push_back(
            {*cbor::Encoded::encode(cbor::Value::text("part " + std::to_string(n))), "part",
             protocol::Parties{{"holder", holders[n]}}});
    }
    return a;
}

protocol::Id id_from_hex(const json& text) {
    auto bytes = cexchain::from_hex(text.get<std::string>());
    REQUIRE(bytes);
    auto id = protocol::to_id(*bytes);
    REQUIRE(id);
    return *id;
}

} // namespace

TEST_CASE("a registrar records a contract call once both parties consented", "[node][contracts]") {
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    Home home(supplier, bank, buyer);
    auto api = home.api();
    Running server(*api);
    const auto staff = server.client(home.staff);
    const auto supplier_client = server.client(home.supplier_token);
    const auto bank_client = server.client(home.bank_token);
    const auto buyer_client = server.client(home.buyer_token);

    // Without consents the contract asks for both; with the supplier's, for
    // the bank's; with both, it takes the agreement into effect.
    const protocol::Id s = supplier.ledger().id();
    const protocol::Id b = bank.ledger().id();
    const cbor::Value arguments = outputs({needs({s, b}), needs({b}), accept("effective")});
    const std::uint64_t head = api->ledger().state().instance(home.agreement)->head;

    // The buyer is no party: it cannot propose, nor see the call.
    CHECK(send(buyer_client, "POST", "/v1/contracts/calls", proposal(*api, home, "sign", arguments))
              .status == 404);
    const auto proposed =
        send(staff, "POST", "/v1/contracts/calls", proposal(*api, home, "sign", arguments));
    INFO(text(proposed));
    REQUIRE(proposed.status == 202);
    const json waiting = body_json(proposed);
    CHECK(waiting["status"] == "waiting");
    CHECK(waiting["proposer"] == "staff");
    CHECK(waiting["missing"].size() == 2);
    CHECK(waiting["consented"].empty());
    const std::string call = waiting["call"];
    // Proposing it again answers as it stands.
    CHECK(send(staff, "POST", "/v1/contracts/calls", proposal(*api, home, "sign", arguments))
              .status == 202);

    // The supplier reads the pending call: the digest its consent must name.
    const auto seen = send(supplier_client, "GET", "/v1/contracts/calls/" + call);
    REQUIRE(seen.status == 200);
    const auto digest =
        protocol::contract_arguments_digest(provider(), crypto::HashAlg::sha256, arguments);
    REQUIRE(digest);
    CHECK(body_json(seen)["arguments_digest"] == hex_id(*digest));
    CHECK(body_json(seen)["arguments"] == cexchain::to_hex(*cbor::encode(arguments)));
    CHECK_FALSE(body_json(seen).contains("proposer"));
    CHECK(body_json(send(supplier_client, "GET", "/v1/contracts/calls"))["calls"].size() == 1);
    CHECK(send(buyer_client, "GET", "/v1/contracts/calls/" + call).status == 404);
    CHECK(body_json(send(buyer_client, "GET", "/v1/contracts/calls"))["calls"].empty());

    const protocol::Timestamp until = now() + 30 * day;
    const Bytes supplier_consent = consent(supplier, home.id, crypto::HashAlg::sha256,
                                           home.agreement, head, "sign", arguments, until);
    const Bytes bank_consent = consent(bank, home.id, crypto::HashAlg::sha256, home.agreement, head,
                                       "sign", arguments, until);
    // Only from the token's own ledger, and only those the contract asks.
    CHECK(send(bank_client, "POST", "/v1/contracts/consents", supplier_consent).status == 403);
    CHECK(send(buyer_client, "POST", "/v1/contracts/consents",
               consent(buyer, home.id, crypto::HashAlg::sha256, home.agreement, head, "sign",
                       arguments, until))
              .status == 403);

    const auto first = send(supplier_client, "POST", "/v1/contracts/consents", supplier_consent);
    INFO(text(first));
    REQUIRE(first.status == 202);
    CHECK(body_json(first)["missing"] == json::array({hex_id(b)}));
    CHECK(body_json(first)["consented"] == json::array({hex_id(s)}));

    const auto second = send(bank_client, "POST", "/v1/contracts/consents", bank_consent);
    INFO(text(second));
    REQUIRE(second.status == 201);
    CHECK(body_json(second)["status"] == "recorded");
    CHECK(body_json(second)["instance_status"] == "effective");
    const auto* agreement = api->ledger().state().instance(home.agreement);
    REQUIRE(agreement != nullptr);
    CHECK(agreement->status == "effective");
    CHECK(agreement->head > head);
    // Nothing is pending any more, and a consent to the old head is stale.
    CHECK(body_json(send(staff, "GET", "/v1/contracts/calls"))["calls"].empty());
    CHECK(send(supplier_client, "POST", "/v1/contracts/consents", supplier_consent).status == 409);

    // The instance's evidence: for the staff and the parties, verified
    // offline, the signers the registrar claimed included.
    const std::string evidence_path = "/v1/contracts/instances/" + hex_id(home.agreement);
    const auto for_bank = send(bank_client, "GET", evidence_path);
    INFO(text(for_bank));
    REQUIRE(for_bank.status == 200);
    protocol::VerifyOptions options;
    options.expected_ledger = home.id;
    auto report = protocol::verify_contract_evidence(provider(), for_bank.body, options);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    REQUIRE(report->instance.instance);
    CHECK(report->instance.instance->status == "effective");
    REQUIRE(report->steps.size() == 2);
    CHECK(report->steps.back().consents.size() == 2);
    CHECK(send(staff, "GET", evidence_path).status == 200);
    CHECK(send(supplier_client, "GET", evidence_path).status == 200);
    CHECK(send(buyer_client, "GET", evidence_path).status == 404);

    // The contracts, for read tokens only.
    const auto list = send(staff, "GET", "/v1/contracts");
    REQUIRE(list.status == 200);
    CHECK(body_json(list)["total"] == 1);
    CHECK(body_json(list)["contracts"][0]["instances"] == 1);
    const auto shown = send(staff, "GET", "/v1/contracts/" + hex_id(home.contract));
    REQUIRE(shown.status == 200);
    CHECK(body_json(shown)["name"] == "Supply agreement");
    CHECK(body_json(shown)["functions"]["sign"] == "call");
    CHECK(body_json(shown)["code_size"] == counting().size());
    CHECK(body_json(shown)["source_size"] == 2);
    CHECK(send(supplier_client, "GET", "/v1/contracts").status == 403);
    CHECK(send(staff, "GET", "/v1/contracts/" + hex_id(home.agreement)).status == 404);
}

TEST_CASE("a registrar refuses calls it cannot use, and drops what lapsed", "[node][contracts]") {
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    Home home(supplier, bank, buyer);
    const protocol::Id s = supplier.ledger().id();
    const protocol::Id b = bank.ledger().id();
    const cbor::Value arguments = outputs({needs({s, b}), needs({s, b}), accept("effective")});

    {
        // Without a registrar, neither proposals nor consents are taken.
        auto api = home.api(false);
        Running server(*api);
        CHECK(send(server.client(home.staff), "POST", "/v1/contracts/calls",
                   proposal(*api, home, "sign", arguments))
                  .status == 501);
        CHECK(
            send(server.client(home.supplier_token), "POST", "/v1/contracts/consents", Bytes{0xa0})
                .status == 501);
    }

    auto api = home.api();
    Running server(*api);
    const auto staff = server.client(home.staff);
    const auto supplier_client = server.client(home.supplier_token);
    const auto bank_client = server.client(home.bank_token);
    const std::uint64_t head = api->ledger().state().instance(home.agreement)->head;

    // A party proposes; the contract decides what it makes of it.
    CHECK(send(supplier_client, "POST", "/v1/contracts/calls",
               proposal(*api, home, "sign", outputs({accept("effective")})))
              .status == 409); // it needs no consents: the home signs such calls itself
    const auto refused = send(supplier_client, "POST", "/v1/contracts/calls",
                              proposal(*api, home, "sign", cbor::Value::text("over the limit")));
    CHECK(refused.status == 409);
    CHECK(text(refused).find("over the limit") != std::string::npos);
    CHECK(send(staff, "POST", "/v1/contracts/calls", proposal(*api, home, "propose", arguments))
              .status == 400); // creates: not a call on the instance
    CHECK(send(staff, "POST", "/v1/contracts/calls", Bytes{0x01, 0x02}).status == 400);
    {
        node::PendingCall stale;
        stale.instance = home.agreement;
        stale.head = head - 1;
        stale.function = "sign";
        stale.arguments = arguments;
        CHECK(
            send(staff, "POST", "/v1/contracts/calls", *node::encode_call_proposal(stale)).status ==
            409);
        stale.instance = home.contract;
        stale.head = head;
        CHECK(
            send(staff, "POST", "/v1/contracts/calls", *node::encode_call_proposal(stale)).status ==
            404);
    }

    // A proposal that lapses before anyone consents.
    const auto short_lived = send(staff, "POST", "/v1/contracts/calls",
                                  proposal(*api, home, "close", arguments, now() + 1000));
    REQUIRE(short_lived.status == 202);
    const protocol::Timestamp until = now() + 30 * day;
    const Bytes close_consent = consent(supplier, home.id, crypto::HashAlg::sha256, home.agreement,
                                        head, "close", arguments, until);
    std::this_thread::sleep_for(1500ms);
    CHECK(send(supplier_client, "POST", "/v1/contracts/consents", close_consent).status == 409);
    CHECK(send(staff, "GET",
               "/v1/contracts/calls/" + body_json(short_lived)["call"].get<std::string>())
              .status == 404);

    // A consent that lapses while the call waits is dropped; one that has
    // lapsed already is refused.
    REQUIRE(send(staff, "POST", "/v1/contracts/calls", proposal(*api, home, "sign", arguments))
                .status == 202);
    CHECK(send(supplier_client, "POST", "/v1/contracts/consents",
               consent(supplier, home.id, crypto::HashAlg::sha256, home.agreement, head, "sign",
                       arguments, now() - 1000))
              .status == 422);
    const auto held = send(supplier_client, "POST", "/v1/contracts/consents",
                           consent(supplier, home.id, crypto::HashAlg::sha256, home.agreement, head,
                                   "sign", arguments, now() + 1500));
    INFO(text(held));
    REQUIRE(held.status == 202);
    CHECK(body_json(held)["consented"] == json::array({hex_id(s)}));
    std::this_thread::sleep_for(2000ms);
    const auto after = send(bank_client, "POST", "/v1/contracts/consents",
                            consent(bank, home.id, crypto::HashAlg::sha256, home.agreement, head,
                                    "sign", arguments, until));
    INFO(text(after));
    REQUIRE(after.status == 202);
    CHECK(body_json(after)["consented"] == json::array({hex_id(b)}));

    // The supplier consents again; recorded, and the other pending calls on
    // the old head are dropped.
    REQUIRE(send(staff, "POST", "/v1/contracts/calls",
                 proposal(*api, home, "close", outputs({needs({s}), accept("closed", {}, true)})))
                .status == 202);
    const auto done = send(supplier_client, "POST", "/v1/contracts/consents",
                           consent(supplier, home.id, crypto::HashAlg::sha256, home.agreement, head,
                                   "sign", arguments, until));
    INFO(text(done));
    REQUIRE(done.status == 201);
    CHECK(api->ledger().state().instance(home.agreement)->status == "effective");
    CHECK(body_json(send(staff, "GET", "/v1/contracts/calls"))["calls"].empty());
    CHECK(std::filesystem::is_empty(node::pending_calls_directory(home.dir)));

    // The ledger's rules for requests (v0.8) apply to what the registrar
    // records: once the supplier consents, the contract accepts a call that
    // asks for work due at once, and the registrar refuses it with the
    // ledger's reason instead of signing it.
    protocol::ContractAccept asking = accept("asked");
    asking.requests.push_back({"provision", cbor::Value::null(), 1, "sign"});
    const cbor::Value ask = outputs({needs({s}), asking});
    REQUIRE(send(staff, "POST", "/v1/contracts/calls", proposal(*api, home, "sign", ask)).status ==
            202);
    const std::uint64_t moved = api->ledger().state().instance(home.agreement)->head;
    const std::uint64_t size = api->ledger().size();
    const auto asked = send(supplier_client, "POST", "/v1/contracts/consents",
                            consent(supplier, home.id, crypto::HashAlg::sha256, home.agreement,
                                    moved, "sign", ask, until));
    INFO(text(asked));
    CHECK(asked.status == 409);
    CHECK(text(asked).find("the ledger refuses the call: a request's deadline") !=
          std::string::npos);
    CHECK(api->ledger().size() == size);
    CHECK(api->ledger().state().instance(home.agreement)->status == "effective");
}

TEST_CASE("a registrar takes many consents at once, as it would one after another",
          "[node][contracts]") {
    // Agreements that the supplier's consent alone takes into effect, each
    // proposed, then every consent posted at once from several threads,
    // some twice: each call is recorded once, with its consent, and a
    // consent sent again finds its instance moved on, whether or not it
    // came in the same group as the first.
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    Home home(supplier, bank, buyer);
    const protocol::Id s = supplier.ledger().id();
    const cbor::Value arguments = outputs({needs({s}), accept("effective")});
    constexpr std::size_t count = 24;
    std::vector<protocol::Id> agreements;
    {
        auto fs = ledger::PosixFileSystem::open_directory(home.dir);
        REQUIRE(fs);
        auto ledger = ledger::Ledger::open(*fs, home.clock, provider());
        REQUIRE(ledger);
        std::vector<Bytes> creations;
        for (std::size_t i = 0; i < count; ++i) {
            protocol::ContractCallBody create;
            create.contract = home.contract;
            create.function = "propose";
            create.arguments = outputs(
                {accept("proposed " + std::to_string(i), protocol::Parties{{"supplier", s}})});
            creations.push_back(home.sign(create));
        }
        const std::vector<cexchain::ByteView> views(creations.begin(), creations.end());
        for (auto& r : ledger->submit_batch(views)) {
            REQUIRE(r);
            agreements.push_back(r->statement_id);
        }
    }
    auto api = home.api();
    Running server(*api);
    const auto staff = server.client(home.staff);

    std::vector<Bytes> bundles;
    for (const protocol::Id& a : agreements) {
        node::PendingCall p;
        p.instance = a;
        p.head = api->ledger().state().instance(a)->head;
        p.function = "sign";
        p.arguments = arguments;
        auto encoded = node::encode_call_proposal(p);
        REQUIRE(encoded);
        const auto proposed = send(staff, "POST", "/v1/contracts/calls", *encoded);
        INFO(text(proposed));
        REQUIRE(proposed.status == 202);
        bundles.push_back(consent(supplier, home.id, crypto::HashAlg::sha256, a, p.head, "sign",
                                  arguments, now() + 30 * day));
    }
    // Every consent, and every third one again.
    std::vector<std::size_t> order;
    for (std::size_t i = 0; i < count; ++i) {
        order.push_back(i);
        if (i % 3 == 0) {
            order.push_back(i);
        }
    }
    std::vector<int> statuses(order.size(), 0);
    std::atomic<std::size_t> next = 0;
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            const auto client = server.client(home.supplier_token);
            for (std::size_t k; (k = next.fetch_add(1)) < order.size();) {
                auto r = client.request("POST", "/v1/contracts/consents", bundles[order[k]],
                                        "application/cbor");
                statuses[k] = r ? r->status : -1;
            }
        });
    }
    for (std::thread& t : threads) {
        t.join();
    }
    std::vector<int> recorded(count, 0);
    std::vector<int> stale(count, 0);
    for (std::size_t k = 0; k < order.size(); ++k) {
        INFO("consent " << k << " to agreement " << order[k]);
        CHECK((statuses[k] == 201 || statuses[k] == 409));
        ++(statuses[k] == 201 ? recorded : stale)[order[k]];
    }
    for (std::size_t i = 0; i < count; ++i) {
        INFO("agreement " << i);
        CHECK(recorded[i] == 1);
        CHECK(stale[i] == (i % 3 == 0 ? 1 : 0));
        CHECK(api->ledger().state().instance(agreements[i])->status == "effective");
    }
    // Nothing is pending, and each call's consent is kept: its evidence
    // verifies.
    CHECK(body_json(send(staff, "GET", "/v1/contracts/calls"))["calls"].empty());
    protocol::VerifyOptions options;
    options.expected_ledger = home.id;
    for (const std::size_t i : {std::size_t{0}, count - 1}) {
        const auto evidence =
            send(staff, "GET", "/v1/contracts/instances/" + hex_id(agreements[i]));
        REQUIRE(evidence.status == 200);
        auto report = protocol::verify_contract_evidence(provider(), evidence.body, options);
        INFO((report ? std::string() : std::string(report.error().detail)));
        REQUIRE(report);
        CHECK(report->steps.back().consents.size() == 1);
    }
}

TEST_CASE("a contract call arrives with its consents, and only so", "[node][contracts]") {
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    Home home(supplier, bank, buyer);
    auto api = home.api(false);
    Running server(*api);
    const auto staff = server.client(home.staff);

    // The home's people sign the call themselves, citing the consents with
    // the signers their evidence shows.
    const cbor::Value arguments = outputs({accept("effective")});
    const std::uint64_t head = api->ledger().state().instance(home.agreement)->head;
    const Bytes bundle = consent(supplier, home.id, crypto::HashAlg::sha256, home.agreement, head,
                                 "sign", arguments, now() + 30 * day);
    auto call_with = [&](protocol::ContractSigner signer) {
        protocol::ContractCallBody call;
        call.instance = home.agreement;
        call.head = head;
        call.function = "sign";
        call.arguments = arguments;
        call.consents.push_back({supplier.ledger().id(), protocol::decode_bundle(bundle)->record,
                                 *provider().digest(crypto::HashAlg::sha256, bundle), signer});
        return home.sign(call);
    };
    auto submission = [&](const Bytes& statement, const Bytes& consent_bundle) {
        return *cbor::encode(cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::bytes(statement)},
             {cbor::Value::integer(3), cbor::Value::array({cbor::Value::bytes(consent_bundle)})}}));
    };
    const Bytes honest = call_with({});
    // Alone, it is refused: the home would not hold the consent it cites.
    CHECK(send(staff, "POST", "/v1/statements", honest, "application/cose").status == 400);
    // A citation that claims a person proved presence, where the evidence
    // shows the organization signed, is refused.
    const Bytes misstated = call_with({static_cast<std::uint8_t>(protocol::ActorKind::person),
                                       protocol::PresenceMethod::webauthn, std::nullopt});
    CHECK(send(staff, "POST", "/v1/statements", submission(misstated, bundle),
               node::submission_content_type)
              .status == 422);
    // Another bundle than the one it cites is refused.
    const Bytes other = consent(supplier, home.id, crypto::HashAlg::sha256, home.agreement, head,
                                "sign", arguments, now() + 30 * day);
    CHECK(send(staff, "POST", "/v1/statements", submission(honest, other),
               node::submission_content_type)
              .status == 422);
    const auto recorded = send(staff, "POST", "/v1/statements", submission(honest, bundle),
                               node::submission_content_type);
    INFO(text(recorded));
    REQUIRE(recorded.status == 201);
    CHECK(api->ledger().state().instance(home.agreement)->status == "effective");
    const auto id = protocol::parse_statement(provider(), honest, crypto::HashAlg::sha256)->id;
    CHECK(std::filesystem::exists(node::contract_consents_path(home.dir, id)));

    // Its evidence carries the consent.
    const auto evidence = send(staff, "GET", "/v1/contracts/instances/" + hex_id(home.agreement));
    REQUIRE(evidence.status == 200);
    protocol::VerifyOptions options;
    options.expected_ledger = home.id;
    auto report = protocol::verify_contract_evidence(provider(), evidence.body, options);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    CHECK(report->steps.back().consents.size() == 1);
}

TEST_CASE("a registrar takes calls on parts from their own parties, and serves their ancestors' "
          "consents",
          "[node][contracts]") {
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    Home home(supplier, bank, buyer);
    auto api = home.api();
    Running server(*api);
    const auto staff = server.client(home.staff);
    const auto supplier_client = server.client(home.supplier_token);
    const auto bank_client = server.client(home.bank_token);
    const auto buyer_client = server.client(home.buyer_token);
    const protocol::Id s = supplier.ledger().id();
    const protocol::Id b = bank.ledger().id();
    const protocol::Id k = buyer.ledger().id();
    const protocol::Timestamp until = now() + 30 * day;
    auto head_of = [&](const protocol::Id& instance) {
        return api->ledger().state().instance(instance)->head;
    };

    // With the supplier's consent, the agreement ends in two parts (v0.7):
    // one held by the bank, one by the buyer, which is no party of it.
    const cbor::Value split = outputs({needs({s}), split_among({b, k})});
    const std::uint64_t head = head_of(home.agreement);
    REQUIRE(
        send(staff, "POST", "/v1/contracts/calls", proposal(*api, home, "sign", split)).status ==
        202);
    const auto split_recorded = send(supplier_client, "POST", "/v1/contracts/consents",
                                     consent(supplier, home.id, crypto::HashAlg::sha256,
                                             home.agreement, head, "sign", split, until));
    INFO(text(split_recorded));
    REQUIRE(split_recorded.status == 201);
    const json children = body_json(split_recorded)["children"];
    REQUIRE(children.size() == 2);
    const protocol::Id bank_part = id_from_hex(children[0]);
    const protocol::Id buyer_part = id_from_hex(children[1]);
    const auto split_call = id_from_hex(body_json(split_recorded)["statement_id"]);
    CHECK(bank_part ==
          *protocol::child_instance_id(provider(), crypto::HashAlg::sha256, split_call, 0));
    {
        const auto& state = api->ledger().state();
        CHECK(state.instance(home.agreement)->final);
        const protocol::InstanceState* part = state.instance(buyer_part);
        REQUIRE(part != nullptr);
        CHECK(part->parent == home.agreement);
        CHECK(part->depth == 1);
        CHECK(part->position == 1);
        CHECK(part->parties.at("holder") == k);
    }

    // A final parent takes no proposals. A part's own parties propose calls
    // on it; others, the parent's parties included, find no such instance.
    CHECK(send(supplier_client, "POST", "/v1/contracts/calls",
               proposal(*api, home, "close", outputs({needs({s}), accept("closed")})))
              .status == 409);
    const cbor::Value sell = outputs({needs({k}), accept("sold")});
    CHECK(send(buyer_client, "POST", "/v1/contracts/calls",
               proposal_on(*api, bank_part, "sign", sell))
              .status == 404);
    CHECK(send(supplier_client, "POST", "/v1/contracts/calls",
               proposal_on(*api, buyer_part, "sign", sell))
              .status == 404);
    const auto proposed = send(buyer_client, "POST", "/v1/contracts/calls",
                               proposal_on(*api, buyer_part, "sign", sell));
    INFO(text(proposed));
    REQUIRE(proposed.status == 202);
    CHECK(body_json(proposed)["missing"] == json::array({hex_id(k)}));
    const auto sold = send(buyer_client, "POST", "/v1/contracts/consents",
                           consent(buyer, home.id, crypto::HashAlg::sha256, buyer_part,
                                   head_of(buyer_part), "sign", sell, until));
    INFO(text(sold));
    REQUIRE(sold.status == 201);
    CHECK(body_json(sold)["children"].empty());
    CHECK(api->ledger().state().instance(buyer_part)->status == "sold");

    // A part's evidence goes to its own parties, with the consents its
    // ancestors' calls cite: the supplier's to the split, then the buyer's.
    const std::string buyer_path = "/v1/contracts/instances/" + hex_id(buyer_part);
    CHECK(send(buyer_client, "GET", "/v1/contracts/instances/" + hex_id(bank_part)).status == 404);
    CHECK(send(buyer_client, "GET", "/v1/contracts/instances/" + hex_id(home.agreement)).status ==
          404);
    CHECK(send(supplier_client, "GET", buyer_path).status == 404);
    const auto evidence = send(buyer_client, "GET", buyer_path);
    REQUIRE(evidence.status == 200);
    protocol::VerifyOptions options;
    options.expected_ledger = home.id;
    auto report = protocol::verify_contract_evidence(provider(), evidence.body, options);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    REQUIRE(report->instance.instance);
    CHECK(report->instance.record == buyer_part);
    CHECK(report->instance.instance->parent == home.agreement);
    CHECK(report->instance.instance->ancestors.size() == 1);
    REQUIRE(report->steps.size() == 3); // the creation, the split, the sale
    CHECK(report->steps[1].consents.size() == 1);
    CHECK(report->steps[1].consents[0].ref.ledger == s);
    CHECK(report->steps[2].consents.size() == 1);
    CHECK(report->steps[2].consents[0].ref.ledger == k);
    const auto for_bank = send(bank_client, "GET", "/v1/contracts/instances/" + hex_id(bank_part));
    REQUIRE(for_bank.status == 200);
    auto bank_report = protocol::verify_contract_evidence(provider(), for_bank.body, options);
    REQUIRE(bank_report);
    CHECK(bank_report->steps.size() == 2);

    // The ledger's rules for parts apply to what the registrar records: once
    // the contract is retired, a call that would create parts is refused
    // with the ledger's reason, whether the contract accepts it at once or
    // once the consents are in. Calls that create none carry on.
    REQUIRE(send(staff, "POST", "/v1/statements",
                 home.sign(protocol::ContractRetireBody{home.contract, "version 2"}),
                 "application/cose")
                .status == 201);
    const auto at_once = send(staff, "POST", "/v1/contracts/calls",
                              proposal_on(*api, bank_part, "sign", outputs({split_among({b})})));
    CHECK(at_once.status == 409);
    CHECK(text(at_once).find("a retired contract creates no more instances") != std::string::npos);
    const cbor::Value resplit = outputs({needs({b}), split_among({b, b})});
    REQUIRE(send(bank_client, "POST", "/v1/contracts/calls",
                 proposal_on(*api, bank_part, "sign", resplit))
                .status == 202);
    const auto refused = send(bank_client, "POST", "/v1/contracts/consents",
                              consent(bank, home.id, crypto::HashAlg::sha256, bank_part,
                                      head_of(bank_part), "sign", resplit, until));
    CHECK(refused.status == 409);
    CHECK(text(refused).find("a retired contract creates no more instances") != std::string::npos);
    const cbor::Value keep = outputs({needs({b}), accept("kept")});
    REQUIRE(send(bank_client, "POST", "/v1/contracts/calls",
                 proposal_on(*api, bank_part, "close", keep))
                .status == 202);
    CHECK(send(bank_client, "POST", "/v1/contracts/consents",
               consent(bank, home.id, crypto::HashAlg::sha256, bank_part, head_of(bank_part),
                       "close", keep, until))
              .status == 201);
    CHECK(api->ledger().state().instance(bank_part)->status == "kept");
}

TEST_CASE("pending calls survive their files' round trip", "[node][contracts]") {
    node::PendingCall c;
    c.instance = *protocol::to_id(Bytes(32, 7));
    c.head = 12;
    c.function = "sign";
    c.arguments = cbor::Value::array({cbor::Value::bytes(Bytes{1, 2}), cbor::Value::text("x")});
    c.reference = "PO-1";
    c.until = t0 + day;
    // A proposal names the call only.
    auto proposal = node::encode_call_proposal(c);
    REQUIRE(proposal);
    auto decoded_proposal = node::decode_call_proposal(*proposal);
    REQUIRE(decoded_proposal);
    CHECK(*decoded_proposal == c);
    CHECK_FALSE(node::decode_pending_call(*proposal)); // no proposer

    c.proposer = "staff";
    c.missing = {*protocol::to_id(Bytes(32, 1)), *protocol::to_id(Bytes(32, 3))};
    c.consents = {{*protocol::to_id(Bytes(32, 2)), Bytes{0xa0}}};
    auto file = node::encode_pending_call(c);
    REQUIRE(file);
    auto decoded = node::decode_pending_call(*file);
    REQUIRE(decoded);
    CHECK(*decoded == c);
    CHECK_FALSE(node::decode_call_proposal(*file)); // progress is not a proposal's

    // Unordered ledgers are refused.
    std::ranges::reverse(c.missing);
    CHECK_FALSE(node::encode_pending_call(c));

    // Names: <instance>-<head>-<id>.cbor, strictly.
    const node::PendingName name{c.instance, 12, *protocol::to_id(Bytes(32, 9))};
    const std::string text = node::pending_call_name(name);
    const auto parsed = node::parse_pending_call_name(text);
    REQUIRE(parsed);
    CHECK(parsed->instance == name.instance);
    CHECK(parsed->head == 12);
    CHECK(parsed->id == name.id);
    CHECK_FALSE(node::parse_pending_call_name(text + ".tmp"));
    CHECK_FALSE(node::parse_pending_call_name("../" + text));
    std::string leading_zero = text;
    leading_zero.insert(65, "0");
    CHECK_FALSE(node::parse_pending_call_name(leading_zero));
    std::string upper = text;
    upper[0] = 'A';
    CHECK_FALSE(node::parse_pending_call_name(upper));
}

TEST_CASE("a cluster's registrar carries on with a pending call after a failover",
          "[node][contracts][cluster]") {
    World supplier{crypto::HashAlg::sha256, "Supplier"};
    World bank{crypto::HashAlg::sm3, "Bank"};
    World buyer{crypto::HashAlg::sha256, "Buyer"};
    Home home(supplier, bank, buyer);

    // Three members, each with a copy of the home's ledger; the first founds
    // the cluster.
    struct Member {
        std::filesystem::path dir;
        node::ClusterNode config;
        std::uint16_t api_port = 0;
        std::unique_ptr<node::LedgerApi> api;
        std::unique_ptr<Running> server;
    };
    std::vector<Member> members(3);
    const Bytes secret(node::cluster_secret_size, 0x3c);
    for (int i = 0; i < 3; ++i) {
        Member& m = members[static_cast<std::size_t>(i)];
        m.dir = i == 0
                    ? home.dir
                    : std::filesystem::path(home.dir.string() + "-member" + std::to_string(i + 1));
        if (i > 0) {
            std::filesystem::remove_all(m.dir);
            std::filesystem::copy(home.dir, m.dir, std::filesystem::copy_options::recursive);
        }
        const std::uint16_t port = fixed_port();
        m.api_port = fixed_port();
        m.config = {i + 1, "127.0.0.1:" + std::to_string(port), port,
                    "http://127.0.0.1:" + std::to_string(m.api_port), i == 0};
        REQUIRE(node::init_cluster(m.dir, m.config, secret));
    }
    auto start = [&](Member& m) {
        node::ApiOptions o;
        o.directory = m.dir;
        o.log_keys = {home.log_key};
        o.registrar = home.registrar;
        o.cluster = true;
        auto opened = node::LedgerApi::open(o, provider());
        INFO((opened ? std::string() : std::string(opened.error().detail)));
        REQUIRE(opened);
        m.api = std::move(*opened);
        m.server = std::make_unique<Running>(*m.api, m.api_port);
    };
    auto leads = [&](const Member& m) {
        if (!m.server) {
            return false;
        }
        auto r = m.server->client(home.staff).request("GET", "/v1/cluster");
        return r && r->status == 200 &&
               json::parse(r->body.begin(), r->body.end())["leads"] == true;
    };
    auto leader = [&]() -> Member* {
        for (Member& m : members) {
            if (leads(m)) {
                return &m;
            }
        }
        return nullptr;
    };
    for (Member& m : members) {
        start(m);
    }
    REQUIRE(eventually([&] { return leads(members[0]); }));
    for (std::size_t i = 1; i < 3; ++i) {
        const json member = {{"id", members[i].config.id},
                             {"raft", members[i].config.raft_endpoint},
                             {"api", members[i].config.api_url}};
        const std::string text = member.dump();
        REQUIRE(eventually([&] {
            Member* now = leader();
            if (now == nullptr) {
                return false;
            }
            auto r = now->server->client(home.staff)
                         .request("POST", "/v1/cluster/members", Bytes(text.begin(), text.end()),
                                  "application/json");
            return r && r->status == 200;
        }));
    }
    auto in_step = [&] {
        Member* now = leader();
        if (now == nullptr) {
            return false;
        }
        for (const Member& m : members) {
            if (m.api && m.api->ledger().size() != now->api->ledger().size()) {
                return false;
            }
        }
        return true;
    };
    REQUIRE(eventually(in_step));

    const protocol::Id s = supplier.ledger().id();
    const protocol::Id b = bank.ledger().id();
    const cbor::Value arguments = outputs({needs({s, b}), needs({b}), accept("effective")});
    const std::uint64_t head = members[0].api->ledger().state().instance(home.agreement)->head;
    const protocol::Timestamp until = now() + 30 * day;

    // The leader takes the proposal, and the supplier's consent sent to a
    // follower (which sends writers to the leader); every member holds the
    // pending call.
    Member* first = leader();
    REQUIRE(first != nullptr);
    const auto proposed = send(first->server->client(home.staff), "POST", "/v1/contracts/calls",
                               proposal(*first->api, home, "sign", arguments));
    INFO(text(proposed));
    REQUIRE(proposed.status == 202);
    const Member* follower = first == &members[0] ? &members[1] : &members[0];
    const auto waiting =
        send(follower->server->client(home.supplier_token), "POST", "/v1/contracts/consents",
             consent(supplier, home.id, crypto::HashAlg::sha256, home.agreement, head, "sign",
                     arguments, until));
    INFO(text(waiting));
    REQUIRE(waiting.status == 202);
    for (const Member& m : members) {
        CHECK(eventually([&] {
            const auto held = node::held_calls(m.dir);
            return held.size() == 1 && held.front().call.consents.size() == 1;
        }));
    }

    // The leader goes away; the new one records the call with the bank's
    // consent and the supplier's, which it already held.
    first->server.reset();
    first->api.reset();
    Member* second = nullptr;
    REQUIRE(eventually([&] {
        second = leader();
        return second != nullptr;
    }));
    const auto recorded =
        send(second->server->client(home.bank_token), "POST", "/v1/contracts/consents",
             consent(bank, home.id, crypto::HashAlg::sha256, home.agreement, head, "sign",
                     arguments, until));
    INFO(text(recorded));
    REQUIRE(recorded.status == 201);
    const protocol::Id call = *protocol::to_id(
        *cexchain::from_hex(body_json(recorded)["statement_id"].get<std::string>()));
    for (const Member& m : members) {
        if (!m.api) {
            continue;
        }
        CHECK(eventually([&] {
            // Under the state's lock: the member applies entries meanwhile.
            bool effective = false;
            m.api->ledger().read_state([&](const protocol::LedgerState& state) {
                const auto* i = state.instance(home.agreement);
                effective = i != nullptr && i->status == "effective";
            });
            return effective &&
                   std::filesystem::exists(node::contract_consents_path(m.dir, call)) &&
                   node::held_calls(m.dir).empty();
        }));
    }
    for (std::size_t i = 1; i < 3; ++i) {
        members[i].server.reset();
        members[i].api.reset();
        std::filesystem::remove_all(members[i].dir);
    }
}
