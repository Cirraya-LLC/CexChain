// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Requests and answers (spec v0.8) through a home's server (6b, E3): the
// discovery route, GET /v1/requests, filtered and paged by a cursor, and as a
// long poll that ends when a request is made, when its wait is over, or when
// the server stops; and the executor token scope, which reads requests and
// instances' evidence and submits answers, nothing else. What the route
// gives is a hint: executors check a request in the instance's evidence.

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
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
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "support/ledger_world.hpp"
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
        ("cexchain-requests-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
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
        o.timeout = std::chrono::seconds(15);
        return node::Client(*node::Url::parse("http://127.0.0.1:" + std::to_string(server_.port())),
                            o);
    }

private:
    static node::ServerOptions options() {
        node::ServerOptions o;
        o.port = 0;
        o.request_timeout = std::chrono::seconds(10);
        return o;
    }
    node::Server server_;
    std::thread thread_;
};

cbor::Value text(std::string value) {
    return cbor::Value::text(std::move(value));
}

/// The requesting contract's arguments that make requests: [[kind, params,
/// after], ...], each due `after` ms after the call.
cbor::Value asks(const std::vector<std::pair<std::string, protocol::Timestamp>>& specs) {
    cbor::Array items;
    for (const auto& [kind, after] : specs) {
        items.push_back(cbor::Value::array(
            {text(kind), cbor::Value::map({{text("n"), cbor::Value::unsigned_integer(after)}}),
             cbor::Value::unsigned_integer(after)}));
    }
    return cbor::Value::array(std::move(items));
}

constexpr protocol::Timestamp hour = 3'600'000;

/// A home in a directory, its clock ten minutes behind the server's (which
/// registers at the real time), with the requesting contract
/// (testvectors/test-contracts.json), an instance whose creation made two
/// requests (notify, http.post) and whose next call made one more (notify),
/// the first answered; an executor device that answers notify requests with
/// result (scope keys 7, 8, and 9), with an older, general delegation for
/// calls on the contract; and tokens: staff (read, submit), a reader, an
/// executor, and a peer.
struct Home {
    std::filesystem::path dir = fresh_directory();
    ledger::ManualClock clock{ledger::SystemClock{}.now() - 600'000};
    ledger::SeededEntropy entropy{43};
    KeyPair org = key("requests home org");
    std::shared_ptr<const KeyPair> log_key =
        std::make_shared<const KeyPair>(key("requests home log"));
    KeyPair device = key("requests executor device");
    protocol::Id id;
    protocol::Id contract;
    protocol::Id instance;
    protocol::Id executor;
    protocol::Id general;
    protocol::Id answers;
    /// The requests: [0] notify and [1] http.post, made by the creation; [2]
    /// notify, made by the call `ask`. [0] is answered.
    std::vector<protocol::Id> requests;
    std::uint64_t created_at = 0;
    std::uint64_t asked_at = 0;
    std::uint64_t answered_at = 0;
    std::string staff = "staff-token-0123456789";
    std::string reader = "reader-token-0123456789";
    std::string executor_token = "executor-token-0123456789";
    std::string peer_token = "peer-token-0123456789";

    Home() {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Requests Home",
                                             org.public_key(), log_key->public_key()};
        auto signed_genesis =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, genesis);
        REQUIRE(signed_genesis);
        auto ledger = ledger::Ledger::create(*fs, clock, provider(), signed_genesis->encoded);
        REQUIRE(ledger);
        id = ledger->id();
        auto submit = [&](const KeyPair& signer, const protocol::Id& actor,
                          std::optional<protocol::Id> delegation, protocol::Body body) {
            auto registered =
                ledger->submit(sign(signer, actor, std::move(delegation), std::move(body)));
            INFO((registered ? std::string() : std::string(registered.error().detail)));
            REQUIRE(registered);
            clock.advance(1000);
            return *registered;
        };
        const auto vectors = load_vectors("test-contracts.json");
        protocol::ContractDeployBody deploy;
        deploy.code = hex(vectors["request"].get<std::string>());
        for (const auto& [name, kind] : vectors["request_interface"].items()) {
            deploy.interface.emplace(name, static_cast<protocol::FunctionKind>(kind.get<int>()));
        }
        deploy.language = "wasm";
        deploy.compiler = "test_contracts.py 1";
        deploy.name = "Requesting";
        contract = submit(org, id, std::nullopt, deploy).statement_id;
        protocol::ContractCallBody create;
        create.contract = contract;
        create.function = "open";
        create.arguments = asks({{"notify", hour}, {"http.post", 2 * hour}});
        const auto created = submit(org, id, std::nullopt, create);
        instance = created.statement_id;
        created_at = created.index;
        protocol::ContractCallBody ask;
        ask.instance = instance;
        ask.head = created.index;
        ask.function = "ask";
        ask.arguments = asks({{"notify", 3 * hour}});
        const auto asked = submit(org, id, std::nullopt, ask);
        asked_at = asked.index;
        for (const auto& [call, position] : std::vector<std::pair<protocol::Id, std::uint64_t>>{
                 {instance, 0}, {instance, 1}, {asked.statement_id, 0}}) {
            auto rid = protocol::request_id(provider(), crypto::HashAlg::sha256, call, position);
            REQUIRE(rid);
            requests.push_back(*rid);
        }
        protocol::ContractCallBody answer;
        answer.instance = instance;
        answer.head = asked.index;
        answer.function = "result";
        answer.answer = protocol::ContractAnswer{requests[0], protocol::AnswerStatus::done};
        answered_at = submit(org, id, std::nullopt, answer).index;

        executor = submit(org, id, std::nullopt,
                          protocol::ActorRegisterBody{
                              protocol::ActorKind::device, "Notifier", device.public_key(), {}, {}})
                       .statement_id;
        auto calls = scope({StatementType::contract_call});
        calls.contracts = std::vector<protocol::Id>{contract};
        general = submit(org, id, std::nullopt, protocol::DelegationGrantBody{executor, calls})
                      .statement_id;
        calls.functions = std::vector<std::string>{"result"};
        calls.request_kinds = std::vector<std::string>{"notify"};
        answers = submit(org, id, std::nullopt, protocol::DelegationGrantBody{executor, calls})
                      .statement_id;
        REQUIRE(ledger->checkpoint(*log_key));
        live = true;

        auto s = [](node::Scope scope) {
            return static_cast<node::Scopes>(scope);
        };
        REQUIRE(node::save_tokens(
            dir,
            {{"staff", static_cast<node::Scopes>(s(node::Scope::read) | s(node::Scope::submit)),
              node::token_hash(provider(), staff), t0},
             {"reader", s(node::Scope::read), node::token_hash(provider(), reader), t0},
             {"notifier", s(node::Scope::executor), node::token_hash(provider(), executor_token),
              t0},
             {"partner", s(node::Scope::peer), node::token_hash(provider(), peer_token), t0}}));
    }
    Home(const Home&) = delete;
    Home& operator=(const Home&) = delete;
    ~Home() { std::filesystem::remove_all(dir); }

    /// Set once the fixture's ledger is made: statements then go to the
    /// server, which registers them at the real time.
    bool live = false;

    /// A statement signed at the fixture's time, or at the real time once
    /// `live` (the server's clock).
    Bytes sign(const KeyPair& signer, const protocol::Id& actor,
               std::optional<protocol::Id> delegation, protocol::Body body) {
        protocol::Statement st;
        st.ledger_id = id;
        st.actor_id = actor;
        st.delegation_id = std::move(delegation);
        st.issued_at = live ? ledger::SystemClock{}.now() : clock.now();
        st.nonce = entropy.bytes<16>();
        st.body = std::move(body);
        auto signed_statement =
            protocol::sign_statement(signer, provider(), crypto::HashAlg::sha256, st);
        REQUIRE(signed_statement);
        return signed_statement->encoded;
    }

    std::unique_ptr<node::LedgerApi> api() const {
        node::ApiOptions o;
        o.directory = dir;
        o.log_keys = {log_key};
        auto opened = node::LedgerApi::open(o, provider());
        REQUIRE(opened);
        return std::move(*opened);
    }
};

node::http::ClientResponse get(const node::Client& c, const std::string& path) {
    auto r = c.request("GET", path);
    REQUIRE(r);
    return std::move(*r);
}

node::http::ClientResponse post(const node::Client& c, const std::string& path, const Bytes& body,
                                std::string_view type = "application/cose") {
    auto r = c.request("POST", path, body, type);
    REQUIRE(r);
    return std::move(*r);
}

json body_json(const node::http::ClientResponse& r) {
    return json::parse(r.body.begin(), r.body.end());
}

std::string hex_id(const protocol::Id& id) {
    return cexchain::to_hex(id.bytes());
}

std::vector<std::string> ids(const json& answer) {
    std::vector<std::string> out;
    for (const json& r : answer["requests"]) {
        out.push_back(r["id"].get<std::string>());
    }
    return out;
}

/// A call `ask` on the instance at its head, making a request of `kind`.
Bytes ask(Home& home, const node::LedgerApi& api, const std::string& kind) {
    protocol::ContractCallBody call;
    call.instance = home.instance;
    call.head = api.ledger().state().instance(home.instance)->head;
    call.function = "ask";
    call.arguments = asks({{kind, hour}});
    return home.sign(home.org, home.id, std::nullopt, call);
}

} // namespace

TEST_CASE("the requests route lists requests, filtered, and pages them with a cursor",
          "[node][requests]") {
    Home home;
    const auto api = home.api();
    const Running running(*api);
    const auto staff = running.client(home.staff);
    const std::string r0 = hex_id(home.requests[0]);
    const std::string r1 = hex_id(home.requests[1]);
    const std::string r2 = hex_id(home.requests[2]);

    // Open ones by default, oldest change first, with what an answer needs.
    auto response = get(staff, "/v1/requests");
    REQUIRE(response.status == 200);
    json open = body_json(response);
    CHECK(ids(open) == std::vector<std::string>{r1, r2});
    const json& first = open["requests"][0];
    CHECK(first["kind"] == "http.post");
    CHECK(first["instance"] == hex_id(home.instance));
    CHECK(first["contract"] == hex_id(home.contract));
    CHECK(first["head"] == home.answered_at);
    CHECK(first["reply"] == "result");
    CHECK(first["call"] == home.created_at);
    CHECK(first["position"] == 1);
    CHECK(first["status"] == "open");
    CHECK(first["answered_by"].is_null());
    CHECK(first["overdue"] == false);
    CHECK(first["deadline"].get<protocol::Timestamp>() ==
          first["asked_at"].get<protocol::Timestamp>() + 2 * hour);
    CHECK(first["params"] == "a1616e1a006ddd00"); // {"n": 7200000}
    CHECK(open["cursor"] == api->ledger().size());
    CHECK(open["more"] == false);

    // Answered ones, and all of them by when they last changed.
    json answered = body_json(get(staff, "/v1/requests?state=answered"));
    CHECK(ids(answered) == std::vector<std::string>{r0});
    CHECK(answered["requests"][0]["status"] == "done");
    CHECK(answered["requests"][0]["answered_by"] == home.answered_at);
    CHECK(ids(body_json(get(staff, "/v1/requests?state=all"))) ==
          std::vector<std::string>{r1, r2, r0});

    // Filters: kinds, the instance, the contract.
    CHECK(ids(body_json(get(staff, "/v1/requests?kind=notify"))) == std::vector<std::string>{r2});
    CHECK(ids(body_json(get(staff, "/v1/requests?kind=notify,http.post&state=all"))) ==
          std::vector<std::string>{r1, r2, r0});
    CHECK(ids(body_json(get(staff, "/v1/requests?instance=" + hex_id(home.instance)))).size() == 2);
    CHECK(ids(body_json(get(staff, "/v1/requests?contract=" + hex_id(home.contract)))).size() == 2);
    CHECK(ids(body_json(get(staff, "/v1/requests?instance=" + hex_id(home.contract)))).empty());

    // A page ends between log entries; the cursor goes on from there.
    json page = body_json(get(staff, "/v1/requests?limit=1"));
    CHECK(ids(page) == std::vector<std::string>{r1});
    CHECK(page["more"] == true);
    CHECK(page["cursor"] == home.asked_at);
    page = body_json(get(staff, "/v1/requests?limit=1&after=" + page["cursor"].dump()));
    CHECK(ids(page) == std::vector<std::string>{r2});
    CHECK(page["more"] == false);
    CHECK(ids(body_json(get(staff, "/v1/requests?after=" + page["cursor"].dump()))).empty());
    CHECK(ids(body_json(
              get(staff, "/v1/requests?state=all&after=" + std::to_string(home.answered_at)))) ==
          std::vector<std::string>{r0});

    // Bad questions, and callers without the scope.
    for (const std::string query : {"state=closed", "kind=Notify", "kind=notify,", "contract=12",
                                    "after=x", "limit=0", "limit=1001", "wait=26", "since=3"}) {
        INFO(query);
        CHECK(get(staff, "/v1/requests?" + query).status == 400);
    }
    CHECK(get(running.client(""), "/v1/requests").status == 401);
    CHECK(get(running.client(home.peer_token), "/v1/requests").status == 403);
    CHECK(get(running.client(home.reader), "/v1/requests").status == 200);
    CHECK(post(staff, "/v1/requests", {}).status == 405);
}

TEST_CASE("a long poll for requests ends when one is made, when its wait is over, or when the "
          "server stops",
          "[node][requests]") {
    Home home;
    const auto api = home.api();
    auto running = std::make_unique<Running>(*api);
    const auto staff = running->client(home.staff);
    const std::string cursor = std::to_string(api->ledger().size());

    // Nothing new: the answer comes once the wait is over, empty.
    auto started = std::chrono::steady_clock::now();
    json answer = body_json(get(staff, "/v1/requests?wait=1&after=" + cursor));
    auto took = std::chrono::steady_clock::now() - started;
    CHECK(ids(answer).empty());
    CHECK(answer["cursor"].dump() == cursor);
    CHECK(took >= 900ms);
    CHECK(took < 5s);

    // A request made while a poll waits ends the wait at once.
    auto waiting = std::async(std::launch::async, [&] {
        const auto t = std::chrono::steady_clock::now();
        auto r = staff.request("GET", "/v1/requests?kind=notify&wait=10&after=" + cursor);
        return std::pair(std::move(r), std::chrono::steady_clock::now() - t);
    });
    std::this_thread::sleep_for(300ms);
    // One of another kind first: the poll goes on waiting.
    REQUIRE(post(staff, "/v1/statements", ask(home, *api, "http.post")).status == 201);
    std::this_thread::sleep_for(300ms);
    CHECK(waiting.wait_for(0ms) == std::future_status::timeout);
    REQUIRE(post(staff, "/v1/statements", ask(home, *api, "notify")).status == 201);
    auto [result, waited] = waiting.get();
    REQUIRE(result);
    REQUIRE(result->status == 200);
    answer = body_json(*result);
    REQUIRE(answer["requests"].size() == 1);
    CHECK(answer["requests"][0]["kind"] == "notify");
    CHECK(waited < 3s);

    // A poll that is still waiting when the server stops is answered then,
    // and does not hold the server up.
    auto stopped = std::async(std::launch::async, [&] {
        return staff.request("GET", "/v1/requests?wait=25&after=" + answer["cursor"].dump());
    });
    std::this_thread::sleep_for(500ms);
    started = std::chrono::steady_clock::now();
    running.reset();
    CHECK(std::chrono::steady_clock::now() - started < 5s);
    auto last = stopped.get();
    REQUIRE(last);
    CHECK(last->status == 200);
    CHECK(ids(body_json(*last)).empty());
}

TEST_CASE("an executor's token reads requests and evidence, and submits answers only",
          "[node][requests]") {
    Home home;
    const auto api = home.api();
    const Running running(*api);
    const auto executor = running.client(home.executor_token);

    CHECK(get(executor, "/v1/requests").status == 200);
    // An instance's evidence, to check a request in before acting on it.
    auto evidence = get(executor, "/v1/contracts/instances/" + hex_id(home.instance));
    REQUIRE(evidence.status == 200);
    protocol::VerifyOptions options;
    options.expected_ledger = home.id;
    auto report = protocol::verify_contract_evidence(provider(), evidence.body, options);
    REQUIRE(report);
    REQUIRE(report->instance.instance->open_requests().size() == 2);
    // Nothing else of the home's.
    CHECK(get(executor, "/v1/status").status == 403);
    CHECK(get(executor, "/v1/entries").status == 403);
    CHECK(get(executor, "/v1/contracts").status == 403);

    // The device's delegations: the one for notify answers only for those.
    const protocol::Id notify = home.requests[2];
    const auto head = api->ledger().state().instance(home.instance)->head;
    protocol::ContractCallBody answer;
    answer.instance = home.instance;
    answer.head = head;
    answer.function = "result";
    answer.arguments = cbor::Value::map({{text("ref"), text("N-1")}});
    answer.answer = protocol::ContractAnswer{notify, protocol::AnswerStatus::done};
    const protocol::LedgerState& state = api->ledger().state();
    const auto now = ledger::SystemClock{}.now();
    CHECK(node::choose_delegation(state, home.executor, StatementType::contract_call, std::nullopt,
                                  now, home.contract, &answer) == home.answers);
    protocol::ContractCallBody other = answer;
    other.answer = protocol::ContractAnswer{home.requests[1], protocol::AnswerStatus::done};
    CHECK(node::choose_delegation(state, home.executor, StatementType::contract_call, std::nullopt,
                                  now, home.contract, &other) == home.general);
    protocol::ContractCallBody plain = answer;
    plain.answer.reset();
    plain.function = "ask";
    CHECK(node::choose_delegation(state, home.executor, StatementType::contract_call, std::nullopt,
                                  now, home.contract, &plain) == home.general);

    // Not an answer: refused before the ledger sees it, even though the
    // device's general delegation would allow it.
    plain.arguments = asks({{"notify", hour}});
    auto refused = post(executor, "/v1/statements",
                        home.sign(home.device, home.executor, home.general, plain));
    CHECK(refused.status == 403);
    CHECK(body_json(refused)["error"]["message"] ==
          "an executor's API token submits answers to requests only");
    CHECK(post(executor, "/v1/statements", Bytes{1, 2, 3}).status == 403);
    CHECK(post(executor, "/v1/statements",
               home.sign(home.org, home.id, std::nullopt,
                         protocol::ActorRevokeBody{home.executor, std::nullopt}))
              .status == 403);

    // An answer goes through, signed by the device under its narrow
    // delegation; the ledger then has it closed.
    auto recorded = post(executor, "/v1/statements",
                         home.sign(home.device, home.executor, home.answers, answer));
    INFO(std::string(recorded.body.begin(), recorded.body.end()));
    REQUIRE(recorded.status == 201);
    const protocol::RequestState* closed = api->ledger().state().request(notify);
    REQUIRE(closed != nullptr);
    CHECK(closed->status == protocol::AnswerStatus::done);
    // A second answer is the ledger's to refuse.
    answer.head = api->ledger().state().instance(home.instance)->head;
    CHECK(post(executor, "/v1/statements",
               home.sign(home.device, home.executor, home.answers, answer))
              .status == 409);
    json answered = body_json(get(executor, "/v1/requests?state=answered&kind=notify"));
    CHECK(answered["requests"].size() == 2);
}
