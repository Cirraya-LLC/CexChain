// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The keeper (6b, E4): what is due, found by dry runs (time rules whose
// contract accepts the call and that would change something; requests open
// past their deadline plus a grace, whose expiry the contract takes), within
// a keeper's delegations; and the server's keeper, which fires what is due
// on its ticks, by the ledger's clock (a test clock here, advanced by hand),
// and the route GET /v1/contracts/due.

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/keeper.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "request_query.hpp"
#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
namespace node = cexchain::node;
using cexchain::Bytes;
using json = nlohmann::json;

constexpr protocol::Timestamp hour = 3'600'000;
constexpr protocol::Timestamp minute = 60'000;

std::filesystem::path fresh_directory() {
    static int counter = 0;
    const auto dir =
        std::filesystem::temp_directory_path() /
        ("cexchain-keeper-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

/// A clock moved by hand, read by the server's threads.
class TestClock final : public ledger::Clock {
public:
    explicit TestClock(protocol::Timestamp start) : now_(start) {}
    [[nodiscard]] protocol::Timestamp now() override { return now_.load(); }
    void set(protocol::Timestamp now) { now_.store(now); }
    void advance(protocol::Timestamp ms) { now_.fetch_add(ms); }

private:
    std::atomic<protocol::Timestamp> now_;
};

cbor::Value text(std::string value) {
    return cbor::Value::text(std::move(value));
}

/// A home with two contracts: Bo's time contract (testvectors/bo-v1.json,
/// `when overdue 3 days suspend`, `when suspended 30 days terminate`) with an
/// instance due a day after t0, and the requesting contract
/// (test-contracts.json, whose when.due accepts and changes nothing) with an
/// instance whose creation made a request due an hour after it. A keeper
/// device may call the time rules and result on both; a narrow one only
/// when.suspend on the time contract.
struct Home {
    std::filesystem::path dir = fresh_directory();
    TestClock clock{t0};
    ledger::SeededEntropy entropy{51};
    KeyPair org = key("keeper home org");
    std::shared_ptr<const KeyPair> log_key =
        std::make_shared<const KeyPair>(key("keeper home log"));
    std::shared_ptr<const KeyPair> keeper_key =
        std::make_shared<const KeyPair>(key("keeper home keeper"));
    KeyPair narrow_key = key("keeper home narrow keeper");
    protocol::Id id;
    protocol::Id timed;
    protocol::Id requesting;
    protocol::Id service;
    protocol::Id asker;
    protocol::Id request;
    protocol::Id keeper;
    protocol::Id narrow;
    protocol::Timestamp due = t0 + 86'400'000;
    protocol::Timestamp deadline = 0;
    std::string reader = "reader-token-0123456789";

    Home() {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Keeper Home",
                                             org.public_key(), log_key->public_key()};
        auto signed_genesis =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, genesis);
        REQUIRE(signed_genesis);
        auto ledger = ledger::Ledger::create(*fs, clock, provider(), signed_genesis->encoded);
        REQUIRE(ledger);
        id = ledger->id();
        auto submit = [&](protocol::Body body) {
            auto registered = ledger->submit(sign(org, id, std::nullopt, std::move(body)));
            INFO((registered ? std::string() : std::string(registered.error().detail)));
            REQUIRE(registered);
            clock.advance(1000);
            return *registered;
        };
        // Bo's time contract, from the Bo vectors.
        const auto bo = load_vectors("bo-v1.json");
        for (const auto& c : bo["contracts"]) {
            if (c["name"] != "time") {
                continue;
            }
            protocol::ContractDeployBody deploy;
            deploy.code = hex(c["code"].get<std::string>());
            for (const auto& [name, kind] : c["interface"].items()) {
                deploy.interface.emplace(name, kind == "create" ? protocol::FunctionKind::create
                                                                : protocol::FunctionKind::call);
            }
            deploy.language = "wasm";
            deploy.compiler = c["compiler"].get<std::string>();
            deploy.name = "Timed";
            timed = submit(deploy).statement_id;
        }
        REQUIRE(ledger->state().contract(timed) != nullptr);
        protocol::ContractCallBody create;
        create.contract = timed;
        create.function = "create";
        create.arguments = cbor::Value::map(
            {{text("fields"),
              cbor::Value::map({{text("due"), cbor::Value::unsigned_integer(due)}})},
             {text("parties"),
              cbor::Value::map({{text("we"), cbor::Value::bytes(id.bytes())},
                                {text("customer"), cbor::Value::bytes(Bytes(32, 0xc5))}})}});
        service = submit(create).statement_id;
        // The requesting contract.
        const auto vectors = load_vectors("test-contracts.json");
        protocol::ContractDeployBody deploy;
        deploy.code = hex(vectors["request"].get<std::string>());
        for (const auto& [name, kind] : vectors["request_interface"].items()) {
            deploy.interface.emplace(name, static_cast<protocol::FunctionKind>(kind.get<int>()));
        }
        deploy.language = "wasm";
        deploy.compiler = "test_contracts.py 1";
        deploy.name = "Requesting";
        requesting = submit(deploy).statement_id;
        protocol::ContractCallBody open;
        open.contract = requesting;
        open.function = "open";
        open.arguments = cbor::Value::array({cbor::Value::array(
            {text("notify"), cbor::Value::null(), cbor::Value::unsigned_integer(hour)})});
        const protocol::Timestamp asked = clock.now();
        asker = submit(open).statement_id;
        deadline = asked + hour;
        auto rid = protocol::request_id(provider(), crypto::HashAlg::sha256, asker, 0);
        REQUIRE(rid);
        request = *rid;
        // The keepers.
        keeper =
            submit(protocol::ActorRegisterBody{
                       protocol::ActorKind::device, "Keeper", keeper_key->public_key(), {}, {}})
                .statement_id;
        auto calls = scope({StatementType::contract_call});
        calls.contracts = std::vector<protocol::Id>{timed, requesting};
        std::ranges::sort(*calls.contracts, {},
                          [](const protocol::Id& c) { return protocol::key_of(c); });
        calls.functions = std::vector<std::string>{"result", "when.suspend", "when.terminate"};
        submit(protocol::DelegationGrantBody{keeper, calls});
        narrow = submit(protocol::ActorRegisterBody{
                            protocol::ActorKind::device, "Narrow", narrow_key.public_key(), {}, {}})
                     .statement_id;
        auto only = scope({StatementType::contract_call});
        only.contracts = std::vector<protocol::Id>{timed};
        only.functions = std::vector<std::string>{"when.suspend"};
        submit(protocol::DelegationGrantBody{narrow, only});
        REQUIRE(ledger->checkpoint(*log_key));
        REQUIRE(node::save_tokens(dir, {{"reader", static_cast<node::Scopes>(node::Scope::read),
                                         node::token_hash(provider(), reader), t0}}));
    }
    Home(const Home&) = delete;
    Home& operator=(const Home&) = delete;
    ~Home() { std::filesystem::remove_all(dir); }

    Bytes sign(const KeyPair& signer, const protocol::Id& actor,
               std::optional<protocol::Id> delegation, protocol::Body body) {
        protocol::Statement st;
        st.ledger_id = id;
        st.actor_id = actor;
        st.delegation_id = std::move(delegation);
        st.issued_at = clock.now();
        st.nonce = entropy.bytes<16>();
        st.body = std::move(body);
        auto signed_statement =
            protocol::sign_statement(signer, provider(), crypto::HashAlg::sha256, st);
        REQUIRE(signed_statement);
        return signed_statement->encoded;
    }

    /// The ledger, opened at the fixture's clock.
    struct Opened {
        std::optional<ledger::PosixFileSystem> fs;
        std::optional<ledger::Ledger> ledger;
    };
    std::unique_ptr<Opened> open() {
        auto opened = std::make_unique<Opened>();
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        opened->fs.emplace(std::move(*fs));
        auto l = ledger::Ledger::open(*opened->fs, clock, provider());
        REQUIRE(l);
        opened->ledger.emplace(std::move(*l));
        return opened;
    }

    std::unique_ptr<node::LedgerApi> api() {
        node::ApiOptions o;
        o.directory = dir;
        o.log_keys = {log_key};
        o.keeper = keeper_key;
        o.keeper_interval = std::chrono::seconds(0);
        o.clock = &clock;
        auto opened = node::LedgerApi::open(o, provider());
        REQUIRE(opened);
        return std::move(*opened);
    }
};

/// What is due on the home's ledger at `now`, for `keeper` (or anyone).
node::DueWork due_at(const protocol::LedgerState& state, protocol::Timestamp now,
                     std::optional<protocol::Id> keeper = std::nullopt,
                     std::size_t max_runs = node::default_due_runs, std::uint64_t start = 0) {
    node::DueOptions o;
    o.now = now;
    o.keeper = std::move(keeper);
    o.max_runs = max_runs;
    o.start = start;
    auto work = node::find_due(provider(), state, o);
    REQUIRE(work);
    return std::move(*work);
}

std::vector<std::string> functions(const node::DueWork& work) {
    std::vector<std::string> out;
    for (const node::DueRule& r : work.rules) {
        out.push_back(r.function);
    }
    return out;
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

json get_json(const node::Client& c, const std::string& path, int status = 200) {
    auto r = c.request("GET", path);
    REQUIRE(r);
    INFO(std::string(r->body.begin(), r->body.end()));
    REQUIRE(r->status == status);
    return json::parse(r->body.begin(), r->body.end());
}

std::string hex_id(const protocol::Id& id) {
    return cexchain::to_hex(id.bytes());
}

} // namespace

TEST_CASE("time rules are due once their contract accepts them, within a keeper's delegations",
          "[node][keeper]") {
    Home home;
    const auto opened = home.open();
    const protocol::LedgerState& state = opened->ledger->state();
    const protocol::Timestamp suspend_at = home.due + protocol::Timestamp{3} * 86'400'000;

    CHECK(node::is_time_rule("when.suspend"));
    CHECK_FALSE(node::is_time_rule("when."));
    CHECK_FALSE(node::is_time_rule("result"));
    CHECK(node::time_rules(*state.contract(home.timed)) ==
          std::vector<std::string>{"when.suspend", "when.terminate"});
    CHECK(node::keeper_actors(state) == std::vector<protocol::Id>{home.keeper, home.narrow});

    // Before its time: nothing (the requesting contract's when.due accepts,
    // but changes nothing, so it is never due).
    node::DueWork before = due_at(state, suspend_at - 1);
    CHECK(before.rules.empty());
    CHECK(before.expiries.size() == 1); // the request, days past its deadline
    CHECK(before.instances == 2);
    CHECK(before.runs == 4); // the timed instance's two rules; when.due, the expiry
    CHECK_FALSE(before.next);

    // At its time: when.suspend, with the rule's time and how late, and the
    // keepers that may call it.
    node::DueWork at = due_at(state, suspend_at + 5000);
    REQUIRE(functions(at) == std::vector<std::string>{"when.suspend"});
    const node::DueRule& rule = at.rules.front();
    CHECK(rule.instance == home.service);
    CHECK(rule.contract == home.timed);
    CHECK(rule.status == std::optional<std::string>("active"));
    CHECK(rule.time == std::optional<protocol::Timestamp>(suspend_at));
    CHECK(rule.late == std::optional<protocol::Timestamp>(5000));
    CHECK(rule.keepers == std::vector<protocol::Id>{home.keeper, home.narrow});
    CHECK(rule.head == state.instance(home.service)->head);
    const protocol::ContractCallBody call = node::rule_call(rule);
    CHECK(call.function == "when.suspend");
    CHECK(call.arguments.is_null());
    CHECK_FALSE(call.answer);

    // For a keeper: what its delegations cover; it is the dry runs' caller.
    CHECK(functions(due_at(state, suspend_at, home.narrow)) ==
          std::vector<std::string>{"when.suspend"});
    CHECK(due_at(state, suspend_at, home.narrow).rules.front().keepers.empty());

    // The expiry: open past its deadline plus the grace (15 minutes).
    CHECK(due_at(state, home.deadline + 15 * minute - 1).expiries.empty());
    node::DueWork expired = due_at(state, home.deadline + 15 * minute);
    REQUIRE(expired.expiries.size() == 1);
    const node::DueExpiry& e = expired.expiries.front();
    CHECK(e.request == home.request);
    CHECK(e.instance == home.asker);
    CHECK(e.kind == "notify");
    CHECK(e.reply == "result");
    CHECK(e.deadline == home.deadline);
    CHECK(e.keepers == std::vector<protocol::Id>{home.keeper});
    const protocol::ContractCallBody answer = node::expiry_call(e);
    REQUIRE(answer.answer);
    CHECK(answer.answer->status == protocol::AnswerStatus::expired);
    CHECK(answer.function == "result");
    // The narrow keeper does not call result: not its to expire.
    CHECK(due_at(state, home.deadline + hour, home.narrow).expiries.empty());
    // A grace of zero: from the deadline itself.
    node::DueOptions o;
    o.now = home.deadline;
    o.grace = 0;
    auto no_grace = node::find_due(provider(), state, o);
    REQUIRE(no_grace);
    CHECK(no_grace->expiries.size() == 1);

    // A bounded scan says where to go on, and finishes an instance at least.
    node::DueWork first = due_at(state, suspend_at, std::nullopt, 1);
    CHECK(first.instances == 1);
    REQUIRE(first.next);
    node::DueWork rest = due_at(state, suspend_at, std::nullopt, 1, *first.next);
    CHECK(rest.instances == 1);
    CHECK_FALSE(rest.next);
    CHECK(first.rules.size() + rest.rules.size() == 1);

    // A scan of one instance, one contract.
    o = {};
    o.now = suspend_at;
    o.instance = home.asker;
    auto one = node::find_due(provider(), state, o);
    REQUIRE(one);
    CHECK(one->instances == 1);
    CHECK(one->rules.empty());
    o.instance.reset();
    o.contract = home.requesting;
    CHECK(node::find_due(provider(), state, o)->instances == 1);

    // Not an actor, or a revoked one: refused; a scan of 0 runs too.
    o = {};
    o.now = suspend_at;
    o.keeper = home.request;
    CHECK(node::find_due(provider(), state, o).error().code == cexchain::Errc::not_found);
    o.keeper.reset();
    o.max_runs = 0;
    CHECK_FALSE(node::find_due(provider(), state, o));

    // As the route answers it.
    const json j = json::parse(node::due_json_text(at));
    CHECK(j["at"] == suspend_at + 5000);
    CHECK(j["grace_ms"] == node::default_expiry_grace);
    CHECK(j["keeper"].is_null());
    CHECK(j["rules"][0]["function"] == "when.suspend");
    CHECK(j["rules"][0]["late_ms"] == 5000);
    CHECK(j["rules"][0]["keepers"].size() == 2);
    CHECK(j["expiries"].size() == 1);
    CHECK(j["expiries"][0]["overdue_ms"] == suspend_at + 5000 - home.deadline);
    CHECK(j["next"].is_null());
}

TEST_CASE("the server's keeper fires what is due as its clock moves, and serves the due route",
          "[node][keeper]") {
    Home home;
    const protocol::Timestamp suspend_at = home.due + protocol::Timestamp{3} * 86'400'000;
    const auto api = home.api();
    const auto& ledger = api->ledger();
    // Each tick queues a slice; stop() waits for the queued writes (and
    // answers long polls, of which there are none).
    auto tick = [&] {
        api->tick();
        api->stop();
    };
    const std::uint64_t size = ledger.size();
    tick();
    CHECK(ledger.size() == size); // nothing due yet

    // Past the deadline, within the grace: still open.
    home.clock.set(home.deadline + 10 * minute);
    tick();
    CHECK(ledger.size() == size);
    // Past the grace: the keeper expires it.
    home.clock.set(home.deadline + 15 * minute);
    tick();
    REQUIRE(ledger.size() == size + 1);
    {
        const protocol::RequestState* r = ledger.state().request(home.request);
        REQUIRE(r != nullptr);
        CHECK(r->status == protocol::AnswerStatus::expired);
        CHECK(r->answered_at == home.deadline + 15 * minute);
    }

    // The time rule: not a millisecond early, then once.
    home.clock.set(suspend_at - 1);
    tick();
    CHECK(ledger.size() == size + 1);
    home.clock.set(suspend_at + 2000);
    tick();
    REQUIRE(ledger.size() == size + 2);
    const protocol::InstanceState& service = *ledger.state().instance(home.service);
    CHECK(service.status == std::optional<std::string>("suspended"));
    tick();
    CHECK(ledger.size() == size + 2); // fired for this time: not due again

    // The route: what is due when, for whom. Thirty days suspended, it ends.
    const Running running(*api);
    const auto reader = running.client(home.reader);
    const protocol::Timestamp terminate_at =
        suspend_at + 2000 + protocol::Timestamp{30} * 86'400'000;
    json due = get_json(reader, "/v1/contracts/due");
    CHECK(due["rules"].empty());
    CHECK(due["at"] == suspend_at + 2000); // the server's clock
    due = get_json(reader, "/v1/contracts/due?at=" + std::to_string(terminate_at));
    REQUIRE(due["rules"].size() == 1);
    CHECK(due["rules"][0]["function"] == "when.terminate");
    CHECK(due["rules"][0]["instance"] == hex_id(home.service));
    CHECK(due["rules"][0]["keepers"] == json::array({hex_id(home.keeper)}));
    due = get_json(reader, "/v1/contracts/due?at=" + std::to_string(terminate_at) +
                               "&keeper=" + hex_id(home.narrow));
    CHECK(due["rules"].empty()); // the narrow keeper does not terminate
    CHECK(due["keeper"] == hex_id(home.narrow));
    due = get_json(reader, "/v1/contracts/due?at=" + std::to_string(terminate_at) +
                               "&limit=1&contract=" + hex_id(home.timed) + "&grace=0");
    CHECK(due["runs"] == 2);
    get_json(reader, "/v1/contracts/due?keeper=" + hex_id(home.request), 404);
    get_json(reader, "/v1/contracts/due?limit=0", 400);
    get_json(reader, "/v1/contracts/due?grace=31622401", 400);
    get_json(reader, "/v1/contracts/due?wait=1", 400);
    get_json(running.client("no-such-token-0123456789"), "/v1/contracts/due", 401);
    auto posted = reader.request("POST", "/v1/contracts/due", {}, "application/json");
    REQUIRE(posted);
    CHECK(posted->status == 405);
    // The status says a keeper runs.
    CHECK(get_json(reader, "/v1/status")["keeper"] == true);
}

TEST_CASE("the due route's query is parsed strictly", "[node][keeper]") {
    auto parse = [](std::vector<std::pair<std::string, std::string>> query) {
        node::http::Request r;
        r.method = "GET";
        r.path = "/v1/contracts/due";
        for (auto& [name, value] : query) {
            r.query.emplace(std::move(name), std::move(value));
        }
        return node::detail::parse_due_query(r);
    };
    const auto all = parse({{"at", "1792022400000"},
                            {"grace", "0"},
                            {"keeper", std::string(64, 'a')},
                            {"start", "7"},
                            {"limit", "100000"}});
    const auto* q = std::get_if<node::detail::DueQuery>(&all);
    REQUIRE(q != nullptr);
    CHECK(q->at == std::optional<protocol::Timestamp>(1'792'022'400'000));
    CHECK(q->grace == std::optional<std::uint64_t>(0));
    CHECK(q->keeper);
    CHECK(q->start == 7);
    CHECK(q->limit == 100'000);
    for (const auto& [name, value] :
         std::vector<std::pair<std::string, std::string>>{{"at", "-1"},
                                                          {"at", ""},
                                                          {"grace", "31622401"},
                                                          {"keeper", "abc"},
                                                          {"instance", std::string(63, 'a')},
                                                          {"limit", "0"},
                                                          {"limit", "100001"},
                                                          {"start", "x"},
                                                          {"state", "open"}}) {
        INFO(name << "=" << value);
        CHECK(std::holds_alternative<node::detail::QueryError>(parse({{name, value}})));
    }
}
