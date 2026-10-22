// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The executor runtime against a home's server: it finds requests
// (a hint), verifies each in the instance's evidence before acting, journals
// before every action, answers through the ledger, retries transient
// failures, never acts on what a lying server invents, resumes from its
// journal without acting twice, takes an answer recorded elsewhere as final,
// and lets one copy at a time act, by the server's lease.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/connectors.hpp>
#include <cexchain/node/executor.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
namespace node = cexchain::node;
namespace executor = cexchain::node::executor;
namespace connector = cexchain::node::connector;
using cexchain::Bytes;
using json = nlohmann::json;
using namespace std::chrono_literals;

std::filesystem::path fresh_directory() {
    static int counter = 0;
    const auto dir =
        std::filesystem::temp_directory_path() /
        ("cexchain-executor-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
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
    [[nodiscard]] std::string url() const {
        return "http://127.0.0.1:" + std::to_string(server_.port());
    }

private:
    static node::ServerOptions options() {
        node::ServerOptions o;
        o.port = 0;
        o.threads = 2;
        o.request_timeout = std::chrono::seconds(10);
        return o;
    }
    node::Server server_;
    std::thread thread_;
};

cbor::Value text(std::string value) {
    return cbor::Value::text(std::move(value));
}

/// The requesting contract's arguments that make requests, each due
/// `after` ms after the call.
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

/// A home with the requesting contract (testvectors/test-contracts.json):
/// an instance whose creation asked for a notice and a post; an executor
/// device answering notices (scope keys 7, 8, 9); tokens for staff and the
/// executor.
struct Home {
    std::filesystem::path dir = fresh_directory();
    ledger::ManualClock clock{ledger::SystemClock{}.now() - 600'000};
    ledger::SeededEntropy entropy{51};
    KeyPair org = key("executor home org");
    std::shared_ptr<const KeyPair> log_key =
        std::make_shared<const KeyPair>(key("executor home log"));
    KeyPair device = key("executor home device");
    protocol::Id id;
    protocol::Id contract;
    protocol::Id instance;
    protocol::Id executor;
    protocol::Id answers;
    /// [0] notify, [1] http.post: made by the creation, both open.
    std::vector<protocol::Id> requests;
    std::string staff = "staff-token-0123456789";
    std::string executor_token = "executor-token-0123456789";
    bool live = false;

    Home() {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Executor Home",
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
        const auto vectors = load_vectors("test-contracts.json");
        protocol::ContractDeployBody deploy;
        deploy.code = hex(vectors["request"].get<std::string>());
        for (const auto& [name, kind] : vectors["request_interface"].items()) {
            deploy.interface.emplace(name, static_cast<protocol::FunctionKind>(kind.get<int>()));
        }
        deploy.language = "wasm";
        deploy.compiler = "test_contracts.py 1";
        deploy.name = "Requesting";
        contract = submit(deploy).statement_id;
        protocol::ContractCallBody create;
        create.contract = contract;
        create.function = "open";
        create.arguments = asks({{"notify", hour}, {"http.post", 2 * hour}});
        instance = submit(create).statement_id;
        for (const std::uint64_t position : {0u, 1u}) {
            auto rid =
                protocol::request_id(provider(), crypto::HashAlg::sha256, instance, position);
            REQUIRE(rid);
            requests.push_back(*rid);
        }
        executor = submit(protocol::ActorRegisterBody{
                              protocol::ActorKind::device, "Notifier", device.public_key(), {}, {}})
                       .statement_id;
        auto calls = scope({StatementType::contract_call});
        calls.contracts = std::vector<protocol::Id>{contract};
        calls.functions = std::vector<std::string>{"result"};
        calls.request_kinds = std::vector<std::string>{"notify"};
        answers = submit(protocol::DelegationGrantBody{executor, calls}).statement_id;
        REQUIRE(ledger->checkpoint(*log_key));
        live = true;
        auto s = [](node::Scope scope) {
            return static_cast<node::Scopes>(scope);
        };
        REQUIRE(node::save_tokens(
            dir,
            {{"staff", static_cast<node::Scopes>(s(node::Scope::read) | s(node::Scope::submit)),
              node::token_hash(provider(), staff), t0},
             {"notifier", s(node::Scope::executor), node::token_hash(provider(), executor_token),
              t0}}));
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

    executor::Config config() const {
        executor::Config c;
        c.ledger = id;
        c.actor = executor;
        c.delegation = answers;
        executor::ConnectorConfig notices;
        notices.name = "notices";
        notices.type = "program";
        notices.program = "unused";
        notices.kinds = {"notify"};
        notices.timeout = 10s;
        c.connectors.push_back(notices);
        return c;
    }
};

/// A connector in this process: counts what it is asked to do, and answers
/// as `decide` says.
struct Recorder {
    std::mutex mutex;
    std::vector<protocol::Id> performed;
    std::function<connector::Outcome(const connector::Perform&)> decide;

    std::size_t count() {
        const std::lock_guard lock(mutex);
        return performed.size();
    }
    connector::PerformerFactory factory() {
        struct Performer final : connector::Performer {
            Recorder* recorder = nullptr;
            connector::Outcome perform(const connector::Perform& p) override {
                {
                    const std::lock_guard lock(recorder->mutex);
                    recorder->performed.push_back(p.request);
                }
                if (recorder->decide) {
                    return recorder->decide(p);
                }
                connector::Outcome o;
                o.request = p.request;
                o.result = cbor::Value::map({{text("ref"), text("N-1")}});
                o.response = Bytes{'{', '}'};
                return o;
            }
        };
        return [this](const connector::Hello&, std::string&) {
            auto p = std::make_unique<Performer>();
            p->recorder = this;
            return p;
        };
    }
};

/// Runs the executor once (one poll, then what is due) and returns its
/// events.
std::vector<json> run_once(const Home& home, const std::string& url, Recorder& recorder,
                           const std::filesystem::path& state,
                           std::optional<protocol::Timestamp> at = std::nullopt,
                           const executor::Config* config = nullptr) {
    executor::RunOptions o;
    o.server = url;
    o.client.bearer_token = home.executor_token;
    o.client.timeout = 10s;
    o.state = state;
    o.channels = executor::local_channels(recorder.factory());
    o.signer = &home.device;
    o.provider = &provider();
    o.once = true;
    o.wait = 0s;
    o.lease_ttl = 5s;
    if (at) {
        o.now = [at] {
            return *at;
        };
    }
    std::vector<json> events;
    o.on_event = [&](std::string_view line) {
        events.push_back(json::parse(line));
    };
    const executor::Config c = config != nullptr ? *config : home.config();
    const auto ran = executor::run(c, o);
    INFO((ran ? std::string() : ran.error()));
    REQUIRE(ran);
    return events;
}

bool has_event(const std::vector<json>& events, const std::string& name) {
    return std::ranges::any_of(events, [&](const json& e) { return e["event"] == name; });
}

/// A server in front of the home's that may change what it says: invent a
/// request in the requests list, list an answered one as open, or refuse
/// answers for a while.
class Lying final : public node::Application {
public:
    explicit Lying(std::string upstream) : upstream_(std::move(upstream)) {}
    std::atomic<bool> invent{false};
    std::atomic<bool> refuse_answers{false};
    json extra;

    void handle(node::http::Request request, std::string, Respond respond) override {
        node::ClientOptions o;
        if (const auto auth = request.header("authorization");
            auth && auth->starts_with("Bearer ")) {
            o.bearer_token = std::string(auth->substr(7));
        }
        o.timeout = 15s;
        const node::Client client(*node::Url::parse(upstream_), o);
        if (refuse_answers && request.method == "POST") {
            node::http::Response busy;
            busy.status = 503;
            const std::string body = R"({"error":{"code":"unavailable","message":"busy"}})";
            busy.body.assign(body.begin(), body.end());
            respond(std::move(busy));
            return;
        }
        auto answer = client.request(request.method, request.target, request.body,
                                     request.header("content-type").value_or(""));
        node::http::Response r;
        if (!answer) {
            r.status = 502;
            respond(std::move(r));
            return;
        }
        r.status = answer->status;
        r.content_type = std::string(answer->header("content-type").value_or("application/json"));
        r.body = answer->body;
        if (invent && request.path == "/v1/requests" && r.status == 200) {
            json body = json::parse(r.body.begin(), r.body.end());
            body["requests"].push_back(extra);
            const std::string text = body.dump();
            r.body.assign(text.begin(), text.end());
        }
        respond(std::move(r));
    }

private:
    std::string upstream_;
};

std::string hex_id(const protocol::Id& id) {
    return cexchain::to_hex(id.bytes());
}

/// A request's status on the server's ledger (nullopt: open), and an
/// instance's head, read under the state's lock: the server writes
/// meanwhile.
std::optional<protocol::AnswerStatus> status_of(const node::LedgerApi& api, const protocol::Id& r) {
    std::optional<protocol::AnswerStatus> status;
    api.ledger().read_state([&](const protocol::LedgerState& s) { status = s.request(r)->status; });
    return status;
}
std::uint64_t head_of(const node::LedgerApi& api, const protocol::Id& instance) {
    std::uint64_t head = 0;
    api.ledger().read_state(
        [&](const protocol::LedgerState& s) { head = s.instance(instance)->head; });
    return head;
}

} // namespace

TEST_CASE("an executor verifies a request, acts once, and answers with the response's digest",
          "[node][executor]") {
    Home home;
    const auto api = home.api();
    Running running(*api);
    Recorder recorder;
    const auto state = fresh_directory();
    auto events = run_once(home, running.url(), recorder, state);
    // Only the notice: the post is no kind of its.
    REQUIRE(recorder.count() == 1);
    CHECK(recorder.performed[0] == home.requests[0]);
    CHECK(has_event(events, "verified"));
    CHECK(has_event(events, "answered"));
    REQUIRE(status_of(*api, home.requests[0]) == protocol::AnswerStatus::done);
    CHECK(!status_of(*api, home.requests[1]));

    // The journal keeps the response and its salt; the answer carries the
    // salted digest only.
    const executor::Journal journal(state);
    const auto entry = journal.find(home.requests[0]);
    REQUIRE(entry);
    CHECK(entry->stage == executor::Stage::answered);
    CHECK(entry->attempts == 1);
    REQUIRE(entry->response);
    REQUIRE(entry->salt);
    protocol::Nonce salt{};
    std::ranges::copy(*entry->salt, salt.begin());
    const auto digest = protocol::attachment_commitment(provider(), crypto::HashAlg::sha256, salt,
                                                        *entry->response);
    REQUIRE(digest);
    CHECK(Bytes(digest->bytes().begin(), digest->bytes().end()) == *entry->digest);
    const cbor::Value args = executor::answer_arguments(*entry);
    REQUIRE(args.find("response") != nullptr);
    CHECK(*args.find("response")->as_bytes() == *entry->digest);
    CHECK(args.find("result") != nullptr);
    CHECK(args.find("reason") == nullptr);
    CHECK(std::filesystem::status(state / "journal").permissions() ==
          std::filesystem::perms::owner_all);

    // Again: nothing to do, nothing done twice.
    events = run_once(home, running.url(), recorder, state);
    CHECK(recorder.count() == 1);
    CHECK(!has_event(events, "acting"));
    std::filesystem::remove_all(state);
}

TEST_CASE("an executor retries transient failures and answers failures with a reason",
          "[node][executor]") {
    Home home;
    const auto api = home.api();
    Running running(*api);
    Recorder recorder;
    int calls = 0;
    recorder.decide = [&](const connector::Perform& p) {
        connector::Outcome o;
        o.request = p.request;
        o.status =
            ++calls == 1 ? connector::OutcomeStatus::retry : connector::OutcomeStatus::failed;
        o.reason = calls == 1 ? "unavailable" : "unmapped";
        return o;
    };
    const auto state = fresh_directory();
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    auto events = run_once(home, running.url(), recorder, state, now);
    CHECK(has_event(events, "retry"));
    CHECK(!status_of(*api, home.requests[0]));
    auto entry = executor::Journal(state).find(home.requests[0]);
    REQUIRE(entry);
    CHECK(entry->stage == executor::Stage::verified);
    CHECK(entry->next_at > now);
    CHECK(entry->next_at <= now + 1200);
    // Not yet due: nothing happens.
    run_once(home, running.url(), recorder, state, now + 100);
    CHECK(recorder.count() == 1);
    // Due: the second attempt fails for good, and the answer says why.
    events = run_once(home, running.url(), recorder, state, now + 2000);
    CHECK(recorder.count() == 2);
    REQUIRE(status_of(*api, home.requests[0]) == protocol::AnswerStatus::failed);
    entry = executor::Journal(state).find(home.requests[0]);
    CHECK(entry->stage == executor::Stage::answered);
    CHECK(entry->reason == "unmapped");
    CHECK(*executor::answer_arguments(*entry).find("reason") == text("unmapped"));
    std::filesystem::remove_all(state);
}

TEST_CASE("an executor never acts on a request the signed evidence does not show open",
          "[node][executor]") {
    Home home;
    const auto api = home.api();
    Running upstream(*api);
    Lying lying(upstream.url());
    Running front(lying);
    Recorder recorder;
    const auto state = fresh_directory();

    // An invented request on a real instance.
    std::array<std::uint8_t, 32> fake{};
    fake.fill(0x5a);
    lying.extra = {{"id", hex_id(*protocol::to_id(fake))},
                   {"instance", hex_id(home.instance)},
                   {"kind", "notify"}};
    lying.invent = true;
    auto events = run_once(home, front.url(), recorder, state);
    CHECK(recorder.count() == 1); // the real notice only
    CHECK(recorder.performed[0] == home.requests[0]);
    CHECK(has_event(events, "unverified"));
    const auto invented = executor::Journal(state).find(*protocol::to_id(fake));
    REQUIRE(invented);
    CHECK(invented->stage == executor::Stage::unverified);
    CHECK(invented->attempts == 0);

    // A request answered by hand, listed as open: closed, never acted on.
    node::ClientOptions staff;
    staff.bearer_token = home.staff;
    const node::Client client(*node::Url::parse(upstream.url()), staff);
    protocol::ContractCallBody answer;
    answer.instance = home.instance;
    answer.head = head_of(*api, home.instance);
    answer.function = "result";
    answer.answer = protocol::ContractAnswer{home.requests[1], protocol::AnswerStatus::failed};
    const auto by_hand =
        client.request("POST", "/v1/statements", home.sign(home.org, home.id, std::nullopt, answer),
                       "application/cose");
    REQUIRE(by_hand);
    REQUIRE(by_hand->status == 201);
    lying.extra = {
        {"id", hex_id(home.requests[1])}, {"instance", hex_id(home.instance)}, {"kind", "notify"}};
    events = run_once(home, front.url(), recorder, state);
    CHECK(recorder.count() == 1);
    const auto closed = executor::Journal(state).find(home.requests[1]);
    REQUIRE(closed);
    CHECK(closed->stage == executor::Stage::closed);
    CHECK(closed->answered_status == "failed");
    CHECK(closed->attempts == 0);
    std::filesystem::remove_all(state);
}

TEST_CASE("an executor resumes from its journal without acting twice, and takes an answer "
          "recorded elsewhere as final",
          "[node][executor]") {
    Home home;
    const auto api = home.api();
    Running upstream(*api);
    Lying lying(upstream.url());
    Running front(lying);
    Recorder recorder;
    const auto state = fresh_directory();

    // The action is done, but its answer cannot be recorded (as if the
    // process died between the two): the outcome waits in the journal.
    lying.refuse_answers = true;
    run_once(home, front.url(), recorder, state);
    CHECK(recorder.count() == 1);
    auto entry = executor::Journal(state).find(home.requests[0]);
    REQUIRE(entry);
    CHECK(entry->stage == executor::Stage::answering);
    CHECK(!status_of(*api, home.requests[0]));
    // Resumed: answered from the journal, not acted on again.
    lying.refuse_answers = false;
    run_once(home, front.url(), recorder, state, ledger::SystemClock{}.now() + 2000);
    CHECK(recorder.count() == 1);
    entry = executor::Journal(state).find(home.requests[0]);
    CHECK(entry->stage == executor::Stage::answered);
    CHECK(status_of(*api, home.requests[0]) == protocol::AnswerStatus::done);

    // Another request, answered by someone else while the connector works:
    // the executor's own answer is refused, journaled as final, not retried.
    node::ClientOptions staff;
    staff.bearer_token = home.staff;
    const node::Client client(*node::Url::parse(upstream.url()), staff);
    protocol::ContractCallBody ask;
    ask.instance = home.instance;
    ask.head = head_of(*api, home.instance);
    ask.function = "ask";
    ask.arguments = asks({{"notify", hour}});
    auto asked =
        client.request("POST", "/v1/statements", home.sign(home.org, home.id, std::nullopt, ask),
                       "application/cose");
    REQUIRE(asked);
    REQUIRE(asked->status == 201);
    const auto asked_index = json::parse(asked->body.begin(), asked->body.end())["index"];
    const protocol::Id third = *protocol::request_id(
        provider(), crypto::HashAlg::sha256,
        *protocol::to_id(
            *cexchain::from_hex(json::parse(asked->body.begin(), asked->body.end())["statement_id"]
                                    .get<std::string>())),
        0);
    recorder.decide = [&](const connector::Perform& p) {
        protocol::ContractCallBody answer;
        answer.instance = home.instance;
        answer.head = head_of(*api, home.instance);
        answer.function = "result";
        answer.answer = protocol::ContractAnswer{p.request, protocol::AnswerStatus::failed};
        auto by_hand =
            client.request("POST", "/v1/statements",
                           home.sign(home.org, home.id, std::nullopt, answer), "application/cose");
        REQUIRE(by_hand);
        REQUIRE(by_hand->status == 201);
        connector::Outcome o;
        o.request = p.request;
        return o;
    };
    auto events = run_once(home, upstream.url(), recorder, state);
    CHECK(recorder.count() == 2);
    CHECK(asked_index.get<std::uint64_t>() > 0);
    entry = executor::Journal(state).find(third);
    REQUIRE(entry);
    CHECK(entry->stage == executor::Stage::closed);
    CHECK(entry->answered_status == "failed");
    CHECK(entry->answered_by.has_value());
    CHECK(!(entry->answered_by == home.executor));
    CHECK(entry->status == "done"); // its own outcome stays in the journal
    CHECK(has_event(events, "closed"));
    CHECK(status_of(*api, third) == protocol::AnswerStatus::failed);
    // Not retried.
    run_once(home, upstream.url(), recorder, state);
    CHECK(recorder.count() == 2);
    std::filesystem::remove_all(state);
}

TEST_CASE("one copy of an executor acts at a time, by the server's lease", "[node][executor]") {
    Home home;
    const auto api = home.api();
    Running running(*api);
    Recorder first;
    Recorder second;
    const auto state_a = fresh_directory();
    const auto state_b = fresh_directory();
    // The first copy polls and holds the lease; the second, with its own
    // state directory, is told so and does nothing.
    first.decide = [&](const connector::Perform& p) {
        connector::Outcome o;
        o.request = p.request;
        o.status = connector::OutcomeStatus::retry;
        return o;
    };
    run_once(home, running.url(), first, state_a);
    CHECK(first.count() == 1);
    auto events = run_once(home, running.url(), second, state_b);
    CHECK(second.count() == 0);
    REQUIRE(has_event(events, "lease"));
    CHECK(!has_event(events, "seen"));
    // Once the first stops polling and its lease lapses, the second takes
    // over and finishes the work.
    std::this_thread::sleep_for(5200ms);
    events = run_once(home, running.url(), second, state_b);
    CHECK(second.count() == 1);
    CHECK(status_of(*api, home.requests[0]) == protocol::AnswerStatus::done);

    // Two copies may not share a state directory.
    std::atomic<bool> stop{false};
    auto options = [&](bool once) {
        executor::RunOptions o;
        o.server = running.url();
        o.state = state_a;
        o.channels = executor::local_channels(first.factory());
        o.signer = &home.device;
        o.provider = &provider();
        o.once = once;
        o.wait = once ? 0s : 1s;
        o.stop = &stop;
        o.client.bearer_token = home.executor_token;
        return o;
    };
    std::optional<std::expected<void, std::string>> other;
    const executor::Config config = home.config();
    std::thread holder([&] {
        executor::RunOptions slow = options(false);
        other = executor::run(config, slow);
    });
    std::this_thread::sleep_for(500ms);
    executor::RunOptions o = options(true);
    const auto refused = executor::run(config, o);
    stop = true;
    holder.join();
    REQUIRE(!refused);
    CHECK(refused.error().find("another copy") != std::string::npos);
    REQUIRE(other);
    CHECK(other->has_value());
    std::filesystem::remove_all(state_a);
    std::filesystem::remove_all(state_b);
}

TEST_CASE("an executor's config is checked", "[node][executor]") {
    const std::string ids = R"("ledger_id":")" + std::string(64, 'a') + R"(","actor":")" +
                            std::string(64, 'b') + R"(","delegation":")" + std::string(64, 'c') +
                            "\"";
    auto parse = [&](const std::string& connectors) {
        return executor::parse_config("{" + ids + R"(,"connectors":[)" + connectors + "]}");
    };
    auto config =
        parse(R"({"name":"hook","type":"webhook","kinds":["notify"],)"
              R"("url":"https://example.com/x","secret":"hook-key","timeout":10},)"
              R"({"name":"script","type":"command","kinds":["http.post","notify"],)"
              R"("contracts":[")" +
              std::string(64, 'd') + R"("],"program":"/bin/true","args":["-x"],"secrets":["s1"]})");
    INFO((config ? std::string() : config.error()));
    REQUIRE(config);
    CHECK(config->connectors.size() == 2);
    CHECK(config->connectors[0].secrets == std::vector<std::string>{"hook-key"});
    CHECK(config->kinds() == std::vector<std::string>{"http.post", "notify"});
    // The contract's own connector wins over the general one.
    const auto d = *protocol::to_id(Bytes(32, 0xdd));
    CHECK(config->route(d, "notify")->name == "script");
    CHECK(config->route(*protocol::to_id(Bytes(32, 0xee)), "notify")->name == "hook");
    CHECK(config->route(d, "other") == nullptr);
    // What it writes, it reads back the same.
    const auto again = executor::parse_config(executor::config_text(*config));
    REQUIRE(again);
    CHECK(executor::config_text(*again) == executor::config_text(*config));
    CHECK(again->connectors[1].config == config->connectors[1].config);

    auto refused = [&](const std::string& connectors, const std::string& why) {
        const auto parsed = parse(connectors);
        REQUIRE(!parsed);
        INFO(parsed.error());
        CHECK(parsed.error().find(why) != std::string::npos);
    };
    refused(R"({"name":"a","type":"command","kinds":["notify"],"program":"x"},)"
            R"({"name":"b","type":"command","kinds":["notify"],"program":"y"})",
            "both serve notify");
    refused(R"({"name":"a","type":"command","kinds":["notify"],"program":"x"},)"
            R"({"name":"a","type":"command","kinds":["other"],"program":"y"})",
            "two connectors");
    refused(R"({"name":"a","type":"ftp","kinds":["notify"]})", "type");
    refused(R"({"name":"a","type":"command","kinds":["Notify"],"program":"x"})", "request kinds");
    refused(R"({"name":"a","type":"command","kinds":[],"program":"x"})", "kinds");
    refused(R"({"name":"a","type":"command","kinds":["n"],"program":"x","timeout":301})",
            "timeout");
    refused(R"({"name":"a","type":"command","kinds":["n"],"program":"x","timeout":1.5})",
            "not a JSON object");
    refused(R"({"name":"a","type":"webhook","kinds":["n"],"url":"https://x/"})", "secret");
    refused(R"({"name":"a","type":"webhook","kinds":["n"],"url":"x","secret":"s"})", "url");
    CHECK(!executor::parse_config(R"({"ledger_id":"abc"})"));
    CHECK(!executor::parse_config("[]"));
}

TEST_CASE("an executor's sealed secrets and cursor are read strictly", "[node][executor]") {
    namespace openssl = cexchain::crypto::openssl;
    const auto key = openssl::HpkeKey::generate();
    REQUIRE(key.has_value());
    const std::string_view value = "hook-secret";
    const auto sealed = openssl::hpke_seal(
        key->public_key(), cexchain::as_bytes(executor::secret_info),
        cexchain::as_bytes(std::string_view("hook-key")), cexchain::as_bytes(value));
    REQUIRE(sealed.has_value());
    const Bytes file = executor::encode_sealed_secret(*sealed);
    const auto parsed = executor::parse_sealed_secret(file);
    REQUIRE(parsed.has_value());
    CHECK(parsed->ciphertext == sealed->ciphertext);
    const auto opened = executor::open_sealed_secret("hook-key", file, *key);
    REQUIRE(opened.has_value());
    CHECK(std::string(opened->view().begin(), opened->view().end()) == value);
    // Renamed into another secret, it does not open; damaged, it is refused.
    const auto renamed = executor::open_sealed_secret("panel-token", file, *key);
    REQUIRE(!renamed.has_value());
    CHECK(renamed.error().find("does not open") != std::string::npos);
    Bytes damaged = file;
    damaged[6] ^= 0x01; // the suite's KEM: 0x21, not 0x20
    CHECK(!executor::parse_sealed_secret(damaged).has_value());
    const auto refused = executor::open_sealed_secret("hook-key", damaged, *key);
    REQUIRE(!refused.has_value());
    CHECK(refused.error().find("damaged") != std::string::npos);
    CHECK(!executor::parse_sealed_secret(Bytes(file.begin(), file.end() - 1)).has_value());
    // The cursor belongs to one server.
    const std::string cursor = R"({"after":9,"server":"http://127.0.0.1:8080"})";
    CHECK(executor::parse_cursor(cursor, "http://127.0.0.1:8080") == 9);
    CHECK(executor::parse_cursor(cursor, "http://127.0.0.1:8081") == 0);
    CHECK(executor::parse_cursor(R"({"server":"http://127.0.0.1:8080"})",
                                 "http://127.0.0.1:8080") == 0);
    CHECK(executor::parse_cursor(R"({"after":-1,"server":"x"})", "x") == 0);
    CHECK(executor::parse_cursor("not json", "x") == 0);
}

namespace {

/// A connector in this process that notes, for each request it performs,
/// its instance and how many requests were in its hands at once, overall
/// and per instance. Checked on the test's thread once the runs are over
/// (never assertions on the runtime's threads).
struct Overlaps {
    std::mutex mutex;
    std::map<std::string, std::string> instance_of; // request -> instance (hex)
    std::map<std::string, int> performed;           // request (hex) -> times
    std::map<std::string, int> in_flight;           // instance (hex) -> now
    int most_per_instance = 0;
    int now = 0;
    int most = 0;
    int unknown = 0;
    int total = 0;
    int stop_after = 0;
    std::atomic<bool>* stop = nullptr;

    connector::PerformerFactory factory() {
        struct Performer final : connector::Performer {
            Overlaps* o = nullptr;
            connector::Outcome perform(const connector::Perform& p) override {
                const std::string instance = hex_id(p.instance);
                {
                    const std::lock_guard lock(o->mutex);
                    const auto it = o->instance_of.find(hex_id(p.request));
                    if (it == o->instance_of.end() || it->second != instance) {
                        ++o->unknown;
                    }
                    ++o->performed[hex_id(p.request)];
                    o->most_per_instance = std::max(o->most_per_instance, ++o->in_flight[instance]);
                    o->most = std::max(o->most, ++o->now);
                    if (++o->total == o->stop_after && o->stop != nullptr) {
                        o->stop->store(true);
                    }
                }
                // A few milliseconds of work, so that others overlap it.
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(2 + p.request.bytes()[0] % 5));
                {
                    const std::lock_guard lock(o->mutex);
                    --o->in_flight[instance];
                    --o->now;
                }
                connector::Outcome out;
                out.request = p.request;
                out.result = cbor::Value::map({{text("ref"), text("C-1")}});
                return out;
            }
        };
        return [this](const connector::Hello&, std::string&) {
            auto p = std::make_unique<Performer>();
            p->o = this;
            return p;
        };
    }
};

} // namespace

TEST_CASE("an executor works requests at once, one per instance, each once across stops",
          "[node][executor]") {
    Home home;
    const auto api = home.api();
    Running running(*api);
    node::ClientOptions staff;
    staff.bearer_token = home.staff;
    const node::Client client(*node::Url::parse(running.url()), staff);

    // Twelve more instances with four notices each, and the home's own
    // notice: 49 requests, several per instance.
    Overlaps overlaps;
    std::vector<protocol::Id> notices{home.requests[0]};
    overlaps.instance_of.emplace(hex_id(home.requests[0]), hex_id(home.instance));
    for (int i = 0; i < 12; ++i) {
        protocol::ContractCallBody create;
        create.contract = home.contract;
        create.function = "open";
        create.arguments =
            asks({{"notify", hour}, {"notify", hour}, {"notify", hour}, {"notify", hour}});
        const auto made =
            client.request("POST", "/v1/statements",
                           home.sign(home.org, home.id, std::nullopt, create), "application/cose");
        REQUIRE(made);
        REQUIRE(made->status == 201);
        const protocol::Id instance = *protocol::to_id(*cexchain::from_hex(
            json::parse(made->body.begin(), made->body.end())["statement_id"].get<std::string>()));
        for (std::uint64_t position = 0; position < 4; ++position) {
            const auto id =
                protocol::request_id(provider(), crypto::HashAlg::sha256, instance, position);
            REQUIRE(id);
            notices.push_back(*id);
            overlaps.instance_of.emplace(hex_id(*id), hex_id(instance));
        }
    }

    executor::Config config = home.config();
    config.connectors[0].concurrency = 8;
    const auto state = fresh_directory();
    std::atomic<bool> stop{false};
    overlaps.stop = &stop;
    std::vector<json> events;
    std::mutex events_mutex;
    auto run = [&](bool once) {
        executor::RunOptions o;
        o.server = running.url();
        o.client.bearer_token = home.executor_token;
        o.client.timeout = 10s;
        o.state = state;
        o.channels = executor::local_channels(overlaps.factory());
        o.signer = &home.device;
        o.provider = &provider();
        o.once = once;
        o.wait = once ? 0s : 1s;
        o.lease_ttl = 5s;
        o.concurrency = 8;
        o.stop = &stop;
        o.on_event = [&](std::string_view line) {
            const std::lock_guard lock(events_mutex);
            events.push_back(json::parse(line));
        };
        return executor::run(config, o);
    };
    // Stopped twice while it works (the requests in hand are finished),
    // then a last round: every request acted on once, never two of one
    // instance at once.
    for (const int stop_after : {12, 30}) {
        overlaps.stop_after = stop_after;
        stop = false;
        const auto ran = run(false);
        INFO((ran ? std::string() : ran.error()));
        REQUIRE(ran);
    }
    stop = false;
    overlaps.stop_after = 0;
    const auto last = run(true);
    INFO((last ? std::string() : last.error()));
    REQUIRE(last);

    CHECK(overlaps.unknown == 0);
    CHECK(overlaps.most_per_instance == 1);
    CHECK(overlaps.most > 1);
    CHECK(overlaps.performed.size() == notices.size());
    CHECK(std::ranges::all_of(overlaps.performed, [](const auto& p) { return p.second == 1; }));
    for (const protocol::Id& r : notices) {
        INFO(hex_id(r));
        CHECK(status_of(*api, r) == protocol::AnswerStatus::done);
        const auto entry = executor::Journal(state).find(r);
        REQUIRE(entry);
        CHECK(entry->stage == executor::Stage::answered);
        CHECK(entry->attempts == 1);
    }
    CHECK(!status_of(*api, home.requests[1])); // no connector serves it
    // The runs' events: each started with its concurrency, each request
    // answered once.
    std::size_t answered = 0;
    std::size_t started = 0;
    for (const json& e : events) {
        answered += e["event"] == "answered" ? 1U : 0U;
        if (e["event"] == "started") {
            ++started;
            CHECK(e["concurrency"] == 8);
        }
    }
    CHECK(started == 3);
    CHECK(answered == notices.size());
    std::filesystem::remove_all(state);
}
