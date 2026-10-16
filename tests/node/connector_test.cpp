// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <chrono>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/node/connector.hpp>
#include <cexchain/node/process.hpp>

namespace cbor = cexchain::cbor;
namespace connector = cexchain::node::connector;
using cexchain::Bytes;
using cexchain::Errc;
using cexchain::to_hex;
using cexchain::node::ChildProcess;
using namespace std::chrono_literals;

namespace {

cexchain::protocol::Id id_of(std::uint8_t fill) {
    std::array<std::uint8_t, 32> bytes{};
    bytes.fill(fill);
    return *cexchain::protocol::to_id(bytes);
}

cbor::Value text(std::string value) {
    return cbor::Value::text(std::move(value));
}

} // namespace

TEST_CASE("connector messages round-trip as JSON lines", "[node][connector]") {
    connector::Perform perform;
    perform.request = id_of(1);
    perform.kind = "notify";
    perform.params = cbor::Value::map({{text("about"), text("welcome")},
                                       {text("n"), cbor::Value::integer(-5)},
                                       {text("tag"), cbor::Value::bytes(Bytes{0xab, 0xcd})}});
    perform.deadline = 1'800'000'000'000;
    perform.asked_at = 1'799'000'000'000;
    perform.home = id_of(2);
    perform.contract = id_of(3);
    perform.instance = id_of(4);
    perform.reply = "result";
    perform.attempt = 3;
    perform.timeout_ms = 30'000;
    const std::string line = connector::encode(connector::ToConnector(perform));
    CHECK(line.ends_with("\n"));
    CHECK(line.find("\"params\":{\"about\":\"welcome\",\"n\":-5,\"tag\":\"abcd\"}") !=
          std::string::npos);
    auto decoded = connector::decode_to_connector(line);
    REQUIRE(decoded);
    const auto& back = std::get<connector::Perform>(*decoded);
    CHECK(back.request == perform.request);
    CHECK(back.kind == "notify");
    // The params come back exactly, from params_cbor (byte strings too).
    CHECK(*cbor::encode(back.params) == *cbor::encode(perform.params));
    CHECK(back.deadline == perform.deadline);
    CHECK(back.instance == perform.instance);
    CHECK(back.attempt == 3);
    CHECK(back.timeout_ms == 30'000);

    connector::Hello hello;
    hello.connector = "hook";
    hello.config = R"({"url":"https://example.com/hook"})";
    hello.secrets["hook-key"] = connector::Secret{cexchain::SecureBytes(Bytes{'s', '3', 'c'})};
    const std::string hello_line = connector::encode(connector::ToConnector(std::move(hello)));
    auto hello_back = connector::decode_to_connector(hello_line);
    REQUIRE(hello_back);
    const auto& h = std::get<connector::Hello>(*hello_back);
    CHECK(h.connector == "hook");
    CHECK(h.config == R"({"url":"https://example.com/hook"})");
    REQUIRE(h.secrets.contains("hook-key"));
    CHECK(to_hex(h.secrets.at("hook-key").value.view()) == "733363");

    connector::Outcome outcome;
    outcome.request = id_of(1);
    outcome.status = connector::OutcomeStatus::failed;
    outcome.result = cbor::Value::map({{text("ref"), text("N-1")}});
    outcome.reason = "rejected";
    outcome.response = Bytes{0, 1, 2, 250};
    auto outcome_back =
        connector::decode_from_connector(connector::encode(connector::FromConnector(outcome)));
    REQUIRE(outcome_back);
    const auto& o = std::get<connector::Outcome>(*outcome_back);
    CHECK(o.status == connector::OutcomeStatus::failed);
    CHECK(o.result == outcome.result);
    CHECK(o.reason == "rejected");
    CHECK(o.response == outcome.response);

    connector::Ready ready{1, "webhook", "0.1", {"notify", "http.post"}};
    auto ready_back =
        connector::decode_from_connector(connector::encode(connector::FromConnector(ready)));
    REQUIRE(ready_back);
    CHECK(std::get<connector::Ready>(*ready_back).kinds.size() == 2);
    auto log_back = connector::decode_from_connector(connector::encode(
        connector::FromConnector(connector::Log{connector::LogLevel::warn, "slow", id_of(9)})));
    REQUIRE(log_back);
    CHECK(std::get<connector::Log>(*log_back).message == "slow");
    CHECK(connector::decode_to_connector("{\"type\":\"stop\"}\r\n"));
}

TEST_CASE("connector lines with floats, bad fields, or unknown types are refused",
          "[node][connector]") {
    const std::string id(64, 'a');
    auto outcome = [&](const std::string& rest) {
        return connector::decode_from_connector(R"({"type":"outcome","id":")" + id + "\"" + rest +
                                                "}");
    };
    CHECK(outcome(R"(,"status":"done")"));
    CHECK(outcome(R"(,"status":"done","result":{"amount":1250}})").has_value() == false);
    CHECK(outcome(R"(,"status":"done","result":{"amount":1250})"));
    // No floating point, anywhere: amounts are integers in minor units.
    CHECK(outcome(R"(,"status":"done","result":{"amount":12.5})").error().code == Errc::malformed);
    CHECK(!outcome(R"(,"status":"done","result":1e3)"));
    CHECK(!outcome(R"(,"status":"done","x":[0.5])"));
    CHECK(!outcome(R"(,"status":"done","result":18446744073709551616)"));
    CHECK(!outcome(R"(,"status":"maybe")"));
    CHECK(!outcome(R"(,"status":"failed","reason":"Bad Reason")"));
    CHECK(!outcome(R"(,"status":"failed","response":"not base64!")"));
    CHECK(!outcome(R"(,"status":"done","result":")" + std::string(20'000, 'x') + "\""));
    CHECK(!connector::decode_from_connector(R"({"type":"outcome","id":"abc","status":"done"})"));
    CHECK(!connector::decode_from_connector("[1,2]"));
    CHECK(!connector::decode_from_connector("not json"));
    CHECK(!connector::decode_from_connector(""));
    CHECK(!connector::decode_from_connector(R"({"kind":"x"})"));
    CHECK(connector::decode_from_connector(R"({"type":"later","x":1})").error().code ==
          Errc::unsupported);
    CHECK(connector::decode_to_connector(R"({"type":"later"})").error().code == Errc::unsupported);
    // Unknown fields are ignored.
    CHECK(connector::decode_from_connector(
        R"({"type":"log","level":"info","message":"hi","extra":{"a":[1]}})"));
    // Nesting is bounded before parsing.
    CHECK(!connector::decode_from_connector(R"({"type":"log","level":"info","message":"x","n":)" +
                                            std::string(100, '[') + std::string(100, ']') + "}"));
    CHECK(!connector::decode_from_connector(std::string(connector::max_line + 1, ' ')));
}

TEST_CASE("CBOR and JSON convert with integers only", "[node][connector]") {
    CHECK(connector::cbor_to_json(cbor::Value::map({{cbor::Value::integer(1), text("x")}})) ==
          std::nullopt);
    CHECK(connector::cbor_to_json(cbor::Value::tagged(1, cbor::Value::integer(0))) == std::nullopt);
    CHECK(connector::cbor_to_json(cbor::Value::negative(0)) == "-1");
    CHECK(connector::cbor_to_json(cbor::Value::negative(UINT64_MAX)) == std::nullopt);
    CHECK(connector::cbor_to_json(cbor::Value::array(
              {cbor::Value::null(), cbor::Value::boolean(true)})) == "[null,true]");
    auto value = connector::json_to_cbor(R"({"b":[1,-2,"x"],"a":true})");
    REQUIRE(value);
    CHECK(connector::cbor_to_json(*value) == R"({"a":true,"b":[1,-2,"x"]})");
    CHECK(!connector::json_to_cbor("1.0"));
    CHECK(!connector::json_to_cbor("[1E2]"));
}

TEST_CASE("child processes run without a shell, with lines and timeouts", "[node][process]") {
    // A line in, a line out.
    auto cat = ChildProcess::start("cat", {});
    REQUIRE(cat);
    REQUIRE(cat->write("hello\nwor", 1s));
    auto line = cat->read_line(2s, 100);
    REQUIRE(line);
    CHECK(*line == "hello");
    // Half a line waits for the rest.
    line = cat->read_line(100ms, 100);
    REQUIRE(line);
    CHECK(!line->has_value());
    REQUIRE(cat->write("ld\n", 1s));
    line = cat->read_line(2s, 100);
    REQUIRE(line);
    CHECK(*line == "world");
    // A line that is too long is refused.
    REQUIRE(cat->write(std::string(300, 'x') + "\nnext\n", 1s));
    CHECK(cat->read_line(2s, 100).error().code == Errc::limit_exceeded);
    line = cat->read_line(2s, 100);
    REQUIRE(line);
    CHECK(*line == "next");
    cat->close_input();
    CHECK(cat->read_line(2s, 100).error().code == Errc::unavailable);
    const auto ended = cat->wait(2s);
    REQUIRE(ended);
    CHECK(ended->success());

    // Arguments are passed as given: no shell expands them.
    auto echo = ChildProcess::start("/bin/echo", {"$HOME", "a;b", "`x`"});
    REQUIRE(echo);
    const auto echoed = echo->communicate({}, 2s, 1024);
    REQUIRE(echoed.exit);
    CHECK(std::string(echoed.output.begin(), echoed.output.end()) == "$HOME a;b `x`\n");

    // The environment loses CEXCHAIN_* variables.
    ::setenv("CEXCHAIN_PASSPHRASE", "secret passphrase", 1);
    ::setenv("CONNECTOR_TEST_VISIBLE", "yes", 1);
    auto env = ChildProcess::start("env", {});
    REQUIRE(env);
    const auto listed = env->communicate({}, 2s, 1 << 20);
    const std::string environment(listed.output.begin(), listed.output.end());
    CHECK(environment.find("CONNECTOR_TEST_VISIBLE=yes") != std::string::npos);
    CHECK(environment.find("CEXCHAIN_") == std::string::npos);
    ::unsetenv("CEXCHAIN_PASSPHRASE");

    // Exit codes, output limits, and a program killed at its timeout.
    auto failing = ChildProcess::start("sh", {"-c", "cat > /dev/null; printf abcdef; exit 75"});
    REQUIRE(failing);
    const auto failed = failing->communicate(cexchain::as_bytes(std::string_view("input")), 2s, 4);
    REQUIRE(failed.exit);
    CHECK(failed.exit->code == 75);
    CHECK(std::string(failed.output.begin(), failed.output.end()) == "abcd");
    CHECK(failed.truncated);
    auto slow = ChildProcess::start("sleep", {"30"});
    REQUIRE(slow);
    const auto started = std::chrono::steady_clock::now();
    const auto timed_out = slow->communicate({}, 300ms, 1024);
    CHECK(!timed_out.exit);
    CHECK(std::chrono::steady_clock::now() - started < 5s);
    CHECK(!ChildProcess::start("/nonexistent/program", {}));
}
