// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <chrono>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <cexchain/core/bytes.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/node/connectors.hpp>
#include <cexchain/node/server.hpp>

namespace cbor = cexchain::cbor;
namespace connector = cexchain::node::connector;
namespace http = cexchain::node::http;
using cexchain::Bytes;
using cexchain::to_hex;
using json = nlohmann::json;
using namespace std::chrono_literals;

namespace {

std::filesystem::path fresh_directory() {
    static int counter = 0;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("cexchain-connectors-test-" + std::to_string(::getpid()) + "-" +
                      std::to_string(counter++));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

/// A webhook receiver: records what it receives, answers what it is told.
class Receiver final : public cexchain::node::Application {
public:
    void handle(http::Request request, std::string, Respond respond) override {
        http::Response response;
        {
            const std::lock_guard lock(mutex_);
            received_.push_back(std::move(request));
            response = next_;
        }
        respond(std::move(response));
    }
    void answer(int status, std::string body,
                std::vector<std::pair<std::string, std::string>> headers = {}) {
        const std::lock_guard lock(mutex_);
        next_ = {};
        next_.status = status;
        next_.body.assign(body.begin(), body.end());
        next_.headers = std::move(headers);
    }
    http::Request last() {
        const std::lock_guard lock(mutex_);
        REQUIRE(!received_.empty());
        return received_.back();
    }
    std::size_t count() {
        const std::lock_guard lock(mutex_);
        return received_.size();
    }

private:
    std::mutex mutex_;
    std::vector<http::Request> received_;
    http::Response next_;
};

class Running {
public:
    Running(cexchain::node::Application& app, cexchain::node::ServerOptions options)
        : server_(app, std::move(options)) {
        REQUIRE(server_.listen());
        thread_ = std::thread([this] { server_.run(); });
    }
    Running(const Running&) = delete;
    Running& operator=(const Running&) = delete;
    ~Running() {
        server_.stop();
        thread_.join();
    }
    [[nodiscard]] std::uint16_t port() const { return server_.port(); }

private:
    cexchain::node::Server server_;
    std::thread thread_;
};

cexchain::node::ServerOptions plain() {
    cexchain::node::ServerOptions o;
    o.host = "127.0.0.1";
    o.threads = 1;
    o.port = 0;
    o.request_timeout = 10s;
    return o;
}

/// A self-signed certificate and key for 127.0.0.1.
std::pair<std::filesystem::path, std::filesystem::path>
self_signed(const std::filesystem::path& dir) {
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    REQUIRE(key != nullptr);
    X509* cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    X509_NAME* name = X509_get_subject_name(cert);
    const std::string cn = "cexchain webhook test";
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509V3_CTX context;
    X509V3_set_ctx(&context, cert, cert, nullptr, nullptr, 0);
    for (const auto& [nid, value] : {std::pair{NID_subject_alt_name, std::string("IP:127.0.0.1")},
                                     std::pair{NID_basic_constraints, std::string("CA:TRUE")}}) {
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value.c_str());
        REQUIRE(extension != nullptr);
        X509_add_ext(cert, extension, -1);
        X509_EXTENSION_free(extension);
    }
    REQUIRE(X509_sign(cert, key, EVP_sha256()) > 0);
    const auto cert_path = dir / "cert.pem";
    const auto key_path = dir / "key.pem";
    FILE* out = std::fopen(cert_path.c_str(), "w");
    PEM_write_X509(out, cert);
    std::fclose(out);
    out = std::fopen(key_path.c_str(), "w");
    PEM_write_PrivateKey(out, key, nullptr, nullptr, 0, nullptr, nullptr);
    std::fclose(out);
    X509_free(cert);
    EVP_PKEY_free(key);
    return {cert_path, key_path};
}

cexchain::protocol::Id id_of(std::uint8_t fill) {
    std::array<std::uint8_t, 32> bytes{};
    bytes.fill(fill);
    return *cexchain::protocol::to_id(bytes);
}

connector::Perform request() {
    connector::Perform p;
    p.request = id_of(7);
    p.kind = "notify";
    p.params = cbor::Value::map({{cbor::Value::text("about"), cbor::Value::text("welcome")}});
    p.deadline = 1'800'000'000'000;
    p.asked_at = 1'799'000'000'000;
    p.home = id_of(1);
    p.contract = id_of(2);
    p.instance = id_of(3);
    p.reply = "result";
    p.attempt = 2;
    p.timeout_ms = 10'000;
    return p;
}

connector::Hello hello(json config, const std::string& secret = "",
                       const std::string& secret_name = "hook-key") {
    connector::Hello h;
    h.connector = "test";
    h.config = config.dump();
    if (!secret.empty()) {
        h.secrets[secret_name] =
            connector::Secret{cexchain::SecureBytes(Bytes(secret.begin(), secret.end()))};
    }
    return h;
}

std::string text_of(const Bytes& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

} // namespace

TEST_CASE("the webhook connector posts signed requests and maps the answers",
          "[node][connectors]") {
    Receiver receiver;
    Running running(receiver, plain());
    const std::string url = "http://127.0.0.1:" + std::to_string(running.port()) + "/hooks/in";
    std::string error;
    auto webhook = connector::make_webhook(
        hello({{"url", url}, {"secret", "hook-key"}, {"timeout", 5}}, "shared secret"), error);
    REQUIRE(webhook);

    // Done, with what the receiver chose to publish.
    receiver.answer(200, R"({"result":{"ref":"N-1001"},"note":"not published"})");
    auto o = webhook->perform(request());
    CHECK(o.status == connector::OutcomeStatus::done);
    REQUIRE(o.result);
    CHECK(connector::cbor_to_json(*o.result) == R"({"ref":"N-1001"})");
    REQUIRE(o.response);
    CHECK(text_of(*o.response) == R"({"result":{"ref":"N-1001"},"note":"not published"})");
    const http::Request got = receiver.last();
    CHECK(got.method == "POST");
    CHECK(got.path == "/hooks/in");
    CHECK(got.header("content-type") == "application/json");
    CHECK(got.header("x-cexchain-request") == to_hex(id_of(7).bytes()));
    CHECK(got.header("idempotency-key") == to_hex(id_of(7).bytes()));
    CHECK(got.header("x-cexchain-attempt") == "2");
    // The signature: HMAC-SHA-256 over the timestamp, a dot, and the body.
    const std::string body = text_of(got.body);
    const std::string timestamp(*got.header("x-cexchain-timestamp"));
    const auto expected = cexchain::crypto::openssl::hmac(
        cexchain::crypto::HashAlg::sha256, cexchain::as_bytes(std::string_view("shared secret")),
        cexchain::as_bytes(timestamp + "." + body));
    REQUIRE(expected);
    CHECK(got.header("x-cexchain-signature") == "sha256=" + to_hex(expected->bytes()));
    const json document = json::parse(body);
    CHECK(document["kind"] == "notify");
    CHECK(document["params"]["about"] == "welcome");
    CHECK(document["protocol"] == 1);
    CHECK(document["deadline"] == 1'800'000'000'000);
    CHECK(!document.contains("secrets"));

    // Busy: try again, after what Retry-After says.
    receiver.answer(503, "{}", {{"Retry-After", "7"}});
    o = webhook->perform(request());
    CHECK(o.status == connector::OutcomeStatus::retry);
    CHECK(o.retry_after_ms == 7000);
    receiver.answer(429, "");
    CHECK(webhook->perform(request()).status == connector::OutcomeStatus::retry);
    // Refused: failed, with the receiver's reason code if it gives one.
    receiver.answer(404, "no such hook");
    o = webhook->perform(request());
    CHECK(o.status == connector::OutcomeStatus::failed);
    CHECK(o.reason == "rejected");
    receiver.answer(422, R"({"reason":"unmapped"})");
    CHECK(webhook->perform(request()).reason == "unmapped");
    // A 2xx may still say the work failed.
    receiver.answer(200, R"({"status":"failed","reason":"out-of-stock"})");
    o = webhook->perform(request());
    CHECK(o.status == connector::OutcomeStatus::failed);
    CHECK(o.reason == "out-of-stock");
    // Redirects are not followed.
    receiver.answer(307, "", {{"Location", "http://127.0.0.1:1/elsewhere"}});
    CHECK(webhook->perform(request()).status == connector::OutcomeStatus::failed);
    const std::size_t seen = receiver.count();

    // Nobody listening: try again.
    auto nowhere = connector::make_webhook(
        hello({{"url", "http://127.0.0.1:1/x"}, {"secret", "hook-key"}, {"timeout", 2}}, "s"),
        error);
    REQUIRE(nowhere);
    o = nowhere->perform(request());
    CHECK(o.status == connector::OutcomeStatus::retry);
    CHECK(o.reason == "unavailable");
    CHECK(receiver.count() == seen);

    // Configurations that are refused.
    auto refused = [&](json config, const std::string& secret = "s") {
        std::string why;
        CHECK(!connector::make_webhook(hello(std::move(config), secret), why));
        CHECK(!why.empty());
        return why;
    };
    CHECK(refused({{"url", "http://example.com/x"}, {"secret", "hook-key"}}).find("https") !=
          std::string::npos);
    CHECK(refused({{"url", url}}).find("secret") != std::string::npos);
    CHECK(refused({{"url", url}, {"secret", "other"}}).find("did not arrive") != std::string::npos);
    refused({{"url", url}, {"secret", "hook-key"}, {"timeout", 0}});
    refused({{"url", url}, {"secret", "hook-key"}, {"timeout", 1.5}});
    refused({{"url", "ftp://x"}, {"secret", "hook-key"}});
    refused({{"url", url}, {"secret", "hook-key"}, {"ca_file", "/nonexistent.pem"}});
}

TEST_CASE("the webhook connector verifies TLS certificates", "[node][connectors]") {
    const auto dir = fresh_directory();
    const auto [cert, key] = self_signed(dir);
    Receiver receiver;
    auto options = plain();
    options.tls_certificate = cert;
    options.tls_private_key = key;
    Running running(receiver, options);
    receiver.answer(204, "");
    const std::string url = "https://127.0.0.1:" + std::to_string(running.port()) + "/";
    std::string error;
    // Trusting the receiver's certificate: done.
    auto trusting = connector::make_webhook(
        hello({{"url", url}, {"secret", "hook-key"}, {"ca_file", cert.string()}}, "s"), error);
    REQUIRE(trusting);
    CHECK(trusting->perform(request()).status == connector::OutcomeStatus::done);
    CHECK(receiver.count() == 1);
    // With the system's roots, the self-signed certificate is not trusted:
    // nothing is sent, and the request is tried again later.
    auto system =
        connector::make_webhook(hello({{"url", url}, {"secret", "hook-key"}}, "s"), error);
    REQUIRE(system);
    const auto o = system->perform(request());
    CHECK(o.status == connector::OutcomeStatus::retry);
    CHECK(o.reason == "tls");
    CHECK(receiver.count() == 1);
    std::filesystem::remove_all(dir);
}

TEST_CASE("the command connector runs a program per request, without a shell",
          "[node][connectors]") {
    const auto dir = fresh_directory();
    const auto seen = dir / "stdin.json";
    std::string error;
    // The request on stdin, with the secrets the config names; argv as
    // configured, never built from params.
    const std::string script = "cat > \"$1\"; printf '{\"result\":{\"ref\":\"C-1\"}}'";
    auto command = connector::make_command(hello({{"program", "sh"},
                                                  {"args", {"-c", script, "script", seen.string()}},
                                                  {"secrets", {"panel-token"}},
                                                  {"timeout", 5}},
                                                 "panel secret", "panel-token"),
                                           error);
    INFO(error);
    REQUIRE(command);
    auto o = command->perform(request());
    CHECK(o.status == connector::OutcomeStatus::done);
    REQUIRE(o.result);
    CHECK(connector::cbor_to_json(*o.result) == R"({"ref":"C-1"})");
    CHECK(text_of(*o.response) == R"({"result":{"ref":"C-1"}})");
    std::ifstream in(seen);
    const json document = json::parse(in);
    CHECK(document["id"] == to_hex(id_of(7).bytes()));
    CHECK(document["params"]["about"] == "welcome");
    CHECK(document["secrets"]["panel-token"] == "panel secret");

    auto run = [&](const std::string& body, int timeout = 5) {
        std::string why;
        auto c = connector::make_command(
            hello({{"program", "sh"}, {"args", {"-c", body}}, {"timeout", timeout}}), why);
        REQUIRE(c);
        return c->perform(request());
    };
    o = run("cat > /dev/null; exit 75");
    CHECK(o.status == connector::OutcomeStatus::retry);
    CHECK(o.reason == "unavailable");
    o = run("cat > /dev/null; echo '{\"reason\":\"no-capacity\"}'; exit 3");
    CHECK(o.status == connector::OutcomeStatus::failed);
    CHECK(o.reason == "no-capacity");
    o = run("exit 1");
    CHECK(o.status == connector::OutcomeStatus::failed);
    CHECK(o.reason == "rejected");
    o = run("echo 'not json'");
    CHECK(o.status == connector::OutcomeStatus::done);
    CHECK(!o.result);
    const auto started = std::chrono::steady_clock::now();
    o = run("sleep 30", 1);
    CHECK(o.status == connector::OutcomeStatus::retry);
    CHECK(o.reason == "timeout");
    CHECK(std::chrono::steady_clock::now() - started < 10s);
    o = run("kill -9 $$");
    CHECK(o.status == connector::OutcomeStatus::retry);
    CHECK(o.reason == "crashed");
    std::string why;
    CHECK(!connector::make_command(hello({{"args", {"x"}}}), why));
    CHECK(!connector::make_command(hello({{"program", "sh"}, {"secrets", {"missing"}}}), why));
    std::filesystem::remove_all(dir);
}

TEST_CASE("a connector's loop answers hello, performs requests, and stops", "[node][connectors]") {
    struct Echo final : connector::Performer {
        connector::Outcome perform(const connector::Perform& p) override {
            connector::Outcome o;
            o.request = p.request;
            o.result = cbor::Value::text(p.kind);
            return o;
        }
        std::vector<std::string> kinds() const override { return {"notify"}; }
    };
    std::deque<std::string> input = {
        connector::encode(connector::ToConnector(request())), // before hello
        connector::encode(connector::ToConnector(hello(json::object()))),
        "garbage",
        connector::encode(connector::ToConnector(request())),
        connector::encode(connector::ToConnector(connector::Stop{})),
        connector::encode(connector::ToConnector(request())), // after stop: unread
    };
    std::vector<std::string> output;
    connector::LineIo io;
    io.read = [&]() -> std::optional<std::string> {
        if (input.empty()) {
            return std::nullopt;
        }
        std::string line = std::move(input.front());
        input.pop_front();
        return line;
    };
    io.write = [&](std::string_view line) {
        output.emplace_back(line);
        return true;
    };
    const int code = connector::serve(io, "echo", "1.0", [](const connector::Hello&, std::string&) {
        return std::make_unique<Echo>();
    });
    CHECK(code == 0);
    CHECK(input.size() == 1);
    REQUIRE(output.size() == 4);
    auto first = connector::decode_from_connector(output[0]);
    REQUIRE(first);
    CHECK(std::get<connector::Log>(*first).level == connector::LogLevel::error);
    auto ready = connector::decode_from_connector(output[1]);
    REQUIRE(ready);
    CHECK(std::get<connector::Ready>(*ready).kinds == std::vector<std::string>{"notify"});
    CHECK(std::holds_alternative<connector::Log>(*connector::decode_from_connector(output[2])));
    auto done = connector::decode_from_connector(output[3]);
    REQUIRE(done);
    CHECK(std::get<connector::Outcome>(*done).result == cbor::Value::text("notify"));

    // A configuration it refuses: logged, exit 2.
    input = {connector::encode(connector::ToConnector(hello(json::object())))};
    output.clear();
    CHECK(connector::serve(io, "webhook", "1.0", connector::make_webhook) == 2);
    REQUIRE(output.size() == 1);
    CHECK(std::get<connector::Log>(*connector::decode_from_connector(output[0]))
              .message.find("url") != std::string::npos);
}
