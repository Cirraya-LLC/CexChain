// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's server side: its page, its headers, and the Host and
// Origin checks every request passes first.

#include <filesystem>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>

namespace console = cexchain::console;
namespace http = cexchain::node::http;

namespace {

http::Request request(std::string method, std::string path, std::string host,
                      std::string origin = {}) {
    http::Request r;
    r.method = std::move(method);
    r.target = path;
    r.path = std::move(path);
    r.headers.emplace_back("host", std::move(host));
    if (!origin.empty()) {
        r.headers.emplace_back("origin", std::move(origin));
    }
    return r;
}

std::string header(const http::Response& r, std::string_view name) {
    for (const auto& [key, value] : r.headers) {
        if (key == name) {
            return value;
        }
    }
    return {};
}

std::string body(const http::Response& r) {
    return {r.body.begin(), r.body.end()};
}

const cexchain::crypto::Provider& provider() {
    static const cexchain::crypto::openssl::Provider instance;
    return instance;
}

/// A fresh directory, removed at the end of the test.
struct TempDirectory {
    std::filesystem::path path;
    TempDirectory() {
        static int counter = 0;
        path = std::filesystem::temp_directory_path() /
               ("cexchain-console-test-" + std::to_string(::getpid()) + "-" +
                std::to_string(++counter));
        std::filesystem::remove_all(path);
    }
    ~TempDirectory() { std::filesystem::remove_all(path); }
    TempDirectory(const TempDirectory&) = delete;
    TempDirectory& operator=(const TempDirectory&) = delete;
};

constexpr cexchain::protocol::Timestamp minute = 60'000;

} // namespace

TEST_CASE("the console serves its page with its security headers", "[console]") {
    console::Console c;
    c.set_origins(console::loopback_origins(7470));
    const auto page = c.handle(request("GET", "/console/", "localhost:7470"));
    CHECK(page.status == 200);
    CHECK(page.content_type == "text/html; charset=utf-8");
    CHECK(body(page).starts_with("<!doctype html>"));
    CHECK(header(page, "Content-Security-Policy") == console::content_security_policy);
    CHECK(header(page, "X-Content-Type-Options") == "nosniff");
    CHECK(header(page, "X-Frame-Options") == "DENY");
    CHECK(header(page, "Cache-Control") == "no-store");
    for (const std::string host : {"127.0.0.1:7470", "[::1]:7470", "LOCALHOST:7470"}) {
        INFO(host);
        CHECK(c.handle(request("GET", "/console/console.js", host)).status == 200);
    }
    const auto script = c.handle(request("GET", "/console/console.js", "localhost:7470"));
    CHECK(script.content_type == "text/javascript; charset=utf-8");
    const auto moved = c.handle(request("GET", "/console", "localhost:7470"));
    CHECK(moved.status == 308);
    CHECK(header(moved, "Location") == "/console/");
    const auto missing = c.handle(request("GET", "/console/nothing", "localhost:7470"));
    CHECK(missing.status == 404);
    CHECK(header(missing, "Content-Security-Policy") == console::content_security_policy);
    const auto api = c.handle(request("GET", "/console/api/nothing", "localhost:7470"));
    CHECK(api.status == 404);
    CHECK(api.content_type == "application/json");
}

TEST_CASE("the console answers only for its own names (DNS rebinding)", "[console]") {
    console::Console c;
    CHECK(c.handle(request("GET", "/console/", "localhost:7470")).status == 503);
    c.set_origins(console::loopback_origins(7470));
    for (const std::string host : {"attacker.example:7470", "localhost:7471", "localhost",
                                   "localhost:0", "localhost:x", "local host:7470", ""}) {
        INFO(host);
        CHECK(c.handle(request("GET", "/console/", host)).status != 200);
    }
    http::Request no_host;
    no_host.method = "GET";
    no_host.path = "/console/";
    CHECK(c.handle(no_host).status == 400);
}

TEST_CASE("the console refuses other sites' pages", "[console]") {
    console::Console c;
    c.set_origins(console::loopback_origins(7470));
    const std::string host = "localhost:7470";
    CHECK(c.handle(request("GET", "/console/", host, "http://localhost:7470")).status == 200);
    CHECK(c.handle(request("GET", "/console/", host, "https://attacker.example")).status == 403);
    CHECK(c.handle(request("GET", "/console/", host, "http://localhost:7471")).status == 403);
    CHECK(c.handle(request("GET", "/console/", host, "null")).status == 403);
    // A request that changes something must say it comes from the console.
    CHECK(c.handle(request("POST", "/console/api/session", host)).status == 403);
    CHECK(c.handle(request("POST", "/console/api/nothing", host, "http://localhost:7470")).status ==
          404);
    CHECK(c.handle(request("POST", "/console/", host, "http://localhost:7470")).status == 405);
}

TEST_CASE("a public URL is the console's only name", "[console]") {
    const auto origin = console::parse_origin("https://Ledger.Example.com/");
    REQUIRE(origin);
    CHECK(origin->text() == "https://ledger.example.com");
    CHECK(origin->authority() == "ledger.example.com");
    CHECK(console::parse_origin("https://ledger.example.com:8443")->text() ==
          "https://ledger.example.com:8443");
    CHECK(console::parse_origin("http://ledger.example.com:80")->port == 0);
    for (const std::string_view bad :
         {"ftp://ledger.example.com", "https://", "https://ledger.example.com/path",
          "https://user@ledger.example.com", "https://ledger.example.com:99999",
          "https://ledger.example.com?x", "ledger.example.com"}) {
        INFO(bad);
        CHECK_FALSE(console::parse_origin(bad));
    }
    console::Console c;
    c.set_origins({*origin});
    CHECK(c.handle(request("GET", "/console/", "ledger.example.com")).status == 200);
    CHECK(c.handle(request("GET", "/console/", "ledger.example.com:443")).status == 200);
    CHECK(c.handle(request("GET", "/console/", "localhost:7470")).status == 421);
}

TEST_CASE("a session's bearer token", "[console][sessions]") {
    const std::string token = "cxs_" + std::string(43, 'A');
    CHECK(console::bearer_token("Bearer " + token) == token);
    CHECK(console::bearer_token("bearer " + token) == token);
    for (const std::string& bad :
         {"Bearer " + token + "A", "Bearer " + token.substr(0, 46), "Basic " + token,
          "Bearer  " + token.substr(1), "Bearer cxt_" + std::string(43, 'A'),
          "Bearer cxs_" + std::string(42, 'A') + "=", "Bearer cxs_" + std::string(42, 'A') + " ",
          std::string("Bearer"), std::string()}) {
        INFO(bad);
        CHECK_FALSE(console::bearer_token(bad));
    }
}

TEST_CASE("sessions end when idle, at their lifetime, on sign-out, and when revoked",
          "[console][sessions]") {
    const TempDirectory dir;
    cexchain::ledger::ManualClock clock(1'800'000'000'000);
    cexchain::ledger::SeededEntropy entropy(7);
    console::Sessions sessions(dir.path, provider(), clock, entropy);

    const std::string token = sessions.create("alice");
    CHECK(console::bearer_token("Bearer " + token) == token);
    const auto session = sessions.use(token);
    REQUIRE(session);
    CHECK(session->user == "alice");
    CHECK(session->id.size() == 16);
    CHECK_FALSE(sessions.use("cxs_" + std::string(43, 'A')));

    // Idle: 30 minutes without a request.
    clock.advance(29 * minute);
    REQUIRE(sessions.use(token));
    clock.advance(30 * minute);
    CHECK_FALSE(sessions.use(token));

    // Used every 20 minutes, it still ends 12 hours after it began.
    const std::string busy = sessions.create("bob");
    for (int i = 0; i < 35; ++i) {
        clock.advance(20 * minute);
        REQUIRE(sessions.use(busy));
    }
    clock.advance(20 * minute);
    CHECK_FALSE(sessions.use(busy));

    // Signing out.
    const std::string out = sessions.create("carol");
    CHECK(sessions.end(out));
    CHECK_FALSE(sessions.end(out));
    CHECK_FALSE(sessions.use(out));

    // Revoked from the command line, by the id it lists.
    const std::string revoked = sessions.create("dave");
    const std::string kept = sessions.create("erin");
    const auto listed = console::published_sessions(dir.path);
    REQUIRE(listed.size() == 2);
    const std::string dave_id = sessions.use(revoked)->id;
    console::request_revocation(dir.path, dave_id);
    CHECK_FALSE(sessions.use(revoked));
    CHECK(sessions.use(kept));
    REQUIRE(sessions.list().size() == 1);
    CHECK(console::published_sessions(dir.path).size() == 1);
    CHECK_THROWS(console::request_revocation(dir.path, "not-an-id"));

    // What is published names sessions, never their tokens or hashes.
    const auto text = cexchain::app::read_file(dir.path / "sessions.json");
    const std::string published(text.begin(), text.end());
    CHECK(published.find(kept) == std::string::npos);
    CHECK(published.find("erin") != std::string::npos);
    CHECK(published.find("cxs_") == std::string::npos);
}

TEST_CASE("the console's session route", "[console][sessions]") {
    const TempDirectory dir;
    cexchain::ledger::ManualClock clock(1'800'000'000'000);
    cexchain::ledger::SeededEntropy entropy(8);
    console::Sessions sessions(dir.path, provider(), clock, entropy);
    console::Console c(&sessions);
    c.set_origins(console::loopback_origins(7470));
    const std::string host = "localhost:7470";
    const std::string origin = "http://localhost:7470";

    auto none = c.handle(request("GET", "/console/api/session", host));
    CHECK(none.status == 401);
    CHECK(header(none, "WWW-Authenticate") == "Bearer");
    CHECK(header(none, "Cache-Control") == "no-store");

    const std::string token = sessions.create("alice");
    auto mine = request("GET", "/console/api/session", host);
    mine.headers.emplace_back("authorization", "Bearer " + token);
    const auto who = c.handle(mine);
    CHECK(who.status == 200);
    CHECK(body(who).find("\"user\":\"alice\"") != std::string::npos);
    CHECK(body(who).find(token) == std::string::npos);

    auto forged = request("GET", "/console/api/session", host);
    forged.headers.emplace_back("authorization", "Bearer cxs_" + std::string(43, 'B'));
    CHECK(c.handle(forged).status == 401);

    // Signing out is a change: from the console's page only.
    auto sign_out = request("DELETE", "/console/api/session", host);
    sign_out.headers.emplace_back("authorization", "Bearer " + token);
    CHECK(c.handle(sign_out).status == 403);
    sign_out.headers.emplace_back("origin", origin);
    CHECK(c.handle(sign_out).status == 200);
    CHECK(c.handle(mine).status == 401);

    console::Console without;
    without.set_origins(console::loopback_origins(7470));
    CHECK(without.handle(mine).status == 503);
}
