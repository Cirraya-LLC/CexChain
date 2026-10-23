// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's server side: its page, its headers, and the Host and
// Origin checks every request passes first.

#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/console/console.hpp>

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
