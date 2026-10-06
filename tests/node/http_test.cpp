// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <optional>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/node/client.hpp>
#include <cexchain/node/http.hpp>

namespace http = cexchain::node::http;
using cexchain::node::Url;

namespace {

struct Outcome {
    std::optional<http::Parsed> parsed;
    std::optional<http::ParseError> error;
    bool wants_continue = false;
};

Outcome parse(std::string_view text, http::Limits limits = {}) {
    Outcome o;
    o.parsed = http::parse_request(text, limits, o.error, &o.wants_continue);
    return o;
}

int status_of(std::string_view text, http::Limits limits = {}) {
    const auto o = parse(text, limits);
    REQUIRE_FALSE(o.parsed);
    REQUIRE(o.error);
    return o.error->status;
}

} // namespace

TEST_CASE("well-formed requests parse", "[node][http]") {
    const std::string text = "POST /v1/statements?a=1&b=x%20y HTTP/1.1\r\n"
                             "Host: ledger.example\r\n"
                             "Content-Type: application/cose\r\n"
                             "Content-Length: 5\r\n"
                             "\r\n"
                             "hello"
                             "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n";
    const auto first = parse(text);
    REQUIRE(first.parsed);
    const http::Request& r = first.parsed->request;
    CHECK(r.method == "POST");
    CHECK(r.path == "/v1/statements");
    CHECK(r.query.at("a") == "1");
    CHECK(r.query.at("b") == "x y");
    CHECK(r.header("content-type") == "application/cose");
    CHECK(std::string(r.body.begin(), r.body.end()) == "hello");
    CHECK(r.keep_alive);

    // Pipelined: the next request starts where the first ended.
    const auto second = parse(std::string_view(text).substr(first.parsed->consumed));
    REQUIRE(second.parsed);
    CHECK(second.parsed->request.path == "/healthz");

    // HTTP/1.0 closes by default; Connection: close closes 1.1.
    CHECK_FALSE(parse("GET / HTTP/1.0\r\n\r\n").parsed->request.keep_alive);
    CHECK(parse("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n").parsed->request.keep_alive);
    CHECK_FALSE(
        parse("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").parsed->request.keep_alive);
}

TEST_CASE("incomplete requests wait for more", "[node][http]") {
    const std::string full = "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd";
    for (std::size_t n = 0; n < full.size(); ++n) {
        const auto o = parse(full.substr(0, n));
        CHECK_FALSE(o.parsed);
        CHECK_FALSE(o.error);
    }
    CHECK(parse(full).parsed);

    const auto waiting =
        parse("POST /x HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n");
    CHECK_FALSE(waiting.parsed);
    CHECK(waiting.wants_continue);
}

TEST_CASE("ambiguous framing is refused", "[node][http][security]") {
    // Request smuggling needs two parsers to disagree on where a body ends:
    // anything that could be read two ways is refused.
    CHECK(status_of("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n") ==
          501);
    CHECK(status_of("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"
                    "a") == 400);
    CHECK(status_of("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +1\r\n\r\na") == 400);
    CHECK(status_of("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1, 1\r\n\r\na") == 400);
    CHECK(status_of("POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 1\r\n\r\na") == 400);
    CHECK(status_of("GET / HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n") == 400);
    CHECK(status_of("GET / HTTP/1.1\nHost: x\n\n") == 400);
    CHECK(status_of("GET / HTTP/1.1\r\nHost: x\rY: z\r\n\r\n") == 400);
    CHECK(status_of("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n") == 400);
    CHECK(status_of("GET / HTTP/1.1\r\n\r\n") == 400); // no Host
    CHECK(status_of("GET / HTTP/1.1\r\nHost: x\r\nX: a\x01b\r\n\r\n") == 400);
}

TEST_CASE("malformed request lines are refused", "[node][http]") {
    CHECK(status_of("GET  / HTTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET / HTTP/1.1 \r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET /a b HTTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("G(T / HTTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET / HTTP/2.0\r\nHost: x\r\n\r\n") == 505);
    CHECK(status_of("GET / FTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET /%zz HTTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET /%00 HTTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET /x?a=1&a=2 HTTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET /x?=1 HTTP/1.1\r\nHost: x\r\n\r\n") == 400);
    CHECK(status_of("GET / HTTP/1.1\r\nHost: x\r\nExpect: something\r\n\r\n") == 417);
}

TEST_CASE("limits are enforced", "[node][http]") {
    http::Limits limits;
    limits.max_body = 10;
    limits.max_header_bytes = 200;
    limits.max_headers = 3;
    CHECK(status_of("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n", limits) == 413);
    CHECK(status_of("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\n\r\n",
                    limits) == 400);
    CHECK(status_of("GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", limits) == 431);
    // An endless header section is cut off at the limit, without waiting.
    CHECK(status_of("GET / HTTP/1.1\r\nHost: x\r\nX: " + std::string(300, 'a'), limits) == 431);
    CHECK(
        parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789", limits).parsed);
}

TEST_CASE("responses serialize and parse back", "[node][http]") {
    http::Response response;
    response.status = 201;
    response.content_type = "application/cbor";
    response.body = {1, 2, 3};
    response.headers.emplace_back("Retry-After", "1");
    const std::string text = http::serialize(response, true);
    CHECK(text.starts_with("HTTP/1.1 201 Created\r\n"));
    const auto parsed = http::parse_response(text, 1024, false);
    REQUIRE(parsed);
    REQUIRE(*parsed);
    CHECK((*parsed)->first.status == 201);
    CHECK((*parsed)->first.body == cexchain::Bytes{1, 2, 3});
    CHECK((*parsed)->first.header("retry-after") == "1");
    CHECK((*parsed)->second == text.size());

    // Chunked responses, as a proxy may send them.
    const std::string chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                "3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\n\r\n";
    const auto c = http::parse_response(chunked, 1024, false);
    REQUIRE(c);
    REQUIRE(*c);
    CHECK(std::string((*c)->first.body.begin(), (*c)->first.body.end()) == "abcde");
    CHECK_FALSE(*http::parse_response(chunked.substr(0, chunked.size() - 3), 1024, false));
    CHECK_FALSE(http::parse_response(chunked.substr(0, chunked.size() - 3), 1024, true));
    CHECK_FALSE(http::parse_response(chunked, 4, false)); // too large

    // A body that ends with the connection.
    const std::string until_close = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nxyz";
    CHECK_FALSE(*http::parse_response(until_close, 1024, false));
    CHECK((*http::parse_response(until_close, 1024, true))->first.body.size() == 3);
    CHECK_FALSE(http::parse_response("HTTP/1.1 2000 OK\r\n\r\n", 1024, true));
}

TEST_CASE("server URLs", "[node][http]") {
    const auto a = Url::parse("https://ledger.example.com/cexchain/");
    REQUIRE(a);
    CHECK(a->tls);
    CHECK(a->host == "ledger.example.com");
    CHECK(a->port == 443);
    CHECK(a->base_path == "/cexchain");
    CHECK(a->to_string() == "https://ledger.example.com/cexchain");
    const auto b = Url::parse("http://[::1]:8080");
    REQUIRE(b);
    CHECK(b->host == "::1");
    CHECK(b->port == 8080);
    CHECK(b->to_string() == "http://[::1]:8080");
    CHECK_FALSE(Url::parse("ftp://x"));
    CHECK_FALSE(Url::parse("http://user@x"));
    CHECK_FALSE(Url::parse("http://x/?q"));
    CHECK_FALSE(Url::parse("http://x:0"));
    CHECK_FALSE(Url::parse("http://x:65536"));
    CHECK_FALSE(Url::parse("http://"));
    CHECK(http::percent_encode("a b/é") == "a%20b%2F%C3%A9");
}
