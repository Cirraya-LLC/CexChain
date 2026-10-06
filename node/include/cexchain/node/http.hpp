// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>

/// HTTP/1.1 messages (RFC 9110, RFC 9112), parsed strictly: anything a
/// lenient parser might read differently from a proxy in front of it is
/// refused rather than guessed at. Requests carry their body with
/// Content-Length only; Transfer-Encoding is refused, which also rules out
/// request smuggling through disagreeing framing.
namespace cexchain::node::http {

struct Limits {
    std::size_t max_header_bytes = 16 * 1024;
    std::size_t max_headers = 64;
    std::size_t max_body = 1024 * 1024;
};

struct Request {
    std::string method;
    /// The request target as sent, e.g. "/v1/entries?start=0".
    std::string target;
    /// The target's path, percent-decoded.
    std::string path;
    /// The target's query parameters, percent-decoded. A repeated name is
    /// refused.
    std::map<std::string, std::string, std::less<>> query;
    /// Header fields with lower-case names, in order.
    std::vector<std::pair<std::string, std::string>> headers;
    Bytes body;
    bool keep_alive = true;

    /// The value of the single header field `name` (lower case), if present.
    [[nodiscard]] std::optional<std::string_view> header(std::string_view name) const;
};

struct Response {
    int status = 200;
    std::string content_type = "application/json";
    Bytes body;
    /// Further header fields, e.g. {"retry-after", "1"}.
    std::vector<std::pair<std::string, std::string>> headers;
};

/// Why a request could not be parsed, with the status to answer it with.
struct ParseError {
    int status = 400;
    std::string_view message;
};

/// A request parsed from the front of a buffer, and how many bytes it used.
struct Parsed {
    Request request;
    std::size_t consumed = 0;
};

/// Parses one request from the front of `buffer`. Returns nothing if the
/// buffer does not hold a complete request yet, or sets `error` (400, 413,
/// 417, 431, 501, or 505) if it cannot be a valid one; the connection must
/// then be closed after answering. `wants_continue` is set when the header
/// section is complete and valid, the body is not, and the client sent
/// "Expect: 100-continue".
[[nodiscard]] std::optional<Parsed> parse_request(std::string_view buffer, const Limits& limits,
                                                  std::optional<ParseError>& error,
                                                  bool* wants_continue = nullptr);

/// The status line, header fields, and body of `response`.
[[nodiscard]] std::string serialize(const Response& response, bool keep_alive);

/// A response read by a client.
struct ClientResponse {
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    Bytes body;

    [[nodiscard]] std::optional<std::string_view> header(std::string_view name) const;
};

/// Parses a response to a request, from the front of `buffer`, if complete.
/// Bodies are framed by Content-Length, by chunked transfer coding (as
/// proxies may send them), or by the end of the connection when
/// `at_end_of_stream`.
[[nodiscard]] Result<std::optional<std::pair<ClientResponse, std::size_t>>>
parse_response(std::string_view buffer, std::size_t max_body, bool at_end_of_stream);

/// Percent-encodes a path segment or query value (RFC 3986 unreserved
/// characters stay as they are).
[[nodiscard]] std::string percent_encode(std::string_view text);

/// The reason phrase for a status code.
[[nodiscard]] std::string_view reason(int status);

} // namespace cexchain::node::http
