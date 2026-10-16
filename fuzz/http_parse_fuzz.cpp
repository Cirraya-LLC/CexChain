// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Requests come from anyone who can reach the server, responses from any
// server a replica is pointed at. Parsing must never crash, never read past
// the input, and a request it accepts must be consistent with its framing.
// The input is also fed in pieces, as the server reads it: a request must
// not be accepted (or refused) before all of it has arrived, nor differently
// once more arrives after it. A request's query is also read as the requests
// route reads it (spec v0.8): whatever it accepts is within its limits.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/node/http.hpp>

#include "request_query.hpp"

namespace http = cexchain::node::http;
namespace detail = cexchain::node::detail;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

bool is_field(std::string_view name, std::string_view wanted) {
    return name.size() == wanted.size() && std::ranges::equal(name, wanted, [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) == b;
           });
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    http::Limits limits;
    limits.max_body = 4096;
    limits.max_header_bytes = 2048;
    std::optional<http::ParseError> error;
    bool wants_continue = false;
    const auto parsed = http::parse_request(text, limits, error, &wants_continue);
    if (parsed) {
        const http::Request& r = parsed->request;
        require(!error && parsed->consumed <= size && r.body.size() <= limits.max_body &&
                !r.path.empty() && r.path.front() == '/');
        // The request ends exactly where its framing says.
        const std::size_t headers_end = text.find("\r\n\r\n");
        require(headers_end != std::string_view::npos &&
                parsed->consumed == headers_end + 4 + r.body.size() &&
                std::ranges::equal(
                    r.body, text.substr(headers_end + 4, r.body.size()),
                    [](std::uint8_t a, char b) { return a == static_cast<unsigned char>(b); }));
        // No ambiguous framing is ever accepted.
        std::size_t lengths = 0;
        std::size_t connections = 0;
        for (const auto& [name, value] : r.headers) {
            require(!is_field(name, "transfer-encoding"));
            lengths += is_field(name, "content-length") ? 1 : 0;
            connections += is_field(name, "connection") ? 1 : 0;
        }
        require(lengths <= 1 && connections <= 1);
        // GET /v1/requests: a query it takes is one the route can serve.
        const auto query = detail::parse_request_query(r);
        if (const auto* q = std::get_if<detail::RequestQuery>(&query)) {
            require(q->limit >= 1 && q->limit <= detail::max_request_limit &&
                    static_cast<std::uint64_t>(q->wait.count()) <= detail::max_request_wait);
            for (const std::string& kind : q->kinds) {
                require(cexchain::protocol::is_request_kind(kind));
            }
        } else {
            require(!std::get<detail::QueryError>(query).message.empty() && !r.query.empty());
        }
        // GET /v1/contracts/due (the keeper's): the same.
        const auto due = detail::parse_due_query(r);
        if (const auto* q = std::get_if<detail::DueQuery>(&due)) {
            require(q->limit >= 1 && q->limit <= detail::max_due_limit &&
                    q->grace.value_or(0) <= detail::max_due_grace);
        } else {
            require(!std::get<detail::QueryError>(due).message.empty() && !r.query.empty());
        }
    } else if (error) {
        require(error->status >= 400 && error->status <= 505);
    }
    // Fed in pieces: before the request is complete, nothing; from then on,
    // the same request.
    if (parsed && size <= 1024) {
        for (std::size_t cut = 0; cut <= size; ++cut) {
            std::optional<http::ParseError> part_error;
            const auto part = http::parse_request(text.substr(0, cut), limits, part_error, nullptr);
            if (cut < parsed->consumed) {
                require(!part && !part_error);
            } else {
                require(part && part->consumed == parsed->consumed &&
                        part->request.target == parsed->request.target &&
                        part->request.body == parsed->request.body);
            }
        }
    }
    for (const bool at_end : {false, true}) {
        const auto response = http::parse_response(text, 4096, at_end);
        if (response && *response) {
            require((*response)->second <= size && (*response)->first.body.size() <= 4096);
        }
    }
    return 0;
}
