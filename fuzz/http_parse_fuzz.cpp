// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Requests come from anyone who can reach the server, responses from any
// server a replica is pointed at. Parsing must never crash, never read past
// the input, and a request it accepts must be consistent with its framing.
// The input is also fed in pieces, as the server reads it: a request must
// not be accepted (or refused) before all of it has arrived, nor differently
// once more arrives after it.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include <cexchain/node/http.hpp>

namespace http = cexchain::node::http;

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
