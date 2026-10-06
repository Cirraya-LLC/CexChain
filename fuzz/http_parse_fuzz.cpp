// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Requests come from anyone who can reach the server, responses from any
// server a replica is pointed at. Parsing must never crash, never read past
// the input, and a request it accepts must be consistent with its framing.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <cexchain/node/http.hpp>

namespace http = cexchain::node::http;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    http::Limits limits;
    limits.max_body = 4096;
    limits.max_header_bytes = 2048;
    std::optional<http::ParseError> error;
    bool wants_continue = false;
    if (const auto parsed = http::parse_request(text, limits, error, &wants_continue)) {
        if (error || parsed->consumed > size || parsed->request.body.size() > limits.max_body ||
            parsed->request.path.empty() || parsed->request.path.front() != '/') {
            std::abort();
        }
    } else if (error && (error->status < 400 || error->status > 505)) {
        std::abort();
    }
    for (const bool at_end : {false, true}) {
        const auto response = http::parse_response(text, 4096, at_end);
        if (response && *response &&
            ((*response)->second > size || (*response)->first.body.size() > 4096)) {
            std::abort();
        }
    }
    return 0;
}
