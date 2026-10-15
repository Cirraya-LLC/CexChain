// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/core/protocol/common.hpp>
#include <cexchain/node/http.hpp>

/// GET /v1/requests (spec v0.8, 6b): the query an executor sends to learn of
/// requests. What the route answers is a hint: an executor checks a request
/// in the instance's evidence before acting on it (spec section 15).
namespace cexchain::node::detail {

struct RequestQuery {
    enum class Which : std::uint8_t { open, answered, all };
    Which which = Which::open;
    /// Any kind if empty; each a request kind.
    std::vector<std::string> kinds;
    std::optional<protocol::Id> contract;
    std::optional<protocol::Id> instance;
    /// Only requests made or answered after the log's first `after` entries
    /// (the `cursor` of an earlier answer).
    std::uint64_t after = 0;
    /// 1 to max_request_limit.
    std::uint64_t limit = 100;
    /// A long poll: if nothing matches, wait this long for something to (at
    /// most max_request_wait seconds).
    std::chrono::seconds wait{0};
};

/// The longest a long poll waits: below the server's request timeout (30 s
/// by default), after which the connection would be closed.
inline constexpr std::uint64_t max_request_wait = 25;
inline constexpr std::uint64_t max_request_limit = 1000;

/// Why a query is refused (a 400), in static text.
struct QueryError {
    std::string_view message;
};

/// Parses the request's query: state, kind (comma-separated), contract,
/// instance, after, limit, and wait; anything else is refused.
[[nodiscard]] std::variant<RequestQuery, QueryError> parse_request_query(const http::Request& r);

} // namespace cexchain::node::detail
