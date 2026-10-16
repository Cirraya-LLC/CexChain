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

/// The queries of the routes for executors and keepers (6b). GET
/// /v1/requests (spec v0.8): the query an executor sends to learn of
/// requests. What the route answers is a hint: an executor checks a request
/// in the instance's evidence before acting on it (spec section 15).
namespace cexchain::node::detail {

/// An executor's lease lasts this long after its last poll by default; 5 to
/// 300 seconds.
inline constexpr std::uint64_t default_lease_ttl = 60;
inline constexpr std::uint64_t min_lease_ttl = 5;
inline constexpr std::uint64_t max_lease_ttl = 300;

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
    /// An executor's lease (6b): the copy `lease` (8 to 64 letters, digits,
    /// '-' or '_', random per process) of the executor `executor` (an actor
    /// id) takes or renews the lease for `ttl` after the answer; a copy that
    /// does not hold it is told so and gets no requests. Both or neither.
    std::optional<std::string> lease;
    std::optional<protocol::Id> executor;
    std::chrono::seconds ttl{default_lease_ttl};
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
/// instance, after, limit, wait, and an executor's executor, lease, and
/// ttl; anything else is refused.
[[nodiscard]] std::variant<RequestQuery, QueryError> parse_request_query(const http::Request& r);

/// GET /v1/contracts/due (6b): what a keeper would do at a time.
struct DueQuery {
    /// The time to run at, in milliseconds since the epoch (default: now).
    std::optional<protocol::Timestamp> at;
    /// The grace after a deadline before an expiry, in seconds (default:
    /// the server's).
    std::optional<std::uint64_t> grace;
    /// Whose work: an actor's (its delegations decide), or everything.
    std::optional<protocol::Id> keeper;
    std::optional<protocol::Id> contract;
    std::optional<protocol::Id> instance;
    /// Instances to skip: the `next` of an earlier answer.
    std::uint64_t start = 0;
    /// Contract runs at most: 1 to max_due_limit.
    std::uint64_t limit = 10'000;
};

inline constexpr std::uint64_t max_due_limit = 100'000;
/// A grace of at most 366 days, as a request's deadline.
inline constexpr std::uint64_t max_due_grace = 31'622'400;

/// Parses the due route's query: at, grace, keeper, contract, instance,
/// start, and limit; anything else is refused.
[[nodiscard]] std::variant<DueQuery, QueryError> parse_due_query(const http::Request& r);

} // namespace cexchain::node::detail
