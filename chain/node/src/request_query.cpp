// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "request_query.hpp"

#include <algorithm>
#include <charconv>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/statement.hpp>

namespace cexchain::node::detail {

namespace {

std::optional<std::uint64_t> number(std::string_view text) {
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size() || text.empty()) {
        return std::nullopt;
    }
    return value;
}

std::optional<protocol::Id> id(std::string_view hex) {
    if (hex.size() != 64) {
        return std::nullopt;
    }
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto parsed = protocol::to_id(*bytes);
    return parsed ? std::optional<protocol::Id>(*parsed) : std::nullopt;
}

} // namespace

std::variant<RequestQuery, QueryError> parse_request_query(const http::Request& r) {
    RequestQuery q;
    for (const auto& [name, value] : r.query) {
        if (name == "state") {
            if (value == "open") {
                q.which = RequestQuery::Which::open;
            } else if (value == "answered") {
                q.which = RequestQuery::Which::answered;
            } else if (value == "all") {
                q.which = RequestQuery::Which::all;
            } else {
                return QueryError{"state is open, answered, or all"};
            }
        } else if (name == "kind") {
            std::string_view rest = value;
            while (true) {
                const std::size_t comma = std::min(rest.find(','), rest.size());
                const std::string_view kind = rest.substr(0, comma);
                if (!protocol::is_request_kind(kind)) {
                    return QueryError{"kind is one or more request kinds, comma-separated"};
                }
                q.kinds.emplace_back(kind);
                if (comma == rest.size()) {
                    break;
                }
                rest.remove_prefix(comma + 1);
            }
        } else if (name == "contract" || name == "instance") {
            const auto parsed = id(value);
            if (!parsed) {
                return QueryError{"contract and instance are ids of 64 hex digits"};
            }
            (name == "contract" ? q.contract : q.instance) = *parsed;
        } else if (name == "after") {
            const auto after = number(value);
            if (!after) {
                return QueryError{"after is a number (the cursor of an earlier answer)"};
            }
            q.after = *after;
        } else if (name == "limit") {
            const auto limit = number(value);
            if (!limit || *limit == 0 || *limit > max_request_limit) {
                return QueryError{"limit is 1 to 1000"};
            }
            q.limit = *limit;
        } else if (name == "wait") {
            const auto wait = number(value);
            if (!wait || *wait > max_request_wait) {
                return QueryError{"wait is 0 to 25 seconds"};
            }
            q.wait = std::chrono::seconds(*wait);
        } else if (name == "executor") {
            const auto parsed = id(value);
            if (!parsed) {
                return QueryError{"executor is an actor id of 64 hex digits"};
            }
            q.executor = *parsed;
        } else if (name == "lease") {
            if (value.size() < 8 || value.size() > 64 || !std::ranges::all_of(value, [](char c) {
                    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') || c == '-' || c == '_';
                })) {
                return QueryError{"lease is 8 to 64 letters, digits, '-', or '_'"};
            }
            q.lease = value;
        } else if (name == "ttl") {
            const auto ttl = number(value);
            if (!ttl || *ttl < min_lease_ttl || *ttl > max_lease_ttl) {
                return QueryError{"ttl is 5 to 300 seconds"};
            }
            q.ttl = std::chrono::seconds(*ttl);
        } else {
            return QueryError{"the parameters are state, kind, contract, instance, after, limit, "
                              "wait, executor, lease, and ttl"};
        }
    }
    if (q.lease.has_value() != q.executor.has_value()) {
        return QueryError{"executor and lease go together"};
    }
    return q;
}

std::variant<DueQuery, QueryError> parse_due_query(const http::Request& r) {
    DueQuery q;
    for (const auto& [name, value] : r.query) {
        if (name == "at") {
            const auto at = number(value);
            if (!at) {
                return QueryError{"at is a time in milliseconds since the epoch"};
            }
            q.at = *at;
        } else if (name == "grace") {
            const auto grace = number(value);
            if (!grace || *grace > max_due_grace) {
                return QueryError{"grace is 0 to 31622400 seconds"};
            }
            q.grace = *grace;
        } else if (name == "keeper" || name == "contract" || name == "instance") {
            const auto parsed = id(value);
            if (!parsed) {
                return QueryError{"keeper, contract, and instance are ids of 64 hex digits"};
            }
            (name == "keeper" ? q.keeper : name == "contract" ? q.contract : q.instance) = *parsed;
        } else if (name == "start") {
            const auto start = number(value);
            if (!start) {
                return QueryError{"start is a number (the next of an earlier answer)"};
            }
            q.start = *start;
        } else if (name == "limit") {
            const auto limit = number(value);
            if (!limit || *limit == 0 || *limit > max_due_limit) {
                return QueryError{"limit is 1 to 100000 contract runs"};
            }
            q.limit = *limit;
        } else {
            return QueryError{
                "the parameters are at, grace, keeper, contract, instance, start, and limit"};
        }
    }
    return q;
}

} // namespace cexchain::node::detail
