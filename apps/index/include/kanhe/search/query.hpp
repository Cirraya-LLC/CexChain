// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/search/index.hpp>

/// Searches and reports as their callers spell them: the HTTP API's query
/// parameters (the command line, MCP, and the console build the same), and
/// the answers as JSON and CSV. One spelling, so every way in reads alike.
///
/// Records:   type, state, registrant (hex id), since, until (milliseconds
///            or YYYY-MM-DD[THH:MM:SSZ]), current=1, revoked=no|yes|any,
///            meta.KEY=VALUE, meta.KEY.min=N, meta.KEY.max=N, q=TEXT.
/// Instances: contract (hex id), contract_name, status, final=1|0, party
///            (hex id), since, until, changed_since, reference,
///            field.NAME=VALUE, field.NAME.min=N, field.NAME.max=N.
/// Pages:     limit (1 to 1,000; 100), cursor, order=new|old.
/// Reports:   by=GROUP,... (at most four), utc_offset=+08:00 (or minutes),
///            sum=FIELD (instances).
namespace kanhe::search {

using Params = std::vector<std::pair<std::string, std::string>>;

struct RecordSearch {
    RecordFilter filter;
    PageRequest page;
};
struct InstanceSearch {
    InstanceFilter filter;
    PageRequest page;
};
struct RecordReport {
    RecordFilter filter;
    ReportRequest report;
};
struct InstanceReport {
    InstanceFilter filter;
    ReportRequest report;
};

/// Each a query or why it is refused (a sentence, for a 400 or a usage
/// error). Unknown parameters are refused.
[[nodiscard]] std::variant<RecordSearch, std::string> parse_record_search(const Params& params);
[[nodiscard]] std::variant<InstanceSearch, std::string> parse_instance_search(const Params& params);
[[nodiscard]] std::variant<RecordReport, std::string> parse_record_report(const Params& params);
[[nodiscard]] std::variant<InstanceReport, std::string> parse_instance_report(const Params& params);

/// A time as milliseconds since the epoch, from milliseconds or an ISO date
/// (UTC).
[[nodiscard]] std::optional<Timestamp> parse_time(std::string_view text);
/// "+08:00", "-05:30", "0", or minutes ("480").
[[nodiscard]] std::optional<std::int32_t> parse_utc_offset(std::string_view text);

[[nodiscard]] nlohmann::json to_json(const RecordRow& row);
[[nodiscard]] nlohmann::json to_json(const InstanceRow& row);
/// {"records" | "instances": [...], "next": cursor or null, "as_of": N}.
[[nodiscard]] nlohmann::json to_json(const Page<RecordRow>& page);
[[nodiscard]] nlohmann::json to_json(const Page<InstanceRow>& page);
/// {"by": [...], "groups": [{"key": {GROUP: VALUE}, "count", "sum"?,
/// "min"?, "max"?}], "truncated", "as_of"}.
[[nodiscard]] nlohmann::json to_json(const Report& report);
/// A header line (the groups, then count, and sum, min, max when summed),
/// then a line a group; RFC 4180 quoting.
[[nodiscard]] std::string to_csv(const Report& report);
[[nodiscard]] nlohmann::json to_json(const IndexStatus& status);

} // namespace kanhe::search
