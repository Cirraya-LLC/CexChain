// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <charconv>
#include <chrono>
#include <cstdio>
#include <format>

#include <cexchain/core/bytes.hpp>
#include <cexchain/search/query.hpp>

namespace cexchain::search {

namespace {

std::optional<std::int64_t> integer(std::string_view text) {
    std::int64_t value = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || ec != std::errc{} || ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

std::optional<Id> id(std::string_view hex) {
    if (hex.size() != 64) {
        return std::nullopt;
    }
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto parsed = protocol::to_id(*bytes);
    return parsed ? std::optional<Id>(*parsed) : std::nullopt;
}

std::string iso(Timestamp ms) {
    using namespace std::chrono;
    const sys_time<milliseconds> time{milliseconds{static_cast<std::int64_t>(ms)}};
    return std::format("{:%Y-%m-%dT%H:%M:%S}Z", time);
}

nlohmann::json id_json(const std::optional<Id>& value) {
    return value ? nlohmann::json(to_hex(value->bytes())) : nlohmann::json();
}

/// Parameters the page takes; true if `name` was one.
std::optional<std::string> page_param(PageRequest& page, std::string_view name,
                                      std::string_view value, bool& taken) {
    taken = true;
    if (name == "limit") {
        const auto n = integer(value);
        if (!n || *n < 1 || static_cast<std::uint64_t>(*n) > max_page) {
            return "limit is 1 to 1,000";
        }
        page.limit = static_cast<std::size_t>(*n);
    } else if (name == "cursor") {
        page.cursor = std::string(value);
    } else if (name == "order") {
        if (value != "new" && value != "old") {
            return "order is new or old";
        }
        page.oldest_first = value == "old";
    } else {
        taken = false;
    }
    return std::nullopt;
}

/// `meta.KEY`, `meta.KEY.min`, `meta.KEY.max` (or field.): the key and
/// which.
struct Keyed {
    std::string key;
    enum class Part : std::uint8_t { equals, min, max } part = Part::equals;
};

std::optional<Keyed> keyed(std::string_view name, std::string_view prefix) {
    if (!name.starts_with(prefix) || name.size() == prefix.size()) {
        return std::nullopt;
    }
    std::string_view key = name.substr(prefix.size());
    Keyed out;
    if (key.ends_with(".min")) {
        out.part = Keyed::Part::min;
        key.remove_suffix(4);
    } else if (key.ends_with(".max")) {
        out.part = Keyed::Part::max;
        key.remove_suffix(4);
    }
    if (key.empty()) {
        return std::nullopt;
    }
    out.key = std::string(key);
    return out;
}

std::optional<std::string> record_param(RecordFilter& f, std::string_view name,
                                        std::string_view value, bool& taken) {
    taken = true;
    if (name == "type") {
        f.type = std::string(value);
    } else if (name == "state") {
        f.state = std::string(value);
    } else if (name == "registrant") {
        f.registrant = id(value);
        if (!f.registrant) {
            return "registrant is an actor's id, 64 hex digits";
        }
    } else if (name == "since" || name == "until") {
        const auto t = parse_time(value);
        if (!t) {
            return std::string(name) + " is milliseconds since 1970 or YYYY-MM-DD[THH:MM:SSZ]";
        }
        (name == "since" ? f.since : f.until) = *t;
    } else if (name == "current") {
        if (value != "1" && value != "0" && value != "true" && value != "false") {
            return "current is 1 or 0";
        }
        f.current = value == "1" || value == "true";
    } else if (name == "revoked") {
        if (value == "no") {
            f.revoked = RecordFilter::Revoked::no;
        } else if (value == "yes") {
            f.revoked = RecordFilter::Revoked::yes;
        } else if (value == "any") {
            f.revoked = RecordFilter::Revoked::any;
        } else {
            return "revoked is no, yes, or any";
        }
    } else if (name == "q") {
        // Words, not control characters (a NUL would end the full-text
        // query early).
        if (std::ranges::any_of(value,
                                [](char c) { return static_cast<unsigned char>(c) < 0x20; })) {
            return "q is text without control characters";
        }
        f.text = std::string(value);
    } else if (const auto k = keyed(name, "meta.")) {
        auto it = std::ranges::find(f.metadata, k->key, &RecordFilter::Metadata::key);
        if (it == f.metadata.end()) {
            RecordFilter::Metadata m;
            m.key = k->key;
            f.metadata.push_back(std::move(m));
            it = std::prev(f.metadata.end());
        }
        if (k->part == Keyed::Part::equals) {
            it->equals = std::string(value);
        } else {
            const auto n = integer(value);
            if (!n) {
                return std::string(name) + " is a whole number";
            }
            (k->part == Keyed::Part::min ? it->at_least : it->at_most) = *n;
        }
    } else {
        taken = false;
    }
    return std::nullopt;
}

std::optional<std::string> instance_param(InstanceFilter& f, std::string_view name,
                                          std::string_view value, bool& taken) {
    taken = true;
    if (name == "contract") {
        f.contract = id(value);
        if (!f.contract) {
            return "contract is a contract's id, 64 hex digits";
        }
    } else if (name == "contract_name") {
        f.contract_name = std::string(value);
    } else if (name == "status") {
        f.status = std::string(value);
    } else if (name == "final") {
        if (value != "1" && value != "0" && value != "true" && value != "false") {
            return "final is 1 or 0";
        }
        f.final = value == "1" || value == "true";
    } else if (name == "party") {
        f.party = id(value);
        if (!f.party) {
            return "party is a ledger's id, 64 hex digits";
        }
    } else if (name == "since" || name == "until" || name == "changed_since") {
        const auto t = parse_time(value);
        if (!t) {
            return std::string(name) + " is milliseconds since 1970 or YYYY-MM-DD[THH:MM:SSZ]";
        }
        (name == "since" ? f.since : name == "until" ? f.until : f.changed_since) = *t;
    } else if (name == "reference") {
        f.reference = std::string(value);
    } else if (const auto k = keyed(name, "field.")) {
        auto it = std::ranges::find(f.fields, k->key, &InstanceFilter::Field::name);
        if (it == f.fields.end()) {
            InstanceFilter::Field field;
            field.name = k->key;
            f.fields.push_back(std::move(field));
            it = std::prev(f.fields.end());
        }
        if (k->part == Keyed::Part::equals) {
            it->equals = std::string(value);
        } else {
            const auto n = integer(value);
            if (!n) {
                return std::string(name) + " is a whole number";
            }
            (k->part == Keyed::Part::min ? it->at_least : it->at_most) = *n;
        }
    } else {
        taken = false;
    }
    return std::nullopt;
}

std::optional<std::string> report_param(ReportRequest& r, std::string_view name,
                                        std::string_view value, bool instances, bool& taken) {
    taken = true;
    if (name == "by") {
        r.by.clear();
        std::string_view rest = value;
        while (!rest.empty()) {
            const std::size_t comma = std::min(rest.find(','), rest.size());
            const auto g = group_from(rest.substr(0, comma));
            const bool fits = g && (instances ? *g != Group::type && *g != Group::registrant
                                              : *g != Group::contract);
            if (!fits) {
                return instances ? "by names contract, state, day, week, or month"
                                 : "by names type, state, registrant, day, week, or month";
            }
            r.by.push_back(*g);
            rest.remove_prefix(std::min(comma + 1, rest.size()));
        }
    } else if (name == "utc_offset") {
        const auto offset = parse_utc_offset(value);
        if (!offset) {
            return "utc_offset is like +08:00, at most 14 hours";
        }
        r.utc_offset_minutes = *offset;
    } else if (name == "sum" && instances) {
        r.sum = std::string(value);
    } else {
        taken = false;
    }
    return std::nullopt;
}

std::string unknown(std::string_view name) {
    return "unknown parameter " + std::string(name);
}

} // namespace

std::optional<Timestamp> parse_time(std::string_view text) {
    if (const auto ms = integer(text)) {
        return *ms < 0 ? std::nullopt : std::optional(static_cast<Timestamp>(*ms));
    }
    int y = 0;
    unsigned mo = 0;
    unsigned d = 0;
    unsigned h = 0;
    unsigned mi = 0;
    unsigned s = 0;
    char z = 0;
    const std::string str(text);
    const int fields =
        std::sscanf(str.c_str(), "%4d-%2u-%2uT%2u:%2u:%2u%c", &y, &mo, &d, &h, &mi, &s, &z);
    const bool date_only = fields == 3 && str.size() == 10;
    if (!date_only && !(fields == 7 && z == 'Z' && str.size() == 20)) {
        return std::nullopt;
    }
    using namespace std::chrono;
    const year_month_day date{year{y}, month{mo}, day{d}};
    if (!date.ok() || h > 23 || mi > 59 || s > 59 || y < 1970) {
        return std::nullopt;
    }
    const auto time = sys_days{date} + hours{h} + minutes{mi} + seconds{s};
    return static_cast<Timestamp>(duration_cast<milliseconds>(time.time_since_epoch()).count());
}

std::optional<std::int32_t> parse_utc_offset(std::string_view text) {
    std::int32_t minutes = 0;
    if (const auto n = integer(text)) {
        if (*n < -14 * 60 || *n > 14 * 60) {
            return std::nullopt;
        }
        minutes = static_cast<std::int32_t>(*n);
    } else {
        if (text.size() != 6 || (text[0] != '+' && text[0] != '-') || text[3] != ':') {
            return std::nullopt;
        }
        const auto h = integer(text.substr(1, 2));
        const auto m = integer(text.substr(4, 2));
        if (!h || !m || *h > 14 || *m > 59 || (*h == 14 && *m > 0)) {
            return std::nullopt;
        }
        minutes = static_cast<std::int32_t>(*h * 60 + *m) * (text[0] == '-' ? -1 : 1);
    }
    return minutes;
}

std::variant<RecordSearch, std::string> parse_record_search(const Params& params) {
    RecordSearch out;
    for (const auto& [name, value] : params) {
        bool taken = false;
        if (auto problem = page_param(out.page, name, value, taken)) {
            return *problem;
        }
        if (!taken) {
            if (auto problem = record_param(out.filter, name, value, taken)) {
                return *problem;
            }
        }
        if (!taken) {
            return unknown(name);
        }
    }
    return out;
}

std::variant<InstanceSearch, std::string> parse_instance_search(const Params& params) {
    InstanceSearch out;
    for (const auto& [name, value] : params) {
        bool taken = false;
        if (auto problem = page_param(out.page, name, value, taken)) {
            return *problem;
        }
        if (!taken) {
            if (auto problem = instance_param(out.filter, name, value, taken)) {
                return *problem;
            }
        }
        if (!taken) {
            return unknown(name);
        }
    }
    return out;
}

std::variant<RecordReport, std::string> parse_record_report(const Params& params) {
    RecordReport out;
    for (const auto& [name, value] : params) {
        bool taken = false;
        if (auto problem = report_param(out.report, name, value, false, taken)) {
            return *problem;
        }
        if (!taken) {
            if (auto problem = record_param(out.filter, name, value, taken)) {
                return *problem;
            }
        }
        if (!taken) {
            return unknown(name);
        }
    }
    return out;
}

std::variant<InstanceReport, std::string> parse_instance_report(const Params& params) {
    InstanceReport out;
    for (const auto& [name, value] : params) {
        bool taken = false;
        if (auto problem = report_param(out.report, name, value, true, taken)) {
            return *problem;
        }
        if (!taken) {
            if (auto problem = instance_param(out.filter, name, value, taken)) {
                return *problem;
            }
        }
        if (!taken) {
            return unknown(name);
        }
    }
    return out;
}

nlohmann::json to_json(const RecordRow& r) {
    nlohmann::json metadata = nlohmann::json::object();
    for (const auto& [key, value] : r.metadata) {
        metadata[key] = value;
    }
    return {{"id", to_hex(r.id.bytes())},
            {"type", r.type},
            {"state", r.state},
            {"revoked", r.revoked},
            {"registrant", to_hex(r.registrant.bytes())},
            {"registered_index", r.registered_index},
            {"registered_at", iso(r.registered_at)},
            {"supersedes", id_json(r.supersedes)},
            {"superseded_by", id_json(r.superseded_by)},
            {"endorsements", r.endorsements},
            {"last_index", r.last_index},
            {"last_at", iso(r.last_at)},
            {"metadata", std::move(metadata)}};
}

nlohmann::json to_json(const InstanceRow& r) {
    nlohmann::json parties = nlohmann::json::object();
    for (const auto& [role, ledger] : r.parties) {
        parties[role] = to_hex(ledger.bytes());
    }
    nlohmann::json fields = nlohmann::json::object();
    for (const auto& [name, value] : r.fields) {
        fields[name] = value;
    }
    return {
        {"id", to_hex(r.id.bytes())},
        {"contract", to_hex(r.contract.bytes())},
        {"contract_name", r.contract_name ? nlohmann::json(*r.contract_name) : nlohmann::json()},
        {"status", r.status ? nlohmann::json(*r.status) : nlohmann::json()},
        {"final", r.final},
        {"created_index", r.created_index},
        {"created_at", iso(r.created_at)},
        {"last_index", r.last_index},
        {"last_at", iso(r.last_at)},
        {"calls", r.calls},
        {"open_requests", r.open_requests},
        {"parent", id_json(r.parent)},
        {"reference", r.reference ? nlohmann::json(*r.reference) : nlohmann::json()},
        {"parties", std::move(parties)},
        {"fields", std::move(fields)}};
}

nlohmann::json to_json(const Page<RecordRow>& page) {
    nlohmann::json rows = nlohmann::json::array();
    for (const RecordRow& r : page.rows) {
        rows.push_back(to_json(r));
    }
    return {{"records", std::move(rows)},
            {"next", page.next ? nlohmann::json(*page.next) : nlohmann::json()},
            {"as_of", page.as_of}};
}

nlohmann::json to_json(const Page<InstanceRow>& page) {
    nlohmann::json rows = nlohmann::json::array();
    for (const InstanceRow& r : page.rows) {
        rows.push_back(to_json(r));
    }
    return {{"instances", std::move(rows)},
            {"next", page.next ? nlohmann::json(*page.next) : nlohmann::json()},
            {"as_of", page.as_of}};
}

nlohmann::json to_json(const Report& report) {
    nlohmann::json by = nlohmann::json::array();
    for (const Group g : report.by) {
        by.push_back(std::string(name(g)));
    }
    nlohmann::json groups = nlohmann::json::array();
    for (const ReportRow& r : report.rows) {
        nlohmann::json key = nlohmann::json::object();
        for (std::size_t n = 0; n < r.key.size() && n < report.by.size(); ++n) {
            key[std::string(name(report.by[n]))] = r.key[n];
        }
        nlohmann::json g{{"key", std::move(key)}, {"count", r.count}};
        if (r.sum) {
            g["sum"] = *r.sum;
            g["min"] = *r.min;
            g["max"] = *r.max;
        }
        groups.push_back(std::move(g));
    }
    return {{"by", std::move(by)},
            {"groups", std::move(groups)},
            {"truncated", report.truncated},
            {"as_of", report.as_of}};
}

std::string to_csv(const Report& report) {
    auto quoted = [](std::string_view text) {
        if (text.find_first_of(",\"\r\n") == std::string_view::npos) {
            return std::string(text);
        }
        std::string out = "\"";
        for (const char c : text) {
            out += c;
            if (c == '"') {
                out += '"';
            }
        }
        return out + "\"";
    };
    const bool summed =
        std::ranges::any_of(report.rows, [](const ReportRow& r) { return r.sum.has_value(); });
    std::string out;
    for (const Group g : report.by) {
        out += std::string(name(g)) + ",";
    }
    out += summed ? "count,sum,min,max\r\n" : "count\r\n";
    for (const ReportRow& r : report.rows) {
        for (const std::string& k : r.key) {
            out += quoted(k) + ",";
        }
        out += std::to_string(r.count);
        if (summed) {
            out += "," + (r.sum ? std::to_string(*r.sum) : "") + "," +
                   (r.min ? std::to_string(*r.min) : "") + "," +
                   (r.max ? std::to_string(*r.max) : "");
        }
        out += "\r\n";
    }
    return out;
}

nlohmann::json to_json(const IndexStatus& s) {
    return {
        {"file", s.file.string()},  {"indexed", s.indexed},
        {"log_size", s.log_size},   {"behind", s.log_size > s.indexed ? s.log_size - s.indexed : 0},
        {"records", s.records},     {"instances", s.instances},
        {"contracts", s.contracts}, {"bytes", s.bytes}};
}

} // namespace cexchain::search
