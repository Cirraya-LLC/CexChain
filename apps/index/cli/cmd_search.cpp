// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Searches and reports over the ledger this session opened (a directory, or
// a server's verified mirror), from the search index kept beside it: what
// the ledger holds in the clear, never private field values. The options
// spell the HTTP API's query parameters (search/query.hpp), so a search reads
// the same everywhere.

#include <algorithm>
#include <cctype>
#include <memory>
#include <print>

#include <kanhe/search/index.hpp>
#include <kanhe/search/query.hpp>
#include <kanhe/search/served.hpp>

#include "index_commands.hpp"
#include "output.hpp"
#include "serve.hpp"

namespace kanhe::cli {

namespace {

/// The index beside the session's ledger, caught up with its log.
std::unique_ptr<search::Index> open_index(Session& session) {
    auto index =
        unwrap(search::Index::open(session.ledger(), search::Index::file_for(session.directory())),
               "opening the search index");
    unwrap(index->update(), "updating the search index");
    return index;
}

/// `NAME=VALUE` options as name and value.
std::pair<std::string, std::string> pair_of(const std::string& item, std::string_view option) {
    return split_pair(item, std::string("--") + std::string(option));
}

/// The filters both searches and reports take, as query parameters.
search::Params record_params(Session& session, const Args& args) {
    search::Params p;
    for (const char* name : {"type", "state", "since", "until"}) {
        if (const auto v = args.get(name)) {
            p.emplace_back(name, *v);
        }
    }
    if (const auto v = args.get("registrant")) {
        p.emplace_back("registrant", hex_id(session.actor_id(*v)));
    }
    if (args.has("current")) {
        p.emplace_back("current", "1");
    }
    if (const auto v = args.get("revoked")) {
        p.emplace_back("revoked", *v);
    }
    if (const auto v = args.get("text")) {
        p.emplace_back("q", *v);
    }
    for (const std::string& item : args.all("meta")) {
        const auto [k, v] = pair_of(item, "meta");
        p.emplace_back("meta." + k, v);
    }
    for (const char* bound : {"min", "max"}) {
        for (const std::string& item : args.all(std::string("meta-") + bound)) {
            const auto [k, v] = pair_of(item, std::string("meta-") + bound);
            p.emplace_back("meta." + k + "." + bound, v);
        }
    }
    return p;
}

search::Params instance_params(Session& session, const Args& args) {
    search::Params p;
    if (const auto v = args.get("contract")) {
        p.emplace_back("contract", hex_id(session.contract_id(*v)));
    }
    if (const auto v = args.get("contract-name")) {
        p.emplace_back("contract_name", *v);
    }
    if (const auto v = args.get("status")) {
        p.emplace_back("status", *v);
    }
    if (const auto v = args.get("final")) {
        if (*v != "yes" && *v != "no") {
            throw UsageError{"--final is yes or no"};
        }
        p.emplace_back("final", *v == "yes" ? "1" : "0");
    }
    if (const auto v = args.get("party")) {
        p.emplace_back("party", *v);
    }
    for (const char* name : {"since", "until", "reference"}) {
        if (const auto v = args.get(name)) {
            p.emplace_back(name, *v);
        }
    }
    if (const auto v = args.get("changed-since")) {
        p.emplace_back("changed_since", *v);
    }
    for (const std::string& item : args.all("field")) {
        const auto [k, v] = pair_of(item, "field");
        p.emplace_back("field." + k, v);
    }
    for (const char* bound : {"min", "max"}) {
        for (const std::string& item : args.all(std::string("field-") + bound)) {
            const auto [k, v] = pair_of(item, std::string("field-") + bound);
            p.emplace_back("field." + k + "." + bound, v);
        }
    }
    return p;
}

void page_params(const Args& args, search::Params& p) {
    if (const auto v = args.get("limit")) {
        p.emplace_back("limit", *v);
    }
    if (const auto v = args.get("cursor")) {
        p.emplace_back("cursor", *v);
    }
    if (args.has("oldest")) {
        p.emplace_back("order", "old");
    }
}

void report_params(const Args& args, search::Params& p) {
    p.emplace_back("by", args.get("by").value_or(""));
    if (const auto v = args.get("utc-offset")) {
        p.emplace_back("utc_offset", *v);
    }
    if (const auto v = args.get("sum")) {
        p.emplace_back("sum", *v);
    }
}

template <typename Parsed>
Parsed parsed(std::variant<Parsed, std::string> result) {
    if (auto* problem = std::get_if<std::string>(&result)) {
        throw UsageError{*problem};
    }
    return std::get<Parsed>(std::move(result));
}

std::string summary(const std::vector<std::pair<std::string, std::string>>& items) {
    std::string out;
    for (const auto& [k, v] : items) {
        out += (out.empty() ? "" : ", ") + k + "=" + v;
    }
    return out.size() > 60 ? out.substr(0, 57) + "..." : out;
}

void print_more(const std::optional<std::string>& next, std::uint64_t as_of) {
    if (next) {
        std::println("(more: --cursor {})", *next);
    }
    std::println("(as of log entry {})", as_of);
}

void print_report(const search::Report& report, const Args& args) {
    if (args.has("csv")) {
        std::print("{}", search::to_csv(report));
        return;
    }
    if (args.json()) {
        print_json(search::to_json(report));
        return;
    }
    // Columns as wide as their widest value; ids shortened as elsewhere.
    auto shown = [](const std::string& key) {
        const bool id = key.size() == 64 && std::ranges::all_of(key, [](char c) {
                            return std::isxdigit(static_cast<unsigned char>(c)) != 0;
                        });
        return id ? key.substr(0, 12) : key;
    };
    std::vector<std::size_t> widths;
    for (const search::Group g : report.by) {
        widths.push_back(search::name(g).size());
    }
    for (const search::ReportRow& r : report.rows) {
        for (std::size_t n = 0; n < r.key.size() && n < widths.size(); ++n) {
            widths[n] = std::max(widths[n], shown(r.key[n]).size());
        }
    }
    const bool summed = std::ranges::any_of(
        report.rows, [](const search::ReportRow& r) { return r.sum.has_value(); });
    std::string head;
    for (std::size_t n = 0; n < report.by.size(); ++n) {
        head += std::format("{:<{}}  ", std::string(search::name(report.by[n])), widths[n]);
    }
    std::println("{}{:>8}{}", head, "count",
                 summed ? std::format("{:>14}{:>12}{:>12}", "sum", "min", "max") : "");
    for (const search::ReportRow& r : report.rows) {
        std::string line;
        for (std::size_t n = 0; n < r.key.size() && n < widths.size(); ++n) {
            line += std::format("{:<{}}  ", shown(r.key[n]), widths[n]);
        }
        std::string sums;
        if (summed) {
            sums = r.sum ? std::format("{:>14}{:>12}{:>12}", *r.sum, *r.min, *r.max)
                         : std::format("{:>14}{:>12}{:>12}", "-", "-", "-");
        }
        std::println("{}{:>8}{}", line, r.count, sums);
    }
    if (report.truncated) {
        std::println("(only the first {} groups)", search::max_groups);
    }
    std::println("(as of log entry {})", report.as_of);
}

} // namespace

int cmd_search_records(const Args& args) {
    Session session(args);
    search::Params params = record_params(session, args);
    page_params(args, params);
    const auto q = parsed(search::parse_record_search(params));
    const auto index = open_index(session);
    const auto page = unwrap(index->records(q.filter, q.page), "searching");
    if (args.json()) {
        print_json(search::to_json(page));
        return exit_ok;
    }
    for (const search::RecordRow& r : page.rows) {
        std::println("{}  {:<28} {:<12} {}  {}{}{}", short_id(r.id), r.type, r.state,
                     format_time(r.registered_at), summary(r.metadata),
                     r.superseded_by ? "  [superseded]" : "", r.revoked ? "  [revoked]" : "");
    }
    print_more(page.next, page.as_of);
    return exit_ok;
}

int cmd_search_instances(const Args& args) {
    Session session(args);
    search::Params params = instance_params(session, args);
    page_params(args, params);
    const auto q = parsed(search::parse_instance_search(params));
    const auto index = open_index(session);
    const auto page = unwrap(index->instances(q.filter, q.page), "searching");
    if (args.json()) {
        print_json(search::to_json(page));
        return exit_ok;
    }
    for (const search::InstanceRow& r : page.rows) {
        std::println("{}  {:<22} {:<16} {}  {}{}", short_id(r.id),
                     r.contract_name.value_or(short_id(r.contract)), r.status.value_or("-"),
                     format_time(r.created_at), summary(r.fields), r.final ? "  [final]" : "");
    }
    print_more(page.next, page.as_of);
    return exit_ok;
}

int cmd_report_records(const Args& args) {
    Session session(args);
    search::Params params = record_params(session, args);
    report_params(args, params);
    const auto q = parsed(search::parse_record_report(params));
    const auto index = open_index(session);
    print_report(unwrap(index->report(q.filter, q.report), "reporting"), args);
    return exit_ok;
}

int cmd_report_instances(const Args& args) {
    Session session(args);
    search::Params params = instance_params(session, args);
    report_params(args, params);
    const auto q = parsed(search::parse_instance_report(params));
    const auto index = open_index(session);
    print_report(unwrap(index->report(q.filter, q.report), "reporting"), args);
    return exit_ok;
}

int cmd_index_status(const Args& args) {
    Session session(args);
    auto index =
        unwrap(search::Index::open(session.ledger(), search::Index::file_for(session.directory())),
               "opening the search index");
    if (args.has("update")) {
        unwrap(index->update(), "updating the search index");
    }
    const auto status = unwrap(index->status(), "reading the search index");
    if (args.json()) {
        print_json(search::to_json(status));
        return exit_ok;
    }
    std::println("index:      {}", status.file.string());
    std::println("indexed:    {} of {} log entries{}", status.indexed, status.log_size,
                 status.indexed < status.log_size ? " (searches catch up first)" : "");
    std::println("records:    {}", status.records);
    std::println("instances:  {}", status.instances);
    std::println("contracts:  {}", status.contracts);
    std::println("size:       {} bytes", status.bytes);
    return exit_ok;
}

int cmd_index_rebuild(const Args& args) {
    Session session(args);
    auto index =
        unwrap(search::Index::open(session.ledger(), search::Index::file_for(session.directory())),
               "opening the search index");
    unwrap(index->clear(), "emptying the search index");
    const std::uint64_t reached = unwrap(index->update(), "rebuilding the search index");
    const auto status = unwrap(index->status(), "reading the search index");
    if (args.json()) {
        print_json(search::to_json(status));
        return exit_ok;
    }
    std::println("rebuilt the search index from {} log entries: {} records, {} instances", reached,
                 status.records, status.instances);
    return exit_ok;
}

int cmd_index_serve(const Args& args) {
    // A read-only server of the ledger in the directory, with the index
    // beside it: next to a primary that writes the same directory (it
    // catches up with what the primary wrote before each read), or on a
    // replica that replica sync --follow keeps.
    ServeDefaults defaults;
    defaults.listen = "127.0.0.1:8090";
    auto served = std::make_shared<search::Served>();
    defaults.before_open = [served, dir = args.ledger()](node::ApiOptions& options) {
        options.read_only = true;
        options.extensions.push_back(served->extension(dir));
    };
    defaults.on_address = [](std::uint16_t) {
        return std::pair<std::string, std::string>("index",
                                                   "/v1/records, /v1/instances, /v1/reports");
    };
    return serve(args, defaults);
}

} // namespace kanhe::cli
