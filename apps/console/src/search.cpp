// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Searches and reports for the console's page: the node's search index, read
// with the HTTP API's query parameters (search/query.hpp), for anyone signed
// in. The index holds only what the ledger holds in the clear; a thing's page
// still decides who sees its private fields.

#include <chrono>
#include <string>
#include <variant>

#include <cexchain/console/console.hpp>
#include <cexchain/search/index.hpp>
#include <cexchain/search/query.hpp>

#include "responses.hpp"

namespace cexchain::console {

http::Response Console::search_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    search::Index* index = search_index();
    const ledger::Ledger* served = ledger();
    if (index == nullptr || served == nullptr) {
        return error(503, "unavailable", "this console's node keeps no search index");
    }
    // What was just registered here is found at once.
    if (index->as_of() < served->size()) {
        static_cast<void>(index->update(std::chrono::seconds(2)));
    }
    search::Params params;
    bool csv = false;
    for (const auto& [name, value] : request.query) {
        if (name == "format") {
            if (value != "csv" && value != "json") {
                return error(400, "invalid_argument", "format is csv or json");
            }
            csv = value == "csv";
            continue;
        }
        params.emplace_back(name, value);
    }
    auto refused = [](const std::string& problem) {
        return json(400, {{"error", {{"code", "invalid_argument"}, {"message", problem}}}});
    };
    auto report = [&](const Result<search::Report>& r, std::string_view of) {
        if (!r) {
            return error(400, "invalid_argument", r.error().detail);
        }
        if (csv) {
            const std::string text = search::to_csv(*r);
            return download(Bytes(text.begin(), text.end()), std::string(of) + "-report.csv",
                            "text/csv; charset=utf-8");
        }
        return json(200, search::to_json(*r));
    };
    const std::string_view path = request.path;
    if (path == "/console/api/search/records") {
        const auto q = search::parse_record_search(params);
        if (const auto* problem = std::get_if<std::string>(&q)) {
            return refused(*problem);
        }
        const auto& s = std::get<search::RecordSearch>(q);
        const auto page = index->records(s.filter, s.page);
        return page ? json(200, search::to_json(*page))
                    : error(400, "invalid_argument", page.error().detail);
    }
    if (path == "/console/api/search/instances") {
        const auto q = search::parse_instance_search(params);
        if (const auto* problem = std::get_if<std::string>(&q)) {
            return refused(*problem);
        }
        const auto& s = std::get<search::InstanceSearch>(q);
        const auto page = index->instances(s.filter, s.page);
        return page ? json(200, search::to_json(*page))
                    : error(400, "invalid_argument", page.error().detail);
    }
    if (path == "/console/api/reports/records") {
        const auto q = search::parse_record_report(params);
        if (const auto* problem = std::get_if<std::string>(&q)) {
            return refused(*problem);
        }
        const auto& s = std::get<search::RecordReport>(q);
        return report(index->report(s.filter, s.report), "records");
    }
    const auto q = search::parse_instance_report(params);
    if (const auto* problem = std::get_if<std::string>(&q)) {
        return refused(*problem);
    }
    const auto& s = std::get<search::InstanceReport>(q);
    return report(index->report(s.filter, s.report), "things");
}

} // namespace cexchain::console
