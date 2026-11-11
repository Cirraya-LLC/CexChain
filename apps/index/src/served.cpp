// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/node/responses.hpp>
#include <kanhe/search/query.hpp>
#include <kanhe/search/served.hpp>

namespace kanhe::search {

namespace {

using json = nlohmann::json;
using node::error_response;
using node::json_response;
namespace http = node::http;

std::optional<protocol::Id> id_from(std::string_view text) {
    if (text.size() != 64) {
        return std::nullopt;
    }
    const auto bytes = from_hex(text);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

} // namespace

struct Served::State {
    std::filesystem::path file;
    const ledger::Ledger* ledger = nullptr;
    std::unique_ptr<Index> index;
    std::atomic<Index*> ready = nullptr;
    std::thread follower;
    std::mutex mutex;
    std::condition_variable wake;
    bool stopping = false;

    ~State() { stop(); }

    void open(const ledger::Ledger& opened, const std::filesystem::path& directory) {
        ledger = &opened;
        auto made = Index::open(opened, file.empty() ? Index::file_for(directory) : file);
        if (!made) {
            return; // derived data: the server serves everything but searches
        }
        index = std::move(*made);
        ready = index.get();
        follower = std::thread([this] { follow(); });
    }

    /// What the writer committed goes into the index within a second; a
    /// long catch-up (a new index of a large ledger) goes on a second at a
    /// time, so that queries get their turn.
    void follow() {
        for (;;) {
            {
                std::unique_lock lock(mutex);
                wake.wait_for(lock, std::chrono::milliseconds(500), [&] { return stopping; });
                if (stopping) {
                    return;
                }
            }
            if (index->as_of() < ledger->size()) {
                static_cast<void>(index->update(std::chrono::seconds(1)));
            }
        }
    }

    void stop() {
        {
            const std::lock_guard lock(mutex);
            stopping = true;
        }
        wake.notify_all();
        if (follower.joinable()) {
            follower.join();
        }
    }

    std::optional<http::Response> read(const http::Request& r) const {
        const std::string_view path = r.path;
        constexpr std::string_view records = "/v1/records/";
        const bool listing = path == "/v1/records" || path == "/v1/instances" ||
                             path == "/v1/reports/records" || path == "/v1/reports/instances";
        if (!listing && !path.starts_with(records)) {
            return std::nullopt;
        }
        Index* served = ready.load();
        if (served == nullptr) {
            return error_response(503, "unavailable", "this server has no search index");
        }
        // Read your own writes: catch up first, for at most two seconds.
        if (served->as_of() < ledger->size()) {
            static_cast<void>(served->update(std::chrono::seconds(2)));
        }
        const Params params(r.query.begin(), r.query.end());
        const auto bad = [](const std::string& problem) {
            return json_response(400,
                                 {{"error", {{"code", "invalid_argument"}, {"message", problem}}}});
        };
        const auto answer = [](const auto& result) {
            return result ? json_response(200, to_json(*result)) : error_response(result.error());
        };
        if (path == "/v1/records") {
            const auto q = parse_record_search(params);
            if (const auto* problem = std::get_if<std::string>(&q)) {
                return bad(*problem);
            }
            const auto& s = std::get<RecordSearch>(q);
            return answer(served->records(s.filter, s.page));
        }
        if (path == "/v1/instances") {
            const auto q = parse_instance_search(params);
            if (const auto* problem = std::get_if<std::string>(&q)) {
                return bad(*problem);
            }
            const auto& s = std::get<InstanceSearch>(q);
            return answer(served->instances(s.filter, s.page));
        }
        if (path == "/v1/reports/records") {
            const auto q = parse_record_report(params);
            if (const auto* problem = std::get_if<std::string>(&q)) {
                return bad(*problem);
            }
            const auto& s = std::get<RecordReport>(q);
            return answer(served->report(s.filter, s.report));
        }
        if (path == "/v1/reports/instances") {
            const auto q = parse_instance_report(params);
            if (const auto* problem = std::get_if<std::string>(&q)) {
                return bad(*problem);
            }
            const auto& s = std::get<InstanceReport>(q);
            return answer(served->report(s.filter, s.report));
        }
        // One record, or its versions: the chain from the state, each
        // version's row from the index.
        std::string_view rest = path.substr(records.size());
        const bool all_versions = rest.ends_with("/versions");
        if (all_versions) {
            rest.remove_suffix(std::string_view("/versions").size());
        }
        const auto id = id_from(rest);
        if (!id || !params.empty()) {
            return error_response(400, "invalid_argument", "a record id is 64 hex digits");
        }
        std::vector<protocol::Id> versions;
        ledger->read_state(
            [&](const protocol::LedgerState& s) { versions = protocol::record_versions(s, *id); });
        if (versions.empty()) {
            return error_response(404, "not_found", "no such record");
        }
        json rows = json::array();
        for (const protocol::Id& v : all_versions ? versions : std::vector<protocol::Id>{*id}) {
            const auto row = served->record(v);
            if (!row) {
                return error_response(row.error());
            }
            if (!*row) {
                return error_response(503, "unavailable",
                                      "the search index has not reached this record yet");
            }
            rows.push_back(to_json(**row));
        }
        if (!all_versions) {
            return json_response(200, {{"record", rows[0]},
                                       {"latest", to_hex(versions.back().bytes())},
                                       {"versions", versions.size()},
                                       {"as_of", served->as_of()}});
        }
        return json_response(200, {{"versions", std::move(rows)}, {"as_of", served->as_of()}});
    }
};

Served::Served(std::filesystem::path file) : state_(std::make_shared<State>()) {
    state_->file = std::move(file);
}

Served::~Served() {
    state_->stop();
}

node::ApiOptions::Extension Served::extension(std::filesystem::path ledger_directory) {
    node::ApiOptions::Extension e;
    e.opened = [state = state_,
                directory = std::move(ledger_directory)](const ledger::Ledger& ledger) {
        state->open(ledger, directory);
    };
    e.read = [state = state_](const http::Request& r) {
        return state->read(r);
    };
    e.read_paths = {"/v1/records", "/v1/instances", "/v1/reports/records", "/v1/reports/instances"};
    e.stopping = [state = state_] {
        state->stop();
    };
    return e;
}

Index* Served::index() const noexcept {
    return state_->ready.load();
}

} // namespace kanhe::search
