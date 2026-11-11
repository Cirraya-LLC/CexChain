// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <memory>

#include <kanhe/node/api.hpp>
#include <kanhe/search/index.hpp>

/// The index served beside a ledger: an extension of a ledger server
/// (node::ApiOptions::Extension) that opens the index once the server has
/// opened its ledger, follows the log on a thread of its own, and answers
/// the search routes after the server's checks for a read:
///
///     GET /v1/records, /v1/instances (pages; search::parse_record_search)
///     GET /v1/reports/records, /v1/reports/instances
///     GET /v1/records/{id}, /v1/records/{id}/versions
///
/// Every answer is a hint from what the ledger holds in the clear, never
/// evidence, and names the log size it reflects (`as_of`); a query first
/// catches the index up for at most two seconds, so that a writer reads
/// what it wrote.
namespace kanhe::search {

class Served {
public:
    /// The index at `file`; by default (empty) Index::file_for the ledger's
    /// directory, given when the server opens it.
    explicit Served(std::filesystem::path file = {});
    ~Served();
    Served(const Served&) = delete;
    Served& operator=(const Served&) = delete;

    /// The extension to give the server (once). It holds this object's
    /// state, so it may outlive this object.
    [[nodiscard]] node::ApiOptions::Extension extension(std::filesystem::path ledger_directory);
    /// The index, once the server has opened its ledger; null before, or if
    /// it could not be opened (the routes then answer 503). Safe from any
    /// thread.
    [[nodiscard]] Index* index() const noexcept;

    struct State;

private:
    std::shared_ptr<State> state_;
};

} // namespace kanhe::search
