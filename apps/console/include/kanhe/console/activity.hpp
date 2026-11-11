// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/core/protocol/common.hpp>

/// The console's activity log: one JSON line per change a person made in
/// the console or its command line (people, roles, approvals of people,
/// tokens, kinds, parties, settings, locking), with who made it and when, in
/// `<console>/activity.jsonl` (owner-only). It records the console's own
/// administration; what happens on the ledger is the ledger's.
namespace kanhe::console {

struct Activity {
    protocol::Timestamp at = 0;
    /// The console user, or "cli" for the command line.
    std::string user;
    /// What was done: "people.invite", "people.role", "tokens.create", ...
    std::string action;
    /// What it was done to, as JSON (names, roles, ids; never a secret).
    nlohmann::json detail = nlohmann::json::object();
};

/// The log is kept at most this large; the older half then goes to
/// `activity.1.jsonl`, replacing the one before.
inline constexpr std::size_t max_activity_log = 1024 * 1024;

/// Appends an entry; a failure to write is not the action's failure.
void record_activity(const std::filesystem::path& directory, const Activity& activity) noexcept;
/// The newest `limit` entries, newest first (lines that do not read are
/// skipped).
[[nodiscard]] std::vector<Activity> read_activity(const std::filesystem::path& directory,
                                                  std::size_t limit);
[[nodiscard]] nlohmann::json activity_json(const Activity& activity);

} // namespace kanhe::console
