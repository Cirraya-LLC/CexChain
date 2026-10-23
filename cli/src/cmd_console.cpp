// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's commands (the console itself runs in `serve --console`).

#include <exception>
#include <filesystem>
#include <format>
#include <print>
#include <ranges>

#include <cexchain/console/sessions.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

void require_ledger_directory(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir / "statements")) {
        throw CommandError{"no ledger at " + dir.string()};
    }
}

} // namespace

int cmd_console_session_list(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    std::vector<console::PublishedSession> sessions;
    try {
        sessions = console::published_sessions(console::state_directory(dir));
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
    if (args.json()) {
        Json list = Json::array();
        for (const auto& s : sessions) {
            list.push_back({{"id", s.id},
                            {"user", s.user},
                            {"created", format_time(s.created)},
                            {"ends_by", format_time(s.created + console::session_lifetime)}});
        }
        print_json(list);
        return exit_ok;
    }
    if (sessions.empty()) {
        std::println("no console sessions (signing in to the console begins one)");
    }
    for (const auto& s : sessions) {
        std::println("{}  {:<24} since {}", s.id, s.user, format_time(s.created));
    }
    return exit_ok;
}

int cmd_console_session_revoke(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const std::string id = args.positional().front();
    const std::filesystem::path state = console::state_directory(dir);
    try {
        const auto sessions = console::published_sessions(state);
        if (std::ranges::find(sessions, id, &console::PublishedSession::id) == sessions.end()) {
            throw CommandError{"no console session " + id + " (console session list)"};
        }
        console::request_revocation(state, id);
    } catch (const CommandError&) {
        throw;
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
    if (args.json()) {
        print_json({{"revoked", id}});
    } else {
        std::println("revoked console session {} (the console ends it at its next request)", id);
    }
    return exit_ok;
}

} // namespace cexchain::cli
