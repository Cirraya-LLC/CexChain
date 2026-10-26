// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <variant>

#include <nlohmann/json.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/settings.hpp>
#include <cexchain/ledger/storage.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::string_view settings_file = "settings.json";

[[noreturn]] void damaged() {
    throw std::runtime_error("the console's settings.json is damaged");
}

} // namespace

bool valid_language(std::string_view language) noexcept {
    return std::ranges::find(languages, language) != languages.end();
}

Settings load_settings(const std::filesystem::path& directory) {
    Settings settings;
    const std::filesystem::path file = directory / settings_file;
    if (!std::filesystem::exists(file)) {
        return settings;
    }
    const Bytes bytes = app::read_file(file);
    const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!j.is_object()) {
        damaged();
    }
    if (const auto it = j.find("language"); it != j.end() && !it->is_null()) {
        if (!it->is_string() || !valid_language(it->get<std::string>())) {
            damaged();
        }
        settings.language = it->get<std::string>();
    }
    if (const auto it = j.find("backup_folder"); it != j.end() && !it->is_null()) {
        if (!it->is_string() || !std::filesystem::path(it->get<std::string>()).is_absolute()) {
            damaged();
        }
        settings.backup_folder = it->get<std::string>();
    }
    return settings;
}

void save_settings(const std::filesystem::path& directory, const Settings& settings) {
    const nlohmann::json j{
        {"language", settings.language ? nlohmann::json(*settings.language) : nlohmann::json()},
        {"backup_folder", settings.backup_folder ? nlohmann::json(settings.backup_folder->string())
                                                 : nlohmann::json()}};
    std::filesystem::create_directories(directory);
    app::write_file(directory / settings_file, as_bytes(j.dump(2) + "\n"), true);
}

std::optional<std::string> prepare_backup_folder(const std::filesystem::path& folder) {
    if (!folder.is_absolute()) {
        return "a backup folder is a full path, such as /Volumes/Backup/CexChain";
    }
    std::error_code error;
    std::filesystem::create_directories(folder, error);
    if (error || !std::filesystem::is_directory(folder)) {
        return "the folder cannot be made there: " + error.message();
    }
    // Writable: a file made and removed.
    const std::filesystem::path probe = folder / ".cexchain-write-test";
    try {
        app::write_file(probe, as_bytes("ok\n"), true);
    } catch (const std::exception&) {
        return std::string("this console may not write to that folder");
    }
    std::filesystem::remove(probe, error);
    return std::nullopt;
}

std::filesystem::path suggested_backup_folder() {
    const char* home = std::getenv("HOME");
    const std::filesystem::path base = home != nullptr && *home != '\0'
                                           ? std::filesystem::path(home)
                                           : std::filesystem::temp_directory_path();
    return base / "CexChain backups";
}

nlohmann::json Console::settings_view(Role role) const {
    const Settings settings = load_settings(services_.directory);
    nlohmann::json ledger_view;
    if (const ledger::Ledger* served = ledger()) {
        served->read_state([&](const protocol::LedgerState& state) {
            ledger_view = {{"id", to_hex(state.ledger_id().bytes())},
                           {"organization", state.organization()},
                           {"hash", crypto::name(state.hash())},
                           {"actors", state.actors().size()}};
        });
        ledger_view["entries"] = served->size();
    }
    return {{"ledger", ledger_view},
            {"directory", services_.directory.parent_path().string()},
            {"language", settings.language ? nlohmann::json(*settings.language) : nlohmann::json()},
            {"languages", languages},
            {"backup_folder", settings.backup_folder
                                  ? nlohmann::json(settings.backup_folder->string())
                                  : nlohmann::json()},
            {"suggested_backup_folder", suggested_backup_folder().string()},
            {"keys", key_state()},
            {"may_change", role == Role::owner || role == Role::admin}};
}

http::Response Console::settings_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Role role = std::get<Signed>(who).role;
    if (request.method == "GET") {
        return json(200, settings_view(role));
    }
    if (request.method != "POST") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "GET, POST");
        return refused;
    }
    if (role != Role::owner && role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin changes the settings");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const auto lock = ledger::DirectoryLock::acquire(services_.directory, 2000);
    if (!lock) {
        return error(503, "unavailable", "the console's settings are being changed; try again");
    }
    Settings settings = load_settings(services_.directory);
    if (const auto it = body.find("language"); it != body.end()) {
        if (it->is_null()) {
            settings.language.reset();
        } else if (!it->is_string() || !valid_language(it->get<std::string>())) {
            return error(400, "invalid_argument",
                         "the console is written in en, zh-Hant-HK, "
                         "and zh-Hans-CN");
        } else {
            settings.language = it->get<std::string>();
        }
    }
    if (const auto it = body.find("backup_folder"); it != body.end()) {
        if (it->is_null()) {
            settings.backup_folder.reset();
        } else if (!it->is_string()) {
            return error(400, "invalid_argument", "a backup folder is a path");
        } else {
            const std::filesystem::path folder = it->get<std::string>();
            if (const auto problem = prepare_backup_folder(folder)) {
                return error(400, "invalid_argument", *problem);
            }
            settings.backup_folder = folder.lexically_normal();
        }
    }
    save_settings(services_.directory, settings);
    return json(200, settings_view(role));
}

} // namespace cexchain::console
