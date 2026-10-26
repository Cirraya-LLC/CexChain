// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

/// The console's settings, in settings.json in its folder: the language a
/// browser starts in (each browser may choose its own), and the folder
/// backups go to. Changed by the console's owners and admins, or with
/// console settings set.
namespace cexchain::console {

/// The languages the console's page is written in.
inline constexpr std::array<std::string_view, 3> languages{"en", "zh-Hant-HK", "zh-Hans-CN"};

[[nodiscard]] bool valid_language(std::string_view language) noexcept;

struct Settings {
    std::optional<std::string> language;
    /// An absolute path.
    std::optional<std::filesystem::path> backup_folder;
};

/// Reads them (none set if never written). Throws std::runtime_error if the
/// file is damaged.
[[nodiscard]] Settings load_settings(const std::filesystem::path& directory);
/// Replaces them atomically.
void save_settings(const std::filesystem::path& directory, const Settings& settings);

/// Checks a backup folder: an absolute path to a folder that exists or can
/// be made, and that this process may write to. Makes it. The reason it
/// cannot be one, if it cannot.
[[nodiscard]] std::optional<std::string> prepare_backup_folder(const std::filesystem::path& folder);

/// Where backups go if the person has no better place: a folder in their
/// home folder.
[[nodiscard]] std::filesystem::path suggested_backup_folder();

} // namespace cexchain::console
