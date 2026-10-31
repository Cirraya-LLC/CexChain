// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/app/errors.hpp>

namespace cexchain::cli {

/// The command line is built on the actions of the app library, which it
/// shares with the console: their names are the command line's too.
using namespace app;

/// A mistake in how the command was invoked: app::UsageError.
/// Any other failure, with a message for the user.
using CommandError = app::ActionError;

struct CommandSpec;

/// The arguments of one command, already validated against its spec.
class Args {
public:
    Args(const CommandSpec& spec, std::vector<std::string> positional,
         std::multimap<std::string, std::string, std::less<>> options);

    [[nodiscard]] const CommandSpec& spec() const noexcept { return *spec_; }
    /// Positional arguments after the command words.
    [[nodiscard]] const std::vector<std::string>& positional() const noexcept {
        return positional_;
    }
    [[nodiscard]] std::optional<std::string> get(std::string_view name) const;
    [[nodiscard]] std::vector<std::string> all(std::string_view name) const;
    [[nodiscard]] bool has(std::string_view name) const;
    /// The option's value; throws UsageError if missing.
    [[nodiscard]] std::string need(std::string_view name) const;
    /// True if machine-readable output was requested.
    [[nodiscard]] bool json() const { return has("json"); }
    /// --ledger, or $CEXCHAIN_LEDGER.
    [[nodiscard]] std::filesystem::path ledger() const;
    /// The same, or else this computer's place for a person's ledger (the
    /// console's commands: one console per person, wherever it was set up).
    [[nodiscard]] std::filesystem::path console_ledger() const;

private:
    const CommandSpec* spec_;
    std::vector<std::string> positional_;
    std::multimap<std::string, std::string, std::less<>> options_;
};

/// Where a person's ledger lives on this computer: on macOS
/// ~/Library/Application Support/CexChain/ledger, elsewhere
/// $XDG_DATA_HOME/cexchain/ledger (~/.local/share by default).
[[nodiscard]] std::filesystem::path default_ledger_directory();

} // namespace cexchain::cli
