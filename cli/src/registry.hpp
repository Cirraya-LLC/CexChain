// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "args.hpp"

/// The command registry: the single source for dispatch, option validation,
/// help text, and shell completion.
namespace cexchain::cli {

struct OptionSpec {
    std::string_view name;
    /// Placeholder for the value, e.g. "DIR"; empty for switches.
    std::string_view value;
    std::string_view help;
    bool required = false;
    bool repeatable = false;
};

struct CommandSpec {
    std::vector<std::string_view> path;
    std::string_view summary;
    std::string_view group;
    /// Positional arguments after the command words, e.g. "FILE".
    std::string_view arguments;
    std::size_t min_arguments = 0;
    std::size_t max_arguments = 0;
    std::vector<OptionSpec> options;
    int (*run)(const Args&) = nullptr;
    /// Extra help shown by --help.
    std::string_view details = {};
    /// Aliases are dispatched but not listed in help.
    bool alias = false;
};

[[nodiscard]] const std::vector<CommandSpec>& registry();

/// Parses, validates, and runs a command line. Returns the exit code.
int dispatch(int argc, const char* const* argv);

[[nodiscard]] std::string command_help(const CommandSpec& spec);
[[nodiscard]] std::string overview_help();
[[nodiscard]] std::string completion_script(std::string_view shell);

} // namespace cexchain::cli
