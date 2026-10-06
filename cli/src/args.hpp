// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace cexchain::cli {

/// Parsed command-line arguments: positional words, then `--name value`
/// options (repeatable) and `--flag` switches.
class Args {
public:
    /// `switches` lists the options that take no value.
    Args(int argc, const char* const* argv, std::vector<std::string> switches);

    [[nodiscard]] const std::vector<std::string>& positional() const noexcept {
        return positional_;
    }
    [[nodiscard]] std::optional<std::string> get(std::string_view name) const;
    [[nodiscard]] std::vector<std::string> all(std::string_view name) const;
    [[nodiscard]] bool has(std::string_view name) const;
    /// The option's value; throws UsageError if it is missing.
    [[nodiscard]] std::string need(std::string_view name) const;

    /// Options that were given but never read, for typo detection.
    [[nodiscard]] std::vector<std::string> unused() const;

private:
    std::vector<std::string> positional_;
    std::multimap<std::string, std::string, std::less<>> options_;
    mutable std::map<std::string, bool, std::less<>> read_;
};

/// A mistake in how the command was invoked.
struct UsageError {
    std::string message;
};

/// Any other failure, with a message for the user.
struct CommandError {
    std::string message;
};

} // namespace cexchain::cli
