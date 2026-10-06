// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "args.hpp"

#include <cstdlib>

namespace cexchain::cli {

Args::Args(const CommandSpec& spec, std::vector<std::string> positional,
           std::multimap<std::string, std::string, std::less<>> options)
    : spec_(&spec), positional_(std::move(positional)), options_(std::move(options)) {}

std::optional<std::string> Args::get(std::string_view name) const {
    const auto it = options_.find(name);
    if (it == options_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<std::string> Args::all(std::string_view name) const {
    std::vector<std::string> values;
    const auto [begin, end] = options_.equal_range(name);
    for (auto it = begin; it != end; ++it) {
        values.push_back(it->second);
    }
    return values;
}

bool Args::has(std::string_view name) const {
    return options_.contains(name);
}

std::string Args::need(std::string_view name) const {
    auto value = get(name);
    if (!value || value->empty()) {
        throw UsageError{"missing required option --" + std::string(name)};
    }
    return *value;
}

std::filesystem::path Args::ledger() const {
    if (auto value = get("ledger"); value && !value->empty()) {
        return *value;
    }
    if (const char* env = std::getenv("CEXCHAIN_LEDGER"); env != nullptr && *env != '\0') {
        return env;
    }
    throw UsageError{"no ledger given: pass --ledger DIR or set CEXCHAIN_LEDGER"};
}

} // namespace cexchain::cli
