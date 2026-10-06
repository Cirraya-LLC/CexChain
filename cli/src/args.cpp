// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "args.hpp"

#include <algorithm>

namespace cexchain::cli {

Args::Args(int argc, const char* const* argv, std::vector<std::string> switches) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg.starts_with("--")) {
            std::string name(arg.substr(2));
            std::string value;
            if (const auto eq = name.find('='); eq != std::string::npos) {
                value = name.substr(eq + 1);
                name.resize(eq);
            } else if (!std::ranges::contains(switches, name)) {
                if (i + 1 >= argc) {
                    throw UsageError{"option --" + name + " needs a value"};
                }
                value = argv[++i];
            }
            options_.emplace(name, value);
            read_[name] = false;
        } else {
            positional_.emplace_back(arg);
        }
    }
}

std::optional<std::string> Args::get(std::string_view name) const {
    const auto it = options_.find(name);
    if (it == options_.end()) {
        return std::nullopt;
    }
    read_[std::string(name)] = true;
    return it->second;
}

std::vector<std::string> Args::all(std::string_view name) const {
    std::vector<std::string> values;
    const auto [begin, end] = options_.equal_range(name);
    for (auto it = begin; it != end; ++it) {
        values.push_back(it->second);
    }
    if (!values.empty()) {
        read_[std::string(name)] = true;
    }
    return values;
}

bool Args::has(std::string_view name) const {
    const bool present = options_.contains(name);
    if (present) {
        read_[std::string(name)] = true;
    }
    return present;
}

std::string Args::need(std::string_view name) const {
    auto value = get(name);
    if (!value || value->empty()) {
        throw UsageError{"missing required option --" + std::string(name)};
    }
    return *value;
}

std::vector<std::string> Args::unused() const {
    std::vector<std::string> names;
    for (const auto& [name, was_read] : read_) {
        if (!was_read) {
            names.push_back(name);
        }
    }
    return names;
}

} // namespace cexchain::cli
