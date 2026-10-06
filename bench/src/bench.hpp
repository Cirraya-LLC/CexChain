// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace cexchain::bench {

using Clock = std::chrono::steady_clock;

[[nodiscard]] inline double elapsed_ms(Clock::time_point since) {
    return std::chrono::duration<double, std::milli>(Clock::now() - since).count();
}

/// Named results, printed as a table or as JSON.
class Results {
public:
    void add(std::string name, double value, std::string unit) {
        rows_.push_back({std::move(name), value, std::move(unit)});
    }
    void print(bool json) const;

private:
    struct Row {
        std::string name;
        double value;
        std::string unit;
    };
    std::vector<Row> rows_;
};

/// --name value options.
class Options {
public:
    Options(int argc, char** argv, int first);
    [[nodiscard]] std::uint64_t number(const std::string& name, std::uint64_t fallback) const;
    [[nodiscard]] std::string text(const std::string& name, std::string fallback) const;
    [[nodiscard]] bool flag(const std::string& name) const;

private:
    std::map<std::string, std::string> values_;
};

int ledger_bench(const Options& options);

} // namespace cexchain::bench
