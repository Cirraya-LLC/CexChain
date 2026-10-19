// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <cexchain/core/error.hpp>

namespace cexchain::bench {

using Clock = std::chrono::steady_clock;

[[nodiscard]] inline double elapsed_ms(Clock::time_point since) {
    return std::chrono::duration<double, std::milli>(Clock::now() - since).count();
}

template <class T>
T must(Result<T> result, const char* what) {
    if (!result) {
        throw std::runtime_error(std::string(what) + ": " + std::string(result.error().detail));
    }
    return std::move(*result);
}

inline void must(Status status, const char* what) {
    if (!status) {
        throw std::runtime_error(std::string(what) + ": " + std::string(status.error().detail));
    }
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

/// Durations of single operations, reported as percentiles.
class Latencies {
public:
    void add(double us) { us_.push_back(us); }
    [[nodiscard]] std::size_t size() const noexcept { return us_.size(); }
    [[nodiscard]] double total_us() const noexcept;
    /// `p` in [0, 1]; sorts on first use after an add.
    [[nodiscard]] double percentile(double p);
    /// Rows "NAME throughput" (operations per second over their summed
    /// time: for operations one after another; empty `unit` leaves it out),
    /// "NAME mean", "NAME p50", "NAME p99", and "NAME p99.9".
    void report(Results& results, const std::string& name, const std::string& unit = "ops/s");

private:
    std::vector<double> us_;
    bool sorted_ = false;
};

[[nodiscard]] inline double elapsed_us(Clock::time_point since) {
    return std::chrono::duration<double, std::micro>(Clock::now() - since).count();
}

int ledger_bench(const Options& options);
int http_bench(const Options& options);
int contracts_bench(const Options& options);
int evidence_bench(const Options& options);
int keeper_bench(const Options& options);
int executor_bench(const Options& options);
int registrar_bench(const Options& options);
int bo_bench(const Options& options);

} // namespace cexchain::bench
