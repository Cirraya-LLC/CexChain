// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cstdio>
#include <format>
#include <numeric>
#include <print>
#include <stdexcept>

#include "bench.hpp"

namespace cexchain::bench {

void Results::print(bool json) const {
    if (json) {
        std::string out = "{";
        for (std::size_t i = 0; i < rows_.size(); ++i) {
            out +=
                std::format("{}\"{}\": {:.3f}", i == 0 ? "" : ", ", rows_[i].name, rows_[i].value);
        }
        std::println("{}}}", out);
        return;
    }
    for (const Row& r : rows_) {
        std::println("{:<40} {:>14.3f} {}", r.name, r.value, r.unit);
    }
}

double Latencies::total_us() const noexcept {
    return std::accumulate(us_.begin(), us_.end(), 0.0);
}

double Latencies::percentile(double p) {
    if (us_.empty()) {
        return 0;
    }
    if (!sorted_) {
        std::ranges::sort(us_);
        sorted_ = true;
    }
    const auto at = static_cast<std::size_t>(p * static_cast<double>(us_.size() - 1));
    return us_[at];
}

void Latencies::report(Results& results, const std::string& name, const std::string& unit) {
    const double total = total_us();
    sorted_ = false;
    if (!unit.empty()) {
        results.add(name + " throughput",
                    total > 0 ? static_cast<double>(us_.size()) * 1e6 / total : 0.0, unit);
    }
    results.add(name + " mean", us_.empty() ? 0.0 : total / static_cast<double>(us_.size()), "us");
    results.add(name + " p50", percentile(0.50), "us");
    results.add(name + " p99", percentile(0.99), "us");
    results.add(name + " p99.9", percentile(0.999), "us");
}

Options::Options(int argc, char** argv, int first) {
    for (int i = first; i < argc; ++i) {
        std::string name = argv[i];
        if (!name.starts_with("--")) {
            throw std::invalid_argument("expected --option, got " + name);
        }
        name = name.substr(2);
        if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
            values_[name] = argv[++i];
        } else {
            values_[name] = "";
        }
    }
}

std::uint64_t Options::number(const std::string& name, std::uint64_t fallback) const {
    const auto it = values_.find(name);
    return it == values_.end() ? fallback : std::stoull(it->second);
}

std::string Options::text(const std::string& name, std::string fallback) const {
    const auto it = values_.find(name);
    return it == values_.end() ? fallback : it->second;
}

bool Options::flag(const std::string& name) const {
    return values_.contains(name);
}

} // namespace cexchain::bench

int main(int argc, char** argv) {
    using namespace cexchain::bench;
    const std::string usage =
        "usage: cexchain-bench ledger [--entries N] [--checkpoint-every K] [--batch B]\n"
        "                             [--disk DIR] [--json]\n"
        "       cexchain-bench http [--mode read|submit|health] [--connections C]\n"
        "                           [--server-threads T] [--client-threads T] [--seconds S]\n"
        "                           [--requests N] [--prefill N] [--dir DIR] [--keep] [--json]\n"
        "       cexchain-bench http --mode create|call [--instances N] [--calls K]\n"
        "                           [--contract small|heavy] [--connections C] ...\n"
        "       cexchain-bench contracts [--contract small,heavy,split] [--instances N]\n"
        "                                [--calls K] [--lines L] [--batch B] [--disk DIR] "
        "[--json]\n"
        "       cexchain-bench evidence [--history H] [--entries N] [--repeat R] [--json]\n"
        "       cexchain-bench keeper [--instances N,N,...] [--json]\n"
        "       cexchain-bench executor [--requests N] [--concurrency C]\n"
        "                               [--connector command|webhook] [--program PATH]\n"
        "                               [--state DIR] [--cexchain PATH] [--in-process] [--json]\n"
        "       cexchain-bench registrar [--instances N] [--calls K] [--json]\n"
        "       cexchain-bench bo [--repeat R] [--examples DIR] [--json]\n"
        "Contracts are Bo builds (examples/lending, a bill, examples/multi-tier-split,\n"
        "examples/idc-hosting): every scenario but ledger, http, and executor needs\n"
        "the Bo compiler (a GCC 16 build).\n";
    if (argc < 2) {
        std::print(stderr, "{}", usage);
        return 1;
    }
    try {
        const std::string scenario = argv[1];
        const Options options(argc, argv, 2);
        if (scenario == "ledger") {
            return ledger_bench(options);
        }
        if (scenario == "http") {
            return http_bench(options);
        }
        if (scenario == "contracts") {
            return contracts_bench(options);
        }
        if (scenario == "evidence") {
            return evidence_bench(options);
        }
        if (scenario == "keeper") {
            return keeper_bench(options);
        }
        if (scenario == "executor") {
            return executor_bench(options);
        }
        if (scenario == "registrar") {
            return registrar_bench(options);
        }
        if (scenario == "bo") {
            return bo_bench(options);
        }
    } catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return 1;
    }
    std::print(stderr, "{}", usage);
    return 1;
}
