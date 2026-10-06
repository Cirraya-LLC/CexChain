// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdio>
#include <format>
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
        "                           [--requests N] [--prefill N] [--dir DIR] [--keep] [--json]\n";
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
    } catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return 1;
    }
    std::print(stderr, "{}", usage);
    return 1;
}
