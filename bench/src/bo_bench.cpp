// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Bo builds (D-056): each example under examples/ and the bench's bill,
// built from source (lex, parse, check, lower, emit) again and again.

#include <algorithm>
#include <filesystem>
#include <format>
#include <string>
#include <vector>

#include "bench.hpp"
#include "fixture.hpp"

namespace cexchain::bench {

int bo_bench(const Options& options) {
    const std::uint64_t repeat = std::max<std::uint64_t>(1, options.number("repeat", 20));
    struct Source {
        std::string name;
        std::string text;
        /// The vocabulary packs beside it (`bo build --vocab`).
        std::vector<std::string> vocabularies;
    };
    std::vector<Source> sources;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(examples_directory(options))) {
        if (entry.is_regular_file() && entry.path().extension() == ".bo") {
            Source s{entry.path().stem().string(), read_text(entry.path()), {}};
            for (const auto& beside :
                 std::filesystem::directory_iterator(entry.path().parent_path())) {
                if (beside.path().extension() == ".vocab") {
                    s.vocabularies.push_back(read_text(beside.path()));
                }
            }
            sources.push_back(std::move(s));
        }
    }
    std::ranges::sort(sources, {}, &Source::name);
    sources.push_back({"bill of 400 lines (heavy)", bill_source(400), {}});
    Results results;
    double total = 0;
    for (const auto& [name, source, vocabularies] : sources) {
        Latencies builds;
        std::size_t code = 0;
        for (std::uint64_t i = 0; i < repeat; ++i) {
            double ms = 0;
            code = bo_deploy(source, &ms, vocabularies).code.size();
            builds.add(ms * 1000);
        }
        const double median = builds.percentile(0.5) / 1000;
        total += median;
        results.add(std::format("{} build p50", name), median, "ms");
        results.add(std::format("{} build p99", name), builds.percentile(0.99) / 1000, "ms");
        results.add(std::format("{} code", name), static_cast<double>(code), "bytes");
    }
    results.add("all builds (sum of p50)", total, "ms");
    results.print(options.flag("json"));
    return 0;
}

} // namespace cexchain::bench
