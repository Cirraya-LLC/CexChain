// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <functional>

/// Data parallelism the core can use without starting threads of its own:
/// a caller with a pool of threads passes it in (the ledger passes its
/// `parallel_for`), and without one the work runs on the calling thread.
namespace cexchain {

/// Runs `work(begin, end)` over consecutive ranges covering [0, count),
/// perhaps on several threads at once, and returns when all are done.
/// `work` must not throw, and each range must write only its own results.
using ForRanges = std::function<void(
    std::size_t count, const std::function<void(std::size_t begin, std::size_t end)>& work)>;

/// `for_ranges` over [0, count), or one range on this thread if it is empty.
inline void run_ranges(const ForRanges& for_ranges, std::size_t count,
                       const std::function<void(std::size_t begin, std::size_t end)>& work) {
    if (count == 0) {
        return;
    }
    if (for_ranges) {
        for_ranges(count, work);
    } else {
        work(0, count);
    }
}

} // namespace cexchain
