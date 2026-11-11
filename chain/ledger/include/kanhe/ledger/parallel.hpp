// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <functional>

#include <kanhe/core/parallel.hpp>

/// Data parallelism for pure work (signature checks, decoding, hashing).
/// The ledger's state transitions stay sequential and in log order; only
/// work whose results do not depend on order runs here, each piece writing
/// its own slot, so results are the same with one thread or many.
namespace kanhe::ledger {

/// Calls `work(begin, end)` over consecutive ranges covering [0, count), on
/// a process-wide pool of worker threads and the calling thread, and returns
/// when all are done. Counts below `serial_below` run on the calling thread
/// alone (the default suits cheap pieces; heavy ones, such as contract runs,
/// are worth spreading from 2). `work` must not throw. Calls from several
/// threads at once are fine; nested calls run inline.
void parallel_for(std::size_t count,
                  const std::function<void(std::size_t begin, std::size_t end)>& work,
                  std::size_t serial_below = 8);

/// `parallel_for` as the core takes it (kanhe/core/parallel.hpp).
[[nodiscard]] ForRanges on_pool();

/// Threads the pool uses (workers plus the caller): $KANHE_THREADS if set,
/// else the hardware's.
[[nodiscard]] std::size_t parallelism() noexcept;

} // namespace kanhe::ledger
