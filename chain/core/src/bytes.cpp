// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <atomic>

#include <kanhe/core/bytes.hpp>

namespace kanhe {

void secure_wipe(std::span<std::uint8_t> bytes) noexcept {
    volatile std::uint8_t* p = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        p[i] = 0;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

} // namespace kanhe
