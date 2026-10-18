// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <atomic>
#include <bit>
#include <chrono>
#include <cstdio>
#include <cstdlib>

#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>

namespace cexchain::ledger {

namespace {

std::atomic<protocol::Timestamp> clock_offset{0};

} // namespace

protocol::Timestamp SystemClock::now() {
    const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<protocol::Timestamp>(
               std::chrono::duration_cast<std::chrono::milliseconds>(since_epoch).count()) +
           clock_offset.load(std::memory_order_relaxed);
}

void SystemClock::set_offset(protocol::Timestamp milliseconds) noexcept {
    clock_offset.store(milliseconds, std::memory_order_relaxed);
}

protocol::Timestamp SystemClock::offset() noexcept {
    return clock_offset.load(std::memory_order_relaxed);
}

void SystemEntropy::fill(std::span<std::uint8_t> out) {
    if (!crypto::openssl::random_bytes(out)) {
        std::fputs("cexchain: the system random number generator failed\n", stderr);
        std::abort();
    }
}

namespace {

/// SplitMix64, used to expand a 64-bit seed into xoshiro256** state.
std::uint64_t splitmix64(std::uint64_t& x) noexcept {
    std::uint64_t z = (x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

} // namespace

SeededEntropy::SeededEntropy(std::uint64_t seed) noexcept {
    for (std::uint64_t& word : state_) {
        word = splitmix64(seed);
    }
}

std::uint64_t SeededEntropy::next() noexcept {
    const std::uint64_t result = std::rotl(state_[1] * 5, 7) * 9;
    const std::uint64_t t = state_[1] << 17;
    state_[2] ^= state_[0];
    state_[3] ^= state_[1];
    state_[1] ^= state_[2];
    state_[0] ^= state_[3];
    state_[2] ^= t;
    state_[3] = std::rotl(state_[3], 45);
    return result;
}

std::uint64_t SeededEntropy::below(std::uint64_t bound) noexcept {
    // Rejection sampling avoids modulo bias.
    const std::uint64_t limit = -bound % bound;
    while (true) {
        const std::uint64_t value = next();
        if (value >= limit) {
            return value % bound;
        }
    }
}

void SeededEntropy::fill(std::span<std::uint8_t> out) {
    std::size_t i = 0;
    while (i < out.size()) {
        std::uint64_t word = next();
        for (int k = 0; k < 8 && i < out.size(); ++k, ++i) {
            out[i] = static_cast<std::uint8_t>(word);
            word >>= 8;
        }
    }
}

} // namespace cexchain::ledger
