// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <cexchain/core/protocol/common.hpp>

/// Everything a ledger observes about the outside world besides its storage:
/// time and randomness. Production uses the system implementations;
/// simulations and tests inject deterministic ones, so a whole ledger run can
/// be replayed exactly from a seed.
namespace cexchain::ledger {

class Clock {
public:
    virtual ~Clock() = default;
    /// Unix time in milliseconds.
    [[nodiscard]] virtual protocol::Timestamp now() = 0;

protected:
    Clock() = default;
    Clock(const Clock&) = default;
    Clock& operator=(const Clock&) = default;
};

class Entropy {
public:
    virtual ~Entropy() = default;
    virtual void fill(std::span<std::uint8_t> out) = 0;

    template <std::size_t N>
    [[nodiscard]] std::array<std::uint8_t, N> bytes() {
        std::array<std::uint8_t, N> out{};
        fill(out);
        return out;
    }

protected:
    Entropy() = default;
    Entropy(const Entropy&) = default;
    Entropy& operator=(const Entropy&) = default;
};

/// The system wall clock, plus the process's offset (none by default).
class SystemClock final : public Clock {
public:
    [[nodiscard]] protocol::Timestamp now() override;

    /// Runs every SystemClock of this process `milliseconds` ahead of the
    /// computer's clock, so that time rules can be tried without waiting
    /// (the command line's $CEXCHAIN_CLOCK_OFFSET: demonstrations and tests
    /// only). Set it once, before any clock is read.
    static void set_offset(protocol::Timestamp milliseconds) noexcept;
    [[nodiscard]] static protocol::Timestamp offset() noexcept;
};

/// Cryptographically secure randomness from OpenSSL. Aborts the process if
/// the generator fails, since no safe fallback exists.
class SystemEntropy final : public Entropy {
public:
    void fill(std::span<std::uint8_t> out) override;
};

/// A clock that moves only when told to. For simulation and tests.
class ManualClock final : public Clock {
public:
    explicit ManualClock(protocol::Timestamp start) noexcept : now_(start) {}

    [[nodiscard]] protocol::Timestamp now() override { return now_; }
    void advance(protocol::Timestamp milliseconds) noexcept { now_ += milliseconds; }
    void set(protocol::Timestamp now) noexcept { now_ = now; }

private:
    protocol::Timestamp now_;
};

/// A reproducible pseudo-random stream (xoshiro256**) for simulation and
/// tests. Not cryptographically secure: never use it for keys or nonces in
/// production.
class SeededEntropy final : public Entropy {
public:
    explicit SeededEntropy(std::uint64_t seed) noexcept;

    void fill(std::span<std::uint8_t> out) override;
    [[nodiscard]] std::uint64_t next() noexcept;
    /// A value in [0, bound). `bound` must be non-zero.
    [[nodiscard]] std::uint64_t below(std::uint64_t bound) noexcept;

private:
    std::array<std::uint64_t, 4> state_{};
};

} // namespace cexchain::ledger
