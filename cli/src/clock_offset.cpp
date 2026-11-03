// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include <cexchain/ledger/environment.hpp>

#include "support.hpp"

namespace cexchain::cli {

/// $CEXCHAIN_CLOCK_OFFSET: a whole number of days, hours, minutes, or seconds
/// (30d, 12h, 90m, 45s) by which this process's clock runs ahead of the
/// computer's, so that time rules can be tried without waiting. For
/// demonstrations and tests: a ledger keeps the times it records, and one
/// that ran ahead is behind once the offset is gone.
void apply_clock_offset() {
    const char* env = std::getenv("CEXCHAIN_CLOCK_OFFSET");
    if (env == nullptr || *env == '\0') {
        return;
    }
    const std::string_view text(env);
    const UsageError bad{"CEXCHAIN_CLOCK_OFFSET is a whole number of days, hours, minutes, or "
                         "seconds ahead, such as 30d, 12h, 90m, or 45s (at most 3660d), not '" +
                         std::string(text) + "'"};
    if (text.size() < 2 || text.size() > 10) {
        throw bad;
    }
    std::uint64_t unit = 0;
    switch (text.back()) {
    case 'd':
        unit = 86'400'000;
        break;
    case 'h':
        unit = 3'600'000;
        break;
    case 'm':
        unit = 60'000;
        break;
    case 's':
        unit = 1'000;
        break;
    default:
        throw bad;
    }
    std::uint64_t count = 0;
    for (const char c : text.substr(0, text.size() - 1)) {
        if (c < '0' || c > '9') {
            throw bad;
        }
        count = count * 10 + static_cast<std::uint64_t>(c - '0');
    }
    constexpr std::uint64_t most = std::uint64_t{3660} * 86'400'000;
    if (count > most / unit) {
        throw bad;
    }
    ledger::SystemClock::set_offset(count * unit);
}

} // namespace cexchain::cli
