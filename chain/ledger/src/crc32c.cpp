// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "crc32c.hpp"

#include <array>

namespace cexchain::ledger::detail {

namespace {

constexpr std::array<std::uint32_t, 256> make_table() noexcept {
    constexpr std::uint32_t polynomial = 0x82f63b78; // Castagnoli, reflected
    std::array<std::uint32_t, 256> table{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t crc = i;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1U) != 0 ? (crc >> 1) ^ polynomial : crc >> 1;
        }
        table[i] = crc;
    }
    return table;
}

constexpr auto table = make_table();

} // namespace

std::uint32_t crc32c(ByteView data) noexcept {
    std::uint32_t crc = 0xffffffff;
    for (const std::uint8_t byte : data) {
        crc = table[(crc ^ byte) & 0xffU] ^ (crc >> 8);
    }
    return crc ^ 0xffffffff;
}

} // namespace cexchain::ledger::detail
