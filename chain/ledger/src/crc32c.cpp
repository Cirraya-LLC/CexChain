// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "crc32c.hpp"

#include <array>

namespace kanhe::ledger::detail {

namespace {

// Slicing by eight: tables_[k][b] is the CRC of byte b followed by k zero
// bytes, so eight bytes cost eight lookups and no dependency between them.
// Bytes are loaded one by one, so the result does not depend on the
// machine's byte order.
constexpr std::array<std::array<std::uint32_t, 256>, 8> make_tables() noexcept {
    constexpr std::uint32_t polynomial = 0x82f63b78; // Castagnoli, reflected
    std::array<std::array<std::uint32_t, 256>, 8> tables{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t crc = i;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1U) != 0 ? (crc >> 1) ^ polynomial : crc >> 1;
        }
        tables[0][i] = crc;
    }
    for (std::size_t k = 1; k < 8; ++k) {
        for (std::uint32_t i = 0; i < 256; ++i) {
            const std::uint32_t previous = tables[k - 1][i];
            tables[k][i] = (previous >> 8) ^ tables[0][previous & 0xffU];
        }
    }
    return tables;
}

constexpr auto tables = make_tables();

constexpr std::uint32_t load32(const std::uint8_t* p) noexcept {
    return std::uint32_t{p[0]} | (std::uint32_t{p[1]} << 8) | (std::uint32_t{p[2]} << 16) |
           (std::uint32_t{p[3]} << 24);
}

} // namespace

std::uint32_t crc32c(ByteView data) noexcept {
    std::uint32_t crc = 0xffffffff;
    const std::uint8_t* p = data.data();
    std::size_t n = data.size();
    for (; n >= 8; n -= 8, p += 8) {
        const std::uint32_t low = crc ^ load32(p);
        const std::uint32_t high = load32(p + 4);
        crc = tables[7][low & 0xffU] ^ tables[6][(low >> 8) & 0xffU] ^
              tables[5][(low >> 16) & 0xffU] ^ tables[4][low >> 24] ^ tables[3][high & 0xffU] ^
              tables[2][(high >> 8) & 0xffU] ^ tables[1][(high >> 16) & 0xffU] ^
              tables[0][high >> 24];
    }
    for (; n > 0; --n, ++p) {
        crc = tables[0][(crc ^ *p) & 0xffU] ^ (crc >> 8);
    }
    return crc ^ 0xffffffff;
}

} // namespace kanhe::ledger::detail
