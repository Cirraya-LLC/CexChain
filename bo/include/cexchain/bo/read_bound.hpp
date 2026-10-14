// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>

/// The bound on what reading a call's input costs compiled Bo code (codegen 2
/// on; milestone 18), header-only and with no other dependency, so that the
/// fuzz target of the runtime's reader (Clang, without the compiler) checks
/// the same bound the compiler counts.
namespace cexchain::bo::runtime {

/// The most a map key may be for read_input_fuel's bound, in bytes of text
/// (names in Bo: of fields, inputs, roles, charges, rules).
inline constexpr std::uint32_t max_key_size = 64;

/// read_item's costliest path for one item is an integer, a length, or a
/// tag number in 8 bytes, with its parent's loop: 223 fuel (a nested tag of
/// 8 bytes, 165 an item); a map key adds its comparison with the key before
/// it when their first bytes are equal, at most 137 for keys of 64 bytes
/// beside 240 an item (597 an entry: a 64-byte text key and an 8-byte
/// value). The fixed part covers reading 160 KiB (2,561 fuel) and the
/// routine's own instructions. Each constant has a margin; the test
/// "read_input stays within its bound" measures every kind of item, and
/// bo_runtime_fuzz checks random inputs.
inline constexpr std::uint64_t read_input_fixed = 3'000;
inline constexpr std::uint64_t read_input_per_item = 240;
inline constexpr std::uint64_t read_input_per_key = 160;

/// An upper bound on the fuel `read_input` takes for an input of at most
/// `items` items, at most `keys` of them map keys of at most max_key_size
/// bytes (and no longer key), and at most 160 KiB. Saturates at 2^62.
[[nodiscard]] constexpr std::uint64_t read_input_fuel(const std::uint64_t items,
                                                      const std::uint64_t keys) noexcept {
    constexpr std::uint64_t cap = std::uint64_t{1} << 62U;
    if (items >= cap / read_input_per_item || keys >= cap / read_input_per_key) {
        return cap;
    }
    const std::uint64_t total =
        read_input_fixed + read_input_per_item * items + read_input_per_key * keys;
    return total < cap ? total : cap;
}

} // namespace cexchain::bo::runtime
