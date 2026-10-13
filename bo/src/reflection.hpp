// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Static reflection helpers (C++26, P2996) shared by cexchain::bo's sources.
// Never included by the front end, which Clang builds.

#pragma once

#include <array>
#include <cstddef>
#include <meta>
#include <string_view>

namespace cexchain::bo::detail {

/// True if `table` lists E's enumerators' identifiers, in order, and the
/// enumerators are 0, 1, 2, ...
template <class E, std::size_t N>
consteval bool table_matches(const std::array<std::string_view, N>& table) {
    const auto enumerators = std::meta::enumerators_of(^^E);
    if (enumerators.size() != N) {
        return false;
    }
    for (std::size_t i = 0; i < N; ++i) {
        if (std::meta::identifier_of(enumerators[i]) != table[i] ||
            static_cast<std::size_t>(std::meta::extract<E>(enumerators[i])) != i) {
            return false;
        }
    }
    return true;
}

/// The number of E's enumerators.
template <class E>
consteval std::size_t enumerator_count() {
    return std::meta::enumerators_of(^^E).size();
}

/// An enumerator's identifier, or empty for a value that is none.
template <class E>
constexpr std::string_view enumerator_name(const E value) noexcept {
    template for (constexpr auto e : std::define_static_array(std::meta::enumerators_of(^^E))) {
        if (value == [:e:]) {
            return std::meta::identifier_of(e);
        }
    }
    return {};
}

} // namespace cexchain::bo::detail
