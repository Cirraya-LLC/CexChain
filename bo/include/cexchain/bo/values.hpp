// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/model.hpp>

/// Bo's values as compiled code keeps them, shared by the checker (which
/// checks that every literal is exact) and lowering (which writes the same
/// numbers into the code). Every value is a signed 64-bit integer of its
/// smallest unit: money in cents, quantities in base units (bytes, bits per
/// second, items, grams), rates in millionths, dates in milliseconds since
/// the epoch, durations in milliseconds (days, weeks) or in months (months,
/// years). Nothing here uses floating point.
namespace cexchain::bo {

/// A unit of a quantity, and how many base units it holds.
struct UnitInfo {
    std::string_view id;
    model::Dimension dimension;
    std::uint64_t factor;
};

/// The unit's entry, or null for a concept that is no unit of edition 1.
[[nodiscard]] const UnitInfo* unit_info(const Concept* unit) noexcept;

/// The largest value Bo keeps.
inline constexpr std::uint64_t max_value = std::numeric_limits<std::int64_t>::max();
/// Every edition-1 currency has cents: two decimal places.
inline constexpr std::uint64_t money_factor = 100;
/// Unit prices keep six decimal places (U5).
inline constexpr std::uint64_t unit_price_factor = 1'000'000;
/// Rates are kept in millionths; a percent is 10,000 of them.
inline constexpr std::uint64_t rate_factor = 10'000;
/// 100%, in millionths.
inline constexpr std::int64_t rate_one = 1'000'000;
inline constexpr std::uint64_t day_ms = 86'400'000;
/// Calendar durations are counted in months; ten thousand years at most.
inline constexpr std::uint64_t max_months = 120'000;
/// The contract's offset from UTC (U6), in milliseconds east, when it names
/// none (R25): +08:00. A contract names another with `UTC offset "-05:00"`.
inline constexpr std::int64_t default_offset_ms = 8 * 3'600'000;

struct Exact {
    bool whole = false;
    bool fits = false;
    std::uint64_t value = 0;
};

/// `value` × `factor`, exactly: whole if it is a whole number, and fits if
/// it is at most max_value. Without floating point or a 128-bit type.
[[nodiscard]] Exact exact(const Decimal& value, std::uint64_t factor) noexcept;

/// A literal's value in its smallest unit, as compiled code keeps it (dates
/// at local midnight under the contract's offset, milliseconds east);
/// nullopt for a text, or for a value that is not exact or does not fit (the
/// checker reports those).
[[nodiscard]] std::optional<std::int64_t>
literal_value(const ast::Literal& literal, std::int64_t offset_ms = default_offset_ms) noexcept;

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
[[nodiscard]] std::int64_t days_from_civil(std::int64_t year, std::int64_t month,
                                           std::int64_t day) noexcept;

/// The name compiled code uses for a concept or a name, the same in every
/// language: a name as written; a concept's id without its category
/// (act.pledge is "pledge", field.amount "amount", role.we "we").
[[nodiscard]] std::string wire_name(const Concept* word, const std::string& name);

} // namespace cexchain::bo
