// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Bo's values in their smallest units (values.hpp).

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <numeric>
#include <optional>
#include <string>

#include <cexchain/bo/values.hpp>
#include <cexchain/bo/vocab.hpp>

namespace cexchain::bo {

namespace {

using model::Dimension;

constexpr UnitInfo unit_table[] = {
    {"unit.MB", Dimension::data, 1'000'000},
    {"unit.GB", Dimension::data, 1'000'000'000},
    {"unit.TB", Dimension::data, 1'000'000'000'000},
    {"unit.MiB", Dimension::data, std::uint64_t{1} << 20U},
    {"unit.GiB", Dimension::data, std::uint64_t{1} << 30U},
    {"unit.TiB", Dimension::data, std::uint64_t{1} << 40U},
    {"unit.Mbps", Dimension::bandwidth, 1'000'000},
    {"unit.Gbps", Dimension::bandwidth, 1'000'000'000},
    {"unit.item", Dimension::count, 1},
    {"unit.kg", Dimension::mass, 1'000},
    {"unit.tonne", Dimension::mass, 1'000'000},
    // A temperature in hundredths of a degree Celsius (G5b): 4.5 °C is 450.
    {"unit.celsius", Dimension::temperature, 100},
};

bool is(const Concept* c, std::string_view id) noexcept {
    return c != nullptr && c->id == id;
}

std::optional<std::int64_t> scaled(const Decimal& value, std::uint64_t factor) noexcept {
    const Exact x = exact(value, factor);
    if (!x.whole || !x.fits) {
        return std::nullopt;
    }
    // At most 2^63 - 1, so its negation fits too.
    const auto magnitude = static_cast<std::int64_t>(x.value);
    return value.negative ? -magnitude : magnitude;
}

} // namespace

const UnitInfo* unit_info(const Concept* unit) noexcept {
    if (unit == nullptr) {
        return nullptr;
    }
    const auto it = std::ranges::find(unit_table, unit->id, &UnitInfo::id);
    if (it != std::end(unit_table)) {
        return &*it;
    }
    // A unit of a user's vocabulary pack, of one of the core's dimensions.
    return unit->owner != nullptr ? unit->owner->unit(unit) : nullptr;
}

Exact exact(const Decimal& value, std::uint64_t factor) noexcept {
    std::uint64_t power = 1;
    for (std::uint8_t i = 0; i < value.scale; ++i) {
        power *= 10;
    }
    const std::uint64_t common = std::gcd(factor, power);
    const std::uint64_t multiply = factor / common;
    const std::uint64_t divide = power / common;
    Exact out;
    if (value.digits % divide != 0) {
        return out;
    }
    out.whole = true;
    std::uint64_t product = 0;
    if (__builtin_mul_overflow(value.digits / divide, multiply, &product) || product > max_value) {
        return out;
    }
    out.fits = true;
    out.value = product;
    return out;
}

std::int64_t days_from_civil(std::int64_t year, const std::int64_t month,
                             const std::int64_t day) noexcept {
    // Howard Hinnant's algorithm, as the runtime's days_from_civil.
    year -= month <= 2 ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const std::int64_t yoe = year - era * 400;
    const std::int64_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146'097 + doe - 719'468;
}

std::optional<std::int64_t> literal_value(const ast::Literal& l,
                                          const std::int64_t offset_ms) noexcept {
    switch (l.kind) {
    case ast::LiteralKind::number:
        return scaled(l.number, 1);
    case ast::LiteralKind::money:
        return scaled(l.number, money_factor);
    case ast::LiteralKind::quantity: {
        const UnitInfo* unit = unit_info(l.unit);
        return unit == nullptr ? std::nullopt : scaled(l.number, unit->factor);
    }
    case ast::LiteralKind::duration: {
        const bool calendar = is(l.unit, "time.month") || is(l.unit, "time.year");
        if (!scaled(l.number, 1)) {
            return std::nullopt;
        }
        const std::uint64_t factor = is(l.unit, "time.week")   ? 7 * day_ms
                                     : is(l.unit, "time.day")  ? day_ms
                                     : is(l.unit, "time.year") ? 12
                                                               : 1;
        const std::optional<std::int64_t> value = scaled(l.number, factor);
        if (!value ||
            (calendar && (*value < 0 ? 0 - static_cast<std::uint64_t>(*value)
                                     : static_cast<std::uint64_t>(*value)) > max_months)) {
            return std::nullopt;
        }
        return value;
    }
    case ast::LiteralKind::rate:
        return scaled(l.number, rate_factor);
    case ast::LiteralKind::date: {
        const std::int64_t y = l.date.year;
        const std::int64_t m = l.date.month;
        if (y < 1 || y > 9999 || m < 1 || m > 12 || l.date.day < 1) {
            return std::nullopt;
        }
        const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        constexpr std::int64_t lengths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        if (l.date.day > lengths[m - 1] + (m == 2 && leap ? 1 : 0)) {
            return std::nullopt;
        }
        return days_from_civil(y, m, l.date.day) * static_cast<std::int64_t>(day_ms) - offset_ms;
    }
    case ast::LiteralKind::text:
        return std::nullopt;
    }
    return std::nullopt;
}

std::string wire_name(const Concept* word, const std::string& name) {
    if (word == nullptr) {
        return name;
    }
    const std::size_t dot = word->id.find('.');
    return std::string(dot == std::string_view::npos ? word->id : word->id.substr(dot + 1));
}

} // namespace cexchain::bo
