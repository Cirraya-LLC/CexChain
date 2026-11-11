// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <cexchain/client/claims.hpp>
#include <cexchain/client/errors.hpp>
#include <cexchain/client/support.hpp>
#include <cexchain/verifier/report.hpp>

namespace cexchain::client {

namespace {

using verifier::display_value;

using V = cbor::Value;

std::string trimmed(std::string_view text) {
    while (!text.empty() && text.front() == ' ') {
        text.remove_prefix(1);
    }
    while (!text.empty() && text.back() == ' ') {
        text.remove_suffix(1);
    }
    return std::string(text);
}

bool all_digits(std::string_view s) {
    return !s.empty() && std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; });
}

bool decimal(std::string_view s) {
    std::string_view rest = s.starts_with('-') ? s.substr(1) : s;
    const std::size_t dot = rest.find('.');
    return s.size() <= 40 && all_digits(rest.substr(0, dot)) &&
           (dot == std::string_view::npos || all_digits(rest.substr(dot + 1)));
}

bool date_like(std::string_view s) {
    return s.size() == 10 && s[4] == '-' && s[7] == '-' && all_digits(s.substr(0, 4)) &&
           all_digits(s.substr(5, 2)) && all_digits(s.substr(8, 2));
}

/// "HKD 30,000.00": its currency and its amount in units of 10^-scale.
std::optional<std::pair<std::string, std::string>> money_parts(std::string_view text) {
    const std::string t = trimmed(text);
    if (t.size() < 5 || t[3] != ' ' ||
        !std::ranges::all_of(t.substr(0, 3), [](char c) { return c >= 'A' && c <= 'Z'; })) {
        return std::nullopt;
    }
    std::string amount;
    for (const char c : t.substr(4)) {
        if (c != ',') {
            amount.push_back(c);
        }
    }
    if (!decimal(amount)) {
        return std::nullopt;
    }
    return std::pair{t.substr(0, 3), amount};
}

/// A literal of the condition as a claim's value: money ("HKD 30000.00"),
/// a date, a number, or text (quoted, or anything else).
std::pair<std::string, V> literal(std::string_view text) {
    const std::string t = trimmed(text);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"') {
        return {"text", V::text(t.substr(1, t.size() - 2))};
    }
    if (const auto money = money_parts(t)) {
        const auto& [currency, amount] = *money;
        const std::size_t dot = amount.find('.');
        const std::string fraction = dot == std::string::npos ? "" : amount.substr(dot + 1);
        if (fraction.size() > 4) {
            throw UsageError{"money has at most 4 decimals: " + t};
        }
        const std::string units = amount.substr(0, dot) + fraction;
        return {"money", V::array({V::integer(std::stoll(units)), V::text(currency),
                                   V::unsigned_integer(fraction.size())})};
    }
    if (date_like(t)) {
        return {"date", V::text(t)};
    }
    if (decimal(t)) {
        if (t.find('.') == std::string::npos && t.size() < 19) {
            return {"number", V::integer(std::stoll(t))};
        }
        return {"number", V::text(t)};
    }
    return {"text", V::text(t)};
}

/// One --if: FIELD OP VALUE, FIELD between LOW and HIGH, FIELD in A,B, or
/// FIELD exists.
protocol::ClaimTerm term_from(std::string_view field, std::string_view op, std::string_view typed) {
    const std::string t = std::string(field) + " " + std::string(op) + " " + std::string(typed);
    protocol::ClaimTerm term;
    term.field = std::string(field);
    term.op = std::string(op);
    const std::string value = trimmed(typed);
    if (term.op == "exists") {
        term.type = "text";
        term.value = V::null();
        return term;
    }
    if (term.op == "between") {
        const std::size_t sep = value.find(" and ");
        if (sep == std::string::npos) {
            throw UsageError{"FIELD between LOW and HIGH: " + t};
        }
        auto [low_type, low] = literal(value.substr(0, sep));
        auto [high_type, high] = literal(value.substr(sep + 5));
        if (low_type != high_type) {
            throw UsageError{"between's two values are of one type: " + t};
        }
        term.type = low_type;
        term.value = V::array({std::move(low), std::move(high)});
        return term;
    }
    if (term.op == "in") {
        cbor::Array list;
        for (const std::string& item : split(value, ',')) {
            auto [type, v] = literal(item);
            if (!term.type.empty() && term.type != type) {
                throw UsageError{"in's values are of one type: " + t};
            }
            term.type = type;
            list.push_back(std::move(v));
        }
        term.value = V::array(std::move(list));
        return term;
    }
    auto [type, v] = literal(value);
    term.type = type;
    term.value = std::move(v);
    return term;
}

protocol::ClaimTerm term_of(std::string_view text) {
    const std::string t = trimmed(text);
    const std::size_t space = t.find(' ');
    if (space == std::string::npos) {
        throw UsageError{"a condition is FIELD OP VALUE, such as 'age >= 18': " + t};
    }
    const std::string rest = trimmed(std::string_view(t).substr(space));
    const std::size_t op_end = rest.find(' ');
    return term_from(std::string_view(t).substr(0, space), std::string_view(rest).substr(0, op_end),
                     op_end == std::string::npos ? std::string_view()
                                                 : std::string_view(rest).substr(op_end));
}

/// -1, 0, 1 for two decimal texts.
int compare_decimal(std::string a, std::string b) {
    const auto parts = [](std::string s) {
        const bool negative = s.starts_with('-');
        if (negative) {
            s.erase(0, 1);
        }
        const std::size_t dot = s.find('.');
        std::string whole = s.substr(0, dot);
        std::string fraction = dot == std::string::npos ? "" : s.substr(dot + 1);
        whole.erase(0, std::min(whole.find_first_not_of('0'), whole.size()));
        while (!fraction.empty() && fraction.back() == '0') {
            fraction.pop_back();
        }
        return std::tuple{negative && !(whole.empty() && fraction.empty()), whole, fraction};
    };
    auto [na, wa, fa] = parts(std::move(a));
    auto [nb, wb, fb] = parts(std::move(b));
    if (na != nb) {
        return na ? -1 : 1;
    }
    int m = 0;
    if (wa.size() != wb.size()) {
        m = wa.size() < wb.size() ? -1 : 1;
    } else if (wa != wb) {
        m = wa < wb ? -1 : 1;
    } else {
        const std::size_t n = std::max(fa.size(), fb.size());
        fa.resize(n, '0');
        fb.resize(n, '0');
        m = fa == fb ? 0 : (fa < fb ? -1 : 1);
    }
    return na ? -m : m;
}

std::string decimal_of(const V& v) {
    if (const auto u = v.as_uint64()) {
        return std::to_string(*u);
    }
    if (const auto i = v.as_int64()) {
        return std::to_string(*i);
    }
    return *v.as_text();
}

/// A money value as [currency, decimal amount].
std::pair<std::string, std::string> money_of(const V& v) {
    const cbor::Array& parts = *v.as_array();
    std::string amount = decimal_of(parts[0]);
    const bool negative = amount.starts_with('-');
    std::string digits_only = negative ? amount.substr(1) : amount;
    const std::size_t scale = static_cast<std::size_t>(*parts[2].as_uint64());
    while (digits_only.size() <= scale) {
        digits_only.insert(0, 1, '0');
    }
    std::string text = digits_only.substr(0, digits_only.size() - scale);
    if (scale > 0) {
        text += "." + digits_only.substr(digits_only.size() - scale);
    }
    return {*parts[1].as_text(), (negative ? "-" : "") + text};
}

/// What the source's field holds, read as the term's type; nothing if it
/// cannot be (the condition then does not hold).
std::optional<std::string> field_as(const V& value, const std::string& type,
                                    const std::string& currency) {
    const std::string text = value.as_text() != nullptr              ? trimmed(*value.as_text())
                             : value.as_int64() || value.as_uint64() ? decimal_of(value)
                                                                     : std::string();
    if (type == "text") {
        return value.as_text() != nullptr ? std::optional(*value.as_text()) : std::nullopt;
    }
    if (type == "date") {
        return date_like(text) ? std::optional(text) : std::nullopt;
    }
    if (type == "money") {
        // "HKD 32,000.50", or a bare amount taken in the condition's currency.
        if (const auto money = money_parts(text)) {
            return money->first == currency ? std::optional(money->second) : std::nullopt;
        }
        std::string amount;
        for (const char c : text) {
            if (c != ',') {
                amount.push_back(c);
            }
        }
        return decimal(amount) ? std::optional(amount) : std::nullopt;
    }
    std::string number;
    for (const char c : text) {
        if (c != ',') {
            number.push_back(c);
        }
    }
    return decimal(number) ? std::optional(number) : std::nullopt;
}

/// Whether `term` holds of the record's private data; `seen` gets the value
/// it read.
bool holds(const protocol::ClaimTerm& term, const std::vector<protocol::RecordField>& fields,
           std::vector<std::pair<std::string, std::string>>& seen) {
    const auto field = std::ranges::find(fields, term.field, &protocol::RecordField::name);
    if (term.op == "exists") {
        return field != fields.end();
    }
    if (field == fields.end()) {
        return false;
    }
    seen.emplace_back(term.field, display_value(field->value));
    const auto compare_with = [&](const V& literal) -> std::optional<int> {
        std::string currency;
        std::string wanted;
        if (term.type == "money") {
            std::tie(currency, wanted) = money_of(literal);
        } else {
            wanted = term.type == "number" ? decimal_of(literal) : *literal.as_text();
        }
        const auto have = field_as(field->value, term.type, currency);
        if (!have) {
            return std::nullopt;
        }
        if (term.type == "number" || term.type == "money") {
            return compare_decimal(*have, wanted);
        }
        return *have == wanted ? 0 : (*have < wanted ? -1 : 1);
    };
    if (term.op == "between") {
        const auto low = compare_with((*term.value.as_array())[0]);
        const auto high = compare_with((*term.value.as_array())[1]);
        return low && high && *low >= 0 && *high <= 0;
    }
    if (term.op == "in") {
        return std::ranges::any_of(*term.value.as_array(), [&](const V& v) {
            const auto c = compare_with(v);
            return c && *c == 0;
        });
    }
    const auto c = compare_with(term.value);
    if (!c) {
        return false;
    }
    return term.op == ">"    ? *c > 0
           : term.op == ">=" ? *c >= 0
           : term.op == "<"  ? *c < 0
           : term.op == "<=" ? *c <= 0
           : term.op == "="  ? *c == 0
                             : *c != 0;
}

} // namespace

protocol::ClaimTerm parse_claim_term(std::string_view text) {
    return term_of(text);
}

protocol::ClaimTerm parse_claim_term(std::string_view field, std::string_view op,
                                     std::string_view value) {
    return term_from(field, op, value);
}

ClaimCheck check_claim(const protocol::Claim& claim,
                       const std::vector<protocol::RecordField>& fields) {
    ClaimCheck out;
    std::vector<std::pair<std::string, std::string>> seen;
    out.holds = std::ranges::all_of(
        claim.condition, [&](const protocol::ClaimTerm& t) { return holds(t, fields, seen); });
    for (const auto& [name, value] : seen) {
        if (std::ranges::find(out.basis, "basis." + name,
                              &std::pair<std::string, std::string>::first) == out.basis.end()) {
            out.basis.emplace_back("basis." + name, value);
        }
    }
    if (out.basis.empty()) {
        out.basis.emplace_back("basis", "the fields named exist");
    }
    return out;
}

std::string claim_status(const protocol::LedgerState& state,
                         const protocol::RecordState& claim_record, const protocol::Claim& claim,
                         protocol::Timestamp now) {
    const protocol::RecordState* source = state.record(claim.source);
    return claim_record.revoked                ? "withdrawn"
           : source == nullptr                 ? "unknown"
           : source->revoked                   ? "source revoked"
           : source->superseded_by             ? "source replaced"
           : claim.until && now > *claim.until ? "lapsed"
                                               : "standing";
}

} // namespace cexchain::client
