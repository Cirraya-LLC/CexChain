// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <string>

#include <cexchain/core/protocol/claims.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

constexpr std::array<std::string_view, 9> operators{">",  ">=",      "<",  "<=",    "=",
                                                    "!=", "between", "in", "exists"};
constexpr std::array<std::string_view, 4> types{"number", "money", "date", "text"};
constexpr std::size_t max_field = 64;
constexpr std::size_t max_text = 256;
constexpr std::size_t max_number_text = 40;

bool digits(std::string_view s) {
    return !s.empty() && std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; });
}

/// Any CBOR integer (-2^64 to 2^64 - 1) as decimal text.
std::optional<std::string> integer_text(const cbor::Value& v) {
    if (const auto u = v.as_uint64()) {
        return std::to_string(*u);
    }
    if (const auto n = v.as_negative()) {
        // -1 - n, with n up to 2^64 - 1: add one to n's digits.
        std::string digits_only = std::to_string(n->n);
        std::size_t i = digits_only.size();
        while (i > 0 && digits_only[i - 1] == '9') {
            digits_only[--i] = '0';
        }
        if (i == 0) {
            digits_only.insert(0, 1, '1');
        } else {
            ++digits_only[i - 1];
        }
        return "-" + digits_only;
    }
    return std::nullopt;
}

bool decimal_text(std::string_view s) {
    if (s.size() > max_number_text) {
        return false;
    }
    if (s.starts_with('-')) {
        s.remove_prefix(1);
    }
    const std::size_t dot = s.find('.');
    return digits(s.substr(0, dot)) && (dot == std::string_view::npos || digits(s.substr(dot + 1)));
}

bool valid_date(std::string_view s) {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-' || !digits(s.substr(0, 4)) ||
        !digits(s.substr(5, 2)) || !digits(s.substr(8, 2))) {
        return false;
    }
    const int year = std::stoi(std::string(s.substr(0, 4)));
    const int month = std::stoi(std::string(s.substr(5, 2)));
    const int day = std::stoi(std::string(s.substr(8, 2)));
    if (month < 1 || month > 12 || day < 1) {
        return false;
    }
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    constexpr std::array<int, 12> days{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const int last = days[static_cast<std::size_t>(month - 1)] + (month == 2 && leap ? 1 : 0);
    return day <= last;
}

/// A decimal in a form that compares exactly: its sign, its integer digits
/// without leading zeros, and its fraction's digits without trailing ones.
struct Decimal {
    bool negative = false;
    std::string whole;
    std::string fraction;
};

Decimal decimal_of(std::string_view text) {
    Decimal d;
    if (text.starts_with('-')) {
        d.negative = true;
        text.remove_prefix(1);
    }
    const std::size_t dot = text.find('.');
    d.whole = std::string(text.substr(0, dot));
    d.fraction = dot == std::string_view::npos ? std::string() : std::string(text.substr(dot + 1));
    d.whole.erase(0, std::min(d.whole.find_first_not_of('0'), d.whole.size()));
    while (!d.fraction.empty() && d.fraction.back() == '0') {
        d.fraction.pop_back();
    }
    if (d.whole.empty() && d.fraction.empty()) {
        d.negative = false; // -0 is 0
    }
    return d;
}

/// -1, 0, or 1.
int compare(const Decimal& a, const Decimal& b) {
    if (a.negative != b.negative) {
        return a.negative ? -1 : 1;
    }
    int magnitude = 0;
    if (a.whole.size() != b.whole.size()) {
        magnitude = a.whole.size() < b.whole.size() ? -1 : 1;
    } else if (const int c = a.whole.compare(b.whole); c != 0) {
        magnitude = c < 0 ? -1 : 1;
    } else {
        const std::size_t n = std::max(a.fraction.size(), b.fraction.size());
        std::string fa = a.fraction;
        std::string fb = b.fraction;
        fa.resize(n, '0');
        fb.resize(n, '0');
        const int f = fa.compare(fb);
        magnitude = f == 0 ? 0 : (f < 0 ? -1 : 1);
    }
    return a.negative ? -magnitude : magnitude;
}

/// The amount of a money value as decimal text: amount times 10^-scale.
std::string money_decimal(const std::string& amount, std::size_t scale) {
    std::string digits_only = amount.starts_with('-') ? amount.substr(1) : amount;
    while (digits_only.size() <= scale) {
        digits_only.insert(0, 1, '0');
    }
    const std::size_t split = digits_only.size() - scale;
    std::string out = (amount.starts_with('-') ? "-" : "") + digits_only.substr(0, split);
    if (scale > 0) {
        out += "." + digits_only.substr(split);
    }
    return out;
}

/// Whether `v` is a value of `type`.
bool of_type(const cbor::Value& v, std::string_view type) {
    if (type == "number") {
        const std::string* text = v.as_text();
        return integer_text(v).has_value() || (text != nullptr && decimal_text(*text));
    }
    if (type == "money") {
        const cbor::Array* parts = v.as_array();
        if (parts == nullptr || parts->size() != 3 || !integer_text((*parts)[0])) {
            return false;
        }
        const std::string* currency = (*parts)[1].as_text();
        const auto scale = (*parts)[2].as_uint64();
        return currency != nullptr && currency->size() == 3 &&
               std::ranges::all_of(*currency, [](char c) { return c >= 'A' && c <= 'Z'; }) &&
               scale && *scale <= 4;
    }
    const std::string* text = v.as_text();
    if (type == "date") {
        return text != nullptr && valid_date(*text);
    }
    return text != nullptr && !text->empty() && text->size() <= max_text;
}

/// A number's or money's amount as a Decimal (money: its currency too).
std::pair<Decimal, std::string> magnitude_of(const cbor::Value& v, std::string_view type) {
    if (type == "money") {
        const cbor::Array& parts = *v.as_array();
        return {decimal_of(money_decimal(*integer_text(parts[0]),
                                         static_cast<std::size_t>(*parts[2].as_uint64()))),
                *parts[1].as_text()};
    }
    return {decimal_of(integer_text(v) ? *integer_text(v) : *v.as_text()), std::string()};
}

/// Whether low is not above high (of a type that orders).
bool ordered(const cbor::Value& low, const cbor::Value& high, std::string_view type) {
    if (type == "date") {
        return *low.as_text() <= *high.as_text();
    }
    const auto [a, ca] = magnitude_of(low, type);
    const auto [b, cb] = magnitude_of(high, type);
    return ca == cb && compare(a, b) <= 0;
}

/// Whether two values of `type` are the same value: 1 and "1.0" are one
/// number, HKD 1 and HKD 1.00 one amount (spec section 6).
bool same_value(const cbor::Value& a, const cbor::Value& b, std::string_view type) {
    if (type == "number" || type == "money") {
        const auto [x, cx] = magnitude_of(a, type);
        const auto [y, cy] = magnitude_of(b, type);
        return cx == cy && compare(x, y) == 0;
    }
    return *a.as_text() == *b.as_text();
}

Status check_term(const ClaimTerm& t) {
    if (t.field.empty() || t.field.size() > max_field) {
        return fail(Errc::malformed, "a claim's term names a field of 1 to 64 bytes");
    }
    if (!std::ranges::contains(operators, std::string_view(t.op))) {
        return fail(Errc::malformed, "a claim's term has an unknown operator");
    }
    if (!std::ranges::contains(types, std::string_view(t.type))) {
        return fail(Errc::malformed, "a claim's term has an unknown type");
    }
    if (t.op == "exists") {
        if (t.type != "text" || !t.value.is_null()) {
            return fail(Errc::malformed, "\"exists\" is of type text, with a null value");
        }
        return {};
    }
    const bool orders = t.type != "text";
    if (t.op == "between") {
        const cbor::Array* pair = t.value.as_array();
        if (!orders || pair == nullptr || pair->size() != 2 || !of_type((*pair)[0], t.type) ||
            !of_type((*pair)[1], t.type) || !ordered((*pair)[0], (*pair)[1], t.type)) {
            return fail(Errc::malformed,
                        "\"between\" takes [low, high] of a number, money, or a date, "
                        "low not above high, in one currency");
        }
        return {};
    }
    if (t.op == "in") {
        const cbor::Array* list = t.value.as_array();
        if (list == nullptr || list->empty() || list->size() > max_claim_values) {
            return fail(Errc::malformed, "\"in\" takes 1 to 64 values");
        }
        for (std::size_t i = 0; i < list->size(); ++i) {
            if (!of_type((*list)[i], t.type)) {
                return fail(Errc::malformed, "\"in\" takes values of the term's type");
            }
            for (std::size_t j = 0; j < i; ++j) {
                if (same_value((*list)[j], (*list)[i], t.type)) {
                    return fail(Errc::malformed, "\"in\" takes distinct values");
                }
            }
        }
        return {};
    }
    if (!orders && t.op != "=" && t.op != "!=") {
        return fail(Errc::malformed, "text is compared with = and != only");
    }
    if (!of_type(t.value, t.type)) {
        return fail(Errc::malformed, "a claim's term has a value of another type");
    }
    return {};
}

std::string grouped(std::string digits_only) {
    std::string out;
    const std::size_t n = digits_only.size();
    for (std::size_t i = 0; i < n; ++i) {
        if (i > 0 && (n - i) % 3 == 0) {
            out.push_back(',');
        }
        out.push_back(digits_only[i]);
    }
    return out;
}

std::string value_text(const cbor::Value& v, std::string_view type) {
    if (type == "number") {
        return integer_text(v) ? *integer_text(v) : *v.as_text();
    }
    if (type == "money") {
        const cbor::Array& parts = *v.as_array();
        const std::string amount =
            money_decimal(*integer_text(parts[0]), static_cast<std::size_t>(*parts[2].as_uint64()));
        const bool negative = amount.starts_with('-');
        const std::string body = negative ? amount.substr(1) : amount;
        const std::size_t dot = body.find('.');
        return *parts[1].as_text() + " " + (negative ? "-" : "") + grouped(body.substr(0, dot)) +
               (dot == std::string::npos ? std::string() : body.substr(dot));
    }
    if (type == "date") {
        return *v.as_text();
    }
    return "\"" + *v.as_text() + "\"";
}

std::string term_text(const ClaimTerm& t) {
    const std::string field = t.field + " ";
    if (t.op == "exists") {
        return field + "is given";
    }
    if (t.op == "between") {
        const cbor::Array& pair = *t.value.as_array();
        return field + "is between " + value_text(pair[0], t.type) + " and " +
               value_text(pair[1], t.type);
    }
    if (t.op == "in") {
        std::string list;
        for (const cbor::Value& v : *t.value.as_array()) {
            list += (list.empty() ? "" : ", ") + value_text(v, t.type);
        }
        return field + "is one of " + list;
    }
    const std::string_view words = t.op == ">"    ? "is above "
                                   : t.op == ">=" ? "is at least "
                                   : t.op == "<"  ? "is below "
                                   : t.op == "<=" ? "is at most "
                                   : t.op == "="  ? "is "
                                                  : "is not ";
    return field + std::string(words) + value_text(t.value, t.type);
}

} // namespace

Result<std::vector<ClaimTerm>> decode_claim_condition(const cbor::Value& value) {
    const cbor::Array* terms = value.as_array();
    if (terms == nullptr || terms->empty() || terms->size() > max_claim_terms) {
        return fail(Errc::malformed, "a condition has 1 to 16 terms");
    }
    std::vector<ClaimTerm> out;
    for (const cbor::Value& item : *terms) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 4 || (*parts)[0].as_text() == nullptr ||
            (*parts)[1].as_text() == nullptr || (*parts)[2].as_text() == nullptr) {
            return fail(Errc::malformed, "a condition's term is [field, op, type, value]");
        }
        ClaimTerm t{*(*parts)[0].as_text(), *(*parts)[1].as_text(), *(*parts)[2].as_text(),
                    (*parts)[3]};
        if (auto s = check_term(t); !s) {
            return std::unexpected(s.error());
        }
        out.push_back(std::move(t));
    }
    return out;
}

cbor::Value encode_claim_condition(const std::vector<ClaimTerm>& condition) {
    cbor::Array terms;
    for (const ClaimTerm& t : condition) {
        terms.push_back(cbor::Value::array({cbor::Value::text(t.field), cbor::Value::text(t.op),
                                            cbor::Value::text(t.type), t.value}));
    }
    return cbor::Value::array(std::move(terms));
}

Result<Claim> decode_claim(const cbor::Value& metadata) {
    const cbor::Map* map = metadata.as_map();
    if (map == nullptr) {
        return fail(Errc::malformed, "a claim's metadata is a map");
    }
    constexpr std::array<std::string_view, 7> known{"source", "condition", "holds", "as_of",
                                                    "until",  "subject",   "for"};
    for (const cbor::MapEntry& e : *map) {
        const std::string* key = e.key.as_text();
        if (key == nullptr || !std::ranges::contains(known, std::string_view(*key))) {
            return fail(Errc::malformed, "a claim's metadata has an unknown key");
        }
    }
    const auto get = [&](std::string_view key) {
        return metadata.find(key);
    };
    Claim c;
    const cbor::Value* source = get("source");
    if (source == nullptr || source->as_bytes() == nullptr) {
        return fail(Errc::malformed, "a claim names its source");
    }
    CEXCHAIN_TRY(c.source, to_id(*source->as_bytes()));
    const cbor::Value* condition = get("condition");
    if (condition == nullptr) {
        return fail(Errc::malformed, "a claim's condition has 1 to 16 terms");
    }
    CEXCHAIN_TRY(c.condition, decode_claim_condition(*condition));
    const cbor::Value* holds = get("holds");
    const cbor::Value* as_of = get("as_of");
    if (holds == nullptr || !holds->as_bool() || as_of == nullptr || !as_of->as_uint64()) {
        return fail(Errc::malformed, "a claim says whether it holds, and as of when");
    }
    c.holds = *holds->as_bool();
    c.as_of = *as_of->as_uint64();
    if (const cbor::Value* until = get("until")) {
        if (!until->as_uint64() || *until->as_uint64() <= c.as_of) {
            return fail(Errc::malformed, "a claim's \"until\" comes after its \"as_of\"");
        }
        c.until = *until->as_uint64();
    }
    if (const cbor::Value* subject = get("subject")) {
        const std::string* text = subject->as_text();
        if (text == nullptr || text->empty() || text->size() > max_text) {
            return fail(Errc::malformed, "a claim's subject is 1 to 256 bytes");
        }
        c.subject = *text;
    }
    if (const cbor::Value* answers = get("for")) {
        const cbor::Array* pair = answers->as_array();
        if (pair == nullptr || pair->size() != 2 || (*pair)[0].as_bytes() == nullptr ||
            (*pair)[1].as_bytes() == nullptr) {
            return fail(Errc::malformed, "a claim's \"for\" is [ledger, record]");
        }
        Id ledger;
        Id record;
        CEXCHAIN_TRY(ledger, to_id(*(*pair)[0].as_bytes()));
        CEXCHAIN_TRY(record, to_id(*(*pair)[1].as_bytes()));
        c.answers = std::pair{ledger, record};
    }
    return c;
}

Result<cbor::Value> encode_claim(const Claim& claim) {
    cbor::Map map{
        {cbor::Value::text("source"), cbor::Value::bytes(claim.source.bytes())},
        {cbor::Value::text("condition"), encode_claim_condition(claim.condition)},
        {cbor::Value::text("holds"), cbor::Value::boolean(claim.holds)},
        {cbor::Value::text("as_of"), cbor::Value::unsigned_integer(claim.as_of)},
    };
    if (claim.until) {
        map.push_back({cbor::Value::text("until"), cbor::Value::unsigned_integer(*claim.until)});
    }
    if (claim.subject) {
        map.push_back({cbor::Value::text("subject"), cbor::Value::text(*claim.subject)});
    }
    if (claim.answers) {
        map.push_back({cbor::Value::text("for"),
                       cbor::Value::array({cbor::Value::bytes(claim.answers->first.bytes()),
                                           cbor::Value::bytes(claim.answers->second.bytes())})});
    }
    cbor::Value value = cbor::Value::map(std::move(map));
    if (auto checked = decode_claim(value); !checked) {
        return std::unexpected(checked.error());
    }
    return value;
}

std::string condition_text(const std::vector<ClaimTerm>& condition) {
    std::string out;
    for (const ClaimTerm& t : condition) {
        out += (out.empty() ? "" : " and ") + term_text(t);
    }
    return out;
}

std::string claim_text(const Claim& claim) {
    return condition_text(claim.condition);
}

std::optional<Id> claim_source(std::span<const Statement> events) {
    for (const Statement& s : events) {
        const auto* body = std::get_if<RecordRegisterBody>(&s.body);
        if (body != nullptr && body->record_type == claim_type && body->metadata) {
            if (auto claim = decode_claim(*body->metadata)) {
                return claim->source;
            }
        }
    }
    return std::nullopt;
}

} // namespace cexchain::protocol
