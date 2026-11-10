// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Claims (spec v0.14): the issuer confirms that, in one of its records, a
// condition on fields holds, without disclosing them. The condition is
// checked here against the record's private data, and a claim that it does
// not hold is issued only on purpose (--allow-no), so that asking reveals
// nothing more than silence.

#include <algorithm>
#include <optional>
#include <print>
#include <string>
#include <tuple>
#include <vector>

#include <cexchain/core/protocol/claims.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/ledger/environment.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

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
protocol::ClaimTerm term_of(const std::string& text) {
    const std::string t = trimmed(text);
    const std::size_t space = t.find(' ');
    if (space == std::string::npos) {
        throw UsageError{"--if FIELD OP VALUE, such as 'age >= 18': " + t};
    }
    protocol::ClaimTerm term;
    term.field = t.substr(0, space);
    std::string rest = trimmed(std::string_view(t).substr(space));
    const std::size_t op_end = rest.find(' ');
    term.op = rest.substr(0, op_end);
    const std::string value = op_end == std::string::npos ? "" : trimmed(rest.substr(op_end));
    if (term.op == "exists") {
        term.type = "text";
        term.value = V::null();
        return term;
    }
    if (term.op == "between") {
        const std::size_t sep = value.find(" and ");
        if (sep == std::string::npos) {
            throw UsageError{"--if FIELD between LOW and HIGH: " + t};
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
bool holds(const protocol::ClaimTerm& term, const Vault& vault,
           std::vector<std::pair<std::string, std::string>>& seen) {
    const auto field = std::ranges::find(vault.fields, term.field, &protocol::RecordField::name);
    if (term.op == "exists") {
        return field != vault.fields.end();
    }
    if (field == vault.fields.end()) {
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

/// The claims on the ledger: records of the type, with their metadata.
struct Listed {
    const protocol::RecordState* record;
    protocol::Claim claim;
};

std::vector<Listed> claims(const client::Session& session) {
    std::vector<Listed> out;
    for (const auto& [key, record] : session.state().records()) {
        if (record.record_type != protocol::claim_type) {
            continue;
        }
        const auto body = client::registration_of(session, protocol::Id(record.id));
        if (auto claim = body.metadata ? protocol::decode_claim(*body.metadata)
                                       : Result<protocol::Claim>(fail(Errc::malformed, "none"))) {
            out.push_back({&record, std::move(*claim)});
        }
    }
    return out;
}

Json claim_json(const client::Session& session, const Listed& c) {
    const protocol::RecordState* source = session.state().record(c.claim.source);
    const std::string status = c.record->revoked       ? "withdrawn"
                               : source == nullptr     ? "unknown"
                               : source->revoked       ? "source revoked"
                               : source->superseded_by ? "source replaced"
                               : c.claim.until && ledger::SystemClock().now() > *c.claim.until
                                   ? "lapsed"
                                   : "standing";
    return {{"claim", id_json(protocol::Id(c.record->id))},
            {"source", id_json(c.claim.source)},
            {"source_type", source != nullptr ? Json(source->record_type) : Json(nullptr)},
            {"text", protocol::claim_text(c.claim)},
            {"holds", c.claim.holds},
            {"subject", c.claim.subject ? Json(*c.claim.subject) : Json(nullptr)},
            {"as_of", format_time(c.claim.as_of)},
            {"until", c.claim.until ? Json(format_time(*c.claim.until)) : Json(nullptr)},
            {"status", status}};
}

} // namespace

int cmd_claim_issue(const Args& args) {
    Session session(args);
    const protocol::Id source = session.record_id(args.positional().front());
    protocol::Claim claim;
    claim.source = source;
    for (const std::string& condition : args.all("if")) {
        claim.condition.push_back(term_of(condition));
    }
    if (claim.condition.empty()) {
        throw UsageError{"say what to confirm: --if 'FIELD OP VALUE'"};
    }
    claim.subject = args.get("subject");
    claim.as_of = ledger::SystemClock().now();
    if (const auto until = args.get("until")) {
        claim.until = parse_time(*until);
    }
    // A condition of the right shape first, then checked against the
    // source's private data.
    if (const auto shaped = encode_claim(claim); !shaped) {
        throw UsageError{std::string(shaped.error().detail)};
    }
    const Vault vault = read_vault(session, source, args);
    std::vector<std::pair<std::string, std::string>> seen;
    claim.holds = std::ranges::all_of(
        claim.condition, [&](const protocol::ClaimTerm& t) { return holds(t, vault, seen); });
    if (!claim.holds && !args.has("allow-no")) {
        throw CommandError{"the condition does not hold: no claim is issued (--allow-no issues "
                           "one that says so)"};
    }
    const auto metadata = encode_claim(claim);
    if (!metadata) {
        throw UsageError{std::string(metadata.error().detail)};
    }
    // The claim's own fields, sealed: the values it was checked against.
    IssueRequest request;
    request.record_type = std::string(protocol::claim_type);
    request.metadata_value = *metadata;
    for (const auto& [name, value] : seen) {
        if (std::ranges::find(request.fields, "basis." + name,
                              &std::pair<std::string, std::string>::first) ==
            request.fields.end()) {
            request.fields.emplace_back("basis." + name, value);
        }
    }
    if (request.fields.empty()) {
        request.fields.emplace_back("basis", "the fields named exist");
    }
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id id = issue_record(session, *load_signer(args.need("as"), args), request);
    return report_submitted(
        args, session, id,
        {{"claim", id_json(id)}, {"text", protocol::claim_text(claim)}, {"holds", claim.holds}},
        std::format("issued claim {}: {} {}", hex_id(id),
                    claim.holds ? "holds:" : "does NOT hold:", protocol::claim_text(claim)));
}

int cmd_claim_list(const Args& args) {
    Session session(args);
    const auto of = args.get("source");
    const std::optional<protocol::Id> source =
        of ? std::optional(session.record_id(*of)) : std::nullopt;
    Json out = Json::array();
    for (const Listed& c : claims(session)) {
        if (source && c.claim.source != *source) {
            continue;
        }
        const Json j = claim_json(session, c);
        if (args.json()) {
            out.push_back(j);
            continue;
        }
        std::println("{}  {:<16} {}{}", short_id(protocol::Id(c.record->id)),
                     j["status"].get<std::string>(),
                     c.claim.holds ? "" : "NOT: ", protocol::claim_text(c.claim));
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_claim_show(const Args& args) {
    Session session(args);
    const protocol::Id id = session.record_id(args.positional().front());
    const auto all = claims(session);
    const auto found = std::ranges::find_if(
        all, [&](const Listed& c) { return protocol::Id(c.record->id) == id; });
    if (found == all.end()) {
        throw CommandError{"no claim " + hex_id(id)};
    }
    const Json j = claim_json(session, *found);
    if (args.json()) {
        print_json(j);
        return exit_ok;
    }
    std::println("claim:    {}", hex_id(id));
    std::println("{}:    {}", found->claim.holds ? "holds" : "NOT  ",
                 protocol::claim_text(found->claim));
    if (found->claim.subject) {
        std::println("subject:  {}", *found->claim.subject);
    }
    std::println("as of:    {}{}", format_time(found->claim.as_of),
                 found->claim.until ? ", until " + format_time(*found->claim.until)
                                    : std::string());
    std::println("source:   {} ({})", hex_id(found->claim.source),
                 j["source_type"].is_null() ? "unknown" : j["source_type"].get<std::string>());
    std::println("status:   {}", j["status"].get<std::string>());
    return exit_ok;
}

int cmd_claim_revoke(const Args& args) {
    Session session(args);
    const protocol::Id id = session.record_id(args.positional().front());
    const protocol::RecordState* record = session.state().record(id);
    if (record == nullptr || record->record_type != protocol::claim_type) {
        throw CommandError{"no claim " + hex_id(id)};
    }
    const protocol::Id revoked =
        session.submit(args, protocol::RecordRevokeBody{id, args.get("reason")});
    return report_submitted(args, session, revoked, {{"claim", id_json(id)}},
                            "withdrew claim " + hex_id(id));
}

} // namespace cexchain::cli
