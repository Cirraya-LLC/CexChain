// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The contract text (explain.hpp): a checked model written out in one
// language, from the sentences of that language's pack. Nothing here reads a
// place or a spelling of the source, so a contract gives the same text
// through any spelling of it; whatever compiled code decides (the final
// states, the numbering of requirements, the amount `over` compares, the
// creation function's name) comes from model.hpp's shared functions, which
// lowering uses too.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/bo/vocab.hpp>

namespace cexchain::bo {

namespace {

namespace m = model;
using ast::ExprKind;
using ast::LiteralKind;
using ast::Operator;
using m::Refers;
using m::TypeKind;

template <class... F>
struct Overloaded : F... {
    using F::operator()...;
};

bool is(const Concept* c, std::string_view id) noexcept {
    return c != nullptr && c->id == id;
}

// --- Characters. Languages written without spaces between words (Chinese)
// still set Latin words and numbers apart: where a value meets a Chinese
// character at a placeholder's edge, a space goes between them ("名為 Terms",
// "港元 120"). Names and texts themselves are never changed.

char32_t point_at(std::string_view text, std::size_t i) noexcept {
    const auto lead = static_cast<unsigned char>(text[i]);
    if (lead < 0x80) {
        return lead;
    }
    std::size_t more = 1;
    if (lead >= 0xF0) {
        more = 3;
    } else if (lead >= 0xE0) {
        more = 2;
    }
    char32_t c = lead & (0x3FU >> more);
    for (std::size_t k = 1; k <= more && i + k < text.size(); ++k) {
        c = (c << 6U) | (static_cast<unsigned char>(text[i + k]) & 0x3FU);
    }
    return c;
}

char32_t first_point(std::string_view text) noexcept {
    return text.empty() ? 0 : point_at(text, 0);
}

char32_t last_point(std::string_view text) noexcept {
    if (text.empty()) {
        return 0;
    }
    std::size_t i = text.size() - 1;
    while (i > 0 && (static_cast<unsigned char>(text[i]) & 0xC0U) == 0x80U) {
        --i;
    }
    return point_at(text, i);
}

/// Han characters, kana, and Hangul: written without spaces.
bool is_wide(char32_t c) noexcept {
    return (c >= 0x3040 && c <= 0x30FF) || (c >= 0x3400 && c <= 0x4DBF) ||
           (c >= 0x4E00 && c <= 0x9FFF) || (c >= 0xAC00 && c <= 0xD7AF) ||
           (c >= 0xF900 && c <= 0xFAFF) || (c >= 0x20000 && c <= 0x3FFFF);
}

/// Latin, Greek, and Cyrillic letters, digits, and the percent sign.
bool is_narrow(char32_t c) noexcept {
    return (c >= U'0' && c <= U'9') || (c >= U'A' && c <= U'Z') || (c >= U'a' && c <= U'z') ||
           c == U'%' || (c >= 0xC0 && c <= 0x24F) || (c >= 0x370 && c <= 0x4FF);
}

bool needs_space(char32_t a, char32_t b) noexcept {
    return (is_narrow(a) && is_wide(b)) || (is_wide(a) && is_narrow(b));
}

/// The number as written, its whole part grouped by thousands: "5,000,000",
/// "0.10".
std::string grouped(std::string_view text) {
    const std::size_t dot = text.find('.');
    const std::string_view whole = text.substr(0, dot);
    std::string out;
    for (std::size_t i = 0; i < whole.size(); ++i) {
        if (i > 0 && (whole.size() - i) % 3 == 0) {
            out += ',';
        }
        out += whole[i];
    }
    if (dot != std::string_view::npos) {
        out += text.substr(dot);
    }
    return out;
}

/// True if the decimal is exactly 1 (1, 1.0, 1.00).
bool is_one(const Decimal& d) noexcept {
    std::uint64_t ten = 1;
    for (std::uint8_t i = 0; i < d.scale; ++i) {
        ten *= 10;
    }
    return d.digits == ten;
}

/// A whole number of `factor`ths (factor a power of ten) as a decimal,
/// trailing zeros dropped down to `keep` places: 25000000/100 is
/// "250,000.00" with keep 2.
std::string scaled(std::int64_t value, std::uint64_t factor, std::size_t keep) {
    const bool negative = value < 0;
    const std::uint64_t magnitude = negative ? std::uint64_t{0} - static_cast<std::uint64_t>(value)
                                             : static_cast<std::uint64_t>(value);
    std::string fraction;
    std::uint64_t places = 0;
    for (std::uint64_t f = factor; f > 1; f /= 10) {
        ++places;
    }
    std::uint64_t rest = factor > 0 ? magnitude % factor : 0;
    for (std::uint64_t i = 0; i < places; ++i) {
        fraction.insert(fraction.begin(), static_cast<char>('0' + rest % 10));
        rest /= 10;
    }
    while (fraction.size() > keep && fraction.back() == '0') {
        fraction.pop_back();
    }
    std::string out = grouped(std::to_string(factor > 0 ? magnitude / factor : magnitude));
    if (!fraction.empty()) {
        out += "." + fraction;
    }
    return negative ? "-" + out : out;
}

/// Beyond any date compiled code keeps (years 1 to 9999), in milliseconds.
constexpr std::int64_t max_date_ms = 400'000'000'000'000;

/// A date of the proleptic Gregorian calendar from days since 1970-01-01
/// (Howard Hinnant's algorithm), as compiled code computes it.
Date civil_from_days(std::int64_t days) noexcept {
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const std::int64_t doe = days - era * 146097;
    const std::int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const std::int64_t mp = (5 * doy + 2) / 153;
    const std::int64_t day = doy - (153 * mp + 2) / 5 + 1;
    const std::int64_t month = mp < 10 ? mp + 3 : mp - 9;
    const std::int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);
    Date d;
    d.year = static_cast<std::uint16_t>(std::clamp<std::int64_t>(year, 0, 65535));
    d.month = static_cast<std::uint8_t>(month);
    d.day = static_cast<std::uint8_t>(day);
    return d;
}

// --- Rules, in the order of their ids.

std::size_t rule_rank(std::string_view id) noexcept {
    const auto all = rule_specs();
    for (std::size_t i = 0; i < all.size(); ++i) {
        if (all[i].id == id) {
            return i;
        }
    }
    return all.size();
}

struct RuleLess {
    bool operator()(std::string_view a, std::string_view b) const noexcept {
        const std::size_t ra = rule_rank(a);
        const std::size_t rb = rule_rank(b);
        return ra != rb ? ra < rb : a < b;
    }
};

using Rules = std::set<std::string_view, RuleLess>;

void note(Rules& rules, std::string_view rule) {
    if (!rule.empty()) {
        rules.insert(rule);
    }
}

// --- Sentences.

/// A placeholder's value: its text, and the word it spells, whose forms a
/// sentence may ask for ("{party.object}": "us" for we).
struct Phrase {
    std::string text;
    const Word* word = nullptr;
};

using Values = std::vector<std::pair<std::string_view, Phrase>>;

Phrase plain(std::string text) {
    return Phrase{std::move(text), nullptr};
}

class Writer {
public:
    explicit Writer(const Pack* language)
        : pack_(language != nullptr ? language : &english_pack()),
          spaced_(pack_->reading.separation == Separation::spaces) {}

    [[nodiscard]] const Pack& pack() const noexcept { return *pack_; }

    /// A sentence of the pack (else the English pack's), its placeholders
    /// filled, forms included.
    [[nodiscard]] std::string say(std::string_view id, const Values& values = {}) const {
        const std::string* pattern = find(id);
        if (pattern == nullptr) {
            return std::string(id);
        }
        std::string out;
        bool after_value = false;
        const auto glue = [&](std::string_view piece, bool value) {
            if (piece.empty()) {
                return;
            }
            if (!spaced_ && (value || after_value) && !out.empty() &&
                needs_space(last_point(out), first_point(piece))) {
                out += ' ';
            }
            out += piece;
            after_value = value;
        };
        std::string_view rest = *pattern;
        while (!rest.empty()) {
            const std::size_t open = rest.find('{');
            const std::size_t close = open == std::string_view::npos ? open : rest.find('}', open);
            if (close == std::string_view::npos) {
                glue(rest, false);
                break;
            }
            glue(rest.substr(0, open), false);
            const std::string_view inside = rest.substr(open + 1, close - open - 1);
            const std::size_t dot = inside.find('.');
            const std::string_view name = inside.substr(0, dot);
            const std::string_view form =
                dot == std::string_view::npos ? std::string_view{} : inside.substr(dot + 1);
            const auto found = std::ranges::find(values, name, &Values::value_type::first);
            if (found == values.end()) {
                glue(rest.substr(open, close - open + 1), false);
            } else {
                glue(form_of(found->second, form), true);
            }
            rest.remove_prefix(close + 1);
        }
        return out;
    }

    /// A concept's word in the language (else in English), with its forms.
    [[nodiscard]] Phrase word(const Concept* c) const {
        if (c == nullptr) {
            return {};
        }
        for (const Pack* pack : {pack_, &english_pack()}) {
            if (const Word* w = pack->word(c->id); w != nullptr && !w->spellings.empty()) {
                return Phrase{w->spellings.front(), w};
            }
        }
        return plain(std::string(c->id));
    }

    /// A word in the form a sentence would ask for, else as spelled.
    [[nodiscard]] std::string form(const Concept* c, std::string_view name) const {
        return std::string(form_of(word(c), name));
    }

    /// Items joined: "a and b", "a, b, and c" (or "or").
    [[nodiscard]] std::string join(const std::vector<std::string>& items, bool all) const {
        if (items.empty()) {
            return {};
        }
        if (items.size() == 1) {
            return items.front();
        }
        std::string rest;
        const std::string separator = say("list-separator");
        for (std::size_t i = 0; i + 1 < items.size(); ++i) {
            rest += (i == 0 ? "" : separator) + items[i];
        }
        const std::string_view id = items.size() == 2 ? (all ? "list-and" : "list-or")
                                                      : (all ? "list-and-many" : "list-or-many");
        return say(id, {{"rest", plain(rest)}, {"last", plain(items.back())}});
    }

    /// Parts of one value or one list of items: "a; b".
    [[nodiscard]] std::string parts(const std::vector<std::string>& items) const {
        std::string out;
        const std::string separator = say("value-separator");
        for (std::size_t i = 0; i < items.size(); ++i) {
            out += (i == 0 ? "" : separator) + items[i];
        }
        return out;
    }

    /// Words side by side: separated by spaces, or, in a language written
    /// without them, only where Latin meets Chinese.
    [[nodiscard]] std::string words(const std::vector<std::string>& items) const {
        std::string out;
        for (const std::string& item : items) {
            if (item.empty()) {
                continue;
            }
            if (!out.empty() && (spaced_ || needs_space(last_point(out), first_point(item)))) {
                out += ' ';
            }
            out += item;
        }
        return out;
    }

    [[nodiscard]] std::string quoted(std::string_view text) const {
        // R18 (the user's review): texts, written or read as text, always
        // in quotation marks. One place: the pack's sentence value-text.
        return say("value-text", {{"text", plain(std::string(text))}});
    }

    [[nodiscard]] std::string date(const Date& d) const {
        const DateForms& forms = pack_->reading.dates.write.empty() ? english_pack().reading.dates
                                                                    : pack_->reading.dates;
        if (forms.write.empty()) {
            return std::to_string(d.year) + "-" + (d.month < 10 ? "0" : "") +
                   std::to_string(d.month) + "-" + (d.day < 10 ? "0" : "") + std::to_string(d.day);
        }
        std::string month = std::to_string(d.month);
        if (d.month >= 1 && d.month <= forms.months.size()) {
            month = forms.months[d.month - 1U];
        }
        const std::pair<std::string_view, std::string> values[] = {{"Y", std::to_string(d.year)},
                                                                   {"M", std::to_string(d.month)},
                                                                   {"D", std::to_string(d.day)},
                                                                   {"MONTH", month}};
        return fill(forms.write, values);
    }

    [[nodiscard]] std::string literal(const ast::Literal& l) const {
        const std::string amount = grouped(to_string(l.number));
        switch (l.kind) {
        case LiteralKind::number:
            return amount;
        case LiteralKind::money:
            if (l.unit == nullptr) {
                return amount;
            }
            return say("value-money", {{"currency", word(l.unit)}, {"amount", plain(amount)}});
        case LiteralKind::quantity:
        case LiteralKind::duration:
            if (l.unit == nullptr) {
                return amount;
            }
            return say(is_one(l.number) ? "value-unit-one" : "value-unit",
                       {{"amount", plain(amount)}, {"unit", word(l.unit)}});
        case LiteralKind::rate:
            return amount + "%";
        case LiteralKind::date:
            return date(l.date);
        case LiteralKind::text:
            return quoted(l.text);
        }
        return amount;
    }

    /// A value as compiled code keeps it, in words of its type.
    [[nodiscard]] std::string value(const m::Type& type, const cbor::Value& v,
                                    const LedgerLabel& ledger) const {
        const std::optional<std::int64_t> n = v.as_int64();
        switch (type.kind) {
        case TypeKind::number:
            if (n) {
                return scaled(*n, 1, 0);
            }
            break;
        case TypeKind::money:
            if (n && type.currency != nullptr) {
                return say("value-money", {{"currency", word(type.currency)},
                                           {"amount", plain(scaled(*n, money_factor, 2))}});
            }
            break;
        case TypeKind::rate:
            if (n) {
                return scaled(*n, rate_factor, 0) + "%";
            }
            break;
        case TypeKind::date:
            // Years 1 to 9999 at most, as compiled code keeps them; anything
            // far outside is shown as it is.
            if (n && *n > -max_date_ms && *n < max_date_ms) {
                const std::int64_t local = *n + default_offset_ms;
                const auto day = static_cast<std::int64_t>(day_ms);
                const std::int64_t days = (local >= 0 ? local : local - day + 1) / day;
                std::string out = date(civil_from_days(days));
                if (const std::int64_t in_day = local - days * day; in_day != 0) {
                    const std::int64_t minutes = in_day / 60'000;
                    out += " " + std::string(minutes / 60 < 10 ? "0" : "") +
                           std::to_string(minutes / 60) + ":" +
                           std::string(minutes % 60 < 10 ? "0" : "") + std::to_string(minutes % 60);
                    if (in_day % 60'000 != 0) {
                        out += ":" + scaled(in_day % 60'000, 1000, 0);
                    }
                    out += " (UTC+08:00)";
                }
                return out;
            }
            break;
        case TypeKind::duration:
            if (n && type.calendar) {
                return amount_of(scaled(*n, 1, 0), *n == 1, "time.month");
            }
            if (n && *n % static_cast<std::int64_t>(day_ms) == 0) {
                const std::int64_t days = *n / static_cast<std::int64_t>(day_ms);
                return amount_of(scaled(days, 1, 0), days == 1, "time.day");
            }
            break;
        case TypeKind::quantity:
            if (n) {
                const Concept* unit = type.unit;
                const UnitInfo* info = unit_info(unit);
                if (info != nullptr) {
                    return amount_of(scaled(*n, info->factor, 0),
                                     *n == static_cast<std::int64_t>(info->factor), unit->id);
                }
            }
            break;
        case TypeKind::text:
            if (const std::string* t = v.as_text()) {
                return quoted(*t);
            }
            break;
        case TypeKind::yes_no:
            if (const std::optional<bool> b = v.as_bool()) {
                return word(find_concept(*b ? "val.yes" : "val.no")).text;
            }
            break;
        case TypeKind::party:
            if (const Bytes* id = v.as_bytes(); id != nullptr && id->size() == 32 && ledger) {
                return ledger(ByteView(*id));
            }
            break;
        case TypeKind::list:
            // Each item as its type is written, in parentheses.
            if (const cbor::Array* items = v.as_array();
                items != nullptr && type.element.size() == 1) {
                std::string out;
                const std::string separator = say("list-separator");
                for (const cbor::Value& item : *items) {
                    out +=
                        (out.empty() ? "" : separator) + value(type.element.front(), item, ledger);
                }
                return say("group", {{"text", plain(out)}});
            }
            break;
        default:
            break;
        }
        return cbor::diagnostic(v);
    }

    [[nodiscard]] std::string mark(const Rules& rules) const {
        if (rules.empty()) {
            return {};
        }
        std::string ids;
        const std::string separator = say("list-separator");
        for (const std::string_view id : rules) {
            ids += (ids.empty() ? "" : separator) + std::string(id);
        }
        return say("mark", {{"rules", plain(ids)}});
    }

private:
    const Pack* pack_;
    bool spaced_;

    [[nodiscard]] std::string amount_of(std::string amount, bool one, std::string_view unit) const {
        return say(one ? "value-unit-one" : "value-unit",
                   {{"amount", plain(std::move(amount))}, {"unit", word(find_concept(unit))}});
    }

    [[nodiscard]] const std::string* find(std::string_view id) const {
        for (const Pack* pack : {pack_, &english_pack()}) {
            if (const auto it = pack->sentences.find(id); it != pack->sentences.end()) {
                return &it->second;
            }
        }
        return nullptr;
    }

    [[nodiscard]] static std::string_view form_of(const Phrase& p, std::string_view name) {
        if (!name.empty() && p.word != nullptr) {
            if (const auto it = p.word->forms.find(name); it != p.word->forms.end()) {
                return it->second;
            }
        }
        return p.text;
    }
};

// --- The explainer.

/// Binding strength, loosest first: how an expression nests in another.
enum Level : int {
    loosest = 0,
    level_or = 1,
    level_and = 2,
    level_not = 3,
    level_compare = 4,
    level_add = 5,
    level_multiply = 6,
    level_atom = 7,
};

int level_of(const m::Expr& e) noexcept {
    if (e.kind == ExprKind::unary) {
        return level_not;
    }
    if (e.kind != ExprKind::binary) {
        return level_atom;
    }
    switch (e.op) {
    case Operator::logical_or:
        return level_or;
    case Operator::logical_and:
        return level_and;
    case Operator::plus:
    case Operator::minus:
        return level_add;
    case Operator::times:
    case Operator::divide:
        return level_multiply;
    default:
        return level_compare;
    }
}

class Explainer {
public:
    Explainer(const m::Model& model, const Pack* language) : model_(model), w_(language) {}

    Explained run() {
        out_.language = w_.pack().id;
        out_.title = model_.name.empty() ? w_.say("fragment")
                                         : w_.say("contract", {{"name", plain(model_.name)}});
        out_.intro = w_.say("intro", {{"edition", plain(std::to_string(model_.edition))}});
        if (!model_.packs.empty()) {
            std::vector<std::string> names;
            for (const std::string& id : model_.packs) {
                const VocabularyPack* pack = find_vocabulary_pack(id);
                names.push_back(w_.say(
                    "vocab-pack",
                    {{"pack", plain(w_.say("vocab-" + id))},
                     {"version", plain(std::to_string(pack != nullptr ? pack->version : 0))}}));
            }
            out_.packs = w_.say("packs-used", {{"packs", plain(w_.join(names, true))}});
        }
        parties();
        instance();
        charges();
        states();
        actions();
        time_rules();
        rules_section();
        write_text();
        return std::move(out_);
    }

private:
    const m::Model& model_;
    Writer w_;
    Explained out_;
    Rules used_;
    /// While an action's or a time rule's clauses are written.
    const m::Action* action_ = nullptr;
    std::uint32_t requirement_ = 0;
    std::string function_;
    /// While the standard terms of an action are written: every clause is
    /// marked with their rule (R19).
    std::string_view terms_rule_;

    // --- Clauses and sections.

    ExplainedSection& section(std::string_view kind, std::string_view title_id) {
        ExplainedSection s;
        s.number = std::to_string(out_.sections.size() + 1);
        s.kind = kind;
        s.title = w_.say(title_id);
        out_.sections.push_back(std::move(s));
        return out_.sections.back();
    }

    /// Adds a clause numbered after its parent's number, and returns its
    /// number (for its own clauses).
    std::string add(std::vector<ExplainedClause>& list, const std::string& parent,
                    std::size_t& counter, std::string_view kind, std::string text,
                    const Rules& rules, std::uint32_t requirement = 0) {
        ExplainedClause c;
        c.number = parent + "." + std::to_string(++counter);
        c.kind = kind;
        c.text = std::move(text);
        Rules all = rules;
        note(all, terms_rule_);
        c.rules.assign(all.begin(), all.end());
        c.function = function_;
        c.requirement = requirement;
        used_.insert(all.begin(), all.end());
        list.push_back(std::move(c));
        return list.back().number;
    }

    // --- Words for what the model refers to.

    /// A party, a party field, or a name, with its word's forms.
    Phrase party(const m::Expr& e) const {
        if (e.kind == ExprKind::word) {
            return w_.word(e.concept_entry);
        }
        return plain(e.name);
    }

    /// Who starts the current action: its `by` party, or "the party that
    /// starts it".
    Phrase starter() const {
        if (action_ != nullptr && action_->by) {
            return party(*action_->by);
        }
        return plain(w_.say("starter"));
    }

    std::string label(const Concept* word, const std::string& name) const {
        return word != nullptr ? w_.word(word).text : name;
    }

    std::string state_text(const m::Expr& e) const { return label(e.concept_entry, e.name); }

    /// The action's display name: a vocabulary action in the language, a
    /// name of the contract's as written.
    std::string action_name(const m::Action& a) const { return label(a.word, a.name); }

    /// The amount `over N` compares in the current action (R6).
    std::string amount() const {
        const std::optional<std::string> key =
            action_ != nullptr ? m::action_amount(model_, *action_) : std::nullopt;
        if (!key) {
            return w_.say("value-amount");
        }
        if (const Concept* c = find_concept(*key)) {
            return w_.form(c, "object");
        }
        return *key;
    }

    // --- Expressions.

    std::string expr(const m::Expr& e, Rules& rules, int parent = loosest) {
        note(rules, e.rule);
        std::string text = expr_text(e, rules);
        if (level_of(e) < parent) {
            text = w_.say("group", {{"text", plain(std::move(text))}});
        }
        return text;
    }

    /// True if the expression is a state read as a condition (R7).
    static bool state_condition(const m::Expr& e) noexcept {
        return (e.kind == ExprKind::word || e.kind == ExprKind::name) &&
               e.refers == Refers::state && !e.rule.empty();
    }

    /// The states of an `or` of states read as conditions, if it is one.
    static bool state_alternatives(const m::Expr& e, std::vector<const m::Expr*>& out) {
        if (state_condition(e)) {
            out.push_back(&e);
            return true;
        }
        if (e.kind == ExprKind::binary && e.op == Operator::logical_or && e.operands.size() == 2) {
            return state_alternatives(e.operands[0], out) && state_alternatives(e.operands[1], out);
        }
        return false;
    }

    std::string expr_text(const m::Expr& e, Rules& rules) {
        switch (e.kind) {
        case ExprKind::literal:
            return w_.literal(e.literal);
        case ExprKind::name:
            if (state_condition(e)) {
                return w_.say("cond-state", {{"state", plain(e.name)}});
            }
            return e.name;
        case ExprKind::word:
            return word_text(e);
        case ExprKind::apply:
            return apply_text(e, rules);
        case ExprKind::phrase:
            return phrase_text(e, rules);
        case ExprKind::list: {
            std::vector<std::string> items;
            for (const m::Expr& o : e.operands) {
                items.push_back(expr(o, rules));
            }
            return w_.say("group", {{"text", plain(join_plain(items))}});
        }
        case ExprKind::unary:
            if (e.operands.size() == 1 && state_condition(e.operands[0])) {
                note(rules, e.operands[0].rule);
                return w_.say("cond-not-state", {{"state", plain(state_text(e.operands[0]))}});
            }
            if (e.operands.size() == 1 && e.operands[0].kind == ExprKind::word &&
                is(e.operands[0].concept_entry, "cond.overdue")) {
                return w_.say("cond-not-overdue");
            }
            if (e.operands.size() == 1 && e.operands[0].kind == ExprKind::phrase &&
                e.operands[0].operands.size() == 2 &&
                e.operands[0].operands[0].kind == ExprKind::word &&
                is(e.operands[0].operands[0].concept_entry, "cond.overdue")) {
                return w_.say("cond-not-overdue-by",
                              {{"duration", plain(expr(e.operands[0].operands[1], rules))}});
            }
            if (e.operands.size() == 1 && e.operands[0].kind == ExprKind::apply &&
                is(e.operands[0].concept_entry, "cond.within") &&
                e.operands[0].operands.size() == 1) {
                // not within N: N or more since the last change of state.
                return w_.say("cond-not-within",
                              {{"duration", plain(expr(e.operands[0].operands[0], rules))}});
            }
            if (e.operands.size() == 1 && e.operands[0].kind == ExprKind::binary &&
                e.operands[0].op == Operator::equals && e.operands[0].operands.size() == 2) {
                // not a = b: a is not b.
                const m::Expr& eq = e.operands[0];
                note(rules, eq.rule);
                return w_.say("op-not-equals",
                              {{"left", plain(expr(eq.operands[0], rules, level_compare + 1))},
                               {"right", plain(expr(eq.operands[1], rules, level_compare + 1))}});
            }
            return w_.say("op-not",
                          {{"operand", plain(e.operands.empty()
                                                 ? std::string()
                                                 : expr(e.operands[0], rules, level_not + 1))}});
        case ExprKind::binary:
            return binary_text(e, rules);
        }
        return {};
    }

    std::string join_plain(const std::vector<std::string>& items) const {
        std::string out;
        const std::string separator = w_.say("list-separator");
        for (std::size_t i = 0; i < items.size(); ++i) {
            out += (i == 0 ? "" : separator) + items[i];
        }
        return out;
    }

    std::string word_text(const m::Expr& e) {
        const Concept* c = e.concept_entry;
        if (c == nullptr) {
            return e.name;
        }
        if (state_condition(e)) {
            return w_.say("cond-state", {{"state", w_.word(c)}});
        }
        if (is(c, "cond.in_person")) {
            return w_.say("cond-in-person", {{"party", starter()}});
        }
        if (is(c, "time.now")) {
            return w_.say("value-now");
        }
        if (is(c, "time.today")) {
            return w_.say("value-today");
        }
        if (is(c, "cond.overdue")) {
            return w_.say("cond-overdue");
        }
        if (c->category == Category::field || c->category == Category::role) {
            return w_.form(c, "object");
        }
        return w_.word(c).text;
    }

    std::string apply_text(const m::Expr& e, Rules& rules) {
        const Concept* c = e.concept_entry;
        if (e.operands.empty()) {
            return w_.word(c).text;
        }
        const m::Expr& o = e.operands[0];
        if (is(c, "cond.consent_of")) {
            note(rules, o.rule);
            return w_.say("cond-consent", {{"party", party(o)}});
        }
        if (is(c, "cond.over")) {
            return w_.say("cond-over",
                          {{"amount", plain(amount())}, {"value", plain(expr(o, rules))}});
        }
        if (is(c, "cond.before_due")) {
            return w_.say("cond-before-due", {{"duration", plain(expr(o, rules))}});
        }
        if (is(c, "cond.within")) {
            return w_.say("cond-within", {{"duration", plain(expr(o, rules))}});
        }
        if (is(c, "expr.sum_of")) {
            return w_.say("expr-sum", {{"list", plain(expr(o, rules))}});
        }
        if (is(c, "expr.count_of")) {
            return w_.say("expr-count", {{"list", plain(expr(o, rules))}});
        }
        if (is(c, "expr.at_most")) {
            return w_.say("expr-at-most", {{"value", plain(expr(o, rules))}});
        }
        return w_.words({w_.word(c).text, expr(o, rules, level_atom)});
    }

    std::string phrase_text(const m::Expr& e, Rules& rules) {
        const std::vector<m::Expr>& ops = e.operands;
        const auto word_is = [&](std::size_t i, Category category) {
            return i < ops.size() && ops[i].kind == ExprKind::word &&
                   ops[i].concept_entry != nullptr && ops[i].concept_entry->category == category;
        };
        if (ops.size() == 2 && word_is(0, Category::time)) {
            // monthly HKD 120: a recurring amount.
            return w_.say("type-recurring", {{"value", plain(expr(ops[1], rules))},
                                             {"period", w_.word(ops[0].concept_entry)}});
        }
        if (ops.size() == 2 && ops[0].kind == ExprKind::word &&
            is(ops[0].concept_entry, "charge.by")) {
            return w_.say("value-basis", {{"field", plain(expr(ops[1], rules))}});
        }
        if (ops.size() == 2 && ops[0].kind == ExprKind::word &&
            is(ops[0].concept_entry, "cond.overdue")) {
            return w_.say("cond-overdue-by", {{"duration", plain(expr(ops[1], rules))}});
        }
        if (ops.size() == 2 && ops[0].refers == Refers::state) {
            // suspended 30 days: the state, held that long.
            return w_.say("cond-held", {{"state", plain(state_text(ops[0]))},
                                        {"duration", plain(expr(ops[1], rules))}});
        }
        if (const std::size_t n = ops.size(); n >= 3 && ops[n - 3].kind == ExprKind::word &&
                                              is(ops[n - 3].concept_entry, "price.per") &&
                                              word_is(n - 2, Category::unit)) {
            // overage per GB HKD 0.10: a unit price, with its label.
            const std::string price =
                w_.say("value-unit-price", {{"money", plain(expr(ops[n - 1], rules))},
                                            {"unit", w_.word(ops[n - 2].concept_entry)}});
            std::vector<std::string> label;
            for (std::size_t i = 0; i + 3 < n; ++i) {
                label.push_back(expr(ops[i], rules, level_atom));
            }
            if (label.empty()) {
                return price;
            }
            return w_.say("value-labelled",
                          {{"label", plain(w_.words(label))}, {"value", plain(price)}});
        }
        std::vector<std::string> items;
        for (const m::Expr& o : ops) {
            items.push_back(expr(o, rules, level_atom));
        }
        return w_.words(items);
    }

    std::string binary_text(const m::Expr& e, Rules& rules) {
        if (e.operands.size() != 2) {
            return {};
        }
        if (e.op == Operator::logical_and && (e.operands[0].type.kind == TypeKind::date ||
                                              e.operands[1].type.kind == TypeKind::date)) {
            // A rule's date joined to conditions: from that day on.
            const auto side = [&](const m::Expr& o) {
                return o.type.kind == TypeKind::date
                           ? w_.say("cond-from-date", {{"date", plain(expr(o, rules))}})
                           : expr(o, rules, level_and);
            };
            return w_.say("op-and", {{"left", plain(side(e.operands[0]))},
                                     {"right", plain(side(e.operands[1]))}});
        }
        if (std::vector<const m::Expr*> states;
            e.op == Operator::logical_or && state_alternatives(e, states)) {
            // proposed or signed: the instance is in one of them (R7).
            std::vector<std::string> names;
            for (const m::Expr* s : states) {
                note(rules, s->rule);
                names.push_back(state_text(*s));
            }
            return w_.say("cond-state", {{"state", plain(w_.join(names, false))}});
        }
        const m::Expr& l = e.operands[0];
        const m::Expr& r = e.operands[1];
        const int own = level_of(e);
        const bool compare = own == level_compare;
        const bool loose_right = e.op == Operator::minus || e.op == Operator::divide;
        const std::string left = expr(l, rules, compare ? own + 1 : own);
        const std::string right = expr(r, rules, compare || loose_right ? own + 1 : own);
        const auto say = [&](std::string_view id) {
            return w_.say(id, {{"left", plain(left)}, {"right", plain(right)}});
        };
        const bool dates = l.type.kind == TypeKind::date;
        switch (e.op) {
        case Operator::logical_or:
            return say("op-or");
        case Operator::logical_and:
            return say("op-and");
        case Operator::equals:
            return say("op-equals");
        case Operator::less:
            return say(dates ? "op-before" : "op-less");
        case Operator::less_equal:
            return say(dates ? "op-on-or-before" : "op-less-equal");
        case Operator::greater:
            return say(dates ? "op-after" : "op-greater");
        case Operator::greater_equal:
            return say(dates ? "op-on-or-after" : "op-greater-equal");
        case Operator::member:
            return say("op-in");
        case Operator::plus:
            return left + " + " + right;
        case Operator::minus:
            return left + " − " + right;
        case Operator::times:
            return left + " × " + right;
        case Operator::divide:
            if (l.type.kind == TypeKind::duration && r.type.kind == TypeKind::duration) {
                // R32: whole times, the rest dropped.
                return say("op-whole-times");
            }
            return left + " ÷ " + right;
        case Operator::none:
        case Operator::logical_not:
            break;
        }
        return w_.words({left, right});
    }

    // --- Parties.

    void parties() {
        if (model_.parties.empty()) {
            return;
        }
        ExplainedSection& s = section("parties", "section-parties");
        std::size_t n = 0;
        for (const m::Party& p : model_.parties) {
            Rules rules;
            note(rules, p.rule);
            const Phrase who = p.role != nullptr ? w_.word(p.role) : plain(p.name);
            std::string text;
            if (p.binding == m::Binding::creation) {
                text = w_.say("party-creation", {{"party", who}});
            } else {
                const Concept* by = find_concept(p.bound_by);
                if (p.each_call) {
                    // R23: each allocation binds it again.
                    note(rules, "R23");
                }
                text = w_.say(p.each_call ? "party-each" : "party-action",
                              {{"party", who}, {"action", plain(label(by, p.bound_by))}});
            }
            add(s.clauses, s.number, n, "party", std::move(text), rules);
        }
    }

    // --- What each instance records.

    std::string field_value(const m::Field& f, Rules& rules) {
        std::vector<std::string> values;
        if (f.value) {
            values.push_back(expr(*f.value, rules));
        }
        for (const m::Expr& more : f.more) {
            values.push_back(expr(more, rules));
        }
        return w_.parts(values);
    }

    std::string type_text(const m::Type& type) const {
        return describe_type(encode(type), &w_.pack());
    }

    void instance() {
        if (model_.kind == nullptr && model_.fields.empty()) {
            ExplainedSection& s = section("instance", "section-instance");
            std::size_t n = 0;
            add(s.clauses, s.number, n, "kind", w_.say("instance-none"), {});
            return;
        }
        ExplainedSection& s = section("instance", "section-instance");
        std::size_t n = 0;
        if (model_.kind != nullptr) {
            add(s.clauses, s.number, n, "kind",
                w_.say("instance-kind",
                       {{"kind", w_.word(model_.kind)}, {"name", plain(model_.kind_name)}}),
                {});
        }
        for (const m::Field& f : model_.fields) {
            Rules rules;
            note(rules, f.rule);
            const Phrase name = plain(label(f.word, f.name));
            std::string text;
            if (f.kind == m::FieldKind::constant) {
                text = w_.say("field-constant",
                              {{"field", name}, {"value", plain(field_value(f, rules))}});
            } else if (f.empty_at_start) {
                text = w_.say("field-empty", {{"field", name}, {"type", plain(type_text(f.type))}});
            } else if (f.type.kind == TypeKind::party && f.value) {
                text = w_.say("field-party", {{"field", name},
                                              {"type", plain(type_text(f.type))},
                                              {"party", party(*f.value)}});
            } else if (f.initial) {
                text = w_.say("field-default", {{"field", name},
                                                {"type", plain(type_text(f.type))},
                                                {"value", plain(expr(*f.initial, rules))}});
            } else {
                text = w_.say("field-given", {{"field", name}, {"type", plain(type_text(f.type))}});
            }
            add(s.clauses, s.number, n, "field", std::move(text), rules);
        }
        add(s.clauses, s.number, n, "creation",
            w_.say("creation", {{"function", plain(std::string(m::creation_function(model_)))}}),
            {});
        if (dated()) {
            // U6: the contract's offset from UTC, fixed (R25 unless written).
            Rules rules;
            note(rules, model_.offset_rule);
            const std::int64_t minutes = model_.utc_offset_ms / 60'000;
            const std::int64_t whole = minutes < 0 ? -minutes : minutes;
            add(s.clauses, s.number, n, "utc-offset",
                w_.say("utc-offset",
                       {{"offset", plain(std::format("{}{:02}:{:02}", minutes < 0 ? '-' : '+',
                                                     whole / 60, whole % 60))}}),
                rules);
        }
    }

    /// True if the contract counts in local days or calendar months: a time
    /// rule, a date, or a duration in months or years, anywhere.
    [[nodiscard]] bool dated() const {
        if (!model_.rules.empty()) {
            return true;
        }
        const auto local = [](const m::Type& t) {
            return t.kind == TypeKind::date || (t.kind == TypeKind::duration && t.calendar);
        };
        const auto in = [&](const m::Expr& e, const auto& self) -> bool {
            return local(e.type) ||
                   std::ranges::any_of(e.operands, [&](const m::Expr& o) { return self(o, self); });
        };
        const auto walk = [&](const std::vector<m::Statement>& list, const auto& self) -> bool {
            return std::ranges::any_of(list, [&](const m::Statement& st) {
                return std::visit(
                    Overloaded{
                        [&](const m::Requires& r) {
                            return in(r.condition, in) || (r.guard && in(*r.guard, in));
                        },
                        [&](const m::If& i) {
                            return in(i.condition, in) || self(i.then, self) ||
                                   self(i.otherwise, self);
                        },
                        [&](const m::Each& e) { return in(e.list, in) || self(e.body, self); },
                        [&](const m::Reject&) { return false; },
                        [&](const m::Set& set) { return in(set.value, in); },
                        [&](const m::Transition&) { return false; },
                        [&](const m::Do&) { return false; },
                    },
                    st.node);
            });
        };
        return std::ranges::any_of(model_.fields,
                                   [&](const m::Field& f) {
                                       return local(f.type) || (f.value && in(*f.value, in));
                                   }) ||
               std::ranges::any_of(model_.charges,
                                   [&](const m::Charge& c) {
                                       return !c.dated.empty() ||
                                              (c.condition && in(*c.condition, in));
                                   }) ||
               std::ranges::any_of(model_.actions, [&](const m::Action& a) {
                   return std::ranges::any_of(a.inputs,
                                              [&](const m::Field& f) { return local(f.type); }) ||
                          walk(a.body, walk);
               });
    }

    // --- Charges.

    std::string rounding(const m::Expr* mode, Rules& rules) {
        if (mode != nullptr && mode->kind == ExprKind::word) {
            return w_.word(mode->concept_entry).text;
        }
        // U5: half up, unless the charge says otherwise.
        note(rules, "R17");
        return w_.word(find_concept("round.half_up")).text;
    }

    void charges() {
        if (model_.charges.empty()) {
            return;
        }
        ExplainedSection& s = section("charges", "section-charges");
        std::size_t n = 0;
        if (const m::Field* bill = m::bill_field(model_); bill != nullptr) {
            // R26: what the charges are computed on, and when.
            Rules rules;
            note(rules, "R26");
            add(s.clauses, s.number, n, "charge-bill",
                w_.say("charge-bill", {{"document", w_.word(bill->word)}}), rules);
        }
        for (const m::Charge& c : model_.charges) {
            const std::string number =
                add(s.clauses, s.number, n, "charge",
                    w_.say("charge", {{"kind", w_.word(c.kind)}, {"name", plain(c.name)}}), {});
            const bool fixed = c.amount.has_value();
            std::size_t k = 0;
            bool rounded = false;
            for (const m::ChargeLine& line : c.lines) {
                Rules rules;
                const m::Expr* value = line.values.empty() ? nullptr : &line.values.front();
                const Concept* head = line.head;
                std::string text;
                const bool base =
                    is(head, "charge.by") && value != nullptr &&
                    (value->refers == Refers::charge ||
                     (value->kind == ExprKind::word && is(value->concept_entry, "price.price")));
                if (is(head, "charge.rate") && value != nullptr) {
                    text = w_.say("charge-rate", {{"rate", plain(expr(*value, rules))}});
                } else if (is(head, "field.amount") && value != nullptr) {
                    text = w_.say("charge-amount", {{"value", plain(expr(*value, rules))}});
                } else if (is(head, "charge.applies_to") && line.argument) {
                    text = w_.say("charge-applies",
                                  {{"condition", plain(expr(*line.argument, rules))}});
                } else if (is(head, "charge.included")) {
                    note(rules, "R27");
                    text = w_.say("charge-included");
                } else if (is(head, "charge.added")) {
                    note(rules, "R27");
                    text = w_.say("charge-added");
                } else if (fixed &&
                           (is(head, "charge.per_line") || is(head, "charge.per_document") ||
                            (is(head, "charge.by") && !base))) {
                    // A fixed amount is never rounded: once per bill, or on each line.
                    note(rules, "R27");
                    text = w_.say(is(head, "charge.per_line") ? "charge-each-line" : "charge-once");
                    rounded = true;
                } else if (is(head, "charge.per_line")) {
                    text = w_.say("charge-per-line", {{"rounding", plain(rounding(value, rules))}});
                    rounded = true;
                } else if (head != nullptr && head->category == Category::rounding) {
                    // A rounding mode alone: per line.
                    text = w_.say("charge-per-line", {{"rounding", w_.word(head)}});
                    rounded = true;
                } else if (is(head, "charge.per_document")) {
                    text = w_.say("charge-per-document",
                                  {{"rounding", plain(rounding(value, rules))}});
                    rounded = true;
                } else if (base) {
                    // according to price, OTHER: what it is computed on (R27).
                    note(rules, "R27");
                    std::vector<std::string> items;
                    for (const m::Expr& v : line.values) {
                        items.push_back(v.kind == ExprKind::word ? w_.say("charge-price") : v.name);
                    }
                    text = w_.say("charge-on", {{"base", plain(w_.join(items, true))}});
                } else if (is(head, "charge.by") && value != nullptr) {
                    // according to invoice [half up]: per document of that kind.
                    const bool with_mode =
                        value->kind == ExprKind::phrase && value->operands.size() == 2;
                    const m::Expr& document = with_mode ? value->operands[0] : *value;
                    text = w_.say(
                        "charge-by-document",
                        {{"document", w_.word(document.concept_entry)},
                         {"rounding",
                          plain(rounding(with_mode ? &value->operands[1] : nullptr, rules))}});
                    rounded = true;
                } else if (is(head, "charge.from") && line.argument && value != nullptr) {
                    note(rules, "R28");
                    text = w_.say("charge-from", {{"date", plain(expr(*line.argument, rules))},
                                                  {"rate", plain(expr(*value, rules))}});
                } else {
                    std::vector<std::string> items{w_.word(head).text};
                    if (line.argument) {
                        items.push_back(expr(*line.argument, rules, level_atom));
                    }
                    for (const m::Expr& v : line.values) {
                        items.push_back(expr(v, rules, level_atom));
                    }
                    text = w_.say("charge-other", {{"text", plain(w_.words(items))}});
                }
                add(s.clauses, number, k, "charge-line", std::move(text), rules);
            }
            if (!rounded) {
                Rules rules;
                if (fixed) {
                    note(rules, "R27");
                    add(s.clauses, number, k, "charge-line", w_.say("charge-once"), rules);
                } else {
                    const std::string mode = rounding(nullptr, rules);
                    add(s.clauses, number, k, "charge-line",
                        w_.say("charge-per-line", {{"rounding", plain(mode)}}), rules);
                }
            }
        }
    }

    // --- States.

    void states() {
        if (model_.states.empty()) {
            return;
        }
        ExplainedSection& s = section("states", "section-states");
        std::size_t n = 0;
        const m::State& first = model_.states.front();
        {
            Rules rules;
            note(rules, first.rule);
            add(s.clauses, s.number, n, "first-state",
                w_.say("state-first", {{"state", plain(label(first.word, first.name))}}), rules);
        }
        if (model_.states.size() > 1) {
            Rules rules;
            std::vector<std::string> names;
            for (const m::State& state : model_.states) {
                names.push_back(label(state.word, state.name));
                if (state.rule == "R5") {
                    note(rules, state.rule);
                }
            }
            add(s.clauses, s.number, n, "states",
                w_.say("states-all", {{"states", plain(w_.join(names, true))}}), rules);
        }
        const std::vector<bool> finals = m::final_states(model_);
        bool any = false;
        for (std::size_t i = 0; i < model_.states.size(); ++i) {
            if (finals[i]) {
                any = true;
                const m::State& state = model_.states[i];
                add(s.clauses, s.number, n, "final-state",
                    w_.say("state-final", {{"state", plain(label(state.word, state.name))}}), {});
            }
        }
        if (!any) {
            add(s.clauses, s.number, n, "final-state", w_.say("states-no-final"), {});
        }
        add(s.clauses, s.number, n, "events", w_.say("events"), {});
    }

    // --- Actions and time rules: their statements.

    void statements(const std::vector<m::Statement>& list, std::vector<ExplainedClause>& out,
                    const std::string& parent, std::size_t& n) {
        for (const m::Statement& statement : list) {
            std::visit(
                Overloaded{
                    [&](const m::Requires& r) { requirement(r, out, parent, n); },
                    [&](const m::If& i) {
                        Rules rules;
                        const std::string number = add(
                            out, parent, n, "if",
                            w_.say("if", {{"condition", plain(expr(i.condition, rules))}}), rules);
                        std::size_t k = 0;
                        statements(i.then, out, number, k);
                        if (!i.otherwise.empty()) {
                            const std::string other =
                                add(out, parent, n, "otherwise", w_.say("otherwise"), {});
                            std::size_t j = 0;
                            statements(i.otherwise, out, other, j);
                        }
                    },
                    [&](const m::Each& e) {
                        Rules rules;
                        const std::string number =
                            add(out, parent, n, "each",
                                w_.say("each", {{"item", plain(e.name)},
                                                {"list", plain(expr(e.list, rules))}}),
                                rules);
                        std::size_t k = 0;
                        statements(e.body, out, number, k);
                    },
                    [&](const m::Reject& r) {
                        add(out, parent, n, "reject",
                            w_.say("reject", {{"message", plain(w_.quoted(r.message))}}), {});
                    },
                    [&](const m::Set& st) {
                        Rules rules;
                        const std::string field = expr(st.target, rules);
                        const std::string value = expr(st.value, rules);
                        add(out, parent, n, "set",
                            w_.say("set", {{"field", plain(field)}, {"value", plain(value)}}),
                            rules);
                    },
                    [&](const m::Transition& t) {
                        Rules rules;
                        const Phrase to = plain(state_text(t.to));
                        std::string text;
                        if (is(t.to.concept_entry, "expr.previous_state")) {
                            std::vector<std::string> from;
                            for (const m::Expr& f : t.from) {
                                from.push_back(state_text(f));
                            }
                            text = w_.say("transition-previous",
                                          {{"from", plain(w_.join(from, false))}});
                        } else if (t.from.empty()) {
                            text = w_.say("transition", {{"state", to}});
                        } else {
                            std::vector<std::string> from;
                            for (const m::Expr& f : t.from) {
                                from.push_back(state_text(f));
                            }
                            text = w_.say("transition-from",
                                          {{"from", plain(w_.join(from, false))}, {"state", to}});
                        }
                        add(out, parent, n, "transition", std::move(text), rules);
                    },
                    [&](const m::Do& d) { act(d, out, parent, n); },
                },
                statement.node);
        }
    }

    void requirement(const m::Requires& r, std::vector<ExplainedClause>& out,
                     const std::string& parent, std::size_t& n) {
        // Numbered as compiled code numbers them (bo:requires ACTION N):
        // every requires line, depth first, `then` before `otherwise`.
        const std::uint32_t number = ++requirement_;
        Rules rules;
        const m::Expr& c = r.condition;
        std::string need;
        if (c.kind == ExprKind::apply && is(c.concept_entry, "cond.consent_of") &&
            !c.operands.empty()) {
            note(rules, c.rule);
            need = w_.say("need-consent", {{"party", party(c.operands[0])}});
        } else if (c.kind == ExprKind::word && is(c.concept_entry, "cond.in_person")) {
            note(rules, c.rule);
            need = w_.say("need-in-person", {{"party", starter()}});
        } else {
            need = expr(c, rules);
        }
        std::string text;
        if (r.guard) {
            const std::string guard = expr(*r.guard, rules);
            text = w_.say("requirement-if", {{"number", plain(std::to_string(number))},
                                             {"guard", plain(guard)},
                                             {"need", plain(need)}});
        } else {
            text = w_.say("requirement",
                          {{"number", plain(std::to_string(number))}, {"need", plain(need)}});
        }
        add(out, parent, n, "requirement", std::move(text), rules, number);
    }

    /// An action done: its words, with its arguments and parties.
    std::string done(const m::Do& d, Rules& rules) {
        std::string text = state_text(d.action);
        if (!d.args.empty()) {
            std::vector<std::string> args;
            for (const m::Expr& a : d.args) {
                args.push_back(expr(a, rules, level_atom));
            }
            text = w_.say("action-args",
                          {{"action", plain(std::move(text))}, {"args", plain(w_.words(args))}});
        }
        if (d.to) {
            text = w_.say("action-to-party",
                          {{"action", plain(std::move(text))}, {"party", party(*d.to)}});
        }
        if (d.by) {
            text = w_.say("action-by-party",
                          {{"action", plain(std::move(text))}, {"party", party(*d.by)}});
        }
        if (!d.with.empty()) {
            std::vector<std::string> items;
            for (const m::Set& s : d.with) {
                items.push_back(w_.say("op-equals", {{"left", plain(expr(s.target, rules))},
                                                     {"right", plain(expr(s.value, rules))}}));
            }
            text = w_.say("action-with",
                          {{"action", plain(std::move(text))}, {"inputs", plain(w_.parts(items))}});
        }
        return text;
    }

    void act(const m::Do& d, std::vector<ExplainedClause>& out, const std::string& parent,
             std::size_t& n) {
        if (d.parts) {
            issue_parts(d, out, parent, n);
            return;
        }
        Rules rules;
        note(rules, d.rule);
        const std::string action = done(d, rules);
        std::string text;
        if (d.obligation && d.subject) {
            text = w_.say("do-duty", {{"party", party(*d.subject)}, {"action", plain(action)}});
        } else if (d.executor) {
            text = w_.say("do-executor", {{"action", plain(action)}});
        } else if (function_.starts_with("when.") && m::action_of(model_, d) != nullptr) {
            // A time rule does an action under that action's clauses.
            text = w_.say("do-rule", {{"action", plain(action)}});
        } else {
            text = w_.say("do", {{"action", plain(action)}});
        }
        add(out, parent, n, "do", std::move(text), rules);
    }

    /// R30: the parts an action issues, what each holds, how deep parts go,
    /// and what a part's holder sees.
    void issue_parts(const m::Do& d, std::vector<ExplainedClause>& out, const std::string& parent,
                     std::size_t& n) {
        const m::State* first = model_.states.empty() ? nullptr : &model_.states.front();
        {
            Rules rules;
            note(rules, d.rule);
            add(out, parent, n, "parts",
                w_.say("do-parts",
                       {{"parts", d.args.empty() ? plain({}) : party(d.args[0])},
                        {"recipients", d.to ? party(*d.to) : plain({})},
                        {"state", plain(first != nullptr ? label(first->word, first->name)
                                                         : std::string())}}),
                rules);
        }
        for (const m::Set& w : d.with) {
            Rules rules;
            note(rules, d.rule);
            const std::string field = expr(w.target, rules);
            const std::string value = expr(w.value, rules);
            add(out, parent, n, "parts-set",
                w_.say("parts-set", {{"field", plain(field)}, {"value", plain(value)}}), rules);
        }
        {
            Rules rules;
            note(rules, d.rule);
            add(out, parent, n, "parts-depth",
                w_.say("parts-depth", {{"function", plain(function_)}}), rules);
        }
        {
            Rules rules;
            note(rules, d.rule);
            add(out, parent, n, "parts-privacy", w_.say("parts-privacy"), rules);
        }
    }

    // --- Actions.

    void actions() {
        if (model_.actions.empty()) {
            return;
        }
        ExplainedSection& s = section("actions", "section-actions");
        s.note = w_.say("actions-note");
        std::size_t n = 0;
        for (const m::Action& a : model_.actions) {
            action_ = &a;
            requirement_ = 0;
            function_ = wire_name(a.word, a.name);
            const std::string name = action_name(a);
            std::string title = name;
            if (name != function_) {
                title = w_.say("action-function",
                               {{"action", plain(name)}, {"function", plain(function_)}});
            }
            const std::string number = add(s.clauses, s.number, n, "action", title, {});
            std::size_t k = 0;
            if (a.terms && a.word != nullptr && a.word->pack != Vocab::core) {
                add(s.clauses, number, k, "standard",
                    w_.say("action-terms-pack",
                           {{"action", plain(name)},
                            {"function", plain(function_)},
                            {"pack",
                             plain(w_.say("vocab-" + std::string(vocab_name(a.word->pack))))}}),
                    {});
            } else if (a.terms) {
                add(s.clauses, number, k, "standard",
                    w_.say("action-terms",
                           {{"action", plain(name)}, {"function", plain(function_)}}),
                    {});
            } else if (a.word != nullptr) {
                add(s.clauses, number, k, "standard",
                    w_.say("action-standard", {{"action", plain(name)}}), {});
            }
            if (a.rule_only) {
                add(s.clauses, number, k, "rule-only", w_.say("action-rule-only"), {});
            }
            if (a.by) {
                Rules rules;
                note(rules, a.by->rule);
                add(s.clauses, number, k, "by", w_.say("action-by", {{"party", party(*a.by)}}),
                    rules);
            } else if (a.terms && !a.rule_only) {
                // The home's own word (R19); a counterparty may still consent.
                Rules rules;
                note(rules, "R19");
                add(s.clauses, number, k, "by",
                    w_.say(a.consents.empty() ? "action-home" : "action-home-start"), rules);
            }
            if (a.to && !binds(a, *a.to) && a.to->refers != Refers::input) {
                Rules rules;
                note(rules, a.to->rule);
                add(s.clauses, number, k, "to", w_.say("action-to", {{"party", party(*a.to)}}),
                    rules);
            }
            if (!a.inputs.empty()) {
                Rules rules;
                std::vector<std::string> items;
                for (const m::Field& input : a.inputs) {
                    note(rules, input.rule);
                    items.push_back(
                        w_.say("input", {{"input", plain(label(input.word, input.name))},
                                         {"type", plain(type_text(input.type))}}));
                }
                add(s.clauses, number, k, "inputs",
                    w_.say("action-inputs", {{"inputs", plain(w_.parts(items))}}), rules);
            }
            consents(a.consents, s.clauses, number, k);
            if (a.terms) {
                const auto split = a.body.begin() + static_cast<std::ptrdiff_t>(a.terms_from);
                statements(std::vector<m::Statement>(a.body.begin(), split), s.clauses, number, k);
                terms_rule_ = "R19";
                statements(std::vector<m::Statement>(split, a.body.end()), s.clauses, number, k);
                terms_rule_ = {};
            } else {
                statements(a.body, s.clauses, number, k);
            }
            if (!a.rule_only) {
                Rules rules;
                std::string text;
                if (a.agents_propose) {
                    text = w_.say("agents-propose");
                } else {
                    note(rules, a.agents_rule);
                    text = w_.say("agents-delegation");
                }
                add(s.clauses, number, k, "agents", std::move(text), rules);
            }
            if (a.executor) {
                Rules rules;
                note(rules, a.executor_rule);
                add(s.clauses, number, k, "executor", w_.say("action-executor"), rules);
            }
        }
        action_ = nullptr;
        function_.clear();
        if (m::has_proposals(model_)) {
            // approve: a person approves an AI agent's proposal.
            function_ = std::string(m::approve_function);
            const std::string name = w_.word(find_concept("act.approve")).text;
            const std::string title =
                name == function_ ? name
                                  : w_.say("action-function", {{"action", plain(name)},
                                                               {"function", plain(function_)}});
            const std::string number = add(s.clauses, s.number, n, "action", title, {});
            std::size_t k = 0;
            Rules rules;
            note(rules, "R14");
            add(s.clauses, number, k, "approve",
                w_.say("approve", {{"function", plain(function_)}}), rules);
            function_.clear();
        }
    }

    /// True if the action binds the party it names after `to` (R3).
    static bool binds(const m::Action& a, const m::Expr& to) {
        const std::string key = m::key(to.concept_entry, to.name);
        return std::ranges::any_of(a.consents, [&](const m::Consent& c) {
            return c.rule == "R3" && m::key(c.party.concept_entry, c.party.name) == key;
        });
    }

    void consents(const std::vector<m::Consent>& list, std::vector<ExplainedClause>& out,
                  const std::string& parent, std::size_t& n) {
        for (const m::Consent& c : list) {
            Rules rules;
            note(rules, c.rule);
            std::string text;
            const Concept* taken =
                c.rule == "R31" && action_ != nullptr ? m::role_taken(*action_) : nullptr;
            if (taken != nullptr) {
                // R31: the counterparty the action makes holder, pledgee, or
                // payee, at every call.
                text =
                    w_.say("consent-takes", {{"party", party(c.party)}, {"field", w_.word(taken)}});
            } else if (c.party.refers == Refers::field) {
                // R8: the party the field holds before the call.
                text = w_.say("consent-taken", {{"field", party(c.party)}});
            } else if (c.party.refers == Refers::input) {
                // R21: the counterparty each call names.
                text = w_.say("consent-call",
                              {{"party", party(c.party)},
                               {"input", plain(wire_name(c.party.concept_entry, c.party.name))}});
            } else if (each_call(c.party)) {
                // R23: each call binds it again.
                note(rules, "R23");
                text = w_.say("consent-rebinds", {{"party", party(c.party)}});
            } else {
                text = w_.say("consent-binds", {{"party", party(c.party)}});
            }
            add(out, parent, n, "consent", std::move(text), rules);
        }
    }

    /// True if a party is a role each call of its action binds again (R23).
    [[nodiscard]] bool each_call(const m::Expr& p) const {
        const std::string key = m::key(p.concept_entry, p.name);
        return std::ranges::any_of(model_.parties, [&](const m::Party& party) {
            return party.each_call && m::key(party.role, party.name) == key;
        });
    }

    // --- Time rules.

    void time_rules() {
        if (model_.rules.empty()) {
            return;
        }
        ExplainedSection& s = section("time", "section-time");
        std::size_t n = 0;
        if (model_.due == m::DueKind::field) {
            add(s.clauses, s.number, n, "due",
                w_.say("due-field", {{"field", w_.word(find_concept("field.due"))}}), {});
        } else if (model_.due == m::DueKind::period) {
            Rules rules;
            note(rules, model_.due_rule);
            add(s.clauses, s.number, n, "due", w_.say("due-period"), rules);
        }
        const std::vector<std::string> functions = m::rule_functions(model_);
        for (std::size_t i = 0; i < model_.rules.size(); ++i) {
            const m::TimeRule& r = model_.rules[i];
            requirement_ = 0;
            // Its clauses are its function's (requirements numbered from 1).
            function_ = functions[i];
            Rules rules;
            const std::string event = expr(r.event, rules);
            const std::string text = r.event.type.kind == TypeKind::date
                                         ? w_.say("when-date", {{"date", plain(event)}})
                                         : w_.say("when", {{"event", plain(event)}});
            const std::string number = add(s.clauses, s.number, n, "when", text, rules);
            std::size_t k = 0;
            if (!function_.empty()) {
                // R24: a keeper calls it once its time has come.
                Rules keeper;
                note(keeper, "R24");
                add(s.clauses, number, k, "keeper",
                    w_.say("when-keeper", {{"function", plain(function_)}}), keeper);
            }
            consents(r.consents, s.clauses, number, k);
            for (const m::Do& d : r.actions) {
                act(d, s.clauses, number, k);
            }
            statements(r.body, s.clauses, number, k);
        }
        function_.clear();
    }

    // --- The rules, and the whole text.

    void rules_section() {
        if (used_.empty()) {
            return;
        }
        out_.rules_number = std::to_string(out_.sections.size() + 1);
        out_.rules_title = w_.say("section-rules");
        for (const std::string_view id : used_) {
            out_.rules.emplace_back(id, w_.say("rule-" + std::string(id)));
        }
    }

    void write_text() {
        std::string& t = out_.text;
        t = out_.title + "\n\n" + out_.intro + "\n";
        if (!out_.packs.empty()) {
            t += out_.packs + "\n";
        }
        for (const ExplainedSection& s : out_.sections) {
            t += "\n" + s.number + ". " + s.title + "\n";
            if (!s.note.empty()) {
                t += s.note + "\n";
            }
            for (const ExplainedClause& c : s.clauses) {
                const auto depth = static_cast<std::size_t>(std::ranges::count(c.number, '.'));
                if (c.kind == "action" || (c.kind == "when" && depth == 1)) {
                    // Each action and each time rule set apart.
                    t += "\n";
                }
                t.append(depth > 1 ? 2 * (depth - 1) : 0, ' ');
                Rules rules(c.rules.begin(), c.rules.end());
                t += c.number + " " + c.text + w_.mark(rules) + "\n";
            }
        }
        if (!out_.rules.empty()) {
            t += "\n" + out_.rules_number + ". " + out_.rules_title + "\n";
            for (const auto& [id, text] : out_.rules) {
                t +=
                    w_.say("rule-line", {{"rule", plain(std::string(id))}, {"text", plain(text)}}) +
                    "\n";
            }
        }
    }
};

} // namespace

Explained explain(const model::Model& model, const Pack* language) {
    return Explainer(model, language).run();
}

ExplainedState explain_state(const model::Model& model, const cbor::Value& state,
                             const Pack* language, const LedgerLabel& ledger) {
    const Writer w(language);
    ExplainedState out;
    if (const cbor::Value* name = state.find("state"); name != nullptr && name->as_text()) {
        for (const model::State& s : model.states) {
            if (wire_name(s.word, s.name) == *name->as_text()) {
                out.state = s.word != nullptr ? w.word(s.word).text : s.name;
            }
        }
    }
    const cbor::Value* fields = state.find("fields");
    if (fields == nullptr || fields->as_map() == nullptr) {
        return out;
    }
    for (const model::Field& f : model.fields) {
        if (f.kind != model::FieldKind::instance) {
            continue;
        }
        if (const cbor::Value* v = fields->find(std::string_view(wire_name(f.word, f.name)))) {
            out.fields.push_back(ExplainedValue{f.word != nullptr ? w.word(f.word).text : f.name,
                                                w.value(f.type, *v, ledger)});
        }
    }
    return out;
}

std::string quoted_text(std::string_view text, const Pack* language) {
    return Writer(language).quoted(text);
}

} // namespace cexchain::bo
