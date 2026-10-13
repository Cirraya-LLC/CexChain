// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The concepts of edition 1, the compiler's messages, and the sentences
// `explain` writes. The spellings and texts are in the language packs
// (bo/packs/).

#include <algorithm>
#include <array>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <string_view>

#include <cexchain/bo/concepts.hpp>

namespace cexchain::bo {

namespace {

using enum Category;

// Edition 1: the keywords of bo-1.0, the vocabulary of its section 4, and the
// words its examples need (types, fields, states, actors, roles, built-in
// expressions, and charges). Append only: once an edition is released, its
// concepts never change meaning.
constexpr Concept unsorted_concepts[] = {
    // Keywords.
    {"kw.contract", keyword, 0},
    {"kw.parties", keyword, 0},
    {"kw.can", keyword, 0},
    {"kw.by", keyword, 0},
    {"kw.to", keyword, 0},
    {"kw.with", keyword, 0},
    {"kw.requires", keyword, 0},
    {"kw.when", keyword, 0},
    {"kw.if", keyword, 0},
    {"kw.otherwise", keyword, 0},
    {"kw.and", keyword, 0},
    {"kw.or", keyword, 0},
    {"kw.not", keyword, 0},
    {"kw.each", keyword, 0},
    {"kw.in", keyword, 0},
    {"kw.reject", keyword, 0},
    {"kw.test", keyword, 0},
    {"kw.use", keyword, 0},
    // What a block declares.
    {"kind.asset", kind, 0},
    {"kind.service", kind, 0},
    {"kind.resource", kind, 0},
    {"kind.record", kind, 0},
    // Business actions.
    {"act.issue", action, 0},
    {"act.transfer", action, 0},
    {"act.pledge", action, 0},
    {"act.release", action, 0},
    {"act.enforce", action, 0},
    {"act.redeem", action, 0},
    {"act.split", action, 0},
    {"act.merge", action, 0},
    {"act.cancel", action, 0},
    {"act.pay", action, 0},
    {"act.confirm_payment", action, 0},
    {"act.dispute", action, 0},
    {"act.refund", action, 0},
    {"act.credit", action, 0},
    {"act.subscribe", action, 0},
    {"act.renew", action, 0},
    {"act.upgrade", action, 0},
    {"act.downgrade", action, 0},
    {"act.suspend", action, 0},
    {"act.resume", action, 0},
    {"act.terminate", action, 0},
    {"act.allocate", action, 0},
    {"act.reclaim", action, 0},
    {"act.freeze", action, 0},
    {"act.unfreeze", action, 0},
    {"act.approve", action, 0},
    {"act.propose", action, 0},
    {"act.notify", action, 0},
    // Conditions.
    {"cond.over", condition, 1},
    {"cond.in_person", condition, 0},
    {"cond.consent_of", condition, 1},
    {"cond.overdue", condition, 0},
    {"cond.before_due", condition, 1},
    {"cond.within", condition, 1},
    // Prices and usage.
    {"price.price", pricing, 0},
    {"price.usage", pricing, 0},
    {"price.traffic", pricing, 0},
    {"price.overage", pricing, 0},
    {"price.per", pricing, 0},
    {"price.setup_fee", pricing, 0},
    {"price.proration", pricing, 0},
    // Charges: taxes, fees, commissions, discounts.
    {"charge.charge", charge, 0},
    {"charge.tax", charge, 0},
    {"charge.rate", charge, 0},
    {"charge.applies_to", charge, 1},
    {"charge.from", charge, 1},
    {"charge.included", charge, 0},
    {"charge.added", charge, 0},
    {"charge.per_line", charge, 0},
    {"charge.per_document", charge, 0},
    {"charge.by", charge, 0},
    // Time.
    {"time.day", time, 0},
    {"time.week", time, 0},
    {"time.month", time, 0},
    {"time.year", time, 0},
    {"time.daily", time, 0},
    {"time.weekly", time, 0},
    {"time.monthly", time, 0},
    {"time.yearly", time, 0},
    {"time.now", time, 0},
    {"time.today", time, 0},
    // When a test's step happens (`at 2027-01-06`).
    {"time.at", time, 1},
    // Units: TB is 1,000 GB, TiB 1,024 GiB.
    {"unit.MB", unit, 0},
    {"unit.GB", unit, 0},
    {"unit.TB", unit, 0},
    {"unit.MiB", unit, 0},
    {"unit.GiB", unit, 0},
    {"unit.TiB", unit, 0},
    {"unit.Mbps", unit, 0},
    {"unit.Gbps", unit, 0},
    {"unit.item", unit, 0},
    {"unit.kg", unit, 0},
    {"unit.tonne", unit, 0},
    // Currencies.
    {"cur.HKD", currency, 0},
    {"cur.CNY", currency, 0},
    {"cur.USD", currency, 0},
    {"cur.SGD", currency, 0},
    {"cur.EUR", currency, 0},
    // Rounding modes.
    {"round.half_up", rounding, 0},
    {"round.half_even", rounding, 0},
    {"round.down", rounding, 0},
    // Documents.
    {"doc.invoice", document, 0},
    {"doc.credit_note", document, 0},
    {"doc.receipt", document, 0},
    // Types and values.
    {"type.date", type, 0},
    {"type.text", type, 0},
    {"type.number", type, 0},
    {"type.yes_no", type, 0},
    {"type.list", type, 0},
    {"val.yes", value, 0},
    {"val.no", value, 0},
    // A test's expectation that a step is refused (`-> refused`).
    {"val.refused", value, 0},
    // Fields.
    {"field.holder", field, 0},
    {"field.amount", field, 0},
    {"field.due", field, 0},
    {"field.quantity", field, 0},
    {"field.tier", field, 0},
    {"field.pledgee", field, 0},
    {"field.parts", field, 0},
    {"field.customer_location", field, 0},
    {"field.cooling_period", field, 0},
    // States.
    {"state.active", state, 0},
    {"state.proposed", state, 0},
    {"state.pledged", state, 0},
    {"state.paid", state, 0},
    {"state.settled", state, 0},
    {"state.frozen", state, 0},
    {"state.suspended", state, 0},
    {"state.terminated", state, 0},
    {"state.cancelled", state, 0},
    // Who acts.
    {"actor.person", actor, 0},
    {"actor.ai_agent", actor, 0},
    {"actor.device", actor, 0},
    // Common roles.
    {"role.we", role, 0},
    {"role.customer", role, 0},
    {"role.supplier", role, 0},
    {"role.bank", role, 0},
    {"role.issuer", role, 0},
    // Built-in expressions.
    {"expr.sum_of", expression, 1},
    {"expr.count_of", expression, 1},
    {"expr.at_most", expression, 1},
};

constexpr std::size_t concept_count = std::size(unsorted_concepts);

constexpr auto sorted_concepts = [] {
    std::array<Concept, concept_count> out{};
    std::ranges::copy(unsorted_concepts, out.begin());
    std::ranges::sort(out, {}, &Concept::id);
    return out;
}();

static_assert(std::ranges::adjacent_find(sorted_concepts, {}, &Concept::id) ==
                  sorted_concepts.end(),
              "concept ids are unique");

constexpr std::size_t keywords =
    static_cast<std::size_t>(std::ranges::count(unsorted_concepts, keyword, &Concept::category));
static_assert(keywords == 18, "bo-1.0 has 18 keywords");

constexpr MessageSpec unsorted_messages[] = {
    // Reading a pack.
    {"pack.syntax", Severity::error, "detail"},
    {"pack.too-large", Severity::error, "size limit"},
    {"pack.expected-map", Severity::error, "path"},
    {"pack.expected-text", Severity::error, "path"},
    {"pack.expected-list", Severity::error, "path"},
    {"pack.expected-integer", Severity::error, "path"},
    {"pack.expected-boolean", Severity::error, "path"},
    {"pack.unknown-key", Severity::error, "path key"},
    {"pack.missing-key", Severity::error, "path key"},
    {"pack.format", Severity::error, "value"},
    {"pack.edition", Severity::error, "value"},
    {"pack.bad-id", Severity::error, "value"},
    {"pack.bad-language", Severity::error, "value"},
    {"pack.bad-version", Severity::error, "value"},
    {"pack.bad-text", Severity::error, "path"},
    {"pack.bad-value", Severity::error, "path value"},
    {"pack.too-many", Severity::error, "path limit"},
    // Concepts and their spellings.
    {"pack.unknown-concept", Severity::error, "path concept"},
    {"pack.wrong-category", Severity::error, "path concept category"},
    {"pack.missing-keyword", Severity::error, "pack concept"},
    {"pack.partial", Severity::warning, "pack missing total"},
    {"pack.bad-spelling", Severity::error, "path spelling"},
    {"pack.bad-character", Severity::error, "path spelling character"},
    {"pack.needs-hole", Severity::error, "path spelling concept"},
    {"pack.unexpected-hole", Severity::error, "path spelling concept"},
    {"pack.bad-form", Severity::error, "path form"},
    // Never guess.
    {"pack.duplicate-spelling", Severity::error, "pack spelling concept other"},
    {"pack.conflict", Severity::error, "spelling pack meaning other_pack other"},
    {"pack.ambiguous-attachment", Severity::error, "spelling meaning first second"},
    // Reading rules.
    {"pack.bad-attach", Severity::error, "path concept"},
    {"pack.unknown-category", Severity::error, "path category"},
    {"pack.bad-punctuation", Severity::error, "path character"},
    {"pack.bad-multiplier", Severity::error, "path value"},
    {"pack.bad-date", Severity::error, "path pattern"},
    // Messages and sentences.
    {"pack.unknown-message", Severity::error, "path code"},
    {"pack.unknown-sentence", Severity::error, "path id"},
    {"pack.bad-placeholder", Severity::error, "path placeholder"},
    // Pack sets.
    {"pack.false-official", Severity::error, "pack"},
    {"pack.duplicate-id", Severity::error, "pack"},
    // Reading a source: characters and lines.
    {"lex.too-large", Severity::error, "size limit"},
    {"lex.utf8", Severity::error, ""},
    {"lex.invisible", Severity::error, "character"},
    {"lex.tab", Severity::error, ""},
    {"lex.indent-character", Severity::error, "character"},
    {"lex.dedent", Severity::error, ""},
    {"lex.too-deep", Severity::error, "limit"},
    {"lex.bad-character", Severity::error, "character"},
    // Numbers, dates, texts, the edition.
    {"lex.bad-number", Severity::error, "text"},
    {"lex.digit-comma", Severity::error, "text suggestion"},
    {"lex.number-too-large", Severity::error, "text"},
    {"lex.number-suffix", Severity::error, "text suffix"},
    {"lex.multiplier", Severity::error, "word"},
    {"lex.percent", Severity::error, ""},
    {"lex.bad-date", Severity::error, "text"},
    {"lex.unterminated-text", Severity::error, ""},
    {"lex.text-too-long", Severity::error, "limit"},
    {"lex.edition", Severity::error, "value"},
    {"lex.bad-edition", Severity::error, ""},
    // Words and names: never guess.
    {"lex.ambiguous", Severity::error, "text first second"},
    {"lex.ambiguous-money", Severity::error, "text"},
    {"lex.needs-space", Severity::error, "text first second"},
    {"lex.bad-name", Severity::error, "name"},
    {"lex.name-too-long", Severity::error, "name limit"},
    {"lex.not-normalized", Severity::error, "character"},
    {"lex.mixed-script", Severity::error, "name"},
    {"lex.confusable", Severity::error, "name other"},
    // Parsing: lines and blocks.
    {"parse.top-level", Severity::error, "found"},
    {"parse.statement", Severity::error, "found"},
    {"parse.field", Severity::error, "found"},
    {"parse.step", Severity::error, "found"},
    {"parse.trailing", Severity::error, "found"},
    {"parse.unexpected-block", Severity::error, ""},
    {"parse.empty-block", Severity::error, "word"},
    {"parse.otherwise", Severity::error, "word"},
    {"parse.duplicate", Severity::error, "word"},
    {"parse.reserved", Severity::error, "word"},
    {"parse.too-deep", Severity::error, "limit"},
    // Clauses.
    {"parse.expected-name", Severity::error, "after"},
    {"parse.expected-action", Severity::error, "after"},
    {"parse.expected-party", Severity::error, "after"},
    {"parse.expected-value", Severity::error, "after"},
    {"parse.expected-text", Severity::error, "after"},
    {"parse.expected-state", Severity::error, "after"},
    {"parse.expected-set", Severity::error, "after"},
    {"parse.can", Severity::error, "found"},
    {"parse.when", Severity::error, ""},
    {"parse.each", Severity::error, ""},
    {"parse.bare-condition", Severity::error, ""},
    // Expressions.
    {"parse.unclosed", Severity::error, ""},
    {"parse.missing-head", Severity::error, "text concept"},
    {"parse.missing-tail", Severity::error, "text concept"},
    {"parse.missing-argument", Severity::error, "text concept"},
    {"parse.chained-comparison", Severity::error, "operator"},
    {"parse.phrase-operator", Severity::error, "operator"},
    // Names: never guess.
    {"parse.ambiguous-name", Severity::error, "name prefix rest"},
    {"parse.undeclared-split", Severity::error, "name prefix rest"},
    // Checking: the contract and its declarations.
    {"check.fragment", Severity::warning, ""},
    {"check.no-parties", Severity::error, ""},
    {"check.duplicate", Severity::error, "name"},
    {"check.one-kind", Severity::error, "name"},
    {"check.unknown-name", Severity::error, "name"},
    {"check.unknown-party", Severity::error, "party"},
    {"check.unknown-field", Severity::error, "field"},
    {"check.unknown-input", Severity::error, "name action"},
    {"check.field-head", Severity::error, "text"},
    {"check.field-needs-type", Severity::error, "field"},
    {"check.field-type", Severity::error, "field type expected_type"},
    {"check.field-values", Severity::error, "field"},
    // Checking: values, types, and units.
    {"check.not-a-value", Severity::error, "text"},
    {"check.phrase", Severity::error, "text"},
    {"check.type", Severity::error, "text type expected_type"},
    {"check.operands", Severity::error, "operator left_type right_type"},
    {"check.mixed-currencies", Severity::error, "left_type right_type"},
    {"check.mixed-units", Severity::error, "left_type right_type"},
    {"check.calendar", Severity::error, "text"},
    {"check.precision", Severity::error, "text"},
    {"check.whole-number", Severity::error, "text"},
    {"check.overflow", Severity::error, "text"},
    {"check.zero-division", Severity::error, "text"},
    {"check.list-items", Severity::error, "text"},
    {"check.list-bound", Severity::error, "text limit"},
    // Checking: states and actions.
    {"check.set-constant", Severity::error, "field"},
    {"check.set-target", Severity::error, "text"},
    {"check.initial-state", Severity::error, "states"},
    {"check.unreachable-state", Severity::error, "state"},
    {"check.needs-by", Severity::error, "action"},
    {"check.recursion", Severity::error, "action"},
    {"check.permit", Severity::error, "text"},
    {"check.subject", Severity::error, "text"},
    {"check.threshold-amount", Severity::error, "text action"},
    // Checking: time rules.
    {"check.when-event", Severity::error, "text"},
    {"check.when-person", Severity::error, "text"},
    {"check.needs-due", Severity::error, "text"},
    // Checking: charges.
    {"check.charge-field", Severity::error, "text"},
    {"check.charge-rate", Severity::error, "name"},
    {"check.charge-included", Severity::error, "name"},
    // Checking: what comes in later steps.
    {"check.needs-executor", Severity::warning, "action"},
    // Building (lowering a checked model to code).
    {"build.fragment", Severity::error, ""},
    {"build.standard-action", Severity::error, "action"},
    {"build.executor", Severity::error, "action"},
    {"build.time-rule", Severity::error, "text"},
    {"build.unsupported", Severity::error, "text feature"},
    {"build.name-taken", Severity::error, "name"},
    {"build.name-too-long", Severity::error, "name limit"},
    {"build.too-many-functions", Severity::error, "limit"},
    {"build.too-many-parties", Severity::error, "limit"},
    {"build.too-many-fields", Severity::error, "limit"},
    {"build.too-many-inputs", Severity::error, "action limit"},
    {"build.too-many-events", Severity::error, "action limit"},
    {"build.too-large", Severity::error, ""},
    {"build.reject-text", Severity::error, "text"},
    {"build.late-party", Severity::error, "field party"},
    // Refusals of compiled code at run time: the reason "bo:CODE VALUES" is
    // the message run.CODE, its values the parameters in order (render_reason).
    {"run.input", Severity::error, ""},
    {"run.overflow", Severity::error, ""},
    {"run.division-by-zero", Severity::error, ""},
    {"run.date", Severity::error, ""},
    {"run.output", Severity::error, ""},
    {"run.consents", Severity::error, ""},
    {"run.function", Severity::error, ""},
    {"run.arguments", Severity::error, ""},
    {"run.argument", Severity::error, "name"},
    {"run.state", Severity::error, "action"},
    {"run.requires", Severity::error, "action number"},
    {"run.in-person", Severity::error, "action"},
    {"run.party", Severity::error, "party"},
    // Any reading.
    {"bo.truncated", Severity::warning, "limit"},
};

constexpr auto sorted_messages = [] {
    std::array<MessageSpec, std::size(unsorted_messages)> out{};
    std::ranges::copy(unsorted_messages, out.begin());
    std::ranges::sort(out, {}, &MessageSpec::code);
    return out;
}();

static_assert(std::ranges::adjacent_find(sorted_messages, {}, &MessageSpec::code) ==
                  sorted_messages.end(),
              "message codes are unique");

// The sentences of the contract text (`explain`, milestone 8 builds on them).
constexpr SentenceSpec unsorted_sentences[] = {
    {"contract", "name"},
    {"parties", "parties"},
    {"can", "party action"},
    {"can-to", "party action counterparty"},
    {"consent", "party"},
    {"in-person", "party"},
    {"agents-propose", ""},
    {"when", "event action"},
    {"reject", "message"},
    {"recognized", "rule"},
    // Types, for messages (and the contract text): "money in {currency}".
    {"type-number", ""},
    {"type-money", "currency"},
    {"type-any-money", ""},
    {"type-data", ""},
    {"type-bandwidth", ""},
    {"type-count", ""},
    {"type-mass", ""},
    {"type-any-quantity", ""},
    {"type-rate", ""},
    {"type-date", ""},
    {"type-duration", ""},
    {"type-text", ""},
    {"type-yes-no", ""},
    {"type-party", ""},
    {"type-state", ""},
    {"type-list", "element limit"},
    {"type-any-list", ""},
    {"type-unit-price", "currency unit"},
    {"type-recurring", "value period"},
    {"type-basis", ""},
    {"type-unknown", ""},
    // What each recognition rule infers (rule_specs).
    {"rule-R1", ""},
    {"rule-R2", ""},
    {"rule-R3", ""},
    {"rule-R4", ""},
    {"rule-R5", ""},
    {"rule-R6", ""},
    {"rule-R7", ""},
    {"rule-R8", ""},
    {"rule-R9", ""},
    {"rule-R10", ""},
    {"rule-R11", ""},
    {"rule-R12", ""},
    {"rule-R13", ""},
    {"rule-R14", ""},
    {"rule-R15", ""},
    {"rule-R16", ""},
    {"rule-R17", ""},
    {"rule-R18", ""},
};

constexpr auto sorted_sentences = [] {
    std::array<SentenceSpec, std::size(unsorted_sentences)> out{};
    std::ranges::copy(unsorted_sentences, out.begin());
    std::ranges::sort(out, {}, &SentenceSpec::id);
    return out;
}();

static_assert(std::ranges::adjacent_find(sorted_sentences, {}, &SentenceSpec::id) ==
                  sorted_sentences.end(),
              "sentence ids are unique");

// The recognition rules of edition 1, in the order of their ids. Their
// texts are the packs' sentences "rule-ID". Append only.
constexpr RuleSpec rules[] = {
    {"R1", "field-meaning"},      // a vocabulary field has the vocabulary's type
    {"R2", "party-field"},        // a field given a party: per instance, and may change
    {"R3", "role-binding"},       // roles: at creation, or by the first `to` (U4)
    {"R4", "first-state"},        // the one state nothing leads to, else active
    {"R5", "states"},             // the states are those state changes name
    {"R6", "threshold"},          // over N: the action's one amount (plan 5.1, item 7)
    {"R7", "state-condition"},    // a state as a condition: the instance is in it
    {"R8", "consent-taken"},      // changing a party's field needs that party's consent
    {"R9", "obligation"},         // when due issuer pays: a duty, no call (U7)
    {"R10", "executor"},          // notify, a service's changes: executors (6b)
    {"R11", "service-due"},       // a recurring price: due at each period's end
    {"R12", "customer-location"}, // customer location: text each instance holds
    {"R13", "presence"},          // in person: the starter's presence (U2)
    {"R14", "agents"},            // AI agents within delegation, unless propose (U3)
    {"R15", "parts"},             // parts: a list of amounts
    {"R16", "list-bound"},        // lists: at most 16 items (plan 5.1, item 8)
    {"R17", "rounding"},          // products and quotients round half up (U5)
    {"R18", "bare-text"},         // an undeclared name compared with text is text
};

template <class T, std::size_t N, class Key>
const T* find_sorted(const std::array<T, N>& table, std::string_view id, Key key) noexcept {
    const auto it = std::ranges::lower_bound(table, id, {}, key);
    return it != table.end() && std::invoke(key, *it) == id ? &*it : nullptr;
}

} // namespace

std::optional<Category> category_from_name(std::string_view name) noexcept {
    const auto it = std::ranges::find(category_names, name);
    if (it == category_names.end()) {
        return std::nullopt;
    }
    return static_cast<Category>(it - category_names.begin());
}

std::span<const Concept> concepts() noexcept {
    return sorted_concepts;
}

const Concept* find_concept(std::string_view id) noexcept {
    return find_sorted(sorted_concepts, id, &Concept::id);
}

std::size_t keyword_count() noexcept {
    return keywords;
}

std::span<const MessageSpec> message_specs() noexcept {
    return sorted_messages;
}

const MessageSpec* find_message(std::string_view code) noexcept {
    return find_sorted(sorted_messages, code, &MessageSpec::code);
}

std::span<const SentenceSpec> sentence_specs() noexcept {
    return sorted_sentences;
}

const SentenceSpec* find_sentence(std::string_view id) noexcept {
    return find_sorted(sorted_sentences, id, &SentenceSpec::id);
}

std::span<const RuleSpec> rule_specs() noexcept {
    return rules;
}

const RuleSpec* find_rule(std::string_view id) noexcept {
    const auto it = std::ranges::find(rules, id, &RuleSpec::id);
    return it == std::end(rules) ? nullptr : &*it;
}

bool has_param(std::string_view params, std::string_view name) noexcept {
    while (!params.empty()) {
        const std::size_t space = params.find(' ');
        if (params.substr(0, space) == name) {
            return true;
        }
        if (space == std::string_view::npos) {
            break;
        }
        params.remove_prefix(space + 1);
    }
    return false;
}

} // namespace cexchain::bo
