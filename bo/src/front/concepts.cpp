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

// Edition 1: the keywords of bo-1.0 and Bo's core words (D-054). Append only:
// once an edition is released, its concepts never change meaning. The
// official vocabulary packs' words, which a source declares with `use`, are
// defined by their files (bo/vocab/; vocab.cpp), and join these in the
// edition's table (concepts()).
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
    // Requests (E8, language packs version 5): `request KIND [to PARTY]
    // [with NAME = VALUE, ...] within DURATION`, and the rules and test
    // steps for their answers, `when KIND done`, `fails`, or `expires`. The
    // outcomes are keywords only there (is_contextual).
    {"kw.request", keyword, 0, Vocab::core, {}, 0, false, nullptr, requests_version},
    {"kw.done", keyword, 0, Vocab::core, {}, 0, false, nullptr, requests_version},
    {"kw.fails", keyword, 0, Vocab::core, {}, 0, false, nullptr, requests_version},
    {"kw.expires", keyword, 0, Vocab::core, {}, 0, false, nullptr, requests_version},
    // What a block declares.
    {"kind.thing", kind, 0},
    // Retired (Concept::retired): spelled only by the packs of before
    // vocabulary packs, so that their deploys rebuild.
    {"kind.record", kind, 0, Vocab::core, {}, 0, true},
    // Business actions.
    {"act.issue", action, 0},
    {"act.transfer", action, 0},
    {"act.merge", action, 0, Vocab::core, {}, 0, true},
    {"act.cancel", action, 0},
    {"act.suspend", action, 0},
    {"act.resume", action, 0},
    {"act.terminate", action, 0},
    {"act.approve", action, 0},
    {"act.propose", action, 0},
    {"act.notify", action, 0},
    // A test step that creates an instance that is not an asset (`we create`;
    // an asset is issued).
    {"act.create", action, 0},
    // Conditions.
    {"cond.over", condition, 1},
    {"cond.in_person", condition, 0},
    {"cond.consent_of", condition, 1},
    {"cond.overdue", condition, 0},
    {"cond.before_due", condition, 1},
    {"cond.within", condition, 1},
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
    // A temperature (G5b), also written °C or ℃ in every language.
    {"unit.celsius", unit, 0},
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
    // No party: what a party field holds before an action sets it
    // (`pledgee = none`; milestone 11).
    {"val.none", value, 0},
    // A test's expectation that an AI agent's call is kept as a proposal
    // (`-> pending approval`).
    {"val.pending_approval", value, 0},
    // Fields.
    {"field.holder", field, 0, Vocab::core, "party", field_taking},
    {"field.amount", field, 0, Vocab::core, "amount"},
    {"field.due", field, 0, Vocab::core, "date"},
    {"field.quantity", field, 0, Vocab::core, "quantity"},
    {"field.parts", field, 0, Vocab::core, "list"},
    // The contract's offset from UTC (U6, milestone 12): a constant text
    // such as "+08:00" in the kind's block.
    {"field.utc_offset", field, 0, Vocab::core, "offset"},
    // The parties a split's parts go to, one for each part (the standard
    // library's split; milestone 17): a list of parties (R1).
    {"field.recipients", field, 0, Vocab::core, "parties"},
    // States.
    {"state.active", state, 0},
    {"state.proposed", state, 0},
    {"state.suspended", state, 0},
    {"state.terminated", state, 0},
    {"state.cancelled", state, 0},
    // An instance that issued its parts (the standard library's split): it
    // has ended, and its parts carry on.
    {"state.divided", state, 0},
    // Who acts.
    {"actor.person", actor, 0},
    {"actor.ai_agent", actor, 0},
    {"actor.device", actor, 0},
    // The device that calls a contract's time rules when their time comes
    // (a test step `keeper suspend`; milestone 12).
    {"actor.keeper", actor, 0},
    // The device that carries out a contract's requests outside the ledger
    // and answers them (a test step `executor notify done`; E8).
    {"actor.executor", actor, 0},
    // Common roles.
    {"role.we", role, 0},
    // The party an action names after `to`: in the standard library's terms,
    // and, when the contract does not declare it, named by each call (R21).
    {"role.counterparty", role, 0},
    // Built-in expressions.
    {"expr.sum_of", expression, 1},
    {"expr.count_of", expression, 1},
    {"expr.at_most", expression, 1},
    // `frozen -> previous state`: the state the instance was in before it
    // entered its current one.
    {"expr.previous_state", expression, 0},
    // In a rule for answers (E8): the answer's result and reason, as texts;
    // names everywhere else (is_contextual).
    {"expr.result", expression, 0},
    {"expr.reason", expression, 0},
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
static_assert(keywords == 22, "bo-1.0 has 18 keywords, and E8 added four");

constexpr std::size_t words_of(Vocab pack) {
    return static_cast<std::size_t>(std::ranges::count_if(unsorted_concepts, [&](const Concept& c) {
        return c.category != keyword && !c.retired && c.pack == pack;
    }));
}

// D-054: an 80-word core and three official vocabulary packs; G5b added a
// unit of temperature to the core, and E8 the executor and an answer's result
// and reason.
static_assert(words_of(Vocab::core) == 84, "the core has 84 words");
static_assert(std::ranges::all_of(unsorted_concepts,
                                  [](const Concept& c) {
                                      return (c.category == field) == !c.type.empty() || c.retired;
                                  }),
              "every field, and only a field, has a type");

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
    {"vocab.syntax", Severity::error, "detail"},
    {"vocab.too-large", Severity::error, "size limit"},
    {"vocab.format", Severity::error, "value"},
    {"vocab.bad-id", Severity::error, "value"},
    {"vocab.official-id", Severity::error, "value"},
    {"vocab.bad-language", Severity::error, "value"},
    {"vocab.bad-requires", Severity::error, "path value"},
    {"vocab.bad-concept", Severity::error, "path concept"},
    {"vocab.category", Severity::error, "path category"},
    {"vocab.shadows", Severity::error, "path concept other"},
    {"vocab.argument", Severity::error, "path"},
    {"vocab.type", Severity::error, "path value"},
    {"vocab.flag", Severity::error, "path"},
    {"vocab.unit", Severity::error, "path"},
    {"vocab.bad-terms", Severity::error, "path"},
    {"vocab.unspelled", Severity::error, "language concept"},
    {"vocab.not-own", Severity::error, "path concept"},
    {"vocab.duplicate-spelling", Severity::error, "pack spelling concept other"},
    {"vocab.bad-attach", Severity::error, "path concept"},
    {"vocab.conflict", Severity::error, "pack spelling meaning"},
    {"vocab.duplicate-id", Severity::error, "pack"},
    {"vocab.unknown-requires", Severity::error, "pack other"},
    {"vocab.cycle", Severity::error, "pack"},
    {"vocab.no-language", Severity::warning, "pack language"},
    {"vocab.terms", Severity::error, "pack line code"},
    {"vocab.terms-clause", Severity::error, "pack line"},
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
    // `request KIND [to PARTY] [with NAME = VALUE, ...] within DURATION` (E8).
    {"parse.request", Severity::error, "found"},
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
    // Vocabulary packs (D-054): `use finance`.
    {"check.unknown-pack", Severity::error, "pack"},
    {"check.pack-not-used", Severity::error, "word pack"},
    {"check.pack-requires", Severity::error, "pack other"},
    {"check.duplicate", Severity::error, "name"},
    {"check.one-kind", Severity::error, "name"},
    {"check.unknown-name", Severity::error, "name"},
    {"check.unknown-party", Severity::error, "party"},
    {"check.unknown-field", Severity::error, "field"},
    {"check.unknown-input", Severity::error, "name action"},
    {"check.field-head", Severity::error, "text"},
    {"check.field-needs-type", Severity::error, "field"},
    {"check.default-field", Severity::error, "field"},
    {"check.default-value", Severity::error, "text"},
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
    {"check.each-body", Severity::error, "text"},
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
    // Checking: built-in actions and their standard terms (milestone 11).
    {"check.standard-by", Severity::error, "action party"},
    {"check.standard-to", Severity::error, "action"},
    {"check.standard-change", Severity::error, "action text"},
    {"check.standard-field", Severity::error, "action field"},
    {"check.standard-unreachable", Severity::error, "action states"},
    // Checking: time rules.
    {"check.when-event", Severity::error, "text"},
    {"check.when-person", Severity::error, "text"},
    {"check.needs-due", Severity::error, "text"},
    {"check.when-action", Severity::error, "action"},
    {"check.utc-offset", Severity::error, "text"},
    // Checking: charges.
    {"check.charge-field", Severity::error, "text"},
    {"check.charge-rate", Severity::error, "name"},
    {"check.charge-included", Severity::error, "name"},
    // Bills and charges computed (milestone 13).
    {"check.document", Severity::error, "field"},
    {"check.charge-document", Severity::error, "name"},
    {"check.charge-twice", Severity::error, "name text"},
    {"check.charge-on", Severity::error, "name other"},
    {"check.charge-rounding", Severity::error, "name"},
    {"check.charge-bill", Severity::error, "name document"},
    // Checking: what comes in later steps.
    {"check.needs-executor", Severity::warning, "action"},
    // notify PARTY, a request of its own (R10, E9).
    {"check.notify", Severity::error, "text"},
    {"check.service-bill", Severity::error, "text"},
    // Checking: requests and the rules for their answers (E8).
    {"check.request-kind", Severity::error, "text"},
    {"check.request-value", Severity::error, "name type"},
    {"check.request-within", Severity::error, "text"},
    {"check.request-count", Severity::error, "function count"},
    {"check.answer-twice", Severity::error, "text"},
    {"check.answer-unasked", Severity::warning, "kind"},
    {"check.answer-line", Severity::error, "text"},
    // Checking: tests (U8).
    {"check.test-start", Severity::error, "action"},
    {"check.test-again", Severity::error, "action"},
    {"check.test-creation", Severity::error, "text action"},
    {"check.test-home", Severity::error, "party"},
    {"check.test-action", Severity::error, "action"},
    {"check.test-party", Severity::error, "text"},
    {"check.test-to", Severity::error, "action"},
    {"check.test-counterparty", Severity::error, "action party"},
    {"check.test-signer", Severity::error, "text"},
    {"check.test-step", Severity::error, "text"},
    {"check.test-time", Severity::error, "text"},
    {"check.test-time-back", Severity::error, "text"},
    {"check.test-value", Severity::error, "text"},
    {"check.test-missing", Severity::error, "action name"},
    {"check.test-expect", Severity::error, "text"},
    {"check.test-field", Severity::error, "name"},
    {"check.test-fields", Severity::error, "text"},
    {"check.test-expect-step", Severity::error, ""},
    {"check.test-reason", Severity::error, "text"},
    {"check.test-proposal", Severity::error, "action"},
    {"check.test-needs-to", Severity::error, "action"},
    {"check.test-rule", Severity::error, "action"},
    {"check.test-keeper", Severity::error, "text"},
    // A step answers a request the contract makes (E8).
    {"check.test-answer", Severity::error, "text"},
    // A step names the instance it acts on by its holder (milestone 17).
    {"check.test-part", Severity::error, "text"},
    // Issuing parts (R30, milestone 17).
    {"check.parts-place", Severity::error, "text"},
    {"check.parts-shape", Severity::error, "text"},
    {"check.parts-instance", Severity::error, "action"},
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
    {"build.too-many-charges", Severity::error, "limit"},
    {"build.too-large", Severity::error, ""},
    {"build.reject-text", Severity::error, "text"},
    {"build.late-party", Severity::error, "field party"},
    {"build.fuel", Severity::error, "function bound limit"},
    {"build.output", Severity::warning, "function bound limit"},
    {"build.comments", Severity::warning, "count"},
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
    {"run.empty", Severity::error, "party"},
    {"run.pending", Severity::error, ""},
    {"run.proposal", Severity::error, ""},
    {"run.approve", Severity::error, "action"},
    {"run.when", Severity::error, "rule"},
    {"run.fired", Severity::error, "rule"},
    {"run.depth", Severity::error, "action"},
    {"run.parts", Severity::error, "action"},
    // Requests and answers (E8).
    {"run.request", Severity::error, "kind"},
    {"run.answer", Severity::error, ""},
    // The formatter (bo fmt).
    {"fmt.unstable", Severity::error, "language"},
    {"fmt.internal", Severity::error, ""},
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

// The sentences of the contract text (`explain`, explain.hpp), and their
// parameters. A placeholder may ask for a form of a word: "{party.object}".
constexpr SentenceSpec unsorted_sentences[] = {
    // The text: its title, its introduction, the rule marks, the sections.
    {"contract", "name"},
    {"fragment", ""},
    {"intro", "edition"},
    // The vocabulary packs a contract uses (D-054): "the finance pack,
    // version 1", each named in the reader's language.
    {"packs-used", "packs"},
    {"vocab-pack", "pack version"},
    {"vocab-core", ""},
    {"vocab-finance", "", true},
    {"vocab-commerce", "", true},
    {"vocab-services", "", true},
    {"mark", "rules"},
    {"rule-line", "rule text"},
    {"section-parties", ""},
    {"section-instance", ""},
    {"section-charges", ""},
    {"section-states", ""},
    {"section-actions", ""},
    {"section-time", ""},
    {"section-rules", ""},
    {"section-answers", ""},
    // Parties.
    {"party-creation", "party"},
    {"party-action", "party action"},
    {"party-each", "party action"},
    // What each instance records.
    {"instance-kind", "kind name"},
    {"instance-none", ""},
    {"field-given", "field type"},
    {"field-default", "field type value"},
    {"field-party", "field type party"},
    {"field-constant", "field value"},
    {"field-empty", "field type"},
    {"field-empty-date", "field type"},
    {"creation", "function"},
    // States.
    {"state-first", "state"},
    {"states-all", "states"},
    {"state-final", "state"},
    {"states-no-final", ""},
    {"events", ""},
    // Actions.
    {"actions-note", ""},
    {"action-function", "action function"},
    {"action-standard", "action"},
    {"action-terms", "action function"},
    {"action-terms-pack", "action function pack"},
    {"action-home", ""},
    {"action-home-start", ""},
    {"action-rule-only", ""},
    {"action-by", "party"},
    {"action-to", "party"},
    {"action-inputs", "inputs"},
    {"input", "input type"},
    {"consent-binds", "party"},
    {"consent-rebinds", "party"},
    {"consent-taken", "field"},
    {"consent-call", "party input"},
    {"consent-takes", "party field"},
    {"requirement", "number need"},
    {"requirement-if", "number guard need"},
    {"need-consent", "party"},
    {"need-in-person", "party"},
    {"starter", ""},
    {"if", "condition"},
    {"otherwise", ""},
    {"reject", "message"},
    {"set", "field value"},
    {"transition", "state"},
    {"transition-from", "from state"},
    {"transition-previous", "from"},
    {"each", "item list"},
    {"do", "action"},
    {"do-executor", "action"},
    {"do-duty", "party action"},
    {"do-rule", "action"},
    {"do-parts", "parts recipients state"},
    {"parts-set", "field value"},
    {"parts-depth", "function"},
    {"parts-privacy", ""},
    {"action-args", "action args"},
    {"action-to-party", "action party"},
    {"action-by-party", "action party"},
    {"action-with", "action inputs"},
    {"agents-delegation", ""},
    {"agents-propose", ""},
    {"approve", "function"},
    {"action-executor", ""},
    // Time rules.
    {"due-field", "field"},
    {"due-period", ""},
    {"when", "event"},
    {"when-date", "date"},
    {"when-keeper", "function"},
    {"utc-offset", "offset"},
    // Requests and the rules for their answers (E8).
    {"request", "kind duration"},
    {"request-to", "kind party duration"},
    {"request-due", "kind duration"},
    {"request-to-due", "kind party duration"},
    {"request-values", "values"},
    {"request-failure", "kind"},
    {"request-failure-expiry", "kind"},
    {"request-expiry-only", "kind"},
    {"request-no-failure", ""},
    {"answers-note", "function"},
    {"answer-done", "kind"},
    {"answer-fails", "kind"},
    {"answer-fails-expired", "kind"},
    {"answer-expires", "kind"},
    // Charges.
    {"charge", "kind name"},
    {"charge-rate", "rate"},
    {"charge-amount", "value"},
    {"charge-applies", "condition"},
    {"charge-included", ""},
    {"charge-added", ""},
    {"charge-per-line", "rounding"},
    {"charge-per-document", "rounding"},
    {"charge-by-document", "document rounding"},
    {"charge-from", "date rate"},
    {"charge-other", "text"},
    {"charge-bill", "document"},
    {"charge-on", "base"},
    {"charge-price", ""},
    {"charge-once", ""},
    {"charge-each-line", ""},
    // Values.
    {"value-money", "currency amount"},
    {"value-unit", "amount unit"},
    {"value-unit-one", "amount unit"},
    {"value-unit-price", "money unit"},
    {"value-labelled", "label value"},
    {"value-basis", "field"},
    {"value-text", "text"},
    {"value-now", ""},
    {"value-today", ""},
    {"value-result", ""},
    {"value-reason", ""},
    {"value-amount", ""},
    {"value-separator", ""},
    {"list-separator", ""},
    {"list-and", "rest last"},
    {"list-and-many", "rest last"},
    {"list-or", "rest last"},
    {"list-or-many", "rest last"},
    {"group", "text"},
    // Conditions and operators.
    {"cond-state", "state"},
    {"cond-not-state", "state"},
    {"cond-consent", "party"},
    {"cond-in-person", "party"},
    {"cond-over", "amount value"},
    {"cond-overdue", ""},
    {"cond-overdue-by", "duration"},
    {"cond-before-due", "duration"},
    {"cond-within", "duration"},
    {"cond-held", "state duration"},
    {"cond-not-within", "duration"},
    {"cond-from-date", "date"},
    {"cond-not-overdue", ""},
    {"cond-not-overdue-by", "duration"},
    {"op-not", "operand"},
    {"op-not-equals", "left right"},
    {"op-and", "left right"},
    {"op-or", "left right"},
    {"op-equals", "left right"},
    {"op-no-date", "left"},
    {"op-equals-date", "left right"},
    {"op-less", "left right"},
    {"op-less-equal", "left right"},
    {"op-greater", "left right"},
    {"op-greater-equal", "left right"},
    {"op-before", "left right"},
    {"op-after", "left right"},
    {"op-on-or-before", "left right"},
    {"op-on-or-after", "left right"},
    {"op-in", "left right"},
    {"op-whole-times", "left right"},
    {"expr-sum", "list"},
    {"expr-count", "list"},
    {"expr-at-most", "value"},
    // Types, for messages (and the contract text): "money in {currency}".
    {"type-number", ""},
    {"type-money", "currency"},
    {"type-any-money", ""},
    {"type-data", ""},
    {"type-bandwidth", ""},
    {"type-count", ""},
    {"type-mass", ""},
    {"type-temperature", ""},
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
    // The results of tests (bo test).
    {"test-passed", "name"},
    {"test-failed", "name step"},
    {"test-unnamed", "number"},
    {"test-summary", "total passed failed"},
    {"test-summary-one", "passed failed"},
    {"test-none", ""},
    {"step-passed", "number line text"},
    {"step-failed", "number line text"},
    {"step-skipped", "number line text"},
    {"step-result", "what"},
    {"step-expected", "what"},
    {"step-clause", "number text"},
    {"step-part", "part"},
    {"step-requests", "requests"},
    {"request-made", "kind deadline"},
    {"outcome-accepted", "state"},
    {"outcome-accepted-consents", "state parties"},
    {"outcome-final", "outcome"},
    {"outcome-waits", "parties"},
    {"outcome-waits-home", "party"},
    {"outcome-waits-both", "parties party"},
    {"outcome-refused", "reason"},
    {"outcome-refused-code", "reason code"},
    {"outcome-no-instance", ""},
    {"outcome-final-instance", ""},
    // Answers to requests (E8).
    {"outcome-no-request", "kind"},
    {"outcome-early", "kind deadline"},
    {"outcome-too-many-requests", ""},
    {"outcome-broken", "detail"},
    {"outcome-proposed", "action"},
    {"outcome-no-part", "party"},
    {"outcome-no-part-step", ""},
    {"expect-accepted", ""},
    {"expect-state", "state"},
    {"expect-refused", ""},
    {"expect-refused-reason", "reason"},
    {"expect-waits", "parties"},
    {"expect-waits-home", "party"},
    {"expect-waits-both", "parties party"},
    {"expect-proposed", ""},
    {"expect-fields", "what fields"},
    {"outcome-fields", "what fields"},
    {"field-is", "field value"},
    // The standard library (bo stdlib).
    {"stdlib-starter", "party"},
    {"stdlib-home", ""},
    {"stdlib-counterparty", ""},
    {"stdlib-states", "from to"},
    {"stdlib-states-kept", "from"},
    {"stdlib-terms", "action"},
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
    {"rule-R19", ""},
    {"rule-R20", ""},
    {"rule-R21", ""},
    {"rule-R22", ""},
    {"rule-R23", ""},
    {"rule-R24", ""},
    {"rule-R25", ""},
    {"rule-R26", ""},
    {"rule-R27", ""},
    {"rule-R28", ""},
    {"rule-R29", ""},
    {"rule-R30", ""},
    {"rule-R31", ""},
    {"rule-R32", ""},
    {"rule-R33", ""},
    {"rule-R34", ""},
    {"rule-R35", ""},
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
    {"R1", "field-meaning"},                 // a vocabulary field has the vocabulary's type
    {"R2", "party-field"},                   // a field given a party: per instance, and may change
    {"R3", "role-binding"},                  // roles: at creation, or by the first `to` (U4)
    {"R4", "first-state"},                   // the one state nothing leads to, else active
    {"R5", "states"},                        // the states are those state changes name
    {"R6", "threshold"},                     // over N: the action's one amount (plan 5.1, item 7)
    {"R7", "state-condition"},               // a state as a condition: the instance is in it
    {"R8", "consent-taken"},                 // changing a party's field needs that party's consent
    {"R9", "obligation"},                    // when due issuer pays: a duty, no call (U7)
    {"R10", "executor"},                     // notify, a service's changes: requests (E9)
    {"R11", "service-due", Vocab::services}, // a recurring price: due when paid until
    {"R12", "customer-location", Vocab::commerce}, // customer location: text each instance holds
    {"R13", "presence"},                           // in person: the starter's presence (U2)
    {"R14", "agents"},          // AI agents within delegation, unless propose (U3)
    {"R15", "parts"},           // parts: a list of amounts
    {"R16", "list-bound"},      // lists: at most 16 items (plan 5.1, item 8)
    {"R17", "rounding"},        // products and quotients round half up (U5)
    {"R18", "bare-text"},       // an undeclared name compared with text is text
    {"R19", "standard-terms"},  // a built-in action has the standard library's terms
    {"R20", "standard-fields"}, // fields the standard terms use: added, empty at first
    {"R21", "counterparty"},    // an undeclared counterparty: each call names it
    {"R22", "zero"},            // a bare 0 is zero of any amount
    {"R23", "each-allocation", Vocab::services}, // allocate binds its role again on each call
    {"R24", "keeper"},                           // a time rule: a function a keeper calls in time
    {"R25", "utc-offset"},                       // dates and days at UTC+08:00 unless written (U6)
    {"R26", "bill", Vocab::commerce},            // a document's field: a bill, made when it is set
    {"R27", "charges", Vocab::commerce},         // charges in order: on the price and earlier ones
    {"R28", "rate-in-force", Vocab::commerce},   // the rate in force at the bill's time (U9)
    {"R29", "one-item"},                         // one value where a list is needed: a list of one
    {"R30", "issue-parts"},   // issue PARTS to RECIPIENTS: parts are instances of their own
    {"R31", "role-taking"},   // a counterparty made holder, pledgee, or payee consents
    {"R32", "whole-times"},   // a duration by a duration: whole times, the rest dropped
    {"R33", "expired-fails"}, // an expired request is a failed one, unless a rule says otherwise
    {"R34", "service-bill", Vocab::services}, // each period billed: invoice, then collect (E9)
    {"R35", "service-paid", Vocab::services}, // a collection done pays a period, resumes (E9)
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

std::span<const Concept> core_concepts() noexcept {
    return sorted_concepts;
}

std::string_view unit_symbol(const Concept* c) noexcept {
    return c != nullptr && c->id == "unit.celsius" ? std::string_view("\u00B0C")
                                                   : std::string_view();
}

const Concept* find_core_concept(std::string_view id) noexcept {
    return find_sorted(sorted_concepts, id, &Concept::id);
}

std::size_t keyword_count() noexcept {
    return keywords;
}

bool is_contextual(const Concept* c) noexcept {
    return c != nullptr && (c->id == "kw.done" || c->id == "kw.fails" || c->id == "kw.expires" ||
                            c->id == "expr.result" || c->id == "expr.reason");
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
