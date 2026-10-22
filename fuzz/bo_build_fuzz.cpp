// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Fuzzes lowering: source, or a contract
// generated from the input's bytes, through the lexer, the parser, and the
// checker, and on a model without errors, through `lower`. Properties:
//   - lowering never fails an assertion (its contracts and the emitter's are
//     on), and gives the same result twice;
//   - a generated contract gives the same result written in English and with
//     every word in a language chosen at random (the same bytes, or the same
//     problems);
//   - formatted (bo fmt) as written and into each official language, the
//     generated contract and its mixed rendering give the same model, the
//     same contract text in each language, and the same bytes (or the same
//     problems); formatting again changes nothing;
//   - every module it returns loads under the profile;
//   - run on calls made from the input (creations and actions with
//     arguments, consents, signers, and times, as the ledger encodes them),
//     a compiled contract only accepts with an output the ledger accepts,
//     asks for consents, or refuses with a reason that is the compiler's
//     own (bo:..., which renders in every official language) or a `reject`
//     text of the contract; it never traps otherwise (no out of fuel, no
//     out of bounds, no unreachable);
//   - generated contracts also carry due dates, UTC offsets, resources with
//     allocate and reclaim, conditions on time (within, overdue, before due,
//     a state held), and time rules whose functions the calls
//     and the tests' keeper steps run; and lists (in fields, inputs, and
//     the state: each, sum of, count of, in, set) and a bill with charges
//     of every shape, which calls with random lines make;
//   - generated contracts also split: the standard library's
//     split, with steps giving parts and recipients, and calls whose parts
//     add up to the amount on instances that are parts at depths up to 8; a
//     call that makes parts ends its instance, never at depth 8, and each
//     part has its state, fields, status, and holder;
//   - every call with arguments of its function's shape uses no more fuel
//     than the function's bound (bo::bound_for), nor does any
//     call a test makes (a step beyond it breaks);
//   - its test blocks (generated: a creation, then steps with parties,
//     counterparties, inputs, dates, signers, and expectations) run as `bo
//     test` runs them: no step breaks (does what compiled code never does),
//     a test stops at its first failure, every refusal is a reason the
//     compiler or the contract gives, every call cites its consents as a
//     ledger does (ascending, never the home's), the results are the same
//     twice, in English and mixed, and formatted into any language, and the
//     report is written in each official language.
//
// Why not libFuzzer: lowering is in cexchain::bo, which needs C++26 static
// reflection (GCC 16 only), and libFuzzer needs Clang. So this target is
// built by the GCC presets (with ASan and UBSan in gcc-asan) and drives
// itself: `bo_build_fuzz [-runs=N] [-max_total_time=S] [-seed=N] [FILE|DIR
// ...]` replays the files given (or the golden sources), then runs N inputs
// of random bytes; most bytes decode to a contract that checks, because a
// generator, not the bytes themselves, writes the source. Without coverage
// guidance the generator is what reaches deep code. The entry point is
// libFuzzer's (LLVMFuzzerTestOneInput), so a Clang with reflection can run it
// under libFuzzer unchanged. A failure prints the input in hex and aborts.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/lower.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/scenario.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace {

namespace bo = cexchain::bo;
namespace cbor = cexchain::cbor;
namespace m = cexchain::bo::model;
namespace protocol = cexchain::protocol;
namespace vm = cexchain::vm;
using cexchain::Bytes;
using cexchain::ByteView;

const std::uint8_t* current_data = nullptr;
std::size_t current_size = 0;

[[noreturn]] void fail(std::string_view what, std::string_view detail = {}) {
    std::fprintf(stderr, "bo_build_fuzz: %.*s\n", static_cast<int>(what.size()), what.data());
    if (!detail.empty()) {
        std::fprintf(stderr, "%.*s\n", static_cast<int>(detail.size()), detail.data());
    }
    if (current_data != nullptr) {
        const std::string hex = cexchain::to_hex(ByteView(current_data, current_size));
        std::fprintf(stderr, "input: %s\n", hex.c_str());
        std::ofstream("bo-build-crash.bin", std::ios::binary)
            .write(reinterpret_cast<const char*>(current_data),
                   static_cast<std::streamsize>(current_size));
    }
    std::abort();
}

void require(const bool condition, std::string_view what, std::string_view detail = {}) {
    if (!condition) {
        fail(what, detail);
    }
}

const cexchain::crypto::Provider& provider() {
    static const cexchain::crypto::openssl::Provider instance;
    return instance;
}

const bo::PackSet& official_set() {
    static const bo::PackSet set = [] {
        bo::PackSetRead read = bo::make_pack_set({});
        return std::move(*read.set);
    }();
    return set;
}

const bo::Lexicon& official() {
    static const bo::Lexicon lexicon(official_set());
    return lexicon;
}

/// Decisions read from the input; zeros once it runs out.
class Choices {
public:
    Choices(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}

    std::uint32_t below(const std::uint32_t n) {
        if (n <= 1) {
            return 0;
        }
        std::uint32_t v = next();
        if (n > 256) {
            v = (v << 8U) | next();
        }
        return v % n;
    }
    bool one_in(const std::uint32_t n) { return below(n) == 0; }
    std::int64_t between(const std::int64_t low, const std::int64_t high) {
        const auto span = static_cast<std::uint64_t>(high - low) + 1;
        std::uint64_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v = (v << 8U) | next();
        }
        return low + static_cast<std::int64_t>(v % span);
    }

private:
    std::uint8_t next() { return at_ < size_ ? data_[at_++] : 0; }
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t at_ = 0;
};

// ---------------------------------------------------------------------------
// The generator: a contract as lines of tokens; a token is a concept (with
// its argument, for spellings with "…"), or text written as it is.

struct Tok {
    std::string concept_id;
    std::string text;
    std::vector<Tok> arg;
};

Tok word(std::string id) {
    return Tok{std::move(id), {}, {}};
}
Tok raw(std::string text) {
    return Tok{{}, std::move(text), {}};
}
Tok apply(std::string id, std::vector<Tok> arg) {
    return Tok{std::move(id), {}, std::move(arg)};
}

using Line = std::vector<Tok>;

const bo::Pack* official_pack(std::uint32_t i) {
    static const std::vector<const bo::Pack*> packs = [] {
        std::vector<const bo::Pack*> out;
        for (const std::string_view id : {"en", "zh-Hant-HK", "zh-Hans-CN"}) {
            out.push_back(bo::official_pack(id));
        }
        return out;
    }();
    return packs[i % packs.size()];
}

std::string render(const std::vector<Tok>& toks, Choices* languages);

std::string render(const Tok& t, Choices* languages) {
    if (t.concept_id.empty()) {
        return t.text;
    }
    const bo::Pack* pack = official_pack(languages != nullptr ? languages->below(3) : 0);
    std::string spelled = bo::spell(t.concept_id, pack);
    const std::string hole = "\xE2\x80\xA6";
    if (const std::size_t at = spelled.find(hole); at != std::string::npos) {
        spelled.replace(at, hole.size(), render(t.arg, languages));
    }
    return spelled;
}

std::string render(const std::vector<Tok>& toks, Choices* languages) {
    std::string out;
    for (const Tok& t : toks) {
        out += (out.empty() ? "" : " ") + render(t, languages);
    }
    return out;
}

enum class T : std::uint8_t {
    text,
    number,
    money,
    usd,
    date,
    flag,
    data,
    days,
    months,
    celsius,
    party
};
constexpr std::uint32_t value_types = 10; // all but party

struct GField {
    std::string name; // a name, or "amount" for field.amount, "invoice" for the bill
    T type = T::text;
    bool constant = false;
    std::string party; // a party field's starting role
    /// A list of `type`: at most `bound` items (0: 16).
    bool list = false;
    std::uint32_t bound = 0;
    /// An instance field with a default: a creation may leave it out.
    bool initial = false;
};

struct GInput {
    std::string name;
    T type = T::text;
    bool list = false;
    std::uint32_t bound = 0;
};

/// A list's most items, as its type says.
std::uint32_t most(const std::uint32_t bound) {
    return bound == 0 ? 16 : bound;
}

/// A charge generated: what later ones may be computed on.
struct GCharge {
    std::string name;
    bool per_line = true;
};

struct GAction {
    std::string name;
    std::vector<GInput> inputs;
    std::optional<Tok> to;
    /// A built-in action (its concept), with the standard library's terms.
    std::string word;
    /// Its counterparty is named by each call (R21): a step always names one.
    bool open_to = false;
    /// AI agents may only propose it.
    bool proposes = false;
    /// The standard library's split: its parts and
    /// recipients, given by each step.
    bool split = false;
};

class Generator {
public:
    explicit Generator(Choices& c) : c_(c) {}

    std::vector<std::pair<int, Line>> contract();

private:
    Tok type_word(T t);
    Line literal(T t);
    Line literal_list(T t, std::uint32_t bound);
    Line list_type(T t, std::uint32_t bound);
    void charges(std::vector<std::pair<int, Line>>& out);
    /// The lists in reach: fields, and an action's inputs.
    std::vector<std::pair<Tok, std::pair<T, std::uint32_t>>> lists() const;
    Line party();
    Line value(T t, int depth);
    Line condition(int depth);
    Line time_condition();
    void statements(int indent, int depth, std::vector<std::pair<int, Line>>& out);
    void time_rules(std::vector<std::pair<int, Line>>& out);
    /// `request KIND [to PARTY] [with NAME = VALUE, ...] within N days`
    /// (now and then a kind or a deadline the checker refuses), and the
    /// rules for the answers to the kinds requested.
    Line request();
    void answer_rules(std::vector<std::pair<int, Line>>& out);
    /// A test step answering a request: `executor KIND done`, ...
    Line answer_step(int& month, int& day);
    Tok field_tok(const GField& f) const {
        return f.name == "amount"         ? word("field.amount")
               : f.name == "due"          ? word("field.due")
               : f.name == "paid_until"   ? word("field.paid_until")
               : f.name == "billed_until" ? word("field.billed_until")
               : f.name == "tier"         ? word("field.tier")
               : f.name == "invoice"      ? word("doc.invoice")
               : f.type == T::party       ? word("field.holder")
                                          : raw(f.name);
    }
    Tok state(std::size_t i) { return i < vocabulary_states_ ? word(states_[i]) : raw(states_[i]); }
    Tok test_party();
    Line step(const GAction& a, int& month, int& day);
    /// `, FIELD = VALUE, ...` after an expectation's state, or the values
    /// alone: instance fields of value types, often their literal.
    void expect_fields(Line& line, bool after_state);
    void tests(std::vector<std::pair<int, Line>>& out);

    Choices& c_;
    std::vector<Tok> roles_;
    std::vector<GField> fields_;
    std::vector<GInput> inputs_;
    std::vector<std::string> states_;
    std::size_t vocabulary_states_ = 0;
    std::size_t used_states_ = 1;
    bool in_action_ = false;
    /// In a time rule's block: nobody proves presence there. In its event:
    /// its date is no `now`.
    bool in_rule_ = false;
    bool in_event_ = false;
    int rejects_ = 0;
    bool asset_ = false;
    bool resource_ = false;
    /// The first state is active.
    bool active_first_ = false;
    /// The instance has a due date (field.due, or a service's paid until).
    bool due_ = false;
    /// A service with a recurring price, billed each period once it is
    /// subscribed to.
    bool service_ = false;
    std::vector<GAction> actions_;
    /// What keeper steps name: the action each time rule does.
    std::vector<Tok> keeper_;
    /// The bill's charges, and the items each loop names.
    std::vector<GCharge> charges_;
    std::vector<std::pair<std::string, T>> items_;
    /// The amount the test's creation gives, which a split may pass on whole.
    Line amount_given_;
    /// The kinds of the requests made; none once the contract splits.
    std::vector<Tok> kinds_;
    bool splits_ = false;
};

Tok Generator::type_word(const T t) {
    switch (t) {
    case T::text:
        return word("type.text");
    case T::number:
        return word("type.number");
    case T::money:
        return word("cur.HKD");
    case T::usd:
        return word("cur.USD");
    case T::date:
        return word("type.date");
    case T::flag:
        return word("type.yes_no");
    case T::data:
        return word("unit.GB");
    case T::days:
        return word("time.day");
    case T::months:
        return word("time.month");
    case T::celsius:
        return c_.one_in(2) ? raw("\u00B0C") : word("unit.celsius");
    case T::party:
        break;
    }
    return word("type.text");
}

Line Generator::literal(const T t) {
    switch (t) {
    case T::text: {
        static constexpr std::string_view texts[] = {"x", "any", "香港", "", "a b"};
        return {raw("\"" + std::string(texts[c_.below(5)]) + "\"")};
    }
    case T::number:
        // Now and then negative: a minus directly before the digits.
        return {raw((c_.one_in(8) ? "-" : "") +
                    std::to_string(c_.below(4) == 0 ? 0 : c_.between(1, 1'000'000)))};
    case T::money:
        return {raw(std::format("HKD {}{}.{:02}", c_.one_in(8) ? "-" : "", c_.between(0, 2'000'000),
                                c_.below(100)))};
    case T::usd:
        return {raw(std::format("USD {}", c_.between(0, 5'000)))};
    case T::date:
        return {raw(
            std::format("{}-{:02}-{:02}", 2026 + c_.below(3), 1 + c_.below(12), 1 + c_.below(28)))};
    case T::flag:
        return {word(c_.one_in(2) ? "val.yes" : "val.no")};
    case T::data:
        return {raw(std::format("{} GB", c_.between(0, 5'000)))};
    case T::days:
        return {raw(std::format("{} days", c_.between(0, 400)))};
    case T::months:
        return {raw(std::format("{} months", c_.between(0, 36)))};
    case T::celsius: {
        // Tenths or hundredths of a degree, below zero too; °C, ℃, or words.
        static constexpr std::string_view units[] = {" \u00B0C", "\u00B0C", " \u2103",
                                                     " degrees Celsius"};
        const std::int64_t whole = c_.between(-40, 60);
        return {raw(std::format(
            "{}{}.{}{}", whole < 0 ? "-" : (c_.one_in(8) ? "-" : ""), whole < 0 ? -whole : whole,
            c_.one_in(2) ? std::to_string(c_.below(10)) : std::format("{:02}", c_.below(100)),
            units[c_.below(4)]))};
    }
    case T::party:
        break;
    }
    return {raw("\"x\"")};
}

/// A list written out (now and then one value: a list of one, R29).
Line Generator::literal_list(const T t, const std::uint32_t bound) {
    // One item is written as the value alone: (x) only groups.
    const std::uint32_t n = 1 + c_.below(std::min<std::uint32_t>(most(bound), 4));
    if (n == 1) {
        return literal(t);
    }
    Line out{raw("(")};
    for (std::uint32_t i = 0; i < n; ++i) {
        if (i > 0) {
            out.push_back(raw(","));
        }
        const Line v = literal(t);
        out.insert(out.end(), v.begin(), v.end());
    }
    out.push_back(raw(")"));
    return out;
}

/// `list TYPE [at most N]`.
Line Generator::list_type(const T t, const std::uint32_t bound) {
    Line out{word("type.list"), type_word(t)};
    if (bound != 0) {
        out.push_back(apply("expr.at_most", {raw(std::to_string(bound))}));
    }
    return out;
}

std::vector<std::pair<Tok, std::pair<T, std::uint32_t>>> Generator::lists() const {
    std::vector<std::pair<Tok, std::pair<T, std::uint32_t>>> out;
    for (const GField& f : fields_) {
        if (f.list) {
            out.push_back({field_tok(f), {f.type, f.bound}});
        }
    }
    if (in_action_) {
        for (const GInput& i : inputs_) {
            if (i.list) {
                out.push_back({raw(i.name), {i.type, i.bound}});
            }
        }
    }
    return out;
}

/// Charges on the bill, mostly as the checker accepts them:
/// a rate (now and then only from a date on) or a fixed amount, now and
/// then a condition, included or added, a way of rounding, and what it is
/// computed on (the price and earlier charges it may be computed on).
void Generator::charges(std::vector<std::pair<int, Line>>& out) {
    static constexpr std::string_view modes[] = {"round.half_up", "round.half_even", "round.down"};
    for (std::uint32_t k = 0, n = c_.below(5); k < n; ++k) {
        GCharge made{std::format("c{}", k), true};
        out.push_back({0, {word(c_.one_in(2) ? "charge.charge" : "charge.tax"), raw(made.name)}});
        const bool fixed = c_.one_in(5);
        const bool included = c_.one_in(3);
        if (fixed) {
            out.push_back({2,
                           {word("field.amount"),
                            raw(std::format("HKD {}.{:02}", c_.below(50), c_.below(100)))}});
        } else {
            const bool plain = !c_.one_in(4);
            if (plain) {
                out.push_back({2,
                               {word("charge.rate"),
                                raw(std::format("{}.{}%", c_.below(30), c_.below(10)))}});
            }
            for (std::uint32_t d = 0, dates = plain ? c_.below(3) : 1 + c_.below(2); d < dates;
                 ++d) {
                out.push_back({2,
                               {apply("charge.from", {raw(std::format("{}-{:02}-01", 2026 + d,
                                                                      1 + c_.below(12)))}),
                                word("charge.rate"), raw(std::format("{}%", c_.below(25)))}});
            }
        }
        if (c_.one_in(3)) {
            const Line cond = condition(1);
            out.push_back({2, {apply("charge.applies_to", cond)}});
        }
        out.push_back({2, {word(included ? "charge.included" : "charge.added")}});
        const Tok mode = word(std::string(modes[c_.below(3)]));
        switch (c_.below(5)) {
        case 0:
            break;
        case 1:
            out.push_back(
                {2, fixed ? Line{word("charge.per_line")} : Line{word("charge.per_line"), mode}});
            break;
        case 2:
            made.per_line = false;
            out.push_back({2, fixed ? Line{word("charge.per_document")}
                                    : Line{word("charge.per_document"), mode}});
            break;
        case 3:
            made.per_line = false;
            out.push_back({2, fixed ? Line{word("charge.by"), word("doc.invoice")}
                                    : Line{word("charge.by"), word("doc.invoice"), mode}});
            break;
        default:
            if (!fixed) {
                out.push_back({2, {mode}});
            }
            break;
        }
        if (fixed) {
            made.per_line = false;
        }
        if (!fixed && !charges_.empty() && c_.one_in(2)) {
            // What it is computed on: the price, and earlier charges.
            Line on{word("charge.by")};
            if (c_.one_in(2)) {
                on.push_back(word("price.price"));
            }
            for (const GCharge& earlier : charges_) {
                if (!included && (!made.per_line || earlier.per_line) && c_.one_in(2)) {
                    on.push_back(raw(on.size() > 1 ? "," : ""));
                    on.push_back(raw(earlier.name));
                }
            }
            if (on.size() > 1) {
                Line tidy{on.front()};
                for (std::size_t i = 1; i < on.size(); ++i) {
                    if (!on[i].text.empty() || !on[i].concept_id.empty()) {
                        tidy.push_back(on[i]);
                    }
                }
                out.push_back({2, tidy});
            }
        }
        charges_.push_back(std::move(made));
    }
}

Line Generator::party() {
    std::vector<Line> options;
    for (const Tok& r : roles_) {
        options.push_back({r});
    }
    for (const GField& f : fields_) {
        if (f.type == T::party) {
            options.push_back({word("field.holder")});
        }
    }
    return options[c_.below(static_cast<std::uint32_t>(options.size()))];
}

Line Generator::value(const T t, const int depth) {
    if (t == T::party) {
        return party();
    }
    std::vector<Line> leaves{literal(t)};
    for (const GField& f : fields_) {
        if (f.type == t && !f.list) {
            leaves.push_back({field_tok(f)});
        }
    }
    if (in_action_) {
        for (const GInput& i : inputs_) {
            if (i.type == t && !i.list) {
                leaves.push_back({raw(i.name)});
            }
        }
    }
    if (t == T::date && !in_event_) {
        leaves.push_back({word("time.now")});
        leaves.push_back({word("time.today")});
    }
    // Lists: their counts and sums; each loop's items; the
    // bill's charges, in an action or a time rule.
    for (const auto& [list, of] : lists()) {
        if (t == T::number) {
            leaves.push_back({apply("expr.count_of", {list})});
        }
        if (of.first == t && (t == T::number || t == T::money)) {
            leaves.push_back({apply("expr.sum_of", {list})});
        }
    }
    for (const auto& [name, type] : items_) {
        if (type == t) {
            leaves.push_back({raw(name)});
        }
    }
    if (t == T::money && (in_action_ || in_rule_) && !in_event_) {
        for (const GCharge& k : charges_) {
            leaves.push_back({raw(k.name)});
        }
    }
    if (depth <= 0 || c_.below(3) != 0) {
        return leaves[c_.below(static_cast<std::uint32_t>(leaves.size()))];
    }
    const auto group = [](Line inner) {
        Line out{raw("(")};
        out.insert(out.end(), inner.begin(), inner.end());
        out.push_back(raw(")"));
        return out;
    };
    const auto join = [&](Line a, std::string op, Line b) {
        a.push_back(raw(std::move(op)));
        a.insert(a.end(), b.begin(), b.end());
        return group(std::move(a));
    };
    switch (t) {
    case T::number:
    case T::money:
    case T::usd:
    case T::data:
    case T::days:
    case T::celsius:
        switch (c_.below(5)) {
        case 0:
            return join(value(t, depth - 1), "+", value(t, depth - 1));
        case 1:
            return join(value(t, depth - 1), "-", value(t, depth - 1));
        case 2:
            return join(value(t, depth - 1), "*", value(T::number, depth - 1));
        case 3:
            if (t == T::number && c_.one_in(3)) {
                // R32: a duration by a duration, in whole times.
                const T of = c_.one_in(3) ? T::months : T::days;
                // Mostly a divisor written out, which is not 0.
                return join(value(of, depth - 1), "/",
                            c_.one_in(3)
                                ? value(of, depth - 1)
                                : Line{raw(std::format("{} {}", 1 + c_.below(30),
                                                       of == T::days ? "days" : "months"))});
            }
            if (t == T::number) {
                return join(value(t, depth - 1), "/", {raw(std::to_string(1 + c_.below(9)))});
            }
            if (t == T::days) {
                return join(value(t, depth - 1), "+", value(t, depth - 1));
            }
            return join(value(t, depth - 1), "*", {raw(std::format("{}%", c_.below(300)))});
        default:
            if (t == T::days) {
                return join(value(T::date, depth - 1), "-", value(T::date, depth - 1));
            }
            return join(value(t, depth - 1), "/", value(T::number, depth - 1));
        }
    case T::months:
        return join(value(t, depth - 1), "+", value(t, depth - 1));
    case T::date:
        return join(value(t, depth - 1), c_.one_in(2) ? "+" : "-",
                    value(c_.one_in(2) ? T::days : T::months, depth - 1));
    default:
        return leaves[c_.below(static_cast<std::uint32_t>(leaves.size()))];
    }
}

/// A condition on time: within N, overdue (N), N before
/// due, a state held N.
Line Generator::time_condition() {
    const std::string days = std::format("{} days", c_.between(0, 60));
    switch (c_.below(due_ ? 5 : 2)) {
    case 0:
        return {apply("cond.within", {raw(days)})};
    case 1:
        if (used_states_ > 1) {
            return {state(c_.below(static_cast<std::uint32_t>(used_states_))), raw(days)};
        }
        return {apply("cond.within", {raw(days)})};
    case 2:
        return {word("cond.overdue")};
    case 3:
        return {word("cond.overdue"), raw(days)};
    default:
        return {apply("cond.before_due", {raw(days)})};
    }
}

Line Generator::condition(const int depth) {
    if ((in_action_ || in_rule_) && c_.one_in(6)) {
        return time_condition();
    }
    const std::uint32_t pick = c_.below(depth > 0 ? 9 : 6);
    switch (pick) {
    case 0:
    case 1: {
        static constexpr T ordered[] = {T::number, T::money, T::usd,    T::date,
                                        T::data,   T::days,  T::months, T::celsius};
        const T t = ordered[c_.below(8)];
        static constexpr std::string_view ops[] = {"<", "<=", ">", ">=", "="};
        Line out = value(t, depth);
        out.push_back(raw(std::string(ops[c_.below(5)])));
        const Line right = value(t, depth);
        out.insert(out.end(), right.begin(), right.end());
        return out;
    }
    case 2: {
        static constexpr T equal[] = {T::text, T::flag, T::party};
        const T t = equal[c_.below(3)];
        Line out = value(t, 0);
        out.push_back(raw("="));
        const Line right = value(t, 0);
        out.insert(out.end(), right.begin(), right.end());
        return out;
    }
    case 3:
        if (used_states_ > 1) {
            return {state(c_.below(static_cast<std::uint32_t>(used_states_)))};
        }
        return {word("val.yes")};
    case 4:
        for (const GField& f : fields_) {
            if (f.type == T::flag && c_.one_in(2)) {
                return {raw(f.name)};
            }
        }
        return {word(c_.one_in(2) ? "val.yes" : "val.no")};
    case 5:
        return in_action_ ? Line{word("cond.in_person")} : Line{word("val.no")};
    case 6: {
        Line out{word("kw.not"), raw("(")};
        const Line inner = condition(depth - 1);
        out.insert(out.end(), inner.begin(), inner.end());
        out.push_back(raw(")"));
        return out;
    }
    default: {
        Line out{raw("(")};
        const Line a = condition(depth - 1);
        out.insert(out.end(), a.begin(), a.end());
        out.push_back(raw(")"));
        out.push_back(word(pick == 7 ? "kw.and" : "kw.or"));
        out.push_back(raw("("));
        const Line b = condition(depth - 1);
        out.insert(out.end(), b.begin(), b.end());
        out.push_back(raw(")"));
        return out;
    }
    }
}

void Generator::statements(const int indent, const int depth,
                           std::vector<std::pair<int, Line>>& out) {
    const std::uint32_t count = 1 + c_.below(depth > 0 ? 5 : 3);
    for (std::uint32_t k = 0; k < count; ++k) {
        switch (c_.below(depth > 0 ? 12 : 11)) {
        case 9: {
            // A list's count, or whether it holds a value.
            const auto in_reach = lists();
            if (in_reach.empty()) {
                break;
            }
            const auto& [list, of] =
                in_reach[c_.below(static_cast<std::uint32_t>(in_reach.size()))];
            Line l{word("kw.requires")};
            if (c_.one_in(3)) {
                l.push_back(apply("expr.count_of", {list}));
                l.push_back(raw(c_.one_in(2) ? ">" : "<="));
                l.push_back(raw(std::to_string(c_.below(5))));
            } else {
                const bool negated = c_.one_in(2);
                if (negated) {
                    l.push_back(word("kw.not"));
                    l.push_back(raw("("));
                }
                const Line x = value(of.first, 0);
                l.insert(l.end(), x.begin(), x.end());
                l.push_back(word("kw.in"));
                if (c_.one_in(3)) {
                    const Line written = literal_list(of.first, 3);
                    if (written.front().text == "(") {
                        l.insert(l.end(), written.begin(), written.end());
                    } else {
                        l.push_back(list);
                    }
                } else {
                    l.push_back(list);
                }
                if (negated) {
                    l.push_back(raw(")"));
                }
            }
            out.push_back({indent, l});
            break;
        }
        case 10: {
            // A list field set: to an input of its items, or to a list
            // written out (the bill's: a new bill).
            std::vector<const GField*> settable;
            for (const GField& f : fields_) {
                if (f.list && !f.constant) {
                    settable.push_back(&f);
                }
            }
            if (settable.empty()) {
                break;
            }
            const GField& f = *settable[c_.below(static_cast<std::uint32_t>(settable.size()))];
            Line l{field_tok(f), raw("=")};
            std::vector<Tok> sources;
            if (in_action_) {
                for (const GInput& i : inputs_) {
                    if (i.list && i.type == f.type && most(i.bound) <= most(f.bound)) {
                        sources.push_back(raw(i.name));
                    }
                }
            }
            if (!sources.empty() && !c_.one_in(3)) {
                l.push_back(sources[c_.below(static_cast<std::uint32_t>(sources.size()))]);
            } else {
                const Line v = literal_list(f.type, std::min<std::uint32_t>(most(f.bound), 3));
                l.insert(l.end(), v.begin(), v.end());
            }
            out.push_back({indent, l});
            break;
        }
        case 11: {
            // each ITEM in LIST: requirements on the item, a reject.
            const auto in_reach = lists();
            if (in_reach.empty()) {
                break;
            }
            const auto& [list, of] =
                in_reach[c_.below(static_cast<std::uint32_t>(in_reach.size()))];
            const std::string item = std::format("it{}", items_.size());
            Line head{word("kw.each"), raw(item), word("kw.in")};
            if (c_.one_in(4)) {
                const Line written = literal_list(of.first, 3);
                head.insert(head.end(), written.begin(), written.end());
                if (written.front().text != "(") {
                    head.back() = list;
                }
            } else {
                head.push_back(list);
            }
            out.push_back({indent, head});
            items_.emplace_back(item, of.first);
            Line req{word("kw.requires"), raw(item)};
            req.push_back(raw(of.first == T::text ? "=" : ">="));
            const Line v = value(of.first, 0);
            req.insert(req.end(), v.begin(), v.end());
            out.push_back({indent + 2, req});
            if (c_.one_in(2) && rejects_ < 3) {
                ++rejects_;
                Line when{word("kw.if"), raw(item), raw("=")};
                const Line w = literal(of.first);
                when.insert(when.end(), w.begin(), w.end());
                out.push_back({indent + 2, when});
                out.push_back(
                    {indent + 4, {word("kw.reject"), raw(std::format("\"no {}\"", rejects_))}});
            }
            items_.pop_back();
            break;
        }
        case 0:
        case 1:
            out.push_back({indent, [&] {
                               Line l{word("kw.requires")};
                               const Line cond = condition(2);
                               l.insert(l.end(), cond.begin(), cond.end());
                               return l;
                           }()});
            break;
        case 2:
            out.push_back({indent, {word("kw.requires"), apply("cond.consent_of", party())}});
            break;
        case 3: {
            if (in_rule_) {
                break; // a keeper proves no presence
            }
            bool amount = false;
            int money_inputs = 0;
            for (const GInput& i : inputs_) {
                money_inputs += i.type == T::money || i.type == T::data ? 1 : 0;
            }
            for (const GField& f : fields_) {
                amount = amount || f.name == "amount";
            }
            if (money_inputs == 1 || (money_inputs == 0 && amount)) {
                out.push_back({indent,
                               {apply("cond.over", {raw(std::to_string(c_.between(0, 10'000)))}),
                                word("kw.requires"), word("cond.in_person")}});
            } else {
                out.push_back({indent, {word("kw.requires"), word("cond.in_person")}});
            }
            break;
        }
        case 4: {
            if (depth <= 0) {
                break;
            }
            Line head{word("kw.if")};
            const Line cond = condition(2);
            head.insert(head.end(), cond.begin(), cond.end());
            out.push_back({indent, head});
            statements(indent + 2, depth - 1, out);
            if (c_.one_in(2)) {
                out.push_back({indent, {word("kw.otherwise")}});
                statements(indent + 2, depth - 1, out);
            }
            break;
        }
        case 5:
            if (rejects_ < 3) {
                ++rejects_;
                out.push_back(
                    {indent, {word("kw.reject"), raw(std::format("\"no {}\"", rejects_))}});
            }
            break;
        case 6: {
            std::vector<const GField*> settable;
            for (const GField& f : fields_) {
                if (!f.constant && !f.list) {
                    settable.push_back(&f);
                }
            }
            if (settable.empty()) {
                break;
            }
            const GField& f = *settable[c_.below(static_cast<std::uint32_t>(settable.size()))];
            Line l{field_tok(f), raw("=")};
            const Line v = value(f.type, 2);
            l.insert(l.end(), v.begin(), v.end());
            out.push_back({indent, l});
            break;
        }
        default: {
            // A state change along the chain of states, or a new one.
            if (used_states_ < states_.size() && c_.one_in(2)) {
                out.push_back({indent, {state(used_states_ - 1), raw("->"), state(used_states_)}});
                ++used_states_;
            } else if (used_states_ > 1) {
                const auto from = c_.below(static_cast<std::uint32_t>(used_states_));
                const auto to = 1 + c_.below(static_cast<std::uint32_t>(used_states_ - 1));
                out.push_back({indent, {state(from), raw("->"), state(to)}});
            }
            break;
        }
        }
    }
}

std::vector<std::pair<int, Line>> Generator::contract() {
    std::vector<std::pair<int, Line>> out;
    // Every vocabulary pack: the generator draws on all their words.
    for (const std::string_view pack : {"commerce", "finance", "services"}) {
        out.push_back({0, {word("kw.use"), raw(std::string(pack))}});
    }
    out.push_back({0, {word("kw.contract"), raw("Fuzzed")}});
    // Parties: role words or names.
    static constexpr std::string_view role_words[] = {"role.we", "role.customer", "role.bank",
                                                      "role.supplier"};
    const std::uint32_t parties = 1 + c_.below(3);
    Line line{word("kw.parties")};
    for (std::uint32_t i = 0; i < parties; ++i) {
        if (i > 0) {
            line.push_back(raw(","));
        }
        roles_.push_back(c_.one_in(3) ? raw(std::format("p{}", i))
                                      : word(std::string(role_words[i])));
        line.push_back(roles_.back());
    }
    out.push_back({0, line});
    // The kind and its fields.
    const bool asset = c_.one_in(3);
    asset_ = asset;
    resource_ = !asset && c_.one_in(4);
    service_ = !asset && !resource_ && c_.one_in(3);
    out.push_back({0,
                   {word(asset       ? "kind.asset"
                         : resource_ ? "kind.resource"
                         : service_  ? "kind.service"
                                     : "kind.thing"),
                    raw("Thing")}});
    if (service_) {
        // Due on the date it is paid until, each period (R11).
        static constexpr std::string_view periods[] = {"time.monthly", "time.weekly", "time.daily",
                                                       "time.yearly"};
        due_ = true;
        out.push_back({2,
                       {word("price.price"), word(std::string(periods[c_.below(4)])),
                        raw(std::format("HKD {}.{:02}", c_.between(0, 5'000), c_.below(100)))}});
    } else if (c_.one_in(3)) {
        due_ = true;
        fields_.push_back({"due", T::date, false, {}});
        out.push_back({2, {word("field.due"), word("type.date")}});
    }
    if (c_.one_in(6)) {
        // A fixed offset from UTC, east or west, in quarter hours.
        const auto quarters = c_.between(-56, 56);
        const auto minutes = (quarters < 0 ? -quarters : quarters) * 15;
        out.push_back({2,
                       {word("field.utc_offset"),
                        raw(std::format("\"{}{:02}:{:02}\"", quarters < 0 ? '-' : '+', minutes / 60,
                                        minutes % 60))}});
    }
    if (resource_) {
        out.push_back(
            {2, {word("field.cooling_period"), raw(std::format("{} days", c_.between(0, 40)))}});
    }
    if (c_.one_in(2)) {
        fields_.push_back({"amount", T::money, false, {}});
        out.push_back({2, {word("field.amount"), word("cur.HKD")}});
    }
    if (c_.one_in(3)) {
        const Tok role = roles_[c_.below(static_cast<std::uint32_t>(roles_.size()))];
        fields_.push_back({"holder", T::party, false, role.text});
        out.push_back({2, {word("field.holder"), role}});
        // A tier, which the standard library's split takes one down, and
        // the amount it splits.
        if (c_.one_in(2)) {
            fields_.push_back({"tier", T::number, false, {}});
            out.push_back({2, {word("field.tier"), word("type.number")}});
            if (std::ranges::none_of(fields_, [](const GField& f) { return f.name == "amount"; })) {
                fields_.push_back({"amount", T::money, false, {}});
                out.push_back({2, {word("field.amount"), word("cur.HKD")}});
            }
        }
    }
    const std::uint32_t own = c_.below(6);
    for (std::uint32_t i = 0; i < own; ++i) {
        GField f{std::format("f{}", i), static_cast<T>(c_.below(value_types)), c_.one_in(4), {}};
        Line l{raw(f.name)};
        if (f.constant) {
            const Line v = literal(f.type);
            l.insert(l.end(), v.begin(), v.end());
        } else {
            l.push_back(type_word(f.type));
            // A default: `f0 number = 0`.
            if (c_.one_in(3)) {
                f.initial = true;
                l.push_back(raw("="));
                const Line v = literal(f.type);
                l.insert(l.end(), v.begin(), v.end());
            }
        }
        out.push_back({2, l});
        fields_.push_back(std::move(f));
    }
    // Lists: fields of numbers, texts, or money, bounded.
    for (std::uint32_t i = 0, n = c_.below(3); i < n; ++i) {
        static constexpr T of[] = {T::number, T::text, T::money};
        GField f{std::format("l{}", i),
                 of[c_.below(3)],
                 false,
                 {},
                 true,
                 c_.one_in(2) ? 0 : 1 + c_.below(20)};
        Line l{raw(f.name)};
        const Line type = list_type(f.type, f.bound);
        l.insert(l.end(), type.begin(), type.end());
        if (c_.one_in(4)) {
            f.initial = true;
            l.push_back(raw("="));
            const Line v = literal_list(f.type, f.bound);
            l.insert(l.end(), v.begin(), v.end());
        }
        out.push_back({2, l});
        fields_.push_back(std::move(f));
    }
    // A bill, and the charges computed on it (on a service billed each
    // period, refused: rarely).
    const bool bill = service_ ? c_.below(12) == 11 : c_.one_in(3);
    if (bill) {
        GField f{"invoice", T::money, false, {}, true, c_.one_in(2) ? 0 : 1 + c_.below(20)};
        Line l{word("doc.invoice")};
        const Line type = list_type(T::money, f.bound);
        l.insert(l.end(), type.begin(), type.end());
        out.push_back({2, l});
        fields_.push_back(std::move(f));
        charges(out);
    }
    // States: a chain the actions walk, vocabulary words first.
    static constexpr std::string_view state_words[] = {"state.proposed", "state.active",
                                                       "state.paid"};
    // An instance with a tier (one that may split) starts active too.
    active_first_ = resource_ || service_ || c_.one_in(3) ||
                    std::ranges::any_of(fields_, [](const GField& f) { return f.name == "tier"; });
    if (active_first_) {
        // Active first, where a resource's terms and the time rules' built-in
        // actions start.
        vocabulary_states_ = 1;
        states_.emplace_back("state.active");
    } else {
        vocabulary_states_ = c_.below(3);
        for (std::size_t i = 0; i < vocabulary_states_; ++i) {
            states_.emplace_back(state_words[i]);
        }
    }
    for (std::uint32_t i = 0, n = 2 + c_.below(3); i < n; ++i) {
        states_.push_back(std::format("s{}", i));
    }
    // Actions.
    const std::uint32_t actions = 1 + c_.below(4);
    for (std::uint32_t a = 0; a < actions; ++a) {
        inputs_.clear();
        Line head{word("kw.can"), raw(std::format("a{}", a)), word("kw.by")};
        const Line by = party();
        head.insert(head.end(), by.begin(), by.end());
        if (c_.one_in(3)) {
            head.push_back(word("kw.to"));
            head.push_back(roles_[c_.below(static_cast<std::uint32_t>(roles_.size()))]);
        }
        const std::uint32_t inputs = c_.below(4);
        if (inputs > 0) {
            head.push_back(word("kw.with"));
            for (std::uint32_t i = 0; i < inputs; ++i) {
                if (i > 0) {
                    head.push_back(raw(","));
                }
                GInput input{std::format("i{}", i), static_cast<T>(c_.below(value_types))};
                head.push_back(raw(input.name));
                if (c_.one_in(4)) {
                    // A list.
                    static constexpr T of[] = {T::number, T::text, T::money};
                    input.type = of[c_.below(3)];
                    input.list = true;
                    input.bound = c_.one_in(2) ? 0 : 1 + c_.below(20);
                    const Line type = list_type(input.type, input.bound);
                    head.insert(head.end(), type.begin(), type.end());
                } else {
                    head.push_back(type_word(input.type));
                }
                inputs_.push_back(std::move(input));
            }
        }
        out.push_back({0, head});
        GAction made;
        made.name = std::format("a{}", a);
        made.inputs = inputs_;
        if (head.size() > 4 && head[4].concept_id == "kw.to") {
            made.to = head[5];
        }
        actions_.push_back(std::move(made));
        if (c_.one_in(4)) {
            // AI agents only propose it; a person approves.
            out.push_back({2, {word("actor.ai_agent"), word("kw.can"), word("act.propose")}});
            actions_.back().proposes = true;
        }
        in_action_ = true;
        statements(2, 2, out);
        if (c_.one_in(3)) {
            out.push_back({2, request()});
        }
        in_action_ = false;
    }
    // Built-in actions with the standard library's terms, when
    // the instance has a holder: in groups whose states lead to each other.
    const bool holder =
        std::ranges::any_of(fields_, [](const GField& f) { return f.name == "holder"; });
    if (holder) {
        static constexpr std::string_view groups[][3] = {
            {"act.pledge", "act.release", "act.enforce"},
            {"act.pay", "act.dispute", "act.confirm_payment"},
            {"act.freeze", "act.unfreeze", ""},
            {"act.transfer", "", ""},
            {"act.cancel", "", ""},
            {"act.split", "", ""}};
        for (const auto& group : groups) {
            // Splitting, where the instance has a tier, more often.
            const bool tier =
                std::ranges::any_of(fields_, [](const GField& f) { return f.name == "tier"; });
            if (group[0] == "act.split" ? tier && c_.one_in(4) : !c_.one_in(2)) {
                continue;
            }
            for (const std::string_view id : group) {
                if (id.empty()) {
                    continue;
                }
                GAction action;
                action.word = std::string(id);
                action.name = std::string(id.substr(4));
                action.split = id == "act.split";
                Line head{word("kw.can"), word(action.word)};
                if (id == "act.pledge" || id == "act.transfer") {
                    if (c_.one_in(2)) {
                        action.to = roles_[c_.below(static_cast<std::uint32_t>(roles_.size()))];
                        head.push_back(word("kw.to"));
                        head.push_back(*action.to);
                    } else {
                        action.to = raw("bank1");
                        action.open_to = true;
                    }
                }
                out.push_back({0, head});
                if (c_.one_in(3)) {
                    out.push_back(
                        {2, {word("actor.ai_agent"), word("kw.can"), word("act.propose")}});
                    action.proposes = true;
                }
                actions_.push_back(std::move(action));
            }
        }
    }
    // A resource: allocated to one holder at a time, cooling after a reclaim.
    if (resource_ && c_.one_in(3) == false) {
        GAction allocate;
        allocate.word = "act.allocate";
        allocate.name = "allocate";
        Line head{word("kw.can"), word(allocate.word)};
        if (c_.one_in(2)) {
            allocate.to = roles_[c_.below(static_cast<std::uint32_t>(roles_.size()))];
            head.push_back(word("kw.to"));
            head.push_back(*allocate.to);
        } else {
            allocate.to = raw("bank1");
            allocate.open_to = true;
        }
        out.push_back({0, head});
        actions_.push_back(std::move(allocate));
        GAction reclaim;
        reclaim.word = "act.reclaim";
        reclaim.name = "reclaim";
        out.push_back({0, {word("kw.can"), word(reclaim.word)}});
        actions_.push_back(std::move(reclaim));
    }
    // A service: subscribed to, renewed, its plan changed; each asks an
    // executor (R10), and subscribing and renewing bill a period (R34).
    if (service_) {
        static constexpr std::string_view words[] = {"act.subscribe", "act.renew", "act.upgrade",
                                                     "act.downgrade"};
        for (const std::string_view id : words) {
            if (id != "act.subscribe" && c_.one_in(2)) {
                continue;
            }
            GAction action;
            action.word = std::string(id);
            action.name = std::string(id.substr(4));
            Line head{word("kw.can"), word(action.word)};
            if (c_.one_in(2)) {
                head.push_back(word("kw.by"));
                head.push_back(roles_[c_.below(static_cast<std::uint32_t>(roles_.size()))]);
            }
            out.push_back({0, head});
            actions_.push_back(std::move(action));
            if (id != "act.renew") {
                kinds_.push_back(word(std::string(id)));
            }
        }
        // Their bills: the invoice and its collection; the payment resumes.
        kinds_.push_back(word("doc.invoice"));
        kinds_.push_back(word("act.collect"));
        fields_.push_back({"paid_until", T::date, false, {}});
        fields_.push_back({"billed_until", T::date, false, {}});
    }
    // Now and then, what this version does not compile: a built-in action
    // whose terms come later.
    if (c_.one_in(16)) {
        out.push_back({0, {word("kw.can"), word("act.refund"), word("kw.by"), roles_.front()}});
    }
    // An instance that issues parts makes no requests in this version (its
    // end is not in its state, so answers could not tell): none then.
    if (std::ranges::any_of(actions_, [](const GAction& a) { return a.split; })) {
        std::erase_if(out, [](const std::pair<int, Line>& l) {
            return !l.second.empty() && l.second.front().concept_id == "kw.request";
        });
        kinds_.clear();
        splits_ = true;
    }
    time_rules(out);
    answer_rules(out);
    tests(out);
    return out;
}

Line Generator::request() {
    // Kinds: an action's word, names, and now and then one the ledger
    // would refuse (check.request-kind). (The last choice when the input
    // runs out is always the first.)
    static constexpr std::string_view names[] = {"sync", "sync_v2", "Bad"};
    const std::uint32_t pick = c_.below(40) == 39 ? 3 : c_.below(3);
    const Tok kind = pick == 0 ? word("act.notify") : raw(std::string(names[pick - 1]));
    if (pick != 3 && std::ranges::none_of(kinds_, [&](const Tok& k) {
            return k.text == kind.text && k.concept_id == kind.concept_id;
        })) {
        kinds_.push_back(kind);
    }
    Line l{word("kw.request"), kind};
    if (c_.one_in(2)) {
        l.push_back(word("kw.to"));
        const Line who = party();
        l.insert(l.end(), who.begin(), who.end());
    }
    if (c_.one_in(2)) {
        l.push_back(word("kw.with"));
        for (std::uint32_t i = 0, n = 1 + c_.below(3); i < n; ++i) {
            if (i > 0) {
                l.push_back(raw(","));
            }
            l.push_back(raw(std::format("p{}", i)));
            l.push_back(raw("="));
            const Line v = value(static_cast<T>(c_.below(value_types)), 1);
            l.insert(l.end(), v.begin(), v.end());
        }
    }
    // Within 1 to 366 days, now and then more (check.request-within).
    const std::int64_t days = c_.below(40) == 39 ? c_.between(367, 400) : c_.between(1, 366);
    l.push_back(apply("cond.within", {raw(std::format("{} days", days))}));
    return l;
}

void Generator::answer_rules(std::vector<std::pair<int, Line>>& out) {
    static constexpr std::string_view outcomes[] = {"kw.done", "kw.fails", "kw.expires"};
    const std::vector<Tok> asked = kinds_;
    for (const Tok& kind : asked) {
        for (const std::string_view outcome : outcomes) {
            if (c_.below(3) != 1) {
                continue;
            }
            out.push_back({0, {word("kw.when"), kind, word(std::string(outcome))}});
            // A text field takes the answer's result or reason; another a
            // value; now and then a state change, a new request, or a line
            // an answer's rule may not have (check.answer-line).
            bool any = false;
            for (const GField& f : fields_) {
                if (f.constant || f.list || f.type == T::party || !c_.one_in(2)) {
                    continue;
                }
                Line set{field_tok(f), raw("=")};
                if (f.type == T::text) {
                    set.push_back(word(c_.one_in(2) ? "expr.result" : "expr.reason"));
                } else {
                    const Line v = value(f.type, 1);
                    set.insert(set.end(), v.begin(), v.end());
                }
                out.push_back({2, set});
                any = true;
            }
            if (used_states_ > 1 && c_.one_in(3)) {
                out.push_back(
                    {2, {raw("->"), state(c_.below(static_cast<std::uint32_t>(used_states_)))}});
                any = true;
            }
            if (c_.one_in(4) || !any) {
                out.push_back({2, request()});
            }
            if (c_.below(12) == 11) {
                out.push_back({2, {word("kw.reject"), raw("\"never\"")}});
            }
        }
    }
}

Line Generator::answer_step(int& month, int& day) {
    static constexpr std::string_view outcomes[] = {"kw.done", "kw.fails", "kw.expires"};
    const std::string_view outcome = outcomes[c_.below(3)];
    Line line{word(c_.one_in(2) ? "actor.executor" : "actor.keeper"),
              kinds_[c_.below(static_cast<std::uint32_t>(kinds_.size()))],
              word(std::string(outcome))};
    if (outcome != "kw.expires" && c_.one_in(2)) {
        line.push_back(word("kw.with"));
        line.push_back(word(outcome == "kw.done" ? "expr.result" : "expr.reason"));
        line.push_back(raw("="));
        line.push_back(raw(std::format("\"r{}\"", c_.below(10))));
    }
    if (c_.one_in(2)) {
        // Time only goes on (an expiry needs its deadline to have come).
        month += static_cast<int>(c_.below(3));
        day = 1 + static_cast<int>(c_.below(28));
        line.push_back(apply("time.at", {raw(std::format("{}-{:02}-{:02}", 2026 + month / 12,
                                                         1 + month % 12, day))}));
    }
    return line;
}

/// Time rules: each fires at a date, N before due, overdue
/// (N), or a state held N, now and then joined to a condition; it does a
/// built-in action, one of the contract's own, or a block.
void Generator::time_rules(std::vector<std::pair<int, Line>>& out) {
    if (!c_.one_in(2)) {
        return;
    }
    for (std::uint32_t r = 0, n = 1 + c_.below(3); r < n; ++r) {
        Line line{word("kw.when")};
        switch (c_.below(4)) {
        case 0:
            if (due_) {
                line.push_back(word("cond.overdue"));
                if (c_.one_in(2)) {
                    line.push_back(raw(std::format("{} days", c_.between(0, 40))));
                }
                break;
            }
            [[fallthrough]];
        case 1:
            if (due_ && c_.one_in(2)) {
                line.push_back(
                    apply("cond.before_due", {raw(std::format("{} days", c_.between(0, 40)))}));
                break;
            }
            [[fallthrough]];
        case 2:
            if (used_states_ > 1) {
                line.push_back(state(c_.below(static_cast<std::uint32_t>(used_states_))));
                line.push_back(raw(std::format("{} days", c_.between(0, 40))));
                break;
            }
            [[fallthrough]];
        default: {
            in_event_ = true;
            const Line d = value(T::date, 1);
            in_event_ = false;
            line.insert(line.end(), d.begin(), d.end());
            break;
        }
        }
        if (c_.one_in(3)) {
            line.push_back(word("kw.and"));
            line.push_back(raw("("));
            in_rule_ = true;
            const Line cond = condition(1);
            in_rule_ = false;
            line.insert(line.end(), cond.begin(), cond.end());
            line.push_back(raw(")"));
        }
        // What it does.
        std::optional<Tok> does;
        switch (c_.below(6)) {
        case 0:
            // A built-in action, when active is first (otherwise, now and
            // then, one whose states the contract never reaches: refused).
            // Resume starts from suspended, which suspend leads to.
            if (active_first_ || c_.one_in(8)) {
                static constexpr std::string_view built_in[] = {"act.suspend", "act.terminate",
                                                                "act.resume"};
                const bool suspends = std::ranges::any_of(
                    keeper_, [](const Tok& t) { return t.concept_id == "act.suspend"; });
                does = word(std::string(built_in[c_.below(suspends ? 3 : 2)]));
                // Renewed automatically, before its due date.
                if (service_ && c_.one_in(3)) {
                    does = word("act.renew");
                }
                // On a service they ask an executor too (R10); a payment
                // resumes a suspended one (R35).
                for (const std::string_view kind :
                     {std::string_view(does->concept_id),
                      std::string_view(does->concept_id == "act.suspend" ? "act.resume" : "")}) {
                    if (service_ && !kind.empty() && kind != "act.renew" &&
                        !std::ranges::any_of(kinds_,
                                             [&](const Tok& k) { return k.concept_id == kind; })) {
                        kinds_.push_back(word(std::string(kind)));
                    }
                }
            }
            break;
        case 1:
        case 2:
        case 3: {
            // One of the contract's own (now and then one with inputs or a
            // counterparty, which is refused: the keeper's call gives no
            // arguments).
            std::vector<const GAction*> own;
            for (const GAction& a : actions_) {
                if (a.word.empty() && ((a.inputs.empty() && !a.to) || c_.one_in(8))) {
                    own.push_back(&a);
                }
            }
            if (!own.empty()) {
                does = raw(own[c_.below(static_cast<std::uint32_t>(own.size()))]->name);
            }
            break;
        }
        default:
            break;
        }
        if (does) {
            line.push_back(*does);
            keeper_.push_back(*does);
        }
        out.push_back({0, line});
        if (!does || c_.one_in(3)) {
            in_rule_ = true;
            statements(2, 1, out);
            if (!splits_ && c_.one_in(4)) {
                out.push_back({2, request()});
            }
            in_rule_ = false;
        }
    }
}

/// A party a test names: a role, or a ledger only tests name.
Tok Generator::test_party() {
    const std::uint32_t pick = c_.below(static_cast<std::uint32_t>(roles_.size()) + 2);
    return pick < roles_.size() ? roles_[pick] : raw(std::format("bank{}", pick - roles_.size()));
}

/// A step doing an action: its party, its counterparty, its inputs, when,
/// how it is signed, and what it expects.
Line Generator::step(const GAction& a, int& month, int& day) {
    Line line{test_party(), a.word.empty() ? raw(a.name) : word(a.word)};
    const bool propose = a.proposes && c_.one_in(3);
    if (a.to && (a.open_to || !c_.one_in(4))) {
        line.push_back(word("kw.to"));
        // Now and then another party, which a role bound at creation refuses.
        line.push_back(c_.one_in(4) ? test_party() : *a.to);
    }
    Line with;
    if (a.split) {
        // Parts and their recipients, now and then as many of one as of the
        // other; the recipients are the test's parties.
        with.push_back(word("kw.with"));
        with.push_back(word("field.parts"));
        with.push_back(raw("="));
        // Now and then the whole amount, to one recipient: the parts add up.
        const bool whole = !amount_given_.empty() && c_.one_in(2);
        const Line parts = whole ? amount_given_ : literal_list(T::money, 4);
        with.insert(with.end(), parts.begin(), parts.end());
        with.push_back(raw(","));
        with.push_back(word("field.recipients"));
        with.push_back(raw("="));
        const std::uint32_t n = whole ? 1 : 1 + c_.below(4);
        if (n > 1) {
            with.push_back(raw("("));
        }
        for (std::uint32_t i = 0; i < n; ++i) {
            if (i > 0) {
                with.push_back(raw(","));
            }
            with.push_back(test_party());
        }
        if (n > 1) {
            with.push_back(raw(")"));
        }
    } else if (!a.inputs.empty()) {
        with.push_back(word("kw.with"));
        for (std::size_t i = 0; i < a.inputs.size(); ++i) {
            if (i > 0) {
                with.push_back(raw(","));
            }
            with.push_back(raw(a.inputs[i].name));
            with.push_back(raw("="));
            const Line v = a.inputs[i].list ? literal_list(a.inputs[i].type, a.inputs[i].bound)
                                            : literal(a.inputs[i].type);
            with.insert(with.end(), v.begin(), v.end());
        }
    }
    const bool with_first = c_.one_in(2);
    if (with_first) {
        line.insert(line.end(), with.begin(), with.end());
    }
    if (c_.one_in(3)) {
        // Time only goes on.
        if (c_.one_in(2)) {
            month += 1 + static_cast<int>(c_.below(3));
            day = 1 + static_cast<int>(c_.below(28));
        } else {
            day += static_cast<int>(c_.below(static_cast<std::uint32_t>(29 - day)));
        }
        line.push_back(apply("time.at", {raw(std::format("{}-{:02}-{:02}", 2026 + month / 12,
                                                         1 + month % 12, day))}));
    }
    switch (propose ? 1 : c_.below(4)) {
    case 0:
        line.push_back(word("cond.in_person"));
        break;
    case 1:
        line.push_back(word("kw.by"));
        line.push_back(word("actor.ai_agent"));
        break;
    default:
        break;
    }
    if (!with_first) {
        line.insert(line.end(), with.begin(), with.end());
    }
    if (propose) {
        // Kept as a proposal, awaiting a person's approval.
        line.push_back(raw("->"));
        line.push_back(word("val.pending_approval"));
        return line;
    }
    switch (c_.below(9)) {
    case 0:
        // A state some state change names.
        if (used_states_ > 1) {
            line.push_back(raw("->"));
            line.push_back(state(c_.below(static_cast<std::uint32_t>(used_states_))));
            expect_fields(line, true);
        }
        break;
    case 8:
        // Values of fields alone: the call accepted.
        line.push_back(raw("->"));
        expect_fields(line, false);
        break;
    case 1:
        line.push_back(raw("->"));
        line.push_back(word("val.refused"));
        break;
    case 2:
        line.push_back(raw("->"));
        line.push_back(word("val.refused"));
        line.push_back(
            raw(rejects_ > 0 && c_.one_in(2)
                    ? std::format("\"no {}\"", 1 + c_.below(static_cast<std::uint32_t>(rejects_)))
                    : std::format("\"bo:requires {} 1\"", a.name)));
        break;
    case 3:
        line.push_back(raw("->"));
        line.push_back(apply("cond.consent_of", {test_party()}));
        break;
    default:
        break;
    }
    return line;
}

void Generator::expect_fields(Line& line, const bool after_state) {
    std::vector<const GField*> held;
    for (const GField& f : fields_) {
        if (!f.constant && f.type != T::party && f.name != "invoice") {
            held.push_back(&f);
        }
    }
    if (held.empty()) {
        line.push_back(word("val.refused"));
        return;
    }
    if (after_state && c_.one_in(2)) {
        return;
    }
    // Distinct fields: a field named twice is check.duplicate.
    const auto size = static_cast<std::uint32_t>(held.size());
    const std::uint32_t n = 1 + c_.below(std::min<std::uint32_t>(3, size));
    const std::uint32_t start = c_.below(size);
    for (std::uint32_t i = 0; i < n; ++i) {
        const GField& f = *held[(start + i) % size];
        if (i > 0 || after_state) {
            line.push_back(raw(","));
        }
        line.push_back(field_tok(f));
        line.push_back(raw("="));
        const Line v = f.list ? literal_list(f.type, f.bound) : literal(f.type);
        line.insert(line.end(), v.begin(), v.end());
    }
}

/// Test blocks: each creates the instance, then does some actions.
void Generator::tests(std::vector<std::pair<int, Line>>& out) {
    const std::uint32_t count = c_.below(4);
    for (std::uint32_t t = 0; t < count; ++t) {
        out.push_back({0, {word("kw.test"), raw(std::format("\"t{}\"", t))}});
        // The home creates it: we, if the contract has that role.
        Tok home = roles_.front();
        for (const Tok& r : roles_) {
            if (r.concept_id == "role.we") {
                home = r;
            }
        }
        Line create{home, word(asset_ ? "act.issue" : "act.create")};
        bool first = true;
        for (const GField& f : fields_) {
            // A field with a default may be left out.
            if (f.constant || f.type == T::party || (f.initial && c_.one_in(2))) {
                continue;
            }
            create.push_back(first ? word("kw.with") : raw(","));
            first = false;
            create.push_back(field_tok(f));
            create.push_back(raw("="));
            const Line v = f.list ? literal_list(f.type, f.bound) : literal(f.type);
            create.insert(create.end(), v.begin(), v.end());
            if (f.name == "amount") {
                amount_given_ = v;
            }
        }
        out.push_back({2, create});
        int month = static_cast<int>(c_.below(12));
        int day = 1 + static_cast<int>(c_.below(28));
        const bool proposals =
            std::ranges::any_of(actions_, [](const GAction& a) { return a.proposes; });
        for (std::uint32_t k = 0, n = 1 + c_.below(6); k < n; ++k) {
            if (!keeper_.empty() && c_.one_in(3)) {
                // The keeper calls a time rule, by the action it does.
                Line keep{word("actor.keeper"),
                          keeper_[c_.below(static_cast<std::uint32_t>(keeper_.size()))]};
                if (c_.one_in(2)) {
                    // Time only goes on.
                    if (c_.one_in(2)) {
                        month += 1 + static_cast<int>(c_.below(3));
                        day = 1 + static_cast<int>(c_.below(28));
                    } else {
                        day += static_cast<int>(c_.below(static_cast<std::uint32_t>(29 - day)));
                    }
                    keep.push_back(
                        apply("time.at", {raw(std::format("{}-{:02}-{:02}", 2026 + month / 12,
                                                          1 + month % 12, day))}));
                }
                if (c_.one_in(3)) {
                    keep.push_back(raw("->"));
                    keep.push_back(word("val.refused"));
                }
                out.push_back({2, keep});
                continue;
            }
            if (!kinds_.empty() && c_.one_in(4)) {
                // An executor or a keeper answers a request.
                out.push_back({2, answer_step(month, day)});
                continue;
            }
            if (proposals && c_.one_in(4)) {
                // A person approves the first proposal kept.
                Line approve{test_party(), word("act.approve")};
                if (c_.one_in(2)) {
                    approve.push_back(word("cond.in_person"));
                }
                out.push_back({2, approve});
                continue;
            }
            out.push_back({2, step(actions_[c_.below(static_cast<std::uint32_t>(actions_.size()))],
                                   month, day)});
        }
    }
}

std::string write(const std::vector<std::pair<int, Line>>& lines, Choices* languages) {
    std::string out;
    for (const auto& [indent, line] : lines) {
        out += std::string(static_cast<std::size_t>(indent), ' ') + render(line, languages) + "\n";
    }
    return out;
}

// ---------------------------------------------------------------------------
// Compiling and running.

struct Compiled {
    std::optional<bo::Checked> checked;
    bo::Lowered lowered;
};

Compiled compile(std::string_view source) {
    Compiled out;
    const bo::Lexed lexed = bo::lex(source, official());
    if (bo::has_errors(lexed.diagnostics)) {
        return out;
    }
    const bo::Parsed parsed = bo::parse(source, lexed);
    if (!parsed.diagnostics.empty()) {
        return out;
    }
    bo::Checked checked = bo::check(source, parsed.file);
    if (bo::has_errors(checked.diagnostics)) {
        return out;
    }
    out.lowered = bo::lower(source, checked.model);
    out.checked = std::move(checked);
    return out;
}

/// The result as text: the code, or the problems' codes and values.
std::string result_of(const bo::Lowered& lowered) {
    if (lowered.build) {
        std::string out = cexchain::to_hex(lowered.build->code);
        for (const auto& [name, kind] : lowered.build->interface) {
            out += " " + name + std::to_string(static_cast<int>(kind));
        }
        return out;
    }
    std::string out;
    for (const bo::Diagnostic& d : lowered.diagnostics) {
        out += std::string(d.code);
        for (const auto& [name, value] : d.args) {
            if (name != "text") {
                out += " " + value;
            }
        }
        out += "\n";
    }
    return out;
}

protocol::Id ledger(const std::uint8_t fill) {
    return protocol::Id::from_bytes(Bytes(32, fill)).value();
}

std::size_t runs_done = 0;
/// Calls checked against their fuel bound, and the highest share of its
/// bound one used (in thousandths).
std::size_t bounded_calls = 0;
std::uint64_t tightest = 0;
std::size_t tests_run = 0;
std::size_t steps_run = 0;
std::map<std::string, std::size_t> happenings;
std::size_t built = 0;
/// Builds with a built-in action's standard terms; with lists,
/// and with a bill and its charges; calls that made a bill.
std::size_t standard_built = 0;
std::size_t lists_built = 0;
std::size_t bills_built = 0;
std::size_t bills_made = 0;
/// Builds that issue parts, and calls that made parts.
std::size_t parts_built = 0;
/// Builds that make requests, and calls that made some.
std::size_t requests_built = 0;
std::size_t requests_made = 0;
/// Builds of services due each period, and those billing it.
std::size_t services_built = 0;
std::size_t billing_built = 0;
std::size_t parts_made = 0;
std::size_t generated_checked = 0;
std::size_t accepted = 0;
std::size_t needed = 0;
std::map<std::string, std::size_t> refusals;

void collect_rejects(const std::vector<m::Statement>& list, std::set<std::string>& out) {
    for (const m::Statement& s : list) {
        if (const auto* r = std::get_if<m::Reject>(&s.node)) {
            out.insert(r->message);
        } else if (const auto* i = std::get_if<m::If>(&s.node)) {
            collect_rejects(i->then, out);
            collect_rejects(i->otherwise, out);
        } else if (const auto* e = std::get_if<m::Each>(&s.node)) {
            collect_rejects(e->body, out);
        }
    }
}

/// A value of a type, from the choices (now and then of the wrong type).
cbor::Value random_value(const m::Type& t, Choices& c) {
    if (c.one_in(40)) {
        return cbor::Value::text("wrong");
    }
    switch (t.kind) {
    case m::TypeKind::text:
        return cbor::Value::text(c.one_in(2) ? "any" : "x");
    case m::TypeKind::yes_no:
        return cbor::Value::boolean(c.one_in(2));
    case m::TypeKind::party:
        return cbor::Value::bytes(ledger(static_cast<std::uint8_t>(1 + c.below(4))).bytes());
    case m::TypeKind::date:
        return cbor::Value::integer(c.between(1'700'000'000'000, 1'900'000'000'000));
    case m::TypeKind::list: {
        // Now and then one item more than its bound allows.
        cbor::Array items;
        const std::uint32_t n = c.below(std::min<std::uint32_t>(t.bound, 6) + 2);
        for (std::uint32_t i = 0; i < n && !t.element.empty(); ++i) {
            items.push_back(random_value(t.element.front(), c));
        }
        return cbor::Value::array(std::move(items));
    }
    default:
        if (c.one_in(20)) {
            return cbor::Value::integer(c.one_in(2) ? std::numeric_limits<std::int64_t>::max()
                                                    : std::numeric_limits<std::int64_t>::min());
        }
        return cbor::Value::integer(c.between(-1'000, 1'000'000'000));
    }
}

void run_calls(const bo::Build& build, const m::Model& model, Choices& c) {
    auto module = vm::load(build.code);
    require(module.has_value(), "a built module does not load");
    const protocol::Id home = ledger(1);
    std::set<std::string> rejects;
    for (const m::Action& a : model.actions) {
        collect_rejects(a.body, rejects);
    }
    for (const m::TimeRule& r : model.rules) {
        collect_rejects(r.body, rejects);
    }
    std::optional<protocol::ContractInstanceView> instance;
    std::string creation;
    std::vector<std::string> functions;
    for (const auto& [name, kind] : build.interface) {
        (kind == protocol::FunctionKind::create ? creation : functions.emplace_back()) = name;
    }
    const std::uint32_t calls = 1 + c.below(12);
    for (std::uint32_t k = 0; k < calls; ++k) {
        protocol::ContractInput input;
        input.home = home;
        input.contract = ledger(0xC0);
        input.caller = ledger(0xAC);
        input.time =
            static_cast<protocol::Timestamp>(c.between(1'700'000'000'000, 1'900'000'000'000));
        input.caller_signer = protocol::ContractSigner{
            static_cast<std::uint8_t>(c.below(4)),
            c.one_in(2) ? std::optional(protocol::PresenceMethod::webauthn) : std::nullopt,
            std::nullopt};
        cbor::Map arguments;
        if (!instance || c.one_in(10)) {
            input.function = creation;
            cbor::Map parties;
            for (const m::Party& p : model.parties) {
                if (p.binding == m::Binding::creation && !c.one_in(30)) {
                    parties.push_back(
                        {cbor::Value::text(bo::wire_name(p.role, p.name)),
                         cbor::Value::bytes(
                             ledger(static_cast<std::uint8_t>(1 + c.below(4))).bytes())});
                }
            }
            cbor::Map fields;
            for (const m::Field& f : model.fields) {
                const bool from_role = f.type.kind == m::TypeKind::party && f.value;
                if (f.kind == m::FieldKind::instance && !from_role && !f.empty_at_start &&
                    !c.one_in(30)) {
                    fields.push_back({cbor::Value::text(bo::wire_name(f.word, f.name)),
                                      random_value(f.type, c)});
                }
            }
            if (!parties.empty()) {
                arguments.push_back(
                    {cbor::Value::text("parties"), cbor::Value::map(std::move(parties))});
            }
            if (!fields.empty()) {
                arguments.push_back(
                    {cbor::Value::text("fields"), cbor::Value::map(std::move(fields))});
            }
            instance.reset();
        } else {
            input.function = functions.empty() || c.one_in(30)
                                 ? std::string("nothing")
                                 : functions[c.below(static_cast<std::uint32_t>(functions.size()))];
            // A contract that splits: its split, more often.
            for (const m::Action& a : model.actions) {
                if (m::issued_parts(a) != nullptr && !a.rule_only && c.one_in(2)) {
                    input.function = bo::wire_name(a.word, a.name);
                }
            }
            input.instance = instance;
            if (input.function == bo::model::approve_function && !c.one_in(10)) {
                // The first proposal kept, as approve names one.
                const cbor::Value state = instance->state.value();
                const cbor::Value* pending = state.find("pending");
                const cbor::Array* list = pending != nullptr ? pending->as_array() : nullptr;
                if (list != nullptr && !list->empty() && list->front().as_array() != nullptr &&
                    list->front().as_array()->size() == 2) {
                    arguments.push_back(
                        {cbor::Value::text("function"), list->front().as_array()->front()});
                    arguments.push_back(
                        {cbor::Value::text("arguments"), list->front().as_array()->back()});
                }
            }
            // Now and then the instance is a part (v0.7), at a depth up to 8.
            if (c.one_in(4)) {
                input.instance->parent = ledger(0x9A);
                input.instance->depth = 1 + c.below(8);
            }
            for (const m::Action& a : model.actions) {
                if (bo::wire_name(a.word, a.name) != input.function) {
                    continue;
                }
                // Parts that add up to the instance's amount, one for each
                // recipient (R30): the split's arguments, as a holder gives them.
                const cbor::Value state = instance->state.value();
                const cbor::Value* fields = state.find("fields");
                const cbor::Value* amount = fields != nullptr ? fields->find("amount") : nullptr;
                const std::int64_t total =
                    amount != nullptr && amount->as_int64() ? *amount->as_int64() : 0;
                const bool exact = m::issued_parts(a) != nullptr && total > 0 && c.one_in(2);
                const std::int64_t count =
                    exact ? 1 + c.between(0, std::min<std::int64_t>(total, 16) - 1) : 0;
                for (const m::Field& f : a.inputs) {
                    if (exact && f.word != nullptr && f.word->id == "field.parts") {
                        cbor::Array parts;
                        std::int64_t left = total;
                        for (std::int64_t i = 0; i < count; ++i) {
                            const std::int64_t part =
                                i + 1 == count ? left : 1 + c.between(0, left - (count - i));
                            parts.push_back(cbor::Value::integer(part));
                            left -= part;
                        }
                        arguments.push_back(
                            {cbor::Value::text("parts"), cbor::Value::array(std::move(parts))});
                        continue;
                    }
                    if (exact && f.word != nullptr && f.word->id == "field.recipients") {
                        cbor::Array to;
                        for (std::int64_t i = 0; i < count; ++i) {
                            to.push_back(cbor::Value::bytes(
                                ledger(static_cast<std::uint8_t>(1 + c.below(4))).bytes()));
                        }
                        arguments.push_back(
                            {cbor::Value::text("recipients"), cbor::Value::array(std::move(to))});
                        continue;
                    }
                    if (!c.one_in(30)) {
                        arguments.push_back({cbor::Value::text(bo::wire_name(f.word, f.name)),
                                             random_value(f.type, c)});
                    }
                }
                if (a.to && c.one_in(2)) {
                    arguments.push_back(
                        {cbor::Value::text(bo::wire_name(a.to->concept_entry, a.to->name)),
                         cbor::Value::bytes(
                             ledger(static_cast<std::uint8_t>(1 + c.below(4))).bytes())});
                }
            }
            // Consents, as a call cites them: ascending, never the home (all
            // of them, now and then, as a split's recipients give them).
            const bool all = c.one_in(3);
            for (std::uint8_t l = 2; l <= 4; ++l) {
                if (all || c.one_in(2)) {
                    input.consents.push_back(
                        {ledger(l),
                         protocol::ContractSigner{
                             static_cast<std::uint8_t>(c.below(4)),
                             c.one_in(2) ? std::optional(protocol::PresenceMethod::hardware_key)
                                         : std::nullopt,
                             std::nullopt}});
                }
            }
        }
        input.arguments = arguments.empty() && c.one_in(2) ? cbor::Value::null()
                                                           : cbor::Value::map(std::move(arguments));
        auto encoded = protocol::encode_contract_input(input);
        if (!encoded) {
            continue; // keys given twice, or not in order: no ledger sends that
        }
        auto outcome = vm::run(*module, *encoded, provider(), cexchain::crypto::HashAlg::sha256);
        require(outcome.has_value(), "vm::run failed");

        ++runs_done;
        // The fuel bound holds for arguments of the
        // function's shape: refusals of other arguments aside.
        const std::string why(outcome->abort_reason.begin(), outcome->abort_reason.end());
        if (const auto bound = bo::bound_for(build, *encoded);
            bound && !why.starts_with("bo:argument")) {
            require(
                outcome->fuel_used <= *bound, "a call used more fuel than its bound",
                std::format("{} on {}: {} > {}", why, input.function, outcome->fuel_used, *bound));
            ++bounded_calls;
            tightest =
                std::max(tightest, outcome->fuel_used * 1000 / std::max<std::uint64_t>(*bound, 1));
        }
        if (outcome->trap) {
            const std::string reason(outcome->abort_reason.begin(), outcome->abort_reason.end());
            require(*outcome->trap == vm::Trap::aborted, "a compiled contract trapped",
                    std::string(vm::name(*outcome->trap)) + " on " + input.function);
            ++refusals[reason.starts_with("bo:") ? reason.substr(0, reason.find(' ')) : "reject"];
            if (reason.starts_with("bo:")) {
                require(bo::render_reason(reason, nullptr).has_value() &&
                            bo::render_reason(reason, bo::official_pack("zh-Hant-HK")).has_value(),
                        "a reason without a text", reason);
            } else {
                require(rejects.contains(reason), "a reason that is no reject text", reason);
            }
            continue;
        }
        auto output = protocol::decode_contract_output(outcome->output, home);
        require(output.has_value(), "an output the ledger refuses",
                cexchain::to_hex(outcome->output));
        needed += std::holds_alternative<protocol::ContractNeeds>(*output) ? 1U : 0U;
        if (const auto* accept = std::get_if<protocol::ContractAccept>(&*output)) {
            ++accepted;
            const cbor::Value state = accept->state.value();
            require(state.find("state") != nullptr && state.find("fields") != nullptr,
                    "a state without its name and fields");
            // A bill made: its event and the state's bill are the same, and
            // its total is its price and its added charges (R26, R27).
            if (const m::Field* bill = m::bill_field(model); bill != nullptr) {
                const cbor::Value* kept = state.find("bill");
                require(kept != nullptr, "an instance with a bill field keeps no bill");
                for (const protocol::ContractEvent& e : accept->events) {
                    if (e.name == bo::wire_name(bill->word, bill->name)) {
                        require(e.data == *kept, "the bill's event is not the state's bill");
                        ++bills_made;
                    }
                }
                std::int64_t added = 0;
                const cbor::Value* price = kept->find("price");
                const cbor::Value* total = kept->find("total");
                const cbor::Value* charges = kept->find("charges");
                require(price != nullptr && total != nullptr && charges != nullptr &&
                            charges->as_map() != nullptr && price->as_int64() && total->as_int64(),
                        "a bill without its price, total, and charges");
                for (const m::Charge& charge : model.charges) {
                    if (const cbor::Value* x = charges->find(std::string_view(charge.name));
                        x != nullptr && !charge.included) {
                        const cbor::Value* amount = x->find("amount");
                        require(amount != nullptr && amount->as_int64(),
                                "a charge without its amount");
                        added += *amount->as_int64();
                    }
                }
                require(*price->as_int64() + added == *total->as_int64(),
                        "a bill's total is not its price and added charges");
            }
            // Parts (R30): only from an instance above depth 8, which then
            // ends; each with its state and its holder.
            // Requests: at most 16, each well formed, its deadline
            // within 366 days of the call, its reply the contract's own.
            if (!accept->requests.empty()) {
                ++requests_made;
                require(accept->requests.size() <= 16, "more than 16 requests");
                for (const protocol::ContractRequest& q : accept->requests) {
                    require(protocol::is_request_kind(q.kind), "a request's kind");
                    require(q.reply == "result", "a request's reply");
                    require(q.deadline > input.time &&
                                q.deadline - input.time <= protocol::max_request_deadline,
                            "a request's deadline");
                    const auto params = cbor::encode(q.params);
                    require(params.has_value() && params->size() <= 4096, "a request's params");
                }
            }
            if (!accept->children.empty()) {
                ++parts_made;
                require(input.instance.has_value() && input.instance->depth < 8,
                        "parts made at depth 8");
                require(accept->final, "an instance that issued parts did not end");
                require(accept->children.size() <= 16, "more than 16 parts");
                for (const protocol::ContractChild& child : accept->children) {
                    const cbor::Value made = child.state.value();
                    require(made.find("state") != nullptr && made.find("fields") != nullptr &&
                                child.parties.contains("holder") && child.status.has_value(),
                            "a part without its state, fields, status, or holder");
                }
            }
            if (!instance) {
                instance = protocol::ContractInstanceView{ledger(0x1D), 0, {}, {}, {}, {}, 0};
            }
            instance->head += 1;
            instance->state = accept->state;
            instance->status = accept->status;
            if (accept->parties) {
                instance->parties = *accept->parties;
            }
            if (accept->final) {
                instance.reset();
            }
        }
    }
}

/// Runs a model's tests on its build, as `bo test` does, and checks what
/// happened; returns the results as canonical text.
std::string run_scenarios(const bo::Build& build, const m::Model& model, std::string_view source) {
    if (model.tests.empty()) {
        return {};
    }
    const bo::TestResults results = bo::run_tests(model, build, provider());
    const std::string text = bo::dump(model, results);
    require(bo::dump(model, bo::run_tests(model, build, provider())) == text,
            "running the tests twice differs", source);
    require(results.tests.size() == model.tests.size(), "a test without its results");
    std::set<std::string> rejects;
    for (const m::Action& a : model.actions) {
        collect_rejects(a.body, rejects);
    }
    for (const m::TimeRule& r : model.rules) {
        collect_rejects(r.body, rejects);
    }
    for (std::size_t t = 0; t < results.tests.size(); ++t) {
        const bo::TestResult& test = results.tests[t];
        require(test.steps.size() == model.tests[t].steps.size(), "a step without its result");
        bool failed = false;
        for (const bo::StepResult& r : test.steps) {
            require(r.happened != bo::Happened::broken, "a step broke",
                    r.reason + "\n" + std::string(source));
            require(!failed || r.status == bo::StepStatus::skipped, "a step ran after a failure");
            failed = failed || r.status == bo::StepStatus::failed;
            if (r.status != bo::StepStatus::skipped) {
                ++steps_run;
                ++happenings[std::string(bo::happened_names[static_cast<std::size_t>(r.happened)])];
                happenings["(proposals)"] += r.proposed.empty() ? 0U : 1U;
                // Parts made, and steps on a part.
                happenings["(splits)"] += r.parts > 0 ? 1U : 0U;
                happenings["(on parts)"] += r.part.empty() ? 0U : 1U;
            }
            if (r.happened == bo::Happened::refused) {
                require(
                    r.reason.starts_with("bo:") ? bo::render_reason(r.reason, nullptr).has_value()
                                                : rejects.contains(r.reason),
                    "a refusal that is no reason of the compiler's or the contract's", r.reason);
            }
            for (const bo::TestCall& call : r.calls) {
                const auto& consents = call.input.consents;
                for (std::size_t k = 0; k < consents.size(); ++k) {
                    require(!(consents[k].first == test.home), "a consent of the home's");
                    require(k == 0 || std::ranges::lexicographical_compare(
                                          consents[k - 1].first.bytes(), consents[k].first.bytes()),
                            "consents out of order");
                }
            }
        }
        require(test.passed == !failed, "a test passed with a failing step");
        ++tests_run;
    }
    for (const bo::Pack& language : bo::official_packs()) {
        const std::string report = bo::test_report(model, results, source, &language);
        require(!report.empty() && cbor::is_valid_utf8(report), "a report that is no text");
    }
    return text;
}

void build_and_run(std::string_view source, Choices& c,
                   const std::optional<std::string>& expected = std::nullopt) {
    const Compiled first = compile(source);
    if (!first.checked) {
        require(!expected.has_value(), "a rendering does not check", source);
        return;
    }
    std::string result = result_of(first.lowered);
    require(result == result_of(compile(source).lowered), "lowering twice differs", source);
    if (first.lowered.build) {
        result += run_scenarios(*first.lowered.build, first.checked->model, source);
    }
    if (expected) {
        require(result == *expected, "languages give different results", source);
    }
    for (const bo::Diagnostic& d : first.lowered.diagnostics) {
        require(d.code.starts_with("build."), "a diagnostic that is no build.* code", d.code);
        require(!bo::render(d, bo::official_pack("zh-Hans-CN")).empty(), "an empty message");
    }
    if (first.lowered.build) {
        require(first.lowered.diagnostics.empty(), "a build with problems");
        ++built;
        standard_built += std::ranges::any_of(first.checked->model.actions,
                                              [](const m::Action& a) { return a.terms; })
                              ? 1U
                              : 0U;
        lists_built +=
            std::ranges::any_of(first.checked->model.fields,
                                [](const m::Field& f) { return f.type.kind == m::TypeKind::list; })
                ? 1U
                : 0U;
        bills_built += m::bill_field(first.checked->model) != nullptr ? 1U : 0U;
        parts_built += m::issues_parts(first.checked->model) ? 1U : 0U;
        requests_built += m::makes_requests(first.checked->model) ? 1U : 0U;
        services_built += first.checked->model.due == m::DueKind::period ? 1U : 0U;
        billing_built += m::answer_rule(first.checked->model, "collect", 1) != nullptr ? 1U : 0U;
        run_calls(*first.lowered.build, first.checked->model, c);
    }
}

/// The model and its text in each official language, then the build's
/// result: what formatting must not change.
std::string meaning_of(const Compiled& compiled) {
    std::string out = bo::dump(compiled.checked->model);
    for (const bo::Pack& language : bo::official_packs()) {
        out += bo::explain(compiled.checked->model, &language).text;
    }
    out += result_of(compiled.lowered);
    if (compiled.lowered.build) {
        out +=
            bo::dump(compiled.checked->model,
                     bo::run_tests(compiled.checked->model, *compiled.lowered.build, provider()));
    }
    return out;
}

std::size_t formatted = 0;

/// A source that checks, formatted as written and into each official
/// language: the same model, text, and build; formatting again changes
/// nothing.
void formats_alike(std::string_view source, const Compiled& compiled,
                   std::span<const char* const> ids) {
    const std::string expected = meaning_of(compiled);
    for (const char* id : ids) {
        const bo::Pack* language = *id == '\0' ? nullptr : official_set().find(id);
        const bo::Formatted f = bo::format_source(source, official_set(), official(), language);
        require(f.source.has_value(), "a contract that checks is not formatted",
                f.diagnostics.empty() ? source : f.diagnostics.front().code);
        const Compiled again = compile(*f.source);
        require(again.checked.has_value(), "a formatted contract does not check", *f.source);
        require(meaning_of(again) == expected, "formatting changed the model, text, or code",
                *f.source);
        require(bo::format_source(*f.source, official_set(), official(), language).source ==
                    f.source,
                "formatting twice differs", *f.source);
        ++formatted;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    current_data = data;
    current_size = size;
    if (size == 0) {
        return 0;
    }
    if ((data[0] & 1U) != 0) {
        // Source as it is, then calls from a fixed set of choices.
        const std::string source(reinterpret_cast<const char*>(data + 1), size - 1);
        const std::uint8_t calls[] = {7, 1, 200, 3, 9, 77, 5, 0, 2, 31, 4, 8, 16, 99, 1, 3};
        Choices c(calls, sizeof calls);
        build_and_run(source, c);
        return 0;
    }
    Choices c(data + 1, size - 1);
    Generator generator(c);
    const auto lines = generator.contract();
    const std::string english = write(lines, nullptr);
    const Compiled compiled = compile(english);
    if (!compiled.checked) {
        return 0;
    }
    ++generated_checked;
    std::string result = result_of(compiled.lowered);
    if (compiled.lowered.build) {
        result += run_scenarios(*compiled.lowered.build, compiled.checked->model, english);
    }
    // The same contract, each word in a language chosen at random.
    Choices languages(data + 1, size - 1);
    const std::string mixed = write(lines, &languages);
    build_and_run(mixed, c, result);
    build_and_run(english, c);
    // Formatted, as written and into each language; the mixed rendering as
    // written and into one language the input picks.
    static const char* const all[] = {"", "en", "zh-Hant-HK", "zh-Hans-CN"};
    formats_alike(english, compiled, all);
    if (const Compiled other = compile(mixed); other.checked) {
        const char* const some[] = {"", all[1 + size % 3]};
        formats_alike(mixed, other, some);
    }
    current_data = nullptr;
    return 0;
}

#if defined(CEXCHAIN_BO_FUZZ_DRIVER)

namespace {

std::uint64_t splitmix(std::uint64_t& state) {
    std::uint64_t z = (state += 0x9E37'79B9'7F4A'7C15ULL);
    z = (z ^ (z >> 30U)) * 0xBF58'476D'1CE4'E5B9ULL;
    z = (z ^ (z >> 27U)) * 0x94D0'49BB'1331'11EBULL;
    return z ^ (z >> 31U);
}

Bytes read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

int main(int argc, char** argv) {
    std::uint64_t runs = 1000;
    std::uint64_t seconds = 0;
    std::uint64_t seed = 1;
    std::vector<std::filesystem::path> inputs;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        const auto number = [&](std::string_view flag) {
            return std::strtoull(std::string(arg.substr(flag.size())).c_str(), nullptr, 10);
        };
        if (arg.starts_with("-runs=")) {
            runs = number("-runs=");
        } else if (arg.starts_with("-max_total_time=")) {
            seconds = number("-max_total_time=");
            runs = std::numeric_limits<std::uint64_t>::max();
        } else if (arg.starts_with("-seed=")) {
            seed = number("-seed=");
        } else if (arg.starts_with("-")) {
            // libFuzzer's other flags mean nothing here.
        } else {
            inputs.emplace_back(arg);
        }
    }
    if (inputs.empty()) {
        inputs.emplace_back(CEXCHAIN_BO_GOLDEN_DIR);
    }
    std::size_t replayed = 0;
    for (const std::filesystem::path& input : inputs) {
        std::vector<std::filesystem::path> files;
        if (std::filesystem::is_directory(input)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(input)) {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path());
                }
            }
        } else {
            files.push_back(input);
        }
        std::ranges::sort(files);
        for (const std::filesystem::path& file : files) {
            // Sources (.bo), and inputs as a corpus keeps them (no extension).
            if (file.has_extension() && file.extension() != ".bo") {
                continue;
            }
            Bytes bytes = read_file(file);
            if (file.extension() == ".bo") {
                bytes.insert(bytes.begin(), 1); // as source
            }
            LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
            ++replayed;
        }
    }
    const auto start = std::chrono::steady_clock::now();
    std::uint64_t state = seed;
    std::uint64_t done = 0;
    for (; done < runs; ++done) {
        if (seconds > 0 &&
            std::chrono::steady_clock::now() - start > std::chrono::seconds(seconds)) {
            break;
        }
        Bytes bytes(64 + splitmix(state) % 960);
        for (std::uint8_t& b : bytes) {
            b = static_cast<std::uint8_t>(splitmix(state));
        }
        bytes[0] = static_cast<std::uint8_t>(bytes[0] & 0xFEU); // the generator
        LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    std::printf("bo_build_fuzz: %zu files replayed, %llu inputs generated (%zu contracts that "
                "check) in %lld ms; %zu builds, %zu calls run, %zu sources formatted; no "
                "failures\n",
                replayed, static_cast<unsigned long long>(done), generated_checked,
                static_cast<long long>(elapsed.count()), built, runs_done, formatted);
    std::printf("builds with the standard library's terms: %zu; with lists %zu; with a bill "
                "%zu (bills made by calls: %zu); issuing parts %zu (calls that made parts: %zu)\n",
                standard_built, lists_built, bills_built, bills_made, parts_built, parts_made);
    std::printf("builds making requests: %zu (calls that made requests: %zu); services due each "
                "period %zu, billing it %zu\n",
                requests_built, requests_made, services_built, billing_built);
    std::printf("calls checked against their fuel bound: %zu, the closest at %llu.%llu%% of it\n",
                bounded_calls, static_cast<unsigned long long>(tightest / 10),
                static_cast<unsigned long long>(tightest % 10));
    std::printf("calls: %zu accepted, %zu needing consents, refused:", accepted, needed);
    for (const auto& [reason, count] : refusals) {
        std::printf(" %s %zu", reason.c_str(), count);
    }
    std::printf("\ntests: %zu run, %zu steps:", tests_run, steps_run);
    for (const auto& [what, count] : happenings) {
        std::printf(" %s %zu", what.c_str(), count);
    }
    std::printf("\n");
    return 0;
}

#endif
