// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The checker (milestone 4 of the Bo compiler): the goldens in
// tests/bo/golden/CASE/check.txt (for the cases named example-* and check-*,
// as `bo check --stage model` prints the model, followed by the checker's
// problems), the same model for the same contract in every language, every
// check with an error golden, every recognition rule seen, messages and types
// in three languages, and the rules for values, units, states, roles, and
// thresholds. Set CEXCHAIN_UPDATE_GOLDENS=1 to rewrite the check.txt files
// after a deliberate change.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>

using namespace cexchain::bo;

namespace {

const std::filesystem::path golden_dir = CEXCHAIN_BO_GOLDEN_DIR;

const Lexicon& official() {
    static const Lexicon lexicon = [] {
        const PackSetRead set = make_pack_set({});
        return Lexicon(*set.set);
    }();
    return lexicon;
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

/// Lexes, parses (without problems), and checks a source.
Checked check_text(std::string_view source) {
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    INFO(source);
    INFO(dump(parsed, nullptr));
    REQUIRE(!has_errors(lexed.diagnostics));
    REQUIRE(parsed.diagnostics.empty());
    return check(source, parsed.file);
}

std::string codes(const Checked& checked) {
    std::string out;
    for (const Diagnostic& d : checked.diagnostics) {
        out += (out.empty() ? "" : " ") + std::string(d.code);
    }
    return out;
}

/// The checker's codes for a source.
std::string check_codes(std::string_view source) {
    return codes(check_text(source));
}

/// The model of a source that must check without problems.
std::string model_of(std::string_view source) {
    const Checked checked = check_text(source);
    INFO(dump(checked, nullptr));
    CHECK(checked.diagnostics.empty());
    return dump(checked.model);
}

std::vector<std::filesystem::path> check_cases() {
    std::vector<std::filesystem::path> cases;
    for (const auto& entry : std::filesystem::directory_iterator(golden_dir)) {
        const std::string name = entry.path().filename().string();
        if (std::filesystem::exists(entry.path() / "source.bo") &&
            (name.starts_with("example-") || name.starts_with("check-"))) {
            cases.push_back(entry.path());
        }
    }
    std::ranges::sort(cases);
    return cases;
}

} // namespace

TEST_CASE("the checker's goldens", "[bo][check]") {
    const std::vector<std::filesystem::path> cases = check_cases();
    CHECK(cases.size() >= 32);
    const bool update = std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr;
    for (const auto& path : cases) {
        const std::string name = path.filename().string();
        INFO(name);
        const std::string source = read_text(path / "source.bo");
        const Checked checked = check_text(source);
        const std::string text = dump(checked, nullptr);
        if (update) {
            std::ofstream(path / "check.txt", std::ios::binary) << text;
        }
        CHECK(text == read_text(path / "check.txt"));
        // The same every time.
        const Parsed again = parse(source, lex(source, official()));
        CHECK(dump(check(source, again.file), nullptr) == text);
        // Every problem has a place in the source, but the fragment's note.
        for (const Diagnostic& d : checked.diagnostics) {
            if (d.code != "check.fragment") {
                CHECK(d.span.line >= 1);
                CHECK(std::uint64_t{d.span.offset} + d.span.length <= source.size());
            }
        }
        if (name.starts_with("check-error-")) {
            CHECK(has_errors(checked.diagnostics));
        } else {
            CHECK(!has_errors(checked.diagnostics));
        }
    }
}

TEST_CASE("each example, in each language or mixed, gives the same model", "[bo][check]") {
    for (const std::string group :
         {"example-receivable", "example-ip-pool", "example-vps", "example-split", "example-tax"}) {
        const std::string first = read_text(golden_dir / (group + "-en") / "source.bo");
        const Checked english = check_text(first);
        CHECK(!has_errors(english.diagnostics));
        for (const std::string language : {"zh-hant", "zh-hans", "mixed"}) {
            INFO(group + "-" + language);
            const Checked other =
                check_text(read_text(golden_dir / (group + "-" + language) / "source.bo"));
            CHECK(dump(other.model) == dump(english.model));
            CHECK(codes(other) == codes(english));
        }
    }
    // The examples check: the VPS example's executor clauses are marked
    // (6b), the tax example is a fragment, and the others are clean.
    CHECK(check_codes(read_text(golden_dir / "example-receivable-en" / "source.bo")).empty());
    CHECK(check_codes(read_text(golden_dir / "example-ip-pool-en" / "source.bo")).empty());
    CHECK(check_codes(read_text(golden_dir / "example-split-en" / "source.bo")).empty());
    CHECK(check_codes(read_text(golden_dir / "example-vps-en" / "source.bo")) ==
          "check.needs-executor check.needs-executor check.needs-executor check.needs-executor "
          "check.needs-executor check.needs-executor");
    CHECK(check_codes(read_text(golden_dir / "example-tax-en" / "source.bo")) == "check.fragment");
}

TEST_CASE("every check has an error golden, and every rule is seen", "[bo][check]") {
    std::set<std::string> seen_codes;
    std::string models;
    for (const auto& path : check_cases()) {
        const Checked checked = check_text(read_text(path / "source.bo"));
        for (const Diagnostic& d : checked.diagnostics) {
            seen_codes.insert(std::string(d.code));
        }
        models += dump(checked.model);
    }
    for (const MessageSpec& spec : message_specs()) {
        if (spec.code.starts_with("check.")) {
            INFO(spec.code);
            CHECK(seen_codes.contains(std::string(spec.code)));
        }
    }
    for (const RuleSpec& rule : rule_specs()) {
        INFO(rule.id);
        CHECK(models.find("{" + std::string(rule.id) + "}") != std::string::npos);
        // Each rule's text is a sentence of the edition.
        CHECK(find_sentence("rule-" + std::string(rule.id)) != nullptr);
    }
    // The model names no rule that the edition lacks.
    std::size_t at = 0;
    while ((at = models.find("{R", at)) != std::string::npos) {
        const std::size_t end = models.find('}', at);
        REQUIRE(end != std::string::npos);
        CHECK(find_rule(models.substr(at + 1, end - at - 1)) != nullptr);
        at = end;
    }
    CHECK(rule_specs().size() == 22);
    CHECK(rule_specs().front().id == "R1");
}

TEST_CASE("messages and types, in each language", "[bo][check]") {
    const Checked checked =
        check_text("contract C\nparties issuer\nasset A\n  holder HKD\n  fee USD\n"
                   "can pay by issuer with cost HKD\n  requires cost > fee\n");
    REQUIRE(codes(checked) == "check.field-type check.mixed-currencies");
    const Diagnostic& field = checked.diagnostics[0];
    CHECK(field.arg("field") == "field.holder");
    CHECK(field.arg("type") == "money cur.HKD");
    CHECK(field.arg("expected_type") == "party");
    CHECK(render(field, nullptr) == "holder holds a party, not money in HKD");
    CHECK(render(field, official_pack("zh-Hant-HK")) == "持有人 存放的是訂約方，而非港元金額");
    CHECK(render(field, official_pack("zh-Hans-CN")) == "持有人 存放的是参与方，而不是港元金额");
    const Diagnostic& money = checked.diagnostics[1];
    CHECK(money.span.line == 7);
    CHECK(render(money, nullptr) ==
          "money in HKD and money in USD are in different currencies; Bo never converts one into "
          "the other");
    CHECK(render(money, official_pack("zh-Hant-HK")) ==
          "港元金額與美元金額是不同貨幣；Bo 從不換算貨幣");

    // Types, encoded and in words.
    model::Type list;
    list.kind = model::TypeKind::list;
    list.bound = 16;
    model::Type amount;
    amount.kind = model::TypeKind::money;
    amount.currency = find_concept("cur.HKD");
    list.element.push_back(amount);
    CHECK(encode(list) == "list 16 money cur.HKD");
    CHECK(describe_type(encode(list), nullptr) == "a list of at most 16 items, each money in HKD");
    CHECK(describe_type(encode(list), official_pack("zh-Hant-HK")) ==
          "最多 16 項的清單，每項為港元金額");
    model::Type monthly;
    monthly.kind = model::TypeKind::recurring;
    monthly.period = find_concept("time.monthly");
    model::Type data;
    data.kind = model::TypeKind::quantity;
    data.dimension = model::Dimension::data;
    monthly.element.push_back(data);
    CHECK(encode(monthly) == "recurring time.monthly quantity data");
    CHECK(describe_type(encode(monthly), official_pack("zh-Hans-CN")) ==
          "每月数据量（MB、GB、TB、MiB、GiB、TiB）");
    model::Type price;
    price.kind = model::TypeKind::unit_price;
    price.currency = find_concept("cur.USD");
    price.dimension = model::Dimension::data;
    CHECK(encode(price) == "unit_price cur.USD data");
    CHECK(describe_type(encode(price), nullptr) == "a price in USD per GB");
    CHECK(describe_type(encode(price), official_pack("zh-Hant-HK")) == "每GB的美元價格");
    // Whatever is not an encoded type stays as written.
    CHECK(describe_type("nonsense", nullptr) == "nonsense");
    CHECK(describe_type("", nullptr) == "an unknown type");
    // Concepts in the checker's values are spelled in the reader's language.
    const Checked unknown = check_text("contract C\nparties we\nrecord R\n  note text\n"
                                       "can close by we\n  requires due < today\n");
    REQUIRE(codes(unknown) == "check.unknown-field");
    CHECK(render(unknown.diagnostics[0], official_pack("zh-Hant-HK"))
              .starts_with("實例沒有欄位 到期日："));
}

TEST_CASE("fields: types, constants, parties, and the vocabulary's meanings", "[bo][check]") {
    const std::string model =
        model_of("contract C\nparties we, customer\nservice S\n  price monthly HKD 120\n"
                 "  traffic monthly 2TB, overage per GB HKD 0.000001\n  holder customer\n"
                 "  due\n  tier\n  cooling period\n  IP 1 item\n  limit 5_000 HKD\n");
    CHECK(model.find("field price.price constant recurring time.monthly money cur.HKD") !=
          std::string::npos);
    CHECK(model.find("more (phrase price.overage price.per unit.GB (money cur.HKD 0.000001)) : "
                     "unit_price cur.HKD data") != std::string::npos);
    CHECK(model.find("field field.holder instance party = role.customer{R2}") != std::string::npos);
    CHECK(model.find("field field.due instance date{R1}") != std::string::npos);
    CHECK(model.find("field field.tier instance number{R1}") != std::string::npos);
    CHECK(model.find("field field.cooling_period instance duration{R1}") != std::string::npos);
    CHECK(model.find("field IP constant quantity count") != std::string::npos);
    CHECK(model.find("field limit constant money cur.HKD") != std::string::npos);
    // A due field: due is the field, not the period.
    CHECK(model.find("due field\n") != std::string::npos);
    // Unit prices keep six decimal places; overage counts in the traffic's units.
    CHECK(check_codes("contract C\nparties we\nservice S\n"
                      "  traffic monthly 2TB, overage per GB HKD 0.0000001\n") ==
          "check.precision");
    CHECK(check_codes("contract C\nparties we\nservice S\n"
                      "  traffic monthly 2TB, overage per item HKD 1\n") == "check.mixed-units");
    // Amounts need a unit; parts take the amount's.
    CHECK(check_codes("contract C\nparties we\nasset A\n  amount\n") == "check.field-needs-type");
    CHECK(check_codes("contract C\nparties we\nasset A\n  parts\n") == "check.field-needs-type");
    CHECK(model_of("contract C\nparties we\nasset A\n  amount 2TB\n  parts list TB at most 4\n")
              .find("field field.parts instance list 4 quantity data") != std::string::npos);
    CHECK(check_codes("contract C\nparties we\nasset A\n  amount HKD\n  parts list USD\n") ==
          "check.field-type");
}

TEST_CASE("values are exact, in their smallest units", "[bo][check]") {
    const std::string head = "contract C\nparties we\nrecord R\n  size GB\n  cost HKD\n"
                             "  term days\n  n number\ncan look by we\n";
    const auto requires_ = [&](std::string_view condition) {
        return check_codes(head + "  requires " + std::string(condition) + "\n");
    };
    CHECK(requires_("size > 0.5 GiB").empty());
    CHECK(requires_("size > 0.1 GiB") == "check.precision");
    CHECK(requires_("size > 1.5 MB").empty());
    CHECK(requires_("size > 0.0000001 MB") == "check.precision");
    CHECK(requires_("cost > HKD 0.01").empty());
    CHECK(requires_("cost > 92233720368547758.08 HKD") == "check.overflow");
    CHECK(requires_("cost > 92233720368547758.07 HKD").empty());
    CHECK(requires_("n > 9223372036854775807").empty());
    CHECK(requires_("n > 9223372036854775808") == "check.overflow");
    CHECK(requires_("n > 5.0").empty());
    CHECK(requires_("5.0001% > 0.0001%").empty());
    CHECK(requires_("term > 1.5 days") == "check.whole-number");
    CHECK(requires_("term > 106751991167 days").empty());
    CHECK(requires_("term > 106751991168 days") == "check.overflow");
    CHECK(requires_("term > 10001 years") == "check.overflow");
    // Arithmetic: money by money of one currency, by numbers and rates.
    CHECK(requires_("cost * 2 > cost + HKD 1").empty());
    CHECK(requires_("cost * 5% > HKD 1").empty());
    CHECK(requires_("cost / cost > 50%").empty());
    CHECK(requires_("cost * cost > HKD 1") == "check.operands");
    CHECK(requires_("cost + USD 1 > HKD 1") == "check.mixed-currencies");
    CHECK(requires_("size + 1 Mbps > 1 GB") == "check.mixed-units");
    CHECK(requires_("today + 30 days > today").empty());
    CHECK(requires_("today - today > 30 days").empty());
    CHECK(requires_("1 month + 2 days > 1 month") == "check.calendar");
    CHECK(requires_("cost / 0 > HKD 1") == "check.zero-division");
    CHECK(requires_("cost in (HKD 1, HKD 2)").empty());
    CHECK(requires_("cost in (HKD 1, USD 2)") == "check.list-items");
    CHECK(requires_("cost in HKD 1") == "check.type");
    CHECK(requires_("not cost") == "check.type");
    // R17: products and quotients that round say so.
    CHECK(model_of(head + "  requires cost * 5% > HKD 1\n").find("{R17}") != std::string::npos);
}

TEST_CASE("states: collected, the first one, and reachable", "[bo][check]") {
    // No state changes: every instance is active (R4).
    CHECK(model_of("contract C\nparties we\nrecord R\n  n number\ncan go by we\n")
              .find("state state.active first{R4}\n") != std::string::npos);
    // A cycle with active: active is first.
    const std::string cycle = model_of("contract C\nparties we\nrecord R\n  n number\n"
                                       "can stop by we\n  active -> suspended\n"
                                       "can resume by we\n  suspended -> active\n");
    CHECK(cycle.find("state state.active first{R4}\nstate state.suspended{R5}\n") !=
          std::string::npos);
    // From any state: `-> closed`.
    CHECK(model_of("contract C\nparties we\nrecord R\n  n number\ncan end by we\n  -> closed\n")
              .find("state closed{R5}") != std::string::npos);
    // A cycle without active cannot be reached.
    CHECK(check_codes("contract C\nparties we\nrecord R\n  n number\n"
                      "can a by we\n  x -> y\ncan b by we\n  y -> x\n") ==
          "check.unreachable-state check.unreachable-state");
    // A state used as a condition (R7); one only a vocabulary action whose
    // standard terms come later could reach is not reported.
    CHECK(check_codes("contract C\nparties we\nasset A\n  n number\ncan refund\n"
                      "  requires not frozen\n")
              .empty());
    // The standard terms' states are known (R19): those they reach are the
    // contract's, and no other.
    CHECK(model_of("contract C\nparties we\nasset A\n  holder we\ncan pledge\n"
                   "  requires not frozen\ncan freeze\n")
              .find("state state.active first{R4}\nstate state.pledged{R19}\n"
                    "state state.frozen{R19}\n") != std::string::npos);
    CHECK(check_codes("contract C\nparties we\nasset A\n  holder we\ncan pledge\n"
                      "  requires not frozen\n") == "check.unreachable-state");
    // A transition names states, not parties.
    CHECK(check_codes("contract C\nparties we\nrecord R\n  n number\ncan go by we\n  -> we\n") ==
          "check.type");
}

TEST_CASE("roles: bound at creation, or by the first to (U4)", "[bo][check]") {
    const std::string model =
        model_of("contract C\nparties issuer, supplier, bank\nasset A\n  holder supplier\n"
                 "can audit by bank\n  -> active\ncan pledge to bank\n");
    // The bank is named after `by` first: bound at creation.
    CHECK(model.find("party role.bank bound=creation{R3}") != std::string::npos);
    const std::string later =
        model_of("contract C\nparties issuer, supplier, bank\nasset A\n  holder supplier\n"
                 "can pledge to bank\ncan audit by bank\n  -> active\n");
    CHECK(later.find("party role.bank bound=act.pledge{R3}") != std::string::npos);
    CHECK(later.find("  consent role.bank{R3}\n") != std::string::npos);
    // A name of the contract's own is a party too.
    CHECK(
        model_of("contract C\nparties 甲方, 乙方\nrecord R\n  n number\ncan sign by 甲方 to 乙方\n")
            .find("party 乙方 bound=sign{R3}") != std::string::npos);
    CHECK(check_codes("contract C\nparties we\nrecord R\n  n number\ncan sign by we to bank\n") ==
          "check.unknown-party");
    CHECK(check_codes("contract C\nparties we\nrecord R\n  n number\ncan sign by n\n") ==
          "check.type");
}

TEST_CASE("consents, presence, agents, and thresholds", "[bo][check]") {
    // R8: taking a field that holds a party needs its consent, unless that
    // party starts the action.
    const std::string fields = "  amount HKD\n  holder supplier\n";
    CHECK(model_of("contract C\nparties we, supplier, bank\nasset A\n" + fields +
                   "can seize by we\n  holder = we\n")
              .find("  consent field.holder{R8}\n") != std::string::npos);
    CHECK(model_of("contract C\nparties we, supplier, bank\nasset A\n" + fields +
                   "can give by holder\n  holder = we\n")
              .find("consent") == std::string::npos);
    // R6: a bare threshold takes the unit of the action's one amount.
    CHECK(model_of("contract C\nparties we\nasset A\n  amount TB\ncan ship by we\n"
                   "  over 2 requires in person\n")
              .find("guard=(cond.over (quantity unit.TB 2){R6})") != std::string::npos);
    CHECK(model_of("contract C\nparties we\nasset A\n  amount HKD\ncan ship by we with fee USD\n"
                   "  over 2 requires in person\n")
              .find("guard=(cond.over (money cur.USD 2){R6})") != std::string::npos);
    CHECK(check_codes("contract C\nparties we\nasset A\n  amount HKD\ncan ship by we\n"
                      "  over USD 2 requires in person\n") == "check.mixed-currencies");
    CHECK(check_codes("contract C\nparties we\nasset A\n  amount HKD\ncan ship by we\n"
                      "  over 0.001 requires in person\n") == "check.precision");
    // R13 and R14: presence is the starter's; agents act within delegation
    // unless the action says they only propose.
    const std::string presence = model_of(
        "contract C\nparties we\nasset A\n  amount HKD\ncan ship by we\n  requires in person\n"
        "can send by we\n  AI agent can propose\n");
    CHECK(presence.find("can ship own by=role.we agents=delegation{R14}\n  requires "
                        "cond.in_person{R13}\n") != std::string::npos);
    CHECK(presence.find("can send own by=role.we agents=propose\n") != std::string::npos);
    CHECK(check_codes("contract C\nparties we\nasset A\n  amount HKD\ncan ship by we\n"
                      "  device can propose\n") == "check.permit");
    // consent of names a party.
    CHECK(check_codes("contract C\nparties we\nasset A\n  amount HKD\ncan ship by we\n"
                      "  requires consent of amount\n") == "check.type");
}

TEST_CASE("time rules: events, duties, and what is due", "[bo][check]") {
    // R9: a duty, and the due date it sets.
    CHECK(model_of("contract C\nparties issuer\nasset A\n  due date\nwhen due issuer pays\n")
              .find("  do subject=role.issuer act.pay obligation{R9}\n") != std::string::npos);
    // R11: a service with a recurring price is due each period.
    const std::string service =
        model_of("contract C\nparties we\nservice S\n  price monthly HKD 10\n"
                 "when overdue 3 days we pays\nwhen 1 month before due we pays\n");
    CHECK(service.find("due period{R11}\n") != std::string::npos);
    CHECK(check_codes("contract C\nparties we\nservice S\n  price HKD 10\n"
                      "when overdue 3 days we pays\n") == "check.needs-due");
    CHECK(check_codes("contract C\nparties we\nasset A\n  due date\nwhen due + 3 days we pays\n")
              .empty());
    CHECK(check_codes("contract C\nparties we\nasset A\n  due date\nwhen 5 > 3 we pays\n") ==
          "check.when-event");
    // In a time rule, what a person does has no place; a threshold neither.
    CHECK(check_codes("contract C\nparties we\nasset A\n  due date\nwhen due\n"
                      "  over 5 requires due < today\n") == "check.not-a-value");
}

TEST_CASE("the checker is safe on any tree", "[bo][check]") {
    // Trees with errors still check (the command line checks only clean
    // ones), and nothing the parser accepts upsets the checker.
    for (const std::string_view source :
         {"", "contract X\n", "parties we\n", "asset A\n", "can x\n", "when due\n  x\n",
          "contract C\nparties we\nasset A\n  amount HKD\n  parts\ncan split with parts\n",
          "contract C\nparties we\nrecord R\n  n list list number\n",
          "contract C\nparties we\nrecord R\n  n (1, 2)\ncan a by we\n  each x in n\n"
          "    each y in n\n      requires x = y\n"}) {
        const Lexed lexed = lex(source, official());
        const Parsed parsed = parse(source, lexed);
        const Checked checked = check(source, parsed.file);
        CHECK(dump(check(source, parsed.file), nullptr) == dump(checked, nullptr));
        for (const Diagnostic& d : checked.diagnostics) {
            CHECK(find_message(d.code) != nullptr);
            for (const Pack& pack : official_packs()) {
                CHECK(!render(d, &pack).empty());
            }
        }
    }
}
