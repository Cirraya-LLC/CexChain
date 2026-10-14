// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Lowering (milestone 6 of the Bo compiler): compiled contracts run as the
// ledger runs them, through protocol::encode_contract_input, vm::run, and
// protocol::decode_contract_output. The two-party agreement in
// tests/bo/golden/build/agreement-*/ (proposed, amended, signed, effective,
// closed), whose fuel for each call is a golden (build.txt); the same code
// from every language; roles bound by an action; values and expressions;
// refusals and their texts in three languages; what this version does not
// compile yet, and the limits. A hidden case writes every run for the Python
// reference (CTest bo_codegen_reference: wasm_ref.py --check), the runs of
// the test blocks (bo test) included, and testvectors/bo-v1.json
// (tools/testvectors/bo_vectors.py) pins code hashes and runs. Set CEXCHAIN_UPDATE_GOLDENS=1 to
// rewrite build.txt.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/lower.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/scenario.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/bo/wasm.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace {

namespace bo = cexchain::bo;
namespace cbor = cexchain::cbor;
namespace protocol = cexchain::protocol;
namespace vm = cexchain::vm;
using cexchain::Bytes;
using cexchain::ByteView;
using protocol::ContractSigner;
using protocol::Id;

const std::filesystem::path golden_dir = std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR);
const std::filesystem::path build_dir = golden_dir / "build";
const std::filesystem::path vectors_file =
    std::filesystem::path(CEXCHAIN_TESTVECTORS_DIR) / "bo-v1.json";

bool updating_goldens() {
    const char* value = std::getenv("CEXCHAIN_UPDATE_GOLDENS");
    return value != nullptr && std::string_view(value) == "1";
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

const cexchain::crypto::Provider& provider() {
    static const cexchain::crypto::openssl::Provider instance;
    return instance;
}

const bo::Lexicon& official() {
    static const bo::Lexicon lexicon = [] {
        const bo::PackSetRead set = bo::make_pack_set({});
        return bo::Lexicon(*set.set);
    }();
    return lexicon;
}

const bo::Pack* pack(std::string_view id) {
    for (const bo::Pack& p : bo::official_packs()) {
        if (p.id == id) {
            return &p;
        }
    }
    return nullptr;
}

/// Lexes, parses, and checks a source that has no problems, then lowers it.
bo::Lowered lower_text(std::string_view source) {
    const bo::Lexed lexed = bo::lex(source, official());
    const bo::Parsed parsed = bo::parse(source, lexed);
    INFO(source);
    REQUIRE(!bo::has_errors(lexed.diagnostics));
    REQUIRE(parsed.diagnostics.empty());
    const bo::Checked checked = bo::check(source, parsed.file);
    INFO(bo::dump(checked, nullptr));
    REQUIRE(!bo::has_errors(checked.diagnostics));
    return bo::lower(source, checked.model);
}

/// The code of a source that must compile.
bo::Build build_text(std::string_view source) {
    bo::Lowered lowered = lower_text(source);
    std::string problems;
    for (const bo::Diagnostic& d : lowered.diagnostics) {
        problems += bo::render(d, nullptr) + "\n";
    }
    INFO(problems);
    REQUIRE(lowered.build.has_value());
    REQUIRE(lowered.diagnostics.empty());
    return std::move(*lowered.build);
}

/// The build codes of a source that must not compile.
std::string build_codes(std::string_view source) {
    const bo::Lowered lowered = lower_text(source);
    CHECK(!lowered.build.has_value());
    std::string out;
    for (const bo::Diagnostic& d : lowered.diagnostics) {
        out += (out.empty() ? "" : " ") + std::string(d.code);
        // Every message renders in each language.
        for (const std::string_view language : {"en", "zh-Hant-HK", "zh-Hans-CN"}) {
            const std::string text = bo::render(d, pack(language));
            CHECK(!text.empty());
            CHECK(!text.starts_with("build."));
        }
    }
    return out;
}

/// A ledger id of 32 equal bytes (used before any test runs, so no REQUIRE).
Id ledger(const std::uint8_t fill) {
    return Id::from_bytes(Bytes(32, fill)).value();
}

std::string hex(const ByteView bytes) {
    return cexchain::to_hex(bytes);
}

/// A ledger id in diagnostic notation.
std::string h(const Id& id) {
    return "h'" + hex(id.bytes()) + "'";
}

cbor::Value value(std::string_view diagnostic) {
    auto v = cbor::parse_diagnostic(diagnostic);
    INFO(diagnostic);
    REQUIRE(v.has_value());
    return std::move(*v);
}

constexpr std::int64_t day = 86'400'000;
/// Local midnight (+08:00) of a date, as Bo keeps dates.
std::int64_t date(const std::int64_t y, const std::int64_t m, const std::int64_t d) {
    return bo::days_from_civil(y, m, d) * day - bo::default_offset_ms;
}

const ContractSigner organization{0, std::nullopt, std::nullopt};
const ContractSigner person{1, std::nullopt, std::nullopt};
const ContractSigner present{1, protocol::PresenceMethod::webauthn, std::nullopt};
const ContractSigner agent{2, std::nullopt, std::string("model-x")};

/// One run of a compiled contract.
struct Outcome {
    std::string label;
    /// The call it ran, if the input is one (not raw bytes).
    std::optional<protocol::ContractInput> call;
    Bytes input;
    vm::Outcome run;
    std::optional<protocol::ContractOutput> output;

    [[nodiscard]] const protocol::ContractAccept* accepted() const {
        return output ? std::get_if<protocol::ContractAccept>(&*output) : nullptr;
    }
    [[nodiscard]] const protocol::ContractNeeds* needs() const {
        return output ? std::get_if<protocol::ContractNeeds>(&*output) : nullptr;
    }
    [[nodiscard]] std::string reason() const {
        return std::string(run.abort_reason.begin(), run.abort_reason.end());
    }
    [[nodiscard]] bool refused(std::string_view why) const {
        return run.trap == vm::Trap::aborted && reason() == why;
    }
};

/// A field of an accepted state.
const cbor::Value* field(const protocol::ContractAccept& accept, std::string_view name) {
    const cbor::Value* fields = accept.state.find("fields");
    REQUIRE(fields != nullptr);
    return fields->find(name);
}

std::int64_t int_field(const protocol::ContractAccept& accept, std::string_view name) {
    const cbor::Value* v = field(accept, name);
    REQUIRE(v != nullptr);
    REQUIRE(v->as_int64().has_value());
    return *v->as_int64();
}

/// A contract on its home ledger, with one instance, run as the ledger runs
/// it: each call's input from the instance's state, and its output checked
/// as the ledger checks it.
class Home {
public:
    Home(std::string name, const bo::Build& build, Id home)
        : name_(std::move(name)), code_(build.code), home_(home), contract_(ledger(0xC0)) {
        auto module = vm::load(code_);
        REQUIRE(module.has_value());
        module_.emplace(std::move(*module));
        names_.emplace(hex(home_.bytes()), "home");
    }

    void name(const Id& id, std::string role) { names_.emplace(hex(id.bytes()), std::move(role)); }

    Outcome create(std::string label, std::string_view arguments, std::int64_t time,
                   const ContractSigner& caller = organization) {
        return call(std::move(label), "", arguments, {}, time, caller);
    }

    /// A call: the function ("" for the creation), its arguments in
    /// diagnostic notation, and the consents it cites.
    Outcome call(std::string label, std::string function, std::string_view arguments,
                 std::vector<std::pair<Id, ContractSigner>> consents, std::int64_t time,
                 const ContractSigner& caller = organization) {
        protocol::ContractInput input;
        input.function = function.empty() ? creation_ : function;
        input.arguments = value(arguments);
        input.home = home_;
        input.contract = contract_;
        if (!function.empty()) {
            REQUIRE(instance_.has_value());
            input.instance = *instance_;
        }
        input.caller = ledger(0xAC);
        input.caller_signer = caller;
        input.time = static_cast<protocol::Timestamp>(time);
        input.consents = std::move(consents);
        auto bytes = protocol::encode_contract_input(input);
        REQUIRE(bytes.has_value());
        Outcome out = run(std::move(label), std::move(*bytes), input);
        if (const protocol::ContractAccept* accept = out.accepted()) {
            if (function.empty()) {
                instance_ = protocol::ContractInstanceView{ledger(0x1D), 1, {}, {}, {}};
            }
            instance_->head += 1;
            instance_->state = accept->state;
            instance_->status = accept->status;
            if (accept->parties) {
                instance_->parties = *accept->parties;
            }
            final_ = accept->final;
        }
        return out;
    }

    /// Runs any input, as bytes.
    Outcome run(std::string label, Bytes input,
                std::optional<protocol::ContractInput> call = std::nullopt) {
        Outcome out;
        out.label = std::move(label);
        out.call = std::move(call);
        out.input = std::move(input);
        auto result = vm::run(*module_, out.input, provider(), cexchain::crypto::HashAlg::sha256);
        REQUIRE(result.has_value());
        out.run = std::move(*result);
        // Compiled code never traps but to refuse.
        CHECK((!out.run.trap || *out.run.trap == vm::Trap::aborted));
        if (!out.run.trap) {
            auto decoded = protocol::decode_contract_output(out.run.output, home_);
            INFO(out.label << ": " << hex(out.run.output));
            REQUIRE(decoded.has_value());
            out.output = std::move(*decoded);
        }
        runs_.push_back(out);
        return out;
    }

    void set_creation(std::string name) { creation_ = std::move(name); }
    /// The sources the code was built from, by language.
    void source(std::string language, std::string text) {
        sources_.emplace_back(std::move(language), std::move(text));
    }
    [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& sources() const {
        return sources_;
    }
    [[nodiscard]] bool final() const { return final_; }
    [[nodiscard]] const std::string& name() const { return name_; }
    [[nodiscard]] const Bytes& code() const { return code_; }
    [[nodiscard]] const std::vector<Outcome>& runs() const { return runs_; }
    [[nodiscard]] const protocol::ContractInstanceView& instance() const { return *instance_; }

    /// One line for the golden: what the call did, and its fuel.
    [[nodiscard]] std::string summary(const Outcome& o) const {
        std::string what;
        if (const protocol::ContractAccept* a = o.accepted()) {
            what = "accept " + a->status.value_or("-");
            for (const protocol::ContractEvent& e : a->events) {
                what += ", event " + e.name;
            }
            if (a->final) {
                what += ", final";
            }
        } else if (const protocol::ContractNeeds* n = o.needs()) {
            what = "needs";
            for (const Id& id : n->ledgers) {
                const auto it = names_.find(hex(id.bytes()));
                what += " " + (it != names_.end() ? it->second : hex(id.bytes()));
            }
        } else if (o.run.trap == vm::Trap::aborted) {
            what = "refused \"" + o.reason() + "\"";
        } else {
            what = std::string(vm::name(*o.run.trap));
        }
        return std::format("{}: {}; fuel {}", o.label, what, o.run.fuel_used);
    }

private:
    std::string name_;
    Bytes code_;
    Id home_;
    Id contract_;
    std::optional<vm::Module> module_;
    std::string creation_ = "create";
    std::optional<protocol::ContractInstanceView> instance_;
    bool final_ = false;
    std::map<std::string, std::string> names_;
    std::vector<Outcome> runs_;
    std::vector<std::pair<std::string, std::string>> sources_;
};

// ---------------------------------------------------------------------------
// The scenarios: each runs a compiled contract and checks what it did. The
// visible cases run them; the hidden case writes their runs for the Python
// reference.

const Id we = ledger(0x11);
const Id customer = ledger(0x22);
const Id bank = ledger(0x33);
const Id other_bank = ledger(0x44);
const std::int64_t t0 = date(2026, 10, 14) + 10 * 3'600'000;
const std::int64_t starts = date(2027, 1, 1);

/// The agreement, built from its English source, with all four sources.
Home agreement_home() {
    Home home("agreement", build_text(read_text(build_dir / "agreement-en" / "source.bo")), we);
    for (const auto& [dir, language] : {std::pair{"en", "en"},
                                        {"zh-hant", "zh-Hant-HK"},
                                        {"zh-hans", "zh-Hans-CN"},
                                        {"mixed", "mixed"}}) {
        home.source(language,
                    read_text(build_dir / ("agreement-" + std::string(dir)) / "source.bo"));
    }
    return home;
}

std::string agreement_creation(std::int64_t amount) {
    return std::format(
        R"({{"fields": {{"amount": {}, "starts": {}, "terms": "100 t of steel, monthly"}}, )"
        R"("parties": {{"customer": {}, "we": {}}}}})",
        amount, starts, h(customer), h(we));
}

std::string amendment(std::int64_t amount) {
    return std::format(R"({{"new_amount": {}, "new_start": {}}})", amount, starts + 7 * day);
}

/// The two-party agreement: proposed, amended, signed in person, effective,
/// closed; with the refusals on the way.
Home agreement_scenario() {
    Home home = agreement_home();
    home.name(customer, "customer");
    const auto with = [](const ContractSigner& s) {
        return std::vector<std::pair<Id, ContractSigner>>{{customer, s}};
    };

    const Outcome created = home.create("1 create", agreement_creation(150'000'000), t0);
    REQUIRE(created.accepted() != nullptr);
    const protocol::ContractAccept& a = *created.accepted();
    CHECK(a.status == "proposed");
    CHECK(cbor::diagnostic(a.state) ==
          std::format(R"({{"state": "proposed", "fields": {{"terms": "100 t of steel, monthly", )"
                      R"("amount": 150000000, "starts": {}}}}})",
                      starts));
    REQUIRE(a.parties.has_value());
    CHECK(*a.parties == protocol::Parties{{"customer", customer}, {"we", we}});
    REQUIRE(a.events.size() == 1);
    CHECK(a.events[0] == protocol::ContractEvent{"proposed", cbor::Value::null()});
    CHECK(!a.final);

    CHECK(home.call("2 countersign too early", "countersign", "null", {}, t0)
              .refused("bo:state countersign"));
    // A refusal wins over missing consents: the home learns it at once.
    CHECK(home.call("3 amend by too much", "amend", amendment(300'000'000), {}, t0)
              .refused("an amendment may raise the amount by half at most"));
    const Outcome needs = home.call("4 amend", "amend", amendment(200'000'000), {}, t0);
    REQUIRE(needs.needs() != nullptr);
    CHECK(needs.needs()->ledgers == std::vector<Id>{customer});
    const Outcome amended =
        home.call("5 amend, with consent", "amend", amendment(200'000'000), with(person), t0);
    REQUIRE(amended.accepted() != nullptr);
    CHECK(int_field(*amended.accepted(), "amount") == 200'000'000);
    CHECK(int_field(*amended.accepted(), "starts") == starts + 7 * day);
    CHECK(amended.accepted()->events.empty());
    CHECK(amended.accepted()->status == "proposed");

    const Outcome sign = home.call("6 sign", "sign", "null", {}, t0);
    REQUIRE(sign.needs() != nullptr);
    CHECK(sign.needs()->ledgers == std::vector<Id>{customer});
    // Over HKD 1,000,000: the customer's signer must prove presence.
    CHECK(home.call("7 sign, not in person", "sign", "null", with(person), t0)
              .refused("bo:in-person sign"));
    CHECK(home.call("8 sign, after the start", "sign", "null", with(present), starts + 8 * day)
              .refused("bo:requires sign 2"));
    const Outcome signed_ = home.call("9 sign, in person", "sign", "null", with(present), t0);
    REQUIRE(signed_.accepted() != nullptr);
    CHECK(signed_.accepted()->status == "signed");
    CHECK(signed_.accepted()->events ==
          std::vector<protocol::ContractEvent>{{"signed", cbor::Value::null()}});
    CHECK(home.call("10 amend once signed", "amend", amendment(200'000'000), with(person), t0)
              .refused("bo:requires amend 1"));

    const Outcome effective = home.call("11 countersign", "countersign", "null", {}, t0);
    REQUIRE(effective.accepted() != nullptr);
    CHECK(effective.accepted()->status == "effective");
    CHECK(!effective.accepted()->final);

    const Outcome close = home.call("12 close", "close", "{}", {}, t0);
    REQUIRE(close.needs() != nullptr);
    const Outcome closed =
        home.call("13 close, with consent", "close", "{}", {{customer, organization}}, t0 + day);
    REQUIRE(closed.accepted() != nullptr);
    CHECK(closed.accepted()->status == "closed");
    CHECK(closed.accepted()->final);
    CHECK(home.final());
    return home;
}

/// Refusals of arguments and inputs.
Home agreement_refusals() {
    Home home = agreement_home();
    CHECK(home.create("create, null", "null", t0).refused("bo:arguments"));
    CHECK(home.create("create, extra key", R"({"fields": {}, "parties": {}, "x": 1})", t0)
              .refused("bo:arguments"));
    CHECK(home.create("create, no starts",
                      std::format(R"({{"fields": {{"amount": 1, "terms": "x", "x": 2}}, )"
                                  R"("parties": {{"customer": {}, "we": {}}}}})",
                                  h(customer), h(we)),
                      t0)
              .refused("bo:argument starts"));
    CHECK(home.create("create, amount as text",
                      std::format(R"({{"fields": {{"amount": "1", "starts": 0, "terms": "x"}}, )"
                                  R"("parties": {{"customer": {}, "we": {}}}}})",
                                  h(customer), h(we)),
                      t0)
              .refused("bo:argument amount"));
    CHECK(home.create("create, a short ledger id",
                      std::format(R"({{"fields": {{"amount": 1, "starts": 0, "terms": "x"}}, )"
                                  R"("parties": {{"customer": h'2222', "we": {}}}}})",
                                  h(we)),
                      t0)
              .refused("bo:argument customer"));
    CHECK(home.create("create, amount beyond 64 bits",
                      std::format(R"({{"fields": {{"amount": 18446744073709551615, "starts": 0, )"
                                  R"("terms": "x"}}, "parties": {{"customer": {}, "we": {}}}}})",
                                  h(customer), h(we)),
                      t0)
              .refused("bo:argument amount"));
    REQUIRE(home.create("create", agreement_creation(50'000'000), t0).accepted() != nullptr);
    CHECK(home.call("amend, missing an input", "amend", R"({"new_amount": 1})", {}, t0)
              .refused("bo:arguments"));
    CHECK(home.call("amend, extra input", "amend", R"({"new_amount": 1, "new_start": 0, "x": 0})",
                    {}, t0)
              .refused("bo:arguments"));
    CHECK(home.call("amend, wrong input", "amend", R"({"new_amount": 1, "new_starts": 0})", {}, t0)
              .refused("bo:argument new_start"));
    CHECK(home.call("amend, zero", "amend", amendment(0), {}, t0).refused("bo:requires amend 3"));
    CHECK(home.call("sign with arguments", "sign", R"({"x": 1})", {}, t0).refused("bo:arguments"));
    CHECK(home.call("no such function", "pledge", "null", {}, t0).refused("bo:function"));
    // Up to HKD 1,000,000, no presence is asked.
    const Outcome signed_ = home.call("sign, HKD 500,000", "sign", "null", {{customer, agent}}, t0);
    REQUIRE(signed_.accepted() != nullptr);
    CHECK(home.run("not CBOR", Bytes{0xFF}).refused("bo:input"));
    return home;
}

/// A role bound by the action that names it after `to` (R3, with its
/// consent), and a field that holds a party (R2, R8).
constexpr std::string_view loan_source = R"(contract Loan
parties we, bank

record Note
  amount HKD
  holder we

can lend by we to bank
  holder = bank
can repay by bank
  requires holder = bank
  holder = we
)";

Home loan_scenario() {
    Home home("loan", build_text(loan_source), we);
    home.source("en", std::string(loan_source));
    home.name(bank, "bank");
    home.name(other_bank, "other bank");
    const Outcome created = home.create(
        "create", R"({"fields": {"amount": 1000}, "parties": {"we": )" + h(we) + "}}", t0);
    REQUIRE(created.accepted() != nullptr);
    // The bank is not bound yet; the holder starts as us.
    CHECK(*created.accepted()->parties == protocol::Parties{{"holder", we}, {"we", we}});
    CHECK(home.call("repay before any loan", "repay", "null", {}, t0).refused("bo:party bank"));
    CHECK(home.call("lend without a bank", "lend", "null", {}, t0).refused("bo:argument bank"));
    CHECK(home.call("lend, bank not an id", "lend", R"({"bank": "x"})", {}, t0)
              .refused("bo:argument bank"));
    const Outcome asks = home.call("lend", "lend", "{\"bank\": " + h(bank) + "}", {}, t0);
    REQUIRE(asks.needs() != nullptr);
    CHECK(asks.needs()->ledgers == std::vector<Id>{bank});
    const Outcome lent = home.call("lend, with the bank's consent", "lend",
                                   "{\"bank\": " + h(bank) + "}", {{bank, organization}}, t0);
    REQUIRE(lent.accepted() != nullptr);
    CHECK(*lent.accepted()->parties ==
          protocol::Parties{{"bank", bank}, {"holder", bank}, {"we", we}});
    // Once bound, the argument may repeat the bank, but not name another.
    CHECK(home.call("lend to another bank", "lend", "{\"bank\": " + h(other_bank) + "}", {}, t0)
              .refused("bo:argument bank"));
    // R8: the holder (the bank) loses the note: its consent, once.
    const Outcome repay = home.call("repay", "repay", "null", {}, t0);
    REQUIRE(repay.needs() != nullptr);
    CHECK(repay.needs()->ledgers == std::vector<Id>{bank});
    const Outcome repaid = home.call("repay, with consent", "repay", "{}", {{bank, person}}, t0);
    REQUIRE(repaid.accepted() != nullptr);
    CHECK(*repaid.accepted()->parties ==
          protocol::Parties{{"bank", bank}, {"holder", we}, {"we", we}});
    // Lending again needs the bank's consent and no new argument.
    const Outcome again = home.call("lend again", "lend", "null", {{bank, organization}}, t0);
    REQUIRE(again.accepted() != nullptr);
    return home;
}

/// Values of every kind, computed and compared.
constexpr std::string_view values_source = R"(contract Values
parties we, customer

record Sheet
  label text
  approved yes or no
  total HKD
  ends date
  share 10%
  grace 30 days
  cap HKD 1_000

can fill by we with unit_price HKD, units number, note text, ok yes or no, from_day date
  requires units > 0 and ok = yes
  requires note = label or note = "any"
  total = unit_price * units
  requires total / units = unit_price
  ends = from_day + 3 months
  if ends - from_day > 100 days
    reject "too long"
  approved = total * share > cap
  label = note
can adjust by we with part HKD, whole HKD
  requires part / whole < 50%
  total = part + whole - cap
  ends = ends + grace - 1 month
  if today > ends or not approved
    reject "late"
)";

Home values_scenario() {
    Home home("values", build_text(values_source), we);
    home.source("en", std::string(values_source));
    const Outcome created =
        home.create("create",
                    std::format(R"({{"fields": {{"approved": false, "ends": 0, "label": "start", )"
                                R"("total": 0}}, "parties": {{"customer": {}, "we": {}}}}})",
                                h(customer), h(we)),
                    t0);
    REQUIRE(created.accepted() != nullptr);
    const auto fill = [&](std::string label, std::int64_t price, std::int64_t units,
                          std::string_view note) {
        return home.call(std::move(label), "fill",
                         std::format(R"({{"from_day": {}, "note": "{}", "ok": true, )"
                                     R"("unit_price": {}, "units": {}}})",
                                     date(2027, 1, 31), note, price, units),
                         {}, t0);
    };
    CHECK(fill("fill, no units", 1250, 0, "any").refused("bo:requires fill 1"));
    CHECK(fill("fill, wrong note", 1250, 3, "other").refused("bo:requires fill 2"));
    CHECK(fill("fill, overflow", std::int64_t{1} << 62, 3, "any").refused("bo:overflow"));
    const Outcome small = fill("fill, HKD 12.50 x 3", 1250, 3, "any");
    REQUIRE(small.accepted() != nullptr);
    CHECK(int_field(*small.accepted(), "total") == 3750);
    // 31 January plus three months is 30 April (U6: month ends clamp).
    CHECK(int_field(*small.accepted(), "ends") == date(2027, 4, 30));
    CHECK(cbor::diagnostic(*field(*small.accepted(), "approved")) == "false");
    CHECK(cbor::diagnostic(*field(*small.accepted(), "label")) == "\"any\"");
    const Outcome large = fill("fill, HKD 5,000 x 3", 500'000, 3, "any");
    REQUIRE(large.accepted() != nullptr);
    // HKD 15,000 at 10% is HKD 1,500, over the cap.
    CHECK(cbor::diagnostic(*field(*large.accepted(), "approved")) == "true");

    const auto adjust = [&](std::string label, std::int64_t part, std::int64_t whole) {
        return home.call(std::move(label), "adjust",
                         std::format(R"({{"part": {}, "whole": {}}})", part, whole), {}, t0);
    };
    CHECK(adjust("adjust, two thirds", 2000, 3000).refused("bo:requires adjust 1"));
    CHECK(adjust("adjust, by zero", 2000, 0).refused("bo:division-by-zero"));
    const Outcome adjusted = adjust("adjust, a third", 1000, 3000);
    REQUIRE(adjusted.accepted() != nullptr);
    CHECK(int_field(*adjusted.accepted(), "total") == 1000 + 3000 - 100'000);
    // 30 April plus 30 days is 30 May; less a month, 30 April.
    CHECK(int_field(*adjusted.accepted(), "ends") == date(2027, 4, 30));
    // A year later, the sheet is past its end.
    CHECK(
        home.call("adjust, too late", "adjust", R"({"part": 1, "whole": 3})", {}, date(2028, 1, 1))
            .refused("late"));
    return home;
}

/// Every scenario, in a fixed order.
std::vector<Home> scenarios() {
    std::vector<Home> out;
    out.push_back(agreement_scenario());
    out.push_back(agreement_refusals());
    out.push_back(loan_scenario());
    out.push_back(values_scenario());
    return out;
}

} // namespace

TEST_CASE("bo build: the agreement runs as the ledger runs it, with its fuel as a golden",
          "[bo][build]") {
    const Home home = agreement_scenario();
    const bo::Build build = build_text(read_text(build_dir / "agreement-en" / "source.bo"));
    std::string text = "contract Agreement\n";
    const auto digest = provider().digest(cexchain::crypto::HashAlg::sha256, build.code);
    REQUIRE(digest.has_value());
    text += std::format("code: {} bytes, sha256 {}, codegen {}\n", build.code.size(),
                        hex(digest->bytes()), bo::wasm::codegen_version);
    text += "interface:";
    for (const auto& [name, kind] : build.interface) {
        text += std::format(" {} {}", name, static_cast<int>(kind));
    }
    text += "\n";
    for (const Outcome& o : home.runs()) {
        text += home.summary(o) + "\n";
    }
    const auto path = build_dir / "agreement-en" / "build.txt";
    if (updating_goldens()) {
        std::ofstream(path, std::ios::binary) << text;
    }
    CHECK(read_text(path) == text);
}

TEST_CASE("bo build: one contract in any language compiles to the same bytes", "[bo][build]") {
    const bo::Build en = build_text(read_text(build_dir / "agreement-en" / "source.bo"));
    for (const std::string_view language : {"zh-hant", "zh-hans", "mixed"}) {
        INFO(language);
        const bo::Build other =
            build_text(read_text(build_dir / ("agreement-" + std::string(language)) / "source.bo"));
        CHECK(other.code == en.code);
        CHECK(other.interface == en.interface);
    }
    // Lowering is deterministic, and its modules load.
    CHECK(build_text(read_text(build_dir / "agreement-en" / "source.bo")).code == en.code);
    CHECK(vm::load(en.code).has_value());
    CHECK(en.interface == std::map<std::string, protocol::FunctionKind>{
                              {"amend", protocol::FunctionKind::call},
                              {"close", protocol::FunctionKind::call},
                              {"countersign", protocol::FunctionKind::call},
                              {"create", protocol::FunctionKind::create},
                              {"sign", protocol::FunctionKind::call}});
    // The spec's receivable builds (with the standard library), to the same
    // code in every language.
    const auto example_source = [&](std::string_view example, std::string_view language) {
        return read_text(golden_dir / std::format("example-{}-{}", example, language) /
                         "source.bo");
    };
    const bo::Build receivable = build_text(example_source("receivable", "en"));
    for (const std::string_view language : {"zh-hant", "zh-hans", "mixed"}) {
        INFO(language);
        CHECK(build_text(example_source("receivable", language)).code == receivable.code);
    }
    CHECK(receivable.interface == std::map<std::string, protocol::FunctionKind>{
                                      {"issue", protocol::FunctionKind::create},
                                      {"pledge", protocol::FunctionKind::call},
                                      {"transfer", protocol::FunctionKind::call}});
    // The others (which need later milestones) are refused the same way in
    // every language. The IP pool builds since milestone 12.
    for (const std::string_view example : {"split", "vps", "tax"}) {
        std::string first;
        for (const std::string_view language : {"en", "zh-hant", "zh-hans", "mixed"}) {
            const std::string source = read_text(
                golden_dir / std::format("example-{}-{}", example, language) / "source.bo");
            const bo::Lexed lexed = bo::lex(source, official());
            const bo::Parsed parsed = bo::parse(source, lexed);
            const bo::Checked checked = bo::check(source, parsed.file);
            const bo::Lowered lowered = bo::lower(source, checked.model);
            std::string codes;
            for (const bo::Diagnostic& d : lowered.diagnostics) {
                codes += std::string(d.code) + " ";
                for (const auto& [name, value] : d.args) {
                    if (name != "text") {
                        codes += value + " ";
                    }
                }
            }
            INFO(example << " " << language << ": " << codes);
            CHECK(!lowered.build.has_value());
            if (first.empty()) {
                first = codes;
            }
            CHECK(codes == first);
        }
    }
}

TEST_CASE("bo build: refusals of arguments, and their texts in three languages", "[bo][build]") {
    const Home home = agreement_refusals();
    std::vector<std::string> reasons;
    for (const Home& h : scenarios()) {
        for (const Outcome& o : h.runs()) {
            if (o.run.trap == vm::Trap::aborted && o.reason().starts_with("bo:")) {
                reasons.push_back(o.reason());
            }
        }
    }
    reasons.insert(reasons.end(), {"bo:date", "bo:output", "bo:consents"});
    for (const std::string& reason : reasons) {
        for (const std::string_view language : {"en", "zh-Hant-HK", "zh-Hans-CN"}) {
            INFO(reason << " in " << language);
            const auto text = bo::render_reason(reason, pack(language));
            REQUIRE(text.has_value());
            CHECK(!text->empty());
            CHECK(!text->starts_with("run."));
            CHECK(text->find('{') == std::string::npos);
        }
    }
    CHECK(bo::render_reason("bo:requires sign 2", pack("en")) ==
          "requirement 2 of sign is not met");
    CHECK(bo::render_reason("bo:state pledge", pack("zh-Hant-HK")) == "實例目前的狀態不容許 質押");
    CHECK(bo::render_reason("bo:party bank", pack("zh-Hans-CN")) == "银行 尚未确定账本");
    CHECK(!bo::render_reason("too late", pack("en")).has_value());
    CHECK(!bo::render_reason("bo:unknown", pack("en")).has_value());
    CHECK(!bo::render_reason("bo:requires sign", pack("en")).has_value());
}

TEST_CASE("bo build: roles bound by an action, and fields holding a party", "[bo][build]") {
    const Home home = loan_scenario();
    CHECK(home.instance().parties ==
          protocol::Parties{{"bank", bank}, {"holder", bank}, {"we", we}});
}

TEST_CASE("bo build: values, units, dates, texts, and yes or no", "[bo][build]") {
    const Home home = values_scenario();
    CHECK(!home.final());
}

TEST_CASE("bo build: what this version does not compile yet", "[bo][build]") {
    const std::string head = "contract C\nparties we, customer\n\n";
    // A vocabulary action builds with its standard terms (M11); one whose
    // terms come later does not.
    CHECK(
        vm::load(build_text(head + "asset Note\n  amount HKD\n  holder we\n\ncan transfer\n").code)
            .has_value());
    CHECK(build_codes(head + "asset Note\n  amount HKD\n  holder we\n\ncan refund by we\n") ==
          "build.standard-action");
    // Time rules build (M12), but a service's period ends, which its executors
    // track (6b); charges and lists (M13); agents' proposals.
    CHECK(vm::load(build_text(head + "record R\n  ends date\n\ncan go by we\n  -> active\n"
                                     "when ends\n  -> active\n")
                       .code)
              .has_value());
    CHECK(build_codes(head + "service S\n  price monthly HKD 120\n\ncan go by we\n  -> active\n"
                             "when overdue\n  -> active\n") == "build.time-rule");
    CHECK(build_codes(head + "record R\n  tags list text\n\ncan go by we\n  -> active\n") ==
          "build.unsupported");
    CHECK(build_codes(head + "record R\n  amount HKD\n\ncan go by we with rows list HKD\n"
                             "  each row in rows\n    requires row > HKD 0\n") ==
          "build.unsupported build.unsupported");
    CHECK(vm::load(build_text(head + "can go by we\n  AI agent can propose\n  -> active\n").code)
              .has_value());
    CHECK(build_codes(head + "can go by we\n  -> active\ncan stop by we\n  go\n") ==
          "build.unsupported");
    CHECK(build_codes(head + "service S\n  price monthly HKD 120\n\ncan go by we\n"
                             "  notify customer\n") == "build.executor");
    // A fragment, and limits.
    CHECK(build_codes("parties we\ncan go by we\n  -> active\n") == "build.fragment");
    CHECK(build_codes(head + "can go by we\n  reject \"bo:input\"\n") == "build.reject-text");
    // `create` is the vocabulary's word for the creation (a test step's), so
    // an action named so is a built-in one, and its name is the creation's.
    CHECK(build_codes(head + "can create by we\n  -> active\n") ==
          "build.standard-action build.name-taken");
    std::string long_name(70, 'a');
    CHECK(build_codes(head + "can " + long_name + " by we\n  -> active\n") ==
          "build.name-too-long");
    std::string events = head + "can go by we\n  active -> s0\n";
    for (int i = 0; i < 64; ++i) {
        events += std::format("  s{} -> s{}\n", i, i + 1);
    }
    CHECK(build_codes(events) == "build.too-many-events");
    std::string texts = head + "can go by we\n";
    for (int i = 0; i < 40; ++i) {
        texts += std::format("  if now > 2027-01-0{}\n    reject \"{} {}\"\n", 1 + i % 9, i,
                             std::string(990, 'x'));
    }
    CHECK(build_codes(texts) == "build.too-large");
    // A field cannot start with a party that an action binds later.
    CHECK(build_codes("contract C\nparties we, bank\n\ncan lend by we to bank\n  -> active\n"
                      "record R\n  holder bank\n") == "build.late-party");
    // The counts the profile and spec section 15 allow.
    std::string parties = "contract C\nparties we";
    for (int i = 0; i < 64; ++i) {
        parties += std::format(", p{}", i);
    }
    CHECK(build_codes(parties + "\n\ncan go by we\n  -> active\n") == "build.too-many-parties");
    std::string fields = head + "record R\n";
    for (int i = 0; i < 257; ++i) {
        fields += std::format("  f{} number\n", i);
    }
    CHECK(build_codes(fields + "\ncan go by we\n  -> active\n") == "build.too-many-fields");
    std::string inputs = head + "can go by we with i0 number";
    for (int i = 1; i < 257; ++i) {
        inputs += std::format(", i{} number", i);
    }
    CHECK(build_codes(inputs + "\n  -> active\n") == "build.too-many-inputs");
    std::string actions = head;
    for (int i = 0; i < 256; ++i) {
        actions += std::format("can a{} by we\n  -> active\n", i);
    }
    CHECK(build_codes(actions) == "build.too-many-functions");
}

namespace {

std::string encoded(const cbor::Value& v) {
    auto bytes = cbor::encode(v);
    REQUIRE(bytes.has_value());
    return hex(*bytes);
}

nlohmann::ordered_json signer_json(const ContractSigner& s) {
    nlohmann::ordered_json out{{"kind", s.kind}};
    out["presence"] = s.presence ? nlohmann::ordered_json(static_cast<int>(*s.presence))
                                 : nlohmann::ordered_json();
    out["model"] = s.model ? nlohmann::ordered_json(*s.model) : nlohmann::ordered_json();
    return out;
}

/// A call as the ledger made it, for bo_vectors.py to encode again.
nlohmann::ordered_json call_json(const protocol::ContractInput& c) {
    nlohmann::ordered_json out;
    out["function"] = c.function;
    out["arguments"] = encoded(c.arguments);
    out["home"] = hex(c.home.bytes());
    out["contract"] = hex(c.contract.bytes());
    if (c.instance) {
        nlohmann::ordered_json parties = nlohmann::ordered_json::object();
        for (const auto& [role, id] : c.instance->parties) {
            parties[role] = hex(id.bytes());
        }
        out["instance"] = {{"id", hex(c.instance->id.bytes())},
                           {"head", c.instance->head},
                           {"state", encoded(c.instance->state)},
                           {"status", c.instance->status
                                          ? nlohmann::ordered_json(*c.instance->status)
                                          : nlohmann::ordered_json()},
                           {"parties", parties}};
    } else {
        out["instance"] = nullptr;
    }
    out["caller"] = hex(c.caller.bytes());
    out["signer"] = signer_json(c.caller_signer);
    out["time"] = c.time;
    out["consents"] = nlohmann::ordered_json::array();
    for (const auto& [id, signer] : c.consents) {
        out["consents"].push_back({hex(id.bytes()), signer_json(signer)});
    }
    return out;
}

} // namespace

TEST_CASE("bo build: write the runs for the Python reference", "[.codegen-reference]") {
    const char* path = std::getenv("CEXCHAIN_BO_CODEGEN_REFERENCE");
    REQUIRE(path != nullptr);
    const std::vector<Home> homes = scenarios();
    nlohmann::ordered_json doc;
    doc["format"] = 1;
    doc["codegen"] = bo::wasm::codegen_version;
    nlohmann::ordered_json modules = nlohmann::ordered_json::object();
    nlohmann::ordered_json sources = nlohmann::ordered_json::object();
    nlohmann::ordered_json runs = nlohmann::ordered_json::array();
    for (const Home& home : homes) {
        modules[home.name()] = hex(home.code());
        nlohmann::ordered_json texts = nlohmann::ordered_json::array();
        for (const auto& [language, text] : home.sources()) {
            texts.push_back({{"language", language}, {"text", text}});
        }
        sources[home.name()] = std::move(texts);
        for (const Outcome& o : home.runs()) {
            nlohmann::ordered_json run{{"module", home.name()}, {"label", o.label}};
            run["call"] = o.call ? call_json(*o.call) : nlohmann::ordered_json();
            run["input"] = hex(o.input);
            run["outcome"] = o.run.trap ? std::string(vm::name(*o.run.trap)) : "ok";
            run["output"] = hex(o.run.output);
            run["fuel"] = o.run.fuel_used;
            run["reason"] = hex(o.run.abort_reason);
            runs.push_back(std::move(run));
        }
    }
    // The test blocks' runs (bo test, milestone 10): every call each step
    // made, under the contract it ran on.
    for (const auto& [name, file] : std::vector<std::pair<std::string, std::filesystem::path>>{
             {"agreement", build_dir / "agreement-en" / "source.bo"},
             {"check-agreement", golden_dir / "check-agreement" / "source.bo"},
             {"deal", golden_dir / "test" / "failing" / "source.bo"},
             {"loan-tests", golden_dir / "check-tests" / "source.bo"},
             {"receivable-financing", golden_dir / "test" / "receivable-financing" / "source.bo"},
             {"receivable", golden_dir / "test" / "receivable" / "source.bo"},
             {"warehouse-receipt", golden_dir / "test" / "warehouse-receipt" / "source.bo"},
             {"standard", golden_dir / "check-standard" / "source.bo"},
             // Time rules and the keeper (milestone 12).
             {"time", golden_dir / "test" / "time" / "source.bo"},
             {"membership", golden_dir / "check-time" / "source.bo"},
             {"ip-pool", golden_dir / "test" / "ip-pool" / "source.bo"},
             {"supply-agreement", golden_dir.parent_path().parent_path().parent_path() / "deploy" /
                                      "demo" / "supply-agreement.bo"}}) {
        const std::string text = read_text(file);
        const bo::Compiled compiled = bo::compile(text, *bo::make_pack_set({}).set);
        REQUIRE(compiled.build.has_value());
        REQUIRE(compiled.model.has_value());
        const std::string code = hex(compiled.build->code);
        if (modules.contains(name)) {
            REQUIRE(modules[name] == code);
        } else {
            modules[name] = code;
            sources[name] = nlohmann::ordered_json::array({{{"language", "en"}, {"text", text}}});
        }
        const bo::TestResults results = bo::run_tests(*compiled.model, *compiled.build, provider());
        for (std::size_t t = 0; t < results.tests.size(); ++t) {
            const bo::model::Test& test = compiled.model->tests[t];
            for (std::size_t i = 0; i < results.tests[t].steps.size(); ++i) {
                const std::vector<bo::TestCall>& calls = results.tests[t].steps[i].calls;
                for (std::size_t k = 0; k < calls.size(); ++k) {
                    const bo::TestCall& c = calls[k];
                    nlohmann::ordered_json run{
                        {"module", name},
                        {"label", std::format("test \"{}\" step {}, call {}",
                                              test.name.empty() ? std::to_string(t + 1) : test.name,
                                              i + 1, k + 1)}};
                    run["call"] = call_json(c.input);
                    run["input"] = hex(c.encoded);
                    run["outcome"] = c.run.trap ? std::string(vm::name(*c.run.trap)) : "ok";
                    run["output"] = hex(c.run.output);
                    run["fuel"] = c.run.fuel_used;
                    run["reason"] = hex(c.run.abort_reason);
                    runs.push_back(std::move(run));
                }
            }
        }
    }
    doc["modules"] = std::move(modules);
    doc["sources"] = std::move(sources);
    doc["runs"] = std::move(runs);
    std::ofstream out(path);
    out << doc.dump(1) << "\n";
    REQUIRE(out.good());
}

TEST_CASE("bo build: the conformance vectors (testvectors/bo-v1.json)", "[bo][build]") {
    if (!std::filesystem::exists(vectors_file)) {
        SKIP("no " << vectors_file);
    }
    const auto doc = nlohmann::json::parse(read_text(vectors_file));
    REQUIRE(doc.at("format") == 1);
    std::size_t runs = 0;
    for (const auto& contract : doc.at("contracts")) {
        const std::string name = contract.at("name");
        INFO(name);
        for (const auto& source : contract.at("sources")) {
            const bo::Build build = build_text(source.at("text").get<std::string>());
            const auto digest = provider().digest(cexchain::crypto::HashAlg::sha256, build.code);
            REQUIRE(digest.has_value());
            CHECK(hex(digest->bytes()) == contract.at("code_sha256").get<std::string>());
            CHECK(hex(build.code) == contract.at("code").get<std::string>());
        }
        const Bytes code = *cexchain::from_hex(contract.at("code").get<std::string>());
        const auto module = vm::load(code);
        REQUIRE(module.has_value());
        for (const auto& run : contract.at("runs")) {
            const Bytes input = *cexchain::from_hex(run.at("input").get<std::string>());
            const auto outcome =
                vm::run(*module, input, provider(), cexchain::crypto::HashAlg::sha256);
            REQUIRE(outcome.has_value());
            INFO(run.at("label").get<std::string>());
            CHECK((outcome->trap ? std::string(vm::name(*outcome->trap)) : "ok") ==
                  run.at("outcome").get<std::string>());
            CHECK(hex(outcome->output) == run.at("output").get<std::string>());
            CHECK(outcome->fuel_used == run.at("fuel").get<std::uint64_t>());
            CHECK(hex(outcome->abort_reason) == run.at("reason").get<std::string>());
            ++runs;
        }
    }
    CHECK(runs > 0);
}
