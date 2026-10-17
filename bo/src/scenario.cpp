// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Running a contract's tests (milestone 10 of the Bo compiler): each test
// creates its own instance and runs its steps through the compiled code as a
// ledger runs a call (scenario.hpp says how ledgers, signers, consents, and
// time are chosen), then checks what happened against what the step expects.
// Everything here is deterministic: ledger ids are hashes of the parties'
// keys, times come from the steps, and maps are written in canonical order.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/scenario.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/core/cbor.hpp>

namespace cexchain::bo {

namespace {

namespace m = model;
using protocol::ContractSigner;
using protocol::Id;

constexpr std::string_view ledger_prefix = "cexchain-bo-test ledger ";
constexpr std::string_view contract_seed = "cexchain-bo-test contract";
constexpr std::string_view actor_seed = "cexchain-bo-test actor";
constexpr std::string_view instance_seed = "cexchain-bo-test instance";
/// More rounds than a call can need: it asks for at most 16 consents.
constexpr std::size_t max_rounds = 18;

const ContractSigner organization{0, std::nullopt, std::nullopt};

Id hash_of(std::string_view text, const crypto::Provider& provider) {
    auto digest = provider.digest(crypto::HashAlg::sha256, as_bytes(text));
    // SHA-256 of a short text: the provider fails only if its backend does.
    BO_ASSERT(digest.has_value());
    return digest.has_value() ? *digest : Id{};
}

std::string hex(const Id& id) {
    return to_hex(id.bytes());
}

bool id_less(const Id& a, const Id& b) noexcept {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

/// A map in canonical order: its keys sorted by their encodings.
cbor::Value canonical(cbor::Map entries) {
    std::vector<std::pair<Bytes, cbor::MapEntry>> keyed;
    keyed.reserve(entries.size());
    for (cbor::MapEntry& e : entries) {
        Bytes key = cbor::encode(e.key).value_or(Bytes{});
        keyed.emplace_back(std::move(key), std::move(e));
    }
    std::ranges::sort(keyed, [](const auto& a, const auto& b) { return a.first < b.first; });
    cbor::Map out;
    out.reserve(keyed.size());
    for (auto& [key, entry] : keyed) {
        out.push_back(std::move(entry));
    }
    return cbor::Value::map(std::move(out));
}

/// A value a test gives, as compiled code reads it.
cbor::Value encode_value(const m::Expr& e, const std::int64_t offset_ms) {
    switch (e.kind) {
    case ast::ExprKind::literal:
        if (e.literal.kind == ast::LiteralKind::text) {
            return cbor::Value::text(e.literal.text);
        }
        return cbor::Value::integer(literal_value(e.literal, offset_ms).value_or(0));
    case ast::ExprKind::word:
        return cbor::Value::boolean(e.concept_entry != nullptr && e.concept_entry->id == "val.yes");
    case ast::ExprKind::list: {
        cbor::Array items;
        for (const m::Expr& o : e.operands) {
            items.push_back(encode_value(o, offset_ms));
        }
        return cbor::Value::array(std::move(items));
    }
    default:
        return cbor::Value::null();
    }
}

ContractSigner signer_of(const m::Step& step) {
    if (step.keeper) {
        // The home's keeper: a device.
        return ContractSigner{3, std::nullopt, std::nullopt};
    }
    if (step.in_person) {
        return ContractSigner{1, protocol::PresenceMethod::webauthn, std::nullopt};
    }
    if (step.agent) {
        return ContractSigner{2, std::nullopt, std::string("bo-test-agent")};
    }
    return organization;
}

const m::Action* find_action(const m::Model& model, const m::Step& step) {
    const std::string key = m::key(step.word, step.name);
    for (const m::Action& a : model.actions) {
        if (m::key(a.word, a.name) == key) {
            return &a;
        }
    }
    return nullptr;
}

/// The action with this wire name (as compiled code names it).
const m::Action* action_named(const m::Model& model, std::string_view wire) {
    for (const m::Action& a : model.actions) {
        if (wire_name(a.word, a.name) == wire) {
            return &a;
        }
    }
    return nullptr;
}

/// The first proposal the instance keeps: [function, arguments].
const cbor::Array* first_proposal(const std::optional<protocol::ContractInstanceView>& instance) {
    if (!instance) {
        return nullptr;
    }
    const cbor::Value* pending = instance->state.find("pending");
    const cbor::Array* list = pending != nullptr ? pending->as_array() : nullptr;
    if (list == nullptr || list->empty()) {
        return nullptr;
    }
    const cbor::Array* entry = list->front().as_array();
    return entry != nullptr && entry->size() == 2 && entry->front().as_text() != nullptr ? entry
                                                                                         : nullptr;
}

/// One test's ledger: the instance the step acts on, as the home keeps it.
struct Ledger {
    Id home;
    std::optional<protocol::ContractInstanceView> instance;
    bool final = false;
    /// The parts the step's call created (R30), in order.
    std::vector<protocol::ContractChild> children;
};

/// An instance of a test: the one its first step creates, or a part.
struct Instance {
    protocol::ContractInstanceView view;
    bool final = false;
    /// "" for the instance the test created; "1.2" for the second part of
    /// its first part.
    std::string path;
};

class Runner {
public:
    Runner(const m::Model& model, const Build& build, const vm::Module& module,
           const crypto::Provider& provider)
        : model_(model), build_(build), module_(module), provider_(provider),
          rules_(m::rule_functions(model)), contract_(hash_of(contract_seed, provider)),
          actor_(hash_of(actor_seed, provider)), instance_id_(hash_of(instance_seed, provider)) {}

    TestResult run(const m::Test& test);
    /// The instance a step acts on (scenario.hpp), if there is one.
    std::optional<std::size_t> target(const m::Step& step, const std::vector<Instance>& all,
                                      StepResult& r);
    [[nodiscard]] std::vector<TestLedger> ledgers() const {
        std::vector<TestLedger> out;
        for (const auto& [id, ledger] : ledgers_) {
            out.push_back(ledger);
        }
        return out;
    }

private:
    Id derive(const Concept* word, const std::string& name);
    Id ledger_of(const m::TestParty& p, const Ledger& l);
    [[nodiscard]] std::optional<Id> starter_of(const m::Action& a, const Ledger& l) const;
    cbor::Value arguments(const m::Step& step, const m::Action* action, const Ledger& l);
    cbor::Value given_value(const m::Expr& e, const Ledger& l);
    void run_step(const m::Step& step, Ledger& l, StepResult& r);
    void accept(const m::Step& step, const protocol::ContractAccept& a, Ledger& l, StepResult& r);

    const m::Model& model_;
    const Build& build_;
    const vm::Module& module_;
    const crypto::Provider& provider_;
    /// The time rules' functions (R24).
    std::vector<std::string> rules_;
    Id contract_;
    Id actor_;
    Id instance_id_;
    /// Every ledger named, by its id in hex (so in ascending order).
    std::map<std::string, TestLedger> ledgers_;
};

Id Runner::derive(const Concept* word, const std::string& name) {
    const std::string key = m::key(word, name);
    const Id id = hash_of(std::string(ledger_prefix) + key, provider_);
    ledgers_.try_emplace(hex(id), TestLedger{id, word, word != nullptr ? std::string() : name});
    return id;
}

Id Runner::ledger_of(const m::TestParty& p, const Ledger& l) {
    if (p.role && l.instance) {
        const auto it = l.instance->parties.find(wire_name(p.word, p.name));
        if (it != l.instance->parties.end()) {
            return it->second;
        }
    }
    return derive(p.word, p.name);
}

std::optional<Id> Runner::starter_of(const m::Action& a, const Ledger& l) const {
    if (!l.instance) {
        return std::nullopt;
    }
    if (!a.by) {
        // A built-in action without a starter is the home's own word.
        return a.word != nullptr ? std::optional<Id>(l.home) : std::nullopt;
    }
    // A role, or a field holding a party: the instance's parties name both.
    const auto it = l.instance->parties.find(wire_name(a.by->concept_entry, a.by->name));
    if (it == l.instance->parties.end()) {
        return std::nullopt;
    }
    return it->second;
}

cbor::Value Runner::arguments(const m::Step& step, const m::Action* action, const Ledger& l) {
    cbor::Map given;
    for (const m::Set& w : step.with) {
        given.push_back({cbor::Value::text(wire_name(w.target.concept_entry, w.target.name)),
                         given_value(w.value, l)});
    }
    if (step.creation) {
        // {"fields": {...}, "parties": {role: ledger}}: every role bound at
        // creation, to its own ledger.
        cbor::Map parties;
        for (const m::Party& p : model_.parties) {
            if (p.binding == m::Binding::creation) {
                parties.push_back({cbor::Value::text(wire_name(p.role, p.name)),
                                   cbor::Value::bytes(derive(p.role, p.name).bytes())});
            }
        }
        // "fields" whenever some field is given at creation, even if every
        // one the step leaves out has a default.
        const bool fields = std::ranges::any_of(model_.fields, [](const m::Field& f) {
            return f.kind == m::FieldKind::instance &&
                   !(f.type.kind == m::TypeKind::party && f.value) && !f.empty_at_start;
        });
        cbor::Map out;
        if (!given.empty() || fields) {
            out.push_back({cbor::Value::text("fields"), canonical(std::move(given))});
        }
        if (!parties.empty()) {
            out.push_back({cbor::Value::text("parties"), canonical(std::move(parties))});
        }
        return out.empty() ? cbor::Value::null() : canonical(std::move(out));
    }
    if (step.approve) {
        // {"function": NAME, "arguments": ARGS}: the first proposal kept.
        const cbor::Array* proposal = first_proposal(l.instance);
        return canonical(
            cbor::Map{{cbor::Value::text("function"),
                       proposal != nullptr ? proposal->front() : cbor::Value::text("")},
                      {cbor::Value::text("arguments"),
                       proposal != nullptr ? proposal->back() : cbor::Value::null()}});
    }
    // R21: a counterparty each call names, as the argument counterparty.
    if (action != nullptr && action->to && action->to->refers == m::Refers::input && step.to) {
        given.push_back({cbor::Value::text(wire_name(action->to->concept_entry, action->to->name)),
                         cbor::Value::bytes(ledger_of(*step.to, l).bytes())});
    }
    // The role the action binds (R3), under its name: the step's `to`.
    if (action != nullptr && action->to && step.to) {
        const std::string role = m::key(action->to->concept_entry, action->to->name);
        const std::string action_key = m::key(action->word, action->name);
        for (const m::Party& p : model_.parties) {
            if (m::key(p.role, p.name) == role && p.binding == m::Binding::action &&
                p.bound_by == action_key) {
                given.push_back({cbor::Value::text(wire_name(p.role, p.name)),
                                 cbor::Value::bytes(ledger_of(*step.to, l).bytes())});
            }
        }
    }
    return given.empty() ? cbor::Value::null() : canonical(std::move(given));
}

cbor::Value Runner::given_value(const m::Expr& e, const Ledger& l) {
    // A party is its ledger (a role's, bound or its own; a ledger only tests
    // name); a list of parties, theirs.
    const auto party = [&](const m::Expr& p) {
        const m::TestParty who{p.span, p.concept_entry, p.name, p.refers == m::Refers::party};
        return cbor::Value::bytes(ledger_of(who, l).bytes());
    };
    if (e.type.kind == m::TypeKind::party) {
        return party(e);
    }
    if (e.type.kind == m::TypeKind::list && e.type.element.size() == 1 &&
        e.type.element[0].kind == m::TypeKind::party) {
        cbor::Array items;
        for (const m::Expr& o : e.operands) {
            items.push_back(party(o));
        }
        return cbor::Value::array(std::move(items));
    }
    return encode_value(e, model_.utc_offset_ms);
}

namespace {

/// A bill's event data in short (StepResult::bill), or empty for data that
/// is no bill.
std::string bill_text(const cbor::Value& bill) {
    const cbor::Value* price = bill.find("price");
    const cbor::Value* total = bill.find("total");
    const cbor::Value* charges = bill.find("charges");
    if (price == nullptr || total == nullptr || charges == nullptr || !price->as_int64() ||
        !total->as_int64() || charges->as_map() == nullptr) {
        return {};
    }
    std::string out = std::format("price={} total={}", *price->as_int64(), *total->as_int64());
    const auto text_of = [](const cbor::Value& key) {
        return key.as_text() != nullptr ? *key.as_text() : std::string("?");
    };
    for (const cbor::MapEntry& entry : *charges->as_map()) {
        const cbor::Value* amount = entry.value.find("amount");
        const cbor::Value* rate = entry.value.find("rate");
        out += " " + text_of(entry.key) + "=" +
               (amount != nullptr && amount->as_int64() ? std::to_string(*amount->as_int64())
                                                        : std::string("?"));
        if (rate != nullptr && rate->as_int64()) {
            out += "@" + std::to_string(*rate->as_int64());
        }
    }
    if (const cbor::Value* lines = bill.find("lines"); lines != nullptr && lines->as_array()) {
        out += " lines";
        for (const cbor::Value& line : *lines->as_array()) {
            std::string items;
            if (line.as_map() != nullptr) {
                for (const cbor::MapEntry& entry : *line.as_map()) {
                    items += (items.empty() ? "" : " ") + text_of(entry.key) + "=" +
                             (entry.value.as_int64() ? std::to_string(*entry.value.as_int64())
                                                     : std::string("?"));
                }
            }
            out += " [" + items + "]";
        }
    }
    return out;
}

} // namespace

void Runner::accept(const m::Step& step, const protocol::ContractAccept& a, Ledger& l,
                    StepResult& r) {
    r.happened = Happened::accepted;
    if (const cbor::Value* state = a.state.find("state");
        state != nullptr && state->as_text() != nullptr) {
        r.state = *state->as_text();
    }
    for (const protocol::ContractEvent& e : a.events) {
        const std::string* action = e.data.as_text();
        // A time rule's event: its function, and how late the call came.
        const cbor::Value* rule = e.data.find("rule");
        const cbor::Value* late = e.data.find("late");
        if (rule != nullptr && rule->as_text() != nullptr && late != nullptr && late->as_int64()) {
            r.events.push_back(e.name + ":" + *rule->as_text() +
                               " late=" + std::to_string(*late->as_int64()));
            continue;
        }
        r.events.push_back(action != nullptr ? e.name + ":" + *action : e.name);
        if (e.name == "propose" && action != nullptr) {
            r.proposed = *action;
        }
        if (std::string made = bill_text(e.data); !made.empty()) {
            r.bill = std::move(made);
        }
    }
    r.final = a.final;
    r.parts = a.children.size();
    l.children = a.children;
    if (step.creation) {
        l.instance = protocol::ContractInstanceView{instance_id_, 0, {}, {}, {}, {}, 0};
    }
    l.instance->head += 1;
    l.instance->state = a.state;
    l.instance->status = a.status;
    if (a.parties) {
        l.instance->parties = *a.parties;
    }
    l.final = a.final;
}

void Runner::run_step(const m::Step& step, Ledger& l, StepResult& r) {
    if (!step.creation && !l.instance) {
        r.happened = Happened::no_instance;
        return;
    }
    if (!step.creation && l.final) {
        r.happened = Happened::final_instance;
        return;
    }
    const m::Action* action = step.creation || step.keeper ? nullptr : find_action(model_, step);
    // An approval is started by the proposed action's starter.
    const m::Action* starts = action;
    if (step.approve) {
        const cbor::Array* proposal = first_proposal(l.instance);
        starts = proposal != nullptr ? action_named(model_, *proposal->front().as_text()) : nullptr;
    }
    // The keeper is the home's device.
    const Id subject = step.keeper ? l.home : ledger_of(step.subject, l);
    const ContractSigner own = signer_of(step);
    // Who does not consent: those the step expects the call to wait for,
    // and whoever starts the action if the subject does not.
    std::set<std::string> withheld;
    for (const m::TestParty& p : step.waits) {
        const Id id = ledger_of(p, l);
        r.expected_waits.push_back(id);
        withheld.insert(hex(id));
    }
    std::ranges::sort(r.expected_waits, id_less);
    const auto [first, last] = std::ranges::unique(r.expected_waits);
    r.expected_waits.erase(first, last);
    if (starts != nullptr) {
        if (const std::optional<Id> starter = starter_of(*starts, l);
            starter && *starter != subject) {
            withheld.insert(hex(*starter));
        }
    }
    const bool home_withheld = withheld.contains(hex(l.home));
    const cbor::Value args = arguments(step, action, l);

    std::vector<std::pair<Id, ContractSigner>> given;
    for (std::size_t round = 0; round < max_rounds; ++round) {
        protocol::ContractInput input;
        input.function = step.creation  ? std::string(m::creation_function(model_))
                         : step.approve ? std::string(m::approve_function)
                         : step.keeper  ? rules_.at(step.rule)
                                        : wire_name(step.word, step.name);
        input.arguments = args;
        input.home = l.home;
        input.contract = contract_;
        if (!step.creation) {
            input.instance = l.instance;
        }
        input.caller = actor_;
        // The home's party signs the call; anyone else's call is made by the
        // home's registrar, and the subject signs its consent.
        input.caller_signer = subject == l.home ? own : organization;
        input.time = static_cast<protocol::Timestamp>(std::max<std::int64_t>(r.time, 0));
        input.consents = given;
        TestCall& call = r.calls.emplace_back();
        call.input = input;
        auto encoded = protocol::encode_contract_input(input);
        if (!encoded) {
            r.happened = Happened::broken;
            r.reason = "the call's input does not encode";
            return;
        }
        call.encoded = std::move(*encoded);
        auto run = vm::run(module_, call.encoded, provider_, crypto::HashAlg::sha256);
        if (!run) {
            r.happened = Happened::broken;
            r.reason = "the code did not run";
            return;
        }
        call.run = std::move(*run);
        // The fuel bound (milestone 18) holds for every call a test makes
        // with arguments of the function's shape: one beyond it is a bug in
        // the compiler, which the test reports.
        const std::string why(call.run.abort_reason.begin(), call.run.abort_reason.end());
        if (const auto bound = bound_for(build_, call.encoded);
            bound && call.run.fuel_used > *bound && !why.starts_with("bo:argument")) {
            r.happened = Happened::broken;
            r.reason = std::format("the call used {} fuel, beyond its bound of {}",
                                   call.run.fuel_used, *bound);
            return;
        }
        if (call.run.trap) {
            if (*call.run.trap == vm::Trap::aborted) {
                r.happened = Happened::refused;
                r.reason.assign(call.run.abort_reason.begin(), call.run.abort_reason.end());
            } else {
                r.happened = Happened::broken;
                r.reason = std::string(vm::name(*call.run.trap));
            }
            return;
        }
        auto output = protocol::decode_contract_output(call.run.output, l.home);
        if (!output) {
            r.happened = Happened::broken;
            r.reason = "an output the ledger refuses";
            return;
        }
        call.output = *output;
        if (const auto* accepted = std::get_if<protocol::ContractAccept>(&*output)) {
            if (home_withheld) {
                r.happened = Happened::waits;
                r.waits = {l.home};
                return;
            }
            for (const auto& [id, signer] : given) {
                r.consents.push_back(id);
            }
            accept(step, *accepted, l, r);
            return;
        }
        const auto& needs = std::get<protocol::ContractNeeds>(*output);
        if (step.creation) {
            r.happened = Happened::broken;
            r.reason = "a creation asks for consents";
            return;
        }
        std::vector<Id> missing;
        std::vector<Id> agree;
        for (const Id& id : needs.ledgers) {
            if (std::ranges::find(given, id, &std::pair<Id, ContractSigner>::first) !=
                given.end()) {
                continue;
            }
            missing.push_back(id);
            if (!withheld.contains(hex(id))) {
                agree.push_back(id);
            }
        }
        if (missing.empty()) {
            r.happened = Happened::broken;
            r.reason = "the contract asks again for a consent it was given";
            return;
        }
        if (agree.empty()) {
            r.happened = Happened::waits;
            r.waits = std::move(missing);
            if (home_withheld) {
                r.waits.push_back(l.home);
            }
            std::ranges::sort(r.waits, id_less);
            return;
        }
        for (const Id& id : agree) {
            given.emplace_back(id, id == subject ? own : organization);
        }
        // A call cites its consents in ascending order of ledger.
        std::ranges::sort(given,
                          [](const auto& a, const auto& b) { return id_less(a.first, b.first); });
    }
    r.happened = Happened::broken;
    r.reason = "the contract keeps asking for consents";
}

bool passes(const m::Step& step, const StepResult& r) {
    switch (step.expect) {
    case m::Expectation::accepted:
        return r.happened == Happened::accepted;
    case m::Expectation::state:
        return r.happened == Happened::accepted &&
               r.state == wire_name(step.state_word, step.state_name);
    case m::Expectation::refused:
        if (step.reason) {
            return r.happened == Happened::refused && r.reason == *step.reason;
        }
        return r.happened == Happened::refused || r.happened == Happened::no_instance ||
               r.happened == Happened::final_instance;
    case m::Expectation::waits:
        return r.happened == Happened::waits && r.waits == r.expected_waits;
    case m::Expectation::proposed:
        return r.happened == Happened::accepted && !r.proposed.empty();
    }
    return false;
}

TestResult Runner::run(const m::Test& test) {
    TestResult out;
    out.steps.resize(test.steps.size());
    if (test.steps.empty()) {
        return out;
    }
    Ledger l;
    l.home = ledger_of(test.steps.front().subject, l);
    out.home = l.home;
    // The test's instances: the one it creates, then each part.
    std::vector<Instance> all;
    // The test starts on the default day, or on its first `at` date if
    // that is earlier, so that time never goes back.
    std::int64_t clock = test_start_ms(model_.utc_offset_ms);
    for (const m::Step& s : test.steps) {
        if (s.at) {
            clock =
                std::min(clock, literal_value(s.at->literal, model_.utc_offset_ms).value_or(clock));
            break;
        }
    }
    bool failed = false;
    for (std::size_t i = 0; i < test.steps.size(); ++i) {
        const m::Step& step = test.steps[i];
        StepResult& r = out.steps[i];
        if (step.at) {
            clock = std::max(clock,
                             literal_value(step.at->literal, model_.utc_offset_ms).value_or(clock));
        }
        r.time = clock;
        r.home = l.home;
        if (failed) {
            r.status = StepStatus::skipped;
            continue;
        }
        std::optional<std::size_t> at;
        if (!step.creation && !all.empty()) {
            at = target(step, all, r);
            if (!at) {
                r.happened = Happened::no_part;
                r.status = StepStatus::failed;
                failed = true;
                continue;
            }
            l.instance = all[*at].view;
            l.final = all[*at].final;
            r.part = all[*at].path;
        }
        l.children.clear();
        run_step(step, l, r);
        if (step.creation && r.happened == Happened::accepted && l.instance) {
            all.push_back(Instance{*l.instance, l.final, {}});
            at = 0;
        } else if (at) {
            all[*at].view = *l.instance;
            all[*at].final = l.final;
        }
        // R30: the parts the call created, after the instance.
        for (std::size_t k = 0; at && k < l.children.size(); ++k) {
            const Instance& parent = all[*at];
            const protocol::ContractChild& child = l.children[k];
            Instance part;
            const auto id =
                protocol::child_instance_id(provider_, crypto::HashAlg::sha256, parent.view.id, k);
            part.view.id = id.has_value() ? *id : Id{};
            part.view.head = parent.view.head;
            part.view.state = child.state;
            part.view.status = child.status;
            part.view.parties = child.parties;
            part.view.parent = parent.view.id;
            part.view.depth = parent.view.depth + 1;
            part.path =
                (parent.path.empty() ? std::string() : parent.path + ".") + std::to_string(k + 1);
            all.push_back(std::move(part));
        }
        r.status = passes(step, r) ? StepStatus::passed : StepStatus::failed;
        failed = r.status == StepStatus::failed;
    }
    out.passed = !failed;
    return out;
}

std::optional<std::size_t> Runner::target(const m::Step& step, const std::vector<Instance>& all,
                                          StepResult& r) {
    // Before any split, the test's one instance.
    if (all.size() == 1 && !step.part) {
        return 0;
    }
    // Roles name the ledgers they were bound to at creation.
    Ledger root;
    root.instance = all.front().view;
    std::set<std::string> fields;
    for (const m::Field& f : model_.fields) {
        if (f.kind == m::FieldKind::instance && f.type.kind == m::TypeKind::party) {
            fields.insert(wire_name(f.word, f.name));
        }
    }
    std::optional<Id> who;
    if (step.part) {
        who = ledger_of(*step.part, root);
        r.holder = who;
    } else {
        who = step.keeper ? std::optional<Id>(r.home) : ledger_of(step.subject, root);
    }
    const auto holds = [&](const Instance& i) {
        for (const auto& [name, id] : i.view.parties) {
            const bool counts = step.part ? name == "holder" : fields.contains(name);
            if (counts && id == *who) {
                return true;
            }
        }
        return false;
    };
    std::vector<std::size_t> live;
    std::vector<std::size_t> ended;
    for (std::size_t i = 0; i < all.size(); ++i) {
        if (holds(all[i])) {
            (all[i].final ? ended : live).push_back(i);
        }
    }
    if (live.size() == 1) {
        return live.front();
    }
    if (live.empty() && ended.size() == 1) {
        return ended.front();
    }
    if (!step.part && live.empty() && ended.empty()) {
        // The subject holds nothing: the one instance that takes calls.
        std::optional<std::size_t> only;
        for (std::size_t i = 0; i < all.size(); ++i) {
            if (!all[i].final) {
                if (only) {
                    return std::nullopt;
                }
                only = i;
            }
        }
        return only;
    }
    return std::nullopt;
}

// --- Words.

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

char32_t last_point(std::string_view text) noexcept {
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

/// True if a space goes between two texts written side by side: Latin or
/// digits on one side, Chinese on the other.
bool needs_space(std::string_view before, std::string_view after) noexcept {
    const char32_t a = last_point(before);
    const char32_t b = point_at(after, 0);
    return (is_narrow(a) && is_wide(b)) || (is_wide(a) && is_narrow(b));
}

using Values = std::initializer_list<std::pair<std::string_view, std::string>>;

/// A sentence of the pack (else of the English pack), its placeholders
/// filled. In a language written without spaces, a space still sets a value
/// apart where Latin letters or digits meet Chinese characters ("實例現為
/// signed").
std::string say(std::string_view id, Values values, const Pack* language) {
    const Pack& english = english_pack();
    const Pack& pack = language != nullptr ? *language : english;
    const std::string* pattern = nullptr;
    for (const Pack* p : {&pack, &english}) {
        if (const auto it = p->sentences.find(id); it != p->sentences.end()) {
            pattern = &it->second;
            break;
        }
    }
    if (pattern == nullptr) {
        return std::string(id);
    }
    const bool spaced = pack.reading.separation == Separation::spaces;
    std::string out;
    bool after_value = false;
    const auto glue = [&](std::string_view piece, bool value) {
        if (piece.empty()) {
            return;
        }
        if (!spaced && (value || after_value) && !out.empty() && needs_space(out, piece)) {
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
        const std::string_view name = rest.substr(open + 1, close - open - 1);
        const auto found =
            std::ranges::find_if(values, [&](const std::pair<std::string_view, std::string>& v) {
                return v.first == name;
            });
        if (found == values.end()) {
            glue(rest.substr(open, close - open + 1), false);
        } else {
            glue(found->second, true);
        }
        rest.remove_prefix(close + 1);
    }
    return out;
}

/// Ledgers as the report names them, joined as the pack joins a list.
std::string ledger_list(const TestResults& results, const std::vector<Id>& ids,
                        const Pack* language) {
    std::vector<std::string> names;
    for (const Id& id : ids) {
        names.push_back(ledger_label(results, id, language));
    }
    if (names.empty()) {
        return {};
    }
    if (names.size() == 1) {
        return names.front();
    }
    std::string rest = names.front();
    const std::string separator = say("list-separator", {}, language);
    for (std::size_t i = 1; i + 1 < names.size(); ++i) {
        rest += separator + names[i];
    }
    return say(names.size() > 2 ? "list-and-many" : "list-and",
               {{"rest", rest}, {"last", names.back()}}, language);
}

/// What a call waits for: the consents of some ledgers, and the home's
/// call if the home is among them (the home agrees only by making the call).
std::string waits_words(const TestResults& results, const std::vector<Id>& ledgers, const Id& home,
                        std::string_view prefix, const Pack* language) {
    std::vector<Id> others;
    bool home_too = false;
    for (const Id& id : ledgers) {
        if (id == home) {
            home_too = true;
        } else {
            others.push_back(id);
        }
    }
    const std::string parties = ledger_list(results, others, language);
    const std::string party = ledger_label(results, home, language);
    if (!home_too) {
        return say(std::string(prefix) + "waits", {{"parties", parties}}, language);
    }
    if (others.empty()) {
        return say(std::string(prefix) + "waits-home", {{"party", party}}, language);
    }
    return say(std::string(prefix) + "waits-both", {{"parties", parties}, {"party", party}},
               language);
}

/// A state as the report names it: a vocabulary state's word, or the name.
std::string state_word(std::string_view state, const Pack* language) {
    if (const Concept* c = find_concept("state." + std::string(state)); c != nullptr) {
        return spell(c->id, language);
    }
    return std::string(state);
}

/// A time as the canonical dump writes it: the day at the contract's
/// offset, and the time of day if it is not midnight.
std::string time_text(std::int64_t ms, const std::int64_t offset_ms) {
    const std::int64_t local = ms + offset_ms;
    const std::int64_t day = 86'400'000;
    std::int64_t days = local / day;
    std::int64_t rest = local % day;
    if (rest < 0) {
        rest += day;
        days -= 1;
    }
    // Civil from days (Howard Hinnant's algorithm).
    const std::int64_t z = days + 719'468;
    const std::int64_t era = (z >= 0 ? z : z - 146'096) / 146'097;
    const std::int64_t doe = z - era * 146'097;
    const std::int64_t yoe = (doe - doe / 1'460 + doe / 36'524 - doe / 146'096) / 365;
    const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const std::int64_t mp = (5 * doy + 2) / 153;
    const std::int64_t d = doy - (153 * mp + 2) / 5 + 1;
    const std::int64_t mo = mp < 10 ? mp + 3 : mp - 9;
    const std::int64_t y = yoe + era * 400 + (mo <= 2 ? 1 : 0);
    std::string out = std::format("{:04}-{:02}-{:02}", y, mo, d);
    if (rest != 0) {
        out += std::format("T{:02}:{:02}", rest / 3'600'000, rest / 60'000 % 60);
    }
    return out;
}

} // namespace

const TestLedger* TestResults::ledger(const Id& id) const noexcept {
    const auto it = std::ranges::find(ledgers, id, &TestLedger::id);
    return it == ledgers.end() ? nullptr : &*it;
}

std::int64_t test_start_ms(const std::int64_t offset_ms) noexcept {
    return days_from_civil(2026, 1, 1) * 86'400'000 - offset_ms;
}

Id test_ledger_id(std::string_view key, const crypto::Provider& provider) {
    return hash_of(std::string(ledger_prefix) + std::string(key), provider);
}

TestResults run_tests(const m::Model& model, const Build& build, const crypto::Provider& provider) {
    TestResults out;
    auto module = vm::load(build.code);
    // Lowering returns only modules that load.
    BO_ASSERT(module.has_value());
    if (!module) {
        return out;
    }
    Runner runner(model, build, *module, provider);
    for (const m::Test& test : model.tests) {
        out.tests.push_back(runner.run(test));
        (out.tests.back().passed ? out.passed : out.failed) += 1;
    }
    out.ledgers = runner.ledgers();
    return out;
}

std::string ledger_label(const TestResults& results, const Id& id, const Pack* language) {
    const TestLedger* l = results.ledger(id);
    if (l == nullptr) {
        return hex(id);
    }
    if (l->word == nullptr) {
        return l->name;
    }
    for (const Pack* p : {language, &english_pack()}) {
        if (p == nullptr) {
            continue;
        }
        if (const Word* w = p->word(l->word->id); w != nullptr && !w->spellings.empty()) {
            const auto form = w->forms.find("object");
            return form != w->forms.end() ? form->second : w->spellings.front();
        }
    }
    return std::string(l->word->id);
}

std::string step_source(std::string_view source, const m::Step& step) {
    const auto text = [&](const Span& span) {
        const std::size_t from = std::min<std::size_t>(span.offset, source.size());
        return std::string(source.substr(from, span.length));
    };
    if (step.expect_span.line == 0) {
        return text(step.span);
    }
    if (step.expect_span.line != step.span.line) {
        return text(step.span) + " " + text(step.expect_span);
    }
    const Span both{step.span.line, step.span.column, step.span.offset,
                    step.expect_span.offset + step.expect_span.length - step.span.offset};
    return text(both);
}

std::string expectation_text(const m::Step& step, const StepResult& result,
                             const TestResults& results, const Pack* language) {
    switch (step.expect) {
    case m::Expectation::accepted:
        break;
    case m::Expectation::state:
        return say("expect-state",
                   {{"state", step.state_word != nullptr ? spell(step.state_word->id, language)
                                                         : step.state_name}},
                   language);
    case m::Expectation::refused:
        if (step.reason) {
            return say("expect-refused-reason", {{"reason", quoted_text(*step.reason, language)}},
                       language);
        }
        return say("expect-refused", {}, language);
    case m::Expectation::waits:
        return waits_words(results, result.expected_waits, result.home, "expect-", language);
    case m::Expectation::proposed:
        return say("expect-proposed", {}, language);
    }
    return say("expect-accepted", {}, language);
}

std::string outcome_text(const StepResult& result, const TestResults& results,
                         const Pack* language) {
    switch (result.happened) {
    case Happened::accepted: {
        if (!result.proposed.empty()) {
            const Concept* c = find_concept("act." + result.proposed);
            return say("outcome-proposed",
                       {{"action", c != nullptr ? spell(c->id, language) : result.proposed}},
                       language);
        }
        const std::string state = state_word(result.state, language);
        std::string out = result.consents.empty()
                              ? say("outcome-accepted", {{"state", state}}, language)
                              : say("outcome-accepted-consents",
                                    {{"state", state},
                                     {"parties", ledger_list(results, result.consents, language)}},
                                    language);
        if (result.final) {
            out = say("outcome-final", {{"outcome", out}}, language);
        }
        return out;
    }
    case Happened::waits:
        return waits_words(results, result.waits, result.home, "outcome-", language);
    case Happened::refused:
        if (const std::optional<std::string> worded = render_reason(result.reason, language)) {
            return say("outcome-refused-code", {{"reason", *worded}, {"code", result.reason}},
                       language);
        }
        return say("outcome-refused", {{"reason", quoted_text(result.reason, language)}}, language);
    case Happened::no_instance:
        return say("outcome-no-instance", {}, language);
    case Happened::final_instance:
        return say("outcome-final-instance", {}, language);
    case Happened::broken:
        return say("outcome-broken", {{"detail", result.reason}}, language);
    case Happened::no_part:
        if (result.holder) {
            return say("outcome-no-part",
                       {{"party", ledger_label(results, *result.holder, language)}}, language);
        }
        return say("outcome-no-part-step", {}, language);
    case Happened::none:
        break;
    }
    return {};
}

const ExplainedClause* refusal_clause(const Explained& text, const m::Model& model,
                                      const m::Step& step, const StepResult& result) {
    if (result.happened != Happened::refused) {
        return nullptr;
    }
    const std::vector<std::string> rules = m::rule_functions(model);
    const std::string function = step.creation  ? std::string(m::creation_function(model))
                                 : step.approve ? std::string(m::approve_function)
                                 : step.keeper && step.rule < rules.size()
                                     ? rules[step.rule]
                                     : wire_name(step.word, step.name);
    // "bo:CODE VALUES": the code, then the action and a number.
    std::string_view reason = result.reason;
    std::string_view code;
    std::string_view action;
    std::uint32_t number = 0;
    if (reason.starts_with("bo:")) {
        reason.remove_prefix(3);
        const std::size_t space = reason.find(' ');
        code = reason.substr(0, space);
        if (space != std::string_view::npos) {
            const std::string_view values = reason.substr(space + 1);
            const std::size_t next = values.find(' ');
            action = values.substr(0, next);
            if (next != std::string_view::npos) {
                for (const char c : values.substr(next + 1)) {
                    if (c < '0' || c > '9' || number > 100'000) {
                        number = 0;
                        break;
                    }
                    number = number * 10 + static_cast<std::uint32_t>(c - '0');
                }
            }
        }
    }
    for (const ExplainedSection& section : text.sections) {
        for (const ExplainedClause& c : section.clauses) {
            if (code == "requires" && c.function == action && c.requirement == number &&
                number != 0) {
                return &c;
            }
            if (code == "in-person" && c.function == action && c.kind == "requirement" &&
                std::ranges::find(c.rules, std::string_view("R13")) != c.rules.end()) {
                return &c;
            }
            if (code == "state" && c.function == action && c.kind == "transition") {
                return &c;
            }
            // A part too deep to split; parts and recipients that differ.
            if (code == "depth" && c.function == action && c.kind == "parts-depth") {
                return &c;
            }
            if (code == "parts" && c.function == action && c.kind == "parts") {
                return &c;
            }
            // A time rule whose time has not come, or that already applied.
            if ((code == "when" || code == "fired") && c.function == action && c.kind == "when") {
                return &c;
            }
            if (code.empty() && c.function == function && c.kind == "reject" &&
                c.text.find(result.reason) != std::string::npos) {
                return &c;
            }
        }
    }
    return nullptr;
}

std::string test_report(const m::Model& model, const TestResults& results, std::string_view source,
                        const Pack* language) {
    if (model.tests.empty()) {
        return say("test-none", {}, language) + "\n";
    }
    const Explained text = explain(model, language);
    std::string out;
    for (std::size_t i = 0; i < model.tests.size() && i < results.tests.size(); ++i) {
        const m::Test& test = model.tests[i];
        const TestResult& result = results.tests[i];
        const std::string name =
            test.name.empty() ? say("test-unnamed", {{"number", std::to_string(i + 1)}}, language)
                              : quoted_text(test.name, language);
        std::size_t failed_at = 0;
        for (std::size_t j = 0; j < result.steps.size(); ++j) {
            if (result.steps[j].status == StepStatus::failed) {
                failed_at = j + 1;
            }
        }
        out += result.passed ? say("test-passed", {{"name", name}}, language)
                             : say("test-failed",
                                   {{"name", name}, {"step", std::to_string(failed_at)}}, language);
        out += "\n";
        for (std::size_t j = 0; j < test.steps.size() && j < result.steps.size(); ++j) {
            const m::Step& step = test.steps[j];
            const StepResult& r = result.steps[j];
            const std::string_view id = r.status == StepStatus::passed   ? "step-passed"
                                        : r.status == StepStatus::failed ? "step-failed"
                                                                         : "step-skipped";
            out += "  " +
                   say(id,
                       {{"number", std::to_string(j + 1)},
                        {"line", std::to_string(step.span.line)},
                        {"text", step_source(source, step)}},
                       language) +
                   "\n";
            if (r.status == StepStatus::skipped) {
                continue;
            }
            if (r.status == StepStatus::failed) {
                out += "    " +
                       say("step-expected",
                           {{"what", expectation_text(step, r, results, language)}}, language) +
                       "\n";
            }
            if (!r.part.empty()) {
                out += "    " + say("step-part", {{"part", r.part}}, language) + "\n";
            }
            out += "    " +
                   say("step-result", {{"what", outcome_text(r, results, language)}}, language) +
                   "\n";
            if (const ExplainedClause* c = refusal_clause(text, model, step, r)) {
                out += "    " +
                       say("step-clause", {{"number", c->number}, {"text", c->text}}, language) +
                       "\n";
            }
        }
        out += "\n";
    }
    out += say(results.tests.size() == 1 ? "test-summary-one" : "test-summary",
               {{"total", std::to_string(results.tests.size())},
                {"passed", std::to_string(results.passed)},
                {"failed", std::to_string(results.failed)}},
               language) +
           "\n";
    return out;
}

std::string dump(const m::Model& model, const TestResults& results) {
    const auto key = [&](const Id& id) {
        const TestLedger* l = results.ledger(id);
        return l == nullptr ? hex(id) : m::key(l->word, l->name);
    };
    const auto keys = [&](const std::vector<Id>& ids) {
        std::string out;
        for (const Id& id : ids) {
            out += " " + key(id);
        }
        return out;
    };
    std::string out;
    for (std::size_t i = 0; i < model.tests.size() && i < results.tests.size(); ++i) {
        const m::Test& test = model.tests[i];
        const TestResult& result = results.tests[i];
        out += std::format("test {} {} home={}\n",
                           test.name.empty() ? std::to_string(i + 1) : "\"" + test.name + "\"",
                           result.passed ? "passed" : "failed", key(result.home));
        for (std::size_t j = 0; j < result.steps.size(); ++j) {
            const StepResult& r = result.steps[j];
            std::string line = std::format("  step {} {}", j + 1,
                                           step_status_names[static_cast<std::size_t>(r.status)]);
            if (r.status != StepStatus::skipped) {
                line += " " + time_text(r.time, model.utc_offset_ms) + " " +
                        std::string(happened_names[static_cast<std::size_t>(r.happened)]);
                if (!r.part.empty()) {
                    line += " part=" + r.part;
                }
            }
            switch (r.happened) {
            case Happened::accepted:
                line += " " + r.state;
                for (const std::string& e : r.events) {
                    line += " event=" + e;
                }
                if (r.final) {
                    line += " final";
                }
                if (!r.consents.empty()) {
                    line += " consents" + keys(r.consents);
                }
                if (!r.bill.empty()) {
                    line += " bill " + r.bill;
                }
                if (r.parts > 0) {
                    line += std::format(" parts={}", r.parts);
                }
                break;
            case Happened::waits:
                line += keys(r.waits);
                break;
            case Happened::refused:
            case Happened::broken:
                line += " \"" + r.reason + "\"";
                break;
            default:
                break;
            }
            if (!r.calls.empty()) {
                line += "; fuel";
                for (const TestCall& c : r.calls) {
                    line += " " + std::to_string(c.run.fuel_used);
                }
            }
            out += line + "\n";
        }
    }
    out += std::format("{} tests: {} passed, {} failed\n", results.tests.size(), results.passed,
                       results.failed);
    return out;
}

} // namespace cexchain::bo
