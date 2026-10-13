// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Lowering (milestone 6 of the Bo compiler): a checked model to a contract
// module. lower.hpp says what the compiled contract does and what this
// version compiles. The work is in two passes: the first checks that the
// model is within the subset and the limits and plans the tables (fields,
// roles, states, functions, each with the name compiled code gives it), so
// that the second, which writes the code, meets nothing it cannot write.
//
// Everything is written in one fixed order (the model's), names are sorted
// by their CBOR encodings where the output needs canonical order, and
// nothing depends on spellings, places, addresses, or unordered iteration.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/bo/lower.hpp>
#include <cexchain/bo/runtime.hpp>
#include <cexchain/bo/values.hpp>
#include <cexchain/bo/wasm.hpp>

namespace cexchain::bo {

namespace {

namespace m = model;
namespace rt = runtime;
using ast::ExprKind;
using ast::Operator;
using m::Refers;
using m::TypeKind;
using rt::Routine;
using wasm::FunctionBuilder;
using wasm::Label;
using wasm::Local;
using enum wasm::Op;
constexpr auto I32 = wasm::ValType::i32;
constexpr auto I64 = wasm::ValType::i64;

template <class... F>
struct Overloaded : F... {
    using F::operator()...;
};

/// How compiled code holds a value of a type.
enum class Rep : std::uint8_t {
    none,   ///< not compiled yet
    i64,    ///< numbers, money, quantities, rates, dates, durations
    flag,   ///< yes or no: an i32, 0 or 1
    text,   ///< an address and a length (i32 each)
    ledger, ///< the address of a 32-byte ledger id (i32; 0 while a role is unbound)
};

Rep rep_of(const m::Type& t) noexcept {
    switch (t.kind) {
    case TypeKind::number:
    case TypeKind::money:
    case TypeKind::quantity:
    case TypeKind::rate:
    case TypeKind::date:
    case TypeKind::duration:
        return Rep::i64;
    case TypeKind::yes_no:
        return Rep::flag;
    case TypeKind::text:
        return Rep::text;
    case TypeKind::party:
        return Rep::ledger;
    default:
        return Rep::none;
    }
}

bool is(const Concept* c, std::string_view id) noexcept {
    return c != nullptr && c->id == id;
}

/// What a type the compiler cannot hold yet needs, as a concept to name.
std::string feature_of(const m::Type& t) {
    switch (t.kind) {
    case TypeKind::list:
        return "type.list";
    case TypeKind::unit_price:
        return "price.per";
    case TypeKind::recurring:
        return t.period != nullptr ? std::string(t.period->id) : "time.monthly";
    case TypeKind::basis:
        return "charge.by";
    default:
        return "type.unknown";
    }
}

/// A text's CBOR encoding: what keys and state names look like in the
/// input and the output.
Bytes text_cbor(std::string_view text) {
    Bytes out;
    const std::uint64_t n = text.size();
    if (n < 24) {
        out.push_back(static_cast<std::uint8_t>(0x60 + n));
    } else if (n < 0x100) {
        out.push_back(0x78);
        out.push_back(static_cast<std::uint8_t>(n));
    } else if (n < 0x1'0000) {
        out.push_back(0x79);
        out.push_back(static_cast<std::uint8_t>(n >> 8U));
        out.push_back(static_cast<std::uint8_t>(n));
    } else {
        out.push_back(0x7A);
        for (int shift = 24; shift >= 0; shift -= 8) {
            out.push_back(static_cast<std::uint8_t>(n >> static_cast<unsigned>(shift)));
        }
    }
    out.insert(out.end(), text.begin(), text.end());
    return out;
}

/// One byte: a small unsigned integer key (contract-input, instance-view).
Bytes uint_key(const std::uint8_t k) {
    return Bytes{k};
}

/// Up to 80 bytes of the source at a place, cut at a character, for
/// messages.
std::string quote(std::string_view source, const Span& span) {
    const std::size_t from = std::min<std::size_t>(span.offset, source.size());
    std::string_view text = source.substr(from, span.length);
    constexpr std::size_t max = 80;
    if (text.size() <= max) {
        return std::string(text);
    }
    std::size_t cut = max;
    while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0U) == 0x80U) {
        --cut;
    }
    return std::string(text.substr(0, cut)) + "\xE2\x80\xA6";
}

/// The size an action's body may reach before more statements would risk
/// the profile's limit (131,072 bytes); one statement adds far less.
constexpr std::size_t body_budget = 100 * 1024;
/// Static bytes kept for the runtime's constants and scratch space.
constexpr std::uint32_t static_margin = 1024;
/// How deep constants may refer to constants.
constexpr int max_constant_depth = 16;

/// The most bytes an instance's state may take, encoded (spec section 15).
constexpr std::size_t max_state_size = 65'536;

/// R17: products and quotients round half up.
constexpr std::int32_t round_half_up = static_cast<std::int32_t>(rt::Rounding::half_up);

struct FieldSlot {
    const m::Field* field = nullptr;
    std::string wire;
    Bytes key;
    Rep rep = Rep::none;
    /// The value: an i64, a flag, a ledger's address, or a text's address.
    wasm::Global first{};
    /// A text's length.
    wasm::Global second{};
    /// A party field that starts with a role (R2): that role.
    std::optional<std::size_t> starts_with;
};

struct RoleSlot {
    const m::Party* party = nullptr;
    std::string wire;
    Bytes key;
    wasm::Global ledger{};
};

struct StateSlot {
    std::string wire;
    Bytes encoded;
    bool final = false;
};

struct ActionInfo {
    const m::Action* action = nullptr;
    std::string key;
    std::string wire;
    /// The role the action binds (R3), if it binds one.
    std::optional<std::size_t> binds;
    std::size_t transitions = 0;
    wasm::Func function{};
};

/// One function being written.
struct Ctx {
    FunctionBuilder* b = nullptr;
    const ActionInfo* action = nullptr;
    /// Inputs by key: the value's local, and a text's length.
    std::map<std::string, std::pair<Local, Local>> inputs;
    /// The starter's signer (0 while its consent is missing).
    Local signer{};
    Local t32{};
    Local t64{};
    Local t64b{};
    std::uint32_t requires_count = 0;
    int depth = 0;
};

class Lowering {
public:
    Lowering(std::string_view source, const m::Model& model)
        : source_(source), model_(model), module_(rt::memory_plan()), rt_(module_) {}

    Lowered run();

private:
    // --- Problems.
    void error(const Span& span, std::string_view code,
               std::vector<std::pair<std::string_view, std::string>> args) {
        diagnostics_.push_back(Diagnostic{code, std::move(args), span});
    }
    void unsupported(const Span& span, std::string feature) {
        error(span, "build.unsupported",
              {{"text", quote(source_, span)}, {"feature", std::move(feature)}});
    }

    // --- The first pass: support, limits, and tables.
    void plan();
    void plan_fields();
    void plan_roles();
    void plan_states();
    void plan_actions();
    void plan_finals();
    [[nodiscard]] std::optional<std::pair<Span, std::string>>
    unsupported_in(const m::Expr& e, const ActionInfo* action, bool consent_ok, int depth) const;
    void support(ActionInfo& action, const std::vector<m::Statement>& list);
    [[nodiscard]] const m::Field* constant(const std::string& key) const;
    [[nodiscard]] std::optional<std::string> amount_of(const ActionInfo& action) const;
    void name_check(const std::string& wire, const Span& span, std::size_t limit);

    // --- Static data and refusals.
    [[nodiscard]] std::uint32_t intern(ByteView bytes);
    [[nodiscard]] std::uint32_t intern(std::string_view text) { return intern(as_bytes(text)); }
    void refuse(FunctionBuilder& b, std::string_view reason);
    void call_item(FunctionBuilder& b, std::uint32_t key);
    void push_key(FunctionBuilder& b, const Bytes& key);
    void expect(FunctionBuilder& b, Rep rep, std::string_view reason);
    void store(FunctionBuilder& b, const FieldSlot& slot);
    void load(FunctionBuilder& b, const FieldSlot& slot);
    void out_value(FunctionBuilder& b, Rep rep);
    void state_name(FunctionBuilder& b, Local index);

    // --- The second pass: code.
    void emit();
    void emit_entry(wasm::Func entry);
    void emit_creation(wasm::Func f);
    void emit_action(const ActionInfo& action);
    [[nodiscard]] wasm::Func load_instance();
    [[nodiscard]] wasm::Func write_accept();
    void finish(FunctionBuilder& b);
    void arguments(Ctx& c);
    void statements(Ctx& c, const std::vector<m::Statement>& list);
    void requirement(Ctx& c, const m::Requires& r);
    void transition(Ctx& c, const m::Transition& t);
    void value(Ctx& c, const m::Expr& e);
    void reference(Ctx& c, const m::Expr& e);
    void binary(Ctx& c, const m::Expr& e);
    void arithmetic(Ctx& c, const m::Expr& e);
    void in_person(Ctx& c);
    void record_event(FunctionBuilder& b, std::size_t state);

    std::string_view source_;
    const m::Model& model_;
    wasm::ModuleWriter module_;
    rt::Runtime rt_;
    std::vector<Diagnostic> diagnostics_;
    bool too_large_ = false;

    std::string creation_;
    std::vector<FieldSlot> fields_;
    std::map<std::string, std::size_t> field_index_;
    std::vector<RoleSlot> roles_;
    std::map<std::string, std::size_t> role_index_;
    std::vector<StateSlot> states_;
    std::map<std::string, std::size_t> state_index_;
    std::vector<ActionInfo> actions_;
    std::size_t max_transitions_ = 1;
    wasm::Func creation_function_{};

    // Written in the second pass.
    wasm::Global state_{};
    wasm::Global events_{};
    std::uint32_t events_area_ = 0;
    std::uint32_t state_table_ = 0;
    std::uint32_t final_table_ = 0;
    std::optional<wasm::Func> load_instance_;
    std::optional<wasm::Func> write_accept_;
};

// ---------------------------------------------------------------------------
// The first pass.

void Lowering::name_check(const std::string& wire, const Span& span, const std::size_t limit) {
    if (wire.empty() || wire.size() > limit) {
        error(span, "build.name-too-long", {{"name", wire}, {"limit", std::to_string(limit)}});
    }
}

const m::Field* Lowering::constant(const std::string& key) const {
    for (const m::Field& f : model_.fields) {
        if (f.kind == m::FieldKind::constant && m::key(f.word, f.name) == key) {
            return &f;
        }
    }
    return nullptr;
}

void Lowering::plan_fields() {
    std::set<std::string> wires;
    for (const m::Field& f : model_.fields) {
        if (f.kind != m::FieldKind::instance) {
            continue;
        }
        FieldSlot slot;
        slot.field = &f;
        slot.wire = wire_name(f.word, f.name);
        slot.key = text_cbor(slot.wire);
        slot.rep = rep_of(f.type);
        if (slot.rep == Rep::none) {
            unsupported(f.span, feature_of(f.type));
        }
        if (!wires.insert(slot.wire).second) {
            error(f.span, "build.name-taken", {{"name", slot.wire}});
        }
        name_check(slot.wire, f.span, max_build_name);
        field_index_.emplace(m::key(f.word, f.name), fields_.size());
        fields_.push_back(std::move(slot));
    }
    if (fields_.size() > max_build_fields) {
        error(Span{}, "build.too-many-fields", {{"limit", std::to_string(max_build_fields)}});
    }
}

void Lowering::plan_roles() {
    std::set<std::string> wires;
    for (const m::Party& p : model_.parties) {
        RoleSlot slot;
        slot.party = &p;
        slot.wire = wire_name(p.role, p.name);
        slot.key = text_cbor(slot.wire);
        if (!wires.insert(slot.wire).second) {
            error(p.span, "build.name-taken", {{"name", slot.wire}});
        }
        name_check(slot.wire, p.span, max_build_name);
        role_index_.emplace(m::key(p.role, p.name), roles_.size());
        roles_.push_back(std::move(slot));
    }
    // The parties the output reports: the roles and the fields holding one.
    std::size_t parties = roles_.size();
    for (FieldSlot& slot : fields_) {
        if (slot.rep != Rep::ledger) {
            continue;
        }
        ++parties;
        if (!wires.insert(slot.wire).second) {
            error(slot.field->span, "build.name-taken", {{"name", slot.wire}});
        }
        if (slot.field->value && slot.field->value->refers == Refers::party) {
            const std::string role =
                m::key(slot.field->value->concept_entry, slot.field->value->name);
            const auto it = role_index_.find(role);
            if (it != role_index_.end() &&
                roles_[it->second].party->binding == m::Binding::creation) {
                slot.starts_with = it->second;
            } else {
                error(slot.field->span, "build.late-party",
                      {{"field", m::key(slot.field->word, slot.field->name)}, {"party", role}});
            }
        }
    }
    if (parties > max_build_parties) {
        error(Span{}, "build.too-many-parties", {{"limit", std::to_string(max_build_parties)}});
    }
}

void Lowering::plan_states() {
    std::set<std::string> wires;
    for (const m::State& s : model_.states) {
        StateSlot slot;
        slot.wire = wire_name(s.word, s.name);
        slot.encoded = text_cbor(slot.wire);
        if (!wires.insert(slot.wire).second) {
            error(s.span, "build.name-taken", {{"name", slot.wire}});
        }
        name_check(slot.wire, s.span, max_build_name);
        state_index_.emplace(m::key(s.word, s.name), states_.size());
        states_.push_back(std::move(slot));
    }
}

std::optional<std::string> Lowering::amount_of(const ActionInfo& action) const {
    // R6: the action's one input of money or a quantity; with none, the
    // instance's amount.
    std::optional<std::string> found;
    int amounts = 0;
    for (const m::Field& input : action.action->inputs) {
        if (input.type.kind == TypeKind::money || input.type.kind == TypeKind::quantity) {
            ++amounts;
            found = m::key(input.word, input.name);
        }
    }
    if (amounts == 1) {
        return found;
    }
    if (amounts == 0) {
        for (const m::Field& f : model_.fields) {
            if (is(f.word, "field.amount") && rep_of(f.type) == Rep::i64) {
                return std::string("field.amount");
            }
        }
    }
    return std::nullopt;
}

std::optional<std::pair<Span, std::string>> Lowering::unsupported_in(const m::Expr& e,
                                                                     const ActionInfo* action,
                                                                     const bool consent_ok,
                                                                     const int depth) const {
    using Found = std::optional<std::pair<Span, std::string>>;
    const auto no = [&](std::string feature) -> Found {
        return std::pair{e.span, std::move(feature)};
    };
    const auto all = [&](bool consent) -> Found {
        for (const m::Expr& o : e.operands) {
            if (Found f = unsupported_in(o, action, consent, depth)) {
                return f;
            }
        }
        return std::nullopt;
    };
    if (depth > max_constant_depth) {
        return no(m::key(e.concept_entry, e.name));
    }
    switch (e.kind) {
    case ExprKind::literal:
        if (e.literal.kind == ast::LiteralKind::text || literal_value(e.literal)) {
            return std::nullopt;
        }
        return no(feature_of(e.type));
    case ExprKind::name:
    case ExprKind::word: {
        const std::string key = m::key(e.concept_entry, e.name);
        switch (e.refers) {
        case Refers::field:
            if (const m::Field* c = constant(key)) {
                if (!c->value || rep_of(c->type) == Rep::none) {
                    return no(feature_of(c->type));
                }
                return unsupported_in(*c->value, action, false, depth + 1);
            }
            return field_index_.contains(key) && fields_[field_index_.at(key)].rep != Rep::none
                       ? std::nullopt
                       : no(feature_of(e.type));
        case Refers::input:
            return rep_of(e.type) != Rep::none ? std::nullopt : no(feature_of(e.type));
        case Refers::party:
            return role_index_.contains(key) ? std::nullopt : no(key);
        case Refers::state:
            return e.type.kind == TypeKind::yes_no && state_index_.contains(key)
                       ? std::nullopt
                       : no(feature_of(e.type));
        case Refers::item:
            return no("kw.each");
        case Refers::action:
            return no(key);
        case Refers::none:
            break;
        }
        if (is(e.concept_entry, "val.yes") || is(e.concept_entry, "val.no") ||
            is(e.concept_entry, "time.now") || is(e.concept_entry, "time.today") ||
            (is(e.concept_entry, "cond.in_person") && action != nullptr)) {
            return std::nullopt;
        }
        return no(e.concept_entry != nullptr ? std::string(e.concept_entry->id)
                                             : feature_of(e.type));
    }
    case ExprKind::apply:
        if (is(e.concept_entry, "cond.over") && action != nullptr && amount_of(*action)) {
            return all(false);
        }
        if (is(e.concept_entry, "cond.consent_of") && consent_ok) {
            return all(false);
        }
        return no(e.concept_entry != nullptr ? std::string(e.concept_entry->id) : "cond.over");
    case ExprKind::phrase:
        return no(!e.operands.empty() && e.operands[0].concept_entry != nullptr
                      ? std::string(e.operands[0].concept_entry->id)
                      : "price.per");
    case ExprKind::list:
        return no("type.list");
    case ExprKind::unary:
        return all(false);
    case ExprKind::binary:
        break;
    }
    if (e.operands.size() != 2) {
        return no("type.unknown");
    }
    if (Found f = all(false)) {
        return f;
    }
    const m::Type& l = e.operands[0].type;
    const m::Type& r = e.operands[1].type;
    const TypeKind lk = l.kind;
    const TypeKind rk = r.kind;
    const Rep rep = rep_of(l);
    switch (e.op) {
    case Operator::logical_and:
    case Operator::logical_or:
        return std::nullopt;
    case Operator::member:
        return no("kw.in");
    case Operator::equals:
        return rep != Rep::none && rep == rep_of(r) ? std::nullopt : no(feature_of(l));
    case Operator::less:
    case Operator::less_equal:
    case Operator::greater:
    case Operator::greater_equal:
        return rep == Rep::i64 && rep_of(r) == Rep::i64 ? std::nullopt : no(feature_of(l));
    case Operator::plus:
    case Operator::minus:
    case Operator::times:
    case Operator::divide:
        if (rep == Rep::i64 && rep_of(r) == Rep::i64 && rep_of(e.type) == Rep::i64) {
            if (e.op == Operator::times &&
                (lk == TypeKind::unit_price || rk == TypeKind::unit_price)) {
                return no("price.per");
            }
            return std::nullopt;
        }
        return no(lk == TypeKind::unit_price || rk == TypeKind::unit_price
                      ? std::string("price.per")
                      : feature_of(rep_of(l) == Rep::none ? l : r));
    case Operator::none:
    case Operator::logical_not:
        break;
    }
    return no("type.unknown");
}

void Lowering::support(ActionInfo& action, const std::vector<m::Statement>& list) {
    const auto check = [&](const m::Expr& e, bool consent_ok) {
        if (auto found = unsupported_in(e, &action, consent_ok, 0)) {
            unsupported(found->first, std::move(found->second));
        }
    };
    for (const m::Statement& s : list) {
        std::visit(Overloaded{
                       [&](const m::Requires& r) {
                           if (r.guard) {
                               check(*r.guard, false);
                           }
                           check(r.condition, true);
                       },
                       [&](const m::If& i) {
                           check(i.condition, false);
                           support(action, i.then);
                           support(action, i.otherwise);
                       },
                       [&](const m::Each& e) { unsupported(e.span, "kw.each"); },
                       [&](const m::Reject& r) {
                           if (r.message.starts_with("bo:")) {
                               error(r.span, "build.reject-text",
                                     {{"text", quote(source_, r.span)}});
                           }
                       },
                       [&](const m::Set& st) {
                           const std::string key = m::key(st.target.concept_entry, st.target.name);
                           if (st.target.refers != Refers::field || !field_index_.contains(key)) {
                               unsupported(st.span, feature_of(st.target.type));
                               return;
                           }
                           check(st.value, false);
                       },
                       [&](const m::Transition& t) {
                           ++action.transitions;
                           for (const m::Expr& f : t.from) {
                               if (!state_index_.contains(m::key(f.concept_entry, f.name))) {
                                   unsupported(f.span, "type.unknown");
                               }
                           }
                           if (!state_index_.contains(m::key(t.to.concept_entry, t.to.name))) {
                               unsupported(t.to.span, "type.unknown");
                           }
                       },
                       [&](const m::Do& d) {
                           const std::string key = m::key(d.action.concept_entry, d.action.name);
                           if (d.executor) {
                               error(d.span, "build.executor", {{"action", key}});
                           } else {
                               unsupported(d.span, key);
                           }
                       },
                   },
                   s.node);
    }
}

void Lowering::plan_actions() {
    creation_ = is(model_.kind, "kind.asset") ? "issue" : "create";
    std::set<std::string> names{creation_};
    for (const m::Action& a : model_.actions) {
        ActionInfo info;
        info.action = &a;
        info.key = m::key(a.word, a.name);
        info.wire = wire_name(a.word, a.name);
        if (a.executor) {
            error(a.span, "build.executor", {{"action", info.key}});
        } else if (a.word != nullptr) {
            error(a.span, "build.standard-action", {{"action", info.key}});
        }
        if (a.agents_propose) {
            unsupported(a.span, "actor.ai_agent");
        }
        if (!names.insert(info.wire).second) {
            error(a.span, "build.name-taken", {{"name", info.wire}});
        }
        name_check(info.wire, a.span, max_build_name);
        if (a.to && a.to->refers == Refers::party) {
            const std::string role = m::key(a.to->concept_entry, a.to->name);
            const auto it = role_index_.find(role);
            if (it != role_index_.end() &&
                roles_[it->second].party->binding == m::Binding::action &&
                roles_[it->second].party->bound_by == info.key) {
                info.binds = it->second;
            }
        }
        std::set<std::string> inputs;
        if (info.binds) {
            inputs.insert(roles_[*info.binds].wire);
        }
        for (const m::Field& input : a.inputs) {
            const std::string wire = wire_name(input.word, input.name);
            if (rep_of(input.type) == Rep::none) {
                unsupported(input.span, feature_of(input.type));
            }
            if (!inputs.insert(wire).second) {
                error(input.span, "build.name-taken", {{"name", wire}});
            }
            name_check(wire, input.span, max_build_name);
        }
        if (a.inputs.size() > max_build_inputs) {
            error(a.span, "build.too-many-inputs",
                  {{"action", info.key}, {"limit", std::to_string(max_build_inputs)}});
        }
        const auto check = [&](const m::Expr& e) {
            if (auto found = unsupported_in(e, &info, false, 0)) {
                unsupported(found->first, std::move(found->second));
            }
        };
        if (a.by) {
            check(*a.by);
        }
        for (const m::Consent& c : a.consents) {
            check(c.party);
        }
        support(info, a.body);
        if (info.transitions > max_build_events) {
            error(a.span, "build.too-many-events",
                  {{"action", info.key}, {"limit", std::to_string(max_build_events)}});
        }
        max_transitions_ = std::max(max_transitions_, info.transitions);
        actions_.push_back(std::move(info));
    }
    if (actions_.size() + 1 > max_build_functions) {
        error(Span{}, "build.too-many-functions", {{"limit", std::to_string(max_build_functions)}});
    }
}

/// The states an action can start from, by its top-level lines before
/// anything that may change the state: its first state change with FROM
/// states, and `requires STATE` (or STATE or STATE). Null: any state.
std::optional<std::set<std::string>> entry_states(const m::Action& a) {
    std::optional<std::set<std::string>> allowed;
    const auto narrow = [&](std::set<std::string> states) {
        if (!allowed) {
            allowed = std::move(states);
            return;
        }
        std::set<std::string> both;
        std::ranges::set_intersection(*allowed, states, std::inserter(both, both.begin()));
        allowed = std::move(both);
    };
    // The states a condition names when it is only states joined by `or`.
    const auto states_of = [](const m::Expr& e, std::set<std::string>& out, const auto& self) {
        if ((e.kind == ExprKind::word || e.kind == ExprKind::name) && e.refers == Refers::state) {
            out.insert(m::key(e.concept_entry, e.name));
            return true;
        }
        if (e.kind == ExprKind::binary && e.op == Operator::logical_or && e.operands.size() == 2) {
            return self(e.operands[0], out, self) && self(e.operands[1], out, self);
        }
        return false;
    };
    const auto changes = [](const std::vector<m::Statement>& list, const auto& self) -> bool {
        return std::ranges::any_of(list, [&](const m::Statement& s) {
            if (std::holds_alternative<m::Transition>(s.node)) {
                return true;
            }
            if (const auto* i = std::get_if<m::If>(&s.node)) {
                return self(i->then, self) || self(i->otherwise, self);
            }
            if (const auto* e = std::get_if<m::Each>(&s.node)) {
                return self(e->body, self);
            }
            return false;
        });
    };
    for (const m::Statement& s : a.body) {
        if (const auto* t = std::get_if<m::Transition>(&s.node)) {
            if (!t->from.empty()) {
                std::set<std::string> from;
                for (const m::Expr& f : t->from) {
                    from.insert(m::key(f.concept_entry, f.name));
                }
                narrow(std::move(from));
            }
            break;
        }
        if (const auto* r = std::get_if<m::Requires>(&s.node); r != nullptr && !r->guard) {
            std::set<std::string> states;
            if (states_of(r->condition, states, states_of)) {
                narrow(std::move(states));
            }
            continue;
        }
        if (changes(std::vector<m::Statement>{s}, changes)) {
            break;
        }
    }
    return allowed;
}

void Lowering::plan_finals() {
    // A state is final when no action can start from it.
    std::set<std::string> open;
    bool any = false;
    for (const m::Action& a : model_.actions) {
        const auto allowed = entry_states(a);
        if (!allowed) {
            any = true;
            break;
        }
        open.insert(allowed->begin(), allowed->end());
    }
    for (const m::State& s : model_.states) {
        const std::string key = m::key(s.word, s.name);
        states_[state_index_.at(key)].final = !any && !open.contains(key);
    }
}

void Lowering::plan() {
    if (model_.name.empty()) {
        error(Span{}, "build.fragment", {});
    }
    for (const m::TimeRule& r : model_.rules) {
        error(r.span, "build.time-rule", {{"text", quote(source_, r.span)}});
    }
    for (const m::Charge& c : model_.charges) {
        unsupported(c.span, c.kind != nullptr ? std::string(c.kind->id) : "charge.charge");
    }
    plan_fields();
    plan_roles();
    plan_states();
    plan_actions();
    if (!states_.empty()) {
        plan_finals();
    }
}

// ---------------------------------------------------------------------------
// Static data, typed reads, and refusals.

std::uint32_t Lowering::intern(const ByteView bytes) {
    if (!module_.interned(bytes) && bytes.size() + static_margin > module_.static_free()) {
        too_large_ = true;
        return rt::layout::static_base;
    }
    return module_.intern(bytes);
}

void Lowering::refuse(FunctionBuilder& b, const std::string_view reason) {
    b.u32(intern(reason)).u32(static_cast<std::uint32_t>(reason.size()));
    b.call(module_.host(wasm::Host::abort)).unreachable();
}

void Lowering::call_item(FunctionBuilder& b, const std::uint32_t key) {
    b.i32(0).load(i32_load, rt_.call_table() + 4 * key);
}

void Lowering::push_key(FunctionBuilder& b, const Bytes& key) {
    b.u32(intern(ByteView(key))).u32(static_cast<std::uint32_t>(key.size()));
}

/// The item on the stack, read as `rep`, or a refusal with `reason`.
void Lowering::expect(FunctionBuilder& b, const Rep rep, const std::string_view reason) {
    b.u32(intern(reason)).u32(static_cast<std::uint32_t>(reason.size()));
    switch (rep) {
    case Rep::i64:
        b.call(rt_.get(Routine::expect_int));
        return;
    case Rep::flag:
        b.call(rt_.get(Routine::expect_bool));
        return;
    case Rep::text:
        b.call(rt_.get(Routine::expect_text));
        return;
    case Rep::ledger:
        b.call(rt_.get(Routine::expect_ledger));
        return;
    case Rep::none:
        break;
    }
    BO_ASSERT(rep != Rep::none);
}

void Lowering::store(FunctionBuilder& b, const FieldSlot& slot) {
    if (slot.rep == Rep::text) {
        b.global_set(slot.second);
    }
    b.global_set(slot.first);
}

void Lowering::load(FunctionBuilder& b, const FieldSlot& slot) {
    b.global_get(slot.first);
    if (slot.rep == Rep::text) {
        b.global_get(slot.second);
    }
}

/// Writes the value on the stack.
void Lowering::out_value(FunctionBuilder& b, const Rep rep) {
    switch (rep) {
    case Rep::i64:
        b.call(rt_.get(Routine::out_int));
        return;
    case Rep::flag:
        b.call(rt_.get(Routine::out_bool));
        return;
    case Rep::text:
        b.call(rt_.get(Routine::out_text));
        return;
    case Rep::ledger:
        b.i32(32).call(rt_.get(Routine::out_bytes));
        return;
    case Rep::none:
        break;
    }
    BO_ASSERT(rep != Rep::none);
}

/// Writes the name of the state whose index is in `index`.
void Lowering::state_name(FunctionBuilder& b, const Local index) {
    b.get(index).i32(3).op(i32_shl).load(i32_load, state_table_);
    b.get(index).i32(3).op(i32_shl).load(i32_load, state_table_ + 4);
    b.call(rt_.get(Routine::out_raw));
}

// ---------------------------------------------------------------------------
// The second pass.

wasm::Func Lowering::load_instance() {
    if (load_instance_) {
        return *load_instance_;
    }
    const wasm::Func f = module_.declare({});
    load_instance_ = f;
    FunctionBuilder b = module_.begin(f);
    const Local instance = b.local(I32);
    const Local st = b.local(I32);
    const Local fields = b.local(I32);
    const Local parties = b.local(I32);
    const Local p = b.local(I32);
    const Local n = b.local(I32);
    const wasm::Func map_get = rt_.get(Routine::map_get);
    const std::string_view input = rt::text_of(rt::Reason::input);

    call_item(b, 5);
    b.tee(instance).op(i32_eqz);
    {
        const Label none = b.if_();
        b.call(rt_.fail(rt::Reason::input));
        b.end(none);
    }
    b.get(instance);
    push_key(b, uint_key(3));
    b.call(map_get).set(st);
    // The state, by name.
    b.get(st);
    push_key(b, text_cbor("state"));
    b.call(map_get);
    expect(b, Rep::text, input);
    b.set(n).set(p);
    {
        const Label found = b.block();
        for (std::size_t i = 0; i < states_.size(); ++i) {
            const std::string& wire = states_[i].wire;
            b.get(p).get(n).u32(intern(wire)).u32(static_cast<std::uint32_t>(wire.size()));
            b.call(rt_.get(Routine::bytes_eq));
            const Label same = b.if_();
            b.u32(static_cast<std::uint32_t>(i)).global_set(state_).br(found);
            b.end(same);
        }
        b.call(rt_.fail(rt::Reason::input));
        b.end(found);
    }
    b.get(st);
    push_key(b, text_cbor("fields"));
    b.call(map_get).set(fields);
    for (const FieldSlot& slot : fields_) {
        b.get(fields);
        push_key(b, slot.key);
        b.call(map_get);
        expect(b, slot.rep, input);
        store(b, slot);
    }
    b.get(instance);
    push_key(b, uint_key(5));
    b.call(map_get).set(parties);
    for (const RoleSlot& role : roles_) {
        b.get(parties);
        push_key(b, role.key);
        b.call(map_get).tee(p);
        const Label bound = b.if_();
        b.get(p);
        expect(b, Rep::ledger, input);
        b.global_set(role.ledger);
        b.end(bound);
    }
    module_.define(std::move(b));
    return f;
}

wasm::Func Lowering::write_accept() {
    if (write_accept_) {
        return *write_accept_;
    }
    const wasm::Func f = module_.declare({});
    write_accept_ = f;
    FunctionBuilder b = module_.begin(f);
    const Local final = b.local(I32);
    const Local parties = b.local(I32);
    const Local events = b.local(I32);
    const Local index = b.local(I32);
    const Local i = b.local(I32);
    const Local count = b.local(I64);
    const Local mark = b.local(I32);
    const wasm::Func head = rt_.get(Routine::out_head);
    const wasm::Func out_int = rt_.get(Routine::out_int);
    const wasm::Func out_raw = rt_.get(Routine::out_raw);

    b.global_get(state_).set(index);
    b.get(index).load(i32_load8_u, final_table_).set(final);
    std::size_t party_fields = 0;
    for (const FieldSlot& slot : fields_) {
        party_fields += slot.rep == Rep::ledger ? 1 : 0;
    }
    b.u32(static_cast<std::uint32_t>(party_fields)).set(parties);
    for (const RoleSlot& role : roles_) {
        b.global_get(role.ledger).op(i32_eqz).op(i32_eqz).get(parties).op(i32_add).set(parties);
    }
    b.global_get(events_).set(events);
    // [1, {1: state, 2: status, ? 3: parties, ? 4: events, ? 5: true}]
    b.i32(4).i64(2).call(head);
    b.i64(1).call(out_int);
    b.i32(2).get(parties).op(i32_eqz).op(i32_eqz).op(i32_add);
    b.get(events).op(i32_eqz).op(i32_eqz).op(i32_add).get(final).op(i32_add);
    b.op(i64_extend_i32_u).set(count);
    b.i32(5).get(count).call(head);
    // 1: {"state": NAME, "fields": {...}}, keys in canonical order.
    b.i64(1).call(out_int);
    b.global_get(rt_.var(rt::Var::out)).set(mark);
    b.i32(5).i64(2).call(head);
    push_key(b, text_cbor("state"));
    b.call(out_raw);
    state_name(b, index);
    push_key(b, text_cbor("fields"));
    b.call(out_raw);
    b.i32(5).i64(static_cast<std::int64_t>(fields_.size())).call(head);
    std::vector<const FieldSlot*> sorted;
    for (const FieldSlot& slot : fields_) {
        sorted.push_back(&slot);
    }
    std::ranges::sort(sorted, {}, &FieldSlot::key);
    for (const FieldSlot* slot : sorted) {
        push_key(b, slot->key);
        b.call(out_raw);
        load(b, *slot);
        out_value(b, slot->rep);
    }
    // A state holds at most 64 KiB (spec section 15).
    b.global_get(rt_.var(rt::Var::out)).get(mark).op(i32_sub);
    b.u32(static_cast<std::uint32_t>(max_state_size)).op(i32_gt_u);
    {
        const Label large = b.if_();
        b.call(rt_.fail(rt::Reason::output));
        b.end(large);
    }
    // 2: the status, the state's name.
    b.i64(2).call(out_int);
    state_name(b, index);
    // 3: the parties bound so far, and the fields holding one.
    b.get(parties);
    {
        const Label some = b.if_();
        b.i64(3).call(out_int);
        b.i32(5).get(parties).op(i64_extend_i32_u).call(head);
        std::vector<std::pair<const Bytes*, std::pair<wasm::Global, bool>>> entries;
        for (const RoleSlot& role : roles_) {
            entries.push_back({&role.key, {role.ledger, true}});
        }
        for (const FieldSlot& slot : fields_) {
            if (slot.rep == Rep::ledger) {
                entries.push_back({&slot.key, {slot.first, false}});
            }
        }
        std::ranges::sort(entries,
                          [](const auto& x, const auto& y) { return *x.first < *y.first; });
        for (const auto& [key, ledger] : entries) {
            const auto& [global, maybe_unbound] = ledger;
            std::optional<Label> bound;
            if (maybe_unbound) {
                b.global_get(global);
                bound = b.if_();
            }
            push_key(b, *key);
            b.call(out_raw);
            b.global_get(global);
            out_value(b, Rep::ledger);
            if (bound) {
                b.end(*bound);
            }
        }
        b.end(some);
    }
    // 4: each state change: [state, null].
    b.get(events);
    {
        const Label some = b.if_();
        b.i64(4).call(out_int);
        b.i32(4).get(events).op(i64_extend_i32_u).call(head);
        const Label done = b.block();
        const Label next = b.loop();
        b.get(i).get(events).op(i32_ge_u).br_if(done);
        b.i32(4).i64(2).call(head);
        b.get(i).i32(2).op(i32_shl).load(i32_load, events_area_).set(index);
        state_name(b, index);
        b.call(rt_.get(Routine::out_null));
        b.get(i).i32(1).op(i32_add).set(i).br(next);
        b.end(next);
        b.end(done);
        b.end(some);
    }
    // 5: final.
    b.get(final);
    {
        const Label last = b.if_();
        b.i64(5).call(out_int);
        b.i32(1).call(rt_.get(Routine::out_bool));
        b.end(last);
    }
    b.call(rt_.get(Routine::out_finish));
    module_.define(std::move(b));
    return f;
}

void Lowering::finish(FunctionBuilder& b) {
    b.global_get(rt_.var(rt::Var::needs));
    const Label needs = b.if_();
    b.call(rt_.get(Routine::out_needs)).call(rt_.get(Routine::out_finish));
    b.else_(needs);
    b.call(write_accept());
    b.end(needs);
}

void Lowering::record_event(FunctionBuilder& b, const std::size_t state) {
    b.global_get(events_).i32(2).op(i32_shl).u32(static_cast<std::uint32_t>(state));
    b.store(i32_store, events_area_);
    b.global_get(events_).i32(1).op(i32_add).global_set(events_);
}

void Lowering::emit_entry(const wasm::Func entry) {
    FunctionBuilder b = module_.begin(entry);
    const Local p = b.local(I32);
    const Local n = b.local(I32);
    b.call(rt_.get(Routine::read_call)).op(drop);
    call_item(b, 1);
    expect(b, Rep::text, rt::text_of(rt::Reason::input));
    b.set(n).set(p);
    std::vector<std::pair<std::string, wasm::Func>> functions{{creation_, creation_function_}};
    for (const ActionInfo& a : actions_) {
        functions.emplace_back(a.wire, a.function);
    }
    std::ranges::sort(functions, {}, &std::pair<std::string, wasm::Func>::first);
    for (const auto& [name, f] : functions) {
        b.get(p).get(n).u32(intern(name)).u32(static_cast<std::uint32_t>(name.size()));
        b.call(rt_.get(Routine::bytes_eq));
        const Label same = b.if_();
        b.call(f).return_();
        b.end(same);
    }
    refuse(b, "bo:function");
    module_.define(std::move(b));
}

void Lowering::emit_creation(const wasm::Func f) {
    FunctionBuilder b = module_.begin(f);
    const Local args = b.local(I32);
    const Local map = b.local(I32);
    const wasm::Func map_get = rt_.get(Routine::map_get);
    const wasm::Func head_arg = rt_.get(Routine::head_arg);
    std::vector<const RoleSlot*> roles;
    for (const RoleSlot& role : roles_) {
        if (role.party->binding == m::Binding::creation) {
            roles.push_back(&role);
        }
    }
    std::vector<const FieldSlot*> fields;
    for (const FieldSlot& slot : fields_) {
        if (!slot.starts_with) {
            fields.push_back(&slot);
        }
    }
    call_item(b, 2);
    b.set(args);
    const std::int64_t keys = (roles.empty() ? 0 : 1) + (fields.empty() ? 0 : 1);
    if (keys == 0) {
        // Null, or an empty map.
        b.get(args).load(i32_load8_u).u32(0xF6).op(i32_ne);
        b.get(args).load(i32_load8_u).u32(0xA0).op(i32_ne).op(i32_and);
        const Label other = b.if_();
        refuse(b, "bo:arguments");
        b.end(other);
    } else {
        b.get(args).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne);
        b.get(args).call(head_arg).i64(keys).op(i64_ne).op(i32_or);
        const Label other = b.if_();
        refuse(b, "bo:arguments");
        b.end(other);
    }
    // A map with exactly these keys, or a refusal with `reason`.
    const auto part = [&](std::string_view name, std::size_t count) {
        const std::string reason = "bo:argument " + std::string(name);
        b.get(args);
        push_key(b, text_cbor(name));
        b.call(map_get).tee(map);
        b.load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne);
        b.get(map).op(i32_eqz).op(i32_or);
        b.get(map).call(head_arg).i64(static_cast<std::int64_t>(count)).op(i64_ne).op(i32_or);
        const Label other = b.if_();
        refuse(b, reason);
        b.end(other);
    };
    if (!fields.empty()) {
        part("fields", fields.size());
        for (const FieldSlot* slot : fields) {
            b.get(map);
            push_key(b, slot->key);
            b.call(map_get);
            expect(b, slot->rep, "bo:argument " + slot->wire);
            store(b, *slot);
        }
    }
    if (!roles.empty()) {
        part("parties", roles.size());
        for (const RoleSlot* role : roles) {
            b.get(map);
            push_key(b, role->key);
            b.call(map_get);
            expect(b, Rep::ledger, "bo:argument " + role->wire);
            b.global_set(role->ledger);
        }
    }
    // R2: party fields start with their role.
    for (const FieldSlot& slot : fields_) {
        if (slot.starts_with) {
            b.global_get(roles_[*slot.starts_with].ledger).global_set(slot.first);
        }
    }
    b.i32(0).global_set(state_);
    record_event(b, 0);
    b.call(write_accept());
    module_.define(std::move(b));
}

void Lowering::arguments(Ctx& c) {
    FunctionBuilder& b = *c.b;
    const m::Action& a = *c.action->action;
    const Local args = b.local(I32);
    const wasm::Func map_get = rt_.get(Routine::map_get);
    call_item(b, 2);
    b.set(args);
    if (a.inputs.empty() && !c.action->binds) {
        b.get(args).load(i32_load8_u).u32(0xF6).op(i32_ne);
        b.get(args).load(i32_load8_u).u32(0xA0).op(i32_ne).op(i32_and);
        const Label other = b.if_();
        refuse(b, "bo:arguments");
        b.end(other);
        return;
    }
    const Local given = b.local(I32);
    if (c.action->binds) {
        b.get(args);
        push_key(b, roles_[*c.action->binds].key);
        b.call(map_get).set(given);
    }
    // A map of the inputs and the role it binds, if given; null for none.
    const Local is_map = b.local(I32);
    b.get(args).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_eq).tee(is_map);
    b.op(i32_eqz).get(args).load(i32_load8_u).u32(0xF6).op(i32_ne).op(i32_and);
    {
        const Label other = b.if_();
        refuse(b, "bo:arguments");
        b.end(other);
    }
    b.get(is_map);
    {
        const Label count = b.if_(I64);
        b.get(args).call(rt_.get(Routine::head_arg));
        b.else_(count);
        b.i64(0);
        b.end(count);
    }
    b.i64(static_cast<std::int64_t>(a.inputs.size()));
    b.get(given).op(i32_eqz).op(i32_eqz).op(i64_extend_i32_u).op(i64_add);
    b.op(i64_ne);
    {
        const Label other = b.if_();
        refuse(b, "bo:arguments");
        b.end(other);
    }
    for (const m::Field& input : a.inputs) {
        const std::string wire = wire_name(input.word, input.name);
        const Rep rep = rep_of(input.type);
        const Local value = b.local(rep == Rep::i64 ? I64 : I32);
        const Local length = rep == Rep::text ? b.local(I32) : value;
        b.get(args);
        push_key(b, text_cbor(wire));
        b.call(map_get);
        expect(b, rep, "bo:argument " + wire);
        if (rep == Rep::text) {
            b.set(length);
        }
        b.set(value);
        c.inputs.emplace(m::key(input.word, input.name), std::pair{value, length});
    }
    if (c.action->binds) {
        // R3: the role is bound now, by the argument under its name; once
        // bound, the argument may repeat it.
        const RoleSlot& role = roles_[*c.action->binds];
        const std::string reason = "bo:argument " + role.wire;
        b.global_get(role.ledger).op(i32_eqz);
        const Label unbound = b.if_();
        b.get(given).op(i32_eqz);
        {
            const Label missing = b.if_();
            refuse(b, reason);
            b.end(missing);
        }
        b.get(given);
        expect(b, Rep::ledger, reason);
        b.global_set(role.ledger);
        b.else_(unbound);
        b.get(given);
        {
            const Label repeated = b.if_();
            b.get(given);
            expect(b, Rep::ledger, reason);
            b.i32(32).global_get(role.ledger).i32(32).call(rt_.get(Routine::bytes_eq));
            b.op(i32_eqz);
            const Label other = b.if_();
            refuse(b, reason);
            b.end(other);
            b.end(repeated);
        }
        b.end(unbound);
    }
}

void Lowering::emit_action(const ActionInfo& info) {
    FunctionBuilder b = module_.begin(info.function);
    Ctx c;
    c.b = &b;
    c.action = &info;
    c.signer = b.local(I32);
    c.t32 = b.local(I32);
    c.t64 = b.local(I64);
    c.t64b = b.local(I64);
    const m::Action& a = *info.action;
    b.call(load_instance());
    arguments(c);
    const wasm::Func consent = rt_.get(Routine::consent);
    // The starter agrees through the call (the home) or its consent.
    if (a.by) {
        value(c, *a.by);
        b.call(consent).set(c.signer);
    }
    // R3, R8: the consents the action needs.
    for (const m::Consent& k : a.consents) {
        value(c, k.party);
        b.call(consent).op(drop);
    }
    statements(c, a.body);
    finish(b);
    module_.define(std::move(b));
}

void Lowering::statements(Ctx& c, const std::vector<m::Statement>& list) {
    FunctionBuilder& b = *c.b;
    for (const m::Statement& s : list) {
        if (b.size() > body_budget) {
            too_large_ = true;
            return;
        }
        std::visit(
            Overloaded{
                [&](const m::Requires& r) { requirement(c, r); },
                [&](const m::If& i) {
                    value(c, i.condition);
                    const Label then = b.if_();
                    statements(c, i.then);
                    if (!i.otherwise.empty()) {
                        b.else_(then);
                        statements(c, i.otherwise);
                    }
                    b.end(then);
                },
                [&](const m::Each&) { BO_ASSERT(false); },
                [&](const m::Reject& r) { refuse(b, r.message); },
                [&](const m::Set& st) {
                    const FieldSlot& slot =
                        fields_[field_index_.at(m::key(st.target.concept_entry, st.target.name))];
                    value(c, st.value);
                    store(b, slot);
                },
                [&](const m::Transition& t) { transition(c, t); },
                [&](const m::Do&) { BO_ASSERT(false); },
            },
            s.node);
    }
}

void Lowering::requirement(Ctx& c, const m::Requires& r) {
    FunctionBuilder& b = *c.b;
    const std::uint32_t number = ++c.requires_count;
    std::optional<Label> guard;
    if (r.guard) {
        value(c, *r.guard);
        guard = b.if_();
    }
    const m::Expr& e = r.condition;
    if (e.kind == ExprKind::apply && is(e.concept_entry, "cond.consent_of")) {
        // Asks for the consent; a missing one leaves the call needing it.
        value(c, e.operands[0]);
        b.call(rt_.get(Routine::consent)).op(drop);
    } else if (e.kind == ExprKind::word && is(e.concept_entry, "cond.in_person")) {
        // R13: the starter's signer, once its consent is there.
        b.get(c.signer);
        const Label known = b.if_();
        b.get(c.signer).call(rt_.get(Routine::in_person)).op(i32_eqz);
        const Label absent = b.if_();
        refuse(b, "bo:in-person " + c.action->wire);
        b.end(absent);
        b.end(known);
    } else {
        value(c, e);
        b.op(i32_eqz);
        const Label failed = b.if_();
        const std::string prefix = "bo:requires " + c.action->wire + " ";
        b.u32(intern(prefix)).u32(static_cast<std::uint32_t>(prefix.size())).i64(number);
        b.call(rt_.get(Routine::fail_numbered)).unreachable();
        b.end(failed);
    }
    if (guard) {
        b.end(*guard);
    }
}

void Lowering::transition(Ctx& c, const m::Transition& t) {
    FunctionBuilder& b = *c.b;
    if (!t.from.empty()) {
        for (std::size_t i = 0; i < t.from.size(); ++i) {
            const std::size_t from =
                state_index_.at(m::key(t.from[i].concept_entry, t.from[i].name));
            b.global_get(state_).u32(static_cast<std::uint32_t>(from)).op(i32_eq);
            if (i > 0) {
                b.op(i32_or);
            }
        }
        b.op(i32_eqz);
        const Label other = b.if_();
        refuse(b, "bo:state " + c.action->wire);
        b.end(other);
    }
    const std::size_t to = state_index_.at(m::key(t.to.concept_entry, t.to.name));
    b.u32(static_cast<std::uint32_t>(to)).global_set(state_);
    record_event(b, to);
}

void Lowering::in_person(Ctx& c) {
    // While the starter's consent is missing, the call needs it anyway.
    FunctionBuilder& b = *c.b;
    b.get(c.signer).op(i32_eqz);
    const Label missing = b.if_(I32);
    b.i32(1);
    b.else_(missing);
    b.get(c.signer).call(rt_.get(Routine::in_person));
    b.end(missing);
}

void Lowering::reference(Ctx& c, const m::Expr& e) {
    FunctionBuilder& b = *c.b;
    const std::string key = m::key(e.concept_entry, e.name);
    switch (e.refers) {
    case Refers::field:
        if (const m::Field* k = constant(key)) {
            ++c.depth;
            value(c, *k->value);
            --c.depth;
            return;
        }
        load(b, fields_[field_index_.at(key)]);
        return;
    case Refers::input: {
        const auto& [first, second] = c.inputs.at(key);
        b.get(first);
        if (rep_of(e.type) == Rep::text) {
            b.get(second);
        }
        return;
    }
    case Refers::party: {
        const RoleSlot& role = roles_[role_index_.at(key)];
        b.global_get(role.ledger).tee(c.t32).op(i32_eqz);
        const Label unbound = b.if_();
        refuse(b, "bo:party " + role.wire);
        b.end(unbound);
        b.get(c.t32);
        return;
    }
    case Refers::state:
        // R7: the instance is in that state.
        b.global_get(state_).u32(static_cast<std::uint32_t>(state_index_.at(key))).op(i32_eq);
        return;
    case Refers::item:
    case Refers::action:
    case Refers::none:
        break;
    }
    if (is(e.concept_entry, "val.yes") || is(e.concept_entry, "val.no")) {
        b.i32(is(e.concept_entry, "val.yes") ? 1 : 0);
        return;
    }
    if (is(e.concept_entry, "time.now") || is(e.concept_entry, "time.today")) {
        call_item(b, 7);
        expect(b, Rep::i64, rt::text_of(rt::Reason::input));
        if (is(e.concept_entry, "time.today")) {
            // The local midnight that starts the day (U6).
            b.tee(c.t64).i64(default_offset_ms).call(rt_.get(Routine::local_days));
            b.set(c.t64b).op(drop);
            b.get(c.t64).get(c.t64b).op(i64_sub);
        }
        return;
    }
    if (is(e.concept_entry, "cond.in_person")) {
        in_person(c);
        return;
    }
    BO_ASSERT(false);
}

void Lowering::value(Ctx& c, const m::Expr& e) {
    FunctionBuilder& b = *c.b;
    switch (e.kind) {
    case ExprKind::literal:
        if (e.literal.kind == ast::LiteralKind::text) {
            b.u32(intern(e.literal.text)).u32(static_cast<std::uint32_t>(e.literal.text.size()));
        } else {
            b.i64(literal_value(e.literal).value_or(0));
        }
        return;
    case ExprKind::name:
    case ExprKind::word:
        reference(c, e);
        return;
    case ExprKind::apply: {
        // cond.over (R6): the action's amount is over the threshold.
        const std::string amount = *amount_of(*c.action);
        m::Expr ref;
        ref.kind = ExprKind::name;
        if (amount == "field.amount") {
            ref.kind = ExprKind::word;
            ref.concept_entry = find_concept("field.amount");
            ref.refers = Refers::field;
        } else {
            for (const m::Field& input : c.action->action->inputs) {
                if (m::key(input.word, input.name) == amount) {
                    ref.kind = input.word != nullptr ? ExprKind::word : ExprKind::name;
                    ref.concept_entry = input.word;
                    ref.name = input.name;
                    ref.type = input.type;
                }
            }
            ref.refers = Refers::input;
        }
        reference(c, ref);
        value(c, e.operands[0]);
        b.op(i64_gt_s);
        return;
    }
    case ExprKind::unary:
        value(c, e.operands[0]);
        b.op(i32_eqz);
        return;
    case ExprKind::binary:
        binary(c, e);
        return;
    case ExprKind::phrase:
    case ExprKind::list:
        break;
    }
    BO_ASSERT(false);
}

void Lowering::binary(Ctx& c, const m::Expr& e) {
    FunctionBuilder& b = *c.b;
    const m::Expr& x = e.operands[0];
    const m::Expr& y = e.operands[1];
    switch (e.op) {
    case Operator::logical_and: {
        value(c, x);
        const Label both = b.if_(I32);
        value(c, y);
        b.else_(both);
        b.i32(0);
        b.end(both);
        return;
    }
    case Operator::logical_or: {
        value(c, x);
        const Label either = b.if_(I32);
        b.i32(1);
        b.else_(either);
        value(c, y);
        b.end(either);
        return;
    }
    case Operator::equals:
    case Operator::less:
    case Operator::less_equal:
    case Operator::greater:
    case Operator::greater_equal: {
        const Rep rep = rep_of(x.type);
        value(c, x);
        if (rep == Rep::ledger) {
            b.i32(32);
        }
        value(c, y);
        if (rep == Rep::ledger) {
            b.i32(32);
        }
        if (rep == Rep::text || rep == Rep::ledger) {
            b.call(rt_.get(Routine::bytes_eq));
            return;
        }
        if (rep == Rep::flag) {
            b.op(i32_eq);
            return;
        }
        switch (e.op) {
        case Operator::equals:
            b.op(i64_eq);
            return;
        case Operator::less:
            b.op(i64_lt_s);
            return;
        case Operator::less_equal:
            b.op(i64_le_s);
            return;
        case Operator::greater:
            b.op(i64_gt_s);
            return;
        default:
            b.op(i64_ge_s);
            return;
        }
    }
    default:
        arithmetic(c, e);
        return;
    }
}

void Lowering::arithmetic(Ctx& c, const m::Expr& e) {
    FunctionBuilder& b = *c.b;
    const m::Expr& x = e.operands[0];
    const m::Expr& y = e.operands[1];
    const TypeKind xk = x.type.kind;
    const TypeKind yk = y.type.kind;
    const auto muldiv = [&] {
        b.i32(round_half_up).call(rt_.get(Routine::muldiv));
    };
    switch (e.op) {
    case Operator::plus:
    case Operator::minus:
        if (xk == TypeKind::date && yk == TypeKind::duration && y.type.calendar) {
            value(c, x);
            value(c, y);
            if (e.op == Operator::minus) {
                b.call(rt_.get(Routine::neg));
            }
            b.i64(default_offset_ms).call(rt_.get(Routine::add_months));
            return;
        }
        if (xk == TypeKind::duration && yk == TypeKind::date && x.type.calendar) {
            value(c, y);
            value(c, x);
            b.i64(default_offset_ms).call(rt_.get(Routine::add_months));
            return;
        }
        value(c, x);
        value(c, y);
        b.call(rt_.get(e.op == Operator::plus ? Routine::add : Routine::sub));
        return;
    case Operator::times:
        if (xk == TypeKind::rate && yk != TypeKind::number) {
            // R17: rounded half up.
            value(c, y);
            value(c, x);
            b.i64(rate_one);
            muldiv();
            return;
        }
        if (yk == TypeKind::rate && xk != TypeKind::number) {
            value(c, x);
            value(c, y);
            b.i64(rate_one);
            muldiv();
            return;
        }
        value(c, x);
        value(c, y);
        b.call(rt_.get(Routine::mul));
        return;
    case Operator::divide:
        if (yk == TypeKind::number) {
            value(c, x);
            b.i64(1);
            value(c, y);
            muldiv();
            return;
        }
        // Money by money, or a quantity by one: a rate.
        value(c, x);
        b.i64(rate_one);
        value(c, y);
        muldiv();
        return;
    default:
        break;
    }
    BO_ASSERT(false);
}

void Lowering::emit() {
    // Static data first, in a fixed order.
    state_ = module_.add_global(I32, 0);
    events_ = module_.add_global(I32, 0);
    for (FieldSlot& slot : fields_) {
        slot.first = module_.add_global(slot.rep == Rep::i64 ? I64 : I32, 0);
        if (slot.rep == Rep::text) {
            slot.second = module_.add_global(I32, 0);
        }
    }
    for (RoleSlot& role : roles_) {
        role.ledger = module_.add_global(I32, 0);
    }
    events_area_ = module_.reserve(static_cast<std::uint32_t>(4 * max_transitions_), 4);
    Bytes names;
    Bytes finals;
    for (const StateSlot& s : states_) {
        const std::uint32_t at = intern(ByteView(s.encoded));
        for (const std::uint32_t v : {at, static_cast<std::uint32_t>(s.encoded.size())}) {
            for (unsigned shift = 0; shift < 32; shift += 8) {
                names.push_back(static_cast<std::uint8_t>(v >> shift));
            }
        }
        finals.push_back(s.final ? 1 : 0);
    }
    state_table_ = intern(ByteView(names));
    final_table_ = intern(ByteView(finals));

    // Functions: the entry, the creation, the actions, in the model's order.
    const wasm::Func entry = module_.declare({});
    creation_function_ = module_.declare({});
    for (ActionInfo& a : actions_) {
        a.function = module_.declare({});
    }
    emit_entry(entry);
    emit_creation(creation_function_);
    for (const ActionInfo& a : actions_) {
        emit_action(a);
    }
    module_.entry(entry);
}

Lowered Lowering::run() {
    plan();
    Lowered out;
    if (has_errors(diagnostics_)) {
        out.diagnostics = std::move(diagnostics_);
        return out;
    }
    emit();
    if (too_large_) {
        out.diagnostics.push_back(Diagnostic{"build.too-large", {}, Span{}});
        return out;
    }
    auto code = module_.finish();
    // Every module the emitter writes loads; anything else is a bug here.
    BO_ASSERT(code.has_value());
    Build build;
    build.code = std::move(*code);
    build.interface.emplace(creation_, protocol::FunctionKind::create);
    for (const ActionInfo& a : actions_) {
        build.interface.emplace(a.wire, protocol::FunctionKind::call);
    }
    out.build = std::move(build);
    return out;
}

} // namespace

Lowered lower(const std::string_view source, const model::Model& model) {
    return Lowering(source, model).run();
}

} // namespace cexchain::bo
