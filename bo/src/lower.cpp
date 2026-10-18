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
#include <functional>
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
#include <cexchain/core/vm.hpp>

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
    list,   ///< a CBOR array of items of one of the above: its address and length (i32 each)
};

/// True for a representation held as two i32s: an address and a length.
bool pair_rep(const Rep rep) noexcept {
    return rep == Rep::text || rep == Rep::list;
}

Rep rep_of(const m::Type& t) noexcept;

/// How compiled code holds a list's items (Rep::none if it cannot).
Rep element_rep(const m::Type& t) noexcept {
    if (t.kind != TypeKind::list || t.element.size() != 1) {
        return Rep::none;
    }
    const Rep rep = rep_of(t.element.front());
    return rep == Rep::list ? Rep::none : rep;
}

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
    case TypeKind::list:
        return element_rep(t) != Rep::none ? Rep::list : Rep::none;
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

/// A CBOR head in its shortest form.
void put_head(Bytes& out, const std::uint8_t major, const std::uint64_t n) {
    const auto top = static_cast<std::uint8_t>(major << 5U);
    if (n < 24) {
        out.push_back(static_cast<std::uint8_t>(top | n));
        return;
    }
    int width = 8;
    std::uint8_t info = 27;
    if (n < 0x100) {
        width = 1;
        info = 24;
    } else if (n < 0x1'0000) {
        width = 2;
        info = 25;
    } else if (n < 0x1'0000'0000) {
        width = 4;
        info = 26;
    }
    out.push_back(static_cast<std::uint8_t>(top | info));
    for (int shift = 8 * (width - 1); shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(n >> static_cast<unsigned>(shift)));
    }
}

/// A signed integer's CBOR encoding.
void put_int(Bytes& out, const std::int64_t v) {
    if (v >= 0) {
        put_head(out, 0, static_cast<std::uint64_t>(v));
    } else {
        put_head(out, 1, static_cast<std::uint64_t>(-(v + 1)));
    }
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
/// The most bytes a text or a list read from the input may take: the state,
/// and the arguments, hold at most 64 KiB each (spec section 15).
constexpr std::uint64_t max_value_size = 65'536;
/// The most entries of maps the code searches: the instance view (spec
/// section 15), the state ("bill", "fired", "since", "state", "fields",
/// "pending", "previous"), a bill ("time", "lines", "price", "total",
/// "charges"), and a signer (kind, presence, model).
constexpr std::uint64_t view_keys = 6;
/// Regions of code that only some functions can reach (cost.hpp): writing
/// the parts a call issues, and a bill a call makes.
constexpr std::uint32_t region_parts = 1;
constexpr std::uint32_t region_bill = 2;
constexpr std::uint64_t state_keys = 7;
constexpr std::uint64_t bill_keys = 5;
constexpr std::uint64_t signer_keys = 3;

/// R17: products and quotients round half up.
constexpr std::int32_t round_half_up = static_cast<std::int32_t>(rt::Rounding::half_up);
/// R32: a duration by a duration drops the rest (toward zero).
constexpr std::int32_t round_down = static_cast<std::int32_t>(rt::Rounding::down);

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
    /// A party field that may hold no party (its ledger's address is 0
    /// then, and the state holds null).
    bool optional = false;
    /// R20: not given at creation; each instance starts with none.
    bool empty_at_start = false;
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
    /// AI agents may only propose it: `function` reads the call and runs
    /// `core`, which `approve` runs too, with the proposal's arguments.
    wasm::Func core{};
    /// Only time rules do it: no function of its own.
    bool rule_only = false;
    /// It issues parts (R30): a part at depth 8 cannot do it.
    bool parts = false;
};

/// A field each part gets as `with` sets it (R30): its value, computed on
/// the instance that issues the parts, and whether this call gave it.
struct PartField {
    wasm::Global first{};
    wasm::Global second{};
    wasm::Global given{};
};

/// A time rule with code (R24): its function, the time it applies at, and
/// the time it last applied for.
struct RuleInfo {
    const m::TimeRule* rule = nullptr;
    std::string wire;
    Bytes key;
    m::Trigger trigger;
    std::size_t transitions = 0;
    wasm::Func function{};
    /// The time it last applied for (i64), and whether it has (i32).
    wasm::Global fired{};
    wasm::Global fired_set{};
};

/// A charge (R26, R27): its name, and what compiled code keeps of it while
/// a call runs: whether it applies to the bill, the rate in force, its amount
/// on the bill, and (for one on each line) its amount on the current line.
struct ChargeInfo {
    const m::Charge* charge = nullptr;
    std::string wire;
    Bytes key;
    wasm::Global applies{};
    wasm::Global rate{};
    wasm::Global amount{};
    wasm::Global line{};
};

/// How much of the input reading a call's input meets: items, and map keys
/// among them (runtime::read_input_fuel).
struct Shape {
    std::uint64_t items = 0;
    std::uint64_t keys = 0;

    Shape& operator+=(const Shape& o) {
        items = wasm::add_saturating(items, o.items);
        keys = wasm::add_saturating(keys, o.keys);
        return *this;
    }
    friend Shape operator+(Shape a, const Shape& b) { return a += b; }
    friend Shape operator*(const std::uint64_t n, const Shape& a) {
        return {wasm::mul_saturating(n, a.items), wasm::mul_saturating(n, a.keys)};
    }
};

/// A value of a type, as the input holds it: one item, or a list's items.
Shape value_shape(const m::Type& t) {
    return t.kind == TypeKind::list ? Shape{1 + std::uint64_t{t.bound}, 0} : Shape{1, 0};
}

/// A map's head and its keys.
Shape map_shape(const std::uint64_t keys) {
    return {1 + keys, keys};
}

/// One function being written.
struct Ctx {
    FunctionBuilder* b = nullptr;
    /// The action whose lines are written; null for a time rule's own.
    const ActionInfo* action = nullptr;
    /// Whose refusals they are: the action's or the time rule's function.
    std::string wire;
    /// The arguments' item, for an action's core (a parameter); otherwise
    /// the call's (input key 2).
    std::optional<Local> args;
    /// Inputs by key: the value's local, and a text's length.
    std::map<std::string, std::pair<Local, Local>> inputs;
    /// The starter's signer (0 while its consent is missing).
    Local signer{};
    Local t32{};
    Local t64{};
    Local t64b{};
    std::uint32_t requires_count = 0;
    int depth = 0;
    /// The items `each` names: the value's local, and a text's length.
    std::map<std::string, std::pair<Local, Local>> items;
    /// Locals of the `each` loops, by depth (shared by loops one after
    /// another): where the next item is, how many are left, and the item.
    struct Loop {
        Local p{};
        Local n{};
        Local v64{};
        Local a{};
        Local b{};
    };
    std::vector<Loop> loops;
    /// The size of each text item an `each` names, for what comparing it
    /// costs (the loop's items, cost.hpp).
    std::map<std::string, wasm::Size> item_sizes;
    /// Two scratch locals, shared by every comparison of parties that may
    /// be none and every `consent of` a list (from codegen 2 on; codegen 1 took two
    /// new ones each time, so that thousands could exceed the 4,096 locals
    /// a function may have).
    std::optional<std::pair<Local, Local>> scratch;
    /// In the reply function (E8): whether the instance had ended before the
    /// answer (its state changes and requests are then skipped), and the
    /// answer's result and reason, texts (empty when it gives none).
    bool answer = false;
    Local final_before{};
    Local result_p{};
    Local result_n{};
    Local reason_p{};
    Local reason_n{};
};

class Lowering {
public:
    Lowering(std::string_view source, const m::Model& model, const std::uint32_t codegen)
        : source_(source), model_(model), codegen_(codegen), module_(rt::memory_plan()),
          rt_(module_, codegen) {}

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
    void plan_rules();
    void plan_charges();
    void plan_finals();
    void plan_answers();
    [[nodiscard]] std::optional<std::pair<Span, std::string>>
    unsupported_in(const m::Expr& e, const ActionInfo* action, bool consent_ok, int depth) const;
    void support(ActionInfo& action, const std::vector<m::Statement>& list, bool rule = false);
    [[nodiscard]] const ActionInfo* action_info(const m::Do& d) const;
    [[nodiscard]] const m::Field* constant(const std::string& key) const;
    [[nodiscard]] std::optional<std::string> amount_of(const ActionInfo& action) const;
    void name_check(const std::string& wire, const Span& span, std::size_t limit);

    // --- Static data and refusals.
    [[nodiscard]] std::uint32_t intern(ByteView bytes);
    [[nodiscard]] std::uint32_t intern(std::string_view text) { return intern(as_bytes(text)); }
    void refuse(FunctionBuilder& b, std::string_view reason);
    void call_item(FunctionBuilder& b, std::uint32_t key);
    void push_key(FunctionBuilder& b, const Bytes& key);
    // Calls whose cost depends on a size (cost.hpp), each with its size.
    /// [map] -> [value]: the value under `key`, in a map of at most
    /// `entries` entries.
    void lookup(FunctionBuilder& b, const Bytes& key, wasm::Size entries);
    /// [p, n, q, m] -> [flag]: equal bytes, at most `length` compared.
    void equal_bytes(FunctionBuilder& b, wasm::Size length);
    /// [p, n] -> []: n bytes of output as they are, at most `length`.
    void out_raw(FunctionBuilder& b, wasm::Size length);
    /// Writes a key (or any constant encoding).
    void out_key(FunctionBuilder& b, const Bytes& key);
    /// [p, n] -> []: a text of at most `length` bytes.
    void out_text(FunctionBuilder& b, wasm::Size length);
    /// The most bytes comparing two texts reads: no more than either holds.
    [[nodiscard]] wasm::Size text_size(const Ctx& c, const m::Expr& x, const m::Expr& y) const;
    /// A text's length if it is written in the contract (directly or as a
    /// constant's value), or an `each` item's size; none otherwise.
    [[nodiscard]] std::optional<wasm::Size> known_size(const Ctx& c, const m::Expr& e,
                                                       bool items) const;
    /// The two scratch locals of the function (from codegen 2 on), or two new ones.
    [[nodiscard]] std::pair<Local, Local> scratch(Ctx& c);
    void expect(FunctionBuilder& b, Rep rep, std::string_view reason);
    void read_value(FunctionBuilder& b, const m::Type& type, std::string_view reason);
    void store(FunctionBuilder& b, const FieldSlot& slot);
    void load(FunctionBuilder& b, const FieldSlot& slot);
    void out_value(FunctionBuilder& b, Rep rep);
    void state_name(FunctionBuilder& b, Local index);

    // --- Bounds (milestone 18): the input each function meets at most.
    [[nodiscard]] Shape arguments_shape(const ActionInfo& action) const;
    [[nodiscard]] Shape creation_shape() const;
    [[nodiscard]] Shape proposal_shape() const;
    [[nodiscard]] Shape state_shape() const;
    [[nodiscard]] Shape rest_shape() const;
    /// True if the statements (and the actions they do) set the bill's field.
    [[nodiscard]] bool sets_bill(const std::vector<m::Statement>& list, int depth = 0) const;
    void bounds(Build& build);

    // --- The second pass: code.
    void emit();
    void emit_entry(wasm::Func entry);
    void emit_creation(wasm::Func f);
    void emit_action(const ActionInfo& action);
    void emit_core(const ActionInfo& action);
    void emit_approve(wasm::Func f);
    void emit_rule(const RuleInfo& rule);
    void emit_reply(wasm::Func f);
    void request(Ctx& c, const m::Request& r);
    void write_answer_event(FunctionBuilder& b);
    /// The params of the contract's requests, the most any has (E8).
    [[nodiscard]] Shape params_shape() const;
    void run_action(Ctx& c, const m::Do& d);
    void now(Ctx& c);
    void due(Ctx& c);
    void shift(Ctx& c, const m::Expr& duration, bool earlier);
    void moment(Ctx& c, const m::Trigger& trigger);
    void entry_check(Ctx& c);
    void depth_check(Ctx& c);
    void issue_parts(Ctx& c, const m::Do& d);
    /// The most parts one call issues: no more than its lists hold.
    [[nodiscard]] std::uint64_t parts_bound() const;
    void party_raw(Ctx& c, const m::Expr& e);
    void ledger_equals(Ctx& c, const m::Expr& x, const m::Expr& y);
    void consent_of(Ctx& c, const m::Expr& party);
    [[nodiscard]] bool may_be_empty(const m::Expr& e) const;
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
    // --- Bills and charges (milestone 13).
    [[nodiscard]] wasm::Func compute_bill();
    [[nodiscard]] wasm::Func line_charges();
    void charge_base(Ctx& c, const ChargeInfo& k, std::optional<Local> price, bool per_line);
    void charge_divisor(FunctionBuilder& b, const ChargeInfo& k);
    void write_bill(FunctionBuilder& b);
    [[nodiscard]] std::vector<const ChargeInfo*> sorted_charges(bool per_line_only) const;

    // --- Lists (milestone 13).
    [[nodiscard]] wasm::Func list_reader(Rep element);
    [[nodiscard]] wasm::Func list_sum();
    [[nodiscard]] wasm::Func list_has(Rep element);
    void item_value(FunctionBuilder& b, Local p, Rep element);
    void next_item(FunctionBuilder& b, Local p, Rep element);
    [[nodiscard]] const m::Expr* literal_items(const m::Expr& e) const;
    [[nodiscard]] bool constant_items(const m::Expr& list) const;
    void encoded_list(FunctionBuilder& b, const m::Expr& list);
    void each(Ctx& c, const m::Each& e);
    void member(Ctx& c, const m::Expr& e);
    void list_apply(Ctx& c, const m::Expr& e);
    void record_event(FunctionBuilder& b, std::size_t state);
    void record_event_at(FunctionBuilder& b, Local state);
    void write_pending(FunctionBuilder& b);
    void write_event(FunctionBuilder& b);
    void write_rule_event(FunctionBuilder& b);
    /// True if this codegen's code asks consent K: codegens 1 and 2 came
    /// before R31 and never ask its consents, so that their deploys rebuild
    /// to the same bytes.
    [[nodiscard]] bool asks(const m::Consent& k) const noexcept {
        return codegen_ >= 3 || k.rule != "R31";
    }

    std::string_view source_;
    const m::Model& model_;
    std::uint32_t codegen_;
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
    /// The contract goes back to a previous state (`previous state`), or
    /// keeps AI agents' proposals: its instances' state holds them too.
    bool previous_used_ = false;
    bool proposals_ = false;
    wasm::Func approve_function_{};
    /// The time rules with code; whether the instance keeps the time it
    /// last changed state (`within`, a state held N).
    std::vector<RuleInfo> rules_;
    bool since_used_ = false;
    /// The bill (R26): the field that holds its lines, and the charges.
    std::optional<std::size_t> bill_slot_;
    std::vector<ChargeInfo> charges_;
    std::optional<wasm::Func> compute_bill_;
    std::optional<wasm::Func> line_charges_;
    /// Made in this call (i32); the bill the instance held (its item and
    /// length); the bill's time, its lines' sum, and its total (i64); the
    /// included charges' rates, 100% plus them (i64); where the bill was
    /// written in the output (i32 each).
    wasm::Global bill_new_{};
    wasm::Global bill_old_{};
    wasm::Global bill_old_length_{};
    wasm::Global bill_time_{};
    wasm::Global bill_price_{};
    wasm::Global bill_total_{};
    wasm::Global bill_divisor_{};
    wasm::Global bill_at_{};
    wasm::Global bill_length_{};
    /// The list routines, by the representation of the items.
    std::map<Rep, wasm::Func> list_readers_;
    std::map<Rep, wasm::Func> list_has_;
    std::optional<wasm::Func> list_sum_;
    /// Parts (R30): some action issues them; the fields `with` sets on them.
    bool parts_used_ = false;
    std::map<std::size_t, PartField> part_fields_;

    // Written in the second pass.
    wasm::Func entry_{};
    wasm::Global state_{};
    wasm::Global events_{};
    std::uint32_t events_area_ = 0;
    std::uint32_t state_table_ = 0;
    std::uint32_t final_table_ = 0;
    std::optional<wasm::Func> load_instance_;
    std::optional<wasm::Func> write_accept_;
    /// The state before the current one, as its index plus 1 (0: none).
    wasm::Global previous_{};
    /// The instance's proposals (the state's "pending" array item, or 0);
    /// the one an approval removes (its index plus 1, or 0); and the one a
    /// proposal adds (its function's name, and its arguments' item, or 0).
    wasm::Global pending_{};
    wasm::Global drop_{};
    wasm::Global add_name_{};
    wasm::Global add_length_{};
    wasm::Global add_args_{};
    /// An event besides the state changes: 1 propose, 2 approve (0 none),
    /// and the action's name.
    wasm::Global event_kind_{};
    wasm::Global event_name_{};
    wasm::Global event_length_{};
    /// When the instance last changed state (i64); a time rule's event: 1
    /// once it applies (i32), its function's name, its time, how late.
    wasm::Global since_{};
    wasm::Global rule_event_{};
    wasm::Global rule_name_{};
    wasm::Global rule_length_{};
    wasm::Global rule_time_{};
    wasm::Global rule_late_{};
    /// Parts issued in this call (i32: 1 if any), and the lists of their
    /// amounts and recipients (their items' addresses).
    wasm::Global parts_made_{};
    wasm::Global parts_list_{};
    wasm::Global parts_to_{};
    /// Requests (E8): the contract makes some, so it has the reply function;
    /// the requests a call has made so far (drafted at the start of the
    /// output region); and an answer's event: 1 once there is one, the
    /// request's kind (address, length), its id, and the answer's status.
    bool requests_used_ = false;
    std::size_t answer_transitions_ = 0;
    /// The most requests one call makes (at most 16, the checker sees to it).
    std::uint64_t most_requests_ = 0;
    wasm::Func reply_function_{};
    wasm::Global requests_{};
    wasm::Global answer_event_{};
    wasm::Global answer_kind_{};
    wasm::Global answer_kind_length_{};
    wasm::Global answer_id_{};
    wasm::Global answer_status_{};
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
        slot.optional = f.optional && slot.rep == Rep::ledger;
        slot.empty_at_start = f.empty_at_start && slot.rep == Rep::ledger;
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
    return m::action_amount(model_, *action.action);
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
            // A state no instance reaches (named by the standard terms) is
            // never the instance's.
            return e.type.kind == TypeKind::yes_no ? std::nullopt : no(feature_of(e.type));
        case Refers::item:
            return rep_of(e.type) != Rep::none ? std::nullopt : no(feature_of(e.type));
        case Refers::action:
            return no(key);
        case Refers::charge:
            // Its amount on the bill (R26).
            return std::nullopt;
        case Refers::none:
            break;
        }
        if (is(e.concept_entry, "val.yes") || is(e.concept_entry, "val.no") ||
            is(e.concept_entry, "val.none") || is(e.concept_entry, "time.now") ||
            is(e.concept_entry, "time.today") || is(e.concept_entry, "expr.result") ||
            is(e.concept_entry, "expr.reason") ||
            (is(e.concept_entry, "cond.in_person") && action != nullptr) ||
            (is(e.concept_entry, "cond.overdue") && model_.due == m::DueKind::field)) {
            return std::nullopt;
        }
        return no(e.concept_entry != nullptr ? std::string(e.concept_entry->id)
                                             : feature_of(e.type));
    }
    case ExprKind::apply:
        if (is(e.concept_entry, "cond.over") && action != nullptr && amount_of(*action)) {
            return all(false);
        }
        if ((is(e.concept_entry, "expr.sum_of") || is(e.concept_entry, "expr.count_of")) &&
            e.operands.size() == 1) {
            // A list written out needs only its items; any other, its value.
            if (const m::Expr* items = literal_items(e.operands[0])) {
                for (const m::Expr& o : items->operands) {
                    if (Found f = unsupported_in(o, action, false, depth + 1)) {
                        return f;
                    }
                }
                return element_rep(e.operands[0].type) != Rep::none ? std::nullopt
                                                                    : no("type.list");
            }
            return unsupported_in(e.operands[0], action, false, depth);
        }
        // Times: N before the due date, less than N since the last change.
        if ((is(e.concept_entry, "cond.before_due") && model_.due == m::DueKind::field) ||
            is(e.concept_entry, "cond.within")) {
            return all(false);
        }
        if (is(e.concept_entry, "cond.consent_of") && consent_ok) {
            // A list of parties written out: each party.
            if (const m::Expr* items = literal_items(e.operands[0])) {
                for (const m::Expr& o : items->operands) {
                    if (Found f = unsupported_in(o, action, false, depth + 1)) {
                        return f;
                    }
                }
                return std::nullopt;
            }
            return all(false);
        }
        return no(e.concept_entry != nullptr ? std::string(e.concept_entry->id) : "cond.over");
    case ExprKind::phrase:
        // overdue N; a state held N.
        if (m::is_trigger(e) &&
            (e.operands[0].refers == Refers::state || model_.due == m::DueKind::field)) {
            return unsupported_in(e.operands[1], action, false, depth);
        }
        return no(!e.operands.empty() && e.operands[0].concept_entry != nullptr
                      ? std::string(e.operands[0].concept_entry->id)
                      : "price.per");
    case ExprKind::list:
        // A list as a whole: constants only, written into the module once.
        return constant_items(e) ? std::nullopt : no("type.list");
    case ExprKind::unary:
        return all(false);
    case ExprKind::binary:
        break;
    }
    if (e.operands.size() != 2) {
        return no("type.unknown");
    }
    if (e.op == Operator::member) {
        // X in LIST: a list written out needs only its items.
        if (Found f = unsupported_in(e.operands[0], action, false, depth)) {
            return f;
        }
        if (rep_of(e.operands[0].type) == Rep::none) {
            return no(feature_of(e.operands[0].type));
        }
        if (const m::Expr* items = literal_items(e.operands[1])) {
            for (const m::Expr& o : items->operands) {
                if (Found f = unsupported_in(o, action, false, depth + 1)) {
                    return f;
                }
            }
            return std::nullopt;
        }
        return unsupported_in(e.operands[1], action, false, depth);
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
        return std::nullopt;
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

const ActionInfo* Lowering::action_info(const m::Do& d) const {
    const std::string key =
        m::key(d.action.kind == ExprKind::word ? d.action.concept_entry : nullptr, d.action.name);
    for (const ActionInfo& a : actions_) {
        if (a.key == key) {
            return &a;
        }
    }
    return nullptr;
}

void Lowering::support(ActionInfo& action, const std::vector<m::Statement>& list, const bool rule) {
    // A time rule's own lines (`rule`) are no action's.
    const auto check = [&](const m::Expr& e, bool consent_ok) {
        if (auto found = unsupported_in(e, rule ? nullptr : &action, consent_ok, 0)) {
            unsupported(found->first, std::move(found->second));
        }
    };
    for (const m::Statement& s : list) {
        std::visit(
            Overloaded{
                [&](const m::Requires& r) {
                    if (r.guard) {
                        check(*r.guard, false);
                    }
                    check(r.condition, true);
                },
                [&](const m::If& i) {
                    check(i.condition, false);
                    support(action, i.then, rule);
                    support(action, i.otherwise, rule);
                },
                [&](const m::Each& e) {
                    // A list written out needs only its items.
                    if (const m::Expr* items = literal_items(e.list)) {
                        for (const m::Expr& item : items->operands) {
                            check(item, false);
                        }
                        if (element_rep(e.list.type) == Rep::none) {
                            unsupported(e.list.span, feature_of(e.list.type));
                        }
                    } else {
                        check(e.list, false);
                    }
                    support(action, e.body, rule);
                },
                [&](const m::Reject& r) {
                    if (r.message.starts_with("bo:")) {
                        error(r.span, "build.reject-text", {{"text", quote(source_, r.span)}});
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
                    if (is(t.to.concept_entry, "expr.previous_state")) {
                        previous_used_ = true;
                    } else if (!state_index_.contains(m::key(t.to.concept_entry, t.to.name))) {
                        unsupported(t.to.span, "type.unknown");
                    }
                },
                [&](const m::Do& d) {
                    const std::string key = m::key(d.action.concept_entry, d.action.name);
                    if (d.parts && !rule) {
                        // R30: the parts, their recipients, and the fields
                        // each part gets.
                        parts_used_ = true;
                        action.parts = true;
                        for (const m::Expr& a : d.args) {
                            check(a, false);
                        }
                        if (d.to) {
                            check(*d.to, false);
                        }
                        for (const m::Set& w : d.with) {
                            const auto at =
                                field_index_.find(m::key(w.target.concept_entry, w.target.name));
                            if (at == field_index_.end()) {
                                unsupported(w.span, feature_of(w.target.type));
                                continue;
                            }
                            part_fields_.try_emplace(at->second);
                            check(w.value, false);
                        }
                        return;
                    }
                    if (d.executor) {
                        error(d.span, "build.executor", {{"action", key}});
                    } else if (rule && d.obligation) {
                        // A duty (R9): no call.
                    } else if (const ActionInfo* done = rule ? action_info(d) : nullptr) {
                        // A time rule does an action: its state changes count.
                        action.transitions += done->transitions;
                    } else if (rule && d.action.kind == ExprKind::word) {
                        error(d.span, "build.standard-action", {{"action", key}});
                    } else {
                        unsupported(d.span, key);
                    }
                },
                [&](const m::Request& r) {
                    // E8: a request, its party, and its values.
                    requests_used_ = true;
                    if (r.to) {
                        check(*r.to, false);
                    }
                    for (const m::Set& w : r.with) {
                        check(w.value, false);
                        if (rep_of(w.value.type) == Rep::none) {
                            unsupported(w.span, feature_of(w.value.type));
                        }
                    }
                },
            },
            s.node);
    }
}

void Lowering::plan_actions() {
    creation_ = std::string(m::creation_function(model_));
    std::set<std::string> names{creation_};
    if (m::makes_requests(model_)) {
        names.emplace(m::reply_function);
    }
    proposals_ = m::has_proposals(model_);
    if (proposals_) {
        names.emplace(m::approve_function);
    }
    for (const m::Action& a : model_.actions) {
        ActionInfo info;
        info.action = &a;
        info.key = m::key(a.word, a.name);
        info.wire = wire_name(a.word, a.name);
        info.rule_only = a.rule_only;
        if (a.executor) {
            error(a.span, "build.executor", {{"action", info.key}});
        } else if (a.word != nullptr && !a.terms) {
            error(a.span, "build.standard-action", {{"action", info.key}});
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
        // An approval reports one more event: approve.
        if (info.transitions + (a.agents_propose ? 1 : 0) > max_build_events) {
            error(a.span, "build.too-many-events",
                  {{"action", info.key}, {"limit", std::to_string(max_build_events)}});
        }
        max_transitions_ = std::max(max_transitions_, info.transitions);
        actions_.push_back(std::move(info));
    }
}

namespace {

/// True if an expression reads the due date: the field, overdue, or N
/// before due.
bool reads_due(const m::Expr& e) {
    return is(e.concept_entry, "field.due") || is(e.concept_entry, "cond.overdue") ||
           is(e.concept_entry, "cond.before_due") ||
           std::ranges::any_of(e.operands, [](const m::Expr& o) { return reads_due(o); });
}

} // namespace

void Lowering::plan_rules() {
    // R24: each time rule with code is a function a keeper calls once its
    // time has come (the duties of R9 have none).
    const std::vector<std::string> names = m::rule_functions(model_);
    for (std::size_t i = 0; i < model_.rules.size(); ++i) {
        const m::TimeRule& r = model_.rules[i];
        if (!m::rule_runs(r)) {
            continue;
        }
        std::optional<m::Trigger> trigger = m::trigger_of(r.event);
        // A service is due at the end of each paid period (R11), which its
        // executors track (6b).
        if (!trigger || (model_.due != m::DueKind::field && reads_due(r.event))) {
            error(r.span, "build.time-rule", {{"text", quote(source_, r.span)}});
            continue;
        }
        RuleInfo info;
        info.rule = &r;
        info.wire = names[i];
        info.key = text_cbor(info.wire);
        info.trigger = std::move(*trigger);
        name_check(info.wire, r.span, max_build_name);
        if (auto found = unsupported_in(r.event, nullptr, false, 0)) {
            unsupported(found->first, std::move(found->second));
        }
        for (const m::Consent& k : r.consents) {
            if (auto found = unsupported_in(k.party, nullptr, false, 0)) {
                unsupported(found->first, std::move(found->second));
            }
        }
        // What it does: its line's actions, then its block.
        ActionInfo own;
        own.wire = info.wire;
        for (const m::Do& d : r.actions) {
            support(own, {m::Statement{d}}, true);
        }
        support(own, r.body, true);
        info.transitions = own.transitions;
        // Its event, and each state change.
        if (info.transitions + 1 > max_build_events) {
            error(r.span, "build.too-many-events",
                  {{"action", info.wire}, {"limit", std::to_string(max_build_events)}});
        }
        max_transitions_ = std::max(max_transitions_, info.transitions);
        rules_.push_back(std::move(info));
    }
}

void Lowering::plan_answers() {
    // E8: a contract that makes requests has the reply function, which takes
    // every answer and runs the rule for it.
    if (!m::makes_requests(model_)) {
        return;
    }
    requests_used_ = true;
    // The most one call makes: an action's, a time rule's with the actions
    // it does, or one rule for answers (only one runs).
    const auto count = [](const std::vector<m::Statement>& list) {
        return static_cast<std::uint64_t>(m::requests_in(list).size());
    };
    for (const m::Action& a : model_.actions) {
        most_requests_ = std::max(most_requests_, count(a.body));
    }
    for (const m::TimeRule& r : model_.rules) {
        std::uint64_t n = count(r.body);
        for (const m::Do* d : m::rule_actions(r)) {
            if (const m::Action* a = m::action_of(model_, *d)) {
                n += count(a->body);
            }
        }
        most_requests_ = std::max(most_requests_, n);
    }
    for (const m::AnswerRule& r : model_.answers) {
        most_requests_ = std::max(most_requests_, count(r.body));
    }
    most_requests_ = std::min(most_requests_, m::max_call_requests);
    for (const m::AnswerRule& r : model_.answers) {
        ActionInfo own;
        own.wire = std::string(m::reply_function);
        support(own, r.body, true);
        answer_transitions_ = std::max(answer_transitions_, own.transitions);
    }
    // The answer's event, and each state change.
    if (answer_transitions_ + 1 > max_build_events) {
        error(model_.answers.front().span, "build.too-many-events",
              {{"action", std::string(m::reply_function)},
               {"limit", std::to_string(max_build_events)}});
    }
    max_transitions_ = std::max(max_transitions_, answer_transitions_);
    // An instance that issues parts ends, which its state alone may not
    // show: answers to its requests could not tell (a later version).
    if (parts_used_) {
        for (const m::Action& a : model_.actions) {
            if (const std::vector<const m::Request*> list = m::requests_in(a.body); !list.empty()) {
                unsupported(list.front()->span, "kw.request");
                return;
            }
        }
        for (const m::TimeRule& r : model_.rules) {
            if (const std::vector<const m::Request*> list = m::requests_in(r.body); !list.empty()) {
                unsupported(list.front()->span, "kw.request");
                return;
            }
        }
    }
}

void Lowering::plan_charges() {
    // R26: the field that holds the bill, and the charges computed on it.
    if (const m::Field* bill = m::bill_field(model_); bill != nullptr) {
        const auto it = field_index_.find(m::key(bill->word, bill->name));
        if (it != field_index_.end() && fields_[it->second].rep == Rep::list) {
            bill_slot_ = it->second;
        }
    }
    if (model_.charges.size() > max_build_charges) {
        error(Span{}, "build.too-many-charges", {{"limit", std::to_string(max_build_charges)}});
        return;
    }
    const auto check = [&](const m::Expr& e) {
        if (auto found = unsupported_in(e, nullptr, false, 0)) {
            unsupported(found->first, std::move(found->second));
        }
    };
    for (const m::Charge& c : model_.charges) {
        ChargeInfo info;
        info.charge = &c;
        info.wire = c.name;
        info.key = text_cbor(info.wire);
        name_check(info.wire, c.span, max_build_name);
        if (c.condition) {
            check(*c.condition);
        }
        if (c.rate) {
            check(*c.rate);
        }
        for (const m::DatedRate& d : c.dated) {
            check(d.rate);
        }
        if (c.amount) {
            check(*c.amount);
        }
        charges_.push_back(std::move(info));
    }
    if (!charges_.empty() && !bill_slot_) {
        error(model_.charges.front().span, "build.unsupported",
              {{"text", quote(source_, model_.charges.front().span)}, {"feature", "doc.invoice"}});
    }
}

void Lowering::plan_finals() {
    // A state is final when no action can start from it.
    const std::vector<bool> finals = m::final_states(model_);
    for (std::size_t i = 0; i < model_.states.size(); ++i) {
        const m::State& s = model_.states[i];
        states_[state_index_.at(m::key(s.word, s.name))].final = finals[i];
    }
}

void Lowering::plan() {
    if (model_.name.empty()) {
        error(Span{}, "build.fragment", {});
    }
    plan_fields();
    plan_roles();
    plan_states();
    plan_actions();
    plan_rules();
    plan_answers();
    plan_charges();
    // The interface: the creation, each action that has a function, approve,
    // each time rule, and the reply (at most 256, spec section 15).
    std::size_t functions = 1 + rules_.size() + (proposals_ ? 1U : 0U) + (requests_used_ ? 1U : 0U);
    for (const ActionInfo& a : actions_) {
        functions += a.rule_only ? 0U : 1U;
    }
    if (functions > max_build_functions) {
        error(Span{}, "build.too-many-functions", {{"limit", std::to_string(max_build_functions)}});
    }
    // A call that makes a bill reports one more event (R26): with it, no
    // more than 64 (spec section 15).
    if (bill_slot_) {
        for (const ActionInfo& a : actions_) {
            if (a.transitions + (a.action->agents_propose ? 1U : 0U) == max_build_events &&
                sets_bill(a.action->body)) {
                error(a.action->span, "build.too-many-events",
                      {{"action", a.key}, {"limit", std::to_string(max_build_events)}});
            }
        }
        for (const RuleInfo& r : rules_) {
            std::vector<m::Statement> all;
            for (const m::Do& d : r.rule->actions) {
                all.push_back(m::Statement{d});
            }
            if (r.transitions + 1 == max_build_events &&
                (sets_bill(all) || sets_bill(r.rule->body))) {
                error(r.rule->span, "build.too-many-events",
                      {{"action", r.wire}, {"limit", std::to_string(max_build_events)}});
            }
        }
    }
    since_used_ = m::uses_since(model_);
    if (!states_.empty()) {
        plan_finals();
    }
    // The globals the module will hold, within the profile's limit (the
    // runtime's four included).
    std::size_t globals = 2 + 4 + roles_.size();
    for (const FieldSlot& slot : fields_) {
        globals += pair_rep(slot.rep) ? 2U : 1U;
    }
    globals += (previous_used_ ? 1U : 0U) + (proposals_ ? 8U : 0U) + (since_used_ ? 1U : 0U);
    globals += rules_.empty() ? 0 : 2 * rules_.size() + 5;
    globals += requests_used_ ? 6U : 0U;
    if (bill_slot_) {
        globals += 9;
        for (const ChargeInfo& k : charges_) {
            globals += k.charge->per_document ? 3U : 4U;
        }
    }
    if (globals > vm::max_globals) {
        error(Span{}, "build.too-large", {});
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

void Lowering::lookup(FunctionBuilder& b, const Bytes& key, wasm::Size entries) {
    push_key(b, key);
    b.call(rt_.get(Routine::map_get), {std::move(entries), key.size()});
}

void Lowering::equal_bytes(FunctionBuilder& b, wasm::Size length) {
    b.call(rt_.get(Routine::bytes_eq), {std::move(length)});
}

void Lowering::out_raw(FunctionBuilder& b, wasm::Size length) {
    b.call(rt_.get(Routine::out_raw), {std::move(length)});
}

void Lowering::out_key(FunctionBuilder& b, const Bytes& key) {
    push_key(b, key);
    out_raw(b, key.size());
}

void Lowering::out_text(FunctionBuilder& b, wasm::Size length) {
    b.call(rt_.get(Routine::out_text), {std::move(length)});
}

std::optional<wasm::Size> Lowering::known_size(const Ctx& c, const m::Expr& e,
                                               const bool items) const {
    const m::Expr* at = &e;
    for (int depth = 0; depth <= max_constant_depth; ++depth) {
        if (at->kind == ExprKind::literal && at->literal.kind == ast::LiteralKind::text) {
            return wasm::Size(at->literal.text.size());
        }
        if (items && at->refers == Refers::item) {
            const auto it = c.item_sizes.find(m::key(at->concept_entry, at->name));
            return it != c.item_sizes.end() ? std::optional(it->second) : std::nullopt;
        }
        const m::Field* k =
            at->refers == Refers::field ? constant(m::key(at->concept_entry, at->name)) : nullptr;
        if (k == nullptr || !k->value) {
            return std::nullopt;
        }
        at = &*k->value;
    }
    return std::nullopt;
}

wasm::Size Lowering::text_size(const Ctx& c, const m::Expr& x, const m::Expr& y) const {
    // A text written in the contract first, then an item's (cost.hpp: the
    // size of an item must not pass through min), else the most a text in
    // the input holds.
    for (const bool items : {false, true}) {
        for (const m::Expr* e : {&x, &y}) {
            if (auto size = known_size(c, *e, items)) {
                return *size;
            }
        }
    }
    return max_value_size;
}

std::pair<Local, Local> Lowering::scratch(Ctx& c) {
    FunctionBuilder& b = *c.b;
    if (codegen_ < 2) {
        return {b.local(I32), b.local(I32)};
    }
    if (!c.scratch) {
        c.scratch = std::pair{b.local(I32), b.local(I32)};
    }
    return *c.scratch;
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
    case Rep::list:
    case Rep::none:
        break;
    }
    BO_ASSERT(rep != Rep::none && rep != Rep::list);
}

/// The item on the stack, read as a value of `type` (a list with its bound
/// and its items' type), or a refusal with `reason`.
void Lowering::read_value(FunctionBuilder& b, const m::Type& type, const std::string_view reason) {
    const Rep rep = rep_of(type);
    if (rep != Rep::list) {
        expect(b, rep, reason);
        return;
    }
    b.u32(type.bound).u32(intern(reason)).u32(static_cast<std::uint32_t>(reason.size()));
    b.call(list_reader(element_rep(type)), {type.bound});
}

void Lowering::store(FunctionBuilder& b, const FieldSlot& slot) {
    if (pair_rep(slot.rep)) {
        b.global_set(slot.second);
    }
    b.global_set(slot.first);
}

void Lowering::load(FunctionBuilder& b, const FieldSlot& slot) {
    b.global_get(slot.first);
    if (pair_rep(slot.rep)) {
        b.global_get(slot.second);
    }
}

/// Writes the value on the stack (a text or a list as the input or the
/// module holds it: at most 64 KiB).
void Lowering::out_value(FunctionBuilder& b, const Rep rep) {
    switch (rep) {
    case Rep::i64:
        b.call(rt_.get(Routine::out_int));
        return;
    case Rep::flag:
        b.call(rt_.get(Routine::out_bool));
        return;
    case Rep::text:
        out_text(b, max_value_size);
        return;
    case Rep::ledger:
        b.i32(32).call(rt_.get(Routine::out_bytes), {32});
        return;
    case Rep::list:
        // Its encoding, as read or interned.
        out_raw(b, max_value_size);
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
    std::size_t longest = 0;
    for (const StateSlot& st : states_) {
        longest = std::max(longest, st.encoded.size());
    }
    out_raw(b, longest);
}

// ---------------------------------------------------------------------------
// Bills and charges (milestone 13). A bill is made when the field that holds
// its lines is set (at creation, or by an action): the charges are computed
// on its lines at the call's time (R26), in the order written, each on the
// price and the charges it names (R27), with the rate in force then (R28).
// The instance keeps the bill, {"time", ? "lines", "price", "total",
// "charges"}, and the call reports it as an event [DOCUMENT, BILL]; a bill
// already made is kept as it is (a later rate never changes it).

std::vector<const ChargeInfo*> Lowering::sorted_charges(const bool per_line_only) const {
    std::vector<const ChargeInfo*> out;
    for (const ChargeInfo& k : charges_) {
        if (!per_line_only || !k.charge->per_document) {
            out.push_back(&k);
        }
    }
    std::ranges::sort(out, {}, &ChargeInfo::key);
    return out;
}

void Lowering::charge_divisor(FunctionBuilder& b, const ChargeInfo& k) {
    // Added: base x rate / 100%. Included, taken out of the price: base x
    // rate / (100% + the included charges' rates).
    if (k.charge->included) {
        b.global_get(bill_divisor_);
    } else {
        b.i64(rate_one);
    }
    const Concept* mode = k.charge->rounding;
    const rt::Rounding rounding = is(mode, "round.half_even") ? rt::Rounding::half_even
                                  : is(mode, "round.down")    ? rt::Rounding::down
                                                              : rt::Rounding::half_up;
    b.i32(static_cast<std::int32_t>(rounding)).call(rt_.get(Routine::muldiv));
}

void Lowering::charge_base(Ctx& c, const ChargeInfo& k, const std::optional<Local> price,
                           const bool per_line) {
    // What the charge is computed on: the price (a line's, or the bill's)
    // and the charges it names (on that line, or on the bill).
    FunctionBuilder& b = *c.b;
    bool first = true;
    if (k.charge->on_price) {
        if (price) {
            b.get(*price);
        } else {
            b.global_get(bill_price_);
        }
        first = false;
    }
    for (const std::uint64_t j : k.charge->on) {
        const ChargeInfo& other = charges_[static_cast<std::size_t>(j)];
        b.global_get(per_line ? other.line : other.amount);
        if (!first) {
            b.call(rt_.get(Routine::add));
        }
        first = false;
    }
    if (first) {
        b.i64(0);
    }
}

wasm::Func Lowering::line_charges() {
    if (line_charges_) {
        return *line_charges_;
    }
    // [i64 price] -> []: each charge on a line, on that line's price.
    const wasm::Func f = module_.declare({{I64}, {}});
    line_charges_ = f;
    FunctionBuilder b = module_.begin(f);
    Ctx c;
    c.b = &b;
    c.wire = "bill";
    c.signer = b.local(I32);
    c.t32 = b.local(I32);
    c.t64 = b.local(I64);
    c.t64b = b.local(I64);
    const Local price = b.param(0);
    for (const ChargeInfo& k : charges_) {
        if (k.charge->per_document) {
            continue;
        }
        b.global_get(k.applies);
        const Label applies = b.if_(I64);
        if (k.charge->amount) {
            value(c, *k.charge->amount);
        } else {
            charge_base(c, k, price, true);
            b.global_get(k.rate);
            charge_divisor(b, k);
        }
        b.else_(applies);
        b.i64(0);
        b.end(applies);
        b.global_set(k.line);
    }
    module_.define(std::move(b));
    return f;
}

wasm::Func Lowering::compute_bill() {
    if (compute_bill_) {
        return *compute_bill_;
    }
    const wasm::Func f = module_.declare({});
    compute_bill_ = f;
    FunctionBuilder b = module_.begin(f);
    Ctx c;
    c.b = &b;
    c.wire = "bill";
    c.signer = b.local(I32);
    c.t32 = b.local(I32);
    c.t64 = b.local(I64);
    c.t64b = b.local(I64);
    const Local p = b.local(I32);
    const Local n = b.local(I32);
    const Local has = b.local(I32);
    const FieldSlot& lines = fields_[*bill_slot_];
    const wasm::Func add = rt_.get(Routine::add);
    b.i32(1).global_set(bill_new_);
    now(c);
    b.global_set(bill_time_);
    // Whether each charge applies, and the rate in force (R28): the latest
    // of those from a date on or before the bill's time, else its own.
    for (const ChargeInfo& k : charges_) {
        const m::Charge& charge = *k.charge;
        if (charge.condition) {
            value(c, *charge.condition);
        } else {
            b.i32(1);
        }
        b.global_set(k.applies);
        if (charge.amount) {
            continue;
        }
        if (charge.rate) {
            value(c, *charge.rate);
            b.global_set(k.rate);
        } else {
            // No rate until its first date.
            b.i64(0).global_set(k.rate);
            b.i32(0).set(has);
        }
        for (const m::DatedRate& d : charge.dated) {
            b.global_get(bill_time_);
            b.i64(literal_value(d.date.literal, model_.utc_offset_ms).value_or(0));
            b.op(i64_ge_s);
            const Label from = b.if_();
            value(c, d.rate);
            b.global_set(k.rate);
            if (!charge.rate) {
                b.i32(1).set(has);
            }
            b.end(from);
        }
        if (!charge.rate) {
            b.global_get(k.applies).get(has).op(i32_and).global_set(k.applies);
        }
    }
    // 100% plus the rates of the included charges that apply.
    b.i64(rate_one);
    for (const ChargeInfo& k : charges_) {
        if (k.charge->included && !k.charge->amount) {
            b.global_get(k.applies);
            const Label applies = b.if_(I64);
            b.global_get(k.rate);
            b.else_(applies);
            b.i64(0);
            b.end(applies);
            b.call(add);
        }
    }
    b.global_set(bill_divisor_);
    // The price: the lines' sum.
    const std::uint64_t bound = lines.field->type.bound;
    b.global_get(lines.first).call(list_sum(), {bound}).global_set(bill_price_);
    // The charges on each line, summed.
    bool per_line = false;
    for (const ChargeInfo& k : charges_) {
        if (!k.charge->per_document) {
            b.i64(0).global_set(k.amount);
            per_line = true;
        }
    }
    if (per_line) {
        b.global_get(lines.first).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64).set(n);
        b.global_get(lines.first).call(rt_.get(Routine::content)).set(p);
        const Label done = b.block();
        const Label next = b.loop({bound + 1});
        b.get(n).op(i32_eqz).br_if(done);
        item_value(b, p, Rep::i64);
        b.call(line_charges());
        next_item(b, p, Rep::i64);
        for (const ChargeInfo& k : charges_) {
            if (!k.charge->per_document) {
                b.global_get(k.amount).global_get(k.line).call(add).global_set(k.amount);
            }
        }
        b.get(n).i32(1).op(i32_sub).set(n).br(next);
        b.end(next);
        b.end(done);
    }
    // The charges once per bill, in the order written.
    for (const ChargeInfo& k : charges_) {
        if (!k.charge->per_document) {
            continue;
        }
        b.global_get(k.applies);
        const Label applies = b.if_(I64);
        if (k.charge->amount) {
            value(c, *k.charge->amount);
        } else {
            charge_base(c, k, std::nullopt, false);
            b.global_get(k.rate);
            charge_divisor(b, k);
        }
        b.else_(applies);
        b.i64(0);
        b.end(applies);
        b.global_set(k.amount);
    }
    // The total: the price and the charges added to it.
    b.global_get(bill_price_);
    for (const ChargeInfo& k : charges_) {
        if (!k.charge->included) {
            b.global_get(k.amount).call(add);
        }
    }
    b.global_set(bill_total_);
    module_.define(std::move(b));
    return f;
}

void Lowering::write_bill(FunctionBuilder& b) {
    // The bill made in this call, or the one the instance kept.
    const wasm::Func head = rt_.get(Routine::out_head);
    const wasm::Func out_int = rt_.get(Routine::out_int);
    // Routines are emitted in the order of first use (runtime.hpp).
    static_cast<void>(rt_.get(Routine::out_raw));
    const std::vector<const ChargeInfo*> line_keys = sorted_charges(true);
    const bool per_line = !line_keys.empty();
    b.global_get(bill_new_);
    const Label made = b.if_();
    b.region_begin(region_bill);
    b.global_get(rt_.var(rt::Var::out)).global_set(bill_at_);
    b.i32(5).i64(per_line ? 5 : 4).call(head);
    out_key(b, text_cbor("time"));
    b.global_get(bill_time_).call(out_int);
    if (per_line) {
        // "lines": [{CHARGE: amount, ...}, ...], those that apply.
        const Local p = b.local(I32);
        const Local n = b.local(I32);
        const Local count = b.local(I64);
        const FieldSlot& lines = fields_[*bill_slot_];
        out_key(b, text_cbor("lines"));
        b.global_get(lines.first).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64).set(n);
        b.i32(4).get(n).op(i64_extend_i32_u).call(head);
        b.global_get(lines.first).call(rt_.get(Routine::content)).set(p);
        const Label done = b.block();
        const Label next = b.loop({lines.field->type.bound + 1});
        b.get(n).op(i32_eqz).br_if(done);
        item_value(b, p, Rep::i64);
        b.call(line_charges());
        next_item(b, p, Rep::i64);
        b.i64(0);
        for (const ChargeInfo* k : line_keys) {
            b.global_get(k->applies).op(i64_extend_i32_u).op(i64_add);
        }
        b.set(count);
        b.i32(5).get(count).call(head);
        for (const ChargeInfo* k : line_keys) {
            b.global_get(k->applies);
            const Label applies = b.if_();
            out_key(b, k->key);
            b.global_get(k->line).call(out_int);
            b.end(applies);
        }
        b.get(n).i32(1).op(i32_sub).set(n).br(next);
        b.end(next);
        b.end(done);
    }
    out_key(b, text_cbor("price"));
    b.global_get(bill_price_).call(out_int);
    out_key(b, text_cbor("total"));
    b.global_get(bill_total_).call(out_int);
    // "charges": {CHARGE: {? "rate": r, "amount": a}, ...}, those that apply.
    out_key(b, text_cbor("charges"));
    b.i32(5).i64(0);
    for (const ChargeInfo& k : charges_) {
        b.global_get(k.applies).op(i64_extend_i32_u).op(i64_add);
    }
    b.call(head);
    for (const ChargeInfo* k : sorted_charges(false)) {
        b.global_get(k->applies);
        const Label applies = b.if_();
        out_key(b, k->key);
        if (k->charge->amount) {
            b.i32(5).i64(1).call(head);
        } else {
            b.i32(5).i64(2).call(head);
            out_key(b, text_cbor("rate"));
            b.global_get(k->rate).call(out_int);
        }
        out_key(b, text_cbor("amount"));
        b.global_get(k->amount).call(out_int);
        b.end(applies);
    }
    b.global_get(rt_.var(rt::Var::out)).global_get(bill_at_).op(i32_sub).global_set(bill_length_);
    b.region_end();
    b.else_(made);
    // The bill kept, as the state held it.
    b.global_get(bill_old_).global_get(bill_old_length_);
    out_raw(b, max_state_size);
    b.end(made);
}

// ---------------------------------------------------------------------------
// Lists (milestone 13). A list is kept as its CBOR array, an address and a
// length: an instance's list in the state and an action's in its arguments
// where the input holds them, a list of constants written into the module.
// Lists from the input are checked once, when read (an array of at most the
// bound, each item of the items' type); their items are then read in place.

wasm::Func Lowering::list_reader(const Rep element) {
    if (const auto it = list_readers_.find(element); it != list_readers_.end()) {
        return it->second;
    }
    // [item, bound, reason, reason_length] -> [address, length]. Size 0: the
    // bound (at most 1,000, R16).
    const wasm::Func f = module_.declare({{I32, I32, I32, I32}, {I32, I32}});
    list_readers_.emplace(element, f);
    FunctionBuilder b = module_.begin(f);
    b.sizes({m::max_list_bound});
    const Local item = b.param(0);
    const Local bound = b.param(1);
    const Local reason = b.param(2);
    const Local length = b.param(3);
    const Local n = b.local(I64);
    const Local p = b.local(I32);
    const wasm::Func item_end = rt_.get(Routine::item_end);
    const Label bad = b.block();
    b.get(item).op(i32_eqz).br_if(bad);
    b.get(item).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0x80).op(i32_ne).br_if(bad);
    b.get(item).call(rt_.get(Routine::head_arg)).tee(n);
    b.get(bound).op(i64_extend_i32_u).op(i64_gt_u).br_if(bad);
    b.get(item).call(rt_.get(Routine::content)).set(p);
    {
        const Label done = b.block();
        const Label next = b.loop({b.size(0) + 1});
        b.get(n).op(i64_eqz).br_if(done);
        b.get(p).get(reason).get(length);
        switch (element) {
        case Rep::i64:
            b.call(rt_.get(Routine::expect_int)).op(drop);
            break;
        case Rep::flag:
            b.call(rt_.get(Routine::expect_bool)).op(drop);
            break;
        case Rep::text:
            b.call(rt_.get(Routine::expect_text)).op(drop).op(drop);
            break;
        default:
            b.call(rt_.get(Routine::expect_ledger)).op(drop);
            break;
        }
        b.get(p).call(item_end).set(p);
        b.get(n).i64(1).op(i64_sub).set(n).br(next);
        b.end(next);
        b.end(done);
    }
    b.get(item).get(item).call(item_end).get(item).op(i32_sub).return_();
    b.end(bad);
    b.get(reason).get(length).call(module_.host(wasm::Host::abort)).unreachable();
    module_.define(std::move(b));
    return f;
}

/// Pushes the value of the list item at `p` (one the list was checked to
/// hold): an i64, a flag, a text's address and length, a ledger's address.
void Lowering::item_value(FunctionBuilder& b, const Local p, const Rep element) {
    switch (element) {
    case Rep::i64: {
        const std::string_view input = rt::text_of(rt::Reason::input);
        b.get(p).u32(intern(input)).u32(static_cast<std::uint32_t>(input.size()));
        b.call(rt_.get(Routine::expect_int));
        return;
    }
    case Rep::flag:
        b.get(p).load(i32_load8_u).u32(0xF5).op(i32_eq);
        return;
    case Rep::text:
        b.get(p).call(rt_.get(Routine::content));
        b.get(p).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64);
        return;
    default:
        b.get(p).i32(2).op(i32_add);
        return;
    }
}

/// Moves `p` past the list item it is at (items hold no other item).
void Lowering::next_item(FunctionBuilder& b, const Local p, const Rep element) {
    switch (element) {
    case Rep::i64:
        b.get(p).call(rt_.get(Routine::content)).set(p);
        return;
    case Rep::flag:
        b.get(p).i32(1).op(i32_add).set(p);
        return;
    case Rep::text:
        b.get(p).call(rt_.get(Routine::content));
        b.get(p).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64).op(i32_add).set(p);
        return;
    default:
        b.get(p).i32(34).op(i32_add).set(p);
        return;
    }
}

wasm::Func Lowering::list_sum() {
    if (list_sum_) {
        return *list_sum_;
    }
    // [address] -> [i64]: the items' sum, checked. Size 0: the list's bound.
    const wasm::Func f = module_.declare({{I32}, {I64}});
    list_sum_ = f;
    FunctionBuilder b = module_.begin(f);
    b.sizes({m::max_list_bound});
    const Local list = b.param(0);
    const Local n = b.local(I32);
    const Local p = b.local(I32);
    const Local sum = b.local(I64);
    b.get(list).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64).set(n);
    b.get(list).call(rt_.get(Routine::content)).set(p);
    {
        const Label done = b.block();
        const Label next = b.loop({b.size(0) + 1});
        b.get(n).op(i32_eqz).br_if(done);
        b.get(sum);
        item_value(b, p, Rep::i64);
        b.call(rt_.get(Routine::add)).set(sum);
        next_item(b, p, Rep::i64);
        b.get(n).i32(1).op(i32_sub).set(n).br(next);
        b.end(next);
        b.end(done);
    }
    b.get(sum);
    module_.define(std::move(b));
    return f;
}

wasm::Func Lowering::list_has(const Rep element) {
    if (const auto it = list_has_.find(element); it != list_has_.end()) {
        return it->second;
    }
    // [address, value...] -> [flag]: the list holds the value (a ledger's
    // address 0, no party, is in no list).
    std::vector<wasm::ValType> params{I32};
    switch (element) {
    case Rep::i64:
        params.push_back(I64);
        break;
    case Rep::text:
        params.push_back(I32);
        params.push_back(I32);
        break;
    default:
        params.push_back(I32);
        break;
    }
    const wasm::Func f = module_.declare({params, {I32}});
    list_has_.emplace(element, f);
    FunctionBuilder b = module_.begin(f);
    // Sizes: the list's bound, and its texts' bytes in all.
    b.sizes({m::max_list_bound, max_value_size});
    const Local list = b.param(0);
    const Local x = b.param(1);
    const Local n = b.local(I32);
    const Local p = b.local(I32);
    const wasm::Func bytes_eq = rt_.get(Routine::bytes_eq);
    if (element == Rep::ledger) {
        b.get(x).op(i32_eqz);
        const Label none = b.if_();
        b.i32(0).return_();
        b.end(none);
    }
    b.get(list).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64).set(n);
    b.get(list).call(rt_.get(Routine::content)).set(p);
    {
        // A text is compared only with one as long: no more than the item.
        const Label done = b.block();
        const Label next = b.loop({b.size(0) + 1, b.size(1)});
        b.get(n).op(i32_eqz).br_if(done);
        switch (element) {
        case Rep::i64:
            item_value(b, p, element);
            b.get(x).op(i64_eq);
            break;
        case Rep::flag:
            item_value(b, p, element);
            b.get(x).op(i32_eq);
            break;
        case Rep::text:
            item_value(b, p, element);
            b.get(x).get(b.param(2)).call(bytes_eq, {b.item_size(next)});
            break;
        default:
            item_value(b, p, element);
            b.i32(32).get(x).i32(32).call(bytes_eq, {32});
            break;
        }
        {
            const Label found = b.if_();
            b.i32(1).return_();
            b.end(found);
        }
        next_item(b, p, element);
        b.get(n).i32(1).op(i32_sub).set(n).br(next);
        b.end(next);
        b.end(done);
    }
    b.i32(0);
    module_.define(std::move(b));
    return f;
}

const m::Expr* Lowering::literal_items(const m::Expr& e) const {
    // A list written out, directly or as a constant's value.
    const m::Expr* at = &e;
    for (int depth = 0; depth <= max_constant_depth; ++depth) {
        if (at->kind == ExprKind::list) {
            return at;
        }
        if (at->refers != Refers::field) {
            return nullptr;
        }
        const m::Field* k = constant(m::key(at->concept_entry, at->name));
        if (k == nullptr || !k->value) {
            return nullptr;
        }
        at = &*k->value;
    }
    return nullptr;
}

bool Lowering::constant_items(const m::Expr& list) const {
    // Literals (numbers, amounts, dates, texts) and yes or no only.
    const Rep element = element_rep(list.type);
    if (element == Rep::none || element == Rep::ledger) {
        return false;
    }
    return std::ranges::all_of(list.operands, [&](const m::Expr& o) {
        if (o.kind == ExprKind::literal) {
            return o.literal.kind == ast::LiteralKind::text ||
                   literal_value(o.literal, model_.utc_offset_ms).has_value();
        }
        return o.kind == ExprKind::word &&
               (is(o.concept_entry, "val.yes") || is(o.concept_entry, "val.no"));
    });
}

void Lowering::encoded_list(FunctionBuilder& b, const m::Expr& list) {
    // A list of constants, encoded once into the module.
    Bytes out;
    put_head(out, 4, list.operands.size());
    for (const m::Expr& o : list.operands) {
        if (o.kind == ExprKind::literal && o.literal.kind == ast::LiteralKind::text) {
            const Bytes text = text_cbor(o.literal.text);
            out.insert(out.end(), text.begin(), text.end());
        } else if (o.kind == ExprKind::literal) {
            put_int(out, literal_value(o.literal, model_.utc_offset_ms).value_or(0));
        } else {
            out.push_back(is(o.concept_entry, "val.yes") ? 0xF5 : 0xF4);
        }
    }
    b.u32(intern(ByteView(out))).u32(static_cast<std::uint32_t>(out.size()));
}

void Lowering::each(Ctx& c, const m::Each& e) {
    FunctionBuilder& b = *c.b;
    const Rep element = element_rep(e.list.type);
    const std::size_t depth = c.items.size();
    if (c.loops.size() <= depth) {
        c.loops.push_back(
            Ctx::Loop{b.local(I32), b.local(I32), b.local(I64), b.local(I32), b.local(I32)});
    }
    const Ctx::Loop loop = c.loops[depth];
    const Local value_local = element == Rep::i64 ? loop.v64 : loop.a;
    const auto keep = [&] {
        if (element == Rep::text) {
            b.set(loop.b);
        }
        b.set(value_local);
    };
    c.items.emplace(e.name, std::pair{value_local, loop.b});
    if (const m::Expr* items = literal_items(e.list)) {
        // A list written out: the block once for each item, each copy
        // numbering its requirements as the block does.
        const std::uint32_t start = c.requires_count;
        std::uint32_t after = start;
        for (const m::Expr& item : items->operands) {
            value(c, item);
            keep();
            c.requires_count = start;
            statements(c, e.body);
            after = c.requires_count;
        }
        c.requires_count = after;
    } else {
        value(c, e.list);
        b.op(drop).tee(loop.p).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64).set(loop.n);
        b.get(loop.p).call(rt_.get(Routine::content)).set(loop.p);
        // Once per item; a text item's bytes add up to the list's.
        const Label done = b.block();
        const Label next =
            element == Rep::text
                ? b.loop({wasm::Size(e.list.type.bound) + 1, wasm::Size(max_value_size)})
                : b.loop({wasm::Size(e.list.type.bound) + 1});
        if (element == Rep::text) {
            c.item_sizes.insert_or_assign(e.name, b.item_size(next));
        }
        b.get(loop.n).op(i32_eqz).br_if(done);
        item_value(b, loop.p, element);
        keep();
        next_item(b, loop.p, element);
        statements(c, e.body);
        b.get(loop.n).i32(1).op(i32_sub).set(loop.n).br(next);
        b.end(next);
        b.end(done);
    }
    c.items.erase(e.name);
    c.item_sizes.erase(e.name);
}

void Lowering::member(Ctx& c, const m::Expr& e) {
    // X in LIST: X equals one of the items.
    FunctionBuilder& b = *c.b;
    const m::Expr& x = e.operands[0];
    const m::Expr& list = e.operands[1];
    if (const m::Expr* items = literal_items(list)) {
        // A list written out: X = A or X = B ..., each tested.
        for (std::size_t i = 0; i < items->operands.size(); ++i) {
            m::Expr same;
            same.kind = ExprKind::binary;
            same.op = Operator::equals;
            same.type.kind = TypeKind::yes_no;
            same.operands = {x, items->operands[i]};
            binary(c, same);
            if (i > 0) {
                b.op(i32_or);
            }
        }
        return;
    }
    const Rep element = element_rep(list.type);
    value(c, list);
    b.op(drop);
    if (element == Rep::ledger) {
        party_raw(c, x);
    } else {
        value(c, x);
    }
    b.call(list_has(element), {list.type.bound, max_value_size});
}

void Lowering::list_apply(Ctx& c, const m::Expr& e) {
    // sum of LIST, count of LIST.
    FunctionBuilder& b = *c.b;
    const bool count = is(e.concept_entry, "expr.count_of");
    const m::Expr& list = e.operands[0];
    if (const m::Expr* items = literal_items(list)) {
        if (count) {
            b.i64(static_cast<std::int64_t>(items->operands.size()));
            return;
        }
        for (std::size_t i = 0; i < items->operands.size(); ++i) {
            value(c, items->operands[i]);
            if (i > 0) {
                b.call(rt_.get(Routine::add));
            }
        }
        return;
    }
    value(c, list);
    b.op(drop);
    if (count) {
        b.call(rt_.get(Routine::head_arg));
    } else {
        b.call(list_sum(), {list.type.bound});
    }
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
    // Routines are emitted in the order of first use (runtime.hpp).
    static_cast<void>(rt_.get(Routine::map_get));
    const std::string_view input = rt::text_of(rt::Reason::input);
    // The maps the input and the state hold, and their entries at most.
    const std::size_t parties_count = [&] {
        std::size_t count = roles_.size();
        for (const FieldSlot& slot : fields_) {
            count += slot.rep == Rep::ledger ? 1 : 0;
        }
        return count;
    }();

    call_item(b, 5);
    b.tee(instance).op(i32_eqz);
    {
        const Label none = b.if_();
        b.call(rt_.fail(rt::Reason::input));
        b.end(none);
    }
    b.get(instance);
    lookup(b, uint_key(3), view_keys);
    b.set(st);
    // The state, by name.
    b.get(st);
    lookup(b, text_cbor("state"), state_keys);
    expect(b, Rep::text, input);
    b.set(n).set(p);
    {
        const Label found = b.block();
        for (std::size_t i = 0; i < states_.size(); ++i) {
            const std::string& wire = states_[i].wire;
            b.get(p).get(n).u32(intern(wire)).u32(static_cast<std::uint32_t>(wire.size()));
            equal_bytes(b, wire.size());
            const Label same = b.if_();
            b.u32(static_cast<std::uint32_t>(i)).global_set(state_).br(found);
            b.end(same);
        }
        b.call(rt_.fail(rt::Reason::input));
        b.end(found);
    }
    b.get(st);
    lookup(b, text_cbor("fields"), state_keys);
    b.set(fields);
    for (const FieldSlot& slot : fields_) {
        b.get(fields);
        lookup(b, slot.key, fields_.size());
        if (slot.optional) {
            // No party: null.
            b.tee(p).op(i32_eqz).op(i32_eqz);
            {
                const Label present = b.if_(I32);
                b.get(p).load(i32_load8_u).u32(0xF6).op(i32_eq);
                b.else_(present);
                b.i32(0);
                b.end(present);
            }
            {
                const Label none = b.if_(I32);
                b.i32(0);
                b.else_(none);
                b.get(p);
                expect(b, Rep::ledger, input);
                b.end(none);
            }
        } else {
            read_value(b, slot.field->type, input);
        }
        store(b, slot);
    }
    if (previous_used_) {
        // The state before the current one, by name, or null.
        b.get(st);
        lookup(b, text_cbor("previous"), state_keys);
        b.tee(p).op(i32_eqz);
        {
            const Label missing = b.if_();
            b.call(rt_.fail(rt::Reason::input));
            b.end(missing);
        }
        b.get(p).load(i32_load8_u).u32(0xF6).op(i32_ne);
        {
            const Label some = b.if_();
            b.get(p);
            expect(b, Rep::text, input);
            b.set(n).set(p);
            const Label found = b.block();
            for (std::size_t i = 0; i < states_.size(); ++i) {
                const std::string& wire = states_[i].wire;
                b.get(p).get(n).u32(intern(wire)).u32(static_cast<std::uint32_t>(wire.size()));
                equal_bytes(b, wire.size());
                const Label same = b.if_();
                b.u32(static_cast<std::uint32_t>(i + 1)).global_set(previous_).br(found);
                b.end(same);
            }
            b.call(rt_.fail(rt::Reason::input));
            b.end(found);
            b.end(some);
        }
    }
    if (bill_slot_) {
        // The bill the instance keeps, and each charge's amount on it.
        const Local charges = b.local(I32);
        b.get(st);
        lookup(b, text_cbor("bill"), state_keys);
        b.tee(p).op(i32_eqz);
        {
            const Label missing = b.if_();
            b.call(rt_.fail(rt::Reason::input));
            b.end(missing);
        }
        b.get(p).global_set(bill_old_);
        b.get(p).call(rt_.get(Routine::item_end)).get(p).op(i32_sub).global_set(bill_old_length_);
        b.get(p);
        lookup(b, text_cbor("charges"), bill_keys);
        b.set(charges);
        for (const ChargeInfo& k : charges_) {
            b.get(charges);
            lookup(b, k.key, charges_.size());
            b.tee(p);
            const Label present = b.if_(I64);
            b.get(p);
            lookup(b, text_cbor("amount"), 2);
            expect(b, Rep::i64, input);
            b.else_(present);
            b.i64(0);
            b.end(present);
            b.global_set(k.amount);
        }
    }
    if (since_used_) {
        // When the instance last changed state.
        b.get(st);
        lookup(b, text_cbor("since"), state_keys);
        expect(b, Rep::i64, input);
        b.global_set(since_);
    }
    if (!rules_.empty()) {
        // For each time rule, the time it last applied for, or null.
        const Local fired = b.local(I32);
        b.get(st);
        lookup(b, text_cbor("fired"), state_keys);
        b.tee(fired).op(i32_eqz);
        b.get(fired).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne).op(i32_or);
        {
            const Label other = b.if_();
            b.call(rt_.fail(rt::Reason::input));
            b.end(other);
        }
        for (const RuleInfo& rule : rules_) {
            b.get(fired);
            lookup(b, rule.key, rules_.size());
            b.tee(p).op(i32_eqz);
            {
                const Label missing = b.if_();
                b.call(rt_.fail(rt::Reason::input));
                b.end(missing);
            }
            b.get(p).load(i32_load8_u).u32(0xF6).op(i32_ne);
            const Label applied = b.if_();
            b.get(p);
            expect(b, Rep::i64, input);
            b.global_set(rule.fired);
            b.i32(1).global_set(rule.fired_set);
            b.end(applied);
        }
    }
    if (proposals_) {
        // The proposals: an array of [function, arguments].
        b.get(st);
        lookup(b, text_cbor("pending"), state_keys);
        b.tee(p).op(i32_eqz);
        b.get(p).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0x80).op(i32_ne).op(i32_or);
        {
            const Label other = b.if_();
            b.call(rt_.fail(rt::Reason::input));
            b.end(other);
        }
        b.get(p).global_set(pending_);
    }
    b.get(instance);
    lookup(b, uint_key(5), view_keys);
    b.set(parties);
    for (const RoleSlot& role : roles_) {
        b.get(parties);
        lookup(b, role.key, parties_count);
        b.tee(p);
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
    // Routines are emitted in the order of first use (runtime.hpp).
    static_cast<void>(rt_.get(Routine::out_raw));
    // E8: the requests the call made are drafted at the start of the output
    // region; the accept goes after them, and copies them into key 7.
    std::optional<Local> start;
    if (requests_used_) {
        start = b.local(I32);
        b.global_get(rt_.var(rt::Var::out)).set(*start);
    }

    b.global_get(state_).set(index);
    b.get(index).load(i32_load8_u, final_table_).set(final);
    std::size_t party_fields = 0;
    for (const FieldSlot& slot : fields_) {
        party_fields += slot.rep == Rep::ledger && !slot.optional ? 1 : 0;
    }
    const auto count_parties = [&] {
        b.u32(static_cast<std::uint32_t>(party_fields)).set(parties);
        for (const RoleSlot& role : roles_) {
            b.global_get(role.ledger).op(i32_eqz).op(i32_eqz).get(parties).op(i32_add).set(parties);
        }
        // A party field that holds no party is no party of the instance.
        for (const FieldSlot& slot : fields_) {
            if (slot.optional) {
                b.global_get(slot.first)
                    .op(i32_eqz)
                    .op(i32_eqz)
                    .get(parties)
                    .op(i32_add)
                    .set(parties);
            }
        }
    };
    count_parties();
    b.global_get(events_).set(events);
    if (proposals_) {
        // A proposal or an approval: one more event.
        b.global_get(event_kind_).op(i32_eqz).op(i32_eqz).get(events).op(i32_add).set(events);
    }
    if (!rules_.empty()) {
        // A time rule applied: one more event.
        b.global_get(rule_event_).get(events).op(i32_add).set(events);
    }
    if (bill_slot_) {
        // A bill made: one more event.
        b.global_get(bill_new_).get(events).op(i32_add).set(events);
    }
    if (requests_used_) {
        // An answer: one more event.
        b.global_get(answer_event_).get(events).op(i32_add).set(events);
    }
    if (parts_used_) {
        // R30: an instance that issued parts ends.
        b.global_get(parts_made_).get(final).op(i32_or).set(final);
    }
    // [1, {1: state, 2: status, ? 3: parties, ? 4: events, ? 5: true, ? 6:
    // parts}]
    b.i32(4).i64(2).call(head);
    b.i64(1).call(out_int);
    b.i32(2).get(parties).op(i32_eqz).op(i32_eqz).op(i32_add);
    b.get(events).op(i32_eqz).op(i32_eqz).op(i32_add).get(final).op(i32_add);
    if (parts_used_) {
        b.global_get(parts_made_).op(i32_add);
    }
    if (requests_used_) {
        b.global_get(requests_).op(i32_eqz).op(i32_eqz).op(i32_add);
    }
    b.op(i64_extend_i32_u).set(count);
    b.i32(5).get(count).call(head);
    // 1: {"state": NAME, "fields": {...}, ? "pending": [...], ? "previous":
    // NAME or null}, keys in canonical order.
    b.i64(1).call(out_int);
    const auto write_state = [&] {
        // Its bytes count at most 64 KiB: the code refuses a larger state.
        b.cap_begin();
        b.global_get(rt_.var(rt::Var::out)).set(mark);
        b.i32(5)
            .i64(2 + (proposals_ ? 1 : 0) + (previous_used_ ? 1 : 0) + (rules_.empty() ? 0 : 1) +
                 (since_used_ ? 1 : 0) + (bill_slot_ ? 1 : 0))
            .call(head);
        if (bill_slot_) {
            // "bill": the bill made in this call, or the one kept (R26).
            out_key(b, text_cbor("bill"));
            write_bill(b);
        }
        if (!rules_.empty()) {
            // "fired": {RULE: the time it last applied for, or null}.
            out_key(b, text_cbor("fired"));
            b.i32(5).i64(static_cast<std::int64_t>(rules_.size())).call(head);
            std::vector<const RuleInfo*> sorted;
            for (const RuleInfo& rule : rules_) {
                sorted.push_back(&rule);
            }
            std::ranges::sort(sorted, {}, &RuleInfo::key);
            for (const RuleInfo* rule : sorted) {
                out_key(b, rule->key);
                b.global_get(rule->fired_set);
                const Label applied = b.if_();
                b.global_get(rule->fired).call(out_int);
                b.else_(applied);
                b.call(rt_.get(Routine::out_null));
                b.end(applied);
            }
        }
        if (since_used_) {
            out_key(b, text_cbor("since"));
            b.global_get(since_).call(out_int);
        }
        out_key(b, text_cbor("state"));
        state_name(b, index);
        out_key(b, text_cbor("fields"));
        b.i32(5).i64(static_cast<std::int64_t>(fields_.size())).call(head);
        std::vector<const FieldSlot*> sorted;
        for (const FieldSlot& slot : fields_) {
            sorted.push_back(&slot);
        }
        std::ranges::sort(sorted, {}, &FieldSlot::key);
        for (const FieldSlot* slot : sorted) {
            out_key(b, slot->key);
            if (slot->optional) {
                b.global_get(slot->first).op(i32_eqz);
                const Label none = b.if_();
                b.call(rt_.get(Routine::out_null));
                b.else_(none);
                load(b, *slot);
                out_value(b, slot->rep);
                b.end(none);
                continue;
            }
            load(b, *slot);
            out_value(b, slot->rep);
        }
        if (proposals_) {
            out_key(b, text_cbor("pending"));
            write_pending(b);
        }
        if (previous_used_) {
            out_key(b, text_cbor("previous"));
            b.global_get(previous_).op(i32_eqz);
            const Label none = b.if_();
            b.call(rt_.get(Routine::out_null));
            b.else_(none);
            b.global_get(previous_).i32(1).op(i32_sub).set(index);
            state_name(b, index);
            b.global_get(state_).set(index);
            b.end(none);
        }
        // A state holds at most 64 KiB (spec section 15).
        b.global_get(rt_.var(rt::Var::out)).get(mark).op(i32_sub);
        b.u32(static_cast<std::uint32_t>(max_state_size)).op(i32_gt_u);
        {
            const Label large = b.if_();
            b.call(rt_.fail(rt::Reason::output));
            b.end(large);
        }
        b.cap_end(max_state_size);
    };
    write_state();
    // 2: the status, the state's name.
    b.i64(2).call(out_int);
    state_name(b, index);
    const auto write_parties = [&] {
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
                    entries.push_back({&slot.key, {slot.first, slot.optional}});
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
                out_key(b, *key);
                b.global_get(global);
                out_value(b, Rep::ledger);
                if (bound) {
                    b.end(*bound);
                }
            }
            b.end(some);
        }
    };
    write_parties();
    // 4: each state change: [state, null] (after a proposal's or an
    // approval's: [propose or approve, ACTION]).
    b.get(events);
    {
        const Label some = b.if_();
        b.i64(4).call(out_int);
        b.i32(4).get(events).op(i64_extend_i32_u).call(head);
        if (proposals_) {
            write_event(b);
        }
        if (!rules_.empty()) {
            write_rule_event(b);
        }
        if (requests_used_) {
            write_answer_event(b);
        }
        // Each state change a call made: at most the most an action makes.
        const Label done = b.block();
        const Label next = b.loop({max_transitions_ + 1});
        b.get(i);
        if (proposals_ || !rules_.empty() || bill_slot_ || requests_used_) {
            b.global_get(events_);
        } else {
            b.get(events);
        }
        b.op(i32_ge_u).br_if(done);
        b.i32(4).i64(2).call(head);
        b.get(i).i32(2).op(i32_shl).load(i32_load, events_area_).set(index);
        state_name(b, index);
        b.call(rt_.get(Routine::out_null));
        b.get(i).i32(1).op(i32_add).set(i).br(next);
        b.end(next);
        b.end(done);
        if (bill_slot_) {
            // [DOCUMENT, BILL]: the bill made, as the state keeps it.
            b.global_get(bill_new_);
            const Label made = b.if_();
            b.region_begin(region_bill);
            const std::string document = fields_[*bill_slot_].wire;
            b.i32(4).i64(2).call(head);
            b.u32(intern(document)).u32(static_cast<std::uint32_t>(document.size()));
            out_text(b, document.size());
            b.global_get(bill_at_).global_get(bill_length_);
            out_raw(b, max_state_size);
            b.region_end();
            b.end(made);
        }
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
    if (parts_used_) {
        // 6: the parts, each {1: state, 2: status, 3: parties} (R30): the
        // instance's fields but the amount (the part), the holder (its
        // recipient), the fields `with` gives, and those Bo adds (none);
        // roles an action binds unbound; the first state, from now on.
        const Local cp = b.local(I32);
        const Local cr = b.local(I32);
        const Local left = b.local(I32);
        const wasm::Func head_arg = rt_.get(Routine::head_arg);
        const wasm::Func content = rt_.get(Routine::content);
        b.global_get(parts_made_);
        const Label made = b.if_();
        b.region_begin(region_parts);
        b.i64(6).call(out_int);
        b.global_get(parts_list_).call(head_arg).op(i32_wrap_i64).set(left);
        b.i32(4).get(left).op(i64_extend_i32_u).call(head);
        b.global_get(parts_list_).call(content).set(cp);
        b.global_get(parts_to_).call(content).set(cr);
        for (const auto& [at, part] : part_fields_) {
            const FieldSlot& slot = fields_[at];
            b.global_get(part.given);
            const Label given = b.if_();
            b.global_get(part.first);
            if (pair_rep(slot.rep)) {
                b.global_get(part.second);
            }
            store(b, slot);
            b.end(given);
        }
        for (const FieldSlot& slot : fields_) {
            if (slot.empty_at_start) {
                b.i32(0).global_set(slot.first);
            }
        }
        for (const RoleSlot& role : roles_) {
            if (role.party->binding == m::Binding::action) {
                b.i32(0).global_set(role.ledger);
            }
        }
        b.i32(0).global_set(state_);
        if (since_used_) {
            call_item(b, 7);
            expect(b, Rep::i64, rt::text_of(rt::Reason::input));
            b.global_set(since_);
        }
        for (const RuleInfo& rule : rules_) {
            b.i32(0).global_set(rule.fired_set);
        }
        if (proposals_) {
            for (const wasm::Global g : {pending_, drop_, add_args_}) {
                b.i32(0).global_set(g);
            }
        }
        if (previous_used_) {
            b.i32(0).global_set(previous_);
        }
        const FieldSlot& amount = fields_[field_index_.at("field.amount")];
        const FieldSlot& holder = fields_[field_index_.at("field.holder")];
        {
            // Each part: no more than the parts' list holds.
            const Label done = b.block();
            const Label next = b.loop({parts_bound() + 1});
            b.get(left).op(i32_eqz).br_if(done);
            item_value(b, cp, Rep::i64);
            b.global_set(amount.first);
            item_value(b, cr, Rep::ledger);
            b.global_set(holder.first);
            next_item(b, cp, Rep::i64);
            next_item(b, cr, Rep::ledger);
            b.i32(0).set(index);
            count_parties();
            b.i32(5).i32(2).get(parties).op(i32_eqz).op(i32_eqz).op(i32_add);
            b.op(i64_extend_i32_u).call(head);
            b.i64(1).call(out_int);
            write_state();
            b.i64(2).call(out_int);
            state_name(b, index);
            write_parties();
            b.get(left).i32(1).op(i32_sub).set(left).br(next);
            b.end(next);
            b.end(done);
        }
        b.region_end();
        b.end(made);
    }
    if (requests_used_) {
        // 7: the requests, as drafted (at most 16, each at most 4,096 bytes
        // of params and its kind, deadline, and reply).
        b.global_get(requests_);
        const Label some = b.if_();
        b.i64(7).call(out_int);
        b.i32(4).global_get(requests_).op(i64_extend_i32_u).call(head);
        b.u32(rt::layout::output_base).get(*start).u32(rt::layout::output_base).op(i32_sub);
        out_raw(b, most_requests_ * (m::max_request_params + 128));
        b.end(some);
        b.get(*start).call(rt_.get(Routine::out_finish_at));
    } else {
        b.call(rt_.get(Routine::out_finish));
    }
    module_.define(std::move(b));
    return f;
}

void Lowering::finish(FunctionBuilder& b) {
    b.global_get(rt_.var(rt::Var::needs));
    const Label needs = b.if_();
    if (requests_used_) {
        // A call that waits for consents makes no requests: its drafts go.
        b.u32(rt::layout::output_base).global_set(rt_.var(rt::Var::out));
    }
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

void Lowering::record_event_at(FunctionBuilder& b, const Local state) {
    b.global_get(events_).i32(2).op(i32_shl).get(state).store(i32_store, events_area_);
    b.global_get(events_).i32(1).op(i32_add).global_set(events_);
}

void Lowering::write_pending(FunctionBuilder& b) {
    // The proposals kept, but the one an approval took, then the one a
    // proposal adds: [function, arguments] each.
    const Local q = b.local(I32);
    const Local n = b.local(I32);
    const Local k = b.local(I32);
    const Local next = b.local(I32);
    const wasm::Func head = rt_.get(Routine::out_head);
    const wasm::Func item_end = rt_.get(Routine::item_end);
    static_cast<void>(rt_.get(Routine::out_raw));
    b.global_get(pending_);
    {
        const Label some = b.if_(I32);
        b.global_get(pending_).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64);
        b.else_(some);
        b.i32(0);
        b.end(some);
    }
    b.set(n);
    b.i32(4).get(n);
    b.global_get(drop_).op(i32_eqz).op(i32_eqz).op(i32_sub);
    b.global_get(add_args_).op(i32_eqz).op(i32_eqz).op(i32_add);
    b.op(i64_extend_i32_u).call(head);
    b.get(n);
    {
        const Label some = b.if_();
        b.global_get(pending_).call(rt_.get(Routine::content)).set(q);
        // At most 16 proposals, all of them within the state.
        const Label done = b.block();
        const Label loop = b.loop({rt::max_needs + 1, max_state_size});
        b.get(k).get(n).op(i32_ge_u).br_if(done);
        b.get(q).call(item_end).set(next);
        b.get(k).i32(1).op(i32_add).global_get(drop_).op(i32_ne);
        {
            const Label kept = b.if_();
            b.get(q).get(next).get(q).op(i32_sub);
            out_raw(b, b.item_size(loop));
            b.end(kept);
        }
        b.get(next).set(q);
        b.get(k).i32(1).op(i32_add).set(k).br(loop);
        b.end(loop);
        b.end(done);
        b.end(some);
    }
    b.global_get(add_args_);
    {
        const Label added = b.if_();
        b.i32(4).i64(2).call(head);
        b.global_get(add_name_).global_get(add_length_);
        out_text(b, max_build_name);
        b.global_get(add_args_);
        b.global_get(add_args_).call(item_end).global_get(add_args_).op(i32_sub);
        out_raw(b, max_value_size);
        b.end(added);
    }
}

void Lowering::write_event(FunctionBuilder& b) {
    // [propose, ACTION] or [approve, ACTION].
    b.global_get(event_kind_);
    const Label some = b.if_();
    b.i32(4).i64(2).call(rt_.get(Routine::out_head));
    static_cast<void>(rt_.get(Routine::out_text));
    b.global_get(event_kind_).i32(1).op(i32_eq);
    {
        constexpr std::string_view propose_event = "propose";
        const Label propose = b.if_();
        b.u32(intern(propose_event)).u32(static_cast<std::uint32_t>(propose_event.size()));
        out_text(b, propose_event.size());
        b.else_(propose);
        b.u32(intern(m::approve_function))
            .u32(static_cast<std::uint32_t>(m::approve_function.size()));
        out_text(b, m::approve_function.size());
        b.end(propose);
    }
    b.global_get(event_name_).global_get(event_length_);
    out_text(b, max_build_name);
    b.end(some);
}

void Lowering::write_rule_event(FunctionBuilder& b) {
    // [when, {"late": ms, "rule": FUNCTION, "time": ms}]: the time it
    // applies at, and how much later the call came.
    b.global_get(rule_event_);
    const Label some = b.if_();
    const wasm::Func head = rt_.get(Routine::out_head);
    static_cast<void>(rt_.get(Routine::out_raw));
    const wasm::Func out_int = rt_.get(Routine::out_int);
    b.i32(4).i64(2).call(head);
    constexpr std::string_view when_event = "when";
    b.u32(intern(when_event)).u32(static_cast<std::uint32_t>(when_event.size()));
    out_text(b, when_event.size());
    b.i32(5).i64(3).call(head);
    out_key(b, text_cbor("late"));
    b.global_get(rule_late_).call(out_int);
    out_key(b, text_cbor("rule"));
    b.global_get(rule_name_).global_get(rule_length_);
    out_text(b, max_build_name);
    out_key(b, text_cbor("time"));
    b.global_get(rule_time_).call(out_int);
    b.end(some);
}

void Lowering::emit_entry(const wasm::Func entry) {
    FunctionBuilder b = module_.begin(entry);
    const Local p = b.local(I32);
    const Local n = b.local(I32);
    // Sizes: the input's items and map keys, at most (input_shape), for what
    // reading it costs.
    b.sizes({rt::max_input_items, rt::max_input_items / 2});
    b.call(rt_.get(Routine::read_call), {b.size(0), b.size(1)}).op(drop);
    call_item(b, 1);
    expect(b, Rep::text, rt::text_of(rt::Reason::input));
    b.set(n).set(p);
    std::vector<std::pair<std::string, wasm::Func>> functions{{creation_, creation_function_}};
    for (const ActionInfo& a : actions_) {
        if (!a.rule_only) {
            functions.emplace_back(a.wire, a.function);
        }
    }
    if (proposals_) {
        functions.emplace_back(std::string(m::approve_function), approve_function_);
    }
    for (const RuleInfo& r : rules_) {
        functions.emplace_back(r.wire, r.function);
    }
    if (requests_used_) {
        functions.emplace_back(std::string(m::reply_function), reply_function_);
    }
    std::ranges::sort(functions, {}, &std::pair<std::string, wasm::Func>::first);
    for (const auto& [name, f] : functions) {
        b.get(p).get(n).u32(intern(name)).u32(static_cast<std::uint32_t>(name.size()));
        equal_bytes(b, name.size());
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
    // Routines are emitted in the order of first use (runtime.hpp).
    static_cast<void>(rt_.get(Routine::map_get));
    const wasm::Func head_arg = rt_.get(Routine::head_arg);
    std::vector<const RoleSlot*> roles;
    for (const RoleSlot& role : roles_) {
        if (role.party->binding == m::Binding::creation) {
            roles.push_back(&role);
        }
    }
    std::vector<const FieldSlot*> fields;
    for (const FieldSlot& slot : fields_) {
        // Not a party field that starts with a role (R2) or with none (R20).
        if (!slot.starts_with && !slot.empty_at_start) {
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
        // The map has these keys (checked above): at most two.
        lookup(b, text_cbor(name), 2);
        b.tee(map);
        b.load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne);
        b.get(map).op(i32_eqz).op(i32_or);
        b.get(map).call(head_arg).i64(static_cast<std::int64_t>(count)).op(i64_ne).op(i32_or);
        const Label other = b.if_();
        refuse(b, reason);
        b.end(other);
    };
    const auto defaulted = [](const FieldSlot* slot) {
        return slot->field->initial.has_value();
    };
    if (!fields.empty() && std::ranges::none_of(fields, defaulted)) {
        part("fields", fields.size());
        for (const FieldSlot* slot : fields) {
            b.get(map);
            lookup(b, slot->key, fields.size());
            read_value(b, slot->field->type, "bo:argument " + slot->wire);
            store(b, *slot);
        }
    } else if (!fields.empty()) {
        // A field with a default may be left out: the map has every field
        // without one, and some of those with one, and no other key.
        const auto required =
            static_cast<std::int64_t>(std::ranges::count_if(fields, std::not_fn(defaulted)));
        const auto total = static_cast<std::int64_t>(fields.size());
        const std::string reason = "bo:argument fields";
        const Local count = b.local(I64);
        const Local given = b.local(I64);
        const Local item = b.local(I32);
        b.get(args);
        lookup(b, text_cbor("fields"), 2);
        b.tee(map);
        b.load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne);
        b.get(map).op(i32_eqz).op(i32_or);
        {
            const Label other = b.if_();
            refuse(b, reason);
            b.end(other);
        }
        b.get(map).call(head_arg).tee(count).i64(required).op(i64_lt_s);
        b.get(count).i64(total).op(i64_gt_s).op(i32_or);
        {
            const Label other = b.if_();
            refuse(b, reason);
            b.end(other);
        }
        b.i64(required).set(given);
        Ctx c;
        c.b = &b;
        c.wire = creation_;
        for (const FieldSlot* slot : fields) {
            b.get(map);
            lookup(b, slot->key, fields.size());
            if (!slot->field->initial) {
                read_value(b, slot->field->type, "bo:argument " + slot->wire);
                store(b, *slot);
                continue;
            }
            b.tee(item);
            const Label present = b.if_();
            b.get(item);
            read_value(b, slot->field->type, "bo:argument " + slot->wire);
            store(b, *slot);
            b.get(given).i64(1).op(i64_add).set(given);
            b.else_(present);
            value(c, *slot->field->initial);
            store(b, *slot);
            b.end(present);
        }
        // A key that names no field.
        b.get(count).get(given).op(i64_ne);
        {
            const Label other = b.if_();
            refuse(b, reason);
            b.end(other);
        }
    }
    if (!roles.empty()) {
        part("parties", roles.size());
        for (const RoleSlot* role : roles) {
            b.get(map);
            lookup(b, role->key, roles.size());
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
    if (since_used_) {
        call_item(b, 7);
        expect(b, Rep::i64, rt::text_of(rt::Reason::input));
        b.global_set(since_);
    }
    if (bill_slot_) {
        // R26: the bill on the lines given.
        b.call(compute_bill());
    }
    b.call(write_accept());
    module_.define(std::move(b));
}

void Lowering::arguments(Ctx& c) {
    FunctionBuilder& b = *c.b;
    const m::Action& a = *c.action->action;
    const Local args = b.local(I32);
    // Routines are emitted in the order of first use (runtime.hpp).
    static_cast<void>(rt_.get(Routine::map_get));
    // Arguments of the function's shape: a map of its inputs, and the role
    // it binds (the fuel bound holds for those; others are refused).
    const std::uint64_t entries = a.inputs.size() + (c.action->binds ? 1 : 0);
    if (c.args) {
        b.get(*c.args);
    } else {
        call_item(b, 2);
    }
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
        lookup(b, roles_[*c.action->binds].key, entries);
        b.set(given);
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
        const Local length = pair_rep(rep) ? b.local(I32) : value;
        b.get(args);
        lookup(b, text_cbor(wire), entries);
        read_value(b, input.type, "bo:argument " + wire);
        if (pair_rep(rep)) {
            b.set(length);
        }
        b.set(value);
        c.inputs.emplace(m::key(input.word, input.name), std::pair{value, length});
    }
    if (c.action->binds && roles_[*c.action->binds].party->each_call) {
        // R23: each call names the role's ledger, and binds the role to it.
        const RoleSlot& role = roles_[*c.action->binds];
        const std::string reason = "bo:argument " + role.wire;
        b.get(given).op(i32_eqz);
        {
            const Label missing = b.if_();
            refuse(b, reason);
            b.end(missing);
        }
        b.get(given);
        expect(b, Rep::ledger, reason);
        b.global_set(role.ledger);
    } else if (c.action->binds) {
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
            b.i32(32).global_get(role.ledger).i32(32);
            equal_bytes(b, 32);
            b.op(i32_eqz);
            const Label other = b.if_();
            refuse(b, reason);
            b.end(other);
            b.end(repeated);
        }
        b.end(unbound);
    }
}

void Lowering::entry_check(Ctx& c) {
    // A built-in action is refused first in a state it cannot start from.
    const m::Action& a = *c.action->action;
    if (!a.terms) {
        return;
    }
    const std::optional<std::set<std::string>> entry = m::entry_states(a);
    if (!entry) {
        return;
    }
    std::vector<std::uint32_t> indices;
    for (const std::string& k : *entry) {
        if (const auto it = state_index_.find(k); it != state_index_.end()) {
            indices.push_back(static_cast<std::uint32_t>(it->second));
        }
    }
    if (indices.empty()) {
        return;
    }
    FunctionBuilder& b = *c.b;
    for (std::size_t i = 0; i < indices.size(); ++i) {
        b.global_get(state_).u32(indices[i]).op(i32_eq);
        if (i > 0) {
            b.op(i32_or);
        }
    }
    b.op(i32_eqz);
    const Label other = b.if_();
    refuse(b, "bo:state " + c.wire);
    b.end(other);
}

void Lowering::depth_check(Ctx& c) {
    // A part at depth 8 creates no parts (spec section 15): the instance
    // view's [parent, depth] (key 6 of input key 5), which only parts have.
    FunctionBuilder& b = *c.b;
    call_item(b, 5);
    lookup(b, uint_key(6), view_keys);
    b.tee(c.t32);
    const Label part = b.if_();
    b.get(c.t32).call(rt_.get(Routine::content)).call(rt_.get(Routine::item_end));
    expect(b, Rep::i64, rt::text_of(rt::Reason::input));
    b.i64(static_cast<std::int64_t>(m::max_part_depth)).op(i64_ge_s);
    {
        const Label deep = b.if_();
        refuse(b, "bo:depth " + c.wire);
        b.end(deep);
    }
    b.end(part);
}

std::uint64_t Lowering::parts_bound() const {
    std::uint64_t most = 0;
    for (const ActionInfo& a : actions_) {
        const m::Do* d = a.parts ? m::issued_parts(*a.action) : nullptr;
        if (d == nullptr || d->args.empty()) {
            continue;
        }
        const std::uint64_t parts = d->args[0].type.bound;
        const std::uint64_t to = d->to ? d->to->type.bound : parts;
        most = std::max(most, std::min(parts, to));
    }
    return most;
}

void Lowering::issue_parts(Ctx& c, const m::Do& d) {
    // R30: the lists of amounts and recipients, as many of one as of the
    // other and one at least, and the fields each part gets, computed now;
    // the output writes the parts after the instance (write_accept).
    FunctionBuilder& b = *c.b;
    const wasm::Func head_arg = rt_.get(Routine::head_arg);
    value(c, d.args[0]);
    b.op(drop).global_set(parts_list_);
    value(c, *d.to);
    b.op(drop).global_set(parts_to_);
    b.global_get(parts_list_).call(head_arg).global_get(parts_to_).call(head_arg).op(i64_ne);
    b.global_get(parts_list_).call(head_arg).op(i64_eqz).op(i32_or);
    {
        const Label other = b.if_();
        refuse(b, "bo:parts " + c.wire);
        b.end(other);
    }
    for (const m::Set& w : d.with) {
        const std::size_t index = field_index_.at(m::key(w.target.concept_entry, w.target.name));
        const FieldSlot& slot = fields_[index];
        const PartField& part = part_fields_.at(index);
        if (slot.optional) {
            party_raw(c, w.value);
        } else {
            value(c, w.value);
        }
        if (pair_rep(slot.rep)) {
            b.global_set(part.second);
        }
        b.global_set(part.first);
        b.i32(1).global_set(part.given);
    }
    b.i32(1).global_set(parts_made_);
}

void Lowering::emit_action(const ActionInfo& info) {
    FunctionBuilder b = module_.begin(info.function);
    const m::Action& a = *info.action;
    if (a.agents_propose) {
        // The call's arguments, run as a call (not an approval).
        b.call(load_instance());
        call_item(b, 2);
        b.i32(0).call(info.core);
        module_.define(std::move(b));
        emit_core(info);
        return;
    }
    Ctx c;
    c.b = &b;
    c.action = &info;
    c.wire = info.wire;
    c.signer = b.local(I32);
    c.t32 = b.local(I32);
    c.t64 = b.local(I64);
    c.t64b = b.local(I64);
    b.call(load_instance());
    entry_check(c);
    if (info.parts) {
        depth_check(c);
    }
    arguments(c);
    const wasm::Func consent = rt_.get(Routine::consent);
    // The starter agrees through the call (the home) or its consent. A
    // built-in action without one is the home's own word: its caller signs.
    if (a.by) {
        value(c, *a.by);
        b.call(consent).set(c.signer);
    } else if (a.word != nullptr) {
        call_item(b, 3);
        b.call(rt_.get(Routine::content)).call(consent).set(c.signer);
    }
    // R3, R8, R21, R31: the consents the action needs.
    for (const m::Consent& k : a.consents) {
        if (asks(k)) {
            consent_of(c, k.party);
        }
    }
    statements(c, a.body);
    finish(b);
    module_.define(std::move(b));
}

void Lowering::emit_core(const ActionInfo& info) {
    // AI agents may only propose this action (U3): an agent's call is kept
    // as a proposal; approve runs it again, with the proposal's arguments,
    // and then its starter must be a person who proves presence.
    FunctionBuilder b = module_.begin(info.core);
    Ctx c;
    c.b = &b;
    c.action = &info;
    c.wire = info.wire;
    c.args = b.param(0);
    const Local approving = b.param(1);
    c.signer = b.local(I32);
    c.t32 = b.local(I32);
    c.t64 = b.local(I64);
    c.t64b = b.local(I64);
    const m::Action& a = *info.action;
    entry_check(c);
    if (info.parts) {
        depth_check(c);
    }
    arguments(c);
    const wasm::Func consent = rt_.get(Routine::consent);
    if (a.by) {
        value(c, *a.by);
        b.call(consent).set(c.signer);
    } else {
        call_item(b, 3);
        b.call(rt_.get(Routine::content)).call(consent).set(c.signer);
    }
    const std::uint8_t key_kind[] = {0x01};
    b.get(approving);
    {
        const Label approval = b.if_();
        // A missing consent leaves the approval waiting for it.
        b.get(c.signer);
        {
            const Label known = b.if_();
            b.get(c.signer).call(rt_.get(Routine::in_person)).op(i32_eqz);
            const Label absent = b.if_();
            refuse(b, "bo:approve " + info.wire);
            b.end(absent);
            b.end(known);
        }
        b.i32(2).global_set(event_kind_);
        b.else_(approval);
        // An AI agent's signer (kind 2): the call becomes a proposal.
        b.get(c.signer);
        {
            const Label known = b.if_();
            b.get(c.signer).u32(intern(ByteView(key_kind))).i32(1);
            b.call(rt_.get(Routine::map_get), {signer_keys, 1}).tee(c.t32);
            b.op(i32_eqz).op(i32_eqz);
            {
                const Label kind = b.if_(I32);
                b.get(c.t32).load(i32_load8_u).i32(2).op(i32_eq);
                b.else_(kind);
                b.i32(0);
                b.end(kind);
            }
            const Label agent = b.if_();
            b.global_get(pending_).call(rt_.get(Routine::head_arg));
            b.i64(static_cast<std::int64_t>(rt::max_needs)).op(i64_ge_u);
            {
                const Label full = b.if_();
                refuse(b, "bo:pending");
                b.end(full);
            }
            b.u32(intern(info.wire)).global_set(add_name_);
            b.u32(static_cast<std::uint32_t>(info.wire.size())).global_set(add_length_);
            b.get(*c.args).global_set(add_args_);
            b.i32(1).global_set(event_kind_);
            b.u32(intern(info.wire)).global_set(event_name_);
            b.u32(static_cast<std::uint32_t>(info.wire.size())).global_set(event_length_);
            b.call(write_accept()).return_();
            b.end(agent);
            b.end(known);
        }
        b.end(approval);
    }
    b.u32(intern(info.wire)).global_set(event_name_);
    b.u32(static_cast<std::uint32_t>(info.wire.size())).global_set(event_length_);
    for (const m::Consent& k : a.consents) {
        if (asks(k)) {
            consent_of(c, k.party);
        }
    }
    statements(c, a.body);
    finish(b);
    module_.define(std::move(b));
}

void Lowering::emit_approve(const wasm::Func f) {
    // approve {"function": NAME, "arguments": ARGS}: the first proposal
    // with that function and those arguments, run as its action.
    FunctionBuilder b = module_.begin(f);
    const Local args = b.local(I32);
    const Local name = b.local(I32);
    const Local length = b.local(I32);
    const Local given = b.local(I32);
    const Local q = b.local(I32);
    const Local n = b.local(I32);
    const Local k = b.local(I32);
    const Local x = b.local(I32);
    // Routines are emitted in the order of first use (runtime.hpp).
    static_cast<void>(rt_.get(Routine::map_get));
    const wasm::Func item_end = rt_.get(Routine::item_end);
    const wasm::Func content = rt_.get(Routine::content);
    const wasm::Func head_arg = rt_.get(Routine::head_arg);
    static_cast<void>(rt_.get(Routine::bytes_eq));
    b.call(load_instance());
    call_item(b, 2);
    b.tee(args).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne);
    b.get(args).call(head_arg).i64(2).op(i64_ne).op(i32_or);
    {
        const Label other = b.if_();
        refuse(b, "bo:arguments");
        b.end(other);
    }
    b.get(args);
    lookup(b, text_cbor("function"), 2);
    expect(b, Rep::text, "bo:argument function");
    b.set(length).set(name);
    b.get(args);
    lookup(b, text_cbor("arguments"), 2);
    b.tee(given).op(i32_eqz);
    {
        const Label missing = b.if_();
        refuse(b, "bo:argument arguments");
        b.end(missing);
    }
    b.global_get(pending_).call(head_arg).op(i32_wrap_i64).set(n);
    b.global_get(pending_).call(content).set(q);
    {
        // At most 16 proposals, all within the state; a function's name is
        // at most 64 bytes, and arguments are compared only with as many.
        const Label found = b.block();
        const Label next = b.loop({rt::max_needs + 1, max_state_size});
        b.get(k).get(n).op(i32_ge_u);
        {
            const Label none = b.if_();
            refuse(b, "bo:proposal");
            b.end(none);
        }
        // [function, arguments]: the same function, and the same bytes.
        b.get(q).call(content).tee(x).call(content);
        b.get(x).call(head_arg).op(i32_wrap_i64).get(name).get(length);
        equal_bytes(b, max_build_name);
        {
            const Label same = b.if_();
            b.get(x).call(item_end).tee(x);
            b.get(x).call(item_end).get(x).op(i32_sub);
            b.get(given).get(given).call(item_end).get(given).op(i32_sub);
            equal_bytes(b, b.item_size(next));
            b.br_if(found);
            b.end(same);
        }
        b.get(q).call(item_end).set(q);
        b.get(k).i32(1).op(i32_add).set(k).br(next);
        b.end(next);
        b.end(found);
    }
    b.get(k).i32(1).op(i32_add).global_set(drop_);
    for (const ActionInfo& a : actions_) {
        if (!a.action->agents_propose) {
            continue;
        }
        b.get(name).get(length).u32(intern(a.wire)).u32(static_cast<std::uint32_t>(a.wire.size()));
        equal_bytes(b, a.wire.size());
        const Label same = b.if_();
        b.get(given).i32(1).call(a.core).return_();
        b.end(same);
    }
    refuse(b, "bo:proposal");
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
                [&](const m::Each& e) { each(c, e); },
                [&](const m::Reject& r) { refuse(b, r.message); },
                [&](const m::Set& st) {
                    const FieldSlot& slot =
                        fields_[field_index_.at(m::key(st.target.concept_entry, st.target.name))];
                    // A field that may hold no party takes none, or another's none.
                    if (slot.optional) {
                        party_raw(c, st.value);
                    } else {
                        value(c, st.value);
                    }
                    store(b, slot);
                    if (bill_slot_ && &slot == &fields_[*bill_slot_]) {
                        // R26: new lines make a new bill, at this call's time.
                        b.call(compute_bill());
                    }
                },
                [&](const m::Transition& t) { transition(c, t); },
                [&](const m::Do& d) {
                    // In an action, parts issued (R30); in a time rule, an
                    // action it does (a duty, none).
                    BO_ASSERT(!d.executor);
                    if (d.parts) {
                        issue_parts(c, d);
                    } else if (!d.obligation) {
                        run_action(c, d);
                    }
                },
                [&](const m::Request& r) { request(c, r); },
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
        consent_of(c, e.operands[0]);
    } else if (e.kind == ExprKind::word && is(e.concept_entry, "cond.in_person")) {
        // R13: the starter's signer, once its consent is there.
        b.get(c.signer);
        const Label known = b.if_();
        b.get(c.signer).call(rt_.get(Routine::in_person)).op(i32_eqz);
        const Label absent = b.if_();
        refuse(b, "bo:in-person " + c.wire);
        b.end(absent);
        b.end(known);
    } else {
        value(c, e);
        b.op(i32_eqz);
        const Label failed = b.if_();
        const std::string prefix = "bo:requires " + c.wire + " ";
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
    if (c.answer) {
        // E8: an answer to an instance that has ended changes no state.
        b.get(c.final_before).op(i32_eqz);
        const Label live = b.if_();
        c.answer = false;
        transition(c, t);
        c.answer = true;
        b.end(live);
        return;
    }
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
        refuse(b, "bo:state " + c.wire);
        b.end(other);
    }
    if (since_used_) {
        // The instance changes state now.
        now(c);
        b.global_set(since_);
    }
    if (is(t.to.concept_entry, "expr.previous_state")) {
        // Back to the state before the current one; none refuses.
        b.global_get(previous_).op(i32_eqz);
        {
            const Label none = b.if_();
            refuse(b, "bo:state " + c.wire);
            b.end(none);
        }
        b.global_get(previous_).i32(1).op(i32_sub).set(c.t32);
        b.global_get(state_).i32(1).op(i32_add).global_set(previous_);
        b.get(c.t32).global_set(state_);
        record_event_at(b, c.t32);
        return;
    }
    const std::size_t to = state_index_.at(m::key(t.to.concept_entry, t.to.name));
    if (previous_used_) {
        b.global_get(state_).i32(1).op(i32_add).global_set(previous_);
    }
    b.u32(static_cast<std::uint32_t>(to)).global_set(state_);
    record_event(b, to);
}

void Lowering::now(Ctx& c) {
    // The call's registration time (input key 7).
    call_item(*c.b, 7);
    expect(*c.b, Rep::i64, rt::text_of(rt::Reason::input));
}

void Lowering::due(Ctx& c) {
    // The instance's due date (a field, or the same for every instance).
    m::Expr field;
    field.kind = ExprKind::word;
    field.concept_entry = find_concept("field.due");
    field.refers = Refers::field;
    field.type.kind = TypeKind::date;
    reference(c, field);
}

void Lowering::shift(Ctx& c, const m::Expr& duration, const bool earlier) {
    // [time] -> [time]: so long later (or earlier); months by the calendar.
    FunctionBuilder& b = *c.b;
    value(c, duration);
    if (earlier) {
        b.call(rt_.get(Routine::neg));
    }
    if (duration.type.calendar) {
        b.i64(model_.utc_offset_ms).call(rt_.get(Routine::add_months));
    } else {
        b.call(rt_.get(Routine::add));
    }
}

void Lowering::moment(Ctx& c, const m::Trigger& trigger) {
    // The time a rule's event names.
    FunctionBuilder& b = *c.b;
    switch (trigger.kind) {
    case m::TriggerKind::date:
        value(c, *trigger.value);
        return;
    case m::TriggerKind::before_due:
        due(c);
        shift(c, *trigger.value, true);
        return;
    case m::TriggerKind::overdue:
        // Overdue: from the day after the due date; overdue N: from N after it.
        due(c);
        if (trigger.value != nullptr) {
            shift(c, *trigger.value, false);
        } else {
            b.i64(static_cast<std::int64_t>(day_ms)).call(rt_.get(Routine::add));
        }
        return;
    case m::TriggerKind::held:
        b.global_get(since_);
        shift(c, *trigger.value, false);
        return;
    }
}

void Lowering::run_action(Ctx& c, const m::Do& d) {
    // A time rule does an action: the action's requirements, consents, and
    // changes, as the contract's own word (no starter's agreement, R24).
    const ActionInfo* info = action_info(d);
    BO_ASSERT(info != nullptr);
    const ActionInfo* outer = c.action;
    const std::string wire = c.wire;
    const std::uint32_t count = c.requires_count;
    c.action = info;
    c.wire = info->wire;
    c.requires_count = 0;
    entry_check(c);
    for (const m::Consent& k : info->action->consents) {
        if (asks(k)) {
            consent_of(c, k.party);
        }
    }
    statements(c, info->action->body);
    c.action = outer;
    c.wire = wire;
    c.requires_count = count;
}

void Lowering::emit_rule(const RuleInfo& info) {
    FunctionBuilder b = module_.begin(info.function);
    Ctx c;
    c.b = &b;
    c.wire = info.wire;
    c.signer = b.local(I32);
    c.t32 = b.local(I32);
    c.t64 = b.local(I64);
    c.t64b = b.local(I64);
    const Local args = b.local(I32);
    const Local at = b.local(I64);
    const Local time = b.local(I64);
    const m::TimeRule& r = *info.rule;
    b.call(load_instance());
    // No arguments: null, or an empty map.
    call_item(b, 2);
    b.tee(args).load(i32_load8_u).u32(0xF6).op(i32_ne);
    b.get(args).load(i32_load8_u).u32(0xA0).op(i32_ne).op(i32_and);
    {
        const Label other = b.if_();
        refuse(b, "bo:arguments");
        b.end(other);
    }
    // Its time has come (the registration time decides), and its
    // conditions hold; a held state is the instance's.
    const std::string not_yet = "bo:when " + info.wire;
    if (info.trigger.kind == m::TriggerKind::held) {
        const std::size_t state =
            state_index_.at(m::key(info.trigger.state->concept_entry, info.trigger.state->name));
        b.global_get(state_).u32(static_cast<std::uint32_t>(state)).op(i32_ne);
        const Label other = b.if_();
        refuse(b, not_yet);
        b.end(other);
    }
    now(c);
    b.set(time);
    moment(c, info.trigger);
    b.tee(at).get(time).op(i64_gt_s);
    {
        const Label early = b.if_();
        refuse(b, not_yet);
        b.end(early);
    }
    for (const m::Expr* condition : info.trigger.conditions) {
        value(c, *condition);
        b.op(i32_eqz);
        const Label other = b.if_();
        refuse(b, not_yet);
        b.end(other);
    }
    // Once for each time.
    b.global_get(info.fired_set);
    {
        const Label applied = b.if_();
        b.global_get(info.fired).get(at).op(i64_eq);
        const Label same = b.if_();
        refuse(b, "bo:fired " + info.wire);
        b.end(same);
        b.end(applied);
    }
    // Its event first: the rule, its time, and how late the call came.
    b.i32(1).global_set(rule_event_);
    b.u32(intern(info.wire)).global_set(rule_name_);
    b.u32(static_cast<std::uint32_t>(info.wire.size())).global_set(rule_length_);
    b.get(at).global_set(rule_time_);
    b.get(time).get(at).call(rt_.get(Routine::sub)).global_set(rule_late_);
    for (const m::Consent& k : r.consents) {
        consent_of(c, k.party);
    }
    for (const m::Do& d : r.actions) {
        if (!d.obligation) {
            run_action(c, d);
        }
    }
    statements(c, r.body);
    b.get(at).global_set(info.fired);
    b.i32(1).global_set(info.fired_set);
    finish(b);
    module_.define(std::move(b));
}

void Lowering::request(Ctx& c, const m::Request& r) {
    // E8: {1: kind, 2: params, 3: deadline, 4: reply}, drafted where the
    // output goes (write_accept copies it into the accept's key 7).
    FunctionBuilder& b = *c.b;
    std::optional<Label> live;
    if (c.answer) {
        // An instance that has ended makes no requests (spec section 15).
        b.get(c.final_before).op(i32_eqz);
        live = b.if_();
    }
    const wasm::Func head = rt_.get(Routine::out_head);
    const wasm::Func out_int = rt_.get(Routine::out_int);
    static_cast<void>(rt_.get(Routine::out_raw));
    const Local mark = b.local(I32);
    const Local who = b.local(I32);
    const Local at = b.local(I32);
    const Local size = b.local(I32);
    b.global_get(requests_).i32(1).op(i32_add).global_set(requests_);
    b.i32(5).i64(4).call(head);
    b.i64(1).call(out_int);
    b.u32(intern(r.kind)).u32(static_cast<std::uint32_t>(r.kind.size()));
    out_text(b, r.kind.size());
    // The params: `to` and each value, by name, in canonical order; a party
    // as its ledger id, or null for none.
    b.i64(2).call(out_int);
    b.global_get(rt_.var(rt::Var::out)).set(mark);
    std::vector<std::pair<Bytes, const m::Expr*>> params;
    if (r.to) {
        params.emplace_back(text_cbor("to"), &*r.to);
    }
    for (const m::Set& w : r.with) {
        params.emplace_back(text_cbor(wire_name(w.target.concept_entry, w.target.name)), &w.value);
    }
    std::ranges::sort(params, {}, &std::pair<Bytes, const m::Expr*>::first);
    b.i32(5).i64(static_cast<std::int64_t>(params.size())).call(head);
    for (const auto& [key, e] : params) {
        out_key(b, key);
        const Rep rep = rep_of(e->type);
        if (rep == Rep::ledger) {
            party_raw(c, *e);
            b.tee(who).op(i32_eqz);
            const Label none = b.if_();
            b.call(rt_.get(Routine::out_null));
            b.else_(none);
            b.get(who);
            out_value(b, Rep::ledger);
            b.end(none);
        } else if (pair_rep(rep)) {
            // A text or a list longer than the params may be is refused
            // before it is written.
            value(c, *e);
            b.set(size).set(at);
            b.get(size).u32(static_cast<std::uint32_t>(m::max_request_params)).op(i32_gt_u);
            {
                const Label large = b.if_();
                refuse(b, "bo:request " + r.kind);
                b.end(large);
            }
            b.get(at).get(size);
            if (rep == Rep::text) {
                out_text(b, m::max_request_params);
            } else {
                out_raw(b, m::max_request_params);
            }
        } else {
            value(c, *e);
            out_value(b, rep);
        }
    }
    // At most 4,096 bytes of params (spec section 15).
    b.global_get(rt_.var(rt::Var::out)).get(mark).op(i32_sub);
    b.u32(static_cast<std::uint32_t>(m::max_request_params)).op(i32_gt_u);
    {
        const Label large = b.if_();
        refuse(b, "bo:request " + r.kind);
        b.end(large);
    }
    // The deadline: so long after the call's registration time.
    b.i64(3).call(out_int);
    now(c);
    shift(c, r.within, false);
    b.call(out_int);
    b.i64(4).call(out_int);
    b.u32(intern(m::reply_function)).u32(static_cast<std::uint32_t>(m::reply_function.size()));
    out_text(b, m::reply_function.size());
    if (live) {
        b.end(*live);
    }
}

void Lowering::emit_reply(const wasm::Func f) {
    // E8: every answer to the contract's requests calls this function. It
    // records the answer as an event and runs the rule for it, if the
    // contract has one; it refuses only what is not an answer.
    FunctionBuilder b = module_.begin(f);
    Ctx c;
    c.b = &b;
    c.wire = std::string(m::reply_function);
    c.signer = b.local(I32);
    c.t32 = b.local(I32);
    c.t64 = b.local(I64);
    c.t64b = b.local(I64);
    c.answer = true;
    c.final_before = b.local(I32);
    c.result_p = b.local(I32);
    c.result_n = b.local(I32);
    c.reason_p = b.local(I32);
    c.reason_n = b.local(I32);
    const Local args = b.local(I32);
    const Local view = b.local(I32);
    const Local status = b.local(I32);
    const Local kind = b.local(I32);
    const Local kind_n = b.local(I32);
    const Local id = b.local(I32);
    const Local item = b.local(I32);
    const std::string_view input = rt::text_of(rt::Reason::input);
    b.call(load_instance());
    // Its arguments: null, or a map (an executor's result, reason, and
    // response, or anything a person gives by hand).
    call_item(b, 2);
    b.tee(args).load(i32_load8_u).u32(0xF6).op(i32_ne);
    b.get(args).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_ne).op(i32_and);
    {
        const Label other = b.if_();
        refuse(b, "bo:arguments");
        b.end(other);
    }
    // The request it answers: input key 9, which only an answer has.
    b.u32(rt::layout::input_base);
    lookup(b, Bytes{0x09}, 9);
    b.tee(view).op(i32_eqz);
    {
        const Label none = b.if_();
        refuse(b, "bo:answer");
        b.end(none);
    }
    b.get(view);
    lookup(b, Bytes{0x01}, 6);
    expect(b, Rep::ledger, input);
    b.set(id);
    b.get(view);
    lookup(b, Bytes{0x02}, 6);
    expect(b, Rep::text, input);
    b.set(kind_n).set(kind);
    b.get(view);
    lookup(b, Bytes{0x06}, 6);
    expect(b, Rep::i64, input);
    b.op(i32_wrap_i64).set(status);
    b.get(status).i32(1).op(i32_lt_u).get(status).i32(3).op(i32_gt_u).op(i32_or);
    {
        const Label other = b.if_();
        refuse(b, input);
        b.end(other);
    }
    // The answer's result and reason: texts of its arguments, else empty.
    for (const auto& [key, p, n] : {std::tuple{"result", c.result_p, c.result_n},
                                    std::tuple{"reason", c.reason_p, c.reason_n}}) {
        b.get(args).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0xA0).op(i32_eq);
        const Label map = b.if_();
        b.get(args);
        lookup(b, text_cbor(key), 3);
        b.tee(item).op(i32_eqz).op(i32_eqz);
        b.get(item).load(i32_load8_u).u32(0xE0).op(i32_and).u32(0x60).op(i32_eq).op(i32_and);
        const Label text = b.if_();
        b.get(item).call(rt_.get(Routine::content)).set(p);
        b.get(item).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64).set(n);
        b.end(text);
        b.end(map);
    }
    // Whether the instance had ended: then the rule changes no state and
    // makes no requests (spec section 15).
    b.global_get(state_).load(i32_load8_u, final_table_).set(c.final_before);
    // Its event first: the request's kind, its id, and how it went.
    b.i32(1).global_set(answer_event_);
    b.get(kind).global_set(answer_kind_);
    b.get(kind_n).global_set(answer_kind_length_);
    b.get(id).global_set(answer_id_);
    b.get(status).global_set(answer_status_);
    // The rule for it: done (1), failed (2), expired (3; a rule for failures
    // takes it unless one is for expiry, R33).
    for (const m::AnswerRule& r : model_.answers) {
        b.get(kind).get(kind_n).u32(intern(r.kind)).u32(static_cast<std::uint32_t>(r.kind.size()));
        equal_bytes(b, r.kind.size());
        switch (r.outcome) {
        case m::Outcome::done:
            b.get(status).i32(1).op(i32_eq);
            break;
        case m::Outcome::fails:
            b.get(status).i32(2).op(i32_eq);
            if (r.expired) {
                b.get(status).i32(3).op(i32_eq).op(i32_or);
            }
            break;
        case m::Outcome::expires:
            b.get(status).i32(3).op(i32_eq);
            break;
        }
        b.op(i32_and);
        const Label applies = b.if_();
        statements(c, r.body);
        b.end(applies);
    }
    finish(b);
    module_.define(std::move(b));
}

void Lowering::write_answer_event(FunctionBuilder& b) {
    // ["answer", {"kind": KIND, "status": "done" / "failed" / "expired",
    // "request": ID}], keys in canonical order.
    b.global_get(answer_event_);
    const Label some = b.if_();
    const wasm::Func head = rt_.get(Routine::out_head);
    b.i32(4).i64(2).call(head);
    constexpr std::string_view answer_event = "answer";
    b.u32(intern(answer_event)).u32(static_cast<std::uint32_t>(answer_event.size()));
    out_text(b, answer_event.size());
    b.i32(5).i64(3).call(head);
    std::vector<std::pair<Bytes, int>> keys{
        {text_cbor("kind"), 0}, {text_cbor("request"), 1}, {text_cbor("status"), 2}};
    std::ranges::sort(keys);
    for (const auto& [key, which] : keys) {
        out_key(b, key);
        if (which == 0) {
            b.global_get(answer_kind_).global_get(answer_kind_length_);
            out_text(b, 64);
        } else if (which == 1) {
            b.global_get(answer_id_);
            out_value(b, Rep::ledger);
        } else {
            for (const auto& [n, text] : {std::pair{1, std::string_view("done")},
                                          std::pair{2, std::string_view("failed")}}) {
                b.global_get(answer_status_).i32(n).op(i32_eq);
                const Label same = b.if_();
                b.u32(intern(text)).u32(static_cast<std::uint32_t>(text.size()));
                out_text(b, text.size());
                b.end(same);
            }
            constexpr std::string_view expired = "expired";
            b.global_get(answer_status_).i32(3).op(i32_eq);
            const Label same = b.if_();
            b.u32(intern(expired)).u32(static_cast<std::uint32_t>(expired.size()));
            out_text(b, expired.size());
            b.end(same);
        }
    }
    b.end(some);
}

Shape Lowering::params_shape() const {
    Shape most;
    const auto consider = [&](const std::vector<m::Statement>& list) {
        for (const m::Request* r : m::requests_in(list)) {
            Shape one = map_shape(r->with.size() + (r->to ? 1U : 0U));
            one += Shape{r->to ? 1U : 0U, 0};
            for (const m::Set& w : r->with) {
                one += value_shape(w.value.type);
            }
            most = {std::max(most.items, one.items), std::max(most.keys, one.keys)};
        }
    };
    for (const m::Action& a : model_.actions) {
        consider(a.body);
    }
    for (const m::TimeRule& r : model_.rules) {
        consider(r.body);
    }
    for (const m::AnswerRule& r : model_.answers) {
        consider(r.body);
    }
    return most;
}

bool Lowering::may_be_empty(const m::Expr& e) const {
    if (e.kind == ExprKind::word && is(e.concept_entry, "val.none")) {
        return true;
    }
    if (e.refers != Refers::field) {
        return false;
    }
    const auto it = field_index_.find(m::key(e.concept_entry, e.name));
    return it != field_index_.end() && fields_[it->second].optional;
}

void Lowering::party_raw(Ctx& c, const m::Expr& e) {
    // A ledger's address, 0 for no party: none, or a field holding none.
    FunctionBuilder& b = *c.b;
    if (e.kind == ExprKind::word && is(e.concept_entry, "val.none")) {
        b.i32(0);
        return;
    }
    if (may_be_empty(e)) {
        load(b, fields_[field_index_.at(m::key(e.concept_entry, e.name))]);
        return;
    }
    value(c, e);
}

void Lowering::ledger_equals(Ctx& c, const m::Expr& x, const m::Expr& y) {
    // No party equals no party only.
    FunctionBuilder& b = *c.b;
    const auto [left, right] = scratch(c);
    party_raw(c, x);
    b.set(left);
    party_raw(c, y);
    b.set(right);
    b.get(left).op(i32_eqz).get(right).op(i32_eqz).op(i32_or);
    const Label empty = b.if_(I32);
    b.get(left).get(right).op(i32_eq);
    b.else_(empty);
    b.get(left).i32(32).get(right).i32(32);
    equal_bytes(b, 32);
    b.end(empty);
}

void Lowering::consent_of(Ctx& c, const m::Expr& party) {
    // A field that holds no party has nobody to ask.
    FunctionBuilder& b = *c.b;
    const wasm::Func consent = rt_.get(Routine::consent);
    if (party.type.kind == TypeKind::list) {
        // A list of parties (a split's recipients): each one's consent.
        if (const m::Expr* items = literal_items(party)) {
            for (const m::Expr& item : items->operands) {
                consent_of(c, item);
            }
            return;
        }
        const auto [p, n] = scratch(c);
        value(c, party);
        b.op(drop).tee(p).call(rt_.get(Routine::head_arg)).op(i32_wrap_i64).set(n);
        b.get(p).call(rt_.get(Routine::content)).set(p);
        const Label done = b.block();
        const Label next = b.loop({wasm::Size(party.type.bound) + 1});
        b.get(n).op(i32_eqz).br_if(done);
        item_value(b, p, Rep::ledger);
        b.call(consent).op(drop);
        next_item(b, p, Rep::ledger);
        b.get(n).i32(1).op(i32_sub).set(n).br(next);
        b.end(next);
        b.end(done);
        return;
    }
    if (!may_be_empty(party)) {
        value(c, party);
        b.call(consent).op(drop);
        return;
    }
    party_raw(c, party);
    b.tee(c.t32);
    const Label some = b.if_();
    b.get(c.t32).call(consent).op(drop);
    b.end(some);
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
        if (const FieldSlot& slot = fields_[field_index_.at(key)]; slot.optional) {
            // A party field that holds no party: nobody to name.
            load(b, slot);
            b.tee(c.t32).op(i32_eqz);
            const Label none = b.if_();
            refuse(b, "bo:empty " + slot.wire);
            b.end(none);
            b.get(c.t32);
            return;
        }
        load(b, fields_[field_index_.at(key)]);
        return;
    case Refers::input: {
        const auto& [first, second] = c.inputs.at(key);
        b.get(first);
        if (pair_rep(rep_of(e.type))) {
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
        // R7: the instance is in that state (never in one it cannot reach).
        if (const auto it = state_index_.find(key); it != state_index_.end()) {
            b.global_get(state_).u32(static_cast<std::uint32_t>(it->second)).op(i32_eq);
        } else {
            b.i32(0);
        }
        return;
    case Refers::item: {
        // The item an `each` names.
        const auto& [first, second] = c.items.at(key);
        b.get(first);
        if (rep_of(e.type) == Rep::text) {
            b.get(second);
        }
        return;
    }
    case Refers::charge:
        // Its amount on the instance's bill (R26).
        for (const ChargeInfo& k : charges_) {
            if (k.wire == e.name) {
                b.global_get(k.amount);
                return;
            }
        }
        break;
    case Refers::action:
    case Refers::none:
        break;
    }
    if (is(e.concept_entry, "val.yes") || is(e.concept_entry, "val.no")) {
        b.i32(is(e.concept_entry, "val.yes") ? 1 : 0);
        return;
    }
    if (is(e.concept_entry, "val.none")) {
        b.i32(0);
        return;
    }
    if (is(e.concept_entry, "time.now") || is(e.concept_entry, "time.today")) {
        call_item(b, 7);
        expect(b, Rep::i64, rt::text_of(rt::Reason::input));
        if (is(e.concept_entry, "time.today")) {
            // The local midnight that starts the day (U6).
            b.tee(c.t64).i64(model_.utc_offset_ms).call(rt_.get(Routine::local_days));
            b.set(c.t64b).op(drop);
            b.get(c.t64).get(c.t64b).op(i64_sub);
        }
        return;
    }
    if (is(e.concept_entry, "cond.overdue")) {
        // Overdue: from the day after the due date on.
        now(c);
        due(c);
        b.i64(static_cast<std::int64_t>(day_ms)).call(rt_.get(Routine::add));
        b.op(i64_ge_s);
        return;
    }
    if (is(e.concept_entry, "cond.in_person")) {
        in_person(c);
        return;
    }
    if (is(e.concept_entry, "expr.result")) {
        b.get(c.result_p).get(c.result_n);
        return;
    }
    if (is(e.concept_entry, "expr.reason")) {
        b.get(c.reason_p).get(c.reason_n);
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
            b.i64(literal_value(e.literal, model_.utc_offset_ms).value_or(0));
        }
        return;
    case ExprKind::name:
    case ExprKind::word:
        reference(c, e);
        return;
    case ExprKind::apply: {
        if (is(e.concept_entry, "expr.sum_of") || is(e.concept_entry, "expr.count_of")) {
            list_apply(c, e);
            return;
        }
        if (is(e.concept_entry, "cond.before_due")) {
            // From N before the due date on.
            now(c);
            due(c);
            shift(c, e.operands[0], true);
            b.op(i64_ge_s);
            return;
        }
        if (is(e.concept_entry, "cond.within")) {
            // Less than N since the instance last changed state.
            now(c);
            b.global_get(since_);
            shift(c, e.operands[0], false);
            b.op(i64_lt_s);
            return;
        }
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
        if (m::is_trigger(e) && e.operands[0].refers == Refers::state) {
            // In the state, and for at least N since it entered it.
            reference(c, e.operands[0]);
            const Label in_state = b.if_(I32);
            now(c);
            b.global_get(since_);
            shift(c, e.operands[1], false);
            b.op(i64_ge_s);
            b.else_(in_state);
            b.i32(0);
            b.end(in_state);
            return;
        }
        if (m::is_trigger(e)) {
            // Overdue N: from N after the due date on.
            now(c);
            due(c);
            shift(c, e.operands[1], false);
            b.op(i64_ge_s);
            return;
        }
        break;
    case ExprKind::list:
        // A list of constants, as a whole.
        encoded_list(b, e);
        return;
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
    case Operator::member:
        member(c, e);
        return;
    case Operator::equals:
    case Operator::less:
    case Operator::less_equal:
    case Operator::greater:
    case Operator::greater_equal: {
        const Rep rep = rep_of(x.type);
        if (rep == Rep::ledger && (may_be_empty(x) || may_be_empty(y))) {
            ledger_equals(c, x, y);
            return;
        }
        value(c, x);
        if (rep == Rep::ledger) {
            b.i32(32);
        }
        value(c, y);
        if (rep == Rep::ledger) {
            b.i32(32);
        }
        if (rep == Rep::text || rep == Rep::ledger || rep == Rep::list) {
            // Lists are equal when their encodings are (deterministic CBOR).
            equal_bytes(b, rep == Rep::ledger ? wasm::Size(32)
                           : rep == Rep::text ? text_size(c, x, y)
                                              : wasm::Size(max_value_size));
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
            b.i64(model_.utc_offset_ms).call(rt_.get(Routine::add_months));
            return;
        }
        if (xk == TypeKind::duration && yk == TypeKind::date && x.type.calendar) {
            value(c, y);
            value(c, x);
            b.i64(model_.utc_offset_ms).call(rt_.get(Routine::add_months));
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
        if (xk == TypeKind::duration && yk == TypeKind::duration) {
            // R32: a duration by a duration, how many whole times; the rest
            // is dropped (toward zero).
            value(c, x);
            b.i64(1);
            value(c, y);
            b.i32(round_down).call(rt_.get(Routine::muldiv));
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
        if (pair_rep(slot.rep)) {
            slot.second = module_.add_global(I32, 0);
        }
    }
    for (RoleSlot& role : roles_) {
        role.ledger = module_.add_global(I32, 0);
    }
    if (previous_used_) {
        previous_ = module_.add_global(I32, 0);
    }
    if (proposals_) {
        for (wasm::Global* g : {&pending_, &drop_, &add_name_, &add_length_, &add_args_,
                                &event_kind_, &event_name_, &event_length_}) {
            *g = module_.add_global(I32, 0);
        }
    }
    if (since_used_) {
        since_ = module_.add_global(I64, 0);
    }
    if (!rules_.empty()) {
        for (RuleInfo& r : rules_) {
            r.fired = module_.add_global(I64, 0);
            r.fired_set = module_.add_global(I32, 0);
        }
        for (wasm::Global* g : {&rule_event_, &rule_name_, &rule_length_}) {
            *g = module_.add_global(I32, 0);
        }
        rule_time_ = module_.add_global(I64, 0);
        rule_late_ = module_.add_global(I64, 0);
    }
    if (bill_slot_) {
        for (wasm::Global* g :
             {&bill_new_, &bill_old_, &bill_old_length_, &bill_at_, &bill_length_}) {
            *g = module_.add_global(I32, 0);
        }
        for (wasm::Global* g : {&bill_time_, &bill_price_, &bill_total_, &bill_divisor_}) {
            *g = module_.add_global(I64, 0);
        }
        for (ChargeInfo& k : charges_) {
            k.applies = module_.add_global(I32, 0);
            k.rate = module_.add_global(I64, 0);
            k.amount = module_.add_global(I64, 0);
            if (!k.charge->per_document) {
                k.line = module_.add_global(I64, 0);
            }
        }
    }
    if (requests_used_) {
        for (wasm::Global* g : {&requests_, &answer_event_, &answer_kind_, &answer_kind_length_,
                                &answer_id_, &answer_status_}) {
            *g = module_.add_global(I32, 0);
        }
    }
    if (parts_used_) {
        for (wasm::Global* g : {&parts_made_, &parts_list_, &parts_to_}) {
            *g = module_.add_global(I32, 0);
        }
        for (auto& [index, part] : part_fields_) {
            const FieldSlot& slot = fields_[index];
            part.first = module_.add_global(slot.rep == Rep::i64 ? I64 : I32, 0);
            if (pair_rep(slot.rep)) {
                part.second = module_.add_global(I32, 0);
            }
            part.given = module_.add_global(I32, 0);
        }
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
    entry_ = entry;
    creation_function_ = module_.declare({});
    for (ActionInfo& a : actions_) {
        if (a.rule_only) {
            continue;
        }
        a.function = module_.declare({});
        if (a.action->agents_propose) {
            a.core = module_.declare({{I32, I32}, {}});
        }
    }
    if (proposals_) {
        approve_function_ = module_.declare({});
    }
    for (RuleInfo& r : rules_) {
        r.function = module_.declare({});
    }
    if (requests_used_) {
        reply_function_ = module_.declare({});
    }
    emit_entry(entry);
    emit_creation(creation_function_);
    for (const ActionInfo& a : actions_) {
        if (!a.rule_only) {
            emit_action(a);
        }
    }
    if (proposals_) {
        emit_approve(approve_function_);
    }
    for (const RuleInfo& r : rules_) {
        emit_rule(r);
    }
    if (requests_used_) {
        emit_reply(reply_function_);
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
        if (!a.rule_only) {
            build.interface.emplace(a.wire, protocol::FunctionKind::call);
        }
    }
    if (proposals_) {
        build.interface.emplace(std::string(m::approve_function), protocol::FunctionKind::call);
    }
    for (const RuleInfo& r : rules_) {
        build.interface.emplace(r.wire, protocol::FunctionKind::call);
    }
    if (requests_used_) {
        build.interface.emplace(std::string(m::reply_function), protocol::FunctionKind::call);
    }
    if (codegen_ >= 2) {
        bounds(build);
    }
    out.build = std::move(build);
    return out;
}

// ---------------------------------------------------------------------------
// Bounds (milestone 18): what a call of each function can use at most.

Shape Lowering::arguments_shape(const ActionInfo& action) const {
    // A map of the inputs and the role the action binds; null for none.
    const m::Action& a = *action.action;
    const std::uint64_t keys = a.inputs.size() + (action.binds ? 1 : 0);
    if (keys == 0) {
        return {1, 0};
    }
    Shape out = map_shape(keys);
    for (const m::Field& input : a.inputs) {
        out += value_shape(input.type);
    }
    if (action.binds) {
        out += Shape{1, 0};
    }
    return out;
}

Shape Lowering::creation_shape() const {
    // {"fields": {...}, "parties": {...}}, null for nothing.
    std::uint64_t roles = 0;
    for (const RoleSlot& role : roles_) {
        roles += role.party->binding == m::Binding::creation ? 1 : 0;
    }
    Shape fields;
    std::uint64_t field_count = 0;
    for (const FieldSlot& slot : fields_) {
        if (!slot.starts_with && !slot.empty_at_start) {
            fields += value_shape(slot.field->type);
            ++field_count;
        }
    }
    const std::uint64_t keys = (roles > 0 ? 1U : 0U) + (field_count > 0 ? 1U : 0U);
    if (keys == 0) {
        return {1, 0};
    }
    Shape out = map_shape(keys);
    if (field_count > 0) {
        out += map_shape(field_count) + fields;
    }
    if (roles > 0) {
        out += map_shape(roles) + Shape{roles, 0};
    }
    return out;
}

Shape Lowering::proposal_shape() const {
    // The arguments of an action AI agents may propose (the most of any).
    Shape most;
    for (const ActionInfo& a : actions_) {
        if (!a.rule_only && a.action->agents_propose) {
            const Shape s = arguments_shape(a);
            most = {std::max(most.items, s.items), std::max(most.keys, s.keys)};
        }
    }
    return most;
}

Shape Lowering::state_shape() const {
    // {? "bill", ? "fired", ? "since", "state", "fields", ? "pending",
    // ? "previous"}, as write_accept writes it.
    const std::uint64_t keys = 2U + (bill_slot_ ? 1U : 0U) + (rules_.empty() ? 0U : 1U) +
                               (since_used_ ? 1U : 0U) + (proposals_ ? 1U : 0U) +
                               (previous_used_ ? 1U : 0U);
    Shape out = map_shape(keys);
    out += Shape{1, 0}; // the state's name
    out += map_shape(fields_.size());
    for (const FieldSlot& slot : fields_) {
        out += value_shape(slot.field->type);
    }
    if (proposals_) {
        // At most 16 proposals, each [function, arguments].
        out += Shape{1, 0} + rt::max_needs * (Shape{2, 0} + proposal_shape());
    }
    out += Shape{previous_used_ ? 1U : 0U, 0};
    if (!rules_.empty()) {
        out += map_shape(rules_.size()) + Shape{rules_.size(), 0};
    }
    out += Shape{since_used_ ? 1U : 0U, 0};
    if (bill_slot_) {
        // {"time", ? "lines": [{CHARGE: amount}], "price", "total",
        // "charges": {CHARGE: {? "rate", "amount"}}}.
        std::uint64_t per_line = 0;
        for (const ChargeInfo& k : charges_) {
            per_line += k.charge->per_document ? 0 : 1;
        }
        const std::uint64_t lines = fields_[*bill_slot_].field->type.bound;
        out += map_shape(bill_keys) + Shape{3, 0};
        out += Shape{1, 0} + lines * (map_shape(per_line) + Shape{per_line, 0});
        out += map_shape(charges_.size()) + charges_.size() * (map_shape(2) + Shape{2, 0});
    }
    return out;
}

Shape Lowering::rest_shape() const {
    // The input's other items (spec section 15): {1: function, 2: (the
    // arguments), 3: home, 4: contract, 5: {1: id, 2: head, 3: (the state),
    // 4: status, 5: {role: ledger}, 6: [parent, depth]}, 6: [caller,
    // signer], 7: time, 8: [[ledger, signer]] (at most 16)}, a signer being
    // {1: kind, 2: presence, 3: model}.
    std::uint64_t parties = roles_.size();
    for (const FieldSlot& slot : fields_) {
        parties += slot.rep == Rep::ledger ? 1 : 0;
    }
    const Shape signer = map_shape(signer_keys) + Shape{signer_keys, 0};
    Shape out = map_shape(8) + Shape{4, 0};
    out +=
        map_shape(view_keys) + Shape{3, 0} + map_shape(parties) + Shape{parties, 0} + Shape{3, 0};
    out += Shape{2, 0} + signer;
    out += Shape{1, 0} + rt::max_needs * (Shape{2, 0} + signer);
    return out;
}

bool Lowering::sets_bill(const std::vector<m::Statement>& list, const int depth) const {
    if (!bill_slot_ || depth > 4) {
        return bill_slot_.has_value();
    }
    const FieldSlot& bill = fields_[*bill_slot_];
    return std::ranges::any_of(list, [&](const m::Statement& s) {
        return std::visit(Overloaded{
                              [&](const m::Set& st) {
                                  return m::key(st.target.concept_entry, st.target.name) ==
                                         m::key(bill.field->word, bill.field->name);
                              },
                              [&](const m::If& i) {
                                  return sets_bill(i.then, depth) || sets_bill(i.otherwise, depth);
                              },
                              [&](const m::Each& e) { return sets_bill(e.body, depth); },
                              [&](const m::Do& d) {
                                  // A time rule does an action: its lines.
                                  const ActionInfo* a = d.parts ? nullptr : action_info(d);
                                  return a != nullptr && sets_bill(a->action->body, depth + 1);
                              },
                              [](const auto&) { return false; },
                          },
                          s.node);
    });
}

void Lowering::bounds(Build& build) {
    // A call: the entry reads the input and finds the function (each
    // interface function counted only as called), then the function.
    // Each interface function, its arguments, and the regions it never
    // reaches: no parts unless it issues them, no bill unless it makes one.
    struct Entry {
        std::string name;
        wasm::Func function;
        Shape arguments;
        std::uint32_t absent = 0;
    };
    const auto absent = [&](bool parts, bool bill) {
        return (parts ? 0U : region_parts) | (bill ? 0U : region_bill);
    };
    std::vector<Entry> functions;
    functions.push_back(
        {creation_, creation_function_, creation_shape(), absent(false, bill_slot_.has_value())});
    bool proposed_parts = false;
    bool proposed_bill = false;
    for (const ActionInfo& a : actions_) {
        const bool bill = sets_bill(a.action->body);
        if (a.action->agents_propose) {
            proposed_parts = proposed_parts || a.parts;
            proposed_bill = proposed_bill || bill;
        }
        if (!a.rule_only) {
            functions.push_back({a.wire, a.function, arguments_shape(a), absent(a.parts, bill)});
        }
    }
    if (proposals_) {
        functions.push_back({std::string(m::approve_function), approve_function_,
                             map_shape(2) + Shape{1, 0} + proposal_shape(),
                             absent(proposed_parts, proposed_bill)});
    }
    for (const RuleInfo& r : rules_) {
        std::vector<m::Statement> all;
        for (const m::Do& d : r.rule->actions) {
            all.push_back(m::Statement{d});
        }
        const bool bill = sets_bill(all) || sets_bill(r.rule->body);
        functions.push_back({r.wire, r.function, Shape{1, 0}, absent(false, bill)});
    }
    if (requests_used_) {
        // The answer's arguments (a result, a reason, a response), and the
        // request it answers: input key 9, {1: id, 2: kind, 3: params, 4:
        // deadline, 5: asked at, 6: status}.
        bool bill = false;
        for (const m::AnswerRule& r : model_.answers) {
            bill = bill || sets_bill(r.body);
        }
        functions.push_back(
            {std::string(m::reply_function), reply_function_,
             map_shape(3) + Shape{3, 0} + Shape{1, 1} + map_shape(6) + Shape{5, 0} + params_shape(),
             absent(false, bill)});
    }
    std::vector<wasm::Func> interface;
    for (const Entry& f : functions) {
        interface.push_back(f.function);
    }
    const Shape common = state_shape() + rest_shape();
    for (const Entry& f : functions) {
        const std::string& name = f.name;
        const Shape input = common + f.arguments;
        const std::array<std::uint64_t, 2> sizes{input.items, input.keys};
        const wasm::Bound entry = module_.bound(entry_, sizes, interface);
        const wasm::Bound own = module_.bound(f.function, {}, {}, f.absent);
        FunctionBound bound;
        bound.fuel = wasm::add_saturating(entry.fuel, own.fuel);
        bound.input = rt::read_input_fuel(input.items, input.keys);
        bound.input_items = input.items;
        bound.input_keys = input.keys;
        bound.output = wasm::add_saturating(entry.output, own.output);
        build.bounds.emplace(name, bound);
    }
}

} // namespace

Lowered lower(const std::string_view source, const model::Model& model,
              const std::uint32_t codegen) {
    return Lowering(source, model, codegen).run();
}

} // namespace cexchain::bo
