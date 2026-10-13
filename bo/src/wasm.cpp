// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The WebAssembly emitter: the binary format (WebAssembly 2.0) for modules in
// the contract profile, with the operand stack tracked as the validation
// algorithm of the specification's appendix tracks it.

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <meta>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/wasm.hpp>
#include <cexchain/core/vm.hpp>

#include "reflection.hpp"

namespace cexchain::bo::wasm {

namespace {

constexpr std::uint8_t unknown = 0;

constexpr std::uint8_t op_unreachable = 0x00;
constexpr std::uint8_t op_block = 0x02;
constexpr std::uint8_t op_loop = 0x03;
constexpr std::uint8_t op_if = 0x04;
constexpr std::uint8_t op_else = 0x05;
constexpr std::uint8_t op_end = 0x0B;
constexpr std::uint8_t op_br = 0x0C;
constexpr std::uint8_t op_br_if = 0x0D;
constexpr std::uint8_t op_br_table = 0x0E;
constexpr std::uint8_t op_return = 0x0F;
constexpr std::uint8_t op_call = 0x10;
constexpr std::uint8_t op_local_get = 0x20;
constexpr std::uint8_t op_local_set = 0x21;
constexpr std::uint8_t op_local_tee = 0x22;
constexpr std::uint8_t op_global_get = 0x23;
constexpr std::uint8_t op_global_set = 0x24;
constexpr std::uint8_t op_i32_const = 0x41;
constexpr std::uint8_t op_i64_const = 0x42;
constexpr std::uint8_t block_empty = 0x40;

constexpr std::uint8_t byte_of(const ValType type) noexcept {
    return static_cast<std::uint8_t>(type);
}

constexpr std::uint16_t code_of(const Op op) noexcept {
    return static_cast<std::uint16_t>(op);
}

/// The bytes a load or store touches.
constexpr std::uint32_t width(const Op op) noexcept {
    switch (op) {
    case Op::i32_load:
    case Op::i64_load32_s:
    case Op::i64_load32_u:
    case Op::i32_store:
    case Op::i64_store32:
        return 4;
    case Op::i64_load:
    case Op::i64_store:
        return 8;
    case Op::i32_load16_s:
    case Op::i32_load16_u:
    case Op::i64_load16_s:
    case Op::i64_load16_u:
    case Op::i32_store16:
    case Op::i64_store16:
        return 2;
    default:
        return 1;
    }
}

void put_uleb(Bytes& out, std::uint64_t value) {
    do {
        auto b = static_cast<std::uint8_t>(value & 0x7FU);
        value >>= 7U;
        if (value != 0) {
            b = static_cast<std::uint8_t>(b | 0x80U);
        }
        out.push_back(b);
    } while (value != 0);
}

void put_sleb(Bytes& out, std::int64_t value) {
    while (true) {
        const auto b = static_cast<std::uint8_t>(static_cast<std::uint64_t>(value) & 0x7FU);
        value >>= 7; // arithmetic (C++20): the sign stays
        const bool sign = (b & 0x40U) != 0;
        if ((value == 0 && !sign) || (value == -1 && sign)) {
            out.push_back(b);
            return;
        }
        out.push_back(static_cast<std::uint8_t>(b | 0x80U));
    }
}

void put_name(Bytes& out, const std::string_view name) {
    put_uleb(out, name.size());
    out.insert(out.end(), name.begin(), name.end());
}

void put_section(Bytes& out, const std::uint8_t id, const Bytes& content) {
    out.push_back(id);
    put_uleb(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
}

void put_types(Bytes& out, const std::vector<ValType>& types) {
    put_uleb(out, types.size());
    for (const ValType t : types) {
        out.push_back(byte_of(t));
    }
}

/// "i64_add" as the text format writes it: "i64.add". The first underscore
/// after a type or "memory" is a dot.
std::string text_name(const std::string_view identifier) {
    std::string out(identifier);
    for (const std::string_view prefix : {"i32_", "i64_", "memory_"}) {
        if (identifier.starts_with(prefix)) {
            out[prefix.size() - 1] = '.';
        }
    }
    return out;
}

/// Names of Op's enumerators, by reflection.
template <class E>
std::map<E, std::string> text_names() {
    std::map<E, std::string> names;
    template for (constexpr auto e : std::define_static_array(std::meta::enumerators_of(^^E))) {
        names.emplace([:e:], text_name(std::meta::identifier_of(e)));
    }
    return names;
}

const FuncType& host_type(const Host host) {
    using enum ValType;
    static const std::array<FuncType, host_count> types{
        FuncType{{}, {i32}},           // input_size
        FuncType{{i32}, {}},           // input_read
        FuncType{{i32, i32}, {}},      // output_write
        FuncType{{i32, i32, i32}, {}}, // hash
        FuncType{{i32, i32}, {}},      // abort
    };
    return types.at(static_cast<std::size_t>(host));
}

static_assert(detail::enumerator_count<Host>() == host_count);
static_assert(detail::enumerator_name(Host::input_read) == "input_read");
static_assert(detail::enumerator_name(Host::abort) == "abort");

} // namespace

Signature signature(const Op op) {
    using enum ValType;
    const std::uint16_t code = code_of(op);
    if (code >= 0x28 && code <= 0x35) {
        const bool to_i32 = code == 0x28 || (code >= 0x2C && code <= 0x2F);
        return {{i32}, {to_i32 ? i32 : i64}};
    }
    if (code >= 0x36 && code <= 0x3E) {
        const bool from_i32 = code == 0x36 || code == 0x3A || code == 0x3B;
        return {{i32, from_i32 ? i32 : i64}, {}};
    }
    switch (op) {
    case Op::drop:
    case Op::select:
        return {};
    case Op::memory_size:
        return {{}, {i32}};
    case Op::memory_grow:
        return {{i32}, {i32}};
    case Op::memory_copy:
    case Op::memory_fill:
        return {{i32, i32, i32}, {}};
    case Op::i32_eqz:
        return {{i32}, {i32}};
    case Op::i64_eqz:
        return {{i64}, {i32}};
    case Op::i32_wrap_i64:
        return {{i64}, {i32}};
    case Op::i64_extend_i32_s:
    case Op::i64_extend_i32_u:
        return {{i32}, {i64}};
    case Op::i32_extend8_s:
    case Op::i32_extend16_s:
        return {{i32}, {i32}};
    case Op::i64_extend8_s:
    case Op::i64_extend16_s:
    case Op::i64_extend32_s:
        return {{i64}, {i64}};
    default:
        break;
    }
    if (code >= 0x46 && code <= 0x4F) {
        return {{i32, i32}, {i32}};
    }
    if (code >= 0x51 && code <= 0x5A) {
        return {{i64, i64}, {i32}};
    }
    if (code >= 0x67 && code <= 0x69) {
        return {{i32}, {i32}};
    }
    if (code >= 0x6A && code <= 0x78) {
        return {{i32, i32}, {i32}};
    }
    if (code >= 0x79 && code <= 0x7B) {
        return {{i64}, {i64}};
    }
    BO_ASSERT(code >= 0x7C && code <= 0x8A);
    return {{i64, i64}, {i64}};
}

bool is_load(const Op op) noexcept {
    return code_of(op) >= 0x28 && code_of(op) <= 0x35;
}

bool is_store(const Op op) noexcept {
    return code_of(op) >= 0x36 && code_of(op) <= 0x3E;
}

std::string_view name_of(const Op op) noexcept {
    static const std::map<Op, std::string> names = text_names<Op>();
    const auto it = names.find(op);
    return it == names.end() ? std::string_view("?") : std::string_view(it->second);
}

std::string_view name_of(const Host host) noexcept {
    return detail::enumerator_name(host);
}

// ---------------------------------------------------------------------------
// FunctionBuilder
// ---------------------------------------------------------------------------

FunctionBuilder::FunctionBuilder(const ModuleWriter& module, const Func self)
    : module_(&module), self_(self) {
    frames_.push_back(
        Frame{Kind::function, module.type_of(self).results, 0, false, next_serial_++});
}

std::uint32_t FunctionBuilder::params() const noexcept {
    return static_cast<std::uint32_t>(module_->type_of(self_).params.size());
}

bool FunctionBuilder::reachable() const noexcept {
    return !frames_.back().unreachable;
}

bool FunctionBuilder::is_open(const Label label) const noexcept {
    return label.frame > 0 && label.frame < frames_.size() &&
           frames_[label.frame].serial == label.serial;
}

bool FunctionBuilder::is_innermost(const Label label) const noexcept {
    return is_open(label) && label.frame + 1 == frames_.size();
}

bool FunctionBuilder::can_pop(const std::span<const ValType> types) const noexcept {
    const Frame& frame = frames_.back();
    std::size_t h = vals_.size();
    for (auto it = types.rbegin(); it != types.rend(); ++it) {
        if (h == frame.height) {
            if (!frame.unreachable) {
                return false;
            }
            continue;
        }
        const std::uint8_t v = vals_[h - 1];
        if (v != unknown && v != byte_of(*it)) {
            return false;
        }
        --h;
    }
    return true;
}

bool FunctionBuilder::can_pop(const ValType type) const noexcept {
    return can_pop(std::span<const ValType>(&type, 1));
}

bool FunctionBuilder::is_local(const Local local) const noexcept {
    return local.index < params() + locals_.size();
}

ValType FunctionBuilder::type_of(const Local local) const noexcept {
    const std::uint32_t n = params();
    return local.index < n ? module_->type_of(self_).params[local.index] : locals_[local.index - n];
}

bool FunctionBuilder::accepts(const Op op) const {
    const Frame& frame = frames_.back();
    const std::size_t above = vals_.size() - frame.height;
    if (op == Op::drop) {
        return above >= 1 || frame.unreachable;
    }
    if (op == Op::select) {
        if (!can_pop(ValType::i32)) {
            return false;
        }
        // Two operands of one type under the condition.
        if (above < 3) {
            return frame.unreachable;
        }
        const std::uint8_t a = vals_[vals_.size() - 3];
        const std::uint8_t b = vals_[vals_.size() - 2];
        return a == unknown || b == unknown || a == b;
    }
    return can_pop(signature(op).pops);
}

bool FunctionBuilder::can_call(const Func callee) const {
    return module_->is_function(callee) && can_pop(module_->type_of(callee).params);
}

std::vector<ValType> FunctionBuilder::label_types(const Label label) const {
    const Frame& frame = frames_[label.frame];
    return frame.kind == Kind::loop ? std::vector<ValType>{} : frame.results;
}

bool FunctionBuilder::can_branch(const Label label) const {
    return can_pop(label_types(label));
}

bool FunctionBuilder::can_end() const {
    const Frame& frame = frames_.back();
    if (!can_pop(frame.results)) {
        return false;
    }
    const std::size_t above = vals_.size() - frame.height;
    return frame.unreachable ? above <= frame.results.size() : above == frame.results.size();
}

bool FunctionBuilder::is_global(const Global global) const noexcept {
    return global.index < module_->global_count();
}

bool FunctionBuilder::is_mutable(const Global) const noexcept {
    return true;
}

ValType FunctionBuilder::global_type(const Global global) const noexcept {
    return module_->global_type(global);
}

void FunctionBuilder::push(const ValType type) {
    vals_.push_back(byte_of(type));
    max_height_ = std::max(max_height_, height());
}

void FunctionBuilder::push(const std::span<const ValType> types) {
    for (const ValType t : types) {
        push(t);
    }
}

void FunctionBuilder::pop(const ValType type) {
    const Frame& frame = frames_.back();
    if (vals_.size() == frame.height) {
        BO_ASSERT(frame.unreachable);
        return;
    }
    BO_ASSERT(vals_.back() == unknown || vals_.back() == byte_of(type));
    vals_.pop_back();
}

void FunctionBuilder::pop(const std::span<const ValType> types) {
    for (auto it = types.rbegin(); it != types.rend(); ++it) {
        pop(*it);
    }
}

void FunctionBuilder::mark_unreachable() {
    Frame& frame = frames_.back();
    vals_.resize(frame.height);
    frame.unreachable = true;
}

void FunctionBuilder::uleb(const std::uint64_t value) {
    put_uleb(code_, value);
}

void FunctionBuilder::sleb(const std::int64_t value) {
    put_sleb(code_, value);
}

Local FunctionBuilder::param(const std::uint32_t index) const {
    return Local{index};
}

Local FunctionBuilder::local(const ValType type) {
    locals_.push_back(type);
    return Local{params() + static_cast<std::uint32_t>(locals_.size()) - 1};
}

FunctionBuilder& FunctionBuilder::i32(const std::int32_t value) {
    byte(op_i32_const);
    sleb(value);
    push(ValType::i32);
    return *this;
}

FunctionBuilder& FunctionBuilder::i64(const std::int64_t value) {
    byte(op_i64_const);
    sleb(value);
    push(ValType::i64);
    return *this;
}

FunctionBuilder& FunctionBuilder::get(const Local local) {
    byte(op_local_get);
    uleb(local.index);
    push(type_of(local));
    return *this;
}

FunctionBuilder& FunctionBuilder::set(const Local local) {
    pop(type_of(local));
    byte(op_local_set);
    uleb(local.index);
    return *this;
}

FunctionBuilder& FunctionBuilder::tee(const Local local) {
    pop(type_of(local));
    byte(op_local_tee);
    uleb(local.index);
    push(type_of(local));
    return *this;
}

FunctionBuilder& FunctionBuilder::global_get(const Global global) {
    byte(op_global_get);
    uleb(global.index);
    push(global_type(global));
    return *this;
}

FunctionBuilder& FunctionBuilder::global_set(const Global global) {
    pop(global_type(global));
    byte(op_global_set);
    uleb(global.index);
    return *this;
}

FunctionBuilder& FunctionBuilder::op(const Op op) {
    const std::uint16_t code = code_of(op);
    if (op == Op::drop) {
        if (vals_.size() > frames_.back().height) {
            vals_.pop_back();
        }
    } else if (op == Op::select) {
        pop(ValType::i32);
        const Frame& frame = frames_.back();
        std::uint8_t type = unknown;
        for (int i = 0; i < 2; ++i) {
            if (vals_.size() > frame.height) {
                type = vals_.back() != unknown ? vals_.back() : type;
                vals_.pop_back();
            }
        }
        vals_.push_back(type);
        max_height_ = std::max(max_height_, height());
    } else {
        const Signature sig = signature(op);
        pop(sig.pops);
        push(sig.pushes);
    }
    if (code >= 0xFC00) {
        byte(0xFC);
        uleb(code & 0xFFU);
        byte(0x00);
        if (op == Op::memory_copy) {
            byte(0x00);
        }
    } else {
        byte(static_cast<std::uint8_t>(code));
        if (op == Op::memory_size || op == Op::memory_grow) {
            byte(0x00);
        }
    }
    return *this;
}

FunctionBuilder& FunctionBuilder::load(const Op op, const std::uint32_t offset) {
    const Signature sig = signature(op);
    pop(sig.pops);
    push(sig.pushes);
    byte(static_cast<std::uint8_t>(code_of(op)));
    uleb(static_cast<std::uint32_t>(std::countr_zero(width(op))));
    uleb(offset);
    return *this;
}

FunctionBuilder& FunctionBuilder::store(const Op op, const std::uint32_t offset) {
    pop(signature(op).pops);
    byte(static_cast<std::uint8_t>(code_of(op)));
    uleb(static_cast<std::uint32_t>(std::countr_zero(width(op))));
    uleb(offset);
    return *this;
}

Label FunctionBuilder::open(const Kind kind, const BlockType type, const std::uint8_t opcode) {
    byte(opcode);
    byte(type ? byte_of(*type) : block_empty);
    Frame frame;
    frame.kind = kind;
    if (type) {
        frame.results.push_back(*type);
    }
    frame.height = height();
    frame.serial = next_serial_++;
    frames_.push_back(std::move(frame));
    BO_ASSERT(frames_.size() <= vm::max_nesting);
    return Label{static_cast<std::uint32_t>(frames_.size() - 1), frames_.back().serial};
}

Label FunctionBuilder::block(const BlockType type) {
    return open(Kind::block, type, op_block);
}

Label FunctionBuilder::loop(const BlockType type) {
    return open(Kind::loop, type, op_loop);
}

Label FunctionBuilder::if_(const BlockType type) {
    pop(ValType::i32);
    return open(Kind::if_, type, op_if);
}

FunctionBuilder& FunctionBuilder::else_(const Label label) {
    Frame& frame = frames_[label.frame];
    BO_ASSERT(frame.kind == Kind::if_);
    pop(frame.results);
    BO_ASSERT(vals_.size() == frame.height);
    frame.kind = Kind::else_;
    frame.unreachable = false;
    byte(op_else);
    return *this;
}

FunctionBuilder& FunctionBuilder::end(const Label label) {
    const Frame frame = frames_[label.frame];
    // An if without an else gives back what it took: it has no results.
    BO_ASSERT(frame.kind != Kind::if_ || frame.results.empty());
    pop(frame.results);
    BO_ASSERT(vals_.size() == frame.height);
    frames_.pop_back();
    push(frame.results);
    byte(op_end);
    return *this;
}

std::uint32_t FunctionBuilder::depth(const Label label) const {
    return static_cast<std::uint32_t>(frames_.size()) - 1 - label.frame;
}

FunctionBuilder& FunctionBuilder::br(const Label label) {
    const std::uint32_t d = depth(label);
    pop(label_types(label));
    mark_unreachable();
    byte(op_br);
    uleb(d);
    return *this;
}

FunctionBuilder& FunctionBuilder::br_if(const Label label) {
    BO_ASSERT(is_open(label) && can_pop(ValType::i32));
    pop(ValType::i32);
    BO_ASSERT(can_branch(label));
    const std::vector<ValType> types = label_types(label);
    pop(types);
    push(types);
    byte(op_br_if);
    uleb(depth(label));
    return *this;
}

FunctionBuilder& FunctionBuilder::br_table(const std::span<const Label> labels,
                                           const Label otherwise) {
    BO_ASSERT(is_open(otherwise) && can_pop(ValType::i32));
    pop(ValType::i32);
    const std::vector<ValType> types = label_types(otherwise);
    BO_ASSERT(can_pop(types));
    std::vector<std::uint32_t> depths;
    for (const Label label : labels) {
        BO_ASSERT(is_open(label) && label_types(label) == types);
        depths.push_back(depth(label));
    }
    const std::uint32_t fallback = depth(otherwise);
    pop(types);
    mark_unreachable();
    byte(op_br_table);
    uleb(depths.size());
    for (const std::uint32_t d : depths) {
        uleb(d);
    }
    uleb(fallback);
    return *this;
}

FunctionBuilder& FunctionBuilder::return_() {
    const std::vector<ValType> results = frames_.front().results;
    BO_ASSERT(can_pop(results));
    pop(results);
    mark_unreachable();
    byte(op_return);
    return *this;
}

FunctionBuilder& FunctionBuilder::unreachable() {
    mark_unreachable();
    byte(op_unreachable);
    return *this;
}

FunctionBuilder& FunctionBuilder::call(const Func callee) {
    const FuncType type = module_->type_of(callee);
    pop(type.params);
    push(type.results);
    byte(op_call);
    uleb(callee.index);
    return *this;
}

Bytes FunctionBuilder::finish() {
    const std::vector<ValType> results = frames_.front().results;
    pop(results);
    BO_ASSERT(vals_.empty());
    frames_.pop_back();
    BO_ASSERT(max_height_ <= vm::max_stack_height);
    BO_ASSERT(params() + locals_.size() <= vm::max_locals);

    Bytes body;
    // Locals, as runs of one type.
    std::vector<std::pair<std::uint32_t, ValType>> runs;
    for (const ValType t : locals_) {
        if (!runs.empty() && runs.back().second == t) {
            ++runs.back().first;
        } else {
            runs.emplace_back(1, t);
        }
    }
    put_uleb(body, runs.size());
    for (const auto& [count, type] : runs) {
        put_uleb(body, count);
        body.push_back(byte_of(type));
    }
    body.insert(body.end(), code_.begin(), code_.end());
    body.push_back(op_end);
    BO_ASSERT(body.size() <= vm::max_body_size);
    return body;
}

// ---------------------------------------------------------------------------
// ModuleWriter
// ---------------------------------------------------------------------------

ModuleWriter::ModuleWriter(const MemoryPlan& plan) : plan_(plan) {
    for (std::uint32_t i = 0; i < host_count; ++i) {
        functions_.push_back(Function{host_type(static_cast<Host>(i)), Bytes{}, 0});
    }
}

Func ModuleWriter::host(const Host host) const noexcept {
    return Func{static_cast<std::uint32_t>(host)};
}

bool ModuleWriter::is_defined(const Func f) const noexcept {
    return f.index < host_count || functions_[f.index].body.has_value();
}

const FuncType& ModuleWriter::type_of(const Func f) const noexcept {
    return functions_[f.index].type;
}

Func ModuleWriter::declare(FuncType type) {
    BO_ASSERT(functions_.size() < vm::max_functions);
    functions_.push_back(Function{std::move(type), std::nullopt, 0});
    return Func{static_cast<std::uint32_t>(functions_.size() - 1)};
}

FunctionBuilder ModuleWriter::begin(const Func f) const {
    return FunctionBuilder(*this, f);
}

void ModuleWriter::define(FunctionBuilder&& body) {
    const Func f = body.self();
    const std::uint32_t height = body.max_height();
    functions_[f.index].body = body.finish();
    functions_[f.index].max_height = height;
}

std::uint32_t ModuleWriter::max_height(const Func f) const {
    return functions_[f.index].max_height;
}

Global ModuleWriter::add_global(const ValType type, const std::int64_t initial) {
    BO_ASSERT(globals_.size() < vm::max_globals);
    BO_ASSERT(type == ValType::i64 || (initial >= std::numeric_limits<std::int32_t>::min() &&
                                       initial <= std::numeric_limits<std::int32_t>::max()));
    globals_.push_back(GlobalEntry{type, initial});
    return Global{static_cast<std::uint32_t>(globals_.size() - 1)};
}

ValType ModuleWriter::global_type(const Global global) const {
    return globals_[global.index].type;
}

bool ModuleWriter::interned(const ByteView bytes) const {
    return interned_.contains(Bytes(bytes.begin(), bytes.end()));
}

std::uint32_t ModuleWriter::intern(const ByteView bytes) {
    Bytes key(bytes.begin(), bytes.end());
    if (const auto it = interned_.find(key); it != interned_.end()) {
        return it->second;
    }
    const auto address = static_cast<std::uint32_t>(plan_.static_base + statics_.size());
    BO_ASSERT(address + bytes.size() <= plan_.static_end);
    statics_.insert(statics_.end(), bytes.begin(), bytes.end());
    interned_.emplace(std::move(key), address);
    return address;
}

std::uint32_t ModuleWriter::reserve(const std::uint32_t size, const std::uint32_t align) {
    while ((plan_.static_base + statics_.size()) % align != 0) {
        statics_.push_back(0);
    }
    const auto address = static_cast<std::uint32_t>(plan_.static_base + statics_.size());
    BO_ASSERT(std::uint64_t{address} + size <= plan_.static_end);
    statics_.resize(statics_.size() + size, 0);
    return address;
}

void ModuleWriter::entry(const Func f) {
    entry_ = f;
}

Result<Bytes> ModuleWriter::finish() const {
    BO_ASSERT(entry_.has_value());
    // Types in order of first use: the imports', then the functions'.
    std::map<FuncType, std::uint32_t> type_index;
    std::vector<const FuncType*> types;
    std::vector<std::uint32_t> function_types;
    for (const Function& f : functions_) {
        const auto [it, added] =
            type_index.emplace(f.type, static_cast<std::uint32_t>(types.size()));
        if (added) {
            types.push_back(&f.type);
        }
        function_types.push_back(it->second);
    }
    BO_ASSERT(types.size() <= vm::max_types);

    Bytes out{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};
    Bytes section;
    put_uleb(section, types.size());
    for (const FuncType* type : types) {
        section.push_back(0x60);
        put_types(section, type->params);
        put_types(section, type->results);
    }
    put_section(out, 1, section);

    section.clear();
    put_uleb(section, host_count);
    for (std::uint32_t i = 0; i < host_count; ++i) {
        put_name(section, "cexchain");
        put_name(section, name_of(static_cast<Host>(i)));
        section.push_back(0x00);
        put_uleb(section, function_types[i]);
    }
    put_section(out, 2, section);

    section.clear();
    put_uleb(section, functions_.size() - host_count);
    for (std::size_t i = host_count; i < functions_.size(); ++i) {
        BO_ASSERT(functions_[i].body.has_value());
        put_uleb(section, function_types[i]);
    }
    put_section(out, 3, section);

    section = {0x01, 0x01};
    put_uleb(section, plan_.pages);
    put_uleb(section, plan_.pages);
    put_section(out, 5, section);

    if (!globals_.empty()) {
        section.clear();
        put_uleb(section, globals_.size());
        for (const GlobalEntry& g : globals_) {
            section.push_back(byte_of(g.type));
            section.push_back(0x01);
            section.push_back(g.type == ValType::i32 ? op_i32_const : op_i64_const);
            put_sleb(section, g.initial);
            section.push_back(op_end);
        }
        put_section(out, 6, section);
    }

    section.clear();
    put_uleb(section, 2);
    put_name(section, "memory");
    section.push_back(0x02);
    put_uleb(section, 0);
    put_name(section, "cexchain_call");
    section.push_back(0x00);
    put_uleb(section, entry_->index);
    put_section(out, 7, section);

    section.clear();
    put_uleb(section, functions_.size() - host_count);
    for (std::size_t i = host_count; i < functions_.size(); ++i) {
        const Bytes& body = *functions_[i].body;
        put_uleb(section, body.size());
        section.insert(section.end(), body.begin(), body.end());
    }
    put_section(out, 10, section);

    if (!statics_.empty()) {
        section.clear();
        put_uleb(section, 1);
        section.push_back(0x00);
        section.push_back(op_i32_const);
        put_sleb(section, plan_.static_base);
        section.push_back(op_end);
        put_uleb(section, statics_.size());
        section.insert(section.end(), statics_.begin(), statics_.end());
        put_section(out, 11, section);
    }

    if (auto loaded = vm::load(out); !loaded) {
        return std::unexpected(loaded.error());
    }
    return out;
}

} // namespace cexchain::bo::wasm
