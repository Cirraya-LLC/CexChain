// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <cexchain/bo/contracts.hpp>

/// Part of cexchain::bo, the compiler proper (GCC 16). What compiled code can
/// cost at most (milestone 18): the emitter records, as it writes each
/// function, a tree of what the function's instructions cost (spec section
/// 14.3), with every loop bounded and every call named; evaluating the tree
/// gives an upper bound on the fuel a call uses and on the bytes of output it
/// writes, whatever path it takes.
///
/// Sizes. Some costs depend on how large something is: a text compared byte
/// by byte, a map searched entry by entry, a list walked item by item. A
/// function names such sizes as its size parameters, each with a default (the
/// most it can be); a call gives the callee's sizes as expressions over the
/// caller's own, so a search of a map with eight keys costs eight entries,
/// not the most a map can hold.
///
/// Items. A loop that walks items whose cost grows with each item's size (the
/// texts of a list) may say how large the items are in all: the loop then
/// costs its count times the body for an item of size 0, plus what the body
/// adds for one item as large as all of them together. That is an upper
/// bound when what the body adds is superadditive in the item's size, as
/// sums of nonnegative multiples of floor(size / k) are; sizes of items must
/// therefore not pass through `min`.
namespace cexchain::bo::wasm {

/// Bounds saturate here, far beyond any limit (a call has 10 million fuel).
inline constexpr std::uint64_t unbounded = std::uint64_t{1} << 62U;

/// An upper bound on a count or a length: a constant, a size parameter of the
/// function, or an item's size (inside a loop that walks items), combined by
/// saturating sums, products, quotients (rounded down), and minima.
class Size {
public:
    Size() = default;
    /// A constant. Implicit, so that constants read as themselves.
    Size(std::uint64_t value); // NOLINT(google-explicit-constructor)

    /// The function's size parameter `index` (FunctionBuilder::sizes).
    [[nodiscard]] static Size param(std::uint32_t index);
    /// Slot `index` of the evaluation's environment: the parameters first,
    /// then one slot per loop that walks items (FunctionBuilder::item_size).
    [[nodiscard]] static Size slot(std::uint32_t index);

    /// The value in an environment (parameters, then item slots).
    [[nodiscard]] std::uint64_t eval(std::span<const std::uint64_t> env) const;
    /// The value, if it depends on nothing.
    [[nodiscard]] std::optional<std::uint64_t> constant() const;
    /// The highest slot it reads, plus 1 (0 if none).
    [[nodiscard]] std::uint32_t slots() const;

    friend Size operator+(const Size& a, const Size& b);
    friend Size operator*(const Size& a, const Size& b);
    /// Rounded down; `divisor` at least 1.
    [[nodiscard]] Size over(std::uint64_t divisor) const BO_PRE(divisor > 0);
    [[nodiscard]] static Size min(const Size& a, const Size& b);
    [[nodiscard]] static Size max(const Size& a, const Size& b);

private:
    struct Node;
    explicit Size(std::shared_ptr<const Node> node) : node_(std::move(node)) {}
    std::shared_ptr<const Node> node_;
};

/// How often a loop's body may start: its first entry and each branch back to
/// it (so a loop that tests at the top before each of n items starts n + 1
/// times); and for a loop that walks items, the most their sizes add up to.
struct LoopBound {
    LoopBound(Size starts_) : starts(std::move(starts_)) {} // NOLINT(google-explicit-constructor)
    LoopBound(Size starts_, Size items_) : starts(std::move(starts_)), items(std::move(items_)) {}

    Size starts;
    std::optional<Size> items;
};

/// The most an invocation of a function can use: fuel, and bytes of output
/// (the bytes it reserves through the output's routines).
struct Bound {
    std::uint64_t fuel = 0;
    std::uint64_t output = 0;

    friend bool operator==(const Bound&, const Bound&) = default;
};

/// Saturating arithmetic on bounds.
[[nodiscard]] std::uint64_t add_saturating(std::uint64_t a, std::uint64_t b) noexcept;
[[nodiscard]] std::uint64_t mul_saturating(std::uint64_t a, std::uint64_t b) noexcept;

/// A function's cost, as the emitter records it. Plain instructions add
/// their fuel to the innermost sequence; blocks are sequences, an `if` is the
/// more costly of its arms, a loop multiplies its body.
struct CostNode {
    enum class Kind : std::uint8_t {
        seq,    ///< fuel, plus every child
        alt,    ///< fuel, plus the more costly child (per fuel and output)
        loop,   ///< fuel, plus `size` starts of the body (the children)
        call,   ///< fuel (the call), plus the callee with `args` as its sizes
        output, ///< `size` bytes of output
        bulk,   ///< memory.copy or memory.fill of at most `size` bytes
        cap,    ///< the children, their output at most `limit` bytes
        region, ///< the children, unless the evaluation leaves `tag` out
    };
    Kind kind = Kind::seq;
    std::uint64_t fuel = 0;
    std::vector<CostNode> children;
    Size size;
    /// loop: the items' total size, and the slot the body reads it from.
    std::optional<Size> items;
    std::uint32_t slot = 0;
    /// call: the callee's index, and its sizes (absent ones take its defaults).
    std::uint32_t callee = 0;
    std::vector<Size> args;
    /// cap: the most output its children write that counts.
    std::uint64_t limit = 0;
    /// region: what it is for, one bit (code that runs only when a call
    /// does something, such as issuing parts: a function that never does
    /// can be evaluated without it).
    std::uint32_t tag = 0;
};

} // namespace cexchain::bo::wasm
