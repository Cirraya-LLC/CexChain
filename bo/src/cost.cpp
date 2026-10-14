// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Sizes for the bounds on what compiled code can cost (cost.hpp).

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <utility>

#include <cexchain/bo/cost.hpp>

namespace cexchain::bo::wasm {

std::uint64_t add_saturating(const std::uint64_t a, const std::uint64_t b) noexcept {
    return std::min(unbounded, a >= unbounded || b >= unbounded ? unbounded : a + b);
}

std::uint64_t mul_saturating(const std::uint64_t a, const std::uint64_t b) noexcept {
    if (a == 0 || b == 0) {
        return 0;
    }
    if (a >= unbounded || b >= unbounded || a > unbounded / b) {
        return unbounded;
    }
    return std::min(unbounded, a * b);
}

struct Size::Node {
    enum class Kind : std::uint8_t { constant, slot, add, mul, over, min, max };
    Kind kind = Kind::constant;
    std::uint64_t value = 0;
    std::shared_ptr<const Node> a;
    std::shared_ptr<const Node> b;
};

Size::Size(const std::uint64_t value)
    : node_(std::make_shared<const Node>(
          Node{Node::Kind::constant, std::min(value, unbounded), nullptr, nullptr})) {}

Size Size::param(const std::uint32_t index) {
    return slot(index);
}

Size Size::slot(const std::uint32_t index) {
    return Size(std::make_shared<const Node>(Node{Node::Kind::slot, index, nullptr, nullptr}));
}

std::uint64_t Size::eval(const std::span<const std::uint64_t> env) const {
    if (!node_) {
        return 0;
    }
    const Node& n = *node_;
    const auto sub = [&](const std::shared_ptr<const Node>& x) {
        return Size(x).eval(env);
    };
    switch (n.kind) {
    case Node::Kind::constant:
        return n.value;
    case Node::Kind::slot:
        // A slot beyond the environment is a size nobody gave: the most.
        return n.value < env.size() ? std::min(env[n.value], unbounded) : unbounded;
    case Node::Kind::add:
        return add_saturating(sub(n.a), sub(n.b));
    case Node::Kind::mul:
        return mul_saturating(sub(n.a), sub(n.b));
    case Node::Kind::over:
        return sub(n.a) / n.value;
    case Node::Kind::min:
        return std::min(sub(n.a), sub(n.b));
    case Node::Kind::max:
        return std::max(sub(n.a), sub(n.b));
    }
    return unbounded;
}

std::optional<std::uint64_t> Size::constant() const {
    if (slots() != 0) {
        return std::nullopt;
    }
    return eval({});
}

std::uint32_t Size::slots() const {
    if (!node_) {
        return 0;
    }
    const Node& n = *node_;
    switch (n.kind) {
    case Node::Kind::constant:
        return 0;
    case Node::Kind::slot:
        return static_cast<std::uint32_t>(n.value) + 1;
    case Node::Kind::over:
        return Size(n.a).slots();
    default:
        return std::max(Size(n.a).slots(), Size(n.b).slots());
    }
}

Size operator+(const Size& a, const Size& b) {
    return Size(
        std::make_shared<const Size::Node>(Size::Node{Size::Node::Kind::add, 0, a.node_, b.node_}));
}

Size operator*(const Size& a, const Size& b) {
    return Size(
        std::make_shared<const Size::Node>(Size::Node{Size::Node::Kind::mul, 0, a.node_, b.node_}));
}

Size Size::over(const std::uint64_t divisor) const {
    return Size(std::make_shared<const Node>(Node{Node::Kind::over, divisor, node_, nullptr}));
}

Size Size::min(const Size& a, const Size& b) {
    return Size(std::make_shared<const Node>(Node{Node::Kind::min, 0, a.node_, b.node_}));
}

Size Size::max(const Size& a, const Size& b) {
    return Size(std::make_shared<const Node>(Node{Node::Kind::max, 0, a.node_, b.node_}));
}

} // namespace cexchain::bo::wasm
