// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A checked model as CBOR, written by static reflection (C++26, P2996):
// every struct of model.hpp is walked member by member, so the JSON that
// `bo check --stage model --json` prints follows the structs without a
// hand-written case per declaration or statement. Types, expressions, and
// literals, whose useful members depend on their kind, have their own
// writers.

#include <cstddef>
#include <cstdint>
#include <format>
#include <meta>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/model.hpp>
#include <cexchain/bo/names.hpp>

#include "reflection.hpp"

namespace cexchain::bo {

namespace {

// Every overload is declared before the templates that call them, so that
// lookup from inside the templates finds them all.
cbor::Value to_value(bool flag);
cbor::Value to_value(std::uint64_t number);
cbor::Value to_value(const std::string& text);
cbor::Value to_value(std::string_view text);
cbor::Value to_value(const Span& span);
cbor::Value to_value(const Concept* entry);
cbor::Value to_value(const model::Type& type);
cbor::Value to_value(const model::Expr& expr);
cbor::Value to_value(const model::Statement& statement);
template <class E>
    requires std::is_enum_v<E>
cbor::Value to_value(E value);
template <class T>
cbor::Value to_value(const std::vector<T>& list);
template <class T>
cbor::Value to_value(const std::optional<T>& value);
template <class... T>
cbor::Value to_value(const std::variant<T...>& value);
template <class T>
    requires(std::is_class_v<T> && std::is_aggregate_v<T>)
cbor::Value to_value(const T& node);

cbor::Value entry_key(std::string_view key) {
    return cbor::Value::text(std::string(key));
}

cbor::Value to_value(const bool flag) {
    return cbor::Value::boolean(flag);
}

cbor::Value to_value(const std::uint64_t number) {
    return cbor::Value::unsigned_integer(number);
}

cbor::Value to_value(const std::string& text) {
    return cbor::Value::text(text);
}

cbor::Value to_value(const std::string_view text) {
    return cbor::Value::text(std::string(text));
}

cbor::Value to_value(const Span& span) {
    return cbor::Value::map({{entry_key("line"), to_value(std::uint64_t{span.line})},
                             {entry_key("column"), to_value(std::uint64_t{span.column})},
                             {entry_key("offset"), to_value(std::uint64_t{span.offset})},
                             {entry_key("length"), to_value(std::uint64_t{span.length})}});
}

cbor::Value to_value(const Concept* entry) {
    return entry == nullptr ? cbor::Value::null() : cbor::Value::text(std::string(entry->id));
}

cbor::Value to_value(const model::Type& type) {
    return cbor::Value::text(encode(type));
}

template <class E>
    requires std::is_enum_v<E>
cbor::Value to_value(const E value) {
    return entry_key(detail::enumerator_name(value));
}

cbor::Value literal_value(const ast::Literal& literal) {
    cbor::Map map;
    map.push_back({entry_key("kind"), to_value(literal.kind)});
    switch (literal.kind) {
    case ast::LiteralKind::date:
        map.push_back({entry_key("value"),
                       cbor::Value::text(std::format("{:04}-{:02}-{:02}", literal.date.year,
                                                     literal.date.month, literal.date.day))});
        break;
    case ast::LiteralKind::text:
        map.push_back({entry_key("value"), to_value(literal.text)});
        break;
    case ast::LiteralKind::number:
    case ast::LiteralKind::money:
    case ast::LiteralKind::quantity:
    case ast::LiteralKind::duration:
    case ast::LiteralKind::rate:
        map.push_back({entry_key("value"), cbor::Value::text(to_string(literal.number))});
        break;
    }
    if (literal.unit != nullptr) {
        map.push_back({entry_key("unit"), to_value(literal.unit)});
    }
    return cbor::Value::map(std::move(map));
}

cbor::Value to_value(const model::Expr& expr) {
    cbor::Map map;
    map.push_back({entry_key("kind"), to_value(expr.kind)});
    map.push_back({entry_key("span"), to_value(expr.span)});
    map.push_back({entry_key("type"), to_value(expr.type)});
    switch (expr.kind) {
    case ast::ExprKind::literal:
        map.push_back({entry_key("literal"), literal_value(expr.literal)});
        break;
    case ast::ExprKind::name:
        map.push_back({entry_key("name"), to_value(expr.name)});
        break;
    case ast::ExprKind::word:
        map.push_back({entry_key("concept"), to_value(expr.concept_entry)});
        break;
    case ast::ExprKind::apply:
        map.push_back({entry_key("concept"), to_value(expr.concept_entry)});
        map.push_back({entry_key("operands"), to_value(expr.operands)});
        break;
    case ast::ExprKind::unary:
    case ast::ExprKind::binary:
        map.push_back({entry_key("operator"),
                       entry_key(ast::operator_texts[static_cast<std::size_t>(expr.op)])});
        map.push_back({entry_key("operands"), to_value(expr.operands)});
        break;
    case ast::ExprKind::phrase:
    case ast::ExprKind::list:
        map.push_back({entry_key("operands"), to_value(expr.operands)});
        break;
    }
    if (expr.refers != model::Refers::none) {
        map.push_back({entry_key("refers"), to_value(expr.refers)});
    }
    if (!expr.rule.empty()) {
        map.push_back({entry_key("rule"), to_value(expr.rule)});
    }
    return cbor::Value::map(std::move(map));
}

cbor::Value to_value(const model::Statement& statement) {
    return to_value(statement.node);
}

template <class T>
cbor::Value to_value(const std::vector<T>& list) {
    cbor::Array items;
    items.reserve(list.size());
    for (const T& item : list) {
        items.push_back(to_value(item));
    }
    return cbor::Value::array(std::move(items));
}

template <class T>
cbor::Value to_value(const std::optional<T>& value) {
    return value ? to_value(*value) : cbor::Value::null();
}

template <class... T>
cbor::Value to_value(const std::variant<T...>& value) {
    return std::visit([](const auto& node) { return to_value(node); }, value);
}

/// A struct: its tag, if it has one (statements), then its members by name,
/// in declaration order. (A template: GCC 16's -Wshadow takes each expansion
/// of a `template for` in an ordinary function for a new local shadowing the
/// last.)
template <class T>
    requires(std::is_class_v<T> && std::is_aggregate_v<T>)
cbor::Value to_value(const T& node) {
    cbor::Map map;
    if constexpr (requires { T::tag; }) {
        map.push_back({entry_key("node"), entry_key(T::tag)});
    }
    constexpr auto context = std::meta::access_context::current();
    template for (constexpr auto member :
                  std::define_static_array(std::meta::nonstatic_data_members_of(^^T, context))) {
        map.push_back({entry_key(std::meta::identifier_of(member)), to_value(node.[:member:])});
    }
    return cbor::Value::map(std::move(map));
}

} // namespace

cbor::Value to_cbor(const model::Model& model) {
    return to_value(model);
}

} // namespace cexchain::bo
