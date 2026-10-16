// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A parsed tree as CBOR, written by static reflection (C++26, P2996): every
// clause and statement struct of ast.hpp is walked member by member, so the
// JSON that `bo check --stage parse --json` prints follows the structs
// without a hand-written case per node. Expressions, whose members depend on
// their kind, have their own writer.

#include <cstddef>
#include <cstdint>
#include <format>
#include <meta>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/bo/ast.hpp>
#include <cexchain/bo/names.hpp>

#include "reflection.hpp"

namespace cexchain::bo {

namespace {

// Every overload is declared before the templates that call them, so that
// lookup from inside the templates finds them all.
cbor::Value to_value(const std::string& text);
cbor::Value to_value(std::uint64_t number);
cbor::Value to_value(const Span& span);
cbor::Value to_value(const Concept* entry);
cbor::Value to_value(const ast::Expr& expr);
cbor::Value to_value(const ast::Statement& statement);
cbor::Value to_value(const ast::PackWord& word);
template <class T>
cbor::Value to_value(const std::vector<T>& list);
template <class T>
cbor::Value to_value(const std::optional<T>& value);
template <class... T>
cbor::Value to_value(const std::variant<T...>& value);
template <class T>
    requires requires { T::tag; }
cbor::Value to_value(const T& node);

cbor::Value entry_key(std::string_view key) {
    return cbor::Value::text(std::string(key));
}

cbor::Value to_value(const std::string& text) {
    return cbor::Value::text(text);
}

cbor::Value to_value(const std::uint64_t number) {
    return cbor::Value::unsigned_integer(number);
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

cbor::Value literal_value(const ast::Literal& literal) {
    cbor::Map map;
    map.push_back({entry_key("kind"), entry_key(name_of(literal.kind))});
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

cbor::Value to_value(const ast::Expr& expr) {
    cbor::Map map;
    map.push_back({entry_key("kind"), entry_key(name_of(expr.kind))});
    map.push_back({entry_key("span"), to_value(expr.span)});
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
    return cbor::Value::map(std::move(map));
}

cbor::Value to_value(const ast::Statement& statement) {
    return to_value(statement.node);
}

cbor::Value to_value(const ast::PackWord& word) {
    return cbor::Value::map({{entry_key("concept"), to_value(word.concept_entry)},
                             {entry_key("span"), to_value(word.span)}});
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

/// A clause or statement: its tag, then its members by name, in declaration
/// order. (A template: GCC 16's -Wshadow takes each expansion of a
/// `template for` in an ordinary function for a new local shadowing the
/// last.)
template <class T>
    requires requires { T::tag; }
cbor::Value to_value(const T& node) {
    cbor::Map map;
    map.push_back({entry_key("node"), entry_key(T::tag)});
    constexpr auto context = std::meta::access_context::current();
    template for (constexpr auto member :
                  std::define_static_array(std::meta::nonstatic_data_members_of(^^T, context))) {
        map.push_back({entry_key(std::meta::identifier_of(member)), to_value(node.[:member:])});
    }
    return cbor::Value::map(std::move(map));
}

} // namespace

cbor::Value to_cbor(const ast::File& file) {
    return cbor::Value::map(
        {{entry_key("edition"), to_value(file.edition)},
         {entry_key("uses"), to_value(file.uses)},
         {entry_key("clauses"), to_value(file.clauses)},
         {entry_key("pack_words"), to_value(file.pack_words)},
         {entry_key("implicit_vocabulary"), cbor::Value::boolean(file.implicit_vocabulary)}});
}

} // namespace cexchain::bo
