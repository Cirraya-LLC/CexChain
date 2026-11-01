// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>

struct sqlite3;
struct sqlite3_stmt;

// Error propagation, as core's decoders do it.
#define SEARCH_CONCAT_INNER(a, b) a##b
#define SEARCH_CONCAT(a, b) SEARCH_CONCAT_INNER(a, b)
/// Evaluates `expr` (a Result<T>); returns its error, or moves its value
/// into `decl`.
#define SEARCH_TRY(decl, expr)                                                                     \
    auto SEARCH_CONCAT(search_try_, __LINE__) = (expr);                                            \
    if (!SEARCH_CONCAT(search_try_, __LINE__)) {                                                   \
        return std::unexpected(SEARCH_CONCAT(search_try_, __LINE__).error());                      \
    }                                                                                              \
    decl = std::move(*SEARCH_CONCAT(search_try_, __LINE__))
/// Evaluates `expr` (a Status) and returns its error.
#define SEARCH_CHECK(expr)                                                                         \
    if (auto SEARCH_CONCAT(search_check_, __LINE__) = (expr);                                      \
        !SEARCH_CONCAT(search_check_, __LINE__)) {                                                 \
        return std::unexpected(SEARCH_CONCAT(search_check_, __LINE__).error());                    \
    }

/// Just enough of SQLite: a connection, statements with bound values, and
/// errors as the project's.
namespace cexchain::search::sql {

class Statement {
public:
    Statement() = default;
    explicit Statement(sqlite3_stmt* statement) noexcept : statement_(statement) {}
    Statement(Statement&& other) noexcept;
    Statement& operator=(Statement&& other) noexcept;
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    ~Statement();

    /// Binds by position, from 1.
    Statement& bind(int at, std::int64_t value);
    Statement& bind(int at, std::string_view value);
    Statement& bind(int at, ByteView value);
    Statement& bind_null(int at);

    /// True while there is a row; false when done.
    [[nodiscard]] Result<bool> step();
    /// Steps to the end (a statement without rows).
    [[nodiscard]] Status run();
    void reset();

    [[nodiscard]] bool is_null(int column) const;
    [[nodiscard]] std::int64_t integer(int column) const;
    [[nodiscard]] std::string text(int column) const;
    [[nodiscard]] Bytes blob(int column) const;

private:
    sqlite3_stmt* statement_ = nullptr;
};

class Database {
public:
    [[nodiscard]] static Result<Database> open(const std::filesystem::path& file);
    Database() = default;
    Database(Database&& other) noexcept;
    Database& operator=(Database&& other) noexcept;
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    ~Database();

    /// Runs one or more statements without values.
    [[nodiscard]] Status exec(std::string_view sql);
    [[nodiscard]] Result<Statement> prepare(std::string_view sql);
    [[nodiscard]] std::string error() const;

private:
    explicit Database(sqlite3* db) noexcept : db_(db) {}
    sqlite3* db_ = nullptr;
};

} // namespace cexchain::search::sql
