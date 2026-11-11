// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "sqlite.hpp"

#include <sqlite3.h>
#include <utility>

namespace kanhe::search::sql {

namespace {

// Error details are static: SQLite's own message is in `Database::error`.
Error failure(sqlite3* /*db*/, std::string_view what) {
    return Error{Errc::unavailable, what};
}

} // namespace

Statement::Statement(Statement&& other) noexcept
    : statement_(std::exchange(other.statement_, nullptr)) {}

Statement& Statement::operator=(Statement&& other) noexcept {
    if (this != &other) {
        sqlite3_finalize(statement_);
        statement_ = std::exchange(other.statement_, nullptr);
    }
    return *this;
}

Statement::~Statement() {
    sqlite3_finalize(statement_);
}

Statement& Statement::bind(int at, std::int64_t value) {
    sqlite3_bind_int64(statement_, at, value);
    return *this;
}

Statement& Statement::bind(int at, std::string_view value) {
    sqlite3_bind_text64(statement_, at, value.data(), value.size(), SQLITE_TRANSIENT, SQLITE_UTF8);
    return *this;
}

Statement& Statement::bind(int at, ByteView value) {
    sqlite3_bind_blob64(statement_, at, value.data(), value.size(), SQLITE_TRANSIENT);
    return *this;
}

Statement& Statement::bind_null(int at) {
    sqlite3_bind_null(statement_, at);
    return *this;
}

Result<bool> Statement::step() {
    const int rc = sqlite3_step(statement_);
    if (rc == SQLITE_ROW) {
        return true;
    }
    if (rc == SQLITE_DONE) {
        return false;
    }
    return std::unexpected(
        failure(sqlite3_db_handle(statement_), "the search index could not be read or written"));
}

Status Statement::run() {
    for (;;) {
        auto row = step();
        if (!row) {
            return std::unexpected(row.error());
        }
        if (!*row) {
            reset();
            return {};
        }
    }
}

void Statement::reset() {
    sqlite3_reset(statement_);
    sqlite3_clear_bindings(statement_);
}

bool Statement::is_null(int column) const {
    return sqlite3_column_type(statement_, column) == SQLITE_NULL;
}

std::int64_t Statement::integer(int column) const {
    return sqlite3_column_int64(statement_, column);
}

std::string Statement::text(int column) const {
    const auto* data = sqlite3_column_text(statement_, column);
    const int size = sqlite3_column_bytes(statement_, column);
    return data == nullptr
               ? std::string()
               : std::string(reinterpret_cast<const char*>(data), static_cast<std::size_t>(size));
}

Bytes Statement::blob(int column) const {
    const auto* data = static_cast<const std::uint8_t*>(sqlite3_column_blob(statement_, column));
    const int size = sqlite3_column_bytes(statement_, column);
    return data == nullptr ? Bytes() : Bytes(data, data + size);
}

Result<Database> Database::open(const std::filesystem::path& file, bool read_only) {
    sqlite3* db = nullptr;
    const int rc = sqlite3_open_v2(
        file.string().c_str(), &db,
        (read_only ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) |
            SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_EXRESCODE,
        nullptr);
    if (rc != SQLITE_OK) {
        Error e = failure(db, "the search index could not be opened");
        sqlite3_close(db);
        return std::unexpected(std::move(e));
    }
    sqlite3_busy_timeout(db, 5000);
    return Database(db);
}

Database::Database(Database&& other) noexcept : db_(std::exchange(other.db_, nullptr)) {}

Database& Database::operator=(Database&& other) noexcept {
    if (this != &other) {
        sqlite3_close(db_);
        db_ = std::exchange(other.db_, nullptr);
    }
    return *this;
}

Database::~Database() {
    sqlite3_close(db_);
}

Status Database::exec(std::string_view sql) {
    const std::string text(sql);
    if (sqlite3_exec(db_, text.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK) {
        return std::unexpected(failure(db_, "the search index could not be read or written"));
    }
    return {};
}

Result<Statement> Database::prepare(std::string_view sql) {
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v3(db_, sql.data(), static_cast<int>(sql.size()), SQLITE_PREPARE_PERSISTENT,
                           &statement, nullptr) != SQLITE_OK) {
        return std::unexpected(failure(db_, "the search index cannot run this query"));
    }
    return Statement(statement);
}

std::string Database::error() const {
    return db_ != nullptr ? sqlite3_errmsg(db_) : "no database";
}

} // namespace kanhe::search::sql
