// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

/// Document kinds: the console's templates for registering records. A kind
/// names a record type and the fields and files its records carry, so the
/// console can show a form; it is the console's own (kinds.json in its
/// folder), never part of the protocol: a record of the type registered any
/// other way is the same record. Private fields are committed by salted hash
/// (record fields, disclosed one by one); public ones go into the record's
/// metadata, which anyone reading the ledger sees.
///
///   {"sheet": 1, "kind": "document", "type": "example.org.photo/1",
///    "name": "Photo", "description": "...",
///    "fields": [{"name": "place", "label": "Place", "type": "text",
///                "private": true, "required": true}, ...],
///    "files": "optional" | "required" | "none", "keep_files": true}
namespace cexchain::console {

enum class FieldType : std::uint8_t { text, number, date, yes_no };

[[nodiscard]] std::string_view name_of(FieldType type) noexcept;

struct KindField {
    /// The record field's name, as the ledger commits to it.
    std::string name;
    /// What the form shows (the name if empty).
    std::string label;
    FieldType type = FieldType::text;
    bool is_private = true;
    bool required = false;
};

enum class KindFiles : std::uint8_t { none, optional, required };

struct Kind {
    std::string type;
    std::string name;
    std::string description;
    std::vector<KindField> fields;
    KindFiles files = KindFiles::optional;
    /// Keep the files with the record, sealed (else they stay with the
    /// person, committed by hash only).
    bool keep_files = true;
};

/// Reads a kind sheet; throws std::invalid_argument saying what is wrong.
[[nodiscard]] Kind parse_kind(const nlohmann::json& sheet);
[[nodiscard]] nlohmann::json kind_json(const Kind& kind);

/// Checks a value typed for `field`: its form for its type (a number, a
/// date as YYYY-MM-DD, yes or no; text up to 4096 bytes). The reason it is
/// not one, if it is not.
[[nodiscard]] std::optional<std::string> check_value(const KindField& field,
                                                     std::string_view value);

/// The console's kinds (none if never written). Throws std::runtime_error
/// if the file is damaged.
[[nodiscard]] std::vector<Kind> load_kinds(const std::filesystem::path& directory);
/// Replaces them atomically.
void save_kinds(const std::filesystem::path& directory, const std::vector<Kind>& kinds);

} // namespace cexchain::console
