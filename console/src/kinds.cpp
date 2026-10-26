// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cctype>
#include <set>
#include <stdexcept>
#include <string>
#include <variant>

#include <nlohmann/json.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/core/protocol/record_types.hpp>
#include <cexchain/ledger/storage.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::string_view kinds_file = "kinds.json";
constexpr std::size_t max_kinds = 256;
constexpr std::size_t max_fields = 32;

[[noreturn]] void bad(const std::string& message) {
    throw std::invalid_argument(message);
}

/// Text of 1 to `max` bytes with no control characters.
bool plain_text(std::string_view text, std::size_t max) {
    return !text.empty() && text.size() <= max &&
           std::ranges::none_of(text, [](unsigned char c) { return c < 0x20 || c == 0x7f; });
}

std::string text_of(const nlohmann::json& sheet, std::string_view key, bool required) {
    const auto it = sheet.find(key);
    if (it == sheet.end() || it->is_null()) {
        if (required) {
            bad("a kind needs \"" + std::string(key) + "\"");
        }
        return {};
    }
    if (!it->is_string()) {
        bad("\"" + std::string(key) + "\" is text");
    }
    return it->get<std::string>();
}

bool flag_of(const nlohmann::json& sheet, std::string_view key, bool fallback) {
    const auto it = sheet.find(key);
    if (it == sheet.end() || it->is_null()) {
        return fallback;
    }
    if (!it->is_boolean()) {
        bad("\"" + std::string(key) + "\" is true or false");
    }
    return it->get<bool>();
}

FieldType field_type(std::string_view name) {
    if (name == "text") {
        return FieldType::text;
    }
    if (name == "number") {
        return FieldType::number;
    }
    if (name == "date") {
        return FieldType::date;
    }
    if (name == "yes-no") {
        return FieldType::yes_no;
    }
    bad("a field's type is text, number, date, or yes-no");
}

std::string_view files_name(KindFiles files) {
    switch (files) {
    case KindFiles::none:
        return "none";
    case KindFiles::optional:
        return "optional";
    case KindFiles::required:
        return "required";
    }
    return "optional";
}

[[noreturn]] void damaged() {
    throw std::runtime_error("the console's kinds.json is damaged");
}

} // namespace

std::string_view name_of(FieldType type) noexcept {
    switch (type) {
    case FieldType::text:
        return "text";
    case FieldType::number:
        return "number";
    case FieldType::date:
        return "date";
    case FieldType::yes_no:
        return "yes-no";
    }
    return "text";
}

Kind parse_kind(const nlohmann::json& sheet) {
    if (!sheet.is_object()) {
        bad("a kind sheet is a JSON object");
    }
    if (const auto it = sheet.find("sheet"); it == sheet.end() || *it != 1) {
        bad("this console reads kind sheets of version 1 (\"sheet\": 1)");
    }
    if (text_of(sheet, "kind", true) != "document") {
        bad("this console defines document kinds (\"kind\": \"document\") so far");
    }
    Kind kind;
    kind.type = text_of(sheet, "type", true);
    if (!plain_text(kind.type, 128)) {
        bad("a kind's type is 1 to 128 bytes of text, such as example.org.photo/1");
    }
    if (protocol::is_reserved_record_type(kind.type) ||
        protocol::find_record_type(kind.type) != nullptr) {
        bad("record types beginning with cexchain. belong to the protocol");
    }
    kind.name = text_of(sheet, "name", true);
    if (!plain_text(kind.name, 64)) {
        bad("a kind's name is 1 to 64 bytes of text");
    }
    kind.description = text_of(sheet, "description", false);
    if (kind.description.size() > 1000) {
        bad("a kind's description is at most 1000 bytes");
    }
    const auto fields = sheet.find("fields");
    if (fields == sheet.end() || !fields->is_array() || fields->empty() ||
        fields->size() > max_fields) {
        bad("a kind has 1 to 32 fields");
    }
    std::set<std::string> names;
    for (const auto& f : *fields) {
        if (!f.is_object()) {
            bad("a field is a JSON object");
        }
        KindField field;
        field.name = text_of(f, "name", true);
        if (!plain_text(field.name, 64)) {
            bad("a field's name is 1 to 64 bytes of text");
        }
        if (!names.insert(field.name).second) {
            bad("two fields are named " + field.name);
        }
        field.label = text_of(f, "label", false);
        if (field.label.size() > 64) {
            bad("a field's label is at most 64 bytes");
        }
        field.type =
            field_type(text_of(f, "type", false).empty() ? "text" : text_of(f, "type", false));
        field.is_private = flag_of(f, "private", true);
        field.required = flag_of(f, "required", false);
        kind.fields.push_back(std::move(field));
    }
    // A record commits to at least one field.
    if (std::ranges::none_of(kind.fields, &KindField::is_private)) {
        bad("a kind needs at least one private field");
    }
    const std::string files = text_of(sheet, "files", false);
    if (files.empty() || files == "optional") {
        kind.files = KindFiles::optional;
    } else if (files == "required") {
        kind.files = KindFiles::required;
    } else if (files == "none") {
        kind.files = KindFiles::none;
    } else {
        bad("a kind's files are optional, required, or none");
    }
    kind.keep_files = flag_of(sheet, "keep_files", true);
    return kind;
}

nlohmann::json kind_json(const Kind& kind) {
    nlohmann::json fields = nlohmann::json::array();
    for (const KindField& f : kind.fields) {
        fields.push_back({{"name", f.name},
                          {"label", f.label},
                          {"type", name_of(f.type)},
                          {"private", f.is_private},
                          {"required", f.required}});
    }
    return {{"sheet", 1},
            {"kind", "document"},
            {"type", kind.type},
            {"name", kind.name},
            {"description", kind.description},
            {"fields", fields},
            {"files", files_name(kind.files)},
            {"keep_files", kind.keep_files}};
}

std::optional<std::string> check_value(const KindField& field, std::string_view value) {
    const auto digits = [](std::string_view text) {
        return !text.empty() &&
               std::ranges::all_of(text, [](unsigned char c) { return std::isdigit(c) != 0; });
    };
    switch (field.type) {
    case FieldType::text:
        if (value.size() > 4096) {
            return "at most 4096 bytes";
        }
        return std::nullopt;
    case FieldType::number: {
        std::string_view rest = value;
        if (rest.starts_with('-')) {
            rest.remove_prefix(1);
        }
        const std::size_t dot = rest.find('.');
        if (rest.size() > 40 || !digits(rest.substr(0, dot)) ||
            (dot != std::string_view::npos && !digits(rest.substr(dot + 1)))) {
            return "a number, such as 12 or -3.5";
        }
        return std::nullopt;
    }
    case FieldType::date: {
        if (value.size() != 10 || value[4] != '-' || value[7] != '-' ||
            !digits(value.substr(0, 4)) || !digits(value.substr(5, 2)) ||
            !digits(value.substr(8, 2))) {
            return "a date as YYYY-MM-DD";
        }
        const int month = std::stoi(std::string(value.substr(5, 2)));
        const int day = std::stoi(std::string(value.substr(8, 2)));
        if (month < 1 || month > 12 || day < 1 || day > 31) {
            return "a date as YYYY-MM-DD";
        }
        return std::nullopt;
    }
    case FieldType::yes_no:
        if (value != "yes" && value != "no") {
            return "yes or no";
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::vector<Kind> load_kinds(const std::filesystem::path& directory) {
    const std::filesystem::path file = directory / kinds_file;
    std::vector<Kind> kinds;
    if (!std::filesystem::exists(file)) {
        return kinds;
    }
    const Bytes bytes = app::read_file(file);
    const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!j.is_object() || !j.contains("kinds") || !j["kinds"].is_array()) {
        damaged();
    }
    for (const auto& sheet : j["kinds"]) {
        try {
            kinds.push_back(parse_kind(sheet));
        } catch (const std::invalid_argument&) {
            damaged();
        }
    }
    return kinds;
}

void save_kinds(const std::filesystem::path& directory, const std::vector<Kind>& kinds) {
    if (kinds.size() > max_kinds) {
        throw std::invalid_argument("a console keeps at most 256 kinds");
    }
    nlohmann::json list = nlohmann::json::array();
    for (const Kind& k : kinds) {
        list.push_back(kind_json(k));
    }
    std::filesystem::create_directories(directory);
    app::write_file(directory / kinds_file,
                    as_bytes(nlohmann::json{{"kinds", list}}.dump(2) + "\n"), true);
}

http::Response Console::kinds_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Role role = std::get<Signed>(who).role;
    if (request.method == "GET") {
        nlohmann::json list = nlohmann::json::array();
        for (const Kind& k : load_kinds(services_.directory)) {
            list.push_back(kind_json(k));
        }
        return json(200,
                    {{"kinds", list}, {"may_change", role == Role::owner || role == Role::admin}});
    }
    if (request.method != "POST") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "GET, POST");
        return refused;
    }
    if (role != Role::owner && role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin defines kinds");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const auto lock = ledger::DirectoryLock::acquire(services_.directory, 2000);
    if (!lock) {
        return error(503, "unavailable", "the console's kinds are being changed; try again");
    }
    std::vector<Kind> kinds = load_kinds(services_.directory);
    // {"remove": TYPE} removes a kind; anything else is a kind sheet, added
    // or replacing the kind of its type.
    if (const auto it = body.find("remove"); it != body.end()) {
        if (!it->is_string() || std::erase_if(kinds, [&](const Kind& k) {
                                    return k.type == it->get<std::string>();
                                }) == 0) {
            return error(404, "not_found", "no kind of that type");
        }
        save_kinds(services_.directory, kinds);
        return json(200, {{"removed", *it}});
    }
    Kind kind;
    try {
        kind = parse_kind(body);
    } catch (const std::invalid_argument& e) {
        return error(400, "invalid_argument", e.what());
    }
    const auto same = std::ranges::find(kinds, kind.type, &Kind::type);
    if (same != kinds.end()) {
        *same = kind;
    } else {
        kinds.push_back(kind);
    }
    try {
        save_kinds(services_.directory, kinds);
    } catch (const std::invalid_argument& e) {
        return error(409, "conflict", e.what());
    }
    return json(200, kind_json(kind));
}

} // namespace cexchain::console
