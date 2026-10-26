// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Registering documents: files uploaded first, each held for its user in
// the console's folder, then a registration prepared from a kind, its
// fields, and those files. The fields get fresh salts and are committed as
// the command line commits them; private ones stay in the vault, public
// ones go into the metadata. Nothing is sealed or sent until the person's
// passkey approves the statement (approve.cpp).

#include <algorithm>
#include <filesystem>
#include <mutex>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/records.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/node/record_files.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

std::filesystem::path uploads_directory(const std::filesystem::path& state) {
    return state / "uploads";
}

/// A file's name as an attachment's: 1 to 128 bytes, no path, no control
/// characters.
bool valid_file_name(std::string_view name) {
    return !name.empty() && name.size() <= 128 && name != "." && name != ".." &&
           std::ranges::none_of(name, [](unsigned char c) {
               return c < 0x20 || c == 0x7f || c == '/' || c == '\\';
           });
}

} // namespace

http::Response Console::upload_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (signer.role == Role::viewer) {
        return error(403, "forbidden", "a viewer reads and verifies, and registers nothing");
    }
    const auto name = request.query.find("name");
    if (name == request.query.end() || !valid_file_name(name->second)) {
        return error(400, "invalid_argument", "name the file: ?name=photo.jpg");
    }
    if (request.body.size() > node::max_record_file) {
        return error(413, "limit_exceeded", "a file is at most 16 MiB");
    }
    const std::filesystem::path directory = uploads_directory(services_.directory);
    const protocol::Timestamp now = services_.clock->now();
    std::string id;
    std::filesystem::path path;
    {
        const std::lock_guard lock(mutex_);
        std::error_code ec;
        if (!uploads_swept_) {
            std::filesystem::remove_all(directory, ec);
            uploads_swept_ = true;
        }
        for (auto it = uploads_.begin(); it != uploads_.end();) {
            if (it->second.expires <= now) {
                std::filesystem::remove(it->second.path, ec);
                it = uploads_.erase(it);
            } else {
                ++it;
            }
        }
        if (uploads_.size() >= max_uploads) {
            return error(429, "unavailable", "too many files wait to be registered");
        }
        id = to_hex(services_.entropy->bytes<12>());
        path = directory / id;
        uploads_.emplace(id, Upload{signer.user, name->second, app::media_type_of(name->second),
                                    request.body.size(), path, now + upload_lifetime});
    }
    std::filesystem::create_directories(directory);
    app::write_file(path, request.body, true);
    return json(200, {{"upload", id},
                      {"name", name->second},
                      {"size", request.body.size()},
                      {"media_type", app::media_type_of(name->second)}});
}

void Console::forget_uploads(const std::vector<std::string>& ids) const {
    const std::lock_guard lock(mutex_);
    std::error_code ec;
    for (const std::string& id : ids) {
        if (const auto it = uploads_.find(id); it != uploads_.end()) {
            std::filesystem::remove(it->second.path, ec);
            uploads_.erase(it);
        }
    }
}

std::variant<std::pair<protocol::RecordRegisterBody, Draft>, std::string>
Console::register_draft(const nlohmann::json& intent, const std::string& user) const {
    const std::string type = intent.value("kind", "");
    const std::vector<Kind> kinds = load_kinds(services_.directory);
    const auto kind = std::ranges::find(kinds, type, &Kind::type);
    if (kind == kinds.end()) {
        return std::string("this console has no kind of that type");
    }
    const auto values = intent.find("fields");
    if (values == intent.end() || !values->is_object()) {
        return std::string("a registration gives its fields: {\"fields\": {name: value}}");
    }
    for (const auto& [name, value] : values->items()) {
        if (std::ranges::find(kind->fields, name, &KindField::name) == kind->fields.end()) {
            return "the kind " + kind->name + " has no field " + name;
        }
        if (!value.is_string()) {
            return "the field " + name + " is text";
        }
    }
    const crypto::HashAlg hash = ledger()->hash();
    std::vector<protocol::RecordField> fields;
    cbor::Map metadata;
    for (const KindField& f : kind->fields) {
        const auto it = values->find(f.name);
        const std::string value = it == values->end() ? std::string() : it->get<std::string>();
        if (value.empty()) {
            if (f.required) {
                return "the field " + (f.label.empty() ? f.name : f.label) + " is required";
            }
            continue;
        }
        if (const auto problem = check_value(f, value)) {
            return "the field " + (f.label.empty() ? f.name : f.label) + " is " + *problem;
        }
        if (f.is_private) {
            fields.push_back({f.name, services_.entropy->bytes<16>(), cbor::Value::text(value)});
        } else {
            metadata.push_back({cbor::Value::text(f.name), cbor::Value::text(value)});
        }
    }
    if (fields.empty()) {
        return std::string("a record commits to at least one private field: fill one in");
    }
    const auto commitment = protocol::commit_fields(*services_.provider, hash, fields);
    if (!commitment) {
        return std::string(commitment.error().detail);
    }
    protocol::RecordRegisterBody body;
    body.record_type = kind->type;
    body.field_root = Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end());
    body.field_count = commitment->leaves.size();
    if (!metadata.empty()) {
        body.metadata = cbor::Value::map(std::move(metadata));
    }
    Draft draft;
    draft.vault.fields = commitment->fields;
    draft.keep_files = kind->keep_files;

    std::vector<std::string> ids;
    if (const auto files = intent.find("files"); files != intent.end()) {
        if (!files->is_array() ||
            !std::ranges::all_of(*files, [](const auto& f) { return f.is_string(); })) {
            return std::string("files are the uploads' ids");
        }
        for (const auto& f : *files) {
            ids.push_back(f.get<std::string>());
        }
    }
    if (kind->files == KindFiles::none && !ids.empty()) {
        return "the kind " + kind->name + " attaches no files";
    }
    if (kind->files == KindFiles::required && ids.empty()) {
        return "the kind " + kind->name + " needs a file";
    }
    std::vector<Upload> chosen;
    {
        const std::lock_guard lock(mutex_);
        const protocol::Timestamp now = services_.clock->now();
        for (const std::string& id : ids) {
            const auto it = uploads_.find(id);
            if (it == uploads_.end() || it->second.user != user || it->second.expires <= now) {
                return std::string("a file is no longer here: upload it again");
            }
            chosen.push_back(it->second);
        }
    }
    std::set<std::string> names;
    for (const Upload& u : chosen) {
        if (!names.insert(u.name).second) {
            return "two files are named " + u.name;
        }
        const Bytes content = app::read_file(u.path);
        const app::VaultAttachment salt{u.name, services_.entropy->bytes<16>()};
        const auto digest =
            protocol::attachment_commitment(*services_.provider, hash, salt.salt, content);
        if (!digest || content.size() != u.size) {
            return std::string("a file could not be read: upload it again");
        }
        body.attachments.push_back({u.name, u.media_type, content.size(),
                                    Bytes(digest->bytes().begin(), digest->bytes().end())});
        draft.vault.attachments.push_back(salt);
    }
    draft.uploads = std::move(ids);
    return std::pair(std::move(body), std::move(draft));
}

} // namespace cexchain::console
