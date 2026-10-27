// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A thing's page and its proof. A record's page shows what the ledger holds
// (its type, state, registrant, endorsements, public metadata, the files it
// commits to) and, to those allowed, its private fields and kept files,
// opened with the console's vault key and checked against the ledger. Its
// proof is the node's evidence bundle plus the field disclosures and file
// openings the person chose: what `cexchain export --disclose` writes.

#include <algorithm>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/records.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/record_files.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::string_view records_prefix = "/console/api/records/";

std::optional<protocol::Id> id_of(std::string_view hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

nlohmann::json actor_view(const protocol::LedgerState& state, const protocol::Id& id) {
    const protocol::ActorState* a = state.actor(id);
    return {{"id", to_hex(id.bytes())},
            {"name", a != nullptr ? nlohmann::json(a->display_name) : nlohmann::json()}};
}

/// A file as a download, never shown in the console's origin.
http::Response download(Bytes content, std::string_view name, std::string_view media_type) {
    http::Response r;
    r.status = 200;
    r.content_type = std::string(media_type);
    r.body = std::move(content);
    // RFC 5987: the name as UTF-8, percent-encoded.
    std::string encoded;
    for (const char ch : name) {
        const auto c = static_cast<unsigned char>(ch);
        if (std::isalnum(c) != 0 || c == '.' || c == '-' || c == '_') {
            encoded += static_cast<char>(c);
        } else {
            constexpr std::string_view digits = "0123456789ABCDEF";
            encoded += '%';
            encoded += digits[c >> 4U];
            encoded += digits[c & 15U];
        }
    }
    r.headers.emplace_back("Content-Disposition", "attachment; filename*=UTF-8''" + encoded);
    secure(r);
    // A file from a record is never a page of the console's.
    r.headers.emplace_back("Content-Security-Policy", "sandbox; default-src 'none'");
    return r;
}

} // namespace

std::optional<protocol::RecordRegisterBody>
Console::registration(const protocol::LedgerState& state, const protocol::Id& record) const {
    const ledger::Ledger* served = ledger();
    const auto index = state.statement_index(record);
    if (served == nullptr || !index) {
        return std::nullopt;
    }
    std::optional<protocol::RecordRegisterBody> out;
    static_cast<void>(served->visit_entry(*index, [&](ByteView bytes) {
        const auto entry = protocol::decode_log_entry(bytes);
        if (!entry) {
            return;
        }
        const auto parsed =
            protocol::parse_statement(*services_.provider, entry->statement, served->hash());
        if (parsed) {
            if (const auto* body =
                    std::get_if<protocol::RecordRegisterBody>(&parsed->statement.body)) {
                out = *body;
            }
        }
    }));
    return out;
}

bool Console::may_read_private(const Signed& who, const protocol::LedgerState& state,
                               const protocol::RecordState& record) const {
    if (who.role == Role::owner || who.role == Role::admin) {
        return true;
    }
    if (who.role == Role::viewer) {
        return false;
    }
    const People people = load_people(services_.directory);
    const User* user = people.find(who.user);
    const auto actor = user != nullptr ? id_of(user->actor) : std::nullopt;
    if (!actor) {
        return false;
    }
    if (protocol::Id(record.registrant) == *actor) {
        return true;
    }
    return node::choose_delegation(state, *actor, protocol::StatementType::record_register,
                                   record.record_type, services_.clock->now())
        .has_value();
}

std::optional<app::Vault> Console::private_data(const protocol::LedgerState& state,
                                                const protocol::Id& record) const {
    const protocol::RecordState* r = state.record(record);
    const std::filesystem::path file = services_.directory.parent_path() / "vault" / "records" /
                                       (to_hex(record.bytes()) + ".cbor");
    if (r == nullptr || services_.keys == nullptr || !services_.keys->unlocked() ||
        !services_.keys->vault_public_key() || !std::filesystem::exists(file)) {
        return std::nullopt;
    }
    try {
        const auto key = services_.keys->open_vault_key();
        app::Vault vault =
            app::open_vault_file(app::read_file(file), state.ledger_id(), record, &key);
        if (!app::matches_record(*services_.provider, state.hash(), *r, vault)) {
            return std::nullopt;
        }
        return vault;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

http::Response Console::record_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (request.method != "GET") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "GET");
        return refused;
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return services_.keys != nullptr && services_.keys->initialized() &&
                       !services_.keys->unlocked()
                   ? error(423, "locked", "the console is locked: unlock it first")
                   : error(503, "unavailable", "the console has no ledger yet");
    }
    const std::string_view rest = std::string_view(request.path).substr(records_prefix.size());
    const std::size_t slash = rest.find('/');
    const auto id = id_of(rest.substr(0, slash));
    std::optional<std::uint64_t> file_index;
    if (slash != std::string_view::npos) {
        constexpr std::string_view files = "files/";
        const std::string_view tail = rest.substr(slash + 1);
        std::uint64_t index = 0;
        const std::string_view digits = tail.substr(std::min(files.size(), tail.size()));
        const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), index);
        if (!tail.starts_with(files) || ec != std::errc{} || end != digits.data() + digits.size() ||
            digits.empty()) {
            return error(404, "not_found", "no such console route");
        }
        file_index = index;
    }
    if (!id) {
        return error(400, "invalid_argument", "a record's id is 64 hex digits");
    }

    std::optional<http::Response> answer;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* r = state.record(*id);
        if (r == nullptr) {
            answer = error(404, "not_found", "no such record on this ledger");
            return;
        }
        const auto body = registration(state, *id);
        if (!body) {
            answer = error(409, "conflict", "the record's registration cannot be read");
            return;
        }
        const bool allowed = may_read_private(signer, state, *r);
        const bool locked = services_.keys == nullptr || !services_.keys->unlocked();
        const auto vault = allowed ? private_data(state, *id) : std::nullopt;
        const auto kept = node::kept_record_files(services_.directory.parent_path(), *id);

        if (file_index) {
            if (*file_index >= body->attachments.size()) {
                answer = error(404, "not_found", "the record attaches no file there");
            } else if (!allowed) {
                answer = error(403, "forbidden", "you may not read this record's files");
            } else if (!std::ranges::contains(kept, *file_index)) {
                answer = error(404, "not_found", "no copy of that file is kept");
            } else if (!vault) {
                answer = locked ? error(423, "locked", "the console is locked: unlock it first")
                                : error(409, "conflict", "the record's private data is not here");
            } else {
                const protocol::Attachment& a = body->attachments[*file_index];
                try {
                    Bytes content = app::open_sealed_file(
                        app::read_file(node::record_file_path(services_.directory.parent_path(),
                                                              *id, *file_index)),
                        state.ledger_id(), *id, a.name, services_.keys->open_vault_key());
                    if (!app::matches_attachment(*services_.provider, state.hash(), a, *vault,
                                                 content)) {
                        answer = error(409, "conflict",
                                       "the kept copy is not the file the record committed to");
                    } else {
                        answer = download(std::move(content), a.name, "application/octet-stream");
                    }
                } catch (const std::exception&) {
                    answer = error(409, "conflict", "the kept copy cannot be opened");
                }
            }
            return;
        }

        nlohmann::json metadata = nlohmann::json::object();
        if (body->metadata && body->metadata->as_map() != nullptr) {
            for (const auto& entry : *body->metadata->as_map()) {
                if (entry.key.as_text() != nullptr && entry.value.as_text() != nullptr) {
                    metadata[*entry.key.as_text()] = *entry.value.as_text();
                }
            }
        }
        nlohmann::json files = nlohmann::json::array();
        for (std::size_t i = 0; i < body->attachments.size(); ++i) {
            const protocol::Attachment& a = body->attachments[i];
            files.push_back({{"index", i},
                             {"name", a.name},
                             {"media_type", a.media_type},
                             {"size", a.size},
                             {"kept", std::ranges::contains(kept, i)}});
        }
        nlohmann::json endorsements = nlohmann::json::array();
        for (const protocol::Endorsement& e : r->endorsements) {
            endorsements.push_back(
                {{"role", e.role}, {"actor", actor_view(state, e.actor)}, {"index", e.index}});
        }
        nlohmann::json fields;
        if (vault) {
            fields = nlohmann::json::array();
            for (const protocol::RecordField& f : vault->fields) {
                fields.push_back({{"name", f.name},
                                  {"value", f.value.as_text() != nullptr
                                                ? nlohmann::json(*f.value.as_text())
                                                : nlohmann::json(app::display_value(f.value))}});
            }
        }
        std::string kind_name;
        for (const Kind& k : load_kinds(services_.directory)) {
            if (k.type == r->record_type) {
                kind_name = k.name;
            }
        }
        answer = json(
            200, {{"id", to_hex(id->bytes())},
                  {"type", r->record_type},
                  {"kind", kind_name.empty() ? nlohmann::json() : nlohmann::json(kind_name)},
                  {"state", r->state},
                  {"revoked", r->revoked},
                  {"registrant", actor_view(state, r->registrant)},
                  {"index", r->registered_at_index},
                  {"field_count", r->field_count},
                  {"metadata", metadata},
                  {"files", files},
                  {"endorsements", endorsements},
                  {"history", r->history.size()},
                  {"private",
                   {{"allowed", allowed}, {"locked", allowed && locked}, {"fields", fields}}}});
    });
    return std::move(*answer);
}

void Console::proof_route(const http::Request& request, Respond respond) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        respond(std::move(*refused));
        return;
    }
    const Signed signer = std::get<Signed>(who);
    const ledger::Ledger* const served = ledger();
    const Evidence source = evidence();
    if (served == nullptr || !source) {
        respond(error(503, "unavailable", "the console has no ledger to prove anything from"));
        return;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    const auto id = body.is_object() ? id_of(body.value("record", "")) : std::nullopt;
    if (!id) {
        respond(error(400, "invalid_argument", "name the record by its full id (hex)"));
        return;
    }
    std::vector<std::string> disclose;
    if (const auto it = body.find("disclose"); it != body.end()) {
        if (!it->is_array() ||
            !std::ranges::all_of(*it, [](const auto& v) { return v.is_string(); })) {
            respond(error(400, "invalid_argument", "disclose names fields"));
            return;
        }
        for (const auto& v : *it) {
            disclose.push_back(v.get<std::string>());
        }
    }
    const bool with_files = body.value("files", false);
    // What is disclosed is taken from the private data now, before the
    // node builds the bundle.
    std::optional<app::Vault> vault;
    std::string problem;
    int status = 0;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* r = state.record(*id);
        if (r == nullptr) {
            status = 404;
            problem = "no such record on this ledger";
            return;
        }
        if (disclose.empty() && !with_files) {
            return;
        }
        if (!may_read_private(signer, state, *r)) {
            status = 403;
            problem = "you may not disclose this record's private data";
            return;
        }
        vault = private_data(state, *id);
        if (!vault) {
            status = services_.keys != nullptr && !services_.keys->unlocked() ? 423 : 409;
            problem = status == 423 ? "the console is locked: unlock it first"
                                    : "the record's private data is not here";
        }
    });
    if (!problem.empty()) {
        respond(error(status,
                      status == 403   ? "forbidden"
                      : status == 404 ? "not_found"
                      : status == 423 ? "locked"
                                      : "conflict",
                      problem));
        return;
    }
    const crypto::HashAlg hash = served->hash();
    const crypto::Provider* provider = services_.provider;
    source(*id, [=, respond = std::move(respond)](Result<Bytes> encoded) {
        if (!encoded) {
            respond(error(503, "unavailable", encoded.error().detail));
            return;
        }
        auto bundle = protocol::decode_bundle(*encoded);
        if (!bundle) {
            respond(error(500, "internal", "the node's evidence does not decode"));
            return;
        }
        if (vault) {
            const auto commitment = protocol::commit_fields(*provider, hash, vault->fields);
            if (!commitment) {
                respond(error(500, "internal", "the fields could not be committed"));
                return;
            }
            for (const std::string& name : disclose) {
                auto disclosure = protocol::disclose_field(*provider, hash, *commitment, name);
                if (!disclosure) {
                    respond(error(400, "invalid_argument", "the record has no such field"));
                    return;
                }
                bundle->disclosures.push_back(std::move(*disclosure));
            }
            if (with_files) {
                for (const app::VaultAttachment& a : vault->attachments) {
                    bundle->attachments.push_back({a.name, a.salt});
                }
            }
        }
        auto out = protocol::encode_bundle(*bundle);
        if (!out) {
            respond(error(500, "internal", "the proof could not be encoded"));
            return;
        }
        respond(download(std::move(*out), "proof-" + to_hex(id->bytes()).substr(0, 12) + ".cbor",
                         "application/cbor"));
    });
}

} // namespace cexchain::console
