// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "output.hpp"

#include <algorithm>
#include <print>
#include <variant>

#include <cexchain/core/protocol/record_types.hpp>

namespace cexchain::cli {

namespace {

bool presence_user_verified(const protocol::PresenceProof& proof) {
    return proof.authenticator_data.size() > 32 && (proof.authenticator_data[32] & 0x04U) != 0;
}

template <class... Fs>
struct Overloaded : Fs... {
    using Fs::operator()...;
};

Json optional_text(const std::optional<std::string>& text) {
    return text ? Json(*text) : Json(nullptr);
}

} // namespace

Json presence_credential_json(const protocol::PresenceCredential& c) {
    return {{"method",
             c.method == protocol::PresenceMethod::hardware_key ? "hardware-key" : "webauthn"},
            {"rp_id", c.rp_id.empty() ? Json(nullptr) : Json(c.rp_id)},
            {"credential_id", to_base64url(c.credential_id)},
            {"key", public_key_json(c.key)},
            {"label", optional_text(c.label)}};
}

void print_json(const Json& value) {
    std::println("{}", value.dump(2));
}

Json hex_json(ByteView bytes) {
    return to_hex(bytes);
}

Json id_json(const protocol::Id& id) {
    return hex_id(id);
}

Json public_key_json(const crypto::PublicKey& key) {
    return {{"algorithm", crypto::name(key.algorithm)}, {"key", to_hex(key.bytes)}};
}

Json actor_ref(const Session& session, const protocol::Id& id) {
    return {{"id", id_json(id)}, {"name", session.actor_name(id)}};
}

Json actor_json(const Session& session, const protocol::ActorState& actor) {
    Json out{{"id", id_json(actor.id)},
             {"kind", kind_text(actor.kind)},
             {"name", actor.display_name},
             {"key", public_key_json(actor.key)},
             {"kid", id_json(actor.kid)},
             {"revoked", actor.revoked},
             {"registered_at_index", actor.registered_at_index},
             {"rotations", actor.rotations}};
    if (actor.responsible) {
        out["responsible"] = actor_ref(session, *actor.responsible);
    }
    if (actor.agent) {
        out["agent"] = {{"model", optional_text(actor.agent->model)},
                        {"model_version", optional_text(actor.agent->model_version)},
                        {"runtime", optional_text(actor.agent->runtime)}};
    }
    if (actor.kind == protocol::ActorKind::person) {
        Json credentials = Json::array();
        for (const protocol::PresenceCredential& c : actor.presence) {
            credentials.push_back(presence_credential_json(c));
        }
        out["presence_credentials"] = std::move(credentials);
    }
    return out;
}

Json scope_json(const protocol::Scope& scope) {
    Json types = Json::array();
    for (const protocol::StatementType type : scope.statement_types) {
        types.push_back(protocol::name(type));
    }
    Json out{{"statement_types", std::move(types)},
             {"record_types", scope.record_types ? Json(*scope.record_types) : Json(nullptr)},
             {"valid_from", scope.not_before ? Json(iso_time(*scope.not_before)) : Json(nullptr)},
             {"valid_until", scope.not_after ? Json(iso_time(*scope.not_after)) : Json(nullptr)},
             {"may_delegate", scope.may_delegate},
             {"require_presence", scope.require_presence}};
    return out;
}

std::string scope_text(const protocol::Scope& scope) {
    std::string out;
    for (const protocol::StatementType type : scope.statement_types) {
        out += (out.empty() ? "" : ",") + std::string(protocol::name(type));
    }
    if (scope.record_types) {
        std::string types;
        for (const std::string& t : *scope.record_types) {
            types += (types.empty() ? "" : ",") + t;
        }
        out += " on " + types;
    }
    if (scope.not_before) {
        out += " from " + format_time(*scope.not_before);
    }
    if (scope.not_after) {
        out += " until " + format_time(*scope.not_after);
    }
    if (scope.may_delegate) {
        out += " (may delegate)";
    }
    if (scope.require_presence) {
        out += " (presence required)";
    }
    return out;
}

bool delegation_active(const protocol::DelegationState& d, protocol::Timestamp now) {
    return !d.revoked && (!d.scope.not_before || *d.scope.not_before <= now) &&
           (!d.scope.not_after || now <= *d.scope.not_after);
}

std::vector<protocol::Id> authority_chain(const Session& session,
                                          const std::optional<protocol::Id>& delegation) {
    std::vector<protocol::Id> chain;
    std::optional<protocol::Id> current = delegation;
    while (current) {
        const protocol::DelegationState* d = session.state().delegation(*current);
        if (d == nullptr || chain.size() > 64) {
            break;
        }
        chain.push_back(d->grantor);
        current = d->parent;
    }
    return chain;
}

Json delegation_json(const Session& session, const protocol::DelegationState& d) {
    Json chain = Json::array();
    for (const protocol::Id& id : authority_chain(session, d.id)) {
        chain.push_back(actor_ref(session, id));
    }
    return {{"id", id_json(d.id)},
            {"grantor", actor_ref(session, d.grantor)},
            {"grantee", actor_ref(session, d.grantee)},
            {"parent", d.parent ? id_json(*d.parent) : Json(nullptr)},
            {"scope", scope_json(d.scope)},
            {"revoked", d.revoked},
            {"active", delegation_active(d, ledger::SystemClock{}.now())},
            {"granted_at_index", d.granted_at_index},
            {"authority", std::move(chain)}};
}

std::vector<std::string> next_states(const protocol::RecordState& record) {
    std::vector<std::string> out;
    if (record.revoked) {
        return out;
    }
    if (const protocol::RecordType* type = protocol::find_record_type(record.record_type)) {
        for (const protocol::Transition& t : type->transitions) {
            if (t.from == record.state) {
                out.emplace_back(t.to);
            }
        }
    }
    return out;
}

Json record_json(const Session& session, const protocol::RecordState& record) {
    Json endorsements = Json::array();
    for (const protocol::Endorsement& e : record.endorsements) {
        endorsements.push_back(
            {{"role", e.role}, {"actor", actor_ref(session, e.actor)}, {"index", e.index}});
    }
    Json out{
        {"id", id_json(record.id)},
        {"type", record.record_type},
        {"state", record.state},
        {"revoked", record.revoked},
        {"registrant", actor_ref(session, record.registrant)},
        {"registered_at", iso_time(session.log_entry(record.registered_at_index).registered_at)},
        {"field_count", record.field_count},
        {"field_root", hex_json(record.field_root)},
        {"endorsements", std::move(endorsements)},
        {"next_states", next_states(record)},
        {"history", record.history.to_vector()}};
    const protocol::SignedStatement registration = session.statement(record.registered_at_index);
    const auto& body = std::get<protocol::RecordRegisterBody>(registration.statement.body);
    out["metadata"] = body.metadata ? cbor_json(*body.metadata) : Json(nullptr);
    Json attachments = Json::array();
    for (const protocol::Attachment& a : body.attachments) {
        attachments.push_back({{"name", a.name}, {"media_type", a.media_type}, {"size", a.size}});
    }
    out["attachments"] = std::move(attachments);
    return out;
}

Json body_json(const protocol::Body& body) {
    return std::visit(
        Overloaded{
            [](const protocol::GenesisBody& b) -> Json {
                return {{"hash", crypto::name(b.hash_alg)},
                        {"organization", b.organization},
                        {"root_key", public_key_json(b.root_key)},
                        {"log_key", public_key_json(b.log_key)}};
            },
            [](const protocol::ActorRegisterBody& b) -> Json {
                Json out{{"kind", kind_text(b.kind)},
                         {"name", b.display_name},
                         {"key", public_key_json(b.key)},
                         {"responsible", b.responsible ? id_json(*b.responsible) : Json(nullptr)}};
                if (b.agent) {
                    out["agent"] = {{"model", optional_text(b.agent->model)},
                                    {"model_version", optional_text(b.agent->model_version)},
                                    {"runtime", optional_text(b.agent->runtime)}};
                }
                return out;
            },
            [](const protocol::ActorRotateKeyBody& b) -> Json {
                return {{"actor", id_json(b.actor)}, {"key", public_key_json(b.key)}};
            },
            [](const protocol::ActorRevokeBody& b) -> Json {
                return {{"actor", id_json(b.actor)}, {"reason", optional_text(b.reason)}};
            },
            [](const protocol::DelegationGrantBody& b) -> Json {
                return {{"grantee", id_json(b.grantee)}, {"scope", scope_json(b.scope)}};
            },
            [](const protocol::DelegationRevokeBody& b) -> Json {
                return {{"delegation", id_json(b.delegation)}, {"reason", optional_text(b.reason)}};
            },
            [](const protocol::ActorSetPresenceBody& b) -> Json {
                Json credentials = Json::array();
                for (const protocol::PresenceCredential& c : b.credentials) {
                    credentials.push_back(presence_credential_json(c));
                }
                return {{"actor", id_json(b.actor)}, {"credentials", std::move(credentials)}};
            },
            [](const protocol::LedgerRotateLogKeyBody& b) -> Json {
                return {{"log_key", public_key_json(b.key)}};
            },
            [](const protocol::RecordRegisterBody& b) -> Json {
                Json attachments = Json::array();
                for (const protocol::Attachment& a : b.attachments) {
                    attachments.push_back({{"name", a.name},
                                           {"media_type", a.media_type},
                                           {"size", a.size},
                                           {"commitment", to_hex(a.commitment)}});
                }
                return {{"record_type", b.record_type},
                        {"field_root", to_hex(b.field_root)},
                        {"field_count", b.field_count},
                        {"attachments", std::move(attachments)},
                        {"metadata", b.metadata ? cbor_json(*b.metadata) : Json(nullptr)}};
            },
            [](const protocol::RecordEndorseBody& b) -> Json {
                return {{"record", id_json(b.record)}, {"role", b.role}};
            },
            [](const protocol::RecordTransitionBody& b) -> Json {
                return {{"record", id_json(b.record)}, {"from", b.from_state}, {"to", b.to_state}};
            },
            [](const protocol::RecordRevokeBody& b) -> Json {
                return {{"record", id_json(b.record)}, {"reason", optional_text(b.reason)}};
            },
            [](const protocol::AssetActionBody& b) -> Json {
                Json consents = Json::array();
                for (const protocol::ConsentRef& c : b.consents) {
                    consents.push_back({{"ledger", id_json(c.ledger)},
                                        {"record", id_json(c.record)},
                                        {"bundle", id_json(c.bundle)}});
                }
                return {{"asset", id_json(b.asset)},
                        {"action", protocol::name(b.action)},
                        {"head", b.head},
                        {"to", b.to ? id_json(*b.to) : Json(nullptr)},
                        {"quantity", b.quantity ? Json(*b.quantity) : Json(nullptr)},
                        {"consents", std::move(consents)},
                        {"reference", optional_text(b.reference)}};
            },
        },
        body);
}

Json statement_json(const protocol::Statement& s) {
    return {{"type", protocol::name(s.type())},
            {"ledger_id", s.ledger_id ? id_json(*s.ledger_id) : Json(nullptr)},
            {"actor", s.actor_id ? id_json(*s.actor_id) : Json(nullptr)},
            {"delegation", s.delegation_id ? id_json(*s.delegation_id) : Json(nullptr)},
            {"issued_at", iso_time(s.issued_at)},
            {"nonce", hex_json(s.nonce)},
            {"provenance", s.provenance ? provenance_json(*s.provenance) : Json(nullptr)},
            {"presence", s.presence
                             ? Json{{"credential_id", to_base64url(s.presence->credential_id)},
                                    {"user_verified", presence_user_verified(*s.presence)}}
                             : Json(nullptr)},
            {"body", body_json(s.body)}};
}

Json commitment_json(const protocol::StateCommitment& c) {
    return {{"ledger_id", id_json(c.ledger_id)},
            {"tree_hash", crypto::name(c.tree_hash)},
            {"index", c.tree_size},
            {"state_root", to_hex(c.state_root.bytes())},
            {"timestamp", iso_time(c.timestamp)}};
}

Json entry_json(const Session& session, std::uint64_t index) {
    const protocol::LogEntry entry = session.log_entry(index);
    if (entry.is_state_commitment()) {
        const auto commitment = session.state_commitment(index);
        return {{"index", index},
                {"statement_id", id_json(entry.statement_id)},
                {"registered_at", iso_time(entry.registered_at)},
                {"type", "state-commitment"},
                {"summary", "state commitment " +
                                to_hex(commitment.commitment.state_root.bytes()).substr(0, 12)},
                {"signer", {{"id", nullptr}, {"name", "the ledger's log key"}}},
                {"algorithm", crypto::name(commitment.envelope.algorithm)},
                {"kid", id_json(commitment.kid)},
                {"commitment", commitment_json(commitment.commitment)}};
    }
    const protocol::SignedStatement statement = session.statement(index);
    Json out{{"index", index},
             {"statement_id", id_json(entry.statement_id)},
             {"registered_at", iso_time(entry.registered_at)},
             {"type", protocol::name(statement.statement.type())},
             {"summary", statement_summary(session, statement)},
             {"signer", statement.statement.actor_id
                            ? actor_ref(session, *statement.statement.actor_id)
                            : Json{{"id", id_json(entry.statement_id)},
                                   {"name", session.state().organization()}}},
             {"algorithm", crypto::name(statement.envelope.algorithm)},
             {"kid", id_json(statement.kid)}};
    out["statement"] = statement_json(statement.statement);
    return out;
}

std::string body_summary(const Session& session, const protocol::Body& body,
                         const std::optional<protocol::Id>& statement_id) {
    const std::string id = statement_id ? " " + short_id(*statement_id) : "";
    auto name_of = [&](const protocol::Id& actor) {
        return "\"" + session.actor_name(actor) + "\"";
    };
    return std::visit(
        Overloaded{
            [&](const protocol::GenesisBody& b) {
                return "genesis of \"" + b.organization + "\" (" +
                       std::string(crypto::name(b.hash_alg)) + ")";
            },
            [&](const protocol::ActorRegisterBody& b) {
                std::string out =
                    "register " + kind_text(b.kind) + " \"" + b.display_name + "\"" + id;
                if (b.agent && b.agent->model) {
                    out += " (model " + *b.agent->model + ")";
                }
                return out;
            },
            [&](const protocol::ActorRotateKeyBody& b) {
                return b.actor == session.state().ledger_id()
                           ? std::string("rotate the organization's root key")
                           : "rotate the key of " + name_of(b.actor);
            },
            [&](const protocol::ActorRevokeBody& b) {
                return "revoke actor " + name_of(b.actor) +
                       (b.reason ? " (" + *b.reason + ")" : "");
            },
            [&](const protocol::DelegationGrantBody& b) {
                return "delegate to " + name_of(b.grantee) + ": " + scope_text(b.scope) + id;
            },
            [&](const protocol::DelegationRevokeBody& b) {
                return "revoke delegation " + short_id(b.delegation) +
                       (b.reason ? " (" + *b.reason + ")" : "");
            },
            [&](const protocol::ActorSetPresenceBody& b) {
                return b.credentials.empty() ? "remove the passkeys of " + name_of(b.actor)
                                             : "set " + std::to_string(b.credentials.size()) +
                                                   " passkey(s) for " + name_of(b.actor);
            },
            [&](const protocol::LedgerRotateLogKeyBody& b) {
                return "rotate the log key to a new " + std::string(crypto::name(b.key.algorithm)) +
                       " key";
            },
            [&](const protocol::RecordRegisterBody& b) { return "issue " + b.record_type + id; },
            [&](const protocol::RecordEndorseBody& b) {
                return "endorse " + short_id(b.record) + " as " + b.role;
            },
            [&](const protocol::RecordTransitionBody& b) {
                return "move " + short_id(b.record) + " " + b.from_state + " -> " + b.to_state;
            },
            [&](const protocol::RecordRevokeBody& b) {
                return "revoke record " + short_id(b.record) +
                       (b.reason ? " (" + *b.reason + ")" : "");
            },
            [&](const protocol::AssetActionBody& b) {
                std::string out =
                    std::string(protocol::name(b.action)) + " asset " + short_id(b.asset);
                if (b.to) {
                    out += " to ledger " + short_id(*b.to);
                }
                if (b.quantity) {
                    out += " (" + std::to_string(*b.quantity) + ")";
                }
                if (!b.consents.empty()) {
                    out += ", " + std::to_string(b.consents.size()) + " consent(s)";
                }
                return out;
            },
        },
        body);
}

std::string statement_summary(const Session& session,
                              const protocol::SignedStatement& signed_statement) {
    return body_summary(session, signed_statement.statement.body, signed_statement.id);
}

int report_submitted(const Args& args, const Session& session, const protocol::Id& statement,
                     const Json& extra, const std::string& text) {
    if (args.json()) {
        Json out{{"statement_id", id_json(statement)},
                 {"index", session.state().statement_index(statement).value_or(0)}};
        for (const auto& [key, value] : extra.items()) {
            out[key] = value;
        }
        print_json(out);
    } else {
        std::println("{}", text);
    }
    return 0;
}

} // namespace cexchain::cli
