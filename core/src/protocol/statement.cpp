// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <string>
#include <utility>

#include <cexchain/core/protocol/statement.hpp>

#include "envelope.hpp"
#include "reader.hpp"

namespace cexchain::protocol {

namespace {

using detail::entry;
using detail::MapReader;

template <class... Ts>
struct Overloaded : Ts... {
    using Ts::operator()...;
};

// statement-payload keys.
constexpr std::int64_t key_version = 0;
constexpr std::int64_t key_type = 1;
constexpr std::int64_t key_ledger = 2;
constexpr std::int64_t key_actor = 3;
constexpr std::int64_t key_delegation = 4;
constexpr std::int64_t key_issued_at = 5;
constexpr std::int64_t key_nonce = 6;
constexpr std::int64_t key_body = 7;
constexpr std::int64_t key_presence = 8;
constexpr std::int64_t key_provenance = 9;

cbor::Value id_value(const Id& id) {
    return cbor::Value::bytes(id.bytes());
}

cbor::Value text_value(const std::string& text) {
    return cbor::Value::text(text);
}

cbor::Value uint_value(std::uint64_t value) {
    return cbor::Value::unsigned_integer(value);
}

// ---------------------------------------------------------------------------
// Structural rules shared by encoding and decoding
// ---------------------------------------------------------------------------

Status require_text(const std::string& text, std::string_view detail) {
    if (text.empty()) {
        return fail(Errc::malformed, detail);
    }
    return {};
}

Status check_scope(const Scope& scope) {
    if (scope.statement_types.empty()) {
        return fail(Errc::malformed, "scope must allow at least one statement type");
    }
    if (std::ranges::contains(scope.statement_types, StatementType::genesis)) {
        return fail(Errc::malformed, "genesis cannot be delegated");
    }
    if (scope.record_types) {
        if (scope.record_types->empty()) {
            return fail(Errc::malformed, "record type list must not be empty when present");
        }
        for (const std::string& type : *scope.record_types) {
            CEXCHAIN_CHECK(require_text(type, "record type must not be empty"));
        }
    }
    if (scope.not_before && scope.not_after && *scope.not_before > *scope.not_after) {
        return fail(Errc::malformed, "scope validity ends before it begins");
    }
    return {};
}

Status check_metadata(const cbor::Value& metadata) {
    const cbor::Map* map = metadata.as_map();
    if (map == nullptr || map->empty()) {
        return fail(Errc::malformed, "metadata must be a non-empty map");
    }
    for (const cbor::MapEntry& item : *map) {
        if (item.key.as_text() == nullptr) {
            return fail(Errc::malformed, "metadata keys must be text strings");
        }
    }
    return {};
}

Status check_body(const Body& body) {
    return std::visit(
        Overloaded{
            [](const GenesisBody& b) -> Status {
                if (!is_ledger_hash(b.hash_alg)) {
                    return fail(Errc::unsupported, "ledger hash must be SHA-256 or SM3");
                }
                return require_text(b.organization, "organization name must not be empty");
            },
            [](const ActorRegisterBody& b) -> Status {
                CEXCHAIN_CHECK(require_text(b.display_name, "display name must not be empty"));
                if (b.kind == ActorKind::agent && !b.responsible) {
                    return fail(Errc::malformed, "an agent must name a responsible person");
                }
                if (b.kind != ActorKind::agent && b.agent) {
                    return fail(Errc::malformed, "only agents carry an agent profile");
                }
                return {};
            },
            [](const ActorRotateKeyBody&) -> Status { return {}; },
            [](const ActorRevokeBody&) -> Status { return {}; },
            [](const DelegationGrantBody& b) -> Status { return check_scope(b.scope); },
            [](const DelegationRevokeBody&) -> Status { return {}; },
            [](const RecordRegisterBody& b) -> Status {
                CEXCHAIN_CHECK(require_text(b.record_type, "record type must not be empty"));
                if (b.field_root.size() != id_size) {
                    return fail(Errc::malformed, "field commitment root must be 32 bytes");
                }
                if (b.field_count == 0) {
                    return fail(Errc::malformed, "a record must have at least one field");
                }
                for (const Attachment& a : b.attachments) {
                    CEXCHAIN_CHECK(require_text(a.name, "attachment name must not be empty"));
                    CEXCHAIN_CHECK(
                        require_text(a.media_type, "attachment media type must not be empty"));
                    if (a.commitment.size() != id_size) {
                        return fail(Errc::malformed, "attachment commitment must be 32 bytes");
                    }
                }
                for (std::size_t i = 0; i < b.attachments.size(); ++i) {
                    for (std::size_t j = i + 1; j < b.attachments.size(); ++j) {
                        if (b.attachments[i].name == b.attachments[j].name) {
                            return fail(Errc::malformed, "attachment names must be unique");
                        }
                    }
                }
                if (b.metadata) {
                    return check_metadata(*b.metadata);
                }
                return {};
            },
            [](const RecordEndorseBody& b) -> Status {
                return require_text(b.role, "endorsement role must not be empty");
            },
            [](const RecordTransitionBody& b) -> Status {
                CEXCHAIN_CHECK(require_text(b.from_state, "state must not be empty"));
                return require_text(b.to_state, "state must not be empty");
            },
            [](const RecordRevokeBody&) -> Status { return {}; },
        },
        body);
}

Status check_statement(const Statement& statement) {
    if (statement.type() == StatementType::genesis) {
        if (statement.ledger_id || statement.actor_id || statement.delegation_id) {
            return fail(Errc::malformed, "genesis must not name a ledger, actor, or delegation");
        }
    } else if (!statement.ledger_id || !statement.actor_id) {
        return fail(Errc::malformed, "statement must name its ledger and actor");
    }
    if (statement.provenance) {
        for (const ToolPin& tool : statement.provenance->tools) {
            CEXCHAIN_CHECK(require_text(tool.name, "tool name must not be empty"));
            if (tool.digest.empty()) {
                return fail(Errc::malformed, "tool digest must not be empty");
            }
        }
    }
    return check_body(statement.body);
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

Result<cbor::Value> encode_scope(const Scope& scope) {
    std::vector<StatementType> types = scope.statement_types;
    std::ranges::sort(types);
    if (std::ranges::adjacent_find(types) != types.end()) {
        return fail(Errc::invalid_argument, "scope lists a statement type twice");
    }
    cbor::Array type_values;
    for (const StatementType type : types) {
        type_values.push_back(uint_value(static_cast<std::uint64_t>(type)));
    }
    cbor::Map map{entry(1, cbor::Value::array(std::move(type_values)))};
    if (scope.record_types) {
        std::vector<std::string> record_types = *scope.record_types;
        std::ranges::sort(record_types);
        if (std::ranges::adjacent_find(record_types) != record_types.end()) {
            return fail(Errc::invalid_argument, "scope lists a record type twice");
        }
        cbor::Array values;
        for (const std::string& type : record_types) {
            values.push_back(text_value(type));
        }
        map.push_back(entry(2, cbor::Value::array(std::move(values))));
    }
    if (scope.not_before) {
        map.push_back(entry(3, uint_value(*scope.not_before)));
    }
    if (scope.not_after) {
        map.push_back(entry(4, uint_value(*scope.not_after)));
    }
    if (scope.may_delegate) {
        map.push_back(entry(5, cbor::Value::boolean(true)));
    }
    return cbor::Value::map(std::move(map));
}

Result<cbor::Value> encode_body(const Body& body) {
    return std::visit(
        Overloaded{
            [](const GenesisBody& b) -> Result<cbor::Value> {
                return cbor::Value::map({
                    entry(1, cbor::Value::integer(crypto::cose_id(b.hash_alg))),
                    entry(2, text_value(b.organization)),
                    entry(3, encode_public_key(b.root_key)),
                    entry(4, encode_public_key(b.log_key)),
                });
            },
            [](const ActorRegisterBody& b) -> Result<cbor::Value> {
                cbor::Map map{
                    entry(1, uint_value(static_cast<std::uint64_t>(b.kind))),
                    entry(2, text_value(b.display_name)),
                    entry(3, encode_public_key(b.key)),
                };
                if (b.responsible) {
                    map.push_back(entry(4, id_value(*b.responsible)));
                }
                if (b.agent) {
                    cbor::Map profile;
                    if (b.agent->model) {
                        profile.push_back(entry(1, text_value(*b.agent->model)));
                    }
                    if (b.agent->model_version) {
                        profile.push_back(entry(2, text_value(*b.agent->model_version)));
                    }
                    if (b.agent->runtime) {
                        profile.push_back(entry(3, text_value(*b.agent->runtime)));
                    }
                    map.push_back(entry(5, cbor::Value::map(std::move(profile))));
                }
                return cbor::Value::map(std::move(map));
            },
            [](const ActorRotateKeyBody& b) -> Result<cbor::Value> {
                return cbor::Value::map(
                    {entry(1, id_value(b.actor)), entry(2, encode_public_key(b.key))});
            },
            [](const ActorRevokeBody& b) -> Result<cbor::Value> {
                cbor::Map map{entry(1, id_value(b.actor))};
                if (b.reason) {
                    map.push_back(entry(2, text_value(*b.reason)));
                }
                return cbor::Value::map(std::move(map));
            },
            [](const DelegationGrantBody& b) -> Result<cbor::Value> {
                CEXCHAIN_TRY(cbor::Value scope, encode_scope(b.scope));
                return cbor::Value::map(
                    {entry(1, id_value(b.grantee)), entry(2, std::move(scope))});
            },
            [](const DelegationRevokeBody& b) -> Result<cbor::Value> {
                cbor::Map map{entry(1, id_value(b.delegation))};
                if (b.reason) {
                    map.push_back(entry(2, text_value(*b.reason)));
                }
                return cbor::Value::map(std::move(map));
            },
            [](const RecordRegisterBody& b) -> Result<cbor::Value> {
                cbor::Map map{
                    entry(1, text_value(b.record_type)),
                    entry(2, cbor::Value::bytes(b.field_root)),
                    entry(3, uint_value(b.field_count)),
                };
                if (!b.attachments.empty()) {
                    cbor::Array attachments;
                    for (const Attachment& a : b.attachments) {
                        attachments.push_back(cbor::Value::array({
                            text_value(a.name),
                            text_value(a.media_type),
                            uint_value(a.size),
                            cbor::Value::bytes(a.commitment),
                        }));
                    }
                    map.push_back(entry(4, cbor::Value::array(std::move(attachments))));
                }
                if (b.metadata) {
                    map.push_back(entry(5, *b.metadata));
                }
                return cbor::Value::map(std::move(map));
            },
            [](const RecordEndorseBody& b) -> Result<cbor::Value> {
                return cbor::Value::map(
                    {entry(1, id_value(b.record)), entry(2, text_value(b.role))});
            },
            [](const RecordTransitionBody& b) -> Result<cbor::Value> {
                return cbor::Value::map({entry(1, id_value(b.record)),
                                         entry(2, text_value(b.from_state)),
                                         entry(3, text_value(b.to_state))});
            },
            [](const RecordRevokeBody& b) -> Result<cbor::Value> {
                cbor::Map map{entry(1, id_value(b.record))};
                if (b.reason) {
                    map.push_back(entry(2, text_value(*b.reason)));
                }
                return cbor::Value::map(std::move(map));
            },
        },
        body);
}

cbor::Value encode_provenance(const Provenance& provenance) {
    cbor::Map map;
    if (provenance.model) {
        map.push_back(entry(1, text_value(*provenance.model)));
    }
    if (provenance.model_version) {
        map.push_back(entry(2, text_value(*provenance.model_version)));
    }
    if (provenance.input_commitment) {
        map.push_back(entry(3, cbor::Value::bytes(*provenance.input_commitment)));
    }
    if (!provenance.tools.empty()) {
        cbor::Array tools;
        for (const ToolPin& tool : provenance.tools) {
            tools.push_back(
                cbor::Value::array({text_value(tool.name), cbor::Value::bytes(tool.digest)}));
        }
        map.push_back(entry(4, cbor::Value::array(std::move(tools))));
    }
    return cbor::Value::map(std::move(map));
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

Result<std::vector<std::string>> decode_text_list(const cbor::Value& value) {
    CEXCHAIN_TRY(const cbor::Array* items, detail::as_array(value));
    std::vector<std::string> out;
    for (const cbor::Value& item : *items) {
        CEXCHAIN_TRY(std::string text, detail::as_text(item));
        out.push_back(std::move(text));
    }
    return out;
}

Result<Scope> decode_scope(const cbor::Value& value) {
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    Scope scope;

    CEXCHAIN_TRY(const cbor::Value* types_value, reader.need(1));
    CEXCHAIN_TRY(const cbor::Array* types, detail::as_array(*types_value));
    for (const cbor::Value& item : *types) {
        CEXCHAIN_TRY(std::uint64_t raw, detail::as_uint(item));
        const auto type = statement_type_from(raw);
        if (!type) {
            return fail(Errc::unsupported, "scope names an unknown statement type");
        }
        scope.statement_types.push_back(*type);
    }
    if (!std::ranges::is_sorted(scope.statement_types) ||
        std::ranges::adjacent_find(scope.statement_types) != scope.statement_types.end()) {
        return fail(Errc::non_canonical, "scope statement types must be strictly ascending");
    }

    if (const cbor::Value* record_types = reader.get(2)) {
        CEXCHAIN_TRY(std::vector<std::string> list, decode_text_list(*record_types));
        if (std::ranges::adjacent_find(list, std::ranges::greater_equal{}) != list.end()) {
            return fail(Errc::non_canonical, "scope record types must be strictly ascending");
        }
        scope.record_types = std::move(list);
    }
    CEXCHAIN_TRY(scope.not_before, reader.opt_uint(3));
    CEXCHAIN_TRY(scope.not_after, reader.opt_uint(4));
    CEXCHAIN_TRY(std::optional<bool> may_delegate, reader.opt_bool(5));
    if (may_delegate && !*may_delegate) {
        return fail(Errc::non_canonical, "may-delegate is encoded only when true");
    }
    scope.may_delegate = may_delegate.value_or(false);
    CEXCHAIN_CHECK(reader.finish());
    return scope;
}

Result<std::optional<std::string>> decode_reason(MapReader& reader) {
    return reader.opt_text(2);
}

Result<Body> decode_body(StatementType type, const cbor::Value& value) {
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    Body body;
    switch (type) {
    case StatementType::genesis: {
        GenesisBody b;
        CEXCHAIN_TRY(std::int64_t hash_id, reader.need_int(1));
        const auto hash = crypto::hash_alg_from_cose(hash_id);
        if (!hash) {
            return fail(Errc::unsupported, "unknown ledger hash algorithm");
        }
        b.hash_alg = *hash;
        CEXCHAIN_TRY(b.organization, reader.need_text(2));
        CEXCHAIN_TRY(const cbor::Value* root, reader.need(3));
        CEXCHAIN_TRY(b.root_key, decode_public_key(*root));
        CEXCHAIN_TRY(const cbor::Value* log, reader.need(4));
        CEXCHAIN_TRY(b.log_key, decode_public_key(*log));
        body = std::move(b);
        break;
    }
    case StatementType::actor_register: {
        ActorRegisterBody b;
        CEXCHAIN_TRY(std::uint64_t kind, reader.need_uint(1));
        if (kind < 1 || kind > 3) {
            return fail(Errc::unsupported, "unknown actor kind");
        }
        b.kind = static_cast<ActorKind>(kind);
        CEXCHAIN_TRY(b.display_name, reader.need_text(2));
        CEXCHAIN_TRY(const cbor::Value* key, reader.need(3));
        CEXCHAIN_TRY(b.key, decode_public_key(*key));
        CEXCHAIN_TRY(b.responsible, reader.opt_id(4));
        if (const cbor::Value* profile_value = reader.get(5)) {
            CEXCHAIN_TRY(MapReader profile_reader, MapReader::open(*profile_value));
            AgentProfile profile;
            CEXCHAIN_TRY(profile.model, profile_reader.opt_text(1));
            CEXCHAIN_TRY(profile.model_version, profile_reader.opt_text(2));
            CEXCHAIN_TRY(profile.runtime, profile_reader.opt_text(3));
            CEXCHAIN_CHECK(profile_reader.finish());
            b.agent = std::move(profile);
        }
        body = std::move(b);
        break;
    }
    case StatementType::actor_rotate_key: {
        ActorRotateKeyBody b;
        CEXCHAIN_TRY(b.actor, reader.need_id(1));
        CEXCHAIN_TRY(const cbor::Value* key, reader.need(2));
        CEXCHAIN_TRY(b.key, decode_public_key(*key));
        body = std::move(b);
        break;
    }
    case StatementType::actor_revoke: {
        ActorRevokeBody b;
        CEXCHAIN_TRY(b.actor, reader.need_id(1));
        CEXCHAIN_TRY(b.reason, decode_reason(reader));
        body = std::move(b);
        break;
    }
    case StatementType::delegation_grant: {
        DelegationGrantBody b;
        CEXCHAIN_TRY(b.grantee, reader.need_id(1));
        CEXCHAIN_TRY(const cbor::Value* scope, reader.need(2));
        CEXCHAIN_TRY(b.scope, decode_scope(*scope));
        body = std::move(b);
        break;
    }
    case StatementType::delegation_revoke: {
        DelegationRevokeBody b;
        CEXCHAIN_TRY(b.delegation, reader.need_id(1));
        CEXCHAIN_TRY(b.reason, decode_reason(reader));
        body = std::move(b);
        break;
    }
    case StatementType::record_register: {
        RecordRegisterBody b;
        CEXCHAIN_TRY(b.record_type, reader.need_text(1));
        CEXCHAIN_TRY(b.field_root, reader.need_bytes(2));
        CEXCHAIN_TRY(b.field_count, reader.need_uint(3));
        if (const cbor::Value* attachments = reader.get(4)) {
            CEXCHAIN_TRY(const cbor::Array* items, detail::as_array(*attachments));
            if (items->empty()) {
                return fail(Errc::non_canonical, "an empty attachment list must be omitted");
            }
            for (const cbor::Value& item : *items) {
                const cbor::Array* parts = item.as_array();
                if (parts == nullptr || parts->size() != 4) {
                    return fail(Errc::malformed,
                                "attachment must be [name, media type, size, commitment]");
                }
                Attachment a;
                CEXCHAIN_TRY(a.name, detail::as_text((*parts)[0]));
                CEXCHAIN_TRY(a.media_type, detail::as_text((*parts)[1]));
                CEXCHAIN_TRY(a.size, detail::as_uint((*parts)[2]));
                CEXCHAIN_TRY(a.commitment, detail::as_bytes_value((*parts)[3]));
                b.attachments.push_back(std::move(a));
            }
        }
        if (const cbor::Value* metadata = reader.get(5)) {
            b.metadata = *metadata;
        }
        body = std::move(b);
        break;
    }
    case StatementType::record_endorse: {
        RecordEndorseBody b;
        CEXCHAIN_TRY(b.record, reader.need_id(1));
        CEXCHAIN_TRY(b.role, reader.need_text(2));
        body = std::move(b);
        break;
    }
    case StatementType::record_transition: {
        RecordTransitionBody b;
        CEXCHAIN_TRY(b.record, reader.need_id(1));
        CEXCHAIN_TRY(b.from_state, reader.need_text(2));
        CEXCHAIN_TRY(b.to_state, reader.need_text(3));
        body = std::move(b);
        break;
    }
    case StatementType::record_revoke: {
        RecordRevokeBody b;
        CEXCHAIN_TRY(b.record, reader.need_id(1));
        CEXCHAIN_TRY(b.reason, decode_reason(reader));
        body = std::move(b);
        break;
    }
    }
    CEXCHAIN_CHECK(reader.finish());
    return body;
}

Result<Provenance> decode_provenance(const cbor::Value& value) {
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    Provenance provenance;
    CEXCHAIN_TRY(provenance.model, reader.opt_text(1));
    CEXCHAIN_TRY(provenance.model_version, reader.opt_text(2));
    CEXCHAIN_TRY(provenance.input_commitment, reader.opt_bytes(3));
    if (const cbor::Value* tools = reader.get(4)) {
        CEXCHAIN_TRY(const cbor::Array* items, detail::as_array(*tools));
        if (items->empty()) {
            return fail(Errc::non_canonical, "an empty tool list must be omitted");
        }
        for (const cbor::Value& item : *items) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 2) {
                return fail(Errc::malformed, "tool pin must be [name, digest]");
            }
            ToolPin tool;
            CEXCHAIN_TRY(tool.name, detail::as_text((*parts)[0]));
            CEXCHAIN_TRY(tool.digest, detail::as_bytes_value((*parts)[1]));
            provenance.tools.push_back(std::move(tool));
        }
    }
    CEXCHAIN_CHECK(reader.finish());
    return provenance;
}

} // namespace

std::optional<StatementType> statement_type_from(std::uint64_t value) noexcept {
    switch (value) {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 16:
    case 17:
    case 18:
    case 19:
        return static_cast<StatementType>(value);
    default:
        return std::nullopt;
    }
}

std::string_view name(StatementType type) noexcept {
    switch (type) {
    case StatementType::genesis:
        return "genesis";
    case StatementType::actor_register:
        return "actor-register";
    case StatementType::actor_rotate_key:
        return "actor-rotate-key";
    case StatementType::actor_revoke:
        return "actor-revoke";
    case StatementType::delegation_grant:
        return "delegation-grant";
    case StatementType::delegation_revoke:
        return "delegation-revoke";
    case StatementType::record_register:
        return "record-register";
    case StatementType::record_endorse:
        return "record-endorse";
    case StatementType::record_transition:
        return "record-transition";
    case StatementType::record_revoke:
        return "record-revoke";
    }
    return "unknown";
}

StatementType type_of(const Body& body) noexcept {
    return std::visit(
        Overloaded{
            [](const GenesisBody&) { return StatementType::genesis; },
            [](const ActorRegisterBody&) { return StatementType::actor_register; },
            [](const ActorRotateKeyBody&) { return StatementType::actor_rotate_key; },
            [](const ActorRevokeBody&) { return StatementType::actor_revoke; },
            [](const DelegationGrantBody&) { return StatementType::delegation_grant; },
            [](const DelegationRevokeBody&) { return StatementType::delegation_revoke; },
            [](const RecordRegisterBody&) { return StatementType::record_register; },
            [](const RecordEndorseBody&) { return StatementType::record_endorse; },
            [](const RecordTransitionBody&) { return StatementType::record_transition; },
            [](const RecordRevokeBody&) { return StatementType::record_revoke; },
        },
        body);
}

Result<Bytes> encode_payload(const Statement& statement) {
    if (auto s = check_statement(statement); !s) {
        return std::unexpected(Error{Errc::invalid_argument, s.error().detail});
    }
    CEXCHAIN_TRY(cbor::Value body, encode_body(statement.body));
    cbor::Map map{
        entry(key_version, uint_value(protocol_version)),
        entry(key_type, uint_value(static_cast<std::uint64_t>(statement.type()))),
        entry(key_issued_at, uint_value(statement.issued_at)),
        entry(key_nonce, cbor::Value::bytes(statement.nonce)),
        entry(key_body, std::move(body)),
    };
    if (statement.ledger_id) {
        map.push_back(entry(key_ledger, id_value(*statement.ledger_id)));
    }
    if (statement.actor_id) {
        map.push_back(entry(key_actor, id_value(*statement.actor_id)));
    }
    if (statement.delegation_id) {
        map.push_back(entry(key_delegation, id_value(*statement.delegation_id)));
    }
    if (statement.provenance) {
        map.push_back(entry(key_provenance, encode_provenance(*statement.provenance)));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<Statement> decode_payload(ByteView payload) {
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(payload));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    Statement statement;

    CEXCHAIN_TRY(std::uint64_t version, reader.need_uint(key_version));
    if (version != protocol_version) {
        return fail(Errc::unsupported, "unsupported protocol version");
    }
    CEXCHAIN_TRY(std::uint64_t raw_type, reader.need_uint(key_type));
    const auto type = statement_type_from(raw_type);
    if (!type) {
        return fail(Errc::unsupported, "unknown statement type");
    }
    CEXCHAIN_TRY(statement.ledger_id, reader.opt_id(key_ledger));
    CEXCHAIN_TRY(statement.actor_id, reader.opt_id(key_actor));
    CEXCHAIN_TRY(statement.delegation_id, reader.opt_id(key_delegation));
    CEXCHAIN_TRY(statement.issued_at, reader.need_uint(key_issued_at));
    CEXCHAIN_TRY(Bytes nonce, reader.need_bytes(key_nonce));
    if (nonce.size() != statement.nonce.size()) {
        return fail(Errc::malformed, "nonce must be 16 bytes");
    }
    std::ranges::copy(nonce, statement.nonce.begin());
    CEXCHAIN_TRY(const cbor::Value* body, reader.need(key_body));
    CEXCHAIN_TRY(statement.body, decode_body(*type, *body));
    if (reader.get(key_presence) != nullptr) {
        return fail(Errc::unsupported, "proof of presence is not supported in protocol v0.1");
    }
    if (const cbor::Value* provenance = reader.get(key_provenance)) {
        CEXCHAIN_TRY(statement.provenance, decode_provenance(*provenance));
    }
    CEXCHAIN_CHECK(reader.finish());
    CEXCHAIN_CHECK(check_statement(statement));
    return statement;
}

Result<SignedStatement> sign_statement(const crypto::Signer& signer,
                                       const crypto::Provider& provider,
                                       crypto::HashAlg ledger_hash, const Statement& statement) {
    if (!is_ledger_hash(ledger_hash)) {
        return fail(Errc::unsupported, "ledger hash must be SHA-256 or SM3");
    }
    if (const auto* genesis = std::get_if<GenesisBody>(&statement.body);
        genesis != nullptr && genesis->hash_alg != ledger_hash) {
        return fail(Errc::invalid_argument, "genesis declares a different ledger hash");
    }
    CEXCHAIN_TRY(Bytes payload, encode_payload(statement));
    CEXCHAIN_TRY(Bytes encoded, detail::sign_envelope(signer, provider, ledger_hash, payload,
                                                      statement_content_type));
    return parse_statement(provider, encoded, ledger_hash);
}

Result<SignedStatement> parse_statement(const crypto::Provider& provider, ByteView encoded,
                                        std::optional<crypto::HashAlg> ledger_hash) {
    CEXCHAIN_TRY(detail::Envelope envelope,
                 detail::parse_envelope(encoded, statement_content_type));
    CEXCHAIN_TRY(Statement statement, decode_payload(*envelope.message.payload));

    crypto::HashAlg hash{};
    if (const auto* genesis = std::get_if<GenesisBody>(&statement.body)) {
        if (ledger_hash && *ledger_hash != genesis->hash_alg) {
            return fail(Errc::invalid_argument, "genesis declares a different ledger hash");
        }
        hash = genesis->hash_alg;
    } else if (ledger_hash) {
        hash = *ledger_hash;
    } else {
        return fail(Errc::invalid_argument, "the ledger hash is required to parse this statement");
    }
    if (!is_ledger_hash(hash)) {
        return fail(Errc::unsupported, "ledger hash must be SHA-256 or SM3");
    }

    CEXCHAIN_TRY(Bytes to_be_signed, cose::sig_structure(envelope.message.protected_bytes, {},
                                                         *envelope.message.payload));
    CEXCHAIN_TRY(Id id, provider.digest(hash, to_be_signed));
    return SignedStatement{
        .encoded = Bytes(encoded.begin(), encoded.end()),
        .envelope = std::move(envelope.message),
        .statement = std::move(statement),
        .id = id,
        .kid = envelope.kid,
        .hash_alg = hash,
    };
}

Status verify_statement(const crypto::Provider& provider, const SignedStatement& statement,
                        const crypto::PublicKey& key) {
    return detail::verify_envelope(provider, statement.hash_alg,
                                   detail::Envelope{statement.envelope, statement.kid}, key);
}

} // namespace cexchain::protocol
