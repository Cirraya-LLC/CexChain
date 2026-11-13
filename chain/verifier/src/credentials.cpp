// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <format>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/record_types.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/verifier/credentials.hpp>
#include <kanhe/verifier/gzip.hpp>
#include <kanhe/verifier/jcs.hpp>

namespace kanhe::verifier {

namespace {

constexpr std::string_view status_list_type = "BitstringStatusListCredential";
constexpr std::string_view evidence_type = "KanheEvidence";
/// No credential this profile makes comes near this; it bounds the work a
/// hostile one costs.
constexpr std::size_t max_compact_size = 1 << 20;
/// A status list's GZIP may decompress to no more than this before it is
/// refused for its size.
constexpr std::size_t max_status_list_output = std::size_t{1} << 22;

std::string hex_id(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string short_hex(const protocol::Id& id) {
    return hex_id(id).substr(0, 12);
}

/// A decimal without leading zeros, below `limit`.
std::optional<std::uint64_t> decimal(std::string_view text, std::uint64_t limit) {
    if (text.empty() || text.size() > 20 || (text.size() > 1 && text.front() == '0')) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || end != text.data() + text.size() || value >= limit) {
        return std::nullopt;
    }
    return value;
}

bool host_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
}

bool path_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
           c == '.' || c == '_' || c == '~';
}

bool all_digits_and_dots(std::string_view host) {
    return std::ranges::all_of(host, [](char c) { return (c >= '0' && c <= '9') || c == '.'; });
}

const Json* member(const Json& object, std::string_view name) {
    if (!object.is_object()) {
        return nullptr;
    }
    const auto it = object.find(std::string(name));
    return it == object.end() ? nullptr : &*it;
}

const std::string* text_member(const Json& object, std::string_view name) {
    const Json* m = member(object, name);
    return m != nullptr && m->is_string() ? &m->get_ref<const std::string&>() : nullptr;
}

bool only_members(const Json& object, std::initializer_list<std::string_view> allowed) {
    return std::ranges::all_of(object.items(), [&](const auto& item) {
        return std::ranges::contains(allowed, std::string_view(item.key()));
    });
}

bool is_array_of(const Json& value, std::initializer_list<std::string_view> items) {
    if (!value.is_array() || value.size() != items.size()) {
        return false;
    }
    std::size_t i = 0;
    for (const std::string_view item : items) {
        if (!value[i].is_string() || value[i].get_ref<const std::string&>() != item) {
            return false;
        }
        ++i;
    }
    return true;
}

std::optional<protocol::Id> id_from_hex(std::string_view text) {
    if (text.size() != 2 * protocol::id_size || !std::ranges::all_of(text, [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) {
        return std::nullopt;
    }
    const auto bytes = from_hex(text);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::Id::from_bytes(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

/// "u" + base64url, the Multibase form an encodedList takes.
std::optional<Bytes> multibase(std::string_view text) {
    if (text.empty() || text.front() != 'u') {
        return std::nullopt;
    }
    auto bytes = from_base64url(text.substr(1));
    return bytes ? std::optional(std::move(*bytes)) : std::nullopt;
}

std::string base64url_text(std::string_view text) {
    return to_base64url(as_bytes(text));
}

/// A published token: 22 base64url characters.
bool valid_token(std::string_view token) {
    return token.size() == 22 && std::ranges::all_of(token, [](char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '-' || c == '_';
           });
}

/// What a credential's payload names, read without checking it against
/// anything: section 7, step 1.
struct Parsed {
    Jws jws;
    std::string issuer;
    std::string issuer_name;
    std::optional<std::string> name;
    std::string valid_from;
    Json subject;
    StatusEntry entry;
    std::string status_list_url;
    std::string evidence_url;
    BaseUrl base;
    std::string token;
    protocol::Id ledger;
    protocol::Id record;
    std::string thumbprint;
};

Result<Parsed> parse_credential(std::string_view credential) {
    auto jws = parse_jws(credential);
    if (!jws) {
        return std::unexpected(jws.error());
    }
    Parsed out;
    out.jws = std::move(*jws);
    const Json& p = out.jws.payload;
    if (!only_members(p, {"@context", "type", "name", "issuer", "validFrom", "credentialSubject",
                          "credentialStatus", "evidence"})) {
        return fail(Errc::unsupported, "a credential member this profile does not define");
    }
    const Json* context = member(p, "@context");
    const Json* type = member(p, "type");
    if (context == nullptr || !is_array_of(*context, {credentials_context}) || type == nullptr ||
        !is_array_of(*type, {"VerifiableCredential"})) {
        return fail(Errc::unsupported, "not a credential of this profile (its context or type)");
    }
    if (const Json* name = member(p, "name")) {
        if (!name->is_string() || name->get_ref<const std::string&>().empty() ||
            name->get_ref<const std::string&>().size() > max_credential_name) {
            return fail(Errc::malformed, "a credential's name is 1 to 256 bytes of text");
        }
        out.name = name->get<std::string>();
    }
    const Json* issuer = member(p, "issuer");
    if (issuer == nullptr || !issuer->is_object() || !only_members(*issuer, {"id", "name"}) ||
        text_member(*issuer, "id") == nullptr || text_member(*issuer, "name") == nullptr) {
        return fail(Errc::malformed, "a credential's issuer is {id, name}");
    }
    out.issuer = *text_member(*issuer, "id");
    out.issuer_name = *text_member(*issuer, "name");
    const std::string* valid_from = text_member(p, "validFrom");
    if (valid_from == nullptr) {
        return fail(Errc::malformed, "a credential without validFrom");
    }
    out.valid_from = *valid_from;
    const Json* subject = member(p, "credentialSubject");
    if (subject == nullptr || !subject->is_object() || subject->empty() ||
        subject->size() > max_subject_members) {
        return fail(Errc::malformed, "a credential's subject holds 1 to 64 claims");
    }
    for (const auto& [name, value] : subject->items()) {
        if (claim_name_problem(name) ||
            !(value.is_string() || value.is_boolean() || value.is_number_integer())) {
            return fail(Errc::malformed, "a credential claim of a name or value not allowed");
        }
    }
    out.subject = *subject;

    const Json* status = member(p, "credentialStatus");
    if (status == nullptr || !status->is_object() ||
        !only_members(*status,
                      {"id", "type", "statusPurpose", "statusListIndex", "statusListCredential"})) {
        return fail(Errc::malformed, "a credential's status is a BitstringStatusListEntry");
    }
    const std::string* status_id = text_member(*status, "id");
    const std::string* status_type = text_member(*status, "type");
    const std::string* purpose = text_member(*status, "statusPurpose");
    const std::string* index = text_member(*status, "statusListIndex");
    const std::string* list_url = text_member(*status, "statusListCredential");
    if (status_id == nullptr || status_type == nullptr ||
        *status_type != "BitstringStatusListEntry" || purpose == nullptr ||
        *purpose != "revocation" || index == nullptr || list_url == nullptr) {
        return fail(Errc::malformed, "a credential's status is a BitstringStatusListEntry");
    }
    const auto i = decimal(*index, status_list_size);
    if (!i || *status_id != *list_url + "#" + *index) {
        return fail(Errc::malformed, "a credential's status entry index or id is not as defined");
    }

    const Json* evidence = member(p, "evidence");
    if (evidence == nullptr || !evidence->is_array() || evidence->size() != 1 ||
        !(*evidence)[0].is_object() ||
        !only_members((*evidence)[0], {"id", "type", "ledger", "record"})) {
        return fail(Errc::malformed, "a credential's evidence is one KanheEvidence entry");
    }
    const Json& e = (*evidence)[0];
    const Json* e_type = member(e, "type");
    const std::string* e_id = text_member(e, "id");
    const std::string* e_ledger = text_member(e, "ledger");
    const std::string* e_record = text_member(e, "record");
    if (e_type == nullptr || !is_array_of(*e_type, {evidence_type}) || e_id == nullptr ||
        e_ledger == nullptr || e_record == nullptr) {
        return fail(Errc::malformed, "a credential's evidence is one KanheEvidence entry");
    }
    const auto ledger = id_from_hex(*e_ledger);
    const auto record = id_from_hex(*e_record);
    if (!ledger || !record) {
        return fail(Errc::malformed, "a credential's evidence names ids in lowercase hex");
    }
    out.ledger = *ledger;
    out.record = *record;
    out.evidence_url = *e_id;
    // BASE/c/TOKEN: the base URL is what comes before.
    const auto slash = out.evidence_url.rfind("/c/");
    if (slash == std::string::npos || !valid_token(out.evidence_url.substr(slash + 3))) {
        return fail(Errc::malformed, "a credential's evidence address is not BASE/c/TOKEN");
    }
    out.token = out.evidence_url.substr(slash + 3);
    auto base = parse_base_url(out.evidence_url.substr(0, slash));
    if (!base || base->url != out.evidence_url.substr(0, slash)) {
        return fail(Errc::malformed, "a credential's evidence address has no valid base URL");
    }
    out.base = std::move(*base);
    if (out.issuer != out.base.did) {
        return fail(Errc::malformed, "a credential's issuer is not the did:web of its base URL");
    }
    const std::string list_prefix = out.base.url + "/status/";
    const auto n = list_url->starts_with(list_prefix)
                       ? decimal(std::string_view(*list_url).substr(list_prefix.size()),
                                 std::numeric_limits<std::uint64_t>::max())
                       : std::nullopt;
    if (!n || *n == 0) {
        return fail(Errc::malformed, "a credential's status list is not BASE/status/N");
    }
    out.entry = {.list = *n, .index = *i};
    out.status_list_url = *list_url;
    const std::string kid_prefix = out.issuer + "#";
    if (!out.jws.kid.starts_with(kid_prefix) || out.jws.kid.size() != kid_prefix.size() + 43) {
        return fail(Errc::malformed, "a credential's kid is not its issuer's DID and a thumbprint");
    }
    out.thumbprint = out.jws.kid.substr(kid_prefix.size());
    return out;
}

/// The keys of actor `actor` the bundle shows, each with the log index of
/// the statement that set it, oldest first.
std::vector<std::pair<std::uint64_t, crypto::PublicKey>>
actor_keys(const crypto::Provider& provider, const protocol::EvidenceBundle& bundle,
           crypto::HashAlg hash, const protocol::Id& actor) {
    std::vector<std::pair<std::uint64_t, crypto::PublicKey>> keys;
    for (const protocol::EvidenceEntry& e : bundle.entries) {
        const auto entry = protocol::decode_log_entry(e.entry);
        const auto receipt = protocol::parse_receipt(e.receipt);
        if (!entry || !receipt || entry->is_state_commitment()) {
            continue;
        }
        const auto statement = protocol::parse_statement(provider, entry->statement, hash);
        if (!statement) {
            continue;
        }
        const std::uint64_t index = receipt->proof.leaf_index;
        if (const auto* r = std::get_if<protocol::ActorRegisterBody>(&statement->statement.body);
            r != nullptr && statement->id == actor) {
            keys.emplace_back(index, r->key);
        } else if (const auto* k =
                       std::get_if<protocol::ActorRotateKeyBody>(&statement->statement.body);
                   k != nullptr && k->actor == actor) {
            keys.emplace_back(index, k->key);
        }
    }
    std::ranges::sort(keys, {}, &std::pair<std::uint64_t, crypto::PublicKey>::first);
    return keys;
}

/// The keys an actor held from `index` on: the one in effect then, and
/// every later one.
std::vector<crypto::PublicKey>
keys_from(const std::vector<std::pair<std::uint64_t, crypto::PublicKey>>& keys,
          std::uint64_t index) {
    std::vector<crypto::PublicKey> out;
    for (std::size_t i = 0; i < keys.size(); ++i) {
        const bool in_effect =
            keys[i].first < index && (i + 1 == keys.size() || keys[i + 1].first >= index);
        if (in_effect || keys[i].first > index) {
            out.push_back(keys[i].second);
        }
    }
    return out;
}

std::string json_text(const Json& value) {
    return value.is_string() ? value.get<std::string>()
                             : value.dump(-1, ' ', false, Json::error_handler_t::replace);
}

} // namespace

// ---- names --------------------------------------------------------------

Explained<BaseUrl> parse_base_url(std::string_view url) {
    while (url.ends_with('/')) {
        url.remove_suffix(1);
    }
    bool http = false;
    std::string_view rest;
    if (url.starts_with("https://")) {
        rest = url.substr(8);
    } else if (url.starts_with("http://")) {
        http = true;
        rest = url.substr(7);
    } else {
        return std::unexpected(std::format("{} is not an https URL", url));
    }
    const std::size_t path_at = rest.find('/');
    const std::string_view authority = rest.substr(0, path_at);
    const std::string_view path =
        path_at == std::string_view::npos ? std::string_view() : rest.substr(path_at);
    const std::size_t colon = authority.find(':');
    const std::string_view host = authority.substr(0, colon);
    std::optional<std::uint64_t> port;
    if (colon != std::string_view::npos) {
        port = decimal(authority.substr(colon + 1), 65'536);
        if (!port || *port == 0) {
            return std::unexpected(std::format("{} has a port that is not 1 to 65535", url));
        }
    }
    if (host.empty() || host.size() > 253 || !std::ranges::all_of(host, host_char) ||
        host.front() == '.' || host.back() == '.' || host.find("..") != std::string_view::npos) {
        return std::unexpected(
            std::format("{} does not name a host in lowercase letters, digits, - and .", url));
    }
    const bool local = host == "localhost" || host == "127.0.0.1";
    if (http && !local) {
        return std::unexpected(
            std::format("{}: http only for localhost and 127.0.0.1, for tests", url));
    }
    if (!local && all_digits_and_dots(host)) {
        return std::unexpected(std::format("{}: did:web names a host, not an IP address", url));
    }
    BaseUrl out;
    out.url = std::string(url);
    out.did = "did:web:" + std::string(host);
    if (port) {
        out.did += "%3A" + std::to_string(*port);
    }
    if (!path.empty()) {
        std::string_view segments = path.substr(1);
        while (true) {
            const std::size_t next = segments.find('/');
            const std::string_view segment = segments.substr(0, next);
            if (segment.empty() || segment == "." || segment == ".." ||
                !std::ranges::all_of(segment, path_char)) {
                return std::unexpected(std::format("{} has a path segment not allowed", url));
            }
            out.did += ":" + std::string(segment);
            if (next == std::string_view::npos) {
                break;
            }
            segments = segments.substr(next + 1);
        }
    }
    out.did_document_url = out.url + (path.empty() ? "/.well-known/did.json" : "/did.json");
    return out;
}

std::string credential_role(const StatusEntry& entry) {
    return std::format("{}{}/{}", credential_role_prefix, entry.list, entry.index);
}

std::optional<StatusEntry> parse_credential_role(std::string_view role) {
    if (!role.starts_with(credential_role_prefix)) {
        return std::nullopt;
    }
    role.remove_prefix(credential_role_prefix.size());
    const std::size_t slash = role.find('/');
    if (slash == std::string_view::npos) {
        return std::nullopt;
    }
    const auto list = decimal(role.substr(0, slash), std::numeric_limits<std::uint64_t>::max());
    const auto index = decimal(role.substr(slash + 1), status_list_size);
    if (!list || *list == 0 || !index) {
        return std::nullopt;
    }
    return StatusEntry{.list = *list, .index = *index};
}

// ---- keys ---------------------------------------------------------------

Result<Json> public_jwk(const crypto::PublicKey& key) {
    if (key.algorithm != crypto::SigAlg::esp256 || key.bytes.size() != 65 || key.bytes[0] != 4) {
        return fail(Errc::unsupported, "a credential key is an ECDSA P-256 key (esp256)");
    }
    const ByteView point(key.bytes);
    Json jwk = Json::object();
    jwk["kty"] = "EC";
    jwk["crv"] = "P-256";
    jwk["x"] = to_base64url(point.subspan(1, 32));
    jwk["y"] = to_base64url(point.subspan(33, 32));
    return jwk;
}

Result<crypto::PublicKey> jwk_key(const Json& jwk) {
    const std::string* kty = text_member(jwk, "kty");
    const std::string* crv = text_member(jwk, "crv");
    const std::string* x = text_member(jwk, "x");
    const std::string* y = text_member(jwk, "y");
    if (kty == nullptr || *kty != "EC" || crv == nullptr || *crv != "P-256" || x == nullptr ||
        y == nullptr || member(jwk, "d") != nullptr) {
        return fail(Errc::unsupported, "a JWK that is not a public EC P-256 key");
    }
    const auto xb = from_base64url(*x);
    const auto yb = from_base64url(*y);
    if (!xb || !yb || xb->size() != 32 || yb->size() != 32) {
        return fail(Errc::malformed, "a JWK whose coordinates are not 32 bytes each");
    }
    crypto::PublicKey key{.algorithm = crypto::SigAlg::esp256, .bytes = {4}};
    key.bytes.insert(key.bytes.end(), xb->begin(), xb->end());
    key.bytes.insert(key.bytes.end(), yb->begin(), yb->end());
    return key;
}

Result<std::string> jwk_thumbprint(const crypto::Provider& provider, const crypto::PublicKey& key) {
    const auto jwk = public_jwk(key);
    if (!jwk) {
        return std::unexpected(jwk.error());
    }
    // RFC 7638: the required members in lexicographic order, which is JCS's.
    Json required = Json::object();
    required["crv"] = (*jwk)["crv"];
    required["kty"] = (*jwk)["kty"];
    required["x"] = (*jwk)["x"];
    required["y"] = (*jwk)["y"];
    const auto text = jcs(required);
    if (!text) {
        return std::unexpected(text.error());
    }
    const auto digest = provider.digest(crypto::HashAlg::sha256, as_bytes(*text));
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return to_base64url(digest->bytes());
}

// ---- content ------------------------------------------------------------

std::optional<Json> claim_value(const cbor::Value& value) {
    if (const std::string* text = value.as_text()) {
        return Json(*text);
    }
    if (const auto b = value.as_bool()) {
        return Json(*b);
    }
    if (const auto n = value.as_int64(); n && *n <= max_json_integer && *n >= -max_json_integer) {
        return Json(*n);
    }
    return std::nullopt;
}

std::optional<std::string> claim_name_problem(std::string_view name) {
    if (name.empty()) {
        return "an empty name";
    }
    if (name == "id" || name == "type") {
        return std::format("\"{}\" names the subject itself in a credential", name);
    }
    if (name.starts_with('@')) {
        return "a name beginning with @ is JSON-LD's";
    }
    return std::nullopt;
}

Explained<CredentialContent> credential_content(const protocol::EvidenceReport& report,
                                                const BaseUrl& base, std::string token,
                                                const StatusEntry& entry,
                                                std::span<const std::string> metadata,
                                                std::optional<std::string> name) {
    if (report.instance || report.events.empty() ||
        report.events.front().type != protocol::StatementType::record_register) {
        return std::unexpected("the evidence is not a record's");
    }
    if (protocol::find_record_type(report.record_type) != nullptr) {
        return std::unexpected(
            std::format("{} is one of the protocol's own types: it is not issued as a credential",
                        report.record_type));
    }
    if (report.revoked) {
        return std::unexpected("the record is revoked: no credential is issued for it");
    }
    if (report.superseded_by) {
        return std::unexpected(std::format("the record was replaced by a newer version ({}): "
                                           "issue that one's credential instead",
                                           short_hex(*report.superseded_by)));
    }
    if (name && (name->empty() || name->size() > max_credential_name)) {
        return std::unexpected("a credential's name is 1 to 256 bytes");
    }
    CredentialContent out;
    out.base = base;
    out.organization = report.organization;
    out.name = std::move(name);
    out.registered_at = report.events.front().registered_at;
    out.entry = entry;
    out.token = std::move(token);
    out.ledger = report.ledger_id;
    out.record = report.record;
    auto add = [&](const std::string& claim, const cbor::Value& value,
                   std::string_view what) -> std::optional<std::string> {
        if (const auto problem = claim_name_problem(claim)) {
            return std::format("the {} {} cannot be a claim: {}", what, claim, *problem);
        }
        if (std::ranges::contains(out.subject, claim, &std::pair<std::string, Json>::first)) {
            return std::format("{} is both a disclosed field and a metadata entry", claim);
        }
        auto v = claim_value(value);
        if (!v) {
            return std::format("the {} {} holds neither text, an integer, nor true or false", what,
                               claim);
        }
        out.subject.emplace_back(claim, std::move(*v));
        return std::nullopt;
    };
    for (const protocol::RecordField& field : report.disclosed_fields) {
        if (auto problem = add(field.name, field.value, "field")) {
            return std::unexpected(std::move(*problem));
        }
    }
    for (const std::string& key : metadata) {
        const cbor::Value* value =
            report.metadata ? report.metadata->find(std::string_view(key)) : nullptr;
        if (value == nullptr) {
            return std::unexpected(
                std::format("the record's public metadata has no entry {}", key));
        }
        if (auto problem = add(key, *value, "metadata entry")) {
            return std::unexpected(std::move(*problem));
        }
    }
    if (out.subject.empty()) {
        return std::unexpected("the published address discloses no field, and no metadata entry "
                               "was asked for: a credential needs at least one claim");
    }
    if (out.subject.size() > max_subject_members) {
        return std::unexpected("a credential holds at most 64 claims");
    }
    return out;
}

Json credential_json(const CredentialContent& c) {
    Json out = Json::object();
    out["@context"] = Json::array({credentials_context});
    out["type"] = Json::array({"VerifiableCredential"});
    if (c.name) {
        out["name"] = *c.name;
    }
    out["issuer"] = Json{{"id", c.base.did}, {"name", c.organization}};
    out["validFrom"] = iso_time(c.registered_at);
    Json subject = Json::object();
    for (const auto& [claim, value] : c.subject) {
        subject[claim] = value;
    }
    out["credentialSubject"] = std::move(subject);
    const std::string list = std::format("{}/status/{}", c.base.url, c.entry.list);
    out["credentialStatus"] = Json{{"id", std::format("{}#{}", list, c.entry.index)},
                                   {"type", "BitstringStatusListEntry"},
                                   {"statusPurpose", "revocation"},
                                   {"statusListIndex", std::to_string(c.entry.index)},
                                   {"statusListCredential", list}};
    out["evidence"] = Json::array({Json{{"id", c.base.url + "/c/" + c.token},
                                        {"type", Json::array({evidence_type})},
                                        {"ledger", hex_id(c.ledger)},
                                        {"record", hex_id(c.record)}}});
    return out;
}

Json status_list_json(const BaseUrl& base, std::string_view organization, std::uint64_t list,
                      ByteView bits, protocol::Timestamp made_at) {
    const std::string id = std::format("{}/status/{}", base.url, list);
    Json out = Json::object();
    out["@context"] = Json::array({credentials_context});
    out["type"] = Json::array({"VerifiableCredential", status_list_type});
    out["id"] = id;
    out["issuer"] = Json{{"id", base.did}, {"name", std::string(organization)}};
    out["validFrom"] = iso_time(made_at);
    out["credentialSubject"] = Json{{"id", id + "#list"},
                                    {"type", "BitstringStatusList"},
                                    {"statusPurpose", "revocation"},
                                    {"encodedList", encode_status_list(bits)}};
    return out;
}

Result<Json> did_document(const crypto::Provider& provider, const BaseUrl& base,
                          std::span<const crypto::PublicKey> keys, const protocol::Id& ledger) {
    std::map<std::string, Json> methods; // by thumbprint: ordered, each once
    for (const crypto::PublicKey& key : keys) {
        auto thumbprint = jwk_thumbprint(provider, key);
        auto jwk = public_jwk(key);
        if (!thumbprint || !jwk) {
            return std::unexpected(!thumbprint ? thumbprint.error() : jwk.error());
        }
        (*jwk)["alg"] = "ES256";
        methods.emplace(*thumbprint, std::move(*jwk));
    }
    Json verification = Json::array();
    Json assertion = Json::array();
    for (auto& [thumbprint, jwk] : methods) {
        const std::string id = base.did + "#" + thumbprint;
        verification.push_back(Json{{"id", id},
                                    {"type", "JsonWebKey"},
                                    {"controller", base.did},
                                    {"publicKeyJwk", std::move(jwk)}});
        assertion.push_back(id);
    }
    Json out = Json::object();
    out["@context"] = Json::array({"https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"});
    out["id"] = base.did;
    out["verificationMethod"] = std::move(verification);
    out["assertionMethod"] = std::move(assertion);
    out["service"] = Json::array({Json{{"id", base.did + "#kanhe"},
                                       {"type", "KanheLedger"},
                                       {"serviceEndpoint", base.url},
                                       {"ledger", hex_id(ledger)}}});
    return out;
}

// ---- JWS ----------------------------------------------------------------

Result<std::string> sign_credential(const crypto::Signer& key, const crypto::Provider& provider,
                                    std::string_view did, const Json& payload) {
    const auto thumbprint = jwk_thumbprint(provider, key.public_key());
    if (!thumbprint) {
        return std::unexpected(thumbprint.error());
    }
    const Json header{{"alg", "ES256"},
                      {"cty", "vc"},
                      {"kid", std::string(did) + "#" + *thumbprint},
                      {"typ", "vc+jwt"}};
    const auto header_text = jcs(header);
    const auto payload_text = jcs(payload);
    if (!header_text || !payload_text) {
        return std::unexpected(!header_text ? header_text.error() : payload_text.error());
    }
    std::string input = base64url_text(*header_text) + "." + base64url_text(*payload_text);
    const auto signature = key.sign(as_bytes(input));
    if (!signature) {
        return std::unexpected(signature.error());
    }
    return input + "." + to_base64url(*signature);
}

Result<Jws> parse_jws(std::string_view compact) {
    if (compact.size() > max_compact_size) {
        return fail(Errc::limit_exceeded, "a credential larger than 1 MiB");
    }
    while (!compact.empty() && (compact.back() == '\n' || compact.back() == '\r')) {
        compact.remove_suffix(1);
    }
    const std::size_t first = compact.find('.');
    const std::size_t second =
        first == std::string_view::npos ? first : compact.find('.', first + 1);
    if (second == std::string_view::npos ||
        compact.find('.', second + 1) != std::string_view::npos) {
        return fail(Errc::malformed, "not a compact JWS (three parts)");
    }
    const auto header_bytes = from_base64url(compact.substr(0, first));
    const auto payload_bytes = from_base64url(compact.substr(first + 1, second - first - 1));
    const auto signature = from_base64url(compact.substr(second + 1));
    if (!header_bytes || !payload_bytes || !signature) {
        return fail(Errc::malformed, "a JWS part that is not base64url");
    }
    const std::string_view header_text(reinterpret_cast<const char*>(header_bytes->data()),
                                       header_bytes->size());
    const std::string_view payload_text(reinterpret_cast<const char*>(payload_bytes->data()),
                                        payload_bytes->size());
    auto header = parse_jcs(header_text);
    if (!header) {
        return std::unexpected(header.error());
    }
    auto payload = parse_jcs(payload_text);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    if (!header->is_object() || !payload->is_object()) {
        return fail(Errc::malformed, "a JWS whose header or payload is not a JSON object");
    }
    if (!only_members(*header, {"alg", "kid", "typ", "cty"})) {
        return fail(Errc::unsupported, "a JWS header member this profile does not define");
    }
    const std::string* alg = text_member(*header, "alg");
    const std::string* kid = text_member(*header, "kid");
    const Json* typ = member(*header, "typ");
    const Json* cty = member(*header, "cty");
    if (alg == nullptr || *alg != "ES256" || kid == nullptr ||
        (typ != nullptr && *typ != "vc+jwt") || (cty != nullptr && *cty != "vc")) {
        return fail(Errc::unsupported, "a JWS that is not ES256 with a kid, typ vc+jwt, cty vc");
    }
    if (signature->size() != 64) {
        return fail(Errc::malformed, "an ES256 signature is 64 bytes");
    }
    Jws out;
    out.header = std::move(*header);
    out.payload = std::move(*payload);
    out.signing_input = std::string(compact.substr(0, second));
    out.signature = std::move(*signature);
    out.kid = *kid;
    return out;
}

Status verify_jws(const crypto::Provider& provider, const Jws& jws, const crypto::PublicKey& key) {
    return provider.verify(key, as_bytes(jws.signing_input), jws.signature);
}

// ---- status lists -------------------------------------------------------

std::string encode_status_list(ByteView bits) {
    return "u" + to_base64url(gzip_compress(bits));
}

Result<Bytes> decode_status_list(std::string_view encoded) {
    const auto compressed = multibase(encoded);
    if (!compressed) {
        return fail(Errc::malformed, "an encodedList that is not u and base64url");
    }
    auto bits = gzip_decompress(*compressed, max_status_list_output);
    if (!bits) {
        return std::unexpected(bits.error());
    }
    if (bits->size() != status_list_bytes) {
        return fail(Errc::unsupported, "a status list that is not 131,072 bits");
    }
    return bits;
}

bool status_bit(ByteView bits, std::uint64_t index) noexcept {
    if (index / 8 >= bits.size()) {
        return false;
    }
    const auto byte = static_cast<std::size_t>(index / 8);
    return ((bits[byte] >> (7 - index % 8)) & 1U) != 0;
}

void set_status_bit(std::span<std::uint8_t> bits, std::uint64_t index) noexcept {
    if (index / 8 >= bits.size()) {
        return;
    }
    const auto byte = static_cast<std::size_t>(index / 8);
    bits[byte] = static_cast<std::uint8_t>(bits[byte] | (0x80U >> (index % 8)));
}

// ---- verification -------------------------------------------------------

Result<CredentialAddresses> credential_addresses(std::string_view credential) {
    const auto parsed = parse_credential(credential);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return CredentialAddresses{.evidence = parsed->evidence_url,
                               .did_document = parsed->base.did_document_url,
                               .status_list = parsed->status_list_url,
                               .ledger = parsed->ledger};
}

Result<CredentialReport> verify_credential(const crypto::Provider& provider,
                                           std::string_view credential, ByteView bundle,
                                           const CredentialOptions& options) {
    auto parsed = parse_credential(credential);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (options.verify.expected_ledger && *options.verify.expected_ledger != parsed->ledger) {
        return fail(Errc::verification_failed,
                    "the credential names another ledger than the one expected");
    }
    protocol::VerifyOptions verify = options.verify;
    verify.expected_ledger = parsed->ledger;
    auto evidence = protocol::verify_bundle(provider, bundle, verify);
    if (!evidence) {
        return std::unexpected(evidence.error());
    }
    const auto decoded = protocol::decode_bundle(bundle);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }

    CredentialReport r;
    r.issuer = parsed->issuer;
    r.issuer_name = parsed->issuer_name;
    r.name = parsed->name;
    r.valid_from = parsed->valid_from;
    r.subject = parsed->subject;
    r.entry = parsed->entry;
    r.status_list_url = parsed->status_list_url;
    r.evidence_url = parsed->evidence_url;
    r.kid = parsed->jws.kid;
    r.base = parsed->base;
    r.evidence = std::move(*evidence);
    const protocol::EvidenceReport& e = r.evidence;
    r.record_status = e.revoked ? "revoked" : e.superseded_by ? "replaced" : "live";

    if (e.record != parsed->record || e.instance || e.events.empty()) {
        r.problems.push_back("the evidence is not about the record the credential names");
        return r;
    }

    // Step 3: the endorsement that names this entry, and the key it vouches for.
    const std::string role = credential_role(parsed->entry);
    std::optional<crypto::PublicKey> signed_with;
    bool endorsed = false;
    for (const protocol::RecordEvent& event : e.events) {
        if (event.type != protocol::StatementType::record_endorse || event.detail != role ||
            event.actor.kind != protocol::ActorKind::device) {
            continue;
        }
        endorsed = true;
        const auto keys =
            keys_from(actor_keys(provider, *decoded, e.hash, event.actor.id), event.index);
        for (const crypto::PublicKey& key : keys) {
            const auto thumbprint = jwk_thumbprint(provider, key);
            if (thumbprint && *thumbprint == parsed->thumbprint &&
                verify_jws(provider, parsed->jws, key)) {
                signed_with = key;
                r.key_actor = event.actor.id;
                r.key_actor_name = event.actor.name;
                r.key_actor_revoked = event.actor.revoked;
                r.endorsement_index = event.index;
                r.endorsed_at = event.registered_at;
                break;
            }
        }
        if (signed_with) {
            break;
        }
    }
    if (!endorsed) {
        r.problems.push_back(std::format(
            "the record's evidence holds no endorsement as {} by a device: the issuer's ledger "
            "does not show this credential",
            role));
    } else if (!signed_with) {
        r.problems.push_back("the credential's signature is not by a key of the device that "
                             "endorsed the record as its credential");
    }

    // Step 4: what it says, against the evidence.
    if (r.issuer_name != e.organization) {
        r.problems.push_back(std::format("the credential names its issuer \"{}\"; the ledger is "
                                         "\"{}\"'s",
                                         r.issuer_name, e.organization));
    }
    const std::string registered = iso_time(e.events.front().registered_at);
    if (r.valid_from != registered) {
        r.problems.push_back(
            std::format("the credential is valid from {}; the record was registered at {}",
                        r.valid_from, registered));
    }
    for (const auto& [claim, value] : r.subject.items()) {
        bool found = false;
        for (const protocol::RecordField& field : e.disclosed_fields) {
            if (field.name == claim) {
                const auto v = claim_value(field.value);
                found = v && *v == value;
                break;
            }
        }
        if (!found && e.metadata) {
            const cbor::Value* m = e.metadata->find(std::string_view(claim));
            const auto v = m != nullptr ? claim_value(*m) : std::nullopt;
            found = v && *v == value;
        }
        if (!found) {
            r.problems.push_back(std::format(
                "the claim {} = {} is not a field the evidence discloses, nor public metadata",
                claim, json_text(value)));
        }
    }

    // Step 6: the DID document.
    if (options.did_document) {
        r.did_document_checked = true;
        const Json doc = Json::parse(*options.did_document, nullptr, false);
        auto& problems = r.did_document_problems;
        if (doc.is_discarded() || !doc.is_object()) {
            problems.push_back("the DID document is not a JSON object");
        } else {
            const std::string* id = text_member(doc, "id");
            if (id == nullptr || *id != r.issuer) {
                problems.push_back(std::format("the DID document is not {}'s", r.issuer));
            }
            bool key_found = false;
            if (const Json* methods = member(doc, "verificationMethod");
                methods != nullptr && methods->is_array()) {
                for (const Json& method : *methods) {
                    const std::string* method_id = text_member(method, "id");
                    const Json* jwk = member(method, "publicKeyJwk");
                    if (method_id == nullptr || *method_id != r.kid || jwk == nullptr) {
                        continue;
                    }
                    const auto key = jwk_key(*jwk);
                    key_found = key && signed_with && *key == *signed_with;
                    break;
                }
            }
            if (!key_found) {
                problems.push_back(
                    "the DID document does not give, under the credential's kid, the key of the "
                    "device that endorsed the record");
            }
            bool ledger_found = false;
            if (const Json* services = member(doc, "service");
                services != nullptr && services->is_array()) {
                for (const Json& service : *services) {
                    const std::string* type = text_member(service, "type");
                    const std::string* ledger = text_member(service, "ledger");
                    if (type != nullptr && *type == "KanheLedger" && ledger != nullptr) {
                        ledger_found = *ledger == hex_id(e.ledger_id);
                        break;
                    }
                }
            }
            if (!ledger_found) {
                problems.push_back(
                    "the DID document does not name this ledger as its Kanhe ledger");
            }
        }
    }

    // Step 7: the status list.
    if (options.status_list) {
        r.status_list_checked = true;
        auto& problems = r.status_list_problems;
        const auto list = parse_jws(*options.status_list);
        if (!list) {
            problems.push_back(std::format("the status list is not a JWS of this profile ({})",
                                           list.error().detail));
        } else {
            bool signature = false;
            if (r.key_actor && signed_with) {
                const auto keys = keys_from(actor_keys(provider, *decoded, e.hash, *r.key_actor),
                                            r.endorsement_index);
                for (const crypto::PublicKey& key : keys) {
                    const auto thumbprint = jwk_thumbprint(provider, key);
                    if (thumbprint && list->kid == r.issuer + "#" + *thumbprint &&
                        verify_jws(provider, *list, key)) {
                        signature = true;
                        break;
                    }
                }
            }
            if (!signature) {
                problems.push_back(
                    "the status list is not signed by the device that endorsed the record");
            }
            const Json& p = list->payload;
            const std::string* id = text_member(p, "id");
            const Json* type = member(p, "type");
            const Json* subject = member(p, "credentialSubject");
            const std::string* encoded =
                subject != nullptr ? text_member(*subject, "encodedList") : nullptr;
            const std::string* purpose =
                subject != nullptr ? text_member(*subject, "statusPurpose") : nullptr;
            const bool typed =
                type != nullptr && type->is_array() &&
                std::ranges::any_of(*type, [](const Json& t) {
                    return t.is_string() && t.get_ref<const std::string&>() == status_list_type;
                });
            if (id == nullptr || *id != r.status_list_url || !typed || encoded == nullptr ||
                purpose == nullptr || *purpose != "revocation") {
                problems.push_back(std::format("the status list is not {}", r.status_list_url));
            } else if (const auto bits = decode_status_list(*encoded); !bits) {
                problems.push_back(
                    std::format("the status list does not decode ({})", bits.error().detail));
            } else {
                const bool bit = status_bit(*bits, r.entry.index);
                r.status_list_bit = bit;
                const bool ledger_says = r.record_status != "live";
                if (bit != ledger_says) {
                    problems.push_back(std::format(
                        "the issuer's status list says {}; its ledger says the record is {}",
                        bit ? "revoked" : "not revoked", r.record_status));
                }
            }
        }
    }
    return r;
}

// ---- reports ------------------------------------------------------------

Json credential_report_json(const CredentialReport& r, bool ledger_checked) {
    Json key = nullptr;
    if (r.key_actor) {
        key = Json{{"id", hex_id(*r.key_actor)},
                   {"name", r.key_actor_name},
                   {"revoked", r.key_actor_revoked},
                   {"endorsement", r.endorsement_index},
                   {"endorsed_at", iso_time(r.endorsed_at)}};
    }
    Json did = nullptr;
    if (r.did_document_checked) {
        did = Json{{"url", r.base.did_document_url}, {"problems", r.did_document_problems}};
    }
    Json list = nullptr;
    if (r.status_list_checked) {
        list = Json{{"url", r.status_list_url},
                    {"revoked", r.status_list_bit ? Json(*r.status_list_bit) : Json(nullptr)},
                    {"problems", r.status_list_problems}};
    }
    return Json{
        {"verified", r.verified()},
        {"kind", "credential"},
        {"credential", Json{{"issuer", r.issuer},
                            {"issuer_name", r.issuer_name},
                            {"name", r.name ? Json(*r.name) : Json(nullptr)},
                            {"valid_from", r.valid_from},
                            {"subject", r.subject},
                            {"status_list", r.status_list_url},
                            {"status_index", r.entry.index},
                            {"evidence", r.evidence_url},
                            {"kid", r.kid}}},
        {"record", Json{{"id", hex_id(r.evidence.record)},
                        {"type", r.evidence.record_type},
                        {"status", r.record_status},
                        {"complete", r.evidence.complete}}},
        {"credential_key", std::move(key)},
        {"problems", r.problems},
        {"did_document", std::move(did)},
        {"status_list", std::move(list)},
        {"evidence", report_json(r.evidence, ledger_checked)},
    };
}

std::string credential_report_text(const CredentialReport& r, bool ledger_checked) {
    std::string out;
    if (r.verified()) {
        out +=
            std::format("VERIFIED: a W3C credential, and the record behind it on {}'s ledger{}\n",
                        r.evidence.organization,
                        r.evidence.complete ? ""
                                            : " (not complete: a later change could be "
                                              "missing)");
    } else {
        out += "NOT VERIFIED\n";
        for (const auto* list : {&r.problems, &r.did_document_problems, &r.status_list_problems}) {
            for (const std::string& problem : *list) {
                out += "  - " + problem + "\n";
            }
        }
    }
    out += std::format("  Credential   {}, issued by {} ({})\n", r.name ? *r.name : "untitled",
                       r.issuer_name, r.issuer);
    out += std::format("  Valid from   {}\n", r.valid_from);
    std::string claims;
    for (const auto& [claim, value] : r.subject.items()) {
        claims += (claims.empty() ? "" : "; ") + claim + ": " + json_text(value);
    }
    out += std::format("  Claims       {}\n", claims);
    std::string status = r.record_status;
    if (r.evidence.superseded_by) {
        status += " by " + short_hex(*r.evidence.superseded_by);
    }
    out += std::format("  Record       {} ({}), {}\n", short_hex(r.evidence.record),
                       r.evidence.record_type, status);
    if (r.key_actor) {
        out += std::format("  Signed by    {} (a device, {}), which endorsed the record as this "
                           "credential on {}{}\n",
                           r.key_actor_name, short_hex(*r.key_actor), format_time(r.endorsed_at),
                           r.key_actor_revoked ? "; the device was revoked since" : "");
    }
    if (r.status_list_checked) {
        out += std::format("  Status list  {} #{}: {}\n", r.status_list_url, r.entry.index,
                           !r.status_list_bit               ? "not read"
                           : *r.status_list_bit             ? "revoked"
                           : r.status_list_problems.empty() ? "not revoked, as the ledger says"
                                                            : "not revoked");
    } else {
        out +=
            std::format("  Status list  {} #{} (not checked)\n", r.status_list_url, r.entry.index);
    }
    if (r.did_document_checked) {
        out +=
            std::format("  DID document {}{}\n", r.base.did_document_url,
                        r.did_document_problems.empty() ? ": names this key and this ledger" : "");
    }
    out += "\nThe record's evidence:\n";
    out += report_text(r.evidence, ledger_checked);
    return out;
}

} // namespace kanhe::verifier
