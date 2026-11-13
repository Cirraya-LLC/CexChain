// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Records as W3C Verifiable Credentials (spec/credentials.md): credential keys
// (devices that endorse records as credentials), issuing a published
// record's credential, the credentials and status lists the ledger shows,
// and verifying a credential against its record's evidence.

#include <algorithm>
#include <filesystem>
#include <print>
#include <string>
#include <vector>

#include <kanhe/client/credentials.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/ledger/ledger.hpp>
#include <kanhe/node/credentials.hpp>
#include <kanhe/node/published.hpp>
#include <kanhe/verifier/credentials.hpp>
#include <kanhe/verifier/jcs.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "requests.hpp"

namespace kanhe::cli {

namespace {

/// The signed statement at a log index of the session's ledger.
Result<protocol::SignedStatement> statement_at(Session& session, std::uint64_t index) {
    const auto bytes = session.ledger().entry(index);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    const auto entry = protocol::decode_log_entry(*bytes);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    return protocol::parse_statement(session.provider(), entry->statement, session.state().hash());
}

verifier::BaseUrl base_url(const Args& args, const Session& session) {
    std::string url = args.get("url").value_or(session.server_url());
    if (url.empty()) {
        throw UsageError{"give --url: the base URL your server is reached at, which credentials "
                         "name (e.g. https://ledger.example.com)"};
    }
    auto base = verifier::parse_base_url(url);
    if (!base) {
        throw UsageError{"--url: " + base.error()};
    }
    return *base;
}

std::string status_text(const protocol::LedgerState& state, const protocol::Id& record) {
    const protocol::RecordState* r = state.record(record);
    return r != nullptr ? std::string(node::record_status(*r)) : "unknown";
}

Json entry_json(const Session& session, const node::CredentialEntry& e) {
    const protocol::LedgerState& s = session.state();
    const protocol::RecordState* r = s.record(e.record);
    return {{"record", id_json(e.record)},
            {"type", r != nullptr ? Json(r->record_type) : Json(nullptr)},
            {"status", status_text(s, e.record)},
            {"list", e.entry.list},
            {"index", e.entry.index},
            {"credential_key", id_json(e.actor)},
            {"credential_key_name", session.actor_name(e.actor)},
            {"endorsement_index", e.index}};
}

/// The actor `key` belongs to, which must be a credential key.
const protocol::ActorState& credential_actor(const Session& session, const crypto::Signer& key) {
    const protocol::ActorState& actor = session.actor_for(key);
    if (!node::is_credential_key(session.state(), actor)) {
        throw CommandError{"\"" + actor.display_name +
                           "\" is not a credential key: a device with an esp256 key whose "
                           "delegations allow endorsements only (credential key add)"};
    }
    return actor;
}

/// GETs an absolute URL; fails on anything but 200.
Bytes fetch(const std::string& url, const Args& args) {
    const std::size_t scheme = url.find("://");
    const std::size_t path =
        scheme == std::string::npos ? std::string::npos : url.find('/', scheme + 3);
    if (path == std::string::npos) {
        throw CommandError{url + " is not a URL with a path"};
    }
    // Never this ledger's API token: the address is the issuer's, anyone's.
    const node::Client client =
        client::client_for(url.substr(0, path), std::nullopt, args.get("ca-file"));
    const auto response = client.request("GET", url.substr(path));
    if (!response) {
        throw CommandError{"fetching " + url + ": " + std::string(response.error().detail)};
    }
    if (response->status != 200) {
        throw CommandError{"fetching " + url + ": HTTP " + std::to_string(response->status)};
    }
    return response->body;
}

std::string text_of(const Bytes& bytes) {
    return {bytes.begin(), bytes.end()};
}

} // namespace

// ---- credential keys -----------------------------------------------------

int cmd_credential_key_add(const Args& args) {
    Session session(args);
    const std::string name = args.positional().front();
    if (args.has("alg")) {
        throw UsageError{"a credential key is esp256 (ECDSA P-256), which wallets accept"};
    }
    NewActorKey key;
    if (const auto out = args.get("key-out")) {
        if (args.has("key")) {
            throw UsageError{"give --key or --key-out, not both"};
        }
        if (std::filesystem::exists(*out)) {
            throw CommandError{*out + " already exists; keys are never overwritten"};
        }
        const auto made = unwrap(crypto::openssl::KeyPair::generate(crypto::SigAlg::esp256),
                                 "generating the key");
        save_key(*out, made, passphrase(args, *out, true));
        key = {made.public_key(), *out};
    } else {
        key = new_actor_key(args, "the credential key's");
        if (key.key.algorithm != crypto::SigAlg::esp256) {
            throw UsageError{"a credential key is esp256 (kanhe key generate --alg esp256), which "
                             "wallets accept"};
        }
    }
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::record_endorse};
    if (const auto types = args.get("types")) {
        auto list = split(*types, ',');
        std::ranges::sort(list);
        list.erase(std::ranges::unique(list).begin(), list.end());
        scope.record_types = std::move(list);
    }
    scope.not_after = validity_end(args);
    const auto signer = load_signer(args.need("as"), args);
    const auto provenance = session.provenance(args);
    const auto presence = presence_request(args);
    const protocol::Id actor =
        session.submit(*signer,
                       protocol::ActorRegisterBody{protocol::ActorKind::device, name, key.key,
                                                   std::nullopt, std::nullopt},
                       args.get("delegation"), provenance, presence);
    protocol::Id delegation;
    try {
        delegation = session.submit(*signer, protocol::DelegationGrantBody{actor, scope},
                                    args.get("delegation"), provenance, presence);
    } catch (const CommandError& e) {
        throw CommandError{"registered \"" + name + "\" as " + hex_id(actor) +
                           ", but its delegation was refused (" + e.message +
                           "): grant one with delegation grant, or revoke the actor"};
    }
    const std::string thumbprint =
        unwrap(verifier::jwk_thumbprint(session.provider(), key.key), "the key's thumbprint");
    if (args.json()) {
        print_json({{"actor", id_json(actor)},
                    {"name", name},
                    {"delegation", id_json(delegation)},
                    {"types", scope.record_types ? Json(*scope.record_types) : Json(nullptr)},
                    {"thumbprint", thumbprint},
                    {"key_file", key.file ? Json(*key.file) : Json(nullptr)}});
        return exit_ok;
    }
    std::println("registered credential key \"{}\" as {} (thumbprint {})", name, hex_id(actor),
                 thumbprint);
    std::println("granted delegation {}: endorse records of {}", hex_id(delegation),
                 scope.record_types ? "types " + args.need("types") : "any type");
    std::println("issue with credential issue TOKEN --as {}; serve its DID document and status "
                 "lists with serve --credential-key {} --credential-url URL",
                 key.file.value_or("KEY"), key.file.value_or("KEY"));
    return exit_ok;
}

int cmd_credential_key_list(const Args& args) {
    Session session(args);
    const protocol::LedgerState& s = session.state();
    const auto entries = node::credential_entries(s);
    Json out = Json::array();
    for (const auto& [id_key, actor] : s.actors()) {
        (void)id_key;
        const bool endorsed = std::ranges::any_of(
            entries, [&](const node::CredentialEntry& e) { return e.actor == actor.id.id(); });
        if (!node::is_credential_key(s, actor) &&
            !(endorsed && actor.kind == protocol::ActorKind::device)) {
            continue;
        }
        const std::size_t issued = static_cast<std::size_t>(std::ranges::count_if(
            entries, [&](const node::CredentialEntry& e) { return e.actor == actor.id.id(); }));
        const auto thumbprint = verifier::jwk_thumbprint(session.provider(), actor.key);
        out.push_back({{"actor", id_json(actor.id.id())},
                       {"name", actor.display_name},
                       {"thumbprint", thumbprint ? Json(*thumbprint) : Json(nullptr)},
                       {"revoked", actor.revoked},
                       {"rotations", actor.rotations.size()},
                       {"credentials", issued}});
    }
    if (args.json()) {
        print_json(out);
        return exit_ok;
    }
    if (out.empty()) {
        std::println("no credential keys (credential key add)");
    }
    for (const Json& k : out) {
        std::println("{}  {}  {} credential(s){}{}", k["actor"].get<std::string>().substr(0, 12),
                     k["name"].get<std::string>(), k["credentials"].get<std::size_t>(),
                     k["revoked"].get<bool>() ? ", revoked" : "",
                     k["thumbprint"].is_string() ? "  " + k["thumbprint"].get<std::string>() : "");
    }
    return exit_ok;
}

int cmd_credential_key_revoke(const Args& args) {
    Session session(args);
    const protocol::Id actor = session.actor_id(args.positional().front());
    const protocol::ActorState* a = session.state().actor(actor);
    if (a == nullptr || a->kind != protocol::ActorKind::device) {
        throw CommandError{"that is not a device of this ledger"};
    }
    const protocol::Id id =
        session.submit(args, protocol::ActorRevokeBody{actor, args.get("reason")});
    return report_submitted(args, session, id, {{"revoked", id_json(actor)}},
                            "revoked credential key " + short_id(actor) +
                                ": its keys leave the DID document, and credentials it signed no "
                                "longer verify with a standard verifier");
}

// ---- credentials ---------------------------------------------------------

int cmd_credential_issue(const Args& args) {
    Session session(args);
    CredentialRequest request;
    request.token = args.positional().front();
    request.base = base_url(args, session);
    request.name = args.get("name");
    if (args.has("metadata")) {
        request.metadata = split(args.need("metadata"), ',');
    }
    request.delegation = args.get("delegation");
    const auto signer = load_signer(args.need("as"), args);
    const IssuedCredential issued = issue_credential(session, *signer, request, log_key(args));
    if (const auto out = args.get("out")) {
        write_file(*out, as_bytes(issued.credential + "\n"), true);
    }
    if (args.json()) {
        print_json(
            {{"credential", issued.credential},
             {"record", id_json(issued.record)},
             {"token", request.token},
             {"issuer", request.base.did},
             {"list", issued.entry.list},
             {"index", issued.entry.index},
             {"endorsement", issued.endorsement ? id_json(*issued.endorsement) : Json(nullptr)},
             {"again", !issued.endorsement.has_value()},
             {"file", args.get("out") ? Json(*args.get("out")) : Json(nullptr)}});
        return exit_ok;
    }
    if (const auto out = args.get("out")) {
        std::println("{} {}'s credential ({} claims, status {}/{}) to {}",
                     issued.endorsement ? "issued" : "signed again", short_id(issued.record),
                     issued.claims, issued.entry.list, issued.entry.index, *out);
    } else {
        std::println("{}", issued.credential);
    }
    return exit_ok;
}

int cmd_credential_list(const Args& args) {
    Session session(args);
    const auto entries = node::credential_entries(session.state());
    const auto type = args.get("type");
    Json out = Json::array();
    for (const node::CredentialEntry& e : entries) {
        const protocol::RecordState* r = session.state().record(e.record);
        if (type && (r == nullptr || r->record_type != *type)) {
            continue;
        }
        out.push_back(entry_json(session, e));
    }
    if (args.json()) {
        print_json(out);
        return exit_ok;
    }
    if (out.empty()) {
        std::println("no credentials issued (credential issue)");
    }
    for (const Json& e : out) {
        std::println("{}  {}  {}/{}  {}  by {}", e["record"].get<std::string>().substr(0, 12),
                     e["type"].is_string() ? e["type"].get<std::string>() : "",
                     e["list"].get<std::uint64_t>(), e["index"].get<std::uint64_t>(),
                     e["status"].get<std::string>(), e["credential_key_name"].get<std::string>());
    }
    return exit_ok;
}

int cmd_credential_show(const Args& args) {
    Session session(args);
    const protocol::Id record = session.record_id(args.positional().front());
    Json out = Json::array();
    for (const node::CredentialEntry& e : node::credential_entries(session.state())) {
        if (e.record == record) {
            out.push_back(entry_json(session, e));
        }
    }
    if (out.empty()) {
        throw CommandError{"no credential was issued for " + short_id(record)};
    }
    if (args.json()) {
        print_json(out.size() == 1 ? out[0] : out);
        return exit_ok;
    }
    for (const Json& e : out) {
        std::println("record       {} ({})", e["record"].get<std::string>(),
                     e["type"].is_string() ? e["type"].get<std::string>() : "");
        std::println("status       {}", e["status"].get<std::string>());
        std::println("status entry list {}, index {}", e["list"].get<std::uint64_t>(),
                     e["index"].get<std::uint64_t>());
        std::println("issued by    {} ({}), log index {}",
                     e["credential_key_name"].get<std::string>(),
                     e["credential_key"].get<std::string>().substr(0, 12),
                     e["endorsement_index"].get<std::uint64_t>());
    }
    return exit_ok;
}

int cmd_credential_revoke(const Args& args) {
    Session session(args);
    const protocol::Id record = session.record_id(args.positional().front());
    const auto entries = node::credential_entries(session.state());
    if (!std::ranges::any_of(entries,
                             [&](const node::CredentialEntry& e) { return e.record == record; })) {
        throw CommandError{"no credential was issued for " + short_id(record) +
                           " (record revoke revokes a record)"};
    }
    const protocol::Id id =
        session.submit(args, protocol::RecordRevokeBody{record, args.get("reason")});
    return report_submitted(args, session, id, {{"revoked", id_json(record)}},
                            "revoked " + short_id(record) +
                                ": its credentials' status lists now say revoked");
}

int cmd_credential_status(const Args& args) {
    Session session(args);
    const protocol::LedgerState& s = session.state();
    const auto entries = node::credential_entries(s);
    const auto lists = node::status_lists(entries);
    std::uint64_t list = lists.empty() ? 1 : lists.back();
    if (!args.positional().empty()) {
        list = parse_number(args.positional().front(), "the list");
    }
    if (!std::ranges::contains(lists, list)) {
        throw CommandError{"no credential names status list " + std::to_string(list)};
    }
    const Bytes bits = node::status_bits(s, entries, list);
    if (const auto out = args.get("out")) {
        if (!args.has("as")) {
            throw UsageError{"--out writes the signed status list: give --as (the credential key) "
                             "and --url"};
        }
        const verifier::BaseUrl base = base_url(args, session);
        const auto signer = load_signer(args.need("as"), args);
        (void)credential_actor(session, *signer);
        const Json payload = verifier::status_list_json(base, s.organization(), list, bits,
                                                        ledger::SystemClock{}.now());
        const std::string jws = unwrap(
            verifier::sign_credential(*signer, session.provider(), base.did, payload), "signing");
        write_file(*out, as_bytes(jws + "\n"), false);
    }
    Json set = Json::array();
    std::size_t used = 0;
    for (const node::CredentialEntry& e : entries) {
        if (e.entry.list != list) {
            continue;
        }
        ++used;
        if (verifier::status_bit(bits, e.entry.index)) {
            set.push_back({{"index", e.entry.index},
                           {"record", id_json(e.record)},
                           {"status", status_text(s, e.record)}});
        }
    }
    if (args.json()) {
        print_json({{"list", list},
                    {"lists", lists},
                    {"entries", used},
                    {"size", verifier::status_list_size},
                    {"revoked", set},
                    {"file", args.get("out") ? Json(*args.get("out")) : Json(nullptr)}});
        return exit_ok;
    }
    std::println("status list {}: {} of {} entries used, {} revoked or replaced", list, used,
                 verifier::status_list_size, set.size());
    for (const Json& e : set) {
        std::println("  #{}  {}  {}", e["index"].get<std::uint64_t>(),
                     e["record"].get<std::string>().substr(0, 12), e["status"].get<std::string>());
    }
    if (const auto out = args.get("out")) {
        std::println("wrote the signed status list to {}", *out);
    }
    return exit_ok;
}

int cmd_credential_did_document(const Args& args) {
    Session session(args);
    const verifier::BaseUrl base = base_url(args, session);
    std::optional<protocol::Id> also;
    if (const auto key = args.get("key")) {
        const crypto::PublicKey public_key = public_key_of(*key, args);
        for (const auto& [id_key, actor] : session.state().actors()) {
            (void)id_key;
            if (actor.key == public_key) {
                also = actor.id.id();
            }
        }
        if (!also) {
            throw CommandError{*key + " is not an actor's current key on this ledger"};
        }
    }
    const auto entries = node::credential_entries(session.state());
    const auto keys =
        unwrap(node::credential_keys(session.state(), entries, also,
                                     [&](std::uint64_t i) { return statement_at(session, i); }),
               "reading the credential keys");
    const Json doc =
        unwrap(verifier::did_document(session.provider(), base, keys, session.state().ledger_id()),
               "the DID document");
    const std::string text = unwrap(verifier::jcs(doc), "the DID document");
    if (const auto out = args.get("out")) {
        write_file(*out, as_bytes(text + "\n"), false);
        if (!args.json()) {
            std::println("wrote {}'s DID document ({} keys) to {}; it goes at {}", base.did,
                         keys.size(), *out, base.did_document_url);
            return exit_ok;
        }
    }
    if (args.json()) {
        print_json(doc);
    } else {
        std::println("{}", doc.dump(2));
    }
    return exit_ok;
}

int cmd_credential_verify(const Args& args) {
    const std::string credential = [&] {
        std::string text = text_of(read_file(args.positional().front()));
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
            text.pop_back();
        }
        return text;
    }();
    const auto addresses = unwrap(verifier::credential_addresses(credential), "the credential");
    const bool offline = args.has("offline");
    verifier::CredentialOptions options;
    if (const auto id = args.get("ledger-id")) {
        options.verify.expected_ledger =
            unwrap(protocol::to_id(unwrap(from_hex(*id), "--ledger-id")), "--ledger-id");
    }
    for (const std::string& path : args.all("witness")) {
        options.verify.trusted_witnesses.push_back(load_public_key(path));
    }
    options.verify.trusted_timestamp_roots = load_certificates(args.all("tsa-root"));
    const bool remote_ok = [&] {
        // An http:// address only when asked: tests and a local server.
        return !addresses.evidence.starts_with("http://") || args.has("allow-http");
    }();
    auto source = [&](std::string_view option, const std::string& url, bool needed) {
        if (const auto file = args.get(option)) {
            return std::optional(text_of(read_file(*file)));
        }
        if (offline || (!needed && args.has("no-fetch"))) {
            return std::optional<std::string>();
        }
        if (!remote_ok) {
            throw UsageError{"the credential names http:// addresses: give --allow-http to fetch "
                             "them (tests and local servers only), or the files"};
        }
        return std::optional(text_of(fetch(url, args)));
    };
    const auto bundle = source("evidence", addresses.evidence, true);
    if (!bundle) {
        throw UsageError{"--offline needs --evidence FILE (the record's evidence)"};
    }
    options.did_document = source("did-document", addresses.did_document, false);
    options.status_list = source("status-list", addresses.status_list, false);
    const auto report = unwrap(
        verifier::verify_credential(shared_provider(), credential, as_bytes(*bundle), options),
        "verifying the credential");
    const bool pinned = options.verify.expected_ledger.has_value();
    if (args.json()) {
        print_json(verifier::credential_report_json(report, pinned));
    } else {
        std::print("{}", verifier::credential_report_text(report, pinned));
        if (!pinned) {
            std::println("\nThe ledger was not pinned: give --ledger-id, learned from the issuer "
                         "out of band, to be sure whose ledger this is.");
        }
    }
    return report.verified() ? exit_ok : exit_not_verified;
}

} // namespace kanhe::cli
