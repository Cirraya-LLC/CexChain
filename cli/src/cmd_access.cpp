// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Working with other organizations (D-046): peers, and access to records
// across ledgers. A requester asks (a request record on its ledger), the
// granter grants (a grant record on its ledger) and delivers the record's
// private data sealed to a key made for that request, and the requester
// acknowledges (a receipt record on its ledger). Each side checks the
// other's step with the offline evidence verifier, pinned to the peer's
// ledger id.

#include <algorithm>
#include <print>

#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/witness.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/tokens.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "peers.hpp"
#include "records.hpp"

namespace cexchain::cli {

node::Peer peer_named(const std::filesystem::path& dir, const std::string& name) {
    for (node::Peer& p : unwrap(node::load_peers(dir), "reading the peers")) {
        if (p.name == name) {
            return p;
        }
    }
    throw CommandError{"no peer named " + name + " (cexchain peer add)"};
}

node::Client peer_client(const node::Peer& peer) {
    if (!peer.url) {
        throw CommandError{"peer " + peer.name + " has no API URL (cexchain peer add --url)"};
    }
    node::ClientOptions options;
    if (peer.token_file) {
        const Bytes token = read_file(*peer.token_file);
        std::string text(token.begin(), token.end());
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
            text.pop_back();
        }
        options.bearer_token = text;
    }
    if (peer.ca_file) {
        options.ca_file = *peer.ca_file;
    }
    return node::Client(unwrap(node::Url::parse(*peer.url), "the peer's URL"), options);
}

namespace {

constexpr std::string_view access_key_info = "CexChain access key v1";
constexpr protocol::Timestamp day_ms = 86'400'000;

std::vector<node::Peer> peers_of(const std::filesystem::path& dir) {
    return unwrap(node::load_peers(dir), "reading the peers");
}

/// The peer whose ledger `bundle` claims to come from. Nothing is verified
/// here: the callers verify the bundle once, pinned to that peer's ledger.
node::Peer peer_for_bundle(const std::filesystem::path& dir, ByteView bundle) {
    const auto ledger = protocol::bundle_ledger_id(bundle);
    if (!ledger) {
        throw CommandError{"the evidence is malformed: " + std::string(ledger.error().detail)};
    }
    for (node::Peer& p : peers_of(dir)) {
        if (p.ledger_id == *ledger) {
            return p;
        }
    }
    throw CommandError{"the evidence comes from ledger " + hex_id(*ledger) +
                       ", which is not a peer (cexchain peer add)"};
}

/// POSTs to the peer's API and returns the JSON answer.
Json post_to(const node::Peer& peer, const std::string& path, ByteView body,
             std::string_view type) {
    const auto response =
        unwrap(peer_client(peer).request("POST", path, body, type), "reaching peer " + peer.name);
    const Json answer = Json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (response.status / 100 != 2) {
        std::string message = "status " + std::to_string(response.status);
        if (answer.is_object() && answer.contains("error")) {
            message = answer["error"].value("message", message);
        }
        throw CommandError{"peer " + peer.name + " refused: " + message};
    }
    return answer;
}

void store(const std::filesystem::path& path, ByteView bytes) {
    std::filesystem::create_directories(path.parent_path());
    write_file(path, bytes, true);
}

std::vector<std::string> names_from(const Args& args, std::string_view option) {
    std::vector<std::string> out;
    for (const std::string& n : split(args.get(option).value_or(""), ',')) {
        if (!n.empty()) {
            out.push_back(n);
        }
    }
    return out;
}

/// Checkpoints (unless the record already is covered) and exports `record`
/// with the named fields disclosed and attachments opened.
Bytes evidence_of(Session& session, const crypto::Signer& log_key, const protocol::Id& record,
                  const std::vector<std::string>& fields,
                  const std::vector<std::string>& attachments, const Args& args) {
    auto bundle =
        unwrap(session.ledger().export_evidence(log_key, record), "exporting the evidence");
    if (!fields.empty() || !attachments.empty()) {
        const Vault vault = read_vault(session, record, args);
        const auto commitment = unwrap(
            protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
            "fields");
        for (const std::string& name : fields) {
            bundle.disclosures.push_back(
                unwrap(protocol::disclose_field(session.provider(), session.state().hash(),
                                                commitment, name),
                       "disclosing " + name));
        }
        for (const VaultAttachment& a : vault.attachments) {
            if (std::ranges::contains(attachments, a.name)) {
                bundle.attachments.push_back({a.name, a.salt});
            }
        }
    }
    return unwrap(protocol::encode_bundle(bundle), "encoding the evidence");
}

/// Issues an access record on this ledger and checkpoints it, so its
/// evidence can be exported at once.
protocol::Id issue_access_record(Session& session, const Args& args, std::string_view type,
                                 cbor::Value metadata, std::string note,
                                 const crypto::Signer& log_key) {
    IssueRequest request;
    request.record_type = std::string(type);
    request.fields.emplace_back("note", std::move(note));
    request.metadata_value = std::move(metadata);
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id id = issue_record(session, *load_signer(args.need("as"), args), request);
    unwrap(session.ledger().checkpoint(log_key), "checkpointing");
    return id;
}

/// The access metadata of one of this ledger's records.
cbor::Value own_metadata(Session& session, const protocol::Id& record) {
    return unwrap(node::record_metadata(session.provider(), session.ledger(), record),
                  "reading the record's metadata");
}

std::string joined(const std::vector<std::string>& names) {
    std::string out;
    for (const std::string& n : names) {
        out += (out.empty() ? "" : ", ") + n;
    }
    return out.empty() ? "none" : out;
}

Json report_parties(const protocol::EvidenceReport& report) {
    Json events = Json::array();
    for (const auto& e : report.events) {
        Json authority = Json::array();
        for (const auto& a : e.authority) {
            authority.push_back(a.name);
        }
        events.push_back(
            {{"actor", e.actor.name},
             {"kind", kind_text(e.actor.kind)},
             {"authority", authority},
             {"presence", e.presence ? (e.presence->method == protocol::PresenceMethod::hardware_key
                                            ? "hardware key"
                                            : "passkey")
                                     : "none"}});
    }
    return {{"organization", report.organization},
            {"ledger_id", id_json(report.ledger_id)},
            {"events", events}};
}

std::string who(const protocol::EvidenceReport& report) {
    if (report.events.empty()) {
        return report.organization;
    }
    const auto& e = report.events.front();
    std::string out =
        e.actor.kind ? e.actor.name + " of " + report.organization : report.organization;
    if (e.presence) {
        out += e.presence->method == protocol::PresenceMethod::hardware_key
                   ? " (present: hardware key)"
                   : " (present: passkey)";
    }
    return out;
}

/// The key a delivery for `request` is sealed to, from the vault.
crypto::openssl::HpkeKey recipient_key(const Session& session, const protocol::Id& request,
                                       const Args& args) {
    const std::filesystem::path path =
        session.directory() / "vault" / "access" / (hex_id(request) + ".cbor");
    if (!std::filesystem::exists(path)) {
        throw CommandError{"no key for request " + short_id(request) +
                           " in this ledger's vault (was it made here?)"};
    }
    const auto value = unwrap(cbor::decode(read_file(path)), "reading the request's key");
    const cbor::Value* enc = value.find(1);
    const cbor::Value* ciphertext = value.find(2);
    if (enc == nullptr || ciphertext == nullptr || enc->as_bytes() == nullptr ||
        ciphertext->as_bytes() == nullptr) {
        throw CommandError{"the request's key file is corrupted"};
    }
    const auto vault_key = load_vault_key(session, args);
    const auto pkcs8 = unwrap(vault_key.open({*enc->as_bytes(), *ciphertext->as_bytes()},
                                             as_bytes(access_key_info), request.bytes()),
                              "opening the request's key");
    return unwrap(crypto::openssl::HpkeKey::from_pkcs8(pkcs8.view()), "the request's key");
}

} // namespace

// ---------------------------------------------------------------------------
// peer
// ---------------------------------------------------------------------------

int cmd_peer_add(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    const std::string name = args.positional().front();
    if (!node::valid_token_name(name)) {
        throw UsageError{"a peer name is 1-64 letters, digits, '.', '_', or '-'"};
    }
    const auto id_bytes = from_hex(args.need("ledger-id"));
    if (!id_bytes || id_bytes->size() != 32) {
        throw UsageError{"--ledger-id must be the peer's full hex ledger id"};
    }
    node::Peer peer;
    peer.name = name;
    peer.ledger_id = unwrap(protocol::to_id(*id_bytes), "ledger id");
    peer.url = args.get("url");
    if (peer.url) {
        unwrap(node::Url::parse(*peer.url), "reading --url");
    }
    if (const auto token = args.get("token-file")) {
        peer.token_file = std::filesystem::absolute(*token).string();
    }
    if (const auto ca = args.get("ca")) {
        peer.ca_file = std::filesystem::absolute(*ca).string();
    }
    if (const auto key = args.get("witness-key")) {
        peer.witness_key = load_public_key(*key);
    }
    peer.added = ledger::SystemClock{}.now();
    Session session(dir);
    if (peer.ledger_id == session.ledger().id()) {
        throw UsageError{"a ledger cannot be its own peer"};
    }
    auto peers = peers_of(dir);
    if (std::ranges::any_of(peers, [&](const node::Peer& p) {
            return p.name == name || p.ledger_id == peer.ledger_id;
        })) {
        throw CommandError{"a peer with this name or ledger exists; remove it first"};
    }
    peers.push_back(peer);
    unwrap(node::save_peers(dir, peers), "saving the peers");
    if (args.json()) {
        print_json({{"name", name}, {"ledger_id", id_json(peer.ledger_id)}});
    } else {
        std::println("added peer {} (ledger {})", name, hex_id(peer.ledger_id));
    }
    return exit_ok;
}

namespace {

Json peer_json(const node::Peer& p) {
    return {{"name", p.name},
            {"ledger_id", id_json(p.ledger_id)},
            {"url", p.url ? Json(*p.url) : Json(nullptr)},
            {"token_file", p.token_file ? Json(*p.token_file) : Json(nullptr)},
            {"ca_file", p.ca_file ? Json(*p.ca_file) : Json(nullptr)},
            {"witness_key", p.witness_key ? public_key_json(*p.witness_key) : Json(nullptr)},
            {"added", format_time(p.added)}};
}

} // namespace

int cmd_peer_list(const Args& args) {
    const auto peers = peers_of(args.ledger());
    if (args.json()) {
        Json list = Json::array();
        for (const auto& p : peers) {
            list.push_back(peer_json(p));
        }
        print_json(list);
        return exit_ok;
    }
    if (peers.empty()) {
        std::println("no peers (cexchain peer add NAME --ledger-id ID)");
    }
    for (const auto& p : peers) {
        std::println("{:<20} {}  {}", p.name, short_id(p.ledger_id), p.url.value_or("(no URL)"));
    }
    return exit_ok;
}

int cmd_peer_show(const Args& args) {
    const node::Peer p = peer_named(args.ledger(), args.positional().front());
    if (args.json()) {
        print_json(peer_json(p));
        return exit_ok;
    }
    std::println("name:         {}", p.name);
    std::println("ledger:       {}", hex_id(p.ledger_id));
    std::println("url:          {}", p.url.value_or("none"));
    std::println("token file:   {}", p.token_file.value_or("none"));
    std::println("witness key:  {}",
                 p.witness_key ? to_hex(p.witness_key->bytes).substr(0, 16) + "..." : "none");
    std::println("added:        {}", format_time(p.added));
    return exit_ok;
}

int cmd_peer_remove(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    auto peers = peers_of(dir);
    const std::string name = args.positional().front();
    if (std::erase_if(peers, [&](const node::Peer& p) { return p.name == name; }) == 0) {
        throw CommandError{"no peer named " + name};
    }
    unwrap(node::save_peers(dir, peers), "saving the peers");
    if (args.json()) {
        print_json({{"removed", name}});
    } else {
        std::println("removed peer {} (what was granted stays on the ledger)", name);
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// access: the requester's side
// ---------------------------------------------------------------------------

int cmd_access_request(const Args& args) {
    Session session(args.ledger());
    session.require_primary();
    const node::Peer peer = peer_named(session.directory(), args.need("peer"));
    const auto log_key = load_signer(args.need("log-key"), args);
    const auto record_bytes = from_hex(args.need("record"));
    if (!record_bytes || record_bytes->size() != 32) {
        throw UsageError{"--record must be the full hex id of the record on the peer's ledger"};
    }
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    protocol::AccessRequest request;
    request.ledger = peer.ledger_id;
    request.record = unwrap(protocol::to_id(*record_bytes), "record id");
    request.purpose = args.need("purpose");
    request.until = now + parse_number(args.get("days").value_or("30"), "days") * day_ms;
    if (args.has("fields")) {
        request.fields = names_from(args, "fields");
    }
    if (args.has("attachments")) {
        request.attachments = names_from(args, "attachments");
    }
    // A fresh key for this request: deliveries are sealed to it, and it is
    // kept sealed to this ledger's vault key.
    auto key = unwrap(crypto::openssl::HpkeKey::generate(), "making the request's key");
    request.recipient = Bytes(key.public_key().begin(), key.public_key().end());
    const cbor::Value metadata =
        unwrap(protocol::encode_access_request(request), "the request's metadata");
    const Bytes vault_public = vault_public_key(session);

    const protocol::Id id = issue_access_record(session, args, protocol::access_request_type,
                                                metadata, request.purpose, *log_key);
    const auto pkcs8 = unwrap(key.to_pkcs8(), "the request's key");
    const auto sealed = unwrap(crypto::openssl::hpke_seal(vault_public, as_bytes(access_key_info),
                                                          id.bytes(), pkcs8.view()),
                               "sealing the request's key");
    store(session.directory() / "vault" / "access" / (hex_id(id) + ".cbor"),
          unwrap(cbor::encode(cbor::Value::map(
                     {{cbor::Value::integer(1), cbor::Value::bytes(sealed.encapsulated_key)},
                      {cbor::Value::integer(2), cbor::Value::bytes(sealed.ciphertext)}})),
                 "encoding the request's key"));
    const Bytes bundle = evidence_of(session, *log_key, id, {}, {}, args);
    store(node::access_path(session.directory(), node::AccessBox::requests, id), bundle);
    if (const auto out = args.get("out")) {
        write_file(*out, bundle, false);
    }
    Json sent = nullptr;
    if (args.has("send")) {
        sent = post_to(peer, "/v1/access/requests", bundle, "application/cbor");
    }
    if (args.json()) {
        print_json({{"request", id_json(id)},
                    {"peer", peer.name},
                    {"record", id_json(request.record)},
                    {"until", format_time(request.until)},
                    {"file", args.get("out") ? Json(*args.get("out")) : Json(nullptr)},
                    {"sent", !sent.is_null()}});
    } else {
        std::println("requested access to {} from {}: request {}", short_id(request.record),
                     peer.name, hex_id(id));
        if (args.has("send")) {
            std::println("sent to {}; once granted: cexchain access fetch --peer {} --request {}",
                         peer.name, peer.name, short_id(id));
        } else if (args.has("out")) {
            std::println("send {} to {}", *args.get("out"), peer.name);
        }
    }
    return exit_ok;
}

int cmd_access_fetch(const Args& args) {
    Session session(args.ledger());
    const node::Peer peer = peer_named(session.directory(), args.need("peer"));
    const protocol::Id request = session.record_id(args.need("request"));
    const auto response =
        unwrap(peer_client(peer).request("GET", "/v1/access/deliveries/" + hex_id(request)),
               "reaching peer " + peer.name);
    if (response.status == 404) {
        throw CommandError{"peer " + peer.name + " has not granted request " + short_id(request) +
                           " (yet)"};
    }
    if (response.status == 410) {
        throw CommandError{"peer " + peer.name + " withdrew its grant for request " +
                           short_id(request) + " (revoked or expired)"};
    }
    if (response.status != 200) {
        throw CommandError{"peer " + peer.name + " answered with status " +
                           std::to_string(response.status)};
    }
    const std::filesystem::path out = args.need("out");
    write_file(out, response.body, false);
    if (args.json()) {
        print_json({{"file", out.string()}, {"bytes", response.body.size()}});
    } else {
        std::println("fetched the delivery for request {} to {}; next: cexchain access accept {}",
                     short_id(request), out.string(), out.string());
    }
    return exit_ok;
}

int cmd_access_accept(const Args& args) {
    Session session(args.ledger());
    session.require_primary();
    const Bytes delivery_bytes = read_file(args.positional().front());
    const auto delivery = unwrap(protocol::decode_delivery(delivery_bytes), "reading the delivery");
    const node::Peer peer = peer_for_bundle(session.directory(), delivery.grant_bundle);

    // Which of our requests it answers, from the grant; then check the grant
    // fully against that request and its key.
    protocol::VerifyOptions pinned;
    pinned.expected_ledger = peer.ledger_id;
    const auto grant_report = unwrap(
        protocol::verify_bundle(shared_provider(), delivery.grant_bundle, pinned), "the grant");
    if (!grant_report.metadata) {
        throw CommandError{"the delivery's grant has no access metadata"};
    }
    const auto claimed = unwrap(protocol::decode_access_grant(*grant_report.metadata), "the grant");
    const protocol::RecordState* ours = session.state().record(claimed.request);
    if (ours == nullptr || ours->record_type != protocol::access_request_type) {
        throw CommandError{"the delivery answers request " + short_id(claimed.request) +
                           ", which this ledger did not make"};
    }
    if (ours->revoked || ours->state != "requested") {
        throw CommandError{"request " + short_id(claimed.request) + " was withdrawn"};
    }
    // The grant is checked against what we asked, from our own ledger.
    const auto request = unwrap(
        protocol::decode_access_request(own_metadata(session, claimed.request)), "our request");
    const auto key = recipient_key(session, claimed.request, args);
    if (!std::ranges::equal(key.public_key(), request.recipient)) {
        throw CommandError{"the key in the vault for request " + short_id(claimed.request) +
                           " is not the request's"};
    }
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    const auto grant =
        protocol::check_access_grant(shared_provider(), delivery.grant_bundle, peer.ledger_id,
                                     session.ledger().id(), claimed.request, request, now);
    if (!grant) {
        std::println("NOT ACCEPTED: {}", grant.error().detail);
        return grant.error().code == Errc::verification_failed ? exit_not_verified : exit_failure;
    }
    const protocol::Id grant_id = grant->report.record;
    const auto opened = key.open({delivery.encapsulated_key, delivery.ciphertext},
                                 as_bytes(protocol::delivery_info), grant_id.bytes());
    if (!opened) {
        std::println("NOT ACCEPTED: the delivery is not sealed to this request's key");
        return exit_not_verified;
    }
    const auto contents =
        unwrap(protocol::decode_delivery_contents(opened->view()), "the delivery's contents");
    const auto record =
        protocol::check_delivered_record(shared_provider(), contents, peer.ledger_id, *grant);
    if (!record) {
        std::println("NOT ACCEPTED: {}", record.error().detail);
        return exit_not_verified;
    }
    // Keep the delivery (still sealed) and, if asked, write out the files.
    store(node::access_path(session.directory(), node::AccessBox::deliveries, grant_id),
          delivery_bytes);
    if (const auto dir = args.get("save-dir")) {
        std::filesystem::create_directories(*dir);
        for (const auto& [name, content] : contents.attachments) {
            if (name.find('/') != std::string::npos || name == ".." || name == ".") {
                throw CommandError{"the delivery names an attachment with a path: " + name};
            }
            write_file(std::filesystem::path(*dir) / name, content, true);
        }
    }

    // Acknowledge on this ledger, and hand the receipt back.
    const auto digest =
        unwrap(shared_provider().digest(crypto::HashAlg::sha256, delivery_bytes), "hashing");
    const protocol::AccessReceipt receipt{peer.ledger_id, grant_id,
                                          Bytes(digest.bytes().begin(), digest.bytes().end())};
    const auto log_key = load_signer(args.need("log-key"), args);
    const protocol::Id receipt_id = issue_access_record(
        session, args, protocol::access_receipt_type,
        unwrap(protocol::encode_access_receipt(receipt), "the receipt's metadata"), "received",
        *log_key);
    const Bytes receipt_bundle = evidence_of(session, *log_key, receipt_id, {}, {}, args);
    if (const auto out = args.get("out")) {
        write_file(*out, receipt_bundle, false);
    }
    if (args.has("send")) {
        post_to(peer, "/v1/access/receipts", receipt_bundle, "application/cbor");
    }

    Json fields = Json::object();
    for (const auto& f : record->disclosed_fields) {
        fields[f.name] = display_value(f.value);
    }
    if (args.json()) {
        Json attachments = Json::array();
        for (const auto& a : record->attachments) {
            attachments.push_back(
                {{"name", a.name}, {"verified", a.status == protocol::AttachmentStatus::verified}});
        }
        print_json({{"accepted", true},
                    {"request", id_json(claimed.request)},
                    {"grant", id_json(grant_id)},
                    {"record", id_json(record->record)},
                    {"record_type", record->record_type},
                    {"state", record->state},
                    {"from", report_parties(grant->report)},
                    {"fields", fields},
                    {"attachments", attachments},
                    {"until", format_time(grant->value.until)},
                    {"receipt", id_json(receipt_id)}});
        return exit_ok;
    }
    std::println("ACCEPTED: {} {} from {}, granted by {} until {} (request {})",
                 record->record_type, short_id(record->record), record->organization,
                 who(grant->report), format_time(grant->value.until), short_id(claimed.request));
    for (const auto& f : record->disclosed_fields) {
        std::println("  {} = {}", f.name, display_value(f.value));
    }
    for (const auto& a : record->attachments) {
        if (a.status == protocol::AttachmentStatus::verified) {
            std::println("  attachment {} ({} bytes): matches the record{}", a.name, a.size,
                         args.has("save-dir") ? ", saved" : "");
        }
    }
    std::println("receipt {} recorded{}", short_id(receipt_id),
                 args.has("send")  ? " and sent"
                 : args.has("out") ? ", written to " + *args.get("out")
                                   : "");
    return exit_ok;
}

// ---------------------------------------------------------------------------
// access: the granter's side
// ---------------------------------------------------------------------------

namespace {

Bytes request_bundle_for(const Session& session, const std::string& text) {
    if (std::filesystem::is_regular_file(text)) {
        return read_file(text);
    }
    const std::filesystem::path inbox = session.directory() / "access" / "inbox";
    if (std::filesystem::is_directory(inbox) && text.size() >= 8) {
        for (const auto& e : std::filesystem::directory_iterator(inbox)) {
            if (e.path().filename().string().starts_with(text)) {
                return read_file(e.path());
            }
        }
    }
    throw CommandError{"no request file or inbox request " + text};
}

} // namespace

int cmd_access_inbox(const Args& args) {
    Session session(args.ledger());
    const std::filesystem::path inbox = session.directory() / "access" / "inbox";
    std::vector<std::filesystem::path> files;
    if (std::filesystem::is_directory(inbox)) {
        for (const auto& e : std::filesystem::directory_iterator(inbox)) {
            files.push_back(e.path());
        }
    }
    std::ranges::sort(files);
    Json list = Json::array();
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    for (const auto& file : files) {
        const Bytes bundle = read_file(file);
        Json item = {{"file", file.string()}};
        try {
            const node::Peer peer = peer_for_bundle(session.directory(), bundle);
            const auto checked = protocol::check_access_request(
                shared_provider(), bundle, peer.ledger_id, session.ledger().id(), now);
            if (!checked) {
                item["error"] = checked.error().detail;
            } else {
                const protocol::Id request = checked->report.record;
                item["request"] = id_json(request);
                item["peer"] = peer.name;
                item["from"] = who(checked->report);
                item["record"] = id_json(checked->value.record);
                item["purpose"] = checked->value.purpose;
                item["until"] = format_time(checked->value.until);
                item["granted"] = std::filesystem::exists(
                    node::access_path(session.directory(), node::AccessBox::outbox, request));
            }
        } catch (const CommandError& e) {
            item["error"] = e.message;
        }
        list.push_back(item);
    }
    if (args.json()) {
        print_json(list);
        return exit_ok;
    }
    if (list.empty()) {
        std::println("no access requests received");
    }
    for (const auto& item : list) {
        if (item.contains("error")) {
            std::println("{}: {}", item["file"].get<std::string>(),
                         item["error"].get<std::string>());
            continue;
        }
        std::println(
            "{}  {} asks for {}: \"{}\" until {}{}",
            item["request"].get<std::string>().substr(0, 12), item["from"].get<std::string>(),
            item["record"].get<std::string>().substr(0, 12), item["purpose"].get<std::string>(),
            item["until"].get<std::string>(), item["granted"].get<bool>() ? "  [granted]" : "");
    }
    return exit_ok;
}

int cmd_access_grant(const Args& args) {
    Session session(args.ledger());
    session.require_primary();
    const Bytes request_bundle = request_bundle_for(session, args.positional().front());
    const node::Peer peer = peer_for_bundle(session.directory(), request_bundle);
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    const auto checked = protocol::check_access_request(shared_provider(), request_bundle,
                                                        peer.ledger_id, session.ledger().id(), now);
    if (!checked) {
        std::println("NOT GRANTED: {}", checked.error().detail);
        return checked.error().code == Errc::verification_failed ? exit_not_verified : exit_failure;
    }
    const protocol::AccessRequest& request = checked->value;
    const protocol::Id request_id = checked->report.record;
    const protocol::RecordState* record = session.state().record(request.record);
    if (record == nullptr || record->revoked) {
        throw CommandError{"the requested record " + short_id(request.record) +
                           " does not exist or was revoked"};
    }

    // What to grant: what was asked, narrowed by --fields and --attachments.
    const Vault vault = read_vault(session, request.record, args);
    auto choose = [&](const std::optional<std::vector<std::string>>& asked,
                      const std::vector<std::string>& available, std::string_view option) {
        const std::string what = option == "fields" ? "field" : "attachment";
        auto require = [&](const std::vector<std::string>& names) {
            for (const std::string& n : names) {
                if (!std::ranges::contains(available, n)) {
                    throw CommandError{"the record has no " + what + " named " + n};
                }
            }
        };
        std::vector<std::string> out = asked.value_or(available);
        require(out);
        if (args.has(option)) {
            const auto limit = names_from(args, option);
            require(limit);
            std::erase_if(out,
                          [&](const std::string& n) { return !std::ranges::contains(limit, n); });
        }
        return out;
    };
    std::vector<std::string> field_names;
    for (const auto& f : vault.fields) {
        field_names.push_back(f.name);
    }
    std::vector<std::string> attachment_names;
    for (const auto& a : vault.attachments) {
        attachment_names.push_back(a.name);
    }
    const auto fields = choose(request.fields, field_names, "fields");
    const auto attachments = choose(request.attachments, attachment_names, "attachments");
    protocol::DeliveryContents contents;
    for (const std::string& item : args.all("attach")) {
        auto [name, path] = split_pair(item, "--attach");
        contents.attachments[name] = read_file(path);
    }
    for (const std::string& name : attachments) {
        if (!contents.attachments.contains(name)) {
            throw CommandError{"attachment " + name +
                               " is granted: give its content with --attach " + name +
                               "=FILE, or leave it out with --attachments"};
        }
    }
    std::erase_if(contents.attachments, [&](const auto& item) {
        return !std::ranges::contains(attachments, item.first);
    });

    protocol::AccessGrant grant;
    grant.ledger = peer.ledger_id;
    grant.request = request_id;
    grant.record = request.record;
    grant.fields = fields;
    grant.attachments = attachments;
    grant.until = std::min(request.until,
                           now + parse_number(args.get("days").value_or("30"), "days") * day_ms);
    grant.recipient = request.recipient;
    const auto log_key = load_signer(args.need("log-key"), args);
    const protocol::Id grant_id =
        issue_access_record(session, args, protocol::access_grant_type,
                            unwrap(protocol::encode_access_grant(grant), "the grant's metadata"),
                            request.purpose, *log_key);

    // The delivery: the grant's evidence, and the record's sealed to the
    // request's key, both at the checkpoint just made. Checked as the
    // recipient will check it.
    const Bytes grant_bundle = evidence_of(session, *log_key, grant_id, {}, {}, args);
    protocol::VerifyOptions own;
    own.expected_ledger = session.ledger().id();
    const protocol::Checked<protocol::AccessGrant> checked_grant{
        unwrap(protocol::verify_bundle(shared_provider(), grant_bundle, own), "the grant"), grant};
    contents.record_bundle =
        evidence_of(session, *log_key, request.record, fields, attachments, args);
    const auto check = protocol::check_delivered_record(shared_provider(), contents,
                                                        session.ledger().id(), checked_grant);
    if (!check) {
        throw CommandError{"the delivery does not check out: " + std::string(check.error().detail)};
    }
    const auto sealed =
        unwrap(crypto::openssl::hpke_seal(
                   request.recipient, as_bytes(protocol::delivery_info), grant_id.bytes(),
                   unwrap(protocol::encode_delivery_contents(contents), "contents")),
               "sealing the delivery");
    const Bytes delivery = unwrap(
        protocol::encode_delivery({grant_bundle, sealed.encapsulated_key, sealed.ciphertext}),
        "encoding the delivery");
    store(node::access_path(session.directory(), node::AccessBox::outbox, request_id), delivery);
    if (const auto out = args.get("out")) {
        write_file(*out, delivery, false);
    }
    if (args.json()) {
        print_json({{"grant", id_json(grant_id)},
                    {"request", id_json(request_id)},
                    {"peer", peer.name},
                    {"record", id_json(grant.record)},
                    {"fields", fields},
                    {"attachments", attachments},
                    {"until", format_time(grant.until)},
                    {"file", args.get("out") ? Json(*args.get("out")) : Json(nullptr)}});
    } else {
        std::println("granted {} access to {} until {}: grant {}", peer.name,
                     short_id(grant.record), format_time(grant.until), hex_id(grant_id));
        std::println("fields: {}; attachments: {}", joined(fields), joined(attachments));
        std::println("{} can fetch it from this ledger's API{}", peer.name,
                     args.has("out") ? ", or use " + *args.get("out") : "");
    }
    return exit_ok;
}

int cmd_access_receipt(const Args& args) {
    Session session(args.ledger());
    const Bytes bundle = read_file(args.positional().front());
    const node::Peer peer = peer_for_bundle(session.directory(), bundle);
    protocol::VerifyOptions pinned;
    pinned.expected_ledger = peer.ledger_id;
    const auto report =
        unwrap(protocol::verify_bundle(shared_provider(), bundle, pinned), "the receipt");
    if (!report.metadata) {
        throw CommandError{"not an access receipt"};
    }
    const auto claimed = unwrap(protocol::decode_access_receipt(*report.metadata), "the receipt");
    const auto grant =
        unwrap(protocol::decode_access_grant(own_metadata(session, claimed.grant)), "the grant");
    const auto delivery =
        unwrap(node::delivery_for_grant(session.directory(), grant.request, claimed.grant),
               "the delivery");
    const auto digest =
        unwrap(shared_provider().digest(crypto::HashAlg::sha256, delivery), "hashing");
    const auto checked =
        protocol::check_access_receipt(shared_provider(), bundle, peer.ledger_id,
                                       session.ledger().id(), claimed.grant, grant, digest.bytes());
    if (!checked) {
        std::println("NOT ACCEPTED: {}", checked.error().detail);
        return checked.error().code == Errc::verification_failed ? exit_not_verified : exit_failure;
    }
    unwrap(node::store_receipt(session.directory(), claimed.grant, bundle), "storing the receipt");
    if (args.json()) {
        print_json({{"grant", id_json(claimed.grant)},
                    {"peer", peer.name},
                    {"by", who(checked->report)},
                    {"received_at", format_time(checked->report.events.front().registered_at)}});
    } else {
        std::println("receipt for grant {}: {} acknowledged the delivery at {}",
                     short_id(claimed.grant), who(checked->report),
                     format_time(checked->report.events.front().registered_at));
    }
    return exit_ok;
}

int cmd_access_list(const Args& args) {
    Session session(args.ledger());
    Json list = Json::array();
    const auto peers = peers_of(session.directory());
    auto peer_name = [&](const protocol::Id& ledger) -> std::string {
        for (const auto& p : peers) {
            if (p.ledger_id == ledger) {
                return p.name;
            }
        }
        return short_id(ledger);
    };
    for (const auto& [key, record] : session.state().records()) {
        const bool is_request = record.record_type == protocol::access_request_type;
        const bool is_grant = record.record_type == protocol::access_grant_type;
        const bool is_receipt = record.record_type == protocol::access_receipt_type;
        if (!is_request && !is_grant && !is_receipt) {
            continue;
        }
        const auto metadata =
            node::record_metadata(session.provider(), session.ledger(), record.id);
        if (!metadata) {
            continue;
        }
        Json item = {{"id", id_json(record.id)},
                     {"state", record.revoked ? "revoked" : record.state}};
        if (is_request) {
            const auto r = protocol::decode_access_request(*metadata);
            if (!r) {
                continue;
            }
            item["kind"] = "request";
            item["peer"] = peer_name(r->ledger);
            item["record"] = id_json(r->record);
            item["until"] = format_time(r->until);
            item["purpose"] = r->purpose;
        } else if (is_grant) {
            const auto g = protocol::decode_access_grant(*metadata);
            if (!g) {
                continue;
            }
            item["kind"] = "grant";
            item["peer"] = peer_name(g->ledger);
            item["request"] = id_json(g->request);
            item["record"] = id_json(g->record);
            item["until"] = format_time(g->until);
            item["fields"] = g->fields;
            item["attachments"] = g->attachments;
            item["acknowledged"] = std::filesystem::exists(
                node::access_path(session.directory(), node::AccessBox::receipts, record.id));
        } else {
            const auto r = protocol::decode_access_receipt(*metadata);
            if (!r) {
                continue;
            }
            item["kind"] = "receipt";
            item["peer"] = peer_name(r->ledger);
            item["grant"] = id_json(r->grant);
        }
        list.push_back(item);
    }
    if (args.json()) {
        print_json(list);
        return exit_ok;
    }
    if (list.empty()) {
        std::println("no access requests, grants, or receipts on this ledger");
    }
    for (const auto& item : list) {
        const std::string kind = item["kind"];
        std::string detail;
        if (kind == "receipt") {
            detail = "for grant " + item["grant"].get<std::string>().substr(0, 12);
        } else {
            detail = "record " + item["record"].get<std::string>().substr(0, 12) + " until " +
                     item["until"].get<std::string>();
            if (kind == "grant" && item["acknowledged"].get<bool>()) {
                detail += ", acknowledged";
            }
        }
        std::println("{}  {:<8} {:<10} {:<10} {}", item["id"].get<std::string>().substr(0, 12),
                     kind, item["peer"].get<std::string>(), item["state"].get<std::string>(),
                     detail);
    }
    return exit_ok;
}

int cmd_access_send_request(const Args& args) {
    Session session(args.ledger());
    const node::Peer peer = peer_named(session.directory(), args.need("peer"));
    const protocol::Id request = session.record_id(args.positional().front());
    const Bytes bundle =
        read_file(node::access_path(session.directory(), node::AccessBox::requests, request));
    const Json answer = post_to(peer, "/v1/access/requests", bundle, "application/cbor");
    if (args.json()) {
        print_json(answer);
    } else {
        std::println("sent request {} to {}", short_id(request), peer.name);
    }
    return exit_ok;
}

} // namespace cexchain::cli
