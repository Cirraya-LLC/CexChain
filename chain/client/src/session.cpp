// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <variant>

#include <nlohmann/json.hpp>

#include <cexchain/app/session.hpp>
#include <cexchain/app/views.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/cluster.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/replica.hpp>

namespace cexchain::app {

namespace {

constexpr std::size_t min_prefix = 8;

template <class Map>
protocol::Id resolve(const Map& map, std::string_view text, std::string_view what) {
    std::string lower(text);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return std::tolower(c); });
    if (lower.size() < min_prefix) {
        throw UsageError{std::string(what) + " id must have at least 8 hex digits"};
    }
    std::optional<protocol::Id> found;
    for (const auto& [key, value] : map) {
        if (hex_id(value.id).starts_with(lower)) {
            if (found) {
                throw UsageError{"ambiguous " + std::string(what) + " id " + std::string(text)};
            }
            found = value.id;
        }
    }
    if (!found) {
        throw ActionError{"no " + std::string(what) + " with id " + std::string(text)};
    }
    return *found;
}

std::optional<std::string> record_type_for(const protocol::LedgerState& state,
                                           const protocol::Body& body) {
    return std::visit(
        [&](const auto& b) -> std::optional<std::string> {
            using T = std::decay_t<decltype(b)>;
            if constexpr (std::is_same_v<T, protocol::RecordRegisterBody>) {
                return b.record_type;
            } else if constexpr (std::is_same_v<T, protocol::RecordEndorseBody> ||
                                 std::is_same_v<T, protocol::RecordTransitionBody> ||
                                 std::is_same_v<T, protocol::RecordRevokeBody>) {
                const protocol::RecordState* r = state.record(b.record);
                return r == nullptr ? std::nullopt : std::optional(r->record_type);
            } else {
                return std::nullopt;
            }
        },
        body);
}

/// The contract a call or retire acts on, if any (scope key 7).
std::optional<protocol::Id> contract_for(const protocol::LedgerState& state,
                                         const protocol::Body& body) {
    if (const auto* call = std::get_if<protocol::ContractCallBody>(&body)) {
        if (call->contract) {
            return *call->contract;
        }
        const protocol::InstanceState* instance =
            call->instance ? state.instance(*call->instance) : nullptr;
        return instance == nullptr ? std::nullopt : std::optional<protocol::Id>(instance->contract);
    }
    if (const auto* retire = std::get_if<protocol::ContractRetireBody>(&body)) {
        return retire->contract;
    }
    return std::nullopt;
}

/// Where the mirrors live: the location's cache, else $XDG_CACHE_HOME/cexchain
/// or ~/.cache/cexchain.
std::filesystem::path cache_root(const ServerLocation& server) {
    if (server.cache) {
        return *server.cache;
    }
    if (const char* xdg = std::getenv("XDG_CACHE_HOME"); xdg != nullptr && *xdg != '\0') {
        return std::filesystem::path(xdg) / "cexchain";
    }
    if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
        return std::filesystem::path(home) / ".cache" / "cexchain";
    }
    throw UsageError{"no cache directory for the server's mirror: pass --cache DIR"};
}

protocol::Id parse_ledger_id(std::string_view text, std::string_view what) {
    const auto bytes = from_hex(text);
    if (!bytes || bytes->size() != protocol::id_size) {
        throw UsageError{std::string(what) + " must be a full hex ledger id"};
    }
    return unwrap(protocol::to_id(*bytes), "ledger id");
}

/// The message of an API error answer.
std::string error_message(const node::http::ClientResponse& response) {
    const auto answer =
        nlohmann::json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (answer.is_object() && answer.contains("error") && answer["error"].is_object()) {
        return answer["error"].value("message", std::string()) + " (HTTP " +
               std::to_string(response.status) + ")";
    }
    return "HTTP " + std::to_string(response.status);
}

} // namespace

Session::Session(const Location& location) {
    if (const auto* server = std::get_if<ServerLocation>(&location)) {
        open_remote(*server);
    } else {
        open(std::get<std::filesystem::path>(location));
    }
}

void Session::open(const std::filesystem::path& directory) {
    directory_ = directory;
    if (!std::filesystem::is_directory(directory)) {
        throw ActionError{"no ledger directory at " + directory.string()};
    }
    lock_.emplace(unwrap(ledger::DirectoryLock::acquire(directory), "locking the ledger"));
    recover_vault_swap(directory);
    fs_.emplace(unwrap(ledger::PosixFileSystem::open_directory(directory), "opening the ledger"));
    ledger_.emplace(unwrap(ledger::Ledger::open(*fs_, clock_, provider_), "opening the ledger"));
}

void Session::open_remote(const ServerLocation& server) {
    const std::optional<std::string>& ca = server.ca_file;
    remote_.emplace(Remote{client_for(server.url, server.token, ca), {}, false});
    const node::Client& client = remote_->client;
    remote_->url = client.base().to_string();
    const auto status = unwrap(node::primary_status(client), "reaching " + remote_->url);
    const protocol::Id served = parse_ledger_id(status.ledger_id, "the server's ledger id");
    std::optional<protocol::Id> expected;
    if (const auto& text = server.ledger_id) {
        expected = parse_ledger_id(*text, "--ledger-id");
    }

    // The ledger each URL serves is pinned on first use; the mirror of each
    // ledger is shared by every URL that serves it.
    const std::filesystem::path root = cache_root(server);
    std::filesystem::create_directories(root);
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    {
        const auto cache_lock =
            unwrap(ledger::DirectoryLock::acquire(root), "locking the cache " + root.string());
        const std::filesystem::path pins_file = root / "servers.json";
        nlohmann::json pins = nlohmann::json::object();
        if (std::filesystem::exists(pins_file)) {
            const Bytes bytes = read_file(pins_file);
            pins = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
            if (!pins.is_object()) {
                throw ActionError{pins_file.string() + " is corrupted"};
            }
        }
        if (pins.contains(remote_->url)) {
            if (pins[remote_->url] != hex_id(served)) {
                throw ActionError{"the server at " + remote_->url + " now serves ledger " +
                                  hex_id(served) + ", not " +
                                  pins[remote_->url].get<std::string>() +
                                  " as before: refused (if the change is genuine, remove its "
                                  "line from " +
                                  pins_file.string() + ")"};
            }
        } else if (!expected && !client.base().tls) {
            throw UsageError{"the first use of an http:// server needs --ledger-id, to pin the "
                             "ledger it serves (its operator tells you the id)"};
        }
        if (expected && *expected != served) {
            throw ActionError{"the server at " + remote_->url + " serves ledger " + hex_id(served) +
                              ", not the one expected"};
        }
        directory_ = root / hex_id(served);
        if (!std::filesystem::exists(directory_ / "statements")) {
            std::filesystem::create_directories(directory_);
            std::filesystem::permissions(directory_, std::filesystem::perms::owner_all,
                                         std::filesystem::perm_options::replace);
            auto created = [&]() -> Status {
                const auto lock = ledger::DirectoryLock::acquire(directory_);
                if (!lock) {
                    return std::unexpected(lock.error());
                }
                auto fs = ledger::PosixFileSystem::open_directory(directory_);
                if (!fs) {
                    return std::unexpected(fs.error());
                }
                if (auto mirror = node::create_replica(client, *fs, clock_, provider_, served);
                    !mirror) {
                    return std::unexpected(mirror.error());
                }
                return node::write_replica_info(directory_,
                                                {remote_->url, ca, clock_.now(), std::nullopt});
            }();
            if (!created) {
                std::filesystem::remove_all(directory_);
                unwrap(created, "starting a mirror of " + remote_->url);
            }
        }
        pins[remote_->url] = hex_id(served);
        const std::string text = pins.dump(2) + "\n";
        write_file(pins_file, as_bytes(text), true);
    }
    lock_.emplace(unwrap(ledger::DirectoryLock::acquire(directory_), "locking the mirror"));
    fs_.emplace(unwrap(ledger::PosixFileSystem::open_directory(directory_), "opening the mirror"));
    ledger_.emplace(unwrap(ledger::Ledger::open(*fs_, clock_, provider_), "opening the mirror"));
    sync();
}

void Session::sync() {
    const auto report = node::sync_replica(remote_->client, *ledger_, directory_, {},
                                           node::SyncOptions{.tail = true, .vault = false});
    if (!report) {
        const Error& e = report.error();
        if (e.code == Errc::verification_failed) {
            throw ActionError{"the server at " + remote_->url + " does not show the history " +
                              "this client verified before: " + std::string(e.detail) +
                              " (the mirror is " + directory_.string() + ")"};
        }
        throw ActionError{"syncing with " + remote_->url + ": " + std::string(e.detail) + " (" +
                          std::string(to_string(e.code)) + ")"};
    }
}

bool Session::has_checkpoint(ByteView encoded) const {
    const auto parsed = protocol::parse_checkpoint(encoded);
    if (!parsed) {
        return false;
    }
    const auto stored = ledger_->checkpoints_of_size(parsed->checkpoint.tree_size);
    return stored && std::ranges::any_of(*stored, [&](const protocol::SignedCheckpoint& c) {
               return std::ranges::equal(c.encoded, encoded);
           });
}

bool Session::sync_until(const std::function<bool()>& done) {
    for (int attempt = 0; attempt < 100; ++attempt) {
        sync();
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

Bytes Session::call(std::string_view method, std::string_view path, ByteView body,
                    std::string_view content_type) const {
    const auto response = unwrap(remote_->client.request(method, path, body, content_type),
                                 "reaching " + remote_->url);
    if (response.status < 200 || response.status > 299) {
        throw ActionError{"the server at " + remote_->url + " refused: " + error_message(response)};
    }
    return response.body;
}

Bytes Session::request(std::string_view method, std::string_view path, ByteView body,
                       std::string_view content_type) const {
    if (!remote_) {
        throw UsageError{"this needs a server: give --server URL"};
    }
    return call(method, path, body, content_type);
}

protocol::Id Session::actor_id(std::string_view text) const {
    return resolve(state().actors(), text, "actor");
}

protocol::Id Session::record_id(std::string_view text) const {
    return resolve(state().records(), text, "record");
}

protocol::Id Session::delegation_id(std::string_view text) const {
    return resolve(state().delegations(), text, "delegation");
}

protocol::Id Session::contract_id(std::string_view text) const {
    return resolve(state().contracts(), text, "contract");
}

protocol::Id Session::instance_id(std::string_view text) const {
    return resolve(state().instances(), text, "instance");
}

protocol::Id Session::request_id(std::string_view text) const {
    return resolve(state().requests(), text, "request");
}

const protocol::ActorState& Session::actor_for(const crypto::Signer& key) const {
    const auto kid =
        unwrap(protocol::key_id(provider_, state().hash(), key.public_key()), "key id");
    for (const auto& [id, actor] : state().actors()) {
        if (actor.kid == kid) {
            if (actor.revoked) {
                throw ActionError{"the actor holding this key has been revoked"};
            }
            return actor;
        }
    }
    throw ActionError{"this key does not belong to any actor of the ledger"};
}

std::optional<protocol::Id> Session::choose_delegation(const protocol::ActorState& actor,
                                                       const protocol::Body& body) const {
    return node::choose_delegation(state(), actor.id, protocol::type_of(body),
                                   record_type_for(state(), body), ledger::SystemClock{}.now(),
                                   contract_for(state(), body),
                                   std::get_if<protocol::ContractCallBody>(&body));
}

protocol::Id Session::submit(const crypto::Signer& signer, protocol::Body body,
                             const std::optional<std::string>& delegation,
                             std::optional<protocol::Provenance> provenance,
                             const std::optional<PresenceRequest>& presence,
                             const SealVault& seal_vault, std::span<const Bytes> consents,
                             const SealFiles& seal_files) {
    const protocol::SignedStatement signed_statement =
        sign(signer, std::move(body), delegation, std::move(provenance), presence);
    std::optional<Bytes> sealed;
    if (seal_vault) {
        sealed = seal_vault(signed_statement.id);
    }
    std::vector<node::SealedFile> files;
    if (seal_files) {
        files = seal_files(signed_statement.id);
    }
    return submit_signed(signed_statement, sealed, consents, files);
}

protocol::SignedStatement Session::sign(const crypto::Signer& signer, protocol::Body body,
                                        const std::optional<std::string>& delegation,
                                        std::optional<protocol::Provenance> provenance,
                                        const std::optional<PresenceRequest>& presence) {
    const protocol::ActorState& actor = actor_for(signer);
    protocol::Statement statement;
    statement.ledger_id = state().ledger_id();
    statement.actor_id = actor.id;
    statement.issued_at = clock_.now();
    statement.nonce = entropy_.bytes<16>();
    if (!actor.is_organization()) {
        // Own key rotations, and own passkey changes proven with a passkey,
        // need no delegation.
        const bool self_rotation = std::holds_alternative<protocol::ActorRotateKeyBody>(body) &&
                                   std::get<protocol::ActorRotateKeyBody>(body).actor == actor.id;
        const bool self_presence = presence &&
                                   std::holds_alternative<protocol::ActorSetPresenceBody>(body) &&
                                   std::get<protocol::ActorSetPresenceBody>(body).actor == actor.id;
        if (delegation) {
            statement.delegation_id = delegation_id(*delegation);
        } else if (!self_rotation && !self_presence) {
            statement.delegation_id = choose_delegation(actor, body);
            if (!statement.delegation_id) {
                throw ActionError{"no valid delegation lets " + actor.display_name + " do this"};
            }
        }
    }
    if (actor.kind == protocol::ActorKind::agent) {
        if (!provenance) {
            provenance = protocol::Provenance{};
        }
        if (!provenance->model && actor.agent) {
            provenance->model = actor.agent->model;
            provenance->model_version = actor.agent->model_version;
        }
        if (provenance->tools.empty()) {
            const std::string tool = std::string("cexchain-cli/") + CEXCHAIN_VERSION;
            provenance->tools.push_back(
                {"cli:cexchain", hash_text(provider_, crypto::HashAlg::sha256, tool)});
        }
    }
    statement.provenance = std::move(provenance);
    statement.body = std::move(body);
    if (!remote_) {
        require_primary();
    }
    if (presence) {
        prove_presence(actor, statement, signer.public_key(), *presence);
    }
    return unwrap(protocol::sign_statement(signer, provider_, state().hash(), statement),
                  "signing");
}

protocol::Id Session::submit_signed(const protocol::SignedStatement& signed_statement,
                                    const std::optional<Bytes>& sealed,
                                    std::span<const Bytes> consents,
                                    std::span<const node::SealedFile> files) {
    if (remote_) {
        // Signed here; the server registers it, with its private data if
        // any, and the mirror shows it once it re-validated it.
        if (!consents.empty()) {
            cbor::Array list;
            for (const Bytes& c : consents) {
                list.push_back(cbor::Value::bytes(c));
            }
            const Bytes submission =
                unwrap(cbor::encode(cbor::Value::map(
                           {{cbor::Value::integer(1), cbor::Value::bytes(signed_statement.encoded)},
                            {cbor::Value::integer(3), cbor::Value::array(std::move(list))}})),
                       "encoding the submission");
            static_cast<void>(
                call("POST", "/v1/statements", submission, node::submission_content_type));
        } else if (sealed) {
            cbor::Map map{{cbor::Value::integer(1), cbor::Value::bytes(signed_statement.encoded)},
                          {cbor::Value::integer(2), cbor::Value::bytes(*sealed)}};
            if (!files.empty()) {
                map.push_back({cbor::Value::integer(4), node::encode_sealed_files(files)});
            }
            const Bytes submission =
                unwrap(cbor::encode(cbor::Value::map(std::move(map))), "encoding the submission");
            static_cast<void>(
                call("POST", "/v1/statements", submission, node::submission_content_type));
        } else {
            static_cast<void>(
                call("POST", "/v1/statements", signed_statement.encoded, "application/cose"));
        }
        if (!sync_until([&] { return state().statement_index(signed_statement.id).has_value(); })) {
            throw ActionError{"the server accepted the statement but does not show it"};
        }
        return signed_statement.id;
    }
    require_primary();
    if (!consents.empty()) {
        // Kept first: a registered call always has its consents here.
        const Bytes encoded = unwrap(node::encode_consent_bundles(consents), "the consents");
        unwrap(node::store_consents_file(
                   node::contract_consents_path(directory_, signed_statement.id), encoded),
               "keeping the consents");
    }
    const auto registration =
        unwrap(ledger_->submit(signed_statement.encoded), "the ledger refused the statement");
    if (sealed) {
        std::filesystem::create_directories(vault_path(registration.statement_id).parent_path());
        write_file(vault_path(registration.statement_id), *sealed, true);
    }
    for (const node::SealedFile& file : files) {
        unwrap(node::store_record_file(directory_, registration.statement_id, file),
               "keeping the record's files");
    }
    return registration.statement_id;
}

void Session::prove_presence(const protocol::ActorState& actor, protocol::Statement& statement,
                             const crypto::PublicKey& signing_key,
                             const PresenceRequest& request) const {
    if (actor.kind != protocol::ActorKind::person) {
        throw UsageError{"only people prove presence; \"" + actor.display_name + "\" is " +
                         (actor.is_organization() ? std::string("the organization")
                                                  : "an " + kind_label(actor.kind))};
    }
    if (actor.presence.empty()) {
        throw ActionError{"\"" + actor.display_name +
                          "\" has no passkey registered (cexchain presence enroll, then cexchain "
                          "actor set-presence)"};
    }
    const auto kid =
        unwrap(protocol::key_id(provider_, state().hash(), signing_key), "computing the key id");
    const auto challenge =
        unwrap(protocol::presence_challenge(provider_, state().hash(), statement, kid),
               "computing the challenge");
    if (request.hardware_key) {
        // A second key, not the signing key itself: else whoever holds the
        // signing key "proves" presence too.
        if (request.hardware_key->public_key() == signing_key) {
            throw UsageError{"the presence key must not be the signing key (--as)"};
        }
        // The token signs the challenge; it must be one registered for the person.
        const auto credential =
            std::ranges::find_if(actor.presence, [&](const protocol::PresenceCredential& c) {
                return c.method == protocol::PresenceMethod::hardware_key &&
                       c.key == request.hardware_key->public_key();
            });
        if (credential == actor.presence.end()) {
            throw ActionError{
                "this hardware key is not registered for \"" + actor.display_name +
                "\" (cexchain presence enroll --pkcs11, then cexchain actor set-presence)"};
        }
        statement.presence = protocol::PresenceProof{
            credential->credential_id,
            {},
            {},
            unwrap(request.hardware_key->sign(challenge), "signing on the token")};
        unwrap(protocol::verify_presence(provider_, state().hash(), statement, kid, actor.presence),
               "checking the hardware key's proof");
        return;
    }
    const auto passkey = std::ranges::find(actor.presence, protocol::PresenceMethod::webauthn,
                                           &protocol::PresenceCredential::method);
    if (passkey == actor.presence.end()) {
        throw ActionError{"\"" + actor.display_name +
                          "\" has only hardware keys; prove presence with --presence-key"};
    }
    PasskeyRequest ceremony{passkey->rp_id,
                            challenge,
                            {},
                            "Confirm as " + actor.display_name,
                            "On the ledger of \"" + state().organization() + "\":\n" +
                                body_summary(*this, statement.body, std::nullopt)};
    for (const protocol::PresenceCredential& c : actor.presence) {
        if (c.method == protocol::PresenceMethod::webauthn && c.rp_id == ceremony.rp_id) {
            ceremony.allow.push_back(c.credential_id);
        }
    }
    if (!request.passkey) {
        throw ActionError{"no way to ask \"" + actor.display_name + "\" for a passkey here"};
    }
    PasskeyAssertion assertion = request.passkey(ceremony);
    statement.presence = protocol::PresenceProof{
        std::move(assertion.credential_id), std::move(assertion.authenticator_data),
        std::move(assertion.client_data_json), std::move(assertion.signature)};
    unwrap(protocol::verify_presence(provider_, state().hash(), statement, kid, actor.presence),
           "checking the passkey response");
}

std::uint64_t Session::entry_index(std::string_view text) const {
    if (text.size() < min_prefix &&
        std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; })) {
        const std::uint64_t index = parse_number(text, "index");
        if (index >= ledger_->size()) {
            throw ActionError{"no log entry " + std::string(text)};
        }
        return index;
    }
    std::string lower(text);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return std::tolower(c); });
    if (lower.size() < min_prefix) {
        throw UsageError{"give a log index or at least 8 hex digits of a statement id"};
    }
    std::optional<std::uint64_t> found;
    for (std::uint64_t i = 0; i < ledger_->size(); ++i) {
        if (hex_id(log_entry(i).statement_id).starts_with(lower)) {
            if (found) {
                throw UsageError{"ambiguous statement id " + std::string(text)};
            }
            found = i;
        }
    }
    if (!found) {
        throw ActionError{"no statement with id " + std::string(text)};
    }
    return *found;
}

protocol::LogEntry Session::log_entry(std::uint64_t index) const {
    return unwrap(protocol::decode_log_entry(unwrap(ledger_->entry(index), "reading the log")),
                  "decoding log entry " + std::to_string(index));
}

protocol::SignedStatement Session::statement(std::uint64_t index) const {
    return unwrap(protocol::parse_statement(provider_, log_entry(index).statement, state().hash()),
                  "parsing statement " + std::to_string(index));
}

protocol::SignedStateCommitment Session::state_commitment(std::uint64_t index) const {
    return unwrap(protocol::parse_state_commitment(provider_, log_entry(index).state_commitment),
                  "parsing state commitment " + std::to_string(index));
}

std::string Session::actor_name(const protocol::Id& id) const {
    const protocol::ActorState* actor = state().actor(id);
    return actor == nullptr ? "unknown" : actor->display_name;
}

void Session::require_primary() const {
    if (remote_) {
        throw ActionError{"this works on the ledger's directory only: run it where the ledger "
                          "is, without --server"};
    }
    if (node::is_cluster_member(directory_)) {
        throw ActionError{"this ledger is a cluster member: write through the cluster (--server "
                          "a member's API)"};
    }
    if (std::filesystem::exists(directory_ / node::replica_file)) {
        throw ActionError{"this ledger is a replica: write to its primary, or promote it first "
                          "(cexchain replica promote)"};
    }
}

std::filesystem::path Session::vault_path(const protocol::Id& record) const {
    return directory_ / "vault" / "records" / (hex_id(record) + ".cbor");
}

protocol::SignedCheckpoint Session::checkpoint(const LogKey& log_key) {
    if (!remote_) {
        require_primary();
        const auto key = log_key.load();
        return unwrap(ledger_->checkpoint(*key), "checkpointing");
    }
    if (log_key.given) {
        throw UsageError{"with --server the server signs: drop --log-key"};
    }
    const Bytes encoded = call("POST", "/v1/checkpoint");
    // The server's word counts once the mirror took it, checked.
    const auto checkpoint = unwrap(protocol::parse_checkpoint(encoded), "reading the checkpoint");
    if (!sync_until([&] { return has_checkpoint(encoded); })) {
        throw ActionError{"the server's checkpoint is not in the history this client verified"};
    }
    return checkpoint;
}

protocol::EvidenceBundle Session::evidence(const LogKey& log_key, const protocol::Id& record) {
    if (!remote_) {
        const auto key = log_key.load();
        return unwrap(ledger_->export_evidence(*key, record), "exporting evidence");
    }
    if (log_key.given) {
        throw UsageError{"with --server the server signs: drop --log-key"};
    }
    const Bytes encoded = call("GET", "/v1/evidence/" + hex_id(record));
    // Verified here, against the ledger and the checkpoints this client
    // verified, before anything is built on it.
    protocol::VerifyOptions options;
    options.expected_ledger = state().ledger_id();
    const auto report = ledger::verify_bundle(provider_, encoded, options, on_all_cores());
    if (!report || report->record != record) {
        throw ActionError{"the server sent evidence that does not verify"};
    }
    auto bundle = unwrap(protocol::decode_bundle(encoded), "reading the evidence");
    if (!sync_until([&] { return has_checkpoint(bundle.checkpoint); })) {
        throw ActionError{"the server's evidence is anchored to a checkpoint this client has not "
                          "verified"};
    }
    return bundle;
}

Bytes Session::contract_evidence(const LogKey& log_key, const protocol::Id& instance) {
    if (!remote_) {
        const protocol::InstanceState* i = state().instance(instance);
        const auto& latest = ledger_->latest_checkpoint();
        if (i != nullptr && (!latest || latest->checkpoint.tree_size <= i->head)) {
            static_cast<void>(checkpoint(log_key));
        }
        const std::vector<protocol::Id> ancestors = node::ancestor_ids(state(), instance);
        return unwrap(
            node::contract_evidence(provider_, directory_, evidence(log_key, instance), ancestors),
            "the instance's evidence");
    }
    if (log_key.given) {
        throw UsageError{"with --server the server signs: drop --log-key"};
    }
    const Bytes encoded = call("GET", "/v1/contracts/instances/" + hex_id(instance));
    protocol::VerifyOptions options;
    options.expected_ledger = state().ledger_id();
    const auto report =
        ledger::verify_contract_evidence(provider_, encoded, options, on_all_cores());
    if (!report || report->instance.record != instance) {
        throw ActionError{"the server sent contract evidence that does not verify"};
    }
    const auto decoded =
        unwrap(protocol::decode_contract_evidence(encoded), "reading the evidence");
    const auto bundle =
        unwrap(protocol::decode_bundle(decoded.instance_bundle), "reading the evidence");
    if (!sync_until([&] { return has_checkpoint(bundle.checkpoint); })) {
        throw ActionError{"the server's evidence is anchored to a checkpoint this client has not "
                          "verified"};
    }
    return encoded;
}

Bytes Session::receipt(const LogKey& log_key, std::uint64_t index) {
    if (!remote_) {
        const auto key = log_key.load();
        return unwrap(ledger_->receipt(*key, index), "issuing the receipt");
    }
    if (log_key.given) {
        throw UsageError{"with --server the server signs: drop --log-key"};
    }
    const Bytes encoded = call("GET", "/v1/receipts/" + std::to_string(index));
    const auto receipt = unwrap(protocol::parse_receipt(encoded), "reading the receipt");
    sync_until([&] { return ledger_->size() >= receipt.proof.tree_size; });
    const std::uint64_t size = receipt.proof.tree_size;
    const auto root = protocol::verify_receipt(provider_, receipt,
                                               unwrap(ledger_->entry(index), "reading the entry"),
                                               state().log_key_for(size));
    const auto expected = size <= ledger_->size()
                              ? ledger_->root(size)
                              : Result<crypto::Digest>(fail(Errc::not_found, "beyond the mirror"));
    if (!root || receipt.proof.leaf_index != index || !expected || *root != *expected) {
        throw ActionError{"the server sent a receipt that does not verify"};
    }
    return encoded;
}

void Session::add_cosignature(ByteView cosignature, const crypto::PublicKey& witness) {
    if (!remote_) {
        require_primary();
        unwrap(ledger_->add_cosignature(cosignature, witness), "storing the cosignature");
        return;
    }
    const Bytes body =
        unwrap(cbor::encode(cbor::Value::array(
                   {cbor::Value::bytes(cosignature), protocol::encode_public_key(witness)})),
               "encoding the cosignature");
    static_cast<void>(call("POST", "/v1/cosignatures", body, "application/cbor"));
    sync();
}

bool Session::fetch_vault(const protocol::Id& record) const {
    if (!remote_ || std::filesystem::exists(vault_path(record))) {
        return true;
    }
    const auto response =
        unwrap(remote_->client.request("GET", "/v1/vault/records/" + hex_id(record)),
               "reaching " + remote_->url);
    if (response.status == 404) {
        return false;
    }
    if (response.status != 200) {
        throw ActionError{"the server at " + remote_->url + " refused: " + error_message(response)};
    }
    std::filesystem::create_directories(vault_path(record).parent_path());
    write_file(vault_path(record), response.body, true);
    return true;
}

void Session::fetch_vault_public_key() const {
    if (!remote_ || remote_->vault_key_fetched) {
        return;
    }
    const auto response =
        unwrap(remote_->client.request("GET", "/v1/vault/public-key"), "reaching " + remote_->url);
    if (response.status == 200) {
        std::filesystem::create_directories(directory_ / "vault");
        write_file(directory_ / "vault" / "vault.pub", response.body, false);
    } else if (response.status != 404) {
        throw ActionError{"the server at " + remote_->url + " refused: " + error_message(response)};
    }
    remote_->vault_key_fetched = true;
}

} // namespace cexchain::app
