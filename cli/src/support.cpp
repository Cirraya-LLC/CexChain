// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "support.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <termios.h>
#include <unistd.h>
#include <variant>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/presence.hpp>

#include "output.hpp"
#include "webauthn.hpp"

namespace cexchain::cli {

namespace {

constexpr std::size_t min_prefix = 8;

template <class Map>
protocol::Id resolve(const Map& map, std::string_view text, std::string_view what) {
    std::string lower(text);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return std::tolower(c); });
    if (lower.size() < min_prefix) {
        throw UsageError{std::string(what) + " id must have at least 8 hex digits"};
    }
    const protocol::Id* found = nullptr;
    for (const auto& [key, value] : map) {
        if (hex_id(value.id).starts_with(lower)) {
            if (found != nullptr) {
                throw UsageError{"ambiguous " + std::string(what) + " id " + std::string(text)};
            }
            found = &value.id;
        }
    }
    if (found == nullptr) {
        throw CommandError{"no " + std::string(what) + " with id " + std::string(text)};
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

std::string prompt_hidden(const std::string& prompt) {
    const int tty = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (tty < 0) {
        throw UsageError{
            "a key passphrase is needed: use --passphrase-file or set CEXCHAIN_PASSPHRASE"};
    }
    static_cast<void>(::write(tty, prompt.data(), prompt.size()));
    termios saved{};
    const bool have_termios = ::tcgetattr(tty, &saved) == 0;
    if (have_termios) {
        termios quiet = saved;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(tty, TCSAFLUSH, &quiet);
    }
    std::string line;
    char c = 0;
    while (::read(tty, &c, 1) == 1 && c != '\n') {
        line.push_back(c);
    }
    if (have_termios) {
        ::tcsetattr(tty, TCSAFLUSH, &saved);
    }
    static_cast<void>(::write(tty, "\n", 1));
    ::close(tty);
    return line;
}

} // namespace

Bytes read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw CommandError{"cannot read " + path.string()};
    }
    return Bytes(std::istreambuf_iterator<char>(in), {});
}

void write_file(const std::filesystem::path& path, ByteView data, bool private_file) {
    const std::filesystem::path temporary = path.string() + ".tmp";
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          private_file ? 0600 : 0644);
    if (fd < 0) {
        throw CommandError{"cannot write " + path.string()};
    }
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n <= 0) {
            ::close(fd);
            throw CommandError{"cannot write " + path.string()};
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    if (!synced || std::rename(temporary.c_str(), path.c_str()) != 0) {
        throw CommandError{"cannot write " + path.string()};
    }
}

std::string hex_id(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string short_id(const protocol::Id& id) {
    return hex_id(id).substr(0, 12);
}

protocol::Timestamp parse_time(std::string_view text) {
    int y = 0;
    unsigned mo = 0;
    unsigned d = 0;
    unsigned h = 0;
    unsigned mi = 0;
    unsigned s = 0;
    const std::string str(text);
    const int fields = std::sscanf(str.c_str(), "%d-%u-%uT%u:%u:%u", &y, &mo, &d, &h, &mi, &s);
    if (fields != 3 && fields != 6) {
        throw UsageError{"time must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ"};
    }
    using namespace std::chrono;
    const year_month_day date{year{y}, month{mo}, day{d}};
    if (!date.ok() || h > 23 || mi > 59 || s > 59) {
        throw UsageError{"invalid date " + str};
    }
    const auto time = sys_days{date} + hours{h} + minutes{mi} + seconds{s};
    return static_cast<protocol::Timestamp>(
        duration_cast<milliseconds>(time.time_since_epoch()).count());
}

std::string passphrase(const Args& args, const std::string& purpose, bool confirm,
                       std::string_view file_option, const char* env) {
    if (const auto file = args.get(file_option)) {
        const Bytes content = read_file(*file);
        std::string text(content.begin(), content.end());
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
            text.pop_back();
        }
        if (text.empty()) {
            throw UsageError{"the passphrase file " + *file + " is empty"};
        }
        return text;
    }
    if (const char* value = std::getenv(env); value != nullptr && *value != '\0') {
        return value;
    }
    std::string first = prompt_hidden("Passphrase for " + purpose + ": ");
    if (first.empty()) {
        throw UsageError{"the passphrase must not be empty"};
    }
    if (confirm && prompt_hidden("Repeat the passphrase: ") != first) {
        throw UsageError{"the passphrases do not match"};
    }
    return first;
}

crypto::openssl::KeyPair load_key(const std::filesystem::path& path, const Args& args) {
    const Bytes der = read_file(path);
    if (crypto::openssl::is_encrypted_pkcs8(der)) {
        auto key =
            crypto::openssl::KeyPair::from_encrypted_pkcs8(der, passphrase(args, path.string()));
        if (!key && key.error().code == Errc::verification_failed) {
            throw CommandError{"wrong passphrase for " + path.string()};
        }
        return unwrap(std::move(key), "loading " + path.string());
    }
    auto key = crypto::openssl::KeyPair::from_pkcs8(der);
    if (!key) {
        if (const auto value = cbor::decode(der); value && protocol::decode_public_key(*value)) {
            throw CommandError{path.string() + " is a public key; this needs the private key file"};
        }
    }
    return unwrap(std::move(key), "loading " + path.string());
}

void save_key(const std::filesystem::path& path, const crypto::openssl::KeyPair& key,
              const std::optional<std::string>& secret) {
    if (secret) {
        write_file(path, unwrap(key.to_encrypted_pkcs8(*secret), "encrypting the key"), true);
    } else {
        write_file(path, unwrap(key.to_pkcs8(), "encoding the key").view(), true);
    }
}

Bytes encode_public_key_file(const crypto::PublicKey& key) {
    return unwrap(cbor::encode(protocol::encode_public_key(key)), "encoding the public key");
}

crypto::PublicKey load_public_key(const std::filesystem::path& path) {
    const Bytes content = read_file(path);
    if (const auto value = cbor::decode(content)) {
        if (auto key = protocol::decode_public_key(*value)) {
            return *key;
        }
    }
    if (crypto::openssl::is_encrypted_pkcs8(content) ||
        crypto::openssl::KeyPair::from_pkcs8(content)) {
        throw CommandError{path.string() +
                           " is a private key; share only its public half (cexchain key public " +
                           path.string() + " --out FILE)"};
    }
    throw CommandError{path.string() + " is not a CexChain public key file"};
}

crypto::PublicKey public_key_of(const std::filesystem::path& path, const Args& args) {
    if (const auto value = cbor::decode(read_file(path))) {
        if (auto key = protocol::decode_public_key(*value)) {
            return *key;
        }
    }
    return load_key(path, args).public_key();
}

Bytes hash_text(const crypto::Provider& provider, crypto::HashAlg hash, std::string_view text) {
    const auto digest = unwrap(provider.digest(hash, as_bytes(text)), "hashing");
    return Bytes(digest.bytes().begin(), digest.bytes().end());
}

std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = std::min(text.find(separator, start), text.size());
        if (end > start) {
            parts.push_back(text.substr(start, end - start));
        }
        start = end + 1;
    }
    return parts;
}

std::pair<std::string, std::string> split_pair(const std::string& text, std::string_view what) {
    const auto eq = text.find('=');
    if (eq == std::string::npos || eq == 0) {
        throw UsageError{std::string(what) + " must be NAME=VALUE: " + text};
    }
    return {text.substr(0, eq), text.substr(eq + 1)};
}

std::uint64_t parse_number(std::string_view text, std::string_view what) {
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || ec != std::errc{} || end != text.data() + text.size()) {
        throw UsageError{std::string(what) +
                         " must be a non-negative integer: " + std::string(text)};
    }
    return value;
}

crypto::SigAlg parse_algorithm(std::string_view name) {
    for (const crypto::SigAlg alg : crypto::all_sig_algs) {
        std::string lower(crypto::name(alg));
        std::ranges::transform(lower, lower.begin(),
                               [](unsigned char c) { return std::tolower(c); });
        if (lower == name) {
            return alg;
        }
    }
    throw UsageError{"unknown algorithm " + std::string(name) +
                     " (ed25519, esp256, sm2-sm3, ml-dsa-44, ml-dsa-65, ml-dsa-87)"};
}

crypto::HashAlg parse_hash(std::string_view name) {
    if (name == "sha256" || name == "sha-256") {
        return crypto::HashAlg::sha256;
    }
    if (name == "sm3") {
        return crypto::HashAlg::sm3;
    }
    throw UsageError{"hash must be sha256 or sm3"};
}

protocol::StatementType parse_statement_type(std::string_view name) {
    for (std::uint64_t value = 1; value < 32; ++value) {
        const auto type = protocol::statement_type_from(value);
        if (type && protocol::name(*type) == name) {
            return *type;
        }
    }
    throw UsageError{"unknown statement type " + std::string(name)};
}

protocol::ActorKind parse_actor_kind(std::string_view name) {
    if (name == "person") {
        return protocol::ActorKind::person;
    }
    if (name == "agent") {
        return protocol::ActorKind::agent;
    }
    if (name == "device") {
        return protocol::ActorKind::device;
    }
    throw UsageError{"actor kind must be person, agent, or device"};
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

void recover_vault_swap(const std::filesystem::path& directory) {
    // `vault rekey` builds vault.next/ completely (COMPLETE is written last),
    // then renames vault -> vault.old-<time> and vault.next -> vault. After a
    // crash between the two renames, finish the swap; after a crash before
    // COMPLETE, the old vault is untouched and vault.next is discarded.
    const std::filesystem::path vault = directory / "vault";
    const std::filesystem::path next = directory / "vault.next";
    if (!std::filesystem::exists(vault) && std::filesystem::exists(next / "COMPLETE")) {
        std::filesystem::rename(next, vault);
        std::filesystem::remove(vault / "COMPLETE");
    }
    if (std::filesystem::exists(next)) {
        std::filesystem::remove_all(next);
    }
}

Session::Session(const std::filesystem::path& directory) : directory_(directory) {
    if (!std::filesystem::is_directory(directory)) {
        throw CommandError{"no ledger directory at " + directory.string()};
    }
    lock_.emplace(unwrap(ledger::DirectoryLock::acquire(directory), "locking the ledger"));
    recover_vault_swap(directory);
    fs_.emplace(unwrap(ledger::PosixFileSystem::open_directory(directory), "opening the ledger"));
    ledger_.emplace(unwrap(ledger::Ledger::open(*fs_, clock_, provider_), "opening the ledger"));
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

const protocol::ActorState& Session::actor_for(const crypto::Signer& key) const {
    const auto kid =
        unwrap(protocol::key_id(provider_, state().hash(), key.public_key()), "key id");
    for (const auto& [id, actor] : state().actors()) {
        if (actor.kid == kid) {
            if (actor.revoked) {
                throw CommandError{"the actor holding this key has been revoked"};
            }
            return actor;
        }
    }
    throw CommandError{"this key does not belong to any actor of the ledger"};
}

std::optional<protocol::Id>
Session::choose_delegation(const protocol::ActorState& actor, protocol::StatementType type,
                           const std::optional<std::string>& record_type) const {
    const protocol::Timestamp now = ledger::SystemClock{}.now();
    std::optional<protocol::Id> chosen;
    std::uint64_t newest = 0;
    for (const auto& [key, d] : state().delegations()) {
        const bool usable = d.grantee == actor.id && !d.revoked &&
                            std::ranges::contains(d.scope.statement_types, type) &&
                            (!record_type || !d.scope.record_types ||
                             std::ranges::contains(*d.scope.record_types, *record_type)) &&
                            (!d.scope.not_before || *d.scope.not_before <= now) &&
                            (!d.scope.not_after || now <= *d.scope.not_after);
        if (usable && (!chosen || d.granted_at_index > newest)) {
            chosen = d.id;
            newest = d.granted_at_index;
        }
    }
    return chosen;
}

protocol::Id Session::submit(const crypto::Signer& signer, protocol::Body body,
                             const std::optional<std::string>& delegation,
                             std::optional<protocol::Provenance> provenance,
                             std::optional<bool> presence) {
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
            statement.delegation_id =
                choose_delegation(actor, protocol::type_of(body), record_type_for(state(), body));
            if (!statement.delegation_id) {
                throw CommandError{"no valid delegation lets " + actor.display_name + " do this"};
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
    if (presence) {
        prove_presence(actor, statement, signer.public_key(), *presence);
    }

    const auto signed_statement =
        unwrap(protocol::sign_statement(signer, provider_, state().hash(), statement), "signing");
    const auto registration =
        unwrap(ledger_->submit(signed_statement.encoded), "the ledger refused the statement");
    return registration.statement_id;
}

std::optional<protocol::Provenance> Session::provenance(const Args& args) const {
    if (!args.has("model") && !args.has("model-version") && !args.has("inputs")) {
        return std::nullopt;
    }
    protocol::Provenance provenance{args.get("model"), args.get("model-version"), std::nullopt, {}};
    if (const auto inputs = args.get("inputs")) {
        provenance.input_commitment = hash_text(provider_, state().hash(), *inputs);
    }
    return provenance;
}

protocol::Id Session::submit(const Args& args, protocol::Body body) {
    const auto signer = load_key(args.need("as"), args);
    return submit(signer, std::move(body), args.get("delegation"), provenance(args),
                  args.has("presence") ? std::optional(!args.has("no-browser")) : std::nullopt);
}

void Session::prove_presence(const protocol::ActorState& actor, protocol::Statement& statement,
                             const crypto::PublicKey& signing_key, bool open_browser) const {
    if (actor.kind != protocol::ActorKind::person) {
        throw UsageError{"only people prove presence; \"" + actor.display_name + "\" is " +
                         (actor.is_organization() ? std::string("the organization")
                                                  : "an " + kind_label(actor.kind))};
    }
    if (actor.presence.empty()) {
        throw CommandError{"\"" + actor.display_name +
                           "\" has no passkey registered (cexchain presence enroll, then cexchain "
                           "actor set-presence)"};
    }
    const auto kid =
        unwrap(protocol::key_id(provider_, state().hash(), signing_key), "computing the key id");
    const auto challenge =
        unwrap(protocol::presence_challenge(provider_, state().hash(), statement, kid),
               "computing the challenge");
    const std::string rp_id = actor.presence.front().rp_id;
    nlohmann::json allow = nlohmann::json::array();
    for (const protocol::PresenceCredential& c : actor.presence) {
        if (c.rp_id == rp_id) {
            allow.push_back(to_base64url(c.credential_id));
        }
    }
    const nlohmann::json request{
        {"mode", "get"},
        {"rpId", rp_id},
        {"challenge", to_base64url(challenge)},
        {"allow", allow},
        {"title", "Confirm as " + actor.display_name},
        {"summary", "On the ledger of \"" + state().organization() + "\":\n" +
                        body_summary(*this, statement.body, std::nullopt)}};
    const nlohmann::json response = run_webauthn_ceremony(request, open_browser);
    auto field = [&](const char* name) {
        if (!response.contains(name) || !response[name].is_string()) {
            throw CommandError{"the browser's passkey response is incomplete"};
        }
        return unwrap(from_base64url(response[name].get<std::string>()),
                      "reading the passkey response");
    };
    statement.presence = protocol::PresenceProof{field("id"), field("authenticatorData"),
                                                 field("clientDataJSON"), field("signature")};
    unwrap(protocol::verify_presence(provider_, state().hash(), statement, kid, actor.presence),
           "checking the passkey response");
}

std::uint64_t Session::entry_index(std::string_view text) const {
    if (text.size() < min_prefix &&
        std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; })) {
        const std::uint64_t index = parse_number(text, "index");
        if (index >= ledger_->size()) {
            throw CommandError{"no log entry " + std::string(text)};
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
        throw CommandError{"no statement with id " + std::string(text)};
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

std::string Session::actor_name(const protocol::Id& id) const {
    const protocol::ActorState* actor = state().actor(id);
    return actor == nullptr ? "unknown" : actor->display_name;
}

std::filesystem::path Session::vault_path(const protocol::Id& record) const {
    return directory_ / "vault" / "records" / (hex_id(record) + ".cbor");
}

void create_ledger(const std::filesystem::path& directory, const crypto::Signer& root_key,
                   const crypto::PublicKey& log_key, crypto::HashAlg hash,
                   const std::string& organization) {
    const crypto::openssl::Provider provider;
    ledger::SystemClock clock;
    ledger::SystemEntropy entropy;
    auto fs = unwrap(ledger::PosixFileSystem::open_directory(directory), "creating the directory");
    const auto lock = unwrap(ledger::DirectoryLock::acquire(directory), "locking the ledger");

    protocol::Statement genesis;
    genesis.issued_at = clock.now();
    genesis.nonce = entropy.bytes<16>();
    genesis.body = protocol::GenesisBody{hash, organization, root_key.public_key(), log_key};
    const auto signed_genesis =
        unwrap(protocol::sign_statement(root_key, provider, hash, genesis), "signing genesis");
    static_cast<void>(unwrap(ledger::Ledger::create(fs, clock, provider, signed_genesis.encoded),
                             "creating the ledger"));
}

} // namespace cexchain::cli
