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
#include <thread>
#include <unistd.h>
#include <variant>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/cluster.hpp>
#include <cexchain/node/replica.hpp>
#ifdef CEXCHAIN_HAVE_PKCS11
#include <cexchain/crypto/pkcs11.hpp>
#endif

#include "output.hpp"
#include "registry.hpp"
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
    // A fresh temporary file of our own: never one someone else created (or
    // linked) beforehand in a shared directory, which would receive the
    // data, private keys included, with its own permissions.
    std::array<std::uint8_t, 8> random{};
    ledger::SystemEntropy{}.fill(random);
    const std::filesystem::path temporary = path.string() + "." + to_hex(random) + ".tmp";
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          private_file ? 0600 : 0644);
    if (fd < 0) {
        throw CommandError{"cannot write " + path.string()};
    }
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n <= 0) {
            ::close(fd);
            ::unlink(temporary.c_str());
            throw CommandError{"cannot write " + path.string()};
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    if (!synced || std::rename(temporary.c_str(), path.c_str()) != 0) {
        ::unlink(temporary.c_str());
        throw CommandError{"cannot write " + path.string()};
    }
}

std::string redact_pin(std::string_view uri) {
    std::string out(uri);
    const std::size_t at = out.find("pin-value=");
    if (at == std::string::npos) {
        return out;
    }
    const std::size_t value = at + std::string_view("pin-value=").size();
    const std::size_t end = std::min(out.find('&', value), out.size());
    out.replace(value, end - value, "REDACTED");
    return out;
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

const crypto::openssl::Provider& shared_provider() {
    static const crypto::openssl::Provider provider;
    return provider;
}

#ifdef CEXCHAIN_HAVE_PKCS11
namespace {

std::string token_pin(const crypto::pkcs11::KeyUri& uri) {
    if (uri.pin_value) {
        return *uri.pin_value;
    }
    if (uri.pin_source) {
        const Bytes content = read_file(*uri.pin_source);
        std::string pin(content.begin(), content.end());
        while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) {
            pin.pop_back();
        }
        return pin;
    }
    if (const char* env = std::getenv("CEXCHAIN_PKCS11_PIN"); env != nullptr && *env != '\0') {
        return env;
    }
    return prompt_hidden("PIN for token " + uri.token.value_or(uri.serial.value_or("")) + ": ");
}

std::unique_ptr<crypto::Signer> token_key(Result<crypto::pkcs11::Key> key) {
    if (!key && key.error().code == Errc::verification_failed) {
        throw CommandError{"wrong PIN for the token"};
    }
    return std::make_unique<crypto::pkcs11::Key>(
        unwrap(std::move(key), "using the key on the token"));
}

} // namespace
#endif

std::unique_ptr<crypto::Signer> load_signer(const std::string& source, const Args& args) {
    if (source.starts_with("pkcs11:")) {
#ifdef CEXCHAIN_HAVE_PKCS11
        const auto uri = unwrap(crypto::pkcs11::parse_uri(source), "reading the PKCS #11 URI");
        return token_key(crypto::pkcs11::Key::open(uri, token_pin(uri), shared_provider()));
#else
        throw CommandError{
            "this build of cexchain has no PKCS #11 support (it needs p11-kit at build time)"};
#endif
    }
    return std::make_unique<crypto::openssl::KeyPair>(load_key(source, args));
}

std::unique_ptr<crypto::Signer> generate_on_token([[maybe_unused]] const std::string& source,
                                                  [[maybe_unused]] crypto::SigAlg alg) {
#ifdef CEXCHAIN_HAVE_PKCS11
    const auto uri = unwrap(crypto::pkcs11::parse_uri(source), "reading the PKCS #11 URI");
    return token_key(crypto::pkcs11::Key::generate(uri, token_pin(uri), alg, shared_provider()));
#else
    throw CommandError{
        "this build of cexchain has no PKCS #11 support (it needs p11-kit at build time)"};
#endif
}

std::optional<PresenceRequest> presence_request(const Args& args) {
    if (args.has("presence") && args.has("presence-key")) {
        throw UsageError{
            "give --presence (a passkey) or --presence-key (a hardware key), not both"};
    }
    if (const auto uri = args.get("presence-key")) {
        if (!uri->starts_with("pkcs11:")) {
            throw UsageError{"--presence-key takes a pkcs11: URI naming the hardware key"};
        }
#ifdef CEXCHAIN_HAVE_PKCS11
        // Presence means a person unlocked the key now: not a PIN written
        // into the URI, and not a key that can live outside the token.
        const auto parsed = unwrap(crypto::pkcs11::parse_uri(*uri), "reading the PKCS #11 URI");
        if (parsed.pin_value) {
            throw UsageError{"a presence key's PIN is entered, not written into its URI: remove "
                             "pin-value="};
        }
        auto key = std::make_shared<crypto::pkcs11::Key>(
            unwrap(crypto::pkcs11::Key::open(parsed, token_pin(parsed), shared_provider()),
                   "using the key on the token"));
        if (!key->hardware_bound()) {
            throw CommandError{"the token lets this key leave it (not sensitive, or extractable): "
                               "it cannot prove a person's presence"};
        }
        return PresenceRequest{false, std::move(key)};
#else
        throw CommandError{
            "this build of cexchain has no PKCS #11 support (it needs p11-kit at build time)"};
#endif
    }
    if (args.has("presence")) {
        return PresenceRequest{!args.has("no-browser"), nullptr};
    }
    return std::nullopt;
}

crypto::PublicKey public_key_of(const std::filesystem::path& path, const Args& args) {
    if (path.string().starts_with("pkcs11:")) {
        return load_signer(path.string(), args)->public_key();
    }
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

std::optional<std::string> api_token(const Args& args) {
    if (const auto file = args.get("token-file")) {
        const Bytes bytes = read_file(*file);
        std::string text(bytes.begin(), bytes.end());
        while (!text.empty() &&
               (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
            text.pop_back();
        }
        return text;
    }
    if (const char* env = std::getenv("CEXCHAIN_TOKEN"); env != nullptr && *env != '\0') {
        return std::string(env);
    }
    return std::nullopt;
}

node::Client client_for(const std::string& url, const Args& args,
                        const std::optional<std::string>& ca_file) {
    node::ClientOptions options;
    options.bearer_token = api_token(args);
    if (ca_file) {
        options.ca_file = *ca_file;
    }
    return node::Client(unwrap(node::Url::parse(url), "reading the URL"), std::move(options));
}

namespace {

/// The server URL if this command runs in client mode.
std::optional<std::string> server_url(const Args& args) {
    const bool takes_server = std::ranges::any_of(
        args.spec().options, [](const OptionSpec& o) { return o.name == "server"; });
    if (!takes_server) {
        return std::nullopt;
    }
    const auto flag = args.get("server");
    if (flag && args.has("ledger")) {
        throw UsageError{"--server and --ledger exclude each other: a ledger is either here or "
                         "on a server"};
    }
    if (flag) {
        return *flag;
    }
    if (args.has("ledger")) {
        return std::nullopt;
    }
    if (const char* env = std::getenv("CEXCHAIN_SERVER"); env != nullptr && *env != '\0') {
        if (const char* local = std::getenv("CEXCHAIN_LEDGER");
            local != nullptr && *local != '\0') {
            throw UsageError{"both CEXCHAIN_LEDGER and CEXCHAIN_SERVER are set: pass --ledger or "
                             "--server"};
        }
        return std::string(env);
    }
    return std::nullopt;
}

std::filesystem::path cache_root(const Args& args) {
    if (const auto cache = args.get("cache")) {
        return *cache;
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

Session::Session(const std::filesystem::path& directory) {
    open(directory);
}

Session::Session(const Args& args) {
    if (const auto url = server_url(args)) {
        open_remote(args, *url);
    } else {
        open(args.ledger());
    }
}

void Session::open(const std::filesystem::path& directory) {
    directory_ = directory;
    if (!std::filesystem::is_directory(directory)) {
        throw CommandError{"no ledger directory at " + directory.string()};
    }
    lock_.emplace(unwrap(ledger::DirectoryLock::acquire(directory), "locking the ledger"));
    recover_vault_swap(directory);
    fs_.emplace(unwrap(ledger::PosixFileSystem::open_directory(directory), "opening the ledger"));
    ledger_.emplace(unwrap(ledger::Ledger::open(*fs_, clock_, provider_), "opening the ledger"));
}

void Session::open_remote(const Args& args, const std::string& url) {
    const std::optional<std::string> ca = args.get("ca-file");
    remote_.emplace(Remote{client_for(url, args, ca), {}, false});
    const node::Client& client = remote_->client;
    remote_->url = client.base().to_string();
    const auto status = unwrap(node::primary_status(client), "reaching " + remote_->url);
    const protocol::Id served = parse_ledger_id(status.ledger_id, "the server's ledger id");
    std::optional<protocol::Id> expected;
    if (const auto text = args.get("ledger-id")) {
        expected = parse_ledger_id(*text, "--ledger-id");
    }

    // The ledger each URL serves is pinned on first use; the mirror of each
    // ledger is shared by every URL that serves it.
    const std::filesystem::path root = cache_root(args);
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
                throw CommandError{pins_file.string() + " is corrupted"};
            }
        }
        if (pins.contains(remote_->url)) {
            if (pins[remote_->url] != hex_id(served)) {
                throw CommandError{"the server at " + remote_->url + " now serves ledger " +
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
            throw CommandError{"the server at " + remote_->url + " serves ledger " +
                               hex_id(served) + ", not the one expected"};
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
            throw CommandError{"the server at " + remote_->url + " does not show the history " +
                               "this client verified before: " + std::string(e.detail) +
                               " (the mirror is " + directory_.string() + ")"};
        }
        throw CommandError{"syncing with " + remote_->url + ": " + std::string(e.detail) + " (" +
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
        throw CommandError{"the server at " + remote_->url +
                           " refused: " + error_message(response)};
    }
    return response.body;
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
                             const std::optional<PresenceRequest>& presence,
                             const SealVault& seal_vault) {
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
    if (!remote_) {
        require_primary();
    }
    if (presence) {
        prove_presence(actor, statement, signer.public_key(), *presence);
    }

    const auto signed_statement =
        unwrap(protocol::sign_statement(signer, provider_, state().hash(), statement), "signing");
    std::optional<Bytes> sealed;
    if (seal_vault) {
        sealed = seal_vault(signed_statement.id);
    }
    if (remote_) {
        // Signed here; the server registers it, with its private data if
        // any, and the mirror shows it once it re-validated it.
        if (sealed) {
            const Bytes submission =
                unwrap(cbor::encode(cbor::Value::map(
                           {{cbor::Value::integer(1), cbor::Value::bytes(signed_statement.encoded)},
                            {cbor::Value::integer(2), cbor::Value::bytes(*sealed)}})),
                       "encoding the submission");
            static_cast<void>(
                call("POST", "/v1/statements", submission, node::submission_content_type));
        } else {
            static_cast<void>(
                call("POST", "/v1/statements", signed_statement.encoded, "application/cose"));
        }
        if (!sync_until([&] { return state().statement_index(signed_statement.id).has_value(); })) {
            throw CommandError{"the server accepted the statement but does not show it"};
        }
        return signed_statement.id;
    }
    const auto registration =
        unwrap(ledger_->submit(signed_statement.encoded), "the ledger refused the statement");
    if (sealed) {
        std::filesystem::create_directories(vault_path(registration.statement_id).parent_path());
        write_file(vault_path(registration.statement_id), *sealed, true);
    }
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
    const auto signer = load_signer(args.need("as"), args);
    return submit(*signer, std::move(body), args.get("delegation"), provenance(args),
                  presence_request(args));
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
        throw CommandError{"\"" + actor.display_name +
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
            throw CommandError{
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
        throw CommandError{"\"" + actor.display_name +
                           "\" has only hardware keys; prove presence with --presence-key"};
    }
    const std::string rp_id = passkey->rp_id;
    nlohmann::json allow = nlohmann::json::array();
    for (const protocol::PresenceCredential& c : actor.presence) {
        if (c.method == protocol::PresenceMethod::webauthn && c.rp_id == rp_id) {
            allow.push_back(to_base64url(c.credential_id));
        }
    }
    const nlohmann::json ceremony{
        {"mode", "get"},
        {"rpId", rp_id},
        {"challenge", to_base64url(challenge)},
        {"allow", allow},
        {"title", "Confirm as " + actor.display_name},
        {"summary", "On the ledger of \"" + state().organization() + "\":\n" +
                        body_summary(*this, statement.body, std::nullopt)}};
    const nlohmann::json response = run_webauthn_ceremony(ceremony, request.open_browser);
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
        throw CommandError{"this works on the ledger's directory only: run it where the ledger "
                           "is, without --server"};
    }
    if (node::is_cluster_member(directory_)) {
        throw CommandError{"this ledger is a cluster member: write through the cluster (--server "
                           "a member's API)"};
    }
    if (std::filesystem::exists(directory_ / node::replica_file)) {
        throw CommandError{"this ledger is a replica: write to its primary, or promote it first "
                           "(cexchain replica promote)"};
    }
}

std::filesystem::path Session::vault_path(const protocol::Id& record) const {
    return directory_ / "vault" / "records" / (hex_id(record) + ".cbor");
}

protocol::SignedCheckpoint Session::checkpoint(const Args& args) {
    if (!remote_) {
        require_primary();
        const auto log_key = load_signer(args.need("log-key"), args);
        return unwrap(ledger_->checkpoint(*log_key), "checkpointing");
    }
    if (args.has("log-key")) {
        throw UsageError{"with --server the server signs: drop --log-key"};
    }
    const Bytes encoded = call("POST", "/v1/checkpoint");
    // The server's word counts once the mirror took it, checked.
    const auto checkpoint = unwrap(protocol::parse_checkpoint(encoded), "reading the checkpoint");
    if (!sync_until([&] { return has_checkpoint(encoded); })) {
        throw CommandError{"the server's checkpoint is not in the history this client verified"};
    }
    return checkpoint;
}

protocol::EvidenceBundle Session::evidence(const Args& args, const protocol::Id& record) {
    if (!remote_) {
        const auto log_key = load_signer(args.need("log-key"), args);
        return unwrap(ledger_->export_evidence(*log_key, record), "exporting evidence");
    }
    if (args.has("log-key")) {
        throw UsageError{"with --server the server signs: drop --log-key"};
    }
    const Bytes encoded = call("GET", "/v1/evidence/" + hex_id(record));
    // Verified here, against the ledger and the checkpoints this client
    // verified, before anything is built on it.
    protocol::VerifyOptions options;
    options.expected_ledger = state().ledger_id();
    const auto report = protocol::verify_bundle(provider_, encoded, options);
    if (!report || report->record != record) {
        throw CommandError{"the server sent evidence that does not verify"};
    }
    auto bundle = unwrap(protocol::decode_bundle(encoded), "reading the evidence");
    if (!sync_until([&] { return has_checkpoint(bundle.checkpoint); })) {
        throw CommandError{"the server's evidence is anchored to a checkpoint this client has not "
                           "verified"};
    }
    return bundle;
}

Bytes Session::receipt(const Args& args, std::uint64_t index) {
    if (!remote_) {
        const auto log_key = load_signer(args.need("log-key"), args);
        return unwrap(ledger_->receipt(*log_key, index), "issuing the receipt");
    }
    if (args.has("log-key")) {
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
        throw CommandError{"the server sent a receipt that does not verify"};
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
        throw CommandError{"the server at " + remote_->url +
                           " refused: " + error_message(response)};
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
        throw CommandError{"the server at " + remote_->url +
                           " refused: " + error_message(response)};
    }
    remote_->vault_key_fetched = true;
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
