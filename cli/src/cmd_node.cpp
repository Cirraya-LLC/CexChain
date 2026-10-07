// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Running a ledger as a service: the HTTP API (serve), API tokens, replicas
// that copy a primary and check everything they copy, and backups.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <print>
#include <sys/resource.h>
#include <thread>

#include <cexchain/ledger/backup.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/replica.hpp>
#include <cexchain/node/server.hpp>
#include <cexchain/node/tokens.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "witness.hpp"

namespace cexchain::cli {

namespace {

using namespace std::chrono_literals;

void require_ledger_directory(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir / "statements")) {
        throw CommandError{"no ledger at " + dir.string()};
    }
}

std::string trimmed_text(const std::filesystem::path& path) {
    const Bytes bytes = read_file(path);
    std::string text(bytes.begin(), bytes.end());
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
        text.pop_back();
    }
    return text;
}

/// The API token from --token-file or $CEXCHAIN_TOKEN, if any.
std::optional<std::string> api_token(const Args& args) {
    if (const auto file = args.get("token-file")) {
        return trimmed_text(*file);
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

/// HOST:PORT, with [v6]:PORT for IPv6.
std::pair<std::string, std::uint16_t> parse_listen(const std::string& text) {
    std::string host;
    std::string port;
    if (text.starts_with('[')) {
        const std::size_t close = text.find("]:");
        if (close == std::string::npos) {
            throw UsageError{"--listen takes HOST:PORT, e.g. 127.0.0.1:8080 or [::1]:8080"};
        }
        host = text.substr(1, close - 1);
        port = text.substr(close + 2);
    } else {
        const std::size_t colon = text.rfind(':');
        if (colon == std::string::npos) {
            throw UsageError{"--listen takes HOST:PORT, e.g. 127.0.0.1:8080 or [::1]:8080"};
        }
        host = text.substr(0, colon);
        port = text.substr(colon + 1);
    }
    const std::uint64_t number = parse_number(port, "port");
    if (number > 65535) {
        throw UsageError{"the port must be at most 65535"};
    }
    return {host, static_cast<std::uint16_t>(number)};
}

Json token_json(const node::ApiToken& t) {
    return {{"name", t.name},
            {"scopes", node::scope_names(t.scopes)},
            {"created", format_time(t.created)}};
}

std::string scopes_text(node::Scopes scopes) {
    std::string out;
    for (const std::string& name : node::scope_names(scopes)) {
        out += (out.empty() ? "" : ",") + name;
    }
    return out;
}

/// Files a backup may carry, relative to the ledger directory.
bool backup_path_allowed(std::string_view path) {
    if (path == node::tokens_file || path == "vault/vault.pub" || path == "vault/vault.key") {
        return true;
    }
    constexpr std::string_view prefix = "vault/records/";
    if (!path.starts_with(prefix) || !path.ends_with(".cbor")) {
        return false;
    }
    const std::string_view name = path.substr(prefix.size(), path.size() - prefix.size() - 5);
    return name.size() == 64 && std::ranges::all_of(name, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

std::atomic<bool> stop_requested{false};

extern "C" void request_stop(int) {
    stop_requested = true;
}

} // namespace

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

namespace {

/// Each connection takes a file descriptor: lift the soft limit (often 256
/// or 1024) toward what the connections need, as far as the hard limit lets.
void raise_descriptor_limit(std::uint64_t wanted) {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur >= wanted) {
        return;
    }
    limit.rlim_cur = std::min<rlim_t>(limit.rlim_max, static_cast<rlim_t>(wanted));
    static_cast<void>(::setrlimit(RLIMIT_NOFILE, &limit));
}

} // namespace

int cmd_serve(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    node::ApiOptions options;
    options.directory = dir;
    if (const auto key = args.get("log-key")) {
        options.log_key = std::shared_ptr<const crypto::Signer>(load_signer(*key, args));
    }
    options.read_only = args.has("read-only");
    options.public_read = args.has("public-read");
    const std::uint64_t interval = args.has("checkpoint-interval")
                                       ? parse_number(*args.get("checkpoint-interval"), "interval")
                                   : options.log_key ? 60
                                                     : 0;
    if (interval > 0 && !options.log_key) {
        throw UsageError{"--checkpoint-interval needs --log-key"};
    }
    options.checkpoint_interval = std::chrono::seconds(interval);
    options.version = CEXCHAIN_VERSION;
    options.event_log = &std::cerr;
    if (args.has("witness-dir") != args.has("witness-key")) {
        throw UsageError{"--witness-dir and --witness-key go together"};
    }
    if (const auto witness_dir = args.get("witness-dir")) {
        if (!std::filesystem::is_directory(*witness_dir)) {
            throw CommandError{"no witness directory at " + *witness_dir +
                               " (cexchain witness add-log)"};
        }
        std::shared_ptr<const crypto::Signer> witness_key =
            load_signer(args.need("witness-key"), args);
        options.witness = [dir = std::filesystem::path(*witness_dir),
                           witness_key](ByteView request) {
            return witness_cosign(dir, *witness_key, request);
        };
    }
    auto api = unwrap(node::LedgerApi::open(options, shared_provider()), "opening the ledger");

    node::ServerOptions server_options;
    const auto [host, port] = parse_listen(args.get("listen").value_or("127.0.0.1:8080"));
    server_options.host = host;
    server_options.port = port;
    if (const auto cert = args.get("tls-cert")) {
        server_options.tls_certificate = *cert;
    }
    if (const auto key = args.get("tls-key")) {
        server_options.tls_private_key = *key;
    }
    if (const auto n = args.get("threads")) {
        server_options.threads = parse_number(*n, "threads");
        if (server_options.threads == 0 || server_options.threads > 1024) {
            throw UsageError{"--threads is 1 to 1024"};
        }
    }
    if (const auto n = args.get("max-connections")) {
        server_options.max_connections = parse_number(*n, "connections");
    }
    raise_descriptor_limit(server_options.max_connections + 64);
    if (const auto n = args.get("max-body")) {
        server_options.limits.max_body = parse_number(*n, "body size");
    }
    server_options.access_log = args.has("quiet") ? nullptr : &std::cerr;
    const bool tls = server_options.tls_certificate.has_value();

    node::Server server(*api, server_options);
    unwrap(server.listen(), "starting the server");
    const std::string url =
        std::format("{}://{}:{}", tls ? "https" : "http",
                    host.find(':') != std::string::npos ? "[" + host + "]" : host, server.port());
    const std::string role = api->is_replica() ? "replica" : "primary";
    if (args.json()) {
        print_json({{"url", url},
                    {"port", server.port()},
                    {"ledger_id", id_json(api->ledger().id())},
                    {"role", role},
                    {"read_only", options.read_only || api->is_replica()},
                    {"log_key", options.log_key != nullptr},
                    {"checkpoint_interval", interval}});
    } else {
        std::println("serving ledger {} ({}) at {}", hex_id(api->ledger().id()), role, url);
        if (!options.log_key) {
            std::println("no --log-key: receipts, evidence, and checkpoints are not served");
        }
    }
    std::fflush(stdout);
    server.run();
    return exit_ok;
}

// ---------------------------------------------------------------------------
// token
// ---------------------------------------------------------------------------

int cmd_token_create(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const std::string name = args.positional().front();
    if (!node::valid_token_name(name)) {
        throw UsageError{"a token name is 1-64 letters, digits, '.', '_', or '-'"};
    }
    const node::Scopes scopes =
        unwrap(node::parse_scopes(args.get("scope").value_or("read")), "reading --scope");
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the ledger");
    auto tokens = unwrap(node::load_tokens(dir), "reading the API tokens");
    if (std::ranges::any_of(tokens, [&](const node::ApiToken& t) { return t.name == name; })) {
        throw CommandError{"a token named " + name + " exists; revoke it first"};
    }
    ledger::SystemEntropy entropy;
    ledger::SystemClock clock;
    const std::string token = node::generate_token(entropy);
    const node::ApiToken created{name, scopes, node::token_hash(shared_provider(), token),
                                 clock.now()};
    tokens.push_back(created);
    unwrap(node::save_tokens(dir, tokens), "saving the API tokens");
    if (const auto out = args.get("out")) {
        write_file(*out, as_bytes(token + "\n"), true);
    }
    if (args.json()) {
        Json j = token_json(created);
        if (!args.has("out")) {
            j["token"] = token;
        }
        print_json(j);
    } else if (args.has("out")) {
        std::println("created token {} ({}), written to {}", name, scopes_text(scopes),
                     *args.get("out"));
    } else {
        std::println("created token {} ({}). It is shown only once:\n{}", name, scopes_text(scopes),
                     token);
    }
    return exit_ok;
}

int cmd_token_list(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const auto tokens = unwrap(node::load_tokens(dir), "reading the API tokens");
    if (args.json()) {
        Json list = Json::array();
        for (const auto& t : tokens) {
            list.push_back(token_json(t));
        }
        print_json(list);
        return exit_ok;
    }
    if (tokens.empty()) {
        std::println("no API tokens (cexchain token create NAME --scope read)");
    }
    for (const auto& t : tokens) {
        std::println("{:<24} {:<18} created {}", t.name, scopes_text(t.scopes),
                     format_time(t.created));
    }
    return exit_ok;
}

int cmd_token_show(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const auto tokens = unwrap(node::load_tokens(dir), "reading the API tokens");
    const std::string name = args.positional().front();
    const auto it = std::ranges::find(tokens, name, &node::ApiToken::name);
    if (it == tokens.end()) {
        throw CommandError{"no token named " + name};
    }
    if (args.json()) {
        Json j = token_json(*it);
        j["sha256"] = it->sha256;
        print_json(j);
    } else {
        std::println("name:     {}\nscopes:   {}\ncreated:  {}\nsha256:   {}", it->name,
                     scopes_text(it->scopes), format_time(it->created), it->sha256);
    }
    return exit_ok;
}

int cmd_token_revoke(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the ledger");
    auto tokens = unwrap(node::load_tokens(dir), "reading the API tokens");
    const std::string name = args.positional().front();
    const auto removed =
        std::erase_if(tokens, [&](const node::ApiToken& t) { return t.name == name; });
    if (removed == 0) {
        throw CommandError{"no token named " + name};
    }
    unwrap(node::save_tokens(dir, tokens), "saving the API tokens");
    if (args.json()) {
        print_json({{"revoked", name}});
    } else {
        std::println("revoked token {} (running servers notice within a second)", name);
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// replica
// ---------------------------------------------------------------------------

namespace {

Json sync_json(const node::SyncReport& r) {
    return {{"entries", r.entries},
            {"checkpoints", r.checkpoints},
            {"cosignatures", r.cosignatures},
            {"vault_files", r.vault_files},
            {"size", r.size},
            {"primary_size", r.primary_size}};
}

/// One sync round under the lock. Returns the exit code for a failure, or
/// nothing on success.
std::optional<int> sync_round(const std::filesystem::path& dir, const node::Client& client,
                              std::optional<ledger::PosixFileSystem>& fs,
                              std::optional<ledger::Ledger>& replica, ledger::Clock& clock,
                              const Args& args, bool quiet) {
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the ledger");
    if (!replica) {
        fs.emplace(unwrap(ledger::PosixFileSystem::open_directory(dir), "opening the ledger"));
        replica.emplace(
            unwrap(ledger::Ledger::open(*fs, clock, shared_provider()), "opening the replica"));
    } else {
        unwrap(replica->refresh(*fs, true), "re-reading the replica");
    }
    const auto report = node::sync_replica(client, *replica, dir);
    if (!report) {
        const Error& e = report.error();
        if (args.json()) {
            print_json({{"synced", false},
                        {"error", e.detail},
                        {"verified", e.code != Errc::verification_failed}});
        } else if (e.code == Errc::verification_failed) {
            std::println("NOT VERIFIED: {}. Copying stopped; what was copied before is intact.",
                         e.detail);
        } else {
            std::println(stderr, "error: syncing from {}: {} ({})", client.base().to_string(),
                         e.detail, to_string(e.code));
        }
        return e.code == Errc::verification_failed ? exit_not_verified : exit_failure;
    }
    auto info = unwrap(node::read_replica_info(dir), "reading the replica file");
    if (info) {
        info->last_sync = clock.now();
        unwrap(node::write_replica_info(dir, *info), "updating the replica file");
    }
    if (args.json()) {
        print_json(sync_json(*report));
    } else if (!quiet || report->entries + report->checkpoints + report->cosignatures > 0) {
        std::println("synced: {} entries, {} checkpoints, {} cosignatures, {} vault files; size "
                     "{} of {}",
                     report->entries, report->checkpoints, report->cosignatures,
                     report->vault_files, report->size, report->primary_size);
    }
    std::fflush(stdout);
    return std::nullopt;
}

} // namespace

int cmd_replica_init(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    if (std::filesystem::exists(dir / "statements")) {
        throw CommandError{"a ledger already exists at " + dir.string()};
    }
    const std::string url = args.need("from");
    const std::optional<std::string> ca = args.get("ca");
    const node::Client client = client_for(url, args, ca);
    // Without TLS anyone in between could hand over another ledger entirely.
    std::optional<protocol::Id> expected;
    if (const auto text = args.get("ledger-id")) {
        const auto bytes = from_hex(*text);
        if (!bytes || bytes->size() != protocol::id_size) {
            throw UsageError{"--ledger-id must be the full hex ledger id"};
        }
        expected = unwrap(protocol::to_id(*bytes), "ledger id");
    } else if (!client.base().tls) {
        throw UsageError{"an http:// source needs --ledger-id, to pin the ledger replicated"};
    }
    const bool existed = std::filesystem::exists(dir);
    std::filesystem::create_directories(dir);
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    ledger::SystemClock clock;
    {
        std::optional<ledger::DirectoryLock> lock;
        lock.emplace(unwrap(ledger::DirectoryLock::acquire(dir), "locking the ledger"));
        auto fs = unwrap(ledger::PosixFileSystem::open_directory(dir), "opening the directory");
        const auto created = node::create_replica(client, fs, clock, shared_provider(), expected);
        if (!created) {
            if (!existed) {
                lock.reset();
                std::filesystem::remove_all(dir);
            }
            throw CommandError{"starting the replica from " + url + ": " +
                               std::string(created.error().detail) + " (" +
                               std::string(to_string(created.error().code)) + ")"};
        }
        unwrap(node::write_replica_info(dir, {client.base().to_string(), ca, clock.now(), {}}),
               "writing the replica file");
    }
    std::optional<ledger::PosixFileSystem> fs;
    std::optional<ledger::Ledger> replica;
    if (const auto failed = sync_round(dir, client, fs, replica, clock, args, false)) {
        return *failed;
    }
    if (!args.json()) {
        std::println("replica of ledger {} from {} ready at {}; keep it current with: cexchain "
                     "replica sync --follow",
                     hex_id(replica->id()), client.base().to_string(), dir.string());
    }
    return exit_ok;
}

int cmd_replica_sync(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const auto info = unwrap(node::read_replica_info(dir), "reading the replica file");
    if (!info) {
        throw CommandError{"this ledger is not a replica"};
    }
    const node::Client client = client_for(info->source, args, info->ca_file);
    ledger::SystemClock clock;
    std::optional<ledger::PosixFileSystem> fs;
    std::optional<ledger::Ledger> replica;
    if (!args.has("follow")) {
        const auto failed = sync_round(dir, client, fs, replica, clock, args, false);
        return failed ? *failed : exit_ok;
    }
    const auto interval =
        std::chrono::seconds(parse_number(args.get("interval").value_or("10"), "interval"));
    std::signal(SIGINT, request_stop);
    std::signal(SIGTERM, request_stop);
    auto backoff = interval;
    while (!stop_requested) {
        const auto failed = sync_round(dir, client, fs, replica, clock, args, true);
        if (failed == exit_not_verified) {
            return exit_not_verified; // never keep copying a history that failed
        }
        backoff = failed ? std::min(backoff * 2, std::chrono::seconds(300)) : interval;
        for (auto waited = 0ms; waited < backoff && !stop_requested; waited += 100ms) {
            std::this_thread::sleep_for(100ms);
        }
    }
    return exit_ok;
}

int cmd_replica_status(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const auto info = unwrap(node::read_replica_info(dir), "reading the replica file");
    if (!info) {
        if (args.json()) {
            print_json({{"replica", false}});
        } else {
            std::println("this ledger is a primary, not a replica");
        }
        return exit_ok;
    }
    std::uint64_t size = 0;
    std::optional<std::uint64_t> checkpoint;
    protocol::Id id;
    {
        Session session(dir);
        size = session.ledger().size();
        id = session.ledger().id();
        if (const auto& c = session.ledger().latest_checkpoint()) {
            checkpoint = c->checkpoint.tree_size;
        }
    }
    const node::Client client = client_for(info->source, args, info->ca_file);
    const auto primary = node::primary_status(client);
    if (args.json()) {
        Json j = {{"replica", true},
                  {"source", info->source},
                  {"ledger_id", id_json(id)},
                  {"size", size},
                  {"checkpoint_size", checkpoint ? Json(*checkpoint) : Json(nullptr)},
                  {"created", format_time(info->created)},
                  {"last_sync", info->last_sync ? Json(format_time(*info->last_sync)) : Json()}};
        if (primary) {
            j["primary_size"] = primary->size;
            j["behind"] = primary->size > size ? primary->size - size : 0;
        } else {
            j["primary_error"] = primary.error().detail;
        }
        print_json(j);
        return exit_ok;
    }
    std::println("replica of:   {}", info->source);
    std::println("ledger:       {}", hex_id(id));
    std::println("size:         {} entries (checkpoint at {})", size,
                 checkpoint ? std::to_string(*checkpoint) : "none");
    std::println("last sync:    {}", info->last_sync ? format_time(*info->last_sync) : "never");
    if (primary) {
        std::println("primary:      {} entries ({} behind)", primary->size,
                     primary->size > size ? primary->size - size : 0);
    } else {
        std::println("primary:      unreachable ({})", primary.error().detail);
    }
    return exit_ok;
}

int cmd_replica_promote(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the ledger");
    const auto info = unwrap(node::read_replica_info(dir), "reading the replica file");
    if (!info) {
        throw CommandError{"this ledger is not a replica"};
    }
    std::filesystem::remove(dir / node::replica_file);
    if (args.json()) {
        print_json({{"promoted", true}, {"former_primary", info->source}});
    } else {
        std::println("promoted: this ledger now accepts writes. The former primary ({}) must stay\n"
                     "stopped: two primaries would fork the ledger, which witnesses detect.",
                     info->source);
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// backup
// ---------------------------------------------------------------------------

namespace {

Json summary_json(const ledger::BackupSummary& s) {
    Json j = {{"ledger_id", id_json(s.ledger_id)},
              {"created", format_time(s.created)},
              {"signed", s.is_signed},
              {"entries", s.entries},
              {"checkpoints", s.checkpoints},
              {"cosignatures", s.cosignatures},
              {"files", s.files},
              {"skipped_entries", s.skipped_entries},
              {"skipped_files", s.skipped_files}};
    if (s.root) {
        j["head"] = {{"size", s.size},
                     {"root", hex_json(s.root->bytes())},
                     {"checkpoint", s.checkpoint
                                        ? Json{{"size", s.checkpoint->tree_size},
                                               {"root", hex_json(s.checkpoint->root.bytes())},
                                               {"timestamp", format_time(s.checkpoint->timestamp)}}
                                        : Json(nullptr)}};
    }
    return j;
}

/// What a restore took, and what it left out, in words.
void print_restore_head(const ledger::BackupSummary& s) {
    if (s.root) {
        std::println("head: size {}, root {}", s.size, to_hex(s.root->bytes()));
    }
    if (s.checkpoint) {
        std::println("latest checkpoint: size {}, signed {} (compare it with a witness)",
                     s.checkpoint->tree_size, format_time(s.checkpoint->timestamp));
    }
    if (!s.is_signed && (s.skipped_entries > 0 || s.skipped_files > 0)) {
        std::println("unsigned backup: left out {} entries after the last checkpoint and {} files "
                     "(tokens, vault); sign backups with --log-key to keep them",
                     s.skipped_entries, s.skipped_files);
    }
}

int report_restore_failure(const Args& args, const Error& e, std::string_view what) {
    if (args.json()) {
        print_json({{"ok", false}, {"error", e.detail}});
    } else if (e.code == Errc::verification_failed) {
        std::println("NOT VERIFIED: {}", e.detail);
    } else {
        std::println(stderr, "error: {}: {} ({})", what, e.detail, to_string(e.code));
    }
    return e.code == Errc::verification_failed ? exit_not_verified : exit_failure;
}

} // namespace

int cmd_backup_create(const Args& args) {
    Session session(args.ledger());
    const std::filesystem::path dir = session.directory();
    std::vector<ledger::BackupFile> files;
    auto add = [&](const std::string& relative) {
        if (std::filesystem::is_regular_file(dir / relative)) {
            files.push_back({relative, read_file(dir / relative)});
        }
    };
    add(std::string(node::tokens_file));
    if (!args.has("no-vault")) {
        add("vault/vault.pub");
        add("vault/vault.key");
        if (std::filesystem::is_directory(dir / "vault" / "records")) {
            std::vector<std::string> names;
            for (const auto& e : std::filesystem::directory_iterator(dir / "vault" / "records")) {
                const std::string relative = "vault/records/" + e.path().filename().string();
                if (e.is_regular_file() && backup_path_allowed(relative)) {
                    names.push_back(relative);
                }
            }
            std::ranges::sort(names);
            for (const auto& n : names) {
                add(n);
            }
        }
    }
    const std::filesystem::path out = args.need("out");
    const std::filesystem::path temporary = out.string() + ".tmp";
    ledger::SystemClock clock;
    ledger::BackupSummary summary;
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream) {
            throw CommandError{"cannot write " + temporary.string()};
        }
        std::filesystem::permissions(temporary, std::filesystem::perms::owner_read |
                                                    std::filesystem::perms::owner_write);
        std::shared_ptr<const crypto::Signer> log_key;
        if (args.has("log-key")) {
            log_key = load_signer(args.need("log-key"), args);
        }
        summary = unwrap(ledger::write_backup(session.ledger(), session.provider(), files,
                                              clock.now(), stream, log_key.get()),
                         "writing the backup");
    }
    std::filesystem::rename(temporary, out);
    if (args.json()) {
        print_json(summary_json(summary));
    } else {
        std::println("backed up {} entries, {} checkpoints, {} cosignatures, {} files to {} ({})",
                     summary.entries, summary.checkpoints, summary.cosignatures, summary.files,
                     out.string(),
                     summary.is_signed
                         ? "signed by the log key"
                         : "unsigned: a restore takes only what checkpoints cover, and no files");
        if (std::ranges::any_of(files, [](const auto& f) { return f.path == "vault/vault.key"; })) {
            std::println("it includes the vault private key (encrypted if it was): keep it safe");
        }
    }
    return exit_ok;
}

int cmd_backup_verify(const Args& args) {
    std::ifstream in(args.positional().front(), std::ios::binary);
    if (!in) {
        throw CommandError{"cannot read " + args.positional().front()};
    }
    ledger::MemoryFileSystem fs;
    ledger::SystemClock clock;
    std::uint64_t refused = 0;
    const auto summary = ledger::restore_backup(in, fs, clock, shared_provider(),
                                                [&](const ledger::BackupFile& f) -> Status {
                                                    if (!backup_path_allowed(f.path)) {
                                                        ++refused;
                                                    }
                                                    return {};
                                                });
    if (!summary) {
        return report_restore_failure(args, summary.error(), "reading the backup");
    }
    // Reopening replays the restored log once more, as a fresh node would.
    auto reopened = ledger::Ledger::open(fs, clock, shared_provider());
    auto audit = reopened ? reopened->audit()
                          : Result<ledger::AuditReport>(std::unexpected(reopened.error()));
    if (!audit) {
        return report_restore_failure(args, audit.error(), "auditing the backup");
    }
    if (args.json()) {
        Json j = summary_json(*summary);
        j["ok"] = true;
        j["unknown_files"] = refused;
        print_json(j);
    } else {
        std::println("backup verified ({}): ledger {}, {} entries, {} checkpoints, {} "
                     "cosignatures, {} files, made {}",
                     summary->is_signed ? "signed by the log key" : "unsigned",
                     hex_id(summary->ledger_id), summary->entries, summary->checkpoints,
                     summary->cosignatures, summary->files, format_time(summary->created));
        print_restore_head(*summary);
        if (refused > 0) {
            std::println("{} files would not be restored (unknown paths)", refused);
        }
    }
    return exit_ok;
}

int cmd_backup_restore(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    if (std::filesystem::exists(dir / "statements")) {
        throw CommandError{"a ledger already exists at " + dir.string() +
                           "; restore into a new directory"};
    }
    std::ifstream in(args.positional().front(), std::ios::binary);
    if (!in) {
        throw CommandError{"cannot read " + args.positional().front()};
    }
    const bool existed = std::filesystem::exists(dir);
    std::filesystem::create_directories(dir);
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    ledger::SystemClock clock;
    std::optional<ledger::BackupSummary> restored;
    {
        std::optional<ledger::DirectoryLock> lock;
        lock.emplace(unwrap(ledger::DirectoryLock::acquire(dir), "locking the ledger"));
        auto fs = unwrap(ledger::PosixFileSystem::open_directory(dir), "opening the directory");
        const auto summary = ledger::restore_backup(
            in, fs, clock, shared_provider(), [&](const ledger::BackupFile& f) -> Status {
                if (!backup_path_allowed(f.path)) {
                    return fail(Errc::rejected, "the backup holds a file outside the ledger's");
                }
                const std::filesystem::path target = dir / f.path;
                std::filesystem::create_directories(target.parent_path());
                if (f.path.starts_with("vault")) {
                    std::filesystem::permissions(dir / "vault", std::filesystem::perms::owner_all,
                                                 std::filesystem::perm_options::replace);
                }
                write_file(target, f.content, f.path != "vault/vault.pub");
                return {};
            });
        if (!summary) {
            // Leave nothing half-restored behind (a partial ledger would
            // open fine).
            lock.reset();
            if (!existed) {
                std::filesystem::remove_all(dir);
            } else {
                for (const auto& e : std::filesystem::directory_iterator(dir)) {
                    std::filesystem::remove_all(e.path());
                }
            }
            return report_restore_failure(args, summary.error(), "restoring the backup");
        }
        restored = *summary;
    }
    // Open it as any command would (a full replay), and audit it.
    Session session(dir);
    const auto audit = session.ledger().audit();
    if (!audit) {
        return report_restore_failure(args, audit.error(), "auditing the restored ledger");
    }
    if (args.json()) {
        Json j = summary_json(*restored);
        j["ok"] = true;
        j["entries"] = audit->entries;
        j["checkpoints"] = audit->checkpoints;
        j["cosignatures"] = audit->cosignatures;
        print_json(j);
    } else {
        std::println("restored ledger {} to {}: {} entries, {} checkpoints, audit passed",
                     hex_id(session.ledger().id()), dir.string(), audit->entries,
                     audit->checkpoints);
        print_restore_head(*restored);
    }
    return exit_ok;
}

} // namespace cexchain::cli
