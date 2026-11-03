// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Executors at work (spec section 15 and spec/connectors.md): the
// runtime that finds requests, verifies them in evidence, acts through
// connectors, and answers; its config (connectors and routes), its sealed
// secrets, and its journal; and the first-party connectors it runs.
//
//   executor run, check
//   executor connector add, list, show, remove   (the config file)
//   executor secret set, list, remove             (sealed with HPKE)
//   executor journal list, show                   (what it did, and why)
//   connector webhook, command                    (spoken to over stdin and stdout)

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <format>
#include <iostream>
#include <print>
#include <set>
#include <string>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/node/connector.hpp>
#include <cexchain/node/connectors.hpp>
#include <cexchain/node/executor.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"
#include "requests.hpp"

namespace cexchain::cli {

namespace {

namespace executor = node::executor;
namespace connector = node::connector;

constexpr std::size_t max_secret = 4096;

std::atomic<bool> stop_requested{false};

extern "C" void executor_stop_signal(int /*signal*/) {
    stop_requested.store(true);
}

std::filesystem::path state_of(const Args& args) {
    return args.need("state");
}

std::size_t parse_concurrency(const std::string& text) {
    const auto n = parse_number(text, "--concurrency");
    if (n == 0 || n > executor::max_concurrency) {
        throw UsageError{std::format("--concurrency is 1 to {}", executor::max_concurrency)};
    }
    return static_cast<std::size_t>(n);
}

std::string text_of(ByteView bytes) {
    return std::string(bytes.begin(), bytes.end());
}

executor::Config load_config(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        throw CommandError{"no config at " + path.string() +
                           " (executor add --config-out writes one)"};
    }
    auto config = executor::parse_config(text_of(read_file(path)));
    if (!config) {
        throw CommandError{path.string() + ": " + config.error()};
    }
    return std::move(*config);
}

void save_config(const std::filesystem::path& path, const executor::Config& config) {
    const std::string text = executor::config_text(config);
    write_file(path, as_bytes(std::string_view(text)), true);
}

// ---- secrets ---------------------------------------------------------------

std::filesystem::path secrets_directory(const std::filesystem::path& state) {
    return state / "secrets";
}

std::filesystem::path secrets_key_path(const Args& args, const std::filesystem::path& state) {
    if (const auto key = args.get("secrets-key")) {
        return *key;
    }
    return state / "secrets.key";
}

std::filesystem::path secret_file(const std::filesystem::path& state, const std::string& name) {
    return secrets_directory(state) / (name + ".sealed");
}

void check_secret_name(const std::string& name) {
    if (!connector::is_name(name)) {
        throw UsageError{"a secret's name is 1 to 64 letters, digits, '.', '-', or '_'"};
    }
}

/// The public key secrets are sealed to: made, with its private key, on
/// first use.
Bytes secrets_public_key(const Args& args, const std::filesystem::path& state) {
    const auto pub = state / "secrets.pub";
    if (std::filesystem::exists(pub)) {
        auto key = decode_vault_public_key(read_file(pub));
        if (!key) {
            throw CommandError{pub.string() + " is not a sealing public key"};
        }
        return std::move(*key);
    }
    const auto private_path = secrets_key_path(args, state);
    if (std::filesystem::exists(private_path)) {
        throw CommandError{private_path.string() + " exists but " + pub.string() +
                           " does not: restore it, or move both aside"};
    }
    std::filesystem::create_directories(state);
    std::filesystem::permissions(state, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    const auto key = unwrap(crypto::openssl::HpkeKey::generate(), "making the secrets key");
    save_hpke_key(private_path, key,
                  passphrase(args, "the executor's secrets key " + private_path.string(), true));
    write_file(pub, encode_vault_public_key(key.public_key()), false);
    return Bytes(key.public_key().begin(), key.public_key().end());
}

Bytes seal_secret(const std::string& name, ByteView value, ByteView public_key) {
    const auto sealed =
        unwrap(crypto::openssl::hpke_seal(public_key, as_bytes(executor::secret_info),
                                          as_bytes(std::string_view(name)), value),
               "sealing the secret");
    return executor::encode_sealed_secret(sealed);
}

SecureBytes open_secret(const std::string& name, ByteView file,
                        const crypto::openssl::HpkeKey& key) {
    auto opened = executor::open_sealed_secret(name, file, key);
    if (!opened) {
        throw CommandError{opened.error()};
    }
    return std::move(*opened);
}

/// The secrets a config's connectors name, unsealed.
std::map<std::string, SecureBytes> unseal_secrets(const Args& args,
                                                  const std::filesystem::path& state,
                                                  const executor::Config& config) {
    std::set<std::string> names;
    for (const auto& c : config.connectors) {
        names.insert(c.secrets.begin(), c.secrets.end());
    }
    std::map<std::string, SecureBytes> secrets;
    if (names.empty()) {
        return secrets;
    }
    std::optional<crypto::openssl::HpkeKey> key;
    for (const std::string& name : names) {
        const auto file = secret_file(state, name);
        if (!std::filesystem::exists(file)) {
            throw CommandError{"the secret " + name + " is not set: executor secret set " + name +
                               " --state " + state.string()};
        }
        if (!key) {
            const auto path = secrets_key_path(args, state);
            if (!std::filesystem::exists(path)) {
                throw CommandError{"no secrets key at " + path.string() + "; pass --secrets-key"};
            }
            key.emplace(load_hpke_key(path, args));
        }
        secrets.emplace(name, open_secret(name, read_file(file), *key));
    }
    return secrets;
}

// ---- events ------------------------------------------------------------------

std::string short_hex(const Json& value) {
    return value.is_string() ? value.get<std::string>().substr(0, 12) : std::string("-");
}

/// One event of the runtime, for people.
std::string event_text(const Json& e) {
    const std::string name = e.value("event", std::string("?"));
    std::string line = iso_time(e.value("at", std::uint64_t{0})) + "  " + name;
    if (e.contains("request")) {
        line += "  " + short_hex(e["request"]);
    }
    if (e.contains("kind")) {
        line += " " + e["kind"].get<std::string>();
    }
    for (const char* key :
         {"connector", "copy", "attempt", "status", "reason", "index", "in_ms", "why", "note",
          "message", "granted", "holder", "level", "concurrency", "waiting", "resumed"}) {
        if (e.contains(key) && !e[key].is_null()) {
            const Json& v = e[key];
            line += std::format("  {}={}", key, v.is_string() ? v.get<std::string>() : v.dump());
        }
    }
    return line;
}

// ---- the journal -------------------------------------------------------------

Json entry_json(const executor::JournalEntry& e, bool full) {
    Json o = {{"request", id_json(e.request)},
              {"instance", id_json(e.instance)},
              {"contract", e.contract ? id_json(*e.contract) : Json(nullptr)},
              {"kind", e.kind},
              {"connector", e.connector},
              {"stage", std::string(executor::stage_name(e.stage))},
              {"final", executor::is_final(e.stage)},
              {"attempts", e.attempts},
              {"deadline", e.deadline},
              {"next_at", e.next_at},
              {"first_seen", e.first_seen},
              {"updated", e.updated},
              {"note", e.note},
              {"status", e.status ? Json(*e.status) : Json(nullptr)},
              {"reason", e.reason ? Json(*e.reason) : Json(nullptr)},
              {"index", e.index ? Json(*e.index) : Json(nullptr)},
              {"answered_status", e.answered_status ? Json(*e.answered_status) : Json(nullptr)},
              {"answered_by", e.answered_by ? id_json(*e.answered_by) : Json(nullptr)}};
    if (full) {
        const auto result =
            e.result ? cbor::decode(*e.result) : Result<cbor::Value>(cbor::Value::null());
        const auto result_json = result ? connector::cbor_to_json(*result) : std::nullopt;
        o["result"] = e.result && result_json ? Json::parse(*result_json) : Json(nullptr);
        o["response_bytes"] = e.response ? Json(e.response->size()) : Json(nullptr);
        o["salt"] = e.salt ? hex_json(*e.salt) : Json(nullptr);
        o["digest"] = e.digest ? hex_json(*e.digest) : Json(nullptr);
        o["statement_id"] = e.statement_id ? id_json(*e.statement_id) : Json(nullptr);
        o["head"] = e.head ? Json(*e.head) : Json(nullptr);
    }
    return o;
}

executor::JournalEntry journal_entry(const std::filesystem::path& state, const std::string& text) {
    const executor::Journal journal(state);
    std::vector<executor::JournalEntry> matches;
    for (executor::JournalEntry& e : journal.entries()) {
        if (to_hex(e.request.bytes()).starts_with(text)) {
            matches.push_back(std::move(e));
        }
    }
    if (text.size() < 8 || matches.empty()) {
        throw CommandError{"no request " + text + " in the journal (give 8 or more hex digits)"};
    }
    if (matches.size() > 1) {
        throw CommandError{"the prefix " + text + " matches several requests"};
    }
    return std::move(matches.front());
}

} // namespace

// ---- executor run, check ---------------------------------------------------------

int cmd_executor_run(const Args& args) {
    const executor::Config config = load_config(args.need("config"));
    const std::filesystem::path state = state_of(args);
    const auto signer = load_signer(args.need("as"), args);
    executor::RunOptions options;
    options.server = args.need("server");
    options.client.bearer_token = api_token(args);
    if (!options.client.bearer_token) {
        throw UsageError{"give the executor's API token: --token-file FILE or $CEXCHAIN_TOKEN"};
    }
    if (const auto ca = args.get("ca-file")) {
        options.client.ca_file = *ca;
    }
    options.client.timeout = std::chrono::seconds(60);
    options.state = state;
    options.secrets = unseal_secrets(args, state, config);
    options.channels = executor::process_channels(self_path());
    options.signer = signer.get();
    options.provider = &shared_provider();
    options.tool = std::string("cexchain/") + CEXCHAIN_VERSION;
    options.once = args.has("once");
    if (const auto wait = args.get("wait")) {
        const auto seconds = parse_number(*wait, "--wait");
        if (seconds > 25) {
            throw UsageError{"--wait is 0 to 25 seconds"};
        }
        options.wait = std::chrono::seconds(seconds);
    }
    if (const auto ttl = args.get("lease-ttl")) {
        const auto seconds = parse_number(*ttl, "--lease-ttl");
        if (seconds < 5 || seconds > 300) {
            throw UsageError{"--lease-ttl is 5 to 300 seconds"};
        }
        options.lease_ttl = std::chrono::seconds(seconds);
    }
    if (const auto concurrency = args.get("concurrency")) {
        options.concurrency = parse_concurrency(*concurrency);
    }
    stop_requested.store(false);
    std::signal(SIGINT, executor_stop_signal);
    std::signal(SIGTERM, executor_stop_signal);
    options.stop = &stop_requested;
    const bool json = args.json();
    options.on_event = [json](std::string_view line) {
        if (json) {
            std::println("{}", line);
        } else {
            std::println("{}", event_text(Json::parse(line)));
        }
        std::fflush(stdout);
    };
    const auto ran = executor::run(config, options);
    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
    if (!ran) {
        throw CommandError{ran.error()};
    }
    return exit_ok;
}

int cmd_executor_check(const Args& args) {
    const executor::Config config = load_config(args.need("config"));
    std::map<std::string, SecureBytes> secrets;
    if (args.has("state")) {
        secrets = unseal_secrets(args, state_of(args), config);
    }
    const auto channels = executor::process_channels(self_path());
    Json report = Json::array();
    bool ok = !config.connectors.empty();
    for (const executor::ConnectorConfig& c : config.connectors) {
        std::vector<std::string> logs;
        auto opened = executor::open_connector(
            c, channels, secrets, [&](const connector::Log& log) { logs.push_back(log.message); });
        Json item = {{"name", c.name}, {"type", c.type}, {"kinds", c.kinds}};
        if (opened) {
            item["ok"] = true;
            item["ready"] = {{"name", opened->ready.name}, {"version", opened->ready.version}};
            (void)opened->channel->send(
                connector::encode(connector::ToConnector(connector::Stop{})));
            opened->channel->close();
        } else {
            ok = false;
            item["ok"] = false;
            item["error"] = opened.error();
        }
        report.push_back(std::move(item));
    }
    if (args.json()) {
        print_json({{"ok", ok}, {"connectors", report}});
    } else {
        std::println("config:      {} ({} connector(s); answers as actor {})", args.need("config"),
                     config.connectors.size(), to_hex(config.actor.bytes()).substr(0, 12));
        for (const Json& item : report) {
            if (item["ok"].get<bool>()) {
                std::println("  {}: ready ({} {}), serves {}", item["name"].get<std::string>(),
                             item["ready"]["name"].get<std::string>(),
                             item["ready"]["version"].get<std::string>(), item["kinds"].dump());
            } else {
                std::println("  {}: NOT READY: {}", item["name"].get<std::string>(),
                             item["error"].get<std::string>());
            }
        }
        if (config.connectors.empty()) {
            std::println("  no connectors yet: executor connector add");
        }
    }
    return ok ? exit_ok : exit_failure;
}

// ---- executor connector ---------------------------------------------------------

int cmd_executor_connector_add(const Args& args) {
    const std::filesystem::path path = args.need("config");
    executor::Config config = load_config(path);
    const std::string name = args.positional().front();
    const std::string type = args.need("type");
    Json entry = {{"name", name}, {"type", type}};
    entry["kinds"] = parse_request_kinds(args.need("kinds"), "--kinds");
    if (const auto contracts = args.get("contracts")) {
        Json list = Json::array();
        for (const std::string& c : split(*contracts, ',')) {
            list.push_back(c);
        }
        entry["contracts"] = list;
    }
    if (const auto timeout = args.get("timeout")) {
        entry["timeout"] = parse_number(*timeout, "--timeout");
    }
    if (const auto concurrency = args.get("concurrency")) {
        entry["concurrency"] = parse_concurrency(*concurrency);
    }
    if (const auto secrets = args.get("secrets")) {
        entry["secrets"] = split(*secrets, ',');
    }
    auto refuse = [&](std::initializer_list<const char*> options) {
        for (const char* o : options) {
            if (args.has(o)) {
                throw UsageError{std::format("--{} does not go with --type {}", o, type)};
            }
        }
    };
    if (type == "webhook") {
        refuse({"program", "arg", "connector-config", "secrets"});
        entry["url"] = args.need("url");
        entry["secret"] = args.need("secret");
        if (const auto ca = args.get("ca-file")) {
            entry["ca_file"] = std::filesystem::absolute(*ca).string();
        }
    } else if (type == "command" || type == "program") {
        refuse({"url", "secret", "ca-file"});
        entry["program"] = args.need("program");
        entry["args"] = args.all("arg");
        if (type == "program") {
            entry["config"] = args.has("connector-config")
                                  ? Json::parse(*args.get("connector-config"), nullptr, false)
                                  : Json::object();
            if (!entry["config"].is_object()) {
                throw UsageError{"--connector-config is a JSON object"};
            }
        } else {
            refuse({"connector-config"});
        }
    } else {
        throw UsageError{"--type is webhook, command, or program"};
    }
    Json whole = Json::parse(executor::config_text(config));
    for (const Json& existing : whole["connectors"]) {
        if (existing["name"] == name) {
            throw CommandError{"a connector named " + name + " exists; remove it first"};
        }
    }
    whole["connectors"].push_back(entry);
    auto checked = executor::parse_config(whole.dump());
    if (!checked) {
        throw CommandError{checked.error()};
    }
    save_config(path, *checked);
    if (args.json()) {
        print_json(entry);
    } else {
        std::println("connector {} ({}) added to {}: serves {}", name, type, path.string(),
                     args.need("kinds"));
        const auto& added = checked->connectors.back();
        for (const std::string& secret : added.secrets) {
            std::println("it needs the secret {}: cexchain executor secret set {} --state DIR",
                         secret, secret);
        }
    }
    return exit_ok;
}

int cmd_executor_connector_list(const Args& args) {
    const executor::Config config = load_config(args.need("config"));
    const Json whole = Json::parse(executor::config_text(config));
    if (args.json()) {
        print_json(whole["connectors"]);
        return exit_ok;
    }
    if (config.connectors.empty()) {
        std::println("no connectors");
    }
    for (const auto& c : config.connectors) {
        std::string kinds;
        for (const auto& k : c.kinds) {
            kinds += (kinds.empty() ? "" : ",") + k;
        }
        std::println("{:<16} {:<8} serves {}{} (timeout {} s, {})", c.name, c.type, kinds,
                     c.contracts.empty() ? std::string(" on any contract")
                                         : std::format(" on {} contract(s)", c.contracts.size()),
                     c.timeout.count(),
                     c.concurrency != 0    ? std::format("{} at once", c.concurrency)
                     : c.type == "program" ? std::string("1 at once")
                                           : std::string("as many at once as executor run"));
    }
    return exit_ok;
}

int cmd_executor_connector_show(const Args& args) {
    const executor::Config config = load_config(args.need("config"));
    const std::string name = args.positional().front();
    const Json whole = Json::parse(executor::config_text(config));
    for (const Json& c : whole["connectors"]) {
        if (c["name"] == name) {
            if (args.json()) {
                print_json(c);
            } else {
                for (const auto& [key, value] : c.items()) {
                    std::println("{:<10} {}", key + ":",
                                 value.is_string() ? value.get<std::string>() : value.dump());
                }
            }
            return exit_ok;
        }
    }
    throw CommandError{"no connector named " + name};
}

int cmd_executor_connector_remove(const Args& args) {
    const std::filesystem::path path = args.need("config");
    executor::Config config = load_config(path);
    const std::string name = args.positional().front();
    const auto removed = std::erase_if(
        config.connectors, [&](const executor::ConnectorConfig& c) { return c.name == name; });
    if (removed == 0) {
        throw CommandError{"no connector named " + name};
    }
    save_config(path, config);
    if (args.json()) {
        print_json({{"removed", name}});
    } else {
        std::println("connector {} removed from {}", name, path.string());
    }
    return exit_ok;
}

// ---- executor secret ----------------------------------------------------------------

int cmd_executor_secret_set(const Args& args) {
    const std::filesystem::path state = state_of(args);
    const std::string name = args.positional().front();
    check_secret_name(name);
    std::string value;
    if (const auto file = args.get("from-file")) {
        const Bytes bytes = read_file(*file);
        value.assign(bytes.begin(), bytes.end());
    } else {
        value.assign(std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>());
    }
    // One trailing newline is the file's or the terminal's, not the secret's.
    if (value.ends_with("\r\n")) {
        value.resize(value.size() - 2);
    } else if (value.ends_with('\n')) {
        value.pop_back();
    }
    const SecureBytes secret(Bytes(value.begin(), value.end()));
    secure_wipe(std::span(reinterpret_cast<std::uint8_t*>(value.data()), value.size()));
    if (secret.empty() || secret.size() > max_secret) {
        throw UsageError{"a secret is 1 to 4096 bytes (from --from-file FILE, or stdin)"};
    }
    const Bytes public_key = secrets_public_key(args, state);
    std::filesystem::create_directories(secrets_directory(state));
    std::filesystem::permissions(secrets_directory(state), std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    const bool replaced = std::filesystem::exists(secret_file(state, name));
    write_file(secret_file(state, name), seal_secret(name, secret.view(), public_key), true);
    if (args.json()) {
        print_json({{"name", name}, {"bytes", secret.size()}, {"replaced", replaced}});
    } else {
        std::println("secret {} {} ({} bytes, sealed in {})", name, replaced ? "replaced" : "set",
                     secret.size(), secret_file(state, name).string());
    }
    return exit_ok;
}

int cmd_executor_secret_list(const Args& args) {
    const std::filesystem::path dir = secrets_directory(state_of(args));
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& file : std::filesystem::directory_iterator(dir, ec)) {
        if (file.path().extension() == ".sealed") {
            names.push_back(file.path().stem().string());
        }
    }
    std::ranges::sort(names);
    if (args.json()) {
        print_json(names);
        return exit_ok;
    }
    if (names.empty()) {
        std::println("no secrets");
    }
    for (const std::string& name : names) {
        std::println("{}", name);
    }
    return exit_ok;
}

int cmd_executor_secret_remove(const Args& args) {
    const std::filesystem::path state = state_of(args);
    const std::string name = args.positional().front();
    check_secret_name(name);
    if (!std::filesystem::remove(secret_file(state, name))) {
        throw CommandError{"no secret named " + name};
    }
    if (args.json()) {
        print_json({{"removed", name}});
    } else {
        std::println("secret {} removed", name);
    }
    return exit_ok;
}

// ---- executor journal -----------------------------------------------------------------

int cmd_executor_journal_list(const Args& args) {
    const executor::Journal journal(state_of(args));
    if (args.has("open") && args.has("final")) {
        throw UsageError{"--open and --final contradict each other"};
    }
    Json list = Json::array();
    for (const executor::JournalEntry& e : journal.entries()) {
        const bool final = executor::is_final(e.stage);
        if ((args.has("open") && final) || (args.has("final") && !final)) {
            continue;
        }
        list.push_back(entry_json(e, false));
    }
    if (args.json()) {
        print_json(list);
        return exit_ok;
    }
    if (list.empty()) {
        std::println("the journal is empty");
    }
    for (const Json& e : list) {
        std::string line = std::format("{}  {:<10} {:<10} attempts {}", short_hex(e["request"]),
                                       e["kind"].get<std::string>(), e["stage"].get<std::string>(),
                                       e["attempts"].get<int>());
        if (!e["status"].is_null()) {
            line += "  " + e["status"].get<std::string>();
        }
        if (!e["index"].is_null()) {
            line += std::format("  at #{}", e["index"].get<std::uint64_t>());
        }
        if (!e["note"].get<std::string>().empty()) {
            line += "  (" + e["note"].get<std::string>() + ")";
        }
        std::println("{}", line);
    }
    return exit_ok;
}

int cmd_executor_journal_show(const Args& args) {
    const std::filesystem::path state = state_of(args);
    const executor::JournalEntry e = journal_entry(state, args.positional().front());
    Json o = entry_json(e, true);
    // The digest the answer carries is HASH(salt || response), under the
    // home's hash: check it here, so that the response can be disclosed
    // with proof.
    std::optional<std::string> matched;
    if (e.response && e.salt && e.digest && e.salt->size() == 16) {
        protocol::Nonce salt{};
        std::ranges::copy(*e.salt, salt.begin());
        for (const auto hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
            const auto digest =
                protocol::attachment_commitment(shared_provider(), hash, salt, *e.response);
            if (digest && Bytes(digest->bytes().begin(), digest->bytes().end()) == *e.digest) {
                matched = crypto::name(hash);
            }
        }
    }
    o["digest_checked"] = matched ? Json(*matched) : Json(nullptr);
    if (const auto out = args.get("response-out")) {
        if (!e.response) {
            throw CommandError{"the journal keeps no response for this request"};
        }
        write_file(*out, *e.response, true);
        o["response_file"] = *out;
    }
    if (args.json()) {
        print_json(o);
        return exit_ok;
    }
    for (const char* key :
         {"request", "kind", "instance", "contract", "connector", "stage", "attempts", "status",
          "reason", "result", "index", "answered_status", "answered_by", "note", "response_bytes",
          "salt", "digest", "digest_checked", "response_file"}) {
        if (o.contains(key) && !o[key].is_null() &&
            !(o[key].is_string() && o[key].get<std::string>().empty())) {
            std::println("{:<16} {}", std::string(key) + ":",
                         o[key].is_string() ? o[key].get<std::string>() : o[key].dump());
        }
    }
    return exit_ok;
}

// ---- connector webhook, command -----------------------------------------------------------

namespace {

int serve_stdio(std::string_view name, const connector::PerformerFactory& make) {
    std::signal(SIGPIPE, SIG_IGN);
    connector::LineIo io;
    io.read = []() -> std::optional<std::string> {
        std::string line;
        if (!std::getline(std::cin, line)) {
            return std::nullopt;
        }
        return line;
    };
    io.write = [](std::string_view line) {
        std::cout << line;
        std::cout.flush();
        return static_cast<bool>(std::cout);
    };
    return connector::serve(io, name, CEXCHAIN_VERSION, make);
}

} // namespace

int cmd_connector_webhook(const Args&) {
    return serve_stdio("webhook", connector::make_webhook);
}

int cmd_connector_command(const Args&) {
    return serve_stdio("command", connector::make_command);
}

} // namespace cexchain::cli
