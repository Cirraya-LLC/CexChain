// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's commands (the console itself runs in `serve --console`).

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <format>
#include <iostream>
#include <memory>
#include <optional>
#include <print>
#include <ranges>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include <cexchain/app/peers.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/console/activity.hpp>
#include <cexchain/console/backups.hpp>
#include <cexchain/console/deferred.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/console/people.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/console/settings.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/console/users.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/record_files.hpp>
#include <cexchain/node/server.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"
#include "support.hpp"

// POSIX: the process's environment, for the browser it opens.
extern char** environ;

namespace cexchain::cli {

namespace {

void require_ledger_directory(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir / "statements")) {
        throw CommandError{"no ledger at " + dir.string()};
    }
}

/// The console's people, changed under its lock; `change` may throw.
template <class Change>
void change_people(const std::filesystem::path& state, Change change) {
    std::filesystem::create_directories(state);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(state), "locking the console's users");
    console::People people;
    try {
        people = console::load_people(state);
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
    change(people);
    console::save_people(state, people);
}

/// The link that opens an invitation: the running console's address (or
/// --url), then the code in the fragment, which browsers never send.
std::string invitation_link(const Args& args, const std::filesystem::path& state,
                            const std::string& code) {
    std::string base;
    if (const auto url = args.get("url")) {
        base = *url;
    } else if (std::filesystem::exists(state / "url")) {
        const Bytes bytes = app::read_file(state / "url");
        base.assign(bytes.begin(), bytes.end());
        while (!base.empty() && (base.back() == '\n' || base.back() == '\r')) {
            base.pop_back();
        }
    } else {
        throw CommandError{"no console address: start it (serve --console), or pass --url"};
    }
    if (!base.ends_with('/')) {
        base += '/';
    }
    if (!base.ends_with("/console/")) {
        base += "console/";
    }
    return base + "#/enroll/" + code;
}

void print_invitation(const Args& args, const std::string& link,
                      const console::Invitation& invitation, std::string_view who) {
    if (args.json()) {
        print_json({{"link", link},
                    {"invitation", invitation.id},
                    {"user", invitation.user},
                    {"role", console::name_of(invitation.role)},
                    {"expires", format_time(invitation.expires)}});
        return;
    }
    std::println("{}: open this link once, by {} (keep it private):", who,
                 format_time(invitation.expires));
    std::println("{}", link);
}

} // namespace

int cmd_console_setup_link(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    ledger::SystemClock clock;
    ledger::SystemEntropy entropy;
    auto [code, invitation] =
        console::make_invitation(shared_provider(), entropy, "", console::Role::owner, clock.now(),
                                 console::setup_link_lifetime);
    const std::string link = invitation_link(args, state, code);
    change_people(state, [&](console::People& people) {
        if (people.has_owner()) {
            throw CommandError{"the console has an owner; invite people with console user add"};
        }
        // One setup link at a time: a new one replaces any before.
        std::erase_if(people.invitations,
                      [](const console::Invitation& i) { return i.user.empty(); });
        people.invitations.push_back(invitation);
    });
    print_invitation(args, link, invitation, "set up the console as its owner");
    return exit_ok;
}

int cmd_console_session_list(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    std::vector<console::PublishedSession> sessions;
    try {
        sessions = console::published_sessions(console::state_directory(dir));
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
    if (args.json()) {
        Json list = Json::array();
        for (const auto& s : sessions) {
            list.push_back({{"id", s.id},
                            {"user", s.user},
                            {"created", format_time(s.created)},
                            {"ends_by", format_time(s.created + console::session_lifetime)}});
        }
        print_json(list);
        return exit_ok;
    }
    if (sessions.empty()) {
        std::println("no console sessions (signing in to the console begins one)");
    }
    for (const auto& s : sessions) {
        std::println("{}  {:<24} since {}", s.id, s.user, format_time(s.created));
    }
    return exit_ok;
}

int cmd_console_session_revoke(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::string id = args.positional().front();
    const std::filesystem::path state = console::state_directory(dir);
    try {
        const auto sessions = console::published_sessions(state);
        if (std::ranges::find(sessions, id, &console::PublishedSession::id) == sessions.end()) {
            throw CommandError{"no console session " + id + " (console session list)"};
        }
        console::request_revocation(state, id);
    } catch (const CommandError&) {
        throw;
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
    if (args.json()) {
        print_json({{"revoked", id}});
    } else {
        std::println("revoked console session {} (the console ends it at its next request)", id);
    }
    return exit_ok;
}

} // namespace cexchain::cli

namespace cexchain::cli {

namespace {

console::Role role_option(const Args& args, console::Role fallback) {
    const auto text = args.get("role");
    if (!text) {
        return fallback;
    }
    const auto role = console::parse_role(*text);
    if (!role) {
        throw UsageError{"--role is owner, admin, member, or viewer"};
    }
    return *role;
}

console::People read_people(const std::filesystem::path& state) {
    try {
        return console::load_people(state);
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
}

Json user_json(const console::User& user) {
    Json passkeys = Json::array();
    for (const auto& p : user.passkeys) {
        passkeys.push_back({{"label", p.label ? Json(*p.label) : Json()},
                            {"rp_id", p.rp_id},
                            {"credential_id", to_base64url(p.credential_id)}});
    }
    return {{"name", user.name},
            {"role", console::name_of(user.role)},
            {"created", format_time(user.created)},
            {"passkeys", passkeys},
            {"actor", user.actor.empty() ? Json() : Json(user.actor)},
            {"key", user.key.empty() ? Json() : Json(user.key)}};
}

std::size_t owners(const console::People& people) {
    return static_cast<std::size_t>(
        std::ranges::count(people.users, console::Role::owner, &console::User::role));
}

} // namespace

int cmd_console_user_add(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::string name = args.positional().front();
    if (!console::valid_user_name(name)) {
        throw UsageError{"a name is 1 to 64 letters, digits, spaces, '.', '_', or '-'"};
    }
    const std::filesystem::path state = console::state_directory(dir);
    const console::People current = read_people(state);
    const console::User* existing = current.find(name);
    const console::Role role = role_option(args, existing ? existing->role : console::Role::member);
    if (existing && args.has("role") && role != existing->role) {
        throw CommandError{name +
                           " uses the console already: change the role with console user role"};
    }
    ledger::SystemClock clock;
    ledger::SystemEntropy entropy;
    auto [code, invitation] =
        console::make_invitation(shared_provider(), entropy, name, role, clock.now());
    const std::string link = invitation_link(args, state, code);
    change_people(state,
                  [&](console::People& people) { people.invitations.push_back(invitation); });
    print_invitation(args, link, invitation,
                     existing ? "add a passkey for " + name : "invite " + name);
    return exit_ok;
}

int cmd_console_user_list(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const console::People people = read_people(console::state_directory(dir));
    ledger::SystemClock clock;
    const auto now = clock.now();
    if (args.json()) {
        Json users = Json::array();
        for (const auto& u : people.users) {
            users.push_back(user_json(u));
        }
        Json invitations = Json::array();
        for (const auto& i : people.invitations) {
            if (i.expires > now) {
                invitations.push_back({{"id", i.id},
                                       {"user", i.user},
                                       {"role", console::name_of(i.role)},
                                       {"expires", format_time(i.expires)}});
            }
        }
        print_json({{"users", users}, {"invitations", invitations}});
        return exit_ok;
    }
    if (people.users.empty()) {
        std::println("no console users (console setup-link makes the owner's link)");
    }
    for (const auto& u : people.users) {
        std::println("{:<24} {:<7} {} passkey{}", u.name, console::name_of(u.role),
                     u.passkeys.size(), u.passkeys.size() == 1 ? "" : "s");
    }
    for (const auto& i : people.invitations) {
        if (i.expires > now) {
            std::println("{:<24} {:<7} invited, until {}", i.user.empty() ? "(setup)" : i.user,
                         console::name_of(i.role), format_time(i.expires));
        }
    }
    return exit_ok;
}

int cmd_console_user_show(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const console::People people = read_people(console::state_directory(dir));
    const std::string name = args.positional().front();
    const console::User* user = people.find(name);
    if (user == nullptr) {
        throw CommandError{"no console user named " + name};
    }
    if (args.json()) {
        print_json(user_json(*user));
        return exit_ok;
    }
    std::println("{}: {}, since {}", user->name, console::name_of(user->role),
                 format_time(user->created));
    for (const auto& p : user->passkeys) {
        std::println("  passkey {} for {} ({})", p.label.value_or("(no label)"), p.rp_id,
                     to_base64url(p.credential_id).substr(0, 12));
    }
    return exit_ok;
}

int cmd_console_user_role(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::string name = args.positional()[0];
    const auto role = console::parse_role(args.positional()[1]);
    if (!role) {
        throw UsageError{"a role is owner, admin, member, or viewer"};
    }
    change_people(console::state_directory(dir), [&](console::People& people) {
        console::User* user = people.find(name);
        if (user == nullptr) {
            throw CommandError{"no console user named " + name};
        }
        if (user->role == console::Role::owner && *role != console::Role::owner &&
            owners(people) == 1) {
            throw CommandError{name + " is the console's only owner"};
        }
        user->role = *role;
    });
    if (args.json()) {
        print_json({{"user", name}, {"role", console::name_of(*role)}});
    } else {
        std::println("{} is now {} (from the next request)", name, console::name_of(*role));
    }
    return exit_ok;
}

int cmd_console_user_revoke(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::string name = args.positional().front();
    std::size_t invitations = 0;
    bool was_user = false;
    change_people(console::state_directory(dir), [&](console::People& people) {
        const console::User* user = people.find(name);
        if (user != nullptr && user->role == console::Role::owner && owners(people) == 1) {
            throw CommandError{name + " is the console's only owner"};
        }
        was_user =
            std::erase_if(people.users, [&](const console::User& u) { return u.name == name; }) > 0;
        invitations = std::erase_if(people.invitations,
                                    [&](const console::Invitation& i) { return i.user == name; });
        if (!was_user && invitations == 0) {
            throw CommandError{"no console user or invitation named " + name};
        }
    });
    if (args.json()) {
        print_json({{"revoked", name}, {"user", was_user}, {"invitations", invitations}});
    } else {
        std::println("revoked {}{} (their sessions end at their next request)", name,
                     invitations > 0 ? " and their invitations" : "");
    }
    return exit_ok;
}

namespace {

/// The first line of a small file of the console's, if it exists.
std::optional<std::string> state_line(const std::filesystem::path& file) {
    if (!std::filesystem::exists(file)) {
        return std::nullopt;
    }
    const Bytes bytes = app::read_file(file);
    std::string line(bytes.begin(), bytes.end());
    line = line.substr(0, line.find('\n'));
    return line;
}

/// The running console's process, if its pid file names a live one.
std::optional<pid_t> running_console(const std::filesystem::path& state) {
    const auto line = state_line(state / "pid");
    if (!line) {
        return std::nullopt;
    }
    pid_t pid = 0;
    try {
        pid = static_cast<pid_t>(std::stol(*line));
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (pid <= 0 || (::kill(pid, 0) != 0 && errno == ESRCH)) {
        return std::nullopt;
    }
    return pid;
}

} // namespace

namespace {

std::string unlock_secret(const std::string& file);

/// Opens `target` (a URL or a file) in the person's browser; false if this
/// computer has no opener.
bool open_in_browser(const std::string& target) {
#if defined(__APPLE__)
    const char* opener = "open";
#else
    const char* opener = "xdg-open";
#endif
    std::string argument = target;
    std::vector<char*> argv{const_cast<char*>(opener), argument.data(), nullptr};
    pid_t child = 0;
    if (::posix_spawnp(&child, opener, nullptr, nullptr, argv.data(), environ) != 0) {
        return false;
    }
    int status = 0;
    ::waitpid(child, &status, 0);
    return true;
}

/// A person's console: the console at once, the ledger's API once the first
/// run has made the ledger or the console is unlocked (DeferredApi).
int run_person_console(const Args& args, const std::filesystem::path& dir,
                       const std::filesystem::path& state, std::uint16_t port, bool first_run,
                       console::KeyStore& keys) {
    if (const auto file = args.get("unlock-file")) {
        if (!keys.unlock({console::SlotKind::passphrase, {}}, unlock_secret(*file))) {
            throw UsageError{"--unlock-file does not unlock the console's keys"};
        }
    }
    std::optional<console::Origin> public_origin;
    if (const auto public_url = args.get("public-url")) {
        auto parsed = console::parse_origin(*public_url);
        if (!parsed) {
            throw UsageError{std::format("--public-url: {}", parsed.error().detail)};
        }
        public_origin = std::move(*parsed);
    }
    // Serving TLS itself (otherwise a proxy does, or it is on localhost).
    if (args.has("tls-cert") != args.has("tls-key")) {
        throw UsageError{"--tls-cert and --tls-key go together"};
    }
    if (args.has("tls-cert") && (!public_origin || public_origin->scheme != "https")) {
        throw UsageError{"--tls-cert serves an https --public-url"};
    }
    ledger::SystemClock clock;
    ledger::SystemEntropy entropy;
    console::Sessions sessions(state, shared_provider(), clock, entropy);
    auto web = std::make_shared<console::Console>(console::Services{
        state, &shared_provider(), &clock, &entropy, &sessions, &keys, console_compiler()});
    node::ApiOptions base;
    base.directory = dir;
    base.checkpoint_interval = std::chrono::seconds(60);
    base.version = CEXCHAIN_VERSION;
    base.console = [web](const node::http::Request& r, auto respond) {
        web->handle(r, std::move(respond));
    };
    auto deferred = std::make_shared<console::DeferredApi>(web, [&keys, base, web] {
        node::ApiOptions options = base;
        // The console's witness of its parties' ledgers.
        options.witness = [web](ByteView request) {
            return web->witness_cosign(request);
        };
        // The log key signs checkpoints, receipts, and evidence once unlocked.
        if (std::ranges::any_of(keys.keys(), [](const auto& k) { return k.name == "log"; })) {
            options.log_keys.push_back(
                std::make_shared<crypto::openssl::KeyPair>(keys.open("log")));
        }
        // The console's machine, set up at the first run: the ledger's
        // registrar and keeper while the console is unlocked.
        if (std::ranges::any_of(
                keys.keys(), [](const auto& k) { return k.name == console::machine_key_name; })) {
            auto machine =
                std::make_shared<crypto::openssl::KeyPair>(keys.open(console::machine_key_name));
            options.registrar = machine;
            options.keeper = machine;
        }
        return unwrap(node::LedgerApi::open(options, shared_provider()), "opening the ledger");
    });
    web->set_on_ready([weak = std::weak_ptr(deferred)] {
        if (auto d = weak.lock()) {
            d->open_now();
        }
    });
    if (!first_run && keys.unlocked()) {
        deferred->open_now();
    }
    // The parties' registrars, asked for calls waiting on this ledger.
    web->start_polling();

    node::ServerOptions server_options;
    server_options.host = "127.0.0.1";
    server_options.port = port;
    if (const auto cert = args.get("tls-cert")) {
        server_options.tls_certificate = *cert;
        server_options.tls_private_key = *args.get("tls-key");
    }
    // The console's uploads: a file kept with a record, 16 MiB at most.
    server_options.limits.max_body = node::max_record_file + 64 * 1024;
    server_options.access_log = args.has("quiet") ? nullptr : &std::cerr;
    std::optional<node::Server> listening;
    for (unsigned tried = 0;; ++tried) {
        listening.emplace(*deferred, server_options);
        auto status = listening->listen();
        if (status) {
            break;
        }
        if (args.has("port") || tried + 1 >= 20) {
            unwrap(std::move(status), "starting the console");
        }
        listening.reset();
        ++server_options.port;
    }
    node::Server& server = *listening;
    const std::uint16_t got = server.port();
    // Its own names on this computer, or, behind a proxy, its public URL only.
    if (public_origin) {
        web->set_origins({*public_origin});
    } else {
        web->set_origins(console::loopback_origins(got));
    }
    const std::string url = public_origin ? public_origin->text() + "/console/"
                                          : std::format("http://localhost:{}/console/", got);
    std::filesystem::create_directories(state);
    app::write_file(state / "port", as_bytes(std::to_string(got) + "\n"), true);
    app::write_file(state / "url", as_bytes(url + "\n"), true);
    app::write_file(state / "pid", as_bytes(std::to_string(::getpid()) + "\n"), true);

    // The first run: a setup link for whoever sets it up, in a private file
    // and a page that opens it, never on the command line or in a log.
    std::optional<std::filesystem::path> opener;
    if (first_run) {
        auto [code, invitation] =
            console::make_invitation(shared_provider(), entropy, "", console::Role::owner,
                                     clock.now(), console::setup_link_lifetime);
        change_people(state, [&](console::People& people) {
            std::erase_if(people.invitations,
                          [](const console::Invitation& i) { return i.user.empty(); });
            people.invitations.push_back(invitation);
        });
        const std::string link = url + "#/enroll/" + code;
        app::write_file(state / "setup-link", as_bytes(link + "\n"), true);
        const std::string page =
            "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" "
            "content=\"0; url=" +
            link + "\"><title>CexChain</title>\n";
        app::write_file(state / "setup.html", as_bytes(page), true);
        opener = state / "setup.html";
    }
    const bool no_browser = args.has("no-browser") || std::getenv("CEXCHAIN_NO_BROWSER") != nullptr;
    if (args.json()) {
        print_json(
            {{"url", url},
             {"port", got},
             {"setup", first_run},
             {"setup_page", opener ? Json(opener->string()) : Json()},
             {"keys", keys.initialized() ? (keys.unlocked() ? "unlocked" : "locked") : "none"}});
    } else if (first_run) {
        std::println("console: {} (setting up: {})", url,
                     !no_browser && open_in_browser(opener->string())
                         ? "your browser opened the setup page"
                         : "open " + opener->string() + " in your browser, within an hour");
    } else {
        std::println("console: {}{}", url,
                     keys.unlocked() ? "" : " (locked: sign in with your passkey to unlock it)");
    }
    if (first_run && args.json() && !no_browser) {
        open_in_browser(opener->string());
    }
    std::fflush(stdout);
    server.run();
    std::error_code ignored;
    std::filesystem::remove(state / "pid", ignored);
    return exit_ok;
}

} // namespace

int cmd_console_run(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    const std::filesystem::path state = console::state_directory(dir);
    // A directory with no ledger yet: the first run makes it.
    const bool first_run = !console::has_ledger(dir);
    if (first_run) {
        std::filesystem::create_directories(dir);
    }
    if (const auto pid = running_console(state)) {
        throw CommandError{
            std::format("the console runs already (process {}): console open", *pid)};
    }
    std::uint64_t port = 7470;
    if (const auto asked = args.get("port")) {
        port = parse_number(*asked, "--port");
    } else if (const auto remembered = state_line(state / "port")) {
        port = parse_number(*remembered, "the remembered port");
    }
    if (port == 0 || port > 65535) {
        throw UsageError{"--port is 1 to 65535"};
    }
    console::KeyStore keys(state);
    const bool sealed_log =
        keys.initialized() &&
        std::ranges::any_of(keys.keys(), [](const auto& k) { return k.name == "log"; });
    if (first_run || sealed_log) {
        return run_person_console(args, dir, state, static_cast<std::uint16_t>(port), first_run,
                                  keys);
    }
    // A ledger whose keys are files (as the README's quick start makes it).
    ServeDefaults defaults;
    defaults.listen = std::format("127.0.0.1:{}", port);
    defaults.console = true;
    // The next free port if this one is taken, unless one was asked for.
    defaults.port_fallback = args.has("port") ? 1 : 20;
    defaults.on_listening = [state](std::uint16_t got) {
        std::filesystem::create_directories(state);
        app::write_file(state / "port", as_bytes(std::to_string(got) + "\n"), true);
        app::write_file(state / "pid", as_bytes(std::to_string(::getpid()) + "\n"), true);
    };
    const int code = serve(args, defaults);
    std::error_code ignored;
    std::filesystem::remove(state / "pid", ignored);
    return code;
}

int cmd_console_status(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    const std::filesystem::path state = console::state_directory(dir);
    const auto pid = running_console(state);
    const auto url = state_line(state / "url");
    const console::People people = read_people(state);
    std::size_t sessions = 0;
    try {
        sessions = console::published_sessions(state).size();
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
    if (args.json()) {
        print_json({{"running", pid.has_value()},
                    {"directory", dir.string()},
                    {"pid", pid ? Json(*pid) : Json()},
                    {"url", pid && url ? Json(*url) : Json()},
                    {"users", people.users.size()},
                    {"owner", people.has_owner()},
                    {"sessions", pid ? sessions : 0}});
        return exit_ok;
    }
    if (pid) {
        std::println("the console runs (process {}) at {}", *pid, url.value_or("(unknown)"));
        std::println("{} session{}", sessions, sessions == 1 ? "" : "s");
    } else {
        std::println("the console is not running (console run)");
    }
    std::println("{} user{}{}", people.users.size(), people.users.size() == 1 ? "" : "s",
                 people.has_owner() ? "" : " and no owner yet (console setup-link)");
    return exit_ok;
}

int cmd_console_stop(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    const std::filesystem::path state = console::state_directory(dir);
    const auto pid = running_console(state);
    if (!pid) {
        throw CommandError{"the console is not running"};
    }
    if (::kill(*pid, SIGTERM) != 0) {
        throw CommandError{std::format("could not stop process {}", *pid)};
    }
    // A graceful stop finishes what it was writing; wait for it.
    for (int i = 0; i < 300 && running_console(state); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (running_console(state)) {
        throw CommandError{std::format("process {} is still stopping", *pid)};
    }
    if (args.json()) {
        print_json({{"stopped", *pid}});
    } else {
        std::println("stopped the console (process {})", *pid);
    }
    return exit_ok;
}

namespace {

/// Starts `console run` for `dir` in the background, its own session, its
/// output in the console's log, and waits until it answers (15 s at most).
void start_console_process(const std::filesystem::path& dir, const std::filesystem::path& state) {
    std::filesystem::create_directories(state);
    const std::string program = self_path();
    const std::string log = (state / "console.log").string();
    std::vector<std::string> words{program, "console", "run", "--ledger", dir.string(), "--quiet"};
    std::vector<char*> argv;
    for (std::string& w : words) {
        argv.push_back(w.data());
    }
    argv.push_back(nullptr);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, 1, log.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    posix_spawn_file_actions_adddup2(&actions, 1, 2);
    posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSID);
    // The person's browser opens from here, not from the background process.
    std::vector<std::string> environment_text{"CEXCHAIN_NO_BROWSER=1"};
    std::vector<char*> envp;
    for (char** e = environ; *e != nullptr; ++e) {
        if (!std::string_view(*e).starts_with("CEXCHAIN_NO_BROWSER=")) {
            envp.push_back(*e);
        }
    }
    envp.push_back(environment_text.front().data());
    envp.push_back(nullptr);
    pid_t child = 0;
    const int spawned =
        ::posix_spawn(&child, program.c_str(), &actions, &attributes, argv.data(), envp.data());
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    if (spawned != 0) {
        throw CommandError{"cannot start the console: " + program};
    }
    for (int i = 0; i < 150; ++i) {
        if (running_console(state) &&
            (state_line(state / "url") || std::filesystem::exists(state / "setup.html"))) {
            return;
        }
        int status = 0;
        if (::waitpid(child, &status, WNOHANG) == child) {
            throw CommandError{"the console stopped at once: see " + log};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // namespace

int cmd_console_open(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    const std::filesystem::path state = console::state_directory(dir);
    if (!running_console(state)) {
        // Started in the background, as a launcher does, then opened.
        start_console_process(dir, state);
    }
    // A first run opens its setup page; otherwise the console.
    if (!console::has_ledger(dir) && std::filesystem::exists(state / "setup.html") &&
        !args.json() && !args.has("print")) {
        if (!open_in_browser((state / "setup.html").string())) {
            std::println("open {} in your browser", (state / "setup.html").string());
        }
        return exit_ok;
    }
    const auto url = state_line(state / "url");
    if (!running_console(state) || !url) {
        throw CommandError{"the console did not start: see " + (state / "console.log").string()};
    }
    if (args.json() || args.has("print")) {
        if (args.json()) {
            print_json({{"url", *url}});
        } else {
            std::println("{}", *url);
        }
        return exit_ok;
    }
    if (!open_in_browser(*url)) {
        std::println("open {} in your browser", *url);
        return exit_ok;
    }
    std::println("opened {}", *url);
    return exit_ok;
}

namespace {

/// The first line of an unlock file: a passphrase slot's secret.
std::string unlock_secret(const std::string& file) {
    const Bytes bytes = app::read_file(file);
    std::string text(bytes.begin(), bytes.end());
    text = text.substr(0, text.find('\n'));
    if (text.size() < 8) {
        throw UsageError{"the unlock file " + file + " holds fewer than 8 characters"};
    }
    return text;
}

Json slot_json(const console::Slot& slot) {
    return {{"kind", console::name_of(slot.kind)},
            {"id", slot.id.empty() ? Json() : Json(slot.id)}};
}

} // namespace

int cmd_console_key_init(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    console::KeyStore store(console::state_directory(dir));
    if (store.initialized()) {
        throw CommandError{"the console's keys are set up already (console key list)"};
    }
    const std::optional<std::string> unlock =
        args.get("unlock-file") ? std::optional(unlock_secret(*args.get("unlock-file")))
                                : std::nullopt;
    ledger::SystemEntropy entropy;
    const std::string code = store.initialize(entropy);
    if (unlock) {
        store.add_slot({console::SlotKind::passphrase, {}}, *unlock);
    }
    if (args.json()) {
        Json slots = Json::array();
        for (const auto& slot : store.slots()) {
            slots.push_back(slot_json(slot));
        }
        print_json({{"recovery_code", code}, {"slots", slots}});
        return exit_ok;
    }
    std::println("The console's recovery code (shown once: write it down and keep it safe):");
    std::println("");
    std::println("    {}", code);
    std::println("");
    std::println("It unlocks the console's keys if every passkey and passphrase is lost.");
    if (unlock) {
        std::println("The unlock file opens them too (console run --unlock-file).");
    }
    return exit_ok;
}

int cmd_console_setup(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    const std::filesystem::path state = console::state_directory(dir);
    if (console::has_ledger(dir)) {
        throw CommandError{"this directory holds a ledger already (console run opens it)"};
    }
    if (const auto pid = running_console(state)) {
        throw CommandError{std::format(
            "the console runs on this directory (process {}): stop it first, or set it up there",
            *pid)};
    }
    const std::string file = args.need("credential");
    const auto passkey =
        unwrap(protocol::decode_presence_credential(read_file(file)), "reading " + file);
    const std::optional<std::string> unlock =
        args.get("unlock-file") ? std::optional(unlock_secret(*args.get("unlock-file")))
                                : std::nullopt;
    std::filesystem::create_directories(state);
    console::KeyStore keys(state);
    ledger::SystemEntropy entropy;
    console::FirstRun run;
    try {
        run =
            console::set_up({dir, args.need("name"), passkey, std::nullopt, unlock}, keys, entropy);
    } catch (const std::invalid_argument& e) {
        throw UsageError{e.what()};
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
    if (args.json()) {
        print_json({{"ledger", id_json(run.ledger)},
                    {"owner", id_json(run.owner)},
                    {"user", args.need("name")},
                    {"recovery_code", run.recovery_code}});
        return exit_ok;
    }
    std::println("made the ledger {} with its owner {}, who signs in with the passkey in {}",
                 hex_id(run.ledger), args.need("name"), file);
    std::println("");
    std::println("The console's recovery code (shown once: write it down and keep it safe):");
    std::println("");
    std::println("    {}", run.recovery_code);
    std::println("");
    std::println("It unlocks the console's keys, and registers a new passkey, if every passkey is "
                 "lost.");
    std::println("Start the console with: console run{}", unlock ? " --unlock-file FILE" : "");
    return exit_ok;
}

int cmd_console_key_import(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::string name = args.positional()[0];
    if (!console::valid_key_name(name)) {
        throw UsageError{"a key's name is 1 to 64 lower-case letters, digits, '.', '_', or '-'"};
    }
    console::KeyStore store(console::state_directory(dir));
    if (!store.initialized()) {
        throw CommandError{"the console's keys are not set up (console key init)"};
    }
    if (name == "vault") {
        // The ledger's vault key: it opens records' private data and kept files.
        auto vault = load_hpke_key(args.positional()[1], args);
        const std::filesystem::path pub = dir / "vault" / "vault.pub";
        const auto expected =
            std::filesystem::exists(pub) ? decode_vault_public_key(read_file(pub)) : std::nullopt;
        if (!expected || !std::ranges::equal(*expected, vault.public_key())) {
            throw CommandError{"this is not the ledger's vault key"};
        }
        store.seal_vault_key(vault);
        if (args.json()) {
            print_json({{"imported", "vault"}, {"algorithm", "x25519"}});
        } else {
            std::println("sealed the ledger's vault key in the console; the file itself is "
                         "unchanged");
        }
        return exit_ok;
    }
    const auto key = load_key(args.positional()[1], args);
    store.seal(name, key);
    if (args.json()) {
        print_json({{"imported", name}, {"public_key", app::public_key_json(key.public_key())}});
    } else {
        std::println("sealed the key {} in the console ({}); the file itself is unchanged", name,
                     crypto::name(key.algorithm()));
    }
    return exit_ok;
}

int cmd_console_key_list(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    console::KeyStore store(console::state_directory(dir));
    std::vector<console::SealedKeyInfo> keys;
    try {
        keys = store.keys();
    } catch (const std::exception& e) {
        throw CommandError{e.what()};
    }
    if (args.json()) {
        Json slots = Json::array();
        for (const auto& slot : store.slots()) {
            slots.push_back(slot_json(slot));
        }
        Json list = Json::array();
        for (const auto& k : keys) {
            list.push_back({{"name", k.name}, {"public_key", app::public_key_json(k.public_key)}});
        }
        print_json({{"set_up", store.initialized()},
                    {"slots", slots},
                    {"keys", list},
                    {"vault_key", store.vault_public_key().has_value()}});
        return exit_ok;
    }
    if (!store.initialized()) {
        std::println("the console's keys are not set up (console key init)");
        return exit_ok;
    }
    for (const auto& slot : store.slots()) {
        std::println("slot: {}{}", console::name_of(slot.kind),
                     slot.id.empty() ? "" : " " + slot.id.substr(0, 12));
    }
    if (keys.empty()) {
        std::println("no keys sealed (console key import NAME FILE)");
    }
    for (const auto& k : keys) {
        std::println("key: {:<24} {}", k.name, crypto::name(k.public_key.algorithm));
    }
    if (store.vault_public_key()) {
        std::println("key: {:<24} {}", "vault", "X25519 (the ledger's vault key)");
    }
    return exit_ok;
}

int cmd_console_key_remove(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::string name = args.positional().front();
    console::KeyStore store(console::state_directory(dir));
    if (name == "vault" ? !store.remove_vault_key() : !store.remove_key(name)) {
        throw CommandError{"the console holds no key named " + name};
    }
    if (args.json()) {
        print_json({{"removed", name}});
    } else {
        std::println("removed the key {} from the console", name);
    }
    return exit_ok;
}

int cmd_console_user_link(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    const std::string name = args.positional().front();
    const std::string key_name = args.need("key");
    console::KeyStore store(state);
    std::optional<crypto::PublicKey> key;
    for (const auto& k : store.keys()) {
        if (k.name == key_name) {
            key = k.public_key;
        }
    }
    if (!key) {
        throw CommandError{"the console holds no key named " + key_name + " (console key list)"};
    }
    Session session(dir);
    const protocol::Id actor = session.actor_id(args.need("actor"));
    const protocol::ActorState* a = session.state().actor(actor);
    if (a == nullptr || a->revoked) {
        throw CommandError{"no live actor " + hex_id(actor)};
    }
    if (a->kind != protocol::ActorKind::person) {
        throw CommandError{"a console user acts as a person: machines act without one"};
    }
    if (a->key != *key) {
        throw CommandError{"the key " + key_name + " is not this person's current key"};
    }
    std::size_t registered = 0;
    std::size_t passkeys = 0;
    change_people(state, [&](console::People& people) {
        console::User* user = people.find(name);
        if (user == nullptr) {
            throw CommandError{"no console user named " + name};
        }
        user->actor = to_hex(actor.bytes());
        user->key = key_name;
        passkeys = user->passkeys.size();
        for (const auto& p : user->passkeys) {
            registered +=
                std::ranges::any_of(
                    a->presence, [&](const auto& c) { return c.credential_id == p.credential_id; })
                    ? 1U
                    : 0U;
        }
    });
    if (args.json()) {
        print_json({{"user", name},
                    {"actor", id_json(actor)},
                    {"key", key_name},
                    {"passkeys_on_ledger", registered},
                    {"passkeys", passkeys}});
        return exit_ok;
    }
    std::println("{} now acts as {} with the key {}", name, a->display_name, key_name);
    if (registered < passkeys) {
        std::println("{} of {}'s passkeys are registered on the ledger; for approvals to prove "
                     "presence, register them: console user passkeys \"{}\" --out DIR, then "
                     "actor set-presence {} --add --credential FILE",
                     registered, name, name, hex_id(actor));
    }
    return exit_ok;
}

int cmd_console_user_approve(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    const std::string name = args.positional().front();
    const console::People people = read_people(state);
    const console::User* user = people.find(name);
    if (user == nullptr) {
        throw CommandError{"no console user named " + name};
    }
    if (user->role == console::Role::viewer) {
        throw CommandError{"a viewer reads and verifies: they act as no one"};
    }
    if (!user->actor.empty()) {
        throw CommandError{name + " acts as someone on the ledger already (console user show)"};
    }
    if (user->passkeys.empty() || user->passkeys.size() > 16) {
        throw CommandError{name + " has no passkey to register yet (or more than 16)"};
    }
    // What they may do: their role's default, or the words given.
    console::Permissions may = console::default_permissions(console::name_of(user->role));
    if (const auto words = args.get("may")) {
        may = {};
        for (const std::string& w : split(*words, ',')) {
            if (w == "register") {
                may.register_documents = true;
            } else if (w == "endorse") {
                may.endorse = true;
            } else if (w == "revoke") {
                may.revoke = true;
            } else if (w == "act") {
                may.act = true;
            } else if (w == "rules") {
                may.rules = true;
            } else if (w == "people") {
                may.people = true;
            } else if (!w.empty()) {
                throw UsageError{"--may takes register, endorse, revoke, act, rules, people"};
            }
        }
    }
    if (const auto kinds = args.get("kinds")) {
        may.kinds = split(*kinds, ',');
        std::erase(*may.kinds, std::string());
    }
    if (const auto contracts = args.get("contracts")) {
        may.contracts = std::vector<protocol::Id>{};
        for (const std::string& c : split(*contracts, ',')) {
            if (!c.empty()) {
                may.contracts->push_back(app::full_id(c, "a contract"));
            }
        }
    }
    if (const auto until = args.get("until")) {
        may.until = parse_time(*until);
    }
    if (may.people && user->role != console::Role::owner && user->role != console::Role::admin) {
        throw UsageError{"only owners and admins manage people (--may people)"};
    }
    protocol::Scope scope;
    try {
        scope = console::scope_of(may);
    } catch (const std::invalid_argument& e) {
        throw UsageError{e.what()};
    }
    console::KeyStore keys(state);
    if (!keys.initialized()) {
        throw CommandError{"the console's keys are not set up (console key init)"};
    }
    auto key = unwrap(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "a key");
    // Their actor, their passkeys as its presence, and what they may do.
    Session session(dir);
    session.require_primary();
    const protocol::Id actor = session.submit(
        args, protocol::ActorRegisterBody{protocol::ActorKind::person, user->name, key.public_key(),
                                          std::nullopt, std::nullopt});
    const std::string key_name = "person-" + hex_id(actor).substr(0, 16);
    keys.seal(key_name, key);
    static_cast<void>(session.submit(args, protocol::ActorSetPresenceBody{actor, user->passkeys}));
    const protocol::Id delegation =
        session.submit(args, protocol::DelegationGrantBody{actor, scope});
    change_people(state, [&](console::People& p) {
        if (console::User* u = p.find(name); u != nullptr) {
            u->actor = hex_id(actor);
            u->key = key_name;
        }
    });
    console::record_activity(state, {ledger::SystemClock{}.now(),
                                     "cli",
                                     "people.approve",
                                     {{"user", name}, {"actor", hex_id(actor)}}});
    if (args.json()) {
        print_json({{"user", name},
                    {"actor", id_json(actor)},
                    {"delegation", id_json(delegation)},
                    {"key", key_name},
                    {"may", console::permissions_json(may)}});
        return exit_ok;
    }
    std::println(
        "{} now acts as actor {} with the key {}, in person (passkey), under delegation {}", name,
        hex_id(actor), key_name, short_id(delegation));
    return exit_ok;
}

int cmd_console_backup_now(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    if (const auto pid = running_console(state)) {
        throw CommandError{std::format(
            "the console runs (process {}): back up from its Settings (Back up now)", *pid)};
    }
    console::KeyStore keys(state);
    if (!keys.initialized()) {
        throw CommandError{"the console's keys are not set up: nothing to seal backups to"};
    }
    const std::string secret = args.get("unlock-file")
                                   ? unlock_secret(*args.get("unlock-file"))
                                   : prompt_hidden("The console's passphrase or recovery code: ");
    if (!keys.unlock({console::SlotKind::passphrase, {}}, secret) &&
        !keys.unlock({console::SlotKind::recovery, {}}, secret)) {
        throw UsageError{"that does not unlock the console's keys"};
    }
    std::optional<std::filesystem::path> folder;
    if (const auto given = args.get("folder")) {
        folder = *given;
    } else {
        folder = console::load_settings(state).backup_folder;
    }
    if (!folder) {
        throw UsageError{"no backup folder: give --folder, or set one (console settings set)"};
    }
    Session session(dir);
    ledger::SystemClock clock;
    std::filesystem::path written;
    try {
        written = console::write_sealed_backup(session.ledger(), shared_provider(), dir,
                                               keys.open("log"), *folder, clock.now());
    } catch (const std::runtime_error& e) {
        throw CommandError{e.what()};
    }
    console::BackupStatus status = console::load_backup_status(state);
    status.at = clock.now();
    status.file = written.string();
    status.size = std::filesystem::file_size(written);
    status.failed_at = 0;
    status.problem.clear();
    console::save_backup_status(state, status);
    console::record_activity(
        state, {clock.now(), "cli", "backups.write", {{"file", written.filename().string()}}});
    if (args.json()) {
        print_json({{"file", written.string()}, {"size", status.size}});
    } else {
        std::println("backed up to {} ({} bytes), sealed: the recovery code opens it",
                     written.string(), status.size);
    }
    return exit_ok;
}

int cmd_console_backup_list(const Args& args) {
    std::optional<std::filesystem::path> folder;
    if (const auto given = args.get("folder")) {
        folder = *given;
    } else {
        folder =
            console::load_settings(console::state_directory(args.console_ledger())).backup_folder;
    }
    if (!folder) {
        throw UsageError{"no backup folder: give --folder"};
    }
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(*folder, ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        if (it->is_regular_file() &&
            it->path().filename().string().ends_with(console::sealed_backup_extension)) {
            files.push_back(it->path());
        }
    }
    std::ranges::sort(files, std::greater{});
    Json list = Json::array();
    for (const auto& f : files) {
        Json item = {{"file", f.string()}, {"size", std::filesystem::file_size(f)}};
        try {
            const auto info = console::sealed_backup_info(read_file(f));
            item["ledger_id"] = hex_id(info.ledger);
            item["created"] = format_time(info.created);
        } catch (const std::runtime_error& e) {
            item["error"] = e.what();
        }
        list.push_back(std::move(item));
    }
    if (args.json()) {
        print_json(list);
        return exit_ok;
    }
    if (list.empty()) {
        std::println("no sealed backups in {}", folder->string());
    }
    for (const auto& item : list) {
        std::println("{}  {}  {}", item.value("created", "?"),
                     item.value("ledger_id", std::string("?")).substr(0, 12),
                     item["file"].get<std::string>());
    }
    return exit_ok;
}

int cmd_console_restore(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    const std::filesystem::path file = args.positional().front();
    if (std::filesystem::exists(dir / "statements")) {
        throw CommandError{"a ledger already exists at " + dir.string() +
                           "; restore into a new directory"};
    }
    std::string code;
    if (const auto from = args.get("recovery-code-file")) {
        const Bytes bytes = read_file(*from);
        code = std::string(bytes.begin(), bytes.end());
        code = code.substr(0, code.find('\n'));
    } else {
        code = prompt_hidden("The console's recovery code: ");
    }
    Result<ledger::BackupSummary> restored = fail(Errc::unavailable, "not restored");
    try {
        restored = console::restore_sealed_backup(read_file(file), code, dir);
    } catch (const std::runtime_error& e) {
        throw CommandError{e.what()};
    }
    if (!restored) {
        throw CommandError{"restoring: " + std::string(restored.error().detail)};
    }
    Session session(dir);
    const auto audit = session.ledger().audit();
    if (!audit) {
        throw CommandError{"the restored ledger does not audit: " +
                           std::string(audit.error().detail)};
    }
    if (args.json()) {
        print_json({{"ledger_id", hex_id(session.ledger().id())},
                    {"directory", dir.string()},
                    {"entries", audit->entries},
                    {"checkpoints", audit->checkpoints},
                    {"files", restored->files}});
        return exit_ok;
    }
    std::println("restored ledger {} with its console to {}: {} entries, audit passed",
                 hex_id(session.ledger().id()), dir.string(), audit->entries);
    std::println("start it with: cexchain console run --ledger {} (it starts locked: the recovery "
                 "code or the owner's passkey unlocks it)",
                 dir.string());
    return exit_ok;
}

namespace {

// The console as a per-user background service: a LaunchAgent on macOS, a
// systemd user unit elsewhere. It starts at login and restarts if it fails;
// `console stop` stops it until the next login. Locked at start, it signs
// nothing until a passkey's sign-in (or --unlock-file) unlocks it.

constexpr std::string_view service_label = "com.cirraya.cexchain.console";
constexpr std::string_view service_unit = "cexchain-console.service";

struct ServicePlace {
    std::filesystem::path directory;
    std::filesystem::path file;
    bool launchd = false;
};

ServicePlace service_place(const Args& args) {
    ServicePlace out;
#if defined(__APPLE__)
    out.launchd = true;
#endif
    if (const auto dir = args.get("unit-dir")) {
        out.directory = *dir;
    } else {
        const char* home = std::getenv("HOME");
        if (home == nullptr || *home == '\0') {
            throw UsageError{"no home folder: pass --unit-dir"};
        }
        if (out.launchd) {
            out.directory = std::filesystem::path(home) / "Library" / "LaunchAgents";
        } else if (const char* config = std::getenv("XDG_CONFIG_HOME");
                   config != nullptr && std::filesystem::path(config).is_absolute()) {
            out.directory = std::filesystem::path(config) / "systemd" / "user";
        } else {
            out.directory = std::filesystem::path(home) / ".config" / "systemd" / "user";
        }
    }
    out.file = out.directory /
               (out.launchd ? std::string(service_label) + ".plist" : std::string(service_unit));
    return out;
}

std::string xml_text(std::string_view text) {
    std::string out;
    for (const char c : text) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        default:
            out += c;
        }
    }
    return out;
}

/// A systemd word: quoted, with its quotes and backslashes escaped.
std::string unit_word(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
        }
        out += c == '%' ? std::string("%%") : std::string(1, c);
    }
    return out + "\"";
}

std::string service_text(const ServicePlace& place, const std::vector<std::string>& command,
                         const std::filesystem::path& log) {
    if (place.launchd) {
        std::string arguments;
        for (const std::string& word : command) {
            arguments += "    <string>" + xml_text(word) + "</string>\n";
        }
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
               "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
               "<plist version=\"1.0\">\n<dict>\n"
               "  <key>Label</key>\n  <string>" +
               std::string(service_label) +
               "</string>\n"
               "  <key>ProgramArguments</key>\n  <array>\n" +
               arguments +
               "  </array>\n"
               "  <key>EnvironmentVariables</key>\n  <dict>\n"
               "    <key>CEXCHAIN_NO_BROWSER</key>\n    <string>1</string>\n  </dict>\n"
               "  <key>RunAtLoad</key>\n  <true/>\n"
               "  <key>KeepAlive</key>\n  <dict>\n"
               "    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n"
               "  <key>StandardOutPath</key>\n  <string>" +
               xml_text(log.string()) +
               "</string>\n"
               "  <key>StandardErrorPath</key>\n  <string>" +
               xml_text(log.string()) + "</string>\n</dict>\n</plist>\n";
    }
    std::string exec;
    for (const std::string& word : command) {
        exec += (exec.empty() ? "" : " ") + unit_word(word);
    }
    return "[Unit]\n"
           "Description=CexChain console\n"
           "After=network-online.target\n\n"
           "[Service]\n"
           "ExecStart=" +
           exec +
           "\n"
           "Environment=CEXCHAIN_NO_BROWSER=1\n"
           "Restart=on-failure\n"
           "RestartSec=5\n\n"
           "[Install]\n"
           "WantedBy=default.target\n";
}

/// Runs a platform tool (launchctl, systemctl); its exit status.
int run_tool(std::vector<std::string> words) {
    std::vector<char*> argv;
    for (std::string& w : words) {
        argv.push_back(w.data());
    }
    argv.push_back(nullptr);
    pid_t child = 0;
    if (::posix_spawnp(&child, argv.front(), nullptr, nullptr, argv.data(), environ) != 0) {
        return -1;
    }
    int status = 0;
    ::waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

std::string gui_domain() {
    return "gui/" + std::to_string(::getuid());
}

} // namespace

int cmd_console_service_install(const Args& args) {
    const std::filesystem::path dir = std::filesystem::absolute(args.console_ledger());
    const ServicePlace place = service_place(args);
    std::vector<std::string> command{self_path(), "console",    "run",
                                     "--ledger",  dir.string(), "--quiet"};
    if (const auto port = args.get("port")) {
        command.insert(command.end(), {"--port", *port});
    }
    if (const auto file = args.get("unlock-file")) {
        command.insert(command.end(), {"--unlock-file", std::filesystem::absolute(*file).string()});
    }
    const std::filesystem::path log = console::state_directory(dir) / "console.log";
    const std::string text = service_text(place, command, log);
    if (args.has("print")) {
        std::print("{}", text);
        return exit_ok;
    }
    std::filesystem::create_directories(place.directory);
    std::filesystem::create_directories(console::state_directory(dir));
    write_file(place.file, as_bytes(text), false);
    bool started = false;
    if (!args.has("no-start")) {
        if (place.launchd) {
            static_cast<void>(run_tool(
                {"launchctl", "bootout", gui_domain() + "/" + std::string(service_label)}));
            started = run_tool({"launchctl", "bootstrap", gui_domain(), place.file.string()}) == 0;
        } else {
            started = run_tool({"systemctl", "--user", "daemon-reload"}) == 0 &&
                      run_tool({"systemctl", "--user", "enable", "--now",
                                std::string(service_unit)}) == 0;
        }
    }
    if (args.json()) {
        print_json({{"file", place.file.string()}, {"ledger", dir.string()}, {"started", started}});
        return exit_ok;
    }
    std::println("installed {} for {}", place.file.string(), dir.string());
    std::println("{}", started ? "it runs now, and at each login (console open opens it)"
                               : "it runs at the next login (or start it now: console run)");
    return exit_ok;
}

int cmd_console_service_uninstall(const Args& args) {
    const ServicePlace place = service_place(args);
    if (!args.has("no-start")) {
        if (place.launchd) {
            static_cast<void>(run_tool(
                {"launchctl", "bootout", gui_domain() + "/" + std::string(service_label)}));
        } else {
            static_cast<void>(
                run_tool({"systemctl", "--user", "disable", "--now", std::string(service_unit)}));
        }
    }
    const bool removed = std::filesystem::remove(place.file);
    if (!args.has("no-start") && !place.launchd) {
        static_cast<void>(run_tool({"systemctl", "--user", "daemon-reload"}));
    }
    if (args.json()) {
        print_json({{"file", place.file.string()}, {"removed", removed}});
    } else {
        if (removed) {
            std::println("uninstalled {}: the console no longer starts at login (its ledger and "
                         "backups stay)",
                         place.file.string());
        } else {
            std::println("no service at {}", place.file.string());
        }
    }
    return exit_ok;
}

int cmd_console_service_status(const Args& args) {
    const ServicePlace place = service_place(args);
    const bool installed = std::filesystem::exists(place.file);
    std::string ledger;
    if (installed) {
        const Bytes bytes = read_file(place.file);
        const std::string text(bytes.begin(), bytes.end());
        // The word after --ledger, as either format writes it.
        for (const auto& [before, after] :
             {std::pair<std::string_view, std::string_view>{"<string>--ledger</string>",
                                                            "</string>"},
              std::pair<std::string_view, std::string_view>{"\"--ledger\" \"", "\""}}) {
            std::size_t at = text.find(before);
            if (at == std::string::npos) {
                continue;
            }
            at += before.size();
            if (before.starts_with("<")) {
                at = text.find("<string>", at);
                at = at == std::string::npos ? at : at + 8;
            }
            const std::size_t end = at == std::string::npos ? at : text.find(after, at);
            if (end != std::string::npos) {
                ledger = text.substr(at, end - at);
            }
        }
    }
    const std::optional<std::filesystem::path> dir =
        ledger.empty() ? std::nullopt : std::optional<std::filesystem::path>(ledger);
    const bool running = dir && running_console(console::state_directory(*dir)).has_value();
    if (args.json()) {
        print_json({{"installed", installed},
                    {"file", place.file.string()},
                    {"ledger", dir ? Json(dir->string()) : Json()},
                    {"running", running}});
        return exit_ok;
    }
    if (!installed) {
        std::println("no console service installed (console service install)");
        return exit_ok;
    }
    std::println("installed: {} for {}; {}", place.file.string(), ledger,
                 running ? "running" : "not running now");
    return exit_ok;
}

int cmd_console_activity(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::size_t limit =
        static_cast<std::size_t>(parse_number(args.get("limit").value_or("50"), "--limit"));
    const auto entries = console::read_activity(console::state_directory(dir), limit);
    if (args.json()) {
        Json out = Json::array();
        for (const auto& a : entries) {
            Json item = console::activity_json(a);
            item["at"] = format_time(a.at);
            out.push_back(std::move(item));
        }
        print_json(out);
        return exit_ok;
    }
    if (entries.empty()) {
        std::println("no activity recorded in the console yet");
    }
    for (const auto& a : entries) {
        std::println("{}  {:<16} {:<18} {}", format_time(a.at), a.user, a.action, a.detail.dump());
    }
    return exit_ok;
}

int cmd_console_user_passkeys(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const console::People people = read_people(console::state_directory(dir));
    const std::string name = args.positional().front();
    const console::User* user = people.find(name);
    if (user == nullptr) {
        throw CommandError{"no console user named " + name};
    }
    const std::filesystem::path out = args.need("out");
    std::filesystem::create_directories(out);
    std::string stem = name;
    std::ranges::replace(stem, ' ', '-');
    Json files = Json::array();
    for (std::size_t i = 0; i < user->passkeys.size(); ++i) {
        const std::filesystem::path file = out / std::format("{}-{}.passkey", stem, i + 1);
        write_file(
            file,
            unwrap(protocol::encode_presence_credential(user->passkeys[i]), "encoding the passkey"),
            false);
        files.push_back(file.string());
    }
    if (args.json()) {
        print_json({{"user", name}, {"files", files}});
        return exit_ok;
    }
    for (const auto& f : files) {
        std::println("wrote {}", f.get<std::string>());
    }
    return exit_ok;
}

namespace {

Json settings_json(const console::Settings& settings) {
    return {{"language", settings.language ? Json(*settings.language) : Json()},
            {"backup_folder",
             settings.backup_folder ? Json(settings.backup_folder->string()) : Json()}};
}

void print_settings(const Args& args, const console::Settings& settings) {
    if (args.json()) {
        print_json(settings_json(settings));
        return;
    }
    std::println("language: {}", settings.language.value_or("each browser's own"));
    std::println("backup folder: {}", settings.backup_folder
                                          ? settings.backup_folder->string()
                                          : std::string("none chosen (console settings set "
                                                        "--backup-folder DIR)"));
}

} // namespace

int cmd_console_settings_show(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    try {
        print_settings(args, console::load_settings(console::state_directory(dir)));
    } catch (const std::runtime_error& e) {
        throw CommandError{e.what()};
    }
    return exit_ok;
}

int cmd_console_settings_set(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const auto language = args.get("language");
    const auto folder = args.get("backup-folder");
    if (!language && !folder) {
        throw UsageError{"give --language, --backup-folder, or both"};
    }
    if (language && *language != "browser" && !console::valid_language(*language)) {
        throw UsageError{"--language is en, zh-Hant-HK, zh-Hans-CN, or browser"};
    }
    const std::filesystem::path state = console::state_directory(dir);
    std::filesystem::create_directories(state);
    const auto lock =
        unwrap(ledger::DirectoryLock::acquire(state), "locking the console's settings");
    console::Settings settings;
    try {
        settings = console::load_settings(state);
    } catch (const std::runtime_error& e) {
        throw CommandError{e.what()};
    }
    if (language) {
        settings.language =
            *language == "browser" ? std::nullopt : std::optional<std::string>(*language);
    }
    if (folder) {
        if (*folder == "none") {
            settings.backup_folder.reset();
        } else {
            const std::filesystem::path chosen = std::filesystem::absolute(*folder);
            if (const auto problem = console::prepare_backup_folder(chosen)) {
                throw CommandError{*problem};
            }
            settings.backup_folder = chosen.lexically_normal();
        }
    }
    console::save_settings(state, settings);
    print_settings(args, settings);
    return exit_ok;
}

namespace {

/// A kind sheet in the command line's JSON (keys in the sheet's order).
Json kind_value(const console::Kind& kind) {
    return Json::parse(console::kind_json(kind).dump());
}

std::vector<console::Kind> read_kinds(const std::filesystem::path& state) {
    try {
        return console::load_kinds(state);
    } catch (const std::runtime_error& e) {
        throw CommandError{e.what()};
    }
}

void print_kind(const console::Kind& kind) {
    std::println("{} ({})", kind.name, kind.type);
    if (!kind.description.empty()) {
        std::println("  {}", kind.description);
    }
    for (const console::KindField& f : kind.fields) {
        std::println("  field {:<24} {:<8} {}{}", f.name, console::name_of(f.type),
                     f.is_private ? "private" : "public", f.required ? ", required" : "");
    }
    std::println(
        "  files: {}{}",
        kind.files == console::KindFiles::none       ? "none"
        : kind.files == console::KindFiles::required ? "required"
                                                     : "optional",
        kind.files != console::KindFiles::none && kind.keep_files ? ", kept with the record" : "");
}

} // namespace

int cmd_console_kind_add(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::string file = args.positional().front();
    const Bytes bytes = read_file(file);
    const auto sheet = Json::parse(bytes.begin(), bytes.end(), nullptr, false);
    console::Kind kind;
    try {
        kind = console::parse_kind(sheet);
    } catch (const std::invalid_argument& e) {
        throw UsageError{file + ": " + e.what()};
    }
    const std::filesystem::path state = console::state_directory(dir);
    std::filesystem::create_directories(state);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(state), "locking the console's kinds");
    std::vector<console::Kind> kinds = read_kinds(state);
    const auto same = std::ranges::find(kinds, kind.type, &console::Kind::type);
    const bool replaced = same != kinds.end();
    if (replaced && !args.has("replace")) {
        throw CommandError{"a kind of type " + kind.type + " exists (--replace replaces it)"};
    }
    if (replaced) {
        *same = kind;
    } else {
        kinds.push_back(kind);
    }
    try {
        console::save_kinds(state, kinds);
    } catch (const std::invalid_argument& e) {
        throw CommandError{e.what()};
    }
    if (args.json()) {
        print_json(kind_value(kind));
    } else {
        std::println("{} the kind {} ({})", replaced ? "replaced" : "added", kind.name, kind.type);
    }
    return exit_ok;
}

int cmd_console_kind_list(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const auto kinds = read_kinds(console::state_directory(dir));
    if (args.json()) {
        Json list = Json::array();
        for (const auto& k : kinds) {
            list.push_back(kind_value(k));
        }
        print_json(list);
        return exit_ok;
    }
    if (kinds.empty()) {
        std::println("no kinds (console kind add FILE)");
    }
    for (const auto& k : kinds) {
        std::println("{:<32} {} ({} fields)", k.type, k.name, k.fields.size());
    }
    return exit_ok;
}

int cmd_console_kind_show(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const auto kinds = read_kinds(console::state_directory(dir));
    const auto found = std::ranges::find(kinds, args.positional().front(), &console::Kind::type);
    if (found == kinds.end()) {
        throw CommandError{"no kind of type " + args.positional().front()};
    }
    if (args.json()) {
        print_json(kind_value(*found));
    } else {
        print_kind(*found);
    }
    return exit_ok;
}

int cmd_console_kind_remove(const Args& args) {
    const std::filesystem::path dir = args.console_ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    const std::string type = args.positional().front();
    std::filesystem::create_directories(state);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(state), "locking the console's kinds");
    std::vector<console::Kind> kinds = read_kinds(state);
    if (std::erase_if(kinds, [&](const console::Kind& k) { return k.type == type; }) == 0) {
        throw CommandError{"no kind of type " + type};
    }
    console::save_kinds(state, kinds);
    if (args.json()) {
        print_json({{"removed", type}});
    } else {
        std::println("removed the kind {}; its records stay on the ledger", type);
    }
    return exit_ok;
}

} // namespace cexchain::cli
