// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's commands (the console itself runs in `serve --console`).

#include <cerrno>
#include <chrono>
#include <csignal>
#include <exception>
#include <filesystem>
#include <format>
#include <print>
#include <ranges>
#include <spawn.h>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include <cexchain/app/support.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/console/users.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/storage.hpp>

#include "commands.hpp"
#include "output.hpp"
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
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    ledger::SystemClock clock;
    ledger::SystemEntropy entropy;
    auto [code, invitation] =
        console::make_invitation(shared_provider(), entropy, "", console::Role::owner, clock.now());
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
    const std::filesystem::path dir = args.ledger();
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
    const std::filesystem::path dir = args.ledger();
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
            {"passkeys", passkeys}};
}

std::size_t owners(const console::People& people) {
    return static_cast<std::size_t>(
        std::ranges::count(people.users, console::Role::owner, &console::User::role));
}

} // namespace

int cmd_console_user_add(const Args& args) {
    const std::filesystem::path dir = args.ledger();
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
    const std::filesystem::path dir = args.ledger();
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
    const std::filesystem::path dir = args.ledger();
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
    const std::filesystem::path dir = args.ledger();
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
    const std::filesystem::path dir = args.ledger();
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

int cmd_console_run(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
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
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
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
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
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

int cmd_console_open(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const std::filesystem::path state = console::state_directory(dir);
    const auto url = state_line(state / "url");
    if (!running_console(state) || !url) {
        throw CommandError{"the console is not running (console run)"};
    }
    if (args.json() || args.has("print")) {
        if (args.json()) {
            print_json({{"url", *url}});
        } else {
            std::println("{}", *url);
        }
        return exit_ok;
    }
#if defined(__APPLE__)
    const char* opener = "open";
#else
    const char* opener = "xdg-open";
#endif
    std::string target = *url;
    std::vector<char*> argv{const_cast<char*>(opener), target.data(), nullptr};
    pid_t child = 0;
    if (::posix_spawnp(&child, opener, nullptr, nullptr, argv.data(), environ) != 0) {
        std::println("open {} in your browser", *url);
        return exit_ok;
    }
    int status = 0;
    ::waitpid(child, &status, 0);
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
    const std::filesystem::path dir = args.ledger();
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

int cmd_console_key_import(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const std::string name = args.positional()[0];
    if (!console::valid_key_name(name)) {
        throw UsageError{"a key's name is 1 to 64 lower-case letters, digits, '.', '_', or '-'"};
    }
    console::KeyStore store(console::state_directory(dir));
    if (!store.initialized()) {
        throw CommandError{"the console's keys are not set up (console key init)"};
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
    const std::filesystem::path dir = args.ledger();
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
        print_json({{"set_up", store.initialized()}, {"slots", slots}, {"keys", list}});
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
    return exit_ok;
}

int cmd_console_key_remove(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    const std::string name = args.positional().front();
    console::KeyStore store(console::state_directory(dir));
    if (!store.remove_key(name)) {
        throw CommandError{"the console holds no key named " + name};
    }
    if (args.json()) {
        print_json({{"removed", name}});
    } else {
        std::println("removed the key {} from the console", name);
    }
    return exit_ok;
}

} // namespace cexchain::cli
