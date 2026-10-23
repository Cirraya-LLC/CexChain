// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's commands (the console itself runs in `serve --console`).

#include <exception>
#include <filesystem>
#include <format>
#include <print>
#include <ranges>

#include <cexchain/app/support.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/console/users.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/storage.hpp>

#include "commands.hpp"
#include "output.hpp"

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

} // namespace cexchain::cli
