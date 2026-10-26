// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A lost passkey, recovered with the recovery code: the code proves the
// owner (it opens the console's keys), a new passkey is made, and the root
// key replaces the owner's passkeys on the ledger with it. The lost ones
// stop signing in, stop proving presence, and stop unlocking the console,
// and the owner's other sessions end.

#include <algorithm>
#include <cctype>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/console/console.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/ledger/storage.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

std::string field(const nlohmann::json& body, std::string_view key) {
    const auto it = body.find(key);
    return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
}

std::optional<nlohmann::json> object_of(const http::Request& request) {
    auto body = nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return std::nullopt;
    }
    return std::optional<nlohmann::json>(std::in_place, std::move(body));
}

std::string lowered(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/// The owner a recovery is for: the one named, or the only one.
const User* owner_named(const People& people, std::string_view name) {
    if (!name.empty()) {
        const User* user = people.find(name);
        return user != nullptr && user->role == Role::owner ? user : nullptr;
    }
    const User* only = nullptr;
    for (const User& user : people.users) {
        if (user.role == Role::owner) {
            if (only != nullptr) {
                return nullptr;
            }
            only = &user;
        }
    }
    return only;
}

std::optional<protocol::Id> actor_of(const User& user) {
    const auto bytes = from_hex(user.actor);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

} // namespace

http::Response Console::recover_begin(const http::Request& request) const {
    const auto body = object_of(request);
    if (!body) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const std::string origin = lowered(*request.header("origin"));
    const auto parsed = parse_origin(origin);
    if (!parsed || parsed->host.starts_with('[') ||
        parsed->host.find_first_not_of("0123456789.") == std::string::npos) {
        return error(400, "invalid_argument",
                     "passkeys need the console's name, not an address: open it at its "
                     "localhost or public URL");
    }
    KeyStore* keys = services_.keys;
    if (keys == nullptr || !keys->initialized()) {
        return error(409, "conflict", "this console keeps no keys, so it has no recovery code");
    }
    // The code opens the recovery slot, or it is not the code. Each try
    // costs the slot's scrypt: one at a time, and a few wrong ones a minute.
    const protocol::Timestamp now = services_.clock->now();
    {
        const std::lock_guard lock(mutex_);
        std::erase_if(recovery_failures_,
                      [&](protocol::Timestamp t) { return t + recovery_failure_window <= now; });
        if (checking_recovery_ || recovery_failures_.size() >= max_recovery_failures) {
            return error(429, "unavailable",
                         "too many recovery codes were tried: try again in a minute");
        }
        checking_recovery_ = true;
    }
    const bool opened = keys->unlock({SlotKind::recovery, {}}, field(*body, "recovery_code"));
    {
        const std::lock_guard lock(mutex_);
        checking_recovery_ = false;
        if (!opened) {
            recovery_failures_.push_back(now);
        }
    }
    if (!opened) {
        return error(403, "forbidden", "that is not this console's recovery code");
    }
    ready_now();
    const People people = load_people(services_.directory);
    const User* owner = owner_named(people, field(*body, "name"));
    if (owner == nullptr || owner->actor.empty()) {
        return error(404, "not_found", "name the owner whose passkey was lost");
    }
    const Bytes challenge = services_.entropy->bytes<32>() | std::ranges::to<Bytes>();
    const auto id = begin({true,
                           challenge,
                           parsed->host,
                           parsed->text(),
                           {},
                           owner->name,
                           services_.clock->now() + ceremony_lifetime,
                           true});
    if (!id) {
        return error(429, "unavailable", "too many passkey requests are waiting; try again soon");
    }
    return json(200, {{"ceremony", *id},
                      {"user", owner->name},
                      {"keys", key_state()},
                      {"public_key",
                       registration_options(challenge, parsed->host, owner->name, {}, true)}});
}

std::variant<Console::Recovery, http::Response>
Console::recovery_plan(const http::Request& request) const {
    const auto body = object_of(request);
    if (!body) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const auto ceremony = take(field(*body, "ceremony"));
    if (!ceremony || !ceremony->recovery ||
        ceremony->origin != lowered(*request.header("origin"))) {
        return error(404, "not_found", "this recovery is unknown or expired; begin again");
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr || !submitter()) {
        return error(503, "unavailable", "the console has no ledger to act on");
    }
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        return error(423, "locked", "the console was locked meanwhile; begin again");
    }
    auto registered = registered_passkey(*body, *ceremony);
    if (auto* refused = std::get_if<http::Response>(&registered)) {
        return std::move(*refused);
    }
    Recovery recovery;
    recovery.passkey = std::get<protocol::PresenceCredential>(std::move(registered));
    if (const std::string prf = field(*body, "prf"); is_prf_output(prf)) {
        recovery.prf = prf;
    }
    const People people = load_people(services_.directory);
    const User* owner = people.find(ceremony->name);
    if (owner == nullptr || owner->role != Role::owner) {
        return error(404, "not_found", "that owner was removed meanwhile");
    }
    const auto actor = actor_of(*owner);
    if (!actor) {
        return error(409, "conflict", "the owner acts as no one on the ledger");
    }
    if (const User* holder = people.owner_of(recovery.passkey.credential_id);
        holder != nullptr && holder->name != owner->name) {
        return error(409, "conflict", "this passkey is someone else's");
    }
    recovery.user = owner->name;
    for (const auto& p : owner->passkeys) {
        recovery.old_passkeys.push_back(to_base64url(p.credential_id));
    }
    // The root key replaces the owner's passkeys on the ledger.
    const auto root = services_.keys->open(root_key_name);
    protocol::Statement s;
    std::string problem;
    const crypto::HashAlg hash = served->hash();
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::ActorState* org = nullptr;
        for (const auto& [id, a] : state.actors()) {
            if (a.is_organization()) {
                org = &a;
            }
        }
        const protocol::ActorState* person = state.actor(*actor);
        if (org == nullptr || org->key != root.public_key()) {
            problem = "the console's root key is no longer the organization's";
        } else if (person == nullptr || person->revoked) {
            problem = "the owner's actor is not on the ledger, or is revoked";
        } else {
            s.ledger_id = state.ledger_id();
            s.actor_id = org->id;
        }
    });
    if (!problem.empty()) {
        return error(409, "conflict", problem);
    }
    s.issued_at = services_.clock->now();
    s.nonce = services_.entropy->bytes<16>();
    s.body = protocol::ActorSetPresenceBody{*actor, {recovery.passkey}};
    auto made = protocol::sign_statement(root, *services_.provider, hash, s);
    if (!made) {
        return error(500, "internal", "signing failed");
    }
    recovery.statement = std::move(made->encoded);
    return recovery;
}

http::Response Console::finish_recovery(const Recovery& recovery,
                                        const http::Response& registered) const {
    // POST /v1/statements answers 201 when it registers the statement.
    if (registered.status < 200 || registered.status > 299) {
        http::Response refused = registered;
        secure(refused);
        return refused;
    }
    {
        const auto lock = ledger::DirectoryLock::acquire(services_.directory, 2000);
        if (!lock) {
            return error(503, "unavailable",
                         "the ledger has the new passkey, but the console could not record it: "
                         "begin the recovery again");
        }
        People people = load_people(services_.directory);
        User* owner = people.find(recovery.user);
        if (owner == nullptr) {
            return error(404, "not_found", "that owner was removed meanwhile");
        }
        owner->passkeys = {recovery.passkey};
        save_people(services_.directory, people);
    }
    // The lost passkeys unlock nothing any more, and their sessions end.
    for (const std::string& id : recovery.old_passkeys) {
        static_cast<void>(services_.keys->remove_slot({SlotKind::prf, id}));
    }
    if (!recovery.prf.empty()) {
        services_.keys->add_slot({SlotKind::prf, to_base64url(recovery.passkey.credential_id)},
                                 recovery.prf);
    }
    static_cast<void>(services_.sessions->end_all(recovery.user));
    return json(200, {{"session", services_.sessions->create(recovery.user)},
                      {"user", recovery.user},
                      {"role", name_of(Role::owner)},
                      {"keys", key_state()},
                      {"key_slot", !recovery.prf.empty()}});
}

http::Response Console::recover_finish(const http::Request& request) const {
    auto plan = recovery_plan(request);
    if (auto* refused = std::get_if<http::Response>(&plan)) {
        return std::move(*refused);
    }
    // Waits for the ledger's answer, as approve_route does (the node uses
    // the asynchronous handle).
    const Recovery recovery = std::get<Recovery>(std::move(plan));
    auto answered = std::make_shared<std::promise<http::Response>>();
    auto future = answered->get_future();
    submitter()(recovery.statement, false,
                [answered](http::Response r) { answered->set_value(std::move(r)); });
    if (future.wait_for(std::chrono::seconds(30)) != std::future_status::ready) {
        return error(504, "unavailable", "the ledger did not register it in time");
    }
    return finish_recovery(recovery, future.get());
}

} // namespace cexchain::console
