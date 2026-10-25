// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Unlocking the console's keys: with the signed-in passkey's PRF output,
// with a passphrase or the recovery code typed on the page by an owner or an
// admin, or (for servers) with an unlock file at start. Locked, the console
// signs nothing.

#include <filesystem>
#include <mutex>
#include <string>
#include <variant>

#include <nlohmann/json.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/core/bytes.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

bool may_hold_keys(Role role) {
    return role == Role::owner || role == Role::admin;
}

} // namespace

nlohmann::json Console::key_state() const {
    if (services_.keys == nullptr || !services_.keys->initialized()) {
        return "none";
    }
    return services_.keys->unlocked() ? "unlocked" : "locked";
}

std::string Console::prf_salt() const {
    const std::filesystem::path file = services_.directory / "prf-salt";
    const std::lock_guard lock(mutex_);
    if (std::filesystem::exists(file)) {
        const Bytes bytes = app::read_file(file);
        std::string text(bytes.begin(), bytes.end());
        return text.substr(0, text.find('\n'));
    }
    std::string salt = to_base64url(services_.entropy->bytes<32>());
    std::filesystem::create_directories(services_.directory);
    app::write_file(file, as_bytes(salt + "\n"), true);
    return salt;
}

void Console::use_prf(const User& user, ByteView credential, std::string_view prf) const {
    KeyStore* keys = services_.keys;
    const auto output = from_base64url(prf);
    if (keys == nullptr || !keys->initialized() || !output || output->size() != 32) {
        return;
    }
    const Slot slot{SlotKind::prf, to_base64url(credential)};
    if (!keys->unlocked()) {
        static_cast<void>(keys->unlock(slot, prf));
        return;
    }
    // Unlocked already: an owner's or an admin's passkey gets a slot of its
    // own, so that its sign-in unlocks the console from now on.
    const auto slots = keys->slots();
    const bool has_slot = std::ranges::any_of(
        slots, [&](const Slot& s) { return s.kind == SlotKind::prf && s.id == slot.id; });
    if (!has_slot && may_hold_keys(user.role)) {
        keys->add_slot(slot, prf);
    }
}

http::Response Console::unlock_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    if (!may_hold_keys(std::get<Signed>(who).role)) {
        return error(403, "forbidden", "only an owner or an admin unlocks the console");
    }
    KeyStore* keys = services_.keys;
    if (keys == nullptr || !keys->initialized()) {
        return error(409, "conflict", "the console's keys are not set up (console key init)");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    if (body.value("lock", false)) {
        keys->lock();
        return json(200, {{"keys", key_state()}});
    }
    const std::string secret = body.value("secret", "");
    const bool opened = keys->unlock({SlotKind::passphrase, {}}, secret) ||
                        keys->unlock({SlotKind::recovery, {}}, secret);
    if (!opened) {
        return error(403, "forbidden", "that does not unlock the console");
    }
    return json(200, {{"keys", key_state()}});
}

} // namespace cexchain::console
