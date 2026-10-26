// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Registering a passkey with an invitation, and signing in with one. Each
// ceremony's challenge comes from this console, is used once, and expires
// in five minutes; the browser must be on the console's own page, and
// signing in needs the person verified (a PIN or a biometric).

#include <algorithm>
#include <cctype>
#include <exception>
#include <mutex>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/console/console.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/console/users.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/ledger/storage.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

std::string lowered(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::optional<nlohmann::json> body_of(const http::Request& request) {
    auto body = nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return std::nullopt;
    }
    return std::optional<nlohmann::json>(std::in_place, std::move(body));
}

std::string text_field(const nlohmann::json& body, std::string_view key) {
    const auto it = body.find(key);
    return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
}

std::optional<Bytes> bytes_field(const nlohmann::json& body, std::string_view key) {
    auto decoded = from_base64url(text_field(body, key));
    if (!decoded || decoded->empty()) {
        return std::nullopt;
    }
    return std::move(*decoded);
}

/// Passkeys belong to a name, never to an address: "localhost" or the
/// public URL's host.
std::optional<std::string> rp_id_for(std::string_view origin) {
    const auto parsed = parse_origin(origin);
    if (!parsed || parsed->host.starts_with('[') ||
        std::ranges::all_of(parsed->host,
                            [](unsigned char c) { return std::isdigit(c) != 0 || c == '.'; })) {
        return std::nullopt;
    }
    return parsed->host;
}

/// The origin a browser put in WebAuthn client data.
std::string client_origin(ByteView client_data_json) {
    const auto j =
        nlohmann::json::parse(client_data_json.begin(), client_data_json.end(), nullptr, false);
    return j.is_object() ? lowered(text_field(j, "origin")) : std::string();
}

http::Response bad(std::string_view message) {
    return error(400, "invalid_argument", message);
}

http::Response no_passkeys_here() {
    return bad("passkeys need the console's name, not an address: open it at its localhost or "
               "public URL");
}

http::Response signed_in(Sessions& sessions, const User& user) {
    return json(200, {{"session", sessions.create(user.name)},
                      {"user", user.name},
                      {"role", name_of(user.role)}});
}

} // namespace

std::optional<std::string> Console::begin(Ceremony ceremony) const {
    const protocol::Timestamp now = services_.clock->now();
    const std::lock_guard lock(mutex_);
    std::erase_if(ceremonies_, [&](const auto& entry) { return entry.second.expires <= now; });
    if (ceremonies_.size() >= max_ceremonies) {
        return std::nullopt;
    }
    std::string id = to_hex(services_.entropy->bytes<8>());
    ceremonies_.emplace(id, std::move(ceremony));
    return id;
}

std::optional<Ceremony> Console::take(std::string_view id) const {
    const protocol::Timestamp now = services_.clock->now();
    const std::lock_guard lock(mutex_);
    const auto found = ceremonies_.find(std::string(id));
    if (found == ceremonies_.end()) {
        return std::nullopt;
    }
    Ceremony ceremony = std::move(found->second);
    ceremonies_.erase(found);
    if (ceremony.expires <= now) {
        return std::nullopt;
    }
    return ceremony;
}

http::Response Console::enroll_begin(const http::Request& request) const {
    const auto body = body_of(request);
    if (!body) {
        return bad("the request's body is not a JSON object");
    }
    const std::string origin = lowered(*request.header("origin"));
    const auto rp_id = rp_id_for(origin);
    if (!rp_id) {
        return no_passkeys_here();
    }
    const auto hash = invitation_hash(*services_.provider, text_field(*body, "code"));
    if (!hash) {
        return bad("that is not an invitation code");
    }
    const protocol::Timestamp now = services_.clock->now();
    const People people = load_people(services_.directory);
    const auto invitation = std::ranges::find_if(people.invitations, [&](const Invitation& i) {
        return i.hash == *hash && i.expires > now;
    });
    if (invitation == people.invitations.end()) {
        return error(404, "not_found", "this invitation is unknown, used, or expired");
    }
    std::string name = invitation->user;
    if (name.empty()) {
        name = text_field(*body, "name");
        if (!valid_user_name(name)) {
            return bad("a name is 1 to 64 letters, digits, spaces, '.', '_', or '-'");
        }
        if (people.find(name) != nullptr) {
            return error(409, "conflict", "someone of that name uses the console already");
        }
        if (invitation->role == Role::owner && people.has_owner()) {
            return error(409, "conflict", "the console has an owner already");
        }
    }
    const Bytes challenge = services_.entropy->bytes<32>() | std::ranges::to<Bytes>();
    const auto id =
        begin({true, challenge, *rp_id, origin, *hash, name, now + ceremony_lifetime, false});
    if (!id) {
        return error(429, "unavailable", "too many passkey requests are waiting; try again soon");
    }
    std::vector<Bytes> exclude;
    if (const User* existing = people.find(name)) {
        for (const auto& p : existing->passkeys) {
            exclude.push_back(p.credential_id);
        }
    }
    const bool first_run = invitation->user.empty() && invitation->role == Role::owner &&
                           !has_ledger(services_.directory.parent_path());
    const bool keys = services_.keys != nullptr && (services_.keys->initialized() || first_run);
    return json(200,
                {{"ceremony", *id},
                 {"first_run", first_run},
                 {"public_key", registration_options(challenge, *rp_id, name, exclude, keys)}});
}

nlohmann::json Console::registration_options(ByteView challenge, std::string_view rp_id,
                                             std::string_view name,
                                             const std::vector<Bytes>& exclude, bool prf) const {
    nlohmann::json excluded = nlohmann::json::array();
    for (const Bytes& id : exclude) {
        excluded.push_back({{"type", "public-key"}, {"id", to_base64url(id)}});
    }
    const auto handle = services_.entropy->bytes<16>();
    return {{"challenge", to_base64url(challenge)},
            {"rp", {{"id", rp_id}, {"name", "CexChain"}}},
            {"user", {{"id", to_base64url(handle)}, {"name", name}, {"displayName", name}}},
            {"pubKeyCredParams",
             {{{"type", "public-key"}, {"alg", -7}}, {{"type", "public-key"}, {"alg", -8}}}},
            {"authenticatorSelection",
             {{"residentKey", "required"},
              {"requireResidentKey", true},
              {"userVerification", "required"}}},
            {"attestation", "none"},
            // The PRF extension must be asked for when the passkey is made,
            // for its sign-ins to unlock sealed keys; evaluated at once, it
            // unlocks them from the start (where the passkey can).
            {"extensions",
             {{"prf", prf ? nlohmann::json{{"eval", {{"first", prf_salt()}}}}
                          : nlohmann::json::object()}}},
            {"excludeCredentials", excluded},
            {"timeout", ceremony_lifetime}};
}

std::variant<protocol::PresenceCredential, http::Response>
Console::registered_passkey(const nlohmann::json& body, const Ceremony& ceremony) const {
    const auto attestation = bytes_field(body, "attestation_object");
    const auto client_data = bytes_field(body, "client_data_json");
    if (!attestation || !client_data) {
        return bad("the registration needs attestation_object and client_data_json (base64url)");
    }
    std::optional<std::string> label;
    if (const std::string text = text_field(body, "label"); !text.empty()) {
        if (text.size() > 64) {
            return bad("a passkey's label is at most 64 bytes");
        }
        label = text;
    }
    auto credential = protocol::credential_from_registration(
        *services_.provider, *attestation, *client_data, ceremony.challenge, ceremony.rp_id, label);
    if (!credential) {
        return error(400, "verification_failed", credential.error().detail);
    }
    if (client_origin(*client_data) != ceremony.origin) {
        return error(400, "verification_failed", "the passkey was made on another page");
    }
    return std::move(*credential);
}

http::Response Console::enroll_finish(const http::Request& request) const {
    const auto body = body_of(request);
    if (!body) {
        return bad("the request's body is not a JSON object");
    }
    const auto ceremony = take(text_field(*body, "ceremony"));
    const std::string origin = lowered(*request.header("origin"));
    if (!ceremony || !ceremony->enroll || ceremony->recovery || ceremony->origin != origin) {
        return error(404, "not_found", "this registration is unknown or expired; begin again");
    }
    auto registered = registered_passkey(*body, *ceremony);
    if (auto* refused = std::get_if<http::Response>(&registered)) {
        return std::move(*refused);
    }
    protocol::PresenceCredential* const credential =
        &std::get<protocol::PresenceCredential>(registered);
    std::filesystem::create_directories(services_.directory);
    const auto lock = ledger::DirectoryLock::acquire(services_.directory, 2000);
    if (!lock) {
        return error(503, "unavailable", "the console's users are being changed; try again");
    }
    People people = load_people(services_.directory);
    const protocol::Timestamp now = services_.clock->now();
    const auto invitation = std::ranges::find_if(people.invitations, [&](const Invitation& i) {
        return i.hash == ceremony->invitation && i.expires > now;
    });
    if (invitation == people.invitations.end()) {
        return error(404, "not_found", "this invitation was used or expired meanwhile");
    }
    if (people.owner_of(credential->credential_id) != nullptr) {
        return error(409, "conflict", "this passkey is registered already");
    }
    // The first run: there is no ledger yet, so the owner's setup makes it,
    // with the console's keys, and the owner on it.
    const std::filesystem::path ledger_directory = services_.directory.parent_path();
    if (invitation->user.empty() && invitation->role == Role::owner &&
        !has_ledger(ledger_directory)) {
        if (services_.keys == nullptr) {
            return error(503, "unavailable", "this console keeps no keys");
        }
        const std::string prf = text_field(*body, "prf");
        const bool slot = is_prf_output(prf);
        const SetUp setup{ledger_directory, ceremony->name, std::move(*credential),
                          slot ? std::optional(prf) : std::nullopt, std::nullopt};
        FirstRun run;
        try {
            run = set_up(setup, *services_.keys, *services_.entropy);
        } catch (const std::exception& e) {
            return error(409, "conflict", e.what());
        }
        ready_now();
        const People made = load_people(services_.directory);
        http::Response answer = signed_in(*services_.sessions, *made.find(ceremony->name));
        auto fields = nlohmann::json::parse(answer.body.begin(), answer.body.end());
        fields["keys"] = key_state();
        fields["key_slot"] = slot;
        fields["first_run"] = true;
        fields["recovery_code"] = run.recovery_code;
        fields["ledger"] = to_hex(run.ledger.bytes());
        return json(200, fields);
    }
    const Role role = invitation->role;
    if (User* user = people.find(ceremony->name)) {
        if (invitation->user != ceremony->name) {
            return error(409, "conflict", "someone of that name uses the console already");
        }
        user->passkeys.push_back(std::move(*credential));
    } else {
        if (invitation->user.empty() && role == Role::owner && people.has_owner()) {
            return error(409, "conflict", "the console has an owner already");
        }
        people.users.push_back({ceremony->name, role, now, {std::move(*credential)}, {}, {}});
    }
    people.invitations.erase(invitation);
    save_people(services_.directory, people);
    const User& user = *people.find(ceremony->name);
    // An owner's or an admin's new passkey that gave its PRF output unlocks
    // the console from now on.
    const std::string prf = text_field(*body, "prf");
    bool slot = false;
    if (KeyStore* keys = services_.keys; keys != nullptr && keys->unlocked() &&
                                         (role == Role::owner || role == Role::admin) &&
                                         is_prf_output(prf)) {
        keys->add_slot({SlotKind::prf, to_base64url(user.passkeys.back().credential_id)}, prf);
        slot = true;
    }
    http::Response answer = signed_in(*services_.sessions, user);
    auto fields = nlohmann::json::parse(answer.body.begin(), answer.body.end());
    fields["keys"] = key_state();
    fields["key_slot"] = slot;
    return json(200, fields);
}

http::Response Console::sign_in_begin(const http::Request& request) const {
    const std::string origin = lowered(*request.header("origin"));
    const auto rp_id = rp_id_for(origin);
    if (!rp_id) {
        return no_passkeys_here();
    }
    const Bytes challenge = services_.entropy->bytes<32>() | std::ranges::to<Bytes>();
    const auto id = begin({false,
                           challenge,
                           *rp_id,
                           origin,
                           {},
                           {},
                           services_.clock->now() + ceremony_lifetime,
                           false});
    if (!id) {
        return error(429, "unavailable", "too many passkey requests are waiting; try again soon");
    }
    nlohmann::json options{{"challenge", to_base64url(challenge)},
                           {"rpId", *rp_id},
                           {"userVerification", "required"},
                           {"timeout", ceremony_lifetime}};
    // With sealed keys, the passkey's PRF output (where it has one) unlocks
    // them: the same salt every time, so the same passkey gives the same.
    if (services_.keys != nullptr && services_.keys->initialized()) {
        options["extensions"] = {{"prf", {{"eval", {{"first", prf_salt()}}}}}};
    }
    return json(200, {{"ceremony", *id}, {"public_key", options}});
}

http::Response Console::sign_in_finish(const http::Request& request) const {
    const auto body = body_of(request);
    if (!body) {
        return bad("the request's body is not a JSON object");
    }
    const auto ceremony = take(text_field(*body, "ceremony"));
    const std::string origin = lowered(*request.header("origin"));
    if (!ceremony || ceremony->enroll || ceremony->origin != origin) {
        return error(404, "not_found", "this sign-in is unknown or expired; begin again");
    }
    const auto id = bytes_field(*body, "credential_id");
    const auto data = bytes_field(*body, "authenticator_data");
    const auto client_data = bytes_field(*body, "client_data_json");
    const auto signature = bytes_field(*body, "signature");
    if (!id || !data || !client_data || !signature) {
        return bad("signing in needs credential_id, authenticator_data, client_data_json, and "
                   "signature (base64url)");
    }
    const People people = load_people(services_.directory);
    std::vector<protocol::PresenceCredential> passkeys;
    for (const User& user : people.users) {
        for (const auto& p : user.passkeys) {
            if (p.rp_id == ceremony->rp_id) {
                passkeys.push_back(p);
            }
        }
    }
    const protocol::PresenceProof proof{*id, *data, *client_data, *signature};
    const auto check =
        protocol::verify_assertion(*services_.provider, ceremony->challenge, proof, passkeys);
    const User* user = people.owner_of(*id);
    if (!check || !check->user_verified || lowered(check->origin) != ceremony->origin ||
        user == nullptr) {
        http::Response refused = error(401, "unauthorized", "the passkey did not sign in");
        refused.headers.emplace_back("WWW-Authenticate", "Bearer");
        return refused;
    }
    use_prf(*user, *id, text_field(*body, "prf"));
    http::Response answer = signed_in(*services_.sessions, *user);
    auto fields = nlohmann::json::parse(answer.body.begin(), answer.body.end());
    fields["keys"] = key_state();
    return json(200, fields);
}

} // namespace cexchain::console
