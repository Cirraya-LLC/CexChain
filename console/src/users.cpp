// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/console/users.hpp>
#include <cexchain/core/bytes.hpp>

namespace cexchain::console {

namespace {

constexpr std::string_view people_file = "users.json";
constexpr std::string_view invitation_prefix = "cxi_";

constexpr std::array<std::pair<Role, std::string_view>, 4> role_names{{
    {Role::owner, "owner"},
    {Role::admin, "admin"},
    {Role::member, "member"},
    {Role::viewer, "viewer"},
}};

[[noreturn]] void damaged() {
    throw std::runtime_error("the console's users.json is damaged");
}

Bytes decoded(const nlohmann::json& value) {
    if (!value.is_string()) {
        damaged();
    }
    auto bytes = from_base64url(value.get<std::string>());
    if (!bytes) {
        damaged();
    }
    return std::move(*bytes);
}

nlohmann::json passkey_json(const protocol::PresenceCredential& p) {
    nlohmann::json out{{"rp_id", p.rp_id},
                       {"credential_id", to_base64url(p.credential_id)},
                       {"algorithm", crypto::cose_id(p.key.algorithm)},
                       {"public_key", to_base64url(p.key.bytes)}};
    if (p.label) {
        out["label"] = *p.label;
    }
    return out;
}

protocol::PresenceCredential passkey_of(const nlohmann::json& j) {
    if (!j.is_object() || !j.contains("rp_id") || !j["rp_id"].is_string() ||
        !j.contains("algorithm") || !j["algorithm"].is_number_integer()) {
        damaged();
    }
    const auto alg = crypto::sig_alg_from_cose(j["algorithm"].get<std::int64_t>());
    if (!alg) {
        damaged();
    }
    protocol::PresenceCredential p;
    p.rp_id = j["rp_id"].get<std::string>();
    p.credential_id = decoded(j.value("credential_id", nlohmann::json()));
    p.key = crypto::PublicKey{*alg, decoded(j.value("public_key", nlohmann::json()))};
    if (j.contains("label") && j["label"].is_string()) {
        p.label = j["label"].get<std::string>();
    }
    return p;
}

Role role_of(const nlohmann::json& j) {
    const auto role = j.is_string() ? parse_role(j.get<std::string>()) : std::nullopt;
    if (!role) {
        damaged();
    }
    return *role;
}

} // namespace

std::string_view name_of(Role role) noexcept {
    for (const auto& [r, name] : role_names) {
        if (r == role) {
            return name;
        }
    }
    return "viewer";
}

std::optional<Role> parse_role(std::string_view name) noexcept {
    for (const auto& [role, n] : role_names) {
        if (n == name) {
            return role;
        }
    }
    return std::nullopt;
}

bool valid_user_name(std::string_view name) noexcept {
    return !name.empty() && name.size() <= 64 && name.front() != ' ' && name.back() != ' ' &&
           std::ranges::all_of(name, [](unsigned char c) {
               return std::isalnum(c) != 0 || c == ' ' || c == '.' || c == '_' || c == '-';
           });
}

const User* People::find(std::string_view name) const noexcept {
    const auto it = std::ranges::find(users, name, &User::name);
    return it == users.end() ? nullptr : &*it;
}

User* People::find(std::string_view name) noexcept {
    const auto it = std::ranges::find(users, name, &User::name);
    return it == users.end() ? nullptr : &*it;
}

bool People::has_owner() const noexcept {
    return std::ranges::any_of(users, [](const User& u) { return u.role == Role::owner; });
}

const User* People::owner_of(ByteView credential_id) const noexcept {
    for (const User& u : users) {
        for (const auto& p : u.passkeys) {
            if (std::ranges::equal(p.credential_id, credential_id)) {
                return &u;
            }
        }
    }
    return nullptr;
}

People load_people(const std::filesystem::path& directory) {
    People people;
    const std::filesystem::path file = directory / people_file;
    if (!std::filesystem::exists(file)) {
        return people;
    }
    const Bytes bytes = app::read_file(file);
    const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!j.is_object() || !j.contains("users") || !j["users"].is_array() ||
        !j.contains("invitations") || !j["invitations"].is_array()) {
        damaged();
    }
    for (const auto& u : j["users"]) {
        if (!u.is_object() || !u.contains("passkeys") || !u["passkeys"].is_array()) {
            damaged();
        }
        User user{u.value("name", ""),
                  role_of(u.value("role", nlohmann::json())),
                  u.value("created", protocol::Timestamp{0}),
                  {},
                  u.value("actor", ""),
                  u.value("key", "")};
        for (const auto& p : u["passkeys"]) {
            user.passkeys.push_back(passkey_of(p));
        }
        if (!valid_user_name(user.name)) {
            damaged();
        }
        people.users.push_back(std::move(user));
    }
    for (const auto& i : j["invitations"]) {
        if (!i.is_object()) {
            damaged();
        }
        people.invitations.push_back({i.value("id", ""), i.value("hash", ""), i.value("user", ""),
                                      role_of(i.value("role", nlohmann::json())),
                                      i.value("created", protocol::Timestamp{0}),
                                      i.value("expires", protocol::Timestamp{0})});
    }
    return people;
}

void save_people(const std::filesystem::path& directory, const People& people) {
    nlohmann::json users = nlohmann::json::array();
    for (const User& u : people.users) {
        nlohmann::json passkeys = nlohmann::json::array();
        for (const auto& p : u.passkeys) {
            passkeys.push_back(passkey_json(p));
        }
        nlohmann::json user{{"name", u.name},
                            {"role", name_of(u.role)},
                            {"created", u.created},
                            {"passkeys", passkeys}};
        if (!u.actor.empty()) {
            user["actor"] = u.actor;
            user["key"] = u.key;
        }
        users.push_back(std::move(user));
    }
    nlohmann::json invitations = nlohmann::json::array();
    for (const Invitation& i : people.invitations) {
        invitations.push_back({{"id", i.id},
                               {"hash", i.hash},
                               {"user", i.user},
                               {"role", name_of(i.role)},
                               {"created", i.created},
                               {"expires", i.expires}});
    }
    const std::string text =
        nlohmann::json{{"users", users}, {"invitations", invitations}}.dump(2) + "\n";
    std::filesystem::create_directories(directory);
    app::write_file(directory / people_file, as_bytes(text), true);
}

std::optional<std::string> invitation_hash(const crypto::Provider& provider,
                                           std::string_view code) {
    if (code.size() != invitation_prefix.size() + 43 || !code.starts_with(invitation_prefix) ||
        !std::ranges::all_of(code.substr(invitation_prefix.size()), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '-' || c == '_';
        })) {
        return std::nullopt;
    }
    const auto digest = provider.digest(crypto::HashAlg::sha256, as_bytes(code));
    if (!digest) {
        return std::nullopt;
    }
    return to_hex(digest->bytes());
}

std::pair<std::string, Invitation> make_invitation(const crypto::Provider& provider,
                                                   ledger::Entropy& entropy, std::string user,
                                                   Role role, protocol::Timestamp now) {
    std::string code = std::string(invitation_prefix) + to_base64url(entropy.bytes<32>());
    const auto hash = invitation_hash(provider, code);
    if (!hash) {
        throw std::runtime_error("hashing an invitation code failed");
    }
    Invitation invitation{hash->substr(0, 16),      *hash, std::move(user), role, now,
                          now + invitation_lifetime};
    return {std::move(code), std::move(invitation)};
}

} // namespace cexchain::console
