// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cctype>
#include <fstream>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/support.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/core/bytes.hpp>

namespace cexchain::console {

namespace {

constexpr std::string_view token_prefix = "cxs_";
constexpr std::size_t token_size = 4 + 43;
constexpr std::string_view published_file = "sessions.json";
constexpr std::string_view revocations_file = "revoked";

bool base64url(unsigned char c) {
    return std::isalnum(c) != 0 || c == '-' || c == '_';
}

bool session_id(std::string_view id) {
    return id.size() == 16 && std::ranges::all_of(id, [](unsigned char c) {
               return std::isdigit(c) != 0 || (c >= 'a' && c <= 'f');
           });
}

} // namespace

protocol::Timestamp Session::expires() const noexcept {
    return std::min(created + session_lifetime, last_used + session_idle_limit);
}

std::optional<std::string_view> bearer_token(std::string_view authorization) {
    constexpr std::string_view scheme = "bearer ";
    if (authorization.size() != scheme.size() + token_size) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < scheme.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(authorization[i])) != scheme[i]) {
            return std::nullopt;
        }
    }
    const std::string_view token = authorization.substr(scheme.size());
    if (!token.starts_with(token_prefix) ||
        !std::ranges::all_of(token.substr(token_prefix.size()), base64url)) {
        return std::nullopt;
    }
    return token;
}

std::filesystem::path state_directory(const std::filesystem::path& ledger) {
    return ledger / "console";
}

Sessions::Sessions(std::filesystem::path directory, const crypto::Provider& provider,
                   ledger::Clock& clock, ledger::Entropy& entropy)
    : directory_(std::move(directory)), provider_(&provider), clock_(&clock), entropy_(&entropy) {}

std::string Sessions::create(std::string_view user) {
    const std::lock_guard lock(mutex_);
    sweep();
    const std::string token = std::string(token_prefix) + to_base64url(entropy_->bytes<32>());
    const auto digest = provider_->digest(crypto::HashAlg::sha256, as_bytes(token));
    if (!digest) {
        throw std::runtime_error("hashing a session token failed");
    }
    const std::string hash = to_hex(digest->bytes());
    const protocol::Timestamp now = clock_->now();
    sessions_[hash] = Session{hash.substr(0, 16), std::string(user), now, now};
    publish();
    return token;
}

std::optional<Session> Sessions::use(std::string_view token) {
    const auto digest = provider_->digest(crypto::HashAlg::sha256, as_bytes(token));
    if (!digest) {
        return std::nullopt;
    }
    const std::lock_guard lock(mutex_);
    sweep();
    const auto found = sessions_.find(to_hex(digest->bytes()));
    if (found == sessions_.end()) {
        return std::nullopt;
    }
    found->second.last_used = clock_->now();
    return found->second;
}

bool Sessions::end(std::string_view token) {
    const auto digest = provider_->digest(crypto::HashAlg::sha256, as_bytes(token));
    const std::lock_guard lock(mutex_);
    if (!digest || sessions_.erase(to_hex(digest->bytes())) == 0) {
        return false;
    }
    publish();
    return true;
}

std::size_t Sessions::end_all(std::string_view user) {
    const std::lock_guard lock(mutex_);
    const std::size_t ended =
        std::erase_if(sessions_, [&](const auto& entry) { return entry.second.user == user; });
    if (ended != 0) {
        publish();
    }
    return ended;
}

std::vector<Session> Sessions::list() {
    const std::lock_guard lock(mutex_);
    sweep();
    std::vector<Session> live;
    for (const auto& [hash, session] : sessions_) {
        live.push_back(session);
    }
    std::ranges::sort(live, {}, &Session::created);
    return live;
}

/// Drops the sessions that expired, and those the command line revoked
/// since the revocations file was last read; publishes the list if it
/// changed. Holds the mutex.
void Sessions::sweep() {
    bool changed = false;
    const std::filesystem::path revoked = directory_ / revocations_file;
    std::error_code ec;
    const std::uintmax_t size = std::filesystem::file_size(revoked, ec);
    if (!ec && size != revocations_read_) {
        std::ifstream in(revoked);
        std::string id;
        while (std::getline(in, id)) {
            changed |= std::erase_if(sessions_,
                                     [&](const auto& entry) { return entry.second.id == id; }) > 0;
        }
        revocations_read_ = size;
    }
    const protocol::Timestamp now = clock_->now();
    changed |= std::erase_if(sessions_,
                             [&](const auto& entry) { return now >= entry.second.expires(); }) > 0;
    if (changed) {
        publish();
    }
}

/// Writes the live sessions for the command line: ids, users, and start
/// times, never a token or its hash. Holds the mutex. A failure to write is
/// not the request's: the list is only for `console session list`.
void Sessions::publish() {
    nlohmann::json list = nlohmann::json::array();
    for (const auto& [hash, session] : sessions_) {
        list.push_back({{"id", session.id}, {"user", session.user}, {"created", session.created}});
    }
    const std::string text = nlohmann::json{{"sessions", list}}.dump(2) + "\n";
    try {
        std::filesystem::create_directories(directory_);
        app::write_file(directory_ / published_file, as_bytes(text), true);
    } catch (const std::exception&) {
        // Kept in memory regardless; the next change publishes again.
    }
}

std::vector<PublishedSession> published_sessions(const std::filesystem::path& directory) {
    std::vector<PublishedSession> sessions;
    const std::filesystem::path file = directory / published_file;
    if (!std::filesystem::exists(file)) {
        return sessions;
    }
    const Bytes bytes = app::read_file(file);
    const auto document = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!document.is_object() || !document.contains("sessions") ||
        !document["sessions"].is_array()) {
        throw std::runtime_error("the console's list of sessions is damaged");
    }
    for (const auto& s : document["sessions"]) {
        sessions.push_back(
            {s.value("id", ""), s.value("user", ""), s.value("created", protocol::Timestamp{0})});
    }
    std::ranges::sort(sessions, {}, &PublishedSession::created);
    return sessions;
}

void request_revocation(const std::filesystem::path& directory, std::string_view id) {
    if (!session_id(id)) {
        throw std::invalid_argument("a session id is 16 hexadecimal digits");
    }
    std::filesystem::create_directories(directory);
    std::ofstream out(directory / revocations_file, std::ios::app);
    out << id << '\n';
    out.close();
    if (!out) {
        throw std::runtime_error("could not write the console's revocations");
    }
    std::filesystem::permissions(directory / revocations_file,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write);
}

} // namespace cexchain::console
