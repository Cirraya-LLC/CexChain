// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/ledger/environment.hpp>

/// The console's sessions. A session is a random 256-bit token that the page
/// keeps in sessionStorage and sends as "Authorization: Bearer"; the node
/// keeps only the token's hash, in its memory, so a session also ends when
/// the console stops. A session ends after 30 idle minutes, after 12 hours
/// at most, when its user signs out, or when it is revoked from the command
/// line, which writes its id to a file the console reads at each request.
namespace cexchain::console {

inline constexpr protocol::Timestamp session_idle_limit = 30 * 60'000;
inline constexpr protocol::Timestamp session_lifetime = 12 * 60 * 60'000;

struct Session {
    /// 16 hex digits naming it in lists: the first 8 bytes of the token's
    /// hash (the token itself is never kept).
    std::string id;
    std::string user;
    protocol::Timestamp created = 0;
    protocol::Timestamp last_used = 0;

    /// When it ends if not used again: 30 minutes after its last use, and
    /// never later than 12 hours after it began.
    [[nodiscard]] protocol::Timestamp expires() const noexcept;
};

/// The token of an "Authorization: Bearer cxs_..." header, if it is one:
/// "cxs_" and 43 base64url characters.
[[nodiscard]] std::optional<std::string_view> bearer_token(std::string_view authorization);

/// The directory of the console's own files in a ledger directory.
[[nodiscard]] std::filesystem::path state_directory(const std::filesystem::path& ledger);

class Sessions {
public:
    /// `directory` holds the published list and the revocations; the
    /// provider, clock, and entropy must outlive this.
    Sessions(std::filesystem::path directory, const crypto::Provider& provider,
             ledger::Clock& clock, ledger::Entropy& entropy);

    /// Begins a session for `user` and returns its token, which only the
    /// caller ever sees.
    [[nodiscard]] std::string create(std::string_view user);
    /// The live session with this token, its idle time restarted; nothing if
    /// the token is unknown, or its session expired or was revoked.
    [[nodiscard]] std::optional<Session> use(std::string_view token);
    /// Ends the session with this token (signing out); false if none.
    bool end(std::string_view token);
    /// The live sessions, oldest first.
    [[nodiscard]] std::vector<Session> list();

private:
    void sweep();
    void publish();

    std::filesystem::path directory_;
    const crypto::Provider* provider_;
    ledger::Clock* clock_;
    ledger::Entropy* entropy_;
    std::mutex mutex_;
    /// By the token's hash (hex).
    std::map<std::string, Session> sessions_;
    /// The revocations file's size when last read.
    std::uintmax_t revocations_read_ = 0;
};

/// A session as the console publishes it for the command line, which runs
/// in another process: its last use is not published, so it ends by
/// `created` plus 12 hours at the latest.
struct PublishedSession {
    std::string id;
    std::string user;
    protocol::Timestamp created = 0;
};

/// The live sessions as the console last published them (none if it never
/// did).
[[nodiscard]] std::vector<PublishedSession>
published_sessions(const std::filesystem::path& directory);
/// Asks the console to end the session with this id at its next request.
void request_revocation(const std::filesystem::path& directory, std::string_view id);

} // namespace cexchain::console
