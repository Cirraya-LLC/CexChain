// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/console/keystore.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/console/users.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/node/http.hpp>

/// The web console's server side: the page's files, compiled into the
/// binary; the headers every answer carries; and the checks every request
/// passes before anything else (its Host and its Origin). The node serves it
/// beside its API, through `node::ApiOptions::console`.
namespace cexchain::console {

namespace http = node::http;

/// The Content-Security-Policy of every console answer: the page's own
/// scripts, styles, and WebAssembly, nothing inline, nothing from elsewhere.
inline constexpr std::string_view content_security_policy =
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
    "img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'";

/// An origin the console answers for: "http://localhost:7470",
/// "https://ledger.example.com". Lower case, no path, no default port.
struct Origin {
    std::string scheme;
    std::string host;
    /// 0 for the scheme's default port.
    unsigned port = 0;

    /// "scheme://host[:port]", as browsers send it in an Origin header.
    [[nodiscard]] std::string text() const;
    /// "host[:port]", as a Host header names it.
    [[nodiscard]] std::string authority() const;
};

/// Parses a public URL ("https://ledger.example.com", with no path but "/")
/// into its origin. Errc::invalid_argument otherwise.
[[nodiscard]] Result<Origin> parse_origin(std::string_view url);

/// The origins of a console on this computer's loopback addresses at `port`:
/// localhost, 127.0.0.1, and [::1], over http.
[[nodiscard]] std::vector<Origin> loopback_origins(unsigned port);

/// What the console's routes use; each must outlive the console.
struct Services {
    /// The console's folder in the ledger directory (state_directory).
    std::filesystem::path directory;
    const crypto::Provider* provider = nullptr;
    ledger::Clock* clock = nullptr;
    ledger::Entropy* entropy = nullptr;
    Sessions* sessions = nullptr;
    /// The console's sealed keys; without it, nothing is ever unlocked.
    KeyStore* keys = nullptr;
};

/// A passkey ceremony begun and not yet finished: registering one with an
/// invitation, or signing in. Its challenge is used once.
struct Ceremony {
    bool enroll = false;
    Bytes challenge;
    std::string rp_id;
    std::string origin;
    /// For registering: the invitation's hash and the name to register.
    std::string invitation;
    std::string name;
    protocol::Timestamp expires = 0;
};

/// A statement prepared for a person's approval: built and held by the
/// console, approved once, within two minutes, by that person's passkey tap.
struct Prepared {
    std::string user;
    protocol::Statement statement;
    /// The signer's key id, which the presence challenge names.
    protocol::Id kid;
    /// The console's sealed key that signs it.
    std::string key;
    Bytes challenge;
    std::string rp_id;
    std::string origin;
    protocol::Timestamp expires = 0;
};

inline constexpr protocol::Timestamp approval_lifetime = 2 * 60'000;

/// A ceremony must finish within five minutes; at most this many wait.
inline constexpr protocol::Timestamp ceremony_lifetime = 5 * 60'000;
inline constexpr std::size_t max_ceremonies = 256;

class Console {
public:
    /// Without services, every route that needs them answers 503.
    Console() = default;
    explicit Console(Services services) : services_(std::move(services)) {}

    /// The origins it answers for. Until they are set (once the server knows
    /// its port), every request is refused.
    void set_origins(std::vector<Origin> origins);

    /// The ledger the node serves, which the console's views read (under its
    /// readers' lock). Until it is set, they answer 503.
    void set_ledger(const ledger::Ledger* ledger) noexcept { ledger_ = ledger; }

    /// Registers a signed statement on the node's ledger, answering as
    /// POST /v1/statements would (through the callback). Until it is set,
    /// approvals answer 503.
    using Submit = std::function<void(Bytes statement, std::function<void(http::Response)>)>;
    void set_submitter(Submit submit) { submit_ = std::move(submit); }

    /// Answers a request whose path is /console or under /console/.
    [[nodiscard]] http::Response handle(const http::Request& request) const;
    /// The same through `respond`: an approval's answer comes when the ledger
    /// has registered it, so the caller's thread never waits for the writer.
    using Respond = std::function<void(http::Response)>;
    void handle(const http::Request& request, Respond respond) const;

private:
    [[nodiscard]] http::Response route(const http::Request& request) const;
    /// The answer to a request that fails the checks every request passes
    /// first (the console started, its Host, its Origin); nothing if it passes.
    [[nodiscard]] std::optional<http::Response> refuse(const http::Request& request) const;
    /// Checks an approval and signs its statement: the signed statement, or
    /// the answer that refuses it.
    [[nodiscard]] std::variant<Bytes, http::Response>
    sign_approval(const http::Request& request) const;
    [[nodiscard]] bool ready() const noexcept;
    /// Who signed this request: the session's user, or the 401 to answer.
    struct Signed {
        std::string token;
        Session session;
        std::string user;
        Role role = Role::viewer;
    };
    [[nodiscard]] std::variant<Signed, http::Response>
    authenticate(const http::Request& request) const;
    [[nodiscard]] http::Response session_route(const http::Request& request) const;
    [[nodiscard]] http::Response home_route(const Signed& who) const;
    [[nodiscard]] http::Response things_route(const http::Request& request) const;
    [[nodiscard]] http::Response enroll_begin(const http::Request& request) const;
    [[nodiscard]] http::Response enroll_finish(const http::Request& request) const;
    [[nodiscard]] http::Response sign_in_begin(const http::Request& request) const;
    [[nodiscard]] http::Response sign_in_finish(const http::Request& request) const;
    [[nodiscard]] http::Response unlock_route(const http::Request& request) const;
    [[nodiscard]] http::Response prepare_route(const http::Request& request) const;
    [[nodiscard]] http::Response approve_route(const http::Request& request) const;
    /// The salt every PRF evaluation of this console uses (made once).
    [[nodiscard]] std::string prf_salt() const;
    /// After a passkey signed in: unlock with its PRF output, or, unlocked,
    /// give it a slot when its user may.
    void use_prf(const User& user, ByteView credential, std::string_view prf) const;
    [[nodiscard]] nlohmann::json key_state() const;
    /// Stores a ceremony and returns its id; nothing if too many wait.
    [[nodiscard]] std::optional<std::string> begin(Ceremony ceremony) const;
    /// Takes (and forgets) a ceremony that has not expired.
    [[nodiscard]] std::optional<Ceremony> take(std::string_view id) const;

    Services services_;
    const ledger::Ledger* ledger_ = nullptr;
    Submit submit_;
    mutable std::mutex mutex_;
    std::vector<Origin> origins_;
    mutable std::map<std::string, Ceremony> ceremonies_;
    mutable std::map<std::string, Prepared> prepared_;
};

} // namespace cexchain::console
