// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/records.hpp>
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
    /// The `cexchain` program, which the rules routes run as `cexchain bo
    /// ...` in a child process; empty for a console that runs no compiler.
    std::string compiler{};
};

/// The compiler in a child process: at most this long, this much memory,
/// and this much output; sources and sheets at most this large.
inline constexpr std::chrono::seconds compiler_time{30};
inline constexpr std::uint64_t compiler_memory_mib = 1024;
inline constexpr std::size_t compiler_output = 8 * 1024 * 1024;
inline constexpr std::size_t max_rules_input = 256 * 1024;
inline constexpr std::size_t max_compiler_runs = 2;

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
    /// Registering an owner's new passkey after the recovery code opened the
    /// console: only the recovery route finishes it.
    bool recovery = false;
};

/// A statement prepared for a person's approval: built and held by the
/// console, approved once, within two minutes, by that person's passkey tap.
/// A file uploaded for a registration: kept in the console's folder, for
/// its user only, until the registration is approved or it expires.
struct Upload {
    std::string user;
    std::string name;
    std::string media_type;
    std::uint64_t size = 0;
    std::filesystem::path path;
    protocol::Timestamp expires = 0;
};

inline constexpr protocol::Timestamp upload_lifetime = 30 * 60'000;
inline constexpr std::size_t max_uploads = 64;

/// A record's registration being prepared: the private data and the files
/// the console seals once the statement is signed (they name its id).
struct Draft {
    app::Vault vault;
    /// The uploads it attaches, in the registration's order.
    std::vector<std::string> uploads;
    bool keep_files = false;
};

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
    /// For a registration.
    std::optional<Draft> draft;
};

inline constexpr protocol::Timestamp approval_lifetime = 2 * 60'000;

/// Wrong recovery codes: at most this many a minute (each costs a scrypt),
/// and one checked at a time.
inline constexpr std::size_t max_recovery_failures = 5;
inline constexpr protocol::Timestamp recovery_failure_window = 60'000;

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
    void set_ledger(const ledger::Ledger* ledger) {
        const std::lock_guard lock(api_mutex_);
        ledger_ = ledger;
    }

    /// Registers a signed statement on the node's ledger, answering as
    /// POST /v1/statements would (through the callback): `body` is the signed
    /// statement, or, with `submission`, a submission (a record's
    /// registration with its sealed private data and files). Until it is
    /// set, approvals answer 503.
    using Submit =
        std::function<void(Bytes body, bool submission, std::function<void(http::Response)>)>;
    void set_submitter(Submit submit) {
        const std::lock_guard lock(api_mutex_);
        submit_ = std::move(submit);
    }

    /// A record's evidence bundle from the node, without private data
    /// (node::LedgerApi::record_evidence). Until it is set, proofs answer 503.
    using Evidence =
        std::function<void(const protocol::Id& record, std::function<void(Result<Bytes>)>)>;
    void set_evidence(Evidence evidence) {
        const std::lock_guard lock(api_mutex_);
        evidence_ = std::move(evidence);
    }
    /// An instance's contract evidence from the node
    /// (node::LedgerApi::instance_evidence). Until it is set, proofs of
    /// things with rules answer 503.
    void set_instance_evidence(Evidence evidence) {
        const std::lock_guard lock(api_mutex_);
        instance_evidence_ = std::move(evidence);
    }

    /// Called once the console is set up or unlocked, when the ledger's API
    /// can open (DeferredApi::open_now).
    void set_on_ready(std::function<void()> ready) {
        const std::lock_guard lock(api_mutex_);
        on_ready_ = std::move(ready);
    }

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
    /// What an approval sends to the ledger: the signed statement, or a
    /// submission; and the uploads it used, forgotten once it is registered.
    struct Signing {
        Bytes body;
        bool submission = false;
        std::vector<std::string> uploads;
    };
    [[nodiscard]] std::variant<Signing, http::Response>
    sign_approval(const http::Request& request) const;
    [[nodiscard]] http::Response upload_route(const http::Request& request) const;
    /// A registration's statement body and draft from the page's intent, or
    /// why there is none.
    [[nodiscard]] std::variant<std::pair<protocol::RecordRegisterBody, Draft>, std::string>
    register_draft(const nlohmann::json& intent, const std::string& user) const;
    /// Removes uploads (and their files).
    void forget_uploads(const std::vector<std::string>& ids) const;
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
    [[nodiscard]] http::Response settings_route(const http::Request& request) const;
    [[nodiscard]] http::Response kinds_route(const http::Request& request) const;
    /// /console/api/rules/...: the compiler on a sheet or a source.
    [[nodiscard]] http::Response rules_route(const http::Request& request) const;
    /// Things with rules (instances.cpp): a deployed contract as a .boc
    /// (Bo only), what its calls take (`bo calls` in the child), a
    /// contract's page, a thing's page, a call built from an intent, and a
    /// call run on the state before the tap.
    [[nodiscard]] std::optional<Bytes> deployed_boc(const protocol::Id& contract) const;
    [[nodiscard]] std::variant<nlohmann::json, http::Response>
    contract_calls(const Signed& who, const protocol::Id& contract, const std::string& language,
                   const std::vector<std::string>& more = {}) const;
    [[nodiscard]] http::Response contract_route(const Signed& who, const protocol::Id& contract,
                                                const http::Request& request) const;
    [[nodiscard]] http::Response instance_route(const http::Request& request) const;
    [[nodiscard]] std::variant<protocol::ContractCallBody, http::Response>
    call_body(const Signed& who, const nlohmann::json& intent, const std::string& action) const;
    [[nodiscard]] nlohmann::json dry_run(const protocol::LedgerState& state,
                                         const protocol::Statement& statement,
                                         const protocol::ActorState& actor,
                                         const std::string& language) const;
    /// What the compiler answered, and the files it wrote that were asked
    /// for.
    struct CompilerRun {
        nlohmann::json answer;
        std::map<std::string, Bytes> files;
    };
    /// Runs `compiler bo ARGS... --json --max-memory N` for this session's
    /// user, with `files` written to a private directory first (an argument
    /// naming one of them, or one of `outputs`, becomes its path): the
    /// compiler's JSON and the `outputs` it wrote, or the answer that says
    /// why there is none.
    [[nodiscard]] std::variant<CompilerRun, http::Response>
    run_compiler(const Signed& who, std::vector<std::string> args,
                 const std::vector<std::pair<std::string, std::string>>& files,
                 const std::vector<std::string>& outputs = {}) const;
    /// GET /console/api/rules: the contracts deployed on the ledger.
    [[nodiscard]] http::Response contracts_route(const Signed& who) const;
    /// A contract's deploy, built from a source by the compiler, or why not.
    [[nodiscard]] std::variant<protocol::ContractDeployBody, http::Response>
    deploy_body(const Signed& who, const std::string& source) const;
    /// GET /console/api/records/ID, and .../ID/files/INDEX (a kept file).
    [[nodiscard]] http::Response record_route(const http::Request& request) const;
    /// POST /console/api/proof: a record's evidence with the fields and
    /// files the person chose to disclose, as a file.
    void proof_route(const http::Request& request, Respond respond) const;
    /// Whether this user may read a record's private data: owners and
    /// admins every record's, members those they registered and those of
    /// types their delegations let them register, viewers none.
    [[nodiscard]] bool may_read_private(const Signed& who, const protocol::LedgerState& state,
                                        const protocol::RecordState& record) const;
    /// A record's registration, as its log entry holds it.
    [[nodiscard]] std::optional<protocol::RecordRegisterBody>
    registration(const protocol::LedgerState& state, const protocol::Id& record) const;
    /// The record's private data, opened with the console's vault key and
    /// checked against the ledger; nothing if it cannot be.
    [[nodiscard]] std::optional<app::Vault> private_data(const protocol::LedgerState& state,
                                                         const protocol::Id& record) const;
    [[nodiscard]] nlohmann::json settings_view(Role role) const;
    [[nodiscard]] http::Response enroll_begin(const http::Request& request) const;
    [[nodiscard]] http::Response enroll_finish(const http::Request& request) const;
    [[nodiscard]] http::Response sign_in_begin(const http::Request& request) const;
    [[nodiscard]] http::Response sign_in_finish(const http::Request& request) const;
    [[nodiscard]] http::Response unlock_route(const http::Request& request) const;
    [[nodiscard]] http::Response prepare_route(const http::Request& request) const;
    [[nodiscard]] http::Response approve_route(const http::Request& request) const;
    /// A lost passkey: the recovery code opens the console and begins
    /// registering a new passkey for the owner, whose passkeys the root key
    /// then replaces with it on the ledger.
    [[nodiscard]] http::Response recover_begin(const http::Request& request) const;
    [[nodiscard]] http::Response recover_finish(const http::Request& request) const;
    struct Recovery {
        Bytes statement;
        std::string user;
        protocol::PresenceCredential passkey;
        /// The lost passkeys' credential ids (base64url), whose PRF slots go.
        std::vector<std::string> old_passkeys;
        /// The new passkey's PRF output, if it gave one: its slot.
        std::string prf;
    };
    /// Checks a recovery's new passkey and signs the statement that makes it
    /// the owner's only one: the plan, or the answer that refuses it.
    [[nodiscard]] std::variant<Recovery, http::Response>
    recovery_plan(const http::Request& request) const;
    /// Once the ledger registered it: the console's users and keys follow,
    /// the owner's other sessions end, and a new one begins.
    [[nodiscard]] http::Response finish_recovery(const Recovery& recovery,
                                                 const http::Response& registered) const;
    /// A passkey registration's options for `name`, excluding `exclude`.
    /// With `prf`, the passkey is asked for its PRF output at once, so that
    /// it unlocks the console's keys from its first use.
    [[nodiscard]] nlohmann::json registration_options(ByteView challenge, std::string_view rp_id,
                                                      std::string_view name,
                                                      const std::vector<Bytes>& exclude,
                                                      bool prf) const;
    /// Checks a registration's answer to `ceremony`: the new passkey, or the
    /// answer that refuses it.
    [[nodiscard]] std::variant<protocol::PresenceCredential, http::Response>
    registered_passkey(const nlohmann::json& body, const Ceremony& ceremony) const;
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
    [[nodiscard]] const ledger::Ledger* ledger() const {
        const std::lock_guard lock(api_mutex_);
        return ledger_;
    }
    [[nodiscard]] Submit submitter() const {
        const std::lock_guard lock(api_mutex_);
        return submit_;
    }
    [[nodiscard]] Evidence evidence() const {
        const std::lock_guard lock(api_mutex_);
        return evidence_;
    }
    [[nodiscard]] Evidence instance_evidence() const {
        const std::lock_guard lock(api_mutex_);
        return instance_evidence_;
    }
    /// Tells the node the ledger's API may open (set up, or unlocked).
    void ready_now() const;

    mutable std::mutex api_mutex_;
    const ledger::Ledger* ledger_ = nullptr;
    Submit submit_;
    Evidence evidence_;
    Evidence instance_evidence_;
    std::function<void()> on_ready_;
    mutable std::mutex mutex_;
    std::vector<Origin> origins_;
    mutable std::map<std::string, Ceremony> ceremonies_;
    mutable std::map<std::string, Prepared> prepared_;
    mutable std::map<std::string, Upload> uploads_;
    /// The sessions the compiler runs for now (one run each).
    mutable std::set<std::string> compiling_;
    /// Uploads left by an earlier run are removed at the first upload.
    mutable bool uploads_swept_ = false;
    /// When recovery codes were refused lately, and whether one is being
    /// checked.
    mutable std::vector<protocol::Timestamp> recovery_failures_;
    mutable bool checking_recovery_ = false;
};

} // namespace cexchain::console
