// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/app/support.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/node/client.hpp>

namespace cexchain::app {

/// What a person's authenticator is asked to sign: a passkey assertion over
/// the statement's presence challenge.
struct PasskeyRequest {
    std::string rp_id;
    Bytes challenge;
    /// The person's passkeys for `rp_id`, by credential id.
    std::vector<Bytes> allow;
    /// "Confirm as NAME", and what is being signed, for the person.
    std::string title;
    std::string summary;
};

/// The authenticator's answer.
struct PasskeyAssertion {
    Bytes credential_id;
    Bytes authenticator_data;
    Bytes client_data_json;
    Bytes signature;
};

/// Runs a passkey ceremony: the command line's one-time local page, or the
/// console's approval. Throws if the person cancels.
using PasskeyCeremony = std::function<PasskeyAssertion(const PasskeyRequest&)>;

/// How the signer (a person) proves presence before signing.
struct PresenceRequest {
    /// A hardware key (an opened token key) that signs the challenge;
    /// otherwise a passkey, through `passkey`.
    std::shared_ptr<crypto::Signer> hardware_key = nullptr;
    PasskeyCeremony passkey = {};
};

/// The log key, for what is signed with it on a ledger directory:
/// checkpoints, evidence, and receipts. In client mode the server signs, and
/// a log key given is refused.
struct LogKey {
    bool given = false;
    /// Loads it (on a ledger directory only, when it is needed).
    std::function<std::unique_ptr<crypto::Signer>()> load;
};

/// A server whose ledger a session mirrors (client mode).
struct ServerLocation {
    std::string url;
    std::optional<std::string> ca_file;
    std::optional<std::string> token;
    /// The ledger id expected, in hex: required on first use of an http://
    /// URL, which then pins the ledger it serves.
    std::optional<std::string> ledger_id;
    /// Where mirrors live: default $XDG_CACHE_HOME/cexchain or
    /// ~/.cache/cexchain.
    std::optional<std::filesystem::path> cache;
};

/// A ledger directory, or a server.
using Location = std::variant<std::filesystem::path, ServerLocation>;

/// Makes the sealed private data of the record `id` names (for record
/// registrations, which keep it in the vault).
using SealVault = std::function<Bytes(const protocol::Id& record)>;

/// An open ledger with the environment needed to act on it: a ledger
/// directory, or, in client mode, a verified mirror of the ledger a
/// server serves.
///
/// Client mode, at a ServerLocation: the mirror lives in the cache, one
/// directory per ledger id. Each session first syncs it with the replica
/// code, so every entry and checkpoint it shows was re-validated here, and a
/// server that rewrites or rolls back what this client saw is refused. The
/// ledger a URL serves is pinned on first use. Statements are signed here
/// and sent to the server; keys never leave this machine.
class Session {
public:
    explicit Session(const Location& location);

    [[nodiscard]] ledger::Ledger& ledger() { return *ledger_; }
    [[nodiscard]] const protocol::LedgerState& state() const { return ledger_->state(); }
    [[nodiscard]] const crypto::Provider& provider() const { return provider_; }
    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

    /// Resolves a full or abbreviated (8+ hex digits) identifier among actors,
    /// delegations, or records.
    [[nodiscard]] protocol::Id actor_id(std::string_view text) const;
    [[nodiscard]] protocol::Id record_id(std::string_view text) const;
    [[nodiscard]] protocol::Id delegation_id(std::string_view text) const;
    [[nodiscard]] protocol::Id contract_id(std::string_view text) const;
    [[nodiscard]] protocol::Id instance_id(std::string_view text) const;
    /// A request (v0.8), by its id or a unique prefix.
    [[nodiscard]] protocol::Id request_id(std::string_view text) const;

    /// The actor holding `key`.
    [[nodiscard]] const protocol::ActorState& actor_for(const crypto::Signer& key) const;

    /// Builds, signs, and submits a statement by the holder of `signer`,
    /// choosing a delegation that covers it unless `delegation` is given, and
    /// filling in provenance for agents. Returns the statement's id.
    /// With `presence` set, the signer (a person) first proves presence, with
    /// a passkey in the browser or with a hardware key.
    /// With `seal_vault`, the record's sealed private data is kept with it:
    /// written to the vault here, or sent with the statement in client mode.
    /// With `consents` (a contract call's, in the order it cites them), the
    /// consents' evidence is kept with it the same way.
    protocol::Id submit(const crypto::Signer& signer, protocol::Body body,
                        const std::optional<std::string>& delegation,
                        std::optional<protocol::Provenance> provenance = std::nullopt,
                        const std::optional<PresenceRequest>& presence = std::nullopt,
                        const SealVault& seal_vault = {}, std::span<const Bytes> consents = {});

    /// Builds and signs a statement as `submit` does, without registering
    /// it: to run a contract call first, or for a dry run.
    [[nodiscard]] protocol::SignedStatement
    sign(const crypto::Signer& signer, protocol::Body body,
         const std::optional<std::string>& delegation,
         std::optional<protocol::Provenance> provenance = std::nullopt,
         const std::optional<PresenceRequest>& presence = std::nullopt);
    /// Registers a statement from `sign`, with its sealed private data or
    /// its consents' evidence, as `submit` does.
    protocol::Id submit_signed(const protocol::SignedStatement& statement,
                               const std::optional<Bytes>& sealed = std::nullopt,
                               std::span<const Bytes> consents = {});

    /// Resolves an index or (abbreviated) statement id to a log index.
    [[nodiscard]] std::uint64_t entry_index(std::string_view text) const;

    /// The log entry at `index` and its statement, parsed.
    [[nodiscard]] protocol::LogEntry log_entry(std::uint64_t index) const;
    [[nodiscard]] protocol::SignedStatement statement(std::uint64_t index) const;
    /// The state commitment at `index` (which must be one).
    [[nodiscard]] protocol::SignedStateCommitment state_commitment(std::uint64_t index) const;

    /// The actor's display name, or "unknown" for an unknown id.
    [[nodiscard]] std::string actor_name(const protocol::Id& id) const;

    [[nodiscard]] std::filesystem::path vault_path(const protocol::Id& record) const;

    /// Throws unless this ledger is a primary: a replica only copies its
    /// primary, and writing to it would fork the ledger. (In client mode
    /// writes go to the server.)
    void require_primary() const;

    /// True in client mode.
    [[nodiscard]] bool remote() const noexcept { return remote_.has_value(); }

    // What the log key signs: here with `log_key`; in client mode by the
    // server, and checked against the mirror before it is used.
    [[nodiscard]] protocol::SignedCheckpoint checkpoint(const LogKey& log_key);
    [[nodiscard]] protocol::EvidenceBundle evidence(const LogKey& log_key,
                                                    const protocol::Id& record);
    /// An instance's contract evidence with the consents its calls cite,
    /// without private data: built here with the log key (after a
    /// checkpoint, if the latest does not cover the instance's last call), or
    /// the server's, verified against the mirror.
    [[nodiscard]] Bytes contract_evidence(const LogKey& log_key, const protocol::Id& instance);
    [[nodiscard]] Bytes receipt(const LogKey& log_key, std::uint64_t index);
    void add_cosignature(ByteView cosignature, const crypto::PublicKey& witness);

    /// Client mode: fetches a record's sealed private data into the mirror,
    /// unless it is there. False if the server holds none.
    bool fetch_vault(const protocol::Id& record) const;
    /// Client mode: fetches the server's vault public key into the mirror
    /// (once per session).
    void fetch_vault_public_key() const;

    /// Client mode: sends a request to the server, and fails unless it
    /// succeeded (with the server's message). Returns the answer's body.
    Bytes request(std::string_view method, std::string_view path, ByteView body = {},
                  std::string_view content_type = {}) const;

private:
    void prove_presence(const protocol::ActorState& actor, protocol::Statement& statement,
                        const crypto::PublicKey& signing_key, const PresenceRequest& request) const;

    [[nodiscard]] std::optional<protocol::Id> choose_delegation(const protocol::ActorState& actor,
                                                                const protocol::Body& body) const;

    void open(const std::filesystem::path& directory);
    void open_remote(const ServerLocation& server);
    /// Client mode: brings the mirror up to the server, tail included.
    void sync();
    /// Client mode: syncs until `done`, for up to ten seconds: a cluster's
    /// follower may apply what its leader did a moment later.
    bool sync_until(const std::function<bool()>& done);
    /// True if the mirror holds this signed checkpoint.
    [[nodiscard]] bool has_checkpoint(ByteView encoded) const;
    /// Client mode: sends a request, and fails unless it succeeded.
    Bytes call(std::string_view method, std::string_view path, ByteView body = {},
               std::string_view content_type = {}) const;

    struct Remote {
        node::Client client;
        std::string url;
        mutable bool vault_key_fetched = false;
    };

    std::filesystem::path directory_;
    std::optional<Remote> remote_;
    std::optional<ledger::DirectoryLock> lock_;
    crypto::openssl::Provider provider_;
    ledger::SystemClock clock_;
    ledger::SystemEntropy entropy_;
    std::optional<ledger::PosixFileSystem> fs_;
    std::optional<ledger::Ledger> ledger_;
};

} // namespace cexchain::app
