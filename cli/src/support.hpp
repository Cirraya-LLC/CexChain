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
#include <utility>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/verifier/report.hpp>

#include "args.hpp"

namespace cexchain::cli {

using verifier::format_time;
using verifier::iso_time;
using verifier::kind_label;

/// Unwraps a result or throws a CommandError that names what failed.
template <class T>
T unwrap(Result<T> result, std::string_view what) {
    if (!result) {
        throw CommandError{std::string(what) + ": " + std::string(result.error().detail) + " (" +
                           std::string(to_string(result.error().code)) + ")"};
    }
    return std::move(*result);
}

inline void unwrap(Status status, std::string_view what) {
    if (!status) {
        throw CommandError{std::string(what) + ": " + std::string(status.error().detail) + " (" +
                           std::string(to_string(status.error().code)) + ")"};
    }
}

[[nodiscard]] Bytes read_file(const std::filesystem::path& path);
/// Writes atomically (temporary file, fsync, rename). `private_file` sets
/// permissions to owner-only.
void write_file(const std::filesystem::path& path, ByteView data, bool private_file);
/// A pkcs11: URI with any pin-value hidden, for printing.
[[nodiscard]] std::string redact_pin(std::string_view uri);

[[nodiscard]] std::string hex_id(const protocol::Id& id);
[[nodiscard]] std::string short_id(const protocol::Id& id);
/// Parses "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SSZ" (UTC).
[[nodiscard]] protocol::Timestamp parse_time(std::string_view text);

/// A key passphrase, for the key file named `purpose`: read from the
/// `file_option` file if given, else from the `env` variable, else asked for
/// on the terminal (twice if `confirm`).
[[nodiscard]] std::string passphrase(const Args& args, const std::string& purpose,
                                     bool confirm = false,
                                     std::string_view file_option = "passphrase-file",
                                     const char* env = "CEXCHAIN_PASSPHRASE");

/// The provider every key and token in this process uses.
[[nodiscard]] const crypto::openssl::Provider& shared_provider();

/// A key that signs: a private key file, or a key on a token (USB key, smart
/// card, HSM) named by a pkcs11: URI, whose PIN comes from the URI,
/// $CEXCHAIN_PKCS11_PIN, or a prompt.
[[nodiscard]] std::unique_ptr<crypto::Signer> load_signer(const std::string& source,
                                                          const Args& args);

/// Generates a key pair on the token a pkcs11: URI names (ESP256 or Ed25519).
[[nodiscard]] std::unique_ptr<crypto::Signer> generate_on_token(const std::string& uri,
                                                                crypto::SigAlg alg);

/// How the signer proves presence, from --presence, --presence-key, and
/// --no-browser.
struct PresenceRequest {
    /// For a passkey: open the browser (otherwise just print the address).
    bool open_browser = true;
    /// For a hardware key: the opened token key.
    std::shared_ptr<crypto::Signer> hardware_key = nullptr;
};
[[nodiscard]] std::optional<PresenceRequest> presence_request(const Args& args);

/// Loads a private key file, asking for its passphrase if it is encrypted.
[[nodiscard]] crypto::openssl::KeyPair load_key(const std::filesystem::path& path,
                                                const Args& args);

/// Writes a private key file (owner-only permissions), encrypted with
/// `secret` if given.
void save_key(const std::filesystem::path& path, const crypto::openssl::KeyPair& key,
              const std::optional<std::string>& secret);

/// A public key file holds the deterministic CBOR encoding of [alg, key].
[[nodiscard]] Bytes encode_public_key_file(const crypto::PublicKey& key);
/// Loads a public key file. Private key files are refused, so that verifiers
/// never need anyone's private key.
[[nodiscard]] crypto::PublicKey load_public_key(const std::filesystem::path& path);
/// The public key in a public key file, or in a private key file (asking for
/// its passphrase if needed).
[[nodiscard]] crypto::PublicKey public_key_of(const std::filesystem::path& path, const Args& args);

[[nodiscard]] Bytes hash_text(const crypto::Provider& provider, crypto::HashAlg hash,
                              std::string_view text);
[[nodiscard]] std::vector<std::string> split(const std::string& text, char separator);
/// Splits NAME=VALUE.
[[nodiscard]] std::pair<std::string, std::string> split_pair(const std::string& text,
                                                             std::string_view what);
[[nodiscard]] std::uint64_t parse_number(std::string_view text, std::string_view what);
[[nodiscard]] crypto::SigAlg parse_algorithm(std::string_view name);
[[nodiscard]] crypto::HashAlg parse_hash(std::string_view name);
[[nodiscard]] protocol::StatementType parse_statement_type(std::string_view name);
[[nodiscard]] protocol::ActorKind parse_actor_kind(std::string_view name);

/// The API token from --token-file or $CEXCHAIN_TOKEN, if any.
[[nodiscard]] std::optional<std::string> api_token(const Args& args);
/// A client for the API at `url`, with the API token and, if given, the CA
/// certificates to trust.
[[nodiscard]] node::Client client_for(const std::string& url, const Args& args,
                                      const std::optional<std::string>& ca_file);

/// Makes the sealed private data of the record `id` names (for record
/// registrations, which keep it in the vault).
using SealVault = std::function<Bytes(const protocol::Id& record)>;

/// An open ledger with the environment needed to act on it: a ledger
/// directory, or, in client mode (D-050), a verified mirror of the ledger a
/// server serves.
///
/// Client mode, with --server URL (or $CEXCHAIN_SERVER), for commands that
/// list --server among their options: the mirror lives in the cache
/// (--cache, default $XDG_CACHE_HOME/cexchain or ~/.cache/cexchain), one
/// directory per ledger id. Each session first syncs it with the replica
/// code, so every entry and checkpoint it shows was re-validated here, and a
/// server that rewrites or rolls back what this client saw is refused. The
/// ledger a URL serves is pinned on first use (--ledger-id, required for
/// http://). Statements are signed here and sent to the server; keys never
/// leave this machine.
class Session {
public:
    explicit Session(const std::filesystem::path& directory);
    explicit Session(const Args& args);

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
    /// consents' evidence is kept with it the same way (D-053).
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

    /// Signs and submits as the holder of --as, with --delegation, --model,
    /// --model-version, --inputs, --presence, and --no-browser taken from
    /// `args`.
    protocol::Id submit(const Args& args, protocol::Body body);

    /// AI provenance from --model, --model-version, and --inputs (hashed).
    [[nodiscard]] std::optional<protocol::Provenance> provenance(const Args& args) const;

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

    // What the log key signs: here with --log-key; in client mode by the
    // server, and checked against the mirror before it is used.
    [[nodiscard]] protocol::SignedCheckpoint checkpoint(const Args& args);
    [[nodiscard]] protocol::EvidenceBundle evidence(const Args& args, const protocol::Id& record);
    /// An instance's contract evidence with the consents its calls cite
    /// (D-053), without private data: built here with --log-key (after a
    /// checkpoint, if the latest does not cover the instance's last call), or
    /// the server's, verified against the mirror.
    [[nodiscard]] Bytes contract_evidence(const Args& args, const protocol::Id& instance);
    [[nodiscard]] Bytes receipt(const Args& args, std::uint64_t index);
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
    void open_remote(const Args& args, const std::string& url);
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

/// Finishes or discards an interrupted `vault rekey` (call with the ledger
/// locked).
void recover_vault_swap(const std::filesystem::path& directory);

/// Creates a ledger in `directory`.
void create_ledger(const std::filesystem::path& directory, const crypto::Signer& root_key,
                   const crypto::PublicKey& log_key, crypto::HashAlg hash,
                   const std::string& organization);

} // namespace cexchain::cli
