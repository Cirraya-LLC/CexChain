// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/connector.hpp>
#include <cexchain/node/connectors.hpp>

/// The executor runtime (6b, design section 3): `cexchain executor run`.
///
/// It finds open requests at the home's server (GET /v1/requests, a long
/// poll; a hint), verifies each in the instance's contract evidence for the
/// home ledger before acting (a compromised API cannot make it act on a
/// request that is not open in the signed log), keeps a journal synced
/// before every outside action, acts through a connector (a child process,
/// spec/connectors.md), and signs and submits the answer. Transient failures
/// back off (1 s doubling to 5 min, with jitter) until the deadline. One
/// copy of an executor acts at a time, by the server's lease (spec section
/// 16); a stop finishes the request in hand.
namespace cexchain::node::executor {

/// A connector in an executor's config: which requests it serves (kinds,
/// and contracts: empty for any the delegation allows) and how to run it.
struct ConnectorConfig {
    std::string name;
    /// "webhook" or "command" (first-party: the runtime runs `cexchain
    /// connector TYPE`), or "program" (any program speaking the protocol).
    std::string type;
    std::vector<std::string> kinds;
    std::vector<protocol::Id> contracts;
    /// For "program": what to run.
    std::string program;
    std::vector<std::string> arguments;
    /// The connector's own configuration (a JSON object), sent in hello.
    std::string config = "{}";
    /// The secrets it receives in hello.
    std::vector<std::string> secrets;
    /// The longest one action may take: 1 to 300 seconds (default 30).
    std::chrono::seconds timeout{30};
};

/// An executor's config file (JSON): the home ledger, the executor's actor
/// and delegation (`executor add --config-out` writes them), an agent's
/// model, and its connectors.
struct Config {
    protocol::Id ledger;
    protocol::Id actor;
    protocol::Id delegation;
    std::optional<std::string> model;
    std::optional<std::string> model_version;
    std::vector<ConnectorConfig> connectors;

    /// The connector that serves `kind` on `contract`, if any.
    [[nodiscard]] const ConnectorConfig* route(const protocol::Id& contract,
                                               std::string_view kind) const;
    /// Every kind some connector serves, sorted, each once.
    [[nodiscard]] std::vector<std::string> kinds() const;
};

/// Parses and checks a config: ids of 64 hex digits; connectors with
/// unique names, known types, their kinds, and settings; no two serving
/// the same kind on the same contract. The error says what is wrong.
[[nodiscard]] std::expected<Config, std::string> parse_config(std::string_view text);
/// The config as JSON text (two-space indented), as parse_config reads it.
[[nodiscard]] std::string config_text(const Config& config);

/// Where a request is in the runtime's hands.
enum class Stage : std::uint8_t {
    /// Listed by the server; not yet checked in evidence.
    seen,
    /// Not found open in the signed evidence: never acted on. Checked
    /// again only if the server lists it again.
    unverified,
    /// Open in the verified evidence; waiting for its (next) attempt.
    verified,
    /// An attempt was handed to the connector (journaled first).
    acting,
    /// The connector's outcome is journaled; the answer is not yet built.
    outcome,
    /// The signed answer is journaled and being submitted.
    answering,
    /// Final: the ledger recorded this executor's answer.
    answered,
    /// Final: closed without this executor's answer (answered elsewhere, an
    /// answer the ledger refused, no connector for it).
    closed,
};

[[nodiscard]] std::string_view stage_name(Stage stage) noexcept;
[[nodiscard]] bool is_final(Stage stage) noexcept;

/// A request in the journal: <state>/journal/<id>.json, owner-only, written
/// atomically and synced before every outside action. It keeps the outside
/// system's response and the salt of its digest, which the answer commits
/// to: never published, disclosable later with proof.
struct JournalEntry {
    protocol::Id request;
    protocol::Id instance;
    std::optional<protocol::Id> contract;
    std::string kind;
    std::string reply;
    std::string connector;
    Bytes params; // CBOR
    protocol::Timestamp deadline = 0;
    protocol::Timestamp asked_at = 0;
    Stage stage = Stage::seen;
    std::uint32_t attempts = 0;
    /// Transient failures in a row (actions or ledger calls), for backoff.
    std::uint32_t failures = 0;
    protocol::Timestamp next_at = 0;
    protocol::Timestamp first_seen = 0;
    protocol::Timestamp updated = 0;
    /// Our own short text, never an outside system's.
    std::string note;
    // The outcome.
    std::optional<std::string> status; // "done" or "failed"
    std::optional<Bytes> result;       // CBOR
    std::optional<std::string> reason;
    std::optional<Bytes> response;
    std::optional<Bytes> salt;
    std::optional<Bytes> digest;
    // The answer.
    std::optional<Bytes> statement; // COSE
    std::optional<protocol::Id> statement_id;
    std::optional<std::uint64_t> head;
    std::optional<std::uint64_t> index;
    // When closed by another answer: its status and signer.
    std::optional<std::string> answered_status;
    std::optional<protocol::Id> answered_by;
};

/// The journal's files as JSON text, and back.
[[nodiscard]] std::string entry_text(const JournalEntry& entry);
[[nodiscard]] std::optional<JournalEntry> parse_entry(std::string_view text);

/// A state directory: journal/, cursor.json, and secrets/.
class Journal {
public:
    explicit Journal(std::filesystem::path state);

    [[nodiscard]] const std::filesystem::path& directory() const noexcept { return state_; }
    [[nodiscard]] std::vector<JournalEntry> entries() const;
    [[nodiscard]] std::optional<JournalEntry> find(const protocol::Id& request) const;
    /// Writes atomically, owner-only, synced.
    [[nodiscard]] Status save(const JournalEntry& entry) const;

    /// The discovery cursor (the `after` of the next poll) and the server it
    /// belongs to.
    [[nodiscard]] std::uint64_t cursor(std::string_view server) const;
    [[nodiscard]] Status save_cursor(std::string_view server, std::uint64_t cursor) const;

private:
    std::filesystem::path state_;
};

/// The answer's arguments for an outcome: a map with "result" (if any),
/// "reason" (failed only), and "response" (the salted digest of the outside
/// system's response, if any); null if none of them.
[[nodiscard]] cbor::Value answer_arguments(const JournalEntry& entry);

/// A connector, as the runtime talks to it.
class Channel {
public:
    virtual ~Channel() = default;
    [[nodiscard]] virtual Status send(std::string_view line) = 0;
    /// The next line, if one comes within `timeout`; Errc::unavailable once
    /// the connector is gone.
    [[nodiscard]] virtual Result<std::optional<std::string>>
    receive(std::chrono::milliseconds timeout) = 0;
    /// Stops the connector (it was sent stop, or it misbehaved).
    virtual void close() = 0;

protected:
    Channel() = default;
};

using ChannelFactory =
    std::function<Result<std::unique_ptr<Channel>>(const ConnectorConfig& connector)>;

/// Runs connectors as child processes: a "program" as configured, the
/// first-party types as `self connector TYPE`.
[[nodiscard]] ChannelFactory process_channels(std::string self);
/// Runs connectors in this process, for tests: each line sent is answered at
/// once by `connector::serve`'s rules, with the performer `make` builds.
[[nodiscard]] ChannelFactory local_channels(connector::PerformerFactory make);

struct RunOptions {
    /// The home's server, and how to reach it (an executor token).
    std::string server;
    ClientOptions client;
    std::filesystem::path state;
    ChannelFactory channels;
    const crypto::Signer* signer = nullptr;
    const crypto::Provider* provider = nullptr;
    /// Unsealed secrets; each connector gets those its config names.
    std::map<std::string, SecureBytes> secrets;
    /// Provenance for an agent's answers: the tool, e.g. "cexchain/0.9".
    std::string tool = "cexchain";
    std::function<protocol::Timestamp()> now;
    /// The long poll's wait: 0 to 25 seconds.
    std::chrono::seconds wait{25};
    /// The lease's time to live: 5 to 300 seconds.
    std::chrono::seconds lease_ttl{60};
    /// One round: one poll without waiting, then what is due now.
    bool once = false;
    /// Set to stop: the request in hand is finished first.
    const std::atomic<bool>* stop = nullptr;
    /// Events, one JSON object per call (never secrets or params).
    std::function<void(std::string_view json)> on_event;
};

/// Runs the executor until `options.stop` (or one round with `once`).
/// Fails if the state directory is in use by another copy, a connector does
/// not start, or the config does not fit (a kind no connector serves).
[[nodiscard]] std::expected<void, std::string> run(const Config& config, RunOptions& options);

} // namespace cexchain::node::executor
