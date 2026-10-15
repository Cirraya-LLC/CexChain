// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/node/server.hpp>

/// The ledger's HTTP API, version 1. Binary objects (log entries,
/// checkpoints, proofs, receipts, evidence) are CBOR or COSE as the protocol
/// defines them; everything else is JSON. Errors are
///   {"error": {"code": "<Errc name>", "message": "..."}}
///
/// Open:   GET /healthz, /v1/checkpoint[?size=N], /v1/consistency?old=&new=
/// read:   GET /metrics, /v1/status, /v1/entries?start=&count=,
///         /v1/checkpoints?start=&count=, /v1/cosignatures?start=&count=,
///         /v1/inclusion?index=&size=, /v1/statements/{id}, /v1/receipts/{index},
///         /v1/state/{id}, /v1/evidence/{record}, /v1/vault/public-key,
///         /v1/vault/records/{record}, /v1/contracts?start=&count=,
///         /v1/contracts/{contract}, /v1/contracts/instances/{instance},
///         /v1/contracts/calls, /v1/contracts/calls/{call}
/// submit: POST /v1/statements (a signed statement), POST /v1/contracts/calls (a call proposal)
/// admin:  POST /v1/checkpoint, POST /v1/cosignatures ([cosignature, witness key])
/// peer:   POST /v1/access/requests (a request's evidence), GET /v1/access/deliveries/{request},
///         POST /v1/access/receipts (a receipt's evidence), POST /v1/witness/cosign,
///         POST /v1/contracts/calls and
///         GET /v1/contracts/instances/{instance} (the instance's current parties),
///         GET /v1/contracts/calls[/{call}] (calls that concern the peer),
///         POST /v1/contracts/consents (a consent's evidence)
namespace cexchain::node {

/// The content type of a statement sent with what is kept with it: a
/// record's registration with its sealed private data, {1: signed
/// statement, 2: sealed vault file}; or a contract call with the consent
/// bundles it cites, {1: signed statement, 3: [consent bundles]}.
inline constexpr std::string_view submission_content_type = "application/cexchain-submission+cbor";

/// A ledger directory that is a replica holds this file (JSON).
inline constexpr std::string_view replica_file = "replica";

struct ApiOptions {
    std::filesystem::path directory;
    /// The log keys, for checkpoints, receipts, and evidence: the server
    /// signs with whichever is in effect, so across a rotation it can hold
    /// the old key and the new one. Without any, those answer 501.
    std::vector<std::shared_ptr<const crypto::Signer>> log_keys;
    /// Refuse every write. Replicas are always read-only.
    bool read_only = false;
    /// Serve read routes without a token (for a public verification portal).
    bool public_read = false;
    /// Checkpoint this often when the log has grown (needs the log key);
    /// zero turns it off.
    std::chrono::seconds checkpoint_interval{0};
    std::string version;
    /// Notable events (automatic checkpoints, failures), one JSON line each.
    std::ostream* event_log = nullptr;
    /// Cosigns a cosign request as this organization's witness of a peer's
    /// ledger; without it, POST /v1/witness/cosign answers 501.
    std::function<Result<Bytes>(ByteView)> witness;
    /// Serve as a member of the cluster configured in `directory`/cluster
    /// (D-051): the node holds the ledger's lock for as long as it runs,
    /// writes go through Raft, and followers send writers to the leader.
    bool cluster = false;
    /// The registrar (D-053): an actor of this ledger with a delegation for
    /// contract calls. With it, the server takes proposed contract calls
    /// (POST /v1/contracts/calls) and the consents their contracts ask for
    /// (POST /v1/contracts/consents), and records each call once its
    /// contract accepts it. Without it, those routes answer 501.
    std::shared_ptr<const crypto::Signer> registrar;
};

class LedgerApi final : public Application {
public:
    /// Opens the ledger in `options.directory`, holding its lock only while
    /// opening. Fails if the log key is not this ledger's.
    [[nodiscard]] static Result<std::unique_ptr<LedgerApi>> open(ApiOptions options,
                                                                 const crypto::Provider& provider);

    LedgerApi(const LedgerApi&) = delete;
    LedgerApi& operator=(const LedgerApi&) = delete;
    ~LedgerApi() override;

    /// Reads run on the calling thread; writes queue for the API's writer
    /// thread, which commits whatever has queued as one group.
    void handle(http::Request request, std::string peer, Respond respond) override;
    void tick() override;
    /// Waits until every queued write is done.
    void stop() override;

    [[nodiscard]] bool is_replica() const noexcept;
    [[nodiscard]] const ledger::Ledger& ledger() const noexcept;

    struct State;

private:
    explicit LedgerApi(std::unique_ptr<State> state);
    std::unique_ptr<State> state_;
};

} // namespace cexchain::node
