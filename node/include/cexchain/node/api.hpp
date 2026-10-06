// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <filesystem>
#include <memory>
#include <ostream>
#include <string>

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
///         /v1/vault/records/{record}
/// submit: POST /v1/statements (a signed statement)
/// admin:  POST /v1/checkpoint, POST /v1/cosignatures ([cosignature, witness key])
namespace cexchain::node {

/// A ledger directory that is a replica holds this file (JSON).
inline constexpr std::string_view replica_file = "replica";

struct ApiOptions {
    std::filesystem::path directory;
    /// The log key, for checkpoints, receipts, and evidence. Without it
    /// those answer 501.
    std::shared_ptr<const crypto::Signer> log_key;
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

    [[nodiscard]] http::Response handle(const http::Request& request,
                                        std::string_view peer) override;
    void tick() override;
    [[nodiscard]] std::string principal() const override;

    [[nodiscard]] bool is_replica() const noexcept;
    [[nodiscard]] const ledger::Ledger& ledger() const noexcept;

    struct State;

private:
    explicit LedgerApi(std::unique_ptr<State> state);
    std::unique_ptr<State> state_;
};

} // namespace cexchain::node
