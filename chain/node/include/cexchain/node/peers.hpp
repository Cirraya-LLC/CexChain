// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/ledger/ledger.hpp>

/// Peers: other organizations' ledgers this one deals with. Each is
/// pinned by its ledger id, which commits to its genesis, root key, and log
/// key, and is learned out of band (a contract, a call). Operational config,
/// kept in <ledger>/peers.json; what was granted to whom is on the ledger.
namespace cexchain::node {

/// How a ledger that no one reaches directly (a laptop) is reached: the
/// relay that keeps its mailbox, the key requests to it are sealed to (32
/// bytes, X25519), and the key of that relay's public witness, which the
/// sender registers with too (a relay serves the ledgers its witness
/// follows).
struct RelayRoute {
    std::string url;
    Bytes key;
    crypto::PublicKey witness;

    friend bool operator==(const RelayRoute&, const RelayRoute&) = default;
};

struct Peer {
    /// 1-64 letters, digits, '.', '_', '-'.
    std::string name;
    protocol::Id ledger_id;
    /// The peer's API, for online exchange and witnessing.
    std::optional<std::string> url;
    /// A file holding the token the peer issued us for its API.
    std::optional<std::string> token_file;
    std::optional<std::string> ca_file;
    /// The peer's witness key, if it witnesses this ledger.
    std::optional<crypto::PublicKey> witness_key;
    /// Without a URL, how it is reached.
    std::optional<RelayRoute> relay;
    protocol::Timestamp added = 0;
};

/// Whether a peer is reached online: by its API's URL or through its
/// relay, with the token it issued us.
[[nodiscard]] inline bool reachable(const Peer& peer) {
    return (peer.url || peer.relay) && peer.token_file;
}

inline constexpr std::string_view peers_file = "peers.json";

[[nodiscard]] Result<std::vector<Peer>> load_peers(const std::filesystem::path& ledger_directory);
[[nodiscard]] Status save_peers(const std::filesystem::path& ledger_directory,
                                const std::vector<Peer>& peers);

/// Where access exchanges are kept, under <ledger>/access:
///   inbox/<request>.cbor     requests received (evidence bundles)
///   outbox/<request>.cbor    answers made, for the requester to fetch: a
///                            delivery, or a claim's evidence bundle
///   receipts/<grant>.cbor    receipts received (evidence bundles)
///   requests/<request>.cbor  this ledger's own requests (evidence bundles)
///   deliveries/<grant>.cbor  deliveries received (still sealed)
/// The keys deliveries are sealed to live in the vault:
///   <ledger>/vault/access/<request>.cbor
enum class AccessBox { inbox, outbox, receipts, requests, deliveries };

/// The public metadata a record on `ledger` was registered with (from its
/// registering statement in the log). Errc::not_found if the record does
/// not exist or has none.
[[nodiscard]] Result<cbor::Value> record_metadata(const crypto::Provider& provider,
                                                  const ledger::Ledger& ledger,
                                                  const protocol::Id& record);
[[nodiscard]] std::filesystem::path access_path(const std::filesystem::path& ledger_directory,
                                                AccessBox box, const protocol::Id& id);

/// The answer in the outbox for `request`, if it is the one made under
/// `answer` (a later answer to the same request replaces it): a delivery
/// made under that grant, or that claim's evidence bundle. Errc::not_found
/// otherwise.
[[nodiscard]] Result<Bytes> kept_answer(const std::filesystem::path& ledger_directory,
                                        const protocol::Id& request, const protocol::Id& answer);

/// What one of this ledger's answers answered: the requester's ledger and
/// its request, from a grant's metadata or a claim's `for`.
struct Answered {
    protocol::Id ledger;
    protocol::Id request;
    /// The answer is a claim (else a grant).
    bool claim = false;
};
/// Errc::not_found unless `answer` is a grant, or a claim answering a
/// request, on `ledger`.
[[nodiscard]] Result<Answered> answered_request(const crypto::Provider& provider,
                                                const ledger::Ledger& ledger,
                                                const protocol::Id& answer);

/// Stores the receipt for `grant`, once: storing the same bytes again
/// succeeds, different ones are refused (Errc::rejected), so a stored
/// acknowledgement cannot be replaced.
[[nodiscard]] Status store_receipt(const std::filesystem::path& ledger_directory,
                                   const protocol::Id& grant, ByteView receipt);

} // namespace cexchain::node
