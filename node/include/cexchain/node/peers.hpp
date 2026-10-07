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

/// Peers: other organizations' ledgers this one deals with (D-046). Each is
/// pinned by its ledger id, which commits to its genesis, root key, and log
/// key, and is learned out of band (a contract, a call). Operational config,
/// kept in <ledger>/peers.json; what was granted to whom is on the ledger.
namespace cexchain::node {

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
    protocol::Timestamp added = 0;
};

inline constexpr std::string_view peers_file = "peers.json";

[[nodiscard]] Result<std::vector<Peer>> load_peers(const std::filesystem::path& ledger_directory);
[[nodiscard]] Status save_peers(const std::filesystem::path& ledger_directory,
                                const std::vector<Peer>& peers);

/// Where access exchanges are kept, under <ledger>/access:
///   inbox/<request>.cbor     requests received (evidence bundles)
///   outbox/<request>.cbor    deliveries made, for the requester to fetch
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

/// The delivery in the outbox for `request`, if it is the one made under
/// `grant` (a later grant for the same request replaces it): Errc::not_found
/// otherwise.
[[nodiscard]] Result<Bytes> delivery_for_grant(const std::filesystem::path& ledger_directory,
                                               const protocol::Id& request,
                                               const protocol::Id& grant);

/// Stores the receipt for `grant`, once: storing the same bytes again
/// succeeds, different ones are refused (Errc::rejected), so a stored
/// acknowledgement cannot be replaced.
[[nodiscard]] Status store_receipt(const std::filesystem::path& ledger_directory,
                                   const protocol::Id& grant, ByteView receipt);

} // namespace cexchain::node
