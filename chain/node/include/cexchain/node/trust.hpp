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
#include <utility>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/id_map.hpp>
#include <cexchain/ledger/ledger.hpp>

/// Trust nodes (spec v0.16, section 16), on both sides.
///
/// A trust node serves `GET /m/LEDGER`: the evidence of its newest
/// membership naming that ledger. A member lists the trust nodes it belongs
/// to, fetches its proof from each, and adds the proofs it keeps to the
/// evidence it serves and exports (bundle key 9):
///
///   <ledger>/trust/nodes.json            the trust nodes this ledger belongs to
///   <ledger>/trust/proofs/<ledger>.cbor  the proof last fetched from each
namespace cexchain::node {

/// A trust node this ledger belongs to: a local name for it, its ledger, and
/// where its server is.
struct TrustNodeEntry {
    std::string name;
    protocol::Id ledger_id;
    std::string url;
    protocol::Timestamp added = 0;

    friend bool operator==(const TrustNodeEntry&, const TrustNodeEntry&) = default;
};

/// None if the file does not exist.
[[nodiscard]] Result<std::vector<TrustNodeEntry>>
load_trust_nodes(const std::filesystem::path& ledger_directory);
/// At most 16 (a bundle carries at most 16 proofs), names and ledgers each
/// unique.
[[nodiscard]] Status save_trust_nodes(const std::filesystem::path& ledger_directory,
                                      const std::vector<TrustNodeEntry>& nodes);

[[nodiscard]] std::filesystem::path
membership_proof_path(const std::filesystem::path& ledger_directory, const protocol::Id& node);

/// A proof as a member takes it from `node`: a complete bundle of that
/// ledger about a membership that names `member`, with the report.
[[nodiscard]] Result<protocol::EvidenceReport>
check_membership_proof(const crypto::Provider& provider, ByteView proof, const protocol::Id& node,
                       const protocol::Id& member);

/// The proofs kept for the trust nodes listed, in the list's order (a node
/// without one, or with a file that does not read, is left out).
[[nodiscard]] std::vector<Bytes>
kept_membership_proofs(const std::filesystem::path& ledger_directory);

/// Fetches this ledger's (`member`'s) proof from `node`'s server
/// (`GET /m/MEMBER`), checks it, and keeps it in place of the one before.
/// Errc::not_found if the trust node names this ledger in no membership.
[[nodiscard]] Result<protocol::EvidenceReport>
fetch_membership_proof(const crypto::Provider& provider,
                       const std::filesystem::path& ledger_directory, const TrustNodeEntry& node,
                       const protocol::Id& member);

/// Adds the kept proofs to `bundle`, evidence of a record of this ledger's
/// whose type is `record_type` (empty for an instance), unless it is a
/// membership: a proof carries none.
void add_membership_proofs(const std::filesystem::path& ledger_directory,
                           std::string_view record_type, protocol::EvidenceBundle& bundle);

/// Which ledger each membership on a trust node's ledger names, read from
/// its registration once (a membership's metadata never changes).
class MembershipIndex {
public:
    /// The membership registered last that names `member`, if any.
    [[nodiscard]] std::optional<protocol::Id> newest(const crypto::Provider& provider,
                                                     const ledger::Ledger& ledger,
                                                     const protocol::Id& member);

private:
    std::mutex mutex_;
    /// Membership record -> (its registration's log index, its member).
    std::map<protocol::IdKey, std::pair<std::uint64_t, protocol::Id>> known_;
};

} // namespace cexchain::node
