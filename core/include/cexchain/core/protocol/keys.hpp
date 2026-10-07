// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

/// The organization's keys over time (spec v0.4). The root key changes with
/// actor-rotate-key on the organization, the log key with
/// ledger-rotate-log-key; both are signed by the root key in effect.
///
/// The log key in effect for a tree of N entries is the one set by the last
/// rotation at an index below N (or at genesis). Checkpoints of size N,
/// receipts against them, and the state commitment at index i (which commits
/// to the first i entries) are signed with the key in effect for that size.
namespace cexchain::protocol {

/// A key and the log index of the statement that set it (0: genesis).
struct KeyEpoch {
    std::uint64_t index = 0;
    crypto::PublicKey key;

    friend bool operator==(const KeyEpoch&, const KeyEpoch&) = default;
};

/// The key of `epochs` (oldest first, starting at genesis) in effect for a
/// tree of `tree_size` entries.
[[nodiscard]] const crypto::PublicKey& key_in_effect(std::span<const KeyEpoch> epochs,
                                                     std::uint64_t tree_size);

/// What a party that follows a ledger's keys without replaying its log
/// knows: a witness, or a replica checking a checkpoint before the entries it
/// covers are applied.
struct LedgerKeys {
    Id ledger_id;
    crypto::HashAlg hash = crypto::HashAlg::sha256;
    crypto::PublicKey root_key;
    /// Every log key known, oldest first; the last is the newest.
    std::vector<KeyEpoch> log_keys;
    /// The index of the last rotation applied; 0 if none.
    std::uint64_t last_rotation = 0;

    [[nodiscard]] const crypto::PublicKey& log_key() const { return log_keys.back().key; }

    friend bool operator==(const LedgerKeys&, const LedgerKeys&) = default;
};

/// The keys a genesis log entry sets (it is not verified beyond its own
/// signature and id).
[[nodiscard]] Result<LedgerKeys> keys_from_genesis(const crypto::Provider& provider,
                                                   ByteView genesis_entry);

/// True if the encoded log entry rotates the organization's root or log key.
/// (A quick test on the decoded entry: `follow_key_rotation` checks it.)
[[nodiscard]] bool is_key_rotation(const crypto::Provider& provider, const LedgerKeys& keys,
                                   ByteView entry);

/// If the encoded log entry at `index` rotates the organization's root or
/// log key, checks it against `keys` and applies it; any other entry leaves
/// `keys` as it is. A rotation must come after the last one applied, be
/// signed by the root key in effect (and say so in its kid), and name a key
/// that is not weak and was never a log key before. Fails otherwise, with
/// Errc::verification_failed.
[[nodiscard]] Status follow_key_rotation(const crypto::Provider& provider, LedgerKeys& keys,
                                         std::uint64_t index, ByteView entry);

} // namespace cexchain::protocol
