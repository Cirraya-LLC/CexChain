// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/witness.hpp>

/// A witness of other ledgers, as the command line (`witness ...`, `serve
/// --witness-dir`) and the console share it. A witness directory holds one
/// state file per ledger, <ledger id>.cbor:
///   {1: ledger id, 2: log key [alg, key], 3: name, 4: size,
///    ? 5: root, ? 6: tree hash (COSE id), ? 7: last cosigned at (ms),
///    ? 8: root key [alg, key], ? 9: index of the last key rotation followed}
/// Without a root key (a log added by its log key alone) the witness cannot
/// follow key rotations.
namespace cexchain::app {

struct WitnessState {
    protocol::WitnessedLog log;
    std::string name;
    std::optional<protocol::Timestamp> cosigned_at;
};

[[nodiscard]] std::filesystem::path witness_state_path(const std::filesystem::path& dir,
                                                       const protocol::Id& ledger);
[[nodiscard]] Bytes encode_witness_state(const WitnessState& state);
/// Throws ActionError if the file is not a witness state.
[[nodiscard]] WitnessState decode_witness_state(const std::filesystem::path& path);
/// Every ledger the witness at `dir` follows, by file name; throws if there
/// is no such directory.
[[nodiscard]] std::vector<WitnessState> witness_states(const std::filesystem::path& dir);

/// The state of a ledger followed from its genesis entry, which fixes the
/// ledger id, its hash, its root key, and its first log key (so the witness
/// follows every key rotation). Throws if the entry is not a genesis, or not
/// that of `pinned`.
[[nodiscard]] WitnessState state_from_genesis(ByteView genesis, std::string name,
                                              const std::optional<protocol::Id>& pinned);
/// Starts following a ledger: writes its state in `dir` (made if missing),
/// under the directory's lock. Throws if the witness follows it already.
void add_witnessed(const std::filesystem::path& dir, const WitnessState& state);

/// What a witness does with a cosign request: checks it against the state
/// in `dir` and, if the checkpoint extends what this witness cosigned
/// before, cosigns it with `key` and advances the state (cosigned at
/// `now`). Asking again for the checkpoint cosigned last gets it cosigned
/// again (a lost answer can be retried). Fails with Errc::not_found (a ledger
/// this witness does not follow), Errc::rejected (the proof starts elsewhere
/// than the witness's size), or Errc::verification_failed (not signed by the
/// log key, or inconsistent: the ledger was rewritten or forked).
[[nodiscard]] Result<Bytes> witness_cosign(const std::filesystem::path& dir,
                                           const crypto::Signer& key, ByteView request,
                                           protocol::Timestamp now);

} // namespace cexchain::app
