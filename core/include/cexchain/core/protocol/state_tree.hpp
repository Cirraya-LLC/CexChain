// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>

/// The state commitment: when it checkpoints, the ledger appends to its log a
/// signed commitment to the root of a tree over the complete history of every
/// actor, delegation, and record (see StateCommitment in log.hpp). With a
/// proof from this tree, a verifier knows that the history it was shown is all
/// of it: a later revocation cannot be left out.
///
/// The tree is a compact sparse Merkle tree keyed by object id (256 bits,
/// most significant bit first). An empty subtree hashes to HASH(""), a
/// subtree holding one object to its leaf hash, and any other subtree to
/// HASH(0x01 || left || right), where
///   leaf hash = HASH(0x00 || deterministic-CBOR([kind, id, [* index]])).
/// HASH is the ledger hash. See `state-proof` in spec/cexchain.cddl.
namespace cexchain::protocol {

enum class ObjectKind : std::uint8_t {
    actor = 1,
    delegation = 2,
    record = 3,
};

/// One object in the state commitment.
struct StateLeaf {
    ObjectKind kind = ObjectKind::actor;
    Id id;
    /// Ascending log indices of every statement that created or changed the
    /// object: registration, key rotations, passkey changes, and revocation
    /// for actors; grant and revocation for delegations; every statement about
    /// a record.
    std::vector<std::uint64_t> history;

    friend bool operator==(const StateLeaf&, const StateLeaf&) = default;
};

/// Every object of `state`, sorted by id.
[[nodiscard]] std::vector<StateLeaf> state_leaves(const LedgerState& state);
/// The leaf of one object of `state`, if it exists.
[[nodiscard]] std::optional<StateLeaf> state_leaf(const LedgerState& state, const Id& id);

/// The root over `leaves`, which must be sorted by id with no duplicates.
[[nodiscard]] Result<crypto::Digest> state_root(const crypto::Provider& provider,
                                                crypto::HashAlg hash,
                                                std::span<const StateLeaf> leaves);

/// A proof that a leaf is in the tree with a given root.
struct StateProof {
    StateLeaf leaf;
    /// Sibling hashes from the root down to the leaf; at most 256.
    std::vector<crypto::Digest> siblings;

    friend bool operator==(const StateProof&, const StateProof&) = default;
};

/// The proof for object `id` in the tree over `leaves` (sorted by id).
[[nodiscard]] Result<StateProof> prove_state(const crypto::Provider& provider, crypto::HashAlg hash,
                                             std::span<const StateLeaf> leaves, const Id& id);

/// Checks a proof against a root.
[[nodiscard]] Status verify_state_proof(const crypto::Provider& provider, crypto::HashAlg hash,
                                        const StateProof& proof, const crypto::Digest& root);

[[nodiscard]] Result<Bytes> encode_state_leaf(const StateLeaf& leaf);

/// Checks a state commitment found at log index `index` against `state`, the
/// ledger state replayed from every entry before it: signed by the log key,
/// for this ledger and tree hash, at its own index, and committing to the
/// state's actual root.
[[nodiscard]] Status check_state_commitment(const crypto::Provider& provider,
                                            const LedgerState& state,
                                            const SignedStateCommitment& commitment,
                                            std::uint64_t index);

} // namespace cexchain::protocol
