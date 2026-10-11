// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
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
    contract = 4,
    instance = 5,
};

/// One object in the state commitment.
struct StateLeaf {
    ObjectKind kind = ObjectKind::actor;
    Id id;
    /// Ascending log indices of every statement that created or changed the
    /// object: registration, key rotations, passkey changes, and revocation
    /// for actors; grant and revocation for delegations; every statement about
    /// a record; deploy and retire for contracts; creation and every call for
    /// instances.
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

/// The leaf of one object of `state` as it was before log index `before`:
/// its history cut to the indices below it. Nothing if it did not exist then.
[[nodiscard]] std::optional<StateLeaf> state_leaf(const LedgerState& state, const Id& id,
                                                  std::uint64_t before);

/// The state tree kept up to date incrementally, for ledgers: a crit-bit
/// (path-compressed binary) trie over object ids whose subtree hashes are
/// cached, so changing k objects costs O(k log n) hashes and a proof
/// O(log n), where `state_root` and `prove_state` recompute everything,
/// O(n log n). It produces exactly their roots and proofs.
///
/// Nodes live in two chunked arenas and refer to each other by 32-bit
/// index, not by pointer: compact, cache-friendly, and trivially movable.
/// Changes are staged with `set` and hashed by `commit`; `root`, `siblings`,
/// and `leaf_hash` are const and safe to call from many threads at once
/// between commits.
class StateTree {
public:
    /// Fails unless the hash has 32-byte digests (SHA-256, SM3).
    [[nodiscard]] static Result<StateTree> create(const crypto::Provider& provider,
                                                  crypto::HashAlg hash);

    [[nodiscard]] std::size_t size() const noexcept { return leaves_.size(); }

    /// Inserts or replaces the leaf of `leaf.id` (staged until `commit`).
    [[nodiscard]] Status set(const StateLeaf& leaf);
    /// Hashes every subtree changed since the last commit.
    [[nodiscard]] Status commit();

    /// The root, as of the last commit.
    [[nodiscard]] Result<crypto::Digest> root() const;
    /// The proof siblings of `id` (as in StateProof), as of the last commit;
    /// Errc::not_found if the tree has no such object.
    [[nodiscard]] Result<std::vector<crypto::Digest>> siblings(const Id& id) const;
    /// The leaf hash of `id`, as of the last commit.
    [[nodiscard]] std::optional<crypto::Digest> leaf_hash(const Id& id) const;

private:
    using Hash = std::array<std::uint8_t, 32>;
    using Ref = std::uint32_t; // high bit set: a leaf; otherwise an inner node
    static constexpr Ref leaf_flag = 0x8000'0000U;
    static constexpr Ref none = 0xffff'ffffU;

    struct Leaf {
        IdKey key{};
        Hash hash{};
    };
    struct Inner {
        Ref child[2] = {none, none};
        std::uint32_t any_leaf = 0; // a leaf below, for the shared prefix bits
        std::uint16_t crit = 0;     // the bit at which the children differ
        bool dirty = true;
        Hash hash{}; // the subtree hash at depth `crit`
    };

    StateTree(const crypto::Provider& provider, crypto::HashAlg hash, const Hash& empty)
        : provider_(&provider), hash_(hash), empty_(empty) {}

    [[nodiscard]] Result<Hash> node_hash(const Hash& left, const Hash& right) const;
    /// The hash of the subtree `ref` as seen from `depth` (at most its own).
    [[nodiscard]] Result<Hash> hash_at(Ref ref, std::size_t depth) const;
    [[nodiscard]] Status refresh(std::uint32_t inner);
    [[nodiscard]] const IdKey& key_below(Ref ref) const;

    const crypto::Provider* provider_;
    crypto::HashAlg hash_;
    Hash empty_;
    // Stable chunks: no doubling slack, and no pause to copy a large arena.
    StableVector<Leaf> leaves_;
    StableVector<Inner> inners_;
    Ref root_ = none;
    bool dirty_ = false;
};

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
/// The same, with the state's root already known (from a StateTree).
[[nodiscard]] Status check_state_commitment(const crypto::Provider& provider,
                                            const LedgerState& state,
                                            const SignedStateCommitment& commitment,
                                            std::uint64_t index, const crypto::Digest& state_root);

} // namespace cexchain::protocol
