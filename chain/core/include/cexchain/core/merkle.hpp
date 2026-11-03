// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <utility>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Merkle trees as defined by RFC 9162 §2.1 (the Certificate Transparency v2
/// tree), parameterized by hash algorithm. With SHA-256 this is the COSE
/// verifiable data structure RFC9162_SHA256.
namespace cexchain::merkle {

using crypto::Digest;
using crypto::HashAlg;

/// The longest possible proofs for trees of at most 2^64 - 1 leaves. An
/// inclusion path has at most one element per level (64). A consistency proof
/// can need one more, for the old tree's own root (65).
inline constexpr std::size_t max_inclusion_proof_length = 64;
inline constexpr std::size_t max_consistency_proof_length = 65;

/// Leaf hash: HASH(0x00 || entry).
[[nodiscard]] Result<Digest> leaf_hash(const crypto::Provider& provider, HashAlg alg,
                                       ByteView entry);

/// Interior node hash: HASH(0x01 || left || right).
[[nodiscard]] Result<Digest> node_hash(const crypto::Provider& provider, HashAlg alg,
                                       const Digest& left, const Digest& right);

/// Root of the empty tree: HASH() of the empty string.
[[nodiscard]] Result<Digest> empty_root(const crypto::Provider& provider, HashAlg alg);

/// Hashes of one size, back to back in fixed-size chunks: no per-hash
/// overhead, and growing never moves what is stored (so no pause to copy
/// a large array).
class HashArray {
public:
    explicit HashArray(std::size_t stride) noexcept : stride_(stride) {}

    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }
    /// Appends `hash`, which must be `stride` bytes.
    void push_back(ByteView hash);
    [[nodiscard]] ByteView operator[](std::uint64_t index) const noexcept {
        const auto& chunk = chunks_[static_cast<std::size_t>(index / per_chunk)];
        return {chunk.data() + static_cast<std::size_t>(index % per_chunk) * stride_, stride_};
    }
    [[nodiscard]] ByteView back() const noexcept { return (*this)[size_ - 1]; }

private:
    static constexpr std::uint64_t per_chunk = 1024;

    std::size_t stride_;
    std::uint64_t size_ = 0;
    std::vector<std::vector<std::uint8_t>> chunks_;
};

/// The right edge of a tree: the roots of its complete subtrees, largest
/// first (one per set bit of its size). Enough to append leaves and compute
/// roots of the grown tree in O(log n) memory, without the tree itself: to
/// check that entries lead to a signed root before taking them.
class CompactRange {
public:
    CompactRange(const crypto::Provider& provider, HashAlg alg) noexcept
        : provider_(&provider), alg_(alg) {}

    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }
    [[nodiscard]] Status append(ByteView entry);
    [[nodiscard]] Status append_leaf_hash(const Digest& leaf);
    /// The root of the tree of the leaves so far (the empty root if none).
    [[nodiscard]] Result<Digest> root() const;

private:
    friend class Tree;
    const crypto::Provider* provider_;
    HashAlg alg_;
    std::uint64_t size_ = 0;
    std::vector<Digest> roots_;
};

/// An append-only Merkle tree held in memory.
///
/// The tree stores the root of every complete, aligned subtree. Roots and
/// proofs for any current or past tree size therefore cost O(log n) lookups
/// plus at most O(log n) hash operations. About two hashes per entry, with
/// no overhead beyond them.
///
/// The provider must outlive the tree.
class Tree {
public:
    Tree(const crypto::Provider& provider, HashAlg alg) noexcept;

    [[nodiscard]] HashAlg hash_algorithm() const noexcept { return alg_; }
    [[nodiscard]] std::uint64_t size() const noexcept;

    /// Appends an entry and returns its index.
    [[nodiscard]] Result<std::uint64_t> append(ByteView entry);

    /// Appends a precomputed leaf hash and returns its index.
    [[nodiscard]] Result<std::uint64_t> append_leaf_hash(const Digest& leaf);

    /// The leaf hash at `index`.
    [[nodiscard]] Result<Digest> leaf(std::uint64_t index) const;

    /// The root of the tree formed by the first `tree_size` entries.
    [[nodiscard]] Result<Digest> root(std::uint64_t tree_size) const;

    /// The root of the current tree.
    [[nodiscard]] Result<Digest> root() const { return root(size()); }

    /// The right edge of the current tree, to grow a copy of it.
    [[nodiscard]] CompactRange compact_range() const;

    /// Inclusion proof (RFC 9162 §2.1.3.1) for the leaf at `index` within the
    /// tree of size `tree_size`, ordered from the leaf toward the root.
    [[nodiscard]] Result<std::vector<Digest>> inclusion_proof(std::uint64_t index,
                                                              std::uint64_t tree_size) const;

    /// Consistency proof (RFC 9162 §2.1.4.1) that the tree of size `new_size`
    /// extends the tree of size `old_size`. Empty when `old_size` is 0 or
    /// equal to `new_size`.
    [[nodiscard]] Result<std::vector<Digest>> consistency_proof(std::uint64_t old_size,
                                                                std::uint64_t new_size) const;

private:
    [[nodiscard]] Result<Digest> subtree_root(std::uint64_t begin, std::uint64_t end) const;
    [[nodiscard]] Digest stored(std::size_t level, std::uint64_t index) const;
    [[nodiscard]] Status inclusion_path(std::uint64_t index, std::uint64_t begin, std::uint64_t end,
                                        std::vector<Digest>& out) const;
    [[nodiscard]] Status consistency_subproof(std::uint64_t old_size, std::uint64_t begin,
                                              std::uint64_t end, bool complete,
                                              std::vector<Digest>& out) const;

    const crypto::Provider* provider_;
    HashAlg alg_;
    /// levels_[h][i] is the root of the complete subtree covering leaves
    /// [i * 2^h, (i + 1) * 2^h).
    std::vector<HashArray> levels_;
};

/// What `root_from_inclusion_proof` computed, remembered so that proofs
/// sharing the upper part of their path (an evidence bundle's receipts, all
/// into one tree) hash it once. The rest of a computation is a function of
/// the algorithm, the position reached, the hash there, and the rest of the
/// path: a proof that reaches a position with the same hash and the same
/// rest of the path as one before takes that one's root, with the same
/// outcome. Remembers successes only. The proofs it was given must outlive
/// it, unchanged.
class InclusionMemo {
public:
    InclusionMemo() = default;

private:
    friend Result<Digest> root_from_inclusion_proof(const crypto::Provider& provider, HashAlg alg,
                                                    const Digest& leaf, std::uint64_t index,
                                                    std::uint64_t tree_size,
                                                    std::span<const Digest> proof,
                                                    InclusionMemo* memo);
    struct Step {
        HashAlg alg;
        Digest hash;
        std::span<const Digest> rest;
        Digest root;
    };
    /// By (fn, sn) in RFC 9162's terms (ordered: no hash flooding).
    std::map<std::pair<std::uint64_t, std::uint64_t>, Step> steps_;
};

/// Computes the root that an inclusion proof leads to (RFC 9162 §2.1.3.2,
/// without the final comparison). Use this when the root is signed over
/// rather than supplied, as in RFC 9942 receipts. The same caveat as
/// `verify_inclusion` applies: the proof does not authenticate `tree_size`.
/// With `memo`, takes and leaves what proofs share there (see InclusionMemo).
[[nodiscard]] Result<Digest> root_from_inclusion_proof(const crypto::Provider& provider,
                                                       HashAlg alg, const Digest& leaf,
                                                       std::uint64_t index, std::uint64_t tree_size,
                                                       std::span<const Digest> proof,
                                                       InclusionMemo* memo = nullptr);

/// Verifies an inclusion proof (RFC 9162 §2.1.3.2).
///
/// The proof authenticates the leaf against `root`; it does not authenticate
/// `tree_size`, which only determines the proof's shape. Trees of different
/// sizes can share that shape for a given leaf, so `tree_size` and `root` must
/// come from the same signed checkpoint.
[[nodiscard]] Status verify_inclusion(const crypto::Provider& provider, HashAlg alg,
                                      const Digest& leaf, std::uint64_t index,
                                      std::uint64_t tree_size, std::span<const Digest> proof,
                                      const Digest& root);

/// Verifies a consistency proof (RFC 9162 §2.1.4.2). When `old_size` is 0 the
/// proof must be empty and `old_root` must be the empty-tree root. When the
/// sizes are equal the proof must be empty and the roots identical.
///
/// As with inclusion proofs, each size must come from the same signed
/// checkpoint as its root; the proof alone does not authenticate the sizes.
[[nodiscard]] Status verify_consistency(const crypto::Provider& provider, HashAlg alg,
                                        std::uint64_t old_size, std::uint64_t new_size,
                                        const Digest& old_root, const Digest& new_root,
                                        std::span<const Digest> proof);

} // namespace cexchain::merkle
