// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <bit>
#include <cstddef>

#include <cexchain/core/merkle.hpp>

namespace cexchain::merkle {

namespace {

constexpr std::uint8_t leaf_prefix = 0x00;
constexpr std::uint8_t node_prefix = 0x01;

/// The largest power of two strictly less than `n`, for n >= 2.
constexpr std::uint64_t split_point(std::uint64_t n) noexcept {
    return std::bit_floor(n - 1);
}

constexpr bool lsb(std::uint64_t x) noexcept {
    return (x & 1U) != 0;
}

Status check_proof_shape(HashAlg alg, std::span<const Digest> proof, std::size_t max_length) {
    if (proof.size() > max_length) {
        return fail(Errc::verification_failed, "proof is longer than any valid proof");
    }
    const std::size_t expected = crypto::digest_size(alg);
    const bool sizes_ok =
        std::ranges::all_of(proof, [expected](const Digest& d) { return d.size() == expected; });
    if (!sizes_ok) {
        return fail(Errc::verification_failed, "proof element has the wrong digest size");
    }
    return {};
}

} // namespace

Result<Digest> leaf_hash(const crypto::Provider& provider, HashAlg alg, ByteView entry) {
    const std::uint8_t prefix = leaf_prefix;
    return provider.digest(alg, {ByteView(&prefix, 1), entry});
}

Result<Digest> node_hash(const crypto::Provider& provider, HashAlg alg, const Digest& left,
                         const Digest& right) {
    const std::uint8_t prefix = node_prefix;
    return provider.digest(alg, {ByteView(&prefix, 1), left.bytes(), right.bytes()});
}

Result<Digest> empty_root(const crypto::Provider& provider, HashAlg alg) {
    return provider.digest(alg, ByteView{});
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------

Tree::Tree(const crypto::Provider& provider, HashAlg alg) noexcept
    : provider_(&provider), alg_(alg), levels_(1) {}

std::uint64_t Tree::size() const noexcept {
    return levels_.front().size();
}

Result<std::uint64_t> Tree::append(ByteView entry) {
    auto leaf = leaf_hash(*provider_, alg_, entry);
    if (!leaf) {
        return std::unexpected(leaf.error());
    }
    return append_leaf_hash(*leaf);
}

Result<std::uint64_t> Tree::append_leaf_hash(const Digest& leaf) {
    if (leaf.size() != crypto::digest_size(alg_)) {
        return fail(Errc::invalid_argument,
                    "leaf hash has the wrong size for the tree's algorithm");
    }
    // Compute every subtree root this leaf completes before mutating, so a
    // hashing failure leaves the tree unchanged.
    std::vector<Digest> completed;
    Digest carry = leaf;
    const std::uint64_t index = size();
    for (std::size_t h = 0; lsb(index >> h); ++h) {
        auto parent = node_hash(*provider_, alg_, levels_[h].back(), carry);
        if (!parent) {
            return std::unexpected(parent.error());
        }
        carry = *parent;
        completed.push_back(carry);
    }

    levels_.front().push_back(leaf);
    for (std::size_t h = 0; h < completed.size(); ++h) {
        if (levels_.size() <= h + 1) {
            levels_.emplace_back();
        }
        levels_[h + 1].push_back(completed[h]);
    }
    return index;
}

Result<Digest> Tree::leaf(std::uint64_t index) const {
    if (index >= size()) {
        return fail(Errc::invalid_argument, "leaf index is out of range");
    }
    return levels_.front()[static_cast<std::size_t>(index)];
}

Result<Digest> Tree::subtree_root(std::uint64_t begin, std::uint64_t end) const {
    const std::uint64_t n = end - begin;
    if (std::has_single_bit(n) && begin % n == 0) {
        const auto h = static_cast<std::size_t>(std::countr_zero(n));
        return levels_[h][static_cast<std::size_t>(begin >> h)];
    }
    const std::uint64_t k = split_point(n);
    auto left = subtree_root(begin, begin + k);
    if (!left) {
        return left;
    }
    auto right = subtree_root(begin + k, end);
    if (!right) {
        return right;
    }
    return node_hash(*provider_, alg_, *left, *right);
}

Result<Digest> Tree::root(std::uint64_t tree_size) const {
    if (tree_size > size()) {
        return fail(Errc::invalid_argument, "tree size exceeds the number of entries");
    }
    if (tree_size == 0) {
        return empty_root(*provider_, alg_);
    }
    return subtree_root(0, tree_size);
}

Status Tree::inclusion_path(std::uint64_t index, std::uint64_t begin, std::uint64_t end,
                            std::vector<Digest>& out) const {
    const std::uint64_t n = end - begin;
    if (n == 1) {
        return {};
    }
    const std::uint64_t k = split_point(n);
    Result<Digest> sibling;
    if (index < k) {
        if (auto s = inclusion_path(index, begin, begin + k, out); !s) {
            return s;
        }
        sibling = subtree_root(begin + k, end);
    } else {
        if (auto s = inclusion_path(index - k, begin + k, end, out); !s) {
            return s;
        }
        sibling = subtree_root(begin, begin + k);
    }
    if (!sibling) {
        return std::unexpected(sibling.error());
    }
    out.push_back(*sibling);
    return {};
}

Result<std::vector<Digest>> Tree::inclusion_proof(std::uint64_t index,
                                                  std::uint64_t tree_size) const {
    if (tree_size > size() || index >= tree_size) {
        return fail(Errc::invalid_argument, "leaf index or tree size is out of range");
    }
    std::vector<Digest> proof;
    if (auto s = inclusion_path(index, 0, tree_size, proof); !s) {
        return std::unexpected(s.error());
    }
    return proof;
}

Status Tree::consistency_subproof(std::uint64_t old_size, std::uint64_t begin, std::uint64_t end,
                                  bool complete, std::vector<Digest>& out) const {
    const std::uint64_t n = end - begin;
    if (old_size == n) {
        if (!complete) {
            auto root = subtree_root(begin, end);
            if (!root) {
                return std::unexpected(root.error());
            }
            out.push_back(*root);
        }
        return {};
    }
    const std::uint64_t k = split_point(n);
    Result<Digest> sibling;
    if (old_size <= k) {
        if (auto s = consistency_subproof(old_size, begin, begin + k, complete, out); !s) {
            return s;
        }
        sibling = subtree_root(begin + k, end);
    } else {
        if (auto s = consistency_subproof(old_size - k, begin + k, end, false, out); !s) {
            return s;
        }
        sibling = subtree_root(begin, begin + k);
    }
    if (!sibling) {
        return std::unexpected(sibling.error());
    }
    out.push_back(*sibling);
    return {};
}

Result<std::vector<Digest>> Tree::consistency_proof(std::uint64_t old_size,
                                                    std::uint64_t new_size) const {
    if (new_size > size() || old_size > new_size) {
        return fail(Errc::invalid_argument, "tree sizes are out of range");
    }
    std::vector<Digest> proof;
    if (old_size == 0 || old_size == new_size) {
        return proof;
    }
    if (auto s = consistency_subproof(old_size, 0, new_size, true, proof); !s) {
        return std::unexpected(s.error());
    }
    return proof;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

Result<Digest> root_from_inclusion_proof(const crypto::Provider& provider, HashAlg alg,
                                         const Digest& leaf, std::uint64_t index,
                                         std::uint64_t tree_size, std::span<const Digest> proof) {
    if (index >= tree_size) {
        return fail(Errc::verification_failed, "leaf index is outside the tree");
    }
    if (leaf.size() != crypto::digest_size(alg)) {
        return fail(Errc::verification_failed, "leaf hash has the wrong digest size");
    }
    if (auto s = check_proof_shape(alg, proof, max_inclusion_proof_length); !s) {
        return std::unexpected(s.error());
    }

    std::uint64_t fn = index;
    std::uint64_t sn = tree_size - 1;
    Digest r = leaf;
    for (const Digest& p : proof) {
        if (sn == 0) {
            return fail(Errc::verification_failed, "inclusion proof is too long");
        }
        Result<Digest> next;
        if (lsb(fn) || fn == sn) {
            next = node_hash(provider, alg, p, r);
            if (!lsb(fn)) {
                while (!lsb(fn) && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            next = node_hash(provider, alg, r, p);
        }
        if (!next) {
            return std::unexpected(next.error());
        }
        r = *next;
        fn >>= 1;
        sn >>= 1;
    }
    if (sn != 0) {
        return fail(Errc::verification_failed, "inclusion proof is too short");
    }
    return r;
}

Status verify_inclusion(const crypto::Provider& provider, HashAlg alg, const Digest& leaf,
                        std::uint64_t index, std::uint64_t tree_size, std::span<const Digest> proof,
                        const Digest& root) {
    auto computed = root_from_inclusion_proof(provider, alg, leaf, index, tree_size, proof);
    if (!computed) {
        return std::unexpected(computed.error());
    }
    if (*computed != root) {
        return fail(Errc::verification_failed, "inclusion proof does not lead to the root");
    }
    return {};
}

Status verify_consistency(const crypto::Provider& provider, HashAlg alg, std::uint64_t old_size,
                          std::uint64_t new_size, const Digest& old_root, const Digest& new_root,
                          std::span<const Digest> proof) {
    if (old_size > new_size) {
        return fail(Errc::verification_failed, "old tree is larger than the new tree");
    }
    if (auto s = check_proof_shape(alg, proof, max_consistency_proof_length); !s) {
        return s;
    }
    if (old_size == 0) {
        auto empty = empty_root(provider, alg);
        if (!empty) {
            return std::unexpected(empty.error());
        }
        if (!proof.empty() || old_root != *empty) {
            return fail(Errc::verification_failed, "invalid consistency proof from the empty tree");
        }
        return {};
    }
    if (old_size == new_size) {
        if (!proof.empty() || old_root != new_root) {
            return fail(Errc::verification_failed, "trees of equal size must have equal roots");
        }
        return {};
    }
    if (proof.empty()) {
        return fail(Errc::verification_failed, "consistency proof is empty");
    }

    // When the old tree is a complete subtree, its root is the implicit first
    // element of the path.
    std::vector<Digest> path;
    path.reserve(proof.size() + 1);
    if (std::has_single_bit(old_size)) {
        path.push_back(old_root);
    }
    path.insert(path.end(), proof.begin(), proof.end());

    std::uint64_t fn = old_size - 1;
    std::uint64_t sn = new_size - 1;
    while (lsb(fn)) {
        fn >>= 1;
        sn >>= 1;
    }
    Digest fr = path.front();
    Digest sr = path.front();
    for (std::size_t i = 1; i < path.size(); ++i) {
        const Digest& c = path[i];
        if (sn == 0) {
            return fail(Errc::verification_failed, "consistency proof is too long");
        }
        if (lsb(fn) || fn == sn) {
            auto next_fr = node_hash(provider, alg, c, fr);
            auto next_sr = node_hash(provider, alg, c, sr);
            if (!next_fr || !next_sr) {
                return std::unexpected(!next_fr ? next_fr.error() : next_sr.error());
            }
            fr = *next_fr;
            sr = *next_sr;
            if (!lsb(fn)) {
                while (!lsb(fn) && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            auto next_sr = node_hash(provider, alg, sr, c);
            if (!next_sr) {
                return std::unexpected(next_sr.error());
            }
            sr = *next_sr;
        }
        fn >>= 1;
        sn >>= 1;
    }
    if (sn != 0) {
        return fail(Errc::verification_failed, "consistency proof is too short");
    }
    if (fr != old_root || sr != new_root) {
        return fail(Errc::verification_failed, "consistency proof does not match the roots");
    }
    return {};
}

} // namespace cexchain::merkle
