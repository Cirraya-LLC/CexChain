// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/state_tree.hpp>

namespace cexchain::protocol {

namespace {

constexpr std::size_t max_depth = id_size * 8;
constexpr std::uint8_t leaf_prefix = 0x00;
constexpr std::uint8_t node_prefix = 0x01;

bool bit(const Id& id, std::size_t depth) {
    return ((id.bytes()[depth / 8] >> (7 - depth % 8)) & 1U) != 0;
}

Result<crypto::Digest> leaf_hash(const crypto::Provider& provider, crypto::HashAlg hash,
                                 const StateLeaf& leaf) {
    auto encoded = encode_state_leaf(leaf);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    const std::uint8_t prefix = leaf_prefix;
    return provider.digest(hash, {ByteView(&prefix, 1), *encoded});
}

Result<crypto::Digest> node_hash(const crypto::Provider& provider, crypto::HashAlg hash,
                                 const crypto::Digest& left, const crypto::Digest& right) {
    const std::uint8_t prefix = node_prefix;
    return provider.digest(hash, {ByteView(&prefix, 1), left.bytes(), right.bytes()});
}

/// The subtree at `depth` over `leaves`, which all share the path to it.
Result<crypto::Digest> subtree(const crypto::Provider& provider, crypto::HashAlg hash,
                               std::span<const StateLeaf> leaves, std::size_t depth) {
    if (leaves.empty()) {
        return merkle::empty_root(provider, hash);
    }
    if (leaves.size() == 1) {
        return leaf_hash(provider, hash, leaves.front());
    }
    if (depth >= max_depth) {
        return fail(Errc::invalid_argument, "state leaves must have distinct ids");
    }
    // Sorted by id, so the leaves whose bit at `depth` is 0 come first.
    const auto split =
        std::ranges::partition_point(leaves, [&](const StateLeaf& l) { return !bit(l.id, depth); });
    const auto middle = static_cast<std::size_t>(split - leaves.begin());
    auto left = subtree(provider, hash, leaves.first(middle), depth + 1);
    if (!left) {
        return left;
    }
    auto right = subtree(provider, hash, leaves.subspan(middle), depth + 1);
    if (!right) {
        return right;
    }
    return node_hash(provider, hash, *left, *right);
}

void add_index(std::vector<std::uint64_t>& history, std::optional<std::uint64_t> index) {
    if (index) {
        history.push_back(*index);
    }
}

StateLeaf actor_leaf(const ActorState& a) {
    StateLeaf leaf{ObjectKind::actor, a.id, {a.registered_at_index}};
    leaf.history.insert(leaf.history.end(), a.rotations.begin(), a.rotations.end());
    leaf.history.insert(leaf.history.end(), a.presence_updates.begin(), a.presence_updates.end());
    add_index(leaf.history, a.revoked_at_index);
    std::ranges::sort(leaf.history);
    return leaf;
}

StateLeaf delegation_leaf(const DelegationState& d) {
    StateLeaf leaf{ObjectKind::delegation, d.id, {d.granted_at_index}};
    add_index(leaf.history, d.revoked_at_index);
    return leaf;
}

StateLeaf record_leaf(const RecordState& r) {
    return {ObjectKind::record, r.id, r.history};
}

} // namespace

Result<Bytes> encode_state_leaf(const StateLeaf& leaf) {
    if (leaf.id.size() != id_size) {
        return fail(Errc::invalid_argument, "state leaf ids are 32 bytes");
    }
    if (leaf.history.empty() || !std::ranges::is_sorted(leaf.history) ||
        std::ranges::adjacent_find(leaf.history) != leaf.history.end()) {
        return fail(Errc::invalid_argument,
                    "a state leaf's history must be non-empty and strictly ascending");
    }
    cbor::Array history;
    for (const std::uint64_t index : leaf.history) {
        history.push_back(cbor::Value::unsigned_integer(index));
    }
    return cbor::encode(cbor::Value::array(
        {cbor::Value::unsigned_integer(static_cast<std::uint64_t>(leaf.kind)),
         cbor::Value::bytes(leaf.id.bytes()), cbor::Value::array(std::move(history))}));
}

std::vector<StateLeaf> state_leaves(const LedgerState& state) {
    std::vector<StateLeaf> leaves;
    leaves.reserve(state.actors().size() + state.delegations().size() + state.records().size());
    for (const auto& [key, actor] : state.actors()) {
        leaves.push_back(actor_leaf(actor));
    }
    for (const auto& [key, delegation] : state.delegations()) {
        leaves.push_back(delegation_leaf(delegation));
    }
    for (const auto& [key, record] : state.records()) {
        leaves.push_back(record_leaf(record));
    }
    std::ranges::sort(leaves, [](const StateLeaf& a, const StateLeaf& b) {
        return std::ranges::lexicographical_compare(a.id.bytes(), b.id.bytes());
    });
    return leaves;
}

std::optional<StateLeaf> state_leaf(const LedgerState& state, const Id& id) {
    if (const ActorState* a = state.actor(id)) {
        return actor_leaf(*a);
    }
    if (const DelegationState* d = state.delegation(id)) {
        return delegation_leaf(*d);
    }
    if (const RecordState* r = state.record(id)) {
        return record_leaf(*r);
    }
    return std::nullopt;
}

Result<crypto::Digest> state_root(const crypto::Provider& provider, crypto::HashAlg hash,
                                  std::span<const StateLeaf> leaves) {
    return subtree(provider, hash, leaves, 0);
}

Result<StateProof> prove_state(const crypto::Provider& provider, crypto::HashAlg hash,
                               std::span<const StateLeaf> leaves, const Id& id) {
    StateProof proof;
    std::span<const StateLeaf> current = leaves;
    for (std::size_t depth = 0; current.size() > 1; ++depth) {
        if (depth >= max_depth) {
            return fail(Errc::invalid_argument, "state leaves must have distinct ids");
        }
        const auto split = std::ranges::partition_point(
            current, [&](const StateLeaf& l) { return !bit(l.id, depth); });
        const auto middle = static_cast<std::size_t>(split - current.begin());
        const auto left = current.first(middle);
        const auto right = current.subspan(middle);
        auto sibling = subtree(provider, hash, bit(id, depth) ? left : right, depth + 1);
        if (!sibling) {
            return std::unexpected(sibling.error());
        }
        proof.siblings.push_back(*sibling);
        current = bit(id, depth) ? right : left;
    }
    if (current.empty() || current.front().id != id) {
        return fail(Errc::not_found, "the state has no object with this id");
    }
    proof.leaf = current.front();
    return proof;
}

Status verify_state_proof(const crypto::Provider& provider, crypto::HashAlg hash,
                          const StateProof& proof, const crypto::Digest& root) {
    if (proof.siblings.size() > max_depth) {
        return fail(Errc::malformed, "a state proof is deeper than the tree");
    }
    auto current = leaf_hash(provider, hash, proof.leaf);
    if (!current) {
        return std::unexpected(current.error());
    }
    for (std::size_t depth = proof.siblings.size(); depth-- > 0;) {
        const crypto::Digest& sibling = proof.siblings[depth];
        if (sibling.size() != crypto::digest_size(hash)) {
            return fail(Errc::malformed, "a state proof hash has the wrong size");
        }
        current = bit(proof.leaf.id, depth) ? node_hash(provider, hash, sibling, *current)
                                            : node_hash(provider, hash, *current, sibling);
        if (!current) {
            return std::unexpected(current.error());
        }
    }
    if (*current != root) {
        return fail(Errc::verification_failed,
                    "the state proof does not lead to the checkpoint's state root");
    }
    return {};
}

Status check_state_commitment(const crypto::Provider& provider, const LedgerState& state,
                              const SignedStateCommitment& commitment, std::uint64_t index) {
    const StateCommitment& c = commitment.commitment;
    if (!verify_state_commitment(provider, commitment, state.log_key())) {
        return fail(Errc::verification_failed, "a state commitment is not signed by the log key");
    }
    if (c.ledger_id != state.ledger_id() || c.tree_hash != state.hash()) {
        return fail(Errc::verification_failed, "a state commitment belongs to another ledger");
    }
    if (c.tree_size != index) {
        return fail(Errc::verification_failed,
                    "a state commitment is not at the position it claims");
    }
    const auto leaves = state_leaves(state);
    auto root = state_root(provider, state.hash(), leaves);
    if (!root) {
        return std::unexpected(root.error());
    }
    if (*root != c.state_root) {
        return fail(Errc::verification_failed,
                    "a state commitment does not match the state of the log");
    }
    return {};
}

} // namespace cexchain::protocol
