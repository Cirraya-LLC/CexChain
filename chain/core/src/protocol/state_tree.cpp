// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <bit>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/state_tree.hpp>

namespace cexchain::protocol {

namespace {

constexpr std::size_t max_depth = id_size * 8;
constexpr std::uint8_t leaf_prefix = 0x00;
constexpr std::uint8_t node_prefix = 0x01;

bool bit(const Id& id, std::size_t depth) {
    return ((static_cast<unsigned>(id.bytes()[depth / 8]) >> (7 - depth % 8)) & 1U) != 0;
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
    return {ObjectKind::record, r.id, r.history.to_vector()};
}

StateLeaf contract_leaf(const ContractState& c) {
    StateLeaf leaf{ObjectKind::contract, c.id, {c.deployed_at_index}};
    add_index(leaf.history, c.retired_at_index);
    return leaf;
}

StateLeaf instance_leaf(const InstanceState& i) {
    return {ObjectKind::instance, i.id, i.history.to_vector()};
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
    leaves.reserve(state.actors().size() + state.delegations().size() + state.records().size() +
                   state.contracts().size() + state.instances().size());
    for (const auto& [key, actor] : state.actors()) {
        leaves.push_back(actor_leaf(actor));
    }
    for (const auto& [key, delegation] : state.delegations()) {
        leaves.push_back(delegation_leaf(delegation));
    }
    for (const auto& [key, record] : state.records()) {
        leaves.push_back(record_leaf(record));
    }
    for (const auto& [key, contract] : state.contracts()) {
        leaves.push_back(contract_leaf(contract));
    }
    for (const auto& [key, instance] : state.instances()) {
        leaves.push_back(instance_leaf(instance));
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
    if (const ContractState* c = state.contract(id)) {
        return contract_leaf(*c);
    }
    if (const InstanceState* i = state.instance(id)) {
        return instance_leaf(*i);
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
                              const SignedStateCommitment& commitment, std::uint64_t index,
                              const crypto::Digest& state_root) {
    const StateCommitment& c = commitment.commitment;
    // The key in effect for the entries before it (a rotation among them
    // takes over here).
    if (!verify_state_commitment(provider, commitment, state.log_key_for(index))) {
        return fail(Errc::verification_failed, "a state commitment is not signed by the log key");
    }
    if (c.ledger_id != state.ledger_id() || c.tree_hash != state.hash()) {
        return fail(Errc::verification_failed, "a state commitment belongs to another ledger");
    }
    if (c.tree_size != index) {
        return fail(Errc::verification_failed,
                    "a state commitment is not at the position it claims");
    }
    if (state_root != c.state_root) {
        return fail(Errc::verification_failed,
                    "a state commitment does not match the state of the log");
    }
    return {};
}

Status check_state_commitment(const crypto::Provider& provider, const LedgerState& state,
                              const SignedStateCommitment& commitment, std::uint64_t index) {
    const auto leaves = state_leaves(state);
    auto root = state_root(provider, state.hash(), leaves);
    if (!root) {
        return std::unexpected(root.error());
    }
    return check_state_commitment(provider, state, commitment, index, *root);
}

} // namespace cexchain::protocol

// ---------------------------------------------------------------------------
// StateTree
// ---------------------------------------------------------------------------

namespace cexchain::protocol {

namespace {

bool key_bit(const IdKey& key, std::size_t depth) {
    return ((static_cast<unsigned>(key[depth / 8]) >> (7 - depth % 8)) & 1U) != 0;
}

/// The first bit at which two keys differ, if any.
std::optional<std::size_t> first_difference(const IdKey& a, const IdKey& b) {
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            const auto x = static_cast<std::uint8_t>(a[i] ^ b[i]);
            return i * 8 + static_cast<std::size_t>(std::countl_zero(x));
        }
    }
    return std::nullopt;
}

} // namespace

std::optional<StateLeaf> state_leaf(const LedgerState& state, const Id& id, std::uint64_t before) {
    auto leaf = state_leaf(state, id);
    if (!leaf) {
        return std::nullopt;
    }
    std::erase_if(leaf->history, [&](std::uint64_t index) { return index >= before; });
    if (leaf->history.empty()) {
        return std::nullopt;
    }
    return leaf;
}

Result<StateTree> StateTree::create(const crypto::Provider& provider, crypto::HashAlg hash) {
    if (crypto::digest_size(hash) != std::tuple_size_v<Hash>) {
        return fail(Errc::invalid_argument, "the state tree needs a hash with 32-byte digests");
    }
    auto empty = merkle::empty_root(provider, hash);
    if (!empty) {
        return std::unexpected(empty.error());
    }
    Hash e{};
    std::ranges::copy(empty->bytes(), e.begin());
    return StateTree(provider, hash, e);
}

Result<StateTree::Hash> StateTree::node_hash(const Hash& left, const Hash& right) const {
    const std::uint8_t prefix = node_prefix;
    auto digest = provider_->digest(hash_, {ByteView(&prefix, 1), ByteView(left), ByteView(right)});
    if (!digest) {
        return std::unexpected(digest.error());
    }
    Hash out{};
    std::ranges::copy(digest->bytes(), out.begin());
    return out;
}

const IdKey& StateTree::key_below(Ref ref) const {
    return (ref & leaf_flag) != 0 ? leaves_[ref & ~leaf_flag].key
                                  : leaves_[inners_[ref].any_leaf].key;
}

Result<StateTree::Hash> StateTree::hash_at(Ref ref, std::size_t depth) const {
    if ((ref & leaf_flag) != 0) {
        return leaves_[ref & ~leaf_flag].hash; // one object hashes alike at any depth
    }
    // Above its split, an inner node's subtree has an empty side at every
    // level of the prefix its keys share.
    const Inner& node = inners_[ref];
    const IdKey& key = leaves_[node.any_leaf].key;
    Hash h = node.hash;
    for (std::size_t d = node.crit; d-- > depth;) {
        auto next = key_bit(key, d) ? node_hash(empty_, h) : node_hash(h, empty_);
        if (!next) {
            return next;
        }
        h = *next;
    }
    return h;
}

Status StateTree::set(const StateLeaf& leaf) {
    auto digest = protocol::leaf_hash(*provider_, hash_, leaf);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    Hash h{};
    std::ranges::copy(digest->bytes(), h.begin());
    const IdKey key = key_of(leaf.id);
    dirty_ = true;
    if (root_ == none) {
        leaves_.push_back({key, h});
        root_ = leaf_flag;
        return {};
    }
    // The leaf the key leads to shares the longest prefix with it.
    Ref ref = root_;
    while ((ref & leaf_flag) == 0) {
        ref = inners_[ref].child[key_bit(key, inners_[ref].crit) ? 1 : 0];
    }
    const auto crit = first_difference(key, leaves_[ref & ~leaf_flag].key);
    if (!crit) {
        leaves_[ref & ~leaf_flag].hash = h;
        for (Ref r = root_; (r & leaf_flag) == 0;
             r = inners_[r].child[key_bit(key, inners_[r].crit) ? 1 : 0]) {
            inners_[r].dirty = true;
        }
        return {};
    }
    if (leaves_.size() >= leaf_flag || inners_.size() >= leaf_flag - 1) {
        return fail(Errc::limit_exceeded, "the state tree is full");
    }
    // A new inner node goes where the path first passes the differing bit.
    // Parents are kept by index: pushing to the arena may move it.
    const auto leaf_index = static_cast<std::uint32_t>(leaves_.size());
    leaves_.push_back({key, h});
    std::uint32_t parent = none;
    int side = 0;
    Ref current = root_;
    while ((current & leaf_flag) == 0 && inners_[current].crit < *crit) {
        inners_[current].dirty = true;
        parent = current;
        side = key_bit(key, inners_[current].crit) ? 1 : 0;
        current = inners_[current].child[side];
    }
    Inner node;
    node.crit = static_cast<std::uint16_t>(*crit);
    node.any_leaf = leaf_index;
    const int new_side = key_bit(key, *crit) ? 1 : 0;
    node.child[new_side] = leaf_flag | leaf_index;
    node.child[1 - new_side] = current;
    const auto node_index = static_cast<std::uint32_t>(inners_.size());
    inners_.push_back(node);
    if (parent == none) {
        root_ = node_index;
    } else {
        inners_[parent].child[side] = node_index;
    }
    return {};
}

Status StateTree::refresh(std::uint32_t index) {
    for (const Ref child : inners_[index].child) {
        if ((child & leaf_flag) == 0 && inners_[child].dirty) {
            if (auto s = refresh(child); !s) {
                return s;
            }
        }
    }
    const Inner& node = inners_[index];
    auto left = hash_at(node.child[0], node.crit + 1U);
    if (!left) {
        return std::unexpected(left.error());
    }
    auto right = hash_at(node.child[1], node.crit + 1U);
    if (!right) {
        return std::unexpected(right.error());
    }
    auto h = node_hash(*left, *right);
    if (!h) {
        return std::unexpected(h.error());
    }
    inners_[index].hash = *h;
    inners_[index].dirty = false;
    return {};
}

Status StateTree::commit() {
    if (dirty_ && root_ != none && (root_ & leaf_flag) == 0 && inners_[root_].dirty) {
        if (auto s = refresh(root_); !s) {
            return s;
        }
    }
    dirty_ = false;
    return {};
}

Result<crypto::Digest> StateTree::root() const {
    if (dirty_) {
        return fail(Errc::invalid_argument, "the state tree has changes not committed");
    }
    if (root_ == none) {
        return crypto::Digest::from_bytes(empty_);
    }
    auto h = hash_at(root_, 0);
    if (!h) {
        return std::unexpected(h.error());
    }
    return crypto::Digest::from_bytes(*h);
}

Result<std::vector<crypto::Digest>> StateTree::siblings(const Id& id) const {
    if (dirty_) {
        return fail(Errc::invalid_argument, "the state tree has changes not committed");
    }
    if (root_ == none) {
        return fail(Errc::not_found, "the state has no object with this id");
    }
    const IdKey key = key_of(id);
    auto empty = crypto::Digest::from_bytes(empty_);
    if (!empty) {
        return std::unexpected(empty.error());
    }
    std::vector<crypto::Digest> out;
    Ref ref = root_;
    std::size_t depth = 0;
    while ((ref & leaf_flag) == 0) {
        const Inner& node = inners_[ref];
        const IdKey& prefix = leaves_[node.any_leaf].key;
        for (std::size_t d = depth; d < node.crit; ++d) {
            if (key_bit(key, d) != key_bit(prefix, d)) {
                return fail(Errc::not_found, "the state has no object with this id");
            }
            out.push_back(*empty);
        }
        const int side = key_bit(key, node.crit) ? 1 : 0;
        auto sibling = hash_at(node.child[1 - side], node.crit + 1U);
        if (!sibling) {
            return std::unexpected(sibling.error());
        }
        auto digest = crypto::Digest::from_bytes(*sibling);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        out.push_back(*digest);
        ref = node.child[side];
        depth = node.crit + 1U;
    }
    if (leaves_[ref & ~leaf_flag].key != key) {
        return fail(Errc::not_found, "the state has no object with this id");
    }
    return out;
}

std::optional<crypto::Digest> StateTree::leaf_hash(const Id& id) const {
    if (root_ == none) {
        return std::nullopt;
    }
    const IdKey key = key_of(id);
    Ref ref = root_;
    while ((ref & leaf_flag) == 0) {
        ref = inners_[ref].child[key_bit(key, inners_[ref].crit) ? 1 : 0];
    }
    if (leaves_[ref & ~leaf_flag].key != key) {
        return std::nullopt;
    }
    auto digest = crypto::Digest::from_bytes(leaves_[ref & ~leaf_flag].hash);
    return digest ? std::optional(*digest) : std::nullopt;
}

} // namespace cexchain::protocol
