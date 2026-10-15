// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/ledger/record_log.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

protocol::Id id_of(std::uint32_t n) {
    const auto digest = provider().digest(
        crypto::HashAlg::sha256, cexchain::as_bytes("state tree test " + std::to_string(n)));
    return *digest;
}

std::vector<protocol::StateLeaf> leaves(std::uint32_t count) {
    std::vector<protocol::StateLeaf> out;
    for (std::uint32_t i = 0; i < count; ++i) {
        out.push_back({static_cast<protocol::ObjectKind>(1 + i % 3), id_of(i), {i, i + 1000}});
    }
    std::ranges::sort(out, [](const auto& a, const auto& b) {
        return std::ranges::lexicographical_compare(a.id.bytes(), b.id.bytes());
    });
    return out;
}

const crypto::HashAlg sha256 = crypto::HashAlg::sha256;

} // namespace

TEST_CASE("the state tree commits to every object exactly once", "[state]") {
    CHECK(*protocol::state_root(provider(), sha256, {}) ==
          *cexchain::merkle::empty_root(provider(), sha256));

    const auto all = leaves(200);
    const auto root = protocol::state_root(provider(), sha256, all);
    REQUIRE(root);
    for (const auto& leaf : all) {
        const auto proof = protocol::prove_state(provider(), sha256, all, leaf.id);
        REQUIRE(proof);
        CHECK(proof->leaf == leaf);
        CHECK(proof->siblings.size() < 20);
        CHECK(protocol::verify_state_proof(provider(), sha256, *proof, *root));
    }

    // One object's history changes: the root changes, and old proofs fail.
    auto changed = all;
    changed[17].history.push_back(5000);
    const auto new_root = protocol::state_root(provider(), sha256, changed);
    REQUIRE(new_root);
    CHECK(*new_root != *root);
    const auto stale = protocol::prove_state(provider(), sha256, all, all[17].id);
    CHECK_FALSE(protocol::verify_state_proof(provider(), sha256, *stale, *new_root));

    // A proof cannot claim another history for the object.
    auto lie = *protocol::prove_state(provider(), sha256, all, all[3].id);
    lie.leaf.history.pop_back();
    CHECK(protocol::verify_state_proof(provider(), sha256, lie, *root).error().code ==
          Errc::verification_failed);
    lie = *protocol::prove_state(provider(), sha256, all, all[3].id);
    lie.leaf.kind = protocol::ObjectKind::record == lie.leaf.kind ? protocol::ObjectKind::actor
                                                                  : protocol::ObjectKind::record;
    CHECK_FALSE(protocol::verify_state_proof(provider(), sha256, lie, *root));
    lie = *protocol::prove_state(provider(), sha256, all, all[3].id);
    lie.siblings.pop_back();
    CHECK_FALSE(protocol::verify_state_proof(provider(), sha256, lie, *root));

    CHECK(protocol::prove_state(provider(), sha256, all, id_of(999)).error().code ==
          Errc::not_found);
    auto duplicated = all;
    duplicated.insert(duplicated.begin() + 5, duplicated[5]);
    CHECK_FALSE(protocol::state_root(provider(), sha256, duplicated));
    CHECK_FALSE(protocol::encode_state_leaf({protocol::ObjectKind::actor, id_of(1), {}}));
    CHECK_FALSE(protocol::encode_state_leaf({protocol::ObjectKind::actor, id_of(1), {3, 2}}));

    // SM3 ledgers hash their tree with SM3.
    const auto sm3_root = protocol::state_root(provider(), crypto::HashAlg::sm3, all);
    REQUIRE(sm3_root);
    CHECK(sm3_root->bytes().size() == 32);
    CHECK(*sm3_root != *root);
}

TEST_CASE("checkpoints end with a state commitment in the log", "[state][ledger]") {
    World w;
    const auto alice_key = key("alice");
    const auto alice =
        w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::person, alice_key);
    auto checkpoint = w.ledger().checkpoint(w.log_key());
    REQUIRE(checkpoint);
    // Genesis, Alice, and the commitment to the state after them.
    CHECK(checkpoint->checkpoint.tree_size == 3);
    const auto entry = protocol::decode_log_entry(*w.ledger().entry(2));
    REQUIRE(entry);
    REQUIRE(entry->is_state_commitment());
    const auto commitment = protocol::parse_state_commitment(provider(), entry->state_commitment);
    REQUIRE(commitment);
    CHECK(commitment->commitment.tree_size == 2);
    CHECK(commitment->commitment.state_root ==
          *protocol::state_root(provider(), w.hash(), protocol::state_leaves(w.ledger().state())));
    CHECK(protocol::verify_state_commitment(provider(), *commitment, w.log_key().public_key()));
    CHECK(w.ledger().state_commitment() == commitment->commitment);

    // Nothing changed: checkpointing again adds no commitment.
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    CHECK(w.ledger().size() == 3);

    CHECK(protocol::state_leaf(w.ledger().state(), alice)->history ==
          std::vector<std::uint64_t>{1});
    w.ok(w.org(), w.statement(w.org_id(), std::nullopt, protocol::ActorRevokeBody{alice, "left"}));
    CHECK(protocol::state_leaf(w.ledger().state(), alice)->history ==
          std::vector<std::uint64_t>{1, 3});
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    CHECK(w.ledger().size() == 5);
    REQUIRE(ledger::Ledger::open(w.fs(), w.clock(), provider()));
    CHECK(w.ledger().audit());

    // An operator that appends a commitment to a state the log does not have
    // (one where Alice was never revoked) has a log that no longer opens:
    // replay checks every commitment, and the false one stays in the log.
    auto lie = commitment->commitment;
    lie.tree_size = 5;
    lie.timestamp += 10'000;
    const auto signed_lie = protocol::sign_state_commitment(w.log_key(), provider(), lie);
    REQUIRE(signed_lie);
    auto log = ledger::RecordLog::open(w.fs(), "statements");
    REQUIRE(log);
    REQUIRE(log->append(
        *protocol::encode_log_entry({signed_lie->id, lie.timestamp, {}, signed_lie->encoded})));
    const auto reopened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE_FALSE(reopened);
    CHECK(reopened.error().code == Errc::malformed);
}

TEST_CASE("bundles prove that nothing was left out", "[state][evidence]") {
    World w;
    const auto alice_key = key("alice");
    const auto alice =
        w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::person, alice_key);
    protocol::Scope scope;
    scope.statement_types = {StatementType::record_endorse};
    const auto delegation = w.grant(w.org(), w.org_id(), std::nullopt, alice, scope);
    const auto record =
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body(document_type)));
    w.ok(alice_key,
         w.statement(alice, delegation, protocol::RecordEndorseBody{record, "inspector"}));
    // Later: Alice is revoked, and so is the record.
    const auto alice_revoked = w.ok(
        w.org(), w.statement(w.org_id(), std::nullopt, protocol::ActorRevokeBody{alice, "left"}));
    const auto record_revoked =
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                                  protocol::RecordRevokeBody{record, "withdrawn"}));
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    const auto bundle = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(bundle);
    // The record, the org (signer), Alice (signer), and her delegation.
    CHECK(bundle->state_proofs.size() == 4);

    const auto report = protocol::verify_bundle(provider(), *protocol::encode_bundle(*bundle));
    REQUIRE(report);
    CHECK(report->complete);
    CHECK(report->revoked);
    CHECK(report->events[1].actor.revoked); // Alice, since revoked

    auto entry_index = [&](const protocol::Id& statement) {
        return *w.ledger().state().statement_index(statement);
    };
    auto without = [&](std::uint64_t index) {
        auto copy = *bundle;
        std::erase_if(copy.entries, [&](const protocol::EvidenceEntry& e) {
            return protocol::decode_log_entry(e.entry)->statement_id ==
                   *protocol::decode_log_entry(*w.ledger().entry(index))
                        .transform([](const protocol::LogEntry& l) { return l.statement_id; });
        });
        REQUIRE(copy.entries.size() == bundle->entries.size() - 1);
        return protocol::verify_bundle(provider(), *protocol::encode_bundle(copy));
    };
    SECTION("leaving out the record's revocation is caught") {
        CHECK(without(entry_index(record_revoked)).error().code == Errc::verification_failed);
    }
    SECTION("leaving out the signer's revocation is caught") {
        CHECK(without(entry_index(alice_revoked)).error().code == Errc::verification_failed);
    }
    SECTION("leaving out a proof is caught") {
        auto copy = *bundle;
        copy.state_proofs.pop_back();
        CHECK_FALSE(protocol::verify_bundle(provider(), *protocol::encode_bundle(copy)));
    }
    SECTION("a repeated or altered proof is caught") {
        auto copy = *bundle;
        copy.state_proofs.push_back(copy.state_proofs.front());
        CHECK_FALSE(protocol::verify_bundle(provider(), *protocol::encode_bundle(copy)));
        copy = *bundle;
        copy.state_proofs.front().leaf.history.pop_back();
        if (copy.state_proofs.front().leaf.history.empty()) {
            copy.state_proofs.front().leaf.history.push_back(99);
        }
        CHECK_FALSE(protocol::verify_bundle(provider(), *protocol::encode_bundle(copy)));
    }
    SECTION("proofs round-trip through the bundle encoding") {
        CHECK(*protocol::decode_bundle(*protocol::encode_bundle(*bundle)) == *bundle);
    }
}

namespace {

/// The reference: the whole tree recomputed from the sorted leaves.
struct Reference {
    std::map<std::vector<std::uint8_t>, protocol::StateLeaf> leaves;

    std::vector<protocol::StateLeaf> sorted() const {
        std::vector<protocol::StateLeaf> out;
        for (const auto& [key, leaf] : leaves) {
            out.push_back(leaf);
        }
        return out;
    }
};

protocol::Id id_from(std::array<std::uint8_t, 32> bytes) {
    return *protocol::to_id(bytes);
}

void check_against(const protocol::StateTree& tree, const Reference& reference) {
    const auto sorted = reference.sorted();
    const auto expected = protocol::state_root(provider(), crypto::HashAlg::sha256, sorted);
    REQUIRE(expected);
    REQUIRE(tree.root());
    CHECK(*tree.root() == *expected);
    for (const auto& leaf : sorted) {
        const auto proof =
            protocol::prove_state(provider(), crypto::HashAlg::sha256, sorted, leaf.id);
        REQUIRE(proof);
        const auto siblings = tree.siblings(leaf.id);
        REQUIRE(siblings);
        CHECK(*siblings == proof->siblings);
    }
}

} // namespace

TEST_CASE("the incremental state tree matches the reference", "[state][tree]") {
    auto tree = protocol::StateTree::create(provider(), crypto::HashAlg::sha256);
    REQUIRE(tree);
    Reference reference;
    REQUIRE(tree->commit());
    CHECK(*tree->root() == *protocol::state_root(provider(), crypto::HashAlg::sha256, {}));

    std::mt19937_64 random(GENERATE(1U, 2U, 3U, 4U));
    // Ids drawn so that many share long prefixes: random bytes, then copies
    // of earlier ids with one late bit flipped.
    std::vector<std::array<std::uint8_t, 32>> ids;
    for (int round = 0; round < 12; ++round) {
        const int changes = 1 + static_cast<int>(random() % 40);
        for (int c = 0; c < changes; ++c) {
            std::array<std::uint8_t, 32> key{};
            const auto choice = random() % 4;
            if (ids.empty() || choice == 0) {
                for (auto& b : key) {
                    b = static_cast<std::uint8_t>(random());
                }
            } else if (choice == 1) {
                key = ids[random() % ids.size()];
                const auto bit = 128 + random() % 128;
                key[bit / 8] ^= static_cast<std::uint8_t>(0x80U >> (bit % 8));
            } else {
                key = ids[random() % ids.size()]; // an update
            }
            ids.push_back(key);
            const protocol::StateLeaf leaf{static_cast<protocol::ObjectKind>(1 + random() % 3),
                                           id_from(key),
                                           {random() % 1000, 1000 + random() % 1000}};
            REQUIRE(tree->set(leaf));
            reference.leaves[std::vector<std::uint8_t>(key.begin(), key.end())] = leaf;
        }
        // Reads need a commit first.
        CHECK_FALSE(tree->root());
        REQUIRE(tree->commit());
        CHECK(tree->size() == reference.leaves.size());
        check_against(*tree, reference);
    }

    // Proofs from the tree verify; absent ids have none.
    const auto sorted = reference.sorted();
    const auto root = *tree->root();
    for (const auto& leaf : sorted) {
        const protocol::StateProof proof{leaf, *tree->siblings(leaf.id)};
        CHECK(protocol::verify_state_proof(provider(), crypto::HashAlg::sha256, proof, root));
        CHECK(*tree->leaf_hash(leaf.id) != root);
    }
    std::array<std::uint8_t, 32> absent{};
    absent.fill(0xa5);
    CHECK(tree->siblings(id_from(absent)).error().code == Errc::not_found);
    CHECK_FALSE(tree->leaf_hash(id_from(absent)));
}

TEST_CASE("the incremental state tree at the edges of the key space", "[state][tree]") {
    auto tree = protocol::StateTree::create(provider(), crypto::HashAlg::sm3);
    REQUIRE(tree);
    CHECK_FALSE(protocol::StateTree::create(provider(), crypto::HashAlg::sha512));
    // Keys that differ only in their very last bit, and in their first.
    std::array<std::uint8_t, 32> zero{};
    std::array<std::uint8_t, 32> last = zero;
    last[31] = 1;
    std::array<std::uint8_t, 32> first = zero;
    first[0] = 0x80;
    std::vector<protocol::StateLeaf> leaves;
    for (const auto& key : {zero, last, first}) {
        leaves.push_back({protocol::ObjectKind::record, id_from(key), {7}});
        REQUIRE(tree->set(leaves.back()));
    }
    REQUIRE(tree->commit());
    std::ranges::sort(leaves, [](const auto& a, const auto& b) {
        return std::ranges::lexicographical_compare(a.id.bytes(), b.id.bytes());
    });
    CHECK(*tree->root() == *protocol::state_root(provider(), crypto::HashAlg::sm3, leaves));
    const auto deep = tree->siblings(id_from(last));
    REQUIRE(deep);
    CHECK(deep->size() == 256);
    CHECK(*deep ==
          protocol::prove_state(provider(), crypto::HashAlg::sm3, leaves, id_from(last))->siblings);
}
