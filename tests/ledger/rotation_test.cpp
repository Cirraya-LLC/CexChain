// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Rotating the organization's root key and the ledger's log key (spec v0.4):
// the ledger, evidence bundles, witnesses, replicas, and backups all follow
// the keys through their history.

#include <sstream>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/keys.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/witness.hpp>
#include <cexchain/ledger/backup.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::Errc;

protocol::Statement rotate_log(World& w, const KeyPair& to) {
    return w.statement(w.org_id(), std::nullopt, protocol::LedgerRotateLogKeyBody{to.public_key()});
}

protocol::Statement rotate_root(World& w, const KeyPair& to) {
    return w.statement(w.org_id(), std::nullopt,
                       protocol::ActorRotateKeyBody{w.org_id(), to.public_key()});
}

/// A ledger with a certificate checkpointed under the first log key, then
/// a log key rotation and a root key rotation, and a second certificate
/// checkpointed under the new log key.
struct Rotated {
    World w;
    Cast c = build_cast(w);
    KeyPair log2 = key("log 2");
    KeyPair root2 = key("root 2");
    protocol::Id first;
    protocol::Id second;
    protocol::SignedCheckpoint before;
    std::uint64_t log_rotation = 0;
    std::uint64_t root_rotation = 0;

    Rotated() {
        first = w.ok(c.agent, agent_record(w, c, document_type));
        before = *w.ledger().checkpoint(w.log_key());
        const auto rotated = w.ok(w.org(), rotate_log(w, log2));
        log_rotation = *w.ledger().state().statement_index(rotated);
        const auto rooted = w.ok(w.org(), rotate_root(w, root2));
        root_rotation = *w.ledger().state().statement_index(rooted);
        second = w.ok(c.agent, agent_record(w, c, document_type));
        REQUIRE(w.ledger().checkpoint(log2));
    }
};

} // namespace

TEST_CASE("the log key rotates; earlier checkpoints stay valid", "[ledger][rotation]") {
    Rotated r;
    const auto& state = r.w.ledger().state();
    REQUIRE(state.log_keys().size() == 2);
    CHECK(state.log_keys()[1] == protocol::KeyEpoch{r.log_rotation, r.log2.public_key()});
    CHECK(state.log_key() == r.log2.public_key());
    CHECK(state.log_key_for(r.log_rotation) == r.w.log_key().public_key());
    CHECK(state.log_key_for(r.log_rotation + 1) == r.log2.public_key());
    CHECK(state.root_key() == r.root2.public_key());
    REQUIRE(state.root_keys().size() == 2);
    CHECK(state.root_keys()[1].index == r.root_rotation);
    // Both rotations are in the organization's history.
    CHECK(state.actor(r.w.org_id())->rotations ==
          std::vector<std::uint64_t>{r.log_rotation, r.root_rotation});

    // The new checkpoint is the new key's; the old one stays the old key's.
    const auto latest = *r.w.ledger().latest_checkpoint();
    CHECK(protocol::verify_checkpoint(provider(), latest, r.log2.public_key()));
    CHECK(protocol::verify_checkpoint(provider(), r.before, r.w.log_key().public_key()));

    // The old key no longer checkpoints, and says why.
    auto refused = r.w.ledger().checkpoint(r.w.log_key());
    REQUIRE_FALSE(refused);
    CHECK(std::string(refused.error().detail).find("rotated") != std::string::npos);
    // The old root key no longer signs for the organization.
    CHECK(r.w.rejected(r.w.org(), r.w.statement(r.w.org_id(), std::nullopt,
                                                r.w.record_body("other/1"))) == Errc::rejected);
    r.w.ok(r.root2, r.w.statement(r.w.org_id(), std::nullopt, r.w.record_body("other/1")));

    // Reopening replays the log, each commitment and checkpoint under its key.
    auto reopened = ledger::Ledger::open(r.w.fs(), r.w.clock(), provider());
    REQUIRE(reopened);
    CHECK(reopened->state().log_keys().size() == 2);
    CHECK(reopened->latest_checkpoint()->encoded == latest.encoded);
    const auto audit = reopened->audit();
    REQUIRE(audit);
    CHECK(audit->checkpoints == 2);
}

TEST_CASE("bundles carry the rotations, and verify across them", "[ledger][rotation][evidence]") {
    Rotated r;
    // Old key in a ring of one: refused; the new key, or both, works.
    CHECK_FALSE(r.w.ledger().export_evidence(r.w.log_key(), r.first));
    const crypto::Signer* both[] = {&r.w.log_key(), &r.log2};
    for (const protocol::Id& record : {r.first, r.second}) {
        auto bundle = r.w.ledger().export_evidence(ledger::LogKeys(both), record);
        REQUIRE(bundle);
        // Both rotations are in, with receipts.
        std::vector<std::uint64_t> indices;
        for (const auto& e : bundle->entries) {
            indices.push_back(protocol::parse_receipt(e.receipt)->proof.leaf_index);
        }
        CHECK(std::ranges::contains(indices, r.log_rotation));
        CHECK(std::ranges::contains(indices, r.root_rotation));
        const auto encoded = protocol::encode_bundle(*bundle);
        auto report = protocol::verify_bundle(provider(), *encoded);
        INFO((report ? std::string() : std::string(report.error().detail)));
        REQUIRE(report);
        CHECK(report->complete);
        CHECK(report->log_key == r.log2.public_key());
        CHECK(report->log_key_rotations == 1);
        CHECK(report->root_key_rotations == 1);

        // Leaving a rotation out breaks the bundle.
        for (const std::uint64_t left_out : {r.log_rotation, r.root_rotation}) {
            auto trimmed = *bundle;
            std::erase_if(trimmed.entries, [&](const protocol::EvidenceEntry& e) {
                return protocol::parse_receipt(e.receipt)->proof.leaf_index == left_out;
            });
            CHECK_FALSE(protocol::verify_bundle(provider(), *protocol::encode_bundle(trimmed)));
        }
    }
}

TEST_CASE("before the next checkpoint, receipts are still the old key's",
          "[ledger][rotation][evidence]") {
    World w;
    Cast c = build_cast(w);
    const auto record = w.ok(c.agent, agent_record(w, c, document_type));
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    const KeyPair log2 = key("log 2");
    w.ok(w.org(), rotate_log(w, log2));
    // The latest checkpoint predates the rotation: the old key signs for it.
    CHECK_FALSE(w.ledger().receipt(log2, 0));
    const crypto::Signer* both[] = {&log2, &w.log_key()};
    auto bundle = w.ledger().export_evidence(ledger::LogKeys(both), record);
    REQUIRE(bundle);
    auto report = protocol::verify_bundle(provider(), *protocol::encode_bundle(*bundle));
    REQUIRE(report);
    CHECK(report->log_key == w.log_key().public_key());
    CHECK(report->log_key_rotations == 0);
}

TEST_CASE("who may rotate which key, to what", "[ledger][rotation][security]") {
    World w;
    Cast c = build_cast(w);
    const KeyPair log2 = key("log 2");
    const KeyPair root2 = key("root 2");

    // Rotating the log key cannot be delegated, and only the organization
    // signs it.
    protocol::Scope delegated;
    delegated.statement_types = {StatementType::ledger_rotate_log_key};
    CHECK_FALSE(protocol::sign_statement(
        w.org(), provider(), w.hash(),
        w.statement(w.org_id(), std::nullopt,
                    protocol::DelegationGrantBody{c.alice_id, delegated})));
    CHECK(w.rejected(c.alice, w.statement(c.alice_id, std::nullopt,
                                          protocol::LedgerRotateLogKeyBody{log2.public_key()})) ==
          Errc::rejected);
    // Nor does anyone but the organization rotate its root key, even with a
    // delegation covering key rotations.
    const auto rotator = w.grant(w.org(), w.org_id(), std::nullopt, c.alice_id,
                                 scope({StatementType::actor_rotate_key}));
    CHECK(w.rejected(c.alice, w.statement(c.alice_id, rotator,
                                          protocol::ActorRotateKeyBody{
                                              w.org_id(), root2.public_key()})) == Errc::rejected);

    // A log key never comes back, and is never an actor's key; nor is an
    // actor's key ever a log key.
    CHECK(w.rejected(w.org(), rotate_log(w, w.log_key())) == Errc::rejected);
    CHECK(w.rejected(w.org(), rotate_log(w, c.bob)) == Errc::rejected);
    CHECK(w.rejected(w.org(), rotate_log(w, w.org())) == Errc::rejected);
    w.ok(w.org(), rotate_log(w, log2));
    CHECK(w.rejected(w.org(), rotate_log(w, w.log_key())) == Errc::rejected);
    CHECK(w.rejected(w.org(), rotate_root(w, w.log_key())) == Errc::rejected);
    CHECK(w.rejected(w.org(), rotate_root(w, log2)) == Errc::rejected);
    CHECK(w.rejected(w.org(), w.statement(w.org_id(), std::nullopt,
                                          protocol::ActorRotateKeyBody{
                                              c.bob_id, log2.public_key()})) == Errc::rejected);
    const KeyPair someone = key("someone");
    CHECK(w.rejected(w.org(),
                     w.statement(w.org_id(), std::nullopt,
                                 protocol::ActorRegisterBody{protocol::ActorKind::device, "box",
                                                             w.log_key().public_key(), std::nullopt,
                                                             std::nullopt})) == Errc::rejected);

    // The organization rotates its root key with the current one.
    w.ok(w.org(), rotate_root(w, root2));
    CHECK(w.rejected(w.org(), rotate_root(w, someone)) == Errc::rejected);
    w.ok(root2, rotate_root(w, someone));
}

TEST_CASE("following rotations without the state", "[ledger][rotation]") {
    Rotated r;
    auto keys = protocol::keys_from_genesis(provider(), *r.w.ledger().entry(0));
    REQUIRE(keys);
    CHECK(keys->ledger_id == r.w.ledger().id());
    CHECK(keys->log_key() == r.w.log_key().public_key());
    for (std::uint64_t i = 1; i < r.w.ledger().size(); ++i) {
        REQUIRE(protocol::follow_key_rotation(provider(), *keys, i, *r.w.ledger().entry(i)));
    }
    CHECK(*keys == r.w.ledger().keys());
    CHECK(keys->root_key == r.root2.public_key());
    CHECK(keys->last_rotation == r.root_rotation);

    // A rotation is applied once, in order, and must be the root key's.
    auto again = *keys;
    CHECK_FALSE(protocol::follow_key_rotation(provider(), again, r.log_rotation,
                                              *r.w.ledger().entry(r.log_rotation)));
    auto out_of_order = *protocol::keys_from_genesis(provider(), *r.w.ledger().entry(0));
    REQUIRE(protocol::follow_key_rotation(provider(), out_of_order, r.root_rotation,
                                          *r.w.ledger().entry(r.root_rotation)));
    // The log rotation was signed by the genesis root, no longer in effect.
    CHECK_FALSE(protocol::follow_key_rotation(provider(), out_of_order, r.root_rotation + 1,
                                              *r.w.ledger().entry(r.log_rotation)));
    // Entries that rotate nothing leave the keys alone.
    auto untouched = *keys;
    REQUIRE(protocol::follow_key_rotation(provider(), untouched, r.w.ledger().size(),
                                          *r.w.ledger().entry(1)));
    CHECK(untouched == *keys);
}

TEST_CASE("a witness follows key rotations", "[witness][rotation][security]") {
    World w;
    Cast c = build_cast(w);
    w.ok(c.agent, agent_record(w, c, document_type));
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    const auto keys = protocol::keys_from_genesis(provider(), *w.ledger().entry(0));
    REQUIRE(keys);
    protocol::WitnessedLog log;
    log.ledger_id = keys->ledger_id;
    log.log_key = keys->log_key();
    log.root_key = keys->root_key;
    log.tree_hash = keys->hash;
    auto first = protocol::check_cosign_request(provider(), log, *w.ledger().cosign_request(0));
    REQUIRE(first);
    log = first->log;

    const KeyPair log2 = key("log 2");
    const KeyPair root2 = key("root 2");
    w.ok(w.org(), rotate_root(w, root2));
    w.ok(root2, rotate_log(w, log2));
    w.ok(c.agent, agent_record(w, c, document_type));
    REQUIRE(w.ledger().checkpoint(log2));
    const auto request = *w.ledger().cosign_request(log.size);
    REQUIRE(request.rotations.size() == 2);

    // Without the rotations the witness cannot check the new key's
    // checkpoint; with them, it follows and cosigns.
    auto bare = request;
    bare.rotations.clear();
    auto refused = protocol::check_cosign_request(provider(), log, bare);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == Errc::verification_failed);
    auto only_log = request;
    only_log.rotations.erase(only_log.rotations.begin()); // the root rotation left out
    CHECK_FALSE(protocol::check_cosign_request(provider(), log, only_log));
    auto tampered = request;
    tampered.rotations[0].path.front() = tampered.rotations[1].path.front();
    CHECK_FALSE(protocol::check_cosign_request(provider(), log, tampered));

    auto approved = protocol::check_cosign_request(provider(), log, request);
    INFO((approved ? std::string() : std::string(approved.error().detail)));
    REQUIRE(approved);
    CHECK(approved->log.log_key == log2.public_key());
    CHECK(approved->log.root_key == root2.public_key());
    CHECK(approved->log.last_rotation == request.rotations.back().index);
    const auto followed = approved->log;

    // From then on, the old log key's signature counts for nothing, even on
    // a checkpoint of the true history.
    const auto old_signed =
        protocol::sign_checkpoint(w.log_key(), provider(), approved->checkpoint.checkpoint);
    REQUIRE(old_signed);
    auto replay = request;
    replay.checkpoint = old_signed->encoded;
    replay.old_size = followed.size;
    replay.proof.clear();
    CHECK_FALSE(protocol::check_cosign_request(provider(), followed, replay));

    // Rotations it has followed are skipped when sent again.
    w.ok(c.agent, agent_record(w, c, document_type));
    REQUIRE(w.ledger().checkpoint(log2));
    auto next = protocol::check_cosign_request(provider(), followed,
                                               *w.ledger().cosign_request(followed.size));
    REQUIRE(next);
    CHECK(next->log.log_key == log2.public_key());

    // A witness that knows only the log key cannot follow a rotation.
    protocol::WitnessedLog blind = log;
    blind.root_key.reset();
    CHECK_FALSE(protocol::check_cosign_request(provider(), blind, request));
}

TEST_CASE("replicas and backups follow key rotations", "[replica][backup][rotation]") {
    Rotated r;
    // A replica copying checkpoint by checkpoint.
    ledger::MemoryFileSystem fs;
    ledger::ManualClock clock(t0 + day);
    auto replica = ledger::Ledger::create_replica(fs, clock, provider(), *r.w.ledger().entry(0));
    REQUIRE(replica);
    for (const auto& checkpoint : *r.w.ledger().checkpoints()) {
        // Ahead of the entries, the checkpoint verifies only with the key
        // the rotations among them lead to.
        protocol::LedgerKeys keys = replica->keys();
        for (std::uint64_t i = replica->size(); i < checkpoint.checkpoint.tree_size; ++i) {
            REQUIRE(protocol::follow_key_rotation(provider(), keys, i, *r.w.ledger().entry(i)));
        }
        REQUIRE(replica->verify_checkpoint(checkpoint.encoded, &keys.log_key()));
        std::vector<Bytes> entries;
        for (std::uint64_t i = replica->size(); i < checkpoint.checkpoint.tree_size; ++i) {
            entries.push_back(*r.w.ledger().entry(i));
        }
        REQUIRE(replica->append_entries(entries));
        REQUIRE(replica->store_checkpoint(checkpoint.encoded));
    }
    CHECK(replica->keys() == r.w.ledger().keys());
    CHECK(replica->audit());

    // A backup signed with the newest log key, with a rotation in its tail.
    const KeyPair log3 = key("log 3");
    r.w.ok(r.root2, rotate_log(r.w, log3));
    std::ostringstream stale;
    CHECK_FALSE(ledger::write_backup(r.w.ledger(), provider(), {}, t0 + day, stale, &r.log2));
    std::ostringstream out;
    REQUIRE(ledger::write_backup(r.w.ledger(), provider(), {}, t0 + day, out, &log3));
    ledger::MemoryFileSystem restored_fs;
    std::istringstream in(out.str());
    auto summary =
        ledger::restore_backup(in, restored_fs, clock, provider(),
                               [](const ledger::BackupFile&) -> cexchain::Status { return {}; });
    INFO((summary ? std::string() : std::string(summary.error().detail)));
    REQUIRE(summary);
    CHECK(summary->is_signed);
    CHECK(summary->size == r.w.ledger().size());
    CHECK(summary->checkpoints == 2);
}
