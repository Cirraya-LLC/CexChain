// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_all.hpp>

#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/ledger.hpp>

#include "support/crashing_fs.hpp"
#include "support/ledger_world.hpp"

namespace crypto = cexchain::crypto;
namespace ledger = cexchain::ledger;
namespace protocol = cexchain::protocol;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using crypto::openssl::KeyPair;
using protocol::StatementType;

using namespace cexchain::test;

TEST_CASE("a full record lifecycle, checkpoint, receipts, and replay", "[ledger][engine]") {
    const crypto::HashAlg hash = GENERATE(crypto::HashAlg::sha256, crypto::HashAlg::sm3);
    INFO(crypto::name(hash));
    World w(hash);
    Cast c = build_cast(w);

    const protocol::Id record = w.ok(c.agent, agent_record(w, c, certificate));
    const protocol::RecordState* state = w.ledger().state().record(record);
    REQUIRE(state != nullptr);
    CHECK(state->state == "issued");
    CHECK(state->registrant == c.agent_id);

    w.ok(c.bob,
         w.statement(c.bob_id, c.bob_delegation, protocol::RecordEndorseBody{record, "inspector"}));
    w.ok(c.alice, w.statement(c.alice_id, c.alice_delegation,
                              protocol::RecordTransitionBody{record, "issued", "suspended"}));
    w.ok(c.alice, w.statement(c.alice_id, c.alice_delegation,
                              protocol::RecordTransitionBody{record, "suspended", "issued"}));
    CHECK(w.ledger().state().record(record)->endorsements.size() == 1);
    CHECK(w.ledger().state().record(record)->state == "issued");

    // Checkpoint, then receipts for every entry verify against it.
    auto checkpoint = w.ledger().checkpoint(w.log_key());
    REQUIRE(checkpoint);
    CHECK(checkpoint->checkpoint.tree_size == w.ledger().size());
    CHECK(protocol::verify_checkpoint(provider(), *checkpoint, w.log_key().public_key()));
    for (std::uint64_t i = 0; i < w.ledger().size(); ++i) {
        auto receipt_bytes = w.ledger().receipt(w.log_key(), i);
        REQUIRE(receipt_bytes);
        auto receipt = protocol::parse_receipt(*receipt_bytes);
        REQUIRE(receipt);
        auto root = protocol::verify_receipt(provider(), *receipt, *w.ledger().entry(i),
                                             w.log_key().public_key());
        REQUIRE(root);
        CHECK(*root == checkpoint->checkpoint.root);
    }

    // Reopening replays and re-validates everything into the same state.
    auto reopened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(reopened);
    CHECK(reopened->size() == w.ledger().size());
    CHECK(*reopened->root(reopened->size()) == *w.ledger().root(w.ledger().size()));
    CHECK(reopened->state().actors().size() == w.ledger().state().actors().size());
    CHECK(reopened->state().record(record)->state == "issued");
    CHECK(reopened->state().record(record)->endorsements.size() == 1);
    REQUIRE(reopened->latest_checkpoint());
    CHECK(reopened->latest_checkpoint()->encoded == checkpoint->encoded);
}

TEST_CASE("signers must be registered, current, and authorized", "[ledger][engine]") {
    World w;
    Cast c = build_cast(w);
    const KeyPair mallory = key("mallory");

    SECTION("unknown actor") {
        protocol::Id fake = c.alice_id;
        Bytes bytes(fake.bytes().begin(), fake.bytes().end());
        bytes[0] ^= 1;
        fake = *protocol::to_id(bytes);
        CHECK(w.rejected(mallory, w.statement(fake, std::nullopt, w.record_body(certificate))) ==
              Errc::not_found);
    }
    SECTION("wrong key") {
        CHECK(w.rejected(c.bob, w.statement(c.alice_id, c.alice_delegation,
                                            w.record_body(certificate))) == Errc::rejected);
    }
    SECTION("no delegation, or someone else's") {
        CHECK(w.rejected(c.alice, w.statement(c.alice_id, std::nullopt,
                                              w.record_body(certificate))) == Errc::rejected);
        CHECK(w.rejected(c.alice, w.statement(c.alice_id, c.bob_delegation,
                                              w.record_body(certificate))) == Errc::rejected);
    }
    SECTION("outside the delegated statement or record types") {
        CHECK(w.rejected(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                            w.record_body(certificate))) == Errc::rejected);
        CHECK(w.rejected(c.agent, agent_record(w, c, delivery)) == Errc::rejected);
        CHECK(w.rejected(c.alice, w.statement(c.alice_id, c.alice_delegation,
                                              w.record_body("cexchain.agreement/1"))) ==
              Errc::rejected);
    }
    SECTION("agents must name their model") {
        auto s = agent_record(w, c, certificate);
        s.provenance.reset();
        CHECK(w.rejected(c.agent, s) == Errc::rejected);
        s.provenance = protocol::Provenance{};
        CHECK(w.rejected(c.agent, s) == Errc::rejected);
    }
    SECTION("the organization acts without delegation") {
        CHECK(w.rejected(w.org(), w.statement(w.org_id(), c.alice_delegation,
                                              w.record_body(certificate))) == Errc::rejected);
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body("custom.type/1")));
    }
}

TEST_CASE("delegations only narrow, and revocation and expiry cascade", "[ledger][engine]") {
    World w;
    Cast c = build_cast(w);

    SECTION("a delegate cannot grant more than it holds") {
        // Statement types beyond alice's scope.
        CHECK(w.rejected(c.alice,
                         w.statement(c.alice_id, c.alice_delegation,
                                     protocol::DelegationGrantBody{
                                         c.bob_id, scope({StatementType::actor_revoke},
                                                         std::vector<std::string>{certificate},
                                                         false, t0 + day)})) == Errc::rejected);
        // Record types beyond alice's scope, or unrestricted.
        CHECK(w.rejected(c.alice, w.statement(c.alice_id, c.alice_delegation,
                                              protocol::DelegationGrantBody{
                                                  c.bob_id, scope({StatementType::record_register},
                                                                  std::nullopt, false,
                                                                  t0 + day)})) == Errc::rejected);
        // Validity beyond alice's.
        CHECK(w.rejected(c.alice,
                         w.statement(c.alice_id, c.alice_delegation,
                                     protocol::DelegationGrantBody{
                                         c.bob_id, scope({StatementType::record_register},
                                                         std::vector<std::string>{certificate},
                                                         false, t0 + 2 * day)})) == Errc::rejected);
        // The agent may not delegate at all.
        CHECK(w.rejected(c.agent, [&] {
            auto s = w.statement(
                c.agent_id, c.agent_delegation,
                protocol::DelegationGrantBody{c.bob_id, scope({StatementType::record_register},
                                                              std::vector<std::string>{certificate},
                                                              false, t0 + day)});
            s.provenance = provenance();
            return s;
        }()) == Errc::rejected);
    }
    SECTION("revoking a delegation cuts off everything below it") {
        w.ok(c.agent, agent_record(w, c, certificate));
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                                  protocol::DelegationRevokeBody{c.alice_delegation, "test"}));
        CHECK(w.rejected(c.agent, agent_record(w, c, certificate)) == Errc::rejected);
        CHECK(w.rejected(c.alice, w.statement(c.alice_id, c.alice_delegation,
                                              w.record_body(certificate))) == Errc::rejected);
    }
    SECTION("revoking a grantor cuts off its delegates") {
        w.ok(w.org(),
             w.statement(w.org_id(), std::nullopt, protocol::ActorRevokeBody{c.alice_id, "left"}));
        CHECK(w.rejected(c.agent, agent_record(w, c, certificate)) == Errc::rejected);
        CHECK(w.rejected(c.alice, w.statement(c.alice_id, c.alice_delegation,
                                              w.record_body(certificate))) == Errc::rejected);
    }
    SECTION("an expired delegation chain authorizes nothing") {
        w.clock().set(t0 + day + 1);
        CHECK(w.rejected(c.agent, agent_record(w, c, certificate)) == Errc::rejected);
    }
    SECTION("only the grantor or the organization revokes a delegation") {
        CHECK(w.rejected(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                            protocol::DelegationRevokeBody{c.agent_delegation,
                                                                           std::nullopt})) ==
              Errc::rejected);
        w.ok(c.alice,
             w.statement(c.alice_id, c.alice_delegation,
                         protocol::DelegationRevokeBody{c.agent_delegation, std::nullopt}));
        CHECK(w.rejected(c.agent, agent_record(w, c, certificate)) == Errc::rejected);
    }
}

TEST_CASE("record lifecycle rules", "[ledger][engine]") {
    World w;
    Cast c = build_cast(w);
    const protocol::Id record = w.ok(c.agent, agent_record(w, c, certificate));
    auto endorse = [&](const std::string& role) {
        return w.statement(c.bob_id, c.bob_delegation, protocol::RecordEndorseBody{record, role});
    };
    auto transition = [&](const std::string& from, const std::string& to) {
        return w.statement(c.alice_id, c.alice_delegation,
                           protocol::RecordTransitionBody{record, from, to});
    };

    CHECK(w.rejected(c.bob, endorse("receiver")) == Errc::rejected); // not a certificate role
    w.ok(c.bob, endorse("inspector"));
    CHECK(w.rejected(c.bob, endorse("inspector")) == Errc::rejected); // once per role
    CHECK(w.rejected(c.alice, transition("suspended", "issued")) == Errc::rejected); // wrong state
    CHECK(w.rejected(c.alice, transition("issued", "delivered")) == Errc::rejected); // not allowed
    w.ok(c.alice, transition("issued", "suspended"));
    w.ok(c.alice, w.statement(c.alice_id, c.alice_delegation,
                              protocol::RecordRevokeBody{record, "superseded"}));
    CHECK(w.rejected(c.alice, transition("suspended", "issued")) == Errc::rejected); // revoked
    CHECK(w.rejected(c.bob, endorse("approver")) == Errc::rejected);

    protocol::Id missing = record;
    Bytes bytes(missing.bytes().begin(), missing.bytes().end());
    bytes[5] ^= 1;
    CHECK(w.rejected(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                        protocol::RecordEndorseBody{*protocol::to_id(bytes),
                                                                    "inspector"})) ==
          Errc::not_found);
}

TEST_CASE("keys, ledgers, time, and resubmission", "[ledger][engine]") {
    World w;
    Cast c = build_cast(w);

    SECTION("weak and reused keys are refused") {
        Bytes identity(32, 0);
        identity[0] = 1;
        protocol::ActorRegisterBody weak{protocol::ActorKind::device, "weak",
                                         crypto::PublicKey{crypto::SigAlg::ed25519, identity},
                                         std::nullopt, std::nullopt};
        CHECK(w.rejected(w.org(), w.statement(w.org_id(), std::nullopt, weak)) == Errc::rejected);
        protocol::ActorRegisterBody reused{protocol::ActorKind::person, "copy", c.bob.public_key(),
                                           std::nullopt, std::nullopt};
        CHECK(w.rejected(w.org(), w.statement(w.org_id(), std::nullopt, reused)) == Errc::rejected);
    }
    SECTION("an actor may rotate its own key; the old key stops working") {
        const KeyPair new_key = key("alice-2");
        w.ok(c.alice, w.statement(c.alice_id, std::nullopt,
                                  protocol::ActorRotateKeyBody{c.alice_id, new_key.public_key()}));
        CHECK(w.rejected(c.alice, w.statement(c.alice_id, c.alice_delegation,
                                              w.record_body(certificate))) == Errc::rejected);
        w.ok(new_key, w.statement(c.alice_id, c.alice_delegation, w.record_body(certificate)));
    }
    SECTION("statements for another ledger or from the future are refused") {
        auto s = w.statement(w.org_id(), std::nullopt, w.record_body(certificate));
        s.ledger_id = c.alice_id;
        CHECK(w.rejected(w.org(), s) == Errc::rejected);
        auto future = w.statement(w.org_id(), std::nullopt, w.record_body(certificate));
        future.issued_at = w.clock().now() + protocol::max_clock_skew_ms + 1;
        CHECK(w.rejected(w.org(), future) == Errc::rejected);
    }
    SECTION("resubmission is idempotent") {
        const Bytes bytes =
            w.sign(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body(certificate)));
        auto first = w.ledger().submit(bytes);
        REQUIRE(first);
        CHECK(first->newly_registered);
        w.clock().advance(5000);
        auto second = w.ledger().submit(bytes);
        REQUIRE(second);
        CHECK_FALSE(second->newly_registered);
        CHECK(second->index == first->index);
        CHECK(second->registered_at == first->registered_at);
    }
    SECTION("receipts need a covering checkpoint and the log key") {
        CHECK(w.ledger().receipt(w.log_key(), 0).error().code == Errc::not_found);
        CHECK(w.ledger().checkpoint(w.org()).error().code == Errc::invalid_argument);
        REQUIRE(w.ledger().checkpoint(w.log_key()));
        CHECK(w.ledger().receipt(w.log_key(), 0));
        CHECK(w.ledger().receipt(w.org(), 0).error().code == Errc::invalid_argument);
    }
}

TEST_CASE("a ledger refuses a log behind or different from its signed checkpoint",
          "[ledger][engine]") {
    World w;
    Cast c = build_cast(w);
    const std::uint64_t early_size = w.ledger().size();
    std::vector<Bytes> entries;
    w.ok(c.agent, agent_record(w, c, certificate));
    w.ok(c.agent, agent_record(w, c, certificate));
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    for (std::uint64_t i = 0; i < w.ledger().size(); ++i) {
        entries.push_back(*w.ledger().entry(i));
    }
    const Bytes checkpoints = w.fs().contents("checkpoints");
    const Bytes checkpoints_synced = w.fs().contents("checkpoints.synced");

    auto rebuild = [&](const std::vector<Bytes>& log_entries) {
        auto fs = std::make_unique<ledger::MemoryFileSystem>();
        auto log = ledger::RecordLog::open(*fs, "statements");
        REQUIRE(log);
        for (const Bytes& e : log_entries) {
            REQUIRE(log->append(e));
        }
        for (const auto& [name, bytes] : {std::pair{"checkpoints", checkpoints},
                                          std::pair{"checkpoints.synced", checkpoints_synced}}) {
            auto file = fs->open(name);
            REQUIRE(file);
            REQUIRE((*file)->append(bytes));
            REQUIRE((*file)->sync());
        }
        return fs;
    };

    // The intact copy opens.
    auto intact = rebuild(entries);
    CHECK(ledger::Ledger::open(*intact, w.clock(), provider()));

    // Rolled back to before the checkpoint.
    auto rolled_back = rebuild(std::vector<Bytes>(
        entries.begin(), entries.begin() + static_cast<std::ptrdiff_t>(early_size)));
    CHECK(ledger::Ledger::open(*rolled_back, w.clock(), provider()).error().code ==
          Errc::malformed);

    // A validly signed entry whose registration time was altered.
    auto altered = entries;
    auto entry = protocol::decode_log_entry(altered.back());
    REQUIRE(entry);
    entry->registered_at += 1;
    altered.back() = *protocol::encode_log_entry(*entry);
    auto tampered = rebuild(altered);
    CHECK(ledger::Ledger::open(*tampered, w.clock(), provider()).error().code == Errc::malformed);
}

TEST_CASE("the ledger survives crashes at any point", "[ledger][engine][simulation]") {
    for (std::uint64_t seed = 1; seed <= 60; ++seed) {
        INFO("seed " << seed);
        World w;
        Cast c = build_cast(w);
        ledger::SeededEntropy entropy(seed);

        // Submit through a file system on which the process dies after a
        // random number of writes and syncs, possibly mid-submission.
        std::vector<protocol::Id> acknowledged;
        {
            cexchain::test::CrashingFileSystem fs(w.fs(), entropy.below(30));
            auto crashing = ledger::Ledger::open(fs, w.clock(), provider());
            REQUIRE(crashing);
            for (int i = 0; i < 8; ++i) {
                auto registration =
                    crashing->submit(w.sign(c.agent, agent_record(w, c, certificate)));
                if (!registration) {
                    break;
                }
                acknowledged.push_back(registration->statement_id);
                w.clock().advance(10);
                if (entropy.below(3) == 0) {
                    if (!crashing->checkpoint(w.log_key())) {
                        break;
                    }
                }
            }
        }
        w.fs().crash(entropy);

        auto recovered = ledger::Ledger::open(w.fs(), w.clock(), provider());
        INFO((recovered.has_value() ? std::string() : std::string(recovered.error().detail)));
        REQUIRE(recovered);
        for (const protocol::Id& id : acknowledged) {
            CHECK(recovered->state().record(id) != nullptr);
        }
        CHECK(recovered->submit(w.sign(c.agent, agent_record(w, c, certificate))));
        CHECK(recovered->checkpoint(w.log_key()));
    }
}

TEST_CASE("a batch is validated in order and made durable at once", "[ledger][engine][batch]") {
    World w;
    Cast c = build_cast(w);
    const Bytes first = w.sign(c.agent, agent_record(w, c, certificate));
    REQUIRE(w.ledger().submit(first));
    const std::uint64_t size_before = w.ledger().size();

    // A new actor and its first statement, a key rotation and statements on
    // either side of it, a repeat, a forgery, and garbage, in one batch.
    const KeyPair dana = key("dana");
    const KeyPair dana2 = key("dana2");
    protocol::Statement add_dana =
        w.statement(w.org_id(), std::nullopt,
                    protocol::ActorRegisterBody{protocol::ActorKind::device, "Dana",
                                                dana.public_key(), std::nullopt, std::nullopt});
    const Bytes add = w.sign(w.org(), add_dana);
    const protocol::Id dana_id = protocol::parse_statement(provider(), add, w.hash())->id;
    const Bytes rotate =
        w.sign(dana, w.statement(dana_id, std::nullopt,
                                 protocol::ActorRotateKeyBody{dana_id, dana2.public_key()}));
    const Bytes record = w.sign(c.agent, agent_record(w, c, certificate));
    Bytes forged = w.sign(c.agent, agent_record(w, c, certificate));
    forged[forged.size() - 3] ^= 1;
    // Signed with the new key before the rotation applies: refused.
    const Bytes too_early = w.sign(
        dana2, w.statement(dana_id, std::nullopt,
                           protocol::ActorRotateKeyBody{dana_id, key("dana3").public_key()}));
    // Signed with the new key after the rotation: accepted.
    const Bytes after_rotation = w.sign(
        dana2, w.statement(dana_id, std::nullopt,
                           protocol::ActorRotateKeyBody{dana_id, key("dana4").public_key()}));
    const Bytes garbage{1, 2, 3};
    const std::vector<cexchain::ByteView> batch{add,    too_early,      rotate, record, record,
                                                forged, after_rotation, first,  garbage};
    const auto results = w.ledger().submit_batch(batch);
    REQUIRE(results.size() == batch.size());
    CHECK(results[0]);
    CHECK(results[0]->newly_registered);
    CHECK_FALSE(results[1]); // the old key is still current
    CHECK(results[2]);
    CHECK(results[3]);
    CHECK(results[4]); // the same statement again: registered once
    CHECK_FALSE(results[4]->newly_registered);
    CHECK(results[4]->index == results[3]->index);
    CHECK(results[5].error().code == Errc::verification_failed);
    CHECK(results[6]);
    CHECK(results[7]);
    CHECK_FALSE(results[7]->newly_registered);
    CHECK_FALSE(results[8]);
    // Four new entries, in order, all at one registration time.
    CHECK(w.ledger().size() == size_before + 4);
    CHECK(results[0]->index == size_before);
    CHECK(results[6]->index == size_before + 3);
    CHECK(results[0]->registered_at == results[6]->registered_at);

    // The same history replays the same way.
    auto reopened = ledger::Ledger::open(w.fs(), w.clock(), provider());
    REQUIRE(reopened);
    CHECK(*reopened->root(reopened->size()) == *w.ledger().root(w.ledger().size()));
    CHECK(reopened->state().actor(dana_id)->key == key("dana4").public_key());
}

TEST_CASE("batches survive crashes at any point", "[ledger][engine][simulation][batch]") {
    for (std::uint64_t seed = 1; seed <= 60; ++seed) {
        INFO("seed " << seed);
        World w;
        Cast c = build_cast(w);
        ledger::SeededEntropy entropy(seed);
        std::vector<protocol::Id> acknowledged;
        {
            cexchain::test::CrashingFileSystem fs(w.fs(), entropy.below(30));
            auto crashing = ledger::Ledger::open(fs, w.clock(), provider());
            REQUIRE(crashing);
            for (int round = 0; round < 6; ++round) {
                std::vector<Bytes> signed_statements;
                for (std::uint64_t i = 0; i < 1 + entropy.below(12); ++i) {
                    signed_statements.push_back(w.sign(c.agent, agent_record(w, c, certificate)));
                }
                // A repeat within the batch is acknowledged only if the
                // batch was written.
                if (entropy.below(2) == 0) {
                    signed_statements.push_back(signed_statements.front());
                }
                const std::vector<cexchain::ByteView> views(signed_statements.begin(),
                                                            signed_statements.end());
                const auto results = crashing->submit_batch(views);
                bool ok = true;
                for (const auto& r : results) {
                    if (r) {
                        acknowledged.push_back(r->statement_id);
                    } else {
                        ok = false;
                    }
                }
                w.clock().advance(10);
                if (!ok || (entropy.below(3) == 0 && !crashing->checkpoint(w.log_key()))) {
                    break;
                }
            }
        }
        w.fs().crash(entropy);
        auto recovered = ledger::Ledger::open(w.fs(), w.clock(), provider());
        INFO((recovered.has_value() ? std::string() : std::string(recovered.error().detail)));
        REQUIRE(recovered);
        for (const protocol::Id& id : acknowledged) {
            CHECK(recovered->state().record(id) != nullptr);
        }
        CHECK(recovered->submit(w.sign(c.agent, agent_record(w, c, certificate))));
    }
}
