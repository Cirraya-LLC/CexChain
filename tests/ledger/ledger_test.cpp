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

namespace crypto = cexchain::crypto;
namespace ledger = cexchain::ledger;
namespace protocol = cexchain::protocol;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using crypto::openssl::KeyPair;
using protocol::StatementType;

namespace {

constexpr protocol::Timestamp t0 = 1'791'244'800'000; // 2026-10-06T00:00:00Z
constexpr protocol::Timestamp day = 86'400'000;
const std::string certificate = "cexchain.certificate/1";
const std::string delivery = "cexchain.delivery/1";

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

KeyPair key(const std::string& name) {
    auto seed = provider().digest(crypto::HashAlg::sha256, as_bytes("ledger test key: " + name));
    REQUIRE(seed);
    auto pair = KeyPair::from_ed25519_seed(seed->bytes());
    REQUIRE(pair);
    return std::move(*pair);
}

/// A ledger with an organization, plus helpers to build and submit
/// statements.
class World {
public:
    explicit World(crypto::HashAlg hash = crypto::HashAlg::sha256)
        : hash_(hash), clock_(t0), entropy_(7), org_(key("org")), log_key_(key("log")) {
        protocol::Statement genesis;
        genesis.issued_at = t0;
        genesis.nonce = entropy_.bytes<16>();
        genesis.body =
            protocol::GenesisBody{hash, "Test Org", org_.public_key(), log_key_.public_key()};
        auto signed_genesis = protocol::sign_statement(org_, provider(), hash, genesis);
        REQUIRE(signed_genesis);
        genesis_bytes_ = signed_genesis->encoded;
        auto created = ledger::Ledger::create(fs_, clock_, provider(), genesis_bytes_);
        REQUIRE(created);
        ledger_.emplace(std::move(*created));
    }

    ledger::Ledger& ledger() { return *ledger_; }
    ledger::MemoryFileSystem& fs() { return fs_; }
    ledger::ManualClock& clock() { return clock_; }
    const KeyPair& org() const { return org_; }
    const KeyPair& log_key() const { return log_key_; }
    const protocol::Id& org_id() { return ledger_->id(); }
    crypto::HashAlg hash() const { return hash_; }

    protocol::Statement statement(const protocol::Id& actor, std::optional<protocol::Id> delegation,
                                  protocol::Body body) {
        protocol::Statement s;
        s.ledger_id = ledger_->id();
        s.actor_id = actor;
        s.delegation_id = std::move(delegation);
        s.issued_at = clock_.now();
        s.nonce = entropy_.bytes<16>();
        s.body = std::move(body);
        return s;
    }

    Bytes sign(const KeyPair& signer, const protocol::Statement& s) {
        auto signed_statement = protocol::sign_statement(signer, provider(), hash_, s);
        REQUIRE(signed_statement);
        return signed_statement->encoded;
    }

    cexchain::Result<ledger::Registration> submit(const KeyPair& signer,
                                                  const protocol::Statement& s) {
        return ledger_->submit(sign(signer, s));
    }

    protocol::Id ok(const KeyPair& signer, const protocol::Statement& s) {
        auto registration = submit(signer, s);
        INFO((registration.has_value() ? std::string() : std::string(registration.error().detail)));
        REQUIRE(registration);
        CHECK(registration->newly_registered);
        clock_.advance(1000);
        return registration->statement_id;
    }

    Errc rejected(const KeyPair& signer, const protocol::Statement& s) {
        auto registration = submit(signer, s);
        REQUIRE_FALSE(registration);
        return registration.error().code;
    }

    protocol::Id register_actor(const KeyPair& signer, const protocol::Id& actor,
                                std::optional<protocol::Id> delegation, protocol::ActorKind kind,
                                const KeyPair& actor_key,
                                std::optional<protocol::Id> responsible = std::nullopt) {
        protocol::ActorRegisterBody body{kind, "actor", actor_key.public_key(), responsible,
                                         std::nullopt};
        if (kind == protocol::ActorKind::agent) {
            body.agent = protocol::AgentProfile{"claude-opus-5-5", "2026-09", "test"};
        }
        return ok(signer, statement(actor, std::move(delegation), std::move(body)));
    }

    protocol::Id grant(const KeyPair& signer, const protocol::Id& actor,
                       std::optional<protocol::Id> delegation, const protocol::Id& grantee,
                       protocol::Scope scope) {
        return ok(signer, statement(actor, std::move(delegation),
                                    protocol::DelegationGrantBody{grantee, std::move(scope)}));
    }

    protocol::RecordRegisterBody record_body(const std::string& type) {
        return protocol::RecordRegisterBody{type, Bytes(32, 0x42), 3, {}, std::nullopt};
    }

private:
    crypto::HashAlg hash_;
    ledger::MemoryFileSystem fs_;
    ledger::ManualClock clock_;
    ledger::SeededEntropy entropy_;
    KeyPair org_;
    KeyPair log_key_;
    Bytes genesis_bytes_;
    std::optional<ledger::Ledger> ledger_;
};

protocol::Provenance provenance() {
    return protocol::Provenance{"claude-opus-5-5", "2026-09", std::nullopt, {}};
}

protocol::Scope scope(std::vector<StatementType> types,
                      std::optional<std::vector<std::string>> record_types = std::nullopt,
                      bool may_delegate = false,
                      std::optional<protocol::Timestamp> not_after = std::nullopt) {
    protocol::Scope s;
    s.statement_types = std::move(types);
    s.record_types = std::move(record_types);
    s.may_delegate = may_delegate;
    s.not_after = not_after;
    return s;
}

/// The cast of the standard scenario.
struct Cast {
    KeyPair alice = key("alice");
    KeyPair agent = key("agent");
    KeyPair bob = key("bob");
    protocol::Id alice_id;
    protocol::Id alice_delegation;
    protocol::Id agent_id;
    protocol::Id agent_delegation;
    protocol::Id bob_id;
    protocol::Id bob_delegation;
};

Cast build_cast(World& w) {
    Cast c;
    c.alice_id =
        w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::person, c.alice);
    c.alice_delegation =
        w.grant(w.org(), w.org_id(), std::nullopt, c.alice_id,
                scope({StatementType::actor_register, StatementType::delegation_grant,
                       StatementType::delegation_revoke, StatementType::record_register,
                       StatementType::record_transition, StatementType::record_revoke},
                      std::vector<std::string>{certificate, delivery}, true, t0 + day));
    c.agent_id = w.register_actor(c.alice, c.alice_id, c.alice_delegation,
                                  protocol::ActorKind::agent, c.agent, c.alice_id);
    c.agent_delegation = w.grant(c.alice, c.alice_id, c.alice_delegation, c.agent_id,
                                 scope({StatementType::record_register},
                                       std::vector<std::string>{certificate}, false, t0 + day));
    c.bob_id =
        w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::person, c.bob);
    c.bob_delegation =
        w.grant(w.org(), w.org_id(), std::nullopt, c.bob_id,
                scope({StatementType::record_endorse}, std::vector<std::string>{certificate}));
    return c;
}

protocol::Statement agent_record(World& w, const Cast& c, const std::string& type) {
    auto s = w.statement(c.agent_id, c.agent_delegation, w.record_body(type));
    s.provenance = provenance();
    return s;
}

} // namespace

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
