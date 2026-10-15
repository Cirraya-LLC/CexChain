// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/ledger.hpp>

/// A ledger fixture shared by the engine and evidence tests.
namespace cexchain::test {

namespace cbor = cexchain::cbor;
namespace crypto = cexchain::crypto;
namespace ledger = cexchain::ledger;
namespace protocol = cexchain::protocol;
using crypto::openssl::KeyPair;
using protocol::StatementType;

inline constexpr protocol::Timestamp t0 = 1'791'244'800'000; // 2026-10-06T00:00:00Z
inline constexpr protocol::Timestamp day = 86'400'000;
/// Record types of the fixture's own choosing: the generic lifecycle (registered,
/// no transitions, endorsed in any role, revocable).
inline const std::string document_type = "example.document/1";
inline const std::string note_type = "example.note/1";

inline const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

inline KeyPair key(const std::string& name) {
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
    /// Worlds with the same hash and organization name are the same ledger
    /// (same keys, same genesis).
    explicit World(crypto::HashAlg hash = crypto::HashAlg::sha256,
                   const std::string& organization = "Test Org")
        : hash_(hash), clock_(t0), entropy_(7), org_(key("org")), log_key_(key("log")) {
        protocol::Statement genesis;
        genesis.issued_at = t0;
        genesis.nonce = entropy_.bytes<16>();
        genesis.body =
            protocol::GenesisBody{hash, organization, org_.public_key(), log_key_.public_key()};
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

    protocol::Nonce nonce() { return entropy_.bytes<16>(); }

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

inline protocol::Provenance provenance() {
    return protocol::Provenance{"claude-opus-5-5", "2026-09", std::nullopt, {}};
}

inline protocol::Scope scope(std::vector<StatementType> types,
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

inline Cast build_cast(World& w) {
    Cast c;
    c.alice_id =
        w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::person, c.alice);
    c.alice_delegation =
        w.grant(w.org(), w.org_id(), std::nullopt, c.alice_id,
                scope({StatementType::actor_register, StatementType::delegation_grant,
                       StatementType::delegation_revoke, StatementType::record_register,
                       StatementType::record_transition, StatementType::record_revoke},
                      std::vector<std::string>{document_type, note_type}, true, t0 + day));
    c.agent_id = w.register_actor(c.alice, c.alice_id, c.alice_delegation,
                                  protocol::ActorKind::agent, c.agent, c.alice_id);
    c.agent_delegation = w.grant(c.alice, c.alice_id, c.alice_delegation, c.agent_id,
                                 scope({StatementType::record_register},
                                       std::vector<std::string>{document_type}, false, t0 + day));
    c.bob_id =
        w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::person, c.bob);
    c.bob_delegation =
        w.grant(w.org(), w.org_id(), std::nullopt, c.bob_id,
                scope({StatementType::record_endorse}, std::vector<std::string>{document_type}));
    return c;
}

inline protocol::Statement agent_record(World& w, const Cast& c, const std::string& type) {
    auto s = w.statement(c.agent_id, c.agent_delegation, w.record_body(type));
    s.provenance = provenance();
    return s;
}

} // namespace cexchain::test
