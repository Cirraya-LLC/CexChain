// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/presence.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;

Bytes bytes_of(std::string_view text) {
    const auto view = cexchain::as_bytes(text);
    return Bytes(view.begin(), view.end());
}

Bytes sha256(ByteView data) {
    const auto digest = provider().digest(crypto::HashAlg::sha256, data);
    return Bytes(digest->bytes().begin(), digest->bytes().end());
}

void append(Bytes& to, ByteView from) {
    to.insert(to.end(), from.begin(), from.end());
}

/// Minimal DER INTEGER for a big-endian unsigned value.
Bytes der_integer(ByteView value) {
    std::size_t start = 0;
    while (start + 1 < value.size() && value[start] == 0) {
        ++start;
    }
    Bytes body(value.begin() + static_cast<std::ptrdiff_t>(start), value.end());
    if ((body[0] & 0x80U) != 0) {
        body.insert(body.begin(), 0x00);
    }
    Bytes out{0x02, static_cast<std::uint8_t>(body.size())};
    append(out, body);
    return out;
}

Bytes der_signature(ByteView raw) {
    Bytes inner = der_integer(raw.first(32));
    append(inner, der_integer(raw.subspan(32)));
    Bytes out{0x30, static_cast<std::uint8_t>(inner.size())};
    append(out, inner);
    return out;
}

/// s -> n - s for P-256: the other valid signature, which real authenticators
/// may produce.
Bytes high_s(ByteView raw) {
    static const Bytes n =
        *cexchain::from_hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    Bytes out(raw.begin(), raw.end());
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        int d = n[static_cast<std::size_t>(i)] - raw[32 + static_cast<std::size_t>(i)] - borrow;
        borrow = d < 0 ? 1 : 0;
        out[32 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(d + (borrow << 8));
    }
    return out;
}

/// A software stand-in for a passkey authenticator.
struct Authenticator {
    std::shared_ptr<const KeyPair> key;
    Bytes credential_id;
    std::string rp_id = "localhost";
    std::string origin = "http://localhost:43210";
    std::uint8_t flags = 0x05; // user present, user verified
    bool use_high_s = false;

    protocol::PresenceCredential credential() const {
        return {rp_id, credential_id, key->public_key(), std::string("test passkey")};
    }

    Bytes authenticator_data() const {
        Bytes data = sha256(cexchain::as_bytes(rp_id));
        data.push_back(flags);
        append(data, Bytes{0, 0, 0, 7});
        return data;
    }

    protocol::PresenceProof sign(ByteView challenge, std::string_view type = "webauthn.get",
                                 std::string_view tail = ",\"crossOrigin\":false}") const {
        const Bytes data = authenticator_data();
        const std::string client = "{\"type\":\"" + std::string(type) + "\",\"challenge\":\"" +
                                   cexchain::to_base64url(challenge) + "\",\"origin\":\"" + origin +
                                   "\"" + std::string(tail);
        Bytes message = data;
        append(message, sha256(cexchain::as_bytes(client)));
        Bytes signature = *key->sign(message);
        if (key->algorithm() == crypto::SigAlg::esp256) {
            signature = der_signature(use_high_s ? high_s(signature) : signature);
        }
        return {credential_id, data, bytes_of(client), signature};
    }
};

protocol::Scope scope_of(std::vector<StatementType> types) {
    protocol::Scope scope;
    scope.statement_types = std::move(types);
    return scope;
}

/// The challenge a passkey signs for `s`, signed by `signer`.
Bytes challenge_for(World& w, const protocol::Statement& s, const KeyPair& signer) {
    return *protocol::presence_challenge(
        provider(), w.hash(), s, *protocol::key_id(provider(), w.hash(), signer.public_key()));
}

Authenticator authenticator(crypto::SigAlg alg, std::uint8_t id) {
    auto key = KeyPair::generate(alg);
    REQUIRE(key);
    return Authenticator{std::make_shared<const KeyPair>(std::move(*key)), Bytes(16, id)};
}

/// A ledger with a person, Alice, whose passkey the organization registered.
struct Fixture {
    World w;
    KeyPair alice_key = key("alice");
    protocol::Id alice;
    Authenticator passkey = authenticator(crypto::SigAlg::esp256, 1);
    protocol::Id record;

    Fixture() {
        alice = w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::person,
                                 alice_key);
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                                  protocol::ActorSetPresenceBody{alice, {passkey.credential()}}));
        record = w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body(certificate)));
    }

    protocol::Id grant(bool require_presence) {
        protocol::Scope scope =
            scope_of({StatementType::record_endorse, StatementType::record_transition});
        scope.require_presence = require_presence;
        return w.grant(w.org(), w.org_id(), std::nullopt, alice, scope);
    }

    /// Alice's statement, with a presence proof from `with` if given.
    protocol::Statement by_alice(const protocol::Id& delegation, protocol::Body body,
                                 const Authenticator* with = nullptr) {
        auto s = w.statement(alice, delegation, std::move(body));
        if (with != nullptr) {
            s.presence = with->sign(challenge_for(w, s, alice_key));
        }
        return s;
    }
};

} // namespace

TEST_CASE("a person proves presence for exactly one statement", "[presence]") {
    Fixture f;
    const auto delegation = f.grant(true);
    const protocol::RecordEndorseBody endorse{f.record, "inspector"};

    // The delegation requires presence: a key alone is not enough.
    CHECK(f.w.rejected(f.alice_key, f.by_alice(delegation, endorse)) == Errc::rejected);
    const auto id = f.w.ok(f.alice_key, f.by_alice(delegation, endorse, &f.passkey));
    CHECK(f.w.ledger().state().statement_index(id).has_value());

    // A proof for one statement does not carry over to another.
    auto moved = f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "approver"});
    moved.presence =
        f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "approver"}, &f.passkey)
            .presence;
    CHECK(f.w.rejected(f.alice_key, moved) == Errc::verification_failed);
}

TEST_CASE("forged or misused passkey responses are refused", "[presence]") {
    Fixture f;
    const auto delegation = f.grant(false);
    const protocol::RecordEndorseBody endorse{f.record, "inspector"};
    auto refused = [&](const Authenticator& a) {
        return f.w.rejected(f.alice_key, f.by_alice(delegation, endorse, &a));
    };

    SECTION("another site's origin") {
        auto a = f.passkey;
        a.origin = "https://evil.example";
        CHECK(refused(a) == Errc::verification_failed);
    }
    SECTION("a cross-origin frame") {
        auto a = f.passkey;
        auto s = f.by_alice(delegation, endorse);
        s.presence =
            a.sign(challenge_for(f.w, s, f.alice_key), "webauthn.get", ",\"crossOrigin\":true}");
        CHECK(f.w.rejected(f.alice_key, s) == Errc::verification_failed);
    }
    SECTION("a registration response instead of an assertion") {
        auto s = f.by_alice(delegation, endorse);
        s.presence = f.passkey.sign(challenge_for(f.w, s, f.alice_key), "webauthn.create");
        CHECK(f.w.rejected(f.alice_key, s) == Errc::verification_failed);
    }
    SECTION("another relying party") {
        auto a = f.passkey;
        a.rp_id = "example.com";
        a.origin = "https://example.com";
        CHECK(refused(a) == Errc::verification_failed);
    }
    SECTION("no user presence flag") {
        auto a = f.passkey;
        a.flags = 0x04;
        CHECK(refused(a) == Errc::verification_failed);
    }
    SECTION("a passkey that is not registered") {
        CHECK(refused(authenticator(crypto::SigAlg::esp256, 9)) == Errc::verification_failed);
    }
    SECTION("someone else's key under the registered credential id") {
        auto a = authenticator(crypto::SigAlg::esp256, 1);
        CHECK(refused(a) == Errc::verification_failed);
    }
    SECTION("an altered signature") {
        auto s = f.by_alice(delegation, endorse, &f.passkey);
        s.presence->signature[10] ^= 1;
        CHECK(f.w.rejected(f.alice_key, s) != Errc{});
    }
}

TEST_CASE("what real authenticators send is accepted", "[presence]") {
    Fixture f;
    const auto delegation = f.grant(false);

    SECTION("ES256 with high S") {
        auto a = f.passkey;
        a.use_high_s = true;
        f.w.ok(f.alice_key,
               f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "inspector"}, &a));
    }
    SECTION("no crossOrigin member, and extra members after it") {
        auto s = f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "inspector"});
        s.presence = f.passkey.sign(challenge_for(f.w, s, f.alice_key), "webauthn.get", "}");
        f.w.ok(f.alice_key, s);
        auto t = f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "approver"});
        t.presence =
            f.passkey.sign(challenge_for(f.w, t, f.alice_key), "webauthn.get",
                           ",\"crossOrigin\":false,\"other_keys_can_be_added_here\":\"x\"}");
        f.w.ok(f.alice_key, t);
    }
    SECTION("presence without user verification is still presence") {
        auto a = f.passkey;
        a.flags = 0x01;
        auto s = f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "inspector"}, &a);
        const auto check = protocol::verify_presence(
            provider(), f.w.hash(), s,
            *protocol::key_id(provider(), f.w.hash(), f.alice_key.public_key()),
            std::vector{a.credential()});
        REQUIRE(check);
        CHECK_FALSE(check->user_verified);
        CHECK(check->origin == "http://localhost:43210");
        f.w.ok(f.alice_key, s);
    }
    SECTION("Ed25519 passkeys") {
        auto ed = authenticator(crypto::SigAlg::ed25519, 2);
        f.w.ok(f.w.org(),
               f.w.statement(f.w.org_id(), std::nullopt,
                             protocol::ActorSetPresenceBody{f.alice, {ed.credential()}}));
        f.w.ok(f.alice_key,
               f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "inspector"}, &ed));
    }
}

TEST_CASE("who may register passkeys, and for whom", "[presence]") {
    Fixture f;
    auto second = authenticator(crypto::SigAlg::esp256, 2);
    const protocol::ActorSetPresenceBody both{f.alice,
                                              {f.passkey.credential(), second.credential()}};

    // A stolen signing key alone cannot enroll the thief's passkey...
    CHECK(f.w.rejected(f.alice_key, f.w.statement(f.alice, std::nullopt, both)) == Errc::rejected);
    // ...but Alice, proving presence with her registered passkey, can add one.
    auto self = f.w.statement(f.alice, std::nullopt, both);
    self.presence = f.passkey.sign(challenge_for(f.w, self, f.alice_key));
    f.w.ok(f.alice_key, self);
    CHECK(f.w.ledger().state().actor(f.alice)->presence.size() == 2);

    // Only people have passkeys, and only people prove presence.
    const auto agent_key = key("agent");
    const auto agent = f.w.register_actor(f.w.org(), f.w.org_id(), std::nullopt,
                                          protocol::ActorKind::agent, agent_key, f.alice);
    CHECK(f.w.rejected(f.w.org(), f.w.statement(f.w.org_id(), std::nullopt,
                                                protocol::ActorSetPresenceBody{
                                                    agent, {second.credential()}})) ==
          Errc::rejected);
    protocol::Scope scope = scope_of({StatementType::record_register});
    const auto delegation = f.w.grant(f.w.org(), f.w.org_id(), std::nullopt, agent, scope);
    auto by_agent = f.w.statement(agent, delegation, f.w.record_body(certificate));
    by_agent.provenance = provenance();
    by_agent.presence = f.passkey.sign(challenge_for(f.w, by_agent, agent_key));
    CHECK(f.w.rejected(agent_key, by_agent) == Errc::rejected);
}

TEST_CASE("a presence requirement survives delegation", "[presence]") {
    Fixture f;
    protocol::Scope scope =
        scope_of({StatementType::delegation_grant, StatementType::record_endorse});
    scope.may_delegate = true;
    scope.require_presence = true;
    const auto delegation = f.w.grant(f.w.org(), f.w.org_id(), std::nullopt, f.alice, scope);
    const auto bob_key = key("bob");
    const auto bob = f.w.register_actor(f.w.org(), f.w.org_id(), std::nullopt,
                                        protocol::ActorKind::person, bob_key);

    protocol::Scope looser = scope_of({StatementType::record_endorse});
    CHECK(
        f.w.rejected(f.alice_key, f.by_alice(delegation, protocol::DelegationGrantBody{bob, looser},
                                             &f.passkey)) == Errc::rejected);
    looser.require_presence = true;
    f.w.ok(f.alice_key,
           f.by_alice(delegation, protocol::DelegationGrantBody{bob, looser}, &f.passkey));
}

TEST_CASE("evidence shows who was present", "[presence][evidence]") {
    Fixture f;
    const auto delegation = f.grant(false);
    f.w.ok(f.alice_key,
           f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "inspector"}, &f.passkey));
    f.w.ok(f.alice_key, f.by_alice(delegation, protocol::RecordEndorseBody{f.record, "approver"}));
    REQUIRE(f.w.ledger().checkpoint(f.w.log_key()));
    const auto bundle = f.w.ledger().export_evidence(f.w.log_key(), f.record);
    REQUIRE(bundle);
    // The bundle carries Alice's passkey registration, or her presence could
    // not be checked offline.
    const auto report = protocol::verify_bundle(provider(), *protocol::encode_bundle(*bundle));
    REQUIRE(report);
    REQUIRE(report->events.size() == 3);
    CHECK_FALSE(report->events[0].presence); // registered by the organization
    REQUIRE(report->events[1].presence);
    CHECK(report->events[1].presence->user_verified);
    CHECK(report->events[1].presence->rp_id == "localhost");
    CHECK_FALSE(report->events[2].presence);
}

TEST_CASE("passkey registrations become credentials", "[presence]") {
    const Bytes challenge(32, 0x5a);
    auto attestation = [&](const Authenticator& a, std::uint8_t flags,
                           const cbor::Value& cose_key) {
        Bytes data = sha256(cexchain::as_bytes(a.rp_id));
        data.push_back(flags);
        append(data, Bytes{0, 0, 0, 0});
        append(data, Bytes(16, 0)); // AAGUID
        data.push_back(0);
        data.push_back(static_cast<std::uint8_t>(a.credential_id.size()));
        append(data, a.credential_id);
        append(data, *cbor::encode(cose_key));
        return *cbor::encode(
            cbor::Value::map({{cbor::Value::text("fmt"), cbor::Value::text("none")},
                              {cbor::Value::text("attStmt"), cbor::Value::map({})},
                              {cbor::Value::text("authData"), cbor::Value::bytes(data)}}));
    };
    auto client = [&](const Authenticator& a, std::string_view type, ByteView c) {
        return bytes_of("{\"type\":\"" + std::string(type) + "\",\"challenge\":\"" +
                        cexchain::to_base64url(c) + "\",\"origin\":\"" + a.origin +
                        "\",\"crossOrigin\":false}");
    };
    auto ec2 = [](const crypto::PublicKey& key, std::int64_t alg) {
        const ByteView point = key.bytes;
        return cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::integer(2)},
             {cbor::Value::integer(3), cbor::Value::integer(alg)},
             {cbor::Value::integer(-1), cbor::Value::integer(1)},
             {cbor::Value::integer(-2), cbor::Value::bytes(point.subspan(1, 32))},
             {cbor::Value::integer(-3), cbor::Value::bytes(point.subspan(33, 32))}});
    };
    auto okp = [](const crypto::PublicKey& key) {
        return cbor::Value::map({{cbor::Value::integer(1), cbor::Value::integer(1)},
                                 {cbor::Value::integer(3), cbor::Value::integer(-8)},
                                 {cbor::Value::integer(-1), cbor::Value::integer(6)},
                                 {cbor::Value::integer(-2), cbor::Value::bytes(key.bytes)}});
    };

    const auto es = authenticator(crypto::SigAlg::esp256, 3);
    const auto made = protocol::credential_from_registration(
        provider(), attestation(es, 0x45, ec2(es.key->public_key(), -7)),
        client(es, "webauthn.create", challenge), challenge, "localhost", std::string("laptop"));
    REQUIRE(made);
    CHECK(*made == protocol::PresenceCredential{"localhost", es.credential_id, es.key->public_key(),
                                                "laptop"});

    const auto ed = authenticator(crypto::SigAlg::ed25519, 4);
    const auto made_ed = protocol::credential_from_registration(
        provider(), attestation(ed, 0x45, okp(ed.key->public_key())),
        client(ed, "webauthn.create", challenge), challenge, "localhost", std::nullopt);
    REQUIRE(made_ed);
    CHECK(made_ed->key == ed.key->public_key());

    const auto good = attestation(es, 0x45, ec2(es.key->public_key(), -7));
    const auto good_client = client(es, "webauthn.create", challenge);
    CHECK_FALSE(protocol::credential_from_registration(provider(), good, good_client, Bytes(32, 1),
                                                       "localhost", {}));
    CHECK_FALSE(protocol::credential_from_registration(provider(), good, good_client, challenge,
                                                       "example.com", {}));
    CHECK_FALSE(protocol::credential_from_registration(
        provider(), good, client(es, "webauthn.get", challenge), challenge, "localhost", {}));
    CHECK_FALSE(protocol::credential_from_registration(
        provider(), attestation(es, 0x41 | 0x80, ec2(es.key->public_key(), -7)), good_client,
        challenge, "localhost", {}));
    CHECK_FALSE(protocol::credential_from_registration(
        provider(), attestation(es, 0x05, ec2(es.key->public_key(), -7)), good_client, challenge,
        "localhost", {}));
    CHECK(protocol::credential_from_registration(
              provider(), attestation(es, 0x45, ec2(es.key->public_key(), -257)), good_client,
              challenge, "localhost", {})
              .error()
              .code == Errc::unsupported);
}

TEST_CASE("origins and relying parties", "[presence]") {
    using protocol::origin_matches_rp_id;
    CHECK(origin_matches_rp_id("http://localhost:8080", "localhost"));
    CHECK(origin_matches_rp_id("http://localhost", "localhost"));
    CHECK(origin_matches_rp_id("https://example.com", "example.com"));
    CHECK(origin_matches_rp_id("https://login.example.com:8443", "example.com"));
    CHECK_FALSE(origin_matches_rp_id("http://example.com", "example.com"));
    CHECK_FALSE(origin_matches_rp_id("https://badexample.com", "example.com"));
    CHECK_FALSE(origin_matches_rp_id("https://example.com.evil.net", "example.com"));
    CHECK_FALSE(origin_matches_rp_id("https://example.com:80x", "example.com"));
    CHECK_FALSE(origin_matches_rp_id("http://localhost.evil.net", "localhost"));
    CHECK_FALSE(origin_matches_rp_id("http://localhost:8080/path", "localhost"));
    CHECK_FALSE(origin_matches_rp_id("https://example.com", ""));
}

TEST_CASE("presence material round-trips through the codec", "[presence]") {
    const auto a = authenticator(crypto::SigAlg::esp256, 5);
    const auto encoded = protocol::encode_presence_credential(a.credential());
    REQUIRE(encoded);
    CHECK(*protocol::decode_presence_credential(*encoded) == a.credential());

    World w;
    auto s = w.statement(w.org_id(), std::nullopt,
                         protocol::ActorSetPresenceBody{w.org_id(), {a.credential()}});
    s.presence = a.sign(challenge_for(w, s, w.org()));
    const auto payload = protocol::encode_payload(s);
    REQUIRE(payload);
    CHECK(*protocol::decode_payload(*payload) == s);

    protocol::Scope scope = scope_of({StatementType::record_endorse});
    scope.require_presence = true;
    auto grant =
        w.statement(w.org_id(), std::nullopt, protocol::DelegationGrantBody{w.org_id(), scope});
    CHECK(*protocol::decode_payload(*protocol::encode_payload(grant)) == grant);

    CHECK(cexchain::from_base64url(cexchain::to_base64url(Bytes{0xfb, 0xff, 0x01})) ==
          Bytes{0xfb, 0xff, 0x01});
    CHECK(cexchain::to_base64url(Bytes{0xfb, 0xff}) == "-_8");
    CHECK_FALSE(cexchain::from_base64url("-_9")); // nonzero trailing bits
    CHECK_FALSE(cexchain::from_base64url("abc="));
    CHECK_FALSE(cexchain::from_base64url("a"));
}

TEST_CASE("a proof of presence cannot be replayed under a rotated key", "[presence][security]") {
    // A thief has Alice's signing key but not her passkey. Alice once added a
    // second passkey herself; the organization later removed it.
    Fixture f;
    auto second = authenticator(crypto::SigAlg::esp256, 2);
    const protocol::ActorSetPresenceBody both{f.alice,
                                              {f.passkey.credential(), second.credential()}};
    auto added = f.w.statement(f.alice, std::nullopt, both);
    added.presence = f.passkey.sign(*protocol::presence_challenge(
        provider(), f.w.hash(), added,
        *protocol::key_id(provider(), f.w.hash(), f.alice_key.public_key())));
    f.w.ok(f.alice_key, added);
    f.w.ok(f.w.org(),
           f.w.statement(f.w.org_id(), std::nullopt,
                         protocol::ActorSetPresenceBody{f.alice, {f.passkey.credential()}}));

    // Self-rotation needs presence once Alice has passkeys...
    const auto thief_key = key("thief");
    const auto rotate = f.w.statement(
        f.alice, std::nullopt, protocol::ActorRotateKeyBody{f.alice, thief_key.public_key()});
    CHECK(f.w.rejected(f.alice_key, rotate) == Errc::rejected);
    // ...and even after an organization-approved rotation to a key the thief
    // holds, re-signing Alice's old statement does not bring the passkey back.
    f.w.ok(f.w.org(), f.w.statement(f.w.org_id(), std::nullopt,
                                    protocol::ActorRotateKeyBody{f.alice, thief_key.public_key()}));
    CHECK(f.w.rejected(thief_key, added) != Errc{});
    CHECK(f.w.ledger().state().actor(f.alice)->presence.size() == 1);
}
