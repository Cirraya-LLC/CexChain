// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/record.hpp>

#include "support/ledger_world.hpp"

using namespace cexchain::test;
using cexchain::as_bytes;
using cexchain::Bytes;
using cexchain::Errc;

namespace {

/// A document registered by the agent, endorsed by bob in three roles,
/// checkpointed, and cosigned by a witness.
struct Scenario {
    World w;
    Cast c = build_cast(w);
    KeyPair witness = key("witness");
    protocol::FieldCommitment fields;
    protocol::Nonce attachment_salt{};
    Bytes attachment = Bytes(as_bytes("%PDF-1.7 inspection report").begin(),
                             as_bytes("%PDF-1.7 inspection report").end());
    protocol::Id record;
    protocol::Id unrelated;

    Scenario() {
        std::vector<protocol::RecordField> values = {
            {"product", w.nonce(), cbor::Value::text("Flange DN50")},
            {"batch", w.nonce(), cbor::Value::text("B-2026-1006")},
            {"result", w.nonce(), cbor::Value::text("pass")},
        };
        fields = *protocol::commit_fields(provider(), w.hash(), values);
        attachment_salt = w.nonce();
        const auto commitment =
            protocol::attachment_commitment(provider(), w.hash(), attachment_salt, attachment);
        REQUIRE(commitment);

        protocol::RecordRegisterBody body{
            document_type,
            Bytes(fields.root.bytes().begin(), fields.root.bytes().end()),
            fields.leaves.size(),
            {protocol::Attachment{"report.pdf", "application/pdf", attachment.size(),
                                  Bytes(commitment->bytes().begin(), commitment->bytes().end())}},
            cbor::Value::map({{cbor::Value::text("product"), cbor::Value::text("Flange DN50")}})};
        auto s = w.statement(c.agent_id, c.agent_delegation, body);
        s.provenance = provenance();
        record = w.ok(c.agent, s);

        // An unrelated record, which the bundle must not include.
        unrelated = w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body("other/1")));

        w.ok(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                protocol::RecordEndorseBody{record, "inspector"}));
        w.ok(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                protocol::RecordEndorseBody{record, "approver"}));
        w.ok(c.bob, w.statement(c.bob_id, c.bob_delegation,
                                protocol::RecordEndorseBody{record, "witness"}));
        REQUIRE(w.ledger().checkpoint(w.log_key()));
    }

    protocol::EvidenceBundle bundle() {
        auto exported = w.ledger().export_evidence(w.log_key(), record);
        REQUIRE(exported);
        auto cosignature = protocol::cosign_checkpoint(witness, provider(),
                                                       w.ledger().latest_checkpoint()->checkpoint);
        REQUIRE(cosignature);
        exported->cosignatures.push_back(cosignature->encoded);
        exported->disclosures.push_back(
            *protocol::disclose_field(provider(), w.hash(), fields, "result"));
        exported->attachments.push_back(protocol::AttachmentOpening{"report.pdf", attachment_salt});
        return *exported;
    }

    protocol::VerifyOptions options() {
        protocol::VerifyOptions o;
        o.expected_ledger = w.ledger().id();
        o.trusted_witnesses.push_back(witness.public_key());
        o.attachment_contents["report.pdf"] = attachment;
        return o;
    }
};

Bytes encode(const protocol::EvidenceBundle& bundle) {
    auto bytes = protocol::encode_bundle(bundle);
    REQUIRE(bytes);
    return *bytes;
}

Errc verify_error(const protocol::EvidenceBundle& bundle, const protocol::VerifyOptions& options) {
    const auto report = protocol::verify_bundle(provider(), encode(bundle), options);
    REQUIRE_FALSE(report);
    return report.error().code;
}

} // namespace

TEST_CASE("an evidence bundle verifies offline into a full report", "[evidence]") {
    Scenario s;
    const protocol::EvidenceBundle bundle = s.bundle();
    const Bytes bytes = encode(bundle);

    const auto decoded = protocol::decode_bundle(bytes);
    REQUIRE(decoded);
    CHECK(*decoded == bundle);

    const auto report = protocol::verify_bundle(provider(), bytes, s.options());
    INFO((report.has_value() ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    CHECK(report->organization == "Test Org");
    CHECK(report->ledger_id == s.w.ledger().id());
    CHECK(report->record_type == document_type);
    CHECK(report->state == "registered");
    CHECK_FALSE(report->revoked);
    CHECK(report->trusted_cosignatures == 1);
    CHECK(report->untrusted_cosignatures == 0);

    REQUIRE(report->events.size() == 4);
    const protocol::RecordEvent& issued = report->events[0];
    CHECK(issued.type == StatementType::record_register);
    CHECK(issued.actor.kind == protocol::ActorKind::agent);
    CHECK(issued.actor.responsible == "actor");
    REQUIRE(issued.provenance);
    CHECK(issued.provenance->model == "claude-opus-5-5");
    REQUIRE(issued.authority.size() == 2); // alice, then the organization
    CHECK(issued.authority[0].id == s.c.alice_id);
    CHECK_FALSE(issued.authority[1].kind.has_value());
    CHECK(report->events[1].type == StatementType::record_endorse);
    CHECK(report->events[1].detail == "inspector");
    CHECK(report->events[2].detail == "approver");
    CHECK(report->events[3].detail == "witness");

    REQUIRE(report->disclosed_fields.size() == 1);
    CHECK(report->disclosed_fields[0].name == "result");
    CHECK(*report->disclosed_fields[0].value.as_text() == "pass");
    REQUIRE(report->attachments.size() == 1);
    CHECK(report->attachments[0].status == protocol::AttachmentStatus::verified);

    // The bundle carries what the record depends on, and nothing unrelated.
    for (const auto& e : bundle.entries) {
        CHECK(protocol::decode_log_entry(e.entry)->statement_id != s.unrelated);
    }
}

TEST_CASE("a mechanism type's transition shows in its evidence", "[evidence]") {
    // An access request, withdrawn: record-transition stays for the
    // protocol's own types.
    World w;
    const protocol::Id request =
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                                  w.record_body(std::string(protocol::access_request_type))));
    w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                              protocol::RecordTransitionBody{request, "requested", "withdrawn"}));
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    const auto exported = w.ledger().export_evidence(w.log_key(), request);
    REQUIRE(exported);
    protocol::VerifyOptions options;
    options.expected_ledger = w.ledger().id();
    const auto report = protocol::verify_bundle(provider(), encode(*exported), options);
    REQUIRE(report);
    CHECK(report->state == "withdrawn");
    REQUIRE(report->events.size() == 2);
    CHECK(report->events[1].type == StatementType::record_transition);
    CHECK(report->events[1].detail == "requested -> withdrawn");
}

TEST_CASE("evidence verification catches tampering and omissions", "[evidence]") {
    Scenario s;
    const protocol::EvidenceBundle good = s.bundle();
    const protocol::VerifyOptions options = s.options();
    REQUIRE(protocol::verify_bundle(provider(), encode(good), options));

    SECTION("any altered entry") {
        for (std::size_t i = 0; i < good.entries.size(); ++i) {
            auto bad = good;
            bad.entries[i].entry[bad.entries[i].entry.size() / 2] ^= 1;
            CHECK_FALSE(protocol::verify_bundle(provider(), encode(bad), options));
        }
    }
    SECTION("a missing dependency") {
        // Drop the delegation that authorized the agent (granted by alice).
        auto bad = good;
        const auto agent_grant = std::ranges::find_if(bad.entries, [&](const auto& e) {
            return protocol::decode_log_entry(e.entry)->statement_id == s.c.agent_delegation;
        });
        REQUIRE(agent_grant != bad.entries.end());
        bad.entries.erase(agent_grant);
        CHECK(verify_error(bad, options) == Errc::verification_failed);
    }
    SECTION("entries out of order") {
        auto bad = good;
        std::swap(bad.entries[1], bad.entries[2]);
        CHECK(verify_error(bad, options) == Errc::verification_failed);
    }
    SECTION("a different ledger") {
        auto other = options;
        other.expected_ledger = s.c.alice_id;
        CHECK(verify_error(good, other) == Errc::verification_failed);
    }
    SECTION("a forged disclosure") {
        auto bad = good;
        auto field = *protocol::decode_field(bad.disclosures[0].leaf);
        field.value = cbor::Value::text("fail");
        bad.disclosures[0].leaf = *protocol::encode_field(field);
        CHECK(verify_error(bad, options) == Errc::verification_failed);
    }
    SECTION("a mismatched attachment is reported, not hidden") {
        auto other = options;
        other.attachment_contents["report.pdf"] = Bytes{'x'};
        const auto report = protocol::verify_bundle(provider(), encode(good), other);
        REQUIRE(report);
        CHECK(report->attachments[0].status == protocol::AttachmentStatus::mismatch);
        other.attachment_contents.clear();
        CHECK(protocol::verify_bundle(provider(), encode(good), other)->attachments[0].status ==
              protocol::AttachmentStatus::not_provided);
    }
    SECTION("cosignatures by unknown witnesses are only counted") {
        auto other = options;
        other.trusted_witnesses.clear();
        const auto report = protocol::verify_bundle(provider(), encode(good), other);
        REQUIRE(report);
        CHECK(report->trusted_cosignatures == 0);
        CHECK(report->untrusted_cosignatures == 1);
    }
    SECTION("a witness counts once, however many cosignatures it gave") {
        auto repeated = good;
        repeated.cosignatures.push_back(good.cosignatures.front());
        const auto checkpoint = protocol::parse_checkpoint(good.checkpoint);
        // Ed25519 is deterministic, so a second distinct cosignature needs a
        // randomized scheme: re-key the witness with ECDSA.
        const auto ecdsa = crypto::openssl::KeyPair::generate(crypto::SigAlg::esp256);
        REQUIRE(ecdsa);
        auto twice = good;
        twice.cosignatures = {
            protocol::cosign_checkpoint(*ecdsa, provider(), checkpoint->checkpoint)->encoded,
            protocol::cosign_checkpoint(*ecdsa, provider(), checkpoint->checkpoint)->encoded};
        REQUIRE(twice.cosignatures[0] != twice.cosignatures[1]);
        auto with_ecdsa = options;
        with_ecdsa.trusted_witnesses = {ecdsa->public_key(), ecdsa->public_key()};

        const auto report = protocol::verify_bundle(provider(), encode(repeated), options);
        REQUIRE(report);
        CHECK(report->trusted_cosignatures == 1);
        const auto twice_report = protocol::verify_bundle(provider(), encode(twice), with_ecdsa);
        REQUIRE(twice_report);
        CHECK(twice_report->trusted_cosignatures == 1);
        CHECK(twice_report->untrusted_cosignatures == 0);
    }
    SECTION("a checkpoint that does not match the receipts") {
        // A newer checkpoint than the one the receipts were issued against.
        s.w.ok(s.w.org(), s.w.statement(s.w.org_id(), std::nullopt, s.w.record_body("other/1")));
        auto newer = s.w.ledger().checkpoint(s.w.log_key());
        REQUIRE(newer);
        auto bad = good;
        bad.checkpoint = newer->encoded;
        bad.cosignatures.clear();
        CHECK(verify_error(bad, options) == Errc::verification_failed);
    }
    SECTION("a checkpoint signed by another key") {
        auto bad = good;
        const auto checkpoint = protocol::parse_checkpoint(good.checkpoint);
        bad.checkpoint =
            protocol::sign_checkpoint(s.witness, provider(), checkpoint->checkpoint)->encoded;
        CHECK(verify_error(bad, options) == Errc::verification_failed);
    }
}

TEST_CASE("export needs a checkpoint covering the record", "[evidence]") {
    World w;
    Cast c = build_cast(w);
    const protocol::Id record = w.ok(c.agent, agent_record(w, c, document_type));
    CHECK(w.ledger().export_evidence(w.log_key(), record).error().code == Errc::not_found);
    REQUIRE(w.ledger().checkpoint(w.log_key()));
    CHECK(w.ledger().export_evidence(w.log_key(), record));
    CHECK(w.ledger().export_evidence(w.org(), record).error().code == Errc::invalid_argument);
    CHECK(w.ledger().export_evidence(w.log_key(), c.alice_id).error().code == Errc::not_found);
}
