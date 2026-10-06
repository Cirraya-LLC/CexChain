// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/presence.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Evidence bundles: everything needed to verify a record offline, without
/// contacting or trusting the ledger's database. See `evidence-bundle` in
/// spec/cexchain-v0.1.cddl.
namespace cexchain::protocol {

inline constexpr std::uint64_t evidence_bundle_version = 1;

struct EvidenceEntry {
    /// An encoded log entry.
    Bytes entry;
    /// Its RFC 9942 receipt.
    Bytes receipt;

    friend bool operator==(const EvidenceEntry&, const EvidenceEntry&) = default;
};

struct AttachmentOpening {
    std::string name;
    Nonce salt{};

    friend bool operator==(const AttachmentOpening&, const AttachmentOpening&) = default;
};

struct EvidenceBundle {
    /// The record this bundle is about.
    Id record;
    /// Ascending log index. The first is genesis; the rest are the record's
    /// statements and every statement they depend on.
    std::vector<EvidenceEntry> entries;
    /// The signed checkpoint every receipt is anchored to.
    Bytes checkpoint;
    std::vector<Bytes> cosignatures;
    std::vector<FieldDisclosure> disclosures;
    std::vector<AttachmentOpening> attachments;

    friend bool operator==(const EvidenceBundle&, const EvidenceBundle&) = default;
};

[[nodiscard]] Result<Bytes> encode_bundle(const EvidenceBundle& bundle);
[[nodiscard]] Result<EvidenceBundle> decode_bundle(ByteView encoded);

struct VerifyOptions {
    /// If set, the bundle must come from this ledger. Verifiers learn the
    /// expected ledger out of band (for example from a QR code or a contract).
    std::optional<Id> expected_ledger;
    /// Witness keys the verifier trusts. Cosignatures by other keys are
    /// counted but not relied on.
    std::vector<crypto::PublicKey> trusted_witnesses;
    /// Attachment contents to check, by attachment name.
    std::map<std::string, Bytes> attachment_contents;
};

struct ActorSummary {
    Id id;
    /// nullopt for the organization.
    std::optional<ActorKind> kind;
    std::string name;
    std::optional<AgentProfile> agent;
    /// For agents: the accountable person's name.
    std::optional<std::string> responsible;
};

struct RecordEvent {
    std::uint64_t index = 0;
    Timestamp registered_at = 0;
    Timestamp issued_at = 0;
    StatementType type = StatementType::record_register;
    ActorSummary actor;
    /// Who authorized the actor, nearest grantor first. Empty when the
    /// organization acted itself.
    std::vector<ActorSummary> authority;
    std::optional<Provenance> provenance;
    /// Set if a person proved presence for this event (machine by default:
    /// an event without it was signed with a key, nothing more).
    std::optional<PresenceCheck> presence;
    /// Endorsement role, or "from -> to" for a transition, or the revocation
    /// reason.
    std::string detail;
};

enum class AttachmentStatus : std::uint8_t {
    verified,
    mismatch,
    not_provided,
};

struct AttachmentCheck {
    std::string name;
    std::string media_type;
    std::uint64_t size = 0;
    AttachmentStatus status = AttachmentStatus::not_provided;
};

struct EvidenceReport {
    Id ledger_id;
    std::string organization;
    crypto::HashAlg hash = crypto::HashAlg::sha256;
    Checkpoint checkpoint;
    std::size_t trusted_cosignatures = 0;
    std::size_t untrusted_cosignatures = 0;

    Id record;
    std::string record_type;
    std::string state;
    bool revoked = false;
    std::optional<cbor::Value> metadata;
    std::vector<RecordEvent> events;
    std::vector<RecordField> disclosed_fields;
    std::vector<AttachmentCheck> attachments;
};

/// Verifies a bundle completely: every receipt against the signed checkpoint,
/// every included statement replayed under the ledger rules, every disclosed
/// field and provided attachment against the record's commitments.
///
/// A bundle cannot prove that nothing was left out: a revocation registered
/// before an event, if omitted, goes unnoticed. That needs an audit of the
/// full log (or, in a later protocol version, a commitment to ledger state).
[[nodiscard]] Result<EvidenceReport>
verify_bundle(const crypto::Provider& provider, ByteView bundle, const VerifyOptions& options = {});

} // namespace cexchain::protocol
