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
#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Evidence bundles: everything needed to verify a record offline, without
/// contacting or trusting the ledger's database. See `evidence-bundle` in
/// spec/cexchain.cddl.
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
    /// Proofs against the checkpoint's state root of the complete history of
    /// every object involved (see `involved_objects`).
    std::vector<StateProof> state_proofs;

    friend bool operator==(const EvidenceBundle&, const EvidenceBundle&) = default;
};

[[nodiscard]] Result<Bytes> encode_bundle(const EvidenceBundle& bundle);
/// Verifiers refuse larger bundles: verification costs grow with the size.
inline constexpr std::size_t max_bundle_size = std::size_t{64} << 20;

[[nodiscard]] Result<EvidenceBundle> decode_bundle(ByteView encoded);

/// The ledger a bundle claims to come from (its genesis entry's id),
/// without verifying anything: to pick the ledger to pin, then verify once.
[[nodiscard]] Result<Id> bundle_ledger_id(ByteView encoded);

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
    /// Revoked as of the checkpoint (known for certain only in a complete
    /// report).
    bool revoked = false;
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
    /// The bundle proved, against the state commitment in the log, that it
    /// holds the complete history of the record and of everyone involved:
    /// nothing, such as a later revocation, was left out.
    bool complete = false;
    /// That state commitment (the last entry the checkpoint covers).
    std::optional<StateCommitment> state_commitment;
};

/// The objects whose complete history a bundle about `record` must prove:
/// the record, and for each of its events (`events`, the statements in its
/// history) the signer, an agent signer's accountable person, and every
/// delegation in the chain with its grantor. In first-seen order.
[[nodiscard]] std::vector<Id> involved_objects(const LedgerState& state, const Id& record,
                                               std::span<const Statement> events);

/// Verifies a bundle completely: every receipt against the signed checkpoint,
/// every included statement replayed under the ledger rules, every disclosed
/// field and provided attachment against the record's commitments.
///
/// If the checkpoint's last entry is a state commitment, the bundle must also
/// prove the complete history of every involved object against it, so nothing
/// can have been left out; the report then says it is complete. Without one
/// (ledgers from before state commitments), omissions cannot be ruled out.
[[nodiscard]] Result<EvidenceReport>
verify_bundle(const crypto::Provider& provider, ByteView bundle, const VerifyOptions& options = {});

} // namespace cexchain::protocol
