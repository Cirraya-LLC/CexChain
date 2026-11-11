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
#include <cexchain/core/protocol/claims.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/memberships.hpp>
#include <cexchain/core/protocol/network.hpp>
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

/// A checkpoint at or before the bundle's, with time-stamp tokens over its
/// payload (v0.11): a time-stamp authority's word on when the entries below
/// its size existed.
struct Anchor {
    /// The signed checkpoint.
    Bytes checkpoint;
    /// RFC 3161 TimeStampTokens (DER) whose message imprint is the ledger's
    /// hash of the checkpoint's payload, the bytes witnesses cosign.
    std::vector<Bytes> timestamps;
    /// The RFC 9162 consistency proof from its size to the size of the
    /// bundle's checkpoint; empty when the two are the same checkpoint.
    std::vector<crypto::Digest> consistency;
    /// Open-network witnesses' cosignatures of the checkpoint's note (v0.13;
    /// spec section 10.2). An anchor holds tokens, these, or both.
    std::vector<network::NoteSignature> network_cosignatures;

    friend bool operator==(const Anchor&, const Anchor&) = default;
};

/// How much later than a trusted time-stamp authority's time (plus the
/// accuracy it states) the ledger may date what that authority saw: the
/// ledger's clock and the authority's may disagree by this much (v0.11).
inline constexpr Timestamp timestamp_clock_slack = 60'000;

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
    /// Time-stamped checkpoints at or before `checkpoint` (v0.11).
    std::vector<Anchor> anchors;
    /// Membership proofs (v0.16): encoded bundles of memberships, on trust
    /// nodes' ledgers, that name this bundle's ledger; at most 16.
    std::vector<Bytes> memberships;

    friend bool operator==(const EvidenceBundle&, const EvidenceBundle&) = default;
};

[[nodiscard]] Result<Bytes> encode_bundle(const EvidenceBundle& bundle);
/// Verifiers refuse larger bundles: verification costs grow with the size.
inline constexpr std::size_t max_bundle_size = std::size_t{64} << 20;

[[nodiscard]] Result<EvidenceBundle> decode_bundle(ByteView encoded);

/// The ledger a bundle claims to come from (its genesis entry's id),
/// without verifying anything: to pick the ledger to pin, then verify once.
[[nodiscard]] Result<Id> bundle_ledger_id(ByteView encoded);

/// Signature checks made ahead of time (say, on other threads) or remembered
/// from earlier verifications. A verification given one asks it before each
/// signature it would check, and takes its answer instead of checking: an
/// answer must be what `crypto::Provider::verify` returns for exactly that
/// algorithm, key, message, and signature, all compared byte for byte (a
/// signature check is a function of these four alone). One shared by
/// verifications that run at once must be safe to call from their threads.
class SignatureChecks {
public:
    virtual ~SignatureChecks() = default;
    /// The outcome of checking `signature` over `message` with `key`, if this
    /// knows it. Asked only with a well-formed key and signature (see
    /// `crypto::Provider::verify`).
    [[nodiscard]] virtual std::optional<Status> find(const crypto::PublicKey& key, ByteView message,
                                                     ByteView signature) = 0;
    /// Told each signature the verification checked itself, and the outcome.
    virtual void checked(const crypto::PublicKey& key, ByteView message, ByteView signature,
                         const Status& outcome) = 0;

protected:
    SignatureChecks() = default;
    SignatureChecks(const SignatureChecks&) = default;
    SignatureChecks(SignatureChecks&&) = default;
    SignatureChecks& operator=(const SignatureChecks&) = default;
    SignatureChecks& operator=(SignatureChecks&&) = default;
};

/// A provider that asks `checks` before checking a signature with `provider`
/// and tells it every outcome it checked; hashing is `provider`'s. Keys and
/// signatures `crypto::Provider::verify` refuses unseen are refused as
/// before, without asking.
class CheckedProvider final : public crypto::Provider {
public:
    CheckedProvider(const crypto::Provider& provider, SignatureChecks& checks) noexcept
        : provider_(provider), checks_(checks) {}

    [[nodiscard]] bool supports(crypto::HashAlg alg) const noexcept override {
        return provider_.supports(alg);
    }
    [[nodiscard]] bool supports(crypto::SigAlg alg) const noexcept override {
        return provider_.supports(alg);
    }

private:
    [[nodiscard]] Result<crypto::Digest> do_digest(crypto::HashAlg alg,
                                                   std::span<const ByteView> parts) const override;
    [[nodiscard]] Status do_verify(const crypto::PublicKey& key, ByteView message,
                                   ByteView signature) const override;
    [[nodiscard]] Result<crypto::TimestampToken>
    do_read_timestamp(ByteView token, std::span<const Bytes> trusted_roots) const override;

    const crypto::Provider& provider_;
    SignatureChecks& checks_;
};

/// A trust node the verifier believes (v0.16): its ledger, and the name the
/// verifier gives it, which reports use (never one the evidence gives).
struct TrustNode {
    Id ledger;
    std::string name;

    friend bool operator==(const TrustNode&, const TrustNode&) = default;
};

struct VerifyOptions {
    /// If set, the bundle must come from this ledger. Verifiers learn the
    /// expected ledger out of band (for example from a QR code or a contract).
    std::optional<Id> expected_ledger;
    /// Witness keys the verifier trusts. Cosignatures by other keys are
    /// counted but not relied on.
    std::vector<crypto::PublicKey> trusted_witnesses;
    /// Root certificates (DER) of the time-stamp authorities the verifier
    /// trusts (v0.11). Tokens that chain to no such root are counted but not
    /// relied on.
    std::vector<Bytes> trusted_timestamp_roots;
    /// Open-network witnesses the verifier trusts, by their verifier keys
    /// (v0.13). Their cosignatures count as its own witnesses' do.
    std::vector<network::VerifierKey> trusted_network_witnesses;
    /// Trust nodes the verifier believes (v0.16). Memberships from other
    /// ledgers are reported and relied on for nothing.
    std::vector<TrustNode> trust_nodes;
    /// Attachment contents to check, by attachment name.
    std::map<std::string, Bytes> attachment_contents;
    /// Signatures checked ahead of time or remembered, asked before each
    /// signature (see `SignatureChecks`): none by default, so every
    /// signature is checked here, one after another.
    SignatureChecks* signatures = nullptr;
    /// Modules loaded before, asked before each contract's code is loaded
    /// (see `ModuleCache`): none by default.
    ModuleCache* modules = nullptr;
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

    friend bool operator==(const ActorSummary&, const ActorSummary&) = default;
};

/// A request (v0.8) as an instance's evidence shows it, derived by replaying
/// the calls in the bundle.
struct RequestReport {
    Id id;
    /// The instance it belongs to.
    Id instance;
    /// The call that made it (log index), and its index in that call's
    /// accept key 7.
    std::uint64_t call = 0;
    std::uint32_t position = 0;
    std::string kind;
    cbor::Value params;
    Timestamp deadline = 0;
    std::string reply;
    /// Its call's registration time.
    Timestamp asked_at = 0;
    /// Set if an answer in the bundle closed it: its status, log index, and
    /// registration time. For a child's ancestors, a later answer may be
    /// left out of the bundle, so only an instance's own requests are known
    /// to be open.
    std::optional<AnswerStatus> status;
    std::optional<std::uint64_t> answered_by;
    Timestamp answered_at = 0;
    /// The answer's registration time minus the deadline, when positive.
    Timestamp late_by = 0;
    /// Open, and the checkpoint's time has reached its deadline.
    bool overdue = false;

    friend bool operator==(const RequestReport&, const RequestReport&) = default;
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
    /// reason, or the contract function's name.
    std::string detail;
    /// For a contract call: the call, and what the contract made of it.
    std::optional<ContractCallBody> contract_call;
    std::optional<ContractAccept> outcome;
    /// For a contract call that created instances (v0.7): their ids, in the
    /// order of the outcome's children.
    std::vector<Id> children;
    /// For a contract call that made requests (v0.8): their ids, in the order
    /// of the outcome's requests.
    std::vector<Id> requests;
    /// For an answer (v0.8): the request it answered (closed by it), with
    /// the answer's status and how late it was.
    std::optional<RequestReport> answered;
    /// For the registration of a new version that superseded the record
    /// (v0.10): that record's id (`detail` is its type).
    std::optional<Id> new_version;
    /// The time by which a trusted time-stamp authority saw a checkpoint
    /// covering this event (v0.11), the earliest if several did: its time
    /// plus the accuracy it states.
    std::optional<Timestamp> existed_by;

    friend bool operator==(const RecordEvent&, const RecordEvent&) = default;
};

/// An ancestor of a child instance (v0.7), as the child's evidence shows it:
/// up to the call that created the next generation, and no further.
struct AncestorReport {
    Id id;
    std::uint32_t depth = 0;
    /// Its parent and its position among that call's children, if a call
    /// made it a child too.
    std::optional<Id> parent;
    std::uint32_t position = 0;
    /// The call that created it, and its call that created the next
    /// generation.
    std::uint64_t created_by = 0;
    std::uint64_t until = 0;
    /// Its calls from `created_by` to `until`, as positions in the report's
    /// `events`.
    std::vector<std::size_t> events;

    friend bool operator==(const AncestorReport&, const AncestorReport&) = default;
};

/// A contract instance as of the checkpoint (spec section 15).
struct InstanceReport {
    Id contract;
    std::optional<std::string> contract_name;
    std::string language;
    std::string compiler;
    /// The deploy's code, interface, and source (if it carried one), so that
    /// a verifier can rebuild the code from the source and compare (for Bo,
    /// a `bo-source` bundle).
    Bytes code;
    std::map<std::string, FunctionKind> interface;
    std::optional<Bytes> source;
    /// The contract creates no more instances (known for certain only in a
    /// complete report).
    bool contract_retired = false;
    std::uint64_t head = 0;
    cbor::Encoded state;
    std::optional<std::string> status;
    Parties parties;
    bool final = false;
    /// The call that created it: a creation, or its parent's call (v0.7).
    std::uint64_t created_by = 0;
    /// For a child (v0.7): its parent, its position among the children of
    /// the call that created it, its depth (0 without a parent), and its
    /// ancestors, oldest first.
    std::optional<Id> parent;
    std::uint32_t position = 0;
    std::uint32_t depth = 0;
    std::vector<AncestorReport> ancestors;
    /// The report's `events` are the ancestors' calls, then the instance's
    /// own from this position on (the call that created it, first).
    std::size_t first_own_event = 0;
    /// Its own requests (v0.8), in the order its calls made them, each open
    /// or closed as of the checkpoint (the bundle is complete: every answer
    /// is in it). An ancestor's requests are not the instance's.
    std::vector<RequestReport> requests;

    /// Its open requests, as positions in `requests`; and those of them that
    /// are overdue at the checkpoint's time.
    [[nodiscard]] std::vector<std::size_t> open_requests() const;
    [[nodiscard]] std::vector<std::size_t> overdue_requests() const;

    friend bool operator==(const InstanceReport&, const InstanceReport&) = default;
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

    friend bool operator==(const AttachmentCheck&, const AttachmentCheck&) = default;
};

/// A time-stamp token in the bundle, as checked (v0.11).
struct TimestampCheck {
    /// The tree size of the checkpoint it stamps.
    std::uint64_t size = 0;
    /// The authority's time and the accuracy it states (milliseconds).
    Timestamp time = 0;
    std::uint64_t accuracy = 0;
    /// The authority, as its signing certificate names it.
    std::string authority;
    /// It chains to a root the verifier trusts.
    bool trusted = false;

    friend bool operator==(const TimestampCheck&, const TimestampCheck&) = default;
};

/// An open-network witness's cosignature an anchor carries (v0.13).
struct NetworkCosignatureCheck {
    /// The witness, as its cosignature names it.
    std::string witness;
    /// The tree size it cosigned, and its time (POSIX seconds).
    std::uint64_t size = 0;
    std::uint64_t time = 0;
    /// By a witness the verifier trusts, and verified.
    bool trusted = false;

    friend bool operator==(const NetworkCosignatureCheck&,
                           const NetworkCosignatureCheck&) = default;
};

struct EvidenceReport {
    Id ledger_id;
    std::string organization;
    crypto::HashAlg hash = crypto::HashAlg::sha256;
    Checkpoint checkpoint;
    /// The log key that signed the checkpoint, and how many times the log
    /// and root keys had been rotated before it.
    crypto::PublicKey log_key;
    std::size_t log_key_rotations = 0;
    std::size_t root_key_rotations = 0;
    /// Witnesses, each counted once: the ledger's own kind (COSE
    /// cosignatures of the checkpoint) and open-network ones (v0.13).
    std::size_t trusted_cosignatures = 0;
    std::size_t untrusted_cosignatures = 0;
    /// The anchors' open-network cosignatures, in the bundle's order.
    std::vector<NetworkCosignatureCheck> network_cosignatures;
    /// The bundle's time-stamp tokens (v0.11), in its order, and how many
    /// authorities it holds a trusted token of (each counted once).
    std::vector<TimestampCheck> timestamps;
    std::size_t trusted_timestamp_authorities = 0;

    /// The record, or the instance, the bundle is about.
    Id record;
    /// Empty for an instance.
    std::string record_type;
    std::string state;
    bool revoked = false;
    std::optional<cbor::Value> metadata;
    /// Versions (v0.10): the record this one supersedes (its own bundle
    /// shows the link), and the newer version that superseded it, which a
    /// complete report proves was not left out (its event is among
    /// `events`).
    std::optional<Id> supersedes;
    std::optional<Id> superseded_by;
    /// A claim (v0.14): its terms in words, and its source as the bundle
    /// proves it (none of the source's fields).
    struct ClaimReport {
        Claim claim;
        std::string text;
        std::string source_type;
        /// "live", "revoked", or "replaced".
        std::string source_status;
        /// The checkpoint's time is past the claim's `until`.
        bool lapsed = false;

        friend bool operator==(const ClaimReport&, const ClaimReport&) = default;
    };
    std::optional<ClaimReport> claim;
    /// A membership proof (v0.16): the trust node, the membership, and where
    /// it stood when the bundle's record was registered (an instance's
    /// creating call) and at the proof's checkpoint.
    struct MembershipReport {
        /// The trust node's ledger; trusted if on the verifier's list, which
        /// gives its name.
        Id trust_node;
        bool trusted = false;
        std::string trust_node_name;
        /// The membership record, and when the trust node registered it.
        Id record;
        Timestamp registered_at = 0;
        Membership membership;
        Timestamp record_time = 0;
        Standing at_record = Standing::not_yet;
        Timestamp checkpoint_time = 0;
        Standing at_checkpoint = Standing::not_yet;

        friend bool operator==(const MembershipReport&, const MembershipReport&) = default;
    };
    /// In the bundle's order.
    std::vector<MembershipReport> memberships;
    /// If the bundle is about a contract instance.
    std::optional<InstanceReport> instance;
    /// The record's events, or the instance's calls (for a child, its
    /// ancestors' first), oldest first.
    std::vector<RecordEvent> events;
    std::vector<RecordField> disclosed_fields;
    std::vector<AttachmentCheck> attachments;
    /// The bundle proved, against the state commitment in the log, that it
    /// holds the complete history of the record and of everyone involved:
    /// nothing, such as a later revocation, was left out.
    bool complete = false;
    /// That state commitment (the last entry the checkpoint covers).
    std::optional<StateCommitment> state_commitment;

    friend bool operator==(const EvidenceReport&, const EvidenceReport&) = default;
};

/// The objects whose complete history a bundle about `record` must prove:
/// the record (or instance, and then its contract), a claim's source
/// (v0.14), and for each of its events (`events`, the statements in its
/// history; for a child instance, its ancestors' calls first, see
/// `instance_events`; for a claim, its source's after its own) the signer,
/// an agent signer's accountable person, and every delegation in the chain
/// with its grantor. In first-seen order. Never an instance's ancestors
/// (v0.7).
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
