// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/cose.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

/// Statements: the signed objects that actors submit to a ledger.
/// See `statement-payload` in spec/cexchain.cddl.
namespace cexchain::protocol {

enum class StatementType : std::uint8_t {
    genesis = 1,
    actor_register = 2,
    actor_rotate_key = 3,
    actor_revoke = 4,
    delegation_grant = 5,
    delegation_revoke = 6,
    actor_set_presence = 7,
    ledger_rotate_log_key = 8,
    record_register = 16,
    record_endorse = 17,
    record_transition = 18,
    record_revoke = 19,
    asset_action = 20,
    contract_deploy = 21,
    contract_call = 22,
    contract_retire = 23,
};

[[nodiscard]] std::optional<StatementType> statement_type_from(std::uint64_t value) noexcept;
[[nodiscard]] std::string_view name(StatementType type) noexcept;

enum class ActorKind : std::uint8_t {
    person = 1,
    agent = 2,
    device = 3,
};

struct GenesisBody {
    crypto::HashAlg hash_alg;
    std::string organization;
    crypto::PublicKey root_key;
    crypto::PublicKey log_key;

    friend bool operator==(const GenesisBody&, const GenesisBody&) = default;
};

struct AgentProfile {
    std::optional<std::string> model;
    std::optional<std::string> model_version;
    std::optional<std::string> runtime;

    friend bool operator==(const AgentProfile&, const AgentProfile&) = default;
};

struct ActorRegisterBody {
    ActorKind kind;
    std::string display_name;
    crypto::PublicKey key;
    /// The accountable person. Required for agents.
    std::optional<Id> responsible;
    /// Agents only.
    std::optional<AgentProfile> agent;

    friend bool operator==(const ActorRegisterBody&, const ActorRegisterBody&) = default;
};

struct ActorRotateKeyBody {
    Id actor;
    crypto::PublicKey key;

    friend bool operator==(const ActorRotateKeyBody&, const ActorRotateKeyBody&) = default;
};

struct ActorRevokeBody {
    Id actor;
    std::optional<std::string> reason;

    friend bool operator==(const ActorRevokeBody&, const ActorRevokeBody&) = default;
};

/// How a person proves presence.
enum class PresenceMethod : std::uint8_t {
    /// A WebAuthn passkey or security key, through a browser.
    webauthn = 1,
    /// A hardware key held on a token (a USB key, smart card, or HSM),
    /// unlocked with its PIN, that signs the presence challenge directly.
    hardware_key = 2,
};

/// A credential with which a person proves presence. WebAuthn credentials
/// have a relying party id and an ESP256 (ES256) or Ed25519 (EdDSA) key;
/// hardware keys have no relying party and may use any signature algorithm,
/// SM2 among them.
struct PresenceCredential {
    /// The WebAuthn relying party id, e.g. "example.com" or "localhost";
    /// empty for a hardware key.
    std::string rp_id;
    Bytes credential_id;
    crypto::PublicKey key;
    std::optional<std::string> label;
    PresenceMethod method = PresenceMethod::webauthn;

    friend bool operator==(const PresenceCredential&, const PresenceCredential&) = default;
};

/// Sets a person's presence credentials, replacing any before.
struct ActorSetPresenceBody {
    Id actor;
    /// At most 16; empty removes them all.
    std::vector<PresenceCredential> credentials;

    friend bool operator==(const ActorSetPresenceBody&, const ActorSetPresenceBody&) = default;
};

/// Replaces the ledger's log key (spec v0.4). Only the organization signs
/// it, with its root key and without a delegation. The new key signs every
/// state commitment and checkpoint after this entry.
struct LedgerRotateLogKeyBody {
    crypto::PublicKey key;

    friend bool operator==(const LedgerRotateLogKeyBody&, const LedgerRotateLogKeyBody&) = default;
};

struct Scope {
    /// Statement types the grantee may submit. Non-empty, no duplicates.
    std::vector<StatementType> statement_types;
    /// Record types the grantee may act on; nullopt means any.
    std::optional<std::vector<std::string>> record_types;
    std::optional<Timestamp> not_before;
    std::optional<Timestamp> not_after;
    bool may_delegate = false;
    /// Statements under this delegation must carry proof of presence.
    bool require_presence = false;
    /// Contracts that calls and retires may act on (spec v0.6), strictly
    /// ascending; nullopt means any.
    std::optional<std::vector<Id>> contracts;

    friend bool operator==(const Scope&, const Scope&) = default;
};

struct DelegationGrantBody {
    Id grantee;
    Scope scope;

    friend bool operator==(const DelegationGrantBody&, const DelegationGrantBody&) = default;
};

struct DelegationRevokeBody {
    Id delegation;
    std::optional<std::string> reason;

    friend bool operator==(const DelegationRevokeBody&, const DelegationRevokeBody&) = default;
};

struct Attachment {
    std::string name;
    std::string media_type;
    std::uint64_t size;
    Bytes commitment;

    friend bool operator==(const Attachment&, const Attachment&) = default;
};

struct RecordRegisterBody {
    std::string record_type;
    Bytes field_root;
    std::uint64_t field_count;
    std::vector<Attachment> attachments;
    /// Public metadata: a non-empty map with text keys, or nullopt.
    std::optional<cbor::Value> metadata;

    friend bool operator==(const RecordRegisterBody&, const RecordRegisterBody&) = default;
};

struct RecordEndorseBody {
    Id record;
    std::string role;

    friend bool operator==(const RecordEndorseBody&, const RecordEndorseBody&) = default;
};

struct RecordTransitionBody {
    Id record;
    std::string from_state;
    std::string to_state;

    friend bool operator==(const RecordTransitionBody&, const RecordTransitionBody&) = default;
};

struct RecordRevokeBody {
    Id record;
    std::optional<std::string> reason;

    friend bool operator==(const RecordRevokeBody&, const RecordRevokeBody&) = default;
};

/// What an asset action does to an ownership asset (spec v0.5, section 13).
enum class AssetAction : std::uint8_t {
    transfer,
    pledge,
    release,
    enforce,
    redeem,
    pay,
    confirm,
    dispute,
    freeze,
    unfreeze,
    cancel,
};

[[nodiscard]] std::string_view name(AssetAction action) noexcept;
[[nodiscard]] std::optional<AssetAction> asset_action_from(std::string_view name) noexcept;

/// A party's consent to an asset action, given on its own ledger.
struct ConsentRef {
    /// The party's ledger, and its consent record there.
    Id ledger;
    Id record;
    /// HASH (the home ledger's) of the consent's evidence bundle the home
    /// verified and keeps.
    Id bundle;

    friend bool operator==(const ConsentRef&, const ConsentRef&) = default;
};

/// At most this many consents per action (the most any action needs is 2).
inline constexpr std::size_t max_consents = 4;
/// Asset action references and consent references: at most this many bytes.
inline constexpr std::size_t max_asset_reference = 1024;

/// Changes an ownership asset on its home ledger (spec v0.5).
struct AssetActionBody {
    /// The asset: the record id of its registration.
    Id asset;
    AssetAction action = AssetAction::transfer;
    /// The log index of the asset's registration or latest asset action,
    /// which this action follows.
    std::uint64_t head = 0;
    /// The counterparty's ledger: transfer and pledge.
    std::optional<Id> to;
    /// Redeem only.
    std::optional<std::uint64_t> quantity;
    /// One per party the action needs, strictly ascending by ledger.
    std::vector<ConsentRef> consents;
    /// A payment reference, a court order, a reason.
    std::optional<std::string> reference;

    friend bool operator==(const AssetActionBody&, const AssetActionBody&) = default;
};

/// Contract limits (spec v0.6, section 15).
inline constexpr std::size_t max_contract_source = 262'144;
inline constexpr std::size_t max_contract_functions = 256;
inline constexpr std::size_t max_function_name = 64;
inline constexpr std::size_t max_contract_language = 32;
inline constexpr std::size_t max_contract_compiler = 128;
inline constexpr std::size_t max_contract_name = 256;
/// Arguments and an instance's state, encoded.
inline constexpr std::size_t max_contract_value = 65'536;
inline constexpr std::size_t max_contract_consents = 16;
inline constexpr std::size_t max_contract_reference = 1024;

/// Whether a contract function creates an instance or acts on one.
enum class FunctionKind : std::uint8_t {
    create = 1,
    call = 2,
};

/// Deploys a contract (spec v0.6): a module in the profile of section 14.
/// The contract's id is this statement's id.
struct ContractDeployBody {
    /// The WebAssembly module, at most vm::max_module_size bytes.
    Bytes code;
    /// Function names (1-64 bytes) and kinds; at least one creates.
    std::map<std::string, FunctionKind> interface;
    /// "bo", "wasm", ...
    std::string language;
    /// The compiler and its version.
    std::string compiler;
    /// The source, so that anyone can rebuild the module and compare.
    std::optional<Bytes> source;
    std::optional<std::string> name;

    friend bool operator==(const ContractDeployBody&, const ContractDeployBody&) = default;
};

/// Who signed a statement, as a contract sees it.
struct ContractSigner {
    /// 0 for the organization, otherwise the actor's ActorKind.
    std::uint8_t kind = 0;
    /// Set if the statement carries proof of presence: its method.
    std::optional<PresenceMethod> presence;
    /// The model its provenance names (agents).
    std::optional<std::string> model;

    friend bool operator==(const ContractSigner&, const ContractSigner&) = default;
};

/// `signer` as statements and contract inputs encode it.
[[nodiscard]] cbor::Value encode_contract_signer(const ContractSigner& signer);

/// A party's consent to a contract call, given on its own ledger, with who
/// signed the consent's registration there (which the contract decides on,
/// and verifiers check against the bundle).
struct ContractConsentRef {
    Id ledger;
    Id record;
    /// HASH (the home's) of the consent's evidence bundle the home verified.
    Id bundle;
    ContractSigner signer;

    friend bool operator==(const ContractConsentRef&, const ContractConsentRef&) = default;
};

/// Creates an instance (contract set, a creating function, no head, no
/// consents; the instance's id is this statement's id) or acts on one
/// (instance and head set).
struct ContractCallBody {
    std::optional<Id> contract;
    std::optional<Id> instance;
    std::string function;
    /// Any CBOR value, at most max_contract_value bytes encoded.
    cbor::Value arguments;
    /// The log index of the instance's latest call; exactly with an instance.
    std::optional<std::uint64_t> head;
    /// Strictly ascending by ledger.
    std::vector<ContractConsentRef> consents;
    std::optional<std::string> reference;

    friend bool operator==(const ContractCallBody&, const ContractCallBody&) = default;
};

/// Retires a contract: it creates no more instances; its instances carry on.
struct ContractRetireBody {
    Id contract;
    std::optional<std::string> reason;

    friend bool operator==(const ContractRetireBody&, const ContractRetireBody&) = default;
};

using Body = std::variant<GenesisBody, ActorRegisterBody, ActorRotateKeyBody, ActorRevokeBody,
                          DelegationGrantBody, DelegationRevokeBody, ActorSetPresenceBody,
                          LedgerRotateLogKeyBody, RecordRegisterBody, RecordEndorseBody,
                          RecordTransitionBody, RecordRevokeBody, AssetActionBody,
                          ContractDeployBody, ContractCallBody, ContractRetireBody>;

[[nodiscard]] StatementType type_of(const Body& body) noexcept;

struct ToolPin {
    std::string name;
    Bytes digest;

    friend bool operator==(const ToolPin&, const ToolPin&) = default;
};

/// What an AI agent acted on and with.
struct Provenance {
    std::optional<std::string> model;
    std::optional<std::string> model_version;
    std::optional<Bytes> input_commitment;
    std::vector<ToolPin> tools;

    friend bool operator==(const Provenance&, const Provenance&) = default;
};

/// A person's proof of presence for the statement's presence challenge (see
/// presence.hpp): a WebAuthn assertion, or for a hardware key just its
/// signature over the challenge (authenticator data and client data empty).
struct PresenceProof {
    Bytes credential_id;
    Bytes authenticator_data;
    Bytes client_data_json;
    /// WebAuthn: as the authenticator produced it (DER for ES256, raw for
    /// EdDSA). Hardware key: in CexChain's wire format for the key.
    Bytes signature;

    friend bool operator==(const PresenceProof&, const PresenceProof&) = default;
};

struct Statement {
    /// Absent only in genesis.
    std::optional<Id> ledger_id;
    /// The signer's actor. Absent only in genesis.
    std::optional<Id> actor_id;
    /// The delegation that authorizes this statement, if any.
    std::optional<Id> delegation_id;
    /// Claimed by the signer.
    Timestamp issued_at = 0;
    Nonce nonce{};
    Body body;
    /// A person's proof of presence.
    std::optional<PresenceProof> presence;
    std::optional<Provenance> provenance;

    [[nodiscard]] StatementType type() const noexcept { return type_of(body); }

    friend bool operator==(const Statement&, const Statement&) = default;
};

/// Encodes a statement payload. Fails if the statement violates the
/// structural rules of the specification.
[[nodiscard]] Result<Bytes> encode_payload(const Statement& statement);

/// Presence credentials as they are encoded in statements; credential files
/// use the same encoding.
[[nodiscard]] Result<Bytes> encode_presence_credential(const PresenceCredential& credential);
[[nodiscard]] Result<PresenceCredential> decode_presence_credential(ByteView encoded);

/// Decodes and checks a statement payload. Rejects unknown keys.
[[nodiscard]] Result<Statement> decode_payload(ByteView payload);

/// A signed statement as it travels and is stored.
struct SignedStatement {
    /// The tagged COSE_Sign1 bytes.
    Bytes encoded;
    cose::Sign1 envelope;
    Statement statement;
    /// HASH(Sig_structure) under the ledger hash.
    Id id;
    /// The signing key's identifier from the protected header.
    Id kid;
    crypto::HashAlg hash_alg;
};

/// Signs a statement. `ledger_hash` must match the ledger (for genesis, the
/// algorithm declared in its body).
[[nodiscard]] Result<SignedStatement> sign_statement(const crypto::Signer& signer,
                                                     const crypto::Provider& provider,
                                                     crypto::HashAlg ledger_hash,
                                                     const Statement& statement);

/// Parses a signed statement and computes its identifier. For genesis the
/// hash algorithm comes from the body (and must equal `ledger_hash` if one is
/// given); every other statement requires `ledger_hash`. The signature is not
/// verified; see `verify_statement`.
[[nodiscard]] Result<SignedStatement>
parse_statement(const crypto::Provider& provider, ByteView encoded,
                std::optional<crypto::HashAlg> ledger_hash = std::nullopt);

/// Verifies the statement's signature with `key`, which must be the key the
/// protected header's kid names.
[[nodiscard]] Status verify_statement(const crypto::Provider& provider,
                                      const SignedStatement& statement,
                                      const crypto::PublicKey& key);

} // namespace cexchain::protocol
