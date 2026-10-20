// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/ledger/environment.hpp>

/// A home ledger's side of contracts (D-053, spec section 15): it records a
/// call that cites consents only with their evidence, keeps the bundles, and
/// serves them with the instance's evidence. A registrar takes proposed
/// calls, runs each without consents to learn whose the contract needs,
/// collects them from the parties, and records the call once the contract
/// accepts it.
///
/// Files under <ledger>/contracts:
///   consents/<call>.cbor        the consent bundles a call cites, [* bstr]
///                               in its order; written once
///   pending/<instance>-<head>-<id>.cbor
///                               a proposed call (`pending-call` below) with
///                               the consents collected so far; dropped once
///                               the instance moves on, or when it lapses
namespace cexchain::node {

[[nodiscard]] std::filesystem::path
contract_consents_directory(const std::filesystem::path& ledger_directory);
[[nodiscard]] std::filesystem::path
contract_consents_path(const std::filesystem::path& ledger_directory, const protocol::Id& call);
[[nodiscard]] std::filesystem::path
pending_calls_directory(const std::filesystem::path& ledger_directory);

/// The consent bundles a call cites, as kept and replicated: [* bstr], in
/// its order. Decoding takes at most `max` (a call cites up to 16).
[[nodiscard]] Result<Bytes> encode_consent_bundles(std::span<const Bytes> bundles);
[[nodiscard]] Result<std::vector<Bytes>>
decode_consent_bundles(ByteView encoded, std::size_t max = protocol::max_contract_consents);

/// Keeps a statement's consent bundles (encoded) at `path`, once: the same
/// bytes again are fine, other bytes are refused (Errc::rejected).
[[nodiscard]] Status store_consents_file(const std::filesystem::path& path, ByteView encoded);

/// The newest valid delegation of `actor` for `type`, on records of
/// `record_type` and on `contract` if given, at `now`. For a contract call
/// (`call`), the delegation's functions (scope key 8) must name its function,
/// and its request kinds (key 9, v0.8), if any, the kind of the request it
/// answers.
[[nodiscard]] std::optional<protocol::Id>
choose_delegation(const protocol::LedgerState& state, const protocol::Id& actor,
                  protocol::StatementType type, const std::optional<std::string>& record_type,
                  protocol::Timestamp now,
                  const std::optional<protocol::Id>& contract = std::nullopt,
                  const protocol::ContractCallBody* call = nullptr);

/// Checks the bundles a contract call cites, one per consent, in its order:
/// what a home does before recording the call at `now` on the ledger `home`
/// (hash `hash`), the signers the call claims included.
[[nodiscard]] Status check_call_consents(const crypto::Provider& provider, const protocol::Id& home,
                                         crypto::HashAlg hash,
                                         const protocol::ContractCallBody& call,
                                         std::span<const Bytes> bundles, protocol::Timestamp now);

/// True if the signed statement is a contract call that cites consents.
[[nodiscard]] bool cites_contract_consents(const protocol::Statement& statement);

/// The contract evidence for `instance_bundle` (an instance's evidence
/// bundle from this ledger): the bundle and every consent bundle its calls
/// cite, each once, read from `ledger_directory`. For a child (v0.7), the
/// calls on its `ancestors` that the bundle holds (each up to the one that
/// created the next generation) are its calls too, consents and all.
[[nodiscard]] Result<Bytes> contract_evidence(const crypto::Provider& provider,
                                              const std::filesystem::path& ledger_directory,
                                              const protocol::EvidenceBundle& instance_bundle,
                                              std::span<const protocol::Id> ancestors = {});

/// The ids of an instance's ancestors in `state`, oldest first: none unless
/// a call made it a child (v0.7), or if `state` has no such instance.
[[nodiscard]] std::vector<protocol::Id> ancestor_ids(const protocol::LedgerState& state,
                                                     const protocol::Id& instance);

/// Signs a contract call as the registrar `signer` (an actor of the ledger),
/// under its newest delegation that covers calls on the contract.
[[nodiscard]] Result<protocol::SignedStatement>
sign_contract_call(const crypto::Provider& provider, const protocol::LedgerState& state,
                   const crypto::Signer& signer, const protocol::ContractCallBody& call,
                   protocol::Timestamp now, ledger::Entropy& entropy);

/// The statement `sign_contract_call` signs, but for its nonce (all zero):
/// the signer's actor, its delegation, the time, and the call. For callers
/// that draw the nonces in one order and sign elsewhere (on other threads).
[[nodiscard]] Result<protocol::Statement>
contract_call_statement(const crypto::Provider& provider, const protocol::LedgerState& state,
                        const crypto::Signer& signer, const protocol::ContractCallBody& call,
                        protocol::Timestamp now);

/// Pending calls a registrar holds at most.
inline constexpr std::size_t max_pending_calls = 1024;
/// A proposal lapses this long after it is made, unless it says otherwise;
/// it may not ask for longer than the maximum.
inline constexpr protocol::Timestamp default_pending_lifetime = protocol::Timestamp{7} * 86'400'000;
inline constexpr protocol::Timestamp max_pending_lifetime = protocol::Timestamp{30} * 86'400'000;
/// The largest consent bundle a registrar takes.
inline constexpr std::size_t max_consent_bundle = 256 * 1024;

/// A call on an instance, proposed to the home's registrar, which holds it
/// until the consents the contract needs are in.
///
///   call-proposal = {1: instance, 2: head, 3: function, 4: arguments,
///                    ? 5: reference, ? 6: until}
///   pending-call  = {1: instance, 2: head, 3: function, 4: arguments,
///                    ? 5: reference, 6: until, 7: proposer,
///                    ? 8: [+ ledger] (missing), ? 9: [+ [ledger, bundle]]}
///
/// Lists are ascending by ledger. Deterministic CBOR, within the limits of a
/// contract call (spec section 15).
struct PendingCall {
    protocol::Id instance;
    std::uint64_t head = 0;
    std::string function;
    cbor::Value arguments;
    std::optional<std::string> reference;
    /// When it lapses; 0 in a proposal that leaves it to the registrar.
    protocol::Timestamp until = 0;
    /// Who proposed it: the name of the home's token, or of the peer.
    std::string proposer;
    /// The ledgers whose consents the contract asked for when it last ran.
    std::vector<protocol::Id> missing;
    /// The consents held: each party's ledger and consent bundle.
    std::vector<std::pair<protocol::Id, Bytes>> consents;

    friend bool operator==(const PendingCall&, const PendingCall&) = default;
};

[[nodiscard]] Result<Bytes> encode_call_proposal(const PendingCall& proposal);
[[nodiscard]] Result<PendingCall> decode_call_proposal(ByteView encoded);
[[nodiscard]] Result<Bytes> encode_pending_call(const PendingCall& call);
[[nodiscard]] Result<PendingCall> decode_pending_call(ByteView encoded);

/// The call as the registrar would sign it: on the instance at the head,
/// citing no consents yet.
[[nodiscard]] protocol::ContractCallBody call_body(const PendingCall& call);

/// A pending call's id: SHA-256 of [instance, head, function, arguments
/// digest], so that a consent's terms name exactly one. `arguments` is the
/// digest consents carry (the home's hash of the encoded arguments).
[[nodiscard]] Result<protocol::Id> pending_call_id(const crypto::Provider& provider,
                                                   const protocol::Id& instance, std::uint64_t head,
                                                   std::string_view function,
                                                   const protocol::Id& arguments);
[[nodiscard]] Result<protocol::Id> pending_call_id(const crypto::Provider& provider,
                                                   crypto::HashAlg hash, const PendingCall& call);

/// A pending call's file name, "<instance>-<head>-<id>.cbor", and back.
struct PendingName {
    protocol::Id instance;
    std::uint64_t head = 0;
    protocol::Id id;
};
[[nodiscard]] std::string pending_call_name(const PendingName& name);
[[nodiscard]] std::optional<PendingName> parse_pending_call_name(std::string_view file_name);

/// A change to the pending calls: a file written, or removed (no bytes).
struct PendingChange {
    std::string name;
    std::optional<Bytes> file;

    friend bool operator==(const PendingChange&, const PendingChange&) = default;
};

/// As a cluster replicates them: [* [name, file / null]].
[[nodiscard]] cbor::Value pending_changes_value(std::span<const PendingChange> changes);
[[nodiscard]] Result<std::vector<PendingChange>> decode_pending_changes(const cbor::Value& value);

/// Applies changes under <ledger>/contracts/pending: names must be pending
/// calls' and files must decode, or nothing is changed (Errc::malformed).
[[nodiscard]] Status apply_pending_changes(const std::filesystem::path& ledger_directory,
                                           std::span<const PendingChange> changes);

/// A pending call as held, with its file name.
struct HeldCall {
    PendingName name;
    PendingCall call;
};

/// The pending calls held under `ledger_directory`, in name order; files
/// that do not decode are left out. Any thread: files change atomically.
[[nodiscard]] std::vector<HeldCall> held_calls(const std::filesystem::path& ledger_directory);
[[nodiscard]] std::optional<HeldCall> held_call(const std::filesystem::path& ledger_directory,
                                                const protocol::Id& id);

/// The ledgers a pending call concerns: the instance's parties now, those
/// the contract asked, and those that consented.
[[nodiscard]] bool concerns(const protocol::LedgerState& state, const PendingCall& call,
                            const protocol::Id& ledger);

/// What a registrar made of a proposal or a consent.
struct CallProgress {
    enum class Verdict : std::uint8_t { waiting, accepted, refused };
    Verdict verdict = Verdict::waiting;
    protocol::Id id;
    PendingCall call;
    /// Refused: why, for people (the contract's reason when it aborts).
    std::string reason;
    /// Accepted: the call to record, signed as the registrar, and the
    /// bundles it cites, in its order.
    std::optional<protocol::SignedStatement> statement;
    std::vector<Bytes> bundles;
    /// The changes to make to the pending calls (the call itself, and those
    /// that went stale or lapsed).
    std::vector<PendingChange> changes;
};

/// The registrar's logic for contract calls. It reads the pending calls
/// from `ledger_directory` and leaves writing them to the caller (directly,
/// or through a cluster), so it changes nothing itself.
class CallRegistrar {
public:
    CallRegistrar(std::filesystem::path ledger_directory, const crypto::Signer& signer);

    /// Takes a proposal at `now` from `proposer` (a token's name), which,
    /// for a peer, is `party`, one of the instance's parties: it must act on
    /// the instance at its head with a function of kind 2, and the contract,
    /// run without consents, must ask for some. Refused if the contract
    /// accepts it as it is (the home signs such calls itself) or rejects it.
    /// The same proposal again is answered as it stands.
    [[nodiscard]] Result<CallProgress> propose(const crypto::Provider& provider,
                                               const protocol::LedgerState& state,
                                               PendingCall proposal,
                                               const std::optional<protocol::Id>& party,
                                               protocol::Timestamp now, ledger::Entropy& entropy);

    /// Takes `bundle`, the evidence of a consent on `party`'s ledger to a
    /// pending call, which the contract asked for: the consent is checked
    /// as a verifier would, and the citation's signer taken from the
    /// consent's registration. Then the contract runs with the consents
    /// held (lapsed ones dropped): accepted, the call is ready to record;
    /// asking for more, it waits; refusing, the consent is not kept.
    [[nodiscard]] Result<CallProgress> consent(const crypto::Provider& provider,
                                               const protocol::LedgerState& state,
                                               const protocol::Id& party, ByteView bundle,
                                               protocol::Timestamp now, ledger::Entropy& entropy);

    /// Removals of the pending calls whose instance moved on (or is gone, or
    /// final), and with `lapsed`, of those that lapsed by `now`.
    [[nodiscard]] std::vector<PendingChange> sweep(const protocol::LedgerState& state,
                                                   protocol::Timestamp now, bool lapsed) const;

private:
    [[nodiscard]] Result<CallProgress> run(const crypto::Provider& provider,
                                           const protocol::LedgerState& state,
                                           CallProgress progress, protocol::Timestamp now,
                                           ledger::Entropy& entropy) const;

    std::filesystem::path directory_;
    const crypto::Signer* signer_;
};

} // namespace cexchain::node
