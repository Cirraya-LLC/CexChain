// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/node/peers.hpp>

#include "output.hpp"
#include "support.hpp"

/// Contract operations shared by the command line and the MCP server:
/// calls run here before they are recorded, proposals to a home's
/// registrar, and consents to the calls it holds.
namespace cexchain::cli {

inline constexpr protocol::Timestamp day_ms = 86'400'000;

/// Contract arguments written in CBOR diagnostic notation (a superset of
/// JSON without floating point), at most 65,536 bytes encoded. Throws a
/// UsageError that starts with `what`.
[[nodiscard]] cbor::Value parse_contract_arguments(std::string_view text, std::string_view what);
/// Throws a UsageError if the encoded arguments are larger than a call takes.
void check_contract_arguments(const cbor::Value& arguments);
/// A command's arguments: --args in diagnostic notation, --args-cbor from a
/// file of CBOR, or null.
[[nodiscard]] cbor::Value contract_arguments_of(const Args& args);

/// A contract for people: its name and abbreviated id.
[[nodiscard]] std::string contract_label(const Session& session, const protocol::Id& contract);
[[nodiscard]] Json parties_json(const protocol::Parties& parties);
/// Ledger ids (hex strings, as the API lists them) for people: peers by name.
[[nodiscard]] std::string ledgers_text(const Session& session, const Json& list);

/// A call creating an instance with `function`, which must create, of the
/// contract `contract` names (an id or its abbreviation), which must not be
/// retired. Arguments, reference, and consents are left to the caller.
[[nodiscard]] protocol::ContractCallBody
creation_call(const Session& session, std::string_view contract, const std::string& function);
/// A call of `function` on the instance `instance` names, at its head: the
/// instance must not be final, and the function must act on instances.
[[nodiscard]] protocol::ContractCallBody
instance_call(const Session& session, std::string_view instance, const std::string& function);

/// Cites the consents whose evidence the files hold, as the call will cite
/// them: by ledger, record, hash under this ledger's hash, and the signer of
/// the registration, in ledger order, one per party. Checked as a verifier
/// will check them, for a clear answer before signing. Returns the bundles in
/// the order cited.
[[nodiscard]] std::vector<Bytes> cite_consents(const Session& session,
                                               protocol::ContractCallBody& body,
                                               std::span<const std::string> paths);

struct CallOptions {
    std::optional<std::string> delegation;
    std::optional<protocol::Provenance> provenance;
    /// Ignored in a dry run.
    std::optional<PresenceRequest> presence;
    bool dry_run = false;
    /// A dry run's registration time instead of now (--at).
    std::optional<protocol::Timestamp> at;
};

struct CallAttempt {
    protocol::SignedStatement statement;
    protocol::ContractRun run;
    /// Why the ledger refuses a call the contract accepts: the rules for the
    /// children it would create (v0.7: none on a retired contract, none at
    /// depth 8), which apply after the run.
    std::optional<std::string> refused;
    /// Set once the call is recorded: only if the contract accepted it and
    /// the ledger allows it, and never in a dry run.
    std::optional<protocol::Id> recorded;
};

/// Signs the call, runs its contract here as the ledger will, and records
/// it, with its consents' evidence, if the contract accepts it and the
/// ledger's rules for children allow it (unless a dry run). A call the
/// ledger would refuse is not sent.
[[nodiscard]] CallAttempt attempt_call(Session& session, const crypto::Signer& signer,
                                       protocol::ContractCallBody body,
                                       std::span<const Bytes> bundles, const CallOptions& options);

/// Why the call is not recorded, for people: the contract's answer, or the
/// ledger's.
[[nodiscard]] std::string refusal(const Session& session, const CallAttempt& attempt);
/// What a run decided, as JSON: "verdict" accept (with the status, parties,
/// events, finality, state, and any children), needs (the ledgers whose
/// consents it asks for), or refuse (the contract's answer, or the
/// ledger's); with the "reason" unless it accepts.
[[nodiscard]] Json run_json(const Session& session, const CallAttempt& attempt);

/// The instances the recorded call `call` created (v0.7), in order: none
/// unless its contract created children.
[[nodiscard]] std::vector<protocol::Id> created_children(const Session& session,
                                                         const protocol::Id& call);

/// A call a registrar holds, as the server shows it (`GET
/// /v1/contracts/calls`), for people and scripts: arguments in diagnostic
/// notation, times in RFC 3339.
[[nodiscard]] Json held_json(const Json& held);
/// The calls the home's registrar holds that concern this ledger, or the one
/// `call` (a full id) names, each as `held_json` shows it.
[[nodiscard]] Json pending_at(const node::Peer& home, const std::optional<std::string>& call);

/// An instance's contract evidence from its home (a peer), verified for it.
[[nodiscard]] std::pair<Bytes, protocol::ContractReport>
fetch_instance(const node::Peer& home, const protocol::Id& instance);
/// The home's hash, which a consent's terms hash the arguments with: named
/// by the home's latest checkpoint or, if it has none yet, by the
/// instance's evidence (which the home checkpoints for its parties).
[[nodiscard]] crypto::HashAlg home_hash(const node::Peer& home, const protocol::Id& instance);

/// The terms of a call a home's registrar holds, for a consent.
struct HeldTerms {
    /// The home, the instance, its head, the function, and the arguments'
    /// digest, recomputed here.
    protocol::ContractConsent consent;
    cbor::Value arguments;
};
/// Takes the terms from the call `call` the home holds, hashing
/// the arguments with `hash` (default: `home_hash`). Throws if the home's digest or the call's id
/// does not match the terms it sent.
[[nodiscard]] HeldTerms held_call_terms(const Session& session, const node::Peer& home,
                                        const protocol::Id& call,
                                        std::optional<crypto::HashAlg> hash);

struct ConsentOptions {
    /// The consent lapses after this many days.
    std::uint64_t days = 7;
    std::optional<std::string> reference;
    std::optional<std::string> delegation;
    std::optional<protocol::Provenance> provenance;
    std::optional<PresenceRequest> presence;
};

struct GivenConsent {
    protocol::Id record;
    /// The consent's evidence, which the home cites.
    Bytes bundle;
};

/// Records a cexchain.contract-consent/1 record on this ledger naming the
/// terms (setting their lapse and reference from `options`), checkpoints,
/// and returns its evidence. What the log key signs comes from
/// `ledger_args`: --log-key here, or the server in client mode.
[[nodiscard]] GivenConsent give_consent(Session& session, const crypto::Signer& signer,
                                        protocol::ContractConsent& consent,
                                        const ConsentOptions& options, const Args& ledger_args);
/// A consent just given, as JSON: its record and its terms.
[[nodiscard]] Json consent_json(const protocol::Id& record,
                                const protocol::ContractConsent& consent,
                                const cbor::Value& arguments);

} // namespace cexchain::cli
