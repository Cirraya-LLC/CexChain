// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/app/session.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Views of ledger objects for people (text) and programs (JSON: the command
/// line's --json, the console's pages). JSON uses lowercase hex for
/// identifiers and bytes, and RFC 3339 UTC for times; keys keep a stable
/// order.
namespace cexchain::app {

using verifier::cbor_json;
using verifier::checkpoint_json;
using verifier::Json;
using verifier::kind_text;
using verifier::provenance_json;
using verifier::report_json;

[[nodiscard]] Json hex_json(ByteView bytes);
[[nodiscard]] Json id_json(const protocol::Id& id);
[[nodiscard]] Json public_key_json(const crypto::PublicKey& key);

[[nodiscard]] Json actor_ref(const Session& session, const protocol::Id& id);
[[nodiscard]] Json actor_json(const Session& session, const protocol::ActorState& actor);
/// An actor with the delegations it received and granted, and how many
/// records it issued.
[[nodiscard]] Json actor_detail_json(const Session& session, const protocol::ActorState& actor);
[[nodiscard]] Json scope_json(const protocol::Scope& scope);
[[nodiscard]] Json delegation_json(const Session& session,
                                   const protocol::DelegationState& delegation);
[[nodiscard]] Json record_json(const Session& session, const protocol::RecordState& record);
/// A contract: its interface, language, code, and instances.
[[nodiscard]] Json contract_json(const Session& session, const protocol::ContractState& contract);
/// A contract instance: its status, parties, state, head, and calls.
[[nodiscard]] Json instance_json(const Session& session, const protocol::InstanceState& instance);

/// The instances calls created (v0.7), by parent, each list in the order
/// they were created. The ledger keeps no such index: the state is scanned
/// once per view.
using InstanceChildren = std::map<protocol::IdKey, std::vector<const protocol::InstanceState*>>;
[[nodiscard]] InstanceChildren children_by_parent(const protocol::LedgerState& state);
[[nodiscard]] std::span<const protocol::InstanceState* const>
children_of(const InstanceChildren& children, const protocol::Id& parent);
/// The requests calls made (v0.8), by instance, each list in the order they
/// were made. The ledger keeps them in one table: scanned once per view.
using RequestsByInstance = std::map<protocol::IdKey, std::vector<const protocol::RequestState*>>;
[[nodiscard]] RequestsByInstance requests_by_instance(const protocol::LedgerState& state);
[[nodiscard]] std::span<const protocol::RequestState* const>
requests_of(const RequestsByInstance& requests, const protocol::Id& instance);
/// `instance_json`, for many instances: with the maps scanned once.
[[nodiscard]] Json instance_json_with(const Session& session, const protocol::InstanceState& i,
                                      const InstanceChildren& all_children,
                                      const RequestsByInstance& all_requests);

/// The deploy statement's body of a contract: the code, the source, the
/// interface.
[[nodiscard]] protocol::ContractDeployBody deploy_of(const Session& session,
                                                     const protocol::ContractState& contract);
/// Why a retired contract was retired, if it was and a reason was given.
[[nodiscard]] std::optional<std::string> retire_reason(const Session& session,
                                                       const protocol::ContractState& contract);
/// The kind of actor that signed for a consenting party, if known.
[[nodiscard]] std::optional<protocol::ActorKind>
signer_kind(const protocol::ContractSigner& signer);
[[nodiscard]] Json body_json(const protocol::Body& body);
[[nodiscard]] Json statement_json(const protocol::Statement& statement);
[[nodiscard]] Json commitment_json(const protocol::StateCommitment& commitment);
/// A log entry with its statement decoded, and actor names resolved.
[[nodiscard]] Json entry_json(const Session& session, std::uint64_t index);

[[nodiscard]] std::string scope_text(const protocol::Scope& scope);
[[nodiscard]] Json presence_credential_json(const protocol::PresenceCredential& credential);
/// A one-line description of a statement body; `statement_id` is appended
/// for bodies that create something (records, actors, delegations).
[[nodiscard]] std::string body_summary(const Session& session, const protocol::Body& body,
                                       const std::optional<protocol::Id>& statement_id);
/// A one-line description of a statement, e.g. "endorse 3fa2c19be0d1 as inspector".
[[nodiscard]] std::string statement_summary(const Session& session,
                                            const protocol::SignedStatement& statement);

/// True if the delegation is not revoked and `now` is within its validity.
[[nodiscard]] bool delegation_active(const protocol::DelegationState& delegation,
                                     protocol::Timestamp now);
/// The grantors behind a delegation, nearest first, ending with the
/// organization.
[[nodiscard]] std::vector<protocol::Id>
authority_chain(const Session& session, const std::optional<protocol::Id>& delegation);
/// States reachable from the record's current state.
[[nodiscard]] std::vector<std::string> next_states(const protocol::RecordState& record);

} // namespace cexchain::app
