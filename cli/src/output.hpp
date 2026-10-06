// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/core/protocol/statement.hpp>

#include "support.hpp"

/// Rendering of ledger objects for people (text) and scripts (--json).
/// JSON uses lowercase hex for identifiers and bytes, and RFC 3339 UTC for
/// times; keys keep a stable order.
namespace cexchain::cli {

using verifier::cbor_json;
using verifier::checkpoint_json;
using verifier::Json;
using verifier::kind_text;
using verifier::provenance_json;
using verifier::report_json;

void print_json(const Json& value);

[[nodiscard]] Json hex_json(ByteView bytes);
[[nodiscard]] Json id_json(const protocol::Id& id);
[[nodiscard]] Json public_key_json(const crypto::PublicKey& key);

[[nodiscard]] Json actor_ref(const Session& session, const protocol::Id& id);
[[nodiscard]] Json actor_json(const Session& session, const protocol::ActorState& actor);
[[nodiscard]] Json scope_json(const protocol::Scope& scope);
[[nodiscard]] Json delegation_json(const Session& session,
                                   const protocol::DelegationState& delegation);
[[nodiscard]] Json record_json(const Session& session, const protocol::RecordState& record);
[[nodiscard]] Json body_json(const protocol::Body& body);
[[nodiscard]] Json statement_json(const protocol::Statement& statement);
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

/// Prints the result of a statement just registered: its id and log index
/// plus `extra` as JSON, or `text`.
int report_submitted(const Args& args, const Session& session, const protocol::Id& statement,
                     const Json& extra, const std::string& text);

/// True if the delegation is not revoked and `now` is within its validity.
[[nodiscard]] bool delegation_active(const protocol::DelegationState& delegation,
                                     protocol::Timestamp now);
/// The grantors behind a delegation, nearest first, ending with the
/// organization.
[[nodiscard]] std::vector<protocol::Id>
authority_chain(const Session& session, const std::optional<protocol::Id>& delegation);
/// States reachable from the record's current state.
[[nodiscard]] std::vector<std::string> next_states(const protocol::RecordState& record);

} // namespace cexchain::cli
