// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include "args.hpp"

/// Command handlers, one per registry entry (see registry.cpp). Each returns
/// the process exit code; failures are thrown as UsageError or CommandError.
namespace cexchain::cli {

/// Exit codes.
inline constexpr int exit_ok = 0;
inline constexpr int exit_usage = 1;
inline constexpr int exit_failure = 2;
/// Evidence or a ledger failed verification.
inline constexpr int exit_not_verified = 3;

// General
int cmd_version(const Args& args);
int cmd_help(const Args& args);
int cmd_completion(const Args& args);

// Keys
int cmd_key_generate(const Args& args);
int cmd_key_show(const Args& args);
int cmd_key_public(const Args& args);
int cmd_key_passphrase(const Args& args);

// Ledger
int cmd_init(const Args& args);
int cmd_status(const Args& args);
int cmd_audit(const Args& args);
int cmd_log_list(const Args& args);
int cmd_log_show(const Args& args);
int cmd_log_export(const Args& args);

// Actors and delegations
int cmd_actor_add(const Args& args);
int cmd_actor_list(const Args& args);
int cmd_actor_show(const Args& args);
int cmd_actor_revoke(const Args& args);
int cmd_actor_rotate_key(const Args& args);
int cmd_actor_set_presence(const Args& args);
int cmd_delegation_grant(const Args& args);
int cmd_delegation_list(const Args& args);
int cmd_delegation_show(const Args& args);
int cmd_delegation_revoke(const Args& args);

// Records
int cmd_record_issue(const Args& args);
int cmd_record_list(const Args& args);
int cmd_record_show(const Args& args);
int cmd_record_history(const Args& args);
int cmd_record_fields(const Args& args);
int cmd_record_endorse(const Args& args);
int cmd_record_transition(const Args& args);
int cmd_record_revoke(const Args& args);
int cmd_record_types(const Args& args);

// Checkpoints, proofs, and evidence
int cmd_checkpoint_create(const Args& args);
int cmd_checkpoint_list(const Args& args);
int cmd_checkpoint_show(const Args& args);
int cmd_checkpoint_cosign_request(const Args& args);
int cmd_checkpoint_add_cosignature(const Args& args);
int cmd_proof_inclusion(const Args& args);
int cmd_proof_consistency(const Args& args);
int cmd_receipt(const Args& args);
int cmd_export(const Args& args);
int cmd_verify(const Args& args);
int cmd_inspect(const Args& args);
int cmd_qr(const Args& args);

// Presence
int cmd_presence_enroll(const Args& args);

// Vault
int cmd_vault_status(const Args& args);
int cmd_vault_keygen(const Args& args);
int cmd_vault_rekey(const Args& args);

// Witnesses
int cmd_witness_add_log(const Args& args);
int cmd_witness_cosign(const Args& args);
int cmd_witness_status(const Args& args);
int cmd_witness_remove_log(const Args& args);

// AI agents
int cmd_mcp(const Args& args);

} // namespace cexchain::cli
