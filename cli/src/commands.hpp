// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

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
int cmd_ledger_keys(const Args& args);
int cmd_cluster_init(const Args& args);
int cmd_cluster_join(const Args& args);
int cmd_cluster_add(const Args& args);
int cmd_cluster_remove(const Args& args);
int cmd_cluster_step_down(const Args& args);
int cmd_cluster_status(const Args& args);
int cmd_ledger_genesis(const Args& args);
int cmd_ledger_rotate_log_key(const Args& args);
int cmd_ledger_rotate_root_key(const Args& args);

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
int cmd_record_file_list(const Args& args);
int cmd_record_file_get(const Args& args);
int cmd_record_file_add(const Args& args);
int cmd_record_file_remove(const Args& args);
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
int cmd_proof_state(const Args& args);
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

// Serving, replicas, and backups
int cmd_serve(const Args& args);
int cmd_token_create(const Args& args);
int cmd_token_list(const Args& args);
int cmd_token_show(const Args& args);
int cmd_token_revoke(const Args& args);
/// What `serve` uses when its options leave it open: `console run` serves
/// the console on localhost, trying the next ports when one is taken, and
/// learns the port it got.
struct ServeDefaults {
    std::optional<std::string> listen;
    bool console = false;
    /// How many ports to try, from the one asked for (0 or 1: only it).
    unsigned port_fallback = 0;
    std::function<void(std::uint16_t port)> on_listening;
};
int serve(const Args& args, const ServeDefaults& defaults);
int cmd_console_run(const Args& args);
int cmd_console_key_init(const Args& args);
int cmd_console_key_import(const Args& args);
int cmd_console_key_list(const Args& args);
int cmd_console_key_remove(const Args& args);
int cmd_console_status(const Args& args);
int cmd_console_stop(const Args& args);
int cmd_console_open(const Args& args);
int cmd_console_session_list(const Args& args);
int cmd_console_setup(const Args& args);
int cmd_console_kind_add(const Args& args);
int cmd_console_kind_list(const Args& args);
int cmd_console_kind_show(const Args& args);
int cmd_console_kind_remove(const Args& args);
int cmd_console_settings_show(const Args& args);
int cmd_console_settings_set(const Args& args);
int cmd_console_setup_link(const Args& args);
int cmd_console_user_add(const Args& args);
int cmd_console_user_list(const Args& args);
int cmd_console_user_show(const Args& args);
int cmd_console_user_role(const Args& args);
int cmd_console_user_revoke(const Args& args);
int cmd_console_user_link(const Args& args);
int cmd_console_user_passkeys(const Args& args);
int cmd_console_session_revoke(const Args& args);
int cmd_replica_init(const Args& args);
int cmd_replica_sync(const Args& args);
int cmd_replica_status(const Args& args);
int cmd_replica_promote(const Args& args);
int cmd_backup_create(const Args& args);
int cmd_backup_verify(const Args& args);
int cmd_backup_restore(const Args& args);

// Other organizations
int cmd_peer_add(const Args& args);
int cmd_peer_list(const Args& args);
int cmd_peer_show(const Args& args);
int cmd_peer_remove(const Args& args);
int cmd_access_request(const Args& args);
int cmd_access_send_request(const Args& args);
int cmd_access_fetch(const Args& args);
int cmd_access_accept(const Args& args);
int cmd_access_inbox(const Args& args);
int cmd_access_grant(const Args& args);
int cmd_access_receipt(const Args& args);
int cmd_access_list(const Args& args);

// Contracts
int cmd_contract_deploy(const Args& args);
int cmd_contract_show(const Args& args);
int cmd_contract_list(const Args& args);
int cmd_contract_retire(const Args& args);
int cmd_contract_create(const Args& args);
int cmd_contract_call(const Args& args);
int cmd_contract_instance(const Args& args);
int cmd_contract_instances(const Args& args);
int cmd_contract_evidence(const Args& args);
int cmd_contract_propose(const Args& args);
int cmd_contract_pending(const Args& args);
int cmd_contract_consent(const Args& args);
int cmd_contract_withdraw(const Args& args);
int cmd_contract_send(const Args& args);
int cmd_contract_fetch(const Args& args);
int cmd_contract_verify(const Args& args);
int cmd_contract_explain(const Args& args);

// Requests and executors (spec v0.8)
int cmd_request_list(const Args& args);
int cmd_request_show(const Args& args);
int cmd_request_answer(const Args& args);
int cmd_request_cancel(const Args& args);
int cmd_request_wait(const Args& args);
int cmd_executor_add(const Args& args);
int cmd_executor_list(const Args& args);
int cmd_executor_show(const Args& args);
int cmd_executor_revoke(const Args& args);
int cmd_executor_run(const Args& args);
int cmd_executor_check(const Args& args);
int cmd_executor_connector_add(const Args& args);
int cmd_executor_connector_list(const Args& args);
int cmd_executor_connector_show(const Args& args);
int cmd_executor_connector_remove(const Args& args);
int cmd_executor_secret_set(const Args& args);
int cmd_executor_secret_list(const Args& args);
int cmd_executor_secret_remove(const Args& args);
int cmd_executor_journal_list(const Args& args);
int cmd_executor_journal_show(const Args& args);
int cmd_connector_webhook(const Args& args);
int cmd_connector_command(const Args& args);
// Keepers: time rules and expiries
int cmd_keeper_add(const Args& args);
int cmd_keeper_list(const Args& args);
int cmd_keeper_show(const Args& args);
int cmd_keeper_revoke(const Args& args);
int cmd_keeper_due(const Args& args);
int cmd_keeper_run(const Args& args);

// The Bo language; only in builds with the Bo compiler
// (CEXCHAIN_HAVE_BO).
int cmd_bo_check(const Args& args);
int cmd_bo_build(const Args& args);
int cmd_bo_explain(const Args& args);
int cmd_bo_fmt(const Args& args);
int cmd_bo_test(const Args& args);
int cmd_bo_packs_list(const Args& args);
int cmd_bo_packs_show(const Args& args);
int cmd_bo_packs_check(const Args& args);
int cmd_bo_stdlib_list(const Args& args);
int cmd_bo_stdlib_show(const Args& args);
int cmd_bo_vocab_list(const Args& args);
int cmd_bo_vocab_show(const Args& args);
int cmd_bo_vocab_check(const Args& args);

} // namespace cexchain::cli
