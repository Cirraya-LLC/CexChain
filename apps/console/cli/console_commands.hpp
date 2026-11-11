// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cexchain/console/keystore.hpp>

#include "commands.hpp"

/// The cexchain-console program's command handlers (commands_console.cpp).
namespace cexchain::cli {

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
int cmd_console_user_approve(const Args& args);
int cmd_console_activity(const Args& args);
int cmd_console_backup_now(const Args& args);
int cmd_console_backup_list(const Args& args);
int cmd_console_restore(const Args& args);
int cmd_console_service_install(const Args& args);
int cmd_console_service_uninstall(const Args& args);
int cmd_console_service_status(const Args& args);
int cmd_console_session_revoke(const Args& args);
/// Unlocks the console's sealed keys with --unlock-file, else a passphrase
/// or recovery code typed on the terminal.
void unlock_console_keys(console::KeyStore& keys, const Args& args);
int cmd_certificate_allow(const Args& args);
int cmd_answers_allow(const Args& args);
int cmd_certificate_issue(const Args& args);
int cmd_certificate_list(const Args& args);
int cmd_certificate_show(const Args& args);
int cmd_certificate_withdraw(const Args& args);
int cmd_certificate_print(const Args& args);

} // namespace cexchain::cli
