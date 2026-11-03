// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include "commands.hpp"

/// The bo program's command handlers (commands_bo.cpp).
namespace cexchain::cli {

int cmd_bo_version(const Args& args);
int cmd_bo_rebuild(const Args& args);
int cmd_bo_reason(const Args& args);
int cmd_bo_check(const Args& args);
int cmd_bo_build(const Args& args);
int cmd_bo_explain(const Args& args);
int cmd_bo_fmt(const Args& args);
int cmd_bo_form(const Args& args);
int cmd_bo_calls(const Args& args);
int cmd_bo_args(const Args& args);
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
