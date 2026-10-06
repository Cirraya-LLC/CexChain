// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include "args.hpp"

namespace cexchain::cli {

int key_generate(const Args& args);
int key_show(const Args& args);
int init(const Args& args);
int status(const Args& args);
int actor_add(const Args& args);
int actor_list(const Args& args);
int delegate(const Args& args);
int revoke_delegation(const Args& args);
int issue(const Args& args);
int endorse(const Args& args);
int transition(const Args& args);
int revoke_record(const Args& args);
int record_show(const Args& args);
int checkpoint(const Args& args);
int export_bundle(const Args& args);
int verify(const Args& args);
int mcp(const Args& args);

} // namespace cexchain::cli
