// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include "commands.hpp"

/// The kanhe-index program's command handlers (commands_index.cpp).
namespace kanhe::cli {

int cmd_search_records(const Args& args);
int cmd_search_instances(const Args& args);
int cmd_report_records(const Args& args);
int cmd_report_instances(const Args& args);
int cmd_index_status(const Args& args);
int cmd_index_rebuild(const Args& args);
int cmd_index_serve(const Args& args);

} // namespace kanhe::cli
