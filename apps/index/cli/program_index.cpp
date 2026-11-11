// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The search index's command line: searches, reports, and its server.

#include "registry.hpp"
#include "support.hpp"

namespace kanhe::cli {

std::vector<CommandSpec> index_commands();

const Program& program() {
    static const Program p{
        "kanhe-index",
        "kanhe-index - search and count what a ledger holds in the clear\n\n"
        "Usage: kanhe-index COMMAND [arguments] [options]\n"
        "Every command accepts --help and --json. Set KANHE_LEDGER to skip --ledger.\n"
        "The index is derived from the log and kept beside the ledger (search.sqlite): its\n"
        "answers are hints with the log size they reflect, never evidence.\n",
        index_commands, apply_clock_offset};
    return p;
}

} // namespace kanhe::cli
