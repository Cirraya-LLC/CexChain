// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The chain's command line: ledgers, actors, records, contracts, proofs, and
/// evidence, peers, witnesses, servers, and the MCP server.

#include "registry.hpp"
#include "support.hpp"

namespace kanhe::cli {

std::vector<CommandSpec> chain_commands();

const Program& program() {
    static const Program p{
        "kanhe",
        "kanhe - register, move, and prove anything, under rules you define\n\n"
        "Usage: kanhe COMMAND [arguments] [options]\n"
        "Every command accepts --help and --json. Set KANHE_LEDGER to skip --ledger.\n"
        "Set KANHE_CLOCK_OFFSET (such as 30d) to run every command's clock ahead, to try\n"
        "time rules without waiting: for demonstrations and tests only.\n"
        "IDs may be abbreviated to any unique prefix of 8 or more hex digits.\n"
        "Private keys are encrypted; passphrases come from --passphrase-file, "
        "$KANHE_PASSPHRASE,\n"
        "or a prompt. Exit codes: 0 success, 1 usage error, 2 failure, 3 verification failed.\n"
        "Beside it: bo (the Bo contract language), kanhe-console (the web console), and\n"
        "kanhe-index (searches and reports).\n",
        chain_commands, apply_clock_offset};
    return p;
}

} // namespace kanhe::cli
