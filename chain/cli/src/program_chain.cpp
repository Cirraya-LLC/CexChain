// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The chain's command line: ledgers, actors, records, contracts, proofs, and
/// evidence, peers, witnesses, servers, and the MCP server.

#include "registry.hpp"
#include "support.hpp"

namespace cexchain::cli {

std::vector<CommandSpec> chain_commands();

const Program& program() {
    static const Program p{
        "cexchain",
        "cexchain - register, move, and prove anything, under rules you define\n\n"
        "Usage: cexchain COMMAND [arguments] [options]\n"
        "Every command accepts --help and --json. Set CEXCHAIN_LEDGER to skip --ledger.\n"
        "Set CEXCHAIN_CLOCK_OFFSET (such as 30d) to run every command's clock ahead, to try\n"
        "time rules without waiting: for demonstrations and tests only.\n"
        "IDs may be abbreviated to any unique prefix of 8 or more hex digits.\n"
        "Private keys are encrypted; passphrases come from --passphrase-file, "
        "$CEXCHAIN_PASSPHRASE,\n"
        "or a prompt. Exit codes: 0 success, 1 usage error, 2 failure, 3 verification failed.\n"
        "Beside it: bo (the Bo contract language), cexchain-console (the web console), and\n"
        "cexchain-index (searches and reports).\n",
        chain_commands, apply_clock_offset};
    return p;
}

} // namespace cexchain::cli
