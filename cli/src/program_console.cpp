// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's command line: running it, its people, keys, backups, and service.

#include "registry.hpp"
#include "support.hpp"

namespace cexchain::cli {

std::vector<CommandSpec> console_commands();

const Program& program() {
    static const Program p{
        "cexchain-console",
        "cexchain-console - the web console of one ledger: people, documents, rules, and\n"
        "parties, approved with passkeys\n\n"
        "Usage: cexchain-console COMMAND [arguments] [options]\n"
        "Every command accepts --help and --json. Without --ledger or CEXCHAIN_LEDGER, the\n"
        "console is this person's, in this computer's place for it.\n",
        console_commands, apply_clock_offset};
    return p;
}

} // namespace cexchain::cli
