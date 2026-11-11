// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The Bo language's command line: the compiler and its tools.

#include "registry.hpp"

namespace kanhe::cli {

std::vector<CommandSpec> bo_commands();

const Program& program() {
    static const Program p{
        "bo",
        "bo - the Bo contract language: write, check, build, test, and explain contracts\n\n"
        "Usage: bo COMMAND [arguments] [options]\n"
        "Every command accepts --help and --json. Messages come in the language of --language\n"
        "or $KANHE_LANGUAGE (en, zh-Hant-HK, zh-Hans-CN). A built contract (bo build --out)\n"
        "is deployed with kanhe contract deploy; a deployed one is rebuilt and explained\n"
        "from its deploy file (kanhe contract export). Exit codes: 0 success, 1 usage\n"
        "error, 2 failure, 3 does not rebuild or test.\n",
        bo_commands};
    return p;
}

} // namespace kanhe::cli
