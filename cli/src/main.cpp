// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdio>
#include <exception>
#include <print>

#include "commands.hpp"
#include "registry.hpp"

int main(int argc, char** argv) {
    using namespace cexchain::cli;
    try {
        return dispatch(argc, argv);
    } catch (const UsageError& e) {
        std::println(stderr, "usage error: {}", e.message);
        return exit_usage;
    } catch (const CommandError& e) {
        std::println(stderr, "error: {}", e.message);
        return exit_failure;
    } catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return exit_failure;
    }
}
