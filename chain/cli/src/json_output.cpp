// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "json_output.hpp"

#include <print>

namespace kanhe::cli {

void print_json(const Json& value) {
    std::println("{}", value.dump(2));
}

} // namespace kanhe::cli
