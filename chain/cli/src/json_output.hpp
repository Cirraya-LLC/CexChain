// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <nlohmann/json.hpp>

/// Every program's machine-readable output (--json).
namespace cexchain::cli {

using Json = nlohmann::ordered_json;

void print_json(const Json& value);

} // namespace cexchain::cli
