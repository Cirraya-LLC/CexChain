// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>

#include <cexchain/app/views.hpp>

#include "support.hpp"

/// Printing: the app library's views, written to standard output.
namespace cexchain::cli {

void print_json(const Json& value);

/// Prints the result of a statement just registered: its id and log index
/// plus `extra` as JSON, or `text`.
int report_submitted(const Args& args, const app::Session& session, const protocol::Id& statement,
                     const Json& extra, const std::string& text);

} // namespace cexchain::cli
