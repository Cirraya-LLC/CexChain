// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>

#include <kanhe/node/api.hpp>

#include "args.hpp"

/// Serving a ledger's API, for the chain's `serve` and the applications that
/// serve themselves beside it.
namespace kanhe::cli {

/// What `serve` uses when its options leave it open, and the application it
/// may serve beside the ledger's API: `kanhe-console run` serves the
/// console on localhost, trying the next ports when one is taken, and learns
/// the port it got; `kanhe-index serve` adds the index.
struct ServeDefaults {
    std::optional<std::string> listen;
    /// How many ports to try, from the one asked for (0 or 1: only it).
    unsigned port_fallback = 0;
    std::function<void(std::uint16_t port)> on_listening;
    /// The application adds its parts to the API's options before it opens
    /// (the console, extensions), and wires itself to it once it is open.
    std::function<void(node::ApiOptions& options)> before_open;
    std::function<void(node::LedgerApi& api)> after_open;
    /// The application's say on where the server may listen: it throws a
    /// UsageError to refuse an address beyond this computer without TLS.
    std::function<void(bool loopback, bool tls)> check_listen;
    /// The largest request body, if the application takes more than the API
    /// (the console's uploads).
    std::optional<std::size_t> max_body;
    /// Once the server listens: the application's name and where people
    /// reach it, printed beside the API's address ({name: URL} in --json).
    std::function<std::pair<std::string, std::string>(std::uint16_t port)> on_address;
};
int serve(const Args& args, const ServeDefaults& defaults);

/// --listen's HOST:PORT, with [v6]:PORT for IPv6.
[[nodiscard]] std::pair<std::string, std::uint16_t> parse_listen(const std::string& text);

/// Throws unless `dir` holds a ledger.
void require_ledger_directory(const std::filesystem::path& dir);

} // namespace kanhe::cli
