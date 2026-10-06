// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <string>

#include <cexchain/node/client.hpp>
#include <cexchain/node/peers.hpp>

namespace cexchain::cli {

/// The peer named `name` in the ledger at `dir`; throws if there is none.
[[nodiscard]] node::Peer peer_named(const std::filesystem::path& dir, const std::string& name);

/// A client for the peer's API, with the token the peer issued us.
[[nodiscard]] node::Client peer_client(const node::Peer& peer);

} // namespace cexchain::cli
