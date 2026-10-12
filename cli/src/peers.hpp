// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <string>
#include <string_view>

#include <cexchain/node/client.hpp>
#include <cexchain/node/peers.hpp>

#include "support.hpp"

namespace cexchain::cli {

/// The peer named `name` in the ledger at `dir`; throws if there is none.
[[nodiscard]] node::Peer peer_named(const std::filesystem::path& dir, const std::string& name);

/// A client for the peer's API, with the token the peer issued us.
[[nodiscard]] node::Client peer_client(const node::Peer& peer);

/// Answers from a peer's API, as JSON; throws on an error status, with the
/// peer's message.
verifier::Json peer_call(const node::Peer& peer, std::string_view method, const std::string& path,
                         ByteView body = {});

/// An id of an object on another ledger, in full (64 hex digits).
[[nodiscard]] protocol::Id full_id(std::string_view text, std::string_view what);

/// A ledger, by peer name (with a ledger directory) or by its full id.
[[nodiscard]] protocol::Id ledger_of(const Session& session, std::string_view text);

/// A ledger for people: "name (abbreviated id)" for a peer, else
/// "ledger abbreviated-id".
[[nodiscard]] std::string ledger_label(const Session& session, const protocol::Id& ledger);

} // namespace cexchain::cli
