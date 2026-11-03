// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/app/session.hpp>
#include <cexchain/app/views.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/peers.hpp>

/// Peers: other ledgers this one works with, their APIs, and their names.
namespace cexchain::app {

/// The peers of the ledger at `dir`.
[[nodiscard]] std::vector<node::Peer> peers_of(const std::filesystem::path& dir);

/// The peer named `name` in the ledger at `dir`; throws if there is none.
[[nodiscard]] node::Peer peer_named(const std::filesystem::path& dir, const std::string& name);

/// A client for the peer's API, with the token the peer issued us.
[[nodiscard]] node::Client peer_client(const node::Peer& peer);

/// Answers from a peer's API, as JSON; throws on an error status, with the
/// peer's message.
Json peer_call(const node::Peer& peer, std::string_view method, const std::string& path,
               ByteView body = {});

/// An id of an object on another ledger, in full (64 hex digits).
[[nodiscard]] protocol::Id full_id(std::string_view text, std::string_view what);

/// A ledger, by peer name (with a ledger directory) or by its full id.
[[nodiscard]] protocol::Id ledger_of(const Session& session, std::string_view text);

/// A ledger for people: "name (abbreviated id)" for a peer, else
/// "ledger abbreviated-id".
[[nodiscard]] std::string ledger_label(const Session& session, const protocol::Id& ledger);

/// A peer as JSON: its name, ledger, URL, token and CA files, witness key,
/// and when it was added.
[[nodiscard]] Json peer_json(const node::Peer& peer);

/// Adds a peer to the ledger at `dir`: not the ledger itself, and no other
/// peer with its name or ledger.
void add_peer(const std::filesystem::path& dir, const node::Peer& peer);
/// Removes the peer named `name` (what was granted stays on the ledger).
void remove_peer(const std::filesystem::path& dir, const std::string& name);

// ---------------------------------------------------------------------------
// Invitations: two ledgers become each other's peers
// ---------------------------------------------------------------------------

/// An invitation to become a peer (`peer invite`, the console's Parties):
/// the inviting ledger's id, its organization's name as it gives it, the URL
/// of its API if others reach one, and the token it issued for the invited
/// party, to call that API as its peer; and the public key of the witness
/// the inviting organization runs for its parties, if it runs one. Whoever
/// holds the code holds the token: send it to that party only. Written as
/// `cxp_` and the base64url of its CBOR, `{1: 1, 2: ledger, 3: organization,
/// ? 4: url, ? 5: token, ? 6: witness key [alg, key], ? 7: relay {1: url,
/// 2: relay key, 3: the relay's witness key}}`; a ledger that no one
/// reaches directly gives its relay instead of a URL.
struct PeerInvitation {
    protocol::Id ledger;
    std::string organization;
    std::optional<std::string> url;
    std::optional<std::string> token;
    std::optional<crypto::PublicKey> witness;
    std::optional<node::RelayRoute> relay;

    friend bool operator==(const PeerInvitation&, const PeerInvitation&) = default;
};

inline constexpr std::size_t max_invitation_code = 4096;

[[nodiscard]] std::string encode_invitation(const PeerInvitation& invitation);
/// The invitation a code holds, or nullopt if it is not one (a code of
/// another version, a field out of its limits, any other key).
[[nodiscard]] std::optional<PeerInvitation> decode_invitation(std::string_view code);

/// A ledger id for people to compare by voice: its first 20 hex digits, in
/// groups of four ("1a2b 3c4d 5e6f 7a8b 9c0d").
[[nodiscard]] std::string ledger_fingerprint(const protocol::Id& ledger);

/// Issues an API token for the peer `name` (scope peer) on the ledger at
/// `dir`; the token, which is shown once. Throws if a token has that name.
/// The command line takes the ledger's lock; the node's own console, whose
/// node holds it, passes `locked` false and writes the file itself (the node
/// reloads its tokens).
[[nodiscard]] std::string issue_peer_token(const std::filesystem::path& dir,
                                           const std::string& name,
                                           const crypto::Provider& provider,
                                           ledger::Entropy& entropy, ledger::Clock& clock,
                                           bool locked = true);

/// Accepts an invitation as the peer `name` of the ledger at `dir`: its
/// token kept in `token_dir/NAME.token` (owner-only), the peer added with
/// its ledger and URL. Throws if the code is not one, or the name is taken.
/// `own` is this ledger's id when the caller knows it (the node's console);
/// otherwise the ledger is opened to learn it.
node::Peer accept_invitation(const std::filesystem::path& dir,
                             const std::filesystem::path& token_dir, const std::string& name,
                             const PeerInvitation& invitation,
                             const std::optional<protocol::Id>& own = std::nullopt);

} // namespace cexchain::app
