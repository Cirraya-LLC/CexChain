// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

#include <cexchain/app/peers.hpp>
#include <cexchain/ledger/environment.hpp>

namespace cexchain::app {

std::vector<node::Peer> peers_of(const std::filesystem::path& dir) {
    return unwrap(node::load_peers(dir), "reading the peers");
}

node::Peer peer_named(const std::filesystem::path& dir, const std::string& name) {
    for (node::Peer& p : unwrap(node::load_peers(dir), "reading the peers")) {
        if (p.name == name) {
            return p;
        }
    }
    throw ActionError{"no peer named " + name + " (cexchain peer add)"};
}

node::Client peer_client(const node::Peer& peer) {
    if (!peer.url) {
        throw ActionError{"peer " + peer.name + " has no API URL (cexchain peer add --url)"};
    }
    node::ClientOptions options;
    if (peer.token_file) {
        const Bytes token = read_file(*peer.token_file);
        std::string text(token.begin(), token.end());
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
            text.pop_back();
        }
        options.bearer_token = text;
    }
    if (peer.ca_file) {
        options.ca_file = *peer.ca_file;
    }
    return node::Client(unwrap(node::Url::parse(*peer.url), "the peer's URL"), options);
}

Json peer_call(const node::Peer& peer, std::string_view method, const std::string& path,
               ByteView body) {
    const auto response = unwrap(peer_client(peer).request(method, path, body, "application/cbor"),
                                 "reaching peer " + peer.name);
    const Json answer = Json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (response.status / 100 != 2) {
        std::string message = "status " + std::to_string(response.status);
        if (answer.is_object() && answer.contains("error") && answer["error"].is_object()) {
            message = answer["error"].value("message", message);
        }
        throw ActionError{"peer " + peer.name + " refused: " + message};
    }
    return answer;
}

protocol::Id full_id(std::string_view text, std::string_view what) {
    const auto bytes = from_hex(text);
    if (!bytes || bytes->size() != protocol::id_size) {
        throw UsageError{std::string(what) + " must be a full id (64 hex digits)"};
    }
    return *protocol::to_id(*bytes);
}

protocol::Id ledger_of(const Session& session, std::string_view text) {
    if (text.size() == 2 * protocol::id_size) {
        if (const auto bytes = from_hex(text)) {
            return *protocol::to_id(*bytes);
        }
    }
    if (session.remote()) {
        throw UsageError{"with --server, name ledgers by their full id"};
    }
    return peer_named(session.directory(), std::string(text)).ledger_id;
}

std::string ledger_label(const Session& session, const protocol::Id& ledger) {
    if (!session.remote()) {
        if (const auto peers = node::load_peers(session.directory())) {
            for (const node::Peer& p : *peers) {
                if (p.ledger_id == ledger) {
                    return p.name + " (" + short_id(ledger) + ")";
                }
            }
        }
    }
    if (ledger == session.state().ledger_id()) {
        return session.state().organization() + " (this ledger, " + short_id(ledger) + ")";
    }
    return "ledger " + short_id(ledger);
}

Json peer_json(const node::Peer& p) {
    return {{"name", p.name},
            {"ledger_id", id_json(p.ledger_id)},
            {"url", p.url ? Json(*p.url) : Json(nullptr)},
            {"token_file", p.token_file ? Json(*p.token_file) : Json(nullptr)},
            {"ca_file", p.ca_file ? Json(*p.ca_file) : Json(nullptr)},
            {"witness_key", p.witness_key ? public_key_json(*p.witness_key) : Json(nullptr)},
            {"added", format_time(p.added)}};
}

void add_peer(const std::filesystem::path& dir, const node::Peer& peer) {
    Session session(dir);
    if (peer.ledger_id == session.ledger().id()) {
        throw UsageError{"a ledger cannot be its own peer"};
    }
    auto peers = peers_of(dir);
    if (std::ranges::any_of(peers, [&](const node::Peer& p) {
            return p.name == peer.name || p.ledger_id == peer.ledger_id;
        })) {
        throw ActionError{"a peer with this name or ledger exists; remove it first"};
    }
    peers.push_back(peer);
    unwrap(node::save_peers(dir, peers), "saving the peers");
}

void remove_peer(const std::filesystem::path& dir, const std::string& name) {
    auto peers = peers_of(dir);
    if (std::erase_if(peers, [&](const node::Peer& p) { return p.name == name; }) == 0) {
        throw ActionError{"no peer named " + name};
    }
    unwrap(node::save_peers(dir, peers), "saving the peers");
}

} // namespace cexchain::app
