// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cctype>

#include <cexchain/app/peers.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/node/tokens.hpp>

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

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

namespace {

constexpr std::string_view invitation_prefix = "cxp_";

bool printable(std::string_view text) {
    return std::ranges::all_of(text, [](unsigned char c) { return c >= 0x21 && c < 0x7f; });
}

} // namespace

std::string encode_invitation(const PeerInvitation& i) {
    cbor::Map map{{cbor::Value::integer(1), cbor::Value::integer(1)},
                  {cbor::Value::integer(2), cbor::Value::bytes(i.ledger.bytes())},
                  {cbor::Value::integer(3), cbor::Value::text(i.organization)}};
    if (i.url) {
        map.push_back({cbor::Value::integer(4), cbor::Value::text(*i.url)});
    }
    if (i.token) {
        map.push_back({cbor::Value::integer(5), cbor::Value::text(*i.token)});
    }
    if (i.witness) {
        map.push_back({cbor::Value::integer(6), protocol::encode_public_key(*i.witness)});
    }
    const Bytes encoded = unwrap(cbor::encode(cbor::Value::map(std::move(map))), "the invitation");
    return std::string(invitation_prefix) + to_base64url(encoded);
}

std::optional<PeerInvitation> decode_invitation(std::string_view code) {
    while (!code.empty() && std::isspace(static_cast<unsigned char>(code.back())) != 0) {
        code.remove_suffix(1);
    }
    while (!code.empty() && std::isspace(static_cast<unsigned char>(code.front())) != 0) {
        code.remove_prefix(1);
    }
    if (code.size() > max_invitation_code || !code.starts_with(invitation_prefix)) {
        return std::nullopt;
    }
    const auto bytes = from_base64url(code.substr(invitation_prefix.size()));
    if (!bytes) {
        return std::nullopt;
    }
    const auto value = cbor::decode(*bytes);
    const cbor::Map* map = value ? value->as_map() : nullptr;
    if (map == nullptr) {
        return std::nullopt;
    }
    PeerInvitation out;
    bool version = false;
    bool ledger = false;
    bool organization = false;
    for (const cbor::MapEntry& e : *map) {
        const auto key = e.key.as_int64();
        if (!key) {
            return std::nullopt;
        }
        const std::string* text = e.value.as_text();
        if (*key == 1) {
            version = e.value.as_int64() == std::optional<std::int64_t>(1);
        } else if (*key == 2) {
            const Bytes* id = e.value.as_bytes();
            if (id == nullptr) {
                return std::nullopt;
            }
            const auto parsed = protocol::to_id(*id);
            if (!parsed) {
                return std::nullopt;
            }
            out.ledger = *parsed;
            ledger = true;
        } else if (*key == 3 && text != nullptr && !text->empty() && text->size() <= 128) {
            out.organization = *text;
            organization = true;
        } else if (*key == 4 && text != nullptr && !text->empty() && text->size() <= 2048 &&
                   printable(*text)) {
            out.url = *text;
        } else if (*key == 5 && text != nullptr && !text->empty() && text->size() <= 256 &&
                   printable(*text)) {
            out.token = *text;
        } else if (*key == 6) {
            auto witness = protocol::decode_public_key(e.value);
            if (!witness) {
                return std::nullopt;
            }
            out.witness = std::move(*witness);
        } else {
            return std::nullopt;
        }
    }
    if (!version || !ledger || !organization) {
        return std::nullopt;
    }
    return out;
}

std::string ledger_fingerprint(const protocol::Id& ledger) {
    const std::string hex = to_hex(ledger.bytes()).substr(0, 20);
    std::string out;
    for (std::size_t i = 0; i < hex.size(); i += 4) {
        out += (out.empty() ? "" : " ") + hex.substr(i, 4);
    }
    return out;
}

std::string issue_peer_token(const std::filesystem::path& dir, const std::string& name,
                             const crypto::Provider& provider, ledger::Entropy& entropy,
                             ledger::Clock& clock, bool locked) {
    if (!node::valid_token_name(name)) {
        throw UsageError{"a party's name is 1-64 letters, digits, '.', '_', or '-'"};
    }
    std::optional<ledger::DirectoryLock> lock;
    if (locked) {
        lock.emplace(unwrap(ledger::DirectoryLock::acquire(dir), "locking the ledger"));
    }
    auto tokens = unwrap(node::load_tokens(dir), "reading the API tokens");
    if (std::ranges::any_of(tokens, [&](const node::ApiToken& t) { return t.name == name; })) {
        throw ActionError{"a token named " + name + " exists; revoke it first"};
    }
    const std::string token = node::generate_token(entropy);
    tokens.push_back({name, static_cast<node::Scopes>(node::Scope::peer),
                      node::token_hash(provider, token), clock.now()});
    unwrap(node::save_tokens(dir, tokens), "saving the API tokens");
    return token;
}

node::Peer accept_invitation(const std::filesystem::path& dir,
                             const std::filesystem::path& token_dir, const std::string& name,
                             const PeerInvitation& invitation,
                             const std::optional<protocol::Id>& own) {
    if (!node::valid_token_name(name)) {
        throw UsageError{"a party's name is 1-64 letters, digits, '.', '_', or '-'"};
    }
    node::Peer peer;
    peer.name = name;
    peer.ledger_id = invitation.ledger;
    peer.url = invitation.url;
    peer.witness_key = invitation.witness;
    peer.added = ledger::SystemClock{}.now();
    if (own) {
        // The node's console knows its ledger: the peers file only.
        if (peer.ledger_id == *own) {
            throw UsageError{"a ledger cannot be its own peer"};
        }
        if (std::ranges::any_of(peers_of(dir), [&](const node::Peer& p) {
                return p.name == peer.name || p.ledger_id == peer.ledger_id;
            })) {
            throw ActionError{"a peer with this name or ledger exists; remove it first"};
        }
    }
    if (invitation.token) {
        std::filesystem::create_directories(token_dir);
        const std::filesystem::path file = token_dir / (name + ".token");
        write_file(file, as_bytes(*invitation.token + "\n"), true);
        peer.token_file = file.string();
    }
    if (own) {
        auto peers = peers_of(dir);
        peers.push_back(peer);
        unwrap(node::save_peers(dir, peers), "saving the peers");
    } else {
        add_peer(dir, peer);
    }
    return peer;
}

} // namespace cexchain::app
