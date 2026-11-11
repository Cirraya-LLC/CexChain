// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/ledger/ledger.hpp>
#include <kanhe/node/http.hpp>
#include <kanhe/node/peers.hpp>

/// Reaching parties through relays (relay.hpp), and being reached through
/// one, as the command line, serve, and the console share it.
namespace kanhe::client {

/// This ledger as it reaches parties through their relays: the ledger (its
/// id; its genesis entry and checkpoints, to register with a relay's
/// witness when the relay does not know it yet), its log key, which signs
/// what it sends, and where a cosignature that registration gives is kept
/// (may be empty). Each is asked for when needed (a console may be locked,
/// or not set up yet: then nothing).
struct RelaySender {
    std::function<const ledger::Ledger*()> ledger;
    std::function<std::shared_ptr<const crypto::Signer>()> log_key;
    std::function<void(ByteView cosignature, const crypto::PublicKey& witness)> keep;
};

/// Makes `sender` the one peer_request uses on this thread while it lives
/// (for calls made deep inside other actions).
class RelaySenderScope {
public:
    explicit RelaySenderScope(const RelaySender* sender);
    RelaySenderScope(const RelaySenderScope&) = delete;
    RelaySenderScope& operator=(const RelaySenderScope&) = delete;
    ~RelaySenderScope();

private:
    const RelaySender* previous_;
};

/// A request to `peer`'s API with the token it issued us: directly when it
/// has a URL, otherwise through its relay as `sender` (or the scope's),
/// waiting up to `wait` for the answer. Throws ActionError if the peer
/// cannot be reached, or if it has only a relay and there is no sender.
[[nodiscard]] node::http::ClientResponse
peer_request(const node::Peer& peer, std::string_view method, const std::string& path,
             ByteView body = {}, std::string_view content_type = {},
             const RelaySender* sender = nullptr,
             std::chrono::seconds wait = std::chrono::seconds(30));

/// This ledger's own relay, if it is reached through one: relay.json in its
/// directory, {"url", "key": hex public relay key, "witness": hex COSE key
/// of the relay's witness}. The private relay key is kept apart (a key
/// file for serve, the console's key store).
inline constexpr std::string_view relay_file = "relay.json";
[[nodiscard]] std::optional<node::RelayRoute> load_own_relay(const std::filesystem::path& dir);
void save_own_relay(const std::filesystem::path& dir, const std::optional<node::RelayRoute>& route);

/// What this ledger's mailbox holds at its relay (signed fetch, no wait).
struct MailboxView {
    std::size_t requests = 0;
    std::size_t answers = 0;
};
[[nodiscard]] MailboxView look_at_mailbox(const node::RelayRoute& own, const protocol::Id& ledger,
                                          const crypto::Signer& log_key);

/// Answers the requests in this ledger's mailbox at its relay with its own
/// API, as if they had come directly (the peer token in each decides), and
/// sends each answer back through the relay.
class RelayAgent {
public:
    /// The ledger's own API: a request in, its answer through the callback.
    using Api = std::function<void(node::http::Request, std::function<void(node::http::Response)>)>;
    using LogKey = std::function<std::shared_ptr<const crypto::Signer>()>;

    RelayAgent(node::RelayRoute own, std::shared_ptr<const crypto::openssl::HpkeKey> relay_key,
               protocol::Id ledger, LogKey log_key, Api api);

    /// One round: fetches the requests (a long poll of up to `wait`) and
    /// answers each. Returns how many it answered; throws ActionError if the
    /// relay cannot be reached or refuses.
    std::size_t once(std::chrono::seconds wait);
    /// Rounds until `stop`, saying what goes wrong (and "" once it works
    /// again) through `report`; after a failure, again 5 s later.
    void run(const std::stop_token& stop, const std::function<void(const std::string&)>& report);

private:
    node::RelayRoute own_;
    std::shared_ptr<const crypto::openssl::HpkeKey> relay_key_;
    protocol::Id ledger_;
    LogKey log_key_;
    Api api_;
    /// Requests answered, by id, so that one taken late is not answered twice.
    std::set<std::string> answered_;
};

} // namespace kanhe::client
