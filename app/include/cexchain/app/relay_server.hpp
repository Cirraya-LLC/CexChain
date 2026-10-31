// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <cexchain/app/relay.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/id_map.hpp>
#include <cexchain/node/http.hpp>
#include <cexchain/node/server.hpp>

/// A relay (`serve --relay DIR`, beside a public witness): mailboxes for the
/// ledgers its witness follows, which it knows the log keys of (following
/// their rotations), so that it checks every signature without keys of its
/// own. Routes, with no token:
///   POST   /v1/relay/messages                 a message (relay.hpp), signed
///                                             by its sender's log key
///   GET    /v1/relay/messages?to=ID[&wait=S]  the mailbox, oldest first, as
///                                             a CBOR array of messages; a
///                                             long poll with wait (<= 25 s)
///   DELETE /v1/relay/messages/ID?to=LEDGER    taken
/// The last two need "Authorization: CexChain-Relay ..." by the mailbox's
/// ledger (relay.hpp). Messages are kept 14 days at most.
namespace cexchain::app {

struct RelayLimits {
    std::size_t mailbox_messages = 1'000;
    std::uint64_t mailbox_bytes = std::uint64_t{64} << 20;
    std::size_t sender_messages_per_day = 2'000;
    std::uint64_t sender_bytes_per_day = std::uint64_t{256} << 20;
    protocol::Timestamp keep = 14 * 24 * 60 * 60'000;
    /// The longest long poll.
    protocol::Timestamp max_wait = 25'000;
};

class Relay {
public:
    using Respond = node::Application::Respond;

    /// `dir` holds the mailboxes (made if missing); `witness_dir` is the
    /// public witness's state directory.
    Relay(std::filesystem::path dir, std::filesystem::path witness_dir, RelayLimits limits);

    /// Answers a relay route now or, for a long poll, later; false for
    /// another path.
    bool handle(const node::http::Request& request, protocol::Timestamp now, Respond respond);
    /// Answers the long polls whose wait is over, and drops old messages.
    void tick(protocol::Timestamp now);
    /// Answers every long poll now.
    void stopping();

    /// The messages waiting in a ledger's mailbox, and their size.
    [[nodiscard]] std::pair<std::size_t, std::uint64_t> mailbox(const protocol::Id& ledger) const;

private:
    struct Waiting {
        protocol::Id ledger;
        protocol::Timestamp until = 0;
        Respond respond;
    };

    [[nodiscard]] node::http::Response post(ByteView body, protocol::Timestamp now);
    /// The mailbox's messages as an answer, at most max_relay_message of them
    /// together (always at least one).
    [[nodiscard]] node::http::Response listing(const protocol::Id& ledger) const;
    /// The fetcher's ledger, once its signature and time are checked; or the
    /// refusal.
    [[nodiscard]] std::variant<protocol::Id, node::http::Response>
    fetcher(const node::http::Request& request, protocol::Timestamp now) const;
    [[nodiscard]] std::filesystem::path box(const protocol::Id& ledger) const;
    void prune(const protocol::Id& ledger, protocol::Timestamp now) const;

    std::filesystem::path dir_;
    std::filesystem::path witness_dir_;
    RelayLimits limits_;
    mutable std::mutex mutex_;
    std::vector<Waiting> waiting_;
    /// Per sender: the day and what it sent that day.
    std::map<protocol::IdKey, std::pair<std::uint64_t, std::pair<std::size_t, std::uint64_t>>>
        sent_;
    protocol::Timestamp pruned_ = 0;
};

} // namespace cexchain::app
