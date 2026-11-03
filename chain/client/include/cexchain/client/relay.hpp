// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cose.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/crypto/openssl.hpp>

/// A relay carries the peer API between nodes that cannot reach each other
/// (two laptops): a request to a party's /v1 API, with the peer token, goes
/// sealed into the party's mailbox; the party's node opens it, answers it
/// with its own API as if it had come directly, and the sealed answer goes
/// back. The relay learns who writes to whom, when, and how much; never
/// what, and nothing it says is trusted.
///
/// A message on the relay is a COSE_Sign1 by the sender's log key (external
/// data "CexChain relay message v1") over
///   {1: to (ledger id), 2: from (ledger id), 3: id (16 bytes),
///    4: [encapsulated key, ciphertext], ? 5: id of the request it answers,
///    6: until (ms since the epoch)}
/// A request is sealed (HPKE, info "CexChain relay request v1") to the
/// party's relay key:
///   {1: method, 2: path, 3: content type, 4: body, 5: bearer token,
///    6: answer key (X25519 public key)}
/// and its answer to the answer key, which only the sender holds the private
/// half of (info "CexChain relay answer v1"):
///   {1: status, 2: content type, 3: body}
/// Both bind the recipient's ledger id, the sender's, and the request's id
/// (associated data: to || from || id, the request's to and from).
namespace cexchain::app {

using RelayId = std::array<std::uint8_t, 16>;

inline constexpr std::size_t max_relay_message = std::size_t{17} << 20;
inline constexpr std::string_view relay_message_context = "CexChain relay message v1";
inline constexpr std::string_view relay_fetch_context = "CexChain relay fetch v1";
inline constexpr std::string_view relay_request_info = "CexChain relay request v1";
inline constexpr std::string_view relay_answer_info = "CexChain relay answer v1";
/// How far a fetch's time may be from the relay's.
inline constexpr protocol::Timestamp relay_fetch_skew = 5 * 60'000;

struct RelayEnvelope {
    protocol::Id to;
    protocol::Id from;
    RelayId id{};
    crypto::openssl::HpkeSealed sealed;
    std::optional<RelayId> answers;
    /// When the message is no use any more (ms since the epoch): the relay
    /// drops it then, and a request found later is never answered (a party
    /// offline for a day does not answer a day's polls when it comes back).
    protocol::Timestamp until = 0;
};

/// How long a request waits for its answer, at most.
inline constexpr protocol::Timestamp max_relay_wait = 10 * 60'000;

struct RelayRequest {
    std::string method;
    std::string path;
    std::string content_type;
    Bytes body;
    std::string token;
    Bytes answer_key;
};

struct RelayAnswer {
    int status = 0;
    std::string content_type;
    Bytes body;
};

/// A message for the relay, signed by `log_key` (the sender's).
[[nodiscard]] Result<Bytes> sign_relay_message(const crypto::Signer& log_key,
                                               const RelayEnvelope& envelope);

struct RelayMessage {
    RelayEnvelope envelope;
    cose::Sign1 signed_message;
};

/// Reads a message, at most max_relay_message; does not check its
/// signature (verify_relay_message does, with the sender's log key).
[[nodiscard]] Result<RelayMessage> parse_relay_message(ByteView message);
[[nodiscard]] Status verify_relay_message(const crypto::Provider& provider,
                                          const RelayMessage& message,
                                          const crypto::PublicKey& sender_log_key);

/// The request, sealed to the party's relay key (32 bytes, X25519).
[[nodiscard]] Result<crypto::openssl::HpkeSealed>
seal_relay_request(ByteView relay_key, const protocol::Id& to, const protocol::Id& from,
                   const RelayId& id, const RelayRequest& request);
[[nodiscard]] Result<RelayRequest> open_relay_request(const crypto::openssl::HpkeKey& relay_key,
                                                      const RelayEnvelope& envelope);
/// The answer to `request`, sealed to its answer key. `to` and `from` are
/// the request's.
[[nodiscard]] Result<crypto::openssl::HpkeSealed>
seal_relay_answer(const RelayRequest& request, const protocol::Id& to, const protocol::Id& from,
                  const RelayId& id, const RelayAnswer& answer);
/// Opens an answer with the answer key's private half; `to`, `from`, and
/// `id` are the request's.
[[nodiscard]] Result<RelayAnswer> open_relay_answer(const crypto::openssl::HpkeKey& answer_key,
                                                    const protocol::Id& to,
                                                    const protocol::Id& from, const RelayId& id,
                                                    const crypto::openssl::HpkeSealed& sealed);

/// A mailbox's owner proves it is that ledger to fetch or take its
/// messages: "Authorization: CexChain-Relay <base64url COSE_Sign1>", signed
/// by its log key (external data "CexChain relay fetch v1") over
/// {1: ledger id, 2: time (ms)}.
[[nodiscard]] Result<std::string> relay_authorization(const crypto::Signer& log_key,
                                                      const protocol::Id& ledger,
                                                      protocol::Timestamp now);

struct RelayFetcher {
    protocol::Id ledger;
    protocol::Timestamp at = 0;
    cose::Sign1 signed_message;
};

[[nodiscard]] Result<RelayFetcher> parse_relay_authorization(std::string_view header);
[[nodiscard]] Status verify_relay_fetcher(const crypto::Provider& provider,
                                          const RelayFetcher& fetcher,
                                          const crypto::PublicKey& log_key);

} // namespace cexchain::app
