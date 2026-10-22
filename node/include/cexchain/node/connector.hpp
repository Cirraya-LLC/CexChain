// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

/// The connector protocol (spec/connectors.md, informative): how an
/// executor's runtime and a connector, the program that speaks one outside
/// system's API, talk. The connector is a child process of the runtime; they
/// exchange JSON objects, one per line, over the child's stdin and stdout.
/// The runtime does everything on the ledger's side (finding requests,
/// verifying them in evidence, the journal, signing and submitting answers);
/// the connector acts, and never sees the signing key.
///
///   runtime -> connector: hello, perform, cancel, stop
///   connector -> runtime: ready, outcome, log
///
/// Numbers are integers: a JSON number with a fraction or an exponent is
/// refused, so amounts travel in minor units. CBOR params reach the
/// connector as JSON (byte strings as hex text) and as hex CBOR; a result
/// comes back as JSON and becomes CBOR.
namespace cexchain::node::connector {

inline constexpr std::uint64_t protocol_version = 1;
/// A line is at most 1 MiB, its newline included.
inline constexpr std::size_t max_line = 1024 * 1024;
/// A result is at most 16 KiB of CBOR (an answer's arguments, at most 64
/// KiB, also carry the reason and the response's digest).
inline constexpr std::size_t max_result = 16 * 1024;
/// An outside system's response, kept in the journal: at most 512 KiB.
inline constexpr std::size_t max_response = 512 * 1024;
/// A log message: at most 1,024 bytes.
inline constexpr std::size_t max_log_message = 1024;
/// Names (a connector's, a secret's): 1 to 64 letters, digits, '.', '-',
/// or '_'.
[[nodiscard]] bool is_name(std::string_view text) noexcept;

/// A secret's value: held in memory that is wiped, and never formatted.
struct Secret {
    SecureBytes value;
};

/// The runtime's first message: the connector's name and configuration
/// (from the executor's config, without secrets), and the secrets the
/// configuration names, unsealed (only here: never in argv, the
/// environment, the config, a log, or the journal).
struct Hello {
    std::uint64_t protocol = protocol_version;
    std::string connector;
    /// A JSON object, as text.
    std::string config = "{}";
    std::map<std::string, Secret> secrets;
};

/// Carry out a request. `request` is the idempotency key: the same request
/// may be performed again (a retry, or after the runtime restarts), and the
/// outside system must act once.
struct Perform {
    protocol::Id request;
    std::string kind;
    cbor::Value params;
    protocol::Timestamp deadline = 0;
    protocol::Timestamp asked_at = 0;
    protocol::Id home;
    protocol::Id contract;
    protocol::Id instance;
    std::string reply;
    /// 1 for the first attempt.
    std::uint32_t attempt = 1;
    /// How long the runtime waits for the outcome.
    std::uint64_t timeout_ms = 0;
};

/// Stop working on a request: it was answered elsewhere, or expired.
struct Cancel {
    protocol::Id request;
    std::string reason;
};

/// Finish the current work and exit.
struct Stop {};

using ToConnector = std::variant<Hello, Perform, Cancel, Stop>;

/// The connector's answer to hello. `kinds` empty: it serves any kind.
struct Ready {
    std::uint64_t protocol = protocol_version;
    std::string name;
    std::string version;
    std::vector<std::string> kinds;
};

enum class OutcomeStatus : std::uint8_t { done, failed, retry };

/// How a request went. `retry`: a transient failure (a timeout, the outside
/// system busy or down); the runtime tries again later, until the deadline.
struct Outcome {
    protocol::Id request;
    OutcomeStatus status = OutcomeStatus::done;
    /// What the answer carries (only external ids, statuses, amounts, codes;
    /// never personal data, secrets, or raw error texts). At most
    /// max_result bytes of CBOR.
    std::optional<cbor::Value> result;
    /// A code written like a request kind ("rejected", "unavailable").
    std::optional<std::string> reason;
    /// The outside system's response: kept in the journal; the answer
    /// carries only its salted digest.
    std::optional<Bytes> response;
    /// For retry: wait at least this long.
    std::optional<std::uint64_t> retry_after_ms;
};

enum class LogLevel : std::uint8_t { debug, info, warn, error };

/// A line for the runtime's log (never secrets).
struct Log {
    LogLevel level = LogLevel::info;
    std::string message;
    std::optional<protocol::Id> request;
};

using FromConnector = std::variant<Ready, Outcome, Log>;

/// One line, ending in a newline.
[[nodiscard]] std::string encode(const ToConnector& message);
[[nodiscard]] std::string encode(const FromConnector& message);

/// Decodes one line (with or without its newline). Errc::unsupported for a
/// message of an unknown type (a later protocol's: skip it); anything else
/// that is not a message of this protocol fails otherwise. Unknown fields
/// are ignored.
[[nodiscard]] Result<ToConnector> decode_to_connector(std::string_view line);
[[nodiscard]] Result<FromConnector> decode_from_connector(std::string_view line);

[[nodiscard]] std::string_view status_name(OutcomeStatus status) noexcept;
[[nodiscard]] std::string_view level_name(LogLevel level) noexcept;

/// CBOR as JSON text: maps with text keys as objects, byte strings as hex
/// text, integers within 64 bits. nullopt for anything else (tags, other
/// map keys).
[[nodiscard]] std::optional<std::string> cbor_to_json(const cbor::Value& value);
/// JSON text as CBOR: objects as maps, integers, text, arrays, booleans,
/// null. Fails on a fraction or exponent, or nesting past CBOR's limit.
[[nodiscard]] Result<cbor::Value> json_to_cbor(std::string_view text);

} // namespace cexchain::node::connector
