// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/state.hpp>

#include "contracts.hpp"
#include "output.hpp"
#include "support.hpp"

/// Requests and answers (spec v0.8, 6b): what the command line and the MCP
/// server share. A contract's accepted call may ask executors for work
/// outside the ledger; an executor, or a person by hand, answers with a call
/// on the instance that names the request and its status.
namespace cexchain::cli {

/// Which requests to show: by status (open, answered, failed or expired, or
/// open past their deadline), kind, contract, instance, who answered, and
/// since when (asked or answered).
struct RequestFilter {
    enum class Which : std::uint8_t { all, open, answered, failed, overdue };
    Which which = Which::all;
    std::vector<std::string> kinds;
    std::optional<protocol::Id> contract;
    std::optional<protocol::Id> instance;
    std::optional<protocol::Id> answered_by;
    std::optional<protocol::Timestamp> since;
};

/// "open", or the answer's status ("done", "failed", "expired").
[[nodiscard]] std::string request_status(const protocol::RequestState& request);
/// Open, and `now` has reached its deadline.
[[nodiscard]] bool request_overdue(const protocol::RequestState& request, protocol::Timestamp now);

/// The ledger's requests that `filter` selects, in the order they were made.
[[nodiscard]] std::vector<const protocol::RequestState*>
select_requests(const Session& session, const RequestFilter& filter, protocol::Timestamp now);

/// A request for scripts: its kind, params, deadline, and reply; the call
/// that made it, with who signed it; its status, overdue by `now`; and its
/// answer: who gave it (actor, kind, delegation, model, presence), when, how
/// late, and its arguments.
[[nodiscard]] Json request_json(const Session& session, const protocol::RequestState& request,
                                protocol::Timestamp now);
/// The same, for people.
void print_request(const Session& session, const protocol::RequestState& request,
                   protocol::Timestamp now);
/// One line for a list.
[[nodiscard]] std::string request_line(const Session& session,
                                       const protocol::RequestState& request,
                                       protocol::Timestamp now);
/// A duration for people: "2 d 3 h", "45 min", "12 s".
[[nodiscard]] std::string duration_text(protocol::Timestamp ms);

/// A comma-separated list of request kinds, each checked (`what` names the
/// option), sorted, each once.
[[nodiscard]] std::vector<std::string> parse_request_kinds(std::string_view list,
                                                           std::string_view what);
/// "done", "failed", or "expired".
[[nodiscard]] std::optional<protocol::AnswerStatus> parse_answer_status(std::string_view text);

/// An answer's arguments: `arguments` (default null) with, if `reason` is
/// given, the reason code under "reason" (the arguments must then be null
/// or a map without it). A reason code is written like a request kind.
[[nodiscard]] cbor::Value answer_arguments(std::optional<cbor::Value> arguments,
                                           const std::optional<std::string>& reason);

/// The call answering `request` with `status`: on its instance at its head,
/// calling its reply. Throws, with the ledger's reasons in words, if the
/// request is answered already or an expiry is early at `now`.
[[nodiscard]] protocol::ContractCallBody
answer_call(const Session& session, const protocol::RequestState& request,
            protocol::AnswerStatus status, cbor::Value arguments, protocol::Timestamp now);

/// When an answer made with `options` runs: a dry run's --at, or now.
[[nodiscard]] protocol::Timestamp answer_time(const CallOptions& options);

/// Records an answer (from `answer_call`) as `attempt_call` records any
/// call: the contract runs here first, and a dry run reports what the ledger
/// would decide, its own rules for answers included.
[[nodiscard]] CallAttempt attempt_answer(Session& session, const crypto::Signer& signer,
                                         protocol::ContractCallBody answer,
                                         const CallOptions& options);

} // namespace cexchain::cli
