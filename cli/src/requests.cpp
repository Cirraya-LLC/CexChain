// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "requests.hpp"

#include <algorithm>
#include <format>
#include <print>
#include <variant>

namespace cexchain::cli {

namespace {

Json optional_text(const std::optional<std::string>& text) {
    return text ? Json(*text) : Json(nullptr);
}

std::string encoded_hex(const cbor::Value& value) {
    return to_hex(unwrap(cbor::encode(value), "encoding a value"));
}

/// Who signed the statement at `index`: its actor.
protocol::Id signer_of(const protocol::SignedStatement& s) {
    return *s.statement.actor_id;
}

const protocol::ContractCallBody& call_of(const protocol::SignedStatement& s) {
    return std::get<protocol::ContractCallBody>(s.statement.body);
}

} // namespace

std::string request_status(const protocol::RequestState& request) {
    return request.status ? std::string(protocol::name(*request.status)) : std::string("open");
}

bool request_overdue(const protocol::RequestState& request, protocol::Timestamp now) {
    return request.open() && now >= request.deadline;
}

std::string duration_text(protocol::Timestamp ms) {
    const protocol::Timestamp s = ms / 1000;
    if (s >= 86'400) {
        return std::format("{} d {} h", s / 86'400, (s % 86'400) / 3600);
    }
    if (s >= 3600) {
        return std::format("{} h {} min", s / 3600, (s % 3600) / 60);
    }
    if (s >= 60) {
        return std::format("{} min", s / 60);
    }
    return std::format("{} s", s);
}

std::vector<const protocol::RequestState*>
select_requests(const Session& session, const RequestFilter& filter, protocol::Timestamp now) {
    using Which = RequestFilter::Which;
    std::vector<const protocol::RequestState*> out;
    for (const auto& [key, r] : session.state().requests()) {
        const bool failed = r.status && *r.status != protocol::AnswerStatus::done;
        if ((filter.which == Which::open && !r.open()) ||
            (filter.which == Which::answered && r.open()) ||
            (filter.which == Which::failed && !failed) ||
            (filter.which == Which::overdue && !request_overdue(r, now)) ||
            (!filter.kinds.empty() && !std::ranges::contains(filter.kinds, r.kind)) ||
            (filter.instance && !(r.instance == *filter.instance)) ||
            (filter.since && std::max(r.asked_at, r.status ? r.answered_at : 0) < *filter.since)) {
            continue;
        }
        if (filter.contract) {
            const protocol::InstanceState* i = session.state().instance(r.instance);
            if (i == nullptr || !(i->contract == *filter.contract)) {
                continue;
            }
        }
        if (filter.answered_by) {
            if (!r.answered_by ||
                signer_of(session.statement(*r.answered_by)) != *filter.answered_by) {
                continue;
            }
        }
        out.push_back(&r);
    }
    return out;
}

Json request_json(const Session& session, const protocol::RequestState& r,
                  protocol::Timestamp now) {
    const protocol::InstanceState* i = session.state().instance(r.instance);
    const protocol::ContractState* c =
        i != nullptr ? session.state().contract(i->contract) : nullptr;
    const protocol::SignedStatement asked = session.statement(r.call);
    Json answer = nullptr;
    if (r.answered_by) {
        const protocol::SignedStatement s = session.statement(*r.answered_by);
        const protocol::ActorState* actor = session.state().actor(signer_of(s));
        const protocol::ContractCallBody& call = call_of(s);
        answer = {{"index", *r.answered_by},
                  {"statement_id", id_json(s.id)},
                  {"registered_at", iso_time(r.answered_at)},
                  {"status", request_status(r)},
                  {"by", actor_ref(session, signer_of(s))},
                  {"kind", actor != nullptr ? Json(kind_text(actor->kind)) : Json(nullptr)},
                  {"delegation",
                   s.statement.delegation_id ? id_json(*s.statement.delegation_id) : Json(nullptr)},
                  {"model", s.statement.provenance ? optional_text(s.statement.provenance->model)
                                                   : Json(nullptr)},
                  {"presence", s.statement.presence.has_value()},
                  {"late", r.late_by() > 0},
                  {"late_by_ms", r.late_by()},
                  {"arguments", cbor::diagnostic(call.arguments)},
                  {"arguments_cbor", encoded_hex(call.arguments)},
                  {"reference", optional_text(call.reference)}};
    }
    return {{"id", id_json(r.id)},
            {"kind", r.kind},
            {"status", request_status(r)},
            {"overdue", request_overdue(r, now)},
            {"instance", id_json(r.instance)},
            {"contract", i != nullptr ? id_json(i->contract) : Json(nullptr)},
            {"contract_name", c != nullptr ? optional_text(c->name) : Json(nullptr)},
            {"params", cbor::diagnostic(r.params)},
            {"params_cbor", encoded_hex(r.params)},
            {"deadline", iso_time(r.deadline)},
            {"reply", r.reply},
            {"asked_at", iso_time(r.asked_at)},
            {"asked_by",
             {{"index", r.call},
              {"position", r.position},
              {"statement_id", id_json(asked.id)},
              {"function", call_of(asked).function},
              {"by", actor_ref(session, signer_of(asked))}}},
            {"answer", std::move(answer)}};
}

std::string request_line(const Session& session, const protocol::RequestState& r,
                         protocol::Timestamp now) {
    std::string out = std::format("{}  {:<16} {:<8} instance {}  due {}", short_id(r.id), r.kind,
                                  request_status(r), short_id(r.instance), format_time(r.deadline));
    if (request_overdue(r, now)) {
        out += "  OVERDUE";
    }
    if (r.answered_by) {
        out += std::format("  answered #{} by \"{}\"", *r.answered_by,
                           session.actor_name(signer_of(session.statement(*r.answered_by))));
        if (r.late_by() > 0) {
            out += ", late by " + duration_text(r.late_by());
        }
    }
    return out;
}

void print_request(const Session& session, const protocol::RequestState& r,
                   protocol::Timestamp now) {
    const protocol::InstanceState* i = session.state().instance(r.instance);
    const protocol::SignedStatement asked = session.statement(r.call);
    std::println("request:    {}", hex_id(r.id));
    std::println("kind:       {}", r.kind);
    std::println("status:     {}{}", request_status(r),
                 request_overdue(r, now) ? " - OVERDUE: its deadline has passed" : "");
    std::println("instance:   {}{}", hex_id(r.instance),
                 i != nullptr ? ", contract " + contract_label(session, i->contract) : "");
    std::println("asked:      by call #{} ({}, request {} of it), {}, signed by \"{}\"", r.call,
                 call_of(asked).function, r.position, format_time(r.asked_at),
                 session.actor_name(signer_of(asked)));
    std::println("params:     {}", cbor::diagnostic(r.params));
    const std::string when = r.open()
                                 ? (now >= r.deadline ? duration_text(now - r.deadline) + " ago"
                                                      : "in " + duration_text(r.deadline - now))
                                 : std::string();
    std::println("deadline:   {}{}", format_time(r.deadline),
                 when.empty() ? "" : " (" + when + ")");
    std::println("reply:      {} (the function an answer calls)", r.reply);
    if (!r.answered_by) {
        std::println("answer:     none yet (request answer {} --done, --failed, or --expired)",
                     short_id(r.id));
        return;
    }
    const protocol::SignedStatement s = session.statement(*r.answered_by);
    const protocol::ActorState* actor = session.state().actor(signer_of(s));
    std::string who = std::format("\"{}\" ({})", session.actor_name(signer_of(s)),
                                  actor != nullptr ? kind_label(actor->kind) : "unknown");
    if (s.statement.provenance && s.statement.provenance->model) {
        who += ", model " + *s.statement.provenance->model;
    }
    if (s.statement.presence) {
        who += ", present";
    }
    std::println("answer:     {} by entry #{}, {}, by {}", request_status(r), *r.answered_by,
                 format_time(r.answered_at), who);
    if (s.statement.delegation_id) {
        std::println("            under delegation {}", hex_id(*s.statement.delegation_id));
    }
    std::println("            {}", r.late_by() > 0 ? "LATE by " + duration_text(r.late_by())
                                                   : std::string("on time"));
    std::println("arguments:  {}", cbor::diagnostic(call_of(s).arguments));
}

std::vector<std::string> parse_request_kinds(std::string_view list, std::string_view what) {
    std::vector<std::string> kinds;
    for (const std::string& kind : split(std::string(list), ',')) {
        if (!protocol::is_request_kind(kind)) {
            throw UsageError{std::string(what) + ": \"" + kind +
                             "\" is not a request kind (1 to 64 lowercase letters, digits, '.', "
                             "'_', or '-', starting with a letter)"};
        }
        kinds.push_back(kind);
    }
    if (kinds.empty()) {
        throw UsageError{std::string(what) + " names at least one request kind"};
    }
    std::ranges::sort(kinds);
    kinds.erase(std::ranges::unique(kinds).begin(), kinds.end());
    return kinds;
}

std::optional<protocol::AnswerStatus> parse_answer_status(std::string_view text) {
    for (const auto status : {protocol::AnswerStatus::done, protocol::AnswerStatus::failed,
                              protocol::AnswerStatus::expired}) {
        if (protocol::name(status) == text) {
            return status;
        }
    }
    return std::nullopt;
}

cbor::Value answer_arguments(std::optional<cbor::Value> arguments,
                             const std::optional<std::string>& reason) {
    cbor::Value value = arguments ? std::move(*arguments) : cbor::Value::null();
    if (reason) {
        if (!protocol::is_request_kind(*reason)) {
            throw UsageError{"a reason is a code, written like a request kind (such as "
                             "cancelled or unavailable), never an outside system's text"};
        }
        cbor::Map entries;
        if (!value.is_null()) {
            if (value.as_map() == nullptr || value.find("reason") != nullptr) {
                throw UsageError{"with a reason, the arguments are a map without \"reason\""};
            }
            entries = *value.as_map();
        }
        entries.push_back({cbor::Value::text("reason"), cbor::Value::text(*reason)});
        value = cbor::Value::map(std::move(entries));
    }
    check_contract_arguments(value);
    return value;
}

protocol::ContractCallBody answer_call(const Session& session, const protocol::RequestState& r,
                                       protocol::AnswerStatus status, cbor::Value arguments,
                                       protocol::Timestamp now) {
    if (!r.open()) {
        throw CommandError{std::format(
            "request {} is answered already ({}, by entry #{}): a request takes one answer",
            short_id(r.id), request_status(r), r.answered_by.value_or(0))};
    }
    if (status == protocol::AnswerStatus::expired && now < r.deadline) {
        throw CommandError{std::format("request {} is due {}: it can expire only from then",
                                       short_id(r.id), format_time(r.deadline))};
    }
    const protocol::InstanceState& i = *session.state().instance(r.instance);
    protocol::ContractCallBody body;
    body.instance = r.instance;
    body.head = i.head;
    body.function = r.reply;
    body.arguments = std::move(arguments);
    body.answer = protocol::ContractAnswer{r.id, status};
    return body;
}

protocol::Timestamp answer_time(const CallOptions& options) {
    return options.dry_run && options.at ? *options.at : ledger::SystemClock{}.now();
}

CallAttempt attempt_answer(Session& session, const crypto::Signer& signer,
                           protocol::ContractCallBody answer, const CallOptions& options) {
    CallAttempt attempt = attempt_call(session, signer, std::move(answer), {}, options);
    // A dry run answers as the ledger would: its rules for answers (the
    // request open, the reply, an expiry not early) and the signer's
    // authority, checked now. (At another time, --at, only the contract's.)
    if (options.dry_run && !options.at && attempt.run.accepted() != nullptr && !attempt.refused) {
        if (const Status s = session.state().validate(session.provider(), attempt.statement,
                                                      answer_time(options));
            !s) {
            attempt.refused = "the ledger refuses the answer: " + std::string(s.error().detail);
        }
    }
    return attempt;
}

} // namespace cexchain::cli
