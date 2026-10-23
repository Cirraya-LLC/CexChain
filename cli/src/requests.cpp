// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "requests.hpp"

#include <format>
#include <print>
#include <variant>

namespace cexchain::cli {

namespace {

/// Who signed the statement: its actor.
protocol::Id signer_of(const protocol::SignedStatement& s) {
    return *s.statement.actor_id;
}

const protocol::ContractCallBody& call_of(const protocol::SignedStatement& s) {
    return std::get<protocol::ContractCallBody>(s.statement.body);
}

} // namespace

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

std::string request_line(const app::Session& session, const protocol::RequestState& r,
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

void print_request(const app::Session& session, const protocol::RequestState& r,
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

NewActorKey new_actor_key(const Args& args, std::string_view whose) {
    if (args.has("key") == args.has("key-out")) {
        throw UsageError{"give --key (" + std::string(whose) +
                         " key file) or --key-out FILE (make one)"};
    }
    NewActorKey out;
    out.file = args.get("key-out");
    if (out.file) {
        if (std::filesystem::exists(*out.file)) {
            throw CommandError{*out.file + " already exists; keys are never overwritten"};
        }
        const auto made = unwrap(crypto::openssl::KeyPair::generate(
                                     parse_algorithm(args.get("alg").value_or("ed25519"))),
                                 "generating the key");
        save_key(*out.file, made, passphrase(args, *out.file, true));
        out.key = made.public_key();
    } else {
        if (args.has("alg")) {
            throw UsageError{"--alg goes with --key-out"};
        }
        out.key = public_key_of(args.need("key"), args);
    }
    return out;
}

std::optional<protocol::Timestamp> validity_end(const Args& args) {
    if (args.has("until") && args.has("days")) {
        throw UsageError{"give --until or --days, not both"};
    }
    if (const auto until = args.get("until")) {
        return parse_time(*until);
    }
    if (const auto days = args.get("days")) {
        return ledger::SystemClock{}.now() + parse_number(*days, "--days") * day_ms;
    }
    return std::nullopt;
}

} // namespace cexchain::cli
