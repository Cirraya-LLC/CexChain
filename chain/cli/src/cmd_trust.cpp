// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Trust nodes (spec v0.16). A trust node registers memberships: its word
// that another ledger belongs to the organization or person it names, as it
// checked them (trust member ...). A member lists the trust nodes it
// belongs to and fetches its proofs from them; the evidence it exports then
// carries them (trust node ...). A verifier names the trust nodes it
// believes (verify --trust-node).

#include <algorithm>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include <cexchain/client/records.hpp>
#include <cexchain/core/protocol/memberships.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/record_types.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/tokens.hpp>
#include <cexchain/node/trust.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

protocol::Id parse_ledger_id(const std::string& text) {
    const auto bytes = from_hex(text);
    const auto id =
        bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(std::unexpected(bytes.error()));
    if (!id) {
        throw UsageError{"a ledger id is its full 64 hex digits"};
    }
    return *id;
}

/// The memberships on the ledger: records of the type, with their metadata.
struct Listed {
    const protocol::RecordState* record;
    protocol::Membership membership;
};

std::vector<Listed> memberships(const client::Session& session) {
    std::vector<Listed> out;
    for (const auto& [key, record] : session.state().records()) {
        if (record.record_type != protocol::membership_type) {
            continue;
        }
        const auto body = client::registration_of(session, protocol::Id(record.id));
        if (auto m = body.metadata ? protocol::decode_membership(*body.metadata)
                                   : Result<protocol::Membership>(fail(Errc::malformed, "none"))) {
            out.push_back({&record, std::move(*m)});
        }
    }
    return out;
}

/// Where a membership stands now: revoked, lapsed, or its state.
std::string status_of(const Listed& m, protocol::Timestamp now) {
    if (m.record->revoked) {
        return "revoked";
    }
    if (m.membership.until && *m.membership.until < now) {
        return "lapsed";
    }
    return m.record->state;
}

Json membership_json(const Listed& m, protocol::Timestamp now) {
    const protocol::Membership& p = m.membership;
    return {{"membership", id_json(protocol::Id(m.record->id))},
            {"member", id_json(p.member)},
            {"kind", protocol::member_kind_name(p.kind)},
            {"name", p.name},
            {"verified", p.verified},
            {"registration", p.registration ? Json(*p.registration) : Json(nullptr)},
            {"jurisdiction", p.jurisdiction ? Json(*p.jurisdiction) : Json(nullptr)},
            {"until", p.until ? Json(format_time(*p.until)) : Json(nullptr)},
            {"status", status_of(m, now)}};
}

const Listed& membership_named(const std::vector<Listed>& all, const protocol::Id& id) {
    const auto found = std::ranges::find_if(
        all, [&](const Listed& m) { return protocol::Id(m.record->id) == id; });
    if (found == all.end()) {
        throw CommandError{"no membership " + hex_id(id)};
    }
    return *found;
}

/// A membership's transition (suspend, resume, end).
int change(const Args& args, std::string_view to, std::string_view done) {
    Session session(args);
    const protocol::Id id = session.record_id(args.positional().front());
    const auto all = memberships(session);
    const Listed& m = membership_named(all, id);
    const std::string from = m.record->state;
    const protocol::RecordType* type = protocol::find_record_type(protocol::membership_type);
    if (m.record->revoked || !type->allows(from, to)) {
        throw CommandError{std::format("membership {} is {}: it cannot become {}", short_id(id),
                                       m.record->revoked ? "revoked" : from, to)};
    }
    const protocol::Id changed =
        session.submit(args, protocol::RecordTransitionBody{id, from, std::string(to)});
    return report_submitted(
        args, session, changed, {{"membership", id_json(id)}, {"state", std::string(to)}},
        std::format("{} membership {} ({})", done, hex_id(id), m.membership.name));
}

/// The trust nodes this ledger belongs to, on its own directory: in client
/// mode the server keeps them, and adds the proofs to what it serves.
std::filesystem::path own_directory(const Session& session) {
    if (!session.server_url().empty()) {
        throw UsageError{"trust nodes are kept beside the ledger: run this where the ledger is "
                         "(the server adds the proofs it keeps)"};
    }
    return session.directory();
}

std::vector<node::TrustNodeEntry> trust_nodes(const std::filesystem::path& dir) {
    return unwrap(node::load_trust_nodes(dir), "reading the trust nodes");
}

const node::TrustNodeEntry& node_named(const std::vector<node::TrustNodeEntry>& nodes,
                                       const std::string& name) {
    const auto found = std::ranges::find(nodes, name, &node::TrustNodeEntry::name);
    if (found == nodes.end()) {
        throw CommandError{"no trust node named " + name};
    }
    return *found;
}

/// The proof kept from `node`, as this ledger checks it.
std::optional<protocol::EvidenceReport> kept_proof(const std::filesystem::path& dir,
                                                   const node::TrustNodeEntry& node,
                                                   const protocol::Id& member) {
    const auto path = node::membership_proof_path(dir, node.ledger_id);
    if (!std::filesystem::exists(path)) {
        return std::nullopt;
    }
    auto report =
        node::check_membership_proof(shared_provider(), read_file(path), node.ledger_id, member);
    return report ? std::optional(std::move(*report)) : std::nullopt;
}

Json proof_json(const std::optional<protocol::EvidenceReport>& report, protocol::Timestamp now) {
    if (!report) {
        return nullptr;
    }
    const auto m = protocol::decode_membership(*report->metadata);
    return {{"membership", id_json(report->record)},
            {"name", m->name},
            {"verified", m->verified},
            {"state", report->revoked                                        ? "revoked"
                      : m->until && *m->until < report->checkpoint.timestamp ? "lapsed"
                                                                             : report->state},
            {"checkpoint_time", format_time(report->checkpoint.timestamp)},
            {"age_days", (now - std::min(now, report->checkpoint.timestamp)) / 86'400'000}};
}

} // namespace

int cmd_trust_member_add(const Args& args) {
    Session session(args);
    protocol::Membership m;
    m.member = parse_ledger_id(args.positional().front());
    const std::string kind = args.get("kind").value_or("organization");
    if (kind != "organization" && kind != "person") {
        throw UsageError{"--kind is organization or person"};
    }
    m.kind = kind == "person" ? protocol::MemberKind::person : protocol::MemberKind::organization;
    m.name = args.need("name");
    m.verified = args.has("verified");
    m.registration = args.get("registration");
    m.jurisdiction = args.get("jurisdiction");
    if (const auto until = args.get("until")) {
        m.until = parse_time(*until);
    }
    if (m.member == session.state().ledger_id()) {
        throw UsageError{"a ledger is no member of itself: name another ledger"};
    }
    const auto metadata = protocol::encode_membership(m);
    if (!metadata) {
        throw UsageError{std::string(metadata.error().detail)};
    }
    // The membership's own fields, sealed: what the trust node checked.
    IssueRequest request;
    request.record_type = std::string(protocol::membership_type);
    request.metadata_value = *metadata;
    request.fields = {
        {"name", m.name},
        {"checked", args.get("note").value_or(m.verified ? "checked" : "self-declared")}};
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id id = issue_record(session, *load_signer(args.need("as"), args), request);
    return report_submitted(
        args, session, id,
        {{"membership", id_json(id)}, {"member", id_json(m.member)}, {"name", m.name}},
        std::format("registered membership {}: {} ({}, {}), ledger {}", hex_id(id), m.name,
                    protocol::member_kind_name(m.kind), m.verified ? "verified" : "self-declared",
                    short_id(m.member)));
}

int cmd_trust_member_list(const Args& args) {
    Session session(args);
    const auto of = args.get("member");
    const std::optional<protocol::Id> member =
        of ? std::optional(parse_ledger_id(*of)) : std::nullopt;
    const protocol::Timestamp now = ledger::SystemClock().now();
    Json out = Json::array();
    for (const Listed& m : memberships(session)) {
        if (member && m.membership.member != *member) {
            continue;
        }
        if (args.json()) {
            out.push_back(membership_json(m, now));
            continue;
        }
        std::println("{}  {:<10} {}  {} ({}{})", short_id(protocol::Id(m.record->id)),
                     status_of(m, now), short_id(m.membership.member), m.membership.name,
                     protocol::member_kind_name(m.membership.kind),
                     m.membership.verified ? ", verified" : ", self-declared");
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_trust_member_show(const Args& args) {
    Session session(args);
    const protocol::Id id = session.record_id(args.positional().front());
    const auto all = memberships(session);
    const Listed& m = membership_named(all, id);
    const Json j = membership_json(m, ledger::SystemClock().now());
    if (args.json()) {
        print_json(j);
        return exit_ok;
    }
    const protocol::Membership& p = m.membership;
    std::println("membership:   {}", hex_id(id));
    std::println("member:       {}", hex_id(p.member));
    std::println("name:         {} ({}, {})", p.name, protocol::member_kind_name(p.kind),
                 p.verified ? "verified" : "self-declared");
    if (p.registration) {
        std::println("registration: {}", *p.registration);
    }
    if (p.jurisdiction) {
        std::println("jurisdiction: {}", *p.jurisdiction);
    }
    if (p.until) {
        std::println("until:        {}", format_time(*p.until));
    }
    std::println("status:       {}", j["status"].get<std::string>());
    return exit_ok;
}

int cmd_trust_member_suspend(const Args& args) {
    return change(args, "suspended", "suspended");
}

int cmd_trust_member_resume(const Args& args) {
    return change(args, "active", "resumed");
}

int cmd_trust_member_end(const Args& args) {
    return change(args, "ended", "ended");
}

int cmd_trust_member_revoke(const Args& args) {
    Session session(args);
    const protocol::Id id = session.record_id(args.positional().front());
    const auto all = memberships(session);
    const Listed& m = membership_named(all, id);
    if (m.record->revoked) {
        throw CommandError{"membership " + short_id(id) + " was revoked already"};
    }
    const protocol::Id revoked =
        session.submit(args, protocol::RecordRevokeBody{id, args.get("reason")});
    return report_submitted(
        args, session, revoked, {{"membership", id_json(id)}},
        std::format("revoked membership {} ({})", hex_id(id), m.membership.name));
}

int cmd_trust_node_add(const Args& args) {
    Session session(args);
    const auto dir = own_directory(session);
    auto nodes = trust_nodes(dir);
    node::TrustNodeEntry entry{args.positional().front(), parse_ledger_id(args.need("ledger-id")),
                               args.need("url"), ledger::SystemClock().now()};
    if (!node::valid_token_name(entry.name)) {
        throw UsageError{"a trust node's name is letters, digits, dots, dashes, underscores"};
    }
    if (!node::Url::parse(entry.url)) {
        throw UsageError{"--url is the trust node's server, http:// or https://"};
    }
    if (entry.ledger_id == session.state().ledger_id()) {
        throw UsageError{"a ledger is no trust node of its own"};
    }
    if (std::ranges::any_of(nodes, [&](const node::TrustNodeEntry& n) {
            return n.name == entry.name || n.ledger_id == entry.ledger_id;
        })) {
        throw CommandError{"a trust node with that name or ledger is listed already"};
    }
    nodes.push_back(entry);
    unwrap(node::save_trust_nodes(dir, nodes), "saving the trust nodes");
    if (args.json()) {
        print_json(
            {{"name", entry.name}, {"ledger_id", id_json(entry.ledger_id)}, {"url", entry.url}});
    } else {
        std::println("added trust node {} (ledger {}); next: cexchain trust node fetch {}",
                     entry.name, short_id(entry.ledger_id), entry.name);
    }
    return exit_ok;
}

int cmd_trust_node_list(const Args& args) {
    Session session(args);
    const auto dir = own_directory(session);
    const protocol::Timestamp now = ledger::SystemClock().now();
    Json out = Json::array();
    for (const node::TrustNodeEntry& n : trust_nodes(dir)) {
        const auto proof = kept_proof(dir, n, session.state().ledger_id());
        const Json p = proof_json(proof, now);
        if (args.json()) {
            out.push_back({{"name", n.name},
                           {"ledger_id", id_json(n.ledger_id)},
                           {"url", n.url},
                           {"proof", p}});
            continue;
        }
        std::println("{:<16} {}  {}  {}", n.name, short_id(n.ledger_id), n.url,
                     p.is_null() ? std::string("no proof yet")
                                 : std::format("{}: {} as of {}", p["name"].get<std::string>(),
                                               p["state"].get<std::string>(),
                                               p["checkpoint_time"].get<std::string>()));
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_trust_node_remove(const Args& args) {
    Session session(args);
    const auto dir = own_directory(session);
    auto nodes = trust_nodes(dir);
    const node::TrustNodeEntry removed = node_named(nodes, args.positional().front());
    std::erase(nodes, removed);
    unwrap(node::save_trust_nodes(dir, nodes), "saving the trust nodes");
    std::error_code ec;
    std::filesystem::remove(node::membership_proof_path(dir, removed.ledger_id), ec);
    if (args.json()) {
        print_json({{"removed", removed.name}});
    } else {
        std::println("removed trust node {}: its proof no longer goes with the evidence",
                     removed.name);
    }
    return exit_ok;
}

int cmd_trust_node_fetch(const Args& args) {
    Session session(args);
    const auto dir = own_directory(session);
    const auto nodes = trust_nodes(dir);
    std::vector<node::TrustNodeEntry> chosen;
    if (args.positional().empty()) {
        chosen = nodes;
    } else {
        chosen.push_back(node_named(nodes, args.positional().front()));
    }
    if (chosen.empty()) {
        throw CommandError{"no trust node listed: cexchain trust node add NAME --ledger-id ID "
                           "--url URL"};
    }
    const protocol::Timestamp now = ledger::SystemClock().now();
    Json out = Json::array();
    bool all = true;
    for (const node::TrustNodeEntry& n : chosen) {
        auto report =
            node::fetch_membership_proof(shared_provider(), dir, n, session.state().ledger_id());
        if (!report) {
            all = false;
            if (args.json()) {
                out.push_back({{"name", n.name}, {"error", report.error().detail}});
            } else {
                std::println("{}: {}", n.name, report.error().detail);
            }
            continue;
        }
        const Json p = proof_json(*report, now);
        if (args.json()) {
            out.push_back({{"name", n.name}, {"proof", p}});
        } else {
            std::println("{}: {} is {} as of {}; the evidence exported here carries it", n.name,
                         p["name"].get<std::string>(), p["state"].get<std::string>(),
                         p["checkpoint_time"].get<std::string>());
        }
    }
    if (args.json()) {
        print_json(out);
    }
    return all ? exit_ok : exit_failure;
}

} // namespace cexchain::cli
