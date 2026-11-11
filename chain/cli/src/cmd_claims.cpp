// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Claims (spec v0.14): the issuer confirms that, in one of its records, a
// condition on fields holds, without disclosing them. The condition is
// checked here against the record's private data, and a claim that it does
// not hold is issued only on purpose (--allow-no), so that asking reveals
// nothing more than silence.

#include <algorithm>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include <cexchain/client/claims.hpp>
#include <cexchain/core/protocol/claims.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/ledger/environment.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

/// The claims on the ledger: records of the type, with their metadata.
struct Listed {
    const protocol::RecordState* record;
    protocol::Claim claim;
};

std::vector<Listed> claims(const client::Session& session) {
    std::vector<Listed> out;
    for (const auto& [key, record] : session.state().records()) {
        if (record.record_type != protocol::claim_type) {
            continue;
        }
        const auto body = client::registration_of(session, protocol::Id(record.id));
        if (auto claim = body.metadata ? protocol::decode_claim(*body.metadata)
                                       : Result<protocol::Claim>(fail(Errc::malformed, "none"))) {
            out.push_back({&record, std::move(*claim)});
        }
    }
    return out;
}

Json claim_json(const client::Session& session, const Listed& c) {
    const protocol::RecordState* source = session.state().record(c.claim.source);
    const std::string status =
        client::claim_status(session.state(), *c.record, c.claim, ledger::SystemClock().now());
    return {{"claim", id_json(protocol::Id(c.record->id))},
            {"source", id_json(c.claim.source)},
            {"source_type", source != nullptr ? Json(source->record_type) : Json(nullptr)},
            {"text", protocol::claim_text(c.claim)},
            {"holds", c.claim.holds},
            {"subject", c.claim.subject ? Json(*c.claim.subject) : Json(nullptr)},
            {"as_of", format_time(c.claim.as_of)},
            {"until", c.claim.until ? Json(format_time(*c.claim.until)) : Json(nullptr)},
            {"status", status}};
}

} // namespace

int cmd_claim_issue(const Args& args) {
    Session session(args);
    const protocol::Id source = session.record_id(args.positional().front());
    protocol::Claim claim;
    claim.source = source;
    for (const std::string& condition : args.all("if")) {
        claim.condition.push_back(client::parse_claim_term(condition));
    }
    if (claim.condition.empty()) {
        throw UsageError{"say what to confirm: --if 'FIELD OP VALUE'"};
    }
    claim.subject = args.get("subject");
    claim.as_of = ledger::SystemClock().now();
    if (const auto until = args.get("until")) {
        claim.until = parse_time(*until);
    }
    // A condition of the right shape first, then checked against the
    // source's private data.
    if (const auto shaped = encode_claim(claim); !shaped) {
        throw UsageError{std::string(shaped.error().detail)};
    }
    const Vault vault = read_vault(session, source, args);
    const client::ClaimCheck check = client::check_claim(claim, vault.fields);
    claim.holds = check.holds;
    if (!claim.holds && !args.has("allow-no")) {
        throw CommandError{"the condition does not hold: no claim is issued (--allow-no issues "
                           "one that says so)"};
    }
    const auto metadata = encode_claim(claim);
    if (!metadata) {
        throw UsageError{std::string(metadata.error().detail)};
    }
    // The claim's own fields, sealed: the values it was checked against.
    IssueRequest request;
    request.record_type = std::string(protocol::claim_type);
    request.metadata_value = *metadata;
    request.fields = check.basis;
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id id = issue_record(session, *load_signer(args.need("as"), args), request);
    return report_submitted(
        args, session, id,
        {{"claim", id_json(id)}, {"text", protocol::claim_text(claim)}, {"holds", claim.holds}},
        std::format("issued claim {}: {} {}", hex_id(id),
                    claim.holds ? "holds:" : "does NOT hold:", protocol::claim_text(claim)));
}

int cmd_claim_list(const Args& args) {
    Session session(args);
    const auto of = args.get("source");
    const std::optional<protocol::Id> source =
        of ? std::optional(session.record_id(*of)) : std::nullopt;
    Json out = Json::array();
    for (const Listed& c : claims(session)) {
        if (source && c.claim.source != *source) {
            continue;
        }
        const Json j = claim_json(session, c);
        if (args.json()) {
            out.push_back(j);
            continue;
        }
        std::println("{}  {:<16} {}{}", short_id(protocol::Id(c.record->id)),
                     j["status"].get<std::string>(),
                     c.claim.holds ? "" : "NOT: ", protocol::claim_text(c.claim));
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_claim_show(const Args& args) {
    Session session(args);
    const protocol::Id id = session.record_id(args.positional().front());
    const auto all = claims(session);
    const auto found = std::ranges::find_if(
        all, [&](const Listed& c) { return protocol::Id(c.record->id) == id; });
    if (found == all.end()) {
        throw CommandError{"no claim " + hex_id(id)};
    }
    const Json j = claim_json(session, *found);
    if (args.json()) {
        print_json(j);
        return exit_ok;
    }
    std::println("claim:    {}", hex_id(id));
    std::println("{}:    {}", found->claim.holds ? "holds" : "NOT  ",
                 protocol::claim_text(found->claim));
    if (found->claim.subject) {
        std::println("subject:  {}", *found->claim.subject);
    }
    std::println("as of:    {}{}", format_time(found->claim.as_of),
                 found->claim.until ? ", until " + format_time(*found->claim.until)
                                    : std::string());
    std::println("source:   {} ({})", hex_id(found->claim.source),
                 j["source_type"].is_null() ? "unknown" : j["source_type"].get<std::string>());
    std::println("status:   {}", j["status"].get<std::string>());
    return exit_ok;
}

int cmd_claim_revoke(const Args& args) {
    Session session(args);
    const protocol::Id id = session.record_id(args.positional().front());
    const protocol::RecordState* record = session.state().record(id);
    if (record == nullptr || record->record_type != protocol::claim_type) {
        throw CommandError{"no claim " + hex_id(id)};
    }
    const protocol::Id revoked =
        session.submit(args, protocol::RecordRevokeBody{id, args.get("reason")});
    return report_submitted(args, session, revoked, {{"claim", id_json(id)}},
                            "withdrew claim " + hex_id(id));
}

} // namespace cexchain::cli
