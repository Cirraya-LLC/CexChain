// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Records published at a private address (node/published.hpp): anyone who
// holds the address gets the record's evidence as it is now, with the fields
// chosen here disclosed, as a printed certificate's QR code needs.

#include <print>
#include <string>
#include <vector>

#include <kanhe/core/protocol/record.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace kanhe::cli {

namespace {

/// Where the address is reached: --url, else the server's, else the path
/// alone.
std::string address_of(const Args& args, const client::Session& session, const std::string& token) {
    std::string base = args.get("url").value_or(session.server_url());
    while (base.ends_with('/')) {
        base.pop_back();
    }
    return base + "/c/" + token;
}

Json published_json(const Args& args, const client::Session& session,
                    const client::Session::PublishedRecord& p) {
    Json fields = Json::array();
    for (const auto& [name, value] : p.fields) {
        fields.push_back({{"name", name}, {"value", value}});
    }
    return {{"token", p.token},
            {"address", address_of(args, session, p.token)},
            {"record", id_json(p.record)},
            {"fields", fields},
            {"published", format_time(p.published_at)}};
}

std::string field_list(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::string out;
    for (const auto& [name, value] : fields) {
        out += (out.empty() ? "" : ", ") + name;
    }
    return out.empty() ? "no fields" : out;
}

} // namespace

int cmd_record_publish(const Args& args) {
    Session session(args);
    const protocol::Id record = session.record_id(args.positional().front());
    std::vector<protocol::FieldDisclosure> disclosures;
    const auto disclose = split(args.get("disclose").value_or(""), ',');
    if (!disclose.empty()) {
        const Vault vault = read_vault(session, record, args);
        const auto commitment = unwrap(
            protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
            "fields");
        for (const std::string& name : disclose) {
            disclosures.push_back(
                unwrap(protocol::disclose_field(session.provider(), session.state().hash(),
                                                commitment, name),
                       "disclosing " + name));
        }
    }
    const auto published = session.publish(record, std::move(disclosures));
    if (args.json()) {
        print_json(published_json(args, session, published));
    } else {
        std::println("published {} at {} ({})", short_id(record),
                     address_of(args, session, published.token), field_list(published.fields));
        std::println("whoever holds the address gets the record's evidence as it is then; "
                     "keep it as private as the fields it shows");
    }
    return exit_ok;
}

int cmd_record_published(const Args& args) {
    Session session(args);
    const auto list = session.published();
    if (args.json()) {
        Json out = Json::array();
        for (const auto& p : list) {
            out.push_back(published_json(args, session, p));
        }
        print_json(out);
        return exit_ok;
    }
    if (list.empty()) {
        std::println("no published records (kanhe record publish)");
    }
    for (const auto& p : list) {
        std::println("{}  {}  {}  {}", p.token, short_id(p.record), format_time(p.published_at),
                     field_list(p.fields));
    }
    return exit_ok;
}

int cmd_record_unpublish(const Args& args) {
    Session session(args);
    const std::string token = args.positional().front();
    session.unpublish(token);
    if (args.json()) {
        print_json({{"unpublished", token}});
    } else {
        std::println("took the address down; the record stays on the ledger");
    }
    return exit_ok;
}

} // namespace kanhe::cli
