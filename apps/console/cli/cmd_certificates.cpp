// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Certificates (console/certificates.hpp): issued in bulk from a table, each
// published at a private address, printed with the QR code that opens it.

#include <algorithm>
#include <filesystem>
#include <format>
#include <map>
#include <optional>
#include <print>
#include <stdexcept>
#include <string>
#include <vector>

#include <cexchain/console/activity.hpp>
#include <cexchain/console/certificates.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/ledger/environment.hpp>

#include "console_commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

constexpr std::string_view default_verifier = "https://cexchain.cirraya.com/verify/";
std::string_view text_of(const Bytes& bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

/// The kinds that print fields: the one --sheet names, or the console's.
std::map<std::string, console::Kind> certificate_kinds(const Args& args) {
    std::map<std::string, console::Kind> out;
    if (const auto sheet = args.get("sheet")) {
        const Bytes bytes = read_file(*sheet);
        try {
            const console::Kind kind =
                console::parse_kind(Json::parse(bytes.begin(), bytes.end(), nullptr, false));
            out.emplace(kind.type, kind);
        } catch (const std::invalid_argument& e) {
            throw UsageError{*sheet + ": " + e.what()};
        }
    } else {
        try {
            for (console::Kind& kind :
                 console::load_kinds(console::state_directory(args.console_ledger()))) {
                out.emplace(kind.type, std::move(kind));
            }
        } catch (const std::runtime_error& e) {
            throw CommandError{e.what()};
        }
    }
    std::erase_if(out, [](const auto& item) { return item.second.printed.empty(); });
    return out;
}

console::Kind certificate_kind(const Args& args, const std::string& type) {
    auto kinds = certificate_kinds(args);
    const auto found = kinds.find(type);
    if (found == kinds.end()) {
        throw CommandError{"no kind of type " + type +
                           " prints fields here: add one (cexchain-console kind add) whose "
                           "sheet lists them in \"printed\", or give it with --sheet FILE"};
    }
    return std::move(found->second);
}

/// Where the certificates' addresses are reached: --url, else the server's.
std::string address_base(const Args& args, const client::Session& session) {
    std::string base = args.get("url").value_or(session.server_url());
    while (base.ends_with('/')) {
        base.pop_back();
    }
    return base;
}

std::string verifier_of(const Args& args) {
    const std::string verifier = args.get("verifier-url").value_or(std::string(default_verifier));
    if ((!verifier.starts_with("https://") && !verifier.starts_with("http://")) ||
        verifier.find('#') != std::string::npos) {
        throw UsageError{"--verifier-url must be an http(s) URL without a #fragment"};
    }
    return verifier;
}

std::string language_of(const Args& args) {
    const std::string language = args.get("language").value_or("en");
    if (!console::certificate_language(language)) {
        throw UsageError{"--language is en, zh-Hant, or zh-Hans"};
    }
    return language;
}

// ---- certificates as they are --------------------------------------------

/// The published records that are certificates of `kinds`.
std::vector<console::Certificate> certificates(const client::Session& session,
                                               const std::map<std::string, console::Kind>& kinds) {
    std::vector<console::Certificate> out;
    for (const auto& p : session.published()) {
        const protocol::RecordState* record = session.state().record(p.record);
        const auto kind = record != nullptr ? kinds.find(record->record_type) : kinds.end();
        if (kind == kinds.end()) {
            continue;
        }
        // The metadata only when a public field is printed.
        std::optional<cbor::Value> metadata;
        if (std::ranges::any_of(kind->second.printed, [&](const std::string& name) {
                return !std::ranges::find(kind->second.fields, name, &console::KindField::name)
                            ->is_private;
            })) {
            metadata = client::registration_of(session, p.record).metadata;
        }
        out.push_back(
            console::certificate_of(kind->second, *record, metadata,
                                    session.log_entry(record->registered_at_index).registered_at,
                                    p.token, p.published_at, p.fields));
    }
    return out;
}

const console::Certificate& find_certificate(const std::vector<console::Certificate>& all,
                                             const std::string& token) {
    const auto found = std::ranges::find(all, token, &console::Certificate::token);
    if (found == all.end()) {
        throw CommandError{"no certificate is published at " + token};
    }
    return *found;
}

std::string field_summary(const console::Certificate& c) {
    std::string out;
    for (const auto& f : c.fields) {
        out += (out.empty() ? "" : ", ") + f.value;
    }
    return out;
}

std::string issued_on(const console::Certificate& c) {
    return client::iso_time(c.issued_at).substr(0, 10);
}

/// The console's machine on the ledger: the device whose key the console
/// keeps sealed.
protocol::Id console_machine(const client::Session& session, const console::KeyStore& keys) {
    for (const console::SealedKeyInfo& k : keys.keys()) {
        if (k.name != console::machine_key_name) {
            continue;
        }
        for (const auto& [key, actor] : session.state().actors()) {
            if (!actor.revoked && actor.kind == protocol::ActorKind::device &&
                actor.key == k.public_key) {
                return protocol::Id(actor.id);
            }
        }
    }
    throw CommandError{"this console's machine is not on the ledger"};
}

void record(const Args& args, std::string action, Json detail) {
    console::record_activity(console::state_directory(args.console_ledger()),
                             {ledger::SystemClock().now(), "cli", std::move(action),
                              nlohmann::json::parse(detail.dump())});
}

} // namespace

int cmd_certificate_allow(const Args& args) {
    Session session(args);
    const console::Kind kind = certificate_kind(args, args.positional().front());
    const std::filesystem::path state = console::state_directory(args.console_ledger());
    console::KeyStore keys(state);
    unlock_console_keys(keys, args);
    const protocol::Id machine = console_machine(session, keys);
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::record_register};
    scope.record_types = std::vector<std::string>{kind.type};
    scope.may_delegate = false;
    scope.require_presence = false;
    // The organization's grant, signed with its root key, as the console's
    // owner gives it with a tap.
    const auto root = keys.open(console::root_key_name);
    const protocol::Id granted = session.submit(
        root, protocol::DelegationGrantBody{machine, std::move(scope)}, std::nullopt);
    record(args, "certificates.allow", {{"type", kind.type}, {"statement", hex_id(granted)}});
    if (args.json()) {
        print_json(
            {{"delegation", hex_id(granted)}, {"machine", hex_id(machine)}, {"type", kind.type}});
    } else {
        std::println("the console's machine may now issue {} certificates (delegation {})",
                     kind.name, short_id(granted));
    }
    return exit_ok;
}

int cmd_certificate_issue(const Args& args) {
    Session session(args);
    const console::Kind kind = certificate_kind(args, args.positional().front());
    const std::string table = args.need("csv");
    std::vector<console::CertificateRow> rows;
    try {
        rows = console::certificate_rows(kind, text_of(read_file(table)));
    } catch (const std::invalid_argument& e) {
        throw UsageError{table + ": " + e.what()};
    }
    const std::filesystem::path out = args.need("out");
    std::map<std::size_t, console::IssuedRow> issued;
    try {
        issued = console::read_issued(out);
    } catch (const std::runtime_error& e) {
        throw CommandError{std::string(e.what()) + ": give another --out"};
    }
    std::size_t already = 0;
    for (const console::CertificateRow& row : rows) {
        const auto prior = issued.find(row.line);
        if (prior == issued.end()) {
            continue;
        }
        if (prior->second.fingerprint != console::row_fingerprint(session.provider(), row)) {
            throw CommandError{std::format(
                "line {} of {} changed since it was issued as {}: issue from the table as it "
                "was, or give another --out",
                row.line, table, prior->second.record)};
        }
        if (!prior->second.token.empty()) {
            ++already;
        }
    }
    const std::string base = address_base(args, session);
    if (args.has("dry-run")) {
        if (args.json()) {
            print_json({{"certificates", rows.size()},
                        {"issued", already},
                        {"to_issue", rows.size() - already},
                        {"printed", kind.printed}});
        } else {
            std::println("{}: {} certificates of {}, {} issued already, {} to issue", table,
                         rows.size(), kind.name, already, rows.size() - already);
        }
        return exit_ok;
    }
    // A key of one's own, or the console's machine (its key sealed in the
    // console, opened here with the console's passphrase or recovery code).
    if (args.has("machine") == args.has("as")) {
        throw UsageError{"sign with --as KEY or --machine"};
    }
    std::shared_ptr<const crypto::Signer> signer;
    if (args.has("machine")) {
        if (!session.server_url().empty()) {
            throw UsageError{"--machine signs on the console's own ledger directory, not through a "
                             "server"};
        }
        console::KeyStore keys(console::state_directory(args.console_ledger()));
        unlock_console_keys(keys, args);
        static_cast<void>(console_machine(session, keys));
        signer = std::make_shared<crypto::openssl::KeyPair>(keys.open(console::machine_key_name));
    } else {
        signer = load_signer(args.need("as"), args);
    }
    std::size_t count = 0;
    const auto carry_on = [&] {
        return std::format("\n{} certificates issued before that, listed in {}: run the same "
                           "command again to carry on",
                           count, out.string());
    };
    try {
        for (const console::CertificateRow& row : rows) {
            const auto prior = issued.find(row.line);
            if (prior != issued.end() && !prior->second.token.empty()) {
                continue;
            }
            const std::string fingerprint = console::row_fingerprint(session.provider(), row);
            protocol::Id record;
            Vault vault;
            if (prior != issued.end()) {
                // Issued, then stopped before it was published.
                record = session.record_id(prior->second.record);
                vault = read_vault(session, record, args);
            } else {
                IssueRequest request;
                request.record_type = kind.type;
                request.fields = row.fields;
                request.metadata = row.metadata;
                record = issue_record(session, *signer, request, &vault);
                console::append_issued(out, row.line, {fingerprint, hex_id(record), "", ""});
            }
            const auto published = session.publish(
                record, console::printed_disclosures(session.provider(), session.state().hash(),
                                                     kind, vault.fields));
            console::append_issued(
                out, row.line,
                {fingerprint, hex_id(record), published.token, base + "/c/" + published.token});
            ++count;
        }
    } catch (const std::runtime_error& e) {
        throw ActionError{e.what() + carry_on()};
    } catch (const ActionError& e) {
        throw ActionError{e.message + carry_on()};
    }
    if (args.has("machine") && count > 0) {
        record(args, "certificates.issue", {{"type", kind.type}, {"rows", rows.size()}});
    }
    if (args.json()) {
        print_json({{"issued", count}, {"already", already}, {"out", out.string()}});
    } else {
        std::println("issued {} certificates of {} ({} issued before), listed in {}", count,
                     kind.name, already, out.string());
        // Through a server, the addresses are its own; else --url names them.
        std::println("print them: cexchain-console certificate print --type {} --out DIR{}",
                     kind.type,
                     !session.server_url().empty() ? ""
                     : base.empty()                ? " --url URL"
                                                   : " --url " + base);
    }
    return exit_ok;
}

int cmd_certificate_list(const Args& args) {
    Session session(args);
    const auto kinds = certificate_kinds(args); // what the certificates point into
    const std::optional<std::string> type =
        args.positional().empty() ? std::nullopt : std::optional(args.positional().front());
    const std::string base = address_base(args, session);
    Json out = Json::array();
    for (const console::Certificate& c : certificates(session, kinds)) {
        if (type && c.type != *type) {
            continue;
        }
        if (args.json()) {
            out.push_back(Json(console::certificate_json(c, base + "/c/" + c.token)));
            continue;
        }
        std::println("{}  {}  {}  {:<8}  {}", c.token, short_id(c.record), issued_on(c), c.status,
                     field_summary(c));
    }
    if (args.json()) {
        print_json(out);
    } else if (kinds.empty()) {
        std::println("no kind prints fields (a kind sheet's \"printed\"): no certificates");
    }
    return exit_ok;
}

int cmd_certificate_show(const Args& args) {
    Session session(args);
    const auto all = certificates(session, certificate_kinds(args));
    const console::Certificate& c = find_certificate(all, args.positional().front());
    const std::string base = address_base(args, session);
    const std::string link =
        base.empty() ? std::string()
                     : console::verifier_link(verifier_of(args), session.state().ledger_id(),
                                              c.record, base + "/c/" + c.token, language_of(args));
    if (args.json()) {
        Json j(console::certificate_json(c, base + "/c/" + c.token));
        j["verify_url"] = link.empty() ? Json(nullptr) : Json(link);
        print_json(j);
        return exit_ok;
    }
    std::println("certificate: {} ({})", c.kind, c.type);
    std::println("status:      {}", c.status);
    std::println("issued:      {} by {}", issued_on(c), session.state().organization());
    std::println("record:      {}", hex_id(c.record));
    for (const auto& f : c.fields) {
        std::println("{:<12} {}", f.label + ":", f.value);
    }
    std::println("address:     {}/c/{}", base, c.token);
    if (!link.empty()) {
        std::println("verify:      {}", link);
    }
    return exit_ok;
}

int cmd_certificate_withdraw(const Args& args) {
    Session session(args);
    const std::string token = args.positional().front();
    const auto all = certificates(session, certificate_kinds(args));
    static_cast<void>(find_certificate(all, token));
    session.unpublish(token);
    if (args.json()) {
        print_json({{"withdrawn", token}});
    } else {
        std::println("took the certificate's address down; its QR code finds nothing now");
        std::println("the record stays on the ledger: revoke it to say it no longer stands");
    }
    return exit_ok;
}

int cmd_certificate_print(const Args& args) {
    Session session(args);
    const auto all = certificates(session, certificate_kinds(args));
    const std::string base = address_base(args, session);
    if (base.empty()) {
        throw UsageError{"--url URL: where the ledger's server is reached, for the QR code"};
    }
    const std::string verifier = verifier_of(args);
    const std::string language = language_of(args);
    const auto type = args.get("type");
    if (args.positional().empty() == !type) {
        throw UsageError{"name the certificates (TOKEN...) or --type TYPE, not both"};
    }
    std::string html = console::default_certificate_template(language);
    const auto template_file = args.get("template");
    if (template_file) {
        html = std::string(text_of(read_file(*template_file)));
    }
    std::vector<const console::Certificate*> chosen;
    std::size_t skipped = 0;
    for (const std::string& token : args.positional()) {
        const console::Certificate& c = find_certificate(all, token);
        if (c.status != "valid") {
            throw CommandError{"the certificate at " + token + " is " + c.status +
                               ": it is not printed"};
        }
        chosen.push_back(&c);
    }
    for (const console::Certificate& c : all) {
        if (type && c.type == *type) {
            if (c.status == "valid") {
                chosen.push_back(&c);
            } else {
                ++skipped;
            }
        }
    }
    const std::filesystem::path out = args.need("out");
    std::filesystem::create_directories(out);
    Json files = Json::array();
    for (const console::Certificate* c : chosen) {
        const std::string link = console::verifier_link(
            verifier, session.state().ledger_id(), c->record, base + "/c/" + c->token, language);
        std::string page;
        try {
            page = console::fill_certificate(
                html, console::page_of(*c, session.state().organization(), link));
        } catch (const std::invalid_argument& e) {
            throw UsageError{template_file.value_or("the template") + ": " + e.what()};
        }
        const std::filesystem::path file = out / (c->token + ".html");
        write_file(file, as_bytes(page), true);
        files.push_back({{"token", c->token},
                         {"record", id_json(c->record)},
                         {"file", file.string()},
                         {"verify_url", link}});
    }
    if (args.json()) {
        print_json({{"printed", files}, {"skipped", skipped}});
    } else {
        std::println("wrote {} certificates to {}{}; open each in a browser to print it or save it "
                     "as PDF",
                     chosen.size(), out.string(),
                     skipped == 0 ? std::string()
                                  : std::format(" (left out {} revoked or replaced)", skipped));
    }
    return exit_ok;
}

} // namespace cexchain::cli
