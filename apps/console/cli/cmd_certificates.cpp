// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Certificates (console/certificates.hpp): issued in bulk from a table, each
// published at a private address, printed with the QR code that opens it.

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <filesystem>
#include <format>
#include <map>
#include <optional>
#include <print>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

#include <cexchain/console/certificates.hpp>
#include <cexchain/console/kinds.hpp>
#include <cexchain/console/sessions.hpp>
#include <cexchain/core/protocol/record.hpp>

#include "console_commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

constexpr std::string_view default_verifier = "https://cexchain.cirraya.com/verify/";
// What --out lists: a row of the table per line, once issued and again
// once published (the last line of a row is how far it got).
constexpr std::string_view issued_header = "line,fingerprint,record,token,address";

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

// ---- the list of what was issued (--out) ---------------------------------

struct Issued {
    std::string fingerprint;
    std::string record;
    std::string token;
    std::string address;
};

/// The rows of the table issued so far, by line, as far as each got.
std::map<std::size_t, Issued> read_issued(const std::filesystem::path& path) {
    std::map<std::size_t, Issued> out;
    if (!std::filesystem::exists(path)) {
        return out;
    }
    std::vector<std::vector<std::string>> lines;
    try {
        lines = console::parse_csv(text_of(read_file(path)));
    } catch (const std::invalid_argument& e) {
        throw CommandError{path.string() + ": " + e.what()};
    }
    if (lines.empty() || console::csv_line(lines.front()) != issued_header) {
        throw CommandError{path.string() +
                           " is not a list of issued certificates: give another --out"};
    }
    for (std::size_t i = 1; i < lines.size(); ++i) {
        const auto& v = lines[i];
        if (v.size() != 5) {
            throw CommandError{std::format("{}: line {} is damaged", path.string(), i + 1)};
        }
        out[parse_number(v[0], "a line number")] = {v[1], v[2], v[3], v[4]};
    }
    return out;
}

/// Adds a line, durably, before the next certificate is issued.
void append_issued(const std::filesystem::path& path, const std::vector<std::string>& values) {
    const bool fresh = !std::filesystem::exists(path);
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        throw CommandError{"cannot write " + path.string()};
    }
    const std::string text = (fresh ? std::string(issued_header) + "\n" : std::string()) +
                             console::csv_line(values) + "\n";
    std::size_t written = 0;
    while (written < text.size()) {
        const ssize_t n = ::write(fd, text.data() + written, text.size() - written);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            ::close(fd);
            throw CommandError{"cannot write " + path.string()};
        }
        written += static_cast<std::size_t>(n);
    }
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    if (!synced) {
        throw CommandError{"cannot write " + path.string()};
    }
}

/// What a row holds, so that a table changed since is not taken for the one
/// issued.
std::string fingerprint_of(const client::Session& session, const console::CertificateRow& row) {
    std::vector<std::string> values;
    for (const auto& [name, value] : row.fields) {
        values.push_back(name + "=" + value);
    }
    for (const auto& [name, value] : row.metadata) {
        values.push_back(name + "=" + value);
    }
    const Bytes digest =
        hash_text(session.provider(), crypto::HashAlg::sha256, console::csv_line(values));
    return to_hex(ByteView(digest).first(16));
}

/// The printed private fields' disclosures (the public ones are in the
/// record's metadata already).
std::vector<protocol::FieldDisclosure>
printed_disclosures(const client::Session& session, const console::Kind& kind, const Vault& vault) {
    const auto commitment =
        unwrap(protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
               "the certificate's fields");
    std::vector<protocol::FieldDisclosure> out;
    for (const std::string& name : kind.printed) {
        if (std::ranges::find(vault.fields, name, &protocol::RecordField::name) !=
            vault.fields.end()) {
            out.push_back(unwrap(protocol::disclose_field(session.provider(),
                                                          session.state().hash(), commitment, name),
                                 "disclosing " + name));
        }
    }
    return out;
}

// ---- certificates as they are --------------------------------------------

struct Certificate {
    client::Session::PublishedRecord published;
    const console::Kind* kind = nullptr;
    const protocol::RecordState* record = nullptr;
    /// The printed fields: name, label, value, in the kind's order.
    std::vector<std::array<std::string, 3>> fields;
};

std::string_view status_of(const protocol::RecordState& record) {
    return record.revoked ? "revoked" : record.superseded_by ? "replaced" : "valid";
}

/// The published records that are certificates of `kinds` (which they point
/// into: keep it while they are used).
std::vector<Certificate> certificates(const client::Session& session,
                                      const std::map<std::string, console::Kind>& kinds) {
    std::vector<Certificate> out;
    for (auto& p : session.published()) {
        const protocol::RecordState* record = session.state().record(p.record);
        const auto kind = record != nullptr ? kinds.find(record->record_type) : kinds.end();
        if (kind == kinds.end()) {
            continue;
        }
        Certificate c{std::move(p), &kind->second, record, {}};
        std::optional<cbor::Value> metadata;
        for (const std::string& name : kind->second.printed) {
            const auto field =
                std::ranges::find(kind->second.fields, name, &console::KindField::name);
            std::string value;
            if (field->is_private) {
                const auto given = std::ranges::find(c.published.fields, name,
                                                     &std::pair<std::string, std::string>::first);
                value = given == c.published.fields.end() ? std::string() : given->second;
            } else {
                if (!metadata) {
                    metadata = client::registration_of(session, c.published.record)
                                   .metadata.value_or(cbor::Value());
                }
                if (const cbor::Value* v = metadata->find(name)) {
                    value = client::display_value(*v);
                }
            }
            c.fields.push_back({name, field->label.empty() ? name : field->label, value});
        }
        out.push_back(std::move(c));
    }
    return out;
}

const Certificate& find_certificate(const std::vector<Certificate>& all, const std::string& token) {
    const auto found =
        std::ranges::find_if(all, [&](const Certificate& c) { return c.published.token == token; });
    if (found == all.end()) {
        throw CommandError{"no certificate is published at " + token};
    }
    return *found;
}

std::string issued_on(const client::Session& session, const protocol::RecordState& record) {
    return client::iso_time(session.log_entry(record.registered_at_index).registered_at)
        .substr(0, 10);
}

Json certificate_json(const client::Session& session, const Certificate& c,
                      const std::string& base) {
    Json fields = Json::array();
    for (const auto& [name, label, value] : c.fields) {
        fields.push_back({{"name", name}, {"label", label}, {"value", value}});
    }
    return {{"token", c.published.token},
            {"address", base + "/c/" + c.published.token},
            {"record", id_json(c.published.record)},
            {"type", c.record->record_type},
            {"kind", c.kind->name},
            {"status", status_of(*c.record)},
            {"issued", issued_on(session, *c.record)},
            {"published", format_time(c.published.published_at)},
            {"fields", fields}};
}

std::string field_summary(const Certificate& c) {
    std::string out;
    for (const auto& [name, label, value] : c.fields) {
        out += (out.empty() ? "" : ", ") + value;
    }
    return out;
}

console::CertificatePage page_of(const client::Session& session, const Certificate& c,
                                 const std::string& verify_url) {
    console::CertificatePage page;
    page.kind = c.kind->name;
    page.issuer = session.state().organization();
    page.issued = issued_on(session, *c.record);
    page.record = hex_id(c.published.record);
    page.verify_url = verify_url;
    for (const auto& [name, label, value] : c.fields) {
        page.fields.emplace_back(label, value);
        page.by_name[name] = value;
    }
    return page;
}

} // namespace

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
    const std::map<std::size_t, Issued> issued = read_issued(out);
    std::size_t already = 0;
    for (const console::CertificateRow& row : rows) {
        const auto prior = issued.find(row.line);
        if (prior == issued.end()) {
            continue;
        }
        if (prior->second.fingerprint != fingerprint_of(session, row)) {
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
    const auto signer = load_signer(args.need("as"), args);
    std::size_t count = 0;
    try {
        for (const console::CertificateRow& row : rows) {
            const auto prior = issued.find(row.line);
            if (prior != issued.end() && !prior->second.token.empty()) {
                continue;
            }
            const std::string fingerprint = fingerprint_of(session, row);
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
                append_issued(out, {std::to_string(row.line), fingerprint, hex_id(record), "", ""});
            }
            const auto published =
                session.publish(record, printed_disclosures(session, kind, vault));
            append_issued(out, {std::to_string(row.line), fingerprint, hex_id(record),
                                published.token, base + "/c/" + published.token});
            ++count;
        }
    } catch (const ActionError& e) {
        throw ActionError{e.message + std::format("\n{} certificates issued before that, listed in "
                                                  "{}: run the same command again to carry on",
                                                  count, out.string())};
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
    const auto kinds = certificate_kinds(args);
    const std::optional<std::string> type =
        args.positional().empty() ? std::nullopt : std::optional(args.positional().front());
    const std::string base = address_base(args, session);
    Json out = Json::array();
    for (const Certificate& c : certificates(session, kinds)) {
        if (type && c.record->record_type != *type) {
            continue;
        }
        if (args.json()) {
            out.push_back(certificate_json(session, c, base));
            continue;
        }
        std::println("{}  {}  {}  {:<8}  {}", c.published.token, short_id(c.published.record),
                     issued_on(session, *c.record), status_of(*c.record), field_summary(c));
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
    const auto kinds = certificate_kinds(args); // what `all` points into
    const auto all = certificates(session, kinds);
    const Certificate& c = find_certificate(all, args.positional().front());
    const std::string base = address_base(args, session);
    const std::string link =
        base.empty() ? std::string()
                     : console::verifier_link(verifier_of(args), session.state().ledger_id(),
                                              c.published.record, base + "/c/" + c.published.token,
                                              language_of(args));
    if (args.json()) {
        Json j = certificate_json(session, c, base);
        j["verify_url"] = link.empty() ? Json(nullptr) : Json(link);
        print_json(j);
        return exit_ok;
    }
    std::println("certificate: {} ({})", c.kind->name, c.record->record_type);
    std::println("status:      {}", status_of(*c.record));
    std::println("issued:      {} by {}", issued_on(session, *c.record),
                 session.state().organization());
    std::println("record:      {}", hex_id(c.published.record));
    for (const auto& [name, label, value] : c.fields) {
        std::println("{:<12} {}", label + ":", value);
    }
    std::println("address:     {}/c/{}", base, c.published.token);
    if (!link.empty()) {
        std::println("verify:      {}", link);
    }
    return exit_ok;
}

int cmd_certificate_withdraw(const Args& args) {
    Session session(args);
    const std::string token = args.positional().front();
    const auto kinds = certificate_kinds(args); // what `all` points into
    const auto all = certificates(session, kinds);
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
    const auto kinds = certificate_kinds(args); // what `all` points into
    const auto all = certificates(session, kinds);
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
    std::vector<const Certificate*> chosen;
    std::size_t skipped = 0;
    for (const std::string& token : args.positional()) {
        const Certificate& c = find_certificate(all, token);
        if (status_of(*c.record) != "valid") {
            throw CommandError{"the certificate at " + token + " is " +
                               std::string(status_of(*c.record)) + ": it is not printed"};
        }
        chosen.push_back(&c);
    }
    for (const Certificate& c : all) {
        if (type && c.record->record_type == *type) {
            if (status_of(*c.record) == "valid") {
                chosen.push_back(&c);
            } else {
                ++skipped;
            }
        }
    }
    const std::filesystem::path out = args.need("out");
    std::filesystem::create_directories(out);
    Json files = Json::array();
    for (const Certificate* c : chosen) {
        const std::string link =
            console::verifier_link(verifier, session.state().ledger_id(), c->published.record,
                                   base + "/c/" + c->published.token, language);
        std::string page;
        try {
            page = console::fill_certificate(html, page_of(session, *c, link));
        } catch (const std::invalid_argument& e) {
            throw UsageError{template_file.value_or("the template") + ": " + e.what()};
        }
        const std::filesystem::path file = out / (c->published.token + ".html");
        write_file(file, as_bytes(page), true);
        files.push_back({{"token", c->published.token},
                         {"record", id_json(c->published.record)},
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
