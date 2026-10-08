// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Ownership assets (D-052): receivables and warehouse receipts on their
// issuer's ledger (the home), which changes them only with the consent of
// each party involved, given on that party's own ledger.
//
//   home:   asset issue, asset record (pay, freeze, ...), asset evidence,
//           asset show/list; serve --registrar-key takes consents online
//   party:  asset consent (to an action on a peer's asset), asset send,
//           asset fetch, asset withdraw
//   anyone: asset verify

#include <algorithm>
#include <charconv>
#include <format>
#include <limits>
#include <print>

#include <cexchain/core/protocol/asset_evidence.hpp>
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/node/assets.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/peers.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "peers.hpp"
#include "records.hpp"

namespace cexchain::cli {

namespace {

constexpr protocol::Timestamp day_ms = 86'400'000;

protocol::AssetKind kind_from(std::string_view text) {
    if (text == "receivable") {
        return protocol::AssetKind::receivable;
    }
    if (text == "warehouse-receipt") {
        return protocol::AssetKind::warehouse_receipt;
    }
    throw UsageError{"the asset kind is receivable or warehouse-receipt"};
}

protocol::AssetAction action_from(std::string_view text) {
    const auto action = protocol::asset_action_from(text);
    if (!action) {
        throw UsageError{"unknown action " + std::string(text) +
                         ": transfer, pledge, release, enforce, redeem, pay, confirm, dispute, "
                         "freeze, unfreeze, or cancel"};
    }
    return *action;
}

protocol::Id full_id(std::string_view text, std::string_view what) {
    const auto bytes = from_hex(text);
    if (!bytes || bytes->size() != protocol::id_size) {
        throw UsageError{std::string(what) + " must be a full id (64 hex digits)"};
    }
    return *protocol::to_id(*bytes);
}

/// A ledger, by peer name (with a ledger directory) or by its full id.
protocol::Id ledger_of(const Session& session, std::string_view text) {
    if (text.size() == 2 * protocol::id_size) {
        if (const auto bytes = from_hex(text)) {
            return *protocol::to_id(*bytes);
        }
    }
    if (session.remote()) {
        throw UsageError{"with --server, name ledgers by their full id"};
    }
    return peer_named(session.directory(), std::string(text)).ledger_id;
}

/// The asset `text` names on this ledger.
std::pair<const protocol::RecordState*, const protocol::AssetState*>
find_asset(const Session& session, std::string_view text) {
    const protocol::Id id = session.record_id(text);
    const protocol::AssetState* asset = session.state().asset(id);
    if (asset == nullptr) {
        throw CommandError{"record " + short_id(id) + " is not an asset"};
    }
    return {session.state().record(id), asset};
}

std::string ledger_label(const Session& session, const protocol::Id& ledger) {
    if (!session.remote()) {
        if (const auto peers = node::load_peers(session.directory())) {
            for (const node::Peer& p : *peers) {
                if (p.ledger_id == ledger) {
                    return p.name + " (" + short_id(ledger) + ")";
                }
            }
        }
    }
    return "ledger " + short_id(ledger);
}

/// The record metadata the asset was registered with.
protocol::AssetMetadata metadata_of(const Session& session, const protocol::RecordState& record,
                                    protocol::AssetKind kind) {
    const protocol::SignedStatement registration = session.statement(record.registered_at_index);
    const auto& body = std::get<protocol::RecordRegisterBody>(registration.statement.body);
    return unwrap(protocol::decode_asset_metadata(kind, *body.metadata), "the asset's metadata");
}

Json optional_id(const std::optional<protocol::Id>& id) {
    return id ? id_json(*id) : Json(nullptr);
}

} // namespace

Json asset_json(const Session& session, const protocol::RecordState& record,
                const protocol::AssetState& asset) {
    const protocol::AssetMetadata m = metadata_of(session, record, asset.kind);
    Json actions = Json::array();
    for (const std::uint64_t index : record.history) {
        const protocol::SignedStatement s = session.statement(index);
        const auto* action = std::get_if<protocol::AssetActionBody>(&s.statement.body);
        if (action == nullptr) {
            continue;
        }
        Json consents = Json::array();
        for (const protocol::ConsentRef& c : action->consents) {
            consents.push_back({{"ledger", id_json(c.ledger)}, {"record", id_json(c.record)}});
        }
        actions.push_back(
            {{"index", index},
             {"registered_at", iso_time(session.log_entry(index).registered_at)},
             {"action", protocol::name(action->action)},
             {"to", optional_id(action->to)},
             {"quantity", action->quantity ? Json(*action->quantity) : Json(nullptr)},
             {"consents", std::move(consents)},
             {"reference", action->reference ? Json(*action->reference) : Json(nullptr)},
             {"by", actor_ref(session, *s.statement.actor_id)}});
    }
    const bool receivable = asset.kind == protocol::AssetKind::receivable;
    return {{"id", id_json(record.id)},
            {"type", record.record_type},
            {"state", record.state},
            {"holder", id_json(asset.holder)},
            {"pledgee", optional_id(asset.pledgee)},
            {"payee", optional_id(asset.payee)},
            {receivable ? "amount" : "quantity", asset.units},
            {receivable ? "currency" : "unit", m.unit},
            {"display", verifier::format_units(asset.kind, asset.units, m.unit)},
            {"due", m.due ? Json(iso_time(*m.due)) : Json(nullptr)},
            {"head", asset.head},
            {"issued_at", iso_time(session.log_entry(record.registered_at_index).registered_at)},
            {"actions", std::move(actions)}};
}

namespace {

void print_asset(const Session& session, const protocol::RecordState& record,
                 const protocol::AssetState& asset) {
    const protocol::AssetMetadata m = metadata_of(session, record, asset.kind);
    std::println("asset:     {} {}", record.record_type, hex_id(record.id));
    std::println("state:     {}", record.state);
    std::println("holder:    {}", ledger_label(session, asset.holder));
    if (asset.pledgee) {
        std::println("pledgee:   {}", ledger_label(session, *asset.pledgee));
    }
    if (asset.payee) {
        std::println("payee:     {}", ledger_label(session, *asset.payee));
    }
    std::println("{}    {}", asset.kind == protocol::AssetKind::receivable ? "amount:" : "units: ",
                 verifier::format_units(asset.kind, asset.units, m.unit));
    if (m.due) {
        std::println("due:       {}", format_time(*m.due));
    }
    std::println("head:      #{} (consents name it)", asset.head);
    for (const std::uint64_t index : record.history) {
        const protocol::SignedStatement s = session.statement(index);
        if (std::holds_alternative<protocol::AssetActionBody>(s.statement.body) ||
            index == record.registered_at_index) {
            std::println("  #{:<5} {}  {}", index,
                         format_time(session.log_entry(index).registered_at),
                         statement_summary(session, s));
        }
    }
}

/// An amount in a currency's major unit ("125000.50") in its minor unit.
std::uint64_t parse_amount(std::string_view text, std::string_view currency) {
    const int exponent = verifier::currency_exponent(currency);
    const auto dot = text.find('.');
    const std::string_view whole = text.substr(0, dot);
    const std::string_view fraction =
        dot == std::string_view::npos ? std::string_view() : text.substr(dot + 1);
    std::uint64_t major = 0;
    std::uint64_t minor = 0;
    const auto digits = [](std::string_view s) {
        return !s.empty() && std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; });
    };
    if (!digits(whole) || (dot != std::string_view::npos && !digits(fraction)) ||
        fraction.size() > static_cast<std::size_t>(exponent) ||
        std::from_chars(whole.data(), whole.data() + whole.size(), major).ec != std::errc{}) {
        throw UsageError{std::format("--amount is a number with at most {} decimal places in {}",
                                     exponent, currency)};
    }
    std::string padded(fraction);
    padded.resize(static_cast<std::size_t>(exponent), '0');
    if (!padded.empty()) {
        static_cast<void>(std::from_chars(padded.data(), padded.data() + padded.size(), minor));
    }
    std::uint64_t scale = 1;
    for (int i = 0; i < exponent; ++i) {
        scale *= 10;
    }
    if (major > (std::numeric_limits<std::uint64_t>::max() - minor) / scale) {
        throw UsageError{"--amount is too large"};
    }
    return major * scale + minor;
}

/// Answers from a peer's API, as JSON; throws on an error status.
Json peer_call(const node::Peer& peer, std::string_view method, const std::string& path,
               ByteView body = {}) {
    const auto response = unwrap(peer_client(peer).request(method, path, body, "application/cbor"),
                                 "reaching peer " + peer.name);
    const Json answer = Json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (response.status / 100 != 2) {
        std::string message = "status " + std::to_string(response.status);
        if (answer.is_object() && answer.contains("error")) {
            message = answer["error"].value("message", message);
        }
        throw CommandError{"peer " + peer.name + " refused: " + message};
    }
    return answer;
}

/// An asset's evidence from its home (a peer), verified for it.
std::pair<Bytes, protocol::AssetReport> fetch_asset(const node::Peer& home,
                                                    const protocol::Id& asset) {
    const auto response = unwrap(peer_client(home).request("GET", "/v1/assets/" + hex_id(asset)),
                                 "reaching peer " + home.name);
    if (response.status == 404) {
        throw CommandError{"peer " + home.name +
                           " shows this asset only to its parties: ask the holder for its "
                           "evidence (asset consent --evidence FILE), or give --head"};
    }
    if (response.status != 200) {
        throw CommandError{"peer " + home.name + " answered status " +
                           std::to_string(response.status)};
    }
    protocol::VerifyOptions options;
    options.expected_ledger = home.ledger_id;
    auto report = unwrap(protocol::verify_asset_evidence(shared_provider(), response.body, options),
                         "the asset's evidence from " + home.name + " does not verify");
    if (report.asset.record != asset) {
        throw CommandError{"peer " + home.name + " sent evidence of another asset"};
    }
    return {response.body, std::move(report)};
}

/// Adds the asset's private data the vault holds to its evidence:
/// `fields` (all of them if it names "*") and `attachments`.
Bytes with_disclosures(const Session& session, const Args& args, const Bytes& evidence,
                       const std::vector<std::string>& fields,
                       const std::vector<std::string>& attachments) {
    if (fields.empty() && attachments.empty()) {
        return evidence;
    }
    auto decoded = unwrap(protocol::decode_asset_evidence(evidence), "reading the evidence");
    auto bundle = unwrap(protocol::decode_bundle(decoded.asset_bundle), "reading the evidence");
    if (session.remote()) {
        static_cast<void>(session.fetch_vault(bundle.record));
    }
    const Vault vault = read_vault(session, bundle.record, args);
    const auto commitment =
        unwrap(protocol::commit_fields(session.provider(), session.state().hash(), vault.fields),
               "the asset's fields");
    const bool all = std::ranges::contains(fields, std::string("*"));
    for (const protocol::RecordField& f : commitment.fields) {
        if (all || std::ranges::contains(fields, f.name)) {
            bundle.disclosures.push_back(
                unwrap(protocol::disclose_field(session.provider(), session.state().hash(),
                                                commitment, f.name),
                       "disclosing " + f.name));
        }
    }
    for (const std::string& name : fields) {
        if (name != "*" &&
            !std::ranges::contains(commitment.fields, name, &protocol::RecordField::name)) {
            throw UsageError{"the asset has no field " + name};
        }
    }
    for (const VaultAttachment& a : vault.attachments) {
        if (std::ranges::contains(attachments, a.name) ||
            std::ranges::contains(attachments, std::string("*"))) {
            bundle.attachments.push_back({a.name, a.salt});
        }
    }
    decoded.asset_bundle = unwrap(protocol::encode_bundle(bundle), "encoding the evidence");
    return unwrap(protocol::encode_asset_evidence(decoded), "encoding the evidence");
}

std::vector<std::string> names_in(const Args& args, std::string_view option) {
    std::vector<std::string> out;
    for (const std::string& n : split(args.get(option).value_or(""), ',')) {
        if (!n.empty()) {
            out.push_back(n);
        }
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// The home: issuing, recording, showing
// ---------------------------------------------------------------------------

int cmd_asset_issue(const Args& args) {
    Session session(args);
    const protocol::AssetKind kind = kind_from(args.positional().front());
    const bool receivable = kind == protocol::AssetKind::receivable;
    for (const std::string_view option :
         receivable ? std::vector<std::string_view>{"quantity", "unit"}
                    : std::vector<std::string_view>{"amount", "currency", "due"}) {
        if (args.has(option)) {
            throw UsageError{std::format("--{} is not for a {}", option,
                                         receivable ? "receivable" : "warehouse receipt")};
        }
    }
    protocol::AssetMetadata m;
    m.holder = ledger_of(session, args.need("holder"));
    if (receivable) {
        m.unit = args.get("currency").value_or("CNY");
        m.units = parse_amount(args.need("amount"), m.unit);
        m.due = parse_time(args.need("due"));
    } else {
        m.units = parse_number(args.need("quantity"), "--quantity");
        m.unit = args.need("unit");
    }
    cbor::Map extra;
    if (const auto title = args.get("title")) {
        extra.push_back({cbor::Value::text("title"), cbor::Value::text(*title)});
    }
    for (const std::string& item : args.all("meta")) {
        auto [name, value] = split_pair(item, "--meta");
        extra.push_back({cbor::Value::text(name), cbor::Value::text(value)});
    }
    IssueRequest request;
    request.record_type = std::string(protocol::record_type_of(kind));
    request.metadata_value =
        unwrap(protocol::encode_asset_metadata(kind, m, extra), "the asset's metadata");
    for (const std::string& field : args.all("field")) {
        request.fields.push_back(split_pair(field, "--field"));
    }
    for (const std::string& path : args.all("attach")) {
        request.attachments.emplace_back(path);
    }
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id id = issue_record(session, *load_signer(args.need("as"), args), request);
    const auto [record, asset] = find_asset(session, hex_id(id));
    return report_submitted(args, session, id, {{"asset", asset_json(session, *record, *asset)}},
                            std::format("issued {} {}\nholder: {}\n{}: {}", record->record_type,
                                        hex_id(id), ledger_label(session, asset->holder),
                                        receivable ? "amount" : "units",
                                        verifier::format_units(kind, m.units, m.unit)));
}

int cmd_asset_show(const Args& args) {
    Session session(args);
    const auto [record, asset] = find_asset(session, args.positional().front());
    if (args.json()) {
        print_json(asset_json(session, *record, *asset));
    } else {
        print_asset(session, *record, *asset);
    }
    return exit_ok;
}

int cmd_asset_list(const Args& args) {
    Session session(args);
    const auto type = args.get("type");
    const auto state = args.get("state");
    const std::optional<protocol::Id> holder =
        args.has("holder") ? std::optional(ledger_of(session, *args.get("holder"))) : std::nullopt;
    Json out = Json::array();
    for (const auto& [key, asset] : session.state().assets()) {
        const protocol::RecordState& record = *session.state().record(asset.id);
        if ((type && record.record_type != protocol::record_type_of(kind_from(*type))) ||
            (state && record.state != *state) || (holder && asset.holder != *holder)) {
            continue;
        }
        if (args.json()) {
            out.push_back(asset_json(session, record, asset));
            continue;
        }
        const protocol::AssetMetadata m = metadata_of(session, record, asset.kind);
        std::println("{}  {:<28} {:<10} {:>20}  held by {}{}", short_id(asset.id),
                     record.record_type, record.state,
                     verifier::format_units(asset.kind, asset.units, m.unit),
                     ledger_label(session, asset.holder),
                     asset.pledgee ? ", pledged to " + ledger_label(session, *asset.pledgee) : "");
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_asset_record(const Args& args) {
    Session session(args);
    const protocol::AssetAction action = action_from(args.positional()[0]);
    const auto [record, asset] = find_asset(session, args.positional()[1]);
    protocol::AssetActionBody body;
    body.asset = record->id;
    body.action = action;
    body.head = asset->head;
    if (const auto to = args.get("to")) {
        body.to = ledger_of(session, *to);
    }
    if (const auto quantity = args.get("quantity")) {
        body.quantity = parse_number(*quantity, "--quantity");
    }
    body.reference = args.get("reference");
    // Each consent's evidence, as the party sent it: cited by its ledger,
    // its record, and its hash.
    std::vector<std::pair<protocol::ConsentRef, Bytes>> consents;
    for (const std::string& path : args.all("consent")) {
        Bytes bundle = read_file(path);
        const auto decoded = unwrap(protocol::decode_bundle(bundle), "reading " + path);
        const auto ledger = unwrap(protocol::bundle_ledger_id(bundle), "reading " + path);
        const auto digest =
            unwrap(session.provider().digest(session.state().hash(), bundle), "hashing " + path);
        consents.emplace_back(protocol::ConsentRef{ledger, decoded.record, digest},
                              std::move(bundle));
    }
    std::ranges::sort(consents, [](const auto& a, const auto& b) {
        return std::ranges::lexicographical_compare(a.first.ledger.bytes(), b.first.ledger.bytes());
    });
    std::vector<Bytes> bundles;
    for (auto& [ref, bundle] : consents) {
        body.consents.push_back(ref);
        bundles.push_back(std::move(bundle));
    }
    // Checked here first, for a clear answer (the ledger checks again).
    if (auto s =
            protocol::check_asset_action(*asset, record->state, body, session.state().ledger_id());
        !s) {
        throw CommandError{"the asset does not allow this: " + std::string(s.error().detail)};
    }
    unwrap(node::check_action_consents(session.provider(), session.state().ledger_id(),
                                       session.state().hash(), body, bundles,
                                       ledger::SystemClock{}.now()),
           "checking the consents");
    const auto signer = load_signer(args.need("as"), args);
    const protocol::Id id =
        session.submit(*signer, body, args.get("delegation"), session.provenance(args),
                       presence_request(args), {}, bundles);
    const auto [after, now] = find_asset(session, hex_id(record->id));
    return report_submitted(args, session, id, {{"asset", asset_json(session, *after, *now)}},
                            std::format("recorded {} of {}\nstate: {}", protocol::name(action),
                                        short_id(record->id), after->state));
}

int cmd_asset_evidence(const Args& args) {
    Session session(args);
    const auto [record, asset] = find_asset(session, args.positional().front());
    Bytes evidence = session.asset_evidence(args, record->id);
    evidence = with_disclosures(session, args, evidence, names_in(args, "fields"),
                                names_in(args, "attachments"));
    write_file(args.need("out"), evidence, false);
    if (args.json()) {
        print_json({{"asset", id_json(record->id)},
                    {"state", record->state},
                    {"out", args.need("out")},
                    {"size", evidence.size()}});
    } else {
        std::println("wrote the evidence of {} ({}) to {}", short_id(record->id), record->state,
                     args.need("out"));
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// A party: consenting on its own ledger
// ---------------------------------------------------------------------------

int cmd_asset_consent(const Args& args) {
    Session session(args);
    std::optional<node::Peer> home_peer;
    protocol::Id home;
    if (const auto peer = args.get("peer")) {
        if (session.remote()) {
            throw UsageError{"--peer needs this ledger's directory; with --server give --home"};
        }
        home_peer = peer_named(session.directory(), *peer);
        home = home_peer->ledger_id;
    } else {
        home = full_id(args.need("home"), "--home");
    }
    const protocol::Id asset = full_id(args.need("asset"), "--asset");
    protocol::AssetTerms terms{home, asset,        action_from(args.need("action")),
                               0,    std::nullopt, std::nullopt};
    if (const auto to = args.get("to")) {
        terms.to = ledger_of(session, *to);
    }
    if (const auto quantity = args.get("quantity")) {
        terms.quantity = parse_number(*quantity, "--quantity");
    }
    // The head this consent is to: as given, as the asset's evidence shows
    // it, or as its home shows it to this party now.
    if (const auto head = args.get("head")) {
        terms.head = parse_number(*head, "--head");
    } else if (const auto evidence = args.get("evidence")) {
        protocol::VerifyOptions options;
        options.expected_ledger = home;
        const auto report = unwrap(
            protocol::verify_asset_evidence(session.provider(), read_file(*evidence), options),
            "the asset's evidence does not verify");
        if (report.asset.record != asset) {
            throw UsageError{"the evidence is of another asset"};
        }
        terms.head = report.asset.asset->head;
    } else if (home_peer) {
        terms.head = fetch_asset(*home_peer, asset).second.asset.asset->head;
    } else {
        throw UsageError{"give --head, --evidence, or --peer (to ask the asset's home)"};
    }
    const std::uint64_t days =
        args.has("days") ? parse_number(*args.get("days"), "--days") : std::uint64_t{7};
    const protocol::AssetConsent consent{terms, ledger::SystemClock{}.now() + days * day_ms,
                                         args.get("reference")};

    IssueRequest request;
    request.record_type = std::string(protocol::asset_consent_type);
    request.fields.emplace_back("note", "consent to " + std::string(protocol::name(terms.action)));
    request.metadata_value = unwrap(protocol::encode_asset_consent(consent), "the consent");
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id record = issue_record(session, *load_signer(args.need("as"), args), request);
    static_cast<void>(session.checkpoint(args));
    const Bytes bundle =
        unwrap(protocol::encode_bundle(session.evidence(args, record)), "encoding the consent");
    if (const auto out = args.get("out")) {
        write_file(*out, bundle, false);
    }
    Json result{{"consent", id_json(record)}, {"home", id_json(home)},
                {"asset", id_json(asset)},    {"action", protocol::name(terms.action)},
                {"head", terms.head},         {"until", iso_time(consent.until)}};
    std::string text =
        std::format("consented to {} of {} (head #{}) as record {}", protocol::name(terms.action),
                    short_id(asset), terms.head, hex_id(record));
    if (args.has("send")) {
        if (!home_peer) {
            throw UsageError{"--send needs --peer (the asset's home)"};
        }
        const Json answer = peer_call(*home_peer, "POST", "/v1/assets/consents", bundle);
        result["home_answer"] = answer;
        text += "\n" + home_peer->name + ": " + answer.value("status", std::string("?"));
        if (answer.contains("missing") && !answer["missing"].empty()) {
            text += " (waiting for " + std::to_string(answer["missing"].size()) + " more)";
        }
    }
    if (args.json()) {
        print_json(result);
    } else {
        std::println("{}", text);
    }
    return exit_ok;
}

int cmd_asset_withdraw(const Args& args) {
    Session session(args);
    const protocol::Id record = session.record_id(args.positional().front());
    const protocol::RecordState* consent = session.state().record(record);
    if (consent->record_type != protocol::asset_consent_type) {
        throw UsageError{"record " + short_id(record) + " is not a consent"};
    }
    const protocol::Id id = session.submit(
        args, protocol::RecordTransitionBody{record, std::string(protocol::consent_given),
                                             std::string(protocol::consent_withdrawn)});
    return report_submitted(args, session, id, {{"consent", id_json(record)}},
                            "withdrew consent " + short_id(record));
}

int cmd_asset_send(const Args& args) {
    const node::Peer home = peer_named(args.ledger(), args.need("peer"));
    const Bytes bundle = read_file(args.positional().front());
    const Json answer = peer_call(home, "POST", "/v1/assets/consents", bundle);
    if (args.json()) {
        print_json(answer);
    } else {
        std::println("{}: {}", home.name, answer.value("status", std::string("?")));
        if (answer.contains("missing")) {
            for (const auto& m : answer["missing"]) {
                std::println("  still to consent: ledger {}", m.get<std::string>().substr(0, 12));
            }
        }
        if (answer.contains("statement_id")) {
            std::println("  recorded as {} (entry #{})", answer["statement_id"].get<std::string>(),
                         answer.value("index", std::uint64_t{0}));
        }
    }
    return exit_ok;
}

int cmd_asset_fetch(const Args& args) {
    const node::Peer home = peer_named(args.ledger(), args.need("peer"));
    const protocol::Id asset = full_id(args.need("asset"), "--asset");
    const auto [evidence, report] = fetch_asset(home, asset);
    write_file(args.need("out"), evidence, false);
    if (args.json()) {
        Json out = verifier::asset_report_json(report, true);
        out["out"] = args.need("out");
        print_json(out);
    } else {
        std::println("fetched the evidence of {} from {}: {} (verified), written to {}",
                     short_id(asset), home.name, report.asset.state, args.need("out"));
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// Anyone: verifying
// ---------------------------------------------------------------------------

int cmd_asset_verify(const Args& args) {
    const crypto::openssl::Provider provider;
    protocol::VerifyOptions options;
    if (const auto ledger_id = args.get("ledger-id")) {
        options.expected_ledger = full_id(*ledger_id, "--ledger-id");
    }
    for (const std::string& path : args.all("witness")) {
        options.trusted_witnesses.push_back(load_public_key(path));
    }
    for (const std::string& item : args.all("attachment")) {
        auto [name, path] = split_pair(item, "--attachment");
        options.attachment_contents[name] = read_file(path);
    }
    const auto report =
        protocol::verify_asset_evidence(provider, read_file(args.positional().front()), options);
    if (!report) {
        if (args.json()) {
            print_json({{"verified", false}, {"error", report.error().detail}});
        } else {
            std::println("VERIFICATION FAILED: {}", report.error().detail);
        }
        return exit_not_verified;
    }
    std::vector<std::string> problems;
    if (verifier::has_attachment_mismatch(report->asset)) {
        problems.emplace_back("an attachment does not match its commitment");
    }
    const std::uint64_t min_witnesses =
        args.has("min-witnesses") ? parse_number(*args.get("min-witnesses"), "--min-witnesses") : 0;
    if (report->asset.trusted_cosignatures < min_witnesses) {
        problems.push_back(std::format("{} trusted witness cosignatures, {} required",
                                       report->asset.trusted_cosignatures, min_witnesses));
    }
    if (args.has("require-presence")) {
        for (const protocol::AssetStep& step : report->steps) {
            for (const protocol::ConsentCheck& c : step.consents) {
                if (c.report.events.empty() || !c.report.events.front().presence) {
                    problems.push_back("a consent of " + c.report.organization +
                                       " was given without proof of a person's presence");
                }
            }
        }
    }
    const bool verified = problems.empty();
    if (args.json()) {
        Json out = verifier::asset_report_json(*report, options.expected_ledger.has_value());
        out["verified"] = verified;
        if (!verified) {
            out["error"] = problems.front();
        }
        print_json(out);
    } else {
        std::print("{}", verifier::asset_report_text(*report, options.expected_ledger.has_value()));
        for (const std::string& p : problems) {
            std::println("\nVERIFICATION FAILED: {}", p);
        }
    }
    return verified ? exit_ok : exit_not_verified;
}

} // namespace cexchain::cli
