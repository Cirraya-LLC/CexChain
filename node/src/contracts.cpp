// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <set>
#include <string>
#include <system_error>
#include <utility>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/node/contracts.hpp>

#include "files.hpp"

// Error propagation, as the protocol decoders do it (core/src/protocol/reader.hpp).
#define CEXCHAIN_CONCAT_INNER(a, b) a##b
#define CEXCHAIN_CONCAT(a, b) CEXCHAIN_CONCAT_INNER(a, b)
#define CEXCHAIN_TRY(decl, expr)                                                                   \
    auto CEXCHAIN_CONCAT(cexchain_try_, __LINE__) = (expr);                                        \
    if (!CEXCHAIN_CONCAT(cexchain_try_, __LINE__)) {                                               \
        return std::unexpected(CEXCHAIN_CONCAT(cexchain_try_, __LINE__).error());                  \
    }                                                                                              \
    decl = std::move(*CEXCHAIN_CONCAT(cexchain_try_, __LINE__))
#define CEXCHAIN_CHECK(expr)                                                                       \
    if (auto CEXCHAIN_CONCAT(cexchain_check_, __LINE__) = (expr);                                  \
        !CEXCHAIN_CONCAT(cexchain_check_, __LINE__)) {                                             \
        return std::unexpected(CEXCHAIN_CONCAT(cexchain_check_, __LINE__).error());                \
    }

namespace cexchain::node {

namespace {

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

bool before(const protocol::Id& a, const protocol::Id& b) {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

std::filesystem::path contracts_root(const std::filesystem::path& ledger_directory) {
    return ledger_directory / "contracts";
}

/// A pending file holds at most this much: the arguments, and 16 consents.
constexpr std::size_t max_pending_file =
    2 * protocol::max_contract_value + protocol::max_contract_consents * (max_consent_bundle + 64);
constexpr std::size_t max_proposer = 256;

std::optional<protocol::Id> id_value(const cbor::Value* value) {
    const Bytes* bytes = value != nullptr ? value->as_bytes() : nullptr;
    if (bytes == nullptr || bytes->size() != protocol::id_size) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

bool text_within(const std::string& text, std::size_t low, std::size_t high) {
    return text.size() >= low && text.size() <= high;
}

/// Checks the fields a proposal and a pending call share, and the rest.
Status check_call(const PendingCall& c, bool proposal) {
    if (!text_within(c.function, 1, protocol::max_function_name)) {
        return fail(Errc::malformed, "a function name is 1 to 64 bytes");
    }
    if (c.reference && !text_within(*c.reference, 1, protocol::max_contract_reference)) {
        return fail(Errc::malformed, "a call's reference is 1 to 1024 bytes");
    }
    CEXCHAIN_TRY(Bytes arguments, cbor::encode(c.arguments));
    if (arguments.size() > protocol::max_contract_value) {
        return fail(Errc::malformed, "a call's arguments are at most 65,536 bytes");
    }
    if (proposal) {
        if (!c.proposer.empty() || !c.missing.empty() || !c.consents.empty()) {
            return fail(Errc::malformed, "a proposal names the call, not its progress");
        }
        return {};
    }
    if (c.until == 0 || !text_within(c.proposer, 1, max_proposer)) {
        return fail(Errc::malformed, "a pending call has a lapse time and a proposer");
    }
    if (c.missing.size() > protocol::max_contract_consents ||
        c.consents.size() > protocol::max_contract_consents) {
        return fail(Errc::malformed, "a pending call holds at most 16 ledgers");
    }
    for (std::size_t i = 1; i < c.missing.size(); ++i) {
        if (!before(c.missing[i - 1], c.missing[i])) {
            return fail(Errc::malformed, "the missing ledgers ascend, each once");
        }
    }
    for (std::size_t i = 0; i < c.consents.size(); ++i) {
        if (c.consents[i].second.empty() || c.consents[i].second.size() > max_consent_bundle) {
            return fail(Errc::malformed, "a consent bundle is 1 byte to 256 KiB");
        }
        if (i > 0 && !before(c.consents[i - 1].first, c.consents[i].first)) {
            return fail(Errc::malformed, "the consents ascend by ledger, one per ledger");
        }
    }
    return {};
}

Result<Bytes> encode_call(const PendingCall& c, bool proposal) {
    CEXCHAIN_CHECK(check_call(c, proposal));
    cbor::Map map{{cbor::Value::integer(1), cbor::Value::bytes(c.instance.bytes())},
                  {cbor::Value::integer(2), cbor::Value::unsigned_integer(c.head)},
                  {cbor::Value::integer(3), cbor::Value::text(c.function)},
                  {cbor::Value::integer(4), c.arguments}};
    if (c.reference) {
        map.push_back({cbor::Value::integer(5), cbor::Value::text(*c.reference)});
    }
    if (c.until != 0) {
        map.push_back({cbor::Value::integer(6), cbor::Value::unsigned_integer(c.until)});
    }
    if (!proposal) {
        map.push_back({cbor::Value::integer(7), cbor::Value::text(c.proposer)});
        if (!c.missing.empty()) {
            cbor::Array missing;
            for (const protocol::Id& m : c.missing) {
                missing.push_back(cbor::Value::bytes(m.bytes()));
            }
            map.push_back({cbor::Value::integer(8), cbor::Value::array(std::move(missing))});
        }
        if (!c.consents.empty()) {
            cbor::Array consents;
            for (const auto& [ledger, bundle] : c.consents) {
                consents.push_back(cbor::Value::array(
                    {cbor::Value::bytes(ledger.bytes()), cbor::Value::bytes(bundle)}));
            }
            map.push_back({cbor::Value::integer(9), cbor::Value::array(std::move(consents))});
        }
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<PendingCall> decode_call(ByteView encoded, bool proposal) {
    if (encoded.size() > (proposal ? 2 * protocol::max_contract_value : max_pending_file)) {
        return fail(Errc::limit_exceeded, "a pending call is too large");
    }
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    if (map == nullptr) {
        return fail(Errc::malformed, "a call proposal is a map");
    }
    const std::uint64_t last_key = proposal ? 6 : 9;
    for (const cbor::MapEntry& e : *map) {
        const auto key = e.key.as_uint64();
        if (!key || *key < 1 || *key > last_key) {
            return fail(Errc::malformed, "a call proposal has an unknown key");
        }
    }
    PendingCall c;
    const auto instance = id_value(value->find(1));
    const cbor::Value* head = value->find(2);
    const cbor::Value* function = value->find(3);
    const cbor::Value* arguments = value->find(4);
    if (!instance || head == nullptr || !head->as_uint64() || function == nullptr ||
        function->as_text() == nullptr || arguments == nullptr) {
        return fail(Errc::malformed, "a call proposal names an instance, a head, a function, and "
                                     "the arguments");
    }
    c.instance = *instance;
    c.head = *head->as_uint64();
    c.function = *function->as_text();
    c.arguments = *arguments;
    if (const cbor::Value* reference = value->find(5)) {
        if (reference->as_text() == nullptr) {
            return fail(Errc::malformed, "a call's reference is text");
        }
        c.reference = *reference->as_text();
    }
    if (const cbor::Value* until = value->find(6)) {
        if (!until->as_uint64() || *until->as_uint64() == 0) {
            return fail(Errc::malformed, "a lapse time is a positive number of milliseconds");
        }
        c.until = *until->as_uint64();
    }
    if (const cbor::Value* proposer = value->find(7)) {
        if (proposer->as_text() == nullptr) {
            return fail(Errc::malformed, "a proposer is named in text");
        }
        c.proposer = *proposer->as_text();
    }
    if (const cbor::Value* missing = value->find(8)) {
        const cbor::Array* items = missing->as_array();
        if (items == nullptr || items->empty()) {
            return fail(Errc::malformed, "missing ledgers are a non-empty list, or absent");
        }
        for (const cbor::Value& item : *items) {
            const auto ledger = id_value(&item);
            if (!ledger) {
                return fail(Errc::malformed, "a ledger is a 32-byte id");
            }
            c.missing.push_back(*ledger);
        }
    }
    if (const cbor::Value* consents = value->find(9)) {
        const cbor::Array* items = consents->as_array();
        if (items == nullptr || items->empty()) {
            return fail(Errc::malformed, "consents are a non-empty list, or absent");
        }
        for (const cbor::Value& item : *items) {
            const cbor::Array* parts = item.as_array();
            const auto ledger = parts != nullptr && parts->size() == 2
                                    ? id_value(&(*parts)[0])
                                    : std::optional<protocol::Id>();
            if (!ledger || (*parts)[1].as_bytes() == nullptr) {
                return fail(Errc::malformed, "a consent is [ledger, bundle]");
            }
            c.consents.emplace_back(*ledger, *(*parts)[1].as_bytes());
        }
    }
    CEXCHAIN_CHECK(check_call(c, proposal));
    return c;
}

/// Sorted by ledger, one per ledger: `bundle` replaces `party`'s.
void hold(std::vector<std::pair<protocol::Id, Bytes>>& consents, const protocol::Id& party,
          ByteView bundle) {
    const auto it =
        std::ranges::lower_bound(consents, party, before, &std::pair<protocol::Id, Bytes>::first);
    if (it != consents.end() && it->first == party) {
        it->second.assign(bundle.begin(), bundle.end());
    } else {
        consents.emplace(it, party, Bytes(bundle.begin(), bundle.end()));
    }
}

/// The report verified ahead for exactly this party and bundle, if any.
const protocol::EvidenceReport* verified_report(std::span<const VerifiedConsent> verified,
                                                const protocol::Id& party, ByteView bundle) {
    for (const VerifiedConsent& v : verified) {
        if (v.party == party && std::ranges::equal(v.bundle, bundle)) {
            return &v.report;
        }
    }
    return nullptr;
}

/// A consent's citation, checked against `call` at `now`: its signer is the
/// one the bundle shows signed the consent's registration. The bundle is
/// verified here unless `verified` holds it.
Result<protocol::ContractConsentRef>
citation(const crypto::Provider& provider, const protocol::LedgerState& state,
         const protocol::ContractCallBody& call, const protocol::Id& party, ByteView bundle,
         protocol::Timestamp now, std::span<const VerifiedConsent> verified) {
    std::optional<protocol::EvidenceReport> report;
    if (const protocol::EvidenceReport* ahead = verified_report(verified, party, bundle)) {
        report = *ahead;
    } else {
        protocol::VerifyOptions options;
        options.expected_ledger = party;
        auto checked = protocol::verify_bundle(provider, bundle, options);
        if (!checked) {
            return std::unexpected(checked.error());
        }
        report = std::move(*checked);
    }
    if (report->events.empty()) {
        return fail(Errc::verification_failed, "the consent's evidence shows no registration");
    }
    CEXCHAIN_TRY(crypto::Digest digest, provider.digest(state.hash(), bundle));
    const protocol::ContractConsentRef ref{party, report->record, digest,
                                           protocol::registration_signer(report->events.front())};
    CEXCHAIN_CHECK(protocol::check_verified_contract_consent(
        provider, ref, bundle, std::move(*report), call, state.ledger_id(), state.hash(), now));
    return ref;
}

/// The pending calls' names under `ledger_directory`, in name order.
std::vector<PendingName> pending_names(const std::filesystem::path& ledger_directory) {
    std::vector<std::pair<std::string, PendingName>> named;
    std::error_code ec;
    for (auto it =
             std::filesystem::directory_iterator(pending_calls_directory(ledger_directory), ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        std::string file = it->path().filename().string();
        if (auto name = parse_pending_call_name(file)) {
            named.emplace_back(std::move(file), *name);
        }
    }
    // A name's text is the name itself: sort by the text read.
    std::ranges::sort(named, {}, &std::pair<std::string, PendingName>::first);
    std::vector<PendingName> out;
    out.reserve(named.size());
    for (auto& [file, name] : named) {
        out.push_back(name);
    }
    return out;
}

/// How many pending calls are held (as pending_names counts them).
std::size_t pending_count(const std::filesystem::path& ledger_directory) {
    std::size_t n = 0;
    std::error_code ec;
    for (auto it =
             std::filesystem::directory_iterator(pending_calls_directory(ledger_directory), ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        n += parse_pending_call_name(it->path().filename().string()) ? 1U : 0U;
    }
    return n;
}

/// The pending call held under exactly this name, if its file decodes.
std::optional<HeldCall> held_at(const std::filesystem::path& ledger_directory,
                                const PendingName& name) {
    auto file =
        detail::read_file(pending_calls_directory(ledger_directory) / pending_call_name(name));
    auto call =
        file ? decode_pending_call(*file) : Result<PendingCall>(std::unexpected(file.error()));
    if (!call) {
        return std::nullopt;
    }
    return HeldCall{name, std::move(*call)};
}

PendingChange removal(const PendingName& name) {
    return {pending_call_name(name), std::nullopt};
}

/// Text a contract wrote as its reason, for people: printable ASCII and
/// UTF-8 as they are, anything else as '?'.
std::string readable(ByteView reason) {
    const std::string text(reason.begin(), reason.end());
    if (cbor::is_valid_utf8(text) &&
        std::ranges::none_of(text, [](char c) { return static_cast<unsigned char>(c) < 0x20; })) {
        return text;
    }
    std::string out;
    for (const std::uint8_t b : reason) {
        out.push_back(b >= 0x20 && b < 0x7f ? static_cast<char>(b) : '?');
    }
    return out;
}

} // namespace

std::filesystem::path contract_consents_directory(const std::filesystem::path& ledger_directory) {
    return contracts_root(ledger_directory) / "consents";
}

std::filesystem::path contract_consents_path(const std::filesystem::path& ledger_directory,
                                             const protocol::Id& call) {
    return contract_consents_directory(ledger_directory) / (hex(call) + ".cbor");
}

std::filesystem::path pending_calls_directory(const std::filesystem::path& ledger_directory) {
    return contracts_root(ledger_directory) / "pending";
}

Result<Bytes> encode_consent_bundles(std::span<const Bytes> bundles) {
    cbor::Array list;
    for (const Bytes& b : bundles) {
        list.push_back(cbor::Value::bytes(b));
    }
    return cbor::encode(cbor::Value::array(std::move(list)));
}

Result<std::vector<Bytes>> decode_consent_bundles(ByteView encoded, std::size_t max) {
    cbor::DecodeOptions options;
    options.max_items = max + 1;
    auto value = cbor::decode(encoded, options);
    const cbor::Array* list = value ? value->as_array() : nullptr;
    if (list == nullptr || list->empty() || list->size() > max) {
        return fail(Errc::malformed, "consent bundles are a list of byte strings, one per consent");
    }
    std::vector<Bytes> out;
    for (const cbor::Value& item : *list) {
        if (item.as_bytes() == nullptr) {
            return fail(Errc::malformed,
                        "consent bundles are a list of byte strings, one per consent");
        }
        out.push_back(*item.as_bytes());
    }
    return out;
}

Status store_consents_file(const std::filesystem::path& path, ByteView encoded,
                           bool sync_directory) {
    if (auto held = detail::read_file(path)) {
        if (!std::ranges::equal(*held, encoded)) {
            return fail(Errc::rejected, "other consent evidence is kept for this call");
        }
        return {};
    }
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the consents' directory");
    }
    return detail::write_file(path, encoded, true, sync_directory);
}

std::optional<protocol::Id>
choose_delegation(const protocol::LedgerState& state, const protocol::Id& actor,
                  protocol::StatementType type, const std::optional<std::string>& record_type,
                  protocol::Timestamp now, const std::optional<protocol::Id>& contract,
                  const protocol::ContractCallBody* call) {
    // What scope keys 8 and 9 (v0.8) need of a call: its function, and the
    // kind of the request it answers (none: it answers nothing).
    const protocol::RequestState* answered =
        call != nullptr && call->answer ? state.request(call->answer->request) : nullptr;
    auto covers_call = [&](const protocol::Scope& scope) {
        if (call == nullptr) {
            return true;
        }
        return (!scope.functions || std::ranges::contains(*scope.functions, call->function)) &&
               (!scope.request_kinds ||
                (answered != nullptr &&
                 std::ranges::contains(*scope.request_kinds, answered->kind)));
    };
    std::optional<protocol::Id> chosen;
    std::uint64_t newest = 0;
    for (const auto& [key, d] : state.delegations()) {
        const bool usable = d.grantee == actor && !d.revoked &&
                            std::ranges::contains(d.scope.statement_types, type) &&
                            (!record_type || !d.scope.record_types ||
                             std::ranges::contains(*d.scope.record_types, *record_type)) &&
                            (!contract || !d.scope.contracts ||
                             std::ranges::contains(*d.scope.contracts, *contract)) &&
                            (!d.scope.not_before || *d.scope.not_before <= now) &&
                            (!d.scope.not_after || now <= *d.scope.not_after) &&
                            covers_call(d.scope);
        if (usable && (!chosen || d.granted_at_index > newest)) {
            chosen = d.id;
            newest = d.granted_at_index;
        }
    }
    return chosen;
}

Status check_call_consents(const crypto::Provider& provider, const protocol::Id& home,
                           crypto::HashAlg hash, const protocol::ContractCallBody& call,
                           std::span<const Bytes> bundles, protocol::Timestamp now) {
    if (bundles.size() != call.consents.size()) {
        return fail(Errc::invalid_argument,
                    "a contract call comes with the evidence of each consent it cites, in order");
    }
    for (std::size_t i = 0; i < bundles.size(); ++i) {
        auto checked = protocol::check_contract_consent(provider, call.consents[i], bundles[i],
                                                        call, home, hash, now);
        if (!checked) {
            return std::unexpected(checked.error());
        }
    }
    return {};
}

bool cites_contract_consents(const protocol::Statement& statement) {
    const auto* call = std::get_if<protocol::ContractCallBody>(&statement.body);
    return call != nullptr && !call->consents.empty();
}

std::vector<protocol::Id> ancestor_ids(const protocol::LedgerState& state,
                                       const protocol::Id& instance) {
    std::vector<protocol::Id> out;
    if (const protocol::InstanceState* i = state.instance(instance)) {
        for (const protocol::InstanceAncestor& a : protocol::instance_ancestors(state, *i)) {
            out.push_back(a.instance->id);
        }
    }
    return out;
}

Result<Bytes> contract_evidence(const crypto::Provider& provider,
                                const std::filesystem::path& ledger_directory,
                                const protocol::EvidenceBundle& instance_bundle,
                                std::span<const protocol::Id> ancestors) {
    if (instance_bundle.entries.empty()) {
        return fail(Errc::invalid_argument, "the instance's bundle is empty");
    }
    auto genesis = protocol::decode_log_entry(instance_bundle.entries.front().entry);
    if (!genesis) {
        return std::unexpected(genesis.error());
    }
    auto parsed_genesis = protocol::parse_statement(provider, genesis->statement);
    const auto* body = parsed_genesis
                           ? std::get_if<protocol::GenesisBody>(&parsed_genesis->statement.body)
                           : nullptr;
    if (body == nullptr) {
        return fail(Errc::malformed, "the instance's bundle does not start with genesis");
    }
    protocol::ContractEvidence evidence;
    std::set<Bytes> seen;
    for (const protocol::EvidenceEntry& e : instance_bundle.entries) {
        auto entry = protocol::decode_log_entry(e.entry);
        if (!entry || entry->is_state_commitment() ||
            entry->statement_id == genesis->statement_id) {
            continue;
        }
        auto statement = protocol::parse_statement(provider, entry->statement, body->hash_alg);
        if (!statement) {
            return std::unexpected(statement.error());
        }
        const auto* call = std::get_if<protocol::ContractCallBody>(&statement->statement.body);
        // Creations cite no consents: only calls on the instance, or on its
        // ancestors (whose calls the bundle holds up to each one that created
        // the next generation), do.
        if (call == nullptr || !call->instance || call->consents.empty() ||
            (*call->instance != instance_bundle.record &&
             !std::ranges::contains(ancestors, *call->instance))) {
            continue;
        }
        auto held = detail::read_file(contract_consents_path(ledger_directory, statement->id));
        if (!held) {
            return fail(Errc::not_found, "the consents a contract call cites are not kept here");
        }
        auto bundles = decode_consent_bundles(*held, protocol::max_contract_consents);
        if (!bundles) {
            return std::unexpected(bundles.error());
        }
        for (Bytes& b : *bundles) {
            if (seen.insert(b).second) {
                evidence.consent_bundles.push_back(std::move(b));
            }
        }
    }
    auto encoded_bundle = protocol::encode_bundle(instance_bundle);
    if (!encoded_bundle) {
        return std::unexpected(encoded_bundle.error());
    }
    evidence.instance_bundle = std::move(*encoded_bundle);
    return protocol::encode_contract_evidence(evidence);
}

Result<protocol::Statement> contract_call_statement(const crypto::Provider& provider,
                                                    const protocol::LedgerState& state,
                                                    const crypto::Signer& signer,
                                                    const protocol::ContractCallBody& call,
                                                    protocol::Timestamp now) {
    auto kid = protocol::key_id(provider, state.hash(), signer.public_key());
    if (!kid) {
        return std::unexpected(kid.error());
    }
    const protocol::ActorState* actor = state.actor_by_kid(*kid);
    if (actor == nullptr || actor->revoked) {
        return fail(Errc::rejected, "the registrar key is not an active actor's of this ledger");
    }
    const protocol::InstanceState* instance =
        call.instance ? state.instance(*call.instance) : nullptr;
    const std::optional<protocol::Id> contract =
        instance != nullptr ? std::optional<protocol::Id>(instance->contract) : call.contract;
    if (!contract) {
        return fail(Errc::not_found, "no such instance");
    }
    protocol::Statement statement;
    statement.ledger_id = state.ledger_id();
    statement.actor_id = actor->id;
    if (!actor->is_organization()) {
        statement.delegation_id =
            choose_delegation(state, actor->id, protocol::StatementType::contract_call,
                              std::nullopt, now, contract, &call);
        if (!statement.delegation_id) {
            return fail(Errc::rejected,
                        "the registrar has no delegation for calls on this contract");
        }
    }
    statement.issued_at = now;
    statement.body = call;
    return statement;
}

Result<protocol::SignedStatement>
sign_contract_call(const crypto::Provider& provider, const protocol::LedgerState& state,
                   const crypto::Signer& signer, const protocol::ContractCallBody& call,
                   protocol::Timestamp now, ledger::Entropy& entropy) {
    auto statement = contract_call_statement(provider, state, signer, call, now);
    if (!statement) {
        return std::unexpected(statement.error());
    }
    statement->nonce = entropy.bytes<16>();
    return protocol::sign_statement(signer, provider, state.hash(), *statement);
}

Result<Bytes> encode_call_proposal(const PendingCall& proposal) {
    return encode_call(proposal, true);
}

Result<PendingCall> decode_call_proposal(ByteView encoded) {
    return decode_call(encoded, true);
}

Result<Bytes> encode_pending_call(const PendingCall& call) {
    return encode_call(call, false);
}

Result<PendingCall> decode_pending_call(ByteView encoded) {
    return decode_call(encoded, false);
}

protocol::ContractCallBody call_body(const PendingCall& call) {
    protocol::ContractCallBody body;
    body.instance = call.instance;
    body.head = call.head;
    body.function = call.function;
    body.arguments = call.arguments;
    body.reference = call.reference;
    return body;
}

Result<protocol::Id> pending_call_id(const crypto::Provider& provider, const protocol::Id& instance,
                                     std::uint64_t head, std::string_view function,
                                     const protocol::Id& arguments) {
    CEXCHAIN_TRY(
        Bytes encoded,
        cbor::encode(cbor::Value::array(
            {cbor::Value::bytes(instance.bytes()), cbor::Value::unsigned_integer(head),
             cbor::Value::text(std::string(function)), cbor::Value::bytes(arguments.bytes())})));
    return provider.digest(crypto::HashAlg::sha256, encoded);
}

Result<protocol::Id> pending_call_id(const crypto::Provider& provider, crypto::HashAlg hash,
                                     const PendingCall& call) {
    CEXCHAIN_TRY(protocol::Id arguments,
                 protocol::contract_arguments_digest(provider, hash, call.arguments));
    return pending_call_id(provider, call.instance, call.head, call.function, arguments);
}

std::string pending_call_name(const PendingName& name) {
    return hex(name.instance) + "-" + std::to_string(name.head) + "-" + hex(name.id) + ".cbor";
}

std::optional<PendingName> parse_pending_call_name(std::string_view file_name) {
    constexpr std::string_view extension = ".cbor";
    constexpr std::size_t id_hex = 2 * protocol::id_size;
    if (!file_name.ends_with(extension)) {
        return std::nullopt;
    }
    const std::string_view stem = file_name.substr(0, file_name.size() - extension.size());
    if (stem.size() < 2 * id_hex + 3 || stem[id_hex] != '-' ||
        stem[stem.size() - id_hex - 1] != '-') {
        return std::nullopt;
    }
    const std::string_view head = stem.substr(id_hex + 1, stem.size() - 2 * id_hex - 2);
    auto lower_hex = [](std::string_view text) {
        return std::ranges::all_of(
            text, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
    };
    const std::string_view instance = stem.substr(0, id_hex);
    const std::string_view id = stem.substr(stem.size() - id_hex);
    if (!lower_hex(instance) || !lower_hex(id) || head.empty() || head.size() > 20 ||
        (head.size() > 1 && head.front() == '0')) {
        return std::nullopt;
    }
    PendingName out;
    const auto [end, ec] = std::from_chars(head.data(), head.data() + head.size(), out.head);
    if (ec != std::errc{} || end != head.data() + head.size()) {
        return std::nullopt;
    }
    auto instance_bytes = from_hex(instance);
    auto id_bytes = from_hex(id);
    auto instance_id = instance_bytes
                           ? protocol::to_id(*instance_bytes)
                           : Result<protocol::Id>(std::unexpected(instance_bytes.error()));
    auto call_id = id_bytes ? protocol::to_id(*id_bytes)
                            : Result<protocol::Id>(std::unexpected(id_bytes.error()));
    if (!instance_id || !call_id) {
        return std::nullopt;
    }
    out.instance = *instance_id;
    out.id = *call_id;
    return out;
}

cbor::Value pending_changes_value(std::span<const PendingChange> changes) {
    cbor::Array list;
    for (const PendingChange& c : changes) {
        list.push_back(
            cbor::Value::array({cbor::Value::text(c.name),
                                c.file ? cbor::Value::bytes(*c.file) : cbor::Value::null()}));
    }
    return cbor::Value::array(std::move(list));
}

Result<std::vector<PendingChange>> decode_pending_changes(const cbor::Value& value) {
    const cbor::Array* list = value.as_array();
    if (list == nullptr || list->size() > 2 * max_pending_calls) {
        return fail(Errc::malformed, "pending changes are a list");
    }
    std::vector<PendingChange> out;
    for (const cbor::Value& item : *list) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_text() == nullptr ||
            ((*parts)[1].as_bytes() == nullptr && !(*parts)[1].is_null())) {
            return fail(Errc::malformed, "a pending change is [name, file or null]");
        }
        PendingChange change{*(*parts)[0].as_text(), std::nullopt};
        if (const Bytes* file = (*parts)[1].as_bytes()) {
            change.file = *file;
        }
        out.push_back(std::move(change));
    }
    return out;
}

Status apply_pending_changes(const std::filesystem::path& ledger_directory,
                             std::span<const PendingChange> changes, bool sync_directory) {
    for (const PendingChange& c : changes) {
        const auto name = parse_pending_call_name(c.name);
        if (!name) {
            return fail(Errc::malformed, "not a pending call's name");
        }
        if (c.file) {
            auto call = decode_pending_call(*c.file);
            if (!call || call->instance != name->instance || call->head != name->head) {
                return fail(Errc::malformed, "a pending call's file does not match its name");
            }
        }
    }
    const std::filesystem::path directory = pending_calls_directory(ledger_directory);
    std::error_code ec;
    bool written = false;
    for (const PendingChange& c : changes) {
        if (c.file) {
            std::filesystem::create_directories(directory, ec);
            if (ec) {
                return fail(Errc::unavailable, "cannot create the pending calls' directory");
            }
            CEXCHAIN_CHECK(detail::write_file(directory / c.name, *c.file, true, false));
            written = true;
        } else {
            std::filesystem::remove(directory / c.name, ec);
        }
    }
    // The files renamed into place, durable at once.
    if (written && sync_directory) {
        detail::sync_directory(directory);
    }
    return {};
}

std::vector<HeldCall> held_calls(const std::filesystem::path& ledger_directory) {
    std::vector<HeldCall> out;
    for (const PendingName& name : pending_names(ledger_directory)) {
        auto file =
            detail::read_file(pending_calls_directory(ledger_directory) / pending_call_name(name));
        auto call =
            file ? decode_pending_call(*file) : Result<PendingCall>(std::unexpected(file.error()));
        if (call) {
            out.push_back({name, std::move(*call)});
        }
    }
    return out;
}

std::optional<HeldCall> held_call(const std::filesystem::path& ledger_directory,
                                  const protocol::Id& id) {
    for (const PendingName& name : pending_names(ledger_directory)) {
        if (name.id != id) {
            continue;
        }
        auto file =
            detail::read_file(pending_calls_directory(ledger_directory) / pending_call_name(name));
        auto call =
            file ? decode_pending_call(*file) : Result<PendingCall>(std::unexpected(file.error()));
        if (call) {
            return HeldCall{name, std::move(*call)};
        }
    }
    return std::nullopt;
}

bool concerns(const protocol::LedgerState& state, const PendingCall& call,
              const protocol::Id& ledger) {
    if (const protocol::InstanceState* instance = state.instance(call.instance)) {
        for (const auto& [role, party] : instance->parties) {
            if (party == ledger) {
                return true;
            }
        }
    }
    return std::ranges::contains(call.missing, ledger) ||
           std::ranges::contains(call.consents, ledger, &std::pair<protocol::Id, Bytes>::first);
}

CallRegistrar::CallRegistrar(std::filesystem::path ledger_directory, const crypto::Signer& signer)
    : directory_(std::move(ledger_directory)), signer_(&signer) {}

Result<CallProgress> CallRegistrar::propose(const crypto::Provider& provider,
                                            const protocol::LedgerState& state,
                                            PendingCall proposal,
                                            const std::optional<protocol::Id>& party,
                                            protocol::Timestamp now, ledger::Entropy& entropy) {
    if (proposal.until == 0) {
        proposal.until = now + default_pending_lifetime;
    }
    if (proposal.until <= now) {
        return fail(Errc::invalid_argument, "the proposal has lapsed already");
    }
    if (proposal.until - now > max_pending_lifetime) {
        return fail(Errc::invalid_argument, "a proposal lapses within 30 days");
    }
    const protocol::InstanceState* instance = state.instance(proposal.instance);
    const bool party_of = instance != nullptr &&
                          (!party || std::ranges::any_of(instance->parties, [&](const auto& p) {
                              return p.second == *party;
                          }));
    if (!party_of) {
        return fail(Errc::not_found, "no such instance");
    }
    if (instance->final) {
        return fail(Errc::rejected, "the instance is final: it takes no more calls");
    }
    if (proposal.head != instance->head) {
        return fail(Errc::rejected, "the head is not the instance's: it moved on");
    }
    const protocol::ContractState* contract = state.contract(instance->contract);
    bool acts = false;
    if (contract != nullptr) {
        const auto function = contract->interface.find(proposal.function);
        acts = function != contract->interface.end() &&
               function->second == protocol::FunctionKind::call;
    }
    if (!acts) {
        return fail(Errc::invalid_argument, "the contract has no such function on instances");
    }
    CallProgress progress;
    CEXCHAIN_TRY(progress.id, pending_call_id(provider, state.hash(), proposal));
    if (auto held = held_at(directory_, {proposal.instance, proposal.head, progress.id});
        held && held->call.until >= now) {
        if (held->call.reference != proposal.reference) {
            return fail(Errc::rejected,
                        "a call with these terms is pending with another reference");
        }
        progress.call = std::move(held->call);
        return progress; // waiting, as it stands
    }
    if (const std::size_t held_now = pending_count(directory_); held_now >= max_pending_calls) {
        progress.changes = sweep(state, now, true); // removals of held calls only
        if (held_now - progress.changes.size() >= max_pending_calls) {
            return fail(Errc::unavailable,
                        "the registrar holds too many pending calls; retry later");
        }
    }
    proposal.missing.clear();
    proposal.consents.clear();
    progress.call = std::move(proposal);
    CEXCHAIN_TRY(progress, run(provider, state, std::move(progress), now, entropy, {}));
    if (progress.verdict == CallProgress::Verdict::accepted) {
        return fail(Errc::rejected,
                    "the contract takes this call without consents: the home signs it itself");
    }
    if (progress.verdict == CallProgress::Verdict::waiting) {
        CEXCHAIN_TRY(Bytes file, encode_pending_call(progress.call));
        progress.changes.push_back(
            {pending_call_name({progress.call.instance, progress.call.head, progress.id}),
             std::move(file)});
    }
    return progress;
}

Result<VerifiedConsent> verify_consent(const crypto::Provider& provider, const protocol::Id& party,
                                       ByteView bundle) {
    protocol::VerifyOptions options;
    options.expected_ledger = party;
    auto report = protocol::verify_bundle(provider, bundle, options);
    if (!report) {
        return std::unexpected(report.error());
    }
    return VerifiedConsent{party, Bytes(bundle.begin(), bundle.end()), std::move(*report)};
}

Result<PreparedConsent> CallRegistrar::prepare(const crypto::Provider& provider,
                                               const protocol::Id& party, ByteView bundle) const {
    PreparedConsent out;
    CEXCHAIN_TRY(out.consent, verify_consent(provider, party, bundle));
    const protocol::EvidenceReport& report = out.consent.report;
    if (report.record_type != protocol::contract_consent_type || !report.metadata) {
        return out; // `consent` says why
    }
    auto terms = protocol::decode_contract_consent(*report.metadata);
    if (!terms) {
        return out;
    }
    out.instance = terms->instance;
    // The consents held for the call: verified here too, so that the writer
    // need not (a file changed meanwhile is read and checked again there).
    auto id =
        pending_call_id(provider, terms->instance, terms->head, terms->function, terms->arguments);
    auto held = id ? held_at(directory_, {terms->instance, terms->head, *id}) : std::nullopt;
    if (held) {
        for (const auto& [ledger, held_bundle] : held->call.consents) {
            if (ledger == party && std::ranges::equal(held_bundle, bundle)) {
                continue;
            }
            if (auto v = verify_consent(provider, ledger, held_bundle)) {
                out.held.push_back(std::move(*v));
            }
        }
    }
    return out;
}

Result<CallProgress> CallRegistrar::consent(const crypto::Provider& provider,
                                            const protocol::LedgerState& state,
                                            const PreparedConsent& prepared,
                                            protocol::Timestamp now, ledger::Entropy& entropy) {
    // The terms, from the party's own ledger.
    const protocol::Id& party = prepared.consent.party;
    const ByteView bundle = prepared.consent.bundle;
    const protocol::EvidenceReport& report = prepared.consent.report;
    if (report.record_type != protocol::contract_consent_type || !report.metadata) {
        return fail(Errc::invalid_argument, "the evidence is not of a contract consent");
    }
    CEXCHAIN_TRY(protocol::ContractConsent terms,
                 protocol::decode_contract_consent(*report.metadata));
    if (terms.ledger != state.ledger_id()) {
        return fail(Errc::invalid_argument, "the consent is to a call on another ledger");
    }
    const protocol::InstanceState* instance = state.instance(terms.instance);
    if (instance == nullptr) {
        return fail(Errc::not_found, "no such instance on this ledger");
    }
    if (terms.head != instance->head) {
        return fail(Errc::rejected,
                    "the consent is to an earlier head of the instance: it can no longer be used");
    }

    // The pending call it is to.
    CallProgress progress;
    CEXCHAIN_TRY(progress.id, pending_call_id(provider, terms.instance, terms.head, terms.function,
                                              terms.arguments));
    auto held = held_at(directory_, {terms.instance, terms.head, progress.id});
    if (!held) {
        return fail(Errc::not_found, "no call with these terms is pending: propose it first");
    }
    if (held->call.until < now) {
        return fail(Errc::rejected, "the pending call has lapsed");
    }
    if (!std::ranges::contains(held->call.missing, party) &&
        !std::ranges::contains(held->call.consents, party,
                               &std::pair<protocol::Id, Bytes>::first)) {
        return fail(Errc::invalid_argument, "the contract did not ask for your ledger's consent");
    }
    // Verified ahead: the consent and the held ones.
    std::vector<VerifiedConsent> verified;
    verified.reserve(1 + prepared.held.size());
    verified.push_back(prepared.consent);
    verified.insert(verified.end(), prepared.held.begin(), prepared.held.end());
    CEXCHAIN_CHECK(citation(provider, state, call_body(held->call), party, bundle, now, verified));
    progress.call = std::move(held->call);
    hold(progress.call.consents, party, bundle);
    CEXCHAIN_TRY(progress, run(provider, state, std::move(progress), now, entropy, verified));
    if (progress.verdict == CallProgress::Verdict::waiting) {
        CEXCHAIN_TRY(Bytes file, encode_pending_call(progress.call));
        progress.changes.push_back(
            {pending_call_name({progress.call.instance, progress.call.head, progress.id}),
             std::move(file)});
    }
    return progress;
}

std::vector<PendingChange> CallRegistrar::sweep(const protocol::LedgerState& state,
                                                protocol::Timestamp now, bool lapsed) const {
    std::vector<PendingChange> out;
    for (const PendingName& name : pending_names(directory_)) {
        const protocol::InstanceState* instance = state.instance(name.instance);
        if (instance == nullptr || instance->final || instance->head != name.head) {
            out.push_back(removal(name));
            continue;
        }
        if (lapsed) {
            auto file =
                detail::read_file(pending_calls_directory(directory_) / pending_call_name(name));
            auto call = file ? decode_pending_call(*file)
                             : Result<PendingCall>(std::unexpected(file.error()));
            if (!call || call->until < now) {
                out.push_back(removal(name));
            }
        }
    }
    return out;
}

Result<CallProgress> CallRegistrar::run(const crypto::Provider& provider,
                                        const protocol::LedgerState& state, CallProgress progress,
                                        protocol::Timestamp now, ledger::Entropy& entropy,
                                        std::span<const VerifiedConsent> verified) const {
    // The consents held, checked again: they may have lapsed while waiting.
    protocol::ContractCallBody body = call_body(progress.call);
    std::vector<std::pair<protocol::Id, Bytes>> live;
    for (auto& [ledger, bundle] : progress.call.consents) {
        if (auto ref = citation(provider, state, body, ledger, bundle, now, verified)) {
            body.consents.push_back(*ref);
            live.emplace_back(ledger, std::move(bundle));
        }
    }
    progress.call.consents = std::move(live);
    auto signed_call = sign_contract_call(provider, state, *signer_, body, now, entropy);
    if (!signed_call) {
        return std::unexpected(signed_call.error());
    }
    auto run = state.run_contract(provider, *signed_call, now);
    if (!run) {
        return std::unexpected(run.error());
    }
    if (run->outcome.trap) {
        progress.verdict = CallProgress::Verdict::refused;
        progress.reason =
            *run->outcome.trap == vm::Trap::aborted
                ? "the contract refuses the call: " + readable(run->outcome.abort_reason)
                : "the contract trapped on the call (" + std::string(vm::name(*run->outcome.trap)) +
                      ")";
        return progress;
    }
    if (run->malformed) {
        progress.verdict = CallProgress::Verdict::refused;
        progress.reason =
            "the contract's output is not well formed: " + std::string(run->malformed->detail);
        return progress;
    }
    if (const auto* needs =
            run->output ? std::get_if<protocol::ContractNeeds>(&*run->output) : nullptr) {
        progress.verdict = CallProgress::Verdict::waiting;
        progress.call.missing = needs->ledgers;
        return progress;
    }
    // The contract accepts it; the ledger's rules for the children it would
    // create (v0.7) and the requests it would make (v0.8) apply after the
    // run, so check them before signing.
    const protocol::ContractAccept& accept = *run->accepted();
    Status allowed = state.check_children(body, accept);
    if (allowed) {
        allowed = state.check_requests(body, accept, now);
    }
    if (!allowed) {
        progress.verdict = CallProgress::Verdict::refused;
        progress.reason = "the ledger refuses the call: " + std::string(allowed.error().detail);
        return progress;
    }
    progress.verdict = CallProgress::Verdict::accepted;
    progress.call.missing.clear();
    for (const auto& [ledger, bundle] : progress.call.consents) {
        progress.bundles.push_back(bundle);
    }
    progress.statement = std::move(*signed_call);
    return progress;
}

} // namespace cexchain::node
