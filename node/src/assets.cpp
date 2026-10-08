// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <string>
#include <system_error>
#include <utility>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/node/assets.hpp>

#include "files.hpp"

namespace cexchain::node {

namespace {

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::filesystem::path assets_root(const std::filesystem::path& ledger_directory) {
    return ledger_directory / "assets";
}

/// A digest of the terms, to group the consents to them.
Result<std::string> terms_key(const crypto::Provider& provider, const protocol::AssetTerms& t) {
    cbor::Array parts{cbor::Value::bytes(t.ledger.bytes()), cbor::Value::bytes(t.asset.bytes()),
                      cbor::Value::text(std::string(protocol::name(t.action))),
                      cbor::Value::unsigned_integer(t.head)};
    parts.push_back(t.to ? cbor::Value::bytes(t.to->bytes()) : cbor::Value::null());
    parts.push_back(t.quantity ? cbor::Value::unsigned_integer(*t.quantity) : cbor::Value::null());
    auto encoded = cbor::encode(cbor::Value::array(std::move(parts)));
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    auto digest = provider.digest(crypto::HashAlg::sha256, *encoded);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return std::to_string(t.head) + "-" + to_hex(digest->bytes());
}

/// The head a pending directory's name starts with.
std::optional<std::uint64_t> head_of(const std::string& name) {
    const auto dash = name.find('-');
    if (dash == std::string::npos || dash == 0) {
        return std::nullopt;
    }
    std::uint64_t head = 0;
    const auto [end, ec] = std::from_chars(name.data(), name.data() + dash, head);
    if (ec != std::errc{} || end != name.data() + dash) {
        return std::nullopt;
    }
    return head;
}

bool by_ledger(const protocol::ConsentRef& a, const protocol::ConsentRef& b) {
    return std::ranges::lexicographical_compare(a.ledger.bytes(), b.ledger.bytes());
}

} // namespace

std::filesystem::path consents_directory(const std::filesystem::path& ledger_directory) {
    return assets_root(ledger_directory) / "consents";
}

std::filesystem::path consents_path(const std::filesystem::path& ledger_directory,
                                    const protocol::Id& action) {
    return consents_directory(ledger_directory) / (hex(action) + ".cbor");
}

Result<Bytes> encode_consent_bundles(std::span<const Bytes> bundles) {
    cbor::Array list;
    for (const Bytes& b : bundles) {
        list.push_back(cbor::Value::bytes(b));
    }
    return cbor::encode(cbor::Value::array(std::move(list)));
}

Result<std::vector<Bytes>> decode_consent_bundles(ByteView encoded) {
    cbor::DecodeOptions options;
    options.max_items = protocol::max_consents + 1;
    auto value = cbor::decode(encoded, options);
    const cbor::Array* list = value ? value->as_array() : nullptr;
    if (list == nullptr || list->empty() || list->size() > protocol::max_consents) {
        return fail(Errc::malformed, "consent bundles are a list of 1 to 4 byte strings");
    }
    std::vector<Bytes> out;
    for (const cbor::Value& item : *list) {
        if (item.as_bytes() == nullptr) {
            return fail(Errc::malformed, "consent bundles are a list of 1 to 4 byte strings");
        }
        out.push_back(*item.as_bytes());
    }
    return out;
}

Status check_action_consents(const crypto::Provider& provider, const protocol::Id& home,
                             crypto::HashAlg hash, const protocol::AssetActionBody& action,
                             std::span<const Bytes> bundles, protocol::Timestamp now) {
    if (bundles.size() != action.consents.size()) {
        return fail(Errc::invalid_argument,
                    "an asset action comes with the evidence of each consent it cites, in order");
    }
    const protocol::AssetTerms terms = protocol::terms_of(action, home);
    for (std::size_t i = 0; i < bundles.size(); ++i) {
        auto checked =
            protocol::check_consent(provider, action.consents[i], bundles[i], terms, now, hash);
        if (!checked) {
            return std::unexpected(checked.error());
        }
    }
    return {};
}

Status store_consents(const std::filesystem::path& ledger_directory, const protocol::Id& action,
                      ByteView encoded) {
    const std::filesystem::path path = consents_path(ledger_directory, action);
    if (auto held = detail::read_file(path)) {
        if (!std::ranges::equal(*held, encoded)) {
            return fail(Errc::rejected, "other consent evidence is kept for this action");
        }
        return {};
    }
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the assets directory");
    }
    return detail::write_file(path, encoded, true);
}

bool cites_consents(const protocol::Statement& statement) {
    const auto* action = std::get_if<protocol::AssetActionBody>(&statement.body);
    return action != nullptr && !action->consents.empty();
}

Result<Bytes> asset_evidence(const crypto::Provider& provider,
                             const std::filesystem::path& ledger_directory,
                             const protocol::EvidenceBundle& asset_bundle) {
    if (asset_bundle.entries.empty()) {
        return fail(Errc::invalid_argument, "the asset's bundle is empty");
    }
    auto genesis = protocol::decode_log_entry(asset_bundle.entries.front().entry);
    if (!genesis) {
        return std::unexpected(genesis.error());
    }
    auto parsed_genesis = protocol::parse_statement(provider, genesis->statement);
    const auto* body = parsed_genesis
                           ? std::get_if<protocol::GenesisBody>(&parsed_genesis->statement.body)
                           : nullptr;
    if (body == nullptr) {
        return fail(Errc::malformed, "the asset's bundle does not start with genesis");
    }
    protocol::AssetEvidence evidence;
    for (const protocol::EvidenceEntry& e : asset_bundle.entries) {
        auto entry = protocol::decode_log_entry(e.entry);
        if (!entry || entry->is_state_commitment() ||
            entry->statement_id == genesis->statement_id) {
            continue;
        }
        auto statement = protocol::parse_statement(provider, entry->statement, body->hash_alg);
        if (!statement) {
            return std::unexpected(statement.error());
        }
        const auto* action = std::get_if<protocol::AssetActionBody>(&statement->statement.body);
        if (action == nullptr || action->asset != asset_bundle.record || action->consents.empty()) {
            continue;
        }
        auto held = detail::read_file(consents_path(ledger_directory, statement->id));
        if (!held) {
            return fail(Errc::not_found, "the consents an asset action pins are not kept here");
        }
        auto bundles = decode_consent_bundles(*held);
        if (!bundles) {
            return std::unexpected(bundles.error());
        }
        for (Bytes& b : *bundles) {
            evidence.consent_bundles.push_back(std::move(b));
        }
    }
    auto encoded_bundle = protocol::encode_bundle(asset_bundle);
    if (!encoded_bundle) {
        return std::unexpected(encoded_bundle.error());
    }
    evidence.asset_bundle = std::move(*encoded_bundle);
    return protocol::encode_asset_evidence(evidence);
}

std::optional<protocol::Id> choose_delegation(const protocol::LedgerState& state,
                                              const protocol::Id& actor,
                                              protocol::StatementType type,
                                              const std::optional<std::string>& record_type,
                                              protocol::Timestamp now) {
    std::optional<protocol::Id> chosen;
    std::uint64_t newest = 0;
    for (const auto& [key, d] : state.delegations()) {
        const bool usable = d.grantee == actor && !d.revoked &&
                            std::ranges::contains(d.scope.statement_types, type) &&
                            (!record_type || !d.scope.record_types ||
                             std::ranges::contains(*d.scope.record_types, *record_type)) &&
                            (!d.scope.not_before || *d.scope.not_before <= now) &&
                            (!d.scope.not_after || now <= *d.scope.not_after);
        if (usable && (!chosen || d.granted_at_index > newest)) {
            chosen = d.id;
            newest = d.granted_at_index;
        }
    }
    return chosen;
}

Result<protocol::SignedStatement>
sign_asset_action(const crypto::Provider& provider, const protocol::LedgerState& state,
                  const crypto::Signer& signer, const protocol::AssetActionBody& action,
                  protocol::Timestamp now, ledger::Entropy& entropy) {
    auto kid = protocol::key_id(provider, state.hash(), signer.public_key());
    if (!kid) {
        return std::unexpected(kid.error());
    }
    const protocol::ActorState* actor = state.actor_by_kid(*kid);
    if (actor == nullptr || actor->revoked) {
        return fail(Errc::rejected, "the registrar key is not an active actor's of this ledger");
    }
    const protocol::RecordState* asset = state.record(action.asset);
    if (asset == nullptr) {
        return fail(Errc::not_found, "no such asset");
    }
    protocol::Statement statement;
    statement.ledger_id = state.ledger_id();
    statement.actor_id = actor->id;
    if (!actor->is_organization()) {
        statement.delegation_id = choose_delegation(
            state, actor->id, protocol::StatementType::asset_action, asset->record_type, now);
        if (!statement.delegation_id) {
            return fail(Errc::rejected,
                        "the registrar has no delegation for asset actions on this asset type");
        }
    }
    statement.issued_at = now;
    statement.nonce = entropy.bytes<16>();
    statement.body = action;
    return protocol::sign_statement(signer, provider, state.hash(), statement);
}

ConsentPool::ConsentPool(std::filesystem::path ledger_directory)
    : root_(assets_root(ledger_directory) / "pending") {}

Result<ConsentProgress> ConsentPool::add(const crypto::Provider& provider,
                                         const protocol::LedgerState& state,
                                         const protocol::Id& party, ByteView bundle,
                                         protocol::Timestamp now) {
    // The consent itself, from the party's ledger.
    protocol::VerifyOptions options;
    options.expected_ledger = party;
    auto report = protocol::verify_bundle(provider, bundle, options);
    if (!report) {
        return std::unexpected(report.error());
    }
    if (report->record_type != protocol::asset_consent_type || !report->metadata) {
        return fail(Errc::invalid_argument, "the evidence is not of a consent");
    }
    auto consent = protocol::decode_asset_consent(*report->metadata);
    if (!consent) {
        return std::unexpected(consent.error());
    }
    const protocol::AssetTerms& terms = consent->terms;
    if (terms.ledger != state.ledger_id()) {
        return fail(Errc::invalid_argument, "the consent is to an asset on another ledger");
    }
    auto digest = provider.digest(state.hash(), bundle);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    const protocol::ConsentRef own{party, report->record, *digest};
    if (auto checked = protocol::check_consent(provider, own, bundle, terms, now, state.hash());
        !checked) {
        return std::unexpected(checked.error());
    }

    // The action it is to: allowed now, if every party it needs consents.
    const protocol::AssetState* asset = state.asset(terms.asset);
    const protocol::RecordState* record = state.record(terms.asset);
    if (asset == nullptr || record == nullptr) {
        return fail(Errc::not_found, "no such asset on this ledger");
    }
    protocol::AssetActionBody action;
    action.asset = terms.asset;
    action.action = terms.action;
    action.head = terms.head;
    action.to = terms.to;
    action.quantity = terms.quantity;
    const std::vector<protocol::Id> parties =
        protocol::consenting_parties(*asset, record->state, action);
    if (!std::ranges::contains(parties, party)) {
        return fail(Errc::invalid_argument, "your ledger is not a party to this action");
    }
    for (const protocol::Id& p : parties) {
        action.consents.push_back({p, p, p}); // placeholders: only their ledgers count here
    }
    if (auto s = protocol::check_asset_action(*asset, record->state, action, state.ledger_id());
        !s) {
        return std::unexpected(s.error());
    }

    // Held with the others to the same terms; consents to an earlier head
    // can never be used, so they go.
    auto key = terms_key(provider, terms);
    if (!key) {
        return std::unexpected(key.error());
    }
    const std::filesystem::path asset_dir = root_ / hex(terms.asset);
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(asset_dir, ec)) {
        const auto head = head_of(e.path().filename().string());
        if (!head || *head != asset->head) {
            std::filesystem::remove_all(e.path(), ec);
        }
    }
    const std::filesystem::path dir = asset_dir / *key;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot keep the consent");
    }
    if (auto s = detail::write_file(dir / (hex(party) + ".cbor"), bundle, true); !s) {
        return std::unexpected(s.error());
    }

    ConsentProgress progress{terms, {}, std::nullopt, {}};
    std::vector<std::pair<protocol::ConsentRef, Bytes>> held;
    for (const protocol::Id& p : parties) {
        auto file = detail::read_file(dir / (hex(p) + ".cbor"));
        std::optional<protocol::ConsentRef> ref;
        if (file) {
            // Checked again: it may have lapsed while waiting.
            auto record_id = protocol::decode_bundle(*file);
            auto file_digest = provider.digest(state.hash(), *file);
            if (record_id && file_digest) {
                const protocol::ConsentRef candidate{p, record_id->record, *file_digest};
                if (protocol::check_consent(provider, candidate, *file, terms, now, state.hash())) {
                    ref = candidate;
                }
            }
        }
        if (ref) {
            held.emplace_back(*ref, std::move(*file));
        } else {
            progress.missing.push_back(p);
        }
    }
    if (progress.missing.empty()) {
        std::ranges::sort(held, by_ledger, &std::pair<protocol::ConsentRef, Bytes>::first);
        action.consents.clear();
        for (auto& [ref, b] : held) {
            action.consents.push_back(ref);
            progress.bundles.push_back(std::move(b));
        }
        progress.action = std::move(action);
    }
    return progress;
}

void ConsentPool::forget(const protocol::AssetTerms& terms) {
    std::error_code ec;
    const std::filesystem::path asset_dir = root_ / hex(terms.asset);
    for (const auto& e : std::filesystem::directory_iterator(asset_dir, ec)) {
        const auto head = head_of(e.path().filename().string());
        if (head && *head <= terms.head) {
            std::filesystem::remove_all(e.path(), ec);
        }
    }
}

} // namespace cexchain::node
