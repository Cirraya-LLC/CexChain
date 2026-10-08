// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <map>
#include <utility>

#include <cexchain/core/protocol/asset_evidence.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

using detail::entry;
using detail::MapReader;

std::unexpected<Error> verification_failure(std::string_view detail) {
    return fail(Errc::verification_failed, detail);
}

} // namespace

Result<Bytes> encode_asset_evidence(const AssetEvidence& e) {
    if (e.asset_bundle.empty()) {
        return fail(Errc::invalid_argument, "asset evidence needs the asset's bundle");
    }
    if (e.consent_bundles.size() > max_consent_bundles) {
        return fail(Errc::limit_exceeded, "asset evidence holds at most 4096 consent bundles");
    }
    cbor::Map map{entry(0, cbor::Value::unsigned_integer(asset_evidence_version)),
                  entry(1, cbor::Value::bytes(e.asset_bundle))};
    if (!e.consent_bundles.empty()) {
        cbor::Array bundles;
        for (const Bytes& b : e.consent_bundles) {
            bundles.push_back(cbor::Value::bytes(b));
        }
        map.push_back(entry(2, cbor::Value::array(std::move(bundles))));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<AssetEvidence> decode_asset_evidence(ByteView encoded) {
    if (encoded.size() > max_bundle_size) {
        return fail(Errc::limit_exceeded, "the asset evidence is too large");
    }
    cbor::DecodeOptions options;
    options.max_items = max_consent_bundles + 16;
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded, options));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    CEXCHAIN_TRY(std::uint64_t version, reader.need_uint(0));
    if (version != asset_evidence_version) {
        return fail(Errc::unsupported, "unsupported asset evidence version");
    }
    AssetEvidence e;
    CEXCHAIN_TRY(e.asset_bundle, reader.need_bytes(1));
    if (const cbor::Value* list = reader.get(2)) {
        CEXCHAIN_TRY(const cbor::Array* bundles, detail::as_array(*list));
        if (bundles->empty()) {
            return fail(Errc::non_canonical, "an empty list of consent bundles must be omitted");
        }
        if (bundles->size() > max_consent_bundles) {
            return fail(Errc::limit_exceeded, "asset evidence holds at most 4096 consent bundles");
        }
        for (const cbor::Value& item : *bundles) {
            CEXCHAIN_TRY(Bytes bundle, detail::as_bytes_value(item));
            e.consent_bundles.push_back(std::move(bundle));
        }
    }
    CEXCHAIN_CHECK(reader.finish());
    return e;
}

Result<ConsentCheck> check_consent(const crypto::Provider& provider, const ConsentRef& ref,
                                   ByteView bundle, const AssetTerms& terms, Timestamp at,
                                   crypto::HashAlg home_hash,
                                   std::span<const crypto::PublicKey> trusted_witnesses) {
    CEXCHAIN_TRY(crypto::Digest digest, provider.digest(home_hash, bundle));
    if (digest != ref.bundle) {
        return verification_failure("the consent bundle is not the one the action pins");
    }
    VerifyOptions options;
    options.expected_ledger = ref.ledger;
    options.trusted_witnesses.assign(trusted_witnesses.begin(), trusted_witnesses.end());
    auto report = verify_bundle(provider, bundle, options);
    if (!report) {
        return std::unexpected(report.error());
    }
    if (report->record != ref.record || report->record_type != asset_consent_type) {
        return verification_failure("the consent bundle is not about the cited consent record");
    }
    if (!report->complete) {
        return verification_failure(
            "the consent's evidence does not prove its complete history (it could be withdrawn)");
    }
    if (report->revoked || report->state != consent_given) {
        return verification_failure("the consent was withdrawn");
    }
    if (!report->metadata) {
        return verification_failure("the consent record has no terms");
    }
    auto consent = decode_asset_consent(*report->metadata);
    if (!consent) {
        return verification_failure("the consent record's terms are malformed");
    }
    if (consent->terms != terms) {
        return verification_failure("the consent is to other terms than the action's");
    }
    if (consent->until < at) {
        return verification_failure("the consent had lapsed when the action was recorded");
    }
    return ConsentCheck{ref, std::move(*consent), std::move(*report)};
}

Result<AssetReport> verify_asset_evidence(const crypto::Provider& provider, ByteView encoded,
                                          const VerifyOptions& options) {
    CEXCHAIN_TRY(AssetEvidence evidence, decode_asset_evidence(encoded));
    AssetReport out;
    CEXCHAIN_TRY(out.asset, verify_bundle(provider, evidence.asset_bundle, options));
    if (!out.asset.asset) {
        return verification_failure("the evidence is not about an asset");
    }
    if (!out.asset.complete) {
        return verification_failure(
            "the asset's evidence does not prove its complete history, so not its state");
    }

    // The bundles by the hash (the home's) that actions pin them by.
    std::map<Bytes, std::pair<const Bytes*, bool>> bundles;
    for (const Bytes& bundle : evidence.consent_bundles) {
        CEXCHAIN_TRY(crypto::Digest digest, provider.digest(out.asset.hash, bundle));
        const Bytes key(digest.bytes().begin(), digest.bytes().end());
        if (!bundles.emplace(key, std::pair(&bundle, false)).second) {
            return verification_failure("a consent bundle is repeated");
        }
    }
    for (std::size_t i = 0; i < out.asset.events.size(); ++i) {
        const RecordEvent& event = out.asset.events[i];
        if (!event.asset_action) {
            continue;
        }
        AssetStep step{i, {}};
        const AssetTerms terms = terms_of(*event.asset_action, out.asset.ledger_id);
        for (const ConsentRef& ref : event.asset_action->consents) {
            const Bytes key(ref.bundle.bytes().begin(), ref.bundle.bytes().end());
            const auto found = bundles.find(key);
            if (found == bundles.end()) {
                return verification_failure("a consent an action cites is missing its evidence");
            }
            found->second.second = true;
            CEXCHAIN_TRY(ConsentCheck check,
                         check_consent(provider, ref, *found->second.first, terms,
                                       event.registered_at, out.asset.hash,
                                       options.trusted_witnesses));
            step.consents.push_back(std::move(check));
        }
        out.steps.push_back(std::move(step));
    }
    for (const auto& [key, bundle] : bundles) {
        if (!bundle.second) {
            return verification_failure("a consent bundle is pinned by no action of the asset");
        }
    }
    return out;
}

} // namespace cexchain::protocol
