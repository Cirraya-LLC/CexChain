// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <map>
#include <utility>

#include <cexchain/core/protocol/contract_evidence.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

using detail::entry;
using detail::MapReader;

std::unexpected<Error> verification_failure(std::string_view detail) {
    return fail(Errc::verification_failed, detail);
}

} // namespace

ContractSigner registration_signer(const RecordEvent& registration) {
    ContractSigner signer;
    signer.kind = registration.actor.kind ? static_cast<std::uint8_t>(*registration.actor.kind) : 0;
    if (registration.presence) {
        signer.presence = registration.presence->method;
    }
    if (registration.provenance) {
        signer.model = registration.provenance->model;
    }
    return signer;
}

Result<Bytes> encode_contract_evidence(const ContractEvidence& e) {
    if (e.instance_bundle.empty()) {
        return fail(Errc::invalid_argument, "contract evidence needs the instance's bundle");
    }
    if (e.consent_bundles.size() > max_consent_bundles) {
        return fail(Errc::limit_exceeded, "contract evidence holds at most 4096 consent bundles");
    }
    cbor::Map map{entry(0, cbor::Value::unsigned_integer(contract_evidence_version)),
                  entry(1, cbor::Value::bytes(e.instance_bundle))};
    if (!e.consent_bundles.empty()) {
        cbor::Array bundles;
        for (const Bytes& b : e.consent_bundles) {
            bundles.push_back(cbor::Value::bytes(b));
        }
        map.push_back(entry(2, cbor::Value::array(std::move(bundles))));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<ContractEvidence> decode_contract_evidence(ByteView encoded) {
    if (encoded.size() > max_bundle_size) {
        return fail(Errc::limit_exceeded, "the contract evidence is too large");
    }
    cbor::DecodeOptions options;
    options.max_items = max_consent_bundles + 16;
    CEXCHAIN_TRY(cbor::Value value, cbor::decode(encoded, options));
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    CEXCHAIN_TRY(std::uint64_t version, reader.need_uint(0));
    if (version != contract_evidence_version) {
        return fail(Errc::unsupported, "unsupported contract evidence version");
    }
    ContractEvidence e;
    CEXCHAIN_TRY(e.instance_bundle, reader.need_bytes(1));
    if (const cbor::Value* list = reader.get(2)) {
        CEXCHAIN_TRY(const cbor::Array* bundles, detail::as_array(*list));
        if (bundles->empty()) {
            return fail(Errc::non_canonical, "an empty list of consent bundles must be omitted");
        }
        if (bundles->size() > max_consent_bundles) {
            return fail(Errc::limit_exceeded,
                        "contract evidence holds at most 4096 consent bundles");
        }
        for (const cbor::Value& item : *bundles) {
            CEXCHAIN_TRY(Bytes bundle, detail::as_bytes_value(item));
            e.consent_bundles.push_back(std::move(bundle));
        }
    }
    CEXCHAIN_CHECK(reader.finish());
    return e;
}

Result<ContractConsentCheck>
check_contract_consent(const crypto::Provider& provider, const ContractConsentRef& ref,
                       ByteView bundle, const ContractCallBody& call, const Id& home,
                       crypto::HashAlg home_hash, Timestamp at,
                       std::span<const crypto::PublicKey> trusted_witnesses) {
    CEXCHAIN_TRY(crypto::Digest digest, provider.digest(home_hash, bundle));
    if (digest != ref.bundle) {
        return verification_failure("the consent bundle is not the one the call cites");
    }
    VerifyOptions options;
    options.expected_ledger = ref.ledger;
    options.trusted_witnesses.assign(trusted_witnesses.begin(), trusted_witnesses.end());
    auto report = verify_bundle(provider, bundle, options);
    if (!report) {
        return std::unexpected(report.error());
    }
    if (report->record != ref.record || report->record_type != contract_consent_type) {
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
    auto consent = decode_contract_consent(*report->metadata);
    if (!consent) {
        return verification_failure("the consent record's terms are malformed");
    }
    CEXCHAIN_TRY(Id arguments, contract_arguments_digest(provider, home_hash, call.arguments));
    if (!consent_matches(*consent, home, call, arguments)) {
        return verification_failure("the consent is to other terms than the call's");
    }
    if (consent->until < at) {
        return verification_failure("the consent had lapsed when the call was recorded");
    }
    if (report->events.empty() || registration_signer(report->events.front()) != ref.signer) {
        return verification_failure(
            "the call claims another signer for the consent than its evidence shows");
    }
    return ContractConsentCheck{ref, std::move(*consent), std::move(*report)};
}

Result<ContractReport> verify_contract_evidence(const crypto::Provider& provider, ByteView encoded,
                                                const VerifyOptions& options) {
    CEXCHAIN_TRY(ContractEvidence evidence, decode_contract_evidence(encoded));
    ContractReport out;
    CEXCHAIN_TRY(out.instance, verify_bundle(provider, evidence.instance_bundle, options));
    if (!out.instance.instance) {
        return verification_failure("the evidence is not about a contract instance");
    }
    if (!out.instance.complete) {
        return verification_failure(
            "the instance's evidence does not prove its complete history, so not its state");
    }

    // The bundles by the hash (the home's) that calls cite them by.
    std::map<Bytes, std::pair<const Bytes*, bool>> bundles;
    for (const Bytes& bundle : evidence.consent_bundles) {
        CEXCHAIN_TRY(crypto::Digest digest, provider.digest(out.instance.hash, bundle));
        const Bytes key(digest.bytes().begin(), digest.bytes().end());
        if (!bundles.emplace(key, std::pair(&bundle, false)).second) {
            return verification_failure("a consent bundle is repeated");
        }
    }
    for (std::size_t i = 0; i < out.instance.events.size(); ++i) {
        const RecordEvent& event = out.instance.events[i];
        if (!event.contract_call) {
            continue;
        }
        ContractStep step{i, {}};
        for (const ContractConsentRef& ref : event.contract_call->consents) {
            const Bytes key(ref.bundle.bytes().begin(), ref.bundle.bytes().end());
            const auto found = bundles.find(key);
            if (found == bundles.end()) {
                return verification_failure("a consent a call cites is missing its evidence");
            }
            found->second.second = true;
            CEXCHAIN_TRY(ContractConsentCheck check,
                         check_contract_consent(provider, ref, *found->second.first,
                                                *event.contract_call, out.instance.ledger_id,
                                                out.instance.hash, event.registered_at,
                                                options.trusted_witnesses));
            step.consents.push_back(std::move(check));
        }
        out.steps.push_back(std::move(step));
    }
    for (const auto& [key, bundle] : bundles) {
        if (!bundle.second) {
            return verification_failure(
                "a consent bundle is pinned by no call of the instance or of its ancestors");
        }
    }
    return out;
}

} // namespace cexchain::protocol
