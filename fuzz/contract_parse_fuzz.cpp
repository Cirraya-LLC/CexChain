// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A contract's output comes from code anyone with a delegation can deploy,
// and contract consents and evidence from other organizations (spec section
// 15). Decoding must never crash, whatever decodes must encode back to the
// same bytes, and verifying arbitrary evidence must fail cleanly. Outputs may
// create children, and evidence may be about a child, with its ancestors'
// calls (v0.7). Verified evidence is rendered as every verifier shows it.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/verifier/report.hpp>

namespace protocol = cexchain::protocol;
namespace cbor = cexchain::cbor;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    const cexchain::ByteView input(data, size);
    if (const auto evidence = protocol::decode_contract_evidence(input)) {
        const auto again = protocol::encode_contract_evidence(*evidence);
        require(again && std::ranges::equal(*again, input));
        // Verification replays bundles, contracts included: it must refuse
        // anything not genuine without crashing, and accept only complete
        // evidence about an instance.
        if (const auto report = protocol::verify_contract_evidence(provider, input)) {
            require(report->instance.complete && report->instance.instance.has_value());
            // A child's report shows one ancestor per generation, oldest
            // first, its own calls after theirs, and one step per call.
            const protocol::InstanceReport& i = *report->instance.instance;
            require(i.ancestors.size() == i.depth && i.depth <= protocol::max_instance_depth);
            require(i.parent.has_value() == !i.ancestors.empty());
            require(i.first_own_event < report->instance.events.size());
            require(report->instance.events[i.first_own_event].index == i.created_by);
            require(report->steps.size() == report->instance.events.size());
            for (std::size_t a = 0; a < i.ancestors.size(); ++a) {
                require(i.ancestors[a].depth == a && !i.ancestors[a].events.empty());
                require(
                    i.ancestors[a].until ==
                    (a + 1 < i.ancestors.size() ? i.ancestors[a + 1].created_by : i.created_by));
            }
            // Each call names the instances it created, one per child.
            for (const protocol::RecordEvent& e : report->instance.events) {
                require(e.children.size() == (e.outcome ? e.outcome->children.size() : 0));
            }
            // The reports render, with the chain only for a child.
            const auto json = cexchain::verifier::contract_report_json(*report, false);
            require(json["calls"].size() == report->steps.size());
            require(json["instance"].contains("ancestors") == i.parent.has_value());
            require(!json.dump(-1, ' ', false, cexchain::verifier::Json::error_handler_t::replace)
                         .empty());
            const std::string text = cexchain::verifier::contract_report_text(*report, false);
            require(text.contains("Ancestors") || !i.parent);
        }
    }
    // A home ledger id the outputs may not name.
    static const protocol::Id home = *protocol::to_id(cexchain::Bytes(32, 0x5A));
    if (const auto output = protocol::decode_contract_output(input, home)) {
        const auto again = protocol::encode_contract_output(*output);
        require(again && std::ranges::equal(*again, input));
        if (const auto* needs = std::get_if<protocol::ContractNeeds>(&*output)) {
            require(!std::ranges::contains(needs->ledgers, home));
        } else {
            const auto& accept = std::get<protocol::ContractAccept>(*output);
            require(accept.children.size() <= protocol::max_contract_children);
            for (const protocol::ContractChild& child : accept.children) {
                require(child.parties.size() <= protocol::max_contract_parties);
            }
        }
    }
    if (const auto value = cbor::decode(input)) {
        if (const auto consent = protocol::decode_contract_consent(*value)) {
            const auto again = protocol::encode_contract_consent(*consent);
            const auto encoded =
                again ? cbor::encode(*again)
                      : cexchain::Result<cexchain::Bytes>(std::unexpected(again.error()));
            require(encoded && std::ranges::equal(*encoded, input));
        }
    }
    return 0;
}
