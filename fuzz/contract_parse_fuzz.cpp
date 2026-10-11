// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A contract's output comes from code anyone with a delegation can deploy,
// and contract consents and evidence from other organizations (spec section
// 15). Decoding must never crash, whatever decodes must encode back to the
// same bytes, and verifying arbitrary evidence must fail cleanly.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/crypto/openssl.hpp>

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
        }
    }
    // A home ledger id the outputs may not name.
    static const protocol::Id home = *protocol::to_id(cexchain::Bytes(32, 0x5A));
    if (const auto output = protocol::decode_contract_output(input, home)) {
        const auto again = protocol::encode_contract_output(*output);
        require(again && std::ranges::equal(*again, input));
        if (const auto* needs = std::get_if<protocol::ContractNeeds>(&*output)) {
            require(!std::ranges::contains(needs->ledgers, home));
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
