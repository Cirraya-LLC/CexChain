// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Differential (D-056, P6): `cbor::validate`, which checks without building,
// must decide exactly as `cbor::decode` does, with the same error, under the
// default limits and limits taken from the input. A contract's output read
// from its bytes must equal the output read through trees, as the core read
// it before P6 (tests/support/contract_reference.hpp): the same verdict and
// error, the states sliced from the bytes equal to the trees encoded, and an
// input with each state spliced in equal to the tree-built input.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contracts.hpp>

#include "support/contract_reference.hpp"

namespace protocol = cexchain::protocol;
namespace cbor = cexchain::cbor;
namespace reference = cexchain::test::reference;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

template <class A, class B>
void require_same_verdict(const A& a, const B& b) {
    require(a.has_value() == b.has_value());
    if (!a) {
        require(a.error().code == b.error().code && a.error().detail == b.error().detail);
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const cexchain::ByteView input(data, size);
    // The default limits, then limits from the first two bytes over the
    // rest (depth 0 to 63, items 1 to 1,024).
    require_same_verdict(cbor::decode(input), cbor::validate(input));
    if (size >= 2) {
        const cbor::DecodeOptions limits{.max_depth = std::size_t{data[0]} % 64,
                                         .max_items = 1 + std::size_t{data[1]} * 4};
        const cexchain::ByteView rest = input.subspan(2);
        require_same_verdict(cbor::decode(rest, limits), cbor::validate(rest, limits));
    }
    if (const auto encoded = cbor::Encoded::from_bytes(input)) {
        require(std::ranges::equal(encoded->bytes(), input));
        require(*cbor::encode(encoded->value()) == cexchain::Bytes(input.begin(), input.end()));
    }

    static const protocol::Id home = *protocol::to_id(cexchain::Bytes(32, 0x5A));
    const auto bytes = protocol::decode_contract_output(input, home);
    const auto trees = reference::decode_contract_output(input, home);
    require_same_verdict(bytes, trees);
    if (!bytes) {
        return 0;
    }
    require(*bytes == *trees);
    const auto again = protocol::encode_contract_output(*bytes);
    require(again && std::ranges::equal(*again, input));
    require(*again == *reference::encode_contract_output(*trees));
    if (const auto* accept = std::get_if<protocol::ContractAccept>(&*bytes)) {
        // Each state an instance would keep, spliced into the next input.
        protocol::ContractInput in;
        in.function = "f";
        in.home = home;
        in.contract = home;
        in.caller = home;
        in.instance = protocol::ContractInstanceView{home,
                                                     1,
                                                     accept->state,
                                                     accept->status,
                                                     accept->parties.value_or(protocol::Parties{}),
                                                     std::nullopt,
                                                     0};
        require(*protocol::encode_contract_input(in) == *reference::encode_contract_input(in));
        for (const protocol::ContractChild& child : accept->children) {
            in.instance = protocol::ContractInstanceView{
                home, 2, child.state, child.status, child.parties, home, 1};
            require(*protocol::encode_contract_input(in) == *reference::encode_contract_input(in));
        }
    }
    return 0;
}
