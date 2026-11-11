// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The state a snapshot holds (snapshot-a, snapshot-b beside the log). The
// file's seal is a plain SHA-256 anyone can compute, so to the decoder its
// bytes are untrusted. Decoding must never crash, and a state that decodes
// must encode to bytes that decode and encode to the same bytes again.
// Contracts' modules come from their deploys in the log: here, from the
// test contract of the v0.6 vectors at any index.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/state.hpp>

namespace protocol = kanhe::protocol;
using kanhe::Bytes;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

const Bytes& test_contract() {
    static const Bytes code = *kanhe::from_hex(KANHE_FUZZ_TEST_CONTRACT);
    return code;
}

kanhe::Result<Bytes> deploy_code(std::uint64_t /*index*/) {
    return test_contract();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto state = protocol::LedgerState::decode(kanhe::ByteView(data, size), deploy_code);
    if (!state) {
        return 0;
    }
    const auto encoded = state->encode();
    require(encoded.has_value());
    const auto again = protocol::LedgerState::decode(*encoded, deploy_code);
    require(again.has_value());
    const auto twice = again->encode();
    require(twice && std::ranges::equal(*twice, *encoded));
    return 0;
}
