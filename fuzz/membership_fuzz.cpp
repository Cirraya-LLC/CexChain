// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A membership's metadata (spec v0.16) comes from whoever registers a record,
// and reaches every verifier inside membership proofs: reading it must refuse
// what is not one, never crash, and what it accepts must encode back to
// metadata that reads the same.

#include <cstddef>
#include <cstdint>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/memberships.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto value = kanhe::cbor::decode({data, size});
    if (!value) {
        return 0;
    }
    const auto membership = kanhe::protocol::decode_membership(*value);
    if (!membership) {
        return 0;
    }
    const auto again = kanhe::protocol::encode_membership(*membership);
    if (!again || kanhe::protocol::decode_membership(*again) != membership) {
        __builtin_trap();
    }
    if (kanhe::protocol::member_kind_name(membership->kind).empty()) {
        __builtin_trap();
    }
    return 0;
}
