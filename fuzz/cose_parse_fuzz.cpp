// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Every message the parser accepts must rebuild, from its parsed parts, to
// exactly the same bytes: a COSE_Sign1 has one encoding in the CexChain profile.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/cose.hpp>

namespace cbor = cexchain::cbor;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const cexchain::ByteView input(data, size);
    const auto parsed = cexchain::cose::parse(input);
    if (!parsed) {
        return 0;
    }
    const auto rebuilt = cbor::encode(cbor::Value::tagged(
        cexchain::cose::tag_sign1,
        cbor::Value::array({
            cbor::Value::bytes(parsed->protected_bytes),
            parsed->unprotected_header,
            parsed->payload ? cbor::Value::bytes(*parsed->payload) : cbor::Value::null(),
            cbor::Value::bytes(parsed->signature),
        })));
    if (!rebuilt || !std::ranges::equal(*rebuilt, input)) {
        std::abort();
    }
    return 0;
}
