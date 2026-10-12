// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Diagnostic notation is how the command line takes CBOR values (contract
// arguments) from people and from files others wrote. Two properties:
//   - text that parses yields a value that encodes, and whose diagnostic
//     notation parses back to the same value;
//   - for input that decodes as CBOR, its diagnostic notation parses back to
//     the same value.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include <cexchain/core/cbor.hpp>

namespace {

void same_after_round_trip(const cexchain::cbor::Value& value) {
    const auto again = cexchain::cbor::parse_diagnostic(cexchain::cbor::diagnostic(value));
    if (!again || !(*again == value)) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    if (const auto parsed = cexchain::cbor::parse_diagnostic(text)) {
        if (!cexchain::cbor::encode(*parsed)) {
            std::abort();
        }
        same_after_round_trip(*parsed);
    }
    cexchain::cbor::DecodeOptions options;
    options.max_depth = cexchain::cbor::max_nesting_depth;
    if (const auto decoded = cexchain::cbor::decode(cexchain::ByteView(data, size), options)) {
        same_after_round_trip(*decoded);
    }
    return 0;
}
