// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A published record's file, or a request to publish one (POST
// /v1/published, from an admin token's holder). Whatever arrives, the reader
// must not crash; what it accepts holds at most the fields allowed and
// encodes back to a file that reads the same.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <kanhe/node/published.hpp>

namespace node = kanhe::node;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto published = node::decode_published("AAAAAAAAAAAAAAAAAAAAAA", {data, size});
    if (published) {
        require(published->disclosures.size() <= node::max_published_fields);
        const auto file = node::encode_published(*published);
        require(file.has_value());
        const auto again = node::decode_published(published->token, *file);
        require(again && *again == *published);
    }
    return 0;
}
