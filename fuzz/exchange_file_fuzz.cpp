// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Proposal and consent files come from other ledgers' people, by any
// channel. Properties: reading never crashes; a file that reads encodes back
// to exactly its bytes (one encoding per file); and what reads keeps the
// limits (1 to 16 ledgers for a proposal, none for a consent, a note of 1 to
// 1000 bytes).

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <cexchain/core/protocol/exchange.hpp>

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace cexchain;
    const ByteView input(data, size);
    const auto file = protocol::decode_exchange_file(input);
    if (!file) {
        return 0;
    }
    const auto again = protocol::encode_exchange_file(*file);
    require(again.has_value() && ByteView(*again).size() == size &&
            std::equal(again->begin(), again->end(), data));
    if (file->kind == protocol::ExchangeKind::proposal) {
        require(!file->needs.empty() && file->needs.size() <= protocol::max_exchange_needs);
    } else {
        require(file->needs.empty());
    }
    require(!file->note ||
            (!file->note->empty() && file->note->size() <= protocol::max_exchange_note));
    return 0;
}
