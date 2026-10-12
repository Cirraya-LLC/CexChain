// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A registrar's pending calls (D-053): proposals come from the home's people
// and from peers, pending files from disk, from Raft entries, from snapshots,
// and from backups. Decoding must never crash, and whatever decodes must
// encode back to the same bytes; a file name that parses must be the name
// of what it parsed to (no other path can pass for one).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <cexchain/core/cbor.hpp>
#include <cexchain/node/contracts.hpp>

namespace node = cexchain::node;
namespace cbor = cexchain::cbor;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const cexchain::ByteView input(data, size);
    if (const auto proposal = node::decode_call_proposal(input)) {
        const auto again = node::encode_call_proposal(*proposal);
        require(again && std::ranges::equal(*again, input));
        require(proposal->proposer.empty() && proposal->missing.empty() &&
                proposal->consents.empty());
    }
    if (const auto pending = node::decode_pending_call(input)) {
        const auto again = node::encode_pending_call(*pending);
        require(again && std::ranges::equal(*again, input));
        require(pending->until > 0 && !pending->proposer.empty());
    }
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    if (const auto name = node::parse_pending_call_name(text)) {
        require(node::pending_call_name(*name) == text);
        require(text.find('/') == std::string_view::npos);
    }
    if (const auto value = cbor::decode(input)) {
        if (const auto changes = node::decode_pending_changes(*value)) {
            const auto again = cbor::encode(node::pending_changes_value(*changes));
            require(again && std::ranges::equal(*again, input));
        }
    }
    return 0;
}
