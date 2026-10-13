// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Language packs are untrusted: a counterparty may send a source with its own
// pack, and a deploy's source bundle embeds packs as CBOR. The input is read
// as a pack file (diagnostic notation) and as CBOR. Properties:
//   - a pack is returned exactly when no error is reported;
//   - every diagnostic renders in each official language;
//   - a pack that reads, read again from its canonical CBOR, is the same
//     pack (same bytes, same spellings), and joins the official packs or
//     says why not.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>
#include <vector>

#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/core/cbor.hpp>

namespace {

using namespace cexchain;

void check(const bo::PackRead& read) {
    if (read.pack.has_value() == bo::has_errors(read.diagnostics)) {
        std::abort();
    }
    for (const bo::Diagnostic& diagnostic : read.diagnostics) {
        for (const bo::Pack& language : bo::official_packs()) {
            if (bo::render(diagnostic, &language).empty()) {
                std::abort();
            }
        }
    }
    if (!read.pack) {
        return;
    }
    const auto value = cbor::decode(read.pack->canonical);
    if (!value) {
        std::abort();
    }
    const bo::PackRead again = bo::read_pack(*value);
    if (!again.pack || again.pack->canonical != read.pack->canonical ||
        again.pack->keywords.size() != read.pack->keywords.size() ||
        again.pack->vocabulary.size() != read.pack->vocabulary.size()) {
        std::abort();
    }
    const bo::PackSetRead set = bo::make_pack_set({*read.pack});
    if (set.set.has_value() == bo::has_errors(set.diagnostics)) {
        std::abort();
    }
    if (set.set) {
        // Every spelling of the pack means something in the set.
        for (const auto* words : {&read.pack->keywords, &read.pack->vocabulary}) {
            for (const auto& [id, word] : *words) {
                for (const auto& spelling : word.spellings) {
                    if (set.set->lookup(spelling) == nullptr) {
                        std::abort();
                    }
                }
            }
        }
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Read once before timing anything: the official packs.
    static const bool ready = !cexchain::bo::official_packs().empty();
    if (!ready) {
        std::abort();
    }
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    check(cexchain::bo::read_pack(text));
    cexchain::cbor::DecodeOptions options;
    options.max_depth = cexchain::cbor::max_nesting_depth;
    if (const auto value = cexchain::cbor::decode(cexchain::ByteView(data, size), options)) {
        check(cexchain::bo::read_pack(*value));
    }
    return 0;
}
