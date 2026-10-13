// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A Bo deploy's source is untrusted: deploys come from other organizations,
// and every verifier decodes the bo-source bundle a deploy carries, opens the
// packs it names (embedded ones read from CBOR), and reads the source with
// them. A .boc file comes from whoever built it. The input is read as a
// bundle, as a .boc, and as a compiler string. Properties:
//   - a bundle that decodes encodes to the same bytes, and opens under
//     SHA-256 and SM3 with either a pack set or one stated problem (never
//     both); with a set, its source lexes, parses, and checks;
//   - a bundle opens with no problem only if it names every official pack;
//   - a .boc that decodes encodes to the same bytes, and its bundle decodes;
//   - a compiler string that parses formats to the same text.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace {

using namespace cexchain;

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

void read_source(const bo::SourceBundle& bundle, const bo::PackSet& packs) {
    const bo::Lexicon lexicon(packs);
    const bo::Lexed lexed = bo::lex(bundle.source, lexicon);
    const bo::Parsed parsed = bo::parse(bundle.source, lexed);
    if (!bo::has_errors(lexed.diagnostics) && !bo::has_errors(parsed.diagnostics)) {
        static_cast<void>(bo::check(bundle.source, parsed.file));
    }
}

void bundle(ByteView data) {
    const auto decoded = bo::decode_source_bundle(data);
    if (!decoded) {
        return;
    }
    const auto again = bo::encode_source_bundle(*decoded);
    if (!again || !std::ranges::equal(*again, data)) {
        std::abort();
    }
    for (const crypto::HashAlg hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
        const bo::OpenedSource opened = bo::open_source_bundle(*decoded, provider(), hash);
        if (opened.packs.has_value() != (opened.problem == bo::OpenProblem::none) ||
            opened.detail.empty() != (opened.problem == bo::OpenProblem::none)) {
            std::abort();
        }
        if (!opened.packs) {
            continue;
        }
        for (const bo::Pack& official : bo::official_packs()) {
            if (opened.packs->find(official.id) == nullptr) {
                std::abort();
            }
        }
        read_source(*decoded, *opened.packs);
    }
}

void built(ByteView data) {
    const auto decoded = bo::decode_built(data);
    if (!decoded) {
        return;
    }
    const auto again = bo::encode_built(*decoded);
    if (!again || !std::ranges::equal(*again, data) || !bo::decode_source_bundle(decoded->source)) {
        std::abort();
    }
}

void compiler(std::string_view text) {
    if (const auto id = bo::parse_compiler(text); id && bo::format_compiler(*id) != text) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Read once before timing anything: the official packs.
    static const bool ready = !cexchain::bo::official_packs().empty();
    if (!ready) {
        std::abort();
    }
    const cexchain::ByteView bytes(data, size);
    bundle(bytes);
    built(bytes);
    compiler(std::string_view(reinterpret_cast<const char*>(data), size));
    return 0;
}
