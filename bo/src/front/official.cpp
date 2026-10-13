// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The official language packs, compiled in from bo/packs/ with #embed and
// read once. Official packs are append-only: once released, a version never
// changes, and later compilers carry every released version so that old
// sources rebuild (milestone 7 adds the older versions as they appear).

#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>

namespace cexchain::bo {

namespace {

#if defined(__clang__)
#pragma clang diagnostic push
// Clang 23 accepts #embed in C++ as an extension of C23's.
#pragma clang diagnostic ignored "-Wc23-extensions"
#endif

constexpr unsigned char en_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/en.pack"
#else
#include "en.pack.inc"
#endif
};

constexpr unsigned char zh_hant_hk_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/zh-Hant-HK.pack"
#else
#include "zh-Hant-HK.pack.inc"
#endif
};

constexpr unsigned char zh_hans_cn_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/zh-Hans-CN.pack"
#else
#include "zh-Hans-CN.pack.inc"
#endif
};

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

std::string_view as_text(std::span<const unsigned char> bytes) noexcept {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

const PackText texts[] = {
    {"en", as_text(en_bytes)},
    {"zh-Hant-HK", as_text(zh_hant_hk_bytes)},
    {"zh-Hans-CN", as_text(zh_hans_cn_bytes)},
};

/// The official packs, read once. They are part of the compiler: one that
/// does not read is a defect of the build, which the tests catch first.
const std::vector<Pack>& read_official() {
    static const std::vector<Pack> packs = [] {
        std::vector<Pack> out;
        for (const PackText& text : texts) {
            PackRead read = read_pack(text.text);
            if (!read.pack || read.pack->id != text.id || !read.pack->official) {
                std::fprintf(stderr, "bo: the official pack %.*s does not read\n",
                             static_cast<int>(text.id.size()), text.id.data());
                for (const Diagnostic& diagnostic : read.diagnostics) {
                    std::fprintf(stderr, "  %s %s\n", std::string(diagnostic.code).c_str(),
                                 diagnostic.args.empty() ? "" : diagnostic.args[0].second.c_str());
                }
                std::abort();
            }
            out.push_back(std::move(*read.pack));
        }
        return out;
    }();
    return packs;
}

} // namespace

std::span<const PackText> official_pack_texts() noexcept {
    return texts;
}

std::span<const Pack> official_packs() noexcept {
    return read_official();
}

const Pack* official_pack(std::string_view id) noexcept {
    for (const Pack& pack : read_official()) {
        if (pack.id == id) {
            return &pack;
        }
    }
    return nullptr;
}

const Pack& english_pack() noexcept {
    const Pack* pack = official_pack("en");
    BO_ASSERT(pack != nullptr);
    if (pack == nullptr) {
        std::abort();
    }
    return *pack;
}

} // namespace cexchain::bo
