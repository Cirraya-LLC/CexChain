// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The official language packs, compiled in from bo/packs/ with #embed and
// read once. Official packs are append-only: a version never changes, and
// later compilers carry every earlier version so that old sources rebuild:
// version 1 of each, from before vocabulary packs (D-054), is in
// bo/packs/history/, byte for byte as it was.

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

// Version 1 of each, from before vocabulary packs (D-054), carried so that
// the deploys made with them rebuild (bo/packs/history/).
constexpr unsigned char en_1_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/history/en-1.pack"
#else
#include "history/en-1.pack.inc"
#endif
};

constexpr unsigned char zh_hant_hk_1_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/history/zh-Hant-HK-1.pack"
#else
#include "history/zh-Hant-HK-1.pack.inc"
#endif
};

constexpr unsigned char zh_hans_cn_1_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/history/zh-Hans-CN-1.pack"
#else
#include "history/zh-Hans-CN-1.pack.inc"
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

const PackText earlier_texts[] = {
    {"en", as_text(en_1_bytes)},
    {"zh-Hant-HK", as_text(zh_hant_hk_1_bytes)},
    {"zh-Hans-CN", as_text(zh_hans_cn_1_bytes)},
};

/// Official packs, read. They are part of the compiler: one that does not
/// read is a defect of the build, which the tests catch first.
std::vector<Pack> read_all(std::span<const PackText> list) {
    std::vector<Pack> out;
    for (const PackText& text : list) {
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
}

const std::vector<Pack>& read_official() {
    static const std::vector<Pack> packs = read_all(texts);
    return packs;
}

const std::vector<Pack>& read_earlier() {
    static const std::vector<Pack> packs = read_all(earlier_texts);
    return packs;
}

} // namespace

std::span<const PackText> official_pack_texts() noexcept {
    return texts;
}

std::span<const PackText> earlier_official_pack_texts() noexcept {
    return earlier_texts;
}

std::span<const Pack> official_packs() noexcept {
    return read_official();
}

std::span<const Pack> earlier_official_packs() noexcept {
    return read_earlier();
}

std::span<const Pack> official_packs(const Officials officials) noexcept {
    return officials == Officials::current ? official_packs() : earlier_official_packs();
}

const Pack* official_pack(std::string_view id, std::uint64_t version,
                          Officials* officials) noexcept {
    for (const Officials which : {Officials::current, Officials::before_vocabulary}) {
        for (const Pack& pack : official_packs(which)) {
            if (pack.id == id && pack.version == version) {
                if (officials != nullptr) {
                    *officials = which;
                }
                return &pack;
            }
        }
    }
    return nullptr;
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
