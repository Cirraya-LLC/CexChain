// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The official language packs, compiled in from bo/packs/ with #embed and
// read once. Official packs are append-only: a version never changes, and
// later compilers carry every earlier release so that old sources rebuild,
// in bo/packs/history/, byte for byte as they were: version 1 of each, from
// before vocabulary packs (D-054), and version 2, from before temperatures
// and field defaults (G5b).

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

// Version 2 of each, with vocabulary packs, from before temperatures and
// field defaults (G5b).
constexpr unsigned char en_2_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/history/en-2.pack"
#else
#include "history/en-2.pack.inc"
#endif
};

constexpr unsigned char zh_hant_hk_2_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/history/zh-Hant-HK-2.pack"
#else
#include "history/zh-Hant-HK-2.pack.inc"
#endif
};

constexpr unsigned char zh_hans_cn_2_bytes[] = {
#if CEXCHAIN_BO_EMBED
#embed "../../packs/history/zh-Hans-CN-2.pack"
#else
#include "history/zh-Hans-CN-2.pack.inc"
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

const PackText texts_1[] = {
    {"en", as_text(en_1_bytes)},
    {"zh-Hant-HK", as_text(zh_hant_hk_1_bytes)},
    {"zh-Hans-CN", as_text(zh_hans_cn_1_bytes)},
};

const PackText texts_2[] = {
    {"en", as_text(en_2_bytes)},
    {"zh-Hant-HK", as_text(zh_hant_hk_2_bytes)},
    {"zh-Hans-CN", as_text(zh_hans_cn_2_bytes)},
};

/// Every release carried, the current one first, then newest first.
constexpr Officials release_order[] = {Officials::current, Officials::before_temperature,
                                       Officials::before_vocabulary};

std::span<const PackText> texts_of(const Officials which) noexcept {
    switch (which) {
    case Officials::current:
        return texts;
    case Officials::before_temperature:
        return texts_2;
    case Officials::before_vocabulary:
        return texts_1;
    }
    return texts;
}

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

/// A release's packs, each release read on first use.
template <Officials which>
const std::vector<Pack>& read_once() {
    static const std::vector<Pack> packs = read_all(texts_of(which));
    return packs;
}

const std::vector<Pack>& read_release(const Officials which) {
    switch (which) {
    case Officials::current:
        return read_once<Officials::current>();
    case Officials::before_temperature:
        return read_once<Officials::before_temperature>();
    case Officials::before_vocabulary:
        return read_once<Officials::before_vocabulary>();
    }
    return read_once<Officials::current>();
}

const std::vector<Pack>& read_official() {
    return read_release(Officials::current);
}

} // namespace

std::span<const PackText> official_pack_texts() noexcept {
    return texts;
}

std::span<const PackText> official_pack_texts(const Officials officials) noexcept {
    return texts_of(officials);
}

std::span<const Officials> official_releases() noexcept {
    return release_order;
}

std::span<const Pack> official_packs() noexcept {
    return read_official();
}

std::span<const Pack> official_packs(const Officials officials) noexcept {
    return read_release(officials);
}

const Pack* official_pack(std::string_view id, std::uint64_t version,
                          Officials* officials) noexcept {
    for (const Officials which : release_order) {
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
