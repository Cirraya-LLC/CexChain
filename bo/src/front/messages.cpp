// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Diagnostics as text, in the reader's language.

#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <cexchain/bo/messages.hpp>

#include "internal.hpp"

namespace cexchain::bo {

std::string fill(std::string_view pattern,
                 std::span<const std::pair<std::string_view, std::string>> values) {
    std::string out;
    out.reserve(pattern.size());
    std::size_t i = 0;
    while (i < pattern.size()) {
        const std::size_t open = pattern.find('{', i);
        if (open == std::string_view::npos) {
            out += pattern.substr(i);
            break;
        }
        out += pattern.substr(i, open - i);
        const std::size_t close = pattern.find('}', open);
        if (close == std::string_view::npos) {
            out += pattern.substr(open);
            break;
        }
        const std::string_view name = pattern.substr(open + 1, close - open - 1);
        bool found = false;
        for (const auto& [key, value] : values) {
            if (key == name) {
                out += value;
                found = true;
                break;
            }
        }
        if (!found) {
            out += pattern.substr(open, close - open + 1);
        }
        i = close + 1;
    }
    return out;
}

std::string visible(std::string_view text) {
    const auto points = detail::code_points(text);
    if (!points) {
        return std::string(text);
    }
    std::string out;
    for (const char32_t c : *points) {
        out += detail::is_invisible(c) ? std::format("U+{:04X}", static_cast<std::uint32_t>(c))
                                       : detail::utf8(c);
    }
    return out;
}

std::string render(const Diagnostic& diagnostic, const Pack* language) {
    const std::string* text = nullptr;
    for (const Pack* pack : {language, &english_pack()}) {
        if (pack == nullptr) {
            continue;
        }
        if (const auto it = pack->messages.find(diagnostic.code); it != pack->messages.end()) {
            text = &it->second;
            break;
        }
    }
    if (text != nullptr) {
        return fill(*text, diagnostic.args);
    }
    // No pack has the text: the code and the values, still exact.
    std::string out(diagnostic.code);
    for (const auto& [key, value] : diagnostic.args) {
        out += " " + std::string(key) + "=" + value;
    }
    return out;
}

} // namespace cexchain::bo
