// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>
#include <string_view>

#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/pack.hpp>

namespace cexchain::bo {

/// A diagnostic's text in a pack's language: the pack's message for its
/// code, else the English pack's, with the parameters filled in. A null
/// pack means English.
[[nodiscard]] std::string render(const Diagnostic& diagnostic, const Pack* language)
    BO_PRE(find_message(diagnostic.code) != nullptr);

/// Fills a message's or sentence's placeholders ("{path}") with values;
/// placeholders without a value stay as written.
[[nodiscard]] std::string fill(std::string_view pattern,
                               std::span<const std::pair<std::string_view, std::string>> values);

/// Text for a terminal: each space or invisible character shown as its
/// code point ("U+3000"), everything else as it is.
[[nodiscard]] std::string visible(std::string_view text);

} // namespace cexchain::bo
