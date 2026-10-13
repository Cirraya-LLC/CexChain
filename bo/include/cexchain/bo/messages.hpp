// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <cexchain/bo/contracts.hpp>
#include <cexchain/bo/pack.hpp>

namespace cexchain::bo {

/// A diagnostic's text in a pack's language: the pack's message for its
/// code, else the English pack's, with the parameters filled in. A null
/// pack means English. The checker's and the builder's messages (check.*,
/// build.*) carry concepts and types in a neutral form, which become words
/// of the language here: a parameter named `type` or `..._type` holds an
/// encoded type (checker.hpp, encode), described in words; any other value
/// that is a concept id, or a list of them separated by ", ", is spelled.
[[nodiscard]] std::string render(const Diagnostic& diagnostic, const Pack* language)
    BO_PRE(find_message(diagnostic.code) != nullptr);

/// A refusal of compiled code in a pack's language. Compiled contracts
/// abort with "bo:CODE VALUES" for the compiler's own checks (values
/// separated by spaces: "bo:requires sign 2"), which is the message run.CODE
/// with the values as its parameters, in order; actions and parties that are
/// vocabulary are spelled in the language ("bo:state pledge" names 質押 in
/// Chinese). Nullopt for any other reason, such as the text of a `reject`,
/// which tools show as written.
[[nodiscard]] std::optional<std::string> render_reason(std::string_view reason,
                                                       const Pack* language);

/// A concept's first spelling in the pack's language, else in English, else
/// its id: "質押" for act.pledge in zh-Hant-HK.
[[nodiscard]] std::string spell(std::string_view concept_id, const Pack* language);

/// A sentence of the pack (else of the English pack) with its placeholders
/// filled; the id itself if no pack has it.
[[nodiscard]] std::string sentence(std::string_view id,
                                   std::span<const std::pair<std::string_view, std::string>> values,
                                   const Pack* language);

/// Fills a message's or sentence's placeholders ("{path}") with values;
/// placeholders without a value stay as written.
[[nodiscard]] std::string fill(std::string_view pattern,
                               std::span<const std::pair<std::string_view, std::string>> values);

/// Text for a terminal: each space or invisible character shown as its
/// code point ("U+3000"), everything else as it is.
[[nodiscard]] std::string visible(std::string_view text);

} // namespace cexchain::bo
