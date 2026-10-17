// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Diagnostics as text, in the reader's language.

#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/messages.hpp>

#include "internal.hpp"

namespace cexchain::bo {

namespace {

/// The text of a diagnostic whose values are words already.
std::string render_text(const Diagnostic& diagnostic, const Pack* language);

} // namespace

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

std::string spell(std::string_view concept_id, const Pack* language) {
    // A unit with a symbol is written so in every language (°C).
    if (const std::string_view symbol = unit_symbol(find_concept(concept_id)); !symbol.empty()) {
        return std::string(symbol);
    }
    for (const Pack* pack : {language, &english_pack()}) {
        if (pack == nullptr) {
            continue;
        }
        if (const Word* word = pack->word(concept_id);
            word != nullptr && !word->spellings.empty()) {
            return word->spellings.front();
        }
    }
    // A user's vocabulary pack's word (`events:act.reserve`) that the
    // language packs here do not hold: its plain name.
    if (concept_id.find(':') != std::string_view::npos) {
        const std::size_t dot = concept_id.find('.');
        return std::string(dot == std::string_view::npos ? concept_id : concept_id.substr(dot + 1));
    }
    return std::string(concept_id);
}

std::string sentence(std::string_view id,
                     std::span<const std::pair<std::string_view, std::string>> values,
                     const Pack* language) {
    for (const Pack* pack : {language, &english_pack()}) {
        if (pack == nullptr) {
            continue;
        }
        if (const auto it = pack->sentences.find(id); it != pack->sentences.end()) {
            return fill(it->second, values);
        }
    }
    return std::string(id);
}

namespace {

bool is_type_param(std::string_view name) noexcept {
    return name == "type" || name.ends_with("_type");
}

/// A value with every concept id in it spelled: the value is a concept id,
/// or a list of them (and names) separated by ", ".
std::string spelled(std::string_view value, const Pack* language) {
    std::string out;
    while (true) {
        const std::size_t comma = value.find(", ");
        const std::string_view part = value.substr(0, comma);
        // A user's vocabulary pack's concept id (`events:act.reserve`) too.
        const bool user_concept = part.find(':') != std::string_view::npos &&
                                  part.find('.', part.find(':')) != std::string_view::npos;
        out += find_concept(part) != nullptr || user_concept ? spell(part, language)
                                                             : std::string(part);
        if (comma == std::string_view::npos) {
            return out;
        }
        out += ", ";
        value.remove_prefix(comma + 2);
    }
}

} // namespace

std::string render(const Diagnostic& diagnostic, const Pack* language) {
    if (diagnostic.code.starts_with("check.") || diagnostic.code.starts_with("build.")) {
        std::vector<std::pair<std::string_view, std::string>> words;
        words.reserve(diagnostic.args.size());
        for (const auto& [name, value] : diagnostic.args) {
            words.emplace_back(name, is_type_param(name) ? describe_type(value, language)
                                                         : spelled(value, language));
        }
        Diagnostic in_words{diagnostic.code, std::move(words), diagnostic.span};
        return render_text(in_words, language);
    }
    return render_text(diagnostic, language);
}

std::optional<std::string> render_reason(std::string_view reason, const Pack* language) {
    if (!reason.starts_with("bo:")) {
        return std::nullopt;
    }
    reason.remove_prefix(3);
    const std::size_t space = reason.find(' ');
    const std::string code = "run." + std::string(reason.substr(0, space));
    const MessageSpec* spec = find_message(code);
    if (spec == nullptr) {
        return std::nullopt;
    }
    std::vector<std::string_view> values;
    if (space != std::string_view::npos) {
        std::string_view rest = reason.substr(space + 1);
        while (true) {
            const std::size_t next = rest.find(' ');
            values.push_back(rest.substr(0, next));
            if (next == std::string_view::npos) {
                break;
            }
            rest.remove_prefix(next + 1);
        }
    }
    std::vector<std::string_view> params;
    for (std::string_view rest = spec->params; !rest.empty();) {
        const std::size_t next = rest.find(' ');
        params.push_back(rest.substr(0, next));
        rest = next == std::string_view::npos ? std::string_view{} : rest.substr(next + 1);
    }
    if (values.size() != params.size()) {
        return std::nullopt;
    }
    // Compiled code names vocabulary by its id without the category
    // (wire_name): spell it again where the parameter says which category.
    const auto word = [&](std::string_view param, std::string_view value) {
        std::vector<std::string_view> prefixes;
        if (param == "action") {
            prefixes = {"act."};
        } else if (param == "party") {
            prefixes = {"role.", "field."};
        }
        for (const std::string_view prefix : prefixes) {
            const std::string id = std::string(prefix) + std::string(value);
            if (find_concept(id) != nullptr) {
                return spell(id, language);
            }
        }
        return std::string(value);
    };
    std::vector<std::pair<std::string_view, std::string>> args;
    for (std::size_t i = 0; i < params.size(); ++i) {
        args.emplace_back(params[i], word(params[i], values[i]));
    }
    return render_text(Diagnostic{spec->code, std::move(args), Span{}}, language);
}

namespace {

std::string render_text(const Diagnostic& diagnostic, const Pack* language) {
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

} // namespace

} // namespace cexchain::bo
