// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The form that writes Bo reads untrusted input both ways: a rules sheet
// (JSON) someone sends or a page posts, and a source to read back into one.
// The first byte picks which. Properties:
//   - a sheet: reading it never crashes; one that reads writes JSON that
//     reads back to the same sheet; its source has a sheet path for every
//     line; and if that source reads without problems and fits the form,
//     the sheet read back from it writes the same tree again;
//   - a source: one that reads without problems either does not fit the
//     form, with a place in the source, or fits, and its sheet writes a
//     source that reads to the same tree.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include <cexchain/bo/form.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>

namespace {

using namespace cexchain;

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

const bo::PackSet& packs() {
    static const bo::PackSet instance = [] {
        bo::PackSetRead set = bo::make_pack_set({});
        require(set.set.has_value());
        return std::move(*set.set);
    }();
    return instance;
}

const bo::Lexicon& lexicon() {
    static const bo::Lexicon instance(packs());
    return instance;
}

/// The tree of a source that reads without problems, as its dump.
std::optional<std::string> tree(std::string_view source, bo::Parsed* out = nullptr) {
    const bo::Lexed lexed = bo::lex(source, lexicon());
    bo::Parsed parsed = bo::parse(source, lexed);
    if (bo::has_errors(lexed.diagnostics) || bo::has_errors(parsed.diagnostics)) {
        return std::nullopt;
    }
    std::string dumped = bo::dump(parsed.file);
    if (out != nullptr) {
        *out = std::move(parsed);
    }
    return dumped;
}

/// A source that fits: its sheet writes the same tree.
void fits_again(std::string_view source, const bo::Parsed& parsed, const std::string& dumped) {
    const auto back = bo::form::read_sheet(source, parsed.file);
    if (const auto* unfit = std::get_if<bo::form::Unfit>(&back)) {
        require(!unfit->reason.empty());
        require(unfit->span.offset + unfit->span.length <= source.size());
        return;
    }
    const bo::form::Sheet& sheet = std::get<bo::form::Sheet>(back);
    const bo::form::Generated again = bo::form::generate(sheet);
    const auto reread = tree(again.source);
    require(reread.has_value() && *reread == dumped);
    const auto json = bo::form::parse_sheet(bo::form::sheet_json(sheet));
    require(std::holds_alternative<bo::form::Sheet>(json) &&
            std::get<bo::form::Sheet>(json) == sheet);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::string_view input(reinterpret_cast<const char*>(data) + 1, size - 1);
    if (data[0] % 2 == 0) {
        const auto read = bo::form::parse_sheet(input);
        if (std::holds_alternative<bo::form::SheetError>(read)) {
            return 0;
        }
        const bo::form::Sheet& sheet = std::get<bo::form::Sheet>(read);
        const auto again = bo::form::parse_sheet(bo::form::sheet_json(sheet));
        require(std::holds_alternative<bo::form::Sheet>(again) &&
                std::get<bo::form::Sheet>(again) == sheet);
        const bo::form::Generated generated = bo::form::generate(sheet);
        std::size_t lines = 0;
        for (const char c : generated.source) {
            lines += c == '\n' ? 1U : 0U;
        }
        require(lines == generated.paths.size());
        bo::Parsed parsed;
        if (const auto dumped = tree(generated.source, &parsed)) {
            fits_again(generated.source, parsed, *dumped);
        }
        return 0;
    }
    bo::Parsed parsed;
    if (const auto dumped = tree(input, &parsed)) {
        fits_again(input, parsed, *dumped);
    }
    return 0;
}
