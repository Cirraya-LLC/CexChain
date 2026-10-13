// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Bo source is untrusted: a counterparty may send a contract to check, and a
// deploy carries its source for anyone to rebuild. The input is lexed with
// the official packs. Properties:
//   - the tokens end with `end`, and blocks balance (as many dedents as
//     indents);
//   - every place lies in the source, tokens in order, and each place's line
//     and column match its byte offset;
//   - a name is exactly the bytes it spans;
//   - every diagnostic is a known code and renders in each official
//     language;
//   - lexing again gives the same dump.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>

namespace {

using namespace cexchain;

const bo::Lexicon& lexicon() {
    static const bo::Lexicon instance = [] {
        const bo::PackSetRead set = bo::make_pack_set({});
        if (!set.set) {
            std::abort();
        }
        return bo::Lexicon(*set.set);
    }();
    return instance;
}

/// The line and column of a byte offset, counting characters by their lead
/// bytes (the source before any place is valid UTF-8).
void check_place(std::string_view source, const bo::Span& span) {
    if (span.line == 0) {
        return;
    }
    if (std::size_t{span.offset} + span.length > source.size()) {
        std::abort();
    }
    std::uint32_t line = 1;
    std::uint32_t column = 1;
    for (std::size_t i = 0; i < span.offset; ++i) {
        const auto byte = static_cast<unsigned char>(source[i]);
        if (byte == '\n') {
            ++line;
            column = 1;
        } else if ((byte & 0xC0U) != 0x80U) {
            ++column;
        }
    }
    if (line != span.line || column != span.column) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const bo::Lexicon& lx = lexicon();
    const std::string_view source(reinterpret_cast<const char*>(data), size);
    const bo::Lexed lexed = bo::lex(source, lx);

    if (lexed.tokens.empty() || lexed.tokens.back().kind != bo::TokenKind::end) {
        std::abort();
    }
    if (std::ranges::count(lexed.tokens, bo::TokenKind::indent, &bo::Token::kind) !=
        std::ranges::count(lexed.tokens, bo::TokenKind::dedent, &bo::Token::kind)) {
        std::abort();
    }
    std::uint32_t last = 0;
    for (const bo::Token& token : lexed.tokens) {
        check_place(source, token.span);
        if (token.span.offset < last) {
            std::abort();
        }
        last = token.span.offset;
        if (token.kind == bo::TokenKind::name &&
            source.substr(token.span.offset, token.span.length) != token.text) {
            std::abort();
        }
        if (token.kind == bo::TokenKind::word && token.concept_entry == nullptr) {
            std::abort();
        }
    }
    for (const bo::Comment& comment : lexed.comments) {
        check_place(source, comment.span);
    }
    for (const bo::Diagnostic& diagnostic : lexed.diagnostics) {
        if (bo::find_message(diagnostic.code) == nullptr) {
            std::abort();
        }
        check_place(source, diagnostic.span);
        for (const bo::Pack& language : bo::official_packs()) {
            if (bo::render(diagnostic, &language).empty()) {
                std::abort();
            }
        }
    }
    const std::string text = bo::dump(source, lexed, nullptr);
    if (bo::dump(source, bo::lex(source, lx), nullptr) != text) {
        std::abort();
    }
    return 0;
}
