// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A form's values for a contract's calls come from a page or a command line:
// JSON, and in it values that Bo's lexer reads. The first byte picks how the
// rest is used: as the JSON of the values, or as one value written for each
// of a contract's typed fields in turn. Properties: reading never crashes;
// arguments built are canonical CBOR that encodes and decodes to the same
// value, the same whatever order the values come in; and a call either has
// arguments or names a problem, never both.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <variant>

#include <cexchain/bo/calls.hpp>
#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/core/cbor.hpp>

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

constexpr std::string_view contract = "contract Order\nparties we, buyer, carrier\n\nthing Deal\n"
                                      "  cost HKD\n  fee HKD = HKD 10\n  starts date\n"
                                      "  weight kg\n  urgent yes or no\n"
                                      "  tags list text at most 2\n  note text\n  count number\n\n"
                                      "can ship by we to carrier with lead day, wait month\n"
                                      "  requires lead > 0\n  open -> shipped\n";

const bo::model::Model& model() {
    static const bo::model::Model instance = [] {
        const bo::Lexed lexed = bo::lex(contract, lexicon());
        const bo::Parsed parsed = bo::parse(contract, lexed);
        bo::Checked checked = bo::check(contract, parsed.file);
        require(!bo::has_errors(lexed.diagnostics) && !bo::has_errors(parsed.diagnostics));
        return std::move(checked.model);
    }();
    return instance;
}

void build(std::string_view function, const bo::calls::Values& values) {
    const bo::calls::Arguments built = bo::calls::arguments(model(), lexicon(), function, values);
    require(built.value.has_value() != !built.problems.empty());
    if (!built.value) {
        for (const bo::calls::Problem& p : built.problems) {
            require(!p.code.empty() && !p.detail.empty());
        }
        return;
    }
    const auto encoded = cbor::encode(*built.value);
    require(encoded.has_value());
    const auto decoded = cbor::decode(*encoded);
    require(decoded.has_value() && *decoded == *built.value);
    bo::calls::Values reversed = values;
    std::ranges::reverse(reversed);
    const bo::calls::Arguments again = bo::calls::arguments(model(), lexicon(), function, reversed);
    require(again.value.has_value() && *again.value == *built.value);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::string_view input(reinterpret_cast<const char*>(data) + 1, size - 1);
    if (data[0] % 2 == 0) {
        const auto read = bo::calls::parse_values(input);
        if (const auto* values = std::get_if<bo::calls::Values>(&read)) {
            for (const std::string_view function : {"create", "ship", "nothing"}) {
                build(function, *values);
            }
        }
        return 0;
    }
    // One text as each typed value in turn, the others valid.
    const std::string text(input);
    for (const char* name : {"cost", "starts", "weight", "count", "note"}) {
        bo::calls::Values values{{"cost", {std::string("HKD 1")}},
                                 {"starts", {std::string("2027-01-06")}},
                                 {"weight", {std::string("1 kg")}},
                                 {"urgent", {true}},
                                 {"tags", {std::vector<bo::calls::Value>{}}},
                                 {"note", {std::string("n")}},
                                 {"count", {std::string("1")}},
                                 {"we", {std::string(64, 'a')}},
                                 {"buyer", {std::string(64, 'b')}}};
        for (auto& [key, value] : values) {
            if (key == name) {
                value = {text};
            }
        }
        build("create", values);
    }
    build("ship", {{"lead", {text}}, {"wait", {text}}});
    return 0;
}
