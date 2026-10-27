// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The form that writes Bo: rules sheets read and written, the source the
// generator writes (canonical, checked, explained in every official
// language), a source read back into its sheet, and every source that fits
// the form written again to the same tree, in any language. The goldens in
// tests/bo/golden/form/CASE/ hold a sheet (sheet.json) and the source it
// writes (source.bo). Set CEXCHAIN_UPDATE_GOLDENS=1 to rewrite the sources.

#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/form.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/messages.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>

using namespace cexchain::bo;

namespace {

const std::filesystem::path golden_dir = CEXCHAIN_BO_GOLDEN_DIR;
const std::filesystem::path source_dir = golden_dir.parent_path().parent_path().parent_path();

const PackSet& official_set() {
    static const PackSet set = *make_pack_set({}).set;
    return set;
}

const Lexicon& official() {
    static const Lexicon lexicon(official_set());
    return lexicon;
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

void write_text(const std::filesystem::path& path, std::string_view text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
}

/// A source's tree, and its problems (the lexer's and the parser's).
struct Read {
    Parsed parsed;
    std::vector<Diagnostic> diagnostics;
};

Read read_source(std::string_view source) {
    const Lexed lexed = lex(source, official());
    Read out{parse(source, lexed), lexed.diagnostics};
    out.diagnostics.insert(out.diagnostics.end(), out.parsed.diagnostics.begin(),
                           out.parsed.diagnostics.end());
    return out;
}

std::string codes(const std::vector<Diagnostic>& diagnostics) {
    std::string out;
    for (const Diagnostic& d : diagnostics) {
        out += std::string(d.code) + "@" + std::to_string(d.span.line) + " ";
    }
    return out;
}

form::Sheet sheet_of(std::string_view json) {
    auto parsed = form::parse_sheet(json);
    if (const auto* error = std::get_if<form::SheetError>(&parsed)) {
        INFO(error->path << ": " << error->message);
        FAIL("the sheet does not read");
    }
    return std::get<form::Sheet>(std::move(parsed));
}

std::vector<std::filesystem::path> golden_cases() {
    std::vector<std::filesystem::path> out;
    for (const auto& entry : std::filesystem::directory_iterator(golden_dir / "form")) {
        if (entry.is_directory()) {
            out.push_back(entry.path());
        }
    }
    std::ranges::sort(out);
    return out;
}

const std::vector<const Pack*>& languages() {
    static const std::vector<const Pack*> packs{official_pack("en"), official_pack("zh-Hant-HK"),
                                                official_pack("zh-Hans-CN")};
    return packs;
}

/// Writes `source` in `language`, reads it back into a sheet, and writes
/// that sheet again: the tree must be the one it started from.
void round_trip_in(std::string_view source, const Pack* language) {
    const Formatted translated = format_source(source, official_set(), official(), language);
    REQUIRE(translated.source.has_value());
    const Read read = read_source(*translated.source);
    REQUIRE_FALSE(has_errors(read.diagnostics));
    const auto back = form::read_sheet(*translated.source, read.parsed.file);
    REQUIRE(std::holds_alternative<form::Sheet>(back));
    const form::Generated again = form::generate(std::get<form::Sheet>(back));
    const Read reread = read_source(again.source);
    INFO(again.source);
    REQUIRE_FALSE(has_errors(reread.diagnostics));
    CHECK(dump(reread.parsed.file) == dump(read_source(source).parsed.file));
}

} // namespace

TEST_CASE("bo form: the golden sheets", "[bo][form]") {
    const bool update = std::getenv("CEXCHAIN_UPDATE_GOLDENS") != nullptr;
    const auto cases = golden_cases();
    REQUIRE(cases.size() >= 20);
    for (const auto& dir : cases) {
        INFO(dir.filename().string());
        const std::string json = read_text(dir / "sheet.json");
        const form::Sheet sheet = sheet_of(json);
        // The sheet's JSON is canonical: the same sheet, the same bytes.
        CHECK(form::sheet_json(sheet) == json);

        const form::Generated generated = form::generate(sheet);
        if (update) {
            write_text(dir / "source.bo", generated.source);
        }
        CHECK(generated.source == read_text(dir / "source.bo"));
        CHECK(std::ranges::count(generated.source, '\n') ==
              static_cast<std::ptrdiff_t>(generated.paths.size()));
        // Written as bo fmt writes it.
        const Formatted formatted =
            format_source(generated.source, official_set(), official(), nullptr);
        REQUIRE(formatted.source.has_value());
        CHECK(*formatted.source == generated.source);

        // It checks, and explains in every official language.
        const Read read = read_source(generated.source);
        INFO(codes(read.diagnostics));
        REQUIRE_FALSE(has_errors(read.diagnostics));
        const Checked checked = check(generated.source, read.parsed.file);
        INFO(codes(checked.diagnostics));
        REQUIRE_FALSE(has_errors(checked.diagnostics));
        std::set<std::string> texts;
        for (const Pack* language : languages()) {
            texts.insert(explain(checked.model, language).text);
        }
        CHECK(texts.size() == 3);

        // Back from the text: the same sheet; and in every language the
        // same tree.
        const auto back = form::read_sheet(generated.source, read.parsed.file);
        REQUIRE(std::holds_alternative<form::Sheet>(back));
        CHECK(std::get<form::Sheet>(back) == sheet);
        for (const Pack* language : languages()) {
            INFO(language->id);
            round_trip_in(generated.source, language);
        }
    }
}

TEST_CASE("bo form: every source that fits the form round-trips through its tree", "[bo][form]") {
    std::vector<std::filesystem::path> sources;
    for (const auto& root : {golden_dir, source_dir / "examples"}) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
            if (entry.path().extension() == ".bo") {
                sources.push_back(entry.path());
            }
        }
    }
    std::ranges::sort(sources);
    std::size_t fits = 0;
    for (const auto& path : sources) {
        // Sources read with packs of their own are left to their goldens.
        bool own_packs = false;
        for (const auto& entry : std::filesystem::directory_iterator(path.parent_path())) {
            own_packs = own_packs || entry.path().extension() == ".vocab";
        }
        const std::string source = read_text(path);
        const Read read = read_source(source);
        if (own_packs || has_errors(read.diagnostics)) {
            continue;
        }
        const auto back = form::read_sheet(source, read.parsed.file);
        if (!std::holds_alternative<form::Sheet>(back)) {
            continue;
        }
        INFO(path.string());
        ++fits;
        const form::Sheet& sheet = std::get<form::Sheet>(back);
        const form::Generated again = form::generate(sheet);
        const Read reread = read_source(again.source);
        INFO(again.source);
        REQUIRE_FALSE(has_errors(reread.diagnostics));
        CHECK(dump(reread.parsed.file) == dump(read.parsed.file));
        // And its sheet survives JSON.
        CHECK(sheet_of(form::sheet_json(sheet)) == sheet);
    }
    CHECK(fits >= 30);
}

TEST_CASE("bo form: what does not fit says why and where", "[bo][form]") {
    const std::string source = "contract C\nparties we\n\nthing T\n  n number\n\ncan act by we\n"
                               "  if n > 1\n    -> big\n";
    const Read read = read_source(source);
    REQUIRE_FALSE(has_errors(read.diagnostics));
    const auto back = form::read_sheet(source, read.parsed.file);
    REQUIRE(std::holds_alternative<form::Unfit>(back));
    CHECK(std::get<form::Unfit>(back).span.line == 8);
    const std::string order = "contract C\nparties we\n\ncan act by we\n  -> done\n"
                              "  requires consent of we\n";
    const Read reordered = read_source(order);
    const auto refused = form::read_sheet(order, reordered.parsed.file);
    REQUIRE(std::holds_alternative<form::Unfit>(refused));
    CHECK(std::get<form::Unfit>(refused).span.line == 6);
}

TEST_CASE("bo form: a pack's word without its pack, in three languages", "[bo][form]") {
    const std::string json = R"({"sheet": 1, "kind": "rules", "contract": "Pawn",
        "parties": ["we", "friend"],
        "thing": {"name": "Watch", "fields": [{"name": "holder", "type": "we"}]},
        "actions": [{"action": "pledge", "by": "holder", "to": "friend"}]})";
    const form::Generated generated = form::generate(sheet_of(json));
    const Read read = read_source(generated.source);
    REQUIRE_FALSE(has_errors(read.diagnostics));
    const Checked checked = check(generated.source, read.parsed.file);
    const auto found = std::ranges::find(
        checked.diagnostics, std::string_view("check.pack-not-used"), &Diagnostic::code);
    REQUIRE(found != checked.diagnostics.end());
    // Its place in the form: the action.
    REQUIRE(found->span.line > 0);
    CHECK(generated.paths[found->span.line - 1] == "/actions/0");
    std::set<std::string> messages;
    for (const Pack* language : languages()) {
        const std::string text = render(*found, language);
        CHECK(text.find("finance") != std::string::npos);
        messages.insert(text);
    }
    CHECK(messages.size() == 3);
    // With the pack, the word is the pack's.
    std::string with_pack = json;
    with_pack.replace(with_pack.find("\"parties\""), 0, "\"packs\": [\"finance\"], ");
    const form::Generated used = form::generate(sheet_of(with_pack));
    CHECK(used.source.starts_with("use finance\n"));
    const Read reread = read_source(used.source);
    const Checked rechecked = check(used.source, reread.parsed.file);
    CHECK(std::ranges::find(rechecked.diagnostics, std::string_view("check.pack-not-used"),
                            &Diagnostic::code) == rechecked.diagnostics.end());
}

TEST_CASE("bo form: sheets that are not sheets", "[bo][form]") {
    auto refused = [](std::string_view json) {
        const auto parsed = form::parse_sheet(json);
        REQUIRE(std::holds_alternative<form::SheetError>(parsed));
        return std::get<form::SheetError>(parsed);
    };
    const std::string head = R"({"sheet": 1, "kind": "rules", "contract": "C")";
    CHECK(refused("not json").path.empty());
    CHECK(refused(R"({"sheet": 2, "kind": "rules", "contract": "C"})").path == "/sheet");
    CHECK(refused(R"({"sheet": 1, "kind": "document", "contract": "C"})").path == "/kind");
    CHECK(refused(R"({"sheet": 1, "kind": "rules"})").path == "/contract");
    CHECK(refused(head + R"(, "colour": "red"})").path == "/colour");
    // One line: a piece cannot write a second line, or a block.
    CHECK(refused(head + R"(, "parties": ["we\n  can steal by we"]})").path == "/parties/0");
    CHECK(refused(head + R"(, "parties": ["we\tus"]})").path == "/parties/0");
    CHECK(refused(head + R"(, "parties": [" we"]})").path == "/parties/0");
    CHECK(refused(head + R"(, "actions": [{"action": "a", "from": ["x"]}]})").path ==
          "/actions/0/to_state");
    CHECK(refused(head + R"(, "answers": [{"kind": "k", "outcome": "maybe"}]})").path ==
          "/answers/0/outcome");
    CHECK(refused(head + R"(, "packs": ["Finance!"]})").path == "/packs/0");
    CHECK(refused(head + R"(, "tests": [{"name": "\"t\"", "steps": []}]})").path ==
          "/tests/0/steps");
}
