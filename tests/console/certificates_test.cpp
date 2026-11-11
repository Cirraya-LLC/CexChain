// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Certificates: tables read from CSV, rows checked against a kind, the
// verifier's link, and pages filled from a template.

#include <stdexcept>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <kanhe/console/certificates.hpp>
#include <kanhe/core/bytes.hpp>

namespace console = kanhe::console;
using Catch::Matchers::ContainsSubstring;
using Table = std::vector<std::vector<std::string>>;

namespace {

console::Kind diploma() {
    console::Kind kind;
    kind.type = "example.org.diploma/1";
    kind.name = "Diploma";
    kind.fields = {{"name", "Name", console::FieldType::text, true, true},
                   {"grades", "", console::FieldType::text, true, false},
                   {"year", "Year", console::FieldType::number, false, false},
                   {"qr", "", console::FieldType::text, true, false}};
    kind.printed = {"name", "year", "qr"};
    return kind;
}

std::string refusal(const auto& call) {
    try {
        call();
    } catch (const std::invalid_argument& e) {
        return e.what();
    }
    return "accepted";
}

} // namespace

TEST_CASE("a table is read as CSV", "[console][certificates]") {
    CHECK(console::parse_csv("a,b\n1,2\n") == Table{{"a", "b"}, {"1", "2"}});
    CHECK(console::parse_csv("\xEF\xBB\xBF"
                             "a,b\r\n1,2") == Table{{"a", "b"}, {"1", "2"}});
    CHECK(console::parse_csv("\"x, y\",\"say \"\"hi\"\"\",\"two\nlines\"\n") ==
          Table{{"x, y", "say \"hi\"", "two\nlines"}});
    CHECK(console::parse_csv("a,,\n\n") == Table{{"a", "", ""}, {""}});
    CHECK(console::parse_csv("").empty());
    CHECK_THAT(refusal([] { return console::parse_csv("a\n\"open\n"); }),
               ContainsSubstring("line 2: a quoted value is never closed"));
    CHECK_THAT(refusal([] { return console::parse_csv("a\nb\"c\n"); }),
               ContainsSubstring("line 2"));
    CHECK_THAT(refusal([] { return console::parse_csv("\"a\"b\n"); }), ContainsSubstring("line 1"));
    // A quoted line break still counts as a line.
    CHECK_THAT(refusal([] { return console::parse_csv("\"a\nb\"\nc\"d\n"); }),
               ContainsSubstring("line 3"));
}

TEST_CASE("a line is written back as CSV", "[console][certificates]") {
    CHECK(console::csv_line({"a", "b c", ""}) == "a,b c,");
    CHECK(console::csv_line({"x, y", "say \"hi\"", "two\nlines"}) ==
          "\"x, y\",\"say \"\"hi\"\"\",\"two\nlines\"");
    const std::vector<std::string> values{"=1+2", "\r", "\"", "plain"};
    CHECK(console::parse_csv(console::csv_line(values)) == Table{values});
}

TEST_CASE("a table's rows are checked against the kind", "[console][certificates]") {
    const auto rows = console::certificate_rows(
        diploma(), "Year, Name ,grades\n2026,Chan Tai Man,\"A, B\"\n,,\n2025,Wong,\n");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].line == 2);
    using Pairs = std::vector<std::pair<std::string, std::string>>;
    CHECK(rows[0].fields == Pairs{{"name", "Chan Tai Man"}, {"grades", "A, B"}});
    CHECK(rows[0].metadata == Pairs{{"year", "2026"}});
    CHECK(rows[1].line == 4);
    CHECK(rows[1].fields == Pairs{{"name", "Wong"}});

    const console::Kind kind = diploma();
    CHECK_THAT(refusal([&] { return console::certificate_rows(kind, "Name,Nick\n"); }),
               ContainsSubstring("line 1: the kind Diploma has no field \"Nick\""));
    CHECK_THAT(refusal([&] { return console::certificate_rows(kind, "Year\n2026\n"); }),
               ContainsSubstring("no column holds the required field name"));
    CHECK_THAT(refusal([&] { return console::certificate_rows(kind, "name,Name\n"); }),
               ContainsSubstring("two columns hold the field name"));
    CHECK_THAT(refusal([&] { return console::certificate_rows(kind, "Name,Year\nA,soon\n"); }),
               ContainsSubstring("line 2: the field Year is a number"));
    CHECK_THAT(refusal([&] { return console::certificate_rows(kind, "Name,Year\n,2026\n"); }),
               ContainsSubstring("line 2: the field Name is required"));
    CHECK_THAT(refusal([&] { return console::certificate_rows(kind, "Name,Year\nA\n"); }),
               ContainsSubstring("line 2: 1 values, but the first line names 2 fields"));
    CHECK_THAT(refusal([&] { return console::certificate_rows(kind, "Name\n"); }),
               ContainsSubstring("no certificates"));
    CHECK_THAT(refusal([&] { return console::certificate_rows(kind, ""); }),
               ContainsSubstring("the table is empty"));
}

TEST_CASE("the verifier's link names the ledger, the record, and the address",
          "[console][certificates]") {
    const auto ledger = *kanhe::protocol::to_id(kanhe::Bytes(32, 0xab));
    const auto record = *kanhe::protocol::to_id(kanhe::Bytes(32, 0x01));
    const std::string link = console::verifier_link("https://v.example/verify/", ledger, record,
                                                    "https://l.example/c/a_b-c?x=1&y");
    CHECK(link.starts_with("https://v.example/verify/#l="));
    CHECK_THAT(link, ContainsSubstring("#l=" + kanhe::to_hex(ledger.bytes())));
    CHECK_THAT(link, ContainsSubstring("&r=" + kanhe::to_hex(record.bytes())));
    CHECK_THAT(link, ContainsSubstring("&b=https://l.example/c/a_b-c%3Fx%3D1%26y"));
    CHECK_THAT(console::verifier_link("https://v/", ledger, record, "https://l/c/t", "zh-Hant"),
               ContainsSubstring("&b=https://l/c/t&lang=zh-Hant"));
    CHECK(console::certificate_language("zh-Hans"));
    CHECK_FALSE(console::certificate_language("fr"));
}

TEST_CASE("a page is filled from a template", "[console][certificates]") {
    console::CertificatePage page;
    page.kind = "Diploma";
    page.issuer = "Example & Co";
    page.issued = "2026-11-10";
    page.record = std::string(64, 'f');
    page.verify_url = "https://v/#l=1&r=2";
    page.fields = {{"Name", "<Chan>"}, {"Year", "2026"}, {"qr", "a field"}};
    page.by_name = {{"name", "<Chan>"}, {"year", "2026"}, {"qr", "a field"}};

    CHECK(console::fill_certificate("{{name}}|{{ year }}|{{issuer}}|{{verify_url}}", page) ==
          "&lt;Chan&gt;|2026|Example &amp; Co|https://v/#l=1&amp;r=2");
    // A field named like one of the words is reached as field.NAME.
    CHECK(console::fill_certificate("{{field.qr}}", page) == "a field");
    CHECK_THAT(console::fill_certificate("{{qr}}", page), ContainsSubstring("<svg"));
    CHECK_THAT(console::fill_certificate("{{fields}}", page),
               ContainsSubstring("<dt>Name</dt><dd>&lt;Chan&gt;</dd>"));
    CHECK_THAT(refusal([&] { return console::fill_certificate("{{grades}}", page); }),
               ContainsSubstring("{{grades}}"));
    CHECK_THAT(refusal([&] { return console::fill_certificate("{{name", page); }),
               ContainsSubstring("never closes"));

    // The default template fills, in each language.
    for (const char* language : {"en", "zh-Hant", "zh-Hans"}) {
        const std::string html =
            console::fill_certificate(console::default_certificate_template(language), page);
        CHECK_THAT(html, ContainsSubstring(std::string("lang=\"") + language + "\""));
        CHECK_THAT(html, ContainsSubstring("&lt;Chan&gt;"));
        CHECK_THAT(html, ContainsSubstring("href=\"https://v/#l=1&amp;r=2\""));
    }
    CHECK_THAT(console::default_certificate_template("zh-Hant"), ContainsSubstring("簽發日期"));
    CHECK_THAT(console::default_certificate_template("zh-Hans"), ContainsSubstring("签发日期"));
}
