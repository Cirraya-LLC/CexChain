// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A table of certificates comes from a spreadsheet someone exports, and a
// certificate's template from a file someone writes: reading either must
// refuse what it does not take, saying why, and never crash. A table read
// writes back to one that reads the same.

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

#include <cexchain/console/certificates.hpp>

namespace console = cexchain::console;

namespace {

console::Kind kind() {
    console::Kind k;
    k.type = "example.org.certificate/1";
    k.name = "Certificate";
    k.fields = {{"name", "Name", console::FieldType::text, true, true},
                {"date", "Date", console::FieldType::date, true, false},
                {"count", "", console::FieldType::number, false, false}};
    k.printed = {"name", "date"};
    return k;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    try {
        const auto table = console::parse_csv(text);
        // A leading byte order mark is skipped, so one in front keeps a
        // first value that begins with one.
        std::string again = "\xEF\xBB\xBF";
        for (const auto& row : table) {
            again += console::csv_line(row) + "\n";
        }
        if (console::parse_csv(again) != table) {
            __builtin_trap();
        }
    } catch (const std::invalid_argument&) {
        // Refused, naming the line.
    }
    static const console::Kind certificate = kind();
    try {
        for (const auto& row : console::certificate_rows(certificate, text)) {
            if (row.fields.empty() || row.line == 0) {
                __builtin_trap();
            }
        }
    } catch (const std::invalid_argument&) {
    }
    console::CertificatePage page;
    page.kind = "Certificate";
    page.verify_url = "https://verify.example/#l=1";
    page.fields = {{"Name", "A <name>"}};
    page.by_name = {{"name", "A <name>"}};
    try {
        const std::string html = console::fill_certificate(text, page);
        if (text.find("<name>") == std::string_view::npos &&
            html.find("<name>") != std::string::npos) {
            __builtin_trap(); // a value unescaped
        }
    } catch (const std::invalid_argument&) {
    }
    return 0;
}
