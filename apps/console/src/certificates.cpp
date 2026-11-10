// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <format>
#include <qrcodegen.hpp>
#include <set>
#include <stdexcept>
#include <string>

#include <cexchain/console/certificates.hpp>
#include <cexchain/core/bytes.hpp>

namespace cexchain::console {

namespace {

// QR codes need a light margin of four modules (ISO/IEC 18004).
constexpr int quiet_zone = 4;

[[noreturn]] void bad(std::size_t line, const std::string& why) {
    throw std::invalid_argument(std::format("line {}: {}", line, why));
}

struct Line {
    std::size_t number = 0;
    std::vector<std::string> values;
};

/// The table's rows, each with the line it starts on.
std::vector<Line> read_table(std::string_view text) {
    if (text.size() > max_table_bytes) {
        throw std::invalid_argument("a table is at most 64 MiB");
    }
    if (text.starts_with("\xEF\xBB\xBF")) {
        text.remove_prefix(3);
    }
    std::vector<Line> rows;
    Line row{1, {}};
    std::string value;
    std::size_t line = 1;
    bool quoted = false;     // inside quotes
    bool was_quoted = false; // the value began with a quote
    auto end_value = [&] {
        row.values.push_back(std::move(value));
        value.clear();
        was_quoted = false;
    };
    auto end_row = [&] {
        end_value();
        rows.push_back(std::move(row));
        if (rows.size() > max_certificate_rows + 1) {
            bad(line, "a table holds at most 100,000 rows");
        }
        row = Line{line + 1, {}};
    };
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (quoted) {
            if (c == '"' && i + 1 < text.size() && text[i + 1] == '"') {
                value.push_back('"');
                ++i;
            } else if (c == '"') {
                quoted = false;
            } else {
                if (c == '\n') {
                    ++line;
                }
                value.push_back(c);
            }
            continue;
        }
        if (c == '"') {
            if (!value.empty() || was_quoted) {
                bad(line, "a quote inside a value must be doubled, in a quoted value");
            }
            quoted = was_quoted = true;
        } else if (c == ',') {
            end_value();
        } else if (c == '\r' && i + 1 < text.size() && text[i + 1] == '\n') {
            continue; // CRLF: the LF ends the row
        } else if (c == '\n') {
            end_row();
            ++line;
        } else if (was_quoted) {
            bad(line, "nothing may follow a quoted value but a comma or the line's end");
        } else {
            value.push_back(c);
        }
    }
    if (quoted) {
        bad(row.number, "a quoted value is never closed");
    }
    if (!value.empty() || was_quoted || !row.values.empty()) {
        end_row();
    }
    return rows;
}

std::string trimmed(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return std::string(text);
}

std::string percent_encode(std::string_view text) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        const bool plain = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                           (byte >= '0' && byte <= '9') || c == '-' || c == '_' || c == '.' ||
                           c == '~' || c == '/' || c == ':';
        if (plain) {
            out.push_back(c);
        } else {
            out.push_back('%');
            out.push_back(digits[byte >> 4U]);
            out.push_back(digits[byte & 0x0FU]);
        }
    }
    return out;
}

std::string escape_html(std::string_view text) {
    std::string out;
    for (const char c : text) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        default:
            out.push_back(c);
        }
    }
    return out;
}

/// The default template's words: issued, record, and what scanning does.
struct Words {
    std::string_view issued;
    std::string_view record;
    std::string_view scan;
};

Words words_in(std::string_view language) {
    if (language == "zh-Hant") {
        return {"簽發日期", "記錄編號",
                "掃描二維碼，查核此證書：由誰簽發、何時簽發、現在是否仍然有效。"};
    }
    if (language == "zh-Hans") {
        return {"签发日期", "记录编号",
                "扫描二维码，核验此证书：由谁签发、何时签发、现在是否仍然有效。"};
    }
    return {"Issued", "Record",
            "Scan the code to check this certificate: who issued it, when, and whether it "
            "still stands."};
}

constexpr std::string_view page_template = R"(<!doctype html>
<html lang="@LANG@">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{kind}}</title>
<style>
@page { size: A4; margin: 0 }
html { background: #efede8 }
body { margin: 0; color: #1f1e1b; font-family: "Iowan Old Style", "Palatino Linotype", Palatino,
  "Songti TC", "Songti SC", "Noto Serif CJK TC", "Noto Serif CJK SC", serif }
.sheet { box-sizing: border-box; width: 210mm; height: 297mm; margin: 10mm auto; background: #fff;
  padding: 30mm 26mm 24mm; display: flex; flex-direction: column;
  outline: 0.25mm solid #b8b1a3; outline-offset: -11mm }
.issuer { text-align: center; font-size: 10.5pt; letter-spacing: 0.2em; text-transform: uppercase;
  color: #6d675c }
h1 { text-align: center; font-weight: 400; font-size: 30pt; line-height: 1.2; margin: 14mm 0 16mm }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 5mm 10mm; margin: 0 auto;
  width: 100%; max-width: 132mm; font-size: 13pt; line-height: 1.4 }
dt { color: #6d675c }
dd { margin: 0; white-space: pre-line }
.foot { margin-top: auto; display: flex; align-items: flex-end; justify-content: space-between;
  gap: 12mm; font-size: 9.5pt; line-height: 1.55; color: #6d675c }
.id { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 7.5pt; word-break: break-all }
.qr svg { display: block; width: 34mm; height: 34mm }
@media print { html { background: none } .sheet { margin: 0 } }
</style>
</head>
<body>
<main class="sheet">
<div class="issuer">{{issuer}}</div>
<h1>{{kind}}</h1>
{{fields}}
<div class="foot">
<div>@ISSUED@: {{issued}}<br>@RECORD@: <span class="id">{{record}}</span><br><br>@SCAN@</div>
<a class="qr" href="{{verify_url}}">{{qr}}</a>
</div>
</main>
</body>
</html>
)";

void replace_all(std::string& text, std::string_view from, std::string_view to) {
    for (std::size_t at = text.find(from); at != std::string::npos;
         at = text.find(from, at + to.size())) {
        text.replace(at, from.size(), to);
    }
}

} // namespace

std::vector<std::vector<std::string>> parse_csv(std::string_view text) {
    std::vector<std::vector<std::string>> out;
    for (Line& row : read_table(text)) {
        out.push_back(std::move(row.values));
    }
    return out;
}

std::string csv_line(const std::vector<std::string>& values) {
    std::string out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        const std::string& v = values[i];
        out += i == 0 ? "" : ",";
        if (v.find_first_of(",\"\r\n") == std::string::npos) {
            out += v;
            continue;
        }
        out.push_back('"');
        for (const char c : v) {
            out += c == '"' ? std::string_view("\"\"") : std::string_view(&c, 1);
        }
        out.push_back('"');
    }
    return out;
}

std::vector<CertificateRow> certificate_rows(const Kind& kind, std::string_view csv) {
    const std::vector<Line> table = read_table(csv);
    if (table.empty()) {
        throw std::invalid_argument("the table is empty: its first line names the fields");
    }
    // Which of the kind's fields each column holds.
    std::vector<const KindField*> columns;
    std::set<std::string> seen;
    for (const std::string& heading : table.front().values) {
        const std::string name = trimmed(heading);
        auto field = std::ranges::find(kind.fields, name, &KindField::name);
        if (field == kind.fields.end()) {
            field = std::ranges::find(kind.fields, name, &KindField::label);
        }
        if (name.empty() || field == kind.fields.end()) {
            bad(1, "the kind " + kind.name + " has no field \"" + name + "\"");
        }
        if (!seen.insert(field->name).second) {
            bad(1, "two columns hold the field " + field->name);
        }
        columns.push_back(&*field);
    }
    for (const KindField& f : kind.fields) {
        if (f.required && !seen.contains(f.name)) {
            bad(1, "no column holds the required field " + f.name);
        }
    }
    std::vector<CertificateRow> rows;
    for (std::size_t r = 1; r < table.size(); ++r) {
        const Line& line = table[r];
        if (std::ranges::all_of(line.values, [](const std::string& v) { return v.empty(); })) {
            continue; // a blank line
        }
        if (line.values.size() != columns.size()) {
            bad(line.number, std::format("{} values, but the first line names {} fields",
                                         line.values.size(), columns.size()));
        }
        CertificateRow row;
        row.line = line.number;
        for (const KindField& f : kind.fields) {
            const auto column = std::ranges::find(columns, &f);
            const std::string value =
                column == columns.end()
                    ? std::string()
                    : trimmed(line.values[static_cast<std::size_t>(column - columns.begin())]);
            const std::string& label = f.label.empty() ? f.name : f.label;
            if (value.empty()) {
                if (f.required) {
                    bad(line.number, "the field " + label + " is required");
                }
                continue;
            }
            if (const auto problem = check_value(f, value)) {
                bad(line.number, "the field " + label + " is " + *problem);
            }
            (f.is_private ? row.fields : row.metadata).emplace_back(f.name, value);
        }
        if (row.fields.empty()) {
            bad(line.number, "a record commits to at least one private field: fill one in");
        }
        rows.push_back(std::move(row));
    }
    if (rows.empty()) {
        throw std::invalid_argument("the table has its first line only: no certificates");
    }
    return rows;
}

bool certificate_language(std::string_view language) noexcept {
    return language == "en" || language == "zh-Hant" || language == "zh-Hans";
}

std::string verifier_link(std::string_view verifier, const protocol::Id& ledger,
                          const protocol::Id& record, std::string_view address,
                          std::string_view language) {
    std::string link = std::string(verifier) + "#l=" + to_hex(ledger.bytes()) +
                       "&r=" + to_hex(record.bytes()) + "&b=" + percent_encode(address);
    if (language != "en") {
        link += "&lang=" + std::string(language);
    }
    return link;
}

std::string qr_svg(std::string_view text) {
    const auto qr =
        qrcodegen::QrCode::encodeText(std::string(text).c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    const int size = qr.getSize() + 2 * quiet_zone;
    std::string path;
    for (int y = 0; y < qr.getSize(); ++y) {
        for (int x = 0; x < qr.getSize(); ++x) {
            if (qr.getModule(x, y)) {
                path += std::format("M{},{}h1v1h-1z", x + quiet_zone, y + quiet_zone);
            }
        }
    }
    return std::format(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 {0} {0}\" "
        "stroke=\"none\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" "
        "fill=\"#FFFFFF\"/><path d=\"{1}\" fill=\"#000000\"/></svg>\n",
        size, path);
}

std::string default_certificate_template(std::string_view language) {
    const Words words = words_in(language);
    std::string page(page_template);
    replace_all(page, "@LANG@", certificate_language(language) ? language : "en");
    replace_all(page, "@ISSUED@", words.issued);
    replace_all(page, "@RECORD@", words.record);
    replace_all(page, "@SCAN@", words.scan);
    return page;
}

std::string fill_certificate(std::string_view html, const CertificatePage& page) {
    static const std::set<std::string, std::less<>> words{
        "kind", "issuer", "issued", "record", "verify_url", "qr", "fields"};
    auto value_of = [&](const std::string& name) -> std::string {
        if (name == "kind") {
            return escape_html(page.kind);
        }
        if (name == "issuer") {
            return escape_html(page.issuer);
        }
        if (name == "issued") {
            return escape_html(page.issued);
        }
        if (name == "record") {
            return escape_html(page.record);
        }
        if (name == "verify_url") {
            return escape_html(page.verify_url);
        }
        if (name == "qr") {
            return qr_svg(page.verify_url);
        }
        if (name == "fields") {
            std::string list = "<dl>\n";
            for (const auto& [label, value] : page.fields) {
                list += "<dt>" + escape_html(label) + "</dt><dd>" + escape_html(value) + "</dd>\n";
            }
            return list + "</dl>";
        }
        const std::string field =
            name.starts_with("field.") ? name.substr(6) : (words.contains(name) ? "" : name);
        if (const auto it = page.by_name.find(field); !field.empty() && it != page.by_name.end()) {
            return escape_html(it->second);
        }
        throw std::invalid_argument("the template names {{" + name +
                                    "}}, which a certificate of this kind does not have");
    };
    std::string out;
    std::size_t at = 0;
    while (true) {
        const std::size_t open = html.find("{{", at);
        if (open == std::string_view::npos) {
            out.append(html.substr(at));
            return out;
        }
        const std::size_t close = html.find("}}", open + 2);
        if (close == std::string_view::npos) {
            throw std::invalid_argument("the template opens {{ and never closes it");
        }
        out.append(html.substr(at, open - at));
        out += value_of(trimmed(html.substr(open + 2, close - open - 2)));
        at = close + 2;
    }
}

} // namespace cexchain::console
