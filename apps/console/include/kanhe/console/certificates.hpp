// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/console/kinds.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/state.hpp>

/// Certificates: records of a kind that prints fields (a kind sheet's
/// "printed"), each published at a private address (node/published.hpp)
/// whose QR code goes on the paper. Whoever scans it sees the record as it is
/// then, revoked or replaced included, with the printed fields disclosed and
/// the others sealed. Issued in bulk from a table, one row per certificate;
/// printed from an HTML template the browser prints or saves as PDF.
namespace kanhe::console {

/// At most this many rows a table issues at once, and this many bytes.
inline constexpr std::size_t max_certificate_rows = 100'000;
inline constexpr std::size_t max_table_bytes = 64UZ << 20U;

/// A table in CSV (RFC 4180: commas, double quotes around a value that holds
/// a comma, a quote, or a line break, "" for a quote; lines end in LF or
/// CRLF; a UTF-8 byte order mark before it is skipped). Throws
/// std::invalid_argument naming the line.
[[nodiscard]] std::vector<std::vector<std::string>> parse_csv(std::string_view text);
/// One CSV line, quoting what must be (no line break at the end).
[[nodiscard]] std::string csv_line(const std::vector<std::string>& values);

/// A certificate to issue: its line in the table, its private fields (for
/// the record's commitment), and its public ones (for the metadata), each
/// in the kind's order.
struct CertificateRow {
    std::size_t line = 0;
    std::vector<std::pair<std::string, std::string>> fields;
    std::vector<std::pair<std::string, std::string>> metadata;
};

/// Reads a table of certificates of `kind`: a header naming the kind's
/// fields (by name or label; every required one, in any order), then a row
/// per certificate, each value checked as the console's form checks it.
/// Throws std::invalid_argument saying which line is wrong and why.
[[nodiscard]] std::vector<CertificateRow> certificate_rows(const Kind& kind, std::string_view csv);

/// What a certificate's row holds, so that a table changed since it was
/// issued is not taken for the one issued: 32 hex digits.
[[nodiscard]] std::string row_fingerprint(const crypto::Provider& provider,
                                          const CertificateRow& row);

/// The list of a table's certificates issued so far (`certificate issue
/// --out`, and the console's own for each table): CSV, a line when a row's
/// record is registered and another when it is published, so that a run
/// that stops carries on without issuing anything twice.
///   line,fingerprint,record,token,address
struct IssuedRow {
    std::string fingerprint;
    /// Hex.
    std::string record;
    /// Empty until published.
    std::string token;
    std::string address;
};
/// The rows issued so far, by line, as far as each got (none if the file is
/// missing). Throws std::runtime_error if it is not such a list.
[[nodiscard]] std::map<std::size_t, IssuedRow> read_issued(const std::filesystem::path& path);
/// Adds a line, durably (private to its owner), before the next row.
void append_issued(const std::filesystem::path& path, std::size_t line, const IssuedRow& row);

/// The disclosures of the printed private fields of a record of `kind`
/// whose private data is `fields` (the public ones are in its metadata).
[[nodiscard]] std::vector<protocol::FieldDisclosure>
printed_disclosures(const crypto::Provider& provider, crypto::HashAlg hash, const Kind& kind,
                    const std::vector<protocol::RecordField>& fields);

/// The printed fields that are public (in the record's metadata), in the
/// kind's order: what a certificate's credential claims beside the fields
/// its address discloses.
[[nodiscard]] std::vector<std::string> printed_public_fields(const Kind& kind);

/// A certificate as it is: published, of a kind that prints fields.
struct Certificate {
    std::string token;
    protocol::Id record;
    std::string type;
    /// The kind's name.
    std::string kind;
    /// "valid", "revoked", or "replaced".
    std::string status;
    protocol::Timestamp issued_at = 0;
    protocol::Timestamp published_at = 0;
    struct Field {
        std::string name;
        std::string label;
        std::string value;
    };
    /// The printed fields, in the kind's order.
    std::vector<Field> fields;
};

/// A certificate from what the ledger holds: the record's state, its
/// metadata (for the printed public fields), when it was registered, and
/// what its publication discloses (name and value, for the private ones).
[[nodiscard]] Certificate
certificate_of(const Kind& kind, const protocol::RecordState& record,
               const std::optional<cbor::Value>& metadata, protocol::Timestamp issued_at,
               std::string token, protocol::Timestamp published_at,
               const std::vector<std::pair<std::string, std::string>>& disclosed);
[[nodiscard]] nlohmann::json certificate_json(const Certificate& certificate,
                                              std::string_view address);

/// The languages a certificate's page and default template come in.
[[nodiscard]] bool certificate_language(std::string_view language) noexcept;

/// The verifier's link a certificate's QR code holds:
/// VERIFIER#l=LEDGER&r=RECORD&b=ADDRESS[&lang=LANGUAGE] (the page fetches the
/// address and checks what it gets is the record of that ledger).
[[nodiscard]] std::string verifier_link(std::string_view verifier, const protocol::Id& ledger,
                                        const protocol::Id& record, std::string_view address,
                                        std::string_view language = "en");

/// A QR code of `text` as an SVG element (medium error correction, the
/// quiet zone included), to put in a page.
[[nodiscard]] std::string qr_svg(std::string_view text);

/// The verifier page's language for one of the console's (zh-Hant-HK is
/// zh-Hant); English for any other.
[[nodiscard]] std::string certificate_language_of(std::string_view console_language);

/// What a certificate's page is filled with.
struct CertificatePage {
    std::string kind;
    std::string issuer;
    /// YYYY-MM-DD.
    std::string issued;
    std::string record;
    std::string verify_url;
    /// The printed fields, label and value, in the kind's order.
    std::vector<std::pair<std::string, std::string>> fields;
    /// The same by field name, for {{NAME}}.
    std::map<std::string, std::string> by_name;
};

/// A certificate's page: what it shows, issued by `issuer`, opened by
/// `verify_url`.
[[nodiscard]] CertificatePage page_of(const Certificate& certificate, std::string issuer,
                                      std::string verify_url);

/// The template a certificate prints with unless another is given: one A4
/// page, its words in `language`.
[[nodiscard]] std::string default_certificate_template(std::string_view language);

/// Fills a template: {{kind}}, {{issuer}}, {{issued}}, {{record}},
/// {{verify_url}}, {{qr}} (the QR code, an SVG), {{fields}} (the printed
/// fields as a list), and {{NAME}} or {{field.NAME}} for one printed field
/// (field.NAME when NAME is one of the words before). Values are escaped as
/// HTML text. Throws std::invalid_argument for a placeholder it does not
/// know, so that a mistyped name shows before anything is printed.
[[nodiscard]] std::string fill_certificate(std::string_view html, const CertificatePage& page);

} // namespace kanhe::console
