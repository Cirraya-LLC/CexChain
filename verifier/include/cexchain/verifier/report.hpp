// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Rendering of verification results, shared by every verifier front end
/// (the command line and the browser), so they all report the same facts in
/// the same words. Portable C++23, like core.
namespace cexchain::verifier {

using Json = nlohmann::ordered_json;

/// "2026-10-06 08:00:00 UTC"
[[nodiscard]] std::string format_time(protocol::Timestamp ms);
/// RFC 3339 with milliseconds: "2026-10-06T08:00:00.000Z"
[[nodiscard]] std::string iso_time(protocol::Timestamp ms);

/// Machine form: "person", "agent", "device", or "organization".
[[nodiscard]] std::string kind_text(const std::optional<protocol::ActorKind>& kind);
/// Human form: "person", "AI agent", "device", or "organization".
[[nodiscard]] std::string kind_label(const std::optional<protocol::ActorKind>& kind);

/// A text value as itself; anything else in CBOR diagnostic notation.
[[nodiscard]] std::string display_value(const cbor::Value& value);

/// A CBOR value as JSON: text, integers, booleans, and null map directly;
/// maps with text keys and arrays recurse; anything else becomes its
/// diagnostic notation.
[[nodiscard]] Json cbor_json(const cbor::Value& value);
[[nodiscard]] Json provenance_json(const protocol::Provenance& provenance);
[[nodiscard]] Json checkpoint_json(const protocol::Checkpoint& checkpoint);

/// The verification report as JSON. `ledger_checked` says whether the
/// verifier compared the ledger id with one learned out of band.
[[nodiscard]] Json report_json(const protocol::EvidenceReport& report, bool ledger_checked);
/// The verification report as text for a terminal.
[[nodiscard]] std::string report_text(const protocol::EvidenceReport& report, bool ledger_checked);

/// True if any attachment content was provided and did not match.
[[nodiscard]] bool has_attachment_mismatch(const protocol::EvidenceReport& report);

} // namespace cexchain::verifier
