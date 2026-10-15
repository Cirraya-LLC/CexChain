// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/asset_evidence.hpp>
#include <cexchain/core/protocol/assets.hpp>
#include <cexchain/core/protocol/contract_evidence.hpp>
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

/// Digits after the decimal point in an ISO 4217 currency's amounts (2 for
/// most; 0 for JPY, KRW, ...; 3 for BHD, KWD, ...).
[[nodiscard]] int currency_exponent(std::string_view currency);
/// An asset's units for people: "125000.00 CNY", "60 t".
[[nodiscard]] std::string format_units(protocol::AssetKind kind, std::uint64_t units,
                                       std::string_view unit);

/// An asset's verification report (D-052): its state, and its chain of
/// title with each party's consent. Parties are named as their own ledgers
/// declare themselves, where a consent of theirs shows it.
[[nodiscard]] Json asset_report_json(const protocol::AssetReport& report, bool ledger_checked);
[[nodiscard]] std::string asset_report_text(const protocol::AssetReport& report,
                                            bool ledger_checked);

/// A contract instance's verification report (D-053): the instance as of
/// the checkpoint (its contract, status, parties, state, and whether it is
/// final), and every call: who called under whose authority, the arguments,
/// what the contract made of it, and each consent the call cites, verified
/// on the consenting party's own ledger, with who gave it (a person present,
/// a key alone, an AI agent and its model). Since v0.8 also the requests each
/// call made, each answer with its request, status, and lateness, and the
/// instance's requests, with the open ones and those overdue at the
/// checkpoint's time. Parties are named as their own ledgers declare
/// themselves, where a consent of theirs shows it.
[[nodiscard]] Json contract_report_json(const protocol::ContractReport& report,
                                        bool ledger_checked);
[[nodiscard]] std::string contract_report_text(const protocol::ContractReport& report,
                                               bool ledger_checked);

} // namespace cexchain::verifier
