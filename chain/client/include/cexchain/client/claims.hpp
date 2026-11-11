// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/core/protocol/claims.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/core/protocol/state.hpp>

/// Claims as an issuer makes them (spec v0.14): conditions as people type
/// them, checked against a record's private data. The command line's
/// `claim` commands and the console share these.
namespace cexchain::client {

/// One condition as typed: FIELD OP VALUE ("monthly_salary > HKD 30000.00",
/// "age >= 18", "born < 2008-11-10", "name = \"Chan Tai Man\""), FIELD between
/// LOW and HIGH, FIELD in A,B, or FIELD exists. Money is a currency code and
/// an amount, dates YYYY-MM-DD; text may be quoted. Throws UsageError.
[[nodiscard]] protocol::ClaimTerm parse_claim_term(std::string_view text);
/// The same, given apart (a form's field, which may hold spaces, its
/// operator, and its value as typed).
[[nodiscard]] protocol::ClaimTerm parse_claim_term(std::string_view field, std::string_view op,
                                                   std::string_view value);

/// A claim's condition checked against its source's private data.
struct ClaimCheck {
    bool holds = false;
    /// The claim's own private fields: "basis.FIELD" with each value it read
    /// (or "basis" alone when it read none), so that the issuer can show
    /// later what it relied on.
    std::vector<std::pair<std::string, std::string>> basis;
};
[[nodiscard]] ClaimCheck check_claim(const protocol::Claim& claim,
                                     const std::vector<protocol::RecordField>& fields);

/// A claim's standing for lists, by the ledger's state at `now`:
/// "withdrawn", "source revoked", "source replaced", "lapsed", "standing",
/// or "unknown" (its source is not on the ledger).
[[nodiscard]] std::string claim_status(const protocol::LedgerState& state,
                                       const protocol::RecordState& claim_record,
                                       const protocol::Claim& claim, protocol::Timestamp now);

} // namespace cexchain::client
