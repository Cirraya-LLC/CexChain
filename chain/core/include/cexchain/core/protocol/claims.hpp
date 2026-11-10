// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/statement.hpp>

/// Claims (spec v0.14, section 6): a `cexchain.claim/1` record says that, in
/// another record of the same ledger (its source), a condition on fields
/// holds, or does not, as of a time, without disclosing them. Its metadata
/// is `claim` in the CDDL, which the ledger checks.
namespace cexchain::protocol {

inline constexpr std::string_view claim_type = "cexchain.claim/1";
inline constexpr std::size_t max_claim_terms = 16;
inline constexpr std::size_t max_claim_values = 64;

/// One term of a condition: the source's field, an operator, the type of
/// the value, and the value (as encoded: an int or text for a number,
/// [amount, currency, scale] for money, a date or text as text; for
/// "between" [low, high], for "in" an array, for "exists" null).
struct ClaimTerm {
    std::string field;
    std::string op;
    std::string type;
    cbor::Value value;

    friend bool operator==(const ClaimTerm&, const ClaimTerm&) = default;
};

struct Claim {
    Id source;
    std::vector<ClaimTerm> condition;
    bool holds = true;
    Timestamp as_of = 0;
    std::optional<Timestamp> until;
    std::optional<std::string> subject;
    /// An access request it answers: [ledger, record].
    std::optional<std::pair<Id, Id>> answers;

    friend bool operator==(const Claim&, const Claim&) = default;
};

/// Reads a claim's metadata, checking its shape as the ledger does; other
/// keys are refused.
[[nodiscard]] Result<Claim> decode_claim(const cbor::Value& metadata);
/// The metadata of `claim` (checked: what it encodes decodes).
[[nodiscard]] Result<cbor::Value> encode_claim(const Claim& claim);

/// The condition in words (spec section 11, "A claim in words"): each term
/// its field, the operator's words, and the value, joined by " and ".
[[nodiscard]] std::string claim_text(const Claim& claim);

/// The source a claim's registration among `events` (a record's history)
/// names, if the record is a claim: the record whose history its evidence
/// carries too (spec section 11).
[[nodiscard]] std::optional<Id> claim_source(std::span<const Statement> events);

} // namespace cexchain::protocol
