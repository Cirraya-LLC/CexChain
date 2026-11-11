// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>

/// Memberships (spec v0.16, section 6): a `cexchain.membership/1` record is a
/// ledger's word that another ledger (the member) belongs to the
/// organization or person it names, as it checked them. Any ledger may
/// register memberships, and so be a trust node; whether a verifier believes
/// one is the verifier's choice (section 11). Its metadata is `membership` in
/// the CDDL, which the ledger checks.
namespace cexchain::protocol {

inline constexpr std::string_view membership_type = "cexchain.membership/1";
/// Membership proofs one evidence bundle carries at most (key 9).
inline constexpr std::size_t max_membership_proofs = 16;

enum class MemberKind : std::uint8_t { organization, person };

[[nodiscard]] std::string_view member_kind_name(MemberKind kind) noexcept;

struct Membership {
    /// The member's ledger.
    Id member;
    MemberKind kind = MemberKind::organization;
    /// The name the trust node checked, or a person's display name.
    std::string name;
    /// Whether the trust node checked who the member is; false is the
    /// member's own word (self-declared).
    bool verified = false;
    /// A company or registry number.
    std::optional<std::string> registration;
    /// ISO 3166-1 alpha-2, optionally with a subdivision: "HK", "CN-44".
    std::optional<std::string> jurisdiction;
    /// After it the membership has lapsed (ms since the epoch).
    std::optional<Timestamp> until;

    friend bool operator==(const Membership&, const Membership&) = default;
};

/// Reads a membership's metadata, checking its shape as the ledger does;
/// other keys are refused.
[[nodiscard]] Result<Membership> decode_membership(const cbor::Value& metadata);
/// The metadata of `membership` (checked: what it encodes decodes).
[[nodiscard]] Result<cbor::Value> encode_membership(const Membership& membership);

/// Where a membership stood at a time (spec section 11, step 9).
enum class Standing : std::uint8_t { not_yet, active, suspended, ended, revoked, lapsed };

[[nodiscard]] std::string_view standing_name(Standing standing) noexcept;

/// One change to a membership after its registration, oldest first: a
/// transition to `to` ("suspended", "active", "ended"), or its revocation
/// (`to` empty).
struct MembershipChange {
    Timestamp at = 0;
    std::string to;

    friend bool operator==(const MembershipChange&, const MembershipChange&) = default;
};

/// The membership's standing at `t`: not yet a member before its
/// registration; else revoked if revoked at or before `t`; else lapsed if
/// `t` is after its `until`; else the state its last transition at or
/// before `t` left it in.
[[nodiscard]] Standing standing_at(const Membership& membership, Timestamp registered_at,
                                   std::span<const MembershipChange> changes, Timestamp t);

} // namespace cexchain::protocol
