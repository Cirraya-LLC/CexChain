// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <span>
#include <string_view>
#include <utility>

/// Record types (spec section 6). A record's type is any text its registrant
/// chooses, with the one generic lifecycle: initial state "registered", no
/// transitions, endorsements in any role (once per actor and role), and
/// revocable. The protocol's own mechanisms (access, consents to contract
/// calls) have four types of their own, each with its lifecycle; no other
/// type may begin with the reserved prefix "cexchain." (spec v0.9).
namespace cexchain::protocol {

struct Transition {
    std::string_view from;
    std::string_view to;
};

/// A mechanism type's lifecycle: its initial state, the transitions allowed
/// between states, and the roles in which actors may endorse it (none).
struct RecordType {
    std::string_view name;
    std::string_view initial_state;
    std::span<const Transition> transitions;
    std::span<const std::string_view> roles;

    [[nodiscard]] bool allows(std::string_view from, std::string_view to) const noexcept;
    [[nodiscard]] bool has_role(std::string_view role) const noexcept;
};

/// The mechanism type `name`, or nullptr for a type of the generic lifecycle.
[[nodiscard]] const RecordType* find_record_type(std::string_view name) noexcept;

/// The four mechanism types.
[[nodiscard]] std::span<const RecordType> builtin_record_types() noexcept;

inline constexpr std::string_view generic_initial_state = "registered";

/// Record types that begin with these nine bytes (exactly, case-sensitive)
/// belong to the protocol.
inline constexpr std::string_view reserved_type_prefix = "cexchain.";

/// Whether a registration of `name` is refused: it begins with the reserved
/// prefix and is not a mechanism type. Registrations only: a scope may name
/// any type.
[[nodiscard]] bool is_reserved_record_type(std::string_view name) noexcept;

} // namespace cexchain::protocol
