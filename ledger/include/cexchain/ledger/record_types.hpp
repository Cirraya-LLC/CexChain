// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <span>
#include <string_view>
#include <utility>

/// Built-in record types (D-027). A record type defines a record's lifecycle:
/// its initial state, the transitions allowed between states, and the roles in
/// which actors may endorse it.
///
/// Records of other types are accepted with a generic lifecycle: initial state
/// "registered", no transitions, and any endorsement role.
namespace cexchain::ledger {

struct Transition {
    std::string_view from;
    std::string_view to;
};

struct RecordType {
    std::string_view name;
    std::string_view initial_state;
    std::span<const Transition> transitions;
    std::span<const std::string_view> roles;

    [[nodiscard]] bool allows(std::string_view from, std::string_view to) const noexcept;
    [[nodiscard]] bool has_role(std::string_view role) const noexcept;
};

/// The built-in definition for `name`, or nullptr for a custom type.
[[nodiscard]] const RecordType* find_record_type(std::string_view name) noexcept;

/// All built-in definitions.
[[nodiscard]] std::span<const RecordType> builtin_record_types() noexcept;

inline constexpr std::string_view generic_initial_state = "registered";

} // namespace cexchain::ledger
