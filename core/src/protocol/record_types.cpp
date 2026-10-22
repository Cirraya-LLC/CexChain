// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>

#include <cexchain/core/protocol/record_types.hpp>

namespace cexchain::protocol {

namespace {

// Access across organizations: a request on the asker's ledger, a
// grant on the granter's (ended by revoking it), a receipt on the asker's.
constexpr std::array access_request_transitions{
    Transition{"requested", "withdrawn"},
};
constexpr std::array<Transition, 0> no_transitions{};
constexpr std::array<std::string_view, 0> no_roles{};

// A party's consent to a contract call (spec v0.6), on its own ledger.
constexpr std::array consent_transitions{
    Transition{"given", "withdrawn"},
};

constexpr std::array types{
    RecordType{"cexchain.access-request/1", "requested", access_request_transitions, no_roles},
    RecordType{"cexchain.access-grant/1", "granted", no_transitions, no_roles},
    RecordType{"cexchain.access-receipt/1", "received", no_transitions, no_roles},
    RecordType{"cexchain.contract-consent/1", "given", consent_transitions, no_roles},
};

} // namespace

bool RecordType::allows(std::string_view from, std::string_view to) const noexcept {
    return std::ranges::any_of(transitions,
                               [&](const Transition& t) { return t.from == from && t.to == to; });
}

bool RecordType::has_role(std::string_view role) const noexcept {
    return std::ranges::contains(roles, role);
}

const RecordType* find_record_type(std::string_view name) noexcept {
    const auto it = std::ranges::find(types, name, &RecordType::name);
    return it == types.end() ? nullptr : &*it;
}

std::span<const RecordType> builtin_record_types() noexcept {
    return types;
}

bool is_reserved_record_type(std::string_view name) noexcept {
    return name.starts_with(reserved_type_prefix) && find_record_type(name) == nullptr;
}

} // namespace cexchain::protocol
