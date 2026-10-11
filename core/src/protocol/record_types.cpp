// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>

#include <cexchain/core/protocol/record_types.hpp>

namespace cexchain::protocol {

namespace {

// Quality certificate / certificate of conformity (质检报告 / 合格证).
constexpr std::array certificate_transitions{
    Transition{"issued", "suspended"},
    Transition{"suspended", "issued"},
};
constexpr std::array<std::string_view, 2> certificate_roles{"inspector", "approver"};

// Delivery note with proof of delivery (送货单 / 签收单).
constexpr std::array delivery_transitions{
    Transition{"dispatched", "delivered"},
    Transition{"dispatched", "rejected"},
    Transition{"delivered", "disputed"},
    Transition{"disputed", "delivered"},
};
constexpr std::array<std::string_view, 2> delivery_roles{"carrier", "receiver"};

// Agreement between parties (协议).
constexpr std::array agreement_transitions{
    Transition{"proposed", "effective"},
    Transition{"proposed", "withdrawn"},
    Transition{"effective", "terminated"},
};
constexpr std::array<std::string_view, 2> agreement_roles{"party", "witness"};

// Access across organizations (D-046): a request on the asker's ledger, a
// grant on the granter's (ended by revoking it), a receipt on the asker's.
constexpr std::array access_request_transitions{
    Transition{"requested", "withdrawn"},
};
constexpr std::array<Transition, 0> no_transitions{};
constexpr std::array<std::string_view, 0> no_roles{};

// Ownership assets (D-052): receivables (应收账款) and warehouse receipts
// (仓单). They change only through asset actions (see assets.hpp), never
// through record transitions. A party's consent to an asset action is a
// record on its own ledger.
constexpr std::array<std::string_view, 2> warehouse_receipt_roles{"inspector", "insurer"};
constexpr std::array asset_consent_transitions{
    Transition{"given", "withdrawn"},
};

constexpr std::array types{
    RecordType{"cexchain.certificate/1", "issued", certificate_transitions, certificate_roles},
    RecordType{"cexchain.delivery/1", "dispatched", delivery_transitions, delivery_roles},
    RecordType{"cexchain.agreement/1", "proposed", agreement_transitions, agreement_roles},
    RecordType{"cexchain.access-request/1", "requested", access_request_transitions, no_roles},
    RecordType{"cexchain.access-grant/1", "granted", no_transitions, no_roles},
    RecordType{"cexchain.access-receipt/1", "received", no_transitions, no_roles},
    RecordType{"cexchain.asset-consent/1", "given", asset_consent_transitions, no_roles},
    // A party's consent to a contract call (spec v0.6), on its own ledger.
    RecordType{"cexchain.contract-consent/1", "given", asset_consent_transitions, no_roles},
    RecordType{"cexchain.receivable/1", "active", no_transitions, no_roles},
    RecordType{"cexchain.warehouse-receipt/1", "active", no_transitions, warehouse_receipt_roles},
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

} // namespace cexchain::protocol
