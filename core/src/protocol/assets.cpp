// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <initializer_list>
#include <utility>

#include <cexchain/core/protocol/assets.hpp>

namespace cexchain::protocol {

namespace {

namespace status = asset_status;

cbor::MapEntry text_entry(std::string_view key, cbor::Value value) {
    return {cbor::Value::text(std::string(key)), std::move(value)};
}

/// Reads a map with text keys: asset metadata (other keys allowed) or a
/// consent's (no other keys).
class TextMap {
public:
    static Result<TextMap> open(const cbor::Value& value) {
        const cbor::Map* map = value.as_map();
        if (map == nullptr) {
            return fail(Errc::malformed, "asset metadata must be a map");
        }
        for (const cbor::MapEntry& e : *map) {
            if (e.key.as_text() == nullptr) {
                return fail(Errc::malformed, "asset metadata keys must be text");
            }
        }
        return TextMap(*map);
    }

    [[nodiscard]] Status only(std::initializer_list<std::string_view> known) const {
        for (const cbor::MapEntry& e : *map_) {
            if (std::ranges::find(known, std::string_view(*e.key.as_text())) == known.end()) {
                return fail(Errc::malformed, "a consent's metadata has an unknown key");
            }
        }
        return {};
    }

    [[nodiscard]] const cbor::Value* get(std::string_view key) const {
        for (const cbor::MapEntry& e : *map_) {
            if (*e.key.as_text() == key) {
                return &e.value;
            }
        }
        return nullptr;
    }

    [[nodiscard]] Result<Id> id(std::string_view key) const {
        const cbor::Value* v = get(key);
        if (v == nullptr || v->as_bytes() == nullptr) {
            return fail(Errc::malformed, "asset metadata lacks a ledger or asset id");
        }
        return to_id(*v->as_bytes());
    }

    [[nodiscard]] Result<std::optional<Id>> opt_id(std::string_view key) const {
        if (get(key) == nullptr) {
            return std::optional<Id>{};
        }
        auto value = id(key);
        if (!value) {
            return std::unexpected(value.error());
        }
        return std::optional(*value);
    }

    [[nodiscard]] Result<std::uint64_t> uint(std::string_view key) const {
        const cbor::Value* v = get(key);
        const auto value = v == nullptr ? std::nullopt : v->as_uint64();
        if (!value) {
            return fail(Errc::malformed, "asset metadata lacks a number");
        }
        return *value;
    }

    [[nodiscard]] Result<std::optional<std::uint64_t>> opt_uint(std::string_view key) const {
        if (get(key) == nullptr) {
            return std::optional<std::uint64_t>{};
        }
        auto value = uint(key);
        if (!value) {
            return std::unexpected(value.error());
        }
        return std::optional(*value);
    }

    [[nodiscard]] Result<std::string> text(std::string_view key) const {
        const cbor::Value* v = get(key);
        if (v == nullptr || v->as_text() == nullptr) {
            return fail(Errc::malformed, "asset metadata lacks a text");
        }
        return *v->as_text();
    }

private:
    explicit TextMap(const cbor::Map& map) : map_(&map) {}
    const cbor::Map* map_;
};

bool is_currency(const std::string& code) {
    return code.size() == 3 &&
           std::ranges::all_of(code, [](char c) { return c >= 'A' && c <= 'Z'; });
}

constexpr std::size_t max_unit = 16;

/// Where an action may start, for which kinds, and what it takes.
struct Rule {
    AssetAction action;
    bool receivable;
    bool warehouse_receipt;
    /// Unused places are empty.
    std::array<std::string_view, 4> from;
    bool takes_counterparty;
    bool takes_quantity;

    [[nodiscard]] bool starts_from(std::string_view s) const noexcept {
        return !s.empty() && std::ranges::find(from, s) != from.end();
    }
};

const Rule& rule_for(AssetAction action) {
    static constexpr std::array<Rule, 11> rules{{
        {AssetAction::transfer, true, true, {status::active}, true, false},
        {AssetAction::pledge, true, true, {status::active}, true, false},
        {AssetAction::release, true, true, {status::pledged}, false, false},
        {AssetAction::enforce, true, true, {status::pledged}, false, false},
        {AssetAction::redeem, false, true, {status::active, status::pledged}, false, true},
        {AssetAction::pay,
         true,
         false,
         {status::active, status::pledged, status::disputed},
         false,
         false},
        {AssetAction::confirm, true, false, {status::paid, status::disputed}, false, false},
        {AssetAction::dispute, true, false, {status::paid}, false, false},
        {AssetAction::freeze,
         true,
         true,
         {status::active, status::pledged, status::paid, status::disputed},
         false,
         false},
        {AssetAction::unfreeze, true, true, {status::frozen}, false, false},
        {AssetAction::cancel, true, true, {status::active}, false, false},
    }};
    return *std::ranges::find(rules, action, &Rule::action);
}

} // namespace

std::optional<AssetKind> asset_kind_of(std::string_view record_type) noexcept {
    if (record_type == receivable_type) {
        return AssetKind::receivable;
    }
    if (record_type == warehouse_receipt_type) {
        return AssetKind::warehouse_receipt;
    }
    return std::nullopt;
}

std::string_view record_type_of(AssetKind kind) noexcept {
    return kind == AssetKind::receivable ? receivable_type : warehouse_receipt_type;
}

bool is_final_asset_status(std::string_view s) noexcept {
    return s == status::settled || s == status::redeemed || s == status::cancelled;
}

Result<AssetMetadata> decode_asset_metadata(AssetKind kind, const cbor::Value& metadata) {
    auto map = TextMap::open(metadata);
    if (!map) {
        return std::unexpected(map.error());
    }
    AssetMetadata out;
    auto holder = map->id("holder");
    if (!holder) {
        return fail(Errc::malformed, "an asset's metadata names its holder's ledger (\"holder\")");
    }
    out.holder = *holder;
    if (kind == AssetKind::receivable) {
        auto amount = map->uint("amount");
        if (!amount || *amount == 0) {
            return fail(Errc::malformed,
                        "a receivable's \"amount\" is a whole number of at least 1 "
                        "(in the currency's minor unit)");
        }
        out.units = *amount;
        auto currency = map->text("currency");
        if (!currency || !is_currency(*currency)) {
            return fail(Errc::malformed,
                        "a receivable's \"currency\" is an ISO 4217 code: three capital letters");
        }
        out.unit = std::move(*currency);
        auto due = map->uint("due");
        if (!due) {
            return fail(Errc::malformed, "a receivable's \"due\" is a time (ms)");
        }
        out.due = *due;
    } else {
        auto quantity = map->uint("quantity");
        if (!quantity || *quantity == 0) {
            return fail(Errc::malformed,
                        "a warehouse receipt's \"quantity\" is a whole number of at least 1");
        }
        out.units = *quantity;
        auto unit = map->text("unit");
        if (!unit || unit->empty() || unit->size() > max_unit) {
            return fail(Errc::malformed, "a warehouse receipt's \"unit\" is 1 to 16 bytes");
        }
        out.unit = std::move(*unit);
    }
    return out;
}

Result<cbor::Value> encode_asset_metadata(AssetKind kind, const AssetMetadata& m,
                                          const cbor::Map& extra) {
    cbor::Map map{text_entry("holder", cbor::Value::bytes(m.holder.bytes()))};
    if (kind == AssetKind::receivable) {
        if (!m.due) {
            return fail(Errc::invalid_argument, "a receivable needs a due date");
        }
        map.push_back(text_entry("amount", cbor::Value::unsigned_integer(m.units)));
        map.push_back(text_entry("currency", cbor::Value::text(m.unit)));
        map.push_back(text_entry("due", cbor::Value::unsigned_integer(*m.due)));
    } else {
        map.push_back(text_entry("quantity", cbor::Value::unsigned_integer(m.units)));
        map.push_back(text_entry("unit", cbor::Value::text(m.unit)));
    }
    for (const cbor::MapEntry& e : extra) {
        const std::string* key = e.key.as_text();
        if (key == nullptr) {
            return fail(Errc::invalid_argument, "metadata keys are text");
        }
        const bool reserved = std::ranges::any_of(
            map, [&](const cbor::MapEntry& m2) { return *m2.key.as_text() == *key; });
        if (reserved) {
            return fail(Errc::invalid_argument, "extra metadata repeats a key the asset sets");
        }
        map.push_back(e);
    }
    cbor::Value value = cbor::Value::map(std::move(map));
    if (auto checked = decode_asset_metadata(kind, value); !checked) {
        return std::unexpected(Error{Errc::invalid_argument, checked.error().detail});
    }
    return value;
}

Result<AssetState> register_asset(AssetKind kind, const std::optional<cbor::Value>& metadata,
                                  const Id& home, const Id& id, std::uint64_t index) {
    if (!metadata) {
        return fail(Errc::rejected, "an asset's registration carries its metadata");
    }
    auto m = decode_asset_metadata(kind, *metadata);
    if (!m) {
        return std::unexpected(Error{Errc::rejected, m.error().detail});
    }
    if (m->holder == home) {
        return fail(Errc::rejected, "an asset's holder is another ledger than its home");
    }
    AssetState asset;
    asset.id = id;
    asset.kind = kind;
    asset.holder = m->holder;
    asset.units = m->units;
    asset.head = index;
    return asset;
}

std::vector<Id> consenting_parties(const AssetState& asset, std::string_view s,
                                   const AssetActionBody& action) {
    std::vector<Id> out;
    switch (action.action) {
    case AssetAction::transfer:
    case AssetAction::pledge:
        out.push_back(asset.holder);
        if (action.to) {
            out.push_back(*action.to);
        }
        break;
    case AssetAction::release:
    case AssetAction::enforce:
        if (asset.pledgee) {
            out.push_back(*asset.pledgee);
        }
        break;
    case AssetAction::redeem:
        out.push_back(asset.holder);
        if (s == status::pledged && asset.pledgee) {
            out.push_back(*asset.pledgee);
        }
        break;
    case AssetAction::confirm:
    case AssetAction::dispute:
        if (asset.payee) {
            out.push_back(*asset.payee);
        }
        break;
    case AssetAction::cancel:
        out.push_back(asset.holder);
        break;
    case AssetAction::pay:
    case AssetAction::freeze:
    case AssetAction::unfreeze:
        break;
    }
    std::ranges::sort(out, [](const Id& a, const Id& b) {
        return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
    });
    const auto [first, last] = std::ranges::unique(out);
    out.erase(first, last);
    return out;
}

Status check_asset_action(const AssetState& asset, std::string_view s,
                          const AssetActionBody& action, const Id& home) {
    if (is_final_asset_status(s)) {
        return fail(Errc::rejected,
                    "the asset is settled, redeemed, or cancelled: it takes no more actions");
    }
    if (action.head != asset.head) {
        return fail(Errc::rejected, "the action follows an earlier state of the asset (its head "
                                    "has moved on): consent again to the current one");
    }
    const Rule& rule = rule_for(action.action);
    if (!(asset.kind == AssetKind::receivable ? rule.receivable : rule.warehouse_receipt)) {
        return fail(Errc::rejected, "this action is not defined for this type of asset");
    }
    if (!rule.starts_from(s)) {
        return fail(Errc::rejected, "the asset's state does not allow this action");
    }
    if (rule.takes_counterparty != action.to.has_value()) {
        return fail(Errc::rejected, rule.takes_counterparty
                                        ? "this action needs a counterparty (\"to\")"
                                        : "this action takes no counterparty");
    }
    if (action.to && *action.to == home) {
        return fail(Errc::rejected,
                    "the counterparty must be another ledger than the asset's home");
    }
    if (action.to && *action.to == asset.holder) {
        return fail(Errc::rejected, "the counterparty is already the asset's holder");
    }
    if (rule.takes_quantity != action.quantity.has_value()) {
        return fail(Errc::rejected, rule.takes_quantity ? "redeeming needs a quantity"
                                                        : "only redeeming takes a quantity");
    }
    if (action.quantity && *action.quantity > asset.units) {
        return fail(Errc::rejected, "more than remains of the asset");
    }
    const std::vector<Id> parties = consenting_parties(asset, s, action);
    const bool exact = std::ranges::equal(parties, action.consents, {}, {}, &ConsentRef::ledger);
    if (!exact) {
        return fail(Errc::rejected, parties.empty()
                                        ? "this action is the home's own: it cites no consents"
                                        : "the action must cite one consent from each party it "
                                          "needs, and no others");
    }
    return {};
}

std::string apply_asset_action(AssetState& asset, std::string_view s, const AssetActionBody& action,
                               std::uint64_t index) {
    asset.head = index;
    switch (action.action) {
    case AssetAction::transfer:
        asset.holder = *action.to;
        return std::string(status::active);
    case AssetAction::pledge:
        asset.pledgee = *action.to;
        return std::string(status::pledged);
    case AssetAction::release:
        asset.pledgee.reset();
        return std::string(status::active);
    case AssetAction::enforce:
        asset.holder = *asset.pledgee;
        asset.pledgee.reset();
        return std::string(status::active);
    case AssetAction::redeem:
        asset.units -= *action.quantity;
        if (asset.units == 0) {
            asset.pledgee.reset();
            return std::string(status::redeemed);
        }
        return std::string(s);
    case AssetAction::pay:
        // Paid again after a dispute: to the same payee.
        if (s != status::disputed) {
            asset.payee = asset.pledgee ? *asset.pledgee : asset.holder;
        }
        return std::string(status::paid);
    case AssetAction::confirm:
        return std::string(status::settled);
    case AssetAction::dispute:
        return std::string(status::disputed);
    case AssetAction::freeze:
        asset.frozen_from = std::string(s);
        return std::string(status::frozen);
    case AssetAction::unfreeze: {
        std::string back = std::move(asset.frozen_from);
        asset.frozen_from.clear();
        return back;
    }
    case AssetAction::cancel:
        return std::string(status::cancelled);
    }
    return std::string(s);
}

AssetTerms terms_of(const AssetActionBody& action, const Id& home) {
    return AssetTerms{home, action.asset, action.action, action.head, action.to, action.quantity};
}

Result<cbor::Value> encode_asset_consent(const AssetConsent& c) {
    if (c.until == 0) {
        return fail(Errc::invalid_argument, "a consent lapses at some time (\"until\")");
    }
    if (c.reference && (c.reference->empty() || c.reference->size() > max_asset_reference)) {
        return fail(Errc::invalid_argument, "a consent's reference is 1 to 1024 bytes");
    }
    if (c.terms.quantity && *c.terms.quantity == 0) {
        return fail(Errc::invalid_argument, "a consent's quantity is at least 1");
    }
    cbor::Map map{
        text_entry("ledger", cbor::Value::bytes(c.terms.ledger.bytes())),
        text_entry("asset", cbor::Value::bytes(c.terms.asset.bytes())),
        text_entry("action", cbor::Value::text(std::string(name(c.terms.action)))),
        text_entry("head", cbor::Value::unsigned_integer(c.terms.head)),
        text_entry("until", cbor::Value::unsigned_integer(c.until)),
    };
    if (c.terms.to) {
        map.push_back(text_entry("to", cbor::Value::bytes(c.terms.to->bytes())));
    }
    if (c.terms.quantity) {
        map.push_back(text_entry("quantity", cbor::Value::unsigned_integer(*c.terms.quantity)));
    }
    if (c.reference) {
        map.push_back(text_entry("reference", cbor::Value::text(*c.reference)));
    }
    return cbor::Value::map(std::move(map));
}

Result<AssetConsent> decode_asset_consent(const cbor::Value& metadata) {
    auto map = TextMap::open(metadata);
    if (!map) {
        return std::unexpected(map.error());
    }
    if (auto s = map->only(
            {"ledger", "asset", "action", "head", "to", "quantity", "until", "reference"});
        !s) {
        return std::unexpected(s.error());
    }
    AssetConsent c;
    auto ledger = map->id("ledger");
    auto asset = map->id("asset");
    auto action = map->text("action");
    auto head = map->uint("head");
    auto to = map->opt_id("to");
    auto quantity = map->opt_uint("quantity");
    auto until = map->uint("until");
    if (!ledger || !asset || !action || !head || !to || !quantity || !until) {
        return fail(Errc::malformed, "a consent names a ledger, an asset, an action, a head, and "
                                     "an end, each well-formed");
    }
    const auto known = asset_action_from(*action);
    if (!known) {
        return fail(Errc::malformed, "a consent names an unknown asset action");
    }
    if (*until == 0 || (*quantity && **quantity == 0)) {
        return fail(Errc::malformed, "a consent's end and quantity are not zero");
    }
    c.terms = AssetTerms{*ledger, *asset, *known, *head, *to, *quantity};
    c.until = *until;
    if (map->get("reference") != nullptr) {
        auto reference = map->text("reference");
        if (!reference || reference->empty() || reference->size() > max_asset_reference) {
            return fail(Errc::malformed, "a consent's reference is 1 to 1024 bytes");
        }
        c.reference = std::move(*reference);
    }
    return c;
}

} // namespace cexchain::protocol
