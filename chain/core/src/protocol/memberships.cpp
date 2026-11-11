// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <string>

#include <cexchain/core/protocol/memberships.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

constexpr std::size_t max_name = 256;
constexpr std::size_t max_registration = 64;

bool upper(char c) {
    return c >= 'A' && c <= 'Z';
}

/// ISO 3166-1 alpha-2, then optionally "-" and 1 to 3 upper-case letters or
/// digits of a subdivision (ISO 3166-2).
bool jurisdiction_ok(std::string_view s) {
    if (s.size() < 2 || !upper(s[0]) || !upper(s[1])) {
        return false;
    }
    if (s.size() == 2) {
        return true;
    }
    const std::string_view sub = s.substr(3);
    return s[2] == '-' && !sub.empty() && sub.size() <= 3 &&
           std::ranges::all_of(sub, [](char c) { return upper(c) || (c >= '0' && c <= '9'); });
}

const cbor::Value* text_of(const cbor::Value& metadata, std::string_view key,
                           std::size_t max_size) {
    const cbor::Value* v = metadata.find(key);
    const std::string* text = v != nullptr ? v->as_text() : nullptr;
    return text != nullptr && !text->empty() && text->size() <= max_size ? v : nullptr;
}

} // namespace

std::string_view member_kind_name(MemberKind kind) noexcept {
    return kind == MemberKind::person ? "person" : "organization";
}

Result<Membership> decode_membership(const cbor::Value& metadata) {
    const cbor::Map* map = metadata.as_map();
    if (map == nullptr) {
        return fail(Errc::malformed, "a membership's metadata is a map");
    }
    constexpr std::array<std::string_view, 7> known{
        "member", "kind", "name", "verified", "registration", "jurisdiction", "until"};
    for (const cbor::MapEntry& e : *map) {
        const std::string* key = e.key.as_text();
        if (key == nullptr || !std::ranges::contains(known, std::string_view(*key))) {
            return fail(Errc::malformed, "a membership's metadata has an unknown key");
        }
    }
    Membership m;
    const cbor::Value* member = metadata.find("member");
    if (member == nullptr || member->as_bytes() == nullptr) {
        return fail(Errc::malformed, "a membership names its member's ledger");
    }
    CEXCHAIN_TRY(m.member, to_id(*member->as_bytes()));
    const cbor::Value* kind = metadata.find("kind");
    const std::string* kind_text = kind != nullptr ? kind->as_text() : nullptr;
    if (kind_text == nullptr || (*kind_text != "organization" && *kind_text != "person")) {
        return fail(Errc::malformed, "a membership's kind is organization or person");
    }
    m.kind = *kind_text == "person" ? MemberKind::person : MemberKind::organization;
    const cbor::Value* name = text_of(metadata, "name", max_name);
    if (name == nullptr) {
        return fail(Errc::malformed, "a membership's name is 1 to 256 bytes");
    }
    m.name = *name->as_text();
    const cbor::Value* verified = metadata.find("verified");
    if (verified == nullptr || !verified->as_bool()) {
        return fail(Errc::malformed, "a membership says whether its member was checked");
    }
    m.verified = *verified->as_bool();
    if (metadata.find("registration") != nullptr) {
        const cbor::Value* registration = text_of(metadata, "registration", max_registration);
        if (registration == nullptr) {
            return fail(Errc::malformed, "a membership's registration is 1 to 64 bytes");
        }
        m.registration = *registration->as_text();
    }
    if (const cbor::Value* jurisdiction = metadata.find("jurisdiction")) {
        const std::string* text = jurisdiction->as_text();
        if (text == nullptr || !jurisdiction_ok(*text)) {
            return fail(Errc::malformed,
                        "a membership's jurisdiction is an ISO 3166 code: HK, or CN-44");
        }
        m.jurisdiction = *text;
    }
    if (const cbor::Value* until = metadata.find("until")) {
        if (!until->as_uint64() || *until->as_uint64() == 0) {
            return fail(Errc::malformed, "a membership's \"until\" is a time in milliseconds");
        }
        m.until = *until->as_uint64();
    }
    return m;
}

Result<cbor::Value> encode_membership(const Membership& m) {
    cbor::Map map{
        {cbor::Value::text("member"), cbor::Value::bytes(m.member.bytes())},
        {cbor::Value::text("kind"), cbor::Value::text(std::string(member_kind_name(m.kind)))},
        {cbor::Value::text("name"), cbor::Value::text(m.name)},
        {cbor::Value::text("verified"), cbor::Value::boolean(m.verified)},
    };
    if (m.registration) {
        map.push_back({cbor::Value::text("registration"), cbor::Value::text(*m.registration)});
    }
    if (m.jurisdiction) {
        map.push_back({cbor::Value::text("jurisdiction"), cbor::Value::text(*m.jurisdiction)});
    }
    if (m.until) {
        map.push_back({cbor::Value::text("until"), cbor::Value::unsigned_integer(*m.until)});
    }
    cbor::Value value = cbor::Value::map(std::move(map));
    if (auto checked = decode_membership(value); !checked) {
        return std::unexpected(Error{Errc::invalid_argument, checked.error().detail});
    }
    return value;
}

std::string_view standing_name(Standing standing) noexcept {
    switch (standing) {
    case Standing::not_yet:
        return "not yet a member";
    case Standing::active:
        return "active";
    case Standing::suspended:
        return "suspended";
    case Standing::ended:
        return "ended";
    case Standing::revoked:
        return "revoked";
    case Standing::lapsed:
        return "lapsed";
    }
    return "unknown";
}

Standing standing_at(const Membership& membership, Timestamp registered_at,
                     std::span<const MembershipChange> changes, Timestamp t) {
    if (t < registered_at) {
        return Standing::not_yet;
    }
    std::string state = "active";
    for (const MembershipChange& change : changes) {
        if (change.at > t) {
            break;
        }
        if (change.to.empty()) {
            return Standing::revoked;
        }
        state = change.to;
    }
    if (membership.until && *membership.until < t) {
        return Standing::lapsed;
    }
    return state == "suspended" ? Standing::suspended
           : state == "ended"   ? Standing::ended
                                : Standing::active;
}

} // namespace cexchain::protocol
