// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Memberships (spec v0.16): their metadata's shape, and where one stood at a
// time, from its registration, transitions, and revocation.

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/memberships.hpp>

namespace protocol = kanhe::protocol;
namespace cbor = kanhe::cbor;
using kanhe::Bytes;

namespace {

using V = cbor::Value;

protocol::Membership school() {
    protocol::Membership m;
    m.member = *protocol::to_id(Bytes(32, 0x5a));
    m.kind = protocol::MemberKind::organization;
    m.name = "Kowloon Example School";
    m.verified = true;
    m.registration = "12345678";
    m.jurisdiction = "HK";
    m.until = 2'000'000'000'000;
    return m;
}

/// Its metadata with `key` set to `value`.
cbor::Value with(const protocol::Membership& m, std::string_view key, cbor::Value value) {
    cbor::Map map = *protocol::encode_membership(m)->as_map();
    std::erase_if(map, [&](const cbor::MapEntry& e) { return *e.key.as_text() == key; });
    map.push_back({V::text(std::string(key)), std::move(value)});
    return V::map(std::move(map));
}

cbor::Value without(const protocol::Membership& m, std::string_view key) {
    cbor::Map map = *protocol::encode_membership(m)->as_map();
    std::erase_if(map, [&](const cbor::MapEntry& e) { return *e.key.as_text() == key; });
    return V::map(std::move(map));
}

} // namespace

TEST_CASE("a membership's metadata is read as written, and strictly", "[memberships]") {
    const auto m = school();
    const auto encoded = protocol::encode_membership(m);
    REQUIRE(encoded);
    CHECK(*protocol::decode_membership(*encoded) == m);
    protocol::Membership person;
    person.member = m.member;
    person.kind = protocol::MemberKind::person;
    person.name = "Chan";
    CHECK(*protocol::decode_membership(*protocol::encode_membership(person)) == person);
    CHECK(protocol::member_kind_name(person.kind) == "person");

    CHECK_FALSE(protocol::decode_membership(with(m, "extra", V::boolean(true))));
    CHECK_FALSE(protocol::decode_membership(with(m, "member", V::bytes(Bytes(31, 1)))));
    CHECK_FALSE(protocol::decode_membership(with(m, "kind", V::text("company"))));
    CHECK_FALSE(protocol::decode_membership(with(m, "name", V::text(""))));
    CHECK_FALSE(protocol::decode_membership(with(m, "name", V::text(std::string(257, 'a')))));
    CHECK(protocol::decode_membership(with(m, "name", V::text(std::string(256, 'a')))));
    CHECK_FALSE(protocol::decode_membership(with(m, "verified", V::text("yes"))));
    CHECK_FALSE(protocol::decode_membership(with(m, "registration", V::text(""))));
    CHECK_FALSE(
        protocol::decode_membership(with(m, "registration", V::text(std::string(65, '1')))));
    for (const char* bad : {"hk", "H", "HKG", "HK-", "HK-1234", "CN_44", "CN-4a"}) {
        INFO(bad);
        CHECK_FALSE(protocol::decode_membership(with(m, "jurisdiction", V::text(bad))));
    }
    for (const char* good : {"HK", "CN-44", "US-CA", "GB-ENG"}) {
        INFO(good);
        CHECK(protocol::decode_membership(with(m, "jurisdiction", V::text(good))));
    }
    CHECK_FALSE(protocol::decode_membership(with(m, "until", V::unsigned_integer(0))));
    CHECK_FALSE(protocol::decode_membership(with(m, "until", V::null())));
    for (const char* key : {"member", "kind", "name", "verified"}) {
        INFO(key);
        CHECK_FALSE(protocol::decode_membership(without(m, key)));
    }
    CHECK(protocol::decode_membership(without(m, "until")));
    CHECK_FALSE(protocol::decode_membership(V::text("x")));
}

TEST_CASE("where a membership stood at a time", "[memberships]") {
    auto m = school();
    const protocol::Timestamp r = 1'000;
    const std::vector<protocol::MembershipChange> changes{
        {2'000, "suspended"}, {3'000, "active"}, {4'000, "ended"}};
    using S = protocol::Standing;
    CHECK(protocol::standing_at(m, r, changes, 999) == S::not_yet);
    CHECK(protocol::standing_at(m, r, changes, 1'000) == S::active);
    CHECK(protocol::standing_at(m, r, changes, 2'000) == S::suspended);
    CHECK(protocol::standing_at(m, r, changes, 2'999) == S::suspended);
    CHECK(protocol::standing_at(m, r, changes, 3'500) == S::active);
    CHECK(protocol::standing_at(m, r, changes, 4'000) == S::ended);
    // Lapsed once its end passes, but revoked wins.
    m.until = 3'200;
    CHECK(protocol::standing_at(m, r, changes, 3'201) == S::lapsed);
    CHECK(protocol::standing_at(m, r, changes, 3'200) == S::active);
    const std::vector<protocol::MembershipChange> revoked{{2'000, "suspended"}, {2'500, ""}};
    CHECK(protocol::standing_at(m, r, revoked, 2'400) == S::suspended);
    CHECK(protocol::standing_at(m, r, revoked, 2'500) == S::revoked);
    CHECK(protocol::standing_at(m, r, revoked, 9'999) == S::revoked);
    CHECK(protocol::standing_name(S::not_yet) == "not yet a member");
}
