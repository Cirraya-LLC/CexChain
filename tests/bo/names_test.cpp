// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// cexchain::bo, the part of the compiler built with C++26 reflection and
// contracts (GCC 16): names from the enumerators, and records written member
// by member.

#include <cstddef>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/names.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;

TEST_CASE("names come from the enumerators", "[bo][names]") {
    for (std::size_t i = 0; i < category_names.size(); ++i) {
        CHECK(name_of(static_cast<Category>(i)) == category_names[i]);
    }
    CHECK(name_of(Category::unit) == "unit");
    CHECK(name_of(Severity::warning) == "warning");
    CHECK(name_of(Separation::none) == "none");
    CHECK(name_of(MeaningKind::multiplier) == "multiplier");
    // Contracts are on: this build checks BO_PRE, BO_POST, and BO_ASSERT.
    CHECK(BO_CONTRACTS == 1);
}

TEST_CASE("a pack's facts, written member by member", "[bo][names]") {
    const crypto::openssl::Provider provider;
    const Pack& pack = *official_pack("zh-Hant-HK");
    const auto facts_or = facts(pack, provider, crypto::HashAlg::sm3);
    REQUIRE(facts_or);
    const PackFacts& f = *facts_or;
    CHECK(f.id == "zh-Hant-HK");
    CHECK(f.official);
    CHECK(f.separation == "none");
    CHECK(f.keywords == 18);
    CHECK(f.words == pack.vocabulary.size());
    CHECK(f.size == pack.canonical.size());
    CHECK(f.hash == "SM3");
    const auto d = digest(pack, provider, crypto::HashAlg::sm3);
    REQUIRE(d);
    CHECK(f.digest == to_hex(d->bytes()));

    const cbor::Value value = to_cbor(f);
    const cbor::Map& map = *value.as_map();
    REQUIRE(map.size() == 15);
    // Declaration order, names as declared.
    CHECK(*map[0].key.as_text() == "id");
    CHECK(*map[0].value.as_text() == "zh-Hant-HK");
    CHECK(*map[4].key.as_text() == "official");
    CHECK(map[4].value.as_bool() == true);
    CHECK(*map[7].key.as_text() == "keywords");
    CHECK(map[7].value.as_uint64() == 18U);
    CHECK(*map[14].key.as_text() == "digest");
}
