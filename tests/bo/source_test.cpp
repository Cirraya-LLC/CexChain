// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// What a Bo deploy records besides its code (milestone 7 of the Bo compiler):
// the bo-source bundle, the compiler string, and the .boc file. Front end
// only, so these run with every compiler; rebuilding is in build_test.cpp.

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/bo/vocab.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

constexpr std::string_view source = "use commerce\ncontract Deal\nparties we, customer\n";

/// A company's own pack: every keyword spelled as English spells it, and a
/// word of its own.
std::string company_pack_text(std::string_view id = "acme-terms", std::uint64_t version = 3) {
    std::string keywords;
    const Pack& en = english_pack();
    for (const auto& [concept_id, word] : en.keywords) {
        keywords += (keywords.empty() ? "" : ", ") + std::string("\"") + concept_id + "\": \"" +
                    word.spellings.front() + "\"";
    }
    return "{\"format\": 1, \"id\": \"" + std::string(id) +
           "\", \"version\": " + std::to_string(version) +
           ", \"language\": \"en-x-acme\", \"name\": \"Acme terms\", \"official\": false, "
           "\"edition\": 1, \"reading\": {\"separation\": \"spaces\"}, \"keywords\": {" +
           keywords + "}, \"vocabulary\": {\"role.supplier\": \"vendor\"}}";
}

Pack company_pack(std::string_view id = "acme-terms", std::uint64_t version = 3) {
    PackRead read = read_pack(company_pack_text(id, version));
    REQUIRE(read.pack.has_value());
    return std::move(*read.pack);
}

PackSet pack_set(std::vector<Pack> extra = {}) {
    PackSetRead set = make_pack_set(std::move(extra));
    REQUIRE(set.set.has_value());
    return std::move(*set.set);
}

SourceBundle bundle_of(const PackSet& set, crypto::HashAlg hash = crypto::HashAlg::sha256) {
    auto bundle = make_source_bundle(source, 1, set, provider(), hash);
    REQUIRE(bundle.has_value());
    return std::move(*bundle);
}

Bytes encoded(const SourceBundle& bundle) {
    auto bytes = encode_source_bundle(bundle);
    REQUIRE(bytes.has_value());
    return std::move(*bytes);
}

/// Encodes a value the way a hostile deploy might: any shape at all.
Bytes raw(const cbor::Value& value) {
    auto bytes = cbor::encode(value);
    REQUIRE(bytes.has_value());
    return std::move(*bytes);
}

cbor::Value k(std::int64_t key) {
    return cbor::Value::integer(key);
}

cbor::Value ref(std::string id, std::uint64_t version, Bytes digest) {
    return cbor::Value::array({cbor::Value::text(std::move(id)),
                               cbor::Value::unsigned_integer(version),
                               cbor::Value::bytes(std::move(digest))});
}

} // namespace

TEST_CASE("a source bundle names every official pack and round-trips", "[bo][source]") {
    const PackSet set = pack_set();
    const SourceBundle bundle = bundle_of(set);
    CHECK(bundle.edition == 1);
    CHECK(bundle.source == source);
    REQUIRE(bundle.packs.size() == 3);
    // By ascending id, each with its digest under the home's hash.
    CHECK(bundle.packs[0].id == "en");
    CHECK(bundle.packs[1].id == "zh-Hans-CN");
    CHECK(bundle.packs[2].id == "zh-Hant-HK");
    for (const PackRef& r : bundle.packs) {
        const Pack* official = official_pack(r.id);
        REQUIRE(official != nullptr);
        CHECK(r.version == official->version);
        const auto d = digest(*official, provider(), crypto::HashAlg::sha256);
        REQUIRE(d.has_value());
        CHECK(std::ranges::equal(d->bytes(), r.digest));
    }
    CHECK(bundle.embedded.empty());
    const Bytes bytes = encoded(bundle);
    const auto decoded = decode_source_bundle(bytes);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == bundle);
    CHECK(encoded(*decoded) == bytes);
    // {1: 1, 2: 1, 3: source, 4: [...], 6: [...]}: no key 5 without
    // embedded packs; key 6 names the vocabulary pack the source uses.
    const auto value = cbor::decode(bytes);
    REQUIRE(value.has_value());
    CHECK(value->as_map()->size() == 5);
    REQUIRE(bundle.vocabulary.size() == 1);
    CHECK(bundle.vocabulary[0].id == "commerce");
    CHECK(bundle.vocabulary[0].version == 2);
    const auto vd = digest(*find_vocabulary_pack("commerce"), provider(), crypto::HashAlg::sha256);
    REQUIRE(vd.has_value());
    CHECK(std::ranges::equal(vd->bytes(), bundle.vocabulary[0].digest));
    // Without `use` lines, no key 6.
    const auto core_only =
        make_source_bundle("contract C\nparties we\n", 1, set, provider(), crypto::HashAlg::sha256);
    REQUIRE(core_only.has_value());
    CHECK(core_only->vocabulary.empty());
    CHECK(cbor::decode(encoded(*core_only))->as_map()->size() == 4);
    // A pack the compiler does not have cannot be pinned.
    CHECK(!make_source_bundle("use acme\ncontract C\n", 1, set, provider(), crypto::HashAlg::sha256)
               .has_value());

    // SM3 digests differ, and opening under the wrong hash says which pack.
    const SourceBundle sm3 = bundle_of(set, crypto::HashAlg::sm3);
    CHECK(sm3.packs[0].digest != bundle.packs[0].digest);
    const OpenedSource wrong = open_source_bundle(sm3, provider(), crypto::HashAlg::sha256);
    CHECK(wrong.problem == OpenProblem::official_differs);
    CHECK(wrong.detail.find("the official pack en version 4") != std::string::npos);
    const OpenedSource right = open_source_bundle(sm3, provider(), crypto::HashAlg::sm3);
    CHECK(right.problem == OpenProblem::none);
    REQUIRE(right.packs.has_value());
    CHECK(right.packs->packs().size() == 3);
}

TEST_CASE("a source bundle embeds the packs that are not official", "[bo][source]") {
    const PackSet set = pack_set({company_pack()});
    const SourceBundle bundle = bundle_of(set);
    REQUIRE(bundle.packs.size() == 4);
    CHECK(bundle.packs[0].id == "acme-terms");
    CHECK(bundle.packs[0].version == 3);
    REQUIRE(bundle.embedded.size() == 1);
    CHECK(bundle.embedded[0].find("id")->as_text() != nullptr);
    const auto decoded = decode_source_bundle(encoded(bundle));
    REQUIRE(decoded.has_value());
    CHECK(*decoded == bundle);
    const OpenedSource opened = open_source_bundle(*decoded, provider(), crypto::HashAlg::sha256);
    CHECK(opened.problem == OpenProblem::none);
    REQUIRE(opened.packs.has_value());
    REQUIRE(opened.packs->find("acme-terms") != nullptr);
    // The company's word reads as its concept.
    const Meaning* vendor = opened.packs->lookup("vendor");
    REQUIRE(vendor != nullptr);
    CHECK(vendor->concept_entry->id == "role.supplier");

    SECTION("another version of the pack under the same reference") {
        SourceBundle changed = bundle;
        changed.embedded[0] = *cbor::decode(company_pack("acme-terms", 4).canonical);
        const OpenedSource other = open_source_bundle(changed, provider(), crypto::HashAlg::sha256);
        CHECK(other.problem == OpenProblem::embedded);
        CHECK(other.detail.find("version 4") != std::string::npos);
    }
    SECTION("a digest that does not match the embedded pack") {
        SourceBundle changed = bundle;
        changed.packs[0].digest[0] ^= 1;
        const OpenedSource opened2 =
            open_source_bundle(changed, provider(), crypto::HashAlg::sha256);
        CHECK(opened2.problem == OpenProblem::embedded);
        CHECK(opened2.detail.find("the embedded pack acme-terms") != std::string::npos);
    }
    SECTION("a reference without its pack, or a pack without its reference") {
        SourceBundle missing = bundle;
        missing.embedded.clear();
        const OpenedSource a = open_source_bundle(missing, provider(), crypto::HashAlg::sha256);
        CHECK(a.problem == OpenProblem::unknown_official);
        CHECK(a.detail.find("acme-terms version 3, which is neither in the bundle") !=
              std::string::npos);
        SourceBundle extra = bundle;
        extra.embedded.push_back(*cbor::decode(company_pack("other-terms", 1).canonical));
        const OpenedSource b = open_source_bundle(extra, provider(), crypto::HashAlg::sha256);
        CHECK(b.problem == OpenProblem::embedded);
    }
    SECTION("an embedded pack that calls itself official") {
        SourceBundle fake = bundle;
        const Pack* en = official_pack("en");
        fake.embedded = {*cbor::decode(en->canonical)};
        fake.packs = {PackRef{"en", 1, fake.packs[1].digest}};
        const OpenedSource opened2 = open_source_bundle(fake, provider(), crypto::HashAlg::sha256);
        CHECK(opened2.problem == OpenProblem::embedded);
        CHECK(opened2.detail.find("calls itself official") != std::string::npos);
    }
    SECTION("an embedded pack that does not read") {
        SourceBundle broken = bundle;
        broken.embedded[0] =
            cbor::Value::map({{cbor::Value::text("id"), cbor::Value::text("acme-terms")}});
        const OpenedSource opened2 =
            open_source_bundle(broken, provider(), crypto::HashAlg::sha256);
        CHECK(opened2.problem == OpenProblem::embedded);
        CHECK(opened2.detail.find("does not read") != std::string::npos);
    }
}

TEST_CASE("opening a bundle names what this compiler cannot read it with", "[bo][source]") {
    const SourceBundle bundle = bundle_of(pack_set());
    SECTION("an official pack version this compiler does not carry") {
        SourceBundle newer = bundle;
        newer.packs[0].version = 5;
        const OpenedSource opened = open_source_bundle(newer, provider(), crypto::HashAlg::sha256);
        CHECK(opened.problem == OpenProblem::unknown_official);
        CHECK(opened.detail ==
              "the source was read with the official pack en version 5; this compiler carries "
              "version 4 (and the versions of earlier releases)");
    }
    SECTION("official packs of two releases") {
        SourceBundle mixed = bundle;
        const Pack* earlier = official_pack("en", 1);
        REQUIRE(earlier != nullptr);
        const auto d = digest(*earlier, provider(), crypto::HashAlg::sha256);
        REQUIRE(d.has_value());
        mixed.packs[0] = PackRef{"en", 1, Bytes(d->bytes().begin(), d->bytes().end())};
        const OpenedSource opened = open_source_bundle(mixed, provider(), crypto::HashAlg::sha256);
        CHECK(opened.problem == OpenProblem::conflict);
        CHECK(opened.detail.find("not of the same release") != std::string::npos);
    }
    SECTION("a vocabulary pack version this compiler does not carry") {
        SourceBundle newer = bundle;
        newer.vocabulary[0].version = 3;
        const OpenedSource opened = open_source_bundle(newer, provider(), crypto::HashAlg::sha256);
        CHECK(opened.problem == OpenProblem::unknown_official);
        CHECK(opened.detail == "the source uses the vocabulary pack commerce version 3, which "
                               "this compiler does not carry");
        newer.vocabulary[0].id = "acme";
        newer.vocabulary[0].version = 1;
        CHECK(open_source_bundle(newer, provider(), crypto::HashAlg::sha256).problem ==
              OpenProblem::unknown_official);
    }
    SECTION("a vocabulary pack's digest differs") {
        SourceBundle other = bundle;
        other.vocabulary[0].digest[0] ^= 1;
        const OpenedSource opened = open_source_bundle(other, provider(), crypto::HashAlg::sha256);
        CHECK(opened.problem == OpenProblem::official_differs);
        CHECK(opened.detail.find("the vocabulary pack commerce version 2 has the digest") !=
              std::string::npos);
    }
    SECTION("use lines that differ from key 6") {
        // Key 6 left out, or naming another pack, or the source's line
        // gone.
        SourceBundle none = bundle;
        none.vocabulary.clear();
        CHECK(open_source_bundle(none, provider(), crypto::HashAlg::sha256).problem ==
              OpenProblem::uses_differ);
        SourceBundle more = bundle;
        const auto d =
            digest(*find_vocabulary_pack("finance"), provider(), crypto::HashAlg::sha256);
        REQUIRE(d.has_value());
        more.vocabulary.push_back(
            PackRef{"finance", 2, Bytes(d->bytes().begin(), d->bytes().end())});
        CHECK(open_source_bundle(more, provider(), crypto::HashAlg::sha256).problem ==
              OpenProblem::uses_differ);
        SourceBundle bare = bundle;
        bare.source = "contract Deal\nparties we, customer\n";
        const OpenedSource opened = open_source_bundle(bare, provider(), crypto::HashAlg::sha256);
        CHECK(opened.problem == OpenProblem::uses_differ);
        CHECK(opened.detail.find("use lines") != std::string::npos);
    }
    SECTION("an official pack left out") {
        SourceBundle fewer = bundle;
        fewer.packs.erase(fewer.packs.begin() + 1);
        const OpenedSource opened = open_source_bundle(fewer, provider(), crypto::HashAlg::sha256);
        CHECK(opened.problem == OpenProblem::official_missing);
        CHECK(opened.detail.find("without the official pack zh-Hans-CN") != std::string::npos);
    }
    SECTION("a later edition") {
        SourceBundle later = bundle;
        later.edition = edition + 1;
        const OpenedSource opened = open_source_bundle(later, provider(), crypto::HashAlg::sha256);
        CHECK(opened.problem == OpenProblem::unknown_edition);
    }
    SECTION("two packs that give one spelling two meanings") {
        // A pack spelling role.supplier as "bank", which English gives role.bank.
        std::string text = company_pack_text();
        text.replace(text.find("\"vendor\""), 8, "\"bank\"");
        PackRead conflicting = read_pack(text);
        REQUIRE(conflicting.pack.has_value());
        SourceBundle b = bundle;
        auto d = digest(*conflicting.pack, provider(), crypto::HashAlg::sha256);
        REQUIRE(d.has_value());
        b.packs.insert(b.packs.begin(),
                       PackRef{"acme-terms", 3, Bytes(d->bytes().begin(), d->bytes().end())});
        b.embedded = {*cbor::decode(conflicting.pack->canonical)};
        const OpenedSource opened = open_source_bundle(b, provider(), crypto::HashAlg::sha256);
        CHECK(opened.problem == OpenProblem::conflict);
        CHECK(opened.detail.find("pack.conflict") != std::string::npos);
    }
}

TEST_CASE("a bundle read before vocabulary packs opens with the packs it was read with",
          "[bo][source]") {
    // What a deploy recorded before D-054: the official packs version 1, no
    // key 6, and a source without `use` lines whose kind word is `record`.
    constexpr std::string_view old_source =
        "contract Deal\nparties we, customer\nrecord Terms\n  holder customer\n";
    PackSetRead earlier = make_pack_set({}, Officials::before_vocabulary);
    REQUIRE(earlier.set.has_value());
    CHECK(earlier.set->implicit_vocabulary());
    const auto bundle =
        make_source_bundle(old_source, 1, *earlier.set, provider(), crypto::HashAlg::sha256);
    REQUIRE(bundle.has_value());
    CHECK(bundle->vocabulary.empty());
    REQUIRE(bundle->packs.size() == 3);
    for (const PackRef& r : bundle->packs) {
        CHECK(r.version == 1);
    }
    const OpenedSource opened = open_source_bundle(*bundle, provider(), crypto::HashAlg::sha256);
    CHECK(opened.problem == OpenProblem::none);
    REQUIRE(opened.packs.has_value());
    CHECK(opened.packs->officials() == Officials::before_vocabulary);
    CHECK(opened.packs->implicit_vocabulary());
    // Such a bundle names no vocabulary packs: they came later.
    SourceBundle named = *bundle;
    const auto d = digest(*find_vocabulary_pack("commerce"), provider(), crypto::HashAlg::sha256);
    REQUIRE(d.has_value());
    named.vocabulary.push_back(PackRef{"commerce", 2, Bytes(d->bytes().begin(), d->bytes().end())});
    const OpenedSource refused = open_source_bundle(named, provider(), crypto::HashAlg::sha256);
    CHECK(refused.problem == OpenProblem::conflict);
    CHECK(refused.detail.find("before vocabulary packs") != std::string::npos);
    // Today's packs do not read its kind word.
    const OpenedSource today =
        open_source_bundle(bundle_of(pack_set()), provider(), crypto::HashAlg::sha256);
    CHECK(today.packs->officials() == Officials::current);
}

TEST_CASE("a bundle read with version 2 of the official packs opens with them", "[bo][source]") {
    // What a deploy recorded with vocabulary packs, before temperatures and
    // field defaults (G5b): the official packs version 2, key 6, `use`.
    constexpr std::string_view second_source =
        "use commerce\ncontract Deal\nparties we, customer\nthing Terms\n  holder customer\n";
    PackSetRead second = make_pack_set({}, Officials::before_temperature);
    REQUIRE(second.set.has_value());
    CHECK(!second.set->implicit_vocabulary());
    const auto bundle =
        make_source_bundle(second_source, 1, *second.set, provider(), crypto::HashAlg::sha256);
    REQUIRE(bundle.has_value());
    CHECK(bundle->vocabulary.size() == 1);
    REQUIRE(bundle->packs.size() == 3);
    for (const PackRef& r : bundle->packs) {
        CHECK(r.version == 2);
    }
    const OpenedSource opened = open_source_bundle(*bundle, provider(), crypto::HashAlg::sha256);
    CHECK(opened.problem == OpenProblem::none);
    REQUIRE(opened.packs.has_value());
    CHECK(opened.packs->officials() == Officials::before_temperature);
    CHECK(!opened.packs->implicit_vocabulary());
    // Version 2 beside version 3 is two releases.
    SourceBundle mixed = *bundle;
    mixed.packs[0] = bundle_of(pack_set()).packs[0];
    CHECK(open_source_bundle(mixed, provider(), crypto::HashAlg::sha256).problem ==
          OpenProblem::conflict);
}

TEST_CASE("a bundle read with version 3 of the official packs opens with them", "[bo][source]") {
    // What a deploy recorded before vocabulary pack files (G6): the official
    // language packs version 3, which spell the vocabulary packs' words, and
    // key 6 naming version 1 of the vocabulary packs, which spell none.
    constexpr std::string_view third_source =
        "use commerce\ncontract Deal\nparties we, customer\nthing Terms\n  holder customer\n";
    PackSetRead third = make_pack_set({}, Officials::before_pack_files);
    REQUIRE(third.set.has_value());
    const auto bundle =
        make_source_bundle(third_source, 1, *third.set, provider(), crypto::HashAlg::sha256);
    REQUIRE(bundle.has_value());
    REQUIRE(bundle->vocabulary.size() == 1);
    CHECK(bundle->vocabulary[0].version == 1);
    for (const PackRef& r : bundle->packs) {
        CHECK(r.version == 3);
    }
    const OpenedSource opened = open_source_bundle(*bundle, provider(), crypto::HashAlg::sha256);
    CHECK(opened.problem == OpenProblem::none);
    REQUIRE(opened.packs.has_value());
    CHECK(opened.packs->officials() == Officials::before_pack_files);
    // The customer is a word of commerce there too, spelled by the language
    // packs of that release.
    const Meaning* customer = opened.packs->lookup("customer");
    REQUIRE(customer != nullptr);
    CHECK(customer->concept_entry->id == "role.customer");
    // Each release reads with its own versions of the vocabulary packs:
    // version 2 beside the language packs version 3, or version 1 beside
    // version 4, is refused.
    const SourceBundle today = bundle_of(pack_set(), crypto::HashAlg::sha256);
    SourceBundle newer_vocabulary = *bundle;
    const auto v2 = digest(*find_vocabulary_pack("commerce"), provider(), crypto::HashAlg::sha256);
    REQUIRE(v2.has_value());
    newer_vocabulary.vocabulary[0] =
        PackRef{"commerce", 2, Bytes(v2->bytes().begin(), v2->bytes().end())};
    const OpenedSource a =
        open_source_bundle(newer_vocabulary, provider(), crypto::HashAlg::sha256);
    CHECK(a.problem == OpenProblem::conflict);
    CHECK(a.detail.find("commerce version 2 is not of the release") != std::string::npos);
    SourceBundle older_vocabulary = *bundle;
    older_vocabulary.packs = today.packs;
    const OpenedSource b =
        open_source_bundle(older_vocabulary, provider(), crypto::HashAlg::sha256);
    CHECK(b.problem == OpenProblem::conflict);
}

TEST_CASE("decoding refuses bundles of any other shape", "[bo][source]") {
    const SourceBundle bundle = bundle_of(pack_set());
    const Bytes digest = bundle.packs[0].digest;
    const auto base = [&](cbor::Map extra = {}) {
        cbor::Map map{{k(1), cbor::Value::unsigned_integer(1)},
                      {k(2), cbor::Value::unsigned_integer(1)},
                      {k(3), cbor::Value::text("contract X\n")},
                      {k(4), cbor::Value::array({ref("en", 1, digest)})}};
        for (cbor::MapEntry& e : extra) {
            const auto key = e.key.as_int64();
            const auto it = std::ranges::find_if(
                map, [&](const cbor::MapEntry& m) { return m.key.as_int64() == key; });
            if (it != map.end()) {
                it->value = std::move(e.value);
            } else {
                map.push_back(std::move(e));
            }
        }
        return cbor::Value::map(std::move(map));
    };
    CHECK(decode_source_bundle(raw(base())).has_value());
    const auto refused = [&](const cbor::Value& value) {
        return !decode_source_bundle(raw(value)).has_value();
    };
    CHECK(refused(cbor::Value::array({})));
    CHECK(refused(base({{k(1), cbor::Value::unsigned_integer(2)}})));
    CHECK(
        decode_source_bundle(raw(base({{k(1), cbor::Value::unsigned_integer(2)}}))).error().code ==
        Errc::unsupported);
    CHECK(refused(base({{k(2), cbor::Value::unsigned_integer(0)}})));
    CHECK(refused(base({{k(3), cbor::Value::bytes(Bytes{0x41})}})));
    CHECK(refused(base({{k(4), cbor::Value::array({})}})));
    CHECK(refused(base({{k(4), cbor::Value::array({ref("en", 0, digest)})}})));
    CHECK(refused(base({{k(4), cbor::Value::array({ref("en", 1, Bytes(31))})}})));
    CHECK(refused(base({{k(4), cbor::Value::array({ref("-en", 1, digest)})}})));
    CHECK(
        refused(base({{k(4), cbor::Value::array({ref("zh", 1, digest), ref("en", 1, digest)})}})));
    CHECK(
        refused(base({{k(4), cbor::Value::array({ref("en", 1, digest), ref("en", 1, digest)})}})));
    CHECK(refused(base({{k(4), cbor::Value::array({cbor::Value::array({})})}})));
    CHECK(refused(base({{k(5), cbor::Value::array({})}})));
    CHECK(refused(base({{k(5), cbor::Value::array({cbor::Value::text("pack")})}})));
    CHECK(
        refused(base({{k(5), cbor::Value::array({cbor::Value::map({}), cbor::Value::map({})})}})));
    CHECK(refused(base({{k(6), cbor::Value::null()}})));
    CHECK(refused(base({{k(6), cbor::Value::array({})}})));
    CHECK(refused(base({{k(6), cbor::Value::array({ref("finance", 0, digest)})}})));
    CHECK(refused(base({{k(6), cbor::Value::array({ref("finance", 1, Bytes(31))})}})));
    CHECK(refused(base(
        {{k(6), cbor::Value::array({ref("services", 1, digest), ref("finance", 1, digest)})}})));
    CHECK(refused(base(
        {{k(6), cbor::Value::array({ref("finance", 1, digest), ref("finance", 1, digest)})}})));
    CHECK(!refused(base({{k(6), cbor::Value::array({ref("finance", 1, digest)})}})));
    CHECK(refused(base({{k(7), cbor::Value::null()}})));
    CHECK(refused(base({{cbor::Value::text("1"), cbor::Value::null()}})));
    // Key 1 missing.
    CHECK(refused(cbor::Value::map({{k(2), cbor::Value::unsigned_integer(1)},
                                    {k(3), cbor::Value::text("x")},
                                    {k(4), cbor::Value::array({ref("en", 1, digest)})}})));
    // Not deterministic CBOR: a longer head than needed.
    Bytes bytes = raw(base());
    CHECK(bytes[0] == 0xa4);
    Bytes longer = {0xb8, 0x04};
    longer.insert(longer.end(), bytes.begin() + 1, bytes.end());
    CHECK(!decode_source_bundle(longer).has_value());
    // At most a deploy's source.
    CHECK(!decode_source_bundle(Bytes(max_bundle_size + 1)).has_value());
    SourceBundle big = bundle;
    big.source = std::string(max_bundle_size, 'x');
    CHECK(!encode_source_bundle(big).has_value());
}

TEST_CASE("the compiler string", "[bo][source]") {
    const CompilerId id{"0.0.1", 1, 1};
    CHECK(format_compiler(id) == "cexchain-bo 0.0.1; codegen 1; edition 1");
    CHECK(parse_compiler("cexchain-bo 0.0.1; codegen 1; edition 1") == id);
    CHECK(parse_compiler("cexchain-bo 2.10.0-rc1; codegen 12; edition 3") ==
          CompilerId{"2.10.0-rc1", 12, 3});
    for (const std::string_view other :
         {"", "bo 1.0", "cexchain-bo", "cexchain-bo 0.0.1", "cexchain-bo 0.0.1; codegen 1",
          "cexchain-bo 0.0.1; codegen x; edition 1", "cexchain-bo 0.0.1; codegen 01; edition 1",
          "cexchain-bo 0.0.1; codegen 1; edition 1 ", "cexchain-bo ; codegen 1; edition 1",
          "cexchain-bo a b; codegen 1; edition 1", "cexchain-bo 0.0.1;codegen 1; edition 1",
          "cexchain-bo 0.0.1; codegen 99999999999999999999; edition 1",
          "acme-bo 0.0.1; codegen 1; edition 1"}) {
        INFO(other);
        CHECK(!parse_compiler(other).has_value());
    }
}

TEST_CASE("a built contract file (.boc) round-trips and refuses other shapes", "[bo][source]") {
    const SourceBundle bundle = bundle_of(pack_set());
    BuiltContract built;
    built.code = Bytes{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    built.interface = {{"create", protocol::FunctionKind::create},
                       {"sign", protocol::FunctionKind::call}};
    built.compiler = "cexchain-bo 0.0.1; codegen 1; edition 1";
    built.source = encoded(bundle);
    built.name = "Deal";
    built.hash = crypto::HashAlg::sm3;
    const auto bytes = encode_built(built);
    REQUIRE(bytes.has_value());
    const auto decoded = decode_built(*bytes);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == built);

    const auto refused = [&](BuiltContract b) {
        return !encode_built(b).has_value();
    };
    BuiltContract b = built;
    b.interface = {{"sign", protocol::FunctionKind::call}};
    CHECK(refused(b));
    b = built;
    b.interface.clear();
    CHECK(refused(b));
    b = built;
    b.interface.emplace(std::string(65, 'f'), protocol::FunctionKind::call);
    CHECK(refused(b));
    b = built;
    b.compiler.clear();
    CHECK(refused(b));
    b = built;
    b.source = Bytes{0x01};
    CHECK(refused(b));
    b = built;
    b.name.clear();
    CHECK(refused(b));
    b = built;
    b.hash = crypto::HashAlg::sha384;
    CHECK(refused(b));
    b = built;
    b.code.clear();
    CHECK(refused(b));
    // Another language, a missing key, an extra key.
    auto value = cbor::decode(*bytes);
    REQUIRE(value.has_value());
    cbor::Map map = *value->as_map();
    map[2].value = cbor::Value::text("wasm");
    CHECK(!decode_built(raw(cbor::Value::map(map))).has_value());
    map = *value->as_map();
    map.pop_back();
    CHECK(!decode_built(raw(cbor::Value::map(map))).has_value());
    map = *value->as_map();
    map.push_back({k(8), cbor::Value::null()});
    CHECK(!decode_built(raw(cbor::Value::map(map))).has_value());
    CHECK(!decode_built(Bytes(max_built_size + 1)).has_value());
}
