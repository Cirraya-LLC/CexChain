// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Published records: the file's shape, the tokens, and publishing, listing,
// and taking addresses down beside a ledger.

#include <filesystem>
#include <string>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/node/published.hpp>

namespace node = cexchain::node;
namespace cbor = cexchain::cbor;
namespace protocol = cexchain::protocol;
using cexchain::Bytes;

namespace {

protocol::Id id_of(std::uint8_t fill) {
    return *protocol::to_id(Bytes(protocol::id_size, fill));
}

protocol::FieldDisclosure disclosure(std::uint8_t fill, std::uint64_t index) {
    return {Bytes(40, fill),
            index,
            {*cexchain::crypto::Digest::from_bytes(Bytes(32, 1)),
             *cexchain::crypto::Digest::from_bytes(Bytes(32, 2))}};
}

} // namespace

TEST_CASE("a published record's file reads back as written", "[node][published]") {
    const node::Published published{"AAAAAAAAAAAAAAAAAAAAAA",
                                    id_of(5),
                                    {disclosure(7, 0), disclosure(8, 3)},
                                    1'791'244'800'000};
    const auto file = node::encode_published(published);
    REQUIRE(file);
    const auto back = node::decode_published(published.token, *file);
    REQUIRE(back);
    CHECK(*back == published);

    // A request to publish may leave the time out.
    const auto request = cbor::encode(cbor::Value::map(
        {{cbor::Value::integer(1), cbor::Value::bytes(Bytes(protocol::id_size, 5))},
         {cbor::Value::integer(2), cbor::Value::array({})}}));
    const auto untimed = node::decode_published({}, *request);
    REQUIRE(untimed);
    CHECK(untimed->published_at == 0);
    CHECK(untimed->disclosures.empty());

    node::Published crowded = published;
    crowded.disclosures.assign(node::max_published_fields + 1, disclosure(7, 0));
    CHECK_FALSE(node::encode_published(crowded));
}

TEST_CASE("a damaged published record's file is refused", "[node][published]") {
    const auto refused = [](const cbor::Value& value) {
        return !node::decode_published({}, *cbor::encode(value));
    };
    const auto record = cbor::Value::bytes(Bytes(protocol::id_size, 5));
    const auto entry = [](cbor::Value path) {
        return cbor::Value::array(
            {cbor::Value::bytes(Bytes(40, 7)), cbor::Value::unsigned_integer(0), std::move(path)});
    };
    CHECK(refused(cbor::Value::text("published")));
    CHECK(refused(cbor::Value::map({{cbor::Value::integer(1), record}})));
    CHECK(refused(cbor::Value::map({{cbor::Value::integer(1), cbor::Value::bytes(Bytes(31, 5))},
                                    {cbor::Value::integer(2), cbor::Value::array({})}})));
    CHECK(refused(cbor::Value::map({{cbor::Value::integer(1), record},
                                    {cbor::Value::integer(2), cbor::Value::array({})},
                                    {cbor::Value::integer(3), cbor::Value::text("now")}})));
    CHECK(refused(cbor::Value::map({{cbor::Value::integer(1), record},
                                    {cbor::Value::integer(2), cbor::Value::array({})},
                                    {cbor::Value::integer(4), cbor::Value::unsigned_integer(1)}})));
    // A path node that is not a digest, a disclosure of the wrong shape.
    CHECK(refused(cbor::Value::map(
        {{cbor::Value::integer(1), record},
         {cbor::Value::integer(2),
          cbor::Value::array({entry(cbor::Value::array({cbor::Value::bytes(Bytes{})}))})}})));
    CHECK(refused(cbor::Value::map(
        {{cbor::Value::integer(1), record},
         {cbor::Value::integer(2),
          cbor::Value::array({cbor::Value::array({cbor::Value::bytes(Bytes(40, 7))})})}})));
    CHECK(refused(
        cbor::Value::map({{cbor::Value::integer(1), record},
                          {cbor::Value::integer(2),
                           cbor::Value::array(std::vector<cbor::Value>(
                               node::max_published_fields + 1, entry(cbor::Value::array({}))))}})));
}

TEST_CASE("a token is 22 base64url characters", "[node][published]") {
    CHECK(node::valid_published_token("abcdefghijklmnopqrst-_"));
    CHECK(node::valid_published_token("ABCDEFGHIJKLMNOPQRST09"));
    CHECK_FALSE(node::valid_published_token("abcdefghijklmnopqrstu"));
    CHECK_FALSE(node::valid_published_token("abcdefghijklmnopqrstuvw"));
    CHECK_FALSE(node::valid_published_token("abcdefghijklmnopqrst+/"));
    CHECK_FALSE(node::valid_published_token("../../../../ledger.key"));
    CHECK_FALSE(node::valid_published_token(""));
}

TEST_CASE("records are published, listed, and taken down", "[node][published]") {
    const auto dir = std::filesystem::temp_directory_path() /
                     ("cexchain-published-test-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    cexchain::ledger::SeededEntropy entropy(7);
    cexchain::ledger::ManualClock clock(1'791'244'800'000);
    CHECK(node::list_published(dir).empty());

    const auto first = node::publish_record(dir, id_of(1), {disclosure(7, 0)}, entropy, clock);
    REQUIRE(first);
    CHECK(node::valid_published_token(first->token));
    CHECK(first->published_at == 1'791'244'800'000);
    clock.advance(1000);
    const auto second = node::publish_record(dir, id_of(1), {}, entropy, clock);
    REQUIRE(second);
    CHECK(second->token != first->token);
    const auto perms =
        std::filesystem::status(node::published_directory(dir) / (first->token + ".cbor"))
            .permissions();
    CHECK((perms & (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) ==
          std::filesystem::perms::none);

    const auto loaded = node::load_published(dir, first->token);
    REQUIRE(loaded);
    CHECK(*loaded == *first);
    // Oldest first; other names in the directory are not published records.
    std::filesystem::copy_file(node::published_directory(dir) / (first->token + ".cbor"),
                               node::published_directory(dir) / "x.cbor");
    const auto list = node::list_published(dir);
    REQUIRE(list.size() == 2);
    CHECK(list[0] == *first);
    CHECK(list[1] == *second);

    CHECK(node::unpublish(dir, first->token));
    const auto gone = node::load_published(dir, first->token);
    REQUIRE_FALSE(gone);
    CHECK(gone.error().code == cexchain::Errc::not_found);
    const auto again = node::unpublish(dir, first->token);
    REQUIRE_FALSE(again);
    CHECK(again.error().code == cexchain::Errc::not_found);
    CHECK_FALSE(node::unpublish(dir, "x"));
    CHECK_FALSE(node::load_published(dir, "x"));
    CHECK(node::list_published(dir).size() == 1);
    std::filesystem::remove_all(dir);
}
