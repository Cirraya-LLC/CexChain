// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Kept files: their shape, the submission's list of them, the check against
// the attachment they are for, and storing each once.

#include <filesystem>
#include <string>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/node/record_files.hpp>

namespace node = cexchain::node;
namespace cbor = cexchain::cbor;
using cexchain::Bytes;

namespace {

Bytes sealed_of(std::size_t content_size, std::uint8_t fill = 9) {
    return *cbor::encode(cbor::Value::map(
        {{cbor::Value::integer(1), cbor::Value::unsigned_integer(1)},
         {cbor::Value::integer(2),
          cbor::Value::array({cbor::Value::unsigned_integer(32), cbor::Value::unsigned_integer(1),
                              cbor::Value::unsigned_integer(2)})},
         {cbor::Value::integer(3), cbor::Value::bytes(Bytes(32, 7))},
         {cbor::Value::integer(4),
          cbor::Value::bytes(Bytes(content_size + node::sealed_file_overhead, fill))}}));
}

cexchain::protocol::RecordRegisterBody registration() {
    cexchain::protocol::RecordRegisterBody body;
    body.attachments.push_back({"photo.jpg", "image/jpeg", 12, Bytes(32, 1)});
    body.attachments.push_back(
        {"big.bin", "application/octet-stream", node::max_record_file + 1, Bytes(32, 2)});
    return body;
}

} // namespace

TEST_CASE("a kept file is checked against the attachment it is for", "[node][files]") {
    const auto body = registration();
    CHECK(node::check_sealed_file(body, {0, sealed_of(12)}));
    CHECK_FALSE(node::check_sealed_file(body, {0, sealed_of(11)}));
    CHECK_FALSE(node::check_sealed_file(body, {2, sealed_of(12)}));
    // Larger than a kept file may be, whatever it holds.
    CHECK_FALSE(node::check_sealed_file(body, {1, sealed_of(12)}));
    CHECK_FALSE(node::check_sealed_file(body, {0, Bytes{1, 2, 3}}));
    const auto box = node::parse_sealed_box(sealed_of(12));
    REQUIRE(box);
    CHECK(box->suite == std::array<std::uint64_t, 3>{32, 1, 2});
    CHECK(box->ciphertext.size() == 28);
}

TEST_CASE("a submission's files ascend and differ", "[node][files]") {
    const std::vector<node::SealedFile> files{{0, sealed_of(1)}, {3, sealed_of(2)}};
    const auto decoded = node::decode_sealed_files(node::encode_sealed_files(files));
    REQUIRE(decoded);
    CHECK(*decoded == files);
    const std::vector<node::SealedFile> backwards{{3, sealed_of(1)}, {0, sealed_of(2)}};
    CHECK_FALSE(node::decode_sealed_files(node::encode_sealed_files(backwards)));
    const std::vector<node::SealedFile> twice{{1, sealed_of(1)}, {1, sealed_of(1)}};
    CHECK_FALSE(node::decode_sealed_files(node::encode_sealed_files(twice)));
    CHECK_FALSE(node::decode_sealed_files(cbor::Value::text("files")));
    CHECK_FALSE(node::decode_sealed_files(node::encode_sealed_files(files), 1));
}

TEST_CASE("a kept file is stored once", "[node][files]") {
    const auto dir = std::filesystem::temp_directory_path() /
                     ("cexchain-files-test-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    const cexchain::protocol::Id record{};
    CHECK(node::kept_record_files(dir, record).empty());
    REQUIRE(node::store_record_file(dir, record, {1, sealed_of(4)}));
    // The same bytes again are a retry; other bytes are refused.
    CHECK(node::store_record_file(dir, record, {1, sealed_of(4)}));
    const auto other = node::store_record_file(dir, record, {1, sealed_of(4, 8)});
    REQUIRE_FALSE(other);
    CHECK(other.error().code == cexchain::Errc::rejected);
    REQUIRE(node::store_record_file(dir, record, {0, sealed_of(2)}));
    // Names the store never writes are not kept files.
    std::filesystem::copy_file(node::record_file_path(dir, record, 0),
                               node::record_files_directory(dir, record) / "01.cbor");
    std::filesystem::copy_file(node::record_file_path(dir, record, 0),
                               node::record_files_directory(dir, record) / "x.cbor");
    CHECK(node::kept_record_files(dir, record) == std::vector<std::uint64_t>{0, 1});
    CHECK(node::remove_record_file(dir, record, 0));
    CHECK_FALSE(node::remove_record_file(dir, record, 0));
    CHECK(node::kept_record_files(dir, record) == std::vector<std::uint64_t>{1});
    std::filesystem::remove_all(dir);
}
