// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/record.hpp>
#include <cexchain/ledger/environment.hpp>

/// Records published at a private address: `GET /c/TOKEN` gives anyone who
/// holds the address the record's evidence as it is now (revoked or replaced
/// since, it says so), with the fields chosen when it was published
/// disclosed, as a printed certificate's QR code needs. The token is 128
/// random bits, not derived from the record, so published records cannot be
/// listed or guessed; the fields are the ones the holder of the address may
/// see anyway (those printed on the paper).
///
///   kept at  <ledger>/published/<token>.cbor
///   file     {1: record id, 2: [* [leaf, index, [* digest]]], 3: published at (ms)}
namespace cexchain::node {

struct Published {
    /// 22 base64url characters: 16 random bytes.
    std::string token;
    protocol::Id record;
    /// Each as an evidence bundle carries it (spec section 10).
    std::vector<protocol::FieldDisclosure> disclosures;
    protocol::Timestamp published_at = 0;

    friend bool operator==(const Published&, const Published&) = default;
};

/// At most this many disclosed fields a published record carries.
inline constexpr std::size_t max_published_fields = 64;

[[nodiscard]] std::filesystem::path published_directory(const std::filesystem::path& ledger);
[[nodiscard]] bool valid_published_token(std::string_view token) noexcept;

/// The file. A request to publish (POST /v1/published) is the same, key 3
/// optional and ignored: the server chooses the token and the time.
[[nodiscard]] Result<Bytes> encode_published(const Published& published);
[[nodiscard]] Result<Published> decode_published(std::string token, ByteView file);

/// Publishes `record` with `disclosures` under a new token from `entropy`,
/// kept privately and durably; returns what was kept.
[[nodiscard]] Result<Published> publish_record(const std::filesystem::path& ledger,
                                               const protocol::Id& record,
                                               std::vector<protocol::FieldDisclosure> disclosures,
                                               ledger::Entropy& entropy, ledger::Clock& clock);
/// The record published under `token`; Errc::not_found if none.
[[nodiscard]] Result<Published> load_published(const std::filesystem::path& ledger,
                                               std::string_view token);
/// Every published record, oldest first (files that do not read are left out).
[[nodiscard]] std::vector<Published> list_published(const std::filesystem::path& ledger);
/// Takes the address down (the record stays on the ledger); Errc::not_found
/// if nothing is published under `token`.
[[nodiscard]] Status unpublish(const std::filesystem::path& ledger, std::string_view token);

} // namespace cexchain::node
