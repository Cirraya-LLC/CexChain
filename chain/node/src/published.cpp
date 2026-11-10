// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <system_error>
#include <utility>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/node/published.hpp>

#include "files.hpp"

namespace cexchain::node {

namespace {

constexpr std::size_t token_bytes = 16;
constexpr std::size_t token_length = 22; // base64url without padding

std::filesystem::path published_path(const std::filesystem::path& ledger, std::string_view token) {
    return published_directory(ledger) / (std::string(token) + ".cbor");
}

} // namespace

std::filesystem::path published_directory(const std::filesystem::path& ledger) {
    return ledger / "published";
}

bool valid_published_token(std::string_view token) noexcept {
    return token.size() == token_length && std::ranges::all_of(token, [](char c) {
               return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                      c == '-' || c == '_';
           });
}

Result<Bytes> encode_published(const Published& published) {
    if (published.disclosures.size() > max_published_fields) {
        return fail(Errc::invalid_argument, "a published record discloses at most 64 fields");
    }
    cbor::Array disclosures;
    for (const protocol::FieldDisclosure& d : published.disclosures) {
        cbor::Array path;
        for (const crypto::Digest& node : d.path) {
            path.push_back(cbor::Value::bytes(node.bytes()));
        }
        disclosures.push_back(
            cbor::Value::array({cbor::Value::bytes(d.leaf), cbor::Value::unsigned_integer(d.index),
                                cbor::Value::array(std::move(path))}));
    }
    return cbor::encode(cbor::Value::map(
        {{cbor::Value::integer(1), cbor::Value::bytes(published.record.bytes())},
         {cbor::Value::integer(2), cbor::Value::array(std::move(disclosures))},
         {cbor::Value::integer(3), cbor::Value::unsigned_integer(published.published_at)}}));
}

Result<Published> decode_published(std::string token, ByteView file) {
    const auto value = cbor::decode(file);
    const cbor::Value* record = value ? value->find(1) : nullptr;
    const cbor::Value* list = value ? value->find(2) : nullptr;
    const cbor::Value* at = value ? value->find(3) : nullptr;
    if (record == nullptr || record->as_bytes() == nullptr || list == nullptr ||
        list->as_array() == nullptr || (at != nullptr && !at->as_uint64()) ||
        value->as_map()->size() != (at != nullptr ? 3U : 2U) ||
        list->as_array()->size() > max_published_fields) {
        return fail(Errc::malformed, "a published record's file is damaged");
    }
    Published out;
    out.token = std::move(token);
    auto id = protocol::to_id(*record->as_bytes());
    if (!id) {
        return std::unexpected(id.error());
    }
    out.record = *id;
    out.published_at = at != nullptr ? *at->as_uint64() : 0;
    for (const cbor::Value& item : *list->as_array()) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 3 || (*parts)[0].as_bytes() == nullptr ||
            !(*parts)[1].as_uint64() || (*parts)[2].as_array() == nullptr) {
            return fail(Errc::malformed, "a published record's file is damaged");
        }
        protocol::FieldDisclosure d;
        d.leaf = *(*parts)[0].as_bytes();
        d.index = *(*parts)[1].as_uint64();
        for (const cbor::Value& node : *(*parts)[2].as_array()) {
            auto digest = node.as_bytes() != nullptr
                              ? crypto::Digest::from_bytes(*node.as_bytes())
                              : Result<crypto::Digest>(fail(Errc::malformed, "not a digest"));
            if (!digest) {
                return fail(Errc::malformed, "a published record's file is damaged");
            }
            d.path.push_back(*digest);
        }
        out.disclosures.push_back(std::move(d));
    }
    return out;
}

Result<Published> publish_record(const std::filesystem::path& ledger, const protocol::Id& record,
                                 std::vector<protocol::FieldDisclosure> disclosures,
                                 ledger::Entropy& entropy, ledger::Clock& clock) {
    Published published{to_base64url(entropy.bytes<token_bytes>()), record, std::move(disclosures),
                        clock.now()};
    auto encoded = encode_published(published);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    std::error_code ec;
    std::filesystem::create_directories(published_directory(ledger), ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the published records' directory");
    }
    if (auto s = detail::write_file(published_path(ledger, published.token), *encoded, true); !s) {
        return std::unexpected(s.error());
    }
    return published;
}

Result<Published> load_published(const std::filesystem::path& ledger, std::string_view token) {
    if (!valid_published_token(token)) {
        return fail(Errc::not_found, "nothing is published at that address");
    }
    auto file = detail::read_file(published_path(ledger, token));
    if (!file) {
        return fail(Errc::not_found, "nothing is published at that address");
    }
    return decode_published(std::string(token), *file);
}

std::vector<Published> list_published(const std::filesystem::path& ledger) {
    std::vector<Published> out;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(published_directory(ledger), ec)) {
        const std::string name = entry.path().filename().string();
        if (!name.ends_with(".cbor")) {
            continue;
        }
        if (auto published = load_published(ledger, name.substr(0, name.size() - 5))) {
            out.push_back(std::move(*published));
        }
    }
    std::ranges::sort(out, [](const Published& a, const Published& b) {
        return std::pair(a.published_at, a.token) < std::pair(b.published_at, b.token);
    });
    return out;
}

Status unpublish(const std::filesystem::path& ledger, std::string_view token) {
    std::error_code ec;
    if (!valid_published_token(token) ||
        !std::filesystem::remove(published_path(ledger, token), ec)) {
        return fail(Errc::not_found, "nothing is published at that address");
    }
    return {};
}

} // namespace cexchain::node
