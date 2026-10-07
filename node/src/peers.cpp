// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <array>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/tokens.hpp>

#include "files.hpp"

namespace cexchain::node {

namespace {

using json = nlohmann::json;

std::optional<std::string> optional_text(const json& j, const char* key) {
    if (j.contains(key) && j[key].is_string()) {
        return j[key].get<std::string>();
    }
    return std::nullopt;
}

} // namespace

Result<std::vector<Peer>> load_peers(const std::filesystem::path& ledger_directory) {
    auto bytes = detail::read_file(ledger_directory / peers_file);
    if (!bytes) {
        if (bytes.error().code == Errc::not_found) {
            return std::vector<Peer>{};
        }
        return std::unexpected(bytes.error());
    }
    const auto document = json::parse(bytes->begin(), bytes->end(), nullptr, false);
    if (document.is_discarded() || !document.is_object() || document.value("version", 0) != 1 ||
        !document.contains("peers") || !document["peers"].is_array()) {
        return fail(Errc::malformed, "the peers file is malformed");
    }
    std::vector<Peer> peers;
    for (const auto& p : document["peers"]) {
        if (!p.is_object() || !p.contains("name") || !p["name"].is_string() ||
            !p.contains("ledger_id") || !p["ledger_id"].is_string()) {
            return fail(Errc::malformed, "the peers file is malformed");
        }
        Peer peer;
        peer.name = p["name"].get<std::string>();
        const auto id_bytes = from_hex(p["ledger_id"].get<std::string>());
        const auto id = id_bytes ? protocol::to_id(*id_bytes)
                                 : Result<protocol::Id>(std::unexpected(id_bytes.error()));
        if (!valid_token_name(peer.name) || !id) {
            return fail(Errc::malformed, "the peers file is malformed");
        }
        peer.ledger_id = *id;
        peer.url = optional_text(p, "url");
        peer.token_file = optional_text(p, "token_file");
        peer.ca_file = optional_text(p, "ca_file");
        if (const auto key = optional_text(p, "witness_key")) {
            const auto encoded = from_hex(*key);
            const auto value = encoded ? cbor::decode(*encoded)
                                       : Result<cbor::Value>(std::unexpected(encoded.error()));
            auto public_key = value ? protocol::decode_public_key(*value)
                                    : Result<crypto::PublicKey>(std::unexpected(value.error()));
            if (!public_key) {
                return fail(Errc::malformed, "the peers file holds a malformed witness key");
            }
            peer.witness_key = std::move(*public_key);
        }
        peer.added = p.value("added", protocol::Timestamp{0});
        peers.push_back(std::move(peer));
    }
    return peers;
}

Status save_peers(const std::filesystem::path& ledger_directory, const std::vector<Peer>& peers) {
    json list = json::array();
    for (const Peer& p : peers) {
        json j = {{"name", p.name}, {"ledger_id", to_hex(p.ledger_id.bytes())}, {"added", p.added}};
        if (p.url) {
            j["url"] = *p.url;
        }
        if (p.token_file) {
            j["token_file"] = *p.token_file;
        }
        if (p.ca_file) {
            j["ca_file"] = *p.ca_file;
        }
        if (p.witness_key) {
            auto encoded = cbor::encode(protocol::encode_public_key(*p.witness_key));
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            j["witness_key"] = to_hex(*encoded);
        }
        list.push_back(std::move(j));
    }
    const std::string text = json{{"version", 1}, {"peers", list}}.dump(2) + "\n";
    return detail::write_file(ledger_directory / peers_file, as_bytes(text), true);
}

std::filesystem::path access_path(const std::filesystem::path& ledger_directory, AccessBox box,
                                  const protocol::Id& id) {
    static constexpr std::array<std::string_view, 5> names{"inbox", "outbox", "receipts",
                                                           "requests", "deliveries"};
    return ledger_directory / "access" / names[static_cast<std::size_t>(box)] /
           (to_hex(id.bytes()) + ".cbor");
}

Result<cbor::Value> record_metadata(const crypto::Provider& provider, const ledger::Ledger& ledger,
                                    const protocol::Id& record) {
    std::optional<std::uint64_t> first;
    ledger.read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* found = state.record(record);
        if (found != nullptr && !found->history.empty()) {
            first = found->history.front();
        }
    });
    if (!first) {
        return fail(Errc::not_found, "no such record");
    }
    auto bytes = ledger.entry(*first);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    auto entry = protocol::decode_log_entry(*bytes);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    auto statement = protocol::parse_statement(provider, entry->statement, ledger.hash());
    if (!statement) {
        return std::unexpected(statement.error());
    }
    const auto* body = std::get_if<protocol::RecordRegisterBody>(&statement->statement.body);
    if (body == nullptr || !body->metadata) {
        return fail(Errc::not_found, "the record has no metadata");
    }
    return *body->metadata;
}

Result<Bytes> delivery_for_grant(const std::filesystem::path& ledger_directory,
                                 const protocol::Id& request, const protocol::Id& grant) {
    auto bytes = detail::read_file(access_path(ledger_directory, AccessBox::outbox, request));
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    // Our own file: decoding is enough to tell which grant it was made under.
    auto delivery = protocol::decode_delivery(*bytes);
    if (!delivery) {
        return std::unexpected(delivery.error());
    }
    auto bundle = protocol::decode_bundle(delivery->grant_bundle);
    if (!bundle) {
        return std::unexpected(bundle.error());
    }
    if (bundle->record != grant) {
        return fail(Errc::not_found, "the delivery for this request was made under another grant");
    }
    return bytes;
}

Status store_receipt(const std::filesystem::path& ledger_directory, const protocol::Id& grant,
                     ByteView receipt) {
    const auto path = access_path(ledger_directory, AccessBox::receipts, grant);
    if (auto existing = detail::read_file(path)) {
        if (std::ranges::equal(*existing, receipt)) {
            return {};
        }
        return fail(Errc::rejected, "a different receipt for this grant is already stored");
    } else if (existing.error().code != Errc::not_found) {
        return std::unexpected(existing.error());
    }
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the access directory");
    }
    return detail::write_file(path, receipt, true);
}

} // namespace cexchain::node
