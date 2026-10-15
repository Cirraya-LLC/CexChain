// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>

#include <nlohmann/json.hpp>

#include <cexchain/core/bytes.hpp>
#include <cexchain/node/tokens.hpp>

#include "files.hpp"

namespace cexchain::node {

namespace {

constexpr std::array<std::pair<std::string_view, Scope>, 5> scope_table{{
    {"read", Scope::read},
    {"submit", Scope::submit},
    {"admin", Scope::admin},
    {"peer", Scope::peer},
    {"executor", Scope::executor},
}};

} // namespace

Result<Scopes> parse_scopes(std::string_view list) {
    Scopes scopes = 0;
    while (!list.empty()) {
        const std::size_t comma = std::min(list.find(','), list.size());
        const std::string_view name = list.substr(0, comma);
        list.remove_prefix(std::min(comma + 1, list.size()));
        const auto* found =
            std::ranges::find(scope_table, name, &decltype(scope_table)::value_type::first);
        if (found == scope_table.end()) {
            return fail(Errc::invalid_argument,
                        "scopes are read, submit, admin, peer, and executor");
        }
        scopes |= static_cast<Scopes>(found->second);
    }
    if (scopes == 0) {
        return fail(Errc::invalid_argument, "a token needs at least one scope");
    }
    return scopes;
}

std::vector<std::string> scope_names(Scopes scopes) {
    std::vector<std::string> out;
    for (const auto& [name, scope] : scope_table) {
        if (has_scope(scopes, scope)) {
            out.emplace_back(name);
        }
    }
    return out;
}

bool valid_token_name(std::string_view name) {
    return !name.empty() && name.size() <= 64 && std::ranges::all_of(name, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '.' || c == '_' || c == '-';
    });
}

Result<std::vector<ApiToken>> load_tokens(const std::filesystem::path& ledger_directory) {
    auto bytes = detail::read_file(ledger_directory / tokens_file);
    if (!bytes) {
        if (bytes.error().code == Errc::not_found) {
            return std::vector<ApiToken>{};
        }
        return std::unexpected(bytes.error());
    }
    const auto document = nlohmann::json::parse(bytes->begin(), bytes->end(), nullptr, false);
    // (value("version", 0) would throw on a version that is not a number:
    // a reload must fail closed, not keep the old tokens.)
    if (document.is_discarded() || !document.is_object() || !document.contains("version") ||
        !document["version"].is_number_unsigned() ||
        document["version"].get<std::uint64_t>() != 1 || !document.contains("tokens") ||
        !document["tokens"].is_array()) {
        return fail(Errc::malformed, "the API tokens file is malformed");
    }
    std::vector<ApiToken> tokens;
    for (const auto& t : document["tokens"]) {
        if (!t.is_object() || !t.contains("name") || !t["name"].is_string() ||
            !t.contains("sha256") || !t["sha256"].is_string() || !t.contains("scopes") ||
            !t["scopes"].is_array() || !t.contains("created") ||
            !t["created"].is_number_unsigned()) {
            return fail(Errc::malformed, "the API tokens file is malformed");
        }
        ApiToken token;
        token.name = t["name"].get<std::string>();
        token.sha256 = t["sha256"].get<std::string>();
        token.created = t["created"].get<protocol::Timestamp>();
        std::string list;
        for (const auto& s : t["scopes"]) {
            if (!s.is_string()) {
                return fail(Errc::malformed, "the API tokens file is malformed");
            }
            list += (list.empty() ? "" : ",") + s.get<std::string>();
        }
        auto scopes = parse_scopes(list);
        const auto hash = from_hex(token.sha256);
        if (!scopes || !valid_token_name(token.name) || !hash || hash->size() != 32) {
            return fail(Errc::malformed, "the API tokens file is malformed");
        }
        token.scopes = *scopes;
        tokens.push_back(std::move(token));
    }
    return tokens;
}

Status save_tokens(const std::filesystem::path& ledger_directory,
                   const std::vector<ApiToken>& tokens) {
    nlohmann::json list = nlohmann::json::array();
    for (const ApiToken& t : tokens) {
        list.push_back({{"name", t.name},
                        {"scopes", scope_names(t.scopes)},
                        {"sha256", t.sha256},
                        {"created", t.created}});
    }
    const std::string text = nlohmann::json{{"version", 1}, {"tokens", list}}.dump(2) + "\n";
    return detail::write_file(ledger_directory / tokens_file, as_bytes(text), true);
}

std::string generate_token(ledger::Entropy& entropy) {
    return "cxt_" + to_base64url(entropy.bytes<32>());
}

std::string token_hash(const crypto::Provider& provider, std::string_view token) {
    const auto digest = provider.digest(crypto::HashAlg::sha256, as_bytes(token));
    return digest ? to_hex(digest->bytes()) : std::string();
}

const ApiToken* find_token(const std::vector<ApiToken>& tokens, const crypto::Provider& provider,
                           std::string_view presented) {
    const std::string hash = token_hash(provider, presented);
    const ApiToken* found = nullptr;
    for (const ApiToken& t : tokens) {
        // Constant time in the hash: every byte is compared.
        std::size_t difference = t.sha256.size() ^ hash.size();
        for (std::size_t i = 0; i < std::min(t.sha256.size(), hash.size()); ++i) {
            difference |= static_cast<unsigned char>(t.sha256[i] ^ hash[i]);
        }
        if (difference == 0 && found == nullptr) {
            found = &t;
        }
    }
    return found;
}

} // namespace cexchain::node
