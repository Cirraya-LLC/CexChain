// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

#include <nlohmann/json.hpp>

#include <kanhe/client/errors.hpp>
#include <kanhe/client/public_witness.hpp>
#include <kanhe/client/public_witnesses.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/core/protocol/witness.hpp>
#include <kanhe/node/client.hpp>

#ifndef KANHE_PUBLIC_WITNESSES
#define KANHE_PUBLIC_WITNESSES ""
#endif

namespace kanhe::client {

namespace {

/// The host of a URL, as a name.
std::string host_of(std::string_view url) {
    const std::size_t start = url.find("://");
    url.remove_prefix(start == std::string_view::npos ? 0 : start + 3);
    return std::string(url.substr(0, url.find_first_of(":/")));
}

node::Client witness_client(const std::string& url) {
    auto base = node::Url::parse(url);
    if (!base) {
        throw UsageError{"not a witness URL (https://host[:port][/path]): " + url};
    }
    node::ClientOptions options;
    options.max_body = 64 * 1024;
    return node::Client(std::move(*base), options);
}

/// The witness's answer: a cosignature, or a refusal.
Bytes cosignature_of(const node::http::ClientResponse& response) {
    if (response.status / 100 == 2) {
        return response.body;
    }
    const auto answer =
        nlohmann::json::parse(response.body.begin(), response.body.end(), nullptr, false);
    std::string message = "status " + std::to_string(response.status);
    if (answer.is_object() && answer.contains("error") && answer["error"].is_object()) {
        message = answer["error"].value("message", message);
    }
    throw WitnessRefused{response.status, message};
}

std::uint64_t last_cosigned_size(const ledger::Ledger& ledger, const crypto::PublicKey& key) {
    const auto last = unwrap(ledger.last_cosigned(key), "reading cosignatures");
    return last ? last->tree_size : 0;
}

} // namespace

std::string witness_key_hex(const crypto::PublicKey& key) {
    return to_hex(unwrap(cbor::encode(protocol::encode_public_key(key)), "encoding the key"));
}

crypto::PublicKey witness_key_from_hex(std::string_view hex) {
    const auto bytes = from_hex(hex);
    const auto value =
        bytes ? cbor::decode(*bytes) : Result<cbor::Value>(std::unexpected(bytes.error()));
    auto key = value ? protocol::decode_public_key(*value)
                     : Result<crypto::PublicKey>(std::unexpected(value.error()));
    if (!key) {
        throw UsageError{"not a witness key (hex of a COSE public key)"};
    }
    return std::move(*key);
}

std::vector<UsedWitness> load_used_witnesses(const std::filesystem::path& ledger) {
    const std::filesystem::path path = ledger / witnesses_file;
    if (!std::filesystem::exists(path)) {
        return {};
    }
    const Bytes bytes = read_file(path);
    const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!j.is_array()) {
        throw ActionError{"the witnesses file " + path.string() + " is damaged"};
    }
    std::vector<UsedWitness> out;
    for (const auto& w : j) {
        if (!w.is_object() || !w.contains("name") || !w["name"].is_string() || !w.contains("url") ||
            !w["url"].is_string() || !w.contains("key") || !w["key"].is_string()) {
            throw ActionError{"the witnesses file " + path.string() + " is damaged"};
        }
        try {
            out.push_back({w["name"].get<std::string>(), w["url"].get<std::string>(),
                           witness_key_from_hex(w["key"].get<std::string>()),
                           w.value("added", protocol::Timestamp{0})});
        } catch (const UsageError&) {
            throw ActionError{"the witnesses file " + path.string() + " holds a damaged key"};
        }
    }
    return out;
}

void save_used_witnesses(const std::filesystem::path& ledger,
                         const std::vector<UsedWitness>& witnesses) {
    nlohmann::json j = nlohmann::json::array();
    for (const UsedWitness& w : witnesses) {
        j.push_back({{"name", w.name},
                     {"url", w.url},
                     {"key", witness_key_hex(w.key)},
                     {"added", w.added}});
    }
    const std::string text = j.dump(2) + "\n";
    write_file(ledger / witnesses_file, as_bytes(text), false);
}

WitnessInfo fetch_witness_info(const std::string& url) {
    const auto response =
        unwrap(witness_client(url).request("GET", "/v1/witness"), "reaching " + url);
    const auto j =
        nlohmann::json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (response.status != 200 || !j.is_object() || !j.value("witness", false) ||
        !j.contains("key") || !j["key"].is_string()) {
        throw ActionError{url + " is not a public witness (GET /v1/witness: status " +
                          std::to_string(response.status) + ")"};
    }
    try {
        return {j.value("name", ""), witness_key_from_hex(j["key"].get<std::string>()),
                j.value("ledgers", std::uint64_t{0})};
    } catch (const UsageError&) {
        throw ActionError{url + " gives a malformed witness key"};
    }
}

Bytes register_with_witness(const ledger::Ledger& ledger, const std::string& url,
                            const crypto::PublicKey& key) {
    if (!ledger.latest_checkpoint()) {
        throw ActionError{"the ledger has no checkpoint yet (kanhe checkpoint create)"};
    }
    const protocol::CosignRequest request = unwrap(
        ledger.cosign_request(last_cosigned_size(ledger, key)), "building the cosign request");
    const Bytes body =
        unwrap(encode_witness_registration({unwrap(ledger.entry(0), "reading the genesis entry"),
                                            unwrap(protocol::encode_cosign_request(request),
                                                   "encoding the cosign request")}),
               "encoding the registration");
    return cosignature_of(unwrap(
        witness_client(url).request("POST", "/v1/witness/register", body, "application/cbor"),
        "reaching " + url));
}

std::optional<Bytes> ask_witness(const ledger::Ledger& ledger, const UsedWitness& witness) {
    const auto latest = ledger.latest_checkpoint();
    if (!latest) {
        return std::nullopt;
    }
    const auto last = unwrap(ledger.last_cosigned(witness.key), "reading cosignatures");
    const std::uint64_t old = last ? last->tree_size : 0;
    if (last && old >= latest->checkpoint.tree_size) {
        return std::nullopt;
    }
    const Bytes request = unwrap(
        protocol::encode_cosign_request(unwrap(ledger.cosign_request(old), "the cosign request")),
        "encoding the cosign request");
    return cosignature_of(
        unwrap(witness_client(witness.url)
                   .request("POST", "/v1/witness/cosign", request, "application/cbor"),
               "reaching " + witness.name));
}

bool valid_witness_name(std::string_view name) {
    return !name.empty() && name.size() <= 64 && std::ranges::all_of(name, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '-' || c == '_' || c == '.';
    });
}

Registered register_witness(const ledger::Ledger& ledger, const std::filesystem::path& directory,
                            const std::string& url, const crypto::PublicKey& key,
                            const std::optional<std::string>& name,
                            const std::function<void(ByteView cosignature)>& keep,
                            protocol::Timestamp now) {
    if (!url.starts_with("https://") && !url.starts_with("http://")) {
        throw UsageError{"the witness's URL: https://host[:port]"};
    }
    const WitnessInfo info = fetch_witness_info(url);
    if (info.key != key) {
        throw ActionError{"the witness at " + url +
                          " has another key than the one given: not registered"};
    }
    const std::string chosen =
        name.value_or(valid_witness_name(info.name) ? info.name : host_of(url));
    if (!valid_witness_name(chosen)) {
        throw UsageError{"a witness's name: 1 to 64 letters, digits, '-', '_', or '.'"};
    }
    auto witnesses = load_used_witnesses(directory);
    for (const UsedWitness& w : witnesses) {
        if (w.name == chosen && w.key != key) {
            throw ActionError{"a witness named " + chosen + " is registered already"};
        }
    }
    const Bytes cosignature = register_with_witness(ledger, url, key);
    const auto parsed = unwrap(protocol::parse_cosignature(cosignature), "the cosignature");
    keep(cosignature);
    std::erase_if(witnesses, [&](const UsedWitness& w) { return w.key == key; });
    witnesses.push_back({chosen, url, key, now});
    save_used_witnesses(directory, witnesses);
    return {witnesses.back(), parsed.checkpoint.tree_size};
}

std::vector<UsedWitness> built_in_public_witnesses() {
    std::vector<UsedWitness> out;
    std::string_view list = KANHE_PUBLIC_WITNESSES;
    while (!list.empty()) {
        const std::string_view item = list.substr(0, list.find(','));
        list.remove_prefix(std::min(list.size(), item.size() + 1));
        const std::size_t a = item.find('|');
        const std::size_t b = a == std::string_view::npos ? a : item.find('|', a + 1);
        if (b == std::string_view::npos) {
            continue;
        }
        try {
            out.push_back({std::string(item.substr(0, a)),
                           std::string(item.substr(a + 1, b - a - 1)),
                           witness_key_from_hex(item.substr(b + 1)), 0});
        } catch (const UsageError&) {
            // A malformed entry in the build: left out.
        }
    }
    return out;
}

Bytes cosignature_body(ByteView cosignature, const crypto::PublicKey& witness) {
    return unwrap(cbor::encode(cbor::Value::array(
                      {cbor::Value::bytes(cosignature), protocol::encode_public_key(witness)})),
                  "encoding the cosignature");
}

std::vector<WitnessAsked> ask_used_witnesses(const ledger::Ledger& ledger,
                                             const std::filesystem::path& directory,
                                             const std::function<int(Bytes body)>& keep) {
    std::vector<WitnessAsked> out;
    std::vector<UsedWitness> witnesses;
    try {
        witnesses = load_used_witnesses(directory);
    } catch (const ActionError& e) {
        return {{"", std::nullopt, e.message}};
    }
    for (const UsedWitness& w : witnesses) {
        WitnessAsked asked{w.name, std::nullopt, {}};
        try {
            if (const auto cosignature = ask_witness(ledger, w)) {
                const auto parsed = protocol::parse_cosignature(*cosignature);
                const int status = keep(cosignature_body(*cosignature, w.key));
                if (status / 100 != 2) {
                    asked.problem =
                        "its cosignature was not kept (status " + std::to_string(status) + ")";
                } else if (parsed) {
                    asked.cosigned = parsed->checkpoint.tree_size;
                }
            }
        } catch (const WitnessRefused& e) {
            if (e.status != 429) {
                asked.problem = e.message;
            }
        } catch (const ActionError& e) {
            asked.problem = e.message;
        } catch (const UsageError& e) {
            asked.problem = e.message;
        }
        out.push_back(std::move(asked));
    }
    return out;
}

} // namespace kanhe::client
