// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <format>

#include <nlohmann/json.hpp>

#include <cexchain/client/errors.hpp>
#include <cexchain/client/network_witnesses.hpp>
#include <cexchain/client/support.hpp>

namespace cexchain::client {

std::vector<UsedNetworkWitness> load_network_witnesses(const std::filesystem::path& ledger,
                                                       const crypto::Provider& provider) {
    const std::filesystem::path path = ledger / network_witnesses_file;
    if (!std::filesystem::exists(path)) {
        return {};
    }
    const Bytes bytes = read_file(path);
    const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!j.is_array()) {
        throw ActionError{"the network witnesses file " + path.string() + " is damaged"};
    }
    std::vector<UsedNetworkWitness> out;
    for (const auto& w : j) {
        if (!w.is_object() || !w.contains("url") || !w["url"].is_string() || !w.contains("vkey") ||
            !w["vkey"].is_string()) {
            throw ActionError{"the network witnesses file " + path.string() + " is damaged"};
        }
        auto key = protocol::network::parse_verifier_key(provider, w["vkey"].get<std::string>());
        if (!key) {
            throw ActionError{"the network witnesses file " + path.string() +
                              " holds a damaged verifier key"};
        }
        out.push_back({{w["url"].get<std::string>(), std::move(*key)},
                       w.value("added", protocol::Timestamp{0})});
    }
    return out;
}

void save_network_witnesses(const std::filesystem::path& ledger,
                            const std::vector<UsedNetworkWitness>& witnesses) {
    nlohmann::json j = nlohmann::json::array();
    for (const UsedNetworkWitness& w : witnesses) {
        j.push_back({{"url", w.witness.url},
                     {"vkey", protocol::network::verifier_key_text(w.witness.key)},
                     {"added", w.added}});
    }
    const std::string text = j.dump(2) + "\n";
    write_file(ledger / network_witnesses_file, as_bytes(text), false);
}

std::string log_list_entry(const protocol::network::VerifierKey& note_key, std::uint64_t per_day,
                           std::string_view contact) {
    return std::format("vkey {}\nqpd {}\ncontact {}\n",
                       protocol::network::verifier_key_text(note_key), per_day, contact);
}

} // namespace cexchain::client
