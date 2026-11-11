// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/network.hpp>
#include <kanhe/node/network_witnesses.hpp>

/// The open-network witnesses a ledger asks to cosign its checkpoints (spec
/// v0.13; serve asks each one every --network-interval), kept in
/// network-witnesses.json in the ledger directory:
///   [{"url": "https://...", "vkey": "<verifier key>", "added": ms}, ...]
/// Nothing is sent to register one: a network's maintainers configure its
/// witnesses with the ledger's entry (log_list_entry). A witness's name is
/// its verifier key's.
namespace kanhe::client {

inline constexpr std::string_view network_witnesses_file = "network-witnesses.json";

struct UsedNetworkWitness {
    node::NetworkWitness witness;
    protocol::Timestamp added = 0;
};

/// Throws ActionError if the file is damaged; none if there is no file.
[[nodiscard]] std::vector<UsedNetworkWitness>
load_network_witnesses(const std::filesystem::path& ledger, const crypto::Provider& provider);
void save_network_witnesses(const std::filesystem::path& ledger,
                            const std::vector<UsedNetworkWitness>& witnesses);

/// This ledger's entry in an open network's list of logs (the
/// witness-network log-list format): its note key's verifier key (whose
/// name is the origin), the add-checkpoint requests it may make a day, and
/// how to reach its operator.
[[nodiscard]] std::string log_list_entry(const protocol::network::VerifierKey& note_key,
                                         std::uint64_t per_day, std::string_view contact);

} // namespace kanhe::client
