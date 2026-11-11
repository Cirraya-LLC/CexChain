// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <set>
#include <system_error>

#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/memberships.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/tokens.hpp>
#include <cexchain/node/trust.hpp>

#include "files.hpp"

namespace cexchain::node {

namespace {

using json = nlohmann::json;

std::filesystem::path trust_directory(const std::filesystem::path& ledger) {
    return ledger / "trust";
}

std::filesystem::path nodes_file(const std::filesystem::path& ledger) {
    return trust_directory(ledger) / "nodes.json";
}

} // namespace

Result<std::vector<TrustNodeEntry>>
load_trust_nodes(const std::filesystem::path& ledger_directory) {
    auto bytes = detail::read_file(nodes_file(ledger_directory));
    if (!bytes) {
        if (bytes.error().code == Errc::not_found) {
            return std::vector<TrustNodeEntry>{};
        }
        return std::unexpected(bytes.error());
    }
    const auto document = json::parse(bytes->begin(), bytes->end(), nullptr, false);
    if (document.is_discarded() || !document.is_object() || document.value("version", 0) != 1 ||
        !document.contains("nodes") || !document["nodes"].is_array()) {
        return fail(Errc::malformed, "the trust nodes file is malformed");
    }
    std::vector<TrustNodeEntry> nodes;
    for (const auto& n : document["nodes"]) {
        if (!n.is_object() || !n.value("name", json()).is_string() ||
            !n.value("ledger_id", json()).is_string() || !n.value("url", json()).is_string() ||
            !n.value("added", json()).is_number_unsigned()) {
            return fail(Errc::malformed, "the trust nodes file is malformed");
        }
        const auto id_bytes = from_hex(n["ledger_id"].get<std::string>());
        const auto id = id_bytes ? protocol::to_id(*id_bytes)
                                 : Result<protocol::Id>(std::unexpected(id_bytes.error()));
        if (!id) {
            return fail(Errc::malformed, "the trust nodes file is malformed");
        }
        nodes.push_back({n["name"].get<std::string>(), *id, n["url"].get<std::string>(),
                         n["added"].get<protocol::Timestamp>()});
    }
    return nodes;
}

Status save_trust_nodes(const std::filesystem::path& ledger_directory,
                        const std::vector<TrustNodeEntry>& nodes) {
    if (nodes.size() > protocol::max_membership_proofs) {
        return fail(Errc::limit_exceeded, "a ledger lists at most 16 trust nodes");
    }
    std::set<std::string> names;
    std::set<protocol::IdKey> ledgers;
    json list = json::array();
    for (const TrustNodeEntry& n : nodes) {
        if (!valid_token_name(n.name) || !names.insert(n.name).second ||
            !ledgers.insert(protocol::key_of(n.ledger_id)).second) {
            return fail(Errc::invalid_argument, "trust nodes have unique names and ledgers");
        }
        list.push_back({{"name", n.name},
                        {"ledger_id", to_hex(n.ledger_id.bytes())},
                        {"url", n.url},
                        {"added", n.added}});
    }
    std::error_code ec;
    std::filesystem::create_directories(trust_directory(ledger_directory), ec);
    const std::string text = json{{"version", 1}, {"nodes", list}}.dump(2) + "\n";
    return detail::write_file(nodes_file(ledger_directory), as_bytes(text), true);
}

std::filesystem::path membership_proof_path(const std::filesystem::path& ledger_directory,
                                            const protocol::Id& node) {
    return trust_directory(ledger_directory) / "proofs" / (to_hex(node.bytes()) + ".cbor");
}

Result<protocol::EvidenceReport> check_membership_proof(const crypto::Provider& provider,
                                                        ByteView proof, const protocol::Id& node,
                                                        const protocol::Id& member) {
    // Verified as the member's own evidence would carry it (spec section
    // 11, step 9), so that what is kept never fails what it is added to.
    auto decoded = protocol::decode_bundle(proof);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    if (!decoded->memberships.empty()) {
        return fail(Errc::verification_failed, "a membership proof carries membership proofs");
    }
    protocol::VerifyOptions options;
    options.expected_ledger = node;
    auto report = protocol::verify_bundle(provider, proof, options);
    if (!report) {
        return std::unexpected(report.error());
    }
    if (!report->complete) {
        return fail(Errc::verification_failed, "the membership proof is not complete");
    }
    if (report->record_type != protocol::membership_type || !report->metadata) {
        return fail(Errc::verification_failed, "the proof is not of a membership");
    }
    auto membership = protocol::decode_membership(*report->metadata);
    if (!membership) {
        return std::unexpected(membership.error());
    }
    if (membership->member != member) {
        return fail(Errc::verification_failed, "the membership names another ledger");
    }
    return report;
}

std::vector<Bytes> kept_membership_proofs(const std::filesystem::path& ledger_directory) {
    std::vector<Bytes> out;
    const auto nodes = load_trust_nodes(ledger_directory);
    if (!nodes) {
        return out;
    }
    for (const TrustNodeEntry& n : *nodes) {
        auto bytes = detail::read_file(membership_proof_path(ledger_directory, n.ledger_id));
        if (bytes && protocol::decode_bundle(*bytes)) {
            out.push_back(std::move(*bytes));
        }
    }
    return out;
}

Result<protocol::EvidenceReport>
fetch_membership_proof(const crypto::Provider& provider,
                       const std::filesystem::path& ledger_directory, const TrustNodeEntry& node,
                       const protocol::Id& member) {
    auto url = Url::parse(node.url);
    if (!url) {
        return std::unexpected(url.error());
    }
    const Client client(std::move(*url), ClientOptions{});
    auto response = client.request("GET", "/m/" + to_hex(member.bytes()));
    if (!response) {
        return std::unexpected(response.error());
    }
    if (response->status == 404) {
        return fail(Errc::not_found, "the trust node names this ledger in no membership");
    }
    if (response->status != 200) {
        return fail(Errc::unavailable, "the trust node did not answer with a proof");
    }
    auto report = check_membership_proof(provider, response->body, node.ledger_id, member);
    if (!report) {
        return std::unexpected(report.error());
    }
    const auto path = membership_proof_path(ledger_directory, node.ledger_id);
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (auto written = detail::write_file(path, response->body, false); !written) {
        return std::unexpected(written.error());
    }
    return report;
}

void add_membership_proofs(const std::filesystem::path& ledger_directory,
                           std::string_view record_type, protocol::EvidenceBundle& bundle) {
    if (record_type != protocol::membership_type) {
        bundle.memberships = kept_membership_proofs(ledger_directory);
    }
}

std::optional<protocol::Id> MembershipIndex::newest(const crypto::Provider& provider,
                                                    const ledger::Ledger& ledger,
                                                    const protocol::Id& member) {
    // The memberships, by their registration; the ones not read yet are
    // read from the log, outside the state's lock.
    std::vector<std::pair<protocol::Id, std::uint64_t>> memberships;
    ledger.read_state([&](const protocol::LedgerState& state) {
        for (const auto& [key, record] : state.records()) {
            if (record.record_type == protocol::membership_type && !record.history.empty()) {
                memberships.emplace_back(protocol::Id(record.id), record.history.front());
            }
        }
    });
    const std::scoped_lock lock(mutex_);
    std::optional<std::pair<std::uint64_t, protocol::Id>> best;
    for (const auto& [id, index] : memberships) {
        auto known = known_.find(protocol::key_of(id));
        if (known == known_.end()) {
            const auto metadata = record_metadata(provider, ledger, id);
            const auto membership =
                metadata ? protocol::decode_membership(*metadata)
                         : Result<protocol::Membership>(std::unexpected(metadata.error()));
            if (!membership) {
                continue;
            }
            known =
                known_.emplace(protocol::key_of(id), std::pair{index, membership->member}).first;
        }
        if (known->second.second == member && (!best || known->second.first > best->first)) {
            best = std::pair{known->second.first, id};
        }
    }
    return best ? std::optional(best->second) : std::nullopt;
}

} // namespace cexchain::node
