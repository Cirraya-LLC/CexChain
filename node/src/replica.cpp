// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <format>
#include <system_error>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/replica.hpp>

#include "files.hpp"

namespace cexchain::node {

namespace {

using json = nlohmann::json;

constexpr std::uint64_t batch = 1000;

/// GETs `path` and checks the status.
Result<Bytes> fetch(const Client& primary, const std::string& path, bool allow_missing = false) {
    auto response = primary.request("GET", path);
    if (!response) {
        return std::unexpected(response.error());
    }
    switch (response->status) {
    case 200:
        return std::move(response->body);
    case 401:
    case 403:
        return fail(Errc::rejected, "the primary refused the API token");
    case 404:
        if (allow_missing) {
            return fail(Errc::not_found, "not found on the primary");
        }
        return fail(Errc::not_found, "the primary does not serve this (is the URL right?)");
    default:
        return fail(Errc::unavailable, "the primary answered with an error");
    }
}

/// GETs a CBOR array of byte strings (or of [bytes, value] pairs).
Result<cbor::Array> fetch_array(const Client& primary, const std::string& path) {
    auto body = fetch(primary, path);
    if (!body) {
        return std::unexpected(body.error());
    }
    cbor::DecodeOptions options;
    options.max_items = 1u << 22;
    auto value = cbor::decode(*body, options);
    if (!value || value->as_array() == nullptr) {
        return fail(Errc::malformed, "the primary sent a malformed list");
    }
    return *value->as_array();
}

Result<std::vector<Bytes>> fetch_byte_strings(const Client& primary, const std::string& path) {
    auto items = fetch_array(primary, path);
    if (!items) {
        return std::unexpected(items.error());
    }
    std::vector<Bytes> out;
    for (const cbor::Value& item : *items) {
        if (item.as_bytes() == nullptr) {
            return fail(Errc::malformed, "the primary sent a malformed list");
        }
        out.push_back(*item.as_bytes());
    }
    return out;
}

/// Appends the primary's entries until the replica has `size`.
Status catch_up(const Client& primary, ledger::Ledger& replica, std::uint64_t size,
                SyncReport& report, const std::function<void(const SyncReport&)>& progress) {
    while (replica.size() < size) {
        const std::uint64_t count = std::min(batch, size - replica.size());
        auto entries = fetch_byte_strings(
            primary, std::format("/v1/entries?start={}&count={}", replica.size(), count));
        if (!entries) {
            return std::unexpected(entries.error());
        }
        if (entries->empty()) {
            return fail(Errc::verification_failed,
                        "the primary does not have the entries its checkpoint covers");
        }
        const std::uint64_t before = replica.size();
        if (auto s = replica.append_entries(*entries); !s) {
            report.entries += replica.size() - before;
            return s;
        }
        report.entries += replica.size() - before;
        report.size = replica.size();
        if (progress) {
            progress(report);
        }
    }
    return {};
}

Status sync_vault(const Client& primary, const ledger::Ledger& replica,
                  const std::filesystem::path& directory, SyncReport& report) {
    auto remote_key = fetch(primary, "/v1/vault/public-key", true);
    if (!remote_key) {
        return remote_key.error().code == Errc::not_found ? Status{}
                                                          : std::unexpected(remote_key.error());
    }
    const std::filesystem::path vault = directory / "vault";
    const std::filesystem::path records = vault / "records";
    std::error_code ec;
    std::filesystem::create_directories(records, ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the vault directory");
    }
    std::filesystem::permissions(vault, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    // A new vault key (after `vault rekey`) re-seals every record.
    const auto local_key = detail::read_file(vault / "vault.pub");
    const bool rekeyed = !local_key || *local_key != *remote_key;
    if (rekeyed) {
        if (auto s = detail::write_file(vault / "vault.pub", *remote_key, false); !s) {
            return s;
        }
        ++report.vault_files;
    }
    for (const auto& [id, record] : replica.state().records()) {
        const std::string name = to_hex(id);
        const std::filesystem::path file = records / (name + ".cbor");
        if (!rekeyed && std::filesystem::exists(file, ec)) {
            continue;
        }
        auto sealed = fetch(primary, "/v1/vault/records/" + name, true);
        if (!sealed) {
            if (sealed.error().code == Errc::not_found) {
                continue; // nothing sealed for it on the primary
            }
            return std::unexpected(sealed.error());
        }
        if (auto s = detail::write_file(file, *sealed, true); !s) {
            return s;
        }
        ++report.vault_files;
    }
    return {};
}

} // namespace

Result<std::optional<ReplicaInfo>> read_replica_info(const std::filesystem::path& directory) {
    auto bytes = detail::read_file(directory / replica_file);
    if (!bytes) {
        if (bytes.error().code == Errc::not_found) {
            return std::optional<ReplicaInfo>{};
        }
        return std::unexpected(bytes.error());
    }
    const auto document = json::parse(bytes->begin(), bytes->end(), nullptr, false);
    if (document.is_discarded() || !document.is_object() || !document.contains("source") ||
        !document["source"].is_string()) {
        return fail(Errc::malformed, "the replica file is malformed");
    }
    ReplicaInfo info;
    info.source = document["source"].get<std::string>();
    if (document.contains("ca_file") && document["ca_file"].is_string()) {
        info.ca_file = document["ca_file"].get<std::string>();
    }
    info.created = document.value("created", protocol::Timestamp{0});
    if (document.contains("last_sync") && document["last_sync"].is_number_unsigned()) {
        info.last_sync = document["last_sync"].get<protocol::Timestamp>();
    }
    return std::optional(std::move(info));
}

Status write_replica_info(const std::filesystem::path& directory, const ReplicaInfo& info) {
    json document = {{"source", info.source}, {"created", info.created}};
    if (info.ca_file) {
        document["ca_file"] = *info.ca_file;
    }
    if (info.last_sync) {
        document["last_sync"] = *info.last_sync;
    }
    const std::string text = document.dump(2) + "\n";
    return detail::write_file(directory / replica_file, as_bytes(text), false);
}

Result<PrimaryStatus> primary_status(const Client& primary) {
    auto body = fetch(primary, "/v1/status");
    if (!body) {
        return std::unexpected(body.error());
    }
    const auto document = json::parse(body->begin(), body->end(), nullptr, false);
    if (document.is_discarded() || !document.is_object() || !document.contains("ledger_id") ||
        !document["ledger_id"].is_string() || !document.contains("size") ||
        !document["size"].is_number_unsigned()) {
        return fail(Errc::malformed, "the primary's status is malformed");
    }
    PrimaryStatus status{document["ledger_id"].get<std::string>(),
                         document["size"].get<std::uint64_t>(), std::nullopt};
    if (document.contains("checkpoint") && document["checkpoint"].is_object()) {
        status.checkpoint_size = document["checkpoint"].value("tree_size", std::uint64_t{0});
    }
    return status;
}

Result<ledger::Ledger> create_replica(const Client& primary, ledger::FileSystem& fs,
                                      ledger::Clock& clock, const crypto::Provider& provider) {
    auto first = fetch_byte_strings(primary, "/v1/entries?start=0&count=1");
    if (!first) {
        return std::unexpected(first.error());
    }
    if (first->size() != 1) {
        return fail(Errc::malformed, "the primary sent no genesis entry");
    }
    return ledger::Ledger::create_replica(fs, clock, provider, first->front());
}

Result<SyncReport> sync_replica(const Client& primary, ledger::Ledger& replica,
                                const std::filesystem::path& directory,
                                const std::function<void(const SyncReport&)>& progress) {
    SyncReport report;
    report.size = replica.size();
    auto status = primary_status(primary);
    if (!status) {
        return std::unexpected(status.error());
    }
    report.primary_size = status->size;
    if (status->ledger_id != to_hex(replica.id().bytes())) {
        return fail(Errc::verification_failed, "the primary serves a different ledger");
    }
    if (status->size < replica.size()) {
        return fail(Errc::verification_failed,
                    "the primary's log is shorter than this replica's: its history was rolled "
                    "back");
    }

    // Checkpoints, each after the entries it covers. The last one this
    // replica already has must be the primary's too.
    auto local = replica.checkpoints();
    if (!local) {
        return std::unexpected(local.error());
    }
    const std::uint64_t known = local->size();
    std::uint64_t next = known == 0 ? 0 : known - 1;
    bool overlap_checked = known == 0;
    while (true) {
        auto remote = fetch_byte_strings(
            primary, std::format("/v1/checkpoints?start={}&count={}", next, batch));
        if (!remote) {
            return std::unexpected(remote.error());
        }
        std::size_t i = 0;
        if (!overlap_checked) {
            if (remote->empty() || remote->front() != local->back().encoded) {
                return fail(Errc::verification_failed,
                            "the primary's checkpoints differ from this replica's");
            }
            overlap_checked = true;
            i = 1;
        }
        for (; i < remote->size(); ++i) {
            auto parsed = protocol::parse_checkpoint((*remote)[i]);
            if (!parsed) {
                return fail(Errc::verification_failed, "the primary sent a malformed checkpoint");
            }
            if (auto s = catch_up(primary, replica, parsed->checkpoint.tree_size, report, progress);
                !s) {
                return std::unexpected(s.error());
            }
            if (auto s = replica.store_checkpoint((*remote)[i]); !s) {
                return std::unexpected(s.error());
            }
            ++report.checkpoints;
        }
        next += remote->size();
        if (remote->size() < batch) {
            break;
        }
    }
    if (auto s = catch_up(primary, replica, status->size, report, progress); !s) {
        return std::unexpected(s.error());
    }

    // Witness cosignatures, each checked against its witness's key.
    auto have = replica.cosignatures();
    if (!have) {
        return std::unexpected(have.error());
    }
    auto cosignatures = fetch_array(
        primary, std::format("/v1/cosignatures?start={}&count={}", have->size(), batch));
    if (!cosignatures) {
        return std::unexpected(cosignatures.error());
    }
    for (const cbor::Value& item : *cosignatures) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_bytes() == nullptr) {
            return fail(Errc::verification_failed, "the primary sent a malformed cosignature");
        }
        auto witness = protocol::decode_public_key((*parts)[1]);
        if (!witness) {
            return fail(Errc::verification_failed, "the primary sent a malformed cosignature");
        }
        if (auto s = replica.add_cosignature(*(*parts)[0].as_bytes(), *witness); !s) {
            return fail(Errc::verification_failed, "the primary sent a cosignature that fails");
        }
        ++report.cosignatures;
    }

    if (auto s = sync_vault(primary, replica, directory, report); !s) {
        return std::unexpected(s.error());
    }
    report.size = replica.size();
    return report;
}

} // namespace cexchain::node
