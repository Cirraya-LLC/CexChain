// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <format>
#include <span>
#include <system_error>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/merkle.hpp>
#include <cexchain/core/protocol/log.hpp>
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

/// Entries the replica holds in memory while checking them against a
/// checkpoint; beyond this it fetches them again to take them.
constexpr std::size_t max_held_bytes = std::size_t{64} << 20;
/// Distinct witnesses whose cosignatures a replica keeps.
constexpr std::size_t max_witnesses = 64;

/// Takes the primary's entries up to `checkpoint` and then the checkpoint:
/// but only once they lead to its root and the checkpoint is signed by the
/// log key in effect at its size (following any key rotation among them), so
/// nothing the log key has not signed is ever written. Each entry is still
/// re-validated as it is taken.
Status take_checkpoint(const Client& primary, ledger::Ledger& replica, ByteView encoded,
                       const protocol::SignedCheckpoint& checkpoint, SyncReport& report,
                       const std::function<void(const SyncReport&)>& progress) {
    const std::uint64_t size = checkpoint.checkpoint.tree_size;
    if (size <= replica.size()) {
        if (auto checked = replica.verify_checkpoint(encoded); !checked) {
            return fail(Errc::verification_failed,
                        "the primary sent a checkpoint that is not signed by the log key or goes "
                        "back");
        }
    } else {
        auto range = replica.compact_range();
        protocol::LedgerKeys keys = replica.keys();
        std::vector<Bytes> held;
        std::size_t held_bytes = 0;
        bool holding = true;
        // Leaf hashes, so entries fetched again must be the ones checked.
        Bytes leaves;
        for (std::uint64_t at = replica.size(); at < size;) {
            const std::uint64_t count = std::min(batch, size - at);
            auto page = fetch_byte_strings(primary,
                                           std::format("/v1/entries?start={}&count={}", at, count));
            if (!page) {
                return std::unexpected(page.error());
            }
            if (page->empty() || page->size() > count) {
                return fail(Errc::verification_failed,
                            "the primary does not have the entries its checkpoint covers");
            }
            for (Bytes& entry : *page) {
                auto leaf = merkle::leaf_hash(replica.provider(), replica.hash(), entry);
                if (!leaf) {
                    return std::unexpected(leaf.error());
                }
                const std::uint64_t index = replica.size() + leaves.size() / leaf->size();
                if (auto s = protocol::follow_key_rotation(replica.provider(), keys, index, entry);
                    !s) {
                    return fail(Errc::verification_failed,
                                "the primary sent a key rotation that does not verify");
                }
                if (auto s = range.append_leaf_hash(*leaf); !s) {
                    return s;
                }
                leaves.insert(leaves.end(), leaf->bytes().begin(), leaf->bytes().end());
                if (holding) {
                    held_bytes += entry.size();
                    held.push_back(std::move(entry));
                    if (held_bytes > max_held_bytes) {
                        holding = false;
                        held.clear();
                    }
                }
            }
            at += page->size();
        }
        auto root = range.root();
        if (!root) {
            return std::unexpected(root.error());
        }
        if (*root != checkpoint.checkpoint.root) {
            return fail(Errc::verification_failed,
                        "the primary's entries do not lead to its signed checkpoint");
        }
        if (auto checked = replica.verify_checkpoint(encoded, &keys.log_key()); !checked) {
            return fail(Errc::verification_failed,
                        "the primary sent a checkpoint that is not signed by the log key or goes "
                        "back");
        }
        const std::size_t leaf_size = crypto::digest_size(replica.hash());
        const std::uint64_t first = replica.size();
        auto take = [&](std::span<const Bytes> entries) -> Status {
            const std::uint64_t before = replica.size();
            auto s = replica.append_entries(entries);
            report.entries += replica.size() - before;
            report.size = replica.size();
            if (s && progress) {
                progress(report);
            }
            return s;
        };
        if (holding) {
            for (std::size_t at = 0; at < held.size(); at += batch) {
                const std::size_t end = std::min<std::size_t>(held.size(), at + batch);
                if (auto s = take(std::span(held).subspan(at, end - at)); !s) {
                    return s;
                }
            }
        } else {
            while (replica.size() < size) {
                const std::uint64_t at = replica.size();
                const std::uint64_t count = std::min(batch, size - at);
                auto page = fetch_byte_strings(
                    primary, std::format("/v1/entries?start={}&count={}", at, count));
                if (!page) {
                    return std::unexpected(page.error());
                }
                if (page->empty() || page->size() > count) {
                    return fail(Errc::verification_failed,
                                "the primary does not have the entries its checkpoint covers");
                }
                for (std::size_t k = 0; k < page->size(); ++k) {
                    auto leaf = merkle::leaf_hash(replica.provider(), replica.hash(), (*page)[k]);
                    const std::size_t offset = static_cast<std::size_t>(at - first + k) * leaf_size;
                    if (!leaf || !std::ranges::equal(leaf->bytes(),
                                                     ByteView(leaves).subspan(offset, leaf_size))) {
                        return fail(Errc::verification_failed,
                                    "the primary sent other entries the second time");
                    }
                }
                if (auto s = take(*page); !s) {
                    return s;
                }
            }
        }
    }
    if (auto s = replica.store_checkpoint(encoded); !s) {
        return s;
    }
    ++report.checkpoints;
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
    // A new vault key (after `vault rekey`) re-seals every record. The key
    // is written last: if copying stops halfway, the next sync sees the old
    // key still and copies everything again.
    const auto local_key = detail::read_file(vault / "vault.pub");
    const bool rekeyed = !local_key || *local_key != *remote_key;
    // Records before `synced` were fetched (or found to have no vault data)
    // by an earlier sync; asking again for each would cost a request per
    // record every time.
    std::uint64_t synced = 0;
    if (const auto marker = detail::read_file(vault / "synced"); marker && !rekeyed) {
        const std::string_view text(reinterpret_cast<const char*>(marker->data()), marker->size());
        std::from_chars(text.data(), text.data() + text.size(), synced);
    }
    const std::uint64_t size = replica.size();
    for (const auto& [id, record] : replica.state().records()) {
        if (record.registered_at_index < synced || record.registered_at_index >= size) {
            continue;
        }
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
    if (rekeyed) {
        if (auto s = detail::write_file(vault / "vault.pub", *remote_key, false); !s) {
            return s;
        }
        ++report.vault_files;
    }
    const std::string marker = std::to_string(size);
    return detail::write_file(vault / "synced", as_bytes(marker), false);
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
                                      ledger::Clock& clock, const crypto::Provider& provider,
                                      const std::optional<protocol::Id>& expected) {
    auto first = fetch_byte_strings(primary, "/v1/entries?start=0&count=1");
    if (!first) {
        return std::unexpected(first.error());
    }
    if (first->size() != 1) {
        return fail(Errc::malformed, "the primary sent no genesis entry");
    }
    // The ledger id is the genesis statement's: pinned before anything is
    // written, so nobody in between can substitute a whole ledger.
    if (expected) {
        auto genesis = protocol::decode_log_entry(first->front());
        if (!genesis || genesis->statement_id != *expected) {
            return fail(Errc::verification_failed,
                        "the primary serves another ledger than the one expected");
        }
    }
    return ledger::Ledger::create_replica(fs, clock, provider, first->front());
}

Result<SyncReport> sync_replica(const Client& primary, ledger::Ledger& replica,
                                const std::filesystem::path& directory,
                                const std::function<void(const SyncReport&)>& progress,
                                const SyncOptions& options) {
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

    // Checkpoints, each with the entries it covers once they lead to its
    // root. Entries no checkpoint covers yet are not copied: nothing the log
    // key has not signed is ever written here. The last checkpoint this
    // replica has must be the primary's too.
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
        bool advanced = false;
        for (; i < remote->size(); ++i) {
            const auto latest = replica.latest_checkpoint();
            if (latest && latest->encoded == (*remote)[i]) {
                continue; // a copy of the latest: nothing new
            }
            // Its signature is checked in take_checkpoint, with the log key in
            // effect at its size.
            auto checked = protocol::parse_checkpoint((*remote)[i]);
            if (!checked) {
                return fail(Errc::verification_failed, "the primary sent a malformed checkpoint");
            }
            if (auto s =
                    take_checkpoint(primary, replica, (*remote)[i], *checked, report, progress);
                !s) {
                return std::unexpected(s.error());
            }
            advanced = true;
        }
        next += remote->size();
        if (remote->size() < batch) {
            break;
        }
        if (!advanced) {
            return fail(Errc::verification_failed, "the primary repeats checkpoints without end");
        }
    }

    // Witness cosignatures, each checked against its witness's key, from a
    // bounded number of witnesses.
    auto have = replica.cosignatures();
    if (!have) {
        return std::unexpected(have.error());
    }
    std::vector<crypto::PublicKey> witnesses;
    for (const auto& c : *have) {
        if (!std::ranges::contains(witnesses, c.witness)) {
            witnesses.push_back(c.witness);
        }
    }
    for (std::uint64_t start = have->size();;) {
        auto cosignatures =
            fetch_array(primary, std::format("/v1/cosignatures?start={}&count={}", start, batch));
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
            if (!std::ranges::contains(witnesses, *witness)) {
                if (witnesses.size() >= max_witnesses) {
                    continue;
                }
                witnesses.push_back(*witness);
            }
            if (auto s = replica.add_cosignature(*(*parts)[0].as_bytes(), *witness); !s) {
                return fail(Errc::verification_failed, "the primary sent a cosignature that fails");
            }
            ++report.cosignatures;
        }
        start += cosignatures->size();
        if (cosignatures->size() < batch) {
            break;
        }
    }

    // The entries past the last checkpoint, for a client's mirror.
    while (options.tail && replica.size() < report.primary_size) {
        const std::uint64_t at = replica.size();
        const std::uint64_t count = std::min(batch, report.primary_size - at);
        auto page =
            fetch_byte_strings(primary, std::format("/v1/entries?start={}&count={}", at, count));
        if (!page) {
            return std::unexpected(page.error());
        }
        if (page->empty() || page->size() > count) {
            break; // the primary's log is what it is
        }
        if (auto s = replica.append_entries(*page); !s) {
            return fail(Errc::verification_failed,
                        "the primary sent an entry that does not validate");
        }
        report.entries += page->size();
    }

    if (options.vault) {
        if (auto s = sync_vault(primary, replica, directory, report); !s) {
            return std::unexpected(s.error());
        }
    }
    report.size = replica.size();
    return report;
}

} // namespace cexchain::node
