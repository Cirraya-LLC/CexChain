// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <optional>
#include <string>

#include <kanhe/client/backups.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/ledger/environment.hpp>
#include <kanhe/ledger/storage.hpp>
#include <kanhe/node/contracts.hpp>
#include <kanhe/node/peers.hpp>
#include <kanhe/node/published.hpp>
#include <kanhe/node/tokens.hpp>

namespace kanhe::client {

namespace {

bool hex_id(std::string_view name) {
    return name.size() == 64 && std::ranges::all_of(name, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

/// A file name of letters, digits, '.', '_', and '-', not starting with a
/// dot and with no ".." anywhere: no path, nothing hidden, nothing a reader
/// of the list must look at twice.
bool plain_name(std::string_view name) {
    return !name.empty() && name.size() <= 200 && name.front() != '.' &&
           name.find("..") == std::string_view::npos && std::ranges::all_of(name, [](char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '.' || c == '_' || c == '-';
           });
}

/// `path` is `prefix` then a plain name ending in `suffix`.
bool named_in(std::string_view path, std::string_view prefix, std::string_view suffix) {
    if (!path.starts_with(prefix) || !path.ends_with(suffix) ||
        path.size() < prefix.size() + suffix.size() + 1) {
        return false;
    }
    return plain_name(path.substr(prefix.size(), path.size() - prefix.size()));
}

/// `path` is `prefix`, a ledger object's id, and ".cbor".
bool id_in(std::string_view path, std::string_view prefix) {
    return path.starts_with(prefix) && path.ends_with(".cbor") &&
           hex_id(path.substr(prefix.size(), path.size() - prefix.size() - 5));
}

} // namespace

bool backup_path_allowed(std::string_view path) {
    if (path == node::tokens_file || path == "vault/vault.pub" || path == "vault/vault.key" ||
        path == node::peers_file || path == "witnesses.json" || path == "relay.json" ||
        path == "trust/nodes.json" || id_in(path, "trust/proofs/")) {
        return true;
    }
    constexpr std::string_view pending = "contracts/pending/";
    if (path.starts_with(pending)) {
        return node::parse_pending_call_name(path.substr(pending.size())).has_value();
    }
    // A record published at a private address: published/<token>.cbor.
    constexpr std::string_view published = "published/";
    if (path.starts_with(published) && path.ends_with(".cbor")) {
        return node::valid_published_token(
            path.substr(published.size(), path.size() - published.size() - 5));
    }
    // A kept file: vault/files/<record id>/<attachment index>.cbor.
    constexpr std::string_view files = "vault/files/";
    if (path.starts_with(files) && path.ends_with(".cbor")) {
        const std::string_view rest = path.substr(files.size(), path.size() - files.size() - 5);
        const std::size_t slash = rest.find('/');
        const std::string_view index =
            slash == std::string_view::npos ? std::string_view() : rest.substr(slash + 1);
        return slash != std::string_view::npos && hex_id(rest.substr(0, slash)) && !index.empty() &&
               index.size() <= 6 &&
               std::ranges::all_of(index, [](char c) { return c >= '0' && c <= '9'; }) &&
               (index.size() == 1 || index.front() != '0');
    }
    // Records' sealed data, cited consents, requests' keys, the access boxes.
    for (const std::string_view prefix :
         {"vault/records/", "contracts/consents/", "vault/access/", "access/inbox/",
          "access/outbox/", "access/receipts/", "access/requests/", "access/deliveries/"}) {
        if (path.starts_with(prefix)) {
            return id_in(path, prefix);
        }
    }
    // The console's own folder.
    for (const std::string_view name :
         {"console/users.json", "console/kinds.json", "console/settings.json", "console/node.pub",
          "console/vault.sealed", "console/relay.sealed", "console/prf-salt",
          "console/activity.jsonl", "console/activity.1.jsonl"}) {
        if (path == name) {
            return true;
        }
    }
    return named_in(path, "console/keys/", ".sealed") || named_in(path, "console/slots/", ".p8") ||
           named_in(path, "console/peer-tokens/", ".token") || id_in(path, "console/witness/") ||
           id_in(path, "console/access/");
}

std::vector<ledger::BackupFile> backup_files(const std::filesystem::path& dir, bool vault,
                                             bool console) {
    std::vector<ledger::BackupFile> out;
    auto add = [&](const std::string& relative) {
        if (std::filesystem::is_regular_file(dir / relative) && backup_path_allowed(relative)) {
            out.push_back({relative, read_file(dir / relative)});
        }
    };
    // Every file of a folder whose names a backup may hold, by name.
    auto add_directory = [&](const std::string& prefix) {
        const std::filesystem::path folder = dir / prefix;
        if (!std::filesystem::is_directory(folder)) {
            return;
        }
        std::vector<std::string> names;
        for (const auto& e : std::filesystem::directory_iterator(folder)) {
            const std::string relative = prefix + e.path().filename().string();
            if (e.is_regular_file() && backup_path_allowed(relative)) {
                names.push_back(relative);
            }
        }
        std::ranges::sort(names);
        for (const auto& n : names) {
            add(n);
        }
    };
    add(std::string(node::tokens_file));
    add_directory("contracts/consents/");
    add_directory("contracts/pending/");
    // The trust nodes this ledger belongs to, and their proofs (spec v0.16).
    add("trust/nodes.json");
    add_directory("trust/proofs/");
    if (vault) {
        add("vault/vault.pub");
        add("vault/vault.key");
        if (std::filesystem::is_directory(dir / "vault" / "files")) {
            std::vector<std::string> records;
            for (const auto& e : std::filesystem::directory_iterator(dir / "vault" / "files")) {
                if (e.is_directory()) {
                    records.push_back(e.path().filename().string());
                }
            }
            std::ranges::sort(records);
            for (const std::string& r : records) {
                add_directory("vault/files/" + r + "/");
            }
        }
        add_directory("vault/records/");
        // Published records hold the fields they show, in the clear: with
        // the private data.
        add_directory("published/");
    }
    if (console) {
        add(std::string(node::peers_file));
        // The public witnesses it asks, and the relay it is reached through.
        add("witnesses.json");
        add("relay.json");
        add_directory("vault/access/");
        for (const char* box : {"inbox", "outbox", "receipts", "requests", "deliveries"}) {
            add_directory(std::string("access/") + box + "/");
        }
        for (const char* name :
             {"users.json", "kinds.json", "settings.json", "node.pub", "vault.sealed",
              "relay.sealed", "prf-salt", "activity.1.jsonl", "activity.jsonl"}) {
            add(std::string("console/") + name);
        }
        for (const char* folder : {"keys/", "slots/", "peer-tokens/", "witness/", "access/"}) {
            add_directory(std::string("console/") + folder);
        }
    }
    return out;
}

Result<ledger::BackupSummary> restore_into(std::istream& in, const std::filesystem::path& dir) {
    if (std::filesystem::exists(dir / "statements")) {
        return fail(Errc::rejected, "a ledger already exists there; restore into a new directory");
    }
    // A failure removes what the restore wrote, which in an empty directory
    // is everything there; other files would go with it.
    const bool existed = std::filesystem::exists(dir);
    if (existed && (!std::filesystem::is_directory(dir) || !std::filesystem::is_empty(dir))) {
        return fail(Errc::rejected, "the directory is not empty; restore into a new directory");
    }
    const auto perms =
        existed ? std::filesystem::status(dir).permissions() : std::filesystem::perms::none;
    std::filesystem::create_directories(dir);
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    ledger::SystemClock clock;
    std::optional<ledger::DirectoryLock> lock;
    auto acquired = ledger::DirectoryLock::acquire(dir);
    if (!acquired) {
        return std::unexpected(acquired.error());
    }
    lock.emplace(std::move(*acquired));
    auto fs = ledger::PosixFileSystem::open_directory(dir);
    if (!fs) {
        return std::unexpected(fs.error());
    }
    auto summary = ledger::restore_backup(
        in, *fs, clock, shared_provider(), [&](const ledger::BackupFile& f) -> Status {
            if (!backup_path_allowed(f.path)) {
                return fail(Errc::rejected, "the backup holds a file outside the ledger's");
            }
            const std::filesystem::path target = dir / f.path;
            std::error_code ec;
            std::filesystem::create_directories(target.parent_path(), ec);
            for (const char* top : {"vault", "console", "access"}) {
                if (f.path.starts_with(top)) {
                    std::filesystem::permissions(dir / top, std::filesystem::perms::owner_all,
                                                 std::filesystem::perm_options::replace, ec);
                }
            }
            try {
                write_file(target, f.content, f.path != "vault/vault.pub");
            } catch (const ActionError& e) {
                return fail(Errc::unavailable, e.message);
            }
            return {};
        });
    if (!summary) {
        // Nothing half-restored is left behind (a partial ledger would open).
        lock.reset();
        std::error_code ec;
        if (!existed) {
            std::filesystem::remove_all(dir, ec);
        } else {
            for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
                std::filesystem::remove_all(e.path(), ec);
            }
            std::filesystem::permissions(dir, perms, std::filesystem::perm_options::replace, ec);
        }
    }
    return summary;
}

} // namespace kanhe::client
