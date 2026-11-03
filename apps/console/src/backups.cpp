// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <chrono>
#include <format>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include <cexchain/client/backups.hpp>
#include <cexchain/client/errors.hpp>
#include <cexchain/client/support.hpp>
#include <cexchain/console/backups.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/keystore.hpp>
#include <cexchain/console/settings.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/node/peers.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

constexpr std::string_view magic = "cexchain-sealed-backup";
constexpr std::string_view seal_info = "CexChain sealed backup v1";
constexpr std::string_view status_file = "backups.json";
constexpr protocol::Timestamp week = 7 * 24 * 60 * 60'000;

Bytes aad_of(const protocol::Id& ledger, protocol::Timestamp created) {
    Bytes out(ledger.bytes().begin(), ledger.bytes().end());
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(created >> static_cast<unsigned>(shift)));
    }
    return out;
}

struct Parts {
    SealedBackupInfo info;
    Bytes slot;
    Bytes enc;
    Bytes ciphertext;
};

Parts parts_of(ByteView file) {
    const auto value = cbor::decode(file);
    auto bytes = [&](std::int64_t key) -> const Bytes& {
        const cbor::Value* v = value ? value->find(key) : nullptr;
        if (v == nullptr || v->as_bytes() == nullptr) {
            throw std::runtime_error("this is not a console's sealed backup");
        }
        return *v->as_bytes();
    };
    const cbor::Value* name = value ? value->find(1) : nullptr;
    const cbor::Value* version = value ? value->find(2) : nullptr;
    const cbor::Value* created = value ? value->find(4) : nullptr;
    if (name == nullptr || name->as_text() == nullptr || *name->as_text() != magic ||
        version == nullptr || version->as_int64() != std::optional<std::int64_t>(1) ||
        created == nullptr || !created->as_uint64()) {
        throw std::runtime_error("this is not a console's sealed backup");
    }
    const auto ledger = protocol::to_id(bytes(3));
    if (!ledger) {
        throw std::runtime_error("this is not a console's sealed backup");
    }
    return {{*ledger, *created->as_uint64()}, bytes(5), bytes(6), bytes(7)};
}

/// "cexchain-<12 hex>-": the start of a ledger's backups' names.
std::string prefix_of(const protocol::Id& ledger) {
    return "cexchain-" + to_hex(ledger.bytes()).substr(0, 12) + "-";
}

std::string name_of_backup(const protocol::Id& ledger, protocol::Timestamp created) {
    using namespace std::chrono;
    const sys_seconds at{seconds(created / 1000)};
    const sys_days day = floor<days>(at);
    const year_month_day ymd{day};
    const auto rest = at - day;
    return prefix_of(ledger) +
           std::format("{:04}{:02}{:02}-{:02}{:02}{:02}", static_cast<int>(ymd.year()),
                       static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()),
                       duration_cast<hours>(rest).count(),
                       duration_cast<minutes>(rest).count() % 60, rest.count() % 60) +
           std::string(sealed_backup_extension);
}

/// The time a backup's name gives ("YYYYMMDD-HHMMSS", UTC), in ms.
std::optional<protocol::Timestamp> time_in_name(std::string_view text) {
    using namespace std::chrono;
    if (text.size() != 15 || text[8] != '-') {
        return std::nullopt;
    }
    auto number = [&](std::size_t at, std::size_t n) -> std::optional<int> {
        int v = 0;
        for (std::size_t i = at; i < at + n; ++i) {
            if (text[i] < '0' || text[i] > '9') {
                return std::nullopt;
            }
            v = v * 10 + (text[i] - '0');
        }
        return v;
    };
    const auto y = number(0, 4);
    const auto mo = number(4, 2);
    const auto d = number(6, 2);
    const auto h = number(9, 2);
    const auto mi = number(11, 2);
    const auto se = number(13, 2);
    if (!y || !mo || !d || !h || !mi || !se) {
        return std::nullopt;
    }
    const year_month_day ymd{year{*y}, month{static_cast<unsigned>(*mo)},
                             day{static_cast<unsigned>(*d)}};
    if (!ymd.ok() || *h > 23 || *mi > 59 || *se > 59) {
        return std::nullopt;
    }
    const auto at = sys_days{ymd} + hours{*h} + minutes{*mi} + seconds{*se};
    return static_cast<protocol::Timestamp>(
        duration_cast<milliseconds>(at.time_since_epoch()).count());
}

} // namespace

Bytes seal_backup(ByteView plain, const protocol::Id& ledger, protocol::Timestamp created,
                  ByteView node_public, ByteView recovery_slot) {
    const auto sealed = crypto::openssl::hpke_seal(node_public, as_bytes(seal_info),
                                                   aad_of(ledger, created), plain);
    if (!sealed) {
        throw std::runtime_error("sealing the backup failed");
    }
    auto encoded = cbor::encode(
        cbor::Value::map({{cbor::Value::integer(1), cbor::Value::text(std::string(magic))},
                          {cbor::Value::integer(2), cbor::Value::integer(1)},
                          {cbor::Value::integer(3), cbor::Value::bytes(ledger.bytes())},
                          {cbor::Value::integer(4), cbor::Value::unsigned_integer(created)},
                          {cbor::Value::integer(5), cbor::Value::bytes(recovery_slot)},
                          {cbor::Value::integer(6), cbor::Value::bytes(sealed->encapsulated_key)},
                          {cbor::Value::integer(7), cbor::Value::bytes(sealed->ciphertext)}}));
    if (!encoded) {
        throw std::runtime_error("encoding the sealed backup failed");
    }
    return std::move(*encoded);
}

SealedBackupInfo sealed_backup_info(ByteView file) {
    return parts_of(file).info;
}

Bytes open_sealed_backup(ByteView file, std::string_view recovery_code) {
    const Parts parts = parts_of(file);
    const auto code = canonical_recovery_code(recovery_code);
    if (!code) {
        throw std::runtime_error("that is not a recovery code");
    }
    auto node = crypto::openssl::HpkeKey::from_encrypted_pkcs8(parts.slot, *code);
    if (!node) {
        throw std::runtime_error("the recovery code does not open this backup");
    }
    auto plain = node->open({parts.enc, parts.ciphertext}, as_bytes(seal_info),
                            aad_of(parts.info.ledger, parts.info.created));
    if (!plain) {
        throw std::runtime_error("the backup is damaged: it does not open");
    }
    return Bytes(plain->view().begin(), plain->view().end());
}

BackupStatus load_backup_status(const std::filesystem::path& console) {
    BackupStatus out;
    const std::filesystem::path file = console / status_file;
    if (!std::filesystem::exists(file)) {
        return out;
    }
    const Bytes bytes = client::read_file(file);
    const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (!j.is_object()) {
        return out;
    }
    out.at = j.value("at", protocol::Timestamp{0});
    out.file = j.value("file", "");
    out.size = j.value("size", std::uint64_t{0});
    out.failed_at = j.value("failed_at", protocol::Timestamp{0});
    out.problem = j.value("problem", "");
    return out;
}

void save_backup_status(const std::filesystem::path& console, const BackupStatus& status) {
    const std::string text = nlohmann::json{{"at", status.at},
                                            {"file", status.file},
                                            {"size", status.size},
                                            {"failed_at", status.failed_at},
                                            {"problem", status.problem}}
                                 .dump(2) +
                             "\n";
    std::filesystem::create_directories(console);
    client::write_file(console / status_file, as_bytes(text), true);
}

std::filesystem::path
write_sealed_backup(const ledger::Ledger& ledger, const crypto::Provider& provider,
                    const std::filesystem::path& ledger_dir, const crypto::Signer& log_key,
                    const std::filesystem::path& folder, protocol::Timestamp now) {
    const std::filesystem::path console = ledger_dir / "console";
    const std::filesystem::path slot = console / "slots" / "recovery.p8";
    const std::filesystem::path node_public = console / "node.pub";
    if (!std::filesystem::exists(slot) || !std::filesystem::exists(node_public)) {
        throw std::runtime_error("the console's keys are not set up: nothing to seal backups to");
    }
    const Bytes public_text = client::read_file(node_public);
    std::string text(public_text.begin(), public_text.end());
    text = text.substr(0, text.find('\n'));
    const auto public_key = from_base64url(text);
    if (!public_key) {
        throw std::runtime_error("the console's node key is damaged");
    }
    // The plain backup, checked by restoring it in memory before it is sealed.
    const std::vector<ledger::BackupFile> files = client::backup_files(ledger_dir, true, true);
    std::ostringstream out;
    if (const auto written = ledger::write_backup(ledger, provider, files, now, out, &log_key);
        !written) {
        throw std::runtime_error("writing the backup: " + std::string(written.error().detail));
    }
    const std::string plain = out.str();
    {
        std::istringstream in(plain);
        ledger::MemoryFileSystem fs;
        ledger::SystemClock clock;
        const auto checked = ledger::restore_backup(
            in, fs, clock, provider, [](const ledger::BackupFile& f) -> Status {
                if (!client::backup_path_allowed(f.path)) {
                    return fail(Errc::rejected, "a file outside the ledger's");
                }
                return {};
            });
        if (!checked) {
            throw std::runtime_error("the backup does not restore: " +
                                     std::string(checked.error().detail));
        }
    }
    const Bytes sealed = seal_backup(as_bytes(std::string_view(plain)), ledger.id(), now,
                                     *public_key, client::read_file(slot));
    std::filesystem::create_directories(folder);
    const std::filesystem::path target = folder / name_of_backup(ledger.id(), now);
    client::write_file(target, sealed, true);
    // Read back: it is whole, and names this ledger.
    if (sealed_backup_info(client::read_file(target)).ledger != ledger.id()) {
        throw std::runtime_error("the backup written does not read back");
    }
    static_cast<void>(prune_backups(folder, ledger.id()));
    return target;
}

std::vector<std::filesystem::path> prune_backups(const std::filesystem::path& folder,
                                                 const protocol::Id& ledger) {
    const std::string prefix = prefix_of(ledger);
    // Names sort by time: the newest first.
    std::vector<std::pair<std::string, std::filesystem::path>> found;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(folder, ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (it->is_regular_file() && name.starts_with(prefix) &&
            name.ends_with(sealed_backup_extension) &&
            name.size() == prefix.size() + 15 + sealed_backup_extension.size()) {
            found.emplace_back(name, it->path());
        }
    }
    std::ranges::sort(found, std::greater{});
    auto time_of = [&](const std::string& name) {
        return time_in_name(std::string_view(name).substr(prefix.size(), 15));
    };
    std::vector<std::filesystem::path> removed;
    if (found.empty()) {
        return removed;
    }
    const auto newest = time_of(found.front().first).value_or(0);
    std::map<protocol::Timestamp, bool> weeks;
    for (std::size_t i = 0; i < found.size(); ++i) {
        const auto t = time_of(found[i].first);
        if (!t) {
            continue;
        }
        bool keep = i < kept_daily;
        if (!keep) {
            const protocol::Timestamp age = newest >= *t ? newest - *t : 0;
            const protocol::Timestamp w = age / week;
            if (w >= 1 && w <= kept_weekly && !weeks.contains(w)) {
                weeks[w] = true;
                keep = true;
            }
        }
        if (!keep) {
            std::filesystem::remove(found[i].second, ec);
            if (!ec) {
                removed.push_back(found[i].second);
            }
        }
    }
    return removed;
}

Result<ledger::BackupSummary> restore_sealed_backup(ByteView file, std::string_view recovery_code,
                                                    const std::filesystem::path& dir) {
    const Bytes plain = open_sealed_backup(file, recovery_code);
    std::istringstream in(std::string(plain.begin(), plain.end()));
    auto restored = client::restore_into(in, dir);
    if (!restored) {
        return restored;
    }
    // Party tokens restored into this directory: the peers point at them.
    if (auto peers = node::load_peers(dir)) {
        bool changed = false;
        for (node::Peer& p : *peers) {
            if (!p.token_file) {
                continue;
            }
            const std::filesystem::path here =
                dir / "console" / "peer-tokens" / std::filesystem::path(*p.token_file).filename();
            if (std::filesystem::exists(here) && *p.token_file != here.string()) {
                p.token_file = here.string();
                changed = true;
            }
        }
        if (changed) {
            static_cast<void>(node::save_peers(dir, *peers));
        }
    }
    return restored;
}

// --- The console's own backups ------------------------------------------------------

BackupStatus Console::back_up_now(const std::string& by) const {
    const std::lock_guard lock(backup_mutex_);
    BackupStatus status = load_backup_status(services_.directory);
    const protocol::Timestamp now = services_.clock->now();
    std::string problem;
    std::filesystem::path written;
    try {
        const Settings settings = load_settings(services_.directory);
        const ledger::Ledger* const served = ledger();
        if (!settings.backup_folder) {
            problem = "choose a backup folder in Settings first";
        } else if (served == nullptr) {
            problem = "the console has no ledger to back up yet";
        } else if (services_.keys == nullptr || !services_.keys->unlocked()) {
            problem = "the console is locked: it backs up once unlocked";
        } else {
            const auto log = services_.keys->open("log");
            written =
                write_sealed_backup(*served, *services_.provider, services_.directory.parent_path(),
                                    log, *settings.backup_folder, now);
        }
    } catch (const std::exception& e) {
        problem = e.what();
    } catch (const client::ActionError& e) {
        problem = e.message;
    }
    if (problem.empty()) {
        status.at = now;
        status.file = written.string();
        std::error_code ec;
        status.size = std::filesystem::file_size(written, ec);
        status.failed_at = 0;
        status.problem.clear();
        log_activity(by, "backups.write", {{"file", written.filename().string()}});
    } else {
        status.failed_at = now;
        status.problem = problem;
    }
    try {
        save_backup_status(services_.directory, status);
    } catch (const std::exception&) {
        // Kept in memory for this answer; the next backup writes it.
    } catch (const client::ActionError&) {
    }
    return status;
}

void Console::maybe_back_up() const {
    if (ledger() == nullptr || services_.keys == nullptr || !services_.keys->unlocked()) {
        return;
    }
    try {
        if (!load_settings(services_.directory).backup_folder) {
            return;
        }
    } catch (const std::exception&) {
        return;
    }
    const BackupStatus status = load_backup_status(services_.directory);
    const protocol::Timestamp now = services_.clock->now();
    // Once a day; after a failure, again an hour later.
    if (now - status.at >= backup_interval && now - status.failed_at >= 60 * 60'000) {
        static_cast<void>(back_up_now("console"));
    }
}

nlohmann::json Console::backup_view() const {
    const BackupStatus status = load_backup_status(services_.directory);
    bool folder = false;
    try {
        folder = load_settings(services_.directory).backup_folder.has_value();
    } catch (const std::exception&) {
    }
    const protocol::Timestamp now = services_.clock->now();
    return {{"folder", folder},
            {"at", status.at > 0 ? nlohmann::json(status.at) : nlohmann::json()},
            {"file", status.file.empty()
                         ? nlohmann::json()
                         : nlohmann::json(std::filesystem::path(status.file).filename().string())},
            {"size", status.size},
            {"problem", status.problem.empty() ? nlohmann::json() : nlohmann::json(status.problem)},
            {"overdue", folder && now - status.at > 2 * backup_interval}};
}

http::Response Console::backup_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (request.method == "GET") {
        return json(200, backup_view());
    }
    if (request.method != "POST") {
        return error(405, "unsupported", "method not allowed");
    }
    if (signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin backs the console up");
    }
    const BackupStatus status = back_up_now(signer.user);
    if (!status.problem.empty() && status.failed_at >= status.at) {
        return error(409, "conflict", status.problem);
    }
    return json(200, backup_view());
}

} // namespace cexchain::console
