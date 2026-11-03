// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The parts of a cluster member (cluster.cpp): the durable Raft log, Raft's
// own state, and the state machine that applies committed entries to the
// ledger. Internal to the node library; tests and fuzzers include it.

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <libnuraft/nuraft.hxx>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <variant>
#include <vector>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/common.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/node/cluster.hpp>
#include <cexchain/node/contracts.hpp>

#include "crc32c.hpp"
#include "files.hpp"

namespace cexchain::node::cluster_detail {

using nuraft::buffer;
using nuraft::cs_new;
using nuraft::ptr;
using nuraft::ulong;

constexpr std::string_view node_file = "node.json";
constexpr std::string_view secret_file = "secret";
constexpr std::string_view state_file = "state";
constexpr std::string_view config_file = "config";
constexpr std::string_view log_file = "raft-log";
constexpr std::string_view applied_file = "applied";
constexpr std::string_view snapshot_file = "snapshot";

// Raft entries (CBOR arrays), each applied at the ledger size it names.
constexpr std::uint64_t entry_batch = 1; // [1, at, size, [statement], [sidecar]]
/// A sidecar is [i, vault file], or [i, consent bundles, 3] for a contract
/// call; snapshots carry them as [id, bytes(, kind)], and the
/// pending calls as [name, file, 4]. Kind 2 (the native asset actions' consents,
/// removed in spec v0.9) is reserved: batches and snapshots that carry it are applied
/// without it, as with any unknown kind.
constexpr std::uint64_t sidecar_contract_consents = 3;
constexpr std::uint64_t snapshot_pending_call = 4;
constexpr std::uint64_t entry_checkpoint = 2;  // [2, commitment entry / null, checkpoint]
constexpr std::uint64_t entry_cosignature = 3; // [3, cosignature, witness public key]
constexpr std::uint64_t entry_pending = 4;     // [4, [* [name, file / null]]]

/// Entries and vault files per snapshot object.
constexpr std::uint64_t snapshot_entries = 1000;
constexpr std::size_t snapshot_vault_files = 200;

inline std::filesystem::path cluster_path(const std::filesystem::path& ledger_directory,
                                          std::string_view name) {
    return ledger_directory / cluster_directory / name;
}

inline Bytes to_bytes(const buffer& b) {
    return Bytes(b.data_begin(), b.data_begin() + b.size());
}

inline ptr<buffer> to_buffer(ByteView bytes) {
    ptr<buffer> b = buffer::alloc(bytes.size());
    b->put_raw(bytes.data(), bytes.size());
    b->pos(0);
    return b;
}

inline void put64(Bytes& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(v >> shift));
    }
}

inline std::uint64_t get64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8U) | p[i];
    }
    return v;
}

inline void put32(Bytes& out, std::uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(v >> shift));
    }
}

inline std::uint32_t get32(const std::uint8_t* p) {
    return (std::uint32_t{p[0]} << 24U) | (std::uint32_t{p[1]} << 16U) |
           (std::uint32_t{p[2]} << 8U) | p[3];
}

/// A small file written without a sync: its loss on a crash only repeats
/// (idempotent) work.
inline void write_quick(const std::filesystem::path& path, ByteView data) {
    const std::filesystem::path temporary = path.string() + ".tmp";
    if (FILE* f = std::fopen(temporary.c_str(), "wb")) {
        const bool ok = std::fwrite(data.data(), 1, data.size(), f) == data.size();
        if (std::fclose(f) == 0 && ok) {
            std::error_code ec;
            std::filesystem::rename(temporary, path, ec);
        }
    }
}

[[noreturn]] inline void fatal(std::string_view what) {
    std::fprintf(stderr, "cexchain cluster: fatal: %.*s\n", static_cast<int>(what.size()),
                 what.data());
    std::abort();
}

// ---------------------------------------------------------------------------
// The Raft log: an append-only file with a checksum per record, synced on
// every append; write_at truncates, compaction rewrites it.
//
//   header  "CXRAFT1\0" || start index (u64)
//   record  length (u32) || crc32c(payload) (u32) || payload
//   payload index (u64) || NuRaft's serialized log entry
// ---------------------------------------------------------------------------

constexpr std::array<std::uint8_t, 8> log_magic{'C', 'X', 'R', 'A', 'F', 'T', '1', 0};
constexpr std::size_t log_header = 16;

class RaftLog final : public nuraft::log_store {
public:
    static Result<ptr<RaftLog>> open(const std::filesystem::path& path) {
        auto log = cs_new<RaftLog>();
        log->path_ = path;
        if (auto s = log->load(); !s) {
            return std::unexpected(s.error());
        }
        return log;
    }

    ~RaftLog() override {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    ulong next_slot() const override {
        const std::lock_guard lock(mutex_);
        return start_ + offsets_.size();
    }

    ulong start_index() const override {
        const std::lock_guard lock(mutex_);
        return start_;
    }

    ptr<nuraft::log_entry> last_entry() const override {
        const std::lock_guard lock(mutex_);
        if (offsets_.empty()) {
            return dummy();
        }
        return read(start_ + offsets_.size() - 1);
    }

    ulong append(ptr<nuraft::log_entry>& entry) override {
        const std::lock_guard lock(mutex_);
        const ulong index = start_ + offsets_.size();
        write(index, *entry);
        return index;
    }

    void write_at(ulong index, ptr<nuraft::log_entry>& entry) override {
        const std::lock_guard lock(mutex_);
        truncate_from(index);
        write(index, *entry);
    }

    ptr<std::vector<ptr<nuraft::log_entry>>> log_entries(ulong start, ulong end) override {
        auto out = cs_new<std::vector<ptr<nuraft::log_entry>>>();
        const std::lock_guard lock(mutex_);
        for (ulong i = start; i < end; ++i) {
            out->push_back(in_range(i) ? read(i) : dummy());
        }
        return out;
    }

    ptr<nuraft::log_entry> entry_at(ulong index) override {
        const std::lock_guard lock(mutex_);
        return in_range(index) ? read(index) : dummy();
    }

    ulong term_at(ulong index) override {
        const std::lock_guard lock(mutex_);
        return in_range(index) ? terms_[index - start_] : 0;
    }

    ptr<buffer> pack(ulong index, nuraft::int32 count) override {
        std::vector<ptr<buffer>> entries;
        std::size_t total = 0;
        {
            const std::lock_guard lock(mutex_);
            for (ulong i = index; i < index + static_cast<ulong>(count); ++i) {
                ptr<buffer> b = (in_range(i) ? read(i) : dummy())->serialize();
                total += b->size();
                entries.push_back(b);
            }
        }
        ptr<buffer> out = buffer::alloc(sizeof(nuraft::int32) * (1 + entries.size()) + total);
        out->pos(0);
        out->put(static_cast<nuraft::int32>(entries.size()));
        for (const ptr<buffer>& b : entries) {
            out->put(static_cast<nuraft::int32>(b->size()));
            out->put(*b);
        }
        out->pos(0);
        return out;
    }

    void apply_pack(ulong index, buffer& pack) override {
        pack.pos(0);
        const nuraft::int32 count = pack.get_int();
        const std::lock_guard lock(mutex_);
        if (index < start_ || index > start_ + offsets_.size()) {
            reset(index);
        } else {
            truncate_from(index);
        }
        for (nuraft::int32 i = 0; i < count; ++i) {
            const nuraft::int32 size = pack.get_int();
            ptr<buffer> b = buffer::alloc(static_cast<std::size_t>(size));
            pack.get(b);
            ptr<nuraft::log_entry> entry = nuraft::log_entry::deserialize(*b);
            write(index + static_cast<ulong>(i), *entry);
        }
    }

    bool compact(ulong last_log_index) override {
        const std::lock_guard lock(mutex_);
        if (last_log_index < start_) {
            return true;
        }
        const ulong end = start_ + offsets_.size();
        if (last_log_index + 1 >= end) {
            reset(last_log_index + 1);
            return true;
        }
        // Keep (last_log_index, end): rewrite the file without the rest.
        std::vector<ptr<nuraft::log_entry>> kept;
        for (ulong i = last_log_index + 1; i < end; ++i) {
            kept.push_back(read(i));
        }
        reset(last_log_index + 1);
        for (ulong i = 0; i < kept.size(); ++i) {
            write(last_log_index + 1 + i, *kept[i]);
        }
        return true;
    }

    bool flush() override {
        const std::lock_guard lock(mutex_);
        return ::fsync(fd_) == 0;
    }

private:
    static ptr<nuraft::log_entry> dummy() {
        return cs_new<nuraft::log_entry>(0, buffer::alloc(sizeof(ulong)));
    }

    bool in_range(ulong index) const { return index >= start_ && index < start_ + offsets_.size(); }

    Status load() {
        fd_ = ::open(path_.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd_ < 0) {
            return fail(Errc::unavailable, "cannot open the Raft log");
        }
        struct stat st{};
        if (::fstat(fd_, &st) != 0) {
            return fail(Errc::unavailable, "cannot read the Raft log");
        }
        if (st.st_size == 0) {
            reset(1);
            return {};
        }
        Bytes data(static_cast<std::size_t>(st.st_size));
        if (::pread(fd_, data.data(), data.size(), 0) != static_cast<ssize_t>(data.size())) {
            return fail(Errc::unavailable, "cannot read the Raft log");
        }
        if (data.size() < log_header ||
            !std::equal(log_magic.begin(), log_magic.end(), data.begin())) {
            return fail(Errc::malformed, "the Raft log is not one");
        }
        start_ = get64(data.data() + 8);
        std::size_t at = log_header;
        // Records up to the first torn or damaged one: an append that never
        // completed was never acknowledged.
        while (at + 8 <= data.size()) {
            const std::uint32_t length = get32(data.data() + at);
            const std::uint32_t crc = get32(data.data() + at + 4);
            if (length < 8 || at + 8 + length > data.size()) {
                break;
            }
            const ByteView payload(data.data() + at + 8, length);
            if (ledger::detail::crc32c(payload) != crc ||
                get64(payload.data()) != start_ + offsets_.size()) {
                break;
            }
            buffer_view_term(payload);
            offsets_.push_back(at);
            at += 8 + length;
        }
        file_size_ = at;
        if (at < data.size() && ::ftruncate(fd_, static_cast<off_t>(at)) != 0) {
            return fail(Errc::unavailable, "cannot repair the Raft log");
        }
        return {};
    }

    void buffer_view_term(ByteView payload) {
        ptr<buffer> b = buffer::alloc(payload.size() - 8);
        b->put_raw(payload.data() + 8, payload.size() - 8);
        b->pos(0);
        terms_.push_back(nuraft::log_entry::deserialize(*b)->get_term());
    }

    ptr<nuraft::log_entry> read(ulong index) const {
        const std::uint64_t offset = offsets_[index - start_];
        std::array<std::uint8_t, 8> head{};
        if (::pread(fd_, head.data(), head.size(), static_cast<off_t>(offset)) != 8) {
            fatal("cannot read the Raft log");
        }
        const std::uint32_t length = get32(head.data());
        Bytes payload(length);
        if (::pread(fd_, payload.data(), length, static_cast<off_t>(offset + 8)) !=
                static_cast<ssize_t>(length) ||
            ledger::detail::crc32c(payload) != get32(head.data() + 4)) {
            fatal("the Raft log is damaged");
        }
        ptr<buffer> b = buffer::alloc(length - 8);
        b->put_raw(payload.data() + 8, length - 8);
        b->pos(0);
        return nuraft::log_entry::deserialize(*b);
    }

    void write(ulong index, nuraft::log_entry& entry) {
        ptr<buffer> serialized = entry.serialize();
        Bytes payload;
        put64(payload, index);
        payload.insert(payload.end(), serialized->data_begin(),
                       serialized->data_begin() + serialized->size());
        Bytes record;
        put32(record, static_cast<std::uint32_t>(payload.size()));
        put32(record, ledger::detail::crc32c(payload));
        record.insert(record.end(), payload.begin(), payload.end());
        if (::pwrite(fd_, record.data(), record.size(), static_cast<off_t>(file_size_)) !=
                static_cast<ssize_t>(record.size()) ||
            ::fsync(fd_) != 0) {
            // A Raft log that cannot be written cannot acknowledge anything.
            fatal("cannot write the Raft log");
        }
        offsets_.push_back(file_size_);
        terms_.push_back(entry.get_term());
        file_size_ += record.size();
    }

    void truncate_from(ulong index) {
        if (index < start_) {
            reset(index);
            return;
        }
        const ulong keep = std::min<ulong>(index - start_, offsets_.size());
        if (keep == offsets_.size()) {
            return;
        }
        file_size_ = offsets_[keep];
        offsets_.resize(keep);
        terms_.resize(keep);
        if (::ftruncate(fd_, static_cast<off_t>(file_size_)) != 0 || ::fsync(fd_) != 0) {
            fatal("cannot truncate the Raft log");
        }
    }

    /// An empty log starting at `start`, written in place of the file.
    void reset(ulong start) {
        Bytes header(log_magic.begin(), log_magic.end());
        put64(header, start);
        const std::filesystem::path temporary = path_.string() + ".new";
        const int fd = ::open(temporary.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0 ||
            ::pwrite(fd, header.data(), header.size(), 0) != static_cast<ssize_t>(header.size()) ||
            ::fsync(fd) != 0 || ::rename(temporary.c_str(), path_.c_str()) != 0) {
            fatal("cannot rewrite the Raft log");
        }
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
        if (const int dir = ::open(path_.parent_path().c_str(), O_RDONLY | O_CLOEXEC); dir >= 0) {
            static_cast<void>(::fsync(dir));
            ::close(dir);
        }
        start_ = start;
        offsets_.clear();
        terms_.clear();
        file_size_ = header.size();
    }

    std::filesystem::path path_;
    mutable std::mutex mutex_;
    int fd_ = -1;
    ulong start_ = 1;
    std::vector<std::uint64_t> offsets_;
    std::vector<ulong> terms_;
    std::uint64_t file_size_ = 0;
};

// ---------------------------------------------------------------------------
// Raft's own state and membership
// ---------------------------------------------------------------------------

class StateManager final : public nuraft::state_mgr {
public:
    StateManager(std::filesystem::path directory, ClusterNode node, ptr<RaftLog> log)
        : directory_(std::move(directory)), node_(std::move(node)), log_(std::move(log)) {}

    ptr<nuraft::cluster_config> load_config() override {
        if (auto bytes = detail::read_file(directory_ / config_file)) {
            ptr<buffer> b = to_buffer(*bytes);
            return nuraft::cluster_config::deserialize(*b);
        }
        // To begin with, a cluster of one: the founder leads it; the others
        // wait to be added (and never elect themselves).
        auto config = cs_new<nuraft::cluster_config>();
        config->get_servers().push_back(
            cs_new<nuraft::srv_config>(node_.id, 0, node_.raft_endpoint, node_.api_url, false));
        return config;
    }

    void save_config(const nuraft::cluster_config& config) override {
        save(config_file, *config.serialize());
    }

    void save_state(const nuraft::srv_state& state) override {
        save(state_file, *state.serialize());
    }

    ptr<nuraft::srv_state> read_state() override {
        auto bytes = detail::read_file(directory_ / state_file);
        if (!bytes) {
            return nullptr;
        }
        ptr<buffer> b = to_buffer(*bytes);
        return nuraft::srv_state::deserialize(*b);
    }

    ptr<nuraft::log_store> load_log_store() override { return log_; }

    nuraft::int32 server_id() override { return node_.id; }

    void system_exit(const int code) override {
        fatal("Raft stopped the server (code " + std::to_string(code) + ")");
    }

private:
    void save(std::string_view name, const buffer& b) {
        if (!detail::write_file(directory_ / name, to_bytes(b), true)) {
            fatal("cannot save Raft state");
        }
    }

    std::filesystem::path directory_;
    ClusterNode node_;
    ptr<RaftLog> log_;
};

// ---------------------------------------------------------------------------
// The state machine: committed entries applied to the ledger
// ---------------------------------------------------------------------------

class LedgerMachine final : public nuraft::state_machine {
public:
    using Event = std::function<void(std::string_view, std::string_view)>;

    LedgerMachine(std::filesystem::path ledger_directory, ledger::Ledger& ledger, Event event)
        : directory_(std::move(ledger_directory)), ledger_(&ledger), event_(std::move(event)) {
        if (auto bytes = detail::read_file(cluster_path(directory_, applied_file))) {
            std::uint64_t value = 0;
            const std::string_view text(reinterpret_cast<const char*>(bytes->data()),
                                        bytes->size());
            std::from_chars(text.data(), text.data() + text.size(), value);
            applied_ = value;
        }
        if (auto bytes = detail::read_file(cluster_path(directory_, snapshot_file))) {
            const auto value = cbor::decode(*bytes);
            const cbor::Value* meta = value ? value->find(1) : nullptr;
            const cbor::Value* size = value ? value->find(2) : nullptr;
            if (meta != nullptr && meta->as_bytes() != nullptr && size != nullptr &&
                size->as_uint64()) {
                ptr<buffer> b = to_buffer(*meta->as_bytes());
                snapshot_ = nuraft::snapshot::deserialize(*b);
                snapshot_size_ = *size->as_uint64();
                // Created once its index was applied.
                applied_ = std::max<std::uint64_t>(applied_, snapshot_->get_last_log_idx());
            }
        }
    }

    // ---- applying ----------------------------------------------------------

    ptr<buffer> commit(const ulong log_idx, buffer& data) override {
        const std::lock_guard guard(apply_mutex);
        if (data.size() > 0) {
            apply(log_idx, data);
        }
        set_applied(log_idx);
        ptr<buffer> out = buffer::alloc(sizeof(ulong));
        out->put(log_idx);
        out->pos(0);
        return out;
    }

    void commit_config(const ulong log_idx, ptr<nuraft::cluster_config>&) override {
        set_applied(log_idx);
    }

    ulong last_commit_index() override { return applied_.load(); }

    /// The outcome of applying the entry at `log_idx` here, taken once.
    std::optional<std::variant<BatchResult, Status>> take(ulong log_idx) {
        const std::lock_guard lock(results_mutex_);
        const auto it = results_.find(log_idx);
        if (it == results_.end()) {
            return std::nullopt;
        }
        auto out = std::move(it->second);
        results_.erase(it);
        return out;
    }

    /// Held while an entry is applied: the leader prepares checkpoints
    /// under it, so the two never write to the ledger at once.
    std::mutex apply_mutex;

    // ---- snapshots: the ledger itself --------------------------------------

    void create_snapshot(nuraft::snapshot& s,
                         nuraft::async_result<bool>::handler_type& when_done) override {
        {
            const std::lock_guard lock(snapshot_mutex_);
            ptr<buffer> b = s.serialize();
            snapshot_ = nuraft::snapshot::deserialize(*b);
            snapshot_size_ = ledger_->size();
            const auto meta = cbor::encode(cbor::Value::map(
                {{cbor::Value::integer(1), cbor::Value::bytes(to_bytes(*b))},
                 {cbor::Value::integer(2), cbor::Value::unsigned_integer(snapshot_size_)}}));
            if (meta) {
                write_quick(cluster_path(directory_, snapshot_file), *meta);
            }
        }
        ptr<std::exception> no_error;
        bool done = true;
        when_done(done, no_error);
    }

    ptr<nuraft::snapshot> last_snapshot() override {
        const std::lock_guard lock(snapshot_mutex_);
        return snapshot_;
    }

    int read_logical_snp_obj(nuraft::snapshot& s, void*&, ulong obj_id, ptr<buffer>& data_out,
                             bool& is_last_obj) override {
        std::uint64_t size = 0;
        {
            const std::lock_guard lock(snapshot_mutex_);
            if (!snapshot_ || snapshot_->get_last_log_idx() != s.get_last_log_idx()) {
                return -1;
            }
            size = snapshot_size_;
        }
        const std::uint64_t chunks = (size + snapshot_entries - 1) / snapshot_entries;
        is_last_obj = false;
        Result<Bytes> encoded = fail(Errc::invalid_argument, "no such snapshot object");
        if (obj_id == 0) {
            encoded = cbor::encode(cbor::Value::array({cbor::Value::bytes(ledger_->id().bytes()),
                                                       cbor::Value::unsigned_integer(size),
                                                       cbor::Value::unsigned_integer(chunks)}));
        } else if (obj_id <= chunks) {
            cbor::Array entries;
            for (std::uint64_t i = (obj_id - 1) * snapshot_entries;
                 i < std::min(size, obj_id * snapshot_entries); ++i) {
                auto entry = ledger_->entry(i);
                if (!entry) {
                    return -1;
                }
                entries.push_back(cbor::Value::bytes(*entry));
            }
            encoded = cbor::encode(cbor::Value::array(std::move(entries)));
        } else if (obj_id == chunks + 1) {
            encoded = extras(size);
            is_last_obj = sidecar_files(size).empty();
        } else {
            const auto files_kept = sidecar_files(size);
            const std::size_t first =
                static_cast<std::size_t>(obj_id - chunks - 2) * snapshot_vault_files;
            cbor::Array files;
            for (std::size_t i = first;
                 i < std::min(files_kept.size(), first + snapshot_vault_files); ++i) {
                const KeptFile& kept = files_kept[i];
                if (auto bytes = detail::read_file(path_of(kept))) {
                    cbor::Array item{kept.kind == KeptFile::Kind::pending_call
                                         ? cbor::Value::text(kept.name)
                                         : cbor::Value::bytes(kept.id.bytes()),
                                     cbor::Value::bytes(*bytes)};
                    if (kept.kind != KeptFile::Kind::vault) {
                        item.push_back(
                            cbor::Value::unsigned_integer(static_cast<std::uint64_t>(kept.kind)));
                    }
                    files.push_back(cbor::Value::array(std::move(item)));
                }
            }
            encoded = cbor::encode(cbor::Value::array(std::move(files)));
            is_last_obj = first + snapshot_vault_files >= files_kept.size();
        }
        if (!encoded) {
            return -1;
        }
        data_out = to_buffer(*encoded);
        return 0;
    }

    void save_logical_snp_obj(nuraft::snapshot&, ulong& obj_id, buffer& data, bool, bool) override {
        const std::lock_guard guard(apply_mutex);
        const auto value = cbor::decode(ByteView(data.data_begin(), data.size()));
        const cbor::Array* items = value ? value->as_array() : nullptr;
        if (items == nullptr) {
            failed("a snapshot object is malformed");
            return;
        }
        if (obj_id == 0) {
            if (items->size() != 3 || (*items)[0].as_bytes() == nullptr ||
                !std::ranges::equal(*(*items)[0].as_bytes(), ledger_->id().bytes()) ||
                !(*items)[1].as_uint64() || !(*items)[2].as_uint64()) {
                failed("a snapshot of another ledger");
                return;
            }
            install_size_ = *(*items)[1].as_uint64();
            install_chunks_ = *(*items)[2].as_uint64();
            // Ask only for what this ledger lacks.
            obj_id = ledger_->size() >= install_size_ ? install_chunks_ + 1
                                                      : 1 + ledger_->size() / snapshot_entries;
            return;
        }
        if (obj_id <= install_chunks_) {
            const std::uint64_t first = (obj_id - 1) * snapshot_entries;
            std::vector<Bytes> entries;
            for (std::size_t i = 0; i < items->size(); ++i) {
                if ((*items)[i].as_bytes() != nullptr && first + i >= ledger_->size()) {
                    entries.push_back(*(*items)[i].as_bytes());
                }
            }
            if (first <= ledger_->size() && !entries.empty()) {
                if (auto s = ledger_->append_entries(entries); !s) {
                    failed("a snapshot entry does not validate");
                    return;
                }
            }
        } else if (obj_id == install_chunks_ + 1) {
            apply_extras(*items);
        } else {
            for (const cbor::Value& item : *items) {
                const cbor::Array* parts = item.as_array();
                if (parts == nullptr || parts->size() < 2 || parts->size() > 3 ||
                    (*parts)[1].as_bytes() == nullptr) {
                    continue;
                }
                const std::uint64_t kind =
                    parts->size() == 3 ? (*parts)[2].as_uint64().value_or(0) : 0;
                const Bytes& bytes = *(*parts)[1].as_bytes();
                if (kind == snapshot_pending_call) {
                    if (const std::string* name = (*parts)[0].as_text()) {
                        const PendingChange change{*name, bytes};
                        static_cast<void>(keep_pending(std::span(&change, 1)));
                    }
                    continue;
                }
                const Bytes* id_bytes = (*parts)[0].as_bytes();
                auto id = id_bytes != nullptr
                              ? protocol::to_id(*id_bytes)
                              : Result<protocol::Id>(fail(Errc::malformed, "no id"));
                if (!id) {
                    continue;
                }
                if (kind == sidecar_contract_consents) {
                    keep_contract_consents(*id, bytes);
                } else if (kind == 0) {
                    store_vault(*id, bytes);
                }
            }
        }
        ++obj_id;
    }

    bool apply_snapshot(nuraft::snapshot& s) override {
        const std::lock_guard guard(apply_mutex);
        if (ledger_->size() < install_size_) {
            return false;
        }
        {
            const std::lock_guard lock(snapshot_mutex_);
            ptr<buffer> b = s.serialize();
            snapshot_ = nuraft::snapshot::deserialize(*b);
            snapshot_size_ = install_size_;
        }
        set_applied(s.get_last_log_idx());
        return true;
    }

    void free_user_snp_ctx(void*&) override {}

private:
    std::filesystem::path vault_path(const protocol::Id& record) const {
        return directory_ / "vault" / "records" / (to_hex(record.bytes()) + ".cbor");
    }

    /// A file a snapshot carries besides the ledger.
    struct KeptFile {
        enum class Kind : std::uint8_t {
            vault = 0,
            contract_consents = sidecar_contract_consents,
            pending_call = snapshot_pending_call,
        };
        Kind kind = Kind::vault;
        protocol::Id id;
        /// A pending call's file name.
        std::string name;
    };

    std::filesystem::path path_of(const KeptFile& kept) const {
        switch (kept.kind) {
        case KeptFile::Kind::contract_consents:
            return contract_consents_path(directory_, kept.id);
        case KeptFile::Kind::pending_call:
            return pending_calls_directory(directory_) / kept.name;
        case KeptFile::Kind::vault:
            break;
        }
        return vault_path(kept.id);
    }

    /// The statements below `size` whose consents are kept in `directory`,
    /// in log order.
    std::vector<protocol::Id> consents_kept(const std::filesystem::path& directory,
                                            std::uint64_t size) const {
        std::vector<std::pair<std::uint64_t, protocol::Id>> statements;
        std::error_code ec;
        for (const auto& e : std::filesystem::directory_iterator(directory, ec)) {
            const std::string name = e.path().stem().string();
            auto bytes = from_hex(name);
            auto id =
                bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(fail(Errc::malformed, ""));
            const auto index = id ? ledger_->statement_index(*id) : std::nullopt;
            if (index && *index < size && e.path().extension() == ".cbor") {
                statements.emplace_back(*index, *id);
            }
        }
        std::ranges::sort(statements, {}, &std::pair<std::uint64_t, protocol::Id>::first);
        std::vector<protocol::Id> out;
        for (const auto& [index, id] : statements) {
            out.push_back(id);
        }
        return out;
    }

    /// The files kept with statements below `size`: records' vault files
    /// (in the order the log created the records), then the consents of
    /// contract calls, in log order; then the calls a registrar holds now.
    std::vector<KeptFile> sidecar_files(std::uint64_t size) const {
        std::vector<KeptFile> out;
        ledger_->read_state([&](const protocol::LedgerState& state) {
            for (const auto& [id, record] : state.records()) {
                if (record.registered_at_index < size) {
                    out.push_back(
                        {KeptFile::Kind::vault, protocol::to_id(id).value_or(protocol::Id{}), {}});
                }
            }
        });
        for (const protocol::Id& id :
             consents_kept(contract_consents_directory(directory_), size)) {
            out.push_back({KeptFile::Kind::contract_consents, id, {}});
        }
        for (const HeldCall& held : held_calls(directory_)) {
            out.push_back({KeptFile::Kind::pending_call, {}, pending_call_name(held.name)});
        }
        return out;
    }

    /// Keeps a contract call's consents; a node that holds other bytes for
    /// it has diverged.
    void keep_contract_consents(const protocol::Id& call, ByteView bundles) {
        if (auto s = store_consents_file(contract_consents_path(directory_, call), bundles); !s) {
            failed("cannot keep a contract call's consents");
        }
    }

    /// Writes or removes pending calls; changes that do not hold up change
    /// nothing.
    Status keep_pending(std::span<const PendingChange> changes) {
        auto s = apply_pending_changes(directory_, changes);
        if (!s) {
            failed("cannot keep a registrar's pending calls");
        }
        return s;
    }

    Result<Bytes> extras(std::uint64_t size) const {
        auto checkpoints = ledger_->checkpoints();
        auto cosignatures = ledger_->cosignatures();
        if (!checkpoints || !cosignatures) {
            return fail(Errc::unavailable, "cannot read checkpoints");
        }
        cbor::Array kept;
        for (const auto& c : *checkpoints) {
            if (c.checkpoint.tree_size <= size) {
                kept.push_back(cbor::Value::bytes(c.encoded));
            }
        }
        cbor::Array cosigned;
        for (const auto& c : *cosignatures) {
            if (c.cosignature.checkpoint.tree_size <= size) {
                cosigned.push_back(cbor::Value::array(
                    {cbor::Value::bytes(c.encoded), protocol::encode_public_key(c.witness)}));
            }
        }
        return cbor::encode(cbor::Value::array(
            {cbor::Value::array(std::move(kept)), cbor::Value::array(std::move(cosigned))}));
    }

    void apply_extras(const cbor::Array& items) {
        if (items.size() != 2 || items[0].as_array() == nullptr || items[1].as_array() == nullptr) {
            failed("a snapshot object is malformed");
            return;
        }
        for (const cbor::Value& c : *items[0].as_array()) {
            if (c.as_bytes() != nullptr) {
                static_cast<void>(ledger_->apply_checkpoint(std::nullopt, *c.as_bytes()));
            }
        }
        for (const cbor::Value& c : *items[1].as_array()) {
            const cbor::Array* parts = c.as_array();
            if (parts != nullptr && parts->size() == 2 && (*parts)[0].as_bytes() != nullptr) {
                if (auto key = protocol::decode_public_key((*parts)[1])) {
                    static_cast<void>(ledger_->add_cosignature(*(*parts)[0].as_bytes(), *key));
                }
            }
        }
    }

    /// Writes a record's sealed private data once; false if other data is
    /// there already.
    bool store_vault(const protocol::Id& record, ByteView sealed) {
        const std::filesystem::path path = vault_path(record);
        if (auto held = detail::read_file(path)) {
            return std::ranges::equal(*held, sealed);
        }
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec || !detail::write_file(path, sealed, true)) {
            failed("cannot write a vault file");
        }
        return true;
    }

    /// Applies one entry. Everything here is deterministic: every node
    /// reaches the same outcome from the same ledger.
    void apply(ulong log_idx, buffer& data) {
        const auto value = cbor::decode(ByteView(data.data_begin(), data.size()));
        const cbor::Array* items = value ? value->as_array() : nullptr;
        const auto type =
            items != nullptr && !items->empty() ? (*items)[0].as_uint64() : std::nullopt;
        std::variant<BatchResult, Status> outcome = Status{};
        if (type == entry_batch && items->size() == 5 && (*items)[1].as_uint64() &&
            (*items)[2].as_uint64() && (*items)[3].as_array() != nullptr &&
            (*items)[4].as_array() != nullptr) {
            outcome = apply_batch(*(*items)[1].as_uint64(), *(*items)[2].as_uint64(),
                                  *(*items)[3].as_array(), *(*items)[4].as_array());
        } else if (type == entry_checkpoint && items->size() == 3 &&
                   (*items)[2].as_bytes() != nullptr) {
            std::optional<Bytes> commitment;
            if ((*items)[1].as_bytes() != nullptr) {
                commitment = *(*items)[1].as_bytes();
            }
            outcome = ledger_->apply_checkpoint(commitment, *(*items)[2].as_bytes());
        } else if (type == entry_cosignature && items->size() == 3 &&
                   (*items)[1].as_bytes() != nullptr) {
            auto key = protocol::decode_public_key((*items)[2]);
            outcome = key ? ledger_->add_cosignature(*(*items)[1].as_bytes(), *key)
                          : Status(std::unexpected(key.error()));
        } else if (type == entry_pending && items->size() == 2) {
            auto changes = decode_pending_changes((*items)[1]);
            outcome = changes ? keep_pending(*changes) : Status(std::unexpected(changes.error()));
        } else {
            outcome = Status(fail(Errc::malformed, "a cluster entry is malformed"));
        }
        if (!ledger_->usable()) {
            failed("the ledger failed to write");
        }
        const std::lock_guard lock(results_mutex_);
        results_.insert_or_assign(log_idx, std::move(outcome));
        // Followers never take theirs: keep only the latest.
        while (results_.size() > 1024) {
            results_.erase(results_.begin());
        }
    }

    BatchResult apply_batch(protocol::Timestamp at, std::uint64_t size, const cbor::Array& list,
                            const cbor::Array& vaults) {
        BatchResult results;
        if (ledger_->size() > size) {
            // Applied before (a restart, or a ledger copied ahead): applying
            // it to a later state could accept what was refused then.
            for (std::size_t i = 0; i < list.size(); ++i) {
                results.emplace_back(fail(Errc::unavailable, "applied before"));
            }
            return results;
        }
        if (ledger_->size() < size) {
            failed("an entry belongs after entries this node lacks");
            for (std::size_t i = 0; i < list.size(); ++i) {
                results.emplace_back(fail(Errc::unavailable, "this node is behind"));
            }
            return results;
        }
        std::vector<ByteView> statements;
        for (const cbor::Value& s : list) {
            statements.emplace_back(s.as_bytes() != nullptr ? ByteView(*s.as_bytes()) : ByteView());
        }
        // The consents a contract call cites are kept before it is
        // registered.
        for (const cbor::Value& v : vaults) {
            const cbor::Array* parts = v.as_array();
            const auto kind =
                parts != nullptr && parts->size() == 3 ? (*parts)[2].as_uint64() : std::nullopt;
            if (!kind || *kind != sidecar_contract_consents || !(*parts)[0].as_uint64() ||
                (*parts)[1].as_bytes() == nullptr ||
                *(*parts)[0].as_uint64() >= statements.size()) {
                continue;
            }
            auto parsed = protocol::parse_statement(
                ledger_->provider(), statements[*(*parts)[0].as_uint64()], ledger_->hash());
            if (!parsed) {
                continue;
            }
            keep_contract_consents(parsed->id, *(*parts)[1].as_bytes());
        }
        results = ledger_->submit_batch(statements, at);
        for (const cbor::Value& v : vaults) {
            const cbor::Array* parts = v.as_array();
            if (parts == nullptr || parts->size() != 2 || !(*parts)[0].as_uint64() ||
                (*parts)[1].as_bytes() == nullptr) {
                continue;
            }
            const std::uint64_t i = *(*parts)[0].as_uint64();
            if (i >= results.size() || !results[i]) {
                continue;
            }
            if (!std::filesystem::exists(directory_ / "vault" / "vault.pub")) {
                results[i] = fail(Errc::rejected,
                                  "the statement is registered, but this ledger keeps no vault");
            } else if (!store_vault(results[i]->statement_id, *(*parts)[1].as_bytes())) {
                results[i] = fail(Errc::rejected, "the statement is registered, but the record's "
                                                  "private data was stored before, differently");
            }
        }
        return results;
    }

    void set_applied(ulong log_idx) {
        applied_ = log_idx;
        const std::string text = std::to_string(log_idx);
        write_quick(cluster_path(directory_, applied_file), as_bytes(text));
    }

    void failed(std::string_view what) {
        if (event_) {
            event_("cluster-apply-failed", what);
        }
    }

    std::filesystem::path directory_;
    ledger::Ledger* ledger_;
    Event event_;
    std::atomic<std::uint64_t> applied_ = 0;
    std::mutex results_mutex_;
    std::map<ulong, std::variant<BatchResult, Status>> results_;
    std::mutex snapshot_mutex_;
    ptr<nuraft::snapshot> snapshot_;
    std::uint64_t snapshot_size_ = 0;
    // A snapshot being installed here.
    std::uint64_t install_size_ = 0;
    std::uint64_t install_chunks_ = 0;
};

} // namespace cexchain::node::cluster_detail
