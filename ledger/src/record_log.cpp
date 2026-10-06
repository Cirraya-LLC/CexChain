// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <utility>

#include <cexchain/ledger/record_log.hpp>

#include "crc32c.hpp"

namespace cexchain::ledger {

namespace {

constexpr std::size_t header_size = 8;

void put_u32(Bytes& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void put_u64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::uint64_t get_be(ByteView bytes) {
    std::uint64_t value = 0;
    for (const std::uint8_t b : bytes) {
        value = (value << 8) | b;
    }
    return value;
}

Bytes frame(ByteView payload) {
    Bytes out;
    out.reserve(header_size + payload.size());
    put_u32(out, static_cast<std::uint32_t>(payload.size()));
    put_u32(out, detail::crc32c(payload));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

enum class Scan { record, damaged };

struct ScanResult {
    Scan kind;
    std::uint64_t payload_size = 0;
};

/// The bytes [offset, offset + length) of `file`: a view of its mapping if
/// it lends one, else a copy in `scratch`.
Result<ByteView> bytes_at(const AppendFile& file, std::uint64_t offset, std::size_t length,
                          Bytes& scratch) {
    if (const auto view = file.view(offset, length)) {
        return *view;
    }
    auto copy = file.read(offset, length);
    if (!copy) {
        return std::unexpected(copy.error());
    }
    scratch = std::move(*copy);
    return ByteView(scratch);
}

/// Examines the framed record at `offset`.
Result<ScanResult> scan_record(const AppendFile& file, std::uint64_t offset) {
    const std::uint64_t remaining = file.size() - offset;
    if (remaining < header_size) {
        return ScanResult{Scan::damaged};
    }
    Bytes header_scratch;
    auto header = bytes_at(file, offset, header_size, header_scratch);
    if (!header) {
        return std::unexpected(header.error());
    }
    const std::uint64_t length = get_be(header->first(4));
    const auto crc = static_cast<std::uint32_t>(get_be(header->subspan(4)));
    if (length > max_record_size || length > remaining - header_size) {
        return ScanResult{Scan::damaged};
    }
    Bytes payload_scratch;
    auto payload =
        bytes_at(file, offset + header_size, static_cast<std::size_t>(length), payload_scratch);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    if (detail::crc32c(*payload) != crc) {
        return ScanResult{Scan::damaged};
    }
    return ScanResult{Scan::record, length};
}

/// The durable log size recorded by the last intact entry of the sync file.
/// A damaged tail of the sync file is ignored (that sync was never
/// acknowledged) and, with `recover`, cut off; damage before the tail is
/// corruption.
Result<std::uint64_t> read_synced_size(AppendFile& file, bool recover = true) {
    std::uint64_t offset = 0;
    std::uint64_t synced = 0;
    while (offset < file.size()) {
        auto scanned = scan_record(file, offset);
        if (!scanned) {
            return std::unexpected(scanned.error());
        }
        if (scanned->kind == Scan::damaged || scanned->payload_size != 8) {
            // Only a damaged final entry is acceptable.
            const std::uint64_t entry = header_size + 8;
            if (file.size() - offset > entry) {
                return fail(Errc::malformed, "the log's sync record file is corrupted");
            }
            if (recover) {
                if (auto s = file.truncate(offset); !s) {
                    return std::unexpected(s.error());
                }
            }
            break;
        }
        auto payload = file.read(offset + header_size, 8);
        if (!payload) {
            return std::unexpected(payload.error());
        }
        const std::uint64_t size = get_be(*payload);
        if (size < synced) {
            return fail(Errc::malformed, "the log's sync record file goes backwards");
        }
        synced = size;
        offset += header_size + 8;
    }
    return synced;
}

/// The durable log size, from the last entry of the sync file only, so a
/// refresh costs the same however long the log is. Entries are all the same
/// size; if the last whole one is damaged (a sync that was never
/// acknowledged), the one before it holds. Anything else falls back to the
/// full scan.
Result<std::uint64_t> read_last_synced_size(AppendFile& file, bool recover) {
    constexpr std::uint64_t entry = header_size + 8;
    const std::uint64_t size = file.size();
    const std::uint64_t whole = size - size % entry;
    for (std::uint64_t back = 1; back <= 2 && whole >= back * entry; ++back) {
        const std::uint64_t offset = whole - back * entry;
        auto scanned = scan_record(file, offset);
        if (!scanned) {
            return std::unexpected(scanned.error());
        }
        if (scanned->kind != Scan::record || scanned->payload_size != 8) {
            continue;
        }
        auto payload = file.read(offset + header_size, 8);
        if (!payload) {
            return std::unexpected(payload.error());
        }
        if (recover && offset + entry < size) {
            if (auto s = file.truncate(offset + entry); !s) {
                return std::unexpected(s.error());
            }
        }
        return get_be(*payload);
    }
    return read_synced_size(file, recover);
}

} // namespace

RecordLog::RecordLog(std::unique_ptr<AppendFile> log, std::unique_ptr<AppendFile> synced,
                     std::vector<std::uint64_t> offsets, std::uint64_t end)
    : log_(std::move(log)), synced_(std::move(synced)), end_(end) {
    for (const std::uint64_t offset : offsets) {
        offsets_.push_back(offset);
    }
}

RecordLog::RecordLog(RecordLog&&) noexcept = default;
RecordLog& RecordLog::operator=(RecordLog&&) noexcept = default;
RecordLog::~RecordLog() = default;

Result<RecordLog> RecordLog::open(FileSystem& fs, std::string_view name, RecoveryReport* report) {
    auto log = fs.open(name);
    if (!log) {
        return std::unexpected(log.error());
    }
    auto synced_file = fs.open(std::string(name) + ".synced");
    if (!synced_file) {
        return std::unexpected(synced_file.error());
    }
    auto synced = read_synced_size(**synced_file);
    if (!synced) {
        return std::unexpected(synced.error());
    }
    if (*synced > (*log)->size()) {
        return fail(Errc::malformed, "the log is shorter than its acknowledged size");
    }

    std::vector<std::uint64_t> offsets;
    std::uint64_t offset = 0;
    while (offset < (*log)->size()) {
        auto scanned = scan_record(**log, offset);
        if (!scanned) {
            return std::unexpected(scanned.error());
        }
        if (scanned->kind == Scan::damaged) {
            if (offset < *synced) {
                return fail(Errc::malformed, "an acknowledged log record is corrupted");
            }
            break;
        }
        const std::uint64_t next = offset + header_size + scanned->payload_size;
        if (next > *synced && offset < *synced) {
            // A record straddling the acknowledged boundary cannot occur.
            return fail(Errc::malformed, "the log disagrees with its acknowledged size");
        }
        offsets.push_back(offset);
        offset = next;
    }
    if (offset < *synced) {
        return fail(Errc::malformed, "the log disagrees with its acknowledged size");
    }

    const std::uint64_t truncated = (*log)->size() - offset;
    if (truncated > 0) {
        if (auto s = (*log)->truncate(offset); !s) {
            return std::unexpected(s.error());
        }
    }
    if (report != nullptr) {
        *report = RecoveryReport{offsets.size(), truncated};
    }
    return RecordLog(std::move(*log), std::move(*synced_file), std::move(offsets), offset);
}

Result<ByteView> RecordLog::view(std::uint64_t index, Bytes& scratch) const {
    if (index >= offsets_.size()) {
        return fail(Errc::invalid_argument, "record index is out of range");
    }
    const std::uint64_t offset = offsets_[static_cast<std::size_t>(index)];
    Bytes header_scratch;
    auto header = bytes_at(*log_, offset, header_size, header_scratch);
    if (!header) {
        return std::unexpected(header.error());
    }
    const std::uint64_t length = get_be(header->first(4));
    const auto crc = static_cast<std::uint32_t>(get_be(header->subspan(4)));
    auto payload = bytes_at(*log_, offset + header_size, static_cast<std::size_t>(length), scratch);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    if (detail::crc32c(*payload) != crc) {
        return fail(Errc::malformed, "a log record is corrupted");
    }
    return payload;
}

Result<Bytes> RecordLog::read(std::uint64_t index) const {
    Bytes scratch;
    auto payload = view(index, scratch);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    if (payload->data() == scratch.data()) {
        return scratch; // read() already copied it
    }
    return Bytes(payload->begin(), payload->end());
}

Status RecordLog::append(std::span<const ByteView> payloads) {
    auto pending = write(payloads);
    if (!pending) {
        return std::unexpected(pending.error());
    }
    publish(*pending);
    return {};
}

Result<RecordLog::Pending> RecordLog::write(std::span<const ByteView> payloads) {
    if (failed_) {
        return fail(Errc::invalid_argument, "the log failed earlier and must be reopened");
    }
    for (const ByteView payload : payloads) {
        if (payload.size() > max_record_size) {
            return fail(Errc::invalid_argument, "record is too large");
        }
    }
    Pending pending;
    pending.offsets.reserve(payloads.size());
    std::uint64_t offset = end_;
    // One write for the whole batch.
    Bytes framed;
    for (const ByteView payload : payloads) {
        pending.offsets.push_back(offset);
        const Bytes one = frame(payload);
        framed.insert(framed.end(), one.begin(), one.end());
        offset += one.size();
    }
    pending.end = offset;
    if (auto s = log_->append(framed); !s) {
        failed_ = true;
        return std::unexpected(s.error());
    }
    // Make the records durable, then record the new durable size. A record
    // is acknowledged only once both are durable.
    Bytes size_record;
    put_u64(size_record, pending.end);
    if (auto s = log_->sync(); !s) {
        failed_ = true;
        return std::unexpected(s.error());
    }
    if (auto s = synced_->append(frame(size_record)); !s) {
        failed_ = true;
        return std::unexpected(s.error());
    }
    if (auto s = synced_->sync(); !s) {
        failed_ = true;
        return std::unexpected(s.error());
    }
    return pending;
}

bool RecordLog::outdated() const {
    const auto current = synced_->current_size();
    return !current || *current != synced_->size();
}

void RecordLog::publish(const Pending& pending) {
    for (const std::uint64_t offset : pending.offsets) {
        offsets_.push_back(offset);
    }
    end_ = pending.end;
}

Result<std::uint64_t> RecordLog::refresh(FileSystem& fs, std::string_view name, bool recover) {
    // Fresh handles see what other processes appended.
    auto log = fs.open(name);
    if (!log) {
        return std::unexpected(log.error());
    }
    auto synced_file = fs.open(std::string(name) + ".synced");
    if (!synced_file) {
        return std::unexpected(synced_file.error());
    }
    auto synced = read_last_synced_size(**synced_file, recover);
    if (!synced) {
        return std::unexpected(synced.error());
    }
    if (*synced < end_ || *synced > (*log)->size()) {
        return fail(Errc::malformed, "the log shrank or disagrees with its acknowledged size");
    }
    std::vector<std::uint64_t> added;
    std::uint64_t offset = end_;
    while (offset < *synced) {
        auto scanned = scan_record(**log, offset);
        if (!scanned) {
            return std::unexpected(scanned.error());
        }
        const std::uint64_t next = offset + header_size + scanned->payload_size;
        if (scanned->kind == Scan::damaged || next > *synced) {
            return fail(Errc::malformed, "an acknowledged log record is corrupted");
        }
        added.push_back(offset);
        offset = next;
    }
    if (recover && (*log)->size() > offset) {
        if (auto s = (*log)->truncate(offset); !s) {
            return std::unexpected(s.error());
        }
    }
    log_ = std::move(*log);
    synced_ = std::move(*synced_file);
    for (const std::uint64_t at : added) {
        offsets_.push_back(at);
    }
    end_ = offset;
    failed_ = false;
    return added.size();
}

} // namespace cexchain::ledger
