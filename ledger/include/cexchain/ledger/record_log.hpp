// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/core/protocol/id_map.hpp>
#include <cexchain/ledger/storage.hpp>

/// A durable, append-only sequence of records.
///
/// File `<name>` holds the records, each framed as
///   [length: u32 big-endian][CRC-32C of payload: u32 big-endian][payload]
/// File `<name>.synced` holds a framed record of the log's durable size after
/// every successful sync.
///
/// Recovery after a crash scans the log. A bad or incomplete record beyond the
/// last durable size is the remains of an unacknowledged write and is cut
/// off. A bad record within the durable size is corruption of acknowledged
/// history, and opening fails rather than silently dropping entries.
namespace cexchain::ledger {

/// Records larger than this are rejected (the ledger stores statements, not
/// documents).
inline constexpr std::size_t max_record_size = std::size_t{16} << 20;

struct RecoveryReport {
    std::uint64_t records = 0;
    /// Bytes of unacknowledged, damaged tail that recovery removed.
    std::uint64_t truncated_bytes = 0;
};

class RecordLog {
public:
    /// Opens or creates the log `name` in `fs`, recovering from a crash if
    /// needed. Fails with `Errc::malformed` if acknowledged data is damaged.
    [[nodiscard]] static Result<RecordLog> open(FileSystem& fs, std::string_view name,
                                                RecoveryReport* report = nullptr);

    RecordLog(RecordLog&&) noexcept;
    RecordLog& operator=(RecordLog&&) noexcept;
    ~RecordLog();

    [[nodiscard]] std::uint64_t count() const noexcept { return offsets_.size(); }

    /// The payload of record `index`.
    [[nodiscard]] Result<Bytes> read(std::uint64_t index) const;
    /// The same without a copy where the file lends its bytes (see
    /// AppendFile::view), else copied into `scratch`: valid until this log
    /// is refreshed, reopened, or destroyed, or `scratch` changes.
    [[nodiscard]] Result<ByteView> view(std::uint64_t index, Bytes& scratch) const;

    /// Appends records and makes them durable. On success every record is
    /// acknowledged; on failure none may be relied on, and the log must be
    /// reopened before further use.
    [[nodiscard]] Status append(std::span<const ByteView> payloads);
    [[nodiscard]] Status append(ByteView payload) { return append(std::span(&payload, 1)); }

    /// Records written and durable but not yet visible to `read` and `count`.
    struct Pending {
        std::vector<std::uint64_t> offsets;
        std::uint64_t end = 0;
    };
    /// `append` in two steps, so that readers on other threads need not wait
    /// for the disk: `write` makes the records durable without touching what
    /// readers see (call it from the one writing thread), and `publish` makes
    /// them visible (call it while holding whatever lock readers take). A
    /// write must be published before the next one.
    [[nodiscard]] Result<Pending> write(std::span<const ByteView> payloads);
    void publish(const Pending& pending);

    /// Picks up records that another process appended since this log was
    /// opened or last refreshed, up to their durable size, so that a reader
    /// never sees an unacknowledged record. With `recover`, which requires
    /// holding the ledger's lock, an unacknowledged tail left by a writer
    /// that crashed is cut off, as on open, so this log can append again.
    /// Returns the number of new records.
    [[nodiscard]] Result<std::uint64_t> refresh(FileSystem& fs, std::string_view name,
                                                bool recover);

    /// Whether another process has synced records since this log last
    /// wrote or refreshed (one fstat), so that `refresh` would find more.
    [[nodiscard]] bool outdated() const;

private:
    RecordLog(std::unique_ptr<AppendFile> log, std::unique_ptr<AppendFile> synced,
              std::vector<std::uint64_t> offsets, std::uint64_t end);

    std::unique_ptr<AppendFile> log_;
    std::unique_ptr<AppendFile> synced_;
    /// Chunked: appending never copies (it happens under the readers'
    /// lock) and leaves no doubling slack.
    protocol::StableVector<std::uint64_t> offsets_;
    /// The offset just past the last record.
    std::uint64_t end_ = 0;
    bool failed_ = false;
};

} // namespace cexchain::ledger
