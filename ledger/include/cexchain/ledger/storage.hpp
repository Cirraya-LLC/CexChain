// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/ledger/environment.hpp>

/// The storage the ledger needs: named append-only files with an explicit
/// durability point. Production uses the POSIX implementation; simulations use
/// the in-memory one, which can lose unsynced data the way a crash does.
namespace cexchain::ledger {

/// Reads may run on many threads at once, alongside one thread that
/// appends; offsets a reader asks for must already be written.
class AppendFile {
public:
    virtual ~AppendFile() = default;

    [[nodiscard]] virtual std::uint64_t size() const = 0;
    /// The size as the file system has it now, including what other
    /// processes have appended since this handle was opened (which `size`
    /// does not count).
    [[nodiscard]] virtual Result<std::uint64_t> current_size() const { return size(); }
    [[nodiscard]] virtual Result<Bytes> read(std::uint64_t offset, std::size_t length) const = 0;
    /// Appends `data`. It is not durable until `sync` returns successfully.
    [[nodiscard]] virtual Status append(ByteView data) = 0;
    /// Makes every appended byte durable.
    [[nodiscard]] virtual Status sync() = 0;
    /// Cuts the file to `size` bytes and makes that durable. Used by recovery.
    [[nodiscard]] virtual Status truncate(std::uint64_t size) = 0;

protected:
    AppendFile() = default;
    AppendFile(const AppendFile&) = default;
    AppendFile& operator=(const AppendFile&) = default;
};

class FileSystem {
public:
    virtual ~FileSystem() = default;

    /// Opens `name` for appending, creating it if needed. A newly created
    /// file's directory entry is durable when this returns.
    [[nodiscard]] virtual Result<std::unique_ptr<AppendFile>> open(std::string_view name) = 0;
    [[nodiscard]] virtual bool exists(std::string_view name) const = 0;

protected:
    FileSystem() = default;
    FileSystem(const FileSystem&) = default;
    FileSystem& operator=(const FileSystem&) = default;
};

/// Files in one directory on a POSIX system. Durability uses fsync, and
/// F_FULLFSYNC on Apple platforms, where plain fsync does not flush the
/// drive's cache.
class PosixFileSystem final : public FileSystem {
public:
    /// Creates `directory` if it does not exist.
    [[nodiscard]] static Result<PosixFileSystem> open_directory(std::filesystem::path directory);

    [[nodiscard]] Result<std::unique_ptr<AppendFile>> open(std::string_view name) override;
    [[nodiscard]] bool exists(std::string_view name) const override;

private:
    explicit PosixFileSystem(std::filesystem::path directory) : directory_(std::move(directory)) {}
    std::filesystem::path directory_;
};

/// An exclusive, advisory lock on a ledger directory, so that only one
/// process writes to a ledger at a time. Released on destruction (and by the
/// operating system if the process dies).
class DirectoryLock {
public:
    /// Waits up to `timeout_ms` for the lock on `directory`.
    [[nodiscard]] static Result<DirectoryLock> acquire(const std::filesystem::path& directory,
                                                       std::uint64_t timeout_ms = 5000);

    DirectoryLock(DirectoryLock&& other) noexcept;
    DirectoryLock& operator=(DirectoryLock&& other) noexcept;
    DirectoryLock(const DirectoryLock&) = delete;
    DirectoryLock& operator=(const DirectoryLock&) = delete;
    ~DirectoryLock();

private:
    explicit DirectoryLock(int fd) noexcept : fd_(fd) {}
    int fd_ = -1;
};

/// Files held in memory, for simulation. Each file keeps its durable bytes
/// apart from bytes appended since the last sync, so `crash` can model what
/// survives a power loss.
class MemoryFileSystem final : public FileSystem {
public:
    MemoryFileSystem();
    ~MemoryFileSystem() override;
    MemoryFileSystem(const MemoryFileSystem&) = delete;
    MemoryFileSystem& operator=(const MemoryFileSystem&) = delete;

    [[nodiscard]] Result<std::unique_ptr<AppendFile>> open(std::string_view name) override;
    [[nodiscard]] bool exists(std::string_view name) const override;

    /// Simulates a crash: for every file, keeps the durable bytes plus a
    /// random prefix of the unsynced bytes (possibly none, possibly all),
    /// and sometimes flips a bit in the kept unsynced part to model a torn
    /// sector. Open handles must not be used afterwards.
    void crash(SeededEntropy& entropy);

    /// The current bytes of a file, durable and unsynced.
    [[nodiscard]] Bytes contents(std::string_view name) const;

    /// Overwrites a byte of a file, durable or not, to model media corruption.
    void corrupt(std::string_view name, std::uint64_t offset);

    struct FileData {
        /// Guards the rest: handles share it, possibly across threads.
        mutable std::mutex mutex;
        Bytes bytes;
        std::uint64_t durable = 0;
    };

private:
    std::map<std::string, std::shared_ptr<FileData>, std::less<>> files_;
};

} // namespace cexchain::ledger
