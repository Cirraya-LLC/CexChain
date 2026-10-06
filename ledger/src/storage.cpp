// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>

#include <cexchain/ledger/storage.hpp>

namespace cexchain::ledger {

namespace {

// ---------------------------------------------------------------------------
// POSIX
// ---------------------------------------------------------------------------

/// Flushes a file descriptor to stable storage.
bool full_sync(int fd) noexcept {
#ifdef __APPLE__
    // fsync on macOS does not flush the drive's write cache.
    if (::fcntl(fd, F_FULLFSYNC) == 0) {
        return true;
    }
    // Some file systems (e.g. network mounts) do not support F_FULLFSYNC.
#endif
    return ::fsync(fd) == 0;
}

class PosixFile final : public AppendFile {
public:
    PosixFile(int fd, std::uint64_t size) noexcept : fd_(fd), size_(size) {}
    ~PosixFile() override {
        if (segments_) {
            for (const auto& segment : segments_->base) {
                if (const std::uint8_t* base = segment.load()) {
                    ::munmap(const_cast<std::uint8_t*>(base), segment_size);
                }
            }
        }
        ::close(fd_);
    }
    PosixFile(const PosixFile&) = delete;
    PosixFile& operator=(const PosixFile&) = delete;

    [[nodiscard]] std::uint64_t size() const override {
        return size_.load(std::memory_order_acquire);
    }

    [[nodiscard]] Result<std::uint64_t> current_size() const override {
        struct stat info{};
        if (::fstat(fd_, &info) != 0) {
            return fail(Errc::unavailable, "file stat failed");
        }
        return static_cast<std::uint64_t>(info.st_size);
    }

    [[nodiscard]] Result<Bytes> read(std::uint64_t offset, std::size_t length) const override {
        const std::uint64_t size = this->size();
        if (offset > size || length > size - offset) {
            return fail(Errc::invalid_argument, "read beyond the end of the file");
        }
        Bytes out(length);
        std::size_t done = 0;
        while (done < length) {
            const ssize_t n =
                ::pread(fd_, out.data() + done, length - done, static_cast<off_t>(offset + done));
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n <= 0) {
                return fail(Errc::invalid_argument, "file read failed");
            }
            done += static_cast<std::size_t>(n);
        }
        return out;
    }

    /// Reads come from read-only shared mappings of the file, in segments
    /// mapped once and kept until the handle closes. A segment may extend
    /// past the end of the file (it grows into it), but only bytes below
    /// `size()` are ever touched, so no access faults.
    [[nodiscard]] std::optional<ByteView> view(std::uint64_t offset,
                                               std::size_t length) const override {
        const std::uint64_t size = this->size();
        if (offset > size || length > size - offset) {
            return std::nullopt;
        }
        if (length == 0) {
            return ByteView{};
        }
        const std::uint64_t segment = offset / segment_size;
        if (segment != (offset + length - 1) / segment_size || segment >= max_segments) {
            return std::nullopt; // straddles two segments: rare, so read() it
        }
        const std::uint8_t* base = mapped(static_cast<std::size_t>(segment));
        if (base == nullptr) {
            return std::nullopt;
        }
        return ByteView(base + (offset - segment * segment_size), length);
    }

    [[nodiscard]] Status append(ByteView data) override {
        std::size_t done = 0;
        while (done < data.size()) {
            const ssize_t n = ::write(fd_, data.data() + done, data.size() - done);
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n <= 0) {
                return fail(Errc::invalid_argument, "file write failed");
            }
            done += static_cast<std::size_t>(n);
        }
        size_.fetch_add(data.size(), std::memory_order_acq_rel);
        return {};
    }

    [[nodiscard]] Status sync() override {
        if (!full_sync(fd_)) {
            return fail(Errc::invalid_argument, "file sync failed");
        }
        return {};
    }

    [[nodiscard]] Status truncate(std::uint64_t size) override {
        if (size > this->size()) {
            return fail(Errc::invalid_argument, "cannot truncate beyond the end of the file");
        }
        if (::ftruncate(fd_, static_cast<off_t>(size)) != 0) {
            return fail(Errc::invalid_argument, "file truncate failed");
        }
        size_.store(size, std::memory_order_release);
        return sync();
    }

private:
    static constexpr std::uint64_t segment_size = std::uint64_t{1} << 28; // 256 MiB
    static constexpr std::size_t max_segments = 4096;                     // 1 TiB
    struct Segments {
        std::array<std::atomic<const std::uint8_t*>, max_segments> base{};
    };

    /// The mapping of `segment`, made on first use by whichever reader gets
    /// there first.
    [[nodiscard]] const std::uint8_t* mapped(std::size_t segment) const {
        std::call_once(segments_once_, [this] { segments_ = std::make_unique<Segments>(); });
        std::atomic<const std::uint8_t*>& slot = segments_->base[segment];
        if (const std::uint8_t* base = slot.load(std::memory_order_acquire)) {
            return base;
        }
        void* mapping = ::mmap(nullptr, segment_size, PROT_READ, MAP_SHARED, fd_,
                               static_cast<off_t>(segment * segment_size));
        if (mapping == MAP_FAILED) {
            return nullptr;
        }
        const std::uint8_t* expected = nullptr;
        if (!slot.compare_exchange_strong(expected, static_cast<const std::uint8_t*>(mapping),
                                          std::memory_order_acq_rel)) {
            ::munmap(mapping, segment_size); // another reader mapped it first
            return expected;
        }
        return static_cast<const std::uint8_t*>(mapping);
    }

    int fd_;
    /// Appends run on one thread while reads, which check bounds, run on
    /// others (pread itself is safe to share).
    std::atomic<std::uint64_t> size_;
    mutable std::once_flag segments_once_;
    mutable std::unique_ptr<Segments> segments_;
};

Status sync_directory(const std::filesystem::path& directory) {
    const int fd = ::open(directory.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return fail(Errc::invalid_argument, "could not open the ledger directory");
    }
    const bool ok = full_sync(fd);
    ::close(fd);
    if (!ok) {
        return fail(Errc::invalid_argument, "could not sync the ledger directory");
    }
    return {};
}

bool valid_name(std::string_view name) {
    return !name.empty() && name.find('/') == std::string_view::npos && name != "." && name != "..";
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

class MemoryFile final : public AppendFile {
public:
    explicit MemoryFile(std::shared_ptr<MemoryFileSystem::FileData> data)
        : data_(std::move(data)) {}

    [[nodiscard]] std::uint64_t size() const override {
        const std::lock_guard lock(data_->mutex);
        return data_->bytes.size();
    }

    [[nodiscard]] Result<Bytes> read(std::uint64_t offset, std::size_t length) const override {
        const std::lock_guard lock(data_->mutex);
        const std::uint64_t size = data_->bytes.size();
        if (offset > size || length > size - offset) {
            return fail(Errc::invalid_argument, "read beyond the end of the file");
        }
        const auto begin = data_->bytes.begin() + static_cast<std::ptrdiff_t>(offset);
        return Bytes(begin, begin + static_cast<std::ptrdiff_t>(length));
    }

    [[nodiscard]] Status append(ByteView data) override {
        const std::lock_guard lock(data_->mutex);
        data_->bytes.insert(data_->bytes.end(), data.begin(), data.end());
        return {};
    }

    [[nodiscard]] Status sync() override {
        const std::lock_guard lock(data_->mutex);
        data_->durable = data_->bytes.size();
        return {};
    }

    [[nodiscard]] Status truncate(std::uint64_t size) override {
        const std::lock_guard lock(data_->mutex);
        if (size > data_->bytes.size()) {
            return fail(Errc::invalid_argument, "cannot truncate beyond the end of the file");
        }
        data_->bytes.resize(static_cast<std::size_t>(size));
        data_->durable = size;
        return {};
    }

private:
    std::shared_ptr<MemoryFileSystem::FileData> data_;
};

} // namespace

// ---------------------------------------------------------------------------
// PosixFileSystem
// ---------------------------------------------------------------------------

Result<PosixFileSystem> PosixFileSystem::open_directory(std::filesystem::path directory) {
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error || !std::filesystem::is_directory(directory)) {
        return fail(Errc::invalid_argument, "could not create the ledger directory");
    }
    return PosixFileSystem(std::move(directory));
}

Result<std::unique_ptr<AppendFile>> PosixFileSystem::open(std::string_view name) {
    if (!valid_name(name)) {
        return fail(Errc::invalid_argument, "invalid file name");
    }
    const std::filesystem::path path = directory_ / std::string(name);
    const bool existed = std::filesystem::exists(path);
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return fail(Errc::invalid_argument, "could not open a ledger file");
    }
    struct stat info{};
    if (::fstat(fd, &info) != 0) {
        ::close(fd);
        return fail(Errc::invalid_argument, "could not stat a ledger file");
    }
    auto file = std::make_unique<PosixFile>(fd, static_cast<std::uint64_t>(info.st_size));
    if (!existed) {
        if (auto s = sync_directory(directory_); !s) {
            return std::unexpected(s.error());
        }
    }
    return std::unique_ptr<AppendFile>(std::move(file));
}

bool PosixFileSystem::exists(std::string_view name) const {
    return valid_name(name) && std::filesystem::exists(directory_ / std::string(name));
}

// ---------------------------------------------------------------------------
// DirectoryLock
// ---------------------------------------------------------------------------

Result<DirectoryLock> DirectoryLock::acquire(const std::filesystem::path& directory,
                                             std::uint64_t timeout_ms) {
    const std::filesystem::path path = directory / "lock";
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        return fail(Errc::invalid_argument, "could not open the ledger lock file");
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno != EWOULDBLOCK && errno != EINTR) {
            ::close(fd);
            return fail(Errc::invalid_argument, "could not lock the ledger");
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            ::close(fd);
            return fail(Errc::rejected, "the ledger is in use by another process");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return DirectoryLock(fd);
}

DirectoryLock::DirectoryLock(DirectoryLock&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}

DirectoryLock& DirectoryLock::operator=(DirectoryLock&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
}

DirectoryLock::~DirectoryLock() {
    if (fd_ >= 0) {
        ::close(fd_); // closing releases the flock
    }
}

// ---------------------------------------------------------------------------
// MemoryFileSystem
// ---------------------------------------------------------------------------

MemoryFileSystem::MemoryFileSystem() = default;
MemoryFileSystem::~MemoryFileSystem() = default;

Result<std::unique_ptr<AppendFile>> MemoryFileSystem::open(std::string_view name) {
    if (!valid_name(name)) {
        return fail(Errc::invalid_argument, "invalid file name");
    }
    auto it = files_.find(name);
    if (it == files_.end()) {
        it = files_.emplace(std::string(name), std::make_shared<FileData>()).first;
    }
    return std::unique_ptr<AppendFile>(std::make_unique<MemoryFile>(it->second));
}

bool MemoryFileSystem::exists(std::string_view name) const {
    return files_.contains(name);
}

void MemoryFileSystem::crash(SeededEntropy& entropy) {
    for (auto& [name, file] : files_) {
        // Detach from any open handle: after a crash, old handles are gone.
        auto survivor = std::make_shared<FileData>();
        {
            const std::lock_guard lock(file->mutex);
            survivor->bytes = file->bytes;
            survivor->durable = file->durable;
        }
        const std::uint64_t unsynced = survivor->bytes.size() - survivor->durable;
        const std::uint64_t kept = unsynced == 0 ? 0 : entropy.below(unsynced + 1);
        survivor->bytes.resize(static_cast<std::size_t>(survivor->durable + kept));
        if (kept > 0 && entropy.below(4) == 0) {
            const std::uint64_t offset = survivor->durable + entropy.below(kept);
            survivor->bytes[static_cast<std::size_t>(offset)] ^=
                static_cast<std::uint8_t>(1U << entropy.below(8));
        }
        survivor->durable = survivor->bytes.size();
        file = std::move(survivor);
    }
}

Bytes MemoryFileSystem::contents(std::string_view name) const {
    const auto it = files_.find(name);
    if (it == files_.end()) {
        return {};
    }
    const std::lock_guard lock(it->second->mutex);
    return it->second->bytes;
}

void MemoryFileSystem::corrupt(std::string_view name, std::uint64_t offset) {
    const auto it = files_.find(name);
    if (it == files_.end()) {
        return;
    }
    const std::lock_guard lock(it->second->mutex);
    if (offset < it->second->bytes.size()) {
        it->second->bytes[static_cast<std::size_t>(offset)] ^= 0x01;
    }
}

} // namespace cexchain::ledger
