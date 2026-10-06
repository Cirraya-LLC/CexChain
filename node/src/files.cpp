// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "files.hpp"

#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <system_error>
#include <unistd.h>

namespace cexchain::node::detail {

Result<Bytes> read_file(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return fail(Errc::not_found, "no such file");
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return fail(Errc::unavailable, "cannot read a file");
    }
    Bytes out((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (in.bad()) {
        return fail(Errc::unavailable, "cannot read a file");
    }
    return out;
}

Status write_file(const std::filesystem::path& path, ByteView data, bool private_file) {
    const std::filesystem::path temporary = path.string() + ".tmp";
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          private_file ? 0600 : 0644);
    if (fd < 0) {
        return fail(Errc::unavailable, "cannot write a file");
    }
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n <= 0) {
            ::close(fd);
            return fail(Errc::unavailable, "cannot write a file");
        }
        done += static_cast<std::size_t>(n);
    }
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    if (!synced || std::rename(temporary.c_str(), path.c_str()) != 0) {
        return fail(Errc::unavailable, "cannot write a file");
    }
    const std::filesystem::path parent = path.parent_path().empty() ? "." : path.parent_path();
    if (const int dir = ::open(parent.c_str(), O_RDONLY | O_CLOEXEC); dir >= 0) {
        ::fsync(dir);
        ::close(dir);
    }
    return {};
}

} // namespace cexchain::node::detail
