// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "tool_support.hpp"

#include <array>
#include <charconv>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <random>
#include <string>
#include <unistd.h>

namespace kanhe::cli {

Bytes read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw ActionError{"cannot read " + path.string()};
    }
    return Bytes(std::istreambuf_iterator<char>(in), {});
}

void write_file(const std::filesystem::path& path, ByteView data, bool private_file) {
    // A fresh temporary file of our own beside it, never one someone else
    // created (or linked) beforehand.
    std::random_device random;
    std::array<std::uint8_t, 8> name{};
    for (std::uint8_t& b : name) {
        b = static_cast<std::uint8_t>(random());
    }
    const std::filesystem::path temporary = path.string() + "." + to_hex(name) + ".tmp";
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          private_file ? 0600 : 0644);
    if (fd < 0) {
        throw ActionError{"cannot write " + path.string()};
    }
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n <= 0) {
            ::close(fd);
            ::unlink(temporary.c_str());
            throw ActionError{"cannot write " + path.string()};
        }
        done += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0 || ::close(fd) != 0 || std::rename(temporary.c_str(), path.c_str()) != 0) {
        ::unlink(temporary.c_str());
        throw ActionError{"cannot write " + path.string()};
    }
}

std::uint64_t parse_number(std::string_view text, std::string_view what) {
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || ec != std::errc{} || end != text.data() + text.size()) {
        throw UsageError{std::string(what) +
                         " must be a non-negative integer: " + std::string(text)};
    }
    return value;
}

crypto::HashAlg parse_hash(std::string_view name) {
    if (name == "sha256" || name == "sha-256") {
        return crypto::HashAlg::sha256;
    }
    if (name == "sm3") {
        return crypto::HashAlg::sm3;
    }
    throw UsageError{"hash must be sha256 or sm3"};
}

} // namespace kanhe::cli
