// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <netinet/in.h>
#include <random>
#include <set>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace cexchain::test {

/// The first port of the range the system assigns from: to bind(0), and to
/// the local end of every outgoing connection.
inline unsigned first_ephemeral_port() {
    int first = 0;
#if defined(__APPLE__)
    std::size_t size = sizeof first;
    if (::sysctlbyname("net.inet.ip.portrange.first", &first, &size, nullptr, 0) != 0) {
        first = 0;
    }
#else
    std::ifstream range("/proc/sys/net/ipv4/ip_local_port_range");
    if (!(range >> first)) {
        first = 0;
    }
#endif
    return first > 1024 && first <= 65535 ? static_cast<unsigned>(first) : 32768U;
}

/// Whether a port on the loopback interface is free to bind now.
inline bool can_bind(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    const bool free = ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) == 0;
    ::close(fd);
    return free;
}

/// A port for a server whose address must be known before it starts, such
/// as a cluster member's Raft and API addresses, which the membership names.
///
/// Not a port from bind(0): that comes from the ephemeral range, where the
/// system also picks the local end of every outgoing connection, so by the
/// time the member binds it, a connection (Raft's own, or a client's) may hold
/// it, and the member fails with "Address already in use". This port comes
/// from just below that range, where the system assigns none; it is free when
/// chosen, and no two calls in a process return the same one.
inline std::uint16_t fixed_port() {
    static std::mutex mutex;
    static std::set<std::uint16_t> given;
    static std::mt19937 random{std::random_device{}()};
    const std::lock_guard lock(mutex);
    unsigned end = first_ephemeral_port();
    unsigned begin = end > 1024 + 16384 ? end - 16384 : 1024;
    if (end - begin < 1024) {
        // No room below the range: any port, as free as can be checked.
        begin = 1024;
        end = 65536;
    }
    std::uniform_int_distribution<unsigned> pick(begin, end - 1);
    for (int attempt = 0; attempt < 10000; ++attempt) {
        const auto port = static_cast<std::uint16_t>(pick(random));
        if (!given.contains(port) && can_bind(port)) {
            given.insert(port);
            return port;
        }
    }
    throw std::runtime_error("no free port below the ephemeral range");
}

} // namespace cexchain::test
