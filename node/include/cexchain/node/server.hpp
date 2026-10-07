// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>

#include <cexchain/core/error.hpp>
#include <cexchain/node/http.hpp>

namespace cexchain::node {

/// What the server serves. Requests arrive on the server's I/O threads,
/// many at once: implementations must be thread-safe.
class Application {
public:
    /// Delivers the response; call it exactly once, from any thread, now or
    /// later.
    using Respond = std::function<void(http::Response)>;

    virtual ~Application() = default;

    /// Answers a request from `peer` (the client's address). Exceptions
    /// become 500 responses.
    virtual void handle(http::Request request, std::string peer, Respond respond) = 0;

    /// Called about once a second, from one thread at a time; must not block.
    virtual void tick() {}

    /// The server stops: answer whatever is still outstanding, and call no
    /// `respond` after returning.
    virtual void stop() {}

protected:
    Application() = default;
    Application(const Application&) = default;
    Application& operator=(const Application&) = default;
};

struct ServerOptions {
    /// I/O threads; 0 uses one per hardware thread.
    std::size_t threads = 0;
    /// An IP address; "0.0.0.0" or "::" for every interface.
    std::string host = "127.0.0.1";
    /// 0 picks a free port (see Server::port).
    std::uint16_t port = 8080;
    /// TLS: a PEM certificate chain and its PEM private key. Without them
    /// the server speaks plain HTTP (put it behind a TLS proxy).
    std::optional<std::filesystem::path> tls_certificate;
    std::optional<std::filesystem::path> tls_private_key;
    std::size_t max_connections = 1024;
    /// From one peer address; 0 for no limit (behind a proxy every
    /// connection has the proxy's address). When the server is full, its
    /// longest-idle connection gives way to a new one either way.
    std::size_t max_connections_per_peer = 0;
    http::Limits limits;
    /// Request bytes buffered across all connections at once.
    std::size_t max_buffered_bytes = std::size_t{256} << 20;
    /// For a new connection to send its first request's first bytes (and
    /// finish the TLS handshake).
    std::chrono::seconds header_timeout{10};
    /// To receive a whole request once it has started, and to send a
    /// response.
    std::chrono::seconds request_timeout{30};
    /// Between requests on a kept-alive connection.
    std::chrono::seconds idle_timeout{60};
    /// One JSON line per request, if set.
    std::ostream* access_log = nullptr;
};

/// An HTTP/1.1 server on Asio with C++20 coroutines. Each I/O thread runs
/// its own event loop, and connections are dealt to them in turn: requests
/// on different connections run in parallel, while each connection's
/// handlers stay on one thread and never need locking.
class Server {
public:
    Server(Application& application, ServerOptions options);
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    ~Server();

    /// Binds and listens. Fails with Errc::unavailable if the address is in
    /// use or not local, or Errc::invalid_argument if the TLS files do not
    /// load.
    [[nodiscard]] Status listen();

    /// The bound port, after listen().
    [[nodiscard]] std::uint16_t port() const;

    /// Serves until SIGINT, SIGTERM, or stop(); then stops accepting, lets
    /// requests in progress finish (for up to request_timeout), and returns.
    void run();

    /// Asks run() to return; safe from any thread.
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace cexchain::node
