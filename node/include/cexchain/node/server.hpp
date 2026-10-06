// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>

#include <cexchain/core/error.hpp>
#include <cexchain/node/http.hpp>

namespace cexchain::node {

/// What the server serves. Every call runs on one application thread, so an
/// application needs no locking of its own.
class Application {
public:
    virtual ~Application() = default;

    /// Answers a request. `peer` is the client's address. Exceptions become
    /// 500 responses.
    [[nodiscard]] virtual http::Response handle(const http::Request& request,
                                                std::string_view peer) = 0;

    /// Called about once a second, for periodic work.
    virtual void tick() {}

    /// Who made the last request handled, for the access log (e.g. a token
    /// name), if known.
    [[nodiscard]] virtual std::string principal() const { return {}; }

protected:
    Application() = default;
    Application(const Application&) = default;
    Application& operator=(const Application&) = default;
};

struct ServerOptions {
    /// An IP address; "0.0.0.0" or "::" for every interface.
    std::string host = "127.0.0.1";
    /// 0 picks a free port (see Server::port).
    std::uint16_t port = 8080;
    /// TLS: a PEM certificate chain and its PEM private key. Without them
    /// the server speaks plain HTTP (put it behind a TLS proxy).
    std::optional<std::filesystem::path> tls_certificate;
    std::optional<std::filesystem::path> tls_private_key;
    std::size_t max_connections = 256;
    http::Limits limits;
    /// To receive a whole request once it has started, and to send a
    /// response.
    std::chrono::seconds request_timeout{30};
    /// Between requests on a kept-alive connection.
    std::chrono::seconds idle_timeout{60};
    /// One JSON line per request, if set.
    std::ostream* access_log = nullptr;
};

/// An HTTP/1.1 server on Asio: connections on an I/O thread, application
/// work on its own thread.
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
