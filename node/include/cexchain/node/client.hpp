// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>
#include <cexchain/node/http.hpp>

namespace cexchain::node {

/// An http:// or https:// URL naming a server, e.g. "https://ledger.example.com/cexchain".
struct Url {
    bool tls = false;
    /// A DNS name or IP address (IPv6 without brackets).
    std::string host;
    std::uint16_t port = 0;
    /// The path prefix requests go under, without a trailing slash ("" for
    /// the root).
    std::string base_path;

    /// Parses an absolute URL without user info, query, or fragment.
    [[nodiscard]] static Result<Url> parse(std::string_view text);
    [[nodiscard]] std::string to_string() const;
};

struct ClientOptions {
    /// A PEM file of CA certificates to trust instead of the system's.
    std::optional<std::filesystem::path> ca_file;
    /// For a whole request: connecting, sending, and receiving.
    std::chrono::seconds timeout{30};
    std::size_t max_body = 64 * 1024 * 1024;
    /// Sent as "Authorization: Bearer <token>" if set.
    std::optional<std::string> bearer_token;
    /// More header fields, sent as given (names and values without CR, LF,
    /// or NUL; a request with others fails with Errc::invalid_argument).
    std::vector<std::pair<std::string, std::string>> headers;
    /// Follow a cluster follower's 307 or 308 to its leader (at most three
    /// times, never from https to http). Off for webhooks.
    bool follow_redirects = true;
    /// If set, checked every 100 ms: once true, the request is abandoned and
    /// fails with Errc::unavailable ("stopped"). For long polls in a process
    /// that is stopping.
    const std::atomic<bool>* stop = nullptr;
};

/// A small HTTP/1.1 client: one connection per request. TLS certificates are
/// verified, including the host name.
class Client {
public:
    Client(Url base, ClientOptions options);

    /// Sends `method` to `path` (with any query, starting with "/", relative
    /// to the base URL). Fails with Errc::unavailable if the server cannot be
    /// reached or does not answer in time, or Errc::verification_failed if
    /// its TLS certificate is not trusted. Any HTTP status is a success.
    [[nodiscard]] Result<http::ClientResponse> request(std::string_view method,
                                                       std::string_view path, ByteView body = {},
                                                       std::string_view content_type = {}) const;

    [[nodiscard]] const Url& base() const noexcept { return base_; }

private:
    [[nodiscard]] Result<http::ClientResponse> send(const Url& to, const std::string& target,
                                                    std::string_view method, ByteView body,
                                                    std::string_view content_type) const;

    Url base_;
    ClientOptions options_;
};

/// A keep-alive HTTP/1.1 client to one server: requests go one after
/// another over one connection, opened on the first request and again
/// whenever the server has closed it. A request that fails on a reused
/// connection before any byte of an answer arrives (the server closed it
/// while idle) is sent once more on a new connection, so use it for
/// requests that may be repeated: reads, statements (registered once by
/// id), webhooks (an idempotency key). Redirects (with follow_redirects)
/// go through a one-off Client. Not for concurrent use: one per thread.
class Connection {
public:
    Connection(Url base, ClientOptions options);
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&) noexcept;
    Connection& operator=(Connection&&) noexcept;
    ~Connection();

    /// As Client::request; `headers` are sent with this request only,
    /// after the options' own.
    [[nodiscard]] Result<http::ClientResponse>
    request(std::string_view method, std::string_view path, ByteView body = {},
            std::string_view content_type = {},
            const std::vector<std::pair<std::string, std::string>>& headers = {});
    /// Closes the connection; the next request opens a new one.
    void close() noexcept;

    [[nodiscard]] const Url& base() const noexcept { return base_; }

private:
    struct State;

    Url base_;
    ClientOptions options_;
    std::unique_ptr<State> state_;
};

} // namespace cexchain::node
