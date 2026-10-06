// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <array>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <charconv>
#include <tuple>
#include <utility>

#include <openssl/ssl.h>

#include <cexchain/node/client.hpp>

namespace cexchain::node {

namespace {

using asio::ip::tcp;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

/// What a request ended with.
struct Outcome {
    std::optional<Error> error;
    std::optional<http::ClientResponse> response;
};

template <class Stream>
asio::awaitable<void> exchange(Stream& stream, const std::string& message, std::size_t max_body,
                               Outcome& outcome) {
    if (auto [ec, n] = co_await asio::async_write(stream, asio::buffer(message), use_tuple); ec) {
        outcome.error = Error{Errc::unavailable, "the connection to the server failed"};
        co_return;
    }
    std::string buffer;
    std::array<char, 64 * 1024> chunk{};
    while (true) {
        auto [ec, n] = co_await stream.async_read_some(asio::buffer(chunk), use_tuple);
        buffer.append(chunk.data(), n);
        const bool at_end = static_cast<bool>(ec);
        if (ec && ec != asio::error::eof && ec != asio::ssl::error::stream_truncated) {
            outcome.error = Error{Errc::unavailable, "the connection to the server failed"};
            co_return;
        }
        auto parsed = http::parse_response(buffer, max_body, at_end);
        if (!parsed) {
            outcome.error = parsed.error();
            co_return;
        }
        if (*parsed) {
            outcome.response = std::move((*parsed)->first);
            co_return;
        }
    }
}

} // namespace

Result<Url> Url::parse(std::string_view text) {
    Url url;
    if (text.starts_with("https://")) {
        url.tls = true;
        text.remove_prefix(8);
    } else if (text.starts_with("http://")) {
        text.remove_prefix(7);
    } else {
        return fail(Errc::invalid_argument, "a server URL starts with http:// or https://");
    }
    const std::size_t slash = std::min(text.find('/'), text.size());
    std::string_view authority = text.substr(0, slash);
    std::string_view path = text.substr(slash);
    if (authority.empty() || authority.find('@') != std::string_view::npos ||
        path.find_first_of("?#") != std::string_view::npos) {
        return fail(Errc::invalid_argument,
                    "a server URL has a host, and no user name, query, or fragment");
    }
    std::string_view port;
    if (authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string_view::npos) {
            return fail(Errc::invalid_argument, "a server URL has a malformed IPv6 address");
        }
        url.host = std::string(authority.substr(1, close - 1));
        const std::string_view rest = authority.substr(close + 1);
        if (!rest.empty()) {
            if (rest.front() != ':') {
                return fail(Errc::invalid_argument, "a server URL has a malformed port");
            }
            port = rest.substr(1);
        }
    } else {
        const std::size_t colon = authority.find(':');
        url.host = std::string(authority.substr(0, colon));
        if (colon != std::string_view::npos) {
            port = authority.substr(colon + 1);
        }
    }
    if (url.host.empty()) {
        return fail(Errc::invalid_argument, "a server URL needs a host");
    }
    url.port = url.tls ? 443 : 80;
    if (!port.empty()) {
        unsigned value = 0;
        const auto [ptr, ec] = std::from_chars(port.data(), port.data() + port.size(), value);
        if (ec != std::errc{} || ptr != port.data() + port.size() || value == 0 || value > 65535) {
            return fail(Errc::invalid_argument, "a server URL has a malformed port");
        }
        url.port = static_cast<std::uint16_t>(value);
    }
    while (path.ends_with('/')) {
        path.remove_suffix(1);
    }
    url.base_path = std::string(path);
    return url;
}

std::string Url::to_string() const {
    const bool ipv6 = host.find(':') != std::string::npos;
    std::string out = tls ? "https://" : "http://";
    out += ipv6 ? "[" + host + "]" : host;
    if (port != (tls ? 443 : 80)) {
        out += ":" + std::to_string(port);
    }
    return out + base_path;
}

Client::Client(Url base, ClientOptions options)
    : base_(std::move(base)), options_(std::move(options)) {}

Result<http::ClientResponse> Client::request(std::string_view method, std::string_view path,
                                             ByteView body, std::string_view content_type) const {
    const bool ipv6 = base_.host.find(':') != std::string::npos;
    std::string host_field = ipv6 ? "[" + base_.host + "]" : base_.host;
    if (base_.port != (base_.tls ? 443 : 80)) {
        host_field += ":" + std::to_string(base_.port);
    }
    std::string message = std::string(method) + " " + base_.base_path + std::string(path) +
                          " HTTP/1.1\r\nHost: " + host_field +
                          "\r\nConnection: close\r\nAccept: application/cbor, application/json\r\n";
    if (options_.bearer_token) {
        message += "Authorization: Bearer " + *options_.bearer_token + "\r\n";
    }
    if (!body.empty() || method == "POST") {
        if (!content_type.empty()) {
            message += "Content-Type: " + std::string(content_type) + "\r\n";
        }
        message += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    message += "\r\n";
    message.append(body.begin(), body.end());

    asio::io_context io;
    Outcome outcome;
    std::optional<asio::ssl::context> tls;
    if (base_.tls) {
        tls.emplace(asio::ssl::context::tls_client);
        SSL_CTX_set_min_proto_version(tls->native_handle(), TLS1_2_VERSION);
        asio::error_code ec;
        if (options_.ca_file) {
            tls->load_verify_file(options_.ca_file->string(), ec);
        } else {
            tls->set_default_verify_paths(ec);
        }
        if (ec) {
            return fail(Errc::invalid_argument, "cannot load the trusted CA certificates");
        }
        tls->set_verify_mode(asio::ssl::verify_peer);
    }

    asio::error_code not_an_address;
    const asio::ip::address address = asio::ip::make_address(base_.host, not_an_address);

    auto run = [&]() -> asio::awaitable<void> {
        tcp::socket socket(io);
        asio::error_code connected;
        if (!not_an_address) {
            // An address needs no resolver, whose thread costs more than
            // the request.
            std::tie(connected) =
                co_await socket.async_connect(tcp::endpoint(address, base_.port), use_tuple);
        } else {
            tcp::resolver resolver(io);
            auto [rec, endpoints] =
                co_await resolver.async_resolve(base_.host, std::to_string(base_.port), use_tuple);
            if (rec) {
                outcome.error = Error{Errc::unavailable, "cannot resolve the server's host name"};
                co_return;
            }
            std::tie(connected, std::ignore) =
                co_await asio::async_connect(socket, endpoints, use_tuple);
        }
        if (connected) {
            outcome.error = Error{Errc::unavailable, "cannot connect to the server"};
            co_return;
        }
        if (!tls) {
            co_await exchange(socket, message, options_.max_body, outcome);
            co_return;
        }
        asio::ssl::stream<tcp::socket> stream(std::move(socket), *tls);
        // SNI for host names (not addresses), and the certificate must name
        // the host.
        if (not_an_address) {
            std::string sni = base_.host;
            SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     TLSEXT_NAMETYPE_host_name, sni.data());
        }
        stream.set_verify_callback(asio::ssl::host_name_verification(base_.host));
        if (auto [ec] = co_await stream.async_handshake(asio::ssl::stream_base::client, use_tuple);
            ec) {
            const bool untrusted = ec.category() == asio::error::get_ssl_category();
            outcome.error =
                untrusted ? Error{Errc::verification_failed,
                                  "the server's TLS certificate is not trusted for its name"}
                          : Error{Errc::unavailable, "the TLS handshake with the server failed"};
            co_return;
        }
        co_await exchange(stream, message, options_.max_body, outcome);
    };
    asio::co_spawn(io, run(), asio::detached);
    io.run_for(options_.timeout);
    if (!io.stopped()) {
        return fail(Errc::unavailable, "the server did not answer in time");
    }
    if (outcome.error) {
        return std::unexpected(*outcome.error);
    }
    if (!outcome.response) {
        return fail(Errc::unavailable, "the server did not answer");
    }
    return std::move(*outcome.response);
}

} // namespace cexchain::node
