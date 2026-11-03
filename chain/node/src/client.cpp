// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
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
    /// Some byte of an answer arrived (so the request reached the server).
    bool answered = false;
    /// The server ended the connection, or said it would.
    bool closing = false;
};

/// Whether the comma-separated list `value` holds `token` (lower case),
/// ignoring case.
bool has_token(std::string_view value, std::string_view token) {
    while (!value.empty()) {
        const std::size_t comma = std::min(value.find(','), value.size());
        std::string_view item = value.substr(0, comma);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) {
            item.remove_prefix(1);
        }
        while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) {
            item.remove_suffix(1);
        }
        if (item.size() == token.size() && std::ranges::equal(item, token, [](char a, char b) {
                return (a >= 'A' && a <= 'Z' ? static_cast<char>(a - 'A' + 'a') : a) == b;
            })) {
            return true;
        }
        value.remove_prefix(std::min(comma + 1, value.size()));
    }
    return false;
}

/// The request's bytes: its line, header fields, and body.
Result<std::string>
request_message(const Url& to, const std::string& target, std::string_view method, ByteView body,
                std::string_view content_type, const ClientOptions& options, bool keep_alive,
                const std::vector<std::pair<std::string, std::string>>& extra = {}) {
    const bool ipv6 = to.host.find(':') != std::string::npos;
    std::string host_field = ipv6 ? "[" + to.host + "]" : to.host;
    if (to.port != (to.tls ? 443 : 80)) {
        host_field += ":" + std::to_string(to.port);
    }
    std::string message = std::string(method) + " " + target + " HTTP/1.1\r\nHost: " + host_field +
                          (keep_alive ? "\r\n" : "\r\nConnection: close\r\n") +
                          "Accept: application/cbor, application/json\r\n";
    if (options.bearer_token) {
        message += "Authorization: Bearer " + *options.bearer_token + "\r\n";
    }
    for (const auto* fields : {&options.headers, &extra}) {
        for (const auto& [name, value] : *fields) {
            auto breaks = [](std::string_view text) {
                return text.find_first_of(std::string_view("\r\n\0", 3)) != std::string_view::npos;
            };
            if (name.empty() || name.find(':') != std::string::npos || breaks(name) ||
                breaks(value)) {
                return fail(Errc::invalid_argument, "a header field has a line break or no name");
            }
            message += name + ": " + value + "\r\n";
        }
    }
    if (!body.empty() || method == "POST") {
        if (!content_type.empty()) {
            message += "Content-Type: " + std::string(content_type) + "\r\n";
        }
        message += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    message += "\r\n";
    message.append(body.begin(), body.end());
    return message;
}

/// A TLS client context trusting the system's CAs, or `options.ca_file`'s.
Result<std::unique_ptr<asio::ssl::context>> tls_context(const ClientOptions& options) {
    auto tls = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_client);
    SSL_CTX_set_min_proto_version(tls->native_handle(), TLS1_2_VERSION);
    asio::error_code ec;
    if (options.ca_file) {
        tls->load_verify_file(options.ca_file->string(), ec);
    } else {
        tls->set_default_verify_paths(ec);
    }
    if (ec) {
        return fail(Errc::invalid_argument, "cannot load the trusted CA certificates");
    }
    tls->set_verify_mode(asio::ssl::verify_peer);
    return tls;
}

/// A connection to a server: plain, or TLS over TCP.
struct Stream {
    std::optional<tcp::socket> plain;
    std::optional<asio::ssl::stream<tcp::socket>> secure;

    [[nodiscard]] bool open() const noexcept { return plain.has_value() || secure.has_value(); }
    void close() noexcept {
        asio::error_code ignored;
        if (secure) {
            secure->lowest_layer().close(ignored);
            secure.reset();
        }
        if (plain) {
            plain->close(ignored);
            plain.reset();
        }
    }
};

/// Connects `stream` to `to` (and shakes hands, with the certificate checked
/// for the host's name, if `tls`), or says why not.
asio::awaitable<std::optional<Error>> connect(asio::io_context& io, const Url& to,
                                              asio::ssl::context* tls, Stream& stream) {
    asio::error_code not_an_address;
    const asio::ip::address address = asio::ip::make_address(to.host, not_an_address);
    tcp::socket socket(io);
    asio::error_code connected;
    if (!not_an_address) {
        // An address needs no resolver, whose thread costs more than the
        // request.
        std::tie(connected) =
            co_await socket.async_connect(tcp::endpoint(address, to.port), use_tuple);
    } else {
        tcp::resolver resolver(io);
        auto [rec, endpoints] =
            co_await resolver.async_resolve(to.host, std::to_string(to.port), use_tuple);
        if (rec) {
            co_return Error{Errc::unavailable, "cannot resolve the server's host name"};
        }
        std::tie(connected, std::ignore) =
            co_await asio::async_connect(socket, endpoints, use_tuple);
    }
    if (connected) {
        co_return Error{Errc::unavailable, "cannot connect to the server"};
    }
    if (tls == nullptr) {
        stream.plain.emplace(std::move(socket));
        co_return std::nullopt;
    }
    stream.secure.emplace(std::move(socket), *tls);
    // SNI for host names (not addresses), and the certificate must name the
    // host.
    if (not_an_address) {
        std::string sni = to.host;
        SSL_ctrl(stream.secure->native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                 TLSEXT_NAMETYPE_host_name, sni.data());
    }
    stream.secure->set_verify_callback(asio::ssl::host_name_verification(to.host));
    if (auto [ec] =
            co_await stream.secure->async_handshake(asio::ssl::stream_base::client, use_tuple);
        ec) {
        const bool untrusted = ec.category() == asio::error::get_ssl_category();
        stream.close();
        co_return untrusted ? Error{Errc::verification_failed,
                                    "the server's TLS certificate is not trusted for its name"}
                            : Error{Errc::unavailable, "the TLS handshake with the server failed"};
    }
    co_return std::nullopt;
}

/// Sends `message` and reads one response into `outcome`, through `buffer`
/// (bytes read past the response stay there).
template <class S>
asio::awaitable<void> exchange(S& stream, const std::string& message, std::size_t max_body,
                               std::string& buffer, Outcome& outcome) {
    if (auto [ec, n] = co_await asio::async_write(stream, asio::buffer(message), use_tuple); ec) {
        outcome.error = Error{Errc::unavailable, "the connection to the server failed"};
        co_return;
    }
    std::array<char, 64 * 1024> chunk{};
    // Framing included, a response is never more than twice its body limit.
    // (Re-parsing on each read is bounded by that and by the timeout.)
    const std::size_t max_buffer = 2 * max_body + 64 * 1024;
    while (true) {
        auto [ec, n] = co_await stream.async_read_some(asio::buffer(chunk), use_tuple);
        buffer.append(chunk.data(), n);
        outcome.answered = outcome.answered || n > 0;
        const bool at_end = static_cast<bool>(ec);
        if (ec && ec != asio::error::eof && ec != asio::ssl::error::stream_truncated) {
            outcome.error = Error{Errc::unavailable, "the connection to the server failed"};
            co_return;
        }
        if (buffer.size() > max_buffer) {
            outcome.error = Error{Errc::limit_exceeded, "the server's response is too large"};
            co_return;
        }
        if (at_end && buffer.empty()) {
            // Closed before answering (an idle connection the server ended).
            outcome.error = Error{Errc::unavailable, "the server closed the connection"};
            co_return;
        }
        auto parsed = http::parse_response(buffer, max_body, at_end);
        if (!parsed) {
            outcome.error = parsed.error();
            co_return;
        }
        if (*parsed) {
            // HTTP/1.0 closes unless it says otherwise; 1.1 keeps the
            // connection unless it says close.
            const bool old = buffer.starts_with("HTTP/1.0");
            outcome.response = std::move((*parsed)->first);
            buffer.erase(0, (*parsed)->second);
            const auto field = outcome.response->header("connection");
            outcome.closing = at_end || !buffer.empty() ||
                              (old ? !(field && has_token(*field, "keep-alive"))
                                   : (field && has_token(*field, "close")));
            co_return;
        }
        if (at_end) {
            outcome.error = Error{Errc::unavailable, "the server closed the connection"};
            co_return;
        }
    }
}

/// Runs `io` until its work is done, or the timeout, or `stop`. False if it
/// had not finished.
[[nodiscard]] Result<bool> run_io(asio::io_context& io, const ClientOptions& options) {
    if (options.stop == nullptr) {
        io.run_for(options.timeout);
        return io.stopped();
    }
    // In slices, so that a stopping process need not wait for a long poll.
    const auto until = std::chrono::steady_clock::now() + options.timeout;
    while (!io.stopped() && std::chrono::steady_clock::now() < until) {
        if (options.stop->load()) {
            return fail(Errc::unavailable, "stopped");
        }
        io.run_for(std::min<std::chrono::steady_clock::duration>(
            std::chrono::milliseconds(100), until - std::chrono::steady_clock::now()));
    }
    return io.stopped();
}

/// Where a 307 or 308 sends the request next: the server, and the target.
/// Never from https to http.
std::optional<std::pair<Url, std::string>> redirect_of(const http::ClientResponse& response,
                                                       const Url& from) {
    const auto location = response.header("location");
    const std::size_t scheme = location ? location->find("://") : std::string_view::npos;
    if (scheme == std::string_view::npos) {
        return std::nullopt;
    }
    const std::size_t slash = location->find('/', scheme + 3);
    auto next = Url::parse(location->substr(0, slash));
    if (!next || (from.tls && !next->tls)) {
        return std::nullopt;
    }
    return std::pair(std::move(*next), slash == std::string_view::npos
                                           ? std::string("/")
                                           : std::string(location->substr(slash)));
}

bool redirecting(const http::ClientResponse& response) {
    return response.status == 307 || response.status == 308;
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
    // Nothing that could break a request line or a header field.
    if (std::ranges::any_of(text, [](char c) {
            const auto u = static_cast<unsigned char>(c);
            return u <= 0x20 || u >= 0x7f;
        })) {
        return fail(Errc::invalid_argument, "a server URL has no spaces or control characters");
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
    Url at = base_;
    std::string target = base_.base_path + std::string(path);
    // A cluster's followers send writers to the leader (307), with the
    // method and body kept; never from https to http.
    for (int hops = 0;; ++hops) {
        auto response = send(at, target, method, body, content_type);
        if (!response || !redirecting(*response) || hops == 3 || !options_.follow_redirects) {
            return response;
        }
        auto next = redirect_of(*response, at);
        if (!next) {
            return response;
        }
        at = std::move(next->first);
        target = std::move(next->second);
    }
}

Result<http::ClientResponse> Client::send(const Url& to, const std::string& target,
                                          std::string_view method, ByteView body,
                                          std::string_view content_type) const {
    auto message = request_message(to, target, method, body, content_type, options_, false);
    if (!message) {
        return std::unexpected(message.error());
    }
    std::unique_ptr<asio::ssl::context> tls;
    if (to.tls) {
        auto made = tls_context(options_);
        if (!made) {
            return std::unexpected(made.error());
        }
        tls = std::move(*made);
    }
    asio::io_context io;
    Outcome outcome;
    Stream stream;
    std::string buffer;
    auto run = [&]() -> asio::awaitable<void> {
        if (auto failed = co_await connect(io, to, tls.get(), stream); failed) {
            outcome.error = *failed;
            co_return;
        }
        if (stream.secure) {
            co_await exchange(*stream.secure, *message, options_.max_body, buffer, outcome);
        } else {
            co_await exchange(*stream.plain, *message, options_.max_body, buffer, outcome);
        }
    };
    asio::co_spawn(io, run(), asio::detached);
    const auto finished = run_io(io, options_);
    if (!finished) {
        return std::unexpected(finished.error());
    }
    if (!*finished) {
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

// ---- Connection ----------------------------------------------------------

struct Connection::State {
    std::unique_ptr<asio::io_context> io = std::make_unique<asio::io_context>();
    std::unique_ptr<asio::ssl::context> tls;
    Stream stream;
    /// Read from the connection, not yet part of a response.
    std::string buffer;

    void close() noexcept {
        stream.close();
        buffer.clear();
    }
    /// After a timeout or a stop: abandons what was in progress (a new
    /// io_context; the old one destroys the request's coroutine unresumed).
    void reset() {
        close();
        io = std::make_unique<asio::io_context>();
    }
};

Connection::Connection(Url base, ClientOptions options)
    : base_(std::move(base)), options_(std::move(options)), state_(std::make_unique<State>()) {}

Connection::Connection(Connection&&) noexcept = default;
Connection& Connection::operator=(Connection&&) noexcept = default;
Connection::~Connection() {
    close();
}

void Connection::close() noexcept {
    if (state_) {
        state_->close();
    }
}

Result<http::ClientResponse>
Connection::request(std::string_view method, std::string_view path, ByteView body,
                    std::string_view content_type,
                    const std::vector<std::pair<std::string, std::string>>& headers) {
    const std::string target = base_.base_path + std::string(path);
    auto message =
        request_message(base_, target, method, body, content_type, options_, true, headers);
    if (!message) {
        return std::unexpected(message.error());
    }
    State& s = *state_;
    if (base_.tls && !s.tls) {
        auto made = tls_context(options_);
        if (!made) {
            return std::unexpected(made.error());
        }
        s.tls = std::move(*made);
    }
    for (int attempt = 0;; ++attempt) {
        const bool reused = s.stream.open();
        Outcome outcome;
        auto run = [&]() -> asio::awaitable<void> {
            if (!s.stream.open()) {
                if (auto failed = co_await connect(*s.io, base_, s.tls.get(), s.stream); failed) {
                    outcome.error = *failed;
                    co_return;
                }
            }
            if (s.stream.secure) {
                co_await exchange(*s.stream.secure, *message, options_.max_body, s.buffer, outcome);
            } else {
                co_await exchange(*s.stream.plain, *message, options_.max_body, s.buffer, outcome);
            }
        };
        s.io->restart();
        asio::co_spawn(*s.io, run(), asio::detached);
        const auto finished = run_io(*s.io, options_);
        if (!finished || !*finished) {
            s.reset();
            if (!finished) {
                return std::unexpected(finished.error());
            }
            return fail(Errc::unavailable, "the server did not answer in time");
        }
        if (outcome.error || !outcome.response) {
            s.close();
            // The server closed a connection it had kept idle: once more,
            // on a new one, if nothing of an answer came.
            if (reused && !outcome.answered && attempt == 0 &&
                (!outcome.error || outcome.error->code == Errc::unavailable)) {
                continue;
            }
            if (outcome.error) {
                return std::unexpected(*outcome.error);
            }
            return fail(Errc::unavailable, "the server did not answer");
        }
        if (outcome.closing) {
            s.close();
        }
        http::ClientResponse response = std::move(*outcome.response);
        if (!redirecting(response) || !options_.follow_redirects) {
            return response;
        }
        // Elsewhere (a cluster's leader): through one-off connections.
        auto next = redirect_of(response, base_);
        if (!next) {
            return response;
        }
        ClientOptions elsewhere = options_;
        elsewhere.headers.insert(elsewhere.headers.end(), headers.begin(), headers.end());
        return Client(next->first, elsewhere).request(method, next->second, body, content_type);
    }
}

} // namespace cexchain::node
