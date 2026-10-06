// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <array>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <atomic>
#include <csignal>
#include <exception>
#include <format>
#include <set>
#include <type_traits>
#include <utility>

#include <openssl/ssl.h>

#include <cexchain/node/server.hpp>

namespace cexchain::node {

namespace {

using asio::ip::tcp;
using TlsStream = asio::ssl::stream<tcp::socket>;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

std::string json_escape(std::string_view text) {
    std::string out;
    for (const char c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (u < 0x20 || u == 0x7f) {
            out += std::format("\\u{:04x}", u);
        } else {
            out.push_back(c);
        }
    }
    return out;
}

http::Response plain_error(int status, std::string_view message) {
    http::Response r;
    r.status = status;
    const std::string body =
        R"({"error":{"code":"http","message":")" + json_escape(message) + "\"}}";
    r.body.assign(body.begin(), body.end());
    return r;
}

/// What the server tracks of a connection: whether a request is in
/// progress, and how to close it.
struct Tracked {
    bool busy = false;
    virtual void close() = 0;

protected:
    Tracked() = default;
    Tracked(const Tracked&) = default;
    Tracked& operator=(const Tracked&) = default;
    ~Tracked() = default;
};

template <class Stream>
struct Connection final : Tracked {
    Stream stream;
    asio::steady_timer deadline;
    std::string peer;

    Connection(Stream s, std::string peer_)
        : stream(std::move(s)), deadline(stream.get_executor()), peer(std::move(peer_)) {}

    void close() override {
        asio::error_code ignored;
        stream.lowest_layer().close(ignored);
        deadline.cancel();
    }
};

/// Closes the connection when its deadline passes. Moving the deadline
/// re-arms it; closing the connection ends it.
template <class Stream>
asio::awaitable<void> watchdog(std::shared_ptr<Connection<Stream>> c) {
    while (c->stream.lowest_layer().is_open()) {
        co_await c->deadline.async_wait(use_tuple);
        if (c->deadline.expiry() <= asio::steady_timer::clock_type::now()) {
            c->close();
            co_return;
        }
    }
}

} // namespace

struct Server::Impl {
    Impl(Application& app_, ServerOptions options_) : app(app_), options(std::move(options_)) {}

    Application& app;
    ServerOptions options;
    asio::io_context io{1};
    asio::thread_pool app_thread{1};
    tcp::acceptor acceptor{io};
    std::optional<asio::ssl::context> tls;
    asio::signal_set signals{io, SIGINT, SIGTERM};
    std::atomic<bool> ticking{true};
    // I/O thread only:
    std::set<Tracked*> open_connections;
    bool stopping = false;

    struct Handled {
        http::Response response;
        std::string principal;
    };

    asio::awaitable<Handled> handle_on_app_thread(const http::Request& request,
                                                  const std::string& peer) {
        try {
            http::Response response = app.handle(request, peer);
            co_return Handled{std::move(response), app.principal()};
        } catch (const std::exception&) {
            co_return Handled{plain_error(500, "internal error"), {}};
        }
    }

    void log(const std::string& peer, std::string_view method, std::string_view target, int status,
             std::size_t bytes, std::chrono::steady_clock::duration elapsed,
             const std::string& principal) const {
        if (options.access_log == nullptr) {
            return;
        }
        const auto now =
            std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
        *options.access_log << std::format(
            R"({{"time":"{:%FT%T}Z","peer":"{}","method":"{}","target":"{}","status":{},"bytes":{},"us":{}{}}})"
            "\n",
            now, json_escape(peer), json_escape(method), json_escape(target), status, bytes, us,
            principal.empty() ? std::string()
                              : R"(,"principal":")" + json_escape(principal) + "\"");
        options.access_log->flush();
    }

    template <class Stream>
    asio::awaitable<void> serve(std::shared_ptr<Connection<Stream>> c) {
        open_connections.insert(c.get());
        asio::co_spawn(io, watchdog(c), asio::detached);
        co_await serve_requests(c);
        if constexpr (std::is_same_v<Stream, TlsStream>) {
            if (c->stream.lowest_layer().is_open()) {
                c->deadline.expires_after(std::chrono::seconds(2));
                co_await c->stream.async_shutdown(use_tuple);
            }
        } else {
            asio::error_code ignored;
            c->stream.shutdown(tcp::socket::shutdown_send, ignored);
        }
        c->close();
        open_connections.erase(c.get());
    }

    template <class Stream>
    asio::awaitable<void> serve_requests(std::shared_ptr<Connection<Stream>> c) {
        if constexpr (std::is_same_v<Stream, TlsStream>) {
            c->deadline.expires_after(options.request_timeout);
            auto [ec] =
                co_await c->stream.async_handshake(asio::ssl::stream_base::server, use_tuple);
            if (ec) {
                co_return;
            }
        }
        std::string buffer;
        std::array<char, 16 * 1024> chunk{};
        while (!stopping) {
            c->busy = false;
            c->deadline.expires_after(buffer.empty() ? options.idle_timeout
                                                     : options.request_timeout);
            std::optional<http::ParseError> error;
            std::optional<http::Parsed> parsed;
            bool wants_continue = false;
            bool sent_continue = false;
            while (
                !(parsed = http::parse_request(buffer, options.limits, error, &wants_continue)) &&
                !error) {
                if (wants_continue && !sent_continue) {
                    static constexpr std::string_view proceed = "HTTP/1.1 100 Continue\r\n\r\n";
                    auto [ec, n] =
                        co_await asio::async_write(c->stream, asio::buffer(proceed), use_tuple);
                    if (ec) {
                        co_return;
                    }
                    sent_continue = true;
                }
                auto [ec, n] = co_await c->stream.async_read_some(asio::buffer(chunk), use_tuple);
                if (ec) {
                    co_return; // closed by the client, timed out, or failed
                }
                if (buffer.empty()) {
                    c->deadline.expires_after(options.request_timeout);
                }
                buffer.append(chunk.data(), n);
            }
            c->busy = true;
            const auto started = std::chrono::steady_clock::now();
            Handled handled;
            std::string method = "-";
            std::string target = "-";
            bool keep_alive = false;
            if (error) {
                handled.response = plain_error(error->status, error->message);
            } else {
                buffer.erase(0, parsed->consumed);
                method = parsed->request.method;
                target = parsed->request.target;
                keep_alive = parsed->request.keep_alive;
                handled = co_await asio::co_spawn(app_thread,
                                                  handle_on_app_thread(parsed->request, c->peer),
                                                  asio::use_awaitable);
            }
            keep_alive = keep_alive && !stopping;
            const std::string out = http::serialize(handled.response, keep_alive);
            c->deadline.expires_after(options.request_timeout);
            auto [ec, n] = co_await asio::async_write(c->stream, asio::buffer(out), use_tuple);
            log(c->peer, method, target, handled.response.status, out.size(),
                std::chrono::steady_clock::now() - started, handled.principal);
            if (ec || !keep_alive) {
                co_return;
            }
        }
    }

    asio::awaitable<void> refuse(tcp::socket socket) {
        const std::string out = http::serialize(plain_error(503, "too many connections"), false);
        co_await asio::async_write(socket, asio::buffer(out), use_tuple);
        asio::error_code ignored;
        socket.shutdown(tcp::socket::shutdown_send, ignored);
        socket.close(ignored);
    }

    asio::awaitable<void> accept_loop() {
        asio::steady_timer pause(io);
        while (acceptor.is_open()) {
            auto [ec, socket] = co_await acceptor.async_accept(use_tuple);
            if (ec) {
                if (!acceptor.is_open()) {
                    co_return;
                }
                // Out of descriptors, say: let connections finish first.
                pause.expires_after(std::chrono::milliseconds(100));
                co_await pause.async_wait(use_tuple);
                continue;
            }
            asio::error_code ignored;
            socket.set_option(tcp::no_delay(true), ignored);
            const auto endpoint = socket.remote_endpoint(ignored);
            std::string peer = ignored ? std::string("-") : endpoint.address().to_string();
            if (open_connections.size() >= options.max_connections) {
                asio::co_spawn(io, refuse(std::move(socket)), asio::detached);
                continue;
            }
            if (tls) {
                auto c = std::make_shared<Connection<TlsStream>>(TlsStream(std::move(socket), *tls),
                                                                 std::move(peer));
                asio::co_spawn(io, serve(std::move(c)), asio::detached);
            } else {
                auto c =
                    std::make_shared<Connection<tcp::socket>>(std::move(socket), std::move(peer));
                asio::co_spawn(io, serve(std::move(c)), asio::detached);
            }
        }
    }

    asio::awaitable<void> tick_loop() {
        asio::steady_timer timer(co_await asio::this_coro::executor);
        while (ticking) {
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(use_tuple);
            if (!ticking) {
                break;
            }
            try {
                app.tick();
            } catch (const std::exception&) {
                // The application reports its own failures (e.g. in health).
            }
        }
    }

    /// Stops accepting, closes idle connections, and returns from run() once
    /// the busy ones are done or their time is up.
    void begin_stop() {
        if (stopping) {
            return;
        }
        stopping = true;
        asio::error_code ignored;
        acceptor.close(ignored);
        signals.cancel(ignored);
        for (Tracked* c : std::set(open_connections)) {
            if (!c->busy) {
                c->close();
            }
        }
        asio::co_spawn(io, drain(), asio::detached);
    }

    asio::awaitable<void> drain() {
        asio::steady_timer timer(io);
        const auto until = std::chrono::steady_clock::now() + options.request_timeout;
        while (!open_connections.empty() && std::chrono::steady_clock::now() < until) {
            timer.expires_after(std::chrono::milliseconds(50));
            co_await timer.async_wait(use_tuple);
        }
        io.stop();
    }
};

Server::Server(Application& application, ServerOptions options)
    : impl_(std::make_unique<Impl>(application, std::move(options))) {}

Server::~Server() {
    impl_->ticking = false;
    impl_->app_thread.join();
}

Status Server::listen() {
    Impl& s = *impl_;
    asio::error_code ec;
    const auto address = asio::ip::make_address(s.options.host, ec);
    if (ec) {
        return fail(Errc::invalid_argument, "the listen address must be an IP address");
    }
    const tcp::endpoint endpoint(address, s.options.port);
    s.acceptor.open(endpoint.protocol(), ec);
    if (!ec) {
        s.acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
    }
    if (!ec) {
        s.acceptor.bind(endpoint, ec);
    }
    if (!ec) {
        s.acceptor.listen(asio::socket_base::max_listen_connections, ec);
    }
    if (ec) {
        return fail(Errc::unavailable, "cannot listen on the address (in use, or not local?)");
    }
    if (s.options.tls_certificate || s.options.tls_private_key) {
        if (!s.options.tls_certificate || !s.options.tls_private_key) {
            return fail(Errc::invalid_argument, "TLS needs both a certificate and a private key");
        }
        asio::ssl::context context(asio::ssl::context::tls_server);
        SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_2_VERSION);
        context.set_options(asio::ssl::context::default_workarounds |
                            asio::ssl::context::no_compression);
        context.use_certificate_chain_file(s.options.tls_certificate->string(), ec);
        if (!ec) {
            context.use_private_key_file(s.options.tls_private_key->string(),
                                         asio::ssl::context::pem, ec);
        }
        if (ec || SSL_CTX_check_private_key(context.native_handle()) != 1) {
            return fail(Errc::invalid_argument,
                        "cannot load the TLS certificate and its private key (PEM)");
        }
        s.tls.emplace(std::move(context));
    }
    return {};
}

std::uint16_t Server::port() const {
    asio::error_code ec;
    const auto endpoint = impl_->acceptor.local_endpoint(ec);
    return ec ? 0 : endpoint.port();
}

void Server::run() {
    Impl& s = *impl_;
    asio::co_spawn(s.io, s.accept_loop(), asio::detached);
    asio::co_spawn(s.app_thread, s.tick_loop(), asio::detached);
    s.signals.async_wait([&s](const asio::error_code& ec, int) {
        if (!ec) {
            s.begin_stop();
        }
    });
    s.io.run();
    s.ticking = false;
}

void Server::stop() {
    asio::post(impl_->io, [this] { impl_->begin_stop(); });
}

} // namespace cexchain::node
