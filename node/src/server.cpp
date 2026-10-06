// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <array>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <exception>
#include <format>
#include <mutex>
#include <set>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

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

/// What the server tracks of a connection, from any thread: whether a
/// request is in progress, and a way to close it on its own thread.
struct Tracked {
    Tracked() = default;
    Tracked(const Tracked&) = delete;
    Tracked& operator=(const Tracked&) = delete;
    virtual ~Tracked() = default;

    std::atomic<bool> busy = false;
    virtual void close_soon() = 0;
};

template <class Stream>
struct Connection final : Tracked, std::enable_shared_from_this<Connection<Stream>> {
    using Time = asio::steady_timer::time_point;

    Stream stream;
    asio::steady_timer timer;
    /// When the connection closes unless it gets on. Moving it later costs
    /// nothing (the watchdog finds out when the timer fires); only moving it
    /// earlier than the timer re-arms the timer. Keep-alive requests thus
    /// cost no timer operations.
    Time deadline = Time::max();
    std::string peer;

    Connection(Stream s, std::string peer_)
        : stream(std::move(s)), timer(stream.get_executor(), Time::max()), peer(std::move(peer_)) {}

    /// The rest: only on the connection's thread.
    void expire_after(std::chrono::steady_clock::duration timeout) {
        deadline = asio::steady_timer::clock_type::now() + timeout;
        if (deadline < timer.expiry()) {
            timer.expires_at(deadline); // the watchdog waits again
        }
    }

    void close() {
        asio::error_code ignored;
        stream.lowest_layer().close(ignored);
        timer.cancel();
    }

    void close_soon() override {
        asio::post(stream.get_executor(), [self = this->shared_from_this()] { self->close(); });
    }
};

/// Closes the connection when its deadline passes; closing the connection
/// ends it.
template <class Stream>
asio::awaitable<void> watchdog(std::shared_ptr<Connection<Stream>> c) {
    while (c->stream.lowest_layer().is_open()) {
        co_await c->timer.async_wait(use_tuple);
        const auto now = asio::steady_timer::clock_type::now();
        if (c->deadline <= now) {
            c->close();
            co_return;
        }
        if (c->timer.expiry() <= now) {
            c->timer.expires_at(c->deadline); // the deadline moved on meanwhile
        }
    }
}

} // namespace

struct Server::Impl {
    Impl(Application& app_, ServerOptions options_)
        : app(app_), options(std::move(options_)), acceptor(control),
          signals(control, SIGINT, SIGTERM), ticker(control) {
        const std::size_t threads = options.threads > 0
                                        ? options.threads
                                        : std::max(1U, std::thread::hardware_concurrency());
        for (std::size_t i = 0; i < threads; ++i) {
            workers.push_back(std::make_unique<asio::io_context>(1));
            guards.push_back(asio::make_work_guard(*workers.back()));
        }
    }

    Application& app;
    ServerOptions options;
    /// One event loop per I/O thread, each with its share of the
    /// connections: a connection's handlers all run on one thread, and no
    /// two threads contend for one loop's queue.
    std::vector<std::unique_ptr<asio::io_context>> workers;
    std::vector<asio::executor_work_guard<asio::io_context::executor_type>> guards;
    /// The acceptor, signals, ticks, and stopping, on the thread that called
    /// run().
    asio::io_context control{1};
    std::size_t next_worker = 0;
    tcp::acceptor acceptor;
    std::optional<asio::ssl::context> tls;
    asio::signal_set signals;
    asio::steady_timer ticker;
    std::atomic<bool> stopping = false;
    /// Set by listen(), before any thread runs.
    std::uint16_t bound_port = 0;

    std::mutex connections_mutex;
    std::set<Tracked*> connections;

    std::mutex log_mutex;
    std::string log_buffer;

    void track(Tracked* c) {
        const std::lock_guard lock(connections_mutex);
        connections.insert(c);
    }
    void untrack(Tracked* c) {
        const std::lock_guard lock(connections_mutex);
        connections.erase(c);
    }
    std::size_t open_connections() {
        const std::lock_guard lock(connections_mutex);
        return connections.size();
    }

    /// Lines are buffered and written out together: one lock, no flush per
    /// request.
    void log(const std::string& peer, std::string_view method, std::string_view target, int status,
             std::size_t bytes, std::chrono::steady_clock::duration elapsed,
             const std::string& principal) {
        if (options.access_log == nullptr) {
            return;
        }
        const auto now =
            std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
        std::string line = std::format(
            R"({{"time":"{:%FT%T}Z","peer":"{}","method":"{}","target":"{}","status":{},"bytes":{},"us":{}{}}})"
            "\n",
            now, json_escape(peer), json_escape(method), json_escape(target), status, bytes, us,
            principal.empty() ? std::string()
                              : R"(,"principal":")" + json_escape(principal) + "\"");
        const std::lock_guard lock(log_mutex);
        log_buffer += line;
        if (log_buffer.size() > 64 * 1024) {
            flush_log_locked();
        }
    }
    void flush_log_locked() {
        if (options.access_log != nullptr && !log_buffer.empty()) {
            *options.access_log << log_buffer;
            options.access_log->flush();
            log_buffer.clear();
        }
    }
    void flush_log() {
        const std::lock_guard lock(log_mutex);
        flush_log_locked();
    }

    /// Hands the request to the application and waits, without holding a
    /// thread, for its answer, which may come from any thread. Only the
    /// first answer counts.
    template <class Stream>
    asio::awaitable<http::Response> answer(std::shared_ptr<Connection<Stream>> c,
                                           http::Request request) {
        co_return co_await asio::async_initiate<decltype(asio::use_awaitable),
                                                void(http::Response)>(
            [&](auto handler) {
                using Handler = decltype(handler);
                struct Pending {
                    Handler resume;
                    std::atomic<bool> answered = false;
                };
                auto pending = std::make_shared<Pending>(std::move(handler));
                auto deliver = [pending,
                                executor = c->stream.get_executor()](http::Response response) {
                    if (!pending->answered.exchange(true)) {
                        asio::post(executor, [pending, response = std::move(response)]() mutable {
                            pending->resume(std::move(response));
                        });
                    }
                };
                Application::Respond fallback = deliver;
                try {
                    app.handle(std::move(request), c->peer, std::move(deliver));
                } catch (const std::exception&) {
                    fallback(plain_error(500, "internal error"));
                }
            },
            asio::use_awaitable);
    }

    template <class Stream>
    asio::awaitable<void> serve(std::shared_ptr<Connection<Stream>> c) {
        track(c.get());
        asio::co_spawn(c->stream.get_executor(), watchdog(c), asio::detached);
        co_await serve_requests(c);
        if constexpr (std::is_same_v<Stream, TlsStream>) {
            if (c->stream.lowest_layer().is_open()) {
                c->expire_after(std::chrono::seconds(2));
                co_await c->stream.async_shutdown(use_tuple);
            }
        } else {
            asio::error_code ignored;
            c->stream.shutdown(tcp::socket::shutdown_send, ignored);
        }
        c->close();
        untrack(c.get());
    }

    template <class Stream>
    asio::awaitable<void> serve_requests(std::shared_ptr<Connection<Stream>> c) {
        if constexpr (std::is_same_v<Stream, TlsStream>) {
            c->expire_after(options.request_timeout);
            auto [ec] =
                co_await c->stream.async_handshake(asio::ssl::stream_base::server, use_tuple);
            if (ec) {
                co_return;
            }
        }
        std::string buffer;
        std::array<char, 16 * 1024> chunk{};
        for (;;) {
            // In this order, against begin_stop(): either this sees
            // `stopping`, or begin_stop() sees the connection idle.
            c->busy = false;
            if (stopping) {
                co_return;
            }
            c->expire_after(buffer.empty() ? options.idle_timeout : options.request_timeout);
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
                    c->expire_after(options.request_timeout);
                }
                buffer.append(chunk.data(), n);
            }
            c->busy = true;
            const auto started = std::chrono::steady_clock::now();
            http::Response response;
            std::string method = "-";
            std::string target = "-";
            bool keep_alive = false;
            if (error) {
                response = plain_error(error->status, error->message);
            } else {
                buffer.erase(0, parsed->consumed);
                method = parsed->request.method;
                target = parsed->request.target;
                keep_alive = parsed->request.keep_alive;
                response = co_await answer(c, std::move(parsed->request));
            }
            keep_alive = keep_alive && !stopping;
            const std::string out = http::serialize(response, keep_alive);
            c->expire_after(options.request_timeout);
            auto [ec, n] = co_await asio::async_write(c->stream, asio::buffer(out), use_tuple);
            log(c->peer, method, target, response.status, out.size(),
                std::chrono::steady_clock::now() - started, response.principal);
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
        asio::steady_timer pause(control);
        while (acceptor.is_open()) {
            // Connections go to the I/O threads in turn.
            asio::io_context& worker = *workers[next_worker++ % workers.size()];
            auto [ec, socket] = co_await acceptor.async_accept(worker, use_tuple);
            if (ec) {
                if (!acceptor.is_open()) {
                    co_return;
                }
                // Out of descriptors or memory: let connections finish
                // first. Anything else (a client that gave up while queued,
                // say) concerns one connection only: accept the next at
                // once, before the listen queue overflows.
                if (ec == asio::error::no_descriptors || ec == asio::error::no_buffer_space ||
                    ec == asio::error::no_memory || ec.value() == ENFILE) {
                    pause.expires_after(std::chrono::milliseconds(100));
                    co_await pause.async_wait(use_tuple);
                }
                continue;
            }
            asio::error_code ignored;
            socket.set_option(tcp::no_delay(true), ignored);
            const auto endpoint = socket.remote_endpoint(ignored);
            std::string peer = ignored ? std::string("-") : endpoint.address().to_string();
            if (open_connections() >= options.max_connections) {
                auto executor = socket.get_executor();
                asio::co_spawn(executor, refuse(std::move(socket)), asio::detached);
                continue;
            }
            if (tls) {
                auto c = std::make_shared<Connection<TlsStream>>(TlsStream(std::move(socket), *tls),
                                                                 std::move(peer));
                auto executor = c->stream.get_executor();
                asio::co_spawn(executor, serve(std::move(c)), asio::detached);
            } else {
                auto c =
                    std::make_shared<Connection<tcp::socket>>(std::move(socket), std::move(peer));
                auto executor = c->stream.get_executor();
                asio::co_spawn(executor, serve(std::move(c)), asio::detached);
            }
        }
    }

    asio::awaitable<void> tick_loop() {
        while (!stopping) {
            ticker.expires_after(std::chrono::seconds(1));
            co_await ticker.async_wait(use_tuple);
            if (stopping) {
                break;
            }
            try {
                app.tick();
            } catch (const std::exception&) {
                // The application reports its own failures (e.g. in health).
            }
            flush_log();
        }
    }

    /// On `control`: stops accepting, closes idle connections, and stops
    /// every loop once the busy ones are done or their time is up.
    void begin_stop() {
        if (stopping.exchange(true)) {
            return;
        }
        asio::error_code ignored;
        acceptor.close(ignored);
        signals.cancel(ignored);
        ticker.cancel();
        {
            const std::lock_guard lock(connections_mutex);
            for (Tracked* c : connections) {
                if (!c->busy) {
                    c->close_soon();
                }
            }
        }
        asio::co_spawn(control, drain(), asio::detached);
    }

    asio::awaitable<void> drain() {
        asio::steady_timer timer(control);
        const auto until = std::chrono::steady_clock::now() + options.request_timeout;
        while (open_connections() > 0 && std::chrono::steady_clock::now() < until) {
            timer.expires_after(std::chrono::milliseconds(50));
            co_await timer.async_wait(use_tuple);
        }
        guards.clear();
        for (const auto& worker : workers) {
            worker->stop();
        }
        control.stop();
    }
};

Server::Server(Application& application, ServerOptions options)
    : impl_(std::make_unique<Impl>(application, std::move(options))) {}

Server::~Server() = default;

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
    if (!ec) {
        s.bound_port = s.acceptor.local_endpoint(ec).port();
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
    return impl_->bound_port;
}

void Server::run() {
    Impl& s = *impl_;
    asio::co_spawn(s.control, s.accept_loop(), asio::detached);
    asio::co_spawn(s.control, s.tick_loop(), asio::detached);
    s.signals.async_wait([&s](const asio::error_code& ec, int) {
        if (!ec) {
            s.begin_stop();
        }
    });
    std::vector<std::thread> pool;
    pool.reserve(s.workers.size());
    for (const auto& worker : s.workers) {
        pool.emplace_back([&w = *worker] { w.run(); });
    }
    s.control.run();
    for (std::thread& t : pool) {
        t.join();
    }
    // Answers still owed go nowhere now, but must be given while the loops
    // they would be posted to still exist.
    s.app.stop();
    s.flush_log();
}

void Server::stop() {
    asio::post(impl_->control, [this] { impl_->begin_stop(); });
}

} // namespace cexchain::node
