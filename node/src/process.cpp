// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>

#include <cexchain/node/process.hpp>

extern char** environ; // NOLINT(readability-redundant-declaration)

namespace cexchain::node {

namespace {

using clock = std::chrono::steady_clock;

void close_fd(int& fd) noexcept {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

bool set_flags(int fd, bool nonblocking) noexcept {
    const int fd_flags = ::fcntl(fd, F_GETFD);
    if (fd_flags < 0 || ::fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
        return false;
    }
    if (nonblocking) {
        const int flags = ::fcntl(fd, F_GETFL);
        return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
    }
    return true;
}

ExitStatus status_of(int raw) noexcept {
    ExitStatus s;
    if (WIFEXITED(raw)) {
        s.code = WEXITSTATUS(raw);
    } else if (WIFSIGNALED(raw)) {
        s.signal = WTERMSIG(raw);
        s.code = 128 + s.signal;
    }
    return s;
}

/// Milliseconds left until `until`, for poll (0 if past).
int left_ms(clock::time_point until) noexcept {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - clock::now());
    return static_cast<int>(std::clamp<std::int64_t>(left.count(), 0, 1'000'000));
}

} // namespace

Result<ChildProcess> ChildProcess::start(const std::string& program,
                                         const std::vector<std::string>& arguments) {
    static std::once_flag ignore_sigpipe;
    std::call_once(ignore_sigpipe, [] { std::signal(SIGPIPE, SIG_IGN); });
    if (program.empty() || program.find('\0') != std::string::npos) {
        return fail(Errc::invalid_argument, "a program is named");
    }

    std::array<int, 2> in{-1, -1};
    std::array<int, 2> out{-1, -1};
    auto close_all = [&] {
        for (int* fd : {&in[0], &in[1], &out[0], &out[1]}) {
            close_fd(*fd);
        }
    };
    if (::pipe(in.data()) != 0 || ::pipe(out.data()) != 0 || !set_flags(in[0], false) ||
        !set_flags(in[1], true) || !set_flags(out[0], true) || !set_flags(out[1], false)) {
        close_all();
        return fail(Errc::unavailable, "cannot make pipes for a child process");
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, in[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out[1], STDOUT_FILENO);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    sigset_t defaults;
    sigemptyset(&defaults);
    for (const int s : {SIGPIPE, SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGCHLD}) {
        sigaddset(&defaults, s);
    }
    sigset_t none;
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&attributes, &defaults);
    posix_spawnattr_setsigmask(&attributes, &none);
    posix_spawnattr_setpgroup(&attributes, 0);
    posix_spawnattr_setflags(
        &attributes,
        static_cast<short>(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETPGROUP));

    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(program.c_str()));
    for (const std::string& a : arguments) {
        argv.push_back(const_cast<char*>(a.c_str()));
    }
    argv.push_back(nullptr);
    std::vector<char*> envp;
    for (char** e = environ; e != nullptr && *e != nullptr; ++e) {
        if (std::strncmp(*e, "CEXCHAIN_", 9) != 0) {
            envp.push_back(*e);
        }
    }
    envp.push_back(nullptr);

    pid_t pid = -1;
    const int spawned =
        program.find('/') == std::string::npos
            ? ::posix_spawnp(&pid, program.c_str(), &actions, &attributes, argv.data(), envp.data())
            : ::posix_spawn(&pid, program.c_str(), &actions, &attributes, argv.data(), envp.data());
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    close_fd(in[0]);
    close_fd(out[1]);
    if (spawned != 0) {
        close_all();
        return fail(Errc::unavailable, "cannot start the program");
    }
    ChildProcess child;
    child.pid_ = pid;
    child.input_ = in[1];
    child.output_ = out[0];
    return child;
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : pid_(std::exchange(other.pid_, -1)), input_(std::exchange(other.input_, -1)),
      output_(std::exchange(other.output_, -1)), exited_(other.exited_),
      buffer_(std::move(other.buffer_)), output_closed_(other.output_closed_) {}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
        release();
        pid_ = std::exchange(other.pid_, -1);
        input_ = std::exchange(other.input_, -1);
        output_ = std::exchange(other.output_, -1);
        exited_ = other.exited_;
        buffer_ = std::move(other.buffer_);
        output_closed_ = other.output_closed_;
    }
    return *this;
}

ChildProcess::~ChildProcess() {
    release();
}

void ChildProcess::release() noexcept {
    close_fd(input_);
    close_fd(output_);
    if (pid_ > 0 && !exited_) {
        ::kill(-pid_, SIGKILL);
        ::kill(pid_, SIGKILL);
        int raw = 0;
        while (::waitpid(pid_, &raw, 0) < 0 && errno == EINTR) {
        }
    }
    pid_ = -1;
}

Status ChildProcess::write(std::string_view data, std::chrono::milliseconds timeout) {
    const auto until = clock::now() + timeout;
    while (!data.empty()) {
        if (input_ < 0) {
            return fail(Errc::unavailable, "the child's input is closed");
        }
        const ssize_t n = ::write(input_, data.data(), data.size());
        if (n > 0) {
            data.remove_prefix(static_cast<std::size_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd p{input_, POLLOUT, 0};
            const int ready = ::poll(&p, 1, left_ms(until));
            if (ready == 0) {
                return fail(Errc::unavailable, "the child does not read its input");
            }
            continue;
        }
        return fail(Errc::unavailable, "the child closed its input");
    }
    return {};
}

void ChildProcess::close_input() noexcept {
    close_fd(input_);
}

Result<std::optional<std::string>> ChildProcess::read_line(std::chrono::milliseconds timeout,
                                                           std::size_t max) {
    const auto until = clock::now() + timeout;
    bool skipping = false;
    for (;;) {
        if (const std::size_t newline = buffer_.find('\n'); newline != std::string::npos) {
            std::string line = buffer_.substr(0, newline);
            buffer_.erase(0, newline + 1);
            if (skipping || line.size() > max) {
                return fail(Errc::limit_exceeded, "a line from the child is too long");
            }
            return std::optional<std::string>(std::move(line));
        }
        if (buffer_.size() > max) {
            // Too long already: drop it, and the rest of the line later.
            buffer_.clear();
            skipping = true;
        }
        if (output_closed_ || output_ < 0) {
            return fail(Errc::unavailable, "the child closed its output");
        }
        pollfd p{output_, POLLIN, 0};
        const int ready = ::poll(&p, 1, left_ms(until));
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            if (skipping) {
                return fail(Errc::limit_exceeded, "a line from the child is too long");
            }
            return std::optional<std::string>();
        }
        std::array<char, 65536> chunk{};
        const ssize_t n = ::read(output_, chunk.data(), chunk.size());
        if (n > 0) {
            buffer_.append(chunk.data(), static_cast<std::size_t>(n));
        } else if (n == 0) {
            output_closed_ = true;
        } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            output_closed_ = true;
        }
    }
}

ChildProcess::Run ChildProcess::communicate(ByteView input, std::chrono::milliseconds timeout,
                                            std::size_t max) {
    const auto until = clock::now() + timeout;
    Run run;
    std::size_t written = 0;
    if (input.empty()) {
        close_input();
    }
    while (output_ >= 0 && !output_closed_) {
        std::array<pollfd, 2> fds{pollfd{output_, POLLIN, 0}, pollfd{input_, POLLOUT, 0}};
        const nfds_t count = input_ >= 0 ? 2 : 1;
        const int ready = ::poll(fds.data(), count, left_ms(until));
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            break; // the timeout
        }
        if (input_ >= 0 && (fds[1].revents & (POLLOUT | POLLERR | POLLHUP)) != 0) {
            const ssize_t n = ::write(input_, input.data() + written, input.size() - written);
            if (n > 0) {
                written += static_cast<std::size_t>(n);
            }
            if ((n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) ||
                written == input.size()) {
                close_input(); // done, or the child stopped reading
            }
        }
        if ((fds[0].revents & (POLLIN | POLLERR | POLLHUP)) != 0) {
            std::array<std::uint8_t, 65536> chunk{};
            const ssize_t n = ::read(output_, chunk.data(), chunk.size());
            if (n > 0) {
                const std::size_t room = max - std::min(max, run.output.size());
                const auto take = std::min(room, static_cast<std::size_t>(n));
                run.output.insert(run.output.end(), chunk.begin(),
                                  chunk.begin() + static_cast<std::ptrdiff_t>(take));
                run.truncated = run.truncated || take < static_cast<std::size_t>(n);
            } else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                output_closed_ = true;
            }
        }
    }
    close_input();
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - clock::now());
    run.exit = wait(std::max(left, std::chrono::milliseconds(0)));
    if (!run.exit) {
        terminate(std::chrono::milliseconds(0));
    }
    return run;
}

std::optional<ExitStatus> ChildProcess::wait(std::chrono::milliseconds timeout) {
    if (exited_) {
        return exited_;
    }
    if (pid_ <= 0) {
        return std::nullopt;
    }
    const auto until = clock::now() + timeout;
    for (;;) {
        int raw = 0;
        const pid_t r = ::waitpid(pid_, &raw, WNOHANG);
        if (r == pid_) {
            exited_ = status_of(raw);
            return exited_;
        }
        if (r < 0 && errno != EINTR) {
            exited_ = ExitStatus{127, 0};
            return exited_;
        }
        if (clock::now() >= until) {
            return std::nullopt;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

ExitStatus ChildProcess::terminate(std::chrono::milliseconds grace) {
    if (const auto done = wait(std::chrono::milliseconds(0))) {
        return *done;
    }
    ::kill(-pid_, SIGTERM);
    if (const auto done = wait(grace)) {
        return *done;
    }
    ::kill(-pid_, SIGKILL);
    ::kill(pid_, SIGKILL);
    int raw = 0;
    while (::waitpid(pid_, &raw, 0) < 0 && errno == EINTR) {
    }
    exited_ = status_of(raw);
    return *exited_;
}

} // namespace cexchain::node
