// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/error.hpp>

/// Child processes for executors (6b): connectors, and the programs the
/// `command` connector runs. POSIX only.
namespace cexchain::node {

/// How a child ended: its exit code, or the signal that ended it.
struct ExitStatus {
    int code = 0;
    int signal = 0;

    [[nodiscard]] bool success() const noexcept { return code == 0 && signal == 0; }
};

/// A child process with pipes to its stdin and stdout; its stderr is this
/// process's. It is started without a shell (the program and its arguments
/// are passed as given; a program without a slash is looked up in PATH), in
/// a process group of its own, with the default signal dispositions, and
/// with this process's environment minus every variable whose name starts
/// with CEXCHAIN_ (passphrases, tokens, PINs). Writing to a child that has
/// closed its stdin fails rather than raising SIGPIPE: the first start
/// ignores SIGPIPE in this process.
///
/// The destructor kills the process group (SIGKILL) if the child still runs,
/// and reaps the child.
class ChildProcess {
public:
    [[nodiscard]] static Result<ChildProcess> start(const std::string& program,
                                                    const std::vector<std::string>& arguments);

    ChildProcess(ChildProcess&& other) noexcept;
    ChildProcess& operator=(ChildProcess&& other) noexcept;
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ~ChildProcess();

    [[nodiscard]] pid_t pid() const noexcept { return pid_; }

    /// Writes all of `data` to the child's stdin within `timeout`. Fails
    /// with Errc::unavailable if the child closed its stdin or does not read.
    [[nodiscard]] Status write(std::string_view data, std::chrono::milliseconds timeout);
    /// Closes the child's stdin: it reads end of file.
    void close_input() noexcept;

    /// One line from the child's stdout, without its newline, if one comes
    /// within `timeout` (nullopt otherwise). Errc::unavailable at end of
    /// file; Errc::limit_exceeded for a line longer than `max` bytes (the
    /// rest of it is skipped).
    [[nodiscard]] Result<std::optional<std::string>> read_line(std::chrono::milliseconds timeout,
                                                               std::size_t max);

    /// What a program run to its end gave: its stdout (at most `max` bytes;
    /// `truncated` if it wrote more), and how it ended, or nothing if it
    /// was still running at the timeout (it is then killed).
    struct Run {
        Bytes output;
        bool truncated = false;
        std::optional<ExitStatus> exit;
    };
    /// Writes `input` to the child's stdin and closes it, while reading its
    /// stdout to the end, then waits for it to exit; all within `timeout`.
    [[nodiscard]] Run communicate(ByteView input, std::chrono::milliseconds timeout,
                                  std::size_t max);

    /// Waits up to `timeout` for the child to exit.
    [[nodiscard]] std::optional<ExitStatus> wait(std::chrono::milliseconds timeout);
    /// Asks the child's process group to stop (SIGTERM), and kills it
    /// (SIGKILL) if the child has not exited after `grace`.
    ExitStatus terminate(std::chrono::milliseconds grace);

private:
    ChildProcess() = default;
    void release() noexcept;

    pid_t pid_ = -1;
    int input_ = -1;
    int output_ = -1;
    std::optional<ExitStatus> exited_;
    /// Read from stdout, not yet returned as a line.
    std::string buffer_;
    bool output_closed_ = false;
};

} // namespace cexchain::node
