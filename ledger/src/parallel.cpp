// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <cexchain/ledger/parallel.hpp>

namespace cexchain::ledger {

namespace {

/// One parallel_for call: its ranges are claimed by an atomic cursor, so
/// workers and the caller balance the load between them.
struct Job {
    const std::function<void(std::size_t, std::size_t)>* work = nullptr;
    std::size_t count = 0;
    std::size_t chunk = 1;
    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> done{0};
    std::mutex mutex;
    std::condition_variable finished;

    /// Runs ranges until none are left.
    void run() {
        while (true) {
            const std::size_t begin = next.fetch_add(chunk, std::memory_order_relaxed);
            if (begin >= count) {
                return;
            }
            const std::size_t end = std::min(count, begin + chunk);
            (*work)(begin, end);
            if (done.fetch_add(end - begin, std::memory_order_acq_rel) + (end - begin) == count) {
                const std::lock_guard lock(mutex);
                finished.notify_all();
            }
        }
    }
};

thread_local bool inside_pool = false;

class Pool {
public:
    explicit Pool(std::size_t workers) {
        for (std::size_t i = 0; i < workers; ++i) {
            threads_.emplace_back([this] { loop(); });
        }
    }
    Pool(const Pool&) = delete;
    Pool& operator=(const Pool&) = delete;
    ~Pool() {
        {
            const std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        wake_.notify_all();
        for (std::thread& t : threads_) {
            t.join();
        }
    }

    void submit(const std::shared_ptr<Job>& job, std::size_t helpers) {
        {
            const std::lock_guard lock(mutex_);
            for (std::size_t i = 0; i < helpers; ++i) {
                queue_.push_back(job);
            }
        }
        wake_.notify_all();
    }

    [[nodiscard]] std::size_t workers() const noexcept { return threads_.size(); }

private:
    void loop() {
        inside_pool = true;
        while (true) {
            std::shared_ptr<Job> job;
            {
                std::unique_lock lock(mutex_);
                wake_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (stopping_ && queue_.empty()) {
                    return;
                }
                job = std::move(queue_.front());
                queue_.pop_front();
            }
            job->run();
        }
    }

    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<std::shared_ptr<Job>> queue_;
    std::vector<std::thread> threads_;
    bool stopping_ = false;
};

std::size_t configured_threads() noexcept {
    if (const char* env = std::getenv("CEXCHAIN_THREADS"); env != nullptr && *env != '\0') {
        std::size_t value = 0;
        const auto [ptr, ec] = std::from_chars(env, env + std::strlen(env), value);
        if (ec == std::errc{} && *ptr == '\0' && value > 0) {
            return std::min<std::size_t>(value, 256);
        }
    }
    return std::max(1U, std::thread::hardware_concurrency());
}

Pool& pool() {
    // Never destroyed: worker threads must not outlive their pool, and
    // static destruction order cannot be relied on at exit.
    static Pool* instance = new Pool(configured_threads() - 1);
    return *instance;
}

} // namespace

std::size_t parallelism() noexcept {
    return configured_threads();
}

void parallel_for(std::size_t count,
                  const std::function<void(std::size_t begin, std::size_t end)>& work) {
    constexpr std::size_t min_parallel = 8;
    if (count == 0) {
        return;
    }
    Pool& p = pool();
    if (count < min_parallel || p.workers() == 0 || inside_pool) {
        work(0, count);
        return;
    }
    auto job = std::make_shared<Job>();
    job->work = &work;
    job->count = count;
    // Enough ranges to balance uneven work, few enough to keep overhead low.
    job->chunk = std::max<std::size_t>(1, count / ((p.workers() + 1) * 8));
    const std::size_t helpers = std::min(p.workers(), (count + job->chunk - 1) / job->chunk - 1);
    p.submit(job, helpers);
    job->run();
    std::unique_lock lock(job->mutex);
    job->finished.wait(lock, [&] { return job->done.load(std::memory_order_acquire) == count; });
}

} // namespace cexchain::ledger
