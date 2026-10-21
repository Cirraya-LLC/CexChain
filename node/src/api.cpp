// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <deque>
#include <format>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <utility>
#include <variant>

#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/access.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/core/protocol/witness.hpp>
#include <cexchain/ledger/parallel.hpp>
#include <cexchain/ledger/verify.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/cluster.hpp>
#include <cexchain/node/contracts.hpp>
#include <cexchain/node/keeper.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/tokens.hpp>

#include "files.hpp"
#include "request_query.hpp"

namespace cexchain::node {

namespace {

using json = nlohmann::json;
using steady = std::chrono::steady_clock;

constexpr std::uint64_t max_batch = 1000;
/// Peers' pending access requests: at most this many, this large each.
constexpr std::size_t max_inbox = 4096;
constexpr std::size_t max_access_request = 256 * 1024;
/// A call proposal: its arguments (at most 64 KiB) and a little more.
constexpr std::size_t max_call_proposal = 128 * 1024;
constexpr std::size_t max_batch_bytes = 8 * 1024 * 1024;

std::string_view errc_name(Errc code) {
    switch (code) {
    case Errc::invalid_argument:
        return "invalid_argument";
    case Errc::truncated:
        return "truncated";
    case Errc::malformed:
        return "malformed";
    case Errc::non_canonical:
        return "non_canonical";
    case Errc::unsupported:
        return "unsupported";
    case Errc::limit_exceeded:
        return "limit_exceeded";
    case Errc::verification_failed:
        return "verification_failed";
    case Errc::crypto_failure:
        return "crypto_failure";
    case Errc::rejected:
        return "rejected";
    case Errc::not_found:
        return "not_found";
    case Errc::unavailable:
        return "unavailable";
    }
    return "unknown";
}

int status_of(Errc code) {
    switch (code) {
    case Errc::limit_exceeded:
        return 413;
    case Errc::verification_failed:
        return 422;
    case Errc::rejected:
        return 409;
    case Errc::not_found:
        return 404;
    case Errc::unavailable:
        return 503;
    case Errc::crypto_failure:
        return 500;
    default:
        return 400;
    }
}

http::Response json_response(int status, const json& body) {
    http::Response r;
    r.status = status;
    const std::string text = body.dump() + "\n";
    r.body.assign(text.begin(), text.end());
    return r;
}

http::Response error_response(int status, std::string_view code, std::string_view message) {
    return json_response(status, {{"error", {{"code", code}, {"message", message}}}});
}

http::Response error_response(const Error& error) {
    return error_response(status_of(error.code), errc_name(error.code), error.detail);
}

http::Response binary(std::string_view content_type, Bytes body) {
    http::Response r;
    r.content_type = std::string(content_type);
    r.body = std::move(body);
    return r;
}

http::Response cbor_response(const cbor::Value& value) {
    auto encoded = cbor::encode(value);
    if (!encoded) {
        return error_response(encoded.error());
    }
    return binary("application/cbor", std::move(*encoded));
}

/// A query parameter as an unsigned integer.
std::optional<std::uint64_t> number(const http::Request& r, std::string_view name) {
    const auto it = r.query.find(name);
    if (it == r.query.end()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const std::string& text = it->second;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size() || text.empty()) {
        return std::nullopt;
    }
    return value;
}

std::optional<protocol::Id> id_from(std::string_view hex) {
    if (hex.size() != 64) {
        return std::nullopt;
    }
    auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

json checkpoint_json(const protocol::Checkpoint& c) {
    return {
        {"tree_size", c.tree_size}, {"root", to_hex(c.root.bytes())}, {"timestamp", c.timestamp}};
}

cbor::Value digests_value(const std::vector<crypto::Digest>& digests) {
    cbor::Array out;
    for (const crypto::Digest& d : digests) {
        out.push_back(cbor::Value::bytes(d.bytes()));
    }
    return cbor::Value::array(std::move(out));
}

/// read_or_peer, submit_or_peer: a read (or submit) token, or a peer's (whom
/// the route then checks). The ones with executor take an executor's token
/// too (6b), which the route then restricts.
enum class Access {
    open,
    read,
    submit,
    admin,
    peer,
    read_or_peer,
    submit_or_peer,
    read_or_executor,
    read_peer_or_executor,
    submit_or_executor,
};

/// The token scopes that may use a route of `access` (not open).
constexpr Scopes allowed_scopes(Access access) noexcept {
    auto s = [](Scope scope) {
        return static_cast<Scopes>(scope);
    };
    switch (access) {
    case Access::open:
        return 0;
    case Access::read:
        return s(Scope::read);
    case Access::submit:
        return s(Scope::submit);
    case Access::admin:
        return s(Scope::admin);
    case Access::peer:
        return s(Scope::peer);
    case Access::read_or_peer:
        return s(Scope::read) | s(Scope::peer);
    case Access::submit_or_peer:
        return s(Scope::submit) | s(Scope::peer);
    case Access::read_or_executor:
        return s(Scope::read) | s(Scope::executor);
    case Access::read_peer_or_executor:
        return s(Scope::read) | s(Scope::peer) | s(Scope::executor);
    case Access::submit_or_executor:
        return s(Scope::submit) | s(Scope::executor);
    }
    return 0;
}

enum class Endpoint {
    metrics,
    status,
    get_checkpoint,
    make_checkpoint,
    consistency,
    entries,
    checkpoints,
    cosignatures,
    add_cosignature,
    inclusion,
    submit,
    statement,
    receipt,
    state,
    evidence,
    vault_public_key,
    vault_record,
    access_request,
    access_delivery,
    access_receipt,
    witness_cosign,
    cluster_status,
    cluster_add,
    cluster_remove,
    cluster_step_down,
    contract_list,
    contract_show,
    contracts_due,
    instance_evidence,
    call_propose,
    call_list,
    call_show,
    contract_consent,
    requests,
};

/// Where a request goes. `rest` is where the path's last segment (an id or
/// an index) starts, an offset since the request may move.
struct Routed {
    Endpoint endpoint;
    Access access;
    std::size_t rest = 0;
};

/// Statements one group commit takes at most.
/// The shape of a sealed vault file, {1: 1, 2: [kem, kdf, aead], 3:
/// encapsulated key, 4: ciphertext}: the server cannot open one, but stores
/// nothing else.
bool is_sealed_vault(ByteView file) {
    const auto value = cbor::decode(file);
    const cbor::Map* map = value ? value->as_map() : nullptr;
    if (map == nullptr || map->size() != 4) {
        return false;
    }
    const cbor::Value* version = value->find(1);
    const cbor::Value* suite = value->find(2);
    const cbor::Value* enc = value->find(3);
    const cbor::Value* ciphertext = value->find(4);
    const cbor::Array* ids = suite != nullptr ? suite->as_array() : nullptr;
    return version != nullptr && version->as_uint64() == 1 && ids != nullptr && ids->size() == 3 &&
           std::ranges::all_of(*ids,
                               [](const cbor::Value& id) { return id.as_uint64().has_value(); }) &&
           enc != nullptr && enc->as_bytes() != nullptr && ciphertext != nullptr &&
           ciphertext->as_bytes() != nullptr;
}

constexpr std::size_t max_group = 4096;
constexpr std::size_t max_group_bytes = 32 * 1024 * 1024;

using detail::parse_request_query;
using detail::RequestQuery;

/// Long polls waiting at once; another one is answered at once.
constexpr std::size_t max_waiters = 1024;

/// Randomness shared by the threads that sign (the writer, for the
/// registrar; the keeper's thread): one draw at a time.
class SharedEntropy final : public ledger::Entropy {
public:
    void use(ledger::Entropy& source) noexcept { source_ = &source; }
    void fill(std::span<std::uint8_t> out) override {
        const std::lock_guard lock(mutex_);
        source_->fill(out);
    }

private:
    std::mutex mutex_;
    ledger::SystemEntropy system_;
    ledger::Entropy* source_ = &system_;
};

/// A job handed to the writer by another thread, which waits for it: done
/// once it has run, or once the writer refused it (busy, unusable,
/// stopping) or dropped it.
class Handoff {
public:
    void finish(bool ran) {
        {
            const std::lock_guard lock(mutex_);
            if (finished_) {
                return;
            }
            finished_ = true;
            ran_ = ran;
        }
        done_.notify_all();
    }
    /// True if the job ran.
    [[nodiscard]] bool wait() {
        std::unique_lock lock(mutex_);
        done_.wait(lock, [&] { return finished_; });
        return ran_;
    }

private:
    std::mutex mutex_;
    std::condition_variable done_;
    bool finished_ = false;
    bool ran_ = false;
};

/// Held by the queued job only: a job destroyed without running finishes
/// its handoff as not run.
struct HandoffGuard {
    explicit HandoffGuard(std::shared_ptr<Handoff> h) : handoff(std::move(h)) {}
    std::shared_ptr<Handoff> handoff;
    HandoffGuard(const HandoffGuard&) = delete;
    HandoffGuard& operator=(const HandoffGuard&) = delete;
    ~HandoffGuard() { handoff->finish(false); }
};

} // namespace

/// Requests run on the server's I/O threads, all at once. Reads go straight
/// to the ledger, which lets them run alongside its writer. Writes queue for
/// the one writer thread, which takes everything queued as one group: one
/// lock of the directory, one catch-up, one sync for all the statements.
struct LedgerApi::State {
    using Done = Application::Respond;

    ApiOptions options;
    /// options.log_keys as the ledger takes them.
    std::vector<const crypto::Signer*> log_key_ring;
    const crypto::Provider* provider = nullptr;
    ledger::SystemClock system_clock;
    /// The system's, or ApiOptions::clock.
    ledger::Clock* clock = &system_clock;

    [[nodiscard]] ledger::LogKeys log_keys() const { return log_key_ring; }
    /// The writer thread's (and open's) only.
    std::optional<ledger::PosixFileSystem> fs;
    std::optional<ledger::Ledger> ledger;
    bool replica = false;

    /// Set once the ledger's files hold something that does not validate:
    /// every route but /healthz then answers 503.
    std::atomic<bool> failed = false;
    mutable std::mutex failure_mutex;
    std::string failure_text;

    mutable std::mutex tokens_mutex;
    std::shared_ptr<const std::vector<ApiToken>> tokens =
        std::make_shared<const std::vector<ApiToken>>();
    /// Held by tick(); open() runs before any.
    std::mutex tick_mutex;
    std::optional<std::pair<std::filesystem::file_time_type, std::uintmax_t>> tokens_time;
    steady::time_point last_auto_checkpoint = steady::now();

    std::array<std::atomic<std::uint64_t>, 600> responses{};
    std::atomic<std::uint64_t> registered = 0;
    std::atomic<std::uint64_t> duplicates = 0;
    std::atomic<std::uint64_t> refused = 0;
    std::atomic<std::uint64_t> auto_checkpoints = 0;

    mutable std::mutex event_mutex;
    /// The witness keeps state of its own (what it last cosigned).
    std::mutex witness_mutex;

    // ---- the writer ----------------------------------------------------

    struct Submission {
        Bytes statement;
        std::string principal;
        Done done;
        /// A record's private data, sealed to the vault key, stored with it.
        std::optional<Bytes> vault = std::nullopt;
        /// The consent bundles a contract call cites, checked, encoded, and
        /// stored already (a cluster replicates them with it).
        std::optional<Sidecar> consents = std::nullopt;
    };
    /// Runs on the writer thread holding the ledger's lock, caught up; or,
    /// if that could not be had, gets the answer to give instead.
    using Locked = std::function<void(const http::Response* refusal)>;
    using Job = std::function<void()>;
    /// A locked job as queued. The registrar's (a proposal or a consent)
    /// leave what they write to their group's commit (registrar_flush);
    /// any other job commits the group first.
    struct Queued {
        enum class Kind : std::uint8_t { other, proposal, consent };
        Locked run;
        Kind kind = Kind::other;
        /// The instance a consent acts on, if its terms name one.
        std::optional<protocol::IdKey> instance = std::nullopt;
    };

    std::mutex queue_mutex;
    std::condition_variable queue_ready;
    std::condition_variable queue_idle;
    std::deque<Submission> submissions;
    std::vector<Queued> locked;
    /// Reads that found another process had written: they run once the
    /// writer has caught up.
    std::vector<Job> after_refresh;
    bool writing = false;
    bool stopping = false;
    std::thread writer;
    /// The ledger directory's lock, the writer's, kept from one group to the
    /// next while statements are still syncing (D-056 P7: the next group
    /// validates meanwhile), so no other process writes in between and no
    /// catch-up is needed; let go once the writer runs out of work.
    std::optional<ledger::DirectoryLock> held_lock;

    /// The writer's: the registrar's pending contract calls (with a
    /// registrar). Randomness for the statements the server signs (the
    /// system's, or ApiOptions::entropy): the writer's and the keeper's.
    std::optional<CallRegistrar> calls;
    SharedEntropy entropy;

    /// Long polls of GET /v1/requests waiting for a request to match: each
    /// is answered once one does, once its wait is over, or when the server
    /// stops. `seen` is the log size it was last checked at.
    struct Waiter {
        RequestQuery query;
        std::string principal;
        Done done;
        steady::time_point until;
        std::uint64_t seen = 0;
    };
    std::mutex waiters_mutex;
    std::vector<Waiter> waiters;
    /// Set once the server stops: long polls are answered at once.
    bool polls_stopped = false;
    /// Executors' leases (6b, design 3.5), by executor actor (hex): one
    /// active copy per executor. In memory only: after a restart or a
    /// failover, the first copy to poll takes it. Under waiters_mutex.
    struct Lease {
        std::string holder;
        steady::time_point until;
    };
    std::map<std::string, Lease> leases;

    /// The keeper (6b): its scans run on its own thread, a slice of runs at
    /// a time on worker threads, and each slice's calls go to the writer as
    /// one group. The tick's and the keeper thread's, under keeper_mutex.
    std::mutex keeper_mutex;
    /// Wakes the keeper's thread (a slice to run, or stopping), and drain()
    /// once a slice is done.
    std::condition_variable keeper_wake;
    std::thread keeper_thread;
    /// When the last whole scan ended (the epoch: none yet).
    steady::time_point keeper_last{};
    /// Where the next slice starts (instances in log order), and whether it
    /// goes on at the next tick: a pass over the instances not finished, or
    /// an instance with more due than one call (each call moves its head),
    /// which the next pass takes.
    std::uint64_t keeper_next = 0;
    bool keeper_more = false;
    /// An instance of the pass so far had more due than one call.
    bool keeper_pass_more = false;
    /// Passes in a row since the interval last began.
    std::uint32_t keeper_rounds = 0;
    /// A slice is asked for (keeper_signal) or running (keeper_busy, until it
    /// is done and its calls recorded).
    bool keeper_signal = false;
    bool keeper_busy = false;
    bool keeper_stopping = false;
    /// This node led at the last tick (a new leader scans at once).
    bool keeper_leading = false;
    std::atomic<std::uint64_t> keeper_rules{0};
    std::atomic<std::uint64_t> keeper_expiries{0};
    std::atomic<std::uint64_t> keeper_refusals{0};

    /// A cluster member's (D-051): the ledger's lock, held for life, and
    /// Raft. Declared last, so they stop before anything they use.
    std::optional<ledger::DirectoryLock> member_lock;
    std::unique_ptr<Cluster> cluster;

    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;
    ~State() { stop(); }

    void start() {
        writer = std::thread([this] { run_writer(); });
        if (options.keeper && !replica && !options.read_only) {
            keeper_thread = std::thread([this] { run_keeper(); });
        }
    }

    /// Waits until everything queued so far is done: the keeper's slice
    /// too, and the writes it queued.
    void drain() {
        {
            std::unique_lock lock(keeper_mutex);
            keeper_wake.wait(lock, [&] { return !keeper_busy; });
        }
        std::unique_lock lock(queue_mutex);
        queue_idle.wait(lock, [&] {
            return !writing && submissions.empty() && locked.empty() && after_refresh.empty();
        });
    }

    void stop() {
        // The keeper first: its slice may wait for the writer.
        {
            const std::lock_guard lock(keeper_mutex);
            keeper_stopping = true;
        }
        keeper_wake.notify_all();
        if (keeper_thread.joinable()) {
            keeper_thread.join();
        }
        {
            const std::lock_guard lock(queue_mutex);
            if (stopping) {
                return;
            }
            stopping = true;
        }
        queue_ready.notify_all();
        if (writer.joinable()) {
            writer.join();
        }
    }

    /// Runs `work` on the writer, holding the ledger's lock, caught up, and
    /// waits for it: false if the writer refused it (busy, unusable,
    /// stopping) or it failed. From threads other than the writer's.
    bool on_writer(const std::function<void()>& work) {
        auto handoff = std::make_shared<Handoff>();
        queue_locked([guard = std::make_shared<HandoffGuard>(handoff),
                      &work](const http::Response* refusal) {
            if (refusal == nullptr) {
                work();
            }
            guard->handoff->finish(refusal == nullptr);
        });
        return handoff->wait();
    }

    void queue_submission(Submission submission) {
        {
            const std::lock_guard lock(queue_mutex);
            submissions.push_back(std::move(submission));
        }
        queue_ready.notify_one();
    }

    void queue_locked(Locked job) { queue_job({std::move(job)}); }

    void queue_job(Queued job) {
        {
            const std::lock_guard lock(queue_mutex);
            locked.push_back(std::move(job));
        }
        queue_ready.notify_one();
    }

    void queue_read(Job job) {
        {
            const std::lock_guard lock(queue_mutex);
            after_refresh.push_back(std::move(job));
        }
        queue_ready.notify_one();
    }

    void run_writer() {
        for (;;) {
            std::vector<Submission> batch;
            std::vector<Queued> jobs;
            std::vector<Job> reads;
            bool stopped = false;
            {
                std::unique_lock lock(queue_mutex);
                if (held_lock && !stopping && submissions.empty() && locked.empty() &&
                    after_refresh.empty()) {
                    // Out of work: what is syncing finishes, and other
                    // processes get the directory.
                    lock.unlock();
                    release_lock();
                    lock.lock();
                }
                writing = false;
                queue_idle.notify_all();
                queue_ready.wait(lock, [&] {
                    return stopping || !submissions.empty() || !locked.empty() ||
                           !after_refresh.empty();
                });
                stopped = stopping;
                std::size_t bytes = 0;
                while (!submissions.empty() &&
                       (stopped || (batch.size() < max_group && bytes < max_group_bytes))) {
                    bytes += submissions.front().statement.size();
                    batch.push_back(std::move(submissions.front()));
                    submissions.pop_front();
                }
                jobs.swap(locked);
                reads.swap(after_refresh);
                writing = true;
            }
            if (stopped) {
                const auto refusal = error_response(503, "unavailable", "the server is stopping");
                for (Submission& s : batch) {
                    finish(s.done, s.principal, refusal);
                }
                for (Queued& job : jobs) {
                    job.run(&refusal);
                }
                for (Job& read : reads) {
                    read(); // the ledger is still there, and reads are quick
                }
                release_lock();
                const std::lock_guard lock(queue_mutex);
                writing = false;
                queue_idle.notify_all();
                return;
            }
            bool caught_up = false;
            if (!batch.empty() || !jobs.empty()) {
                // A throw must not end the writer: answer what is left with
                // 500 (an answer given already stays given).
                try {
                    caught_up = write_group(batch, jobs);
                } catch (const std::exception&) {
                    const auto broken = error_response(500, "internal", "internal error");
                    for (Submission& s : batch) {
                        finish(s.done, s.principal, broken);
                    }
                    registrar_abandon(broken);
                    event("writer-error", "a write group failed with an exception");
                }
            }
            if (!reads.empty()) {
                // Holding the directory's lock since the last catch-up, the
                // writer is caught up: no other process can have written.
                if (!caught_up && !held_lock) {
                    static_cast<void>(refresh(false)); // a failure answers the reads
                }
                ledger::parallel_for(reads.size(), [&](std::size_t begin, std::size_t end) {
                    for (std::size_t i = begin; i < end; ++i) {
                        reads[i]();
                    }
                });
            }
        }
    }

    /// One group commit: the queued statements in one batch, then the other
    /// writes, all under one lock of the directory. True if it caught up
    /// with the files. The statements' batch is pipelined (D-056 P7): it is
    /// validated and applied here, and answered from the ledger's commit
    /// thread once it is durable, while this thread goes on with the next
    /// group; the directory's lock is kept until the writer runs out of work.
    bool write_group(std::vector<Submission>& batch, std::vector<Queued>& jobs) {
        if (cluster) {
            write_cluster_group(batch, jobs);
            return true;
        }
        std::optional<http::Response> refusal;
        if (failed) {
            refusal = error_response(503, "unavailable", "the ledger is unusable");
        } else if (!held_lock) {
            // Not held since a catch-up: take it, then catch up.
            auto lock = ledger::DirectoryLock::acquire(options.directory, 2000);
            if (!lock) {
                refusal = error_response(503, "unavailable", "the ledger is busy; retry");
                refusal->headers.emplace_back("Retry-After", "1");
            } else if (auto s = refresh(true); !s) {
                refusal = error_response(503, "unavailable", "the ledger is unusable");
            } else {
                held_lock.emplace(std::move(*lock));
            }
        }
        if (refusal) {
            for (Submission& s : batch) {
                finish(s.done, s.principal, *refusal);
            }
            for (Queued& job : jobs) {
                job.run(&*refusal);
            }
            return false;
        }
        // The round's batches (the statements', the registrar's) are
        // written with one sync, once the round is over or something waits
        // for them.
        ledger->hold_commits();
        struct Release {
            explicit Release(ledger::Ledger& held) : target(held) {}
            Release(const Release&) = delete;
            Release& operator=(const Release&) = delete;
            ~Release() { target.release_commits(); }
            ledger::Ledger& target;
        } const release(*ledger);
        if (!batch.empty()) {
            std::vector<ByteView> views;
            views.reserve(batch.size());
            for (const Submission& s : batch) {
                views.emplace_back(s.statement);
            }
            // The statements stay alive (and their answers wait) until the
            // batch is durable.
            auto held = std::make_shared<std::vector<Submission>>(std::move(batch));
            batch.clear();
            ledger->submit_batch_pipelined(
                views, [this, held](std::vector<Result<ledger::Registration>> results) {
                    for (std::size_t i = 0; i < held->size(); ++i) {
                        Submission& s = (*held)[i];
                        auto response = registration_response(results[i]);
                        if (results[i] && s.vault) {
                            response = store_vault(results[i]->statement_id, *s.vault,
                                                   std::move(response));
                        }
                        finish(s.done, s.principal, std::move(response));
                    }
                    check_waiters(false); // a long poll learns of new requests at once
                });
        }
        run_jobs(jobs);
        return true;
    }

    /// Once the writer runs out of work: waits for the statements still
    /// syncing, then lets go of the directory's lock (other processes may
    /// write; the next group catches up first).
    void release_lock() {
        if (held_lock) {
            ledger->wait_durable();
            held_lock.reset();
        }
    }

    /// The locked jobs of a group, in order. Consecutive registrar jobs make
    /// one group of their own writes, committed before any other job runs,
    /// before a job on an instance the group records a call on, and at the
    /// end.
    void run_jobs(std::vector<Queued>& jobs) {
        for (Queued& job : jobs) {
            if (registrar_conflicts(job)) {
                registrar_commit();
            }
            try {
                job.run(nullptr);
            } catch (const std::exception&) {
                event("writer-error", "a write job failed with an exception");
            }
        }
        registrar_commit();
    }

    /// A cluster member's group: the statements as one Raft entry, applied
    /// on every node; the other writes as entries of their own.
    void write_cluster_group(std::vector<Submission>& batch, std::vector<Queued>& jobs) {
        if (!batch.empty()) {
            if (!cluster->leads()) {
                for (Submission& s : batch) {
                    finish(s.done, s.principal, not_leader("/v1/statements"));
                }
            } else {
                std::vector<ByteView> views;
                std::vector<std::optional<Sidecar>> sidecars;
                for (const Submission& s : batch) {
                    views.emplace_back(s.statement);
                    if (s.vault) {
                        sidecars.emplace_back(Sidecar{Sidecar::Kind::vault, *s.vault});
                    } else if (s.consents) {
                        sidecars.emplace_back(*s.consents);
                    } else {
                        sidecars.emplace_back(std::nullopt);
                    }
                }
                auto results = cluster->submit(views, sidecars, clock->now());
                for (std::size_t i = 0; i < batch.size(); ++i) {
                    http::Response response;
                    if (!results) {
                        response = error_response(results.error());
                        response.headers.emplace_back("Retry-After", "1");
                    } else {
                        response = registration_response((*results)[i]);
                    }
                    finish(batch[i].done, batch[i].principal, std::move(response));
                }
                check_waiters(false);
            }
        }
        run_jobs(jobs);
    }

    /// For a write at a follower: where the leader is (307), or that there
    /// is none yet (503).
    http::Response not_leader(std::string_view target) const {
        if (const auto url = cluster->leader_api_url(); url && !cluster->leads()) {
            auto response = json_response(
                307, {{"error",
                       {{"code", "not_leader"},
                        {"message", "this node does not lead: send writes to the leader"}}},
                      {"leader", *url}});
            response.headers.emplace_back("Location", *url + std::string(target));
            return response;
        }
        auto response = error_response(503, "unavailable", "the cluster has no leader yet; retry");
        response.headers.emplace_back("Retry-After", "1");
        return response;
    }

    /// Keeps a record's sealed private data, once: the same data again is
    /// fine (a retry), other data is refused, so nobody can swap it.
    http::Response store_vault(const protocol::Id& record, const Bytes& sealed,
                               http::Response answer) {
        const std::filesystem::path vault = options.directory / "vault";
        if (!std::filesystem::exists(vault / "vault.pub")) {
            return error_response(409, "conflict",
                                  "the statement is registered, but this ledger keeps no vault");
        }
        const std::filesystem::path file = vault / "records" / (hex(record) + ".cbor");
        if (const auto existing = detail::read_file(file)) {
            return *existing == sealed
                       ? answer
                       : error_response(409, "conflict",
                                        "the statement is registered, but the record's private "
                                        "data was stored before, differently");
        }
        std::error_code ec;
        std::filesystem::create_directories(file.parent_path(), ec);
        if (auto s = detail::write_file(file, sealed, true); ec || !s) {
            return error_response(500, "internal",
                                  "the statement is registered, but its private data could not "
                                  "be stored: send it again");
        }
        return answer;
    }

    http::Response registration_response(const Result<ledger::Registration>& registration) {
        if (!registration) {
            ++refused;
            return error_response(registration.error());
        }
        ++(registration->newly_registered ? registered : duplicates);
        return json_response(registration->newly_registered ? 201 : 200,
                             {{"statement_id", hex(registration->statement_id)},
                              {"index", registration->index},
                              {"registered_at", registration->registered_at},
                              {"newly_registered", registration->newly_registered}});
    }

    // ---- shared helpers ------------------------------------------------

    /// Every answer leaves through here.
    void finish(Done& done, std::string_view principal, http::Response response) {
        const auto status = static_cast<std::size_t>(response.status);
        if (status < responses.size()) {
            responses[status].fetch_add(1, std::memory_order_relaxed);
        }
        response.headers.emplace_back("Cache-Control", "no-store");
        response.headers.emplace_back("X-Content-Type-Options", "nosniff");
        response.principal = principal;
        done(std::move(response));
    }

    [[nodiscard]] std::optional<std::string> failure() const {
        if (!failed.load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        const std::lock_guard lock(failure_mutex);
        return failure_text;
    }

    void event(std::string_view what, std::string_view detail = {}) const {
        if (options.event_log == nullptr) {
            return;
        }
        const auto now =
            std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
        json line = {{"time", std::format("{:%FT%T}Z", now)}, {"event", what}};
        if (!detail.empty()) {
            line["detail"] = detail;
        }
        const std::string text = line.dump() + "\n";
        const std::lock_guard lock(event_mutex);
        *options.event_log << text;
        options.event_log->flush();
    }

    /// From tick() (once a second) and open() only.
    void reload_tokens(bool force) {
        std::error_code ec;
        const auto path = options.directory / tokens_file;
        // Time and size: a rewrite within the clock's granularity changes
        // the size (or is caught on the next change).
        const auto time = std::filesystem::last_write_time(path, ec);
        std::error_code size_error;
        const auto size = std::filesystem::file_size(path, size_error);
        const std::optional<std::pair<std::filesystem::file_time_type, std::uintmax_t>> current =
            ec || size_error ? std::nullopt : std::optional(std::pair(time, size));
        if (!force && current == tokens_time) {
            return;
        }
        Result<std::vector<ApiToken>> loaded = fail(Errc::malformed, "unreadable");
        try {
            loaded = load_tokens(options.directory);
        } catch (const std::exception&) {
            loaded = fail(Errc::malformed, "the API tokens file is malformed");
        }
        auto next = std::make_shared<const std::vector<ApiToken>>(loaded ? std::move(*loaded)
                                                                         : std::vector<ApiToken>{});
        if (!loaded) {
            // Keep serving with no tokens rather than with stale ones.
            event("tokens-unreadable", loaded.error().detail);
        }
        {
            const std::lock_guard lock(tokens_mutex);
            tokens = std::move(next);
        }
        tokens_time = current;
    }

    /// Picks up what other processes appended, so every request sees all
    /// that was durable when it arrived. Writers, under the lock, also
    /// recover what a crashed writer left half-written. The writer thread
    /// only.
    Status refresh(bool for_write) {
        auto report = ledger->refresh(*fs, for_write);
        if (!report) {
            // Only files that do not validate, or a ledger that must be
            // reopened, disable the server. Anything else (out of
            // descriptors, say) fails this round only.
            const Errc code = report.error().code;
            if (!ledger->usable() || code == Errc::malformed || code == Errc::verification_failed) {
                {
                    const std::lock_guard lock(failure_mutex);
                    if (!failed) {
                        failure_text = std::string(report.error().detail);
                    }
                }
                failed.store(true, std::memory_order_release);
                event("ledger-unusable", report.error().detail);
            } else {
                event("refresh-failed", report.error().detail);
            }
            return std::unexpected(report.error());
        }
        return {};
    }

    /// Who is calling (into `principal`), and whether they may.
    std::optional<http::Response> authorize(const http::Request& r, Access access,
                                            std::string& principal, Scopes& scopes) const {
        // A public portal shows the log and proofs, never the vault's sealed
        // records or the server's metrics, and runs no contracts on request
        // (the due route's dry runs): those still need a read token.
        const bool token_only = r.path == "/metrics" || r.path.starts_with("/v1/vault/") ||
                                r.path == "/v1/contracts/due";
        if (access == Access::open ||
            (access == Access::read && options.public_read && !token_only)) {
            principal = "public";
            return std::nullopt;
        }
        std::shared_ptr<const std::vector<ApiToken>> current;
        {
            const std::lock_guard lock(tokens_mutex);
            current = tokens;
        }
        const auto header = r.header("authorization");
        constexpr std::string_view bearer = "Bearer ";
        const ApiToken* token = nullptr;
        if (header && header->size() > bearer.size() &&
            std::equal(bearer.begin(), bearer.end(), header->begin(), [](char a, char b) {
                return a == b || (a >= 'A' && a <= 'Z' && b == a - 'A' + 'a');
            })) {
            token = find_token(*current, *provider, header->substr(bearer.size()));
        }
        if (token == nullptr) {
            auto response = error_response(401, "unauthorized", "a valid API token is required");
            response.headers.emplace_back("WWW-Authenticate", R"(Bearer realm="cexchain")");
            return response;
        }
        principal = token->name;
        scopes = token->scopes;
        // Any of the route's scopes will do; routes that several kinds of
        // caller share check the rest themselves.
        if ((token->scopes & allowed_scopes(access)) == 0) {
            return error_response(403, "forbidden", "the API token lacks the scope for this");
        }
        return std::nullopt;
    }

    // ---- routes --------------------------------------------------------

    http::Response status() const {
        const auto latest = ledger->latest_checkpoint();
        std::string organization;
        ledger->read_state(
            [&](const protocol::LedgerState& s) { organization = s.organization(); });
        return json_response(
            200, {{"ledger_id", hex(ledger->id())},
                  {"organization", organization},
                  {"hash", crypto::name(ledger->hash())},
                  {"size", ledger->size()},
                  {"checkpoint", latest ? checkpoint_json(latest->checkpoint) : json(nullptr)},
                  {"role", replica ? "replica" : "primary"},
                  {"writable", !replica && !options.read_only},
                  {"receipts", !options.log_keys.empty()},
                  {"registrar", options.registrar != nullptr},
                  {"keeper", options.keeper != nullptr},
                  {"cluster", cluster ? cluster_json() : json(nullptr)},
                  // How far the ledger's clock runs ahead ($CEXCHAIN_CLOCK_OFFSET,
                  // demonstrations and tests only): 0 normally.
                  {"clock_offset_ms", ledger::SystemClock::offset()},
                  {"version", options.version}});
    }

    json cluster_json() const {
        const ClusterStatus s = cluster->status();
        json members = json::array();
        for (const ClusterMember& m : s.members) {
            members.push_back({{"id", m.id},
                               {"raft", m.raft_endpoint},
                               {"api", m.api_url},
                               {"leader", s.leader == m.id}});
        }
        return {{"id", s.id},
                {"leader", s.leader ? json(*s.leader) : json(nullptr)},
                {"leads", s.leads},
                {"term", s.term},
                {"committed", s.committed},
                {"applied", s.applied},
                {"members", members}};
    }

    http::Response checkpoint(const http::Request& r) const {
        if (const auto it = r.query.find("size"); it != r.query.end()) {
            const auto size = number(r, "size");
            if (!size) {
                return error_response(400, "invalid_argument", "size must be a number");
            }
            // A binary search: open to anyone, so it must stay cheap.
            auto found = ledger->checkpoints_of_size(*size);
            if (!found) {
                return error_response(found.error());
            }
            if (found->empty()) {
                return error_response(404, "not_found", "no checkpoint of this size");
            }
            return binary("application/cose", std::move(found->back().encoded));
        }
        auto latest = ledger->latest_checkpoint();
        if (!latest) {
            return error_response(404, "not_found", "no checkpoint yet");
        }
        return binary("application/cose", std::move(latest->encoded));
    }

    http::Response consistency(const http::Request& r) const {
        const auto old_size = number(r, "old");
        const auto new_size = number(r, "new");
        if (!old_size || !new_size || *old_size == 0 || *old_size > *new_size ||
            *new_size > ledger->size()) {
            return error_response(400, "invalid_argument",
                                  "old and new must be sizes with 0 < old <= new <= size");
        }
        auto proof = ledger->consistency_proof(*old_size, *new_size);
        return proof ? cbor_response(digests_value(*proof)) : error_response(proof.error());
    }

    /// [start, start + count) of a list of `total`, with sane limits.
    static std::optional<std::pair<std::uint64_t, std::uint64_t>> range(const http::Request& r,
                                                                        std::uint64_t total) {
        const auto start =
            r.query.contains("start") ? number(r, "start") : std::optional<std::uint64_t>(0);
        const auto count =
            r.query.contains("count") ? number(r, "count") : std::optional<std::uint64_t>(100);
        if (!start || !count || *start > total || *count == 0) {
            return std::nullopt;
        }
        return std::pair(*start, std::min({*start + std::min(*count, max_batch), total}));
    }

    http::Response entries(const http::Request& r) const {
        const auto span = range(r, ledger->size());
        if (!span) {
            return error_response(400, "invalid_argument", "start <= size and 0 < count");
        }
        cbor::Array out;
        std::size_t bytes = 0;
        for (std::uint64_t i = span->first; i < span->second && bytes < max_batch_bytes; ++i) {
            if (auto read = ledger->visit_entry(i,
                                                [&](ByteView entry) {
                                                    bytes += entry.size();
                                                    out.push_back(cbor::Value::bytes(entry));
                                                });
                !read) {
                return error_response(read.error());
            }
        }
        return cbor_response(cbor::Value::array(std::move(out)));
    }

    http::Response checkpoints(const http::Request& r) const {
        const auto span = range(r, ledger->checkpoint_count());
        if (!span) {
            return error_response(400, "invalid_argument", "start <= count and 0 < count");
        }
        // Only the page asked for is read.
        auto page = ledger->checkpoints(span->first, span->second - span->first);
        if (!page) {
            return error_response(page.error());
        }
        cbor::Array out;
        for (const auto& c : *page) {
            out.push_back(cbor::Value::bytes(c.encoded));
        }
        return cbor_response(cbor::Value::array(std::move(out)));
    }

    http::Response cosignatures(const http::Request& r) const {
        const auto span = range(r, ledger->cosignature_count());
        if (!span) {
            return error_response(400, "invalid_argument", "start <= count and 0 < count");
        }
        auto page = ledger->cosignatures(span->first, span->second - span->first);
        if (!page) {
            return error_response(page.error());
        }
        cbor::Array out;
        for (const auto& s : *page) {
            out.push_back(cbor::Value::array(
                {cbor::Value::bytes(s.encoded), protocol::encode_public_key(s.witness)}));
        }
        return cbor_response(cbor::Value::array(std::move(out)));
    }

    http::Response inclusion(const http::Request& r) const {
        const auto index = number(r, "index");
        const auto size = number(r, "size");
        if (!index || !size || *index >= *size || *size > ledger->size()) {
            return error_response(400, "invalid_argument", "index < size <= the log's size");
        }
        auto proof = ledger->inclusion_proof(*index, *size);
        return proof ? cbor_response(digests_value(*proof)) : error_response(proof.error());
    }

    http::Response statement(std::string_view id_text) const {
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "a statement id is 64 hex digits");
        }
        const auto index = ledger->statement_index(*id);
        if (!index) {
            return error_response(404, "not_found", "no such statement");
        }
        // Decoded in place: no copy of the entry.
        Result<protocol::LogEntry> entry = fail(Errc::not_found, "no such entry");
        if (auto read = ledger->visit_entry(
                *index, [&](ByteView bytes) { entry = protocol::decode_log_entry(bytes); });
            !read) {
            return error_response(read.error());
        }
        if (!entry) {
            return error_response(entry.error());
        }
        return json_response(200, {{"statement_id", hex(*id)},
                                   {"index", *index},
                                   {"registered_at", entry->registered_at}});
    }

    http::Response receipt(std::string_view index_text) const {
        if (options.log_keys.empty()) {
            return error_response(501, "unsupported", "this server has no log key");
        }
        std::uint64_t index = 0;
        const auto [ptr, ec] =
            std::from_chars(index_text.data(), index_text.data() + index_text.size(), index);
        if (ec != std::errc{} || ptr != index_text.data() + index_text.size()) {
            return error_response(400, "invalid_argument", "an entry index is a number");
        }
        auto receipt = ledger->receipt(log_keys(), index);
        return receipt ? binary("application/cose", std::move(*receipt))
                       : error_response(receipt.error());
    }

    http::Response state_proof(std::string_view id_text) const {
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "an id is 64 hex digits");
        }
        auto committed = ledger->committed_state_proof(*id);
        if (!committed) {
            return error_response(committed.error());
        }
        const auto& proof = committed->proof;
        const auto& commitment = committed->commitment;
        static constexpr std::array kinds{"", "actor", "delegation", "record"};
        json siblings = json::array();
        for (const auto& s : proof.siblings) {
            siblings.push_back(to_hex(s.bytes()));
        }
        return json_response(200, {{"kind", kinds[static_cast<std::size_t>(proof.leaf.kind)]},
                                   {"id", hex(proof.leaf.id)},
                                   {"history", proof.leaf.history},
                                   {"commitment_index", commitment.tree_size},
                                   {"state_root", to_hex(commitment.state_root.bytes())},
                                   {"siblings", siblings}});
    }

    http::Response evidence(std::string_view id_text) const {
        if (options.log_keys.empty()) {
            return error_response(501, "unsupported", "this server has no log key");
        }
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "a record id is 64 hex digits");
        }
        bool exists = false;
        ledger->read_state(
            [&](const protocol::LedgerState& s) { exists = s.record(*id) != nullptr; });
        if (!exists) {
            return error_response(404, "not_found", "no such record");
        }
        auto bundle = ledger->export_evidence(log_keys(), *id);
        if (!bundle) {
            return error_response(bundle.error());
        }
        auto encoded = protocol::encode_bundle(*bundle);
        return encoded ? binary("application/cbor", std::move(*encoded))
                       : error_response(encoded.error());
    }

    /// The peer a token belongs to (peer tokens are named after their peer).
    std::optional<Peer> peer_named(const std::string& principal) const {
        auto peers = load_peers(options.directory);
        if (!peers) {
            return std::nullopt;
        }
        const auto peer = std::ranges::find(*peers, principal, &Peer::name);
        return peer == peers->end() ? std::nullopt : std::optional<Peer>(*peer);
    }

    /// An instance's contract evidence with the consents its calls cite
    /// (D-053), for read tokens and for the instance's current parties; to
    /// other peers it does not exist.
    http::Response instance_evidence_of(std::string_view id_text, const std::string& principal,
                                        Scopes scopes) const {
        if (options.log_keys.empty()) {
            return error_response(501, "unsupported", "this server has no log key");
        }
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "an instance id is 64 hex digits");
        }
        std::optional<protocol::InstanceState> instance;
        std::vector<protocol::Id> ancestors;
        ledger->read_state([&](const protocol::LedgerState& s) {
            if (const protocol::InstanceState* i = s.instance(*id)) {
                instance = *i;
                ancestors = ancestor_ids(s, *id);
            }
        });
        // The home's own (read tokens, and executors, which check requests
        // in it before acting), or the instance's current parties.
        bool allowed = instance.has_value() &&
                       (has_scope(scopes, Scope::read) || has_scope(scopes, Scope::executor));
        if (instance && !allowed) {
            const auto peer = peer_named(principal);
            allowed = peer && std::ranges::any_of(instance->parties, [&](const auto& p) {
                          return p.second == peer->ledger_id;
                      });
        }
        if (!allowed) {
            return error_response(404, "not_found", "no such instance");
        }
        if (const auto latest = ledger->latest_checkpoint();
            !latest || latest->checkpoint.tree_size <= instance->head) {
            return error_response(409, "conflict",
                                  "the instance changed after the latest checkpoint; retry");
        }
        auto bundle = ledger->export_evidence(log_keys(), *id);
        if (!bundle) {
            return error_response(bundle.error());
        }
        auto evidence = contract_evidence(*provider, options.directory, *bundle, ancestors);
        return evidence ? binary("application/cbor", std::move(*evidence))
                        : error_response(evidence.error());
    }

    /// GET /v1/contracts/instances/{instance}: the evidence as of a
    /// checkpoint that covers the instance's latest change (its head). If the
    /// latest does not, a writable server (a cluster's leader) checkpoints
    /// first, on the writer.
    void evidence_request(const http::Request& r, const Routed& routed, std::string principal,
                          Scopes scopes, Done& done) {
        const std::string rest(std::string_view(r.path).substr(routed.rest));
        bool covered = true;
        if (const auto id = id_from(rest)) {
            std::optional<std::uint64_t> head;
            ledger->read_state([&](const protocol::LedgerState& s) {
                if (const protocol::InstanceState* i = s.instance(*id)) {
                    head = i->head;
                }
            });
            const auto latest = ledger->latest_checkpoint();
            covered = !head || (latest && latest->checkpoint.tree_size > *head);
        }
        const bool can_write = !options.read_only && !replica && !options.log_keys.empty();
        if ((covered && !ledger->outdated()) || !can_write) {
            finish(done, principal, answer_safely(r, routed, principal, scopes));
            return;
        }
        if (cluster && !cluster->leads()) {
            finish(done, principal, not_leader(r.target));
            return;
        }
        queue_locked([this, rest, principal = std::move(principal), scopes,
                      done = std::move(done)](const http::Response* refusal) mutable {
            if (refusal != nullptr) {
                finish(done, principal, *refusal);
                return;
            }
            // Caught up with the files: checkpoint unless that covers it now.
            auto evidence = [&] {
                return instance_evidence_of(rest, principal, scopes);
            };
            auto response = evidence();
            if (response.status == 409) {
                auto made =
                    cluster ? cluster->checkpoint(log_keys()) : ledger->checkpoint(log_keys());
                response = made ? evidence() : error_response(made.error());
            }
            finish(done, principal, std::move(response));
        });
    }

    // ---- requests (v0.8, 6b) ---------------------------------------------

    /// A request as GET /v1/requests shows it: params as hex CBOR, times in
    /// milliseconds; `overdue` by this server's clock, `head` the instance's
    /// now (what an answer names).
    static json request_json(const protocol::LedgerState& s, const protocol::RequestState& r,
                             protocol::Timestamp now) {
        const protocol::InstanceState* i = s.instance(r.instance);
        const auto params = cbor::encode(r.params);
        return {{"id", hex(r.id)},
                {"instance", hex(r.instance)},
                {"contract", i != nullptr ? json(hex(i->contract)) : json(nullptr)},
                {"head", i != nullptr ? json(i->head) : json(nullptr)},
                {"kind", r.kind},
                {"params", params ? to_hex(*params) : std::string()},
                {"deadline", r.deadline},
                {"reply", r.reply},
                {"call", r.call},
                {"position", r.position},
                {"asked_at", r.asked_at},
                {"status", r.status ? std::string(protocol::name(*r.status)) : "open"},
                {"answered_by", r.answered_by ? json(*r.answered_by) : json(nullptr)},
                {"answered_at", r.status ? json(r.answered_at) : json(nullptr)},
                {"late_by_ms", r.late_by()},
                {"overdue", r.open() && now >= r.deadline}};
    }

    struct Found {
        json body;
        std::size_t count = 0;
        /// The log size the answer is as of.
        std::uint64_t size = 0;
    };

    /// The requests `q` matches, oldest change first: {"requests", "cursor",
    /// "more", "time"}. Only what the log holds durably counts: its size is
    /// read before the state, so a request that changes meanwhile may be
    /// reported again, but is never missed.
    Found find_requests(const RequestQuery& q) const {
        const std::uint64_t size = ledger->size();
        const protocol::Timestamp now = clock->now();
        json list = json::array();
        std::uint64_t cursor = size;
        bool more = false;
        ledger->read_state([&](const protocol::LedgerState& s) {
            std::vector<std::pair<std::uint64_t, const protocol::RequestState*>> found;
            for (const auto& [key, r] : s.requests()) {
                const std::uint64_t changed = r.answered_by.value_or(r.call);
                if (changed < q.after || changed >= size ||
                    (q.which == RequestQuery::Which::open && !r.open()) ||
                    (q.which == RequestQuery::Which::answered && r.open()) ||
                    (!q.kinds.empty() && !std::ranges::contains(q.kinds, r.kind)) ||
                    (q.instance && !(r.instance == *q.instance))) {
                    continue;
                }
                if (q.contract) {
                    const protocol::InstanceState* i = s.instance(r.instance);
                    if (i == nullptr || !(i->contract == *q.contract)) {
                        continue;
                    }
                }
                found.emplace_back(changed, &r);
            }
            std::ranges::stable_sort(found, {}, &decltype(found)::value_type::first);
            for (std::size_t n = 0; n < found.size(); ++n) {
                // A page ends between log entries, never inside one.
                if (n >= q.limit && found[n].first != found[n - 1].first) {
                    more = true;
                    cursor = found[n].first;
                    break;
                }
                list.push_back(request_json(s, *found[n].second, now));
            }
        });
        const std::size_t count = list.size();
        return {{{"requests", std::move(list)}, {"cursor", cursor}, {"more", more}, {"time", now}},
                count,
                size};
    }

    /// Takes or renews `q`'s lease (if it names one) until `until`. Returns
    /// the answer's "lease": granted, or held by another copy until when.
    /// Under waiters_mutex.
    json take_lease(const RequestQuery& q, steady::time_point now, steady::time_point until) {
        constexpr std::size_t max_leases = 4096;
        const std::string executor = hex(*q.executor);
        auto it = leases.find(executor);
        if (it != leases.end() && it->second.holder != *q.lease && it->second.until > now) {
            const auto left =
                std::chrono::duration_cast<std::chrono::milliseconds>(it->second.until - now);
            return {{"granted", false}, {"holder", it->second.holder}, {"retry_ms", left.count()}};
        }
        if (it == leases.end()) {
            std::erase_if(leases, [&](const auto& l) { return l.second.until <= now; });
            if (leases.size() >= max_leases) {
                return {{"granted", false}, {"holder", nullptr}, {"retry_ms", 1000}};
            }
            it = leases.emplace(executor, Lease{}).first;
        }
        it->second = {*q.lease, until};
        return {{"granted", true},
                {"holder", *q.lease},
                {"ttl_ms", std::chrono::milliseconds(q.ttl).count()}};
    }

    /// The answer to a poll whose copy does not hold its executor's lease:
    /// nothing, and the cursor unchanged.
    json without_lease(const RequestQuery& q, json lease) const {
        return {{"requests", json::array()},
                {"cursor", q.after},
                {"more", false},
                {"time", clock->now()},
                {"lease", std::move(lease)}};
    }

    /// GET /v1/requests: the requests that match at once, or, with a wait,
    /// once some do (a long poll).
    void requests_request(const http::Request& r, std::string principal, Done done) {
        auto parsed = parse_request_query(r);
        if (const auto* refusal = std::get_if<detail::QueryError>(&parsed)) {
            finish(done, principal, error_response(400, "invalid_argument", refusal->message));
            return;
        }
        // A cluster's leases are the leader's: every copy asks the same one.
        if (std::get<RequestQuery>(parsed).lease && cluster && !cluster->leads()) {
            finish(done, principal, not_leader(r.target));
            return;
        }
        auto start = [this, q = std::get<RequestQuery>(std::move(parsed)),
                      principal = std::move(principal), done = std::move(done)]() mutable {
            if (failed) {
                finish(done, principal,
                       error_response(503, "unavailable",
                                      "the ledger's files do not validate; run cexchain audit"));
                return;
            }
            Found found = find_requests(q);
            const std::lock_guard lock(waiters_mutex);
            if (q.lease) {
                // Held through the wait, and for the ttl after the answer.
                const auto now = steady::now();
                json lease = take_lease(q, now, now + q.wait + q.ttl);
                if (!lease["granted"].get<bool>()) {
                    finish(done, principal, json_response(200, without_lease(q, std::move(lease))));
                    return;
                }
                found.body["lease"] = std::move(lease);
            }
            if (found.count > 0 || q.wait.count() == 0 || polls_stopped ||
                waiters.size() >= max_waiters) {
                finish(done, principal, json_response(200, found.body));
                return;
            }
            const auto until = steady::now() + q.wait;
            waiters.push_back(
                {std::move(q), std::move(principal), std::move(done), until, found.size});
        };
        if (ledger->outdated()) {
            // Another process wrote: look once the writer has caught up.
            queue_read(std::move(start));
            return;
        }
        start();
    }

    /// Answers the long polls that something now matches, or whose wait is
    /// over (all of them if `everyone`). A poll is looked at again only once
    /// the log has grown since it last was.
    void check_waiters(bool everyone) {
        const std::lock_guard lock(waiters_mutex);
        if (waiters.empty()) {
            return;
        }
        const auto now = steady::now();
        const std::uint64_t size = ledger->size();
        for (auto it = waiters.begin(); it != waiters.end();) {
            const bool over = everyone || failed || now >= it->until;
            if (!over && size == it->seen) {
                ++it;
                continue;
            }
            Found found = find_requests(it->query);
            if (found.count > 0 || over) {
                if (it->query.lease && !failed) {
                    json lease = take_lease(it->query, now, now + it->query.ttl);
                    if (lease["granted"].get<bool>()) {
                        found.body["lease"] = std::move(lease);
                    } else {
                        found.body = without_lease(it->query, std::move(lease));
                    }
                }
                finish(it->done, it->principal,
                       failed ? error_response(503, "unavailable",
                                               "the ledger's files do not validate; run "
                                               "cexchain audit")
                              : json_response(200, found.body));
                it = waiters.erase(it);
            } else {
                it->seen = found.size;
                ++it;
            }
        }
    }

    /// From tick(): checks the long polls against the ledger, once the
    /// writer has caught up with other processes' writes if it must.
    void poll_requests() {
        {
            const std::lock_guard lock(waiters_mutex);
            if (waiters.empty()) {
                return;
            }
        }
        if (ledger->outdated()) {
            queue_read([this] { check_waiters(false); });
            return;
        }
        check_waiters(false);
    }

    /// The server stops: every long poll is answered now, and later ones at
    /// once.
    void stop_polls() {
        {
            const std::lock_guard lock(waiters_mutex);
            polls_stopped = true;
        }
        check_waiters(true);
    }

    // ---- contracts (D-053) ----------------------------------------------

    static json contract_json(const protocol::ContractState& c, std::size_t instances) {
        json functions = json::object();
        for (const auto& [name, kind] : c.interface) {
            functions[name] = kind == protocol::FunctionKind::create ? "create" : "call";
        }
        return {
            {"id", hex(c.id)},
            {"name", c.name ? json(*c.name) : json(nullptr)},
            {"language", c.language},
            {"compiler", c.compiler},
            {"functions", std::move(functions)},
            {"deployer", hex(c.deployer)},
            {"deployed_at_index", c.deployed_at_index},
            {"retired", c.retired},
            {"retired_at_index", c.retired_at_index ? json(*c.retired_at_index) : json(nullptr)},
            {"instances", instances}};
    }

    /// GET /v1/contracts?start=&count=: the contracts deployed here, oldest
    /// first.
    http::Response contract_list(const http::Request& r) const {
        json list = json::array();
        std::uint64_t total = 0;
        bool bad_range = false;
        ledger->read_state([&](const protocol::LedgerState& s) {
            total = s.contracts().size();
            const auto span = range(r, total);
            if (!span) {
                bad_range = true;
                return;
            }
            std::map<Bytes, std::size_t> instances;
            for (const auto& [key, instance] : s.instances()) {
                ++instances[Bytes(instance.contract.bytes().begin(),
                                  instance.contract.bytes().end())];
            }
            std::uint64_t i = 0;
            for (const auto& [key, contract] : s.contracts()) {
                if (i >= span->first && i < span->second) {
                    const auto n = instances.find(
                        Bytes(contract.id.bytes().begin(), contract.id.bytes().end()));
                    list.push_back(contract_json(contract, n == instances.end() ? 0 : n->second));
                }
                ++i;
            }
        });
        if (bad_range) {
            return error_response(400, "invalid_argument", "start <= count and 0 < count");
        }
        return json_response(200, {{"contracts", std::move(list)}, {"total", total}});
    }

    /// GET /v1/contracts/{contract}: one contract, with its code's size and
    /// hash (the code itself is in its deploy statement).
    http::Response contract_show(std::string_view id_text) const {
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "a contract id is 64 hex digits");
        }
        std::optional<json> shown;
        ledger->read_state([&](const protocol::LedgerState& s) {
            const protocol::ContractState* c = s.contract(*id);
            if (c == nullptr) {
                return;
            }
            std::size_t instances = 0;
            for (const auto& [key, instance] : s.instances()) {
                instances += instance.contract == *id ? 1U : 0U;
            }
            shown = contract_json(*c, instances);
        });
        if (!shown) {
            return error_response(404, "not_found", "no such contract");
        }
        // The deploy statement, for the code's size and hash.
        const auto index = ledger->statement_index(*id);
        Result<protocol::LogEntry> entry = fail(Errc::not_found, "no such entry");
        if (index) {
            if (auto read = ledger->visit_entry(
                    *index, [&](ByteView bytes) { entry = protocol::decode_log_entry(bytes); });
                !read) {
                return error_response(read.error());
            }
        }
        auto parsed = entry ? protocol::parse_statement(*provider, entry->statement, ledger->hash())
                            : Result<protocol::SignedStatement>(std::unexpected(entry.error()));
        const auto* deploy =
            parsed ? std::get_if<protocol::ContractDeployBody>(&parsed->statement.body) : nullptr;
        if (deploy == nullptr) {
            return error_response(500, "internal", "the contract's deploy statement is unreadable");
        }
        auto digest = provider->digest(ledger->hash(), deploy->code);
        if (!digest) {
            return error_response(digest.error());
        }
        (*shown)["code_size"] = deploy->code.size();
        (*shown)["code_hash"] = to_hex(digest->bytes());
        (*shown)["source_size"] = deploy->source ? json(deploy->source->size()) : json(nullptr);
        return json_response(200, *shown);
    }

    /// A pending call for its parties: the arguments as CBOR (hex) and their
    /// digest, which consents name; the proposer only for the home's tokens.
    json pending_json(const protocol::Id& id, const PendingCall& c, bool home) const {
        json missing = json::array();
        for (const protocol::Id& m : c.missing) {
            missing.push_back(hex(m));
        }
        json consented = json::array();
        for (const auto& [ledger_id, bundle] : c.consents) {
            consented.push_back(hex(ledger_id));
        }
        auto arguments = cbor::encode(c.arguments);
        auto digest = protocol::contract_arguments_digest(*provider, ledger->hash(), c.arguments);
        json out = {{"call", hex(id)},
                    {"instance", hex(c.instance)},
                    {"head", c.head},
                    {"function", c.function},
                    {"arguments", arguments ? to_hex(*arguments) : std::string()},
                    {"arguments_digest", digest ? hex(*digest) : std::string()},
                    {"reference", c.reference ? json(*c.reference) : json(nullptr)},
                    {"until", c.until},
                    {"missing", std::move(missing)},
                    {"consented", std::move(consented)}};
        if (home) {
            out["proposer"] = c.proposer;
        }
        return out;
    }

    /// The pending calls a token may see, still current at `now`: all of
    /// them for read tokens, those that concern a peer's ledger for peers.
    std::vector<HeldCall> visible_calls(const std::string& principal, Scopes scopes) const {
        std::vector<HeldCall> held = held_calls(options.directory);
        const bool home = has_scope(scopes, Scope::read);
        const auto peer = home ? std::nullopt : peer_named(principal);
        const protocol::Timestamp now = clock->now();
        std::vector<HeldCall> out;
        ledger->read_state([&](const protocol::LedgerState& s) {
            for (HeldCall& h : held) {
                const protocol::InstanceState* i = s.instance(h.name.instance);
                const bool current =
                    i != nullptr && !i->final && i->head == h.name.head && h.call.until >= now;
                if (current && (home || (peer && concerns(s, h.call, peer->ledger_id)))) {
                    out.push_back(std::move(h));
                }
            }
        });
        return out;
    }

    /// GET /v1/contracts/calls: the calls the registrar holds.
    http::Response pending_list(const std::string& principal, Scopes scopes) const {
        json list = json::array();
        for (const HeldCall& h : visible_calls(principal, scopes)) {
            list.push_back(pending_json(h.name.id, h.call, has_scope(scopes, Scope::read)));
        }
        return json_response(200, {{"calls", std::move(list)}});
    }

    /// GET /v1/contracts/calls/{call}: one of them.
    http::Response pending_show(std::string_view id_text, const std::string& principal,
                                Scopes scopes) const {
        const auto id = id_from(id_text);
        if (!id) {
            return error_response(400, "invalid_argument", "a call id is 64 hex digits");
        }
        for (const HeldCall& h : visible_calls(principal, scopes)) {
            if (h.name.id == *id) {
                return json_response(
                    200, pending_json(h.name.id, h.call, has_scope(scopes, Scope::read)));
            }
        }
        return error_response(404, "not_found", "no such pending call");
    }

    http::Response vault_file(const std::filesystem::path& relative) const {
        auto bytes = detail::read_file(options.directory / "vault" / relative);
        if (!bytes) {
            return bytes.error().code == Errc::not_found
                       ? error_response(404, "not_found", "no such vault file")
                       : error_response(bytes.error());
        }
        return binary("application/cbor", std::move(*bytes));
    }

    /// The peer a peer token belongs to: peer tokens are named after their
    /// peer. Then the evidence must come from that peer's ledger. One answer
    /// for every refusal, so a token cannot probe which ledgers are peers;
    /// and nothing is verified before the token is placed.
    Result<Peer> peer_of(const std::string& principal, ByteView bundle) const {
        auto peers = load_peers(options.directory);
        if (!peers) {
            return std::unexpected(peers.error());
        }
        const auto peer = std::ranges::find(*peers, principal, &Peer::name);
        const auto ledger_id = protocol::bundle_ledger_id(bundle);
        if (peer == peers->end() || !ledger_id || peer->ledger_id != *ledger_id) {
            return fail(Errc::rejected,
                        "this token is not the peer's whose ledger the evidence comes from");
        }
        return *peer;
    }

    Status store(const std::filesystem::path& path, ByteView bytes) const {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return fail(Errc::unavailable, "cannot create the access directory");
        }
        return detail::write_file(path, bytes, true);
    }

    /// Peers write files here too: not on a read-only server or a replica,
    /// whose operator would never see them.
    std::optional<http::Response> refuse_peer_write() const {
        if (options.read_only || replica) {
            return error_response(403, "read_only",
                                  replica ? "this ledger is a replica; send to its primary"
                                          : "this server is read-only");
        }
        return std::nullopt;
    }

    http::Response access_request(const http::Request& r, const std::string& principal) {
        if (auto denied = refuse_peer_write()) {
            return std::move(*denied);
        }
        if (r.body.size() > max_access_request) {
            return error_response(413, "limit_exceeded", "an access request is at most 256 KiB");
        }
        auto peer = peer_of(principal, r.body);
        if (!peer) {
            return error_response(403, "forbidden", peer.error().detail);
        }
        auto checked = protocol::check_access_request(*provider, r.body, peer->ledger_id,
                                                      ledger->id(), clock->now());
        if (!checked) {
            return error_response(checked.error());
        }
        const auto path = access_path(options.directory, AccessBox::inbox, checked->report.record);
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) && inbox_full()) {
            return error_response(503, "unavailable",
                                  "the inbox is full; the operator must handle pending requests");
        }
        if (auto s = store(path, r.body); !s) {
            return error_response(s.error());
        }
        event("access-request", peer->name + " " + hex(checked->report.record));
        return json_response(202, {{"request", hex(checked->report.record)},
                                   {"peer", peer->name},
                                   {"record", hex(checked->value.record)},
                                   {"purpose", checked->value.purpose}});
    }

    /// Peers cannot fill the disk: pending requests are capped.
    bool inbox_full() const {
        std::error_code ec;
        std::size_t count = 0;
        for (auto it =
                 std::filesystem::directory_iterator(options.directory / "access" / "inbox", ec);
             !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
            if (++count >= max_inbox) {
                return true;
            }
        }
        return false;
    }

    http::Response access_delivery(std::string_view request_text,
                                   const std::string& principal) const {
        const auto request = id_from(request_text);
        if (!request) {
            return error_response(400, "invalid_argument", "a request id is 64 hex digits");
        }
        auto bytes = detail::read_file(access_path(options.directory, AccessBox::outbox, *request));
        if (!bytes) {
            return bytes.error().code == Errc::not_found
                       ? error_response(404, "not_found", "not granted (yet)")
                       : error_response(bytes.error());
        }
        // Only to the peer it was granted to; to anyone else it does not exist.
        auto delivery = protocol::decode_delivery(*bytes);
        protocol::VerifyOptions own;
        own.expected_ledger = ledger->id();
        own.signatures = &ledger::signature_cache();
        auto report = delivery
                          ? protocol::verify_bundle(*provider, delivery->grant_bundle, own)
                          : Result<protocol::EvidenceReport>(std::unexpected(delivery.error()));
        auto grant = report && report->metadata
                         ? protocol::decode_access_grant(*report->metadata)
                         : Result<protocol::AccessGrant>(fail(Errc::malformed, "no grant"));
        auto peers = load_peers(options.directory);
        const bool theirs = grant && peers && grant->request == *request &&
                            std::ranges::any_of(*peers, [&](const Peer& p) {
                                return p.ledger_id == grant->ledger && p.name == principal;
                            });
        if (!theirs) {
            return error_response(404, "not_found", "not granted (yet)");
        }
        // Only while the grant lives on this ledger: not once it is revoked
        // or has expired (the file is a snapshot from when it was made).
        bool live = false;
        ledger->read_state([&](const protocol::LedgerState& state) {
            const protocol::RecordState* g = state.record(report->record);
            live = g != nullptr && !g->revoked && g->state == "granted";
        });
        if (!live || grant->until <= clock->now()) {
            return error_response(410, "gone", "the grant was revoked or has expired");
        }
        return binary("application/cbor", std::move(*bytes));
    }

    http::Response access_receipt(const http::Request& r, const std::string& principal) {
        if (auto denied = refuse_peer_write()) {
            return std::move(*denied);
        }
        auto peer = peer_of(principal, r.body);
        if (!peer) {
            return error_response(403, "forbidden", peer.error().detail);
        }
        // Which grant: from the receipt's metadata, checked below.
        protocol::VerifyOptions pinned;
        pinned.expected_ledger = peer->ledger_id;
        pinned.signatures = &ledger::signature_cache();
        auto report = protocol::verify_bundle(*provider, r.body, pinned);
        auto receipt =
            report && report->metadata
                ? protocol::decode_access_receipt(*report->metadata)
                : Result<protocol::AccessReceipt>(fail(Errc::malformed, "not an access receipt"));
        if (!receipt) {
            return error_response(receipt.error());
        }
        auto grant = record_metadata(*provider, *ledger, receipt->grant);
        auto decoded = grant ? protocol::decode_access_grant(*grant)
                             : Result<protocol::AccessGrant>(std::unexpected(grant.error()));
        if (!decoded) {
            return error_response(404, "not_found", "no such grant on this ledger");
        }
        auto delivery = delivery_for_grant(options.directory, decoded->request, receipt->grant);
        auto digest = delivery ? provider->digest(crypto::HashAlg::sha256, *delivery)
                               : Result<crypto::Digest>(std::unexpected(delivery.error()));
        if (!digest) {
            return error_response(404, "not_found", "nothing was delivered for this grant");
        }
        auto checked =
            protocol::check_access_receipt(*provider, r.body, peer->ledger_id, ledger->id(),
                                           receipt->grant, *decoded, digest->bytes());
        if (!checked) {
            return error_response(checked.error());
        }
        if (auto s = store_receipt(options.directory, receipt->grant, r.body); !s) {
            return error_response(s.error());
        }
        event("access-receipt", peer->name + " " + hex(receipt->grant));
        return json_response(202, {{"grant", hex(receipt->grant)}, {"peer", peer->name}});
    }

    http::Response witness_cosign(const http::Request& r) {
        if (!options.witness) {
            return error_response(501, "unsupported", "this server is not a witness");
        }
        // One cosigning at a time (the witness keeps state), and no I/O
        // thread waits for it: a busy witness answers 503.
        const std::unique_lock lock(witness_mutex, std::try_to_lock);
        if (!lock) {
            auto busy = error_response(503, "unavailable", "the witness is busy; retry");
            busy.headers.emplace_back("Retry-After", "1");
            return busy;
        }
        auto cosignature = options.witness(r.body);
        if (!cosignature) {
            return error_response(cosignature.error());
        }
        return binary("application/cose", std::move(*cosignature));
    }

    // ---- writes, for the writer thread ---------------------------------

    void submit(http::Request& r, std::string principal, Scopes scopes, Done& done) {
        const auto type = r.header("content-type");
        // An executor's token (6b) submits answers to requests, and nothing
        // else: no record with private data, no call with consents.
        if (!has_scope(scopes, Scope::submit)) {
            const auto parsed = protocol::parse_statement(*provider, r.body, ledger->hash());
            const auto* call =
                parsed ? std::get_if<protocol::ContractCallBody>(&parsed->statement.body) : nullptr;
            if ((type && type->starts_with(submission_content_type)) || call == nullptr ||
                !call->answer || !call->consents.empty()) {
                finish(done, principal,
                       error_response(403, "forbidden",
                                      "an executor's API token submits answers to requests only"));
                return;
            }
        }
        if (type && type->starts_with(submission_content_type)) {
            submit_with_vault(r, std::move(principal), done);
            return;
        }
        if (type && !type->starts_with("application/cose") &&
            !type->starts_with("application/cbor") &&
            !type->starts_with("application/octet-stream")) {
            finish(done, principal,
                   error_response(415, "unsupported",
                                  "send the signed statement as application/cose"));
            return;
        }
        if (r.body.empty()) {
            finish(done, principal,
                   error_response(400, "invalid_argument", "send a signed statement"));
            return;
        }
        // A home records a contract call only with the consents it cites.
        if (auto parsed = protocol::parse_statement(*provider, r.body, ledger->hash());
            parsed && !ledger->statement_index(parsed->id) &&
            cites_contract_consents(parsed->statement) &&
            !std::filesystem::exists(contract_consents_path(options.directory, parsed->id))) {
            finish(done, principal,
                   error_response(400, "invalid_argument",
                                  "send a contract call with the evidence of the consents it "
                                  "cites, as application/cexchain-submission+cbor"));
            return;
        }
        queue_submission({std::move(r.body), std::move(principal), std::move(done)});
    }

    /// {1: signed statement, 2: sealed private data}: a record's
    /// registration together with its vault file, so the data arrives with
    /// the record and nobody can store other data for it first.
    /// {1: signed statement, 3: [consent bundles]}: a contract call with the
    /// evidence of the consents it cites, checked and kept before it is
    /// registered.
    void submit_with_vault(http::Request& r, std::string principal, Done& done) {
        auto value = cbor::decode(r.body);
        if (value && value->find(3) != nullptr) {
            submit_with_consents(*value, std::move(principal), done);
            return;
        }
        const cbor::Value* statement = value ? value->find(1) : nullptr;
        const cbor::Value* sealed = value ? value->find(2) : nullptr;
        if (statement == nullptr || statement->as_bytes() == nullptr || sealed == nullptr ||
            sealed->as_bytes() == nullptr || value->as_map()->size() != 2 ||
            !is_sealed_vault(*sealed->as_bytes())) {
            finish(done, principal,
                   error_response(400, "malformed",
                                  "send {1: signed statement, 2: sealed private data}"));
            return;
        }
        auto parsed = protocol::parse_statement(*provider, *statement->as_bytes(), ledger->hash());
        if (!parsed ||
            !std::holds_alternative<protocol::RecordRegisterBody>(parsed->statement.body)) {
            finish(done, principal,
                   error_response(400, "invalid_argument",
                                  "only a record's registration carries private data"));
            return;
        }
        queue_submission(
            {*statement->as_bytes(), std::move(principal), std::move(done), *sealed->as_bytes()});
    }

    void submit_with_consents(const cbor::Value& value, std::string principal, Done& done) {
        const cbor::Value* statement = value.find(1);
        const cbor::Value* list = value.find(3);
        const cbor::Array* items = list != nullptr ? list->as_array() : nullptr;
        if (statement == nullptr || statement->as_bytes() == nullptr || items == nullptr ||
            value.as_map()->size() != 2) {
            finish(done, principal,
                   error_response(400, "malformed",
                                  "send {1: signed statement, 3: [consent bundles]}"));
            return;
        }
        auto parsed = protocol::parse_statement(*provider, *statement->as_bytes(), ledger->hash());
        const auto* call =
            parsed ? std::get_if<protocol::ContractCallBody>(&parsed->statement.body) : nullptr;
        std::vector<Bytes> bundles;
        for (const cbor::Value& item : *items) {
            if (item.as_bytes() != nullptr) {
                bundles.push_back(*item.as_bytes());
            }
        }
        if (call == nullptr || call->consents.empty() || bundles.size() != items->size()) {
            finish(done, principal,
                   error_response(400, "invalid_argument",
                                  "only a contract call that cites consents carries their "
                                  "evidence"));
            return;
        }
        const Status checked = check_call_consents(*provider, ledger->id(), ledger->hash(), *call,
                                                   bundles, clock->now());
        if (!checked) {
            finish(done, principal, error_response(checked.error()));
            return;
        }
        auto encoded = encode_consent_bundles(bundles);
        if (!encoded) {
            finish(done, principal, error_response(encoded.error()));
            return;
        }
        // Kept first: a registered call always has its consents here.
        if (auto s = store_consents_file(contract_consents_path(options.directory, parsed->id),
                                         *encoded);
            !s) {
            finish(done, principal, error_response(s.error()));
            return;
        }
        const Sidecar sidecar{Sidecar::Kind::contract_consents, std::move(*encoded)};
        queue_submission(
            {*statement->as_bytes(), std::move(principal), std::move(done), std::nullopt, sidecar});
    }

    // ---- the registrar (D-053) ------------------------------------------

    /// The registrar's group on the writer (D-056 P5): consecutive
    /// proposals and consents run one after another, each on the state the
    /// ones before it left, and what they write is committed together. The
    /// pending calls and consents they write are synced file by file, their
    /// directories once; the calls the contracts accepted are recorded as one
    /// batch (one sync), with their consents; the pending calls their
    /// instances left behind are swept once; and only then is any answer
    /// given that depends on those writes. The writer's only.
    struct RegistrarRecord {
        protocol::SignedStatement statement;
        Sidecar sidecar;
        CallProgress progress;
        /// Its consents file is to be written at the commit (none was kept
        /// yet): all of the group's at once, before the calls are recorded.
        bool write_consents = false;
    };
    /// An answer held for the commit: given as it is, or, for a consent
    /// whose call the group records, made from what became of the call.
    struct HeldAnswer {
        Done done;
        std::string principal;
        http::Response response;
        std::optional<std::size_t> record = std::nullopt;
    };
    struct RegistrarGroup {
        bool active = false;
        bool consents_written = false;
        bool pending_written = false;
        std::vector<RegistrarRecord> records;
        /// The instances whose calls the group records.
        std::set<protocol::IdKey> instances;
        /// In the order of the jobs.
        std::vector<HeldAnswer> answers;
    };
    RegistrarGroup registrar;

    /// Whether `job` must wait for the registrar's group to be committed.
    [[nodiscard]] bool registrar_conflicts(const Queued& job) const {
        if (!registrar.active) {
            return false;
        }
        switch (job.kind) {
        case Queued::Kind::other:
            return true;
        case Queued::Kind::proposal:
            // It counts and reads the pending calls the records leave stale.
            return !registrar.records.empty();
        case Queued::Kind::consent:
            return job.instance && registrar.instances.contains(*job.instance);
        }
        return true;
    }

    /// Writes or removes pending calls: through the cluster (on every node,
    /// at once), or here, leaving the directory's sync to the group's commit.
    Status keep_pending(std::span<const PendingChange> changes) {
        if (changes.empty()) {
            return {};
        }
        if (cluster) {
            return cluster->change_pending(changes);
        }
        const bool writes =
            std::ranges::any_of(changes, [](const PendingChange& c) { return c.file.has_value(); });
        auto s = apply_pending_changes(options.directory, changes, false);
        registrar.pending_written = registrar.pending_written || writes;
        return s;
    }

    /// Answers a registrar's job: at once, or, if the job wrote anything the
    /// answer relies on, once the group is committed.
    void registrar_answer(bool after_commit, Done done, std::string principal,
                          http::Response response) {
        if (!after_commit) {
            finish(done, principal, std::move(response));
            return;
        }
        registrar.answers.push_back(
            {std::move(done), std::move(principal), std::move(response), std::nullopt});
    }

    /// Commits the registrar's group (see RegistrarGroup).
    void registrar_commit() {
        if (!registrar.active) {
            return;
        }
        RegistrarGroup group = std::move(registrar);
        registrar = {};
        // The consents files of the calls to record, written and synced at
        // once (D-056 P7), then their directory: a call is recorded only
        // with its consents kept.
        std::vector<std::optional<Error>> unkept(group.records.size());
        if (group.consents_written) {
            std::error_code ec;
            std::filesystem::create_directories(contract_consents_directory(options.directory), ec);
            ledger::parallel_for(
                group.records.size(),
                [&](std::size_t begin, std::size_t end) {
                    for (std::size_t i = begin; i < end; ++i) {
                        const RegistrarRecord& r = group.records[i];
                        if (!r.write_consents) {
                            continue;
                        }
                        if (auto s = detail::write_file(
                                contract_consents_path(options.directory, r.statement.id),
                                r.sidecar.bytes, true, false);
                            !s) {
                            unkept[i] = s.error();
                        }
                    }
                },
                2);
            detail::sync_directory(contract_consents_directory(options.directory));
        }
        if (group.pending_written) {
            detail::sync_directory(pending_calls_directory(options.directory));
        }
        const protocol::Timestamp now = clock->now();
        if (!group.records.empty()) {
            std::vector<ByteView> views;
            std::vector<std::optional<Sidecar>> sidecars;
            ledger::Ledger::Offers offers;
            std::vector<std::size_t> recorded;
            for (std::size_t i = 0; i < group.records.size(); ++i) {
                RegistrarRecord& r = group.records[i];
                if (unkept[i]) {
                    continue;
                }
                views.emplace_back(r.statement.encoded);
                sidecars.emplace_back(r.sidecar);
                offers.push_back(std::move(r.progress.run));
                recorded.push_back(i);
            }
            std::vector<Result<ledger::Registration>> batch;
            if (views.empty()) {
                // Nothing to record.
            } else if (cluster) {
                auto submitted = cluster->submit(views, sidecars, now);
                if (submitted) {
                    batch = std::move(*submitted);
                } else {
                    batch.assign(views.size(), std::unexpected(submitted.error()));
                }
            } else {
                // Pipelined behind the round's statements, if any, so that
                // both are written with one sync; then waited for.
                ledger->submit_batch_pipelined(
                    views,
                    [&batch](std::vector<Result<ledger::Registration>> r) { batch = std::move(r); },
                    std::nullopt, std::move(offers));
                ledger->wait_durable();
            }
            std::vector<Result<ledger::Registration>> results;
            for (std::size_t i = 0; i < group.records.size(); ++i) {
                results.emplace_back(
                    std::unexpected(unkept[i].value_or(Error{Errc::unavailable, "not recorded"})));
            }
            for (std::size_t k = 0; k < recorded.size(); ++k) {
                results[recorded[k]] = std::move(batch[k]);
            }
            std::vector<http::Response> answers(results.size());
            // What the calls' instances left pending is stale now; and what
            // became of each call.
            std::vector<PendingChange> stale;
            ledger->read_state([&](const protocol::LedgerState& s) {
                stale = calls->sweep(s, now, false);
                for (std::size_t i = 0; i < results.size(); ++i) {
                    answers[i] = recorded_call(s, group.records[i], results[i]);
                }
            });
            sweep_stale(stale);
            for (HeldAnswer& held : group.answers) {
                finish(held.done, held.principal,
                       held.record ? std::move(answers[*held.record]) : std::move(held.response));
            }
            return;
        }
        std::vector<PendingChange> stale;
        ledger->read_state(
            [&](const protocol::LedgerState& s) { stale = calls->sweep(s, now, false); });
        sweep_stale(stale);
        for (HeldAnswer& held : group.answers) {
            finish(held.done, held.principal, std::move(held.response));
        }
    }

    void sweep_stale(std::span<const PendingChange> stale) {
        if (stale.empty()) {
            return;
        }
        if (auto s = cluster ? cluster->change_pending(stale)
                             : apply_pending_changes(options.directory, stale);
            !s) {
            event("contract-pending-failed", s.error().detail);
        }
    }

    /// The answer to a consent whose call the group recorded (or not), on
    /// the state after it.
    http::Response recorded_call(const protocol::LedgerState& s, const RegistrarRecord& r,
                                 const Result<ledger::Registration>& recorded) {
        if (!recorded) {
            ++refused;
            return error_response(recorded.error());
        }
        ++(recorded->newly_registered ? registered : duplicates);
        const CallProgress& progress = r.progress;
        std::optional<std::string> status;
        if (const protocol::InstanceState* i = s.instance(progress.call.instance)) {
            status = i->status;
        }
        // The instances the call created (v0.7), in order.
        json children = json::array();
        for (std::uint32_t n = 0; n < protocol::max_contract_children; ++n) {
            auto child =
                protocol::child_instance_id(*provider, s.hash(), recorded->statement_id, n);
            if (!child || s.instance(*child) == nullptr) {
                break;
            }
            children.push_back(hex(*child));
        }
        event("contract-call", hex(progress.call.instance) + " " + progress.call.function);
        return json_response(201, {{"status", "recorded"},
                                   {"call", hex(progress.id)},
                                   {"instance", hex(progress.call.instance)},
                                   {"function", progress.call.function},
                                   {"statement_id", hex(recorded->statement_id)},
                                   {"index", recorded->index},
                                   {"instance_status", status ? json(*status) : json(nullptr)},
                                   {"children", std::move(children)}});
    }

    /// After a writer's failure: every answer the group holds is `broken`.
    void registrar_abandon(const http::Response& broken) {
        RegistrarGroup group = std::move(registrar);
        registrar = {};
        for (HeldAnswer& held : group.answers) {
            finish(held.done, held.principal, broken);
        }
    }

    /// POST /v1/contracts/calls: a call proposed to the registrar (D-053),
    /// by the home's people (a submit token) or by one of the instance's
    /// parties (a peer). The contract runs without consents and names whose
    /// it needs; the registrar holds the call until they are in.
    void call_proposal(const http::Request& r, std::string principal, Scopes scopes, Done& done) {
        if (auto denied = refuse_peer_write()) {
            finish(done, principal, std::move(*denied));
            return;
        }
        if (!calls) {
            finish(done, principal,
                   error_response(501, "unsupported",
                                  "this ledger has no registrar: its people sign contract calls"));
            return;
        }
        if (r.body.size() > max_call_proposal) {
            finish(done, principal,
                   error_response(413, "limit_exceeded", "a call proposal is at most 128 KiB"));
            return;
        }
        auto proposal = decode_call_proposal(r.body);
        if (!proposal) {
            finish(done, principal, error_response(proposal.error()));
            return;
        }
        std::optional<protocol::Id> party;
        if (!has_scope(scopes, Scope::submit)) {
            const auto peer = peer_named(principal);
            if (!peer) {
                finish(done, principal,
                       error_response(403, "forbidden", "this token is not a peer's"));
                return;
            }
            party = peer->ledger_id;
        }
        proposal->proposer = principal;
        queue_job({[this, proposal = std::move(*proposal), party, scopes,
                    principal = std::move(principal),
                    done = std::move(done)](const http::Response* refusal) mutable {
                       if (refusal != nullptr) {
                           finish(done, principal, *refusal);
                           return;
                       }
                       take_proposal(std::move(proposal), party, scopes, std::move(principal),
                                     std::move(done));
                   },
                   Queued::Kind::proposal});
    }

    /// On the writer: runs the proposal and holds it.
    void take_proposal(PendingCall proposal, const std::optional<protocol::Id>& party,
                       Scopes scopes, std::string principal, Done done) {
        registrar.active = true;
        const protocol::Timestamp now = clock->now();
        Result<CallProgress> progress = fail(Errc::unavailable, "no state");
        ledger->read_state([&](const protocol::LedgerState& s) {
            progress = calls->propose(*provider, s, std::move(proposal), party, now, entropy);
        });
        if (!progress) {
            finish(done, principal, error_response(progress.error()));
            return;
        }
        const bool writes = !progress->changes.empty();
        if (auto s = keep_pending(progress->changes); !s) {
            finish(done, principal, error_response(s.error()));
            return;
        }
        if (progress->verdict == CallProgress::Verdict::refused) {
            registrar_answer(writes, std::move(done), std::move(principal),
                             error_response(409, "rejected", progress->reason));
            return;
        }
        event("contract-proposal", progress->call.proposer + " " + hex(progress->call.instance) +
                                       " " + progress->call.function);
        json body = pending_json(progress->id, progress->call, has_scope(scopes, Scope::submit));
        body["status"] = "waiting";
        registrar_answer(writes, std::move(done), std::move(principal), json_response(202, body));
    }

    /// POST /v1/contracts/consents: a party's consent to a pending call,
    /// from its own ledger; once the contract accepts the call with the
    /// consents held, the registrar signs and records it. The consent's
    /// evidence (and that of the consents held for the call) is verified
    /// here, before the writer takes it.
    void contract_consent(const http::Request& r, std::string principal, Done& done) {
        if (auto denied = refuse_peer_write()) {
            finish(done, principal, std::move(*denied));
            return;
        }
        if (!calls) {
            finish(done, principal,
                   error_response(501, "unsupported",
                                  "this ledger has no registrar: its people sign contract calls"));
            return;
        }
        if (r.body.size() > max_consent_bundle) {
            finish(done, principal,
                   error_response(413, "limit_exceeded", "a consent is at most 256 KiB"));
            return;
        }
        auto peer = peer_of(principal, r.body);
        if (!peer) {
            finish(done, principal, error_response(403, "forbidden", peer.error().detail));
            return;
        }
        auto prepared = calls->prepare(*provider, peer->ledger_id, r.body);
        if (!prepared) {
            finish(done, principal, consent_error(prepared.error()));
            return;
        }
        std::optional<protocol::IdKey> instance;
        if (prepared->instance) {
            instance = protocol::key_of(*prepared->instance);
        }
        queue_job({[this, prepared = std::make_shared<const PreparedConsent>(std::move(*prepared)),
                    name = peer->name, principal = std::move(principal),
                    done = std::move(done)](const http::Response* refusal) mutable {
                       if (refusal != nullptr) {
                           finish(done, principal, *refusal);
                           return;
                       }
                       take_call_consent(*prepared, name, std::move(principal), std::move(done));
                   },
                   Queued::Kind::consent, instance});
    }

    /// A registrar's refusal of a consent, as answered.
    static http::Response consent_error(const Error& e) {
        return e.code == Errc::invalid_argument ? error_response(403, "forbidden", e.detail)
                                                : error_response(e);
    }

    /// On the writer: holds the consent, and once the contract accepts the
    /// call, records it with the group.
    void take_call_consent(const PreparedConsent& prepared, const std::string& name,
                           std::string principal, Done done) {
        registrar.active = true;
        const protocol::Timestamp now = clock->now();
        Result<CallProgress> progress = fail(Errc::unavailable, "no state");
        ledger->read_state([&](const protocol::LedgerState& s) {
            progress = calls->consent(*provider, s, prepared, now, entropy);
        });
        if (!progress) {
            finish(done, principal, consent_error(progress.error()));
            return;
        }
        const bool writes = !progress->changes.empty();
        if (auto s = keep_pending(progress->changes); !s) {
            finish(done, principal, error_response(s.error()));
            return;
        }
        event("contract-consent", name + " " + hex(progress->id));
        if (progress->verdict == CallProgress::Verdict::refused) {
            registrar_answer(writes, std::move(done), std::move(principal),
                             error_response(409, "rejected", progress->reason));
            return;
        }
        if (progress->verdict == CallProgress::Verdict::waiting) {
            json body = pending_json(progress->id, progress->call, false);
            body["status"] = "waiting";
            registrar_answer(writes, std::move(done), std::move(principal),
                             json_response(202, body));
            return;
        }
        protocol::SignedStatement statement = *progress->statement;
        auto encoded = encode_consent_bundles(progress->bundles);
        if (!encoded) {
            finish(done, principal, error_response(encoded.error()));
            return;
        }
        // Kept first: a registered call always has its consents here. The
        // group's files are written (and synced) together at its commit,
        // then their directory, before the calls are recorded.
        bool write_consents = false;
        if (auto held =
                detail::read_file(contract_consents_path(options.directory, statement.id))) {
            if (!std::ranges::equal(*held, *encoded)) {
                finish(done, principal,
                       error_response(
                           Error{Errc::rejected, "other consent evidence is kept for this call"}));
                return;
            }
        } else {
            write_consents = true;
            registrar.consents_written = true;
        }
        registrar.instances.insert(protocol::key_of(progress->call.instance));
        const std::size_t k = registrar.records.size();
        registrar.records.push_back({std::move(statement),
                                     Sidecar{Sidecar::Kind::contract_consents, std::move(*encoded)},
                                     std::move(*progress), write_consents});
        registrar.answers.push_back({std::move(done), std::move(principal), {}, k});
    }

    /// Membership changes and stepping down, on the leader's writer.
    void cluster_change(const http::Request& r, Endpoint endpoint, std::string principal,
                        Done& done) {
        const json body = json::parse(r.body.begin(), r.body.end(), nullptr, false);
        ClusterMember member;
        if (endpoint == Endpoint::cluster_add) {
            if (!body.is_object() || !body.contains("id") || !body["id"].is_number_integer() ||
                !body.contains("raft") || !body["raft"].is_string() || !body.contains("api") ||
                !body["api"].is_string()) {
                finish(done, principal,
                       error_response(400, "malformed", "send {\"id\", \"raft\", \"api\"}"));
                return;
            }
            member = {body["id"].get<int>(), body["raft"].get<std::string>(),
                      body["api"].get<std::string>()};
        } else if (endpoint == Endpoint::cluster_remove) {
            if (!body.is_object() || !body.contains("id") || !body["id"].is_number_integer()) {
                finish(done, principal, error_response(400, "malformed", "send {\"id\"}"));
                return;
            }
            member.id = body["id"].get<int>();
        }
        queue_locked([this, endpoint, member, principal = std::move(principal),
                      done = std::move(done)](const http::Response* refusal) mutable {
            if (refusal != nullptr) {
                finish(done, principal, *refusal);
                return;
            }
            const Status changed = endpoint == Endpoint::cluster_add ? cluster->add_member(member)
                                   : endpoint == Endpoint::cluster_remove
                                       ? cluster->remove_member(member.id)
                                       : cluster->step_down();
            if (changed) {
                event("cluster-change", endpoint == Endpoint::cluster_add      ? "member added"
                                        : endpoint == Endpoint::cluster_remove ? "member removed"
                                                                               : "stepped down");
            }
            finish(done, principal,
                   changed ? json_response(200, {{"accepted", true}})
                           : error_response(changed.error()));
        });
    }

    void make_checkpoint(std::string principal, Done& done) {
        if (options.log_keys.empty()) {
            finish(done, principal,
                   error_response(501, "unsupported", "this server has no log key"));
            return;
        }
        queue_locked([this, principal = std::move(principal),
                      done = std::move(done)](const http::Response* refusal) mutable {
            if (refusal != nullptr) {
                finish(done, principal, *refusal);
                return;
            }
            auto made = cluster ? cluster->checkpoint(log_keys()) : ledger->checkpoint(log_keys());
            finish(done, principal,
                   made ? binary("application/cose", made->encoded) : error_response(made.error()));
        });
    }

    void add_cosignature(const http::Request& r, std::string principal, Done& done) {
        auto value = cbor::decode(r.body);
        const cbor::Array* parts = value ? value->as_array() : nullptr;
        if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_bytes() == nullptr) {
            finish(done, principal,
                   error_response(400, "malformed", "send [cosignature, witness public key]"));
            return;
        }
        auto witness = protocol::decode_public_key((*parts)[1]);
        if (!witness) {
            finish(done, principal, error_response(witness.error()));
            return;
        }
        queue_locked([this, cosignature = Bytes(*(*parts)[0].as_bytes()), key = std::move(*witness),
                      principal = std::move(principal),
                      done = std::move(done)](const http::Response* refusal) mutable {
            if (refusal != nullptr) {
                finish(done, principal, *refusal);
                return;
            }
            auto stored = cluster ? cluster->add_cosignature(cosignature, key)
                                  : ledger->add_cosignature(cosignature, key);
            finish(done, principal,
                   stored ? json_response(200, {{"stored", true}})
                          : error_response(stored.error()));
        });
    }

    /// From tick(): checkpoints when the interval has passed and the log has
    /// grown.
    void auto_checkpoint() {
        if (failed || options.log_keys.empty() || replica || options.read_only ||
            (cluster && !cluster->leads()) || options.checkpoint_interval.count() == 0 ||
            steady::now() - last_auto_checkpoint < options.checkpoint_interval) {
            return;
        }
        last_auto_checkpoint = steady::now();
        auto covered = [this] {
            const auto latest = ledger->latest_checkpoint();
            return latest && latest->checkpoint.tree_size >= ledger->size();
        };
        if (!ledger->outdated() && covered()) {
            return;
        }
        queue_locked([this, covered](const http::Response* refusal) {
            if (refusal != nullptr || covered()) {
                return; // busy or unusable: next time
            }
            auto made = cluster ? cluster->checkpoint(log_keys()) : ledger->checkpoint(log_keys());
            if (!made) {
                event("checkpoint-failed", made.error().detail);
                return;
            }
            ++auto_checkpoints;
            event("checkpoint", std::format("tree size {}", made->checkpoint.tree_size));
        });
    }

    // ---- the keeper (6b) ------------------------------------------------

    /// From tick(): asks the keeper's thread for a slice of its scan when the
    /// interval has passed, or when the last slice left work to go on with.
    /// Leaders only.
    void keep() {
        if (!options.keeper || failed || replica || options.read_only) {
            return;
        }
        const bool leads = !cluster || cluster->leads();
        {
            const std::lock_guard lock(keeper_mutex);
            if (!leads) {
                keeper_leading = false;
                return;
            }
            if (!keeper_leading) {
                // Just started, or just elected: scan now, from the start.
                keeper_leading = true;
                keeper_more = true;
                keeper_next = 0;
                keeper_pass_more = false;
                keeper_rounds = 0;
            }
            if (keeper_busy || keeper_stopping ||
                (!keeper_more && steady::now() - keeper_last < options.keeper_interval)) {
                return;
            }
            keeper_busy = true;
            keeper_signal = true;
        }
        keeper_wake.notify_all();
    }

    /// The keeper's thread: a slice each time keep() asks for one.
    void run_keeper() {
        std::unique_lock lock(keeper_mutex);
        for (;;) {
            keeper_wake.wait(lock, [&] { return keeper_stopping || keeper_signal; });
            if (keeper_stopping) {
                keeper_busy = false;
                keeper_signal = false;
                keeper_wake.notify_all();
                return;
            }
            keeper_signal = false;
            lock.unlock();
            try {
                keeper_slice();
            } catch (const std::exception&) {
                event("keeper-error", "a keeper slice failed with an exception");
            }
            lock.lock();
            keeper_busy = false;
            keeper_wake.notify_all();
        }
    }

    /// Passes over the instances in a row (instances with more due than
    /// one call) before the keeper waits for its interval.
    static constexpr std::uint32_t max_keeper_rounds = 16;
    /// Contract runs in one slice: its calls are one group for the writer.
    static constexpr std::size_t keeper_slice_runs = 2'000;

    /// A call of a slice: what it is for, the event it makes, and its
    /// signed statement (or why it could not be signed).
    struct KeeperCall {
        protocol::ContractCallBody body;
        bool expiry = false;
        std::string detail;
        Result<protocol::Statement> statement = fail(Errc::unavailable, "not prepared");
        Result<protocol::SignedStatement> signed_call = fail(Errc::unavailable, "not signed");
        /// Its instance moved on before the writer took it: the next pass
        /// looks again.
        bool dropped = false;
        /// The scan's dry run, offered to the ledger (taken if the call's
        /// input is the same when it is registered).
        std::optional<protocol::ContractRun> run = std::nullopt;
    };

    /// On the keeper's thread: finds what is due (a slice of the scan, on
    /// worker threads, under the state's read lock), signs one call per
    /// instance, and has the writer record them as one group: one sync.
    void keeper_slice() {
        std::uint64_t start = 0;
        {
            const std::lock_guard lock(keeper_mutex);
            start = keeper_next;
        }
        if (cluster && !cluster->leads()) {
            return;
        }
        // What other processes wrote first, as the writer's jobs see it.
        if (!cluster && ledger->outdated() && !on_writer([] {})) {
            return; // the ledger is busy or unusable: next tick
        }
        const protocol::Timestamp now = clock->now();
        std::optional<protocol::Id> actor;
        Result<DueWork> work = fail(Errc::unavailable, "no state");
        // One call per instance: each moves the instance's head, so what
        // else is due on it waits for the next pass.
        std::vector<KeeperCall> due_calls;
        bool more = false;
        ledger->read_state([&](const protocol::LedgerState& s) {
            const auto kid = protocol::key_id(*provider, s.hash(), options.keeper->public_key());
            const protocol::ActorState* a = kid ? s.actor_by_kid(*kid) : nullptr;
            if (a == nullptr || a->revoked) {
                return;
            }
            actor = a->id.id();
            DueOptions o;
            o.now = now;
            o.grace = static_cast<protocol::Timestamp>(options.expiry_grace.count());
            o.keeper = actor;
            o.start = start;
            o.max_runs = keeper_slice_runs;
            o.keep_runs = true;
            work = find_due(*provider, s, o);
            if (!work) {
                return;
            }
            std::set<protocol::IdKey> touched;
            auto take = [&](protocol::ContractCallBody body, bool expiry, std::string detail,
                            std::optional<protocol::ContractRun>& run) {
                if (!touched.insert(protocol::key_of(*body.instance)).second) {
                    more = true;
                    return;
                }
                due_calls.push_back({.body = std::move(body),
                                     .expiry = expiry,
                                     .detail = std::move(detail),
                                     .statement = fail(Errc::unavailable, "not prepared"),
                                     .signed_call = fail(Errc::unavailable, "not signed"),
                                     .dropped = false,
                                     .run = std::move(run)});
            };
            for (DueExpiry& e : work->expiries) {
                take(expiry_call(e), true,
                     std::format("request {} ({}) on {}", hex(e.request), e.kind, hex(e.instance)),
                     e.run);
            }
            for (DueRule& r : work->rules) {
                take(rule_call(r), false,
                     std::format("{} on {}{}", r.function, hex(r.instance),
                                 r.late ? std::format(", {} ms late", *r.late) : std::string()),
                     r.run);
            }
            // The statements in order, each with its nonce drawn in turn;
            // the signatures on worker threads.
            for (KeeperCall& c : due_calls) {
                c.statement = contract_call_statement(*provider, s, *options.keeper, c.body, now);
                if (c.statement) {
                    c.statement->nonce = entropy.bytes<16>();
                }
            }
            ledger::parallel_for(due_calls.size(), [&](std::size_t begin, std::size_t end) {
                for (std::size_t i = begin; i < end; ++i) {
                    KeeperCall& c = due_calls[i];
                    c.signed_call = c.statement
                                        ? protocol::sign_statement(*options.keeper, *provider,
                                                                   s.hash(), *c.statement)
                                        : Result<protocol::SignedStatement>(
                                              std::unexpected(c.statement.error()));
                }
            });
        });
        if (!actor || !work) {
            event("keeper-idle", !actor ? "the keeper key is not an active actor's of this ledger"
                                        : work.error().detail);
            keeper_done(false, std::nullopt);
            return;
        }
        bool stop = false;
        const bool ran =
            due_calls.empty() || on_writer([&] { record_keeper_calls(due_calls, more, stop); });
        if (!ran || stop) {
            // Busy or unusable: the next tick tries this slice again. No
            // longer leading: keep() starts afresh if this node leads again.
            return;
        }
        keeper_done(more, work->next);
    }

    /// On the writer: records a slice's due_calls as one group, then tells what
    /// became of each, in order. A call whose instance moved on since the
    /// scan (another write came first) is left for the next pass; `stop`
    /// is set if this node no longer leads. Off a cluster the group is
    /// pipelined (D-056 P7): what became of its calls is told from the
    /// ledger's commit thread once they are durable, while the keeper scans
    /// on; the scan's dry runs are offered to the ledger.
    void record_keeper_calls(std::vector<KeeperCall>& due_calls, bool& more, bool& stop) {
        if (cluster && !cluster->leads()) {
            stop = true;
            return;
        }
        std::vector<ByteView> views;
        ledger::Ledger::Offers offers;
        // What each submitted call is for: its detail, and whether it expires
        // a request.
        auto told = std::make_shared<std::vector<std::pair<std::string, bool>>>();
        ledger->read_state([&](const protocol::LedgerState& s) {
            for (KeeperCall& c : due_calls) {
                if (!c.signed_call) {
                    continue;
                }
                const protocol::InstanceState* instance = s.instance(*c.body.instance);
                if (instance == nullptr || instance->head != c.body.head) {
                    c.dropped = true;
                    more = true;
                    continue;
                }
                views.emplace_back(c.signed_call->encoded);
                offers.push_back(std::move(c.run));
                told->emplace_back(c.detail, c.expiry);
            }
        });
        // Calls that could not be signed are refused at once.
        for (const KeeperCall& c : due_calls) {
            if (!c.dropped && !c.signed_call) {
                ++keeper_refusals;
                event("keeper-refused",
                      std::format("{}: {}", c.detail, c.signed_call.error().detail));
            }
        }
        if (views.empty()) {
            return;
        }
        if (!cluster) {
            ledger->submit_batch_pipelined(
                views,
                [this, told](std::vector<Result<ledger::Registration>> results) {
                    keeper_recorded(*told, results, nullptr);
                },
                std::nullopt, std::move(offers));
            return;
        }
        const std::vector<std::optional<Sidecar>> none(views.size());
        auto batch = cluster->submit(views, none, clock->now());
        std::vector<Result<ledger::Registration>> results;
        if (batch) {
            results = std::move(*batch);
        } else {
            results.assign(views.size(), std::unexpected(batch.error()));
        }
        keeper_recorded(*told, results, &stop);
    }

    /// What became of a keeper group's calls (each told's detail), in order:
    /// counters and events. On a cluster, `stop` is set (and the rest left
    /// untold) if this node no longer leads.
    void keeper_recorded(const std::vector<std::pair<std::string, bool>>& told,
                         const std::vector<Result<ledger::Registration>>& results, bool* stop) {
        bool recorded_any = false;
        for (std::size_t i = 0; i < told.size() && i < results.size(); ++i) {
            const auto& [detail, expiry] = told[i];
            const Result<ledger::Registration>& recorded = results[i];
            if (!recorded) {
                ++refused;
                ++keeper_refusals;
                event("keeper-refused", std::format("{}: {}", detail, recorded.error().detail));
                if (stop != nullptr && cluster && !cluster->leads()) {
                    *stop = true; // a follower now: the new leader's keeper carries on
                    break;
                }
                continue;
            }
            ++(recorded->newly_registered ? registered : duplicates);
            recorded_any = true;
            ++(expiry ? keeper_expiries : keeper_rules);
            event(expiry ? "keeper-expired" : "keeper-fired",
                  std::format("{} #{}", detail, recorded->index));
        }
        if (recorded_any) {
            check_waiters(false); // expiries close requests that long polls may watch
        }
    }

    /// A slice ended. A pass over the instances goes on where it stopped;
    /// once it is over, another starts at once if an instance had more due
    /// than one call (up to max_keeper_rounds passes), else the keeper waits
    /// for its interval.
    void keeper_done(bool more, std::optional<std::uint64_t> next) {
        const std::lock_guard lock(keeper_mutex);
        keeper_pass_more = keeper_pass_more || more;
        if (next) {
            keeper_more = true;
            keeper_next = *next;
            return;
        }
        const bool again = keeper_pass_more && keeper_rounds < max_keeper_rounds;
        keeper_next = 0;
        keeper_pass_more = false;
        if (again) {
            ++keeper_rounds;
            keeper_more = true;
            return;
        }
        keeper_more = false;
        keeper_rounds = 0;
        keeper_last = steady::now();
    }

    /// GET /v1/contracts/due: what a keeper would do at a time (now by
    /// default): the time rules due and the requests to expire, found by dry
    /// runs, as a hint.
    http::Response contracts_due(const http::Request& r) const {
        const auto parsed = detail::parse_due_query(r);
        if (const auto* bad = std::get_if<detail::QueryError>(&parsed)) {
            return error_response(400, "invalid_argument", bad->message);
        }
        const auto& q = std::get<detail::DueQuery>(parsed);
        DueOptions o;
        o.now = q.at ? *q.at : clock->now();
        o.grace = q.grace ? *q.grace * 1000
                          : static_cast<protocol::Timestamp>(options.expiry_grace.count());
        o.keeper = q.keeper;
        o.contract = q.contract;
        o.instance = q.instance;
        o.start = q.start;
        o.max_runs = q.limit;
        Result<DueWork> work = fail(Errc::unavailable, "no state");
        ledger->read_state(
            [&](const protocol::LedgerState& s) { work = find_due(*provider, s, o); });
        if (!work) {
            return error_response(work.error());
        }
        http::Response response;
        const std::string body = due_json_text(*work) + "\n";
        response.body.assign(body.begin(), body.end());
        return response;
    }

    // ---- routing -------------------------------------------------------

    http::Response metrics() const {
        const auto latest = ledger->latest_checkpoint();
        const std::uint64_t size = ledger->size();
        const std::uint64_t checkpointed = latest ? latest->checkpoint.tree_size : 0;
        std::string out;
        auto gauge = [&](std::string_view name, std::string_view help, std::uint64_t value) {
            out += std::format("# HELP {0} {1}\n# TYPE {0} gauge\n{0} {2}\n", name, help, value);
        };
        gauge("cexchain_ledger_usable", "1 while the ledger's files validate.", failed ? 0 : 1);
        gauge("cexchain_log_entries", "Entries in the log.", size);
        gauge("cexchain_checkpoint_tree_size", "Entries the latest checkpoint covers.",
              checkpointed);
        gauge("cexchain_checkpoint_timestamp_seconds", "When the latest checkpoint was signed.",
              latest ? latest->checkpoint.timestamp / 1000 : 0);
        gauge("cexchain_unchecked_entries", "Entries no checkpoint covers yet.",
              size - std::min(size, checkpointed));
        out += "# HELP cexchain_http_responses_total Responses by status code.\n"
               "# TYPE cexchain_http_responses_total counter\n";
        for (std::size_t code = 0; code < responses.size(); ++code) {
            if (const std::uint64_t n = responses[code].load(std::memory_order_relaxed); n > 0) {
                out += std::format("cexchain_http_responses_total{{code=\"{}\"}} {}\n", code, n);
            }
        }
        out += "# HELP cexchain_statements_total Submitted statements by outcome.\n"
               "# TYPE cexchain_statements_total counter\n";
        const std::array<std::pair<std::string_view, const std::atomic<std::uint64_t>*>, 3>
            outcomes{
                {{"duplicate", &duplicates}, {"refused", &refused}, {"registered", &registered}}};
        for (const auto& [result, counter] : outcomes) {
            if (const std::uint64_t n = counter->load(std::memory_order_relaxed); n > 0) {
                out += std::format("cexchain_statements_total{{result=\"{}\"}} {}\n", result, n);
            }
        }
        if (options.keeper) {
            out += "# HELP cexchain_keeper_calls_total The keeper's calls by kind.\n"
                   "# TYPE cexchain_keeper_calls_total counter\n";
            out += std::format("cexchain_keeper_calls_total{{kind=\"expiry\"}} {}\n"
                               "cexchain_keeper_calls_total{{kind=\"refused\"}} {}\n"
                               "cexchain_keeper_calls_total{{kind=\"rule\"}} {}\n",
                               keeper_expiries.load(std::memory_order_relaxed),
                               keeper_refusals.load(std::memory_order_relaxed),
                               keeper_rules.load(std::memory_order_relaxed));
        }
        out += std::format("# HELP cexchain_auto_checkpoints_total Automatic checkpoints.\n"
                           "# TYPE cexchain_auto_checkpoints_total counter\n"
                           "cexchain_auto_checkpoints_total {}\n",
                           auto_checkpoints.load(std::memory_order_relaxed));
        http::Response r;
        r.content_type = "text/plain; version=0.0.4";
        r.body.assign(out.begin(), out.end());
        return r;
    }

    /// The route for a request, or the answer if it has none.
    static std::variant<Routed, http::Response> classify(const http::Request& r) {
        const std::string_view path = r.path;
        const bool get = r.method == "GET";
        const bool post = r.method == "POST";
        auto method_not_allowed = [](std::string_view allow) {
            auto response = error_response(405, "unsupported", "method not allowed");
            response.headers.emplace_back("Allow", std::string(allow));
            return response;
        };
        std::size_t rest = 0;
        auto match = [&](std::string_view prefix) {
            if (path.starts_with(prefix) && path.size() > prefix.size() &&
                path.find('/', prefix.size()) == std::string_view::npos) {
                rest = prefix.size();
                return true;
            }
            return false;
        };
        std::optional<Routed> found;
        if (path == "/v1/checkpoint" || path == "/v1/consistency") {
            if (post && path == "/v1/consistency") {
                return method_not_allowed("GET");
            }
            found = post ? Routed{Endpoint::make_checkpoint, Access::admin}
                         : Routed{path == "/v1/checkpoint" ? Endpoint::get_checkpoint
                                                           : Endpoint::consistency,
                                  Access::open};
        } else if (path == "/v1/access/requests" || path == "/v1/access/receipts" ||
                   path == "/v1/witness/cosign") {
            if (!post) {
                return method_not_allowed("POST");
            }
            found = Routed{path == "/v1/access/requests"   ? Endpoint::access_request
                           : path == "/v1/access/receipts" ? Endpoint::access_receipt
                                                           : Endpoint::witness_cosign,
                           Access::peer};
        } else if (match("/v1/access/deliveries/")) {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Routed{Endpoint::access_delivery, Access::peer, rest};
        } else if (path == "/v1/statements") {
            if (!post) {
                return method_not_allowed("POST");
            }
            found = Routed{Endpoint::submit, Access::submit_or_executor};
        } else if (path == "/v1/requests") {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Routed{Endpoint::requests, Access::read_or_executor};
        } else if (path == "/v1/contracts") {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Routed{Endpoint::contract_list, Access::read};
        } else if (path == "/v1/contracts/due") {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Routed{Endpoint::contracts_due, Access::read};
        } else if (path == "/v1/contracts/calls") {
            if (!get && !post) {
                return method_not_allowed("GET, POST");
            }
            found = post ? Routed{Endpoint::call_propose, Access::submit_or_peer}
                         : Routed{Endpoint::call_list, Access::read_or_peer};
        } else if (path == "/v1/contracts/consents") {
            if (!post) {
                return method_not_allowed("POST");
            }
            found = Routed{Endpoint::contract_consent, Access::peer};
        } else if (match("/v1/contracts/calls/")) {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Routed{Endpoint::call_show, Access::read_or_peer, rest};
        } else if (match("/v1/contracts/instances/")) {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Routed{Endpoint::instance_evidence, Access::read_peer_or_executor, rest};
        } else if (match("/v1/contracts/")) {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Routed{Endpoint::contract_show, Access::read, rest};
        } else if (path == "/v1/cluster") {
            if (!get) {
                return method_not_allowed("GET");
            }
            found = Routed{Endpoint::cluster_status, Access::read};
        } else if (path == "/v1/cluster/members" || path == "/v1/cluster/members/remove" ||
                   path == "/v1/cluster/step-down") {
            if (!post) {
                return method_not_allowed("POST");
            }
            found = Routed{path == "/v1/cluster/members"          ? Endpoint::cluster_add
                           : path == "/v1/cluster/members/remove" ? Endpoint::cluster_remove
                                                                  : Endpoint::cluster_step_down,
                           Access::admin};
        } else if (path == "/v1/cosignatures") {
            found = post ? Routed{Endpoint::add_cosignature, Access::admin}
                         : Routed{Endpoint::cosignatures, Access::read};
        } else {
            static constexpr std::array<std::pair<std::string_view, Endpoint>, 6> fixed{{
                {"/metrics", Endpoint::metrics},
                {"/v1/status", Endpoint::status},
                {"/v1/entries", Endpoint::entries},
                {"/v1/checkpoints", Endpoint::checkpoints},
                {"/v1/inclusion", Endpoint::inclusion},
                {"/v1/vault/public-key", Endpoint::vault_public_key},
            }};
            static constexpr std::array<std::pair<std::string_view, Endpoint>, 5> prefixed{{
                {"/v1/statements/", Endpoint::statement},
                {"/v1/receipts/", Endpoint::receipt},
                {"/v1/state/", Endpoint::state},
                {"/v1/evidence/", Endpoint::evidence},
                {"/v1/vault/records/", Endpoint::vault_record},
            }};
            for (const auto& [name, endpoint] : fixed) {
                if (path == name) {
                    found = Routed{endpoint, Access::read};
                }
            }
            for (const auto& [prefix, endpoint] : prefixed) {
                if (!found && match(prefix)) {
                    found = Routed{endpoint, Access::read, rest};
                }
            }
            if (found && !get) {
                return method_not_allowed("GET");
            }
        }
        if (!found) {
            return error_response(404, "not_found", "no such route");
        }
        if (!get && !post) {
            const bool posts = found->endpoint == Endpoint::make_checkpoint ||
                               found->endpoint == Endpoint::add_cosignature ||
                               found->endpoint == Endpoint::cluster_add ||
                               found->endpoint == Endpoint::cluster_remove ||
                               found->endpoint == Endpoint::cluster_step_down;
            return method_not_allowed(posts ? "POST" : "GET");
        }
        return *found;
    }

    /// Everything but the writes: reads, and the peer routes (which read
    /// the ledger and write files of their own).
    http::Response answer(const http::Request& r, const Routed& routed,
                          const std::string& principal, Scopes scopes) {
        if (failed) {
            return error_response(503, "unavailable",
                                  "the ledger's files do not validate; run cexchain audit");
        }
        const std::string_view rest = std::string_view(r.path).substr(routed.rest);
        switch (routed.endpoint) {
        case Endpoint::metrics:
            return metrics();
        case Endpoint::status:
            return status();
        case Endpoint::cluster_status:
            return cluster ? json_response(200, cluster_json())
                           : error_response(404, "not_found", "this node is not in a cluster");
        case Endpoint::get_checkpoint:
            return checkpoint(r);
        case Endpoint::consistency:
            return consistency(r);
        case Endpoint::entries:
            return entries(r);
        case Endpoint::checkpoints:
            return checkpoints(r);
        case Endpoint::cosignatures:
            return cosignatures(r);
        case Endpoint::inclusion:
            return inclusion(r);
        case Endpoint::statement:
            return statement(rest);
        case Endpoint::receipt:
            return receipt(rest);
        case Endpoint::state:
            return state_proof(rest);
        case Endpoint::evidence:
            return evidence(rest);
        case Endpoint::vault_public_key:
            return vault_file("vault.pub");
        case Endpoint::vault_record:
            if (!id_from(rest)) {
                return error_response(400, "invalid_argument", "a record id is 64 hex digits");
            }
            return vault_file(std::filesystem::path("records") / (std::string(rest) + ".cbor"));
        case Endpoint::access_request:
            return access_request(r, principal);
        case Endpoint::access_delivery:
            return access_delivery(rest, principal);
        case Endpoint::access_receipt:
            return access_receipt(r, principal);
        case Endpoint::witness_cosign:
            return witness_cosign(r);
        case Endpoint::contract_list:
            return contract_list(r);
        case Endpoint::contract_show:
            return contract_show(rest);
        case Endpoint::contracts_due:
            return contracts_due(r);
        case Endpoint::instance_evidence:
            return instance_evidence_of(rest, principal, scopes);
        case Endpoint::call_list:
            return pending_list(principal, scopes);
        case Endpoint::call_show:
            return pending_show(rest, principal, scopes);
        case Endpoint::requests:
        case Endpoint::call_propose:
        case Endpoint::contract_consent:
        case Endpoint::make_checkpoint:
        case Endpoint::add_cosignature:
        case Endpoint::submit:
        case Endpoint::cluster_add:
        case Endpoint::cluster_remove:
        case Endpoint::cluster_step_down:
            break;
        }
        return error_response(500, "internal", "unrouted");
    }

    http::Response answer_safely(const http::Request& r, const Routed& routed,
                                 const std::string& principal, Scopes scopes) {
        try {
            return answer(r, routed, principal, scopes);
        } catch (const std::exception&) {
            return error_response(500, "internal", "internal error");
        }
    }

    void serve(http::Request r, Done done) {
        if (r.path == "/healthz") {
            if (r.method != "GET") {
                auto response = error_response(405, "unsupported", "method not allowed");
                response.headers.emplace_back("Allow", "GET");
                finish(done, {}, std::move(response));
                return;
            }
            const auto f = failure();
            http::Response h;
            h.content_type = "text/plain";
            h.status = f ? 503 : 200;
            const std::string text = f ? "unusable: " + *f + "\n" : "ok\n";
            h.body.assign(text.begin(), text.end());
            finish(done, "public", std::move(h));
            return;
        }
        if (failed) {
            finish(done, {},
                   error_response(503, "unavailable",
                                  "the ledger's files do not validate; run cexchain audit"));
            return;
        }
        auto classified = classify(r);
        if (auto* response = std::get_if<http::Response>(&classified)) {
            finish(done, {}, std::move(*response));
            return;
        }
        const Routed routed = std::get<Routed>(classified);
        std::string principal;
        Scopes scopes = 0;
        if (auto denied = authorize(r, routed.access, principal, scopes)) {
            finish(done, principal, std::move(*denied));
            return;
        }
        const bool cluster_write = routed.endpoint == Endpoint::cluster_add ||
                                   routed.endpoint == Endpoint::cluster_remove ||
                                   routed.endpoint == Endpoint::cluster_step_down;
        const bool writes = routed.endpoint == Endpoint::submit ||
                            routed.endpoint == Endpoint::make_checkpoint ||
                            routed.endpoint == Endpoint::add_cosignature ||
                            routed.endpoint == Endpoint::call_propose ||
                            routed.endpoint == Endpoint::contract_consent || cluster_write;
        if (writes && cluster_write && !cluster) {
            finish(done, principal,
                   error_response(404, "not_found", "this node is not in a cluster"));
            return;
        }
        if (writes && cluster && !cluster->leads()) {
            finish(done, principal, not_leader(r.target));
            return;
        }
        if (cluster_write) {
            cluster_change(r, routed.endpoint, std::move(principal), done);
            return;
        }
        if (routed.endpoint == Endpoint::call_propose) {
            call_proposal(r, std::move(principal), scopes, done);
            return;
        }
        if (routed.endpoint == Endpoint::contract_consent) {
            contract_consent(r, std::move(principal), done);
            return;
        }
        if (routed.endpoint == Endpoint::instance_evidence) {
            evidence_request(r, routed, std::move(principal), scopes, done);
            return;
        }
        if (routed.endpoint == Endpoint::requests) {
            requests_request(r, std::move(principal), std::move(done));
            return;
        }
        if (writes) {
            if (options.read_only || replica) {
                finish(done, principal,
                       error_response(403, "read_only",
                                      replica ? "this ledger is a replica; write to its primary"
                                              : "this server is read-only"));
            } else if (routed.endpoint == Endpoint::submit) {
                submit(r, std::move(principal), scopes, done);
            } else if (routed.endpoint == Endpoint::make_checkpoint) {
                make_checkpoint(std::move(principal), done);
            } else {
                add_cosignature(r, std::move(principal), done);
            }
            return;
        }
        if (ledger->outdated()) {
            // Another process wrote: answer once the writer has caught up.
            queue_read([this, r = std::move(r), routed, principal = std::move(principal), scopes,
                        done = std::move(done)]() mutable {
                finish(done, principal, answer_safely(r, routed, principal, scopes));
            });
            return;
        }
        finish(done, principal, answer_safely(r, routed, principal, scopes));
    }
};

Result<std::unique_ptr<LedgerApi>> LedgerApi::open(ApiOptions options,
                                                   const crypto::Provider& provider) {
    auto state = std::make_unique<State>();
    state->provider = &provider;
    if (options.clock != nullptr) {
        state->clock = options.clock;
    }
    if (options.entropy != nullptr) {
        state->entropy.use(*options.entropy);
    }
    std::error_code ec;
    if (!std::filesystem::is_directory(options.directory, ec)) {
        return fail(Errc::not_found, "no ledger directory");
    }
    state->replica = std::filesystem::exists(options.directory / replica_file, ec);
    if (options.cluster && (state->replica || !is_cluster_member(options.directory))) {
        return fail(Errc::invalid_argument,
                    "the ledger is not a cluster member (cexchain cluster init or join)");
    }
    if (!options.cluster && !options.read_only && is_cluster_member(options.directory)) {
        // Writes outside Raft would fork the members.
        return fail(Errc::invalid_argument,
                    "the ledger is a cluster member: serve it with --cluster (or --read-only)");
    }
    {
        auto lock = ledger::DirectoryLock::acquire(options.directory);
        if (!lock) {
            return std::unexpected(lock.error());
        }
        if (options.cluster) {
            // No other process may write a member's files.
            state->member_lock.emplace(std::move(*lock));
        }
        auto fs = ledger::PosixFileSystem::open_directory(options.directory);
        if (!fs) {
            return std::unexpected(fs.error());
        }
        state->fs.emplace(std::move(*fs));
        auto opened = ledger::Ledger::open(*state->fs, *state->clock, provider);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        state->ledger.emplace(std::move(*opened));
    }
    if (!options.log_keys.empty()) {
        // The newest log key must be among them; others may be past keys, or
        // a next key held ahead of a rotation.
        const protocol::LedgerState& ledger_state = state->ledger->state();
        const bool newest = std::ranges::any_of(options.log_keys, [&](const auto& key) {
            return key->public_key() == ledger_state.log_key();
        });
        if (!newest) {
            const bool rotated = std::ranges::any_of(options.log_keys, [&](const auto& key) {
                return std::ranges::any_of(ledger_state.log_keys(), [&](const auto& epoch) {
                    return epoch.key == key->public_key();
                });
            });
            return fail(Errc::invalid_argument,
                        rotated ? "the log key was rotated: give the ledger's newest log key "
                                  "(see `cexchain ledger keys`)"
                                : "the log key is not this ledger's");
        }
    }
    state->options = std::move(options);
    if (state->options.registrar) {
        state->calls.emplace(state->options.directory, *state->options.registrar);
    }
    for (const auto& key : state->options.log_keys) {
        state->log_key_ring.push_back(key.get());
    }
    state->reload_tokens(true);
    if (state->options.cluster) {
        State* raw = state.get();
        auto started = Cluster::start(
            state->options.directory, *state->ledger,
            [raw](std::string_view what, std::string_view detail) { raw->event(what, detail); });
        if (!started) {
            return std::unexpected(started.error());
        }
        state->cluster = std::move(*started);
    }
    state->start();
    return std::unique_ptr<LedgerApi>(new LedgerApi(std::move(state)));
}

LedgerApi::LedgerApi(std::unique_ptr<State> state) : state_(std::move(state)) {}

LedgerApi::~LedgerApi() = default;

void LedgerApi::handle(http::Request request, std::string, Respond respond) {
    state_->serve(std::move(request), std::move(respond));
}

void LedgerApi::tick() {
    // Servers sharing this API tick on their own threads: one at a time.
    const std::unique_lock lock(state_->tick_mutex, std::try_to_lock);
    if (!lock) {
        return;
    }
    state_->reload_tokens(false);
    state_->auto_checkpoint();
    state_->keep();
    state_->poll_requests();
}

void LedgerApi::stopping() {
    state_->stop_polls();
}

void LedgerApi::stop() {
    state_->stop_polls();
    state_->drain();
}

bool LedgerApi::is_replica() const noexcept {
    return state_->replica;
}

const ledger::Ledger& LedgerApi::ledger() const noexcept {
    return *state_->ledger;
}

} // namespace cexchain::node
