// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <thread>
#if defined(__GLIBC__)
#include <pthread.h>
#endif
#include <array>
#include <utility>
#include <variant>

#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/parallel.hpp>

namespace cexchain::ledger {

namespace {

/// A reader-writer lock under which a stream of readers cannot starve the
/// writer. std::shared_mutex is glibc's pthread rwlock there, which prefers
/// readers (libc++'s already prefers writers). Readers must not take it
/// twice: a waiting writer would deadlock them.
class SharedMutex {
public:
    SharedMutex(const SharedMutex&) = delete;
    SharedMutex& operator=(const SharedMutex&) = delete;
#if defined(__GLIBC__)
    SharedMutex() noexcept {
        pthread_rwlockattr_t attr;
        pthread_rwlockattr_init(&attr);
        pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
        pthread_rwlock_init(&lock_, &attr);
        pthread_rwlockattr_destroy(&attr);
    }
    ~SharedMutex() { pthread_rwlock_destroy(&lock_); }
    void lock() noexcept { pthread_rwlock_wrlock(&lock_); }
    bool try_lock() noexcept { return pthread_rwlock_trywrlock(&lock_) == 0; }
    void unlock() noexcept { pthread_rwlock_unlock(&lock_); }
    void lock_shared() noexcept { pthread_rwlock_rdlock(&lock_); }
    bool try_lock_shared() noexcept { return pthread_rwlock_tryrdlock(&lock_) == 0; }
    void unlock_shared() noexcept { pthread_rwlock_unlock(&lock_); }

private:
    pthread_rwlock_t lock_{};
#else
    SharedMutex() = default;
    ~SharedMutex() = default;
    void lock() { lock_.lock(); }
    bool try_lock() { return lock_.try_lock(); }
    void unlock() { lock_.unlock(); }
    void lock_shared() { lock_.lock_shared(); }
    bool try_lock_shared() { return lock_.try_lock_shared(); }
    void unlock_shared() { lock_.unlock_shared(); }

private:
    std::shared_mutex lock_;
#endif
};

constexpr std::string_view statements_file = "statements";
/// Paged reads return at most this many items.
constexpr std::uint64_t max_page = 1000;
constexpr std::string_view checkpoints_file = "checkpoints";
constexpr std::string_view cosignatures_file = "cosignatures";
constexpr std::string_view timestamps_file = "timestamps";
/// Two files a snapshot of the state alternates between: the older one is
/// rewritten, so the newer one stays whole meanwhile.
constexpr std::array<std::string_view, 2> snapshot_files{"snapshot-a", "snapshot-b"};

// A snapshot file: a header, the log's leaf hashes, the state (as
// LedgerState::encode writes it), and a seal: the SHA-256 of the SHA-256s of
// its 4 MiB pieces, computed on every core. Not part of the protocol: it
// never leaves its machine.
//   magic (16) | format u32 | rules u32 | ledger id (32) | hash alg i32 |
//   size u64 | root (32) | state root (32) | written at u64 |
//   leaves (size x 32) | state length u64 | state | seal (32)
constexpr std::string_view snapshot_magic("cexchain state\n\0", 16);
constexpr std::uint32_t snapshot_format = 1;
constexpr std::size_t snapshot_header_size = 16 + 4 + 4 + 32 + 4 + 8 + 32 + 32 + 8;
constexpr std::size_t snapshot_seal_piece = std::size_t{4} << 20;

void put_be(Bytes& out, std::uint64_t value, int bytes) {
    for (int shift = (bytes - 1) * 8; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> static_cast<unsigned>(shift)));
    }
}

std::uint64_t take_be(ByteView in, std::size_t at, int bytes) {
    std::uint64_t value = 0;
    for (int i = 0; i < bytes; ++i) {
        value = (value << 8U) | in[at + static_cast<std::size_t>(i)];
    }
    return value;
}

/// The SHA-256 of the SHA-256s of `data`'s 4 MiB pieces: the seal of a
/// snapshot, and the digest of a state, on every core.
Result<crypto::Digest> snapshot_seal(const crypto::Provider& provider, ByteView data) {
    const std::size_t pieces = (data.size() + snapshot_seal_piece - 1) / snapshot_seal_piece;
    Bytes digests(pieces * 32);
    std::atomic<bool> failed{false};
    parallel_for(pieces, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
            const ByteView piece =
                data.subspan(i * snapshot_seal_piece,
                             std::min(snapshot_seal_piece, data.size() - i * snapshot_seal_piece));
            auto d = provider.digest(crypto::HashAlg::sha256, piece);
            if (!d) {
                failed = true;
                continue;
            }
            std::ranges::copy(d->bytes(), digests.begin() + static_cast<std::ptrdiff_t>(i * 32));
        }
    });
    if (failed) {
        return fail(Errc::crypto_failure, "sealing a snapshot failed");
    }
    return provider.digest(crypto::HashAlg::sha256, digests);
}

/// A snapshot read back, checked on its own (seal, format, rules, ledger).
struct SnapshotFile {
    SnapshotInfo info;
    crypto::Digest root;
    crypto::Digest state_root;
    Bytes bytes;
    /// The state's bytes, within `bytes`.
    std::size_t state_at = 0;
    std::size_t state_size = 0;

    [[nodiscard]] ByteView state() const { return ByteView(bytes).subspan(state_at, state_size); }
    /// The log's leaf hash at `index`, below `info.size`.
    [[nodiscard]] crypto::Digest leaf(std::uint64_t index) const {
        return *crypto::Digest::from_bytes(ByteView(bytes).subspan(
            static_cast<std::size_t>(snapshot_header_size + index * 32), 32));
    }
};

Result<SnapshotFile> read_snapshot(const crypto::Provider& provider, const AppendFile& file,
                                   const protocol::Id& ledger_id, crypto::HashAlg hash) {
    const std::uint64_t file_size = file.size();
    if (file_size < snapshot_header_size + 8 + 32) {
        return fail(Errc::not_found, "no snapshot");
    }
    auto bytes = file.read(0, static_cast<std::size_t>(file_size));
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    const ByteView all = *bytes;
    const ByteView body = all.first(all.size() - 32);
    auto seal = snapshot_seal(provider, body);
    if (!seal || !std::ranges::equal(seal->bytes(), all.last(32))) {
        return fail(Errc::verification_failed, "a snapshot is damaged");
    }
    if (!std::ranges::equal(all.first(snapshot_magic.size()), as_bytes(snapshot_magic)) ||
        take_be(all, 16, 4) != snapshot_format ||
        take_be(all, 20, 4) != protocol::state_rules_version ||
        !std::ranges::equal(all.subspan(24, 32), ledger_id.bytes()) ||
        static_cast<std::int32_t>(take_be(all, 56, 4)) != crypto::cose_id(hash)) {
        return fail(Errc::unsupported, "a snapshot of other rules, or of another ledger");
    }
    SnapshotFile out;
    out.info.size = take_be(all, 60, 8);
    out.info.written_at = take_be(all, 132, 8);
    out.info.bytes = file_size;
    out.root = *crypto::Digest::from_bytes(all.subspan(68, 32));
    out.state_root = *crypto::Digest::from_bytes(all.subspan(100, 32));
    if (out.info.size < 2 || out.info.size > (body.size() - snapshot_header_size) / 32) {
        return fail(Errc::malformed, "a snapshot is malformed");
    }
    const std::uint64_t leaves_end = snapshot_header_size + out.info.size * 32;
    if (leaves_end + 8 > body.size()) {
        return fail(Errc::malformed, "a snapshot is malformed");
    }
    out.state_size =
        static_cast<std::size_t>(take_be(all, static_cast<std::size_t>(leaves_end), 8));
    out.state_at = static_cast<std::size_t>(leaves_end + 8);
    if (out.state_at + out.state_size != body.size()) {
        return fail(Errc::malformed, "a snapshot is malformed");
    }
    out.bytes = std::move(*bytes);
    return out;
}

// A stored cosignature: [cosignature (COSE_Sign1), witness public key].
Result<Bytes> encode_stored_cosignature(ByteView cosignature, const crypto::PublicKey& witness) {
    return cbor::encode(cbor::Value::array(
        {cbor::Value::bytes(cosignature), protocol::encode_public_key(witness)}));
}

Result<StoredCosignature> decode_stored_cosignature(ByteView bytes) {
    auto value = cbor::decode(bytes);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Array* parts = value->as_array();
    if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_bytes() == nullptr) {
        return fail(Errc::malformed, "a stored cosignature is malformed");
    }
    auto witness = protocol::decode_public_key((*parts)[1]);
    if (!witness) {
        return std::unexpected(witness.error());
    }
    auto cosignature = protocol::parse_cosignature(*(*parts)[0].as_bytes());
    if (!cosignature) {
        return std::unexpected(cosignature.error());
    }
    return StoredCosignature{*(*parts)[0].as_bytes(), std::move(*cosignature), std::move(*witness)};
}

// A stored time-stamp token (v0.11): [the checkpoint it stamps, token].
Result<Bytes> encode_stored_timestamp(ByteView checkpoint, ByteView token) {
    return cbor::encode(
        cbor::Value::array({cbor::Value::bytes(checkpoint), cbor::Value::bytes(token)}));
}

Result<StoredTimestamp> decode_stored_timestamp(ByteView bytes) {
    auto value = cbor::decode(bytes);
    const cbor::Array* parts = value ? value->as_array() : nullptr;
    if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_bytes() == nullptr ||
        (*parts)[1].as_bytes() == nullptr) {
        return fail(Errc::malformed, "a stored time-stamp token is malformed");
    }
    auto checkpoint = protocol::parse_checkpoint(*(*parts)[0].as_bytes());
    if (!checkpoint) {
        return std::unexpected(checkpoint.error());
    }
    return StoredTimestamp{*(*parts)[1].as_bytes(), std::move(*checkpoint)};
}

} // namespace

struct Ledger::Impl {
    Impl(Clock& clock_, const crypto::Provider& provider_, RecordLog log_, RecordLog checkpoints_,
         RecordLog cosignatures_, RecordLog timestamps_, protocol::LedgerState state_,
         merkle::Tree tree_, protocol::StateTree state_tree_)
        : clock(&clock_), provider(&provider_), log(std::move(log_)),
          checkpoints(std::move(checkpoints_)), cosignatures(std::move(cosignatures_)),
          timestamps(std::move(timestamps_)), state(std::move(state_)), tree(std::move(tree_)),
          state_tree(std::move(state_tree_)) {}

    Clock* clock;
    const crypto::Provider* provider;
    /// Concurrency: any number of threads may read while one thread
    /// writes. `state_mutex` guards the state, the state tree, and the
    /// commitment it reflects; `log_mutex` guards the logs' indexes, the
    /// Merkle tree, and the latest checkpoint. Lock order: state, then log.
    /// The writer holds them exclusively only to change memory, never while
    /// it waits for the disk, and readers only see what is durable: the
    /// Merkle tree's size is the durable watermark.
    mutable SharedMutex state_mutex;
    mutable SharedMutex log_mutex;
    RecordLog log;
    RecordLog checkpoints;
    RecordLog cosignatures;
    RecordLog timestamps;
    protocol::LedgerState state;
    merkle::Tree tree;
    /// The state tree as of the latest state commitment in the log: what
    /// changed after it is staged in `state` until the next one. Updated
    /// incrementally, it gives roots and proofs in O(log n).
    protocol::StateTree state_tree;
    /// That commitment, and its log index.
    std::optional<protocol::StateCommitment> tree_commitment;
    std::uint64_t tree_commitment_index = 0;
    std::optional<protocol::SignedCheckpoint> latest_checkpoint;
    /// The log key in effect for it: receipts against it are signed with
    /// this key (under `log_mutex`, like the checkpoint).
    crypto::PublicKey latest_log_key;
    /// The receipt seal (the log key's one signature) for the latest
    /// checkpoint: receipts against it need no signing of their own.
    struct Seal {
        protocol::Checkpoint checkpoint;
        crypto::PublicKey key;
        protocol::ReceiptSeal seal;
    };
    mutable std::mutex seal_mutex;
    mutable std::shared_ptr<const Seal> seal;
    /// The snapshot files (none for a ledger opened only to read), the
    /// newest that checks and its slot, the one this ledger opened from with
    /// its state's SHA-256, and when to write the next.
    std::array<std::unique_ptr<AppendFile>, 2> snapshot_slots;
    std::optional<SnapshotInfo> snapshot_on_disk;
    std::size_t snapshot_slot = 0;
    std::optional<SnapshotInfo> opened_from;
    Bytes opened_state_digest;
    std::uint64_t snapshot_interval = Ledger::default_snapshot_interval;
    std::uint64_t last_snapshot_size = 0;
    /// (witness, checkpoint) of every stored cosignature, built on first
    /// use: adding one need not read them all again. The writer's only.
    std::optional<std::set<Bytes>> cosigned;
    /// Stored checkpoints checked against the log: a refresh that failed
    /// after reading new ones checks them next time.
    std::uint64_t checked_checkpoints = 0;
    /// The state commitment the latest checkpoint ends with, if it does.
    std::optional<protocol::StateCommitment> checkpoint_commitment;
    /// The state tree moved past the latest commitment for one that is
    /// prepared but not yet in the log: proofs wait for it.
    bool tree_ahead = false;
    protocol::Timestamp last_registered_at = 0;
    /// Set when a write failed after the in-memory views moved ahead of the
    /// files; the ledger must be reopened.
    std::atomic<bool> failed = false;

    // ---- the pipelined commit --------------------------------
    /// A batch validated and applied in memory, waiting to be written.
    struct Commit {
        /// Its new entries, from log index `first`.
        std::vector<Bytes> entries;
        std::uint64_t first = 0;
        std::vector<Result<Registration>> results;
        Durable durable;
    };
    /// The commit thread's queue, and whether it is writing (under
    /// commit_mutex). It writes whatever is queued as one write and sync.
    std::mutex commit_mutex;
    std::condition_variable commit_wake;
    std::condition_variable commit_idle;
    std::deque<Commit> commits;
    bool commit_busy = false;
    bool commit_stop = false;
    /// Batches queued wait for release_commits (or a drain).
    bool commit_hold = false;
    std::thread commit_thread;
    /// The writer's: the log index after the last entry it staged, and the
    /// registration time of each batch in flight, by its first index (for
    /// repeats of statements not durable yet).
    std::uint64_t staged_end = 0;
    /// The commit thread's: the first log index a failed write lost.
    static constexpr std::uint64_t no_failure = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t failed_from = no_failure;
    std::map<std::uint64_t, std::pair<std::uint64_t, protocol::Timestamp>> staged_times;

    /// A batch validated and applied in memory: its new entries (from log
    /// index `first`, at time `now`) and a result per statement. `fatal`:
    /// the state moved partway, the ledger must be reopened.
    struct Staged {
        std::vector<Bytes> entries;
        std::uint64_t first = 0;
        protocol::Timestamp now = 0;
        std::vector<Result<Registration>> results;
        bool fatal = false;
    };
    /// Parses, checks, runs ahead, validates, and applies a batch (the
    /// writer's): see Ledger::submit_batch.
    Staged stage(std::span<const ByteView> signed_statements, std::optional<protocol::Timestamp> at,
                 Offers offers);
    /// When the entry at `index` (not later than this batch's) was
    /// registered: from the log below `durable`, else its batch's time.
    Result<protocol::Timestamp> registration_time(std::uint64_t index, std::uint64_t durable,
                                                  protocol::Timestamp now) const;

    ~Impl() { stop_commits(); }
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    void stop_commits() {
        {
            const std::lock_guard lock(commit_mutex);
            commit_stop = true;
        }
        commit_wake.notify_all();
        if (commit_thread.joinable()) {
            commit_thread.join();
        }
    }

    /// Waits until the commit thread has written (or failed) everything
    /// queued and called back.
    void drain() {
        std::unique_lock lock(commit_mutex);
        if (commit_hold) {
            commit_hold = false;
            commit_wake.notify_all();
        }
        commit_idle.wait(lock, [&] { return commits.empty() && !commit_busy; });
    }

    /// The commit thread: writes every batch queued (in order, one write and
    /// sync for all), makes the entries visible, then calls each back.
    void run_commits() {
        std::unique_lock lock(commit_mutex);
        for (;;) {
            commit_wake.wait(lock,
                             [&] { return commit_stop || (!commits.empty() && !commit_hold); });
            if (commits.empty()) {
                return; // stopping, with nothing left
            }
            std::vector<Commit> work;
            while (!commits.empty()) {
                work.push_back(std::move(commits.front()));
                commits.pop_front();
            }
            commit_busy = true;
            lock.unlock();
            std::vector<ByteView> views;
            for (const Commit& c : work) {
                views.insert(views.end(), c.entries.begin(), c.entries.end());
            }
            Status written;
            if (!views.empty()) {
                if (auto pending = log.write(views)) {
                    const std::unique_lock log_lock(log_mutex);
                    log.publish(*pending);
                    written = append_merkle(views);
                } else {
                    written = std::unexpected(pending.error());
                }
            }
            if (!written) {
                failed = true;
                failed_from = std::min(failed_from, work.front().first);
            }
            for (Commit& c : work) {
                if (failed_from != no_failure) {
                    // Every registration at or after the first entry lost,
                    // repeats of those entries included.
                    for (auto& r : c.results) {
                        if (r && r->index >= failed_from) {
                            r = std::unexpected(
                                written ? Error{Errc::unavailable, "an earlier write failed"}
                                        : written.error());
                        }
                    }
                }
                if (c.durable) {
                    c.durable(std::move(c.results));
                }
            }
            lock.lock();
            commit_busy = false;
            if (commits.empty()) {
                commit_idle.notify_all();
            }
        }
    }

    /// The durable size (the Merkle tree's), which the commit thread moves.
    std::uint64_t durable_size() const {
        const std::shared_lock lock(log_mutex);
        return tree.size();
    }

    /// Checks that `bytes` may be the log entry at `index`, the next one:
    /// registered no earlier than the entry before it, and either a statement
    /// that passes validation at its registration time or a state commitment,
    /// signed by the log key, of exactly the current state.
    /// Brings the state tree up to the current state.
    Result<crypto::Digest> sync_state_tree() {
        auto changed = state.take_changes();
        std::ranges::sort(changed, [](const protocol::Id& a, const protocol::Id& b) {
            return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
        });
        const auto [first, last] = std::ranges::unique(changed);
        changed.erase(first, last);
        for (const protocol::Id& id : changed) {
            const auto leaf = protocol::state_leaf(state, id);
            if (!leaf) {
                return fail(Errc::malformed, "a changed object is missing from the state");
            }
            if (auto s = state_tree.set(*leaf); !s) {
                return std::unexpected(s.error());
            }
        }
        if (auto s = state_tree.commit(); !s) {
            return std::unexpected(s.error());
        }
        return state_tree.root();
    }

    /// What can be worked out about a log entry without the state: decoded,
    /// parsed, and its statement's signature checked with the key its kid
    /// names. Done for many entries at once, in parallel.
    struct Decoded {
        std::optional<protocol::LogEntry> entry;
        std::optional<protocol::SignedStatement> statement;
        std::optional<protocol::SignedStateCommitment> commitment;
        std::optional<Error> error;
        /// The signature checked ahead, with the key its kid named (a copy:
        /// the state's keys change as statements apply).
        std::optional<protocol::SignatureCheck> signature;
    };

    /// Checks signatures in parallel, each with the key its kid names: an
    /// actor's current key, or one that an earlier statement of the same
    /// batch introduces. `checks[i]` gets the key and the outcome; statements
    /// whose kid names no key are left to the sequential check.
    void pre_verify(std::span<const protocol::SignedStatement* const> statements,
                    std::span<std::optional<protocol::SignatureCheck>> checks) const {
        std::map<protocol::IdKey, crypto::PublicKey> introduced;
        for (const protocol::SignedStatement* s : statements) {
            if (s == nullptr) {
                continue;
            }
            const crypto::PublicKey* key = nullptr;
            if (const auto* b = std::get_if<protocol::ActorRegisterBody>(&s->statement.body)) {
                key = &b->key;
            } else if (const auto* r =
                           std::get_if<protocol::ActorRotateKeyBody>(&s->statement.body)) {
                key = &r->key;
            }
            if (key != nullptr) {
                if (auto kid = protocol::key_id(*provider, state.hash(), *key)) {
                    introduced.emplace(protocol::key_of(*kid), *key);
                }
            }
        }
        parallel_for(statements.size(), [&](std::size_t begin, std::size_t end) {
            for (std::size_t i = begin; i < end; ++i) {
                const protocol::SignedStatement* s = statements[i];
                if (s == nullptr) {
                    continue;
                }
                const crypto::PublicKey* key = nullptr;
                if (const auto it = introduced.find(protocol::key_of(s->kid));
                    it != introduced.end()) {
                    key = &it->second;
                } else if (const protocol::ActorState* actor = state.actor_by_kid(s->kid)) {
                    key = &actor->key;
                }
                if (key != nullptr) {
                    checks[i] = protocol::SignatureCheck{
                        *key, protocol::verify_statement(*provider, *s, *key)};
                }
            }
        });
    }

    /// Decodes log entries and pre-verifies their signatures, in parallel.
    std::vector<Decoded> decode(std::span<const ByteView> entries) const {
        std::vector<Decoded> out(entries.size());
        parallel_for(entries.size(), [&](std::size_t begin, std::size_t end) {
            for (std::size_t i = begin; i < end; ++i) {
                auto entry = protocol::decode_log_entry(entries[i]);
                if (!entry) {
                    out[i].error = entry.error();
                    continue;
                }
                if (entry->is_state_commitment()) {
                    if (auto c =
                            protocol::parse_state_commitment(*provider, entry->state_commitment)) {
                        out[i].commitment = std::move(*c);
                    }
                } else if (auto st = protocol::parse_statement(*provider, entry->statement,
                                                               state.hash())) {
                    out[i].statement = std::move(*st);
                } else {
                    out[i].error = st.error();
                    continue;
                }
                out[i].entry = std::move(*entry);
            }
        });
        std::vector<const protocol::SignedStatement*> statements(out.size(), nullptr);
        std::vector<std::optional<protocol::SignatureCheck>> checks(out.size());
        for (std::size_t i = 0; i < out.size(); ++i) {
            if (out[i].statement) {
                statements[i] = &*out[i].statement;
            }
        }
        pre_verify(statements, checks);
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i].signature = std::move(checks[i]);
        }
        return out;
    }

    /// Contract runs made ahead: how many, and how many validation
    /// took (their input was the one built in turn).
    std::atomic<std::uint64_t> runs_ahead{0};
    std::atomic<std::uint64_t> runs_taken{0};

    /// Runs the contract calls among `statements` (null: none) on the state
    /// as it is, each at its `times[i]`, on all cores: their runs are offered
    /// to validation in turn, which takes one only if the input it builds
    /// then is the run's. The state must not change meanwhile: only the
    /// writer changes it, and it is here.
    std::vector<std::optional<protocol::ContractRun>>
    run_ahead(std::span<const protocol::SignedStatement* const> statements,
              std::span<const protocol::Timestamp> times) const {
        std::vector<std::optional<protocol::ContractRun>> runs(statements.size());
        std::vector<std::size_t> calls;
        for (std::size_t i = 0; i < statements.size(); ++i) {
            if (statements[i] != nullptr &&
                std::holds_alternative<protocol::ContractCallBody>(statements[i]->statement.body)) {
                calls.push_back(i);
            }
        }
        if (calls.size() < 2) {
            // Nothing to run alongside: validation runs it, unlocked too.
            return runs;
        }
        parallel_for(
            calls.size(),
            [&](std::size_t begin, std::size_t end) {
                for (std::size_t k = begin; k < end; ++k) {
                    const std::size_t i = calls[k];
                    if (auto run = state.run_contract(*provider, *statements[i], times[i])) {
                        runs[i] = std::move(*run);
                    }
                }
            },
            2);
        return runs;
    }

    /// Validates `statement` at `now`, offering it the run made ahead.
    Status validate_with(const protocol::SignedStatement& statement, protocol::Timestamp now,
                         const protocol::SignatureCheck* checked,
                         std::optional<protocol::ContractRun>& ahead,
                         protocol::Validation& validation) {
        if (ahead) {
            validation.offer(std::move(*ahead));
            ahead.reset();
            runs_ahead.fetch_add(1, std::memory_order_relaxed);
        }
        auto s = state.validate(*provider, statement, now, checked, &validation);
        if (validation.took_offer()) {
            runs_taken.fetch_add(1, std::memory_order_relaxed);
        }
        return s;
    }

    /// Checks that a decoded entry may be the log entry at `index`, the next
    /// one: registered no earlier than the entry before it, and either a
    /// statement that passes validation at its registration time or a state
    /// commitment, signed by the log key, of exactly the current state.
    Status check(const Decoded& d, std::uint64_t index, protocol::Validation& validation,
                 std::optional<protocol::ContractRun>& ahead) {
        if (d.error) {
            return std::unexpected(*d.error);
        }
        const protocol::LogEntry& entry = *d.entry;
        if (entry.registered_at < last_registered_at) {
            return fail(Errc::verification_failed, "log entries go back in time");
        }
        if (entry.is_state_commitment()) {
            auto root = sync_state_tree();
            if (!root) {
                return std::unexpected(root.error());
            }
            if (!d.commitment || d.commitment->id != entry.statement_id ||
                d.commitment->commitment.timestamp != entry.registered_at ||
                !protocol::check_state_commitment(*provider, state, *d.commitment, index, *root)) {
                return fail(Errc::verification_failed,
                            "a state commitment in the log does not match the log");
            }
            return {};
        }
        if (d.statement->id != entry.statement_id) {
            return fail(Errc::verification_failed, "a log entry has the wrong statement id");
        }
        if (auto s = validate_with(*d.statement, entry.registered_at,
                                   d.signature ? &*d.signature : nullptr, ahead, validation);
            !s) {
            return fail(Errc::verification_failed,
                        "a logged statement does not pass validation on replay");
        }
        return {};
    }

    /// Applies a checked entry at `index` to the state. (The Merkle tree
    /// takes it when it is durable: see append_merkle.)
    Status apply(const Decoded& d, std::uint64_t index, protocol::Validation* validation) {
        if (d.statement) {
            if (auto s =
                    state.apply(*provider, *d.statement, index, d.entry->registered_at, validation);
                !s) {
                return s;
            }
        } else {
            // check() synced the state tree to this commitment.
            tree_commitment = d.commitment->commitment;
            tree_commitment_index = index;
            tree_ahead = false;
        }
        last_registered_at = d.entry->registered_at;
        return {};
    }

    /// Adds durable entries to the Merkle tree, which readers take as the
    /// durable size.
    Status append_merkle(std::span<const ByteView> entries) {
        for (const ByteView entry : entries) {
            if (auto s = tree.append(entry); !s) {
                failed = true;
                return std::unexpected(s.error());
            }
        }
        return {};
    }

    struct Replayed {
        std::size_t applied = 0;
        std::optional<Error> error;
        /// The state may have changed partway: the ledger must be reopened.
        bool fatal = false;
    };

    /// Checks and applies entries that follow the log's current end (index
    /// `first`), decoding and verifying them in parallel. Stops at the first
    /// that fails.
    /// Contract calls run ahead together, at most this many at once.
    static constexpr std::size_t run_window = 256;

    /// With `locking`, the caller holds no lock: each change of the state
    /// is made under the exclusive lock, and the checks and contract runs
    /// outside it, alongside readers. Without, the caller holds it.
    Replayed replay(std::span<const ByteView> entries, std::uint64_t first, bool locking) {
        Replayed out;
        const auto decoded = decode(entries);
        auto exclusive = [&] {
            return locking ? std::unique_lock(state_mutex) : std::unique_lock<SharedMutex>();
        };
        // Each contract call runs once: run ahead in parallel a window at a
        // time, check takes the run if its input still holds, and apply
        // takes check's.
        protocol::Validation validation;
        std::vector<const protocol::SignedStatement*> statements(decoded.size(), nullptr);
        std::vector<protocol::Timestamp> times(decoded.size(), 0);
        for (std::size_t i = 0; i < decoded.size(); ++i) {
            if (decoded[i].statement && decoded[i].entry) {
                statements[i] = &*decoded[i].statement;
                times[i] = decoded[i].entry->registered_at;
            }
        }
        for (std::size_t start = 0; start < decoded.size(); start += run_window) {
            const std::size_t end = std::min(decoded.size(), start + run_window);
            auto ahead = run_ahead(std::span(statements).subspan(start, end - start),
                                   std::span(times).subspan(start, end - start));
            for (std::size_t i = start; i < end; ++i) {
                const bool commitment = decoded[i].entry && decoded[i].entry->is_state_commitment();
                Status checked;
                {
                    // A commitment's check brings the state tree up to date.
                    const auto lock = commitment ? exclusive() : std::unique_lock<SharedMutex>();
                    checked = check(decoded[i], first + i, validation, ahead[i - start]);
                }
                if (!checked) {
                    out.error = checked.error();
                    return out;
                }
                const auto lock = exclusive();
                if (auto s = apply(decoded[i], first + i, &validation); !s) {
                    out.error = s.error();
                    out.fatal = true;
                    return out;
                }
                ++out.applied;
            }
        }
        return out;
    }

    /// Replays log entries [from, to) of this ledger's own log, in chunks.
    Replayed replay_log(std::uint64_t from, std::uint64_t to) {
        constexpr std::uint64_t chunk = 4096;
        Replayed total;
        for (std::uint64_t begin = from; begin < to; begin += chunk) {
            const std::uint64_t end = std::min(to, begin + chunk);
            // Straight from the file's mapping where it lends one.
            std::vector<Bytes> scratch(end - begin);
            std::vector<ByteView> views;
            views.reserve(end - begin);
            for (std::uint64_t i = begin; i < end; ++i) {
                auto view = log.view(i, scratch[i - begin]);
                if (!view) {
                    total.error = view.error();
                    return total;
                }
                views.push_back(*view);
            }
            // Open (no readers yet) or refresh (which holds the locks).
            const Replayed part = replay(views, begin, false);
            // These are already durable: the tree takes them at once.
            if (auto s = append_merkle(std::span(views).first(part.applied)); !s) {
                total.error = s.error();
                total.fatal = true;
                return total;
            }
            total.applied += part.applied;
            if (part.error) {
                total.error = part.error;
                total.fatal = part.fatal;
                return total;
            }
        }
        return total;
    }

    /// Makes `checkpoint` the latest, with the state commitment it ends
    /// with if that is the one the state tree holds.
    void adopt_checkpoint(protocol::SignedCheckpoint checkpoint) {
        // Every stored checkpoint up to here has been checked.
        checked_checkpoints = checkpoints.count();
        if (tree_commitment && tree_commitment_index + 1 == checkpoint.checkpoint.tree_size) {
            checkpoint_commitment = tree_commitment;
        } else {
            checkpoint_commitment.reset();
        }
        // The writer adopts checkpoints, so the state is its own to read.
        latest_log_key = state.log_key_for(checkpoint.checkpoint.tree_size);
        latest_checkpoint = std::move(checkpoint);
    }

    /// Checks a signed checkpoint against the log key and this log: for this
    /// ledger, no smaller than the latest, and with the tree's root.
    /// Checks a signed checkpoint on its own: signed by the log key, for
    /// this ledger and hash, and not before the latest. Checkpoints never go
    /// back in size or time, and two of one size and moment must say the
    /// same (so old ones cannot be replayed, or two genuine ones alternated).
    Result<protocol::SignedCheckpoint>
    check_signed_checkpoint(ByteView encoded, const crypto::PublicKey* log_key = nullptr) const {
        auto checkpoint = protocol::parse_checkpoint(encoded);
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        const protocol::Checkpoint& c = checkpoint->checkpoint;
        // The key in effect at its size (spec v0.4).
        const crypto::PublicKey& key =
            log_key != nullptr ? *log_key : state.log_key_for(c.tree_size);
        if (!protocol::verify_checkpoint(*provider, *checkpoint, key)) {
            return fail(Errc::verification_failed, "a checkpoint is not signed by the log key");
        }
        if (c.ledger_id != state.ledger_id() || c.tree_hash != state.hash()) {
            return fail(Errc::verification_failed, "a checkpoint belongs to another ledger");
        }
        if (latest_checkpoint) {
            const protocol::Checkpoint& last = latest_checkpoint->checkpoint;
            if (c.tree_size < last.tree_size || c.timestamp < last.timestamp ||
                (c.tree_size == last.tree_size && c.timestamp == last.timestamp && c != last)) {
                return fail(Errc::verification_failed,
                            "a checkpoint is out of order with the ones before it");
            }
        }
        return checkpoint;
    }

    /// Checks a signed checkpoint against this log as well: it covers no
    /// more than the log holds, with the log's root, and is no older than
    /// the last entry it covers.
    Result<protocol::SignedCheckpoint> check_checkpoint(ByteView encoded) const {
        auto checkpoint = check_signed_checkpoint(encoded);
        if (!checkpoint) {
            return checkpoint;
        }
        const protocol::Checkpoint& c = checkpoint->checkpoint;
        if (c.tree_size > tree.size()) {
            return fail(Errc::verification_failed, "a checkpoint is out of order with the log");
        }
        auto root = tree.root(c.tree_size);
        if (!root) {
            return std::unexpected(root.error());
        }
        if (*root != c.root) {
            return fail(Errc::verification_failed, "a checkpoint disagrees with the log");
        }
        auto last_covered = log.read(c.tree_size - 1);
        auto entry = last_covered
                         ? protocol::decode_log_entry(*last_covered)
                         : Result<protocol::LogEntry>(std::unexpected(last_covered.error()));
        if (!entry) {
            return std::unexpected(entry.error());
        }
        if (c.timestamp < entry->registered_at) {
            return fail(Errc::verification_failed,
                        "a checkpoint is older than the entries it covers");
        }
        return checkpoint;
    }

    /// A ledger's files opened, and its state at genesis, before any replay.
    /// With `to_read`, the logs are opened to read only (a second reader
    /// beside a writer).
    static Result<std::unique_ptr<Impl>> start(FileSystem& fs, Clock& clock,
                                               const crypto::Provider& provider, bool to_read) {
        if (!fs.exists(statements_file)) {
            return fail(Errc::not_found, "no ledger exists here");
        }
        auto open_log = [&](std::string_view name) {
            return to_read ? RecordLog::open_to_read(fs, name) : RecordLog::open(fs, name);
        };
        auto log = open_log(statements_file);
        if (!log) {
            return std::unexpected(log.error());
        }
        if (log->count() == 0) {
            return fail(Errc::malformed, "the ledger log is empty");
        }
        // Genesis defines the ledger's identity and hash.
        auto first_bytes = log->read(0);
        if (!first_bytes) {
            return std::unexpected(first_bytes.error());
        }
        auto first = protocol::decode_log_entry(*first_bytes);
        if (!first) {
            return std::unexpected(first.error());
        }
        auto genesis = protocol::parse_statement(provider, first->statement);
        if (!genesis) {
            return std::unexpected(genesis.error());
        }
        if (genesis->id != first->statement_id) {
            return fail(Errc::malformed, "log entry 0 has the wrong statement id");
        }
        auto state = protocol::LedgerState::from_genesis(provider, *genesis);
        if (!state) {
            return std::unexpected(state.error());
        }
        merkle::Tree tree(provider, state->hash());
        if (auto s = tree.append(*first_bytes); !s) {
            return std::unexpected(s.error());
        }
        auto checkpoints = open_log(checkpoints_file);
        if (!checkpoints) {
            return std::unexpected(checkpoints.error());
        }
        auto cosignatures = open_log(cosignatures_file);
        if (!cosignatures) {
            return std::unexpected(cosignatures.error());
        }
        auto timestamps = open_log(timestamps_file);
        if (!timestamps) {
            return std::unexpected(timestamps.error());
        }
        auto state_tree = protocol::StateTree::create(provider, state->hash());
        if (!state_tree) {
            return std::unexpected(state_tree.error());
        }
        auto impl = std::make_unique<Impl>(
            clock, provider, std::move(*log), std::move(*checkpoints), std::move(*cosignatures),
            std::move(*timestamps), std::move(*state), std::move(tree), std::move(*state_tree));
        impl->last_registered_at = first->registered_at;
        return impl;
    }

    /// Takes the state from the newest snapshot that checks against this
    /// log, before any replay: its first and last leaves are the log's, its
    /// last entry the state commitment, and the trees rebuilt from it have
    /// its roots. Returns the size to replay from, or nothing (the log is
    /// replayed from the start).
    std::optional<std::uint64_t> load_snapshot() {
        std::optional<SnapshotFile> best;
        for (std::size_t slot = 0; slot < snapshot_slots.size(); ++slot) {
            if (!snapshot_slots[slot]) {
                continue;
            }
            auto read =
                read_snapshot(*provider, *snapshot_slots[slot], state.ledger_id(), state.hash());
            if (read && (!best || read->info.size > best->info.size)) {
                best = std::move(*read);
                snapshot_slot = slot;
            }
        }
        if (!best) {
            return std::nullopt;
        }
        snapshot_on_disk = best->info;
        last_snapshot_size = best->info.size;
        if (!take_snapshot(*best)) {
            return std::nullopt;
        }
        return best->info.size;
    }

    bool take_snapshot(const SnapshotFile& file) {
        const std::uint64_t size = file.info.size;
        if (size > log.count()) {
            return false;
        }
        auto entry_at = [&](std::uint64_t index) -> Result<Bytes> {
            return log.read(index);
        };
        auto leaf_of = [&](std::uint64_t index) -> std::optional<crypto::Digest> {
            auto bytes = entry_at(index);
            if (!bytes) {
                return std::nullopt;
            }
            auto leaf = merkle::leaf_hash(*provider, state.hash(), *bytes);
            return leaf ? std::optional(*leaf) : std::nullopt;
        };
        if (leaf_of(0) != file.leaf(0) || leaf_of(size - 1) != file.leaf(size - 1)) {
            return false;
        }
        auto last_bytes = entry_at(size - 1);
        auto last = last_bytes ? protocol::decode_log_entry(*last_bytes)
                               : Result<protocol::LogEntry>(std::unexpected(last_bytes.error()));
        if (!last || !last->is_state_commitment()) {
            return false;
        }
        auto commitment = protocol::parse_state_commitment(*provider, last->state_commitment);
        if (!commitment || commitment->commitment.tree_size != size - 1 ||
            commitment->commitment.state_root != file.state_root) {
            return false;
        }
        // The state, its modules loaded again from the deploys in the log.
        auto decoded =
            protocol::LedgerState::decode(file.state(), [&](std::uint64_t index) -> Result<Bytes> {
                auto bytes = entry_at(index);
                if (!bytes) {
                    return std::unexpected(bytes.error());
                }
                auto entry = protocol::decode_log_entry(*bytes);
                if (!entry) {
                    return std::unexpected(entry.error());
                }
                auto deploy = protocol::parse_statement(*provider, entry->statement, state.hash());
                if (!deploy) {
                    return std::unexpected(deploy.error());
                }
                const auto* body =
                    std::get_if<protocol::ContractDeployBody>(&deploy->statement.body);
                if (body == nullptr) {
                    return fail(Errc::malformed, "a snapshot's contract names no deploy");
                }
                return body->code;
            });
        if (!decoded || decoded->ledger_id() != state.ledger_id() ||
            decoded->hash() != state.hash() || !decoded->take_changes().empty()) {
            return false;
        }
        merkle::Tree rebuilt(*provider, state.hash());
        for (std::uint64_t i = 0; i < size; ++i) {
            if (!rebuilt.append_leaf_hash(file.leaf(i))) {
                return false;
            }
        }
        auto root = rebuilt.root(size);
        if (!root || *root != file.root) {
            return false;
        }
        // The state tree, its leaves hashed on every core.
        auto tree_of_state = protocol::StateTree::create(*provider, state.hash());
        if (!tree_of_state) {
            return false;
        }
        std::vector<protocol::Id> ids;
        auto collect = [&](const auto& objects) {
            for (const auto& [key, object] : objects) {
                ids.push_back(object.id.id());
            }
        };
        collect(decoded->actors());
        collect(decoded->delegations());
        collect(decoded->records());
        collect(decoded->contracts());
        collect(decoded->instances());
        std::vector<std::optional<crypto::Digest>> hashes(ids.size());
        parallel_for(ids.size(), [&](std::size_t begin, std::size_t end) {
            for (std::size_t i = begin; i < end; ++i) {
                if (const auto leaf = protocol::state_leaf(*decoded, ids[i])) {
                    if (auto h = protocol::state_leaf_hash(*provider, state.hash(), *leaf)) {
                        hashes[i] = *h;
                    }
                }
            }
        });
        for (std::size_t i = 0; i < ids.size(); ++i) {
            if (!hashes[i] || !tree_of_state->set_hashed(ids[i], *hashes[i])) {
                return false;
            }
        }
        if (!tree_of_state->commit()) {
            return false;
        }
        auto state_root = tree_of_state->root();
        if (!state_root || *state_root != file.state_root) {
            return false;
        }
        // What the background check compares a replay with: the state as
        // loaded.
        auto state_digest = snapshot_seal(*provider, file.state());
        if (!state_digest) {
            return false;
        }
        state = std::move(*decoded);
        tree = std::move(rebuilt);
        state_tree = std::move(*tree_of_state);
        tree_commitment = commitment->commitment;
        tree_commitment_index = size - 1;
        tree_ahead = false;
        last_registered_at = last->registered_at;
        opened_from = file.info;
        opened_state_digest.assign(state_digest->bytes().begin(), state_digest->bytes().end());
        return true;
    }

    /// Writes a snapshot of the state, if it is the committed one: the last
    /// entry is the state commitment the state tree holds. The writer's.
    Status write_snapshot() {
        if (!snapshot_slots[0] || !snapshot_slots[1]) {
            return fail(Errc::rejected, "this ledger was opened to read only");
        }
        Bytes bytes;
        SnapshotInfo info;
        {
            const std::shared_lock state_lock(state_mutex);
            const std::shared_lock log_lock(log_mutex);
            const std::uint64_t size = tree.size();
            if (!tree_commitment || tree_commitment_index + 1 != size || tree_ahead ||
                log.count() != size) {
                return fail(Errc::rejected, "a snapshot is taken right after a checkpoint, with "
                                            "nothing logged after it");
            }
            auto encoded = state.encode();
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            auto root = tree.root(size);
            if (!root) {
                return std::unexpected(root.error());
            }
            info.size = size;
            info.written_at = clock->now();
            bytes.reserve(snapshot_header_size + static_cast<std::size_t>(size) * 32 + 8 +
                          encoded->size() + 32);
            bytes.insert(bytes.end(), snapshot_magic.begin(), snapshot_magic.end());
            put_be(bytes, snapshot_format, 4);
            put_be(bytes, protocol::state_rules_version, 4);
            bytes.insert(bytes.end(), state.ledger_id().bytes().begin(),
                         state.ledger_id().bytes().end());
            put_be(bytes, static_cast<std::uint32_t>(crypto::cose_id(state.hash())), 4);
            put_be(bytes, size, 8);
            bytes.insert(bytes.end(), root->bytes().begin(), root->bytes().end());
            bytes.insert(bytes.end(), tree_commitment->state_root.bytes().begin(),
                         tree_commitment->state_root.bytes().end());
            put_be(bytes, info.written_at, 8);
            for (std::uint64_t i = 0; i < size; ++i) {
                auto leaf = tree.leaf(i);
                if (!leaf) {
                    return std::unexpected(leaf.error());
                }
                bytes.insert(bytes.end(), leaf->bytes().begin(), leaf->bytes().end());
            }
            put_be(bytes, encoded->size(), 8);
            bytes.insert(bytes.end(), encoded->begin(), encoded->end());
        }
        auto sealed = snapshot_seal(*provider, bytes);
        if (!sealed) {
            return std::unexpected(sealed.error());
        }
        bytes.insert(bytes.end(), sealed->bytes().begin(), sealed->bytes().end());
        info.bytes = bytes.size();
        // The older slot (the other one, after a first write).
        const std::size_t slot = snapshot_on_disk ? 1 - snapshot_slot : 0;
        AppendFile& file = *snapshot_slots[slot];
        if (auto s = file.truncate(0); !s) {
            return s;
        }
        if (auto s = file.append(bytes); !s) {
            return s;
        }
        if (auto s = file.sync(); !s) {
            return s;
        }
        snapshot_on_disk = info;
        snapshot_slot = slot;
        last_snapshot_size = info.size;
        return {};
    }

    /// After a checkpoint: a snapshot, once the log has grown enough since
    /// the last. A cache: failing to write one fails nothing.
    void maybe_snapshot() {
        if (snapshot_interval == 0 || !snapshot_slots[0] ||
            tree.size() < last_snapshot_size + snapshot_interval) {
            return;
        }
        static_cast<void>(write_snapshot());
    }

    Status require_usable() const {
        if (failed.load()) {
            return fail(Errc::invalid_argument, "a write failed earlier; reopen the ledger");
        }
        return {};
    }

    /// Ledger time for the next registration: never earlier than the last.
    protocol::Timestamp next_time() const { return std::max(clock->now(), last_registered_at); }

    /// The key of `keys` that is the log key `needed` (the one in effect for
    /// what is about to be signed).
    Result<const crypto::Signer*> pick_log_key(LogKeys keys,
                                               const crypto::PublicKey& needed) const {
        for (const crypto::Signer* key : keys) {
            if (key != nullptr && key->public_key() == needed) {
                return key;
            }
        }
        for (const protocol::KeyEpoch& epoch : state.log_keys()) {
            const bool given = std::ranges::any_of(keys, [&](const crypto::Signer* key) {
                return key != nullptr && key->public_key() == epoch.key;
            });
            if (given && epoch.key != needed) {
                return fail(Errc::invalid_argument,
                            "the log key given is not the one in effect for what is signed: the "
                            "log key was rotated (see `cexchain ledger keys`)");
            }
        }
        return fail(Errc::invalid_argument, "the signer is not this ledger's log key");
    }
};

Ledger::Ledger(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Ledger::Ledger(Ledger&&) noexcept = default;
Ledger& Ledger::operator=(Ledger&&) noexcept = default;
Ledger::~Ledger() = default;

Result<Ledger> Ledger::create(FileSystem& fs, Clock& clock, const crypto::Provider& provider,
                              ByteView genesis) {
    if (fs.exists(statements_file)) {
        return fail(Errc::rejected, "a ledger already exists here");
    }
    auto parsed = protocol::parse_statement(provider, genesis);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    // Validates the genesis signature and keys before anything is written.
    auto state = protocol::LedgerState::from_genesis(provider, *parsed);
    if (!state) {
        return std::unexpected(state.error());
    }
    auto log = RecordLog::open(fs, statements_file);
    if (!log) {
        return std::unexpected(log.error());
    }
    const protocol::LogEntry first{parsed->id, std::max(clock.now(), parsed->statement.issued_at),
                                   parsed->encoded};
    auto encoded = protocol::encode_log_entry(first);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    if (auto s = log->append(*encoded); !s) {
        return std::unexpected(s.error());
    }
    return open(fs, clock, provider);
}

Result<Ledger> Ledger::open(FileSystem& fs, Clock& clock, const crypto::Provider& provider) {
    return open(fs, clock, provider, OpenOptions{});
}

Result<Ledger> Ledger::open(FileSystem& fs, Clock& clock, const crypto::Provider& provider,
                            const OpenOptions& options) {
    auto started = Impl::start(fs, clock, provider, false);
    if (!started) {
        return std::unexpected(started.error());
    }
    std::unique_ptr<Impl> impl = std::move(*started);
    for (std::size_t slot = 0; slot < snapshot_files.size(); ++slot) {
        auto file = fs.open(snapshot_files[slot]);
        if (!file) {
            return std::unexpected(file.error());
        }
        impl->snapshot_slots[slot] = std::move(*file);
    }
    // The latest signed checkpoint, whose state commitment is checked when
    // the replay reaches its size.
    std::optional<protocol::SignedCheckpoint> latest;
    if (impl->checkpoints.count() > 0) {
        auto bytes = impl->checkpoints.read(impl->checkpoints.count() - 1);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checkpoint = protocol::parse_checkpoint(*bytes);
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        // Its signature is checked after the replay, which learns the log
        // key in effect at its size.
        latest = std::move(*checkpoint);
    }

    // From the newest snapshot that checks, if asked; then every later entry
    // must pass validation against the state before it, at the time it was
    // registered, and every state commitment must match the state (kept in
    // an incremental tree). Signatures are checked on all cores; the state
    // moves in log order.
    std::uint64_t from = 1;
    if (options.use_snapshot) {
        from = impl->load_snapshot().value_or(1);
    }
    if (const auto replayed = impl->replay_log(from, impl->log.count()); replayed.error) {
        if (replayed.error->code == Errc::verification_failed) {
            return fail(Errc::malformed, replayed.error->detail);
        }
        return std::unexpected(*replayed.error);
    }

    // The log must contain everything the latest signed checkpoint attests.
    if (latest) {
        const protocol::Checkpoint& c = latest->checkpoint;
        if (c.ledger_id != impl->state.ledger_id() || c.tree_size > impl->tree.size()) {
            return fail(Errc::malformed, "the log is behind its latest signed checkpoint");
        }
        if (!protocol::verify_checkpoint(provider, *latest, impl->state.log_key_for(c.tree_size))) {
            return fail(Errc::malformed, "the latest checkpoint is not signed by the log key");
        }
        auto root = impl->tree.root(c.tree_size);
        if (!root) {
            return std::unexpected(root.error());
        }
        if (*root != c.root) {
            return fail(Errc::malformed, "the log disagrees with its latest signed checkpoint");
        }
        impl->adopt_checkpoint(std::move(*latest));
    }
    return Ledger(std::move(impl));
}

Status Ledger::write_snapshot() {
    impl_->drain(); // pipelined batches first
    if (auto s = impl_->require_usable(); !s) {
        return s;
    }
    return impl_->write_snapshot();
}

std::optional<SnapshotInfo> Ledger::snapshot() const {
    return impl_->snapshot_on_disk;
}

std::optional<SnapshotInfo> Ledger::opened_from_snapshot() const {
    return impl_->opened_from;
}

Status Ledger::remove_snapshots() {
    impl_->drain();
    for (auto& file : impl_->snapshot_slots) {
        if (file) {
            if (auto s = file->truncate(0); !s) {
                return s;
            }
        }
    }
    impl_->snapshot_on_disk.reset();
    impl_->last_snapshot_size = 0;
    return {};
}

void Ledger::set_snapshot_interval(std::uint64_t entries) noexcept {
    impl_->snapshot_interval = entries;
}

Status Ledger::verify_snapshot(FileSystem& fs, const std::atomic<bool>* stop) const {
    if (!impl_->opened_from) {
        return {};
    }
    const std::uint64_t size = impl_->opened_from->size;
    auto fresh = Impl::start(fs, *impl_->clock, *impl_->provider, true);
    if (!fresh) {
        return std::unexpected(fresh.error());
    }
    constexpr std::uint64_t chunk = 65'536;
    for (std::uint64_t begin = 1; begin < size; begin += chunk) {
        if (stop != nullptr && stop->load()) {
            return fail(Errc::unavailable, "stopped");
        }
        if (const auto replayed = (*fresh)->replay_log(begin, std::min(size, begin + chunk));
            replayed.error) {
            return fail(Errc::verification_failed, replayed.error->detail);
        }
    }
    auto fresh_root = (*fresh)->tree.root(size);
    auto encoded = (*fresh)->state.encode();
    if (!fresh_root || !encoded) {
        return fail(Errc::verification_failed, "the log does not replay to the snapshot's size");
    }
    auto digest = snapshot_seal(*impl_->provider, *encoded);
    Result<crypto::Digest> root = std::unexpected(Error{});
    {
        const std::shared_lock lock(impl_->log_mutex);
        root = impl_->tree.root(size);
    }
    if (!digest || !root || *fresh_root != *root ||
        !std::ranges::equal(digest->bytes(), impl_->opened_state_digest)) {
        return fail(Errc::verification_failed,
                    "the snapshot disagrees with a replay of the log (remove it, and reopen)");
    }
    return {};
}

Result<Ledger> Ledger::create_replica(FileSystem& fs, Clock& clock,
                                      const crypto::Provider& provider, ByteView genesis_entry) {
    if (fs.exists(statements_file)) {
        return fail(Errc::rejected, "a ledger already exists here");
    }
    auto first = protocol::decode_log_entry(genesis_entry);
    if (!first) {
        return std::unexpected(first.error());
    }
    if (first->is_state_commitment()) {
        return fail(Errc::verification_failed, "a ledger begins with its genesis statement");
    }
    auto genesis = protocol::parse_statement(provider, first->statement);
    if (!genesis || genesis->id != first->statement_id ||
        !protocol::LedgerState::from_genesis(provider, *genesis)) {
        return fail(Errc::verification_failed, "the first entry is not a valid genesis");
    }
    // Kept byte for byte: the ledger's identity and tree commit to it.
    auto canonical = protocol::encode_log_entry(*first);
    if (!canonical || *canonical != Bytes(genesis_entry.begin(), genesis_entry.end())) {
        return fail(Errc::non_canonical, "the first entry is not in canonical form");
    }
    auto log = RecordLog::open(fs, statements_file);
    if (!log) {
        return std::unexpected(log.error());
    }
    if (auto s = log->append(genesis_entry); !s) {
        return std::unexpected(s.error());
    }
    return open(fs, clock, provider);
}

const protocol::LedgerState& Ledger::state() const noexcept {
    return impl_->state;
}

const protocol::Id& Ledger::id() const noexcept {
    return impl_->state.ledger_id(); // fixed at genesis
}

crypto::HashAlg Ledger::hash() const noexcept {
    return impl_->state.hash(); // fixed at genesis
}

const crypto::Provider& Ledger::provider() const noexcept {
    return *impl_->provider;
}

bool Ledger::usable() const noexcept {
    return !impl_->failed.load();
}

std::uint64_t Ledger::size() const noexcept {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->tree.size();
}

Ledger::RunsAhead Ledger::runs_ahead() const noexcept {
    return {impl_->runs_ahead.load(std::memory_order_relaxed),
            impl_->runs_taken.load(std::memory_order_relaxed)};
}

std::optional<std::uint64_t> Ledger::statement_index(const protocol::Id& id) const {
    const std::shared_lock state(impl_->state_mutex);
    const std::shared_lock log(impl_->log_mutex);
    const auto index = impl_->state.statement_index(id);
    // Not until it is durable.
    return index && *index < impl_->tree.size() ? index : std::nullopt;
}

void Ledger::read_state(const std::function<void(const protocol::LedgerState&)>& read) const {
    const std::shared_lock lock(impl_->state_mutex);
    read(impl_->state);
}

Result<Registration> Ledger::submit(ByteView signed_statement) {
    return std::move(submit_batch(std::span(&signed_statement, 1)).front());
}

Ledger::Impl::Staged Ledger::Impl::stage(std::span<const ByteView> signed_statements,
                                         std::optional<protocol::Timestamp> at, Offers offers) {
    const std::size_t n = signed_statements.size();
    Staged out;
    out.results.reserve(n);
    // Parse and check signatures on all cores. (Only this thread changes the
    // state, so reading it here needs no lock.)
    std::vector<std::optional<protocol::SignedStatement>> parsed(n);
    std::vector<std::optional<Error>> errors(n);
    parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
            if (auto st =
                    protocol::parse_statement(*provider, signed_statements[i], state.hash())) {
                parsed[i] = std::move(*st);
            } else {
                errors[i] = st.error();
            }
        }
    });
    std::vector<const protocol::SignedStatement*> pointers(n, nullptr);
    for (std::size_t i = 0; i < n; ++i) {
        if (parsed[i]) {
            pointers[i] = &*parsed[i];
        }
    }
    std::vector<std::optional<protocol::SignatureCheck>> checks(n);
    pre_verify(pointers, checks);

    // Validate and apply in order, each statement against the state the ones
    // before it left. The contract calls run first, on all cores, on the
    // state before the batch; each run counts only if the input built in
    // turn is the run's (else the call runs again). Only this thread changes
    // the state, so it reads it unlocked; it locks it only to change it.
    // Batches still syncing (pipelined) come first in the log.
    out.now = at ? std::max(*at, last_registered_at) : next_time();
    const std::uint64_t durable = durable_size();
    out.first = std::max(staged_end, durable);
    std::erase_if(staged_times, [&](const auto& t) { return t.second.first <= durable; });
    // The calls the caller ran ahead itself are not run again here.
    offers.resize(n);
    std::vector<const protocol::SignedStatement*> to_run = pointers;
    for (std::size_t i = 0; i < n; ++i) {
        if (offers[i]) {
            to_run[i] = nullptr;
        }
    }
    const std::vector<protocol::Timestamp> times(n, out.now);
    auto ahead = run_ahead(to_run, times);
    for (std::size_t i = 0; i < n; ++i) {
        if (offers[i]) {
            ahead[i] = std::move(offers[i]);
        }
    }
    // Each contract call runs once: apply takes validate's run.
    protocol::Validation validation;
    for (std::size_t i = 0; i < n; ++i) {
        if (errors[i]) {
            out.results.emplace_back(std::unexpected(*errors[i]));
            continue;
        }
        const protocol::SignedStatement& statement = *parsed[i];
        if (const auto index = state.statement_index(statement.id)) {
            // Already registered: before this batch, or earlier in it.
            out.results.emplace_back(registration_time(*index, durable, out.now)
                                         .transform([&](protocol::Timestamp registered) {
                                             return Registration{statement.id, *index, registered,
                                                                 false};
                                         }));
            continue;
        }
        if (auto s = validate_with(statement, out.now, checks[i] ? &*checks[i] : nullptr, ahead[i],
                                   validation);
            !s) {
            out.results.emplace_back(std::unexpected(s.error()));
            continue;
        }
        auto encoded = protocol::encode_log_entry({statement.id, out.now, statement.encoded});
        if (!encoded) {
            out.results.emplace_back(std::unexpected(encoded.error()));
            continue;
        }
        const std::uint64_t index = out.first + out.entries.size();
        Status applied;
        {
            const std::unique_lock lock(state_mutex);
            applied = state.apply(*provider, statement, index, out.now, &validation);
        }
        if (!applied) {
            // The state moved partway: nothing of this batch may be
            // written, and the ledger must be reopened.
            failed = true;
            out.fatal = true;
            out.entries.clear();
            out.results.emplace_back(std::unexpected(applied.error()));
            for (auto& r : out.results) {
                if (r && r->index >= out.first) {
                    r = std::unexpected(applied.error());
                }
            }
            while (out.results.size() < n) {
                out.results.emplace_back(std::unexpected(applied.error()));
            }
            return out;
        }
        out.entries.push_back(std::move(*encoded));
        out.results.emplace_back(Registration{statement.id, index, out.now, true});
    }
    if (!out.entries.empty()) {
        staged_end = out.first + out.entries.size();
        staged_times[out.first] = {staged_end, out.now};
        last_registered_at = out.now;
    }
    return out;
}

Result<protocol::Timestamp> Ledger::Impl::registration_time(std::uint64_t index,
                                                            std::uint64_t durable,
                                                            protocol::Timestamp now) const {
    if (index < durable) {
        const std::shared_lock lock(log_mutex);
        auto bytes = log.read(index);
        auto entry = bytes ? protocol::decode_log_entry(*bytes)
                           : Result<protocol::LogEntry>(std::unexpected(bytes.error()));
        if (!entry) {
            return std::unexpected(entry.error());
        }
        return entry->registered_at;
    }
    // In a batch still syncing, or in this one.
    if (auto it = staged_times.upper_bound(index); it != staged_times.begin()) {
        --it;
        if (index < it->second.first) {
            return it->second.second;
        }
    }
    return now;
}

std::vector<Result<Registration>> Ledger::submit_batch(std::span<const ByteView> signed_statements,
                                                       std::optional<protocol::Timestamp> at,
                                                       Offers offers) {
    impl_->drain();
    if (auto s = impl_->require_usable(); !s) {
        return std::vector<Result<Registration>>(signed_statements.size(),
                                                 std::unexpected(s.error()));
    }
    Impl::Staged staged = impl_->stage(signed_statements, at, std::move(offers));
    if (staged.entries.empty()) {
        return std::move(staged.results);
    }
    // One sync for the batch, with no lock held: readers carry on, and see
    // the entries once they are durable. If the files cannot catch up with
    // the state, the ledger must be reopened.
    const std::vector<ByteView> views(staged.entries.begin(), staged.entries.end());
    Status written;
    if (auto pending = impl_->log.write(views)) {
        const std::unique_lock lock(impl_->log_mutex);
        impl_->log.publish(*pending);
        written = impl_->append_merkle(views);
    } else {
        written = std::unexpected(pending.error());
    }
    if (!written) {
        impl_->failed = true;
        // Every registration in this batch, including a repeat of one made
        // earlier in it.
        for (auto& r : staged.results) {
            if (r && r->index >= staged.first) {
                r = std::unexpected(written.error());
            }
        }
    }
    return std::move(staged.results);
}

void Ledger::submit_batch_pipelined(std::span<const ByteView> signed_statements, Durable durable,
                                    std::optional<protocol::Timestamp> at, Offers offers) {
    Impl::Commit commit;
    commit.durable = std::move(durable);
    if (auto s = impl_->require_usable(); !s) {
        commit.results.assign(signed_statements.size(), std::unexpected(s.error()));
    } else {
        Impl::Staged staged = impl_->stage(signed_statements, at, std::move(offers));
        commit.entries = std::move(staged.entries);
        commit.first = staged.first;
        commit.results = std::move(staged.results);
    }
    {
        const std::lock_guard lock(impl_->commit_mutex);
        if (!impl_->commit_thread.joinable()) {
            impl_->commit_thread = std::thread([impl = impl_.get()] { impl->run_commits(); });
        }
        impl_->commits.push_back(std::move(commit));
    }
    impl_->commit_wake.notify_one();
}

void Ledger::wait_durable() {
    impl_->drain();
}

void Ledger::hold_commits() {
    const std::lock_guard lock(impl_->commit_mutex);
    impl_->commit_hold = true;
}

void Ledger::release_commits() {
    {
        const std::lock_guard lock(impl_->commit_mutex);
        impl_->commit_hold = false;
    }
    impl_->commit_wake.notify_all();
}

Status Ledger::append_entries(std::span<const Bytes> entries) {
    impl_->drain(); // pipelined batches first
    if (auto s = impl_->require_usable(); !s) {
        return s;
    }
    // Check and apply in memory (signatures and contract runs on all cores,
    // the state locked only to change it), then write the valid prefix at
    // once: one sync. Entries before a bad one are kept.
    const std::vector<ByteView> views(entries.begin(), entries.end());
    const Impl::Replayed replayed = impl_->replay(views, impl_->tree.size(), true);
    if (replayed.fatal) {
        impl_->failed = true;
        return std::unexpected(*replayed.error);
    }
    if (replayed.applied > 0) {
        const auto applied = std::span(views).first(replayed.applied);
        auto pending = impl_->log.write(applied);
        if (!pending) {
            impl_->failed = true;
            return std::unexpected(pending.error());
        }
        const std::unique_lock lock(impl_->log_mutex);
        impl_->log.publish(*pending);
        if (auto s = impl_->append_merkle(applied); !s) {
            return s;
        }
    }
    if (replayed.error) {
        return std::unexpected(*replayed.error);
    }
    return {};
}

Status Ledger::store_checkpoint(ByteView encoded) {
    auto stored = store_checkpoint_now(encoded);
    if (stored) {
        impl_->maybe_snapshot();
    }
    return stored;
}

Status Ledger::store_checkpoint_now(ByteView encoded) {
    impl_->drain(); // pipelined batches first
    if (auto s = impl_->require_usable(); !s) {
        return s;
    }
    auto checkpoint = impl_->check_checkpoint(encoded);
    if (!checkpoint) {
        return std::unexpected(checkpoint.error());
    }
    if (impl_->latest_checkpoint && impl_->latest_checkpoint->encoded == checkpoint->encoded) {
        return {};
    }
    auto pending = impl_->checkpoints.write(std::span(&encoded, 1));
    if (!pending) {
        return std::unexpected(pending.error());
    }
    const std::unique_lock lock(impl_->log_mutex);
    impl_->checkpoints.publish(*pending);
    impl_->adopt_checkpoint(std::move(*checkpoint));
    return {};
}

Result<RefreshReport> Ledger::refresh(FileSystem& fs, bool recover) {
    impl_->drain(); // pipelined batches first
    if (auto s = impl_->require_usable(); !s) {
        return std::unexpected(s.error());
    }
    // Rare (another process wrote): readers wait while it catches up.
    const std::unique_lock state_lock(impl_->state_mutex);
    const std::unique_lock log_lock(impl_->log_mutex);
    RefreshReport report;
    // Checkpoints and cosignatures first, then the log: a checkpoint is
    // written only once the entries it covers are durable, so everything
    // picked up here is covered by the log read after it. (The other order
    // races a writer, and a checkpoint would seem to run ahead of the log.)
    if (auto s = impl_->checkpoints.refresh(fs, checkpoints_file, recover); !s) {
        return std::unexpected(s.error());
    }
    auto cosignatures = impl_->cosignatures.refresh(fs, cosignatures_file, recover);
    if (!cosignatures) {
        return std::unexpected(cosignatures.error());
    }
    report.cosignatures = *cosignatures;
    if (*cosignatures > 0) {
        impl_->cosigned.reset();
    }
    auto timestamps = impl_->timestamps.refresh(fs, timestamps_file, recover);
    if (!timestamps) {
        return std::unexpected(timestamps.error());
    }
    report.timestamps = *timestamps;
    const std::uint64_t old_size = impl_->log.count();
    auto added = impl_->log.refresh(fs, statements_file, recover);
    if (!added) {
        return std::unexpected(added.error());
    }
    const auto replayed = impl_->replay_log(old_size, impl_->log.count());
    report.entries = replayed.applied;
    if (replayed.error) {
        // Another process wrote an entry that does not validate.
        impl_->failed = true;
        return fail(Errc::malformed, replayed.error->detail);
    }
    for (std::uint64_t i = impl_->checked_checkpoints; i < impl_->checkpoints.count(); ++i) {
        auto bytes = impl_->checkpoints.read(i);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checkpoint = impl_->check_checkpoint(*bytes);
        if (!checkpoint) {
            impl_->failed = true;
            return fail(Errc::malformed, checkpoint.error().detail);
        }
        impl_->adopt_checkpoint(std::move(*checkpoint));
        ++report.checkpoints;
    }
    return report;
}

merkle::CompactRange Ledger::compact_range() const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->tree.compact_range();
}

Result<protocol::SignedCheckpoint>
Ledger::verify_checkpoint(ByteView signed_checkpoint, const crypto::PublicKey* log_key) const {
    const std::shared_lock state(impl_->state_mutex);
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->check_signed_checkpoint(signed_checkpoint, log_key);
}

protocol::LedgerKeys Ledger::keys() const {
    const std::shared_lock lock(impl_->state_mutex);
    return impl_->state.keys();
}

bool Ledger::outdated() const {
    // A refresh swaps the logs' file handles under this lock.
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->log.outdated() || impl_->checkpoints.outdated() ||
           impl_->cosignatures.outdated() || impl_->timestamps.outdated();
}

Result<Bytes> Ledger::entry(std::uint64_t index) const {
    const std::shared_lock lock(impl_->log_mutex);
    if (index >= impl_->tree.size()) {
        return fail(Errc::invalid_argument, "record index is out of range");
    }
    return impl_->log.read(index);
}

Status Ledger::visit_entry(std::uint64_t index, const std::function<void(ByteView)>& visit) const {
    const std::shared_lock lock(impl_->log_mutex);
    if (index >= impl_->tree.size()) {
        return fail(Errc::invalid_argument, "record index is out of range");
    }
    Bytes scratch;
    auto view = impl_->log.view(index, scratch);
    if (!view) {
        return std::unexpected(view.error());
    }
    visit(*view);
    return {};
}

Result<crypto::Digest> Ledger::root(std::uint64_t tree_size) const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->tree.root(tree_size);
}

Result<std::vector<crypto::Digest>> Ledger::inclusion_proof(std::uint64_t index,
                                                            std::uint64_t tree_size) const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->tree.inclusion_proof(index, tree_size);
}

Result<std::vector<crypto::Digest>> Ledger::consistency_proof(std::uint64_t old_size,
                                                              std::uint64_t new_size) const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->tree.consistency_proof(old_size, new_size);
}

namespace {

Result<std::vector<protocol::SignedCheckpoint>>
read_checkpoints(const RecordLog& log, std::uint64_t begin = 0,
                 std::uint64_t end = std::numeric_limits<std::uint64_t>::max()) {
    std::vector<protocol::SignedCheckpoint> out;
    for (std::uint64_t i = begin; i < std::min(end, log.count()); ++i) {
        auto bytes = log.read(i);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checkpoint = protocol::parse_checkpoint(*bytes);
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        out.push_back(std::move(*checkpoint));
    }
    return out;
}

Result<std::vector<StoredCosignature>>
read_cosignatures(const RecordLog& log, std::uint64_t begin = 0,
                  std::uint64_t end = std::numeric_limits<std::uint64_t>::max()) {
    std::vector<StoredCosignature> out;
    for (std::uint64_t i = begin; i < std::min(end, log.count()); ++i) {
        auto bytes = log.read(i);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto stored = decode_stored_cosignature(*bytes);
        if (!stored) {
            return std::unexpected(stored.error());
        }
        out.push_back(std::move(*stored));
    }
    return out;
}

Result<std::vector<StoredTimestamp>>
read_timestamps(const RecordLog& log, std::uint64_t begin = 0,
                std::uint64_t end = std::numeric_limits<std::uint64_t>::max()) {
    std::vector<StoredTimestamp> out;
    for (std::uint64_t i = begin; i < std::min(end, log.count()); ++i) {
        auto bytes = log.read(i);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto stored = decode_stored_timestamp(*bytes);
        if (!stored) {
            return std::unexpected(stored.error());
        }
        out.push_back(std::move(*stored));
    }
    return out;
}

/// Reads `token` and checks it against `checkpoint`: it verifies with its
/// signing certificate, its imprint is the ledger's hash of the checkpoint's
/// payload, and the ledger's clock agrees with the authority's (neither the
/// checkpoint nor `last_registered_at`, the last entry it covers, is dated
/// more than the slack after the authority's time).
Result<crypto::TimestampToken> check_timestamp(const crypto::Provider& provider,
                                               crypto::HashAlg hash, ByteView token,
                                               const protocol::SignedCheckpoint& checkpoint,
                                               protocol::Timestamp last_registered_at) {
    auto read = provider.read_timestamp(token, {});
    if (!read) {
        return std::unexpected(read.error());
    }
    if (!checkpoint.envelope.payload) {
        return fail(Errc::malformed, "the checkpoint has no payload");
    }
    auto digest = provider.digest(hash, *checkpoint.envelope.payload);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    if (read->imprint_alg != hash || !std::ranges::equal(read->imprint, digest->bytes())) {
        return fail(Errc::verification_failed, "the token does not stamp this checkpoint");
    }
    const protocol::Timestamp bound = read->time + read->accuracy + protocol::timestamp_clock_slack;
    if (checkpoint.checkpoint.timestamp > bound || last_registered_at > bound) {
        return fail(Errc::rejected, "the ledger dates the checkpoint after the authority's time "
                                    "(its clock runs ahead): evidence with this token would fail");
    }
    return read;
}

} // namespace

Result<std::vector<protocol::SignedCheckpoint>> Ledger::checkpoints() const {
    const std::shared_lock lock(impl_->log_mutex);
    return read_checkpoints(impl_->checkpoints);
}

std::uint64_t Ledger::checkpoint_count() const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->checkpoints.count();
}

Result<std::vector<protocol::SignedCheckpoint>> Ledger::checkpoints(std::uint64_t start,
                                                                    std::uint64_t count) const {
    const std::shared_lock lock(impl_->log_mutex);
    return read_checkpoints(impl_->checkpoints, start, start + std::min(count, max_page));
}

namespace {

/// The first stored checkpoint whose size is at least `size` (checkpoints
/// are stored in order of size): O(log n) reads, not n.
Result<std::uint64_t> first_checkpoint_at_least(const RecordLog& log, std::uint64_t size) {
    std::uint64_t low = 0;
    std::uint64_t high = log.count();
    while (low < high) {
        const std::uint64_t mid = low + (high - low) / 2;
        auto bytes = log.read(mid);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checkpoint = protocol::parse_checkpoint(*bytes);
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        if (checkpoint->checkpoint.tree_size < size) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    return low;
}

} // namespace

Result<std::vector<protocol::SignedCheckpoint>>
Ledger::checkpoints_of_size(std::uint64_t size) const {
    const std::shared_lock lock(impl_->log_mutex);
    auto first = first_checkpoint_at_least(impl_->checkpoints, size);
    if (!first) {
        return std::unexpected(first.error());
    }
    std::vector<protocol::SignedCheckpoint> out;
    for (std::uint64_t i = *first; i < impl_->checkpoints.count() && out.size() < max_page; ++i) {
        auto bytes = impl_->checkpoints.read(i);
        auto checkpoint = bytes
                              ? protocol::parse_checkpoint(*bytes)
                              : Result<protocol::SignedCheckpoint>(std::unexpected(bytes.error()));
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        if (checkpoint->checkpoint.tree_size != size) {
            break;
        }
        out.push_back(std::move(*checkpoint));
    }
    return out;
}

std::uint64_t Ledger::cosignature_count() const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->cosignatures.count();
}

Result<std::vector<StoredCosignature>> Ledger::cosignatures(std::uint64_t start,
                                                            std::uint64_t count) const {
    const std::shared_lock lock(impl_->log_mutex);
    return read_cosignatures(impl_->cosignatures, start, start + std::min(count, max_page));
}

Status Ledger::add_cosignature(ByteView encoded, const crypto::PublicKey& witness) {
    impl_->drain(); // pipelined batches first
    if (std::ranges::any_of(impl_->state.log_keys(),
                            [&](const protocol::KeyEpoch& e) { return e.key == witness; })) {
        return fail(Errc::rejected, "the log key cannot witness its own checkpoints");
    }
    auto cosignature = protocol::parse_cosignature(encoded);
    if (!cosignature) {
        return std::unexpected(cosignature.error());
    }
    if (!protocol::verify_cosignature(*impl_->provider, *cosignature, witness)) {
        return fail(Errc::verification_failed, "the cosignature is not by this witness's key");
    }
    // Only this thread changes the logs: reading them needs no lock.
    auto same_size = [&]() -> Result<bool> {
        auto first =
            first_checkpoint_at_least(impl_->checkpoints, cosignature->checkpoint.tree_size);
        if (!first) {
            return std::unexpected(first.error());
        }
        for (std::uint64_t i = *first; i < impl_->checkpoints.count(); ++i) {
            auto bytes = impl_->checkpoints.read(i);
            auto c = bytes ? protocol::parse_checkpoint(*bytes)
                           : Result<protocol::SignedCheckpoint>(std::unexpected(bytes.error()));
            if (!c) {
                return std::unexpected(c.error());
            }
            if (c->checkpoint.tree_size != cosignature->checkpoint.tree_size) {
                break;
            }
            if (c->checkpoint == cosignature->checkpoint) {
                return true;
            }
        }
        return false;
    }();
    if (!same_size) {
        return std::unexpected(same_size.error());
    }
    if (!*same_size) {
        return fail(Errc::not_found, "the cosignature is not of a checkpoint of this ledger");
    }
    auto key_of = [](const crypto::PublicKey& w, const protocol::Checkpoint& c) {
        Bytes key = w.bytes;
        key.push_back(static_cast<std::uint8_t>(crypto::cose_id(w.algorithm)));
        auto payload = protocol::encode_checkpoint(c);
        if (payload) {
            key.insert(key.end(), payload->begin(), payload->end());
        }
        return key;
    };
    if (!impl_->cosigned) {
        auto stored = read_cosignatures(impl_->cosignatures);
        if (!stored) {
            return std::unexpected(stored.error());
        }
        impl_->cosigned.emplace();
        for (const StoredCosignature& s : *stored) {
            impl_->cosigned->insert(key_of(s.witness, s.cosignature.checkpoint));
        }
    }
    const Bytes key = key_of(witness, cosignature->checkpoint);
    if (impl_->cosigned->contains(key)) {
        return {};
    }
    auto record = encode_stored_cosignature(encoded, witness);
    if (!record) {
        return std::unexpected(record.error());
    }
    const ByteView view = *record;
    auto pending = impl_->cosignatures.write(std::span(&view, 1));
    if (!pending) {
        return std::unexpected(pending.error());
    }
    const std::unique_lock lock(impl_->log_mutex);
    impl_->cosignatures.publish(*pending);
    impl_->cosigned->insert(key);
    return {};
}

Result<std::vector<StoredCosignature>> Ledger::cosignatures() const {
    const std::shared_lock lock(impl_->log_mutex);
    return read_cosignatures(impl_->cosignatures);
}

namespace {

/// The registration time of the last entry a tree of `size` entries holds.
Result<protocol::Timestamp> last_registered_at(const RecordLog& log, std::uint64_t size) {
    auto bytes = log.read(size - 1);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    auto entry = protocol::decode_log_entry(*bytes);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    return entry->registered_at;
}

} // namespace

Status Ledger::add_timestamp(ByteView token, std::uint64_t size) {
    impl_->drain(); // pipelined batches first
    auto read = impl_->provider->read_timestamp(token, {});
    if (!read) {
        return std::unexpected(read.error());
    }
    if (read->imprint_alg != hash()) {
        return fail(Errc::verification_failed,
                    "the token's imprint is not under the ledger's hash");
    }
    // The checkpoint of that size it stamps. Only this thread changes the
    // logs: reading them needs no lock.
    auto first = first_checkpoint_at_least(impl_->checkpoints, size);
    if (!first) {
        return std::unexpected(first.error());
    }
    std::optional<protocol::SignedCheckpoint> stamped;
    for (std::uint64_t i = *first; i < impl_->checkpoints.count() && !stamped; ++i) {
        auto bytes = impl_->checkpoints.read(i);
        auto checkpoint = bytes
                              ? protocol::parse_checkpoint(*bytes)
                              : Result<protocol::SignedCheckpoint>(std::unexpected(bytes.error()));
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        if (checkpoint->checkpoint.tree_size != size) {
            break;
        }
        if (!checkpoint->envelope.payload) {
            continue;
        }
        auto digest = impl_->provider->digest(hash(), *checkpoint->envelope.payload);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        if (std::ranges::equal(digest->bytes(), read->imprint)) {
            stamped = std::move(*checkpoint);
        }
    }
    if (!stamped) {
        return fail(Errc::not_found, "the token stamps no stored checkpoint of this size");
    }
    auto registered_at = last_registered_at(impl_->log, size);
    if (!registered_at) {
        return std::unexpected(registered_at.error());
    }
    if (auto checked = check_timestamp(*impl_->provider, hash(), token, *stamped, *registered_at);
        !checked) {
        return std::unexpected(checked.error());
    }
    auto stored = read_timestamps(impl_->timestamps);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    if (std::ranges::any_of(*stored, [&](const StoredTimestamp& t) {
            return std::ranges::equal(t.token, token);
        })) {
        return {};
    }
    auto record = encode_stored_timestamp(stamped->encoded, token);
    if (!record) {
        return std::unexpected(record.error());
    }
    const ByteView view = *record;
    auto pending = impl_->timestamps.write(std::span(&view, 1));
    if (!pending) {
        return std::unexpected(pending.error());
    }
    const std::unique_lock lock(impl_->log_mutex);
    impl_->timestamps.publish(*pending);
    return {};
}

Result<std::vector<StoredTimestamp>> Ledger::timestamps() const {
    const std::shared_lock lock(impl_->log_mutex);
    return read_timestamps(impl_->timestamps);
}

std::uint64_t Ledger::timestamp_count() const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->timestamps.count();
}

Result<std::vector<StoredTimestamp>> Ledger::timestamps(std::uint64_t start,
                                                        std::uint64_t count) const {
    const std::shared_lock lock(impl_->log_mutex);
    return read_timestamps(impl_->timestamps, start, start + std::min(count, max_page));
}

Result<std::optional<protocol::Checkpoint>>
Ledger::last_cosigned(const crypto::PublicKey& witness) const {
    auto stored = cosignatures();
    if (!stored) {
        return std::unexpected(stored.error());
    }
    std::optional<protocol::Checkpoint> newest;
    for (const StoredCosignature& s : *stored) {
        if (s.witness == witness &&
            (!newest || s.cosignature.checkpoint.tree_size >= newest->tree_size)) {
            newest = s.cosignature.checkpoint;
        }
    }
    return newest;
}

Result<AuditReport> Ledger::audit() const {
    const std::shared_lock state_lock(impl_->state_mutex);
    const std::shared_lock log_lock(impl_->log_mutex);
    auto all = read_checkpoints(impl_->checkpoints);
    if (!all) {
        return std::unexpected(all.error());
    }
    const std::uint64_t size = impl_->tree.size();
    std::uint64_t previous_size = 0;
    for (const protocol::SignedCheckpoint& checkpoint : *all) {
        if (!protocol::verify_checkpoint(
                *impl_->provider, checkpoint,
                impl_->state.log_key_for(checkpoint.checkpoint.tree_size))) {
            return fail(Errc::verification_failed,
                        "a stored checkpoint is not signed by the log key");
        }
        const protocol::Checkpoint& c = checkpoint.checkpoint;
        if (c.ledger_id != id() || c.tree_hash != hash()) {
            return fail(Errc::verification_failed, "a stored checkpoint belongs to another ledger");
        }
        if (c.tree_size < previous_size || c.tree_size > size) {
            return fail(Errc::verification_failed, "stored checkpoints are out of order");
        }
        auto root = impl_->tree.root(c.tree_size);
        if (!root) {
            return std::unexpected(root.error());
        }
        if (*root != c.root) {
            return fail(Errc::verification_failed, "a stored checkpoint disagrees with the log");
        }
        previous_size = c.tree_size;
    }
    auto stored = read_cosignatures(impl_->cosignatures);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    for (const StoredCosignature& s : *stored) {
        if (!protocol::verify_cosignature(*impl_->provider, s.cosignature, s.witness)) {
            return fail(Errc::verification_failed, "a stored cosignature does not verify");
        }
        if (std::ranges::none_of(*all, [&](const protocol::SignedCheckpoint& c) {
                return c.checkpoint == s.cosignature.checkpoint;
            })) {
            return fail(Errc::verification_failed,
                        "a stored cosignature is of an unknown checkpoint");
        }
    }
    auto stamps = read_timestamps(impl_->timestamps);
    if (!stamps) {
        return std::unexpected(stamps.error());
    }
    for (const StoredTimestamp& t : *stamps) {
        if (std::ranges::none_of(*all, [&](const protocol::SignedCheckpoint& c) {
                return c.encoded == t.checkpoint.encoded;
            })) {
            return fail(Errc::verification_failed,
                        "a stored time-stamp token is of an unknown checkpoint");
        }
        auto registered_at = last_registered_at(impl_->log, t.checkpoint.checkpoint.tree_size);
        if (!registered_at) {
            return std::unexpected(registered_at.error());
        }
        if (!check_timestamp(*impl_->provider, hash(), t.token, t.checkpoint, *registered_at)) {
            return fail(Errc::verification_failed, "a stored time-stamp token does not verify");
        }
    }
    return AuditReport{
        .entries = size,
        .checkpoints = all->size(),
        .cosignatures = stored->size(),
        .timestamps = stamps->size(),
        .actors = impl_->state.actors().size(),
        .delegations = impl_->state.delegations().size(),
        .records = impl_->state.records().size(),
        .unchecked_entries = size - previous_size,
    };
}

Result<protocol::SignedCheckpoint> Ledger::checkpoint(const crypto::Signer& log_key) {
    const crypto::Signer* keys[] = {&log_key};
    return checkpoint(LogKeys(keys));
}

Result<protocol::SignedCheckpoint> Ledger::checkpoint(LogKeys log_keys) {
    auto made = checkpoint_now(log_keys);
    if (made) {
        impl_->maybe_snapshot();
    }
    return made;
}

Result<protocol::SignedCheckpoint> Ledger::checkpoint_now(LogKeys log_keys) {
    impl_->drain(); // pipelined batches first
    if (auto s = impl_->require_usable(); !s) {
        return std::unexpected(s.error());
    }
    // The newest log key: every rotation in the log precedes what is signed
    // now. (Only this thread changes the state.)
    auto picked = impl_->pick_log_key(log_keys, impl_->state.log_key());
    if (!picked) {
        return std::unexpected(picked.error());
    }
    const crypto::Signer& log_key = **picked;
    // The state tree moves to the new commitment here: until the checkpoint
    // that ends with it is published, readers of the state wait (readers of
    // the log do not).
    const std::unique_lock state_lock(impl_->state_mutex);
    // First commit to the state in the log itself, unless the last entry
    // already is such a commitment (nothing has changed since).
    auto last_bytes = impl_->log.read(impl_->tree.size() - 1);
    if (!last_bytes) {
        return std::unexpected(last_bytes.error());
    }
    auto last = protocol::decode_log_entry(*last_bytes);
    if (!last) {
        return std::unexpected(last.error());
    }
    if (!last->is_state_commitment()) {
        auto state_root = impl_->sync_state_tree();
        if (!state_root) {
            return std::unexpected(state_root.error());
        }
        const protocol::Timestamp now = impl_->next_time();
        const std::uint64_t index = impl_->tree.size();
        auto commitment = protocol::sign_state_commitment(
            log_key, *impl_->provider,
            protocol::StateCommitment{id(), hash(), index, *state_root, now});
        if (!commitment) {
            return std::unexpected(commitment.error());
        }
        const protocol::LogEntry entry{commitment->id, now, {}, commitment->encoded};
        auto encoded = protocol::encode_log_entry(entry);
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        const ByteView view = *encoded;
        auto pending = impl_->log.write(std::span(&view, 1));
        if (!pending) {
            impl_->failed = true; // the state tree moved ahead
            return std::unexpected(pending.error());
        }
        {
            const std::unique_lock log_lock(impl_->log_mutex);
            impl_->log.publish(*pending);
            if (auto s = impl_->append_merkle(std::span(&view, 1)); !s) {
                return std::unexpected(s.error());
            }
        }
        impl_->last_registered_at = now;
        impl_->tree_commitment = commitment->commitment;
        impl_->tree_commitment_index = index;
    }
    auto root = impl_->tree.root();
    if (!root) {
        return std::unexpected(root.error());
    }
    // Never before the latest checkpoint (the clock may have stepped back),
    // and nothing new to sign if the latest already says it all.
    protocol::Timestamp at = impl_->next_time();
    if (impl_->latest_checkpoint) {
        at = std::max(at, impl_->latest_checkpoint->checkpoint.timestamp);
    }
    const protocol::Checkpoint checkpoint{id(), hash(), impl_->tree.size(), *root, at};
    if (impl_->latest_checkpoint && impl_->latest_checkpoint->checkpoint == checkpoint) {
        return *impl_->latest_checkpoint;
    }
    auto signed_checkpoint = protocol::sign_checkpoint(log_key, *impl_->provider, checkpoint);
    if (!signed_checkpoint) {
        return std::unexpected(signed_checkpoint.error());
    }
    const ByteView view = signed_checkpoint->encoded;
    auto pending = impl_->checkpoints.write(std::span(&view, 1));
    if (!pending) {
        return std::unexpected(pending.error());
    }
    const std::unique_lock log_lock(impl_->log_mutex);
    impl_->checkpoints.publish(*pending);
    impl_->adopt_checkpoint(*signed_checkpoint);
    return signed_checkpoint;
}

Result<Ledger::PreparedCheckpoint> Ledger::prepare_checkpoint(LogKeys log_keys) {
    impl_->drain(); // pipelined batches first
    if (auto s = impl_->require_usable(); !s) {
        return std::unexpected(s.error());
    }
    auto picked = impl_->pick_log_key(log_keys, impl_->state.log_key());
    if (!picked) {
        return std::unexpected(picked.error());
    }
    const crypto::Signer& log_key = **picked;
    // The tree moves to the new state here; until the commitment is in the
    // log, proofs wait (tree_ahead).
    const std::unique_lock state_lock(impl_->state_mutex);
    auto last_bytes = impl_->log.read(impl_->tree.size() - 1);
    if (!last_bytes) {
        return std::unexpected(last_bytes.error());
    }
    auto last = protocol::decode_log_entry(*last_bytes);
    if (!last) {
        return std::unexpected(last.error());
    }
    PreparedCheckpoint prepared;
    merkle::CompactRange range = impl_->tree.compact_range();
    protocol::Timestamp last_at = impl_->last_registered_at;
    if (!last->is_state_commitment()) {
        auto state_root = impl_->sync_state_tree();
        if (!state_root) {
            return std::unexpected(state_root.error());
        }
        impl_->tree_ahead = true;
        const protocol::Timestamp now = impl_->next_time();
        auto commitment = protocol::sign_state_commitment(
            log_key, *impl_->provider,
            protocol::StateCommitment{id(), hash(), impl_->tree.size(), *state_root, now});
        if (!commitment) {
            return std::unexpected(commitment.error());
        }
        auto encoded = protocol::encode_log_entry({commitment->id, now, {}, commitment->encoded});
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        if (auto s = range.append(*encoded); !s) {
            return std::unexpected(s.error());
        }
        prepared.commitment = std::move(*encoded);
        last_at = now;
    }
    auto root = range.root();
    if (!root) {
        return std::unexpected(root.error());
    }
    protocol::Timestamp at = std::max(impl_->clock->now(), last_at);
    if (impl_->latest_checkpoint) {
        at = std::max(at, impl_->latest_checkpoint->checkpoint.timestamp);
    }
    const protocol::Checkpoint checkpoint{id(), hash(), range.size(), *root, at};
    if (!prepared.commitment && impl_->latest_checkpoint &&
        impl_->latest_checkpoint->checkpoint.tree_size == checkpoint.tree_size) {
        prepared.checkpoint = *impl_->latest_checkpoint; // nothing new to sign
        return prepared;
    }
    auto signed_checkpoint = protocol::sign_checkpoint(log_key, *impl_->provider, checkpoint);
    if (!signed_checkpoint) {
        return std::unexpected(signed_checkpoint.error());
    }
    prepared.checkpoint = std::move(*signed_checkpoint);
    return prepared;
}

Status Ledger::apply_checkpoint(const std::optional<Bytes>& commitment, ByteView checkpoint) {
    impl_->drain(); // pipelined batches first
    if (commitment) {
        auto entry = protocol::decode_log_entry(*commitment);
        auto signed_commitment =
            entry && entry->is_state_commitment()
                ? protocol::parse_state_commitment(*impl_->provider, entry->state_commitment)
                : Result<protocol::SignedStateCommitment>(
                      fail(Errc::malformed, "not a state commitment entry"));
        if (!signed_commitment) {
            return std::unexpected(signed_commitment.error());
        }
        const std::uint64_t index = signed_commitment->commitment.tree_size;
        if (index < size()) {
            auto held = this->entry(index);
            if (!held || *held != *commitment) {
                return fail(Errc::verification_failed,
                            "the log holds another entry where the commitment belongs");
            }
        } else if (index == size()) {
            if (auto s = append_entries(std::span(&*commitment, 1)); !s) {
                return s;
            }
        } else {
            return fail(Errc::verification_failed, "the commitment is beyond the log");
        }
    }
    auto parsed = protocol::parse_checkpoint(checkpoint);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    auto stored = checkpoints_of_size(parsed->checkpoint.tree_size);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    if (std::ranges::any_of(*stored, [&](const protocol::SignedCheckpoint& c) {
            return std::ranges::equal(c.encoded, checkpoint);
        })) {
        return {};
    }
    return store_checkpoint(checkpoint);
}

std::optional<protocol::SignedCheckpoint> Ledger::latest_checkpoint() const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->latest_checkpoint;
}

std::optional<protocol::StateCommitment> Ledger::state_commitment() const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->checkpoint_commitment;
}

namespace {

/// state_proof, for callers holding the state and log locks.
Result<protocol::StateProof> prove(const Ledger::Impl& impl, const protocol::Id& id) {
    if (!impl.latest_checkpoint || !impl.checkpoint_commitment) {
        return fail(Errc::not_found, "no checkpoint commits to the ledger state yet");
    }
    // The tree follows the latest commitment in the log, which may still
    // await its checkpoint (written, or copied, a moment later), or the
    // next one, prepared and not yet in the log.
    if (impl.tree_ahead ||
        impl.tree_commitment_index + 1 != impl.latest_checkpoint->checkpoint.tree_size) {
        return fail(Errc::unavailable,
                    "the latest state commitment awaits its checkpoint; retry shortly");
    }
    // The object as the commitment saw it: its history before that entry.
    auto leaf = protocol::state_leaf(impl.state, id, impl.tree_commitment_index);
    if (!leaf) {
        return fail(Errc::not_found, "the state has no object with this id");
    }
    auto siblings = impl.state_tree.siblings(id);
    if (!siblings) {
        return std::unexpected(siblings.error());
    }
    protocol::StateProof proof{std::move(*leaf), std::move(*siblings)};
    // Cheap, and catches any drift between the tree and the state.
    if (auto s = protocol::verify_state_proof(*impl.provider, impl.state.hash(), proof,
                                              impl.checkpoint_commitment->state_root);
        !s) {
        return fail(Errc::malformed, "the state tree disagrees with the state");
    }
    return proof;
}

/// receipt, for callers holding the log lock.
Result<Bytes> issue(const Ledger::Impl& impl, const crypto::Signer& log_key, std::uint64_t index) {
    if (!impl.latest_checkpoint || index >= impl.latest_checkpoint->checkpoint.tree_size) {
        return fail(Errc::not_found, "no checkpoint covers this entry yet");
    }
    const protocol::Checkpoint& checkpoint = impl.latest_checkpoint->checkpoint;
    auto path = impl.tree.inclusion_proof(index, checkpoint.tree_size);
    if (!path) {
        return std::unexpected(path.error());
    }
    // One signature per checkpoint: receipts differ only in their proofs.
    std::shared_ptr<const Ledger::Impl::Seal> seal;
    {
        const std::lock_guard lock(impl.seal_mutex);
        if (!impl.seal || impl.seal->checkpoint != checkpoint ||
            impl.seal->key != log_key.public_key()) {
            auto made = protocol::seal_receipts(log_key, *impl.provider, impl.state.hash(),
                                                checkpoint.root);
            if (!made) {
                return std::unexpected(made.error());
            }
            impl.seal = std::make_shared<const Ledger::Impl::Seal>(
                Ledger::Impl::Seal{checkpoint, log_key.public_key(), std::move(*made)});
        }
        seal = impl.seal;
    }
    return protocol::issue_receipt(seal->seal,
                                   protocol::InclusionProof{checkpoint.tree_size, index, *path});
}

} // namespace

Result<protocol::StateProof> Ledger::state_proof(const protocol::Id& id) const {
    const std::shared_lock state_lock(impl_->state_mutex);
    const std::shared_lock log_lock(impl_->log_mutex);
    return prove(*impl_, id);
}

Result<Ledger::CommittedProof> Ledger::committed_state_proof(const protocol::Id& id) const {
    const std::shared_lock state_lock(impl_->state_mutex);
    const std::shared_lock log_lock(impl_->log_mutex);
    auto proof = prove(*impl_, id);
    if (!proof) {
        return std::unexpected(proof.error());
    }
    return CommittedProof{std::move(*proof), *impl_->checkpoint_commitment};
}

Result<Bytes> Ledger::receipt(const crypto::Signer& log_key, std::uint64_t index) const {
    const crypto::Signer* keys[] = {&log_key};
    return receipt(LogKeys(keys), index);
}

Result<Bytes> Ledger::receipt(LogKeys log_keys, std::uint64_t index) const {
    const std::shared_lock lock(impl_->log_mutex);
    if (!impl_->latest_checkpoint) {
        return fail(Errc::not_found, "no checkpoint covers this entry yet");
    }
    const auto picked = impl_->pick_log_key(log_keys, impl_->latest_log_key);
    if (!picked) {
        return std::unexpected(picked.error());
    }
    return issue(*impl_, **picked, index);
}

Result<protocol::CosignRequest> Ledger::cosign_request(std::uint64_t old_size) const {
    const std::shared_lock state_lock(impl_->state_mutex);
    const std::shared_lock log_lock(impl_->log_mutex);
    if (!impl_->latest_checkpoint) {
        return fail(Errc::not_found, "the ledger has no checkpoint yet");
    }
    const protocol::Checkpoint& c = impl_->latest_checkpoint->checkpoint;
    if (old_size > c.tree_size) {
        return fail(Errc::invalid_argument, "the old size is beyond the latest checkpoint");
    }
    auto proof = impl_->tree.consistency_proof(old_size, c.tree_size);
    if (!proof) {
        return std::unexpected(proof.error());
    }
    protocol::CosignRequest request{
        impl_->latest_checkpoint->encoded, old_size, std::move(*proof), {}};
    // Every key rotation below the checkpoint, so a witness can follow the
    // log key to the one that signed it.
    const protocol::ActorState* organization = impl_->state.actor(id());
    for (const std::uint64_t index : organization->rotations) {
        if (index >= c.tree_size) {
            break;
        }
        auto entry = impl_->log.read(index);
        if (!entry) {
            return std::unexpected(entry.error());
        }
        auto path = impl_->tree.inclusion_proof(index, c.tree_size);
        if (!path) {
            return std::unexpected(path.error());
        }
        request.rotations.push_back({index, std::move(*entry), std::move(*path)});
    }
    return request;
}

Result<protocol::EvidenceBundle> Ledger::export_evidence(const crypto::Signer& log_key,
                                                         const protocol::Id& record_id) const {
    const crypto::Signer* keys[] = {&log_key};
    return export_evidence(LogKeys(keys), record_id);
}

Result<protocol::EvidenceBundle> Ledger::export_evidence(LogKeys log_keys,
                                                         const protocol::Id& record_id) const {
    // One consistent view of the state and the log throughout.
    const std::shared_lock state_lock(impl_->state_mutex);
    const std::shared_lock log_lock(impl_->log_mutex);
    if (!impl_->latest_checkpoint) {
        return fail(Errc::not_found, "no checkpoint covers the record's statements yet");
    }
    const auto picked = impl_->pick_log_key(log_keys, impl_->latest_log_key);
    if (!picked) {
        return std::unexpected(picked.error());
    }
    const crypto::Signer& log_key = **picked;
    const protocol::LedgerState& state = impl_->state;
    // A record, or a contract instance (spec section 15).
    const protocol::RecordState* record = state.record(record_id);
    const protocol::InstanceState* instance =
        record == nullptr ? state.instance(record_id) : nullptr;
    if (record == nullptr && instance == nullptr) {
        return fail(Errc::not_found, "no record with this id");
    }
    // Its statements: a record's, or an instance's calls, for a child its
    // ancestors' up to each call that created the next generation (spec
    // v0.7). The ancestors get no state proofs: their later calls stay out.
    const std::vector<std::uint64_t> history = record != nullptr
                                                   ? record->history.to_vector()
                                                   : protocol::instance_events(state, *instance);
    // Everything about it must be covered by the latest checkpoint (which
    // also rules out what is not durable yet).
    const auto& checkpoint = impl_->latest_checkpoint;
    if (!checkpoint || std::ranges::any_of(history, [&](std::uint64_t index) {
            return index >= checkpoint->checkpoint.tree_size;
        })) {
        return fail(Errc::not_found, "no checkpoint covers the record's statements yet");
    }

    std::set<std::uint64_t> needed{0};
    std::vector<std::uint64_t> work;
    auto need = [&](std::uint64_t index) {
        if (needed.insert(index).second) {
            work.push_back(index);
        }
    };
    auto need_actor = [&](const protocol::Id& id, std::uint64_t before) {
        const protocol::ActorState* actor = state.actor(id);
        if (actor == nullptr || actor->is_organization()) {
            return;
        }
        need(actor->registered_at_index);
        for (const std::uint64_t rotation : actor->rotations) {
            if (rotation < before) {
                need(rotation);
            }
        }
        for (const std::uint64_t update : actor->presence_updates) {
            if (update < before) {
                need(update);
            }
        }
    };
    auto need_delegation = [&](const protocol::Id& id) {
        if (const protocol::DelegationState* d = state.delegation(id)) {
            need(d->granted_at_index);
        }
    };
    auto need_contract = [&](const protocol::Id& id) {
        if (const protocol::ContractState* c = state.contract(id)) {
            need(c->deployed_at_index);
        }
    };
    for (const std::uint64_t index : history) {
        need(index);
    }
    // Every rotation of the organization's keys below the checkpoint: the
    // verifier follows them to the log key that signed it (spec v0.4).
    for (const std::uint64_t index : state.actor(id())->rotations) {
        if (index < checkpoint->checkpoint.tree_size) {
            need(index);
        }
    }

    // Under a checkpoint that commits to the state, prove the complete history
    // of everything involved, and include all of it.
    std::vector<protocol::StateProof> proofs;
    const bool committed = checkpoint && impl_->checkpoint_commitment;
    if (committed) {
        std::vector<protocol::Statement> events;
        for (const std::uint64_t index : history) {
            auto bytes = impl_->log.read(index);
            if (!bytes) {
                return std::unexpected(bytes.error());
            }
            auto entry = protocol::decode_log_entry(*bytes);
            if (!entry) {
                return std::unexpected(entry.error());
            }
            auto parsed = protocol::parse_statement(*impl_->provider, entry->statement, hash());
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            events.push_back(std::move(parsed->statement));
        }
        for (const protocol::Id& id : protocol::involved_objects(state, record_id, events)) {
            auto proof = prove(*impl_, id);
            if (!proof) {
                return fail(Errc::not_found, "no checkpoint covers the record's statements yet");
            }
            for (const std::uint64_t index : proof->leaf.history) {
                need(index);
            }
            proofs.push_back(std::move(*proof));
        }
    }

    while (!work.empty()) {
        const std::uint64_t index = work.back();
        work.pop_back();
        auto bytes = impl_->log.read(index);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto entry = protocol::decode_log_entry(*bytes);
        if (!entry) {
            return std::unexpected(entry.error());
        }
        auto parsed = protocol::parse_statement(*impl_->provider, entry->statement, hash());
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        const protocol::Statement& statement = parsed->statement;
        if (statement.actor_id) {
            need_actor(*statement.actor_id, index);
        }
        if (statement.delegation_id) {
            need_delegation(*statement.delegation_id);
        }
        std::visit(
            [&](const auto& body) {
                using Body = std::decay_t<decltype(body)>;
                if constexpr (std::is_same_v<Body, protocol::ActorRegisterBody>) {
                    if (body.responsible) {
                        need_actor(*body.responsible, index);
                    }
                } else if constexpr (std::is_same_v<Body, protocol::ActorRotateKeyBody> ||
                                     std::is_same_v<Body, protocol::ActorRevokeBody> ||
                                     std::is_same_v<Body, protocol::ActorSetPresenceBody>) {
                    need_actor(body.actor, index);
                } else if constexpr (std::is_same_v<Body, protocol::DelegationGrantBody>) {
                    need_actor(body.grantee, index);
                } else if constexpr (std::is_same_v<Body, protocol::DelegationRevokeBody>) {
                    need_delegation(body.delegation);
                } else if constexpr (std::is_same_v<Body, protocol::RecordEndorseBody> ||
                                     std::is_same_v<Body, protocol::RecordTransitionBody> ||
                                     std::is_same_v<Body, protocol::RecordRevokeBody>) {
                    if (const protocol::RecordState* r = state.record(body.record)) {
                        need(r->registered_at_index);
                    }
                } else if constexpr (std::is_same_v<Body, protocol::ContractCallBody>) {
                    if (body.contract) {
                        need_contract(*body.contract);
                    } else if (const protocol::InstanceState* i = state.instance(*body.instance)) {
                        need_contract(i->contract);
                    }
                } else if constexpr (std::is_same_v<Body, protocol::ContractRetireBody>) {
                    need_contract(body.contract);
                }
            },
            statement.body);
    }

    if (committed) {
        needed.insert(checkpoint->checkpoint.tree_size - 1); // the state commitment
    }
    if (!checkpoint || *needed.rbegin() >= checkpoint->checkpoint.tree_size) {
        return fail(Errc::not_found, "no checkpoint covers the record's statements yet");
    }
    protocol::EvidenceBundle bundle;
    bundle.record = record_id;
    bundle.checkpoint = checkpoint->encoded;
    bundle.state_proofs = std::move(proofs);
    for (const std::uint64_t index : needed) {
        auto bytes = impl_->log.read(index);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto receipt = issue(*impl_, log_key, index);
        if (!receipt) {
            return std::unexpected(receipt.error());
        }
        bundle.entries.push_back(protocol::EvidenceEntry{std::move(*bytes), std::move(*receipt)});
    }
    auto stored = read_cosignatures(impl_->cosignatures);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    for (const StoredCosignature& s : *stored) {
        if (s.cosignature.checkpoint == checkpoint->checkpoint) {
            bundle.cosignatures.push_back(s.encoded);
        }
    }

    // Anchors (v0.11): the earliest time-stamped checkpoint that covers the
    // record's first event bounds when it began; the latest at or before the
    // bundle's bounds the most. Each with every token over it.
    auto stamps = read_timestamps(impl_->timestamps);
    if (!stamps) {
        return std::unexpected(stamps.error());
    }
    const std::uint64_t size = checkpoint->checkpoint.tree_size;
    const StoredTimestamp* earliest = nullptr;
    const StoredTimestamp* latest = nullptr;
    for (const StoredTimestamp& t : *stamps) {
        const std::uint64_t stamped = t.checkpoint.checkpoint.tree_size;
        if (stamped > size) {
            continue;
        }
        if (stamped > history.front() &&
            (earliest == nullptr || stamped < earliest->checkpoint.checkpoint.tree_size)) {
            earliest = &t;
        }
        if (latest == nullptr || stamped >= latest->checkpoint.checkpoint.tree_size) {
            latest = &t;
        }
    }
    for (const StoredTimestamp* chosen : {earliest, latest}) {
        if (chosen == nullptr ||
            std::ranges::any_of(bundle.anchors, [&](const protocol::Anchor& a) {
                return a.checkpoint == chosen->checkpoint.encoded;
            })) {
            continue;
        }
        protocol::Anchor anchor{
            .checkpoint = chosen->checkpoint.encoded, .timestamps = {}, .consistency = {}};
        for (const StoredTimestamp& t : *stamps) {
            if (t.checkpoint.encoded == chosen->checkpoint.encoded) {
                anchor.timestamps.push_back(t.token);
            }
        }
        const std::uint64_t stamped = chosen->checkpoint.checkpoint.tree_size;
        if (stamped < size) {
            auto proof = impl_->tree.consistency_proof(stamped, size);
            if (!proof) {
                return std::unexpected(proof.error());
            }
            anchor.consistency = std::move(*proof);
        }
        bundle.anchors.push_back(std::move(anchor));
    }
    return bundle;
}

} // namespace cexchain::ledger
