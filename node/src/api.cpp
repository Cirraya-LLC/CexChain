// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <deque>
#include <format>
#include <mutex>
#include <optional>
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
#include <cexchain/node/api.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/tokens.hpp>

#include "files.hpp"

namespace cexchain::node {

namespace {

using json = nlohmann::json;
using steady = std::chrono::steady_clock;

constexpr std::uint64_t max_batch = 1000;
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

enum class Access { open, read, submit, admin, peer };

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
};

/// Where a request goes. `rest` is where the path's last segment (an id or
/// an index) starts, an offset since the request may move.
struct Routed {
    Endpoint endpoint;
    Access access;
    std::size_t rest = 0;
};

/// Statements one group commit takes at most.
constexpr std::size_t max_group = 4096;
constexpr std::size_t max_group_bytes = 32 * 1024 * 1024;

} // namespace

/// Requests run on the server's I/O threads, all at once. Reads go straight
/// to the ledger, which lets them run alongside its writer. Writes queue for
/// the one writer thread, which takes everything queued as one group: one
/// lock of the directory, one catch-up, one sync for all the statements.
struct LedgerApi::State {
    using Done = Application::Respond;

    ApiOptions options;
    const crypto::Provider* provider = nullptr;
    ledger::SystemClock clock;
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
    std::optional<std::filesystem::file_time_type> tokens_time;
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
    };
    /// Runs on the writer thread holding the ledger's lock, caught up; or,
    /// if that could not be had, gets the answer to give instead.
    using Locked = std::function<void(const http::Response* refusal)>;
    using Job = std::function<void()>;

    std::mutex queue_mutex;
    std::condition_variable queue_ready;
    std::condition_variable queue_idle;
    std::deque<Submission> submissions;
    std::vector<Locked> locked;
    /// Reads that found another process had written: they run once the
    /// writer has caught up.
    std::vector<Job> after_refresh;
    bool writing = false;
    bool stopping = false;
    std::thread writer;

    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;
    ~State() { stop(); }

    void start() {
        writer = std::thread([this] { run_writer(); });
    }

    /// Waits until everything queued so far is done.
    void drain() {
        std::unique_lock lock(queue_mutex);
        queue_idle.wait(lock, [&] {
            return !writing && submissions.empty() && locked.empty() && after_refresh.empty();
        });
    }

    void stop() {
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

    void queue_submission(Submission submission) {
        {
            const std::lock_guard lock(queue_mutex);
            submissions.push_back(std::move(submission));
        }
        queue_ready.notify_one();
    }

    void queue_locked(Locked job) {
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
            std::vector<Locked> jobs;
            std::vector<Job> reads;
            bool stopped = false;
            {
                std::unique_lock lock(queue_mutex);
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
                for (Locked& job : jobs) {
                    job(&refusal);
                }
                for (Job& read : reads) {
                    read(); // the ledger is still there, and reads are quick
                }
                const std::lock_guard lock(queue_mutex);
                writing = false;
                queue_idle.notify_all();
                return;
            }
            const bool caught_up = !batch.empty() || !jobs.empty();
            if (caught_up) {
                write_group(batch, jobs);
            }
            if (!reads.empty()) {
                if (!caught_up) {
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
    /// writes, all under one lock of the directory.
    void write_group(std::vector<Submission>& batch, std::vector<Locked>& jobs) {
        std::optional<http::Response> refusal;
        auto lock = ledger::DirectoryLock::acquire(options.directory, 2000);
        if (failed) {
            refusal = error_response(503, "unavailable", "the ledger is unusable");
        } else if (!lock) {
            refusal = error_response(503, "unavailable", "the ledger is busy; retry");
            refusal->headers.emplace_back("Retry-After", "1");
        } else if (auto s = refresh(true); !s) {
            refusal = error_response(503, "unavailable", "the ledger is unusable");
        }
        if (refusal) {
            for (Submission& s : batch) {
                finish(s.done, s.principal, *refusal);
            }
            for (Locked& job : jobs) {
                job(&*refusal);
            }
            return;
        }
        if (!batch.empty()) {
            std::vector<ByteView> views;
            views.reserve(batch.size());
            for (const Submission& s : batch) {
                views.emplace_back(s.statement);
            }
            auto results = ledger->submit_batch(views);
            for (std::size_t i = 0; i < batch.size(); ++i) {
                finish(batch[i].done, batch[i].principal, registration_response(results[i]));
            }
        }
        for (Locked& job : jobs) {
            job(nullptr);
        }
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
        const auto time = std::filesystem::last_write_time(path, ec);
        const std::optional<std::filesystem::file_time_type> current =
            ec ? std::nullopt : std::optional(time);
        if (!force && current == tokens_time) {
            return;
        }
        auto loaded = load_tokens(options.directory);
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
            {
                const std::lock_guard lock(failure_mutex);
                if (!failed) {
                    failure_text = std::string(report.error().detail);
                }
            }
            failed.store(true, std::memory_order_release);
            event("ledger-unusable", report.error().detail);
            return std::unexpected(report.error());
        }
        return {};
    }

    /// Who is calling (into `principal`), and whether they may.
    std::optional<http::Response> authorize(const http::Request& r, Access access,
                                            std::string& principal) const {
        if (access == Access::open || (access == Access::read && options.public_read)) {
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
        const Scope needed = access == Access::read     ? Scope::read
                             : access == Access::submit ? Scope::submit
                             : access == Access::peer   ? Scope::peer
                                                        : Scope::admin;
        if (!has_scope(token->scopes, needed)) {
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
                  {"receipts", options.log_key != nullptr},
                  {"version", options.version}});
    }

    http::Response checkpoint(const http::Request& r) const {
        if (const auto it = r.query.find("size"); it != r.query.end()) {
            const auto size = number(r, "size");
            auto all = ledger->checkpoints();
            if (!size || !all) {
                return error_response(400, "invalid_argument", "size must be a number");
            }
            for (const auto& c : *all) {
                if (c.checkpoint.tree_size == *size) {
                    return binary("application/cose", c.encoded);
                }
            }
            return error_response(404, "not_found", "no checkpoint of this size");
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
            auto entry = ledger->entry(i);
            if (!entry) {
                return error_response(entry.error());
            }
            bytes += entry->size();
            out.push_back(cbor::Value::bytes(*entry));
        }
        return cbor_response(cbor::Value::array(std::move(out)));
    }

    http::Response checkpoints(const http::Request& r) const {
        auto all = ledger->checkpoints();
        if (!all) {
            return error_response(all.error());
        }
        const auto span = range(r, all->size());
        if (!span) {
            return error_response(400, "invalid_argument", "start <= count and 0 < count");
        }
        cbor::Array out;
        for (std::uint64_t i = span->first; i < span->second; ++i) {
            out.push_back(cbor::Value::bytes((*all)[static_cast<std::size_t>(i)].encoded));
        }
        return cbor_response(cbor::Value::array(std::move(out)));
    }

    http::Response cosignatures(const http::Request& r) const {
        auto all = ledger->cosignatures();
        if (!all) {
            return error_response(all.error());
        }
        const auto span = range(r, all->size());
        if (!span) {
            return error_response(400, "invalid_argument", "start <= count and 0 < count");
        }
        cbor::Array out;
        for (std::uint64_t i = span->first; i < span->second; ++i) {
            const auto& s = (*all)[static_cast<std::size_t>(i)];
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
        auto bytes = ledger->entry(*index);
        auto entry = bytes ? protocol::decode_log_entry(*bytes)
                           : Result<protocol::LogEntry>(std::unexpected(bytes.error()));
        if (!entry) {
            return error_response(entry.error());
        }
        return json_response(200, {{"statement_id", hex(*id)},
                                   {"index", *index},
                                   {"registered_at", entry->registered_at}});
    }

    http::Response receipt(std::string_view index_text) const {
        if (!options.log_key) {
            return error_response(501, "unsupported", "this server has no log key");
        }
        std::uint64_t index = 0;
        const auto [ptr, ec] =
            std::from_chars(index_text.data(), index_text.data() + index_text.size(), index);
        if (ec != std::errc{} || ptr != index_text.data() + index_text.size()) {
            return error_response(400, "invalid_argument", "an entry index is a number");
        }
        auto receipt = ledger->receipt(*options.log_key, index);
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
        if (!options.log_key) {
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
        auto bundle = ledger->export_evidence(*options.log_key, *id);
        if (!bundle) {
            return error_response(bundle.error());
        }
        auto encoded = protocol::encode_bundle(*bundle);
        return encoded ? binary("application/cbor", std::move(*encoded))
                       : error_response(encoded.error());
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

    /// The peer whose ledger produced `bundle`, which must verify.
    Result<Peer> peer_of(ByteView bundle) const {
        auto report = protocol::verify_bundle(*provider, bundle, {});
        if (!report) {
            return std::unexpected(report.error());
        }
        auto peers = load_peers(options.directory);
        if (!peers) {
            return std::unexpected(peers.error());
        }
        for (const Peer& p : *peers) {
            if (p.ledger_id == report->ledger_id) {
                return p;
            }
        }
        return fail(Errc::rejected, "the evidence comes from a ledger that is not a peer");
    }

    Status store(const std::filesystem::path& path, ByteView bytes) const {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return fail(Errc::unavailable, "cannot create the access directory");
        }
        return detail::write_file(path, bytes, true);
    }

    /// Peer tokens are named after their peer: each peer sees and sends
    /// only its own exchanges.
    static std::optional<http::Response> require_peer_token(const Peer& peer,
                                                            const std::string& principal) {
        if (peer.name != principal) {
            return error_response(403, "forbidden",
                                  "this token is not the peer's (name it after the peer)");
        }
        return std::nullopt;
    }

    http::Response access_request(const http::Request& r, const std::string& principal) {
        auto peer = peer_of(r.body);
        if (!peer) {
            return error_response(peer.error());
        }
        if (auto denied = require_peer_token(*peer, principal)) {
            return std::move(*denied);
        }
        auto checked = protocol::check_access_request(*provider, r.body, peer->ledger_id,
                                                      ledger->id(), clock.now());
        if (!checked) {
            return error_response(checked.error());
        }
        if (auto s = store(access_path(options.directory, AccessBox::inbox, checked->report.record),
                           r.body);
            !s) {
            return error_response(s.error());
        }
        event("access-request", peer->name + " " + hex(checked->report.record));
        return json_response(202, {{"request", hex(checked->report.record)},
                                   {"peer", peer->name},
                                   {"record", hex(checked->value.record)},
                                   {"purpose", checked->value.purpose}});
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
        auto report = delivery
                          ? protocol::verify_bundle(*provider, delivery->grant_bundle, own)
                          : Result<protocol::EvidenceReport>(std::unexpected(delivery.error()));
        auto grant = report && report->metadata
                         ? protocol::decode_access_grant(*report->metadata)
                         : Result<protocol::AccessGrant>(fail(Errc::malformed, "no grant"));
        auto peers = load_peers(options.directory);
        const bool theirs = grant && peers && std::ranges::any_of(*peers, [&](const Peer& p) {
                                return p.ledger_id == grant->ledger && p.name == principal;
                            });
        if (!theirs) {
            return error_response(404, "not_found", "not granted (yet)");
        }
        return binary("application/cbor", std::move(*bytes));
    }

    http::Response access_receipt(const http::Request& r, const std::string& principal) {
        auto peer = peer_of(r.body);
        if (!peer) {
            return error_response(peer.error());
        }
        if (auto denied = require_peer_token(*peer, principal)) {
            return std::move(*denied);
        }
        // Which grant: from the receipt's metadata, checked below.
        auto report = protocol::verify_bundle(*provider, r.body, {});
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
        auto delivery =
            detail::read_file(access_path(options.directory, AccessBox::outbox, decoded->request));
        auto digest = delivery ? provider->digest(crypto::HashAlg::sha256, *delivery)
                               : Result<crypto::Digest>(std::unexpected(delivery.error()));
        if (!digest) {
            return error_response(404, "not_found", "nothing was delivered for this grant");
        }
        auto checked = protocol::check_access_receipt(
            *provider, r.body, peer->ledger_id, ledger->id(), receipt->grant, digest->bytes());
        if (!checked) {
            return error_response(checked.error());
        }
        if (auto s =
                store(access_path(options.directory, AccessBox::receipts, receipt->grant), r.body);
            !s) {
            return error_response(s.error());
        }
        event("access-receipt", peer->name + " " + hex(receipt->grant));
        return json_response(202, {{"grant", hex(receipt->grant)}, {"peer", peer->name}});
    }

    http::Response witness_cosign(const http::Request& r) {
        if (!options.witness) {
            return error_response(501, "unsupported", "this server is not a witness");
        }
        auto cosignature = [&] {
            const std::lock_guard lock(witness_mutex);
            return options.witness(r.body);
        }();
        if (!cosignature) {
            return error_response(cosignature.error());
        }
        return binary("application/cose", std::move(*cosignature));
    }

    // ---- writes, for the writer thread ---------------------------------

    void submit(http::Request& r, std::string principal, Done& done) {
        const auto type = r.header("content-type");
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
        queue_submission({std::move(r.body), std::move(principal), std::move(done)});
    }

    void make_checkpoint(std::string principal, Done& done) {
        if (!options.log_key) {
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
            auto made = ledger->checkpoint(*options.log_key);
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
            auto stored = ledger->add_cosignature(cosignature, key);
            finish(done, principal,
                   stored ? json_response(200, {{"stored", true}})
                          : error_response(stored.error()));
        });
    }

    /// From tick(): checkpoints when the interval has passed and the log has
    /// grown.
    void auto_checkpoint() {
        if (failed || !options.log_key || replica || options.read_only ||
            options.checkpoint_interval.count() == 0 ||
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
            auto made = ledger->checkpoint(*options.log_key);
            if (!made) {
                event("checkpoint-failed", made.error().detail);
                return;
            }
            ++auto_checkpoints;
            event("checkpoint", std::format("tree size {}", made->checkpoint.tree_size));
        });
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
            found = Routed{Endpoint::submit, Access::submit};
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
                               found->endpoint == Endpoint::add_cosignature;
            return method_not_allowed(posts ? "POST" : "GET");
        }
        return *found;
    }

    /// Everything but the writes: reads, and the peer routes (which read
    /// the ledger and write files of their own).
    http::Response answer(const http::Request& r, const Routed& routed,
                          const std::string& principal) {
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
        case Endpoint::make_checkpoint:
        case Endpoint::add_cosignature:
        case Endpoint::submit:
            break;
        }
        return error_response(500, "internal", "unrouted");
    }

    http::Response answer_safely(const http::Request& r, const Routed& routed,
                                 const std::string& principal) {
        try {
            return answer(r, routed, principal);
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
        if (auto denied = authorize(r, routed.access, principal)) {
            finish(done, principal, std::move(*denied));
            return;
        }
        const bool writes = routed.endpoint == Endpoint::submit ||
                            routed.endpoint == Endpoint::make_checkpoint ||
                            routed.endpoint == Endpoint::add_cosignature;
        if (writes) {
            if (options.read_only || replica) {
                finish(done, principal,
                       error_response(403, "read_only",
                                      replica ? "this ledger is a replica; write to its primary"
                                              : "this server is read-only"));
            } else if (routed.endpoint == Endpoint::submit) {
                submit(r, std::move(principal), done);
            } else if (routed.endpoint == Endpoint::make_checkpoint) {
                make_checkpoint(std::move(principal), done);
            } else {
                add_cosignature(r, std::move(principal), done);
            }
            return;
        }
        if (ledger->outdated()) {
            // Another process wrote: answer once the writer has caught up.
            queue_read([this, r = std::move(r), routed, principal = std::move(principal),
                        done = std::move(done)]() mutable {
                finish(done, principal, answer_safely(r, routed, principal));
            });
            return;
        }
        finish(done, principal, answer_safely(r, routed, principal));
    }
};

Result<std::unique_ptr<LedgerApi>> LedgerApi::open(ApiOptions options,
                                                   const crypto::Provider& provider) {
    auto state = std::make_unique<State>();
    state->provider = &provider;
    std::error_code ec;
    if (!std::filesystem::is_directory(options.directory, ec)) {
        return fail(Errc::not_found, "no ledger directory");
    }
    state->replica = std::filesystem::exists(options.directory / replica_file, ec);
    {
        auto lock = ledger::DirectoryLock::acquire(options.directory);
        if (!lock) {
            return std::unexpected(lock.error());
        }
        auto fs = ledger::PosixFileSystem::open_directory(options.directory);
        if (!fs) {
            return std::unexpected(fs.error());
        }
        state->fs.emplace(std::move(*fs));
        auto opened = ledger::Ledger::open(*state->fs, state->clock, provider);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        state->ledger.emplace(std::move(*opened));
    }
    if (options.log_key && options.log_key->public_key() != state->ledger->state().log_key()) {
        return fail(Errc::invalid_argument, "the log key is not this ledger's");
    }
    state->options = std::move(options);
    state->reload_tokens(true);
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
}

void LedgerApi::stop() {
    state_->drain();
}

bool LedgerApi::is_replica() const noexcept {
    return state_->replica;
}

const ledger::Ledger& LedgerApi::ledger() const noexcept {
    return *state_->ledger;
}

} // namespace cexchain::node
