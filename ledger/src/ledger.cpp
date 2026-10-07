// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <utility>
#include <variant>

#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/ledger/ledger.hpp>
#include <cexchain/ledger/parallel.hpp>

namespace cexchain::ledger {

namespace {

constexpr std::string_view statements_file = "statements";
constexpr std::string_view checkpoints_file = "checkpoints";
constexpr std::string_view cosignatures_file = "cosignatures";

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

} // namespace

struct Ledger::Impl {
    Impl(Clock& clock_, const crypto::Provider& provider_, RecordLog log_, RecordLog checkpoints_,
         RecordLog cosignatures_, protocol::LedgerState state_, merkle::Tree tree_,
         protocol::StateTree state_tree_)
        : clock(&clock_), provider(&provider_), log(std::move(log_)),
          checkpoints(std::move(checkpoints_)), cosignatures(std::move(cosignatures_)),
          state(std::move(state_)), tree(std::move(tree_)), state_tree(std::move(state_tree_)) {}

    Clock* clock;
    const crypto::Provider* provider;
    /// Concurrency (D-048): any number of threads may read while one thread
    /// writes. `state_mutex` guards the state, the state tree, and the
    /// commitment it reflects; `log_mutex` guards the logs' indexes, the
    /// Merkle tree, and the latest checkpoint. Lock order: state, then log.
    /// The writer holds them exclusively only to change memory, never while
    /// it waits for the disk, and readers only see what is durable: the
    /// Merkle tree's size is the durable watermark.
    mutable std::shared_mutex state_mutex;
    mutable std::shared_mutex log_mutex;
    RecordLog log;
    RecordLog checkpoints;
    RecordLog cosignatures;
    protocol::LedgerState state;
    merkle::Tree tree;
    /// The state tree as of the latest state commitment in the log: what
    /// changed after it is staged in `state` until the next one. Updated
    /// incrementally (D-048), it gives roots and proofs in O(log n).
    protocol::StateTree state_tree;
    /// That commitment, and its log index.
    std::optional<protocol::StateCommitment> tree_commitment;
    std::uint64_t tree_commitment_index = 0;
    std::optional<protocol::SignedCheckpoint> latest_checkpoint;
    /// Stored checkpoints checked against the log: a refresh that failed
    /// after reading new ones checks them next time.
    std::uint64_t checked_checkpoints = 0;
    /// The state commitment the latest checkpoint ends with, if it does.
    std::optional<protocol::StateCommitment> checkpoint_commitment;
    protocol::Timestamp last_registered_at = 0;
    /// Set when a write failed after the in-memory views moved ahead of the
    /// files; the ledger must be reopened.
    std::atomic<bool> failed = false;

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

    /// Checks that a decoded entry may be the log entry at `index`, the next
    /// one: registered no earlier than the entry before it, and either a
    /// statement that passes validation at its registration time or a state
    /// commitment, signed by the log key, of exactly the current state.
    Status check(const Decoded& d, std::uint64_t index) {
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
        if (auto s = state.validate(*provider, *d.statement, entry.registered_at,
                                    d.signature ? &*d.signature : nullptr);
            !s) {
            return fail(Errc::verification_failed,
                        "a logged statement does not pass validation on replay");
        }
        return {};
    }

    /// Applies a checked entry at `index` to the state. (The Merkle tree
    /// takes it when it is durable: see append_merkle.)
    Status apply(const Decoded& d, std::uint64_t index) {
        if (d.statement) {
            if (auto s = state.apply(*provider, *d.statement, index); !s) {
                return s;
            }
        } else {
            // check() synced the state tree to this commitment.
            tree_commitment = d.commitment->commitment;
            tree_commitment_index = index;
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
    Replayed replay(std::span<const ByteView> entries, std::uint64_t first) {
        Replayed out;
        const auto decoded = decode(entries);
        for (std::size_t i = 0; i < decoded.size(); ++i) {
            if (auto s = check(decoded[i], first + i); !s) {
                out.error = s.error();
                return out;
            }
            if (auto s = apply(decoded[i], first + i); !s) {
                out.error = s.error();
                out.fatal = true;
                return out;
            }
            ++out.applied;
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
            const Replayed part = replay(views, begin);
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
        latest_checkpoint = std::move(checkpoint);
    }

    /// Checks a signed checkpoint against the log key and this log: for this
    /// ledger, no smaller than the latest, and with the tree's root.
    /// Checks a signed checkpoint on its own: signed by the log key, for
    /// this ledger and hash, and not before the latest. Checkpoints never go
    /// back in size or time, and two of one size and moment must say the
    /// same (so old ones cannot be replayed, or two genuine ones alternated).
    Result<protocol::SignedCheckpoint> check_signed_checkpoint(ByteView encoded) const {
        auto checkpoint = protocol::parse_checkpoint(encoded);
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        if (!protocol::verify_checkpoint(*provider, *checkpoint, state.log_key())) {
            return fail(Errc::verification_failed, "a checkpoint is not signed by the log key");
        }
        const protocol::Checkpoint& c = checkpoint->checkpoint;
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

    Status require_usable() const {
        if (failed.load()) {
            return fail(Errc::invalid_argument, "a write failed earlier; reopen the ledger");
        }
        return {};
    }

    /// Ledger time for the next registration: never earlier than the last.
    protocol::Timestamp next_time() const { return std::max(clock->now(), last_registered_at); }

    Status require_log_key(const crypto::Signer& log_key) const {
        if (log_key.public_key() != state.log_key()) {
            return fail(Errc::invalid_argument, "the signer is not this ledger's log key");
        }
        return {};
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
    if (!fs.exists(statements_file)) {
        return fail(Errc::not_found, "no ledger exists here");
    }
    auto log = RecordLog::open(fs, statements_file);
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
    // The latest signed checkpoint, whose state commitment is checked when
    // the replay reaches its size.
    auto checkpoints = RecordLog::open(fs, checkpoints_file);
    if (!checkpoints) {
        return std::unexpected(checkpoints.error());
    }
    std::optional<protocol::SignedCheckpoint> latest;
    if (checkpoints->count() > 0) {
        auto bytes = checkpoints->read(checkpoints->count() - 1);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checkpoint = protocol::parse_checkpoint(*bytes);
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        if (auto s = protocol::verify_checkpoint(provider, *checkpoint, state->log_key()); !s) {
            return fail(Errc::malformed, "the latest checkpoint is not signed by the log key");
        }
        latest = std::move(*checkpoint);
    }
    auto cosignatures = RecordLog::open(fs, cosignatures_file);
    if (!cosignatures) {
        return std::unexpected(cosignatures.error());
    }
    auto state_tree = protocol::StateTree::create(provider, state->hash());
    if (!state_tree) {
        return std::unexpected(state_tree.error());
    }
    auto impl = std::make_unique<Impl>(clock, provider, std::move(*log), std::move(*checkpoints),
                                       std::move(*cosignatures), std::move(*state), std::move(tree),
                                       std::move(*state_tree));
    impl->last_registered_at = first->registered_at;

    // Replay: every later entry must pass validation against the state
    // before it, at the time it was registered, and every state commitment
    // must match the state (kept in an incremental tree).
    // Signatures are checked on all cores; the state moves in log order.
    if (const auto replayed = impl->replay_log(1, impl->log.count()); replayed.error) {
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

std::vector<Result<Registration>>
Ledger::submit_batch(std::span<const ByteView> signed_statements) {
    const std::size_t n = signed_statements.size();
    std::vector<Result<Registration>> results;
    results.reserve(n);
    if (auto s = impl_->require_usable(); !s) {
        for (std::size_t i = 0; i < n; ++i) {
            results.emplace_back(std::unexpected(s.error()));
        }
        return results;
    }
    // Parse and check signatures on all cores. (Only this thread changes the
    // ledger, so reading the state here needs no lock.)
    std::vector<std::optional<protocol::SignedStatement>> parsed(n);
    std::vector<std::optional<Error>> errors(n);
    parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
            if (auto st =
                    protocol::parse_statement(*impl_->provider, signed_statements[i], hash())) {
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
    impl_->pre_verify(pointers, checks);

    // Validate and apply in order, each statement against the state the ones
    // before it left.
    const protocol::Timestamp now = impl_->next_time();
    const std::uint64_t first = impl_->tree.size();
    std::vector<Bytes> entries;
    {
        const std::unique_lock lock(impl_->state_mutex);
        for (std::size_t i = 0; i < n; ++i) {
            if (errors[i]) {
                results.emplace_back(std::unexpected(*errors[i]));
                continue;
            }
            const protocol::SignedStatement& statement = *parsed[i];
            if (const auto index = impl_->state.statement_index(statement.id)) {
                // Already registered: before this batch, or earlier in it.
                protocol::Timestamp at = now;
                if (*index < first) {
                    auto bytes = impl_->log.read(*index);
                    auto entry = bytes ? protocol::decode_log_entry(*bytes)
                                       : Result<protocol::LogEntry>(std::unexpected(bytes.error()));
                    if (!entry) {
                        results.emplace_back(std::unexpected(entry.error()));
                        continue;
                    }
                    at = entry->registered_at;
                }
                results.emplace_back(Registration{statement.id, *index, at, false});
                continue;
            }
            if (auto s = impl_->state.validate(*impl_->provider, statement, now,
                                               checks[i] ? &*checks[i] : nullptr);
                !s) {
                results.emplace_back(std::unexpected(s.error()));
                continue;
            }
            auto encoded = protocol::encode_log_entry({statement.id, now, statement.encoded});
            if (!encoded) {
                results.emplace_back(std::unexpected(encoded.error()));
                continue;
            }
            const std::uint64_t index = first + entries.size();
            if (auto s = impl_->state.apply(*impl_->provider, statement, index); !s) {
                // The state moved partway: nothing of this batch may be
                // written, and the ledger must be reopened.
                impl_->failed = true;
                results.emplace_back(std::unexpected(s.error()));
                for (auto& r : results) {
                    if (r && r->index >= first) {
                        r = std::unexpected(s.error());
                    }
                }
                while (results.size() < n) {
                    results.emplace_back(std::unexpected(s.error()));
                }
                return results;
            }
            entries.push_back(std::move(*encoded));
            results.emplace_back(Registration{statement.id, index, now, true});
        }
    }
    if (entries.empty()) {
        return results;
    }
    // One sync for the batch, with no lock held: readers carry on, and see
    // the entries once they are durable. If the files cannot catch up with
    // the state, the ledger must be reopened.
    const std::vector<ByteView> views(entries.begin(), entries.end());
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
        for (auto& r : results) {
            if (r && r->index >= first) {
                r = std::unexpected(written.error());
            }
        }
        return results;
    }
    impl_->last_registered_at = now;
    return results;
}

Status Ledger::append_entries(std::span<const Bytes> entries) {
    if (auto s = impl_->require_usable(); !s) {
        return s;
    }
    // Check and apply in memory (signatures on all cores), then write the
    // valid prefix at once: one sync. Entries before a bad one are kept.
    const std::vector<ByteView> views(entries.begin(), entries.end());
    Impl::Replayed replayed;
    {
        const std::unique_lock lock(impl_->state_mutex);
        replayed = impl_->replay(views, impl_->tree.size());
    }
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

Result<protocol::SignedCheckpoint> Ledger::verify_checkpoint(ByteView signed_checkpoint) const {
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->check_signed_checkpoint(signed_checkpoint);
}

bool Ledger::outdated() const {
    // A refresh swaps the logs' file handles under this lock.
    const std::shared_lock lock(impl_->log_mutex);
    return impl_->log.outdated() || impl_->checkpoints.outdated() || impl_->cosignatures.outdated();
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

Result<std::vector<protocol::SignedCheckpoint>> read_checkpoints(const RecordLog& log) {
    std::vector<protocol::SignedCheckpoint> out;
    for (std::uint64_t i = 0; i < log.count(); ++i) {
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

Result<std::vector<StoredCosignature>> read_cosignatures(const RecordLog& log) {
    std::vector<StoredCosignature> out;
    for (std::uint64_t i = 0; i < log.count(); ++i) {
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

} // namespace

Result<std::vector<protocol::SignedCheckpoint>> Ledger::checkpoints() const {
    const std::shared_lock lock(impl_->log_mutex);
    return read_checkpoints(impl_->checkpoints);
}

Status Ledger::add_cosignature(ByteView encoded, const crypto::PublicKey& witness) {
    if (witness == impl_->state.log_key()) {
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
    auto all = read_checkpoints(impl_->checkpoints);
    if (!all) {
        return std::unexpected(all.error());
    }
    if (std::ranges::none_of(*all, [&](const protocol::SignedCheckpoint& c) {
            return c.checkpoint == cosignature->checkpoint;
        })) {
        return fail(Errc::not_found, "the cosignature is not of a checkpoint of this ledger");
    }
    auto stored = read_cosignatures(impl_->cosignatures);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    if (std::ranges::any_of(*stored, [&](const StoredCosignature& s) {
            return s.witness == witness && s.cosignature.checkpoint == cosignature->checkpoint;
        })) {
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
    return {};
}

Result<std::vector<StoredCosignature>> Ledger::cosignatures() const {
    const std::shared_lock lock(impl_->log_mutex);
    return read_cosignatures(impl_->cosignatures);
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
        if (!protocol::verify_checkpoint(*impl_->provider, checkpoint, impl_->state.log_key())) {
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
    return AuditReport{
        .entries = size,
        .checkpoints = all->size(),
        .cosignatures = stored->size(),
        .actors = impl_->state.actors().size(),
        .delegations = impl_->state.delegations().size(),
        .records = impl_->state.records().size(),
        .unchecked_entries = size - previous_size,
    };
}

Result<protocol::SignedCheckpoint> Ledger::checkpoint(const crypto::Signer& log_key) {
    if (auto s = impl_->require_usable(); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = impl_->require_log_key(log_key); !s) {
        return std::unexpected(s.error());
    }
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
    // await its checkpoint (written, or copied, a moment later).
    if (impl.tree_commitment_index + 1 != impl.latest_checkpoint->checkpoint.tree_size) {
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
    return protocol::issue_receipt(log_key, *impl.provider, impl.state.hash(), checkpoint.root,
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
    if (auto s = impl_->require_log_key(log_key); !s) {
        return std::unexpected(s.error());
    }
    const std::shared_lock lock(impl_->log_mutex);
    return issue(*impl_, log_key, index);
}

Result<protocol::EvidenceBundle> Ledger::export_evidence(const crypto::Signer& log_key,
                                                         const protocol::Id& record_id) const {
    if (auto s = impl_->require_log_key(log_key); !s) {
        return std::unexpected(s.error());
    }
    // One consistent view of the state and the log throughout.
    const std::shared_lock state_lock(impl_->state_mutex);
    const std::shared_lock log_lock(impl_->log_mutex);
    const protocol::LedgerState& state = impl_->state;
    const protocol::RecordState* record = state.record(record_id);
    if (record == nullptr) {
        return fail(Errc::not_found, "no record with this id");
    }
    // Everything about it must be covered by the latest checkpoint (which
    // also rules out what is not durable yet).
    const auto& checkpoint = impl_->latest_checkpoint;
    if (!checkpoint || std::ranges::any_of(record->history, [&](std::uint64_t index) {
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
    for (const std::uint64_t index : record->history) {
        need(index);
    }

    // Under a checkpoint that commits to the state, prove the complete history
    // of everything involved, and include all of it.
    std::vector<protocol::StateProof> proofs;
    const bool committed = checkpoint && impl_->checkpoint_commitment;
    if (committed) {
        std::vector<protocol::Statement> events;
        for (const std::uint64_t index : record->history) {
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
    return bundle;
}

} // namespace cexchain::ledger
