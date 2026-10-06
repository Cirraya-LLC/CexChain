// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <set>
#include <utility>
#include <variant>

#include <cexchain/core/protocol/state_tree.hpp>
#include <cexchain/ledger/ledger.hpp>

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
         RecordLog cosignatures_, protocol::LedgerState state_, merkle::Tree tree_)
        : clock(&clock_), provider(&provider_), log(std::move(log_)),
          checkpoints(std::move(checkpoints_)), cosignatures(std::move(cosignatures_)),
          state(std::move(state_)), tree(std::move(tree_)) {}

    Clock* clock;
    const crypto::Provider* provider;
    RecordLog log;
    RecordLog checkpoints;
    RecordLog cosignatures;
    protocol::LedgerState state;
    merkle::Tree tree;
    std::optional<protocol::SignedCheckpoint> latest_checkpoint;
    /// The state commitment the latest checkpoint ends with, and its leaves.
    std::optional<protocol::StateCommitment> checkpoint_commitment;
    std::vector<protocol::StateLeaf> checkpoint_leaves;
    protocol::Timestamp last_registered_at = 0;
    /// The state leaves at the most recent state commitment replayed, kept
    /// until a checkpoint that ends with it arrives.
    struct Snapshot {
        std::uint64_t index = 0;
        std::vector<protocol::StateLeaf> leaves;
        protocol::StateCommitment commitment;
    };
    std::optional<Snapshot> last_commitment;
    /// Set when a write failed after the in-memory views moved ahead of the
    /// files; the ledger must be reopened.
    bool failed = false;

    /// A log entry checked against the current state, ready to apply.
    struct CheckedEntry {
        protocol::LogEntry entry;
        std::optional<protocol::SignedStatement> statement;
        std::optional<protocol::SignedStateCommitment> commitment;
    };

    /// Checks that `bytes` may be the log entry at `index`, the next one:
    /// registered no earlier than the entry before it, and either a statement
    /// that passes validation at its registration time or a state commitment,
    /// signed by the log key, of exactly the current state.
    Result<CheckedEntry> check_entry(ByteView bytes, std::uint64_t index) const {
        auto entry = protocol::decode_log_entry(bytes);
        if (!entry) {
            return std::unexpected(entry.error());
        }
        if (entry->registered_at < last_registered_at) {
            return fail(Errc::verification_failed, "log entries go back in time");
        }
        if (entry->is_state_commitment()) {
            auto commitment = protocol::parse_state_commitment(*provider, entry->state_commitment);
            if (!commitment || commitment->id != entry->statement_id ||
                !protocol::check_state_commitment(*provider, state, *commitment, index)) {
                return fail(Errc::verification_failed,
                            "a state commitment in the log does not match the log");
            }
            return CheckedEntry{std::move(*entry), std::nullopt, std::move(*commitment)};
        }
        auto statement = protocol::parse_statement(*provider, entry->statement, state.hash());
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (statement->id != entry->statement_id) {
            return fail(Errc::verification_failed, "a log entry has the wrong statement id");
        }
        if (auto s = state.validate(*provider, *statement, entry->registered_at); !s) {
            return fail(Errc::verification_failed,
                        "a logged statement does not pass validation on replay");
        }
        return CheckedEntry{std::move(*entry), std::move(*statement), std::nullopt};
    }

    /// Applies a checked entry at `index` to the state and the tree. With
    /// `snapshot`, a state commitment's leaves are kept for state proofs.
    Status apply_entry(const CheckedEntry& checked, ByteView bytes, std::uint64_t index,
                       bool snapshot) {
        if (checked.statement) {
            if (auto s = state.apply(*provider, *checked.statement, index); !s) {
                return s;
            }
        } else if (snapshot) {
            last_commitment =
                Snapshot{index, protocol::state_leaves(state), checked.commitment->commitment};
        }
        if (auto s = tree.append(bytes); !s) {
            return std::unexpected(s.error());
        }
        last_registered_at = checked.entry.registered_at;
        return {};
    }

    /// Makes `checkpoint` the latest, with the state leaves it commits to if
    /// they were kept.
    void adopt_checkpoint(protocol::SignedCheckpoint checkpoint) {
        if (last_commitment && last_commitment->index + 1 == checkpoint.checkpoint.tree_size) {
            checkpoint_leaves = last_commitment->leaves;
            checkpoint_commitment = last_commitment->commitment;
        } else {
            checkpoint_leaves.clear();
            checkpoint_commitment.reset();
        }
        latest_checkpoint = std::move(checkpoint);
    }

    /// Checks a signed checkpoint against the log key and this log: for this
    /// ledger, no smaller than the latest, and with the tree's root.
    Result<protocol::SignedCheckpoint> check_checkpoint(ByteView encoded) const {
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
        if (c.tree_size > tree.size() ||
            (latest_checkpoint && c.tree_size < latest_checkpoint->checkpoint.tree_size)) {
            return fail(Errc::verification_failed, "a checkpoint is out of order with the log");
        }
        auto root = tree.root(c.tree_size);
        if (!root) {
            return std::unexpected(root.error());
        }
        if (*root != c.root) {
            return fail(Errc::verification_failed, "a checkpoint disagrees with the log");
        }
        return checkpoint;
    }

    Status require_usable() const {
        if (failed) {
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
    auto impl =
        std::make_unique<Impl>(clock, provider, std::move(*log), std::move(*checkpoints),
                               std::move(*cosignatures), std::move(*state), std::move(tree));
    impl->last_registered_at = first->registered_at;

    // Replay: every later entry must pass validation against the state
    // before it, at the time it was registered. Only the state commitment
    // the latest checkpoint ends with is kept, for proofs.
    for (std::uint64_t index = 1; index < impl->log.count(); ++index) {
        auto bytes = impl->log.read(index);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checked = impl->check_entry(*bytes, index);
        if (!checked) {
            if (checked.error().code == Errc::verification_failed) {
                return fail(Errc::malformed, checked.error().detail);
            }
            return std::unexpected(checked.error());
        }
        const bool snapshot = latest && latest->checkpoint.tree_size == index + 1;
        if (auto s = impl->apply_entry(*checked, *bytes, index, snapshot); !s) {
            return std::unexpected(s.error());
        }
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
    return impl_->state.ledger_id();
}

crypto::HashAlg Ledger::hash() const noexcept {
    return impl_->state.hash();
}

std::uint64_t Ledger::size() const noexcept {
    return impl_->tree.size();
}

Result<Registration> Ledger::submit(ByteView signed_statement) {
    if (auto s = impl_->require_usable(); !s) {
        return std::unexpected(s.error());
    }
    auto statement = protocol::parse_statement(*impl_->provider, signed_statement, hash());
    if (!statement) {
        return std::unexpected(statement.error());
    }
    if (const auto index = impl_->state.statement_index(statement->id)) {
        auto bytes = impl_->log.read(*index);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto entry = protocol::decode_log_entry(*bytes);
        if (!entry) {
            return std::unexpected(entry.error());
        }
        return Registration{statement->id, *index, entry->registered_at, false};
    }

    const protocol::Timestamp now = impl_->next_time();
    if (auto s = impl_->state.validate(*impl_->provider, *statement, now); !s) {
        return std::unexpected(s.error());
    }
    const protocol::LogEntry entry{statement->id, now, statement->encoded};
    auto encoded = protocol::encode_log_entry(entry);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    const std::uint64_t index = size();
    if (auto s = impl_->log.append(*encoded); !s) {
        return std::unexpected(s.error());
    }
    // The entry is durable. Update the in-memory views; these cannot fail for
    // a statement that passed validation unless the process is out of memory.
    if (auto s = impl_->tree.append(*encoded); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = impl_->state.apply(*impl_->provider, *statement, index); !s) {
        return std::unexpected(s.error());
    }
    impl_->last_registered_at = now;
    return Registration{statement->id, index, now, true};
}

Status Ledger::append_entries(std::span<const Bytes> entries) {
    if (auto s = impl_->require_usable(); !s) {
        return s;
    }
    // Check and apply in memory, then write the whole batch at once: one
    // sync instead of one per entry. Entries before a bad one are kept.
    std::vector<ByteView> batch;
    Status outcome;
    for (const Bytes& bytes : entries) {
        const std::uint64_t index = size();
        auto checked = impl_->check_entry(bytes, index);
        if (!checked) {
            outcome = std::unexpected(checked.error());
            break;
        }
        if (auto s = impl_->apply_entry(*checked, bytes, index, true); !s) {
            impl_->failed = true;
            return s;
        }
        batch.push_back(bytes);
    }
    if (!batch.empty()) {
        if (auto s = impl_->log.append(batch); !s) {
            impl_->failed = true;
            return s;
        }
    }
    return outcome;
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
    if (auto s = impl_->checkpoints.append(checkpoint->encoded); !s) {
        return s;
    }
    impl_->adopt_checkpoint(std::move(*checkpoint));
    return {};
}

Result<RefreshReport> Ledger::refresh(FileSystem& fs, bool recover) {
    if (auto s = impl_->require_usable(); !s) {
        return std::unexpected(s.error());
    }
    RefreshReport report;
    const std::uint64_t old_size = impl_->log.count();
    auto added = impl_->log.refresh(fs, statements_file, recover);
    if (!added) {
        return std::unexpected(added.error());
    }
    for (std::uint64_t index = old_size; index < impl_->log.count(); ++index) {
        auto bytes = impl_->log.read(index);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checked = impl_->check_entry(*bytes, index);
        if (!checked) {
            // Another process wrote an entry that does not validate.
            impl_->failed = true;
            return fail(Errc::malformed, checked.error().detail);
        }
        if (auto s = impl_->apply_entry(*checked, *bytes, index, true); !s) {
            impl_->failed = true;
            return std::unexpected(s.error());
        }
        ++report.entries;
    }
    const std::uint64_t old_checkpoints = impl_->checkpoints.count();
    if (auto s = impl_->checkpoints.refresh(fs, checkpoints_file, recover); !s) {
        return std::unexpected(s.error());
    }
    for (std::uint64_t i = old_checkpoints; i < impl_->checkpoints.count(); ++i) {
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
    auto cosignatures = impl_->cosignatures.refresh(fs, cosignatures_file, recover);
    if (!cosignatures) {
        return std::unexpected(cosignatures.error());
    }
    report.cosignatures = *cosignatures;
    return report;
}

Result<Bytes> Ledger::entry(std::uint64_t index) const {
    return impl_->log.read(index);
}

Result<crypto::Digest> Ledger::root(std::uint64_t tree_size) const {
    return impl_->tree.root(tree_size);
}

Result<std::vector<crypto::Digest>> Ledger::inclusion_proof(std::uint64_t index,
                                                            std::uint64_t tree_size) const {
    return impl_->tree.inclusion_proof(index, tree_size);
}

Result<std::vector<protocol::SignedCheckpoint>> Ledger::checkpoints() const {
    std::vector<protocol::SignedCheckpoint> out;
    for (std::uint64_t i = 0; i < impl_->checkpoints.count(); ++i) {
        auto bytes = impl_->checkpoints.read(i);
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
    auto all = checkpoints();
    if (!all) {
        return std::unexpected(all.error());
    }
    if (std::ranges::none_of(*all, [&](const protocol::SignedCheckpoint& c) {
            return c.checkpoint == cosignature->checkpoint;
        })) {
        return fail(Errc::not_found, "the cosignature is not of a checkpoint of this ledger");
    }
    auto stored = cosignatures();
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
    return impl_->cosignatures.append(*record);
}

Result<std::vector<StoredCosignature>> Ledger::cosignatures() const {
    std::vector<StoredCosignature> out;
    for (std::uint64_t i = 0; i < impl_->cosignatures.count(); ++i) {
        auto bytes = impl_->cosignatures.read(i);
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
    auto all = checkpoints();
    if (!all) {
        return std::unexpected(all.error());
    }
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
        if (c.tree_size < previous_size || c.tree_size > size()) {
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
    auto stored = cosignatures();
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
        .entries = size(),
        .checkpoints = all->size(),
        .cosignatures = stored->size(),
        .actors = impl_->state.actors().size(),
        .delegations = impl_->state.delegations().size(),
        .records = impl_->state.records().size(),
        .unchecked_entries = size() - previous_size,
    };
}

Result<std::vector<crypto::Digest>> Ledger::consistency_proof(std::uint64_t old_size,
                                                              std::uint64_t new_size) const {
    return impl_->tree.consistency_proof(old_size, new_size);
}

Result<protocol::SignedCheckpoint> Ledger::checkpoint(const crypto::Signer& log_key) {
    if (auto s = impl_->require_usable(); !s) {
        return std::unexpected(s.error());
    }
    if (auto s = impl_->require_log_key(log_key); !s) {
        return std::unexpected(s.error());
    }
    // First commit to the state in the log itself, unless the last entry
    // already is such a commitment (nothing has changed since).
    auto last = protocol::decode_log_entry(*impl_->log.read(size() - 1));
    if (!last) {
        return std::unexpected(last.error());
    }
    auto leaves = protocol::state_leaves(impl_->state);
    std::optional<protocol::StateCommitment> made;
    if (last->is_state_commitment()) {
        auto existing = protocol::parse_state_commitment(*impl_->provider, last->state_commitment);
        if (!existing) {
            return std::unexpected(existing.error());
        }
        made = existing->commitment;
    } else {
        auto state_root = protocol::state_root(*impl_->provider, hash(), leaves);
        if (!state_root) {
            return std::unexpected(state_root.error());
        }
        const protocol::Timestamp now = impl_->next_time();
        auto commitment = protocol::sign_state_commitment(
            log_key, *impl_->provider,
            protocol::StateCommitment{id(), hash(), size(), *state_root, now});
        if (!commitment) {
            return std::unexpected(commitment.error());
        }
        const protocol::LogEntry entry{commitment->id, now, {}, commitment->encoded};
        auto encoded = protocol::encode_log_entry(entry);
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        if (auto s = impl_->log.append(*encoded); !s) {
            return std::unexpected(s.error());
        }
        if (auto s = impl_->tree.append(*encoded); !s) {
            return std::unexpected(s.error());
        }
        impl_->last_registered_at = now;
        made = commitment->commitment;
    }
    auto root = impl_->tree.root();
    if (!root) {
        return std::unexpected(root.error());
    }
    const protocol::Checkpoint checkpoint{id(), hash(), size(), *root, impl_->next_time()};
    auto signed_checkpoint = protocol::sign_checkpoint(log_key, *impl_->provider, checkpoint);
    if (!signed_checkpoint) {
        return std::unexpected(signed_checkpoint.error());
    }
    if (auto s = impl_->checkpoints.append(signed_checkpoint->encoded); !s) {
        return std::unexpected(s.error());
    }
    impl_->latest_checkpoint = *signed_checkpoint;
    impl_->checkpoint_leaves = std::move(leaves);
    impl_->checkpoint_commitment = made;
    return signed_checkpoint;
}

const std::optional<protocol::SignedCheckpoint>& Ledger::latest_checkpoint() const noexcept {
    return impl_->latest_checkpoint;
}

const std::optional<protocol::StateCommitment>& Ledger::state_commitment() const noexcept {
    return impl_->checkpoint_commitment;
}

Result<protocol::StateProof> Ledger::state_proof(const protocol::Id& id) const {
    if (!impl_->latest_checkpoint || impl_->checkpoint_leaves.empty()) {
        return fail(Errc::not_found, "no checkpoint commits to the ledger state yet");
    }
    return protocol::prove_state(*impl_->provider, hash(), impl_->checkpoint_leaves, id);
}

Result<Bytes> Ledger::receipt(const crypto::Signer& log_key, std::uint64_t index) const {
    if (auto s = impl_->require_log_key(log_key); !s) {
        return std::unexpected(s.error());
    }
    if (!impl_->latest_checkpoint || index >= impl_->latest_checkpoint->checkpoint.tree_size) {
        return fail(Errc::not_found, "no checkpoint covers this entry yet");
    }
    const protocol::Checkpoint& checkpoint = impl_->latest_checkpoint->checkpoint;
    auto path = impl_->tree.inclusion_proof(index, checkpoint.tree_size);
    if (!path) {
        return std::unexpected(path.error());
    }
    return protocol::issue_receipt(log_key, *impl_->provider, hash(), checkpoint.root,
                                   protocol::InclusionProof{checkpoint.tree_size, index, *path});
}

Result<protocol::EvidenceBundle> Ledger::export_evidence(const crypto::Signer& log_key,
                                                         const protocol::Id& record_id) const {
    if (auto s = impl_->require_log_key(log_key); !s) {
        return std::unexpected(s.error());
    }
    const protocol::LedgerState& state = impl_->state;
    const protocol::RecordState* record = state.record(record_id);
    if (record == nullptr) {
        return fail(Errc::not_found, "no record with this id");
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
    const auto& checkpoint = impl_->latest_checkpoint;
    std::vector<protocol::StateProof> proofs;
    // (The snapshot exists when the checkpoint ends with a state commitment.)
    const bool committed = checkpoint && !impl_->checkpoint_leaves.empty();
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
            auto proof =
                protocol::prove_state(*impl_->provider, hash(), impl_->checkpoint_leaves, id);
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
        auto receipt = this->receipt(log_key, index);
        if (!receipt) {
            return std::unexpected(receipt.error());
        }
        bundle.entries.push_back(protocol::EvidenceEntry{std::move(*bytes), std::move(*receipt)});
    }
    auto stored = cosignatures();
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
