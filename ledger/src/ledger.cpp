// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <set>
#include <utility>
#include <variant>

#include <cexchain/ledger/ledger.hpp>

namespace cexchain::ledger {

namespace {

constexpr std::string_view statements_file = "statements";
constexpr std::string_view checkpoints_file = "checkpoints";

} // namespace

struct Ledger::Impl {
    Impl(Clock& clock_, const crypto::Provider& provider_, RecordLog log_, RecordLog checkpoints_,
         protocol::LedgerState state_, merkle::Tree tree_)
        : clock(&clock_), provider(&provider_), log(std::move(log_)),
          checkpoints(std::move(checkpoints_)), state(std::move(state_)), tree(std::move(tree_)) {}

    Clock* clock;
    const crypto::Provider* provider;
    RecordLog log;
    RecordLog checkpoints;
    protocol::LedgerState state;
    merkle::Tree tree;
    std::optional<protocol::SignedCheckpoint> latest_checkpoint;
    protocol::Timestamp last_registered_at = 0;

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
    protocol::Timestamp last_time = first->registered_at;

    // Replay: every later entry must pass validation against the state
    // before it, at the time it was registered.
    for (std::uint64_t index = 1; index < log->count(); ++index) {
        auto bytes = log->read(index);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto entry = protocol::decode_log_entry(*bytes);
        if (!entry) {
            return std::unexpected(entry.error());
        }
        if (entry->registered_at < last_time) {
            return fail(Errc::malformed, "log entries go back in time");
        }
        auto statement = protocol::parse_statement(provider, entry->statement, state->hash());
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (statement->id != entry->statement_id) {
            return fail(Errc::malformed, "a log entry has the wrong statement id");
        }
        if (auto s = state->validate(provider, *statement, entry->registered_at); !s) {
            return fail(Errc::malformed, "a logged statement does not pass validation on replay");
        }
        if (auto s = state->apply(provider, *statement, index); !s) {
            return std::unexpected(s.error());
        }
        if (auto s = tree.append(*bytes); !s) {
            return std::unexpected(s.error());
        }
        last_time = entry->registered_at;
    }

    auto checkpoints = RecordLog::open(fs, checkpoints_file);
    if (!checkpoints) {
        return std::unexpected(checkpoints.error());
    }
    auto impl = std::make_unique<Impl>(clock, provider, std::move(*log), std::move(*checkpoints),
                                       std::move(*state), std::move(tree));
    impl->last_registered_at = last_time;

    // The log must contain everything the latest signed checkpoint attests.
    if (impl->checkpoints.count() > 0) {
        auto bytes = impl->checkpoints.read(impl->checkpoints.count() - 1);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto checkpoint = protocol::parse_checkpoint(*bytes);
        if (!checkpoint) {
            return std::unexpected(checkpoint.error());
        }
        if (auto s = protocol::verify_checkpoint(provider, *checkpoint, impl->state.log_key());
            !s) {
            return fail(Errc::malformed, "the latest checkpoint is not signed by the log key");
        }
        const protocol::Checkpoint& c = checkpoint->checkpoint;
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
        impl->latest_checkpoint = std::move(*checkpoint);
    }
    return Ledger(std::move(impl));
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

Result<Bytes> Ledger::entry(std::uint64_t index) const {
    return impl_->log.read(index);
}

Result<crypto::Digest> Ledger::root(std::uint64_t tree_size) const {
    return impl_->tree.root(tree_size);
}

Result<std::vector<crypto::Digest>> Ledger::consistency_proof(std::uint64_t old_size,
                                                              std::uint64_t new_size) const {
    return impl_->tree.consistency_proof(old_size, new_size);
}

Result<protocol::SignedCheckpoint> Ledger::checkpoint(const crypto::Signer& log_key) {
    if (auto s = impl_->require_log_key(log_key); !s) {
        return std::unexpected(s.error());
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
    return signed_checkpoint;
}

const std::optional<protocol::SignedCheckpoint>& Ledger::latest_checkpoint() const noexcept {
    return impl_->latest_checkpoint;
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
    };
    auto need_delegation = [&](const protocol::Id& id) {
        if (const protocol::DelegationState* d = state.delegation(id)) {
            need(d->granted_at_index);
        }
    };
    for (const std::uint64_t index : record->history) {
        need(index);
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
                                     std::is_same_v<Body, protocol::ActorRevokeBody>) {
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

    const auto& checkpoint = impl_->latest_checkpoint;
    if (!checkpoint || *needed.rbegin() >= checkpoint->checkpoint.tree_size) {
        return fail(Errc::not_found, "no checkpoint covers the record's statements yet");
    }
    protocol::EvidenceBundle bundle;
    bundle.record = record_id;
    bundle.checkpoint = checkpoint->encoded;
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
    return bundle;
}

} // namespace cexchain::ledger
