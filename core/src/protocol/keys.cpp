// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <variant>

#include <cexchain/core/protocol/keys.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/statement.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

/// The rotation an entry makes, if any: the new key and whether it is the
/// log key (otherwise the root key).
struct Rotation {
    SignedStatement statement;
    crypto::PublicKey key;
    bool log = false;
};

Result<std::optional<Rotation>> rotation_in(const crypto::Provider& provider,
                                            const LedgerKeys& keys, ByteView encoded) {
    CEXCHAIN_TRY(LogEntry entry, decode_log_entry(encoded));
    if (entry.is_state_commitment()) {
        return std::nullopt;
    }
    CEXCHAIN_TRY(SignedStatement statement, parse_statement(provider, entry.statement, keys.hash));
    if (statement.id != entry.statement_id) {
        return fail(Errc::verification_failed, "a log entry has the wrong statement id");
    }
    const Statement& s = statement.statement;
    if (s.ledger_id != keys.ledger_id || s.actor_id != keys.ledger_id) {
        return std::nullopt; // not the organization's
    }
    if (const auto* log = std::get_if<LedgerRotateLogKeyBody>(&s.body)) {
        crypto::PublicKey key = log->key;
        return Rotation{std::move(statement), std::move(key), true};
    }
    if (const auto* root = std::get_if<ActorRotateKeyBody>(&s.body);
        root != nullptr && root->actor == keys.ledger_id) {
        crypto::PublicKey key = root->key;
        return Rotation{std::move(statement), std::move(key), false};
    }
    return std::nullopt;
}

} // namespace

const crypto::PublicKey& key_in_effect(std::span<const KeyEpoch> epochs, std::uint64_t tree_size) {
    // Epochs ascend by index; the genesis epoch (index 0) is always in effect.
    const auto after = std::ranges::lower_bound(epochs, tree_size, {}, &KeyEpoch::index);
    return after == epochs.begin() ? epochs.front().key : std::prev(after)->key;
}

Result<LedgerKeys> keys_from_genesis(const crypto::Provider& provider, ByteView genesis_entry) {
    CEXCHAIN_TRY(LogEntry entry, decode_log_entry(genesis_entry));
    if (entry.is_state_commitment()) {
        return fail(Errc::verification_failed, "a ledger begins with its genesis statement");
    }
    CEXCHAIN_TRY(SignedStatement genesis, parse_statement(provider, entry.statement));
    const auto* body = std::get_if<GenesisBody>(&genesis.statement.body);
    if (body == nullptr || genesis.id != entry.statement_id) {
        return fail(Errc::verification_failed, "the entry is not a ledger's genesis");
    }
    if (auto s = verify_statement(provider, genesis, body->root_key); !s) {
        return fail(Errc::verification_failed, "the genesis statement does not verify");
    }
    return LedgerKeys{genesis.id, genesis.hash_alg, body->root_key, {{0, body->log_key}}, 0};
}

bool is_key_rotation(const crypto::Provider& provider, const LedgerKeys& keys, ByteView entry) {
    const auto rotation = rotation_in(provider, keys, entry);
    return rotation && rotation->has_value();
}

Status follow_key_rotation(const crypto::Provider& provider, LedgerKeys& keys, std::uint64_t index,
                           ByteView entry) {
    auto rotation = rotation_in(provider, keys, entry);
    if (!rotation) {
        return std::unexpected(rotation.error());
    }
    if (!*rotation) {
        return {};
    }
    const Rotation& r = **rotation;
    if (index == 0 || index <= keys.last_rotation) {
        return fail(Errc::verification_failed, "key rotations must follow each other in log order");
    }
    auto root_kid = key_id(provider, keys.hash, keys.root_key);
    if (!root_kid || r.statement.kid != *root_kid || r.statement.statement.delegation_id ||
        !verify_statement(provider, r.statement, keys.root_key)) {
        return fail(Errc::verification_failed,
                    "a key rotation is not signed by the organization's root key");
    }
    if (crypto::is_weak_public_key(r.key.algorithm, r.key.bytes)) {
        return fail(Errc::verification_failed, "a key rotation names a weak key");
    }
    const bool was_log_key =
        std::ranges::any_of(keys.log_keys, [&](const KeyEpoch& e) { return e.key == r.key; });
    if (was_log_key) {
        return fail(Errc::verification_failed, "a key rotation names a key used as a log key");
    }
    if (r.log) {
        keys.log_keys.push_back({index, r.key});
    } else {
        keys.root_key = r.key;
    }
    keys.last_rotation = index;
    return {};
}

} // namespace cexchain::protocol
