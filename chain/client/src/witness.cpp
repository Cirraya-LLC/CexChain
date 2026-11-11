// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

#include <kanhe/client/support.hpp>
#include <kanhe/client/witness.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/ledger/storage.hpp>

// Like KANHE_TRY, for the non-throwing witness path.
#define KANHE_APP_TRY(name, expr)                                                                  \
    auto name##_result = (expr);                                                                   \
    if (!name##_result) {                                                                          \
        return std::unexpected(name##_result.error());                                             \
    }                                                                                              \
    auto name = std::move(*name##_result)

namespace kanhe::client {

std::filesystem::path witness_state_path(const std::filesystem::path& dir,
                                         const protocol::Id& ledger) {
    return dir / (hex_id(ledger) + ".cbor");
}

Bytes encode_witness_state(const WitnessState& s) {
    cbor::Map map{{cbor::Value::integer(1), cbor::Value::bytes(s.log.ledger_id.bytes())},
                  {cbor::Value::integer(2), protocol::encode_public_key(s.log.log_key)},
                  {cbor::Value::integer(3), cbor::Value::text(s.name)},
                  {cbor::Value::integer(4), cbor::Value::unsigned_integer(s.log.size)}};
    if (s.log.size > 0) {
        map.push_back({cbor::Value::integer(5), cbor::Value::bytes(s.log.root.bytes())});
    }
    if (s.log.tree_hash) {
        map.push_back(
            {cbor::Value::integer(6), cbor::Value::integer(crypto::cose_id(*s.log.tree_hash))});
    }
    if (s.cosigned_at) {
        map.push_back({cbor::Value::integer(7), cbor::Value::unsigned_integer(*s.cosigned_at)});
    }
    if (s.log.root_key) {
        map.push_back({cbor::Value::integer(8), protocol::encode_public_key(*s.log.root_key)});
    }
    if (s.log.last_rotation > 0) {
        map.push_back(
            {cbor::Value::integer(9), cbor::Value::unsigned_integer(s.log.last_rotation)});
    }
    return unwrap(cbor::encode(cbor::Value::map(std::move(map))), "encoding the witness state");
}

WitnessState decode_witness_state(const std::filesystem::path& path) {
    const auto value = unwrap(cbor::decode(read_file(path)), "reading " + path.string());
    auto corrupted = [&] {
        return ActionError{"the witness state " + path.string() + " is corrupted"};
    };
    const cbor::Value* id = value.find(1);
    const cbor::Value* key = value.find(2);
    const cbor::Value* name = value.find(3);
    const cbor::Value* size = value.find(4);
    if (id == nullptr || id->as_bytes() == nullptr || key == nullptr || name == nullptr ||
        name->as_text() == nullptr || size == nullptr || !size->as_uint64()) {
        throw corrupted();
    }
    WitnessState s;
    s.log.ledger_id = unwrap(protocol::to_id(*id->as_bytes()), "witness state");
    s.log.log_key = unwrap(protocol::decode_public_key(*key), "witness state");
    s.name = *name->as_text();
    s.log.size = *size->as_uint64();
    if (const cbor::Value* root = value.find(5)) {
        if (root->as_bytes() == nullptr) {
            throw corrupted();
        }
        s.log.root = unwrap(crypto::Digest::from_bytes(*root->as_bytes()), "witness state");
    }
    if (const cbor::Value* hash = value.find(6)) {
        const auto alg =
            hash->as_int64() ? crypto::hash_alg_from_cose(*hash->as_int64()) : std::nullopt;
        if (!alg) {
            throw corrupted();
        }
        s.log.tree_hash = *alg;
    }
    if (const cbor::Value* at = value.find(7); at != nullptr && at->as_uint64()) {
        s.cosigned_at = *at->as_uint64();
    }
    if (const cbor::Value* root_key = value.find(8)) {
        s.log.root_key = unwrap(protocol::decode_public_key(*root_key), "witness state");
    }
    if (const cbor::Value* rotation = value.find(9)) {
        if (!rotation->as_uint64()) {
            throw corrupted();
        }
        s.log.last_rotation = *rotation->as_uint64();
    }
    if ((s.log.size > 0) == s.log.root.empty()) {
        throw corrupted();
    }
    return s;
}

std::vector<WitnessState> witness_states(const std::filesystem::path& dir) {
    std::vector<WitnessState> out;
    if (!std::filesystem::is_directory(dir)) {
        throw ActionError{"no witness directory at " + dir.string() +
                          " (create one with kanhe witness add-log)"};
    }
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == ".cbor") {
            files.push_back(entry.path());
        }
    }
    std::ranges::sort(files);
    for (const auto& file : files) {
        out.push_back(decode_witness_state(file));
    }
    return out;
}

WitnessState state_from_genesis(ByteView genesis, std::string name,
                                const std::optional<protocol::Id>& pinned) {
    const auto keys = unwrap(protocol::keys_from_genesis(shared_provider(), genesis),
                             "reading the genesis entry");
    if (pinned && *pinned != keys.ledger_id) {
        throw ActionError{"the genesis entry is not ledger " + hex_id(*pinned) + "'s"};
    }
    WitnessState state;
    state.log.ledger_id = keys.ledger_id;
    state.log.log_key = keys.log_key();
    state.log.root_key = keys.root_key;
    state.log.tree_hash = keys.hash;
    state.name = std::move(name);
    return state;
}

void add_witnessed(const std::filesystem::path& dir, const WitnessState& state) {
    std::filesystem::create_directories(dir);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the witness directory");
    const std::filesystem::path path = witness_state_path(dir, state.log.ledger_id);
    if (std::filesystem::exists(path)) {
        throw ActionError{"this witness already follows ledger " + hex_id(state.log.ledger_id)};
    }
    write_file(path, encode_witness_state(state), false);
}

Result<Bytes> witness_cosign(const std::filesystem::path& dir, const crypto::Signer& key,
                             ByteView request_bytes, protocol::Timestamp now) {
    if (!std::filesystem::is_directory(dir)) {
        return fail(Errc::not_found, "no witness directory");
    }
    auto lock = ledger::DirectoryLock::acquire(dir);
    if (!lock) {
        return std::unexpected(lock.error());
    }
    KANHE_APP_TRY(request, protocol::decode_cosign_request(request_bytes));
    KANHE_APP_TRY(checkpoint, protocol::parse_checkpoint(request.checkpoint));
    const std::filesystem::path path = witness_state_path(dir, checkpoint.checkpoint.ledger_id);
    if (!std::filesystem::exists(path)) {
        return fail(Errc::not_found, "this witness does not follow the ledger");
    }
    WitnessState state;
    try {
        state = decode_witness_state(path);
    } catch (const ActionError&) {
        return fail(Errc::malformed, "the witness state is corrupted");
    }
    if (key.public_key() == state.log.log_key) {
        return fail(Errc::invalid_argument, "a ledger's log key cannot witness the ledger");
    }
    const auto& provider = shared_provider();
    // The checkpoint cosigned last, asked for again: cosign it again.
    if (state.log.size > 0 && checkpoint.checkpoint.tree_size == state.log.size &&
        checkpoint.checkpoint.root == state.log.root &&
        checkpoint.checkpoint.ledger_id == state.log.ledger_id &&
        protocol::verify_checkpoint(provider, checkpoint, state.log.log_key)) {
        KANHE_APP_TRY(again, protocol::cosign_checkpoint(key, provider, checkpoint.checkpoint));
        return again.encoded;
    }
    KANHE_APP_TRY(approved, protocol::check_cosign_request(provider, state.log, request));
    if (key.public_key() == approved.log.log_key) {
        return fail(Errc::invalid_argument, "a ledger's log key cannot witness the ledger");
    }
    KANHE_APP_TRY(cosigned,
                  protocol::cosign_checkpoint(key, provider, approved.checkpoint.checkpoint));
    state.log = std::move(approved.log);
    state.cosigned_at = now;
    try {
        write_file(path, encode_witness_state(state), false);
    } catch (const ActionError&) {
        return fail(Errc::unavailable, "cannot write the witness state");
    }
    return cosigned.encoded;
}

} // namespace kanhe::client
