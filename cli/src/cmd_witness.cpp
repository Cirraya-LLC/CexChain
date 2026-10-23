// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Both sides of witnessing: the ledger operator asks for and stores
// cosignatures (checkpoint cosign-request / add-cosignature), and a witness
// keeps per-ledger state and cosigns only consistent history (witness ...).
//
// A witness directory holds one state file per ledger, <ledger id>.cbor:
//   {1: ledger id, 2: log key [alg, key], 3: name, 4: size,
//    ? 5: root, ? 6: tree hash (COSE id), ? 7: last cosigned at (ms),
//    ? 8: root key [alg, key], ? 9: index of the last key rotation followed}
// Without a root key (a log added by its log key alone) the witness cannot
// follow key rotations.

#include <print>

#include <cexchain/app/peers.hpp>
#include <cexchain/core/protocol/witness.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "witness.hpp"

// Like CEXCHAIN_TRY, for the non-throwing witness path.
#define CEXCHAIN_CLI_TRY(name, expr)                                                               \
    auto name##_result = (expr);                                                                   \
    if (!name##_result) {                                                                          \
        return std::unexpected(name##_result.error());                                             \
    }                                                                                              \
    auto name = std::move(*name##_result)

namespace cexchain::cli {

namespace {

struct WitnessState {
    protocol::WitnessedLog log;
    std::string name;
    std::optional<protocol::Timestamp> cosigned_at;
};

std::filesystem::path state_path(const std::filesystem::path& dir, const protocol::Id& ledger) {
    return dir / (hex_id(ledger) + ".cbor");
}

Bytes encode_state(const WitnessState& s) {
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

WitnessState decode_state(const std::filesystem::path& path) {
    const auto value = unwrap(cbor::decode(read_file(path)), "reading " + path.string());
    auto corrupted = [&] {
        return CommandError{"the witness state " + path.string() + " is corrupted"};
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

std::vector<WitnessState> all_states(const std::filesystem::path& dir) {
    std::vector<WitnessState> out;
    if (!std::filesystem::is_directory(dir)) {
        throw CommandError{"no witness directory at " + dir.string() +
                           " (create one with cexchain witness add-log)"};
    }
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == ".cbor") {
            files.push_back(entry.path());
        }
    }
    std::ranges::sort(files);
    for (const auto& file : files) {
        out.push_back(decode_state(file));
    }
    return out;
}

Json state_json(const WitnessState& s) {
    return {{"ledger_id", id_json(s.log.ledger_id)},
            {"name", s.name},
            {"log_key", public_key_json(s.log.log_key)},
            {"root_key", s.log.root_key ? public_key_json(*s.log.root_key) : Json(nullptr)},
            {"follows_rotations", s.log.root_key.has_value()},
            {"last_rotation", s.log.last_rotation},
            {"tree_hash", s.log.tree_hash ? Json(crypto::name(*s.log.tree_hash)) : Json(nullptr)},
            {"size", s.log.size},
            {"root", s.log.size > 0 ? Json(to_hex(s.log.root.bytes())) : Json(nullptr)},
            {"cosigned_at", s.cosigned_at ? Json(iso_time(*s.cosigned_at)) : Json(nullptr)}};
}

} // namespace

// ---------------------------------------------------------------------------
// Ledger side
// ---------------------------------------------------------------------------

int cmd_checkpoint_cosign_request(const Args& args) {
    Session session(args);
    const auto& latest = session.ledger().latest_checkpoint();
    if (!latest) {
        throw CommandError{"the ledger has no checkpoint yet (cexchain checkpoint create)"};
    }
    std::optional<node::Peer> peer;
    if (const auto name = args.get("peer")) {
        peer = peer_named(session.directory(), *name);
        if (!peer->witness_key) {
            throw CommandError{"peer " + *name +
                               " has no witness key (cexchain peer add --witness-key)"};
        }
    } else if (!args.has("witness")) {
        throw UsageError{"name the witness: --witness PUBKEY or --peer NAME"};
    }
    if (args.has("send") && !peer) {
        throw UsageError{"--send needs --peer: the request goes to the peer's API"};
    }
    if (!args.has("send") && !args.has("out")) {
        throw UsageError{"--out FILE, or --send to a peer"};
    }
    const crypto::PublicKey witness =
        peer ? *peer->witness_key : load_public_key(args.need("witness"));
    std::uint64_t old_size = 0;
    if (const auto from = args.get("from")) {
        old_size = parse_number(*from, "--from");
    } else if (const auto last =
                   unwrap(session.ledger().last_cosigned(witness), "reading cosignatures")) {
        old_size = last->tree_size;
    }
    const std::uint64_t new_size = latest->checkpoint.tree_size;
    if (old_size > new_size) {
        throw UsageError{std::format("--from must be at most the checkpoint size {}", new_size)};
    }
    // With every key rotation below the checkpoint, for the witness to follow.
    const protocol::CosignRequest request =
        unwrap(session.ledger().cosign_request(old_size), "building the request");
    const Bytes encoded = unwrap(protocol::encode_cosign_request(request), "encoding the request");
    if (const auto out = args.get("out")) {
        write_file(*out, encoded, false);
    }
    if (!args.has("send")) {
        if (args.json()) {
            print_json({{"file", *args.get("out")},
                        {"old_size", old_size},
                        {"new_size", new_size},
                        {"key_rotations", request.rotations.size()}});
        } else {
            std::println("wrote a cosign request for size {} (consistency from size {}) to {}",
                         new_size, old_size, *args.get("out"));
        }
        return exit_ok;
    }
    // Online: the peer cosigns as our witness, and we keep the cosignature.
    session.require_primary();
    const auto response = unwrap(
        peer_client(*peer).request("POST", "/v1/witness/cosign", encoded, "application/cbor"),
        "reaching peer " + peer->name);
    if (response.status != 200) {
        const Json answer = Json::parse(response.body.begin(), response.body.end(), nullptr, false);
        const std::string message = answer.is_object() && answer.contains("error")
                                        ? answer["error"].value("message", std::string())
                                        : "status " + std::to_string(response.status);
        if (args.json()) {
            print_json({{"cosigned", false}, {"error", message}, {"status", response.status}});
        } else {
            std::println("REFUSED by {}: {}", peer->name, message);
        }
        return response.status == 422 ? exit_not_verified : exit_failure;
    }
    unwrap(session.ledger().add_cosignature(response.body, witness), "storing the cosignature");
    if (args.json()) {
        print_json({{"cosigned", true}, {"peer", peer->name}, {"tree_size", new_size}});
    } else {
        std::println("{} cosigned the checkpoint at size {} (consistent since size {}); stored",
                     peer->name, new_size, old_size);
    }
    return exit_ok;
}

int cmd_checkpoint_add_cosignature(const Args& args) {
    Session session(args);
    const crypto::PublicKey witness = load_public_key(args.need("witness"));
    const Bytes cosignature = read_file(args.positional().front());
    session.add_cosignature(cosignature, witness);
    const auto parsed = unwrap(protocol::parse_cosignature(cosignature), "cosignature");
    if (args.json()) {
        print_json(
            {{"tree_size", parsed.checkpoint.tree_size}, {"witness_kid", id_json(parsed.kid)}});
    } else {
        std::println("stored the witness's cosignature of checkpoint size {}",
                     parsed.checkpoint.tree_size);
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// Witness side
// ---------------------------------------------------------------------------

int cmd_witness_add_log(const Args& args) {
    const std::filesystem::path dir = args.need("dir");
    if (args.has("genesis") == args.has("log-key")) {
        throw UsageError{"give --genesis FILE (to follow key rotations), or --ledger-id with "
                         "--log-key"};
    }
    std::optional<protocol::Id> pinned;
    if (const auto id_text = args.get("ledger-id")) {
        const auto id_bytes = from_hex(*id_text);
        if (!id_bytes) {
            throw UsageError{"--ledger-id must be the full hex ledger id"};
        }
        pinned = unwrap(protocol::to_id(*id_bytes), "ledger id");
    } else if (args.has("log-key")) {
        throw UsageError{"--log-key needs --ledger-id"};
    }
    WitnessState state;
    if (const auto genesis = args.get("genesis")) {
        // The genesis entry fixes the ledger id, hash, root key, and first
        // log key: from it the witness follows every rotation.
        const auto keys =
            unwrap(protocol::keys_from_genesis(shared_provider(), read_file(*genesis)),
                   "reading the genesis entry");
        if (pinned && *pinned != keys.ledger_id) {
            throw CommandError{"the genesis entry is not ledger " + hex_id(*pinned) + "'s"};
        }
        state.log.ledger_id = keys.ledger_id;
        state.log.log_key = keys.log_key();
        state.log.root_key = keys.root_key;
        state.log.tree_hash = keys.hash;
    } else {
        state.log.ledger_id = *pinned;
        state.log.log_key = load_public_key(args.need("log-key"));
    }
    std::filesystem::create_directories(dir);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the witness directory");
    state.name = args.get("name").value_or(hex_id(state.log.ledger_id).substr(0, 12));
    const std::filesystem::path path = state_path(dir, state.log.ledger_id);
    if (std::filesystem::exists(path)) {
        throw CommandError{"this witness already follows ledger " + hex_id(state.log.ledger_id)};
    }
    write_file(path, encode_state(state), false);
    if (args.json()) {
        print_json(state_json(state));
    } else {
        std::println("now witnessing \"{}\" ({})", state.name, hex_id(state.log.ledger_id));
    }
    return exit_ok;
}

Result<Bytes> witness_cosign(const std::filesystem::path& dir, const crypto::Signer& key,
                             ByteView request_bytes) {
    if (!std::filesystem::is_directory(dir)) {
        return fail(Errc::not_found, "no witness directory");
    }
    auto lock = ledger::DirectoryLock::acquire(dir);
    if (!lock) {
        return std::unexpected(lock.error());
    }
    CEXCHAIN_CLI_TRY(request, protocol::decode_cosign_request(request_bytes));
    CEXCHAIN_CLI_TRY(checkpoint, protocol::parse_checkpoint(request.checkpoint));
    const std::filesystem::path path = state_path(dir, checkpoint.checkpoint.ledger_id);
    if (!std::filesystem::exists(path)) {
        return fail(Errc::not_found, "this witness does not follow the ledger");
    }
    WitnessState state;
    try {
        state = decode_state(path);
    } catch (const CommandError&) {
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
        CEXCHAIN_CLI_TRY(again, protocol::cosign_checkpoint(key, provider, checkpoint.checkpoint));
        return again.encoded;
    }
    CEXCHAIN_CLI_TRY(approved, protocol::check_cosign_request(provider, state.log, request));
    if (key.public_key() == approved.log.log_key) {
        return fail(Errc::invalid_argument, "a ledger's log key cannot witness the ledger");
    }
    CEXCHAIN_CLI_TRY(cosigned,
                     protocol::cosign_checkpoint(key, provider, approved.checkpoint.checkpoint));
    state.log = std::move(approved.log);
    state.cosigned_at = ledger::SystemClock{}.now();
    try {
        write_file(path, encode_state(state), false);
    } catch (const CommandError&) {
        return fail(Errc::unavailable, "cannot write the witness state");
    }
    return cosigned.encoded;
}

int cmd_witness_cosign(const Args& args) {
    const std::filesystem::path dir = args.need("dir");
    if (!std::filesystem::is_directory(dir)) {
        throw CommandError{"no witness directory at " + dir.string()};
    }
    const Bytes request_bytes = read_file(args.positional().front());
    const auto request =
        unwrap(protocol::decode_cosign_request(request_bytes), "reading the request");
    const auto checkpoint =
        unwrap(protocol::parse_checkpoint(request.checkpoint), "reading the checkpoint");
    const std::filesystem::path path = state_path(dir, checkpoint.checkpoint.ledger_id);
    if (!std::filesystem::exists(path)) {
        throw CommandError{"this witness does not follow ledger " +
                           hex_id(checkpoint.checkpoint.ledger_id) + " (cexchain witness add-log)"};
    }
    const std::uint64_t before = decode_state(path).log.size;
    const auto key = load_signer(args.need("key"), args);
    const auto cosignature = witness_cosign(dir, *key, request_bytes);
    if (!cosignature) {
        const Error& e = cosignature.error();
        if (e.code == Errc::invalid_argument) {
            throw UsageError{std::string(e.detail)};
        }
        if (e.code != Errc::rejected && e.code != Errc::verification_failed) {
            throw CommandError{"cosigning: " + std::string(e.detail)};
        }
        if (args.json()) {
            print_json({{"cosigned", false},
                        {"error", e.detail},
                        {"witness_size", before},
                        {"conflict", e.code == Errc::rejected}});
        } else {
            std::println("REFUSED: {} (this witness last cosigned size {})", e.detail, before);
        }
        return e.code == Errc::rejected ? exit_failure : exit_not_verified;
    }
    const WitnessState state = decode_state(path);
    const std::filesystem::path out = args.need("out");
    write_file(out, *cosignature, false);
    if (args.json()) {
        print_json({{"cosigned", true},
                    {"file", out.string()},
                    {"ledger_id", id_json(state.log.ledger_id)},
                    {"tree_size", state.log.size},
                    {"root", to_hex(state.log.root.bytes())}});
    } else {
        std::println("cosigned \"{}\" at size {} (history consistent since size {}); wrote {}",
                     state.name, state.log.size, request.old_size, out.string());
    }
    return exit_ok;
}

int cmd_witness_status(const Args& args) {
    const auto states = all_states(args.need("dir"));
    if (args.json()) {
        Json out = Json::array();
        for (const WitnessState& s : states) {
            out.push_back(state_json(s));
        }
        print_json(out);
        return exit_ok;
    }
    if (states.empty()) {
        std::println("this witness follows no ledgers yet (cexchain witness add-log)");
    }
    for (const WitnessState& s : states) {
        std::println("{}  {:<24} size {:<8} {}", short_id(s.log.ledger_id), s.name, s.log.size,
                     s.cosigned_at ? "last cosigned " + format_time(*s.cosigned_at)
                                   : "never cosigned");
    }
    return exit_ok;
}

int cmd_witness_remove_log(const Args& args) {
    const std::filesystem::path dir = args.need("dir");
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the witness directory");
    const std::string prefix = args.positional().front();
    std::optional<WitnessState> found;
    for (const WitnessState& s : all_states(dir)) {
        if (hex_id(s.log.ledger_id).starts_with(prefix) || s.name == prefix) {
            if (found) {
                throw UsageError{"ambiguous ledger " + prefix};
            }
            found = s;
        }
    }
    if (!found) {
        throw CommandError{"this witness does not follow " + prefix};
    }
    std::filesystem::remove(state_path(dir, found->log.ledger_id));
    if (args.json()) {
        print_json({{"removed", id_json(found->log.ledger_id)}});
    } else {
        std::println("stopped witnessing \"{}\" ({})", found->name, hex_id(found->log.ledger_id));
    }
    return exit_ok;
}

} // namespace cexchain::cli
