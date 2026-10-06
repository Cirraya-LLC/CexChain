// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Both sides of witnessing: the ledger operator asks for and stores
// cosignatures (checkpoint cosign-request / add-cosignature), and a witness
// keeps per-ledger state and cosigns only consistent history (witness ...).
//
// A witness directory holds one state file per ledger, <ledger id>.cbor:
//   {1: ledger id, 2: log key [alg, key], 3: name, 4: size,
//    ? 5: root, ? 6: tree hash (COSE id), ? 7: last cosigned at (ms)}

#include <print>

#include <cexchain/core/protocol/witness.hpp>

#include "commands.hpp"
#include "output.hpp"

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
    Session session(args.ledger());
    const auto& latest = session.ledger().latest_checkpoint();
    if (!latest) {
        throw CommandError{"the ledger has no checkpoint yet (cexchain checkpoint create)"};
    }
    const crypto::PublicKey witness = load_public_key(args.need("witness"));
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
    const protocol::CosignRequest request{
        latest->encoded, old_size,
        unwrap(session.ledger().consistency_proof(old_size, new_size), "building the proof")};
    const std::filesystem::path out = args.need("out");
    write_file(out, unwrap(protocol::encode_cosign_request(request), "encoding the request"),
               false);
    if (args.json()) {
        print_json({{"file", out.string()}, {"old_size", old_size}, {"new_size", new_size}});
    } else {
        std::println("wrote a cosign request for size {} (consistency from size {}) to {}",
                     new_size, old_size, out.string());
    }
    return exit_ok;
}

int cmd_checkpoint_add_cosignature(const Args& args) {
    Session session(args.ledger());
    const crypto::PublicKey witness = load_public_key(args.need("witness"));
    const Bytes cosignature = read_file(args.positional().front());
    unwrap(session.ledger().add_cosignature(cosignature, witness), "storing the cosignature");
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
    std::filesystem::create_directories(dir);
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the witness directory");
    const auto id_bytes = from_hex(args.need("ledger-id"));
    if (!id_bytes) {
        throw UsageError{"--ledger-id must be the full hex ledger id"};
    }
    WitnessState state;
    state.log.ledger_id = unwrap(protocol::to_id(*id_bytes), "ledger id");
    state.log.log_key = load_public_key(args.need("log-key"));
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

int cmd_witness_cosign(const Args& args) {
    const std::filesystem::path dir = args.need("dir");
    if (!std::filesystem::is_directory(dir)) {
        throw CommandError{"no witness directory at " + dir.string()};
    }
    const auto lock = unwrap(ledger::DirectoryLock::acquire(dir), "locking the witness directory");
    const auto request =
        unwrap(protocol::decode_cosign_request(read_file(args.positional().front())),
               "reading the request");
    const auto checkpoint =
        unwrap(protocol::parse_checkpoint(request.checkpoint), "reading the checkpoint");
    const std::filesystem::path path = state_path(dir, checkpoint.checkpoint.ledger_id);
    if (!std::filesystem::exists(path)) {
        throw CommandError{"this witness does not follow ledger " +
                           hex_id(checkpoint.checkpoint.ledger_id) + " (cexchain witness add-log)"};
    }
    WitnessState state = decode_state(path);
    const auto key = load_signer(args.need("key"), args);
    if (key->public_key() == state.log.log_key) {
        throw UsageError{"a ledger's log key cannot witness the ledger"};
    }
    const crypto::openssl::Provider provider;
    const auto checked = protocol::check_cosign_request(provider, state.log, request);
    if (!checked) {
        if (args.json()) {
            print_json({{"cosigned", false},
                        {"error", checked.error().detail},
                        {"witness_size", state.log.size},
                        {"conflict", checked.error().code == Errc::rejected}});
        } else {
            std::println("REFUSED: {} (this witness last cosigned size {})", checked.error().detail,
                         state.log.size);
        }
        return checked.error().code == Errc::rejected ? exit_failure : exit_not_verified;
    }
    const Bytes cosignature =
        unwrap(protocol::cosign_checkpoint(*key, provider, checked->checkpoint), "cosigning")
            .encoded;
    // Write the cosignature before advancing: a crash in between leaves the
    // witness able to cosign the same checkpoint again.
    const std::filesystem::path out = args.need("out");
    write_file(out, cosignature, false);
    state.log = protocol::advance(state.log, checked->checkpoint);
    state.cosigned_at = ledger::SystemClock{}.now();
    write_file(path, encode_state(state), false);
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
