// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Both sides of witnessing: the ledger operator asks for and stores
// cosignatures (checkpoint cosign-request / add-cosignature; witness register
// with a public witness), and a witness keeps per-ledger state and cosigns
// only consistent history (witness ...).
//
// A witness directory holds one state file per ledger, <ledger id>.cbor:
//   {1: ledger id, 2: log key [alg, key], 3: name, 4: size,
//    ? 5: root, ? 6: tree hash (COSE id), ? 7: last cosigned at (ms),
//    ? 8: root key [alg, key], ? 9: index of the last key rotation followed}
// Without a root key (a log added by its log key alone) the witness cannot
// follow key rotations.

#include <algorithm>
#include <format>
#include <print>

#include <cexchain/app/peers.hpp>
#include <cexchain/app/public_witnesses.hpp>
#include <cexchain/app/relay_client.hpp>
#include <cexchain/app/witness.hpp>
#include <cexchain/core/protocol/witness.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace {

using app::WitnessState;

std::filesystem::path state_path(const std::filesystem::path& dir, const protocol::Id& ledger) {
    return app::witness_state_path(dir, ledger);
}

WitnessState decode_state(const std::filesystem::path& path) {
    return app::decode_witness_state(path);
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
    const RelayReach reach(args, session);
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
    const auto response =
        app::peer_request(*peer, "POST", "/v1/witness/cosign", encoded, "application/cbor");
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
    const std::string name = args.get("name").value_or("");
    WitnessState state;
    if (const auto genesis = args.get("genesis")) {
        // The genesis entry fixes the ledger id, hash, root key, and first
        // log key: from it the witness follows every rotation.
        state = app::state_from_genesis(read_file(*genesis), name, pinned);
    } else {
        state.log.ledger_id = *pinned;
        state.log.log_key = load_public_key(args.need("log-key"));
        state.name = name;
    }
    if (state.name.empty()) {
        state.name = hex_id(state.log.ledger_id).substr(0, 12);
    }
    app::add_witnessed(dir, state);
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
    const auto cosignature =
        app::witness_cosign(dir, *key, request_bytes, ledger::SystemClock{}.now());
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
    const auto states = app::witness_states(args.need("dir"));
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
    for (const WitnessState& s : app::witness_states(dir)) {
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

// ---------------------------------------------------------------------------
// Public witnesses this ledger uses
// ---------------------------------------------------------------------------

namespace {

/// A witness key given as a public key file, or as its hex.
crypto::PublicKey witness_key_argument(const std::string& value) {
    if (std::filesystem::is_regular_file(value)) {
        return load_public_key(value);
    }
    return app::witness_key_from_hex(value);
}

Json used_witness_json(const ledger::Ledger& ledger, const app::UsedWitness& w) {
    Json last;
    if (const auto cosigned = ledger.last_cosigned(w.key); cosigned && *cosigned) {
        last = {{"tree_size", (*cosigned)->tree_size}, {"timestamp", (*cosigned)->timestamp}};
    }
    return {{"name", w.name},
            {"url", w.url},
            {"key", app::witness_key_hex(w.key)},
            {"added", w.added},
            {"last_cosigned", last}};
}

} // namespace

int cmd_witness_register(const Args& args) {
    Session session(args);
    session.require_primary();
    const std::string url = args.positional().front();
    const crypto::PublicKey key = witness_key_argument(args.need("witness-key"));
    app::Registered registered;
    try {
        registered = app::register_witness(
            session.ledger(), session.directory(), url, key, args.get("name"),
            [&](ByteView cosignature) { session.add_cosignature(cosignature, key); },
            ledger::SystemClock{}.now());
    } catch (const app::WitnessRefused& e) {
        if (args.json()) {
            print_json({{"registered", false}, {"error", e.message}, {"status", e.status}});
        } else {
            std::println("REFUSED by {}: {}", url, e.message);
        }
        return e.status == 422 ? exit_not_verified : exit_failure;
    }
    if (args.json()) {
        print_json({{"registered", true},
                    {"name", registered.witness.name},
                    {"url", url},
                    {"tree_size", registered.tree_size}});
    } else {
        std::println("registered with {} ({}): it cosigned the checkpoint at size {}, and will be "
                     "asked to cosign each new one",
                     registered.witness.name, url, registered.tree_size);
    }
    return exit_ok;
}

int cmd_witness_registered(const Args& args) {
    Session session(args);
    const auto witnesses = app::load_used_witnesses(session.directory());
    if (!args.positional().empty()) {
        const std::string& name = args.positional().front();
        const auto it = std::ranges::find(witnesses, name, &app::UsedWitness::name);
        if (it == witnesses.end()) {
            throw CommandError{"no registered witness named " + name + " (witness registered)"};
        }
        const Json j = used_witness_json(session.ledger(), *it);
        if (args.json()) {
            print_json(j);
            return exit_ok;
        }
        std::println("{}\n  url: {}\n  key: {}\n  registered: {}", it->name, it->url,
                     j["key"].get<std::string>(), format_time(it->added));
        if (j["last_cosigned"].is_null()) {
            std::println("  last cosigned: never");
        } else {
            std::println("  last cosigned: size {}, the checkpoint of {}",
                         j["last_cosigned"]["tree_size"].get<std::uint64_t>(),
                         format_time(j["last_cosigned"]["timestamp"].get<protocol::Timestamp>()));
        }
        return exit_ok;
    }
    Json list = Json::array();
    for (const app::UsedWitness& w : witnesses) {
        list.push_back(used_witness_json(session.ledger(), w));
    }
    if (args.json()) {
        print_json({{"witnesses", list}});
        return exit_ok;
    }
    if (witnesses.empty()) {
        std::println("no public witness: cexchain witness register URL --witness-key KEY");
        return exit_ok;
    }
    for (const Json& w : list) {
        std::println("{}  {}  {}", w["name"].get<std::string>(), w["url"].get<std::string>(),
                     w["last_cosigned"].is_null()
                         ? std::string("never cosigned")
                         : std::format("cosigned size {}",
                                       w["last_cosigned"]["tree_size"].get<std::uint64_t>()));
    }
    return exit_ok;
}

int cmd_witness_unregister(const Args& args) {
    Session session(args);
    const std::filesystem::path& dir = session.directory();
    const std::string& name = args.positional().front();
    auto witnesses = app::load_used_witnesses(dir);
    if (std::erase_if(witnesses, [&](const app::UsedWitness& w) { return w.name == name; }) == 0) {
        throw CommandError{"no registered witness named " + name + " (witness registered)"};
    }
    app::save_used_witnesses(dir, witnesses);
    if (args.json()) {
        print_json({{"unregistered", name}});
    } else {
        std::println("no longer asking {} to cosign; what it cosigned stays valid", name);
    }
    return exit_ok;
}

} // namespace cexchain::cli
