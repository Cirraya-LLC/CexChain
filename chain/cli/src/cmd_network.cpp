// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Open witness networks (spec v0.13): a ledger's entry in a network's list
// of logs, its checkpoint notes, asking network witnesses to cosign, and the
// cosignatures they gave.

#include <algorithm>
#include <format>
#include <optional>
#include <print>
#include <string>

#include <cexchain/client/network_witnesses.hpp>
#include <cexchain/core/protocol/network.hpp>
#include <cexchain/node/network_witnesses.hpp>
#include <cexchain/verifier/report.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace cexchain::cli {

namespace network = protocol::network;

namespace {

/// The note key (--note-key): an Ed25519 key, file or token.
std::unique_ptr<crypto::Signer> note_key(const Args& args) {
    auto key = load_signer(args.need("note-key"), args);
    if (key->algorithm() != crypto::SigAlg::ed25519) {
        throw UsageError{"a note key is an Ed25519 key (cexchain key generate --alg ed25519)"};
    }
    return key;
}

void require_sha256(const ledger::Ledger& ledger) {
    if (ledger.hash() != crypto::HashAlg::sha256) {
        throw CommandError{"only SHA-256 ledgers can be witnessed by open networks"};
    }
}

/// The latest checkpoint, or with `--size` the latest of that size.
protocol::SignedCheckpoint chosen_checkpoint(const ledger::Ledger& ledger, const Args& args) {
    if (const auto size = args.get("size")) {
        auto of_size = unwrap(ledger.checkpoints_of_size(parse_number(*size, "--size")),
                              "reading checkpoints");
        if (of_size.empty()) {
            throw CommandError{"no checkpoint of size " + *size};
        }
        return std::move(of_size.back());
    }
    auto latest = ledger.latest_checkpoint();
    if (!latest) {
        throw CommandError{"the ledger has no checkpoints yet (cexchain checkpoint create)"};
    }
    return std::move(*latest);
}

/// The size `witness` cosigned last here (0: never).
std::uint64_t last_cosigned(const ledger::Ledger& ledger, const network::VerifierKey& witness) {
    std::uint64_t last = 0;
    for (const ledger::StoredNetworkCosignature& n :
         unwrap(ledger.network_cosignatures(), "reading network cosignatures")) {
        if (n.witness == witness) {
            last = std::max(last, n.checkpoint.checkpoint.tree_size);
        }
    }
    return last;
}

Json cosignature_json(const ledger::StoredNetworkCosignature& n) {
    return {{"witness", n.witness.name},
            {"vkey", network::verifier_key_text(n.witness)},
            {"tree_size", n.checkpoint.checkpoint.tree_size},
            {"time", verifier::iso_time(static_cast<protocol::Timestamp>(n.time) * 1000)}};
}

} // namespace

int cmd_witness_network_entry(const Args& args) {
    Session session(args);
    require_sha256(session.ledger());
    const auto key = note_key(args);
    const std::string origin = network::origin(session.ledger().id());
    const auto vkey = unwrap(network::make_verifier_key(session.provider(), origin,
                                                        network::log_ed25519, key->public_key()),
                             "making the note key's verifier key");
    const std::uint64_t per_day =
        args.has("qpd") ? parse_number(*args.get("qpd"), "--qpd") : std::uint64_t{24};
    if (per_day == 0 || per_day >= (std::uint64_t{1} << 31)) {
        throw UsageError{"--qpd takes 1 to 2147483647 add-checkpoint requests a day"};
    }
    const std::string entry = client::log_list_entry(vkey, per_day, args.need("contact"));
    if (args.json()) {
        print_json({{"origin", origin},
                    {"vkey", network::verifier_key_text(vkey)},
                    {"qpd", per_day},
                    {"entry", entry}});
    } else {
        std::print("{}", entry);
    }
    return exit_ok;
}

int cmd_checkpoint_note(const Args& args) {
    Session session(args);
    require_sha256(session.ledger());
    const protocol::SignedCheckpoint checkpoint = chosen_checkpoint(session.ledger(), args);
    const auto& at = checkpoint.checkpoint;
    const std::string origin = network::origin(at.ledger_id);
    const std::string note = network::checkpoint_note(origin, at.tree_size, at.root);
    std::string text = note;
    if (args.has("note-key")) {
        text = unwrap(network::sign_note(session.provider(), *note_key(args), origin, note),
                      "signing the note");
    }
    if (args.json()) {
        print_json({{"origin", origin}, {"tree_size", at.tree_size}, {"note", text}});
    } else {
        std::print("{}", text);
    }
    return exit_ok;
}

int cmd_checkpoint_network_cosign(const Args& args) {
    Session session(args);
    require_sha256(session.ledger());
    const auto key = note_key(args);
    auto witnesses = client::load_network_witnesses(session.directory(), session.provider());
    if (const auto only = args.get("witness")) {
        std::erase_if(witnesses, [&](const client::UsedNetworkWitness& w) {
            return w.witness.key.name != *only;
        });
    }
    if (witnesses.empty()) {
        throw CommandError{"no network witness to ask (cexchain witness register URL --vkey VKEY)"};
    }
    const protocol::SignedCheckpoint checkpoint = chosen_checkpoint(session.ledger(), args);
    const std::uint64_t size = checkpoint.checkpoint.tree_size;
    node::ClientOptions options;
    if (const auto ca = args.get("ca-file")) {
        options.ca_file = *ca;
    }
    Json out = Json::array();
    bool all = true;
    for (const client::UsedNetworkWitness& w : witnesses) {
        const std::string& name = w.witness.key.name;
        auto cosignature = node::ask_network_witness(
            session.provider(), checkpoint, *key, w.witness,
            last_cosigned(session.ledger(), w.witness.key),
            [&](std::uint64_t from, std::uint64_t to) {
                return session.ledger().consistency_proof(from, to);
            },
            options);
        if (!cosignature) {
            all = false;
            out.push_back({{"witness", name},
                           {"cosigned", false},
                           {"error", std::string(cosignature.error().detail)}});
            if (!args.json()) {
                std::println("{}: {}", name, cosignature.error().detail);
            }
            continue;
        }
        session.add_network_cosignature(w.witness.key, *cosignature, size);
        const std::uint64_t time = unwrap(network::cosignature_time(cosignature->bytes), "time");
        out.push_back(
            {{"witness", name},
             {"cosigned", true},
             {"tree_size", size},
             {"time", verifier::iso_time(static_cast<protocol::Timestamp>(time) * 1000)}});
        if (!args.json()) {
            std::println("{} cosigned the checkpoint at size {}", name, size);
        }
    }
    if (args.json()) {
        print_json({{"witnesses", out}});
    }
    return all ? exit_ok : exit_failure;
}

int cmd_checkpoint_network_cosignatures(const Args& args) {
    Session session(args);
    std::optional<std::uint64_t> size;
    if (const auto text = args.get("size")) {
        size = parse_number(*text, "--size");
    }
    Json out = Json::array();
    std::vector<std::string> lines;
    for (const ledger::StoredNetworkCosignature& n :
         unwrap(session.ledger().network_cosignatures(), "reading network cosignatures")) {
        const std::uint64_t cosigned = n.checkpoint.checkpoint.tree_size;
        if (size && cosigned != *size) {
            continue;
        }
        out.push_back(cosignature_json(n));
        lines.push_back(
            std::format("{:>10}  {}  {}", cosigned,
                        verifier::format_time(static_cast<protocol::Timestamp>(n.time) * 1000),
                        n.witness.name));
    }
    if (args.json()) {
        print_json(out);
    } else if (lines.empty()) {
        std::println("no network cosignatures yet (cexchain checkpoint network-cosign)");
    } else {
        std::println("{:>10}  {:<23}  {}", "SIZE", "WITNESS'S TIME", "WITNESS");
        for (const std::string& line : lines) {
            std::println("{}", line);
        }
    }
    return exit_ok;
}

} // namespace cexchain::cli
