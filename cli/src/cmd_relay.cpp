// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Being reached through a relay: a ledger that no party reaches directly (a
// laptop) keeps a mailbox at a relay (serve --relay-dir, beside a public
// witness). Its parties' requests come sealed to its relay key; serve
// --relay-key answers them with the ledger's own API. `relay use` sets the
// relay, and invitation codes then carry it.

#include <filesystem>
#include <print>

#include <cexchain/app/public_witnesses.hpp>
#include <cexchain/app/records.hpp>
#include <cexchain/app/relay_client.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace cexchain::cli {

int cmd_relay_key_init(const Args& args) {
    const std::filesystem::path out = args.need("out");
    if (std::filesystem::exists(out)) {
        throw CommandError{out.string() + " already exists; keys are never overwritten"};
    }
    const bool encrypt = !args.has("no-passphrase");
    if (!encrypt && args.has("passphrase-file")) {
        throw UsageError{"--no-passphrase and --passphrase-file contradict each other"};
    }
    const std::optional<std::string> secret =
        encrypt ? std::optional(passphrase(args, out.string(), true)) : std::nullopt;
    const auto key = unwrap(crypto::openssl::HpkeKey::generate(), "generating the relay key");
    app::save_hpke_key(out, key, secret);
    if (args.json()) {
        print_json({{"file", out.string()},
                    {"encrypted", encrypt},
                    {"public_key", to_hex(key.public_key())}});
        return exit_ok;
    }
    std::println("relay key written to {}{}", out.string(),
                 encrypt ? " (encrypted)" : " (NOT encrypted)");
    std::println("Use it with: cexchain relay use URL --relay-key {}", out.string());
    return exit_ok;
}

int cmd_relay_use(const Args& args) {
    Session session(args);
    session.require_primary();
    const std::string url = args.positional().front();
    const auto key = load_hpke_key(args.need("relay-key"), args);
    // The relay serves the ledgers its witness follows: this one must be.
    const app::WitnessInfo info = app::fetch_witness_info(url);
    const auto listed = app::load_used_witnesses(session.directory());
    const auto registered = std::ranges::find(listed, url, &app::UsedWitness::url);
    crypto::PublicKey witness;
    if (const auto given = args.get("witness-key")) {
        witness = std::filesystem::is_regular_file(*given) ? load_public_key(*given)
                                                           : app::witness_key_from_hex(*given);
    } else if (registered != listed.end()) {
        witness = registered->key;
    } else {
        throw UsageError{"register with the relay's witness first (witness register " + url +
                         "), or give --witness-key"};
    }
    if (info.key != witness) {
        throw CommandError{"the witness at " + url +
                           " has another key than the one given: not used"};
    }
    if (registered == listed.end() || registered->key != witness) {
        static_cast<void>(app::register_witness(
            session.ledger(), session.directory(), url, witness, std::nullopt,
            [&](ByteView cosignature) { session.add_cosignature(cosignature, witness); },
            ledger::SystemClock{}.now()));
    }
    const node::RelayRoute route{url, Bytes(key.public_key().begin(), key.public_key().end()),
                                 witness};
    app::save_own_relay(session.directory(), route);
    if (args.json()) {
        print_json({{"url", url}, {"key", to_hex(route.key)}});
    } else {
        std::println("this ledger is reached through {} from now on: invitation codes carry it, "
                     "and serve --relay-key {} answers its parties' requests",
                     url, args.need("relay-key"));
    }
    return exit_ok;
}

int cmd_relay_show(const Args& args) {
    Session session(args);
    const auto route = app::load_own_relay(session.directory());
    if (!route) {
        if (args.json()) {
            print_json({{"relay", nullptr}});
        } else {
            std::println("this ledger is reached directly, not through a relay (relay use URL)");
        }
        return exit_ok;
    }
    Json mailbox;
    if (const auto log_key = args.get("log-key")) {
        const auto signer = load_signer(*log_key, args);
        const auto seen = app::look_at_mailbox(*route, session.ledger().id(), *signer);
        mailbox = {{"requests", seen.requests}, {"answers", seen.answers}};
    }
    if (args.json()) {
        print_json(
            {{"relay", {{"url", route->url}, {"key", to_hex(route->key)}}}, {"mailbox", mailbox}});
        return exit_ok;
    }
    std::println("reached through {}\nrelay key: {}", route->url, to_hex(route->key));
    if (!mailbox.is_null()) {
        std::println("waiting: {} requests, {} answers", mailbox["requests"].get<std::size_t>(),
                     mailbox["answers"].get<std::size_t>());
    }
    return exit_ok;
}

int cmd_relay_stop(const Args& args) {
    Session session(args);
    if (!app::load_own_relay(session.directory())) {
        throw CommandError{"this ledger is not reached through a relay"};
    }
    app::save_own_relay(session.directory(), std::nullopt);
    if (args.json()) {
        print_json({{"relay", nullptr}});
    } else {
        std::println("no longer reached through a relay: new invitation codes carry none");
    }
    return exit_ok;
}

} // namespace cexchain::cli
