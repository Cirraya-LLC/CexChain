// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Witnessing each other. Each console is a witness of its parties' ledgers:
// it follows each one from its genesis entry (fetched from the party's API,
// pinned to the party's ledger id) and cosigns a checkpoint only if it
// extends the history it cosigned before. And each asks its parties to
// cosign its own latest checkpoint, keeping their cosignatures with the
// ledger, so that its proofs carry them. A ledger rewritten, or showing two
// histories, cannot get both cosigned: the witness refuses, and the Parties
// screen says so.

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include <cexchain/app/errors.hpp>
#include <cexchain/app/peers.hpp>
#include <cexchain/app/public_witnesses.hpp>
#include <cexchain/app/relay_client.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/app/witness.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/witness.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

template <typename F>
std::optional<std::string> attempt(F&& f) {
    try {
        f();
        return std::nullopt;
    } catch (const app::ActionError& e) {
        return e.message;
    } catch (const app::UsageError& e) {
        return e.message;
    } catch (const std::exception& e) {
        return std::string(e.what());
    }
}

std::filesystem::path witness_dir(const std::filesystem::path& console) {
    return console / "witness";
}

/// The message in an API's error answer, or its status.
std::string answer_message(const node::http::ClientResponse& response) {
    const auto answer =
        nlohmann::json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (answer.is_object() && answer.contains("error") && answer["error"].is_object()) {
        return answer["error"].value("message", "status " + std::to_string(response.status));
    }
    return "status " + std::to_string(response.status);
}

} // namespace

Result<Bytes> Console::witness_cosign(ByteView request) const {
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        return fail(Errc::unavailable, "this witness is locked: its console must be unlocked");
    }
    // Which ledger asks, for the Parties screen.
    std::string ledger;
    if (const auto decoded = protocol::decode_cosign_request(request)) {
        if (const auto checkpoint = protocol::parse_checkpoint(decoded->checkpoint)) {
            ledger = hex_of(checkpoint->checkpoint.ledger_id);
        }
    }
    Result<Bytes> out = fail(Errc::unavailable, "this console has no witness key");
    if (const auto problem = attempt([&] {
            const auto key = services_.keys->open(witness_key_name);
            out = app::witness_cosign(witness_dir(services_.directory), key, request,
                                      services_.clock->now());
        })) {
        return fail(Errc::unavailable, "this console has no witness key");
    }
    if (!ledger.empty()) {
        const std::lock_guard lock(mutex_);
        if (out) {
            refused_.erase(ledger);
        } else if (out.error().code == Errc::verification_failed) {
            refused_[ledger] = std::string(out.error().detail);
        }
    }
    return out;
}

void Console::poll_witnessing() const {
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return;
    }
    const auto peers = node::load_peers(services_.directory.parent_path());
    if (!peers) {
        return;
    }
    const std::filesystem::path dir = witness_dir(services_.directory);
    const Cosignatures keep = cosignatures();
    for (const node::Peer& peer : *peers) {
        if (!node::reachable(peer)) {
            continue;
        }
        // Follow its ledger from its genesis, which its ledger id pins.
        if (!std::filesystem::exists(app::witness_state_path(dir, peer.ledger_id))) {
            static_cast<void>(attempt([&] {
                const auto response = app::peer_request(peer, "GET", "/v1/genesis");
                if (response.status != 200) {
                    throw app::ActionError{answer_message(response)};
                }
                app::add_witnessed(
                    dir, app::state_from_genesis(response.body, peer.name, peer.ledger_id));
            }));
        }
        // Ask it to cosign this ledger's latest checkpoint, if it has not.
        if (!peer.witness_key || !keep) {
            continue;
        }
        const auto latest = served->latest_checkpoint();
        const auto last = served->last_cosigned(*peer.witness_key);
        if (!latest || !last) {
            continue;
        }
        const std::uint64_t old = *last ? (*last)->tree_size : 0;
        if (*last && old >= latest->checkpoint.tree_size) {
            continue;
        }
        const auto problem = attempt([&] {
            const Bytes request =
                app::unwrap(protocol::encode_cosign_request(app::unwrap(
                                served->cosign_request(old), "making the cosign request")),
                            "encoding the cosign request");
            const auto response =
                app::peer_request(peer, "POST", "/v1/witness/cosign", request, "application/cbor");
            if (response.status != 200) {
                throw app::ActionError{answer_message(response)};
            }
            // Kept with the ledger, through the node's writer.
            const int kept =
                keep_cosignature(app::cosignature_body(response.body, *peer.witness_key));
            if (kept / 100 != 2) {
                throw app::ActionError{"the cosignature was not kept (status " +
                                       std::to_string(kept) + ")"};
            }
        });
        const std::lock_guard lock(mutex_);
        if (problem) {
            not_cosigned_[peer.name] = *problem;
        } else {
            not_cosigned_.erase(peer.name);
        }
    }
    // The public witnesses it registered with, as serve asks them.
    if (keep) {
        const auto asked =
            app::ask_used_witnesses(*served, services_.directory.parent_path(), [this](Bytes body) {
                return keep_cosignature(std::move(body));
            });
        const std::lock_guard lock(mutex_);
        public_not_cosigned_.clear();
        for (const app::WitnessAsked& a : asked) {
            if (!a.problem.empty()) {
                public_not_cosigned_[a.name] = a.problem;
            }
        }
    }
}

int Console::keep_cosignature(Bytes body) const {
    const Cosignatures keep = cosignatures();
    if (!keep) {
        return 503;
    }
    auto stored = std::make_shared<std::promise<int>>();
    auto answer = stored->get_future();
    keep(std::move(body), [stored](http::Response r) { stored->set_value(r.status); });
    return answer.wait_for(std::chrono::seconds(30)) == std::future_status::ready ? answer.get()
                                                                                  : 504;
}

http::Response Console::witnesses_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    const std::filesystem::path dir = services_.directory.parent_path();
    const bool may_change = signer.role == Role::owner || signer.role == Role::admin;
    auto fingerprint = [&](const crypto::PublicKey& key) {
        const Bytes encoded =
            app::unwrap(cbor::encode(protocol::encode_public_key(key)), "the witness key");
        return app::ledger_fingerprint(
            app::unwrap(services_.provider->digest(crypto::HashAlg::sha256, encoded), "hashing"));
    };
    if (request.method == "GET") {
        std::vector<app::UsedWitness> used;
        if (const auto problem = attempt([&] { used = app::load_used_witnesses(dir); })) {
            return error(500, "internal", *problem);
        }
        nlohmann::json list = nlohmann::json::array();
        for (const app::UsedWitness& w : used) {
            nlohmann::json last;
            if (const auto cosigned = served->last_cosigned(w.key); cosigned && *cosigned) {
                last = {{"size", (*cosigned)->tree_size}, {"at", (*cosigned)->timestamp}};
            }
            nlohmann::json item{{"name", w.name},
                                {"url", w.url},
                                {"key", app::witness_key_hex(w.key)},
                                {"fingerprint", fingerprint(w.key)},
                                {"added", w.added},
                                {"cosigned", last}};
            const std::lock_guard lock(mutex_);
            if (const auto it = public_not_cosigned_.find(w.name);
                it != public_not_cosigned_.end()) {
                item["problem"] = it->second;
            }
            list.push_back(std::move(item));
        }
        nlohmann::json known = nlohmann::json::array();
        for (const app::UsedWitness& w : app::built_in_public_witnesses()) {
            if (std::ranges::none_of(used,
                                     [&](const app::UsedWitness& u) { return u.key == w.key; })) {
                known.push_back({{"name", w.name},
                                 {"url", w.url},
                                 {"key", app::witness_key_hex(w.key)},
                                 {"fingerprint", fingerprint(w.key)}});
            }
        }
        return json(200, {{"witnesses", list}, {"known", known}, {"may_change", may_change}});
    }
    if (request.method != "POST") {
        return error(405, "unsupported", "GET or POST");
    }
    if (!may_change) {
        return error(403, "forbidden", "only an owner or an admin chooses the witnesses");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    if (body.contains("remove")) {
        const std::string name = body.value("remove", "");
        std::optional<std::string> problem = attempt([&] {
            auto used = app::load_used_witnesses(dir);
            if (std::erase_if(used, [&](const app::UsedWitness& w) { return w.name == name; }) ==
                0) {
                throw app::ActionError{"no witness named " + name};
            }
            app::save_used_witnesses(dir, used);
        });
        if (problem) {
            return error(404, "not_found", *problem);
        }
        log_activity(signer.user, "witnesses.remove", {{"name", name}});
        return json(200, {{"removed", name}});
    }
    const std::string url = body.value("url", "");
    const std::string key_hex = body.value("key", "");
    std::optional<app::Registered> registered;
    std::optional<int> refused_status;
    std::optional<std::string> problem = attempt([&] {
        const crypto::PublicKey key = app::witness_key_from_hex(key_hex);
        try {
            registered = app::register_witness(
                *served, dir, url, key, std::nullopt,
                [this, &key](ByteView cosignature) {
                    const int kept = keep_cosignature(app::cosignature_body(cosignature, key));
                    if (kept / 100 != 2) {
                        throw app::ActionError{"the cosignature was not kept (status " +
                                               std::to_string(kept) + ")"};
                    }
                },
                services_.clock->now());
        } catch (const app::WitnessRefused& e) {
            refused_status = e.status;
            throw app::ActionError{e.message};
        }
    });
    if (problem) {
        return error(refused_status == 422 ? 422
                     : refused_status      ? 409
                                           : 400,
                     refused_status ? "rejected" : "invalid_argument", *problem);
    }
    log_activity(signer.user, "witnesses.add", {{"name", registered->witness.name}});
    return json(200, {{"name", registered->witness.name},
                      {"url", url},
                      {"fingerprint", fingerprint(registered->witness.key)},
                      {"size", registered->tree_size}});
}

nlohmann::json Console::witnessing_view(const node::Peer& peer) const {
    nlohmann::json us;
    if (peer.witness_key) {
        // They witness this ledger: the size they last cosigned.
        us = {{"size", 0}};
        if (const ledger::Ledger* served = ledger()) {
            if (const auto last = served->last_cosigned(*peer.witness_key); last && *last) {
                us["size"] = (*last)->tree_size;
            }
        }
    }
    nlohmann::json them;
    const std::filesystem::path state =
        app::witness_state_path(witness_dir(services_.directory), peer.ledger_id);
    if (std::filesystem::exists(state)) {
        // This console witnesses theirs: the size it last cosigned.
        static_cast<void>(attempt([&] {
            const app::WitnessState s = app::decode_witness_state(state);
            them = {{"size", s.log.size},
                    {"at", s.cosigned_at ? nlohmann::json(*s.cosigned_at) : nlohmann::json()}};
        }));
    }
    const std::lock_guard lock(mutex_);
    if (const auto it = not_cosigned_.find(peer.name); it != not_cosigned_.end() && !us.is_null()) {
        us["problem"] = it->second;
    }
    if (const auto it = refused_.find(hex_of(peer.ledger_id)); it != refused_.end()) {
        if (them.is_null()) {
            them = {{"size", 0}};
        }
        them["refused"] = it->second;
    }
    return {{"witnesses_us", us}, {"we_witness", them}};
}

} // namespace cexchain::console
