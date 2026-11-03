// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Being reached through a relay. A console on a laptop serves only
// localhost: its parties reach it through a relay, the server of a public
// witness it registered with. Their requests wait there sealed to its relay
// key (kept sealed in the key store, as "relay"); a thread fetches them and
// answers each with the node's own API, as if it had come directly. And the
// console reaches parties that are themselves behind relays as its ledger,
// signing with the log key while it is unlocked.

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include <cexchain/client/errors.hpp>
#include <cexchain/client/peers.hpp>
#include <cexchain/client/public_witnesses.hpp>
#include <cexchain/client/relay_client.hpp>
#include <cexchain/client/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/node/client.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

std::shared_ptr<const crypto::Signer> log_key_of(const KeyStore* keys) {
    if (keys == nullptr || !keys->unlocked()) {
        return nullptr;
    }
    try {
        return std::make_shared<crypto::openssl::KeyPair>(keys->open("log"));
    } catch (const std::exception&) {
        return nullptr;
    }
}

/// Whether the server at `url` runs a relay: it asks who fetches.
bool runs_relay(const std::string& url) {
    try {
        node::ClientOptions options;
        options.timeout = std::chrono::seconds(10);
        node::Client client(client::unwrap(node::Url::parse(url), "the URL"), options);
        const auto response =
            client.request("GET", "/v1/relay/messages?to=" + std::string(64, '0'));
        return response && response->status == 401;
    } catch (const std::exception&) {
        return false;
    } catch (const client::ActionError&) {
        return false;
    }
}

} // namespace

Console::Console(Services services) : services_(std::move(services)) {
    relay_sender_ = client::RelaySender{
        [this] { return ledger(); }, [this] { return log_key_of(services_.keys); },
        [this](ByteView cosignature, const crypto::PublicKey& witness) {
            static_cast<void>(keep_cosignature(client::cosignature_body(cosignature, witness)));
        }};
}

http::Response Console::relay_route(const http::Request& request) const {
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
    std::optional<node::RelayRoute> own;
    std::vector<client::UsedWitness> witnesses;
    try {
        own = client::load_own_relay(dir);
        witnesses = client::load_used_witnesses(dir);
    } catch (const client::ActionError& e) {
        return error(500, "internal", e.message);
    }
    if (request.method == "GET") {
        nlohmann::json candidates = nlohmann::json::array();
        for (const client::UsedWitness& w : witnesses) {
            if (!own || own->url != w.url) {
                candidates.push_back({{"name", w.name}, {"url", w.url}});
            }
        }
        std::string problem;
        {
            const std::lock_guard lock(mutex_);
            problem = relay_problem_;
        }
        return json(200, {{"relay", own ? nlohmann::json{{"url", own->url}} : nlohmann::json()},
                          {"candidates", candidates},
                          {"problem", problem.empty() ? nlohmann::json() : nlohmann::json(problem)},
                          {"may_change", may_change}});
    }
    if (request.method != "POST") {
        return error(405, "unsupported", "GET or POST");
    }
    if (!may_change) {
        return error(403, "forbidden", "only an owner or an admin chooses how parties reach it");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    if (body.value("stop", false)) {
        client::save_own_relay(dir, std::nullopt);
        log_activity(signer.user, "relay.stop", {});
        return json(200, {{"relay", nullptr}});
    }
    const std::string url = body.value("use", "");
    const auto witness = std::ranges::find(witnesses, url, &client::UsedWitness::url);
    if (witness == witnesses.end()) {
        return error(400, "invalid_argument",
                     "a relay is the server of a public witness this ledger asks: add it first");
    }
    if (!runs_relay(url)) {
        return error(409, "conflict", "the witness's server runs no relay");
    }
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        return error(423, "locked", "unlock the console first");
    }
    // A relay key of its own, made once and kept sealed.
    std::optional<Bytes> public_key = services_.keys->hpke_public_key("relay");
    if (!public_key) {
        const auto key =
            client::unwrap(crypto::openssl::HpkeKey::generate(), "making the relay key");
        services_.keys->seal_hpke_key("relay", key);
        public_key = Bytes(key.public_key().begin(), key.public_key().end());
    }
    client::save_own_relay(dir, node::RelayRoute{url, *public_key, witness->key});
    {
        const std::lock_guard lock(mutex_);
        relay_problem_.clear();
    }
    log_activity(signer.user, "relay.use", {{"name", witness->name}});
    return json(200, {{"relay", {{"url", url}, {"name", witness->name}}}});
}

void Console::relay_loop(const std::stop_token& stop) const {
    const client::RelaySenderScope scope(&relay_sender_);
    std::unique_ptr<client::RelayAgent> agent;
    std::string route_key;
    auto pause = [&](std::chrono::milliseconds how_long) {
        for (auto waited = std::chrono::milliseconds(0);
             waited < how_long && !stop.stop_requested();
             waited += std::chrono::milliseconds(100)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    };
    auto say = [&](const std::string& problem) {
        const std::lock_guard lock(mutex_);
        relay_problem_ = problem;
    };
    while (!stop.stop_requested()) {
        const ledger::Ledger* served = ledger();
        NodeApi api;
        {
            const std::lock_guard lock(api_mutex_);
            api = node_api_;
        }
        std::optional<node::RelayRoute> own;
        try {
            own = client::load_own_relay(services_.directory.parent_path());
        } catch (const client::ActionError& e) {
            say(e.message);
        }
        if (!own || served == nullptr || !api || services_.keys == nullptr ||
            !services_.keys->unlocked()) {
            agent.reset();
            pause(std::chrono::seconds(2));
            continue;
        }
        const std::string key = own->url + "|" + to_hex(own->key);
        if (!agent || key != route_key) {
            try {
                agent = std::make_unique<client::RelayAgent>(
                    *own,
                    std::make_shared<const crypto::openssl::HpkeKey>(
                        services_.keys->open_hpke_key("relay")),
                    served->id(), [this] { return log_key_of(services_.keys); }, api);
                route_key = key;
            } catch (const std::exception& e) {
                say(e.what());
                pause(std::chrono::seconds(5));
                continue;
            }
        }
        try {
            static_cast<void>(agent->once(std::chrono::seconds(15)));
            say("");
        } catch (const client::ActionError& e) {
            say(e.message);
            pause(std::chrono::seconds(5));
        } catch (const std::exception& e) {
            say(e.what());
            pause(std::chrono::seconds(5));
        }
    }
}

} // namespace cexchain::console
