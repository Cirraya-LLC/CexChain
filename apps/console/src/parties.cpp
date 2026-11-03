// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Parties: other ledgers this console works with. Two consoles connect with
// one code each way: an invitation carries the inviting ledger's id, its
// name, its API's URL, and a token issued for the invited party; accepting
// it adds the peer, and answers with an invitation back. Once they are
// parties, each node asks the other's registrar, every minute while
// unlocked (and when Home opens), for calls waiting on its consent; the
// person reads one as a proposal, consents with a tap on their own ledger,
// and the consent goes to the home online.

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <cexchain/client/contracts.hpp>
#include <cexchain/client/errors.hpp>
#include <cexchain/client/peers.hpp>
#include <cexchain/client/relay_client.hpp>
#include <cexchain/client/support.hpp>
#include <cexchain/console/console.hpp>
#include <cexchain/console/setup.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/exchange.hpp>
#include <cexchain/ledger/storage.hpp>
#include <cexchain/node/peers.hpp>
#include <cexchain/node/tokens.hpp>

#include "responses.hpp"

namespace cexchain::console {

namespace {

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string language_of(std::string_view asked) {
    return asked == "zh-Hant-HK" || asked == "zh-Hans-CN" ? std::string(asked) : std::string("en");
}

/// What app's actions throw, as a message.
template <typename F>
std::optional<std::string> attempt(F&& f) {
    try {
        f();
        return std::nullopt;
    } catch (const client::ActionError& e) {
        return e.message;
    } catch (const client::UsageError& e) {
        return e.message;
    } catch (const std::exception& e) {
        return std::string(e.what());
    }
}

} // namespace

std::string Console::api_url() const {
    const std::lock_guard lock(api_mutex_);
    return origins_.empty() ? std::string() : origins_.front().text();
}

http::Response Console::parties_route(const http::Request& request) const {
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
    if (request.method == "GET") {
        nlohmann::json peers = nlohmann::json::array();
        std::vector<std::string> named;
        if (const auto loaded = node::load_peers(dir)) {
            for (const node::Peer& p : *loaded) {
                named.push_back(p.name);
                nlohmann::json item{{"name", p.name},
                                    {"ledger", hex_of(p.ledger_id)},
                                    {"fingerprint", client::ledger_fingerprint(p.ledger_id)},
                                    {"url", p.url ? nlohmann::json(*p.url) : nlohmann::json()},
                                    {"online", node::reachable(p)}};
                item.update(witnessing_view(p));
                peers.push_back(std::move(item));
            }
        }
        // Invitations sent whose answer has not come: peer tokens without a peer.
        nlohmann::json waiting = nlohmann::json::array();
        if (const auto tokens = node::load_tokens(dir)) {
            for (const node::ApiToken& t : *tokens) {
                if (node::has_scope(t.scopes, node::Scope::peer) &&
                    !std::ranges::contains(named, t.name)) {
                    waiting.push_back(t.name);
                }
            }
        }
        std::string fingerprint;
        served->read_state([&](const protocol::LedgerState& state) {
            fingerprint = client::ledger_fingerprint(state.ledger_id());
        });
        return json(200, {{"peers", peers},
                          {"waiting", waiting},
                          {"fingerprint", fingerprint},
                          {"may_change", may_change}});
    }
    if (request.method != "POST") {
        return error(405, "unsupported", "method not allowed");
    }
    if (!may_change) {
        return error(403, "forbidden", "only an owner or an admin connects parties");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    client::PeerInvitation ours;
    served->read_state([&](const protocol::LedgerState& state) {
        ours.ledger = state.ledger_id();
        ours.organization = state.organization();
    });
    const std::string url = api_url();
    std::optional<node::RelayRoute> relay;
    try {
        relay = client::load_own_relay(dir);
    } catch (const client::ActionError&) {
    }
    // Reached through a relay, a console on this computer gives no address:
    // no party reaches its localhost.
    const bool local = url.starts_with("http://localhost:") || url.starts_with("http://127.") ||
                       url.starts_with("http://[::1]");
    if (!url.empty() && !(relay && local)) {
        ours.url = url;
    }
    ours.relay = relay;
    // The console's witness of its parties' ledgers, for them to ask.
    if (services_.keys != nullptr && services_.keys->initialized()) {
        ours.witness = witness_public_key(*services_.keys);
    }
    const auto invite = [&](const std::string& name) {
        client::PeerInvitation code = ours;
        code.token = client::issue_peer_token(dir, name, *services_.provider, *services_.entropy,
                                              *services_.clock, false);
        return client::encode_invitation(code);
    };
    if (const auto name = body.find("invite"); name != body.end() && name->is_string()) {
        std::string code;
        if (const auto problem = attempt([&] { code = invite(name->get<std::string>()); })) {
            return error(409, "conflict", *problem);
        }
        log_activity(signer.user, "parties.invite", {{"name", name->get<std::string>()}});
        return json(200, {{"name", name->get<std::string>()},
                          {"code", code},
                          {"fingerprint", client::ledger_fingerprint(ours.ledger)}});
    }
    if (const auto code = body.find("accept"); code != body.end() && code->is_string()) {
        const auto invitation = client::decode_invitation(code->get<std::string>());
        if (!invitation) {
            return error(400, "invalid_argument", "that is not an invitation code");
        }
        const std::string name = body.value("name", "");
        std::optional<std::string> reply;
        const auto problem = attempt([&] {
            static_cast<void>(client::accept_invitation(dir, services_.directory / "peer-tokens",
                                                        name, *invitation, ours.ledger));
            // Invite them back, unless an invitation to them is out already.
            const auto tokens = node::load_tokens(dir);
            const bool invited = tokens && std::ranges::any_of(*tokens, [&](const auto& t) {
                                     return t.name == name;
                                 });
            if (!invited) {
                reply = invite(name);
            }
        });
        if (problem) {
            return error(409, "conflict", *problem);
        }
        log_activity(signer.user, "parties.accept",
                     {{"name", name}, {"organization", invitation->organization}});
        return json(200, {{"name", name},
                          {"organization", invitation->organization},
                          {"ledger", hex_of(invitation->ledger)},
                          {"fingerprint", client::ledger_fingerprint(invitation->ledger)},
                          {"reply", reply ? nlohmann::json(*reply) : nlohmann::json()}});
    }
    if (const auto name = body.find("remove"); name != body.end() && name->is_string()) {
        const std::string party = name->get<std::string>();
        const auto problem = attempt([&] {
            client::remove_peer(dir, party);
            if (auto tokens = node::load_tokens(dir)) {
                std::erase_if(*tokens, [&](const node::ApiToken& t) { return t.name == party; });
                static_cast<void>(node::save_tokens(dir, *tokens));
            }
        });
        if (problem) {
            return error(409, "conflict", *problem);
        }
        log_activity(signer.user, "parties.remove", {{"name", party}});
        return json(200, {{"removed", party}});
    }
    return error(400, "invalid_argument", "invite, accept, or remove a party");
}

// --- Asking the parties for calls waiting on this ledger's consent ------------------

void Console::start_polling(std::chrono::seconds every) {
    poller_ = std::jthread([this, every](const std::stop_token& stop) {
        const client::RelaySenderScope scope(&relay_sender_);
        while (!stop.stop_requested()) {
            poll_peers();
            maybe_back_up();
            std::unique_lock lock(poll_mutex_);
            poll_wake_.wait_for(lock, stop, every, [this] { return poll_asked_; });
            poll_asked_ = false;
        }
    });
    relayer_ = std::jthread([this](const std::stop_token& stop) { relay_loop(stop); });
}

void Console::poll_now() const {
    {
        const std::lock_guard lock(poll_mutex_);
        poll_asked_ = true;
    }
    poll_wake_.notify_all();
}

void Console::poll_peers() const {
    if (ledger() == nullptr) {
        return;
    }
    const auto peers = node::load_peers(services_.directory.parent_path());
    if (!peers) {
        return;
    }
    std::map<std::string, PeerInbox> fresh;
    for (const node::Peer& peer : *peers) {
        if (!node::reachable(peer)) {
            continue;
        }
        PeerInbox box;
        box.ledger = peer.ledger_id;
        box.at = services_.clock->now();
        if (auto problem =
                attempt([&] { box.calls = client::pending_at(peer, std::nullopt).dump(); })) {
            box.problem = std::move(*problem);
        }
        fresh.emplace(peer.name, std::move(box));
    }
    {
        const std::lock_guard lock(mutex_);
        inbox_ = std::move(fresh);
    }
    // And the deliveries granted to this ledger's requests, and witnessing.
    poll_deliveries();
    poll_witnessing();
}

http::Response Console::inbox_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    // Home asks now (the parties answer within a few seconds); otherwise
    // the last answers, and the next poll is asked for.
    if (request.query.contains("refresh")) {
        poll_peers();
    } else {
        poll_now();
    }
    std::string ours;
    served->read_state(
        [&](const protocol::LedgerState& state) { ours = hex_of(state.ledger_id()); });
    nlohmann::json items = nlohmann::json::array();
    nlohmann::json problems = nlohmann::json::array();
    {
        const std::lock_guard lock(mutex_);
        for (const auto& [name, box] : inbox_) {
            if (!box.problem.empty()) {
                problems.push_back({{"peer", name}, {"problem", box.problem}});
                continue;
            }
            for (const auto& call : nlohmann::json::parse(box.calls, nullptr, false)) {
                const auto missing = call.value("missing", nlohmann::json::array());
                items.push_back({{"peer", name},
                                 {"home", hex_of(box.ledger)},
                                 {"call", call.value("call", "")},
                                 {"instance", call.value("instance", "")},
                                 {"function", call.value("function", "")},
                                 {"arguments", call.value("arguments", "")},
                                 {"until", call.value("until", "")},
                                 {"asks_us", std::ranges::any_of(missing, [&](const auto& m) {
                                      return m == ours;
                                  })}});
            }
        }
    }
    return json(200, {{"inbox", items}, {"problems", problems}});
}

http::Response Console::inbox_open_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (signer.role == Role::viewer) {
        return error(403, "forbidden", "a viewer reads and verifies, and acts on nothing");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const std::string name = body.value("peer", "");
    const std::string call_id = body.value("call", "");
    std::optional<nlohmann::json> held;
    {
        const std::lock_guard lock(mutex_);
        if (const auto box = inbox_.find(name); box != inbox_.end()) {
            for (const auto& call : nlohmann::json::parse(box->second.calls, nullptr, false)) {
                if (call.value("call", "") == call_id) {
                    held = call;
                }
            }
        }
    }
    if (!held) {
        return error(404, "not_found", "that call is no longer waiting: look at Home again");
    }
    // The terms from the home, and the instance's evidence, verified for it:
    // read as a proposal file would be.
    protocol::ExchangeFile file;
    std::optional<std::string> problem = attempt([&] {
        const node::Peer peer = client::peer_named(services_.directory.parent_path(), name);
        const auto instance = client::full_id(held->value("instance", ""), "the instance");
        auto [evidence, report] = client::fetch_instance(peer, instance);
        const auto arguments = from_hex(held->value("arguments_cbor", ""));
        if (!arguments) {
            throw client::ActionError{"the home's call does not read"};
        }
        file.kind = protocol::ExchangeKind::proposal;
        file.home = peer.ledger_id;
        file.instance = instance;
        file.head = held->value("head", std::uint64_t{0});
        file.function = held->value("function", "");
        file.arguments = client::unwrap(cbor::decode(*arguments), "the call's arguments");
        file.hash = report.instance.hash;
        file.evidence = std::move(evidence);
        for (const auto& l : held->value("missing", nlohmann::json::array())) {
            file.needs.push_back(client::full_id(l.get<std::string>(), "a ledger"));
        }
    });
    if (problem) {
        return error(502, "unavailable", *problem);
    }
    const auto encoded = protocol::encode_exchange_file(file);
    if (!encoded) {
        return error(502, "unavailable", "the home's call does not make a proposal");
    }
    const std::string upload =
        store_upload(signer.user, "online-" + call_id.substr(0, 12) + ".cexchain", *encoded);
    auto shown = read_exchange(signer, file, language_of(body.value("language", "")));
    if (auto* refused = std::get_if<http::Response>(&shown)) {
        return std::move(*refused);
    }
    nlohmann::json out = std::get<nlohmann::json>(std::move(shown));
    out["upload"] = upload;
    out["online"] = true;
    out["peer"] = name;
    return json(200, out);
}

void Console::exchange_send_route(const http::Request& request, Respond respond) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        respond(std::move(*refused));
        return;
    }
    const Signed signer = std::get<Signed>(who);
    const Evidence source = evidence();
    if (ledger() == nullptr || !source) {
        respond(error(503, "unavailable", "the console has no ledger to answer from"));
        return;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        respond(error(400, "invalid_argument", "the request's body is not a JSON object"));
        return;
    }
    const auto bytes = from_hex(body.value("record", ""));
    const auto record =
        bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(std::unexpected(bytes.error()));
    if (!record) {
        respond(error(400, "invalid_argument", "name the consent's record by its full id (hex)"));
        return;
    }
    auto read = uploaded_file(signer, body.value("upload", ""));
    if (auto* refused = std::get_if<http::Response>(&read)) {
        respond(std::move(*refused));
        return;
    }
    const protocol::ExchangeFile proposal = std::get<protocol::ExchangeFile>(std::move(read));
    std::optional<node::Peer> home;
    if (const auto peers = node::load_peers(services_.directory.parent_path())) {
        for (const node::Peer& p : *peers) {
            if (p.ledger_id == proposal.home && node::reachable(p)) {
                home = p;
            }
        }
    }
    if (!home) {
        respond(error(409, "conflict", "the home is not a party reached online: send the file"));
        return;
    }
    source(*record, [home = *home, respond = std::move(respond),
                     sender = &relay_sender_](Result<Bytes> bundle) mutable {
        if (!bundle) {
            respond(error(503, "unavailable", bundle.error().detail));
            return;
        }
        // To the home's registrar, off the ledger's writer.
        std::thread([home = std::move(home), bundle = std::move(*bundle),
                     respond = std::move(respond), sender]() mutable {
            const client::RelaySenderScope scope(sender);
            nlohmann::json answer;
            const auto problem = attempt([&] {
                answer = nlohmann::json::parse(
                    client::peer_call(home, "POST", "/v1/contracts/consents", bundle).dump());
            });
            if (problem) {
                respond(error(502, "unavailable", *problem));
                return;
            }
            respond(json(200, {{"sent", true}, {"home", answer}}));
        }).detach();
    });
}

} // namespace cexchain::console
