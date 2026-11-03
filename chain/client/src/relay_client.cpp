// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include <nlohmann/json.hpp>

#include <cexchain/app/errors.hpp>
#include <cexchain/app/peers.hpp>
#include <cexchain/app/public_witness.hpp>
#include <cexchain/app/public_witnesses.hpp>
#include <cexchain/app/relay.hpp>
#include <cexchain/app/relay_client.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/id_map.hpp>
#include <cexchain/ledger/environment.hpp>
#include <cexchain/node/client.hpp>

namespace cexchain::app {

namespace {

thread_local const RelaySender* scoped_sender = nullptr;

/// Parties that did not answer through their relays lately, and until when
/// they are not asked again (a poller would otherwise wait 30 s on each).
std::mutex quiet_mutex;
std::map<protocol::IdKey, std::chrono::steady_clock::time_point> quiet_until;
constexpr std::chrono::seconds quiet_for{60};

RelayId fresh_id() {
    RelayId id{};
    ledger::SystemEntropy{}.fill(id);
    return id;
}

std::string token_of(const node::Peer& peer) {
    if (!peer.token_file) {
        return {};
    }
    const Bytes token = read_file(*peer.token_file);
    std::string text(token.begin(), token.end());
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
    }
    return text;
}

/// A client of a relay; with `authorization`, the mailbox owner's.
node::Client relay_client(const std::string& url, std::optional<std::string> authorization = {},
                          std::chrono::seconds timeout = std::chrono::seconds(40)) {
    node::ClientOptions options;
    options.max_body = max_relay_message + 64 * 1024;
    options.timeout = timeout;
    if (authorization) {
        options.headers.emplace_back("Authorization", *authorization);
    }
    return node::Client(unwrap(node::Url::parse(url), "the relay's URL"), options);
}

std::string message_of(const node::http::ClientResponse& response) {
    const auto j =
        nlohmann::json::parse(response.body.begin(), response.body.end(), nullptr, false);
    if (j.is_object() && j.contains("error") && j["error"].is_object()) {
        return j["error"].value("message", "status " + std::to_string(response.status));
    }
    return "status " + std::to_string(response.status);
}

std::string mailbox_path(const protocol::Id& ledger, std::string_view more) {
    return "/v1/relay/messages?to=" + to_hex(ledger.bytes()) + std::string(more);
}

/// The messages a fetch answered.
std::vector<RelayMessage> messages_of(const node::http::ClientResponse& response) {
    if (response.status != 200) {
        throw ActionError{"the relay refused to show the mailbox: " + message_of(response)};
    }
    const auto list = cbor::decode(response.body);
    const cbor::Array* items = list ? list->as_array() : nullptr;
    if (items == nullptr) {
        throw ActionError{"the relay's answer is not a list of messages"};
    }
    std::vector<RelayMessage> out;
    for (const cbor::Value& item : *items) {
        if (item.as_bytes() == nullptr) {
            continue;
        }
        if (auto m = parse_relay_message(*item.as_bytes())) {
            out.push_back(std::move(*m));
        }
    }
    return out;
}

/// Sends a signed message to the relay; registers the sender with the
/// relay's witness first if the relay does not know it.
void post(const std::string& url, const crypto::PublicKey& relay_witness, const Bytes& message,
          const RelaySender* sender) {
    auto response =
        unwrap(relay_client(url).request("POST", "/v1/relay/messages", message, "application/cose"),
               "reaching the relay " + url);
    const ledger::Ledger* ledger = sender != nullptr && sender->ledger ? sender->ledger() : nullptr;
    if (response.status == 403 && ledger != nullptr) {
        // Not witnessed there yet: registered (which proves the log key), then again.
        const Bytes cosignature = register_with_witness(*ledger, url, relay_witness);
        if (sender->keep) {
            sender->keep(cosignature, relay_witness);
        }
        response = unwrap(
            relay_client(url).request("POST", "/v1/relay/messages", message, "application/cose"),
            "reaching the relay " + url);
    }
    if (response.status / 100 != 2) {
        throw ActionError{"the relay " + url + " refused the message: " + message_of(response)};
    }
}

node::http::ClientResponse relayed(const node::Peer& peer, std::string_view method,
                                   const std::string& path, ByteView body,
                                   std::string_view content_type, const RelaySender& sender,
                                   std::chrono::seconds wait) {
    const node::RelayRoute& route = *peer.relay;
    {
        const std::lock_guard lock(quiet_mutex);
        if (const auto it = quiet_until.find(protocol::key_of(peer.ledger_id));
            it != quiet_until.end()) {
            if (std::chrono::steady_clock::now() < it->second) {
                throw ActionError{"peer " + peer.name +
                                  " did not answer through its relay a moment ago (is it "
                                  "online?); asked again within a minute"};
            }
            quiet_until.erase(it);
        }
    }
    const ledger::Ledger* ledger = sender.ledger ? sender.ledger() : nullptr;
    const auto log_key = sender.log_key ? sender.log_key() : nullptr;
    if (ledger == nullptr || !log_key) {
        throw ActionError{"peer " + peer.name +
                          " is reached through a relay: this ledger's log key is not at hand"};
    }
    const protocol::Id from = ledger->id();
    const RelayId id = fresh_id();
    auto answer_key = unwrap(crypto::openssl::HpkeKey::generate(), "making an answer key");
    const RelayRequest request{
        std::string(method),
        path,
        std::string(content_type),
        Bytes(body.begin(), body.end()),
        token_of(peer),
        Bytes(answer_key.public_key().begin(), answer_key.public_key().end())};
    // No use once the asker has stopped waiting.
    const protocol::Timestamp until =
        ledger::SystemClock{}.now() +
        std::min<protocol::Timestamp>(
            static_cast<protocol::Timestamp>(
                std::chrono::duration_cast<std::chrono::milliseconds>(wait).count()) +
                5'000,
            max_relay_wait);
    const RelayEnvelope envelope{
        peer.ledger_id,
        from,
        id,
        unwrap(seal_relay_request(route.key, peer.ledger_id, from, id, request), "sealing"),
        std::nullopt,
        until};
    post(route.url, route.witness, unwrap(sign_relay_message(*log_key, envelope), "signing"),
         &sender);

    // The answer comes into this ledger's mailbox at the same relay.
    const std::string wanted = "&answers=" + to_hex(ByteView(id));
    const auto deadline = std::chrono::steady_clock::now() + wait;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto left = std::chrono::duration_cast<std::chrono::seconds>(
            deadline - std::chrono::steady_clock::now());
        const auto poll = std::clamp<std::int64_t>(left.count(), 1, 25);
        const std::string authorization =
            unwrap(relay_authorization(*log_key, from, ledger::SystemClock{}.now()), "signing");
        const auto response = unwrap(
            relay_client(route.url, authorization)
                .request("GET", mailbox_path(from, wanted + "&wait=" + std::to_string(poll))),
            "reaching the relay " + route.url);
        for (const RelayMessage& m : messages_of(response)) {
            if (m.envelope.from != peer.ledger_id || m.envelope.answers != id) {
                continue;
            }
            auto answer =
                open_relay_answer(answer_key, peer.ledger_id, from, id, m.envelope.sealed);
            if (!answer) {
                continue; // Not from the party that opened the request.
            }
            static_cast<void>(relay_client(route.url, authorization)
                                  .request("DELETE", "/v1/relay/messages/" +
                                                         to_hex(ByteView(m.envelope.id)) +
                                                         "?to=" + to_hex(from.bytes())));
            node::http::ClientResponse out;
            out.status = answer->status;
            out.headers.emplace_back("content-type", answer->content_type);
            out.body = std::move(answer->body);
            return out;
        }
    }
    {
        const std::lock_guard lock(quiet_mutex);
        quiet_until[protocol::key_of(peer.ledger_id)] =
            std::chrono::steady_clock::now() + quiet_for;
    }
    throw ActionError{"peer " + peer.name + " did not answer through its relay (is it online?)"};
}

} // namespace

RelaySenderScope::RelaySenderScope(const RelaySender* sender) : previous_(scoped_sender) {
    scoped_sender = sender;
}

RelaySenderScope::~RelaySenderScope() {
    scoped_sender = previous_;
}

node::http::ClientResponse peer_request(const node::Peer& peer, std::string_view method,
                                        const std::string& path, ByteView body,
                                        std::string_view content_type, const RelaySender* sender,
                                        std::chrono::seconds wait) {
    if (peer.url) {
        return unwrap(peer_client(peer).request(method, path, body, content_type),
                      "reaching peer " + peer.name);
    }
    if (!peer.relay) {
        throw ActionError{"peer " + peer.name + " has no API URL and no relay"};
    }
    const RelaySender* through = sender != nullptr ? sender : scoped_sender;
    if (through == nullptr) {
        throw ActionError{"peer " + peer.name +
                          " is reached through a relay: give this ledger's log key"};
    }
    return relayed(peer, method, path, body, content_type, *through, wait);
}

std::optional<node::RelayRoute> load_own_relay(const std::filesystem::path& dir) {
    const std::filesystem::path path = dir / relay_file;
    if (!std::filesystem::exists(path)) {
        return std::nullopt;
    }
    const Bytes bytes = read_file(path);
    const auto j = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
    const auto key = j.is_object() && j.contains("key") && j["key"].is_string()
                         ? from_hex(j["key"].get<std::string>())
                         : Result<Bytes>(std::unexpected(Error{Errc::malformed, ""}));
    if (!j.is_object() || !j.contains("url") || !j["url"].is_string() || !key ||
        key->size() != 32 || !j.contains("witness") || !j["witness"].is_string()) {
        throw ActionError{"the relay file " + path.string() + " is damaged"};
    }
    try {
        return node::RelayRoute{j["url"].get<std::string>(), *key,
                                witness_key_from_hex(j["witness"].get<std::string>())};
    } catch (const UsageError&) {
        throw ActionError{"the relay file " + path.string() + " holds a damaged key"};
    }
}

void save_own_relay(const std::filesystem::path& dir,
                    const std::optional<node::RelayRoute>& route) {
    const std::filesystem::path path = dir / relay_file;
    if (!route) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return;
    }
    const nlohmann::json j{{"url", route->url},
                           {"key", to_hex(route->key)},
                           {"witness", witness_key_hex(route->witness)}};
    write_file(path, as_bytes(j.dump(2) + "\n"), false);
}

MailboxView look_at_mailbox(const node::RelayRoute& own, const protocol::Id& ledger,
                            const crypto::Signer& log_key) {
    const std::string authorization =
        unwrap(relay_authorization(log_key, ledger, ledger::SystemClock{}.now()), "signing");
    const auto response =
        unwrap(relay_client(own.url, authorization).request("GET", mailbox_path(ledger, "")),
               "reaching the relay " + own.url);
    MailboxView out;
    for (const RelayMessage& m : messages_of(response)) {
        ++(m.envelope.answers ? out.answers : out.requests);
    }
    return out;
}

RelayAgent::RelayAgent(node::RelayRoute own,
                       std::shared_ptr<const crypto::openssl::HpkeKey> relay_key,
                       protocol::Id ledger, LogKey log_key, Api api)
    : own_(std::move(own)), relay_key_(std::move(relay_key)), ledger_(ledger),
      log_key_(std::move(log_key)), api_(std::move(api)) {}

std::size_t RelayAgent::once(std::chrono::seconds wait) {
    const auto key = log_key_();
    if (!key) {
        throw ActionError{"the log key is not at hand (a locked console)"};
    }
    const std::string authorization =
        unwrap(relay_authorization(*key, ledger_, ledger::SystemClock{}.now()), "signing");
    const auto response =
        unwrap(relay_client(own_.url, authorization, wait + std::chrono::seconds(15))
                   .request("GET", mailbox_path(ledger_, "&requests=1&wait=" +
                                                             std::to_string(wait.count()))),
               "reaching the relay " + own_.url);
    std::size_t answered = 0;
    for (const RelayMessage& m : messages_of(response)) {
        const std::string id = to_hex(ByteView(m.envelope.id));
        auto take = [&] {
            static_cast<void>(relay_client(own_.url, authorization)
                                  .request("DELETE", "/v1/relay/messages/" + id +
                                                         "?to=" + to_hex(ledger_.bytes())));
        };
        // Not for this ledger, answered already, or asked by someone who
        // stopped waiting: taken without an answer.
        if (m.envelope.to != ledger_ || answered_.contains(id) ||
            m.envelope.until <= ledger::SystemClock{}.now()) {
            take();
            continue;
        }
        auto request = open_relay_request(*relay_key_, m.envelope);
        if (!request) {
            take(); // Not sealed to this ledger's relay key: nothing to answer.
            continue;
        }
        // Asked of this ledger's API exactly as if it had come directly.
        std::string head = request->method + " " + request->path + " HTTP/1.1\r\nHost: relay\r\n";
        if (!request->token.empty()) {
            head += "Authorization: Bearer " + request->token + "\r\n";
        }
        if (!request->content_type.empty()) {
            head += "Content-Type: " + request->content_type + "\r\n";
        }
        head += "Content-Length: " + std::to_string(request->body.size()) + "\r\n\r\n";
        std::string raw = head;
        raw.append(request->body.begin(), request->body.end());
        node::http::Limits limits;
        limits.max_body = max_relay_message;
        std::optional<node::http::ParseError> error;
        const auto parsed = node::http::parse_request(raw, limits, error);
        RelayAnswer answer{400, "application/json", {}};
        if (!parsed || error) {
            const std::string text = R"({"error":{"code":"malformed","message":"not a request"}})";
            answer.body.assign(text.begin(), text.end());
        } else {
            auto done = std::make_shared<std::promise<node::http::Response>>();
            auto future = done->get_future();
            api_(parsed->request,
                 [done](node::http::Response r) { done->set_value(std::move(r)); });
            if (future.wait_for(std::chrono::seconds(30)) == std::future_status::ready) {
                node::http::Response r = future.get();
                answer = {r.status, r.content_type, std::move(r.body)};
            } else {
                answer.status = 504;
            }
        }
        const RelayEnvelope back{m.envelope.from,
                                 ledger_,
                                 fresh_id(),
                                 unwrap(seal_relay_answer(*request, m.envelope.to, m.envelope.from,
                                                          m.envelope.id, answer),
                                        "sealing the answer"),
                                 m.envelope.id,
                                 m.envelope.until};
        post(own_.url, own_.witness, unwrap(sign_relay_message(*key, back), "signing"), nullptr);
        answered_.insert(id);
        if (answered_.size() > 10'000) {
            answered_.erase(answered_.begin());
        }
        take();
        ++answered;
    }
    return answered;
}

void RelayAgent::run(const std::stop_token& stop,
                     const std::function<void(const std::string&)>& report) {
    std::string last;
    while (!stop.stop_requested()) {
        std::string problem;
        try {
            static_cast<void>(once(std::chrono::seconds(20)));
        } catch (const ActionError& e) {
            problem = e.message;
        } catch (const UsageError& e) {
            problem = e.message;
        } catch (const std::exception& e) {
            problem = e.what();
        }
        if (problem != last) {
            report(problem);
            last = problem;
        }
        if (!problem.empty()) {
            for (int i = 0; i < 50 && !stop.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
}

} // namespace cexchain::app
