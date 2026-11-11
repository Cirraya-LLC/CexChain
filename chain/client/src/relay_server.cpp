// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <string>
#include <system_error>
#include <variant>

#include <nlohmann/json.hpp>

#include <kanhe/client/errors.hpp>
#include <kanhe/client/relay_server.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/client/witness.hpp>
#include <kanhe/core/cbor.hpp>

namespace kanhe::client {

namespace {

using node::http::Response;

constexpr protocol::Timestamp day_ms = 24 * 60 * 60'000;

Response answer(int status, const nlohmann::json& body) {
    Response r;
    r.status = status;
    r.principal = "relay";
    const std::string text = body.dump() + "\n";
    r.body.assign(text.begin(), text.end());
    return r;
}

Response refusal(int status, std::string_view code, std::string_view message) {
    return answer(status, {{"error", {{"code", code}, {"message", message}}}});
}

Response too_many(std::string_view message, protocol::Timestamp retry_ms) {
    auto r = refusal(429, "limit_exceeded", message);
    r.headers.emplace_back("Retry-After",
                           std::to_string(std::max<protocol::Timestamp>(1, retry_ms / 1000)));
    return r;
}

std::optional<protocol::Id> ledger_param(const node::http::Request& r) {
    const auto it = r.query.find("to");
    if (it == r.query.end()) {
        return std::nullopt;
    }
    const auto bytes = from_hex(it->second);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

/// The log key in effect of a ledger the witness follows.
std::optional<crypto::PublicKey> log_key_of(const std::filesystem::path& witness_dir,
                                            const protocol::Id& ledger) {
    const auto path = witness_state_path(witness_dir, ledger);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return std::nullopt;
    }
    try {
        return decode_witness_state(path).log.log_key;
    } catch (const ActionError&) {
        return std::nullopt;
    }
}

std::string digits16(protocol::Timestamp at) {
    std::string digits = std::to_string(at);
    digits.insert(0, digits.size() < 16 ? 16 - digits.size() : 0, '0');
    return digits;
}

/// <sent at>-<until>-<id hex>[-<id of the request it answers>].msg, the times
/// in 16 digits: names sort by arrival, and say when a message expires and
/// which messages are answers.
std::string message_name(protocol::Timestamp at, const RelayEnvelope& e) {
    return digits16(at) + "-" + digits16(e.until) + "-" + to_hex(ByteView(e.id)) +
           (e.answers ? "-" + to_hex(ByteView(*e.answers)) : std::string()) + ".msg";
}

/// The id a message's file name gives, and the request it answers, if any.
std::pair<std::string, std::string> ids_of(const std::filesystem::path& file) {
    const std::string stem = file.stem().string();
    const std::string id = stem.size() >= 66 ? stem.substr(34, 32) : std::string();
    const std::string answers = stem.size() == 99 ? stem.substr(67, 32) : std::string();
    return {id, answers};
}

std::optional<protocol::Timestamp> time_at(const std::string& name, std::size_t offset) {
    if (name.size() < offset + 16) {
        return std::nullopt;
    }
    protocol::Timestamp at = 0;
    const auto [end, ec] = std::from_chars(name.data() + offset, name.data() + offset + 16, at);
    if (ec != std::errc{} || end != name.data() + offset + 16) {
        return std::nullopt;
    }
    return at;
}

std::optional<protocol::Timestamp> sent_at(const std::filesystem::path& file) {
    const std::string name = file.filename().string();
    return name.ends_with(".msg") ? time_at(name, 0) : std::nullopt;
}

std::optional<protocol::Timestamp> until_of(const std::filesystem::path& file) {
    return time_at(file.filename().string(), 17);
}

std::vector<std::filesystem::path> messages_in(const std::filesystem::path& box) {
    std::vector<std::filesystem::path> out;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(box, ec)) {
        if (sent_at(entry.path())) {
            out.push_back(entry.path());
        }
    }
    std::ranges::sort(out);
    return out;
}

} // namespace

bool Relay::Wanted::operator()(const std::filesystem::path& file) const {
    const auto [id, answered] = ids_of(file);
    return answers.empty() ? !requests_only || answered.empty() : answered == answers;
}

Relay::Relay(std::filesystem::path dir, std::filesystem::path witness_dir, RelayLimits limits)
    : dir_(std::move(dir)), witness_dir_(std::move(witness_dir)), limits_(limits) {
    std::filesystem::create_directories(dir_);
}

std::filesystem::path Relay::box(const protocol::Id& ledger) const {
    return dir_ / to_hex(ledger.bytes());
}

std::pair<std::size_t, std::uint64_t> Relay::mailbox(const protocol::Id& ledger) const {
    std::size_t n = 0;
    std::uint64_t bytes = 0;
    std::error_code ec;
    for (const auto& file : messages_in(box(ledger))) {
        ++n;
        bytes += std::filesystem::file_size(file, ec);
    }
    return {n, bytes};
}

void Relay::prune(const protocol::Id& ledger, protocol::Timestamp now) const {
    std::error_code ec;
    for (const auto& file : messages_in(box(ledger))) {
        const auto at = sent_at(file);
        const auto until = until_of(file);
        if (!at || !until || *at + limits_.keep < now || *until < now) {
            std::filesystem::remove(file, ec);
        }
    }
}

bool Relay::handle(const node::http::Request& request, protocol::Timestamp now, Respond respond) {
    constexpr std::string_view base = "/v1/relay/messages";
    if (!request.path.starts_with(base)) {
        return false;
    }
    const std::string_view rest = std::string_view(request.path).substr(base.size());
    if (rest.empty() && request.method == "POST") {
        const std::lock_guard lock(mutex_);
        auto stored = post(request.body, now);
        respond(std::move(stored));
        return true;
    }
    if (rest.empty() && request.method == "GET") {
        auto who = fetcher(request, now);
        if (auto* refused = std::get_if<Response>(&who)) {
            respond(std::move(*refused));
            return true;
        }
        const protocol::Id ledger = std::get<protocol::Id>(who);
        protocol::Timestamp wait = 0;
        if (const auto it = request.query.find("wait"); it != request.query.end()) {
            std::uint64_t seconds = 0;
            const auto [end, ec] =
                std::from_chars(it->second.data(), it->second.data() + it->second.size(), seconds);
            if (ec != std::errc{} || end != it->second.data() + it->second.size()) {
                respond(refusal(400, "invalid_argument", "wait=SECONDS"));
                return true;
            }
            wait = std::min<protocol::Timestamp>(seconds * 1000, limits_.max_wait);
        }
        Wanted wanted;
        if (const auto it = request.query.find("requests"); it != request.query.end()) {
            wanted.requests_only = it->second == "1";
        }
        if (const auto it = request.query.find("answers"); it != request.query.end()) {
            const auto id = from_hex(it->second);
            if (!id || id->size() != RelayId{}.size()) {
                respond(refusal(400, "invalid_argument", "answers=<32 hex digits>"));
                return true;
            }
            wanted.answers = to_hex(*id);
        }
        const std::lock_guard lock(mutex_);
        prune(ledger, now);
        const auto files = messages_in(box(ledger));
        if (wait == 0 || std::ranges::any_of(files, wanted)) {
            respond(listing(ledger, wanted));
        } else {
            waiting_.push_back({ledger, std::move(wanted), now + wait, std::move(respond)});
        }
        return true;
    }
    if (rest.starts_with("/") && request.method == "DELETE") {
        auto who = fetcher(request, now);
        if (auto* refused = std::get_if<Response>(&who)) {
            respond(std::move(*refused));
            return true;
        }
        const auto id = from_hex(rest.substr(1));
        if (!id || id->size() != RelayId{}.size()) {
            respond(refusal(400, "invalid_argument", "DELETE /v1/relay/messages/<32 hex digits>"));
            return true;
        }
        const std::lock_guard lock(mutex_);
        bool removed = false;
        std::error_code ec;
        for (const auto& file : messages_in(box(std::get<protocol::Id>(who)))) {
            if (ids_of(file).first == to_hex(*id)) {
                removed = std::filesystem::remove(file, ec) || removed;
            }
        }
        respond(removed ? answer(200, {{"removed", to_hex(*id)}})
                        : refusal(404, "not_found", "no such message in this mailbox"));
        return true;
    }
    auto r = refusal(405, "unsupported", "method not allowed");
    r.headers.emplace_back("Allow", rest.empty() ? "GET, POST" : "DELETE");
    respond(std::move(r));
    return true;
}

Response Relay::post(ByteView body, protocol::Timestamp now) {
    auto message = parse_relay_message(body);
    if (!message) {
        return message.error().code == Errc::limit_exceeded
                   ? refusal(413, "limit_exceeded", message.error().detail)
                   : refusal(400, "malformed", message.error().detail);
    }
    const RelayEnvelope& e = message->envelope;
    if (e.until <= now) {
        return refusal(422, "rejected", "the message expired before it came");
    }
    if (e.until > now + limits_.keep) {
        return refusal(400, "invalid_argument", "a message is kept 14 days at most");
    }
    const auto sender = log_key_of(witness_dir_, e.from);
    if (!sender) {
        return refusal(403, "forbidden",
                       "the sender's ledger is not witnessed here: register it first");
    }
    if (!verify_relay_message(shared_provider(), *message, *sender)) {
        return refusal(422, "verification_failed", "not signed by the sender's log key in effect");
    }
    if (!log_key_of(witness_dir_, e.to)) {
        return refusal(404, "not_found", "the recipient's ledger is not witnessed here");
    }
    const std::filesystem::path to = box(e.to);
    std::error_code ec;
    for (const auto& file : messages_in(to)) {
        if (ids_of(file).first == to_hex(ByteView(e.id))) {
            // Sent again: kept once.
            return answer(200, {{"id", to_hex(ByteView(e.id))}});
        }
    }
    prune(e.to, now);
    const auto [count, bytes] = mailbox(e.to);
    if (count >= limits_.mailbox_messages || bytes + body.size() > limits_.mailbox_bytes) {
        return too_many("the recipient's mailbox is full", 60'000);
    }
    const std::uint64_t today = now / day_ms;
    auto& [day, sent] = sent_[protocol::key_of(e.from)];
    if (day != today) {
        day = today;
        sent = {0, 0};
    }
    if (sent.first >= limits_.sender_messages_per_day ||
        sent.second + body.size() > limits_.sender_bytes_per_day) {
        return too_many("this ledger sent as much as it may today", (today + 1) * day_ms - now);
    }
    std::filesystem::create_directories(to);
    write_file(to / message_name(now, e), body, false);
    ++sent.first;
    sent.second += body.size();
    // Whoever waits for this mailbox gets it now.
    const std::filesystem::path stored = to / message_name(now, e);
    for (auto it = waiting_.begin(); it != waiting_.end();) {
        if (it->ledger == e.to && it->wanted(stored)) {
            it->respond(listing(e.to, it->wanted));
            it = waiting_.erase(it);
        } else {
            ++it;
        }
    }
    return answer(201, {{"id", to_hex(ByteView(e.id))}});
}

Response Relay::listing(const protocol::Id& ledger, const Wanted& wanted) const {
    cbor::Array items;
    std::size_t total = 0;
    for (const auto& file : messages_in(box(ledger))) {
        if (!wanted(file)) {
            continue;
        }
        Bytes bytes;
        try {
            bytes = read_file(file);
        } catch (const ActionError&) {
            continue;
        }
        if (!items.empty() && total + bytes.size() > max_relay_message) {
            break;
        }
        total += bytes.size();
        items.push_back(cbor::Value::bytes(std::move(bytes)));
    }
    auto encoded = cbor::encode(cbor::Value::array(std::move(items)));
    if (!encoded) {
        return refusal(500, "internal", "cannot encode the mailbox");
    }
    Response r;
    r.principal = "relay";
    r.content_type = "application/cbor";
    r.body = std::move(*encoded);
    return r;
}

std::variant<protocol::Id, Response> Relay::fetcher(const node::http::Request& request,
                                                    protocol::Timestamp now) const {
    const auto ledger = ledger_param(request);
    if (!ledger) {
        return refusal(400, "invalid_argument", "name the mailbox: ?to=<ledger id>");
    }
    const auto header = request.header("authorization");
    if (!header) {
        return refusal(401, "unauthorized", "send Authorization: Kanhe-Relay <signed fetch>");
    }
    auto who = parse_relay_authorization(*header);
    if (!who || who->ledger != *ledger) {
        return refusal(401, "unauthorized", "not a signed fetch for this mailbox");
    }
    if (who->at + relay_fetch_skew < now || now + relay_fetch_skew < who->at) {
        return refusal(401, "unauthorized", "the signed fetch is too old, or from the future");
    }
    const auto key = log_key_of(witness_dir_, *ledger);
    if (!key) {
        return refusal(404, "not_found", "this ledger is not witnessed here: register it first");
    }
    if (!verify_relay_fetcher(shared_provider(), *who, *key)) {
        return refusal(401, "unauthorized", "not signed by the ledger's log key in effect");
    }
    return *ledger;
}

void Relay::tick(protocol::Timestamp now) {
    std::vector<Waiting> due;
    {
        const std::lock_guard lock(mutex_);
        for (auto it = waiting_.begin(); it != waiting_.end();) {
            if (it->until <= now) {
                due.push_back(std::move(*it));
                it = waiting_.erase(it);
            } else {
                ++it;
            }
        }
        // Old messages go once an hour, from every mailbox.
        if (now >= pruned_ + 60 * 60'000) {
            pruned_ = now;
            std::error_code ec;
            for (const auto& entry : std::filesystem::directory_iterator(dir_, ec)) {
                const auto bytes = from_hex(entry.path().filename().string());
                if (!bytes) {
                    continue;
                }
                if (const auto id = protocol::to_id(*bytes)) {
                    prune(*id, now);
                }
            }
        }
    }
    for (Waiting& w : due) {
        const std::lock_guard lock(mutex_);
        w.respond(listing(w.ledger, w.wanted));
    }
}

void Relay::stopping() {
    std::vector<Waiting> all;
    {
        const std::lock_guard lock(mutex_);
        all = std::move(waiting_);
        waiting_.clear();
    }
    for (Waiting& w : all) {
        w.respond(listing(w.ledger, w.wanted));
    }
}

} // namespace kanhe::client
