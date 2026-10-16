// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <asio/ip/address.hpp>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <map>
#include <span>
#include <utility>

#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/crypto/openssl.hpp>
#include <cexchain/node/client.hpp>
#include <cexchain/node/connectors.hpp>
#include <cexchain/node/process.hpp>

#include "json_cbor.hpp"

namespace cexchain::node::connector {

namespace {

using detail::json;

constexpr std::uint64_t max_timeout = 300;
constexpr std::uint64_t default_timeout = 30;
/// The exit code a command uses for a transient failure (sysexits.h).
constexpr int ex_tempfail = 75;

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

Outcome outcome(const Perform& p, OutcomeStatus status, std::optional<std::string> reason = {}) {
    Outcome o;
    o.request = p.request;
    o.status = status;
    o.reason = std::move(reason);
    return o;
}

/// The timeout in a connector's config: seconds, 1 to 300 (default 30).
std::optional<std::chrono::seconds> timeout_of(const json& config, std::string& error) {
    if (!config.contains("timeout")) {
        return std::chrono::seconds(default_timeout);
    }
    const json& t = config["timeout"];
    if (!t.is_number_unsigned() || t.get<std::uint64_t>() == 0 ||
        t.get<std::uint64_t>() > max_timeout) {
        error = "timeout is 1 to 300 seconds";
        return std::nullopt;
    }
    return std::chrono::seconds(t.get<std::uint64_t>());
}

/// What a receiver may add in its answer: a JSON object with "status"
/// (done, failed, or retry), "result", "reason", and "retry_after_ms". The
/// answer's bytes are the response either way. Anything else in the body is
/// ignored, so that only what the receiver means to publish reaches the
/// ledger.
void read_reply(ByteView body, Outcome& o) {
    if (body.empty() || body.size() > max_response) {
        return;
    }
    const auto parsed = detail::parse_integral_json(
        std::string_view(reinterpret_cast<const char*>(body.data()), body.size()));
    if (!parsed || !parsed->is_object()) {
        return;
    }
    const json& reply = *parsed;
    if (const auto s = reply.find("status"); s != reply.end() && s->is_string()) {
        if (*s == "failed") {
            o.status = OutcomeStatus::failed;
        } else if (*s == "retry") {
            o.status = OutcomeStatus::retry;
        }
    }
    if (const auto r = reply.find("result"); r != reply.end() && !r->is_null()) {
        if (auto value = detail::json_cbor(*r)) {
            if (const auto encoded = cbor::encode(*value);
                encoded && encoded->size() <= max_result) {
                o.result = std::move(*value);
            }
        }
    }
    if (const auto r = reply.find("reason");
        r != reply.end() && r->is_string() && protocol::is_request_kind(r->get<std::string>())) {
        o.reason = r->get<std::string>();
    }
    if (const auto r = reply.find("retry_after_ms"); r != reply.end() && r->is_number_unsigned()) {
        o.retry_after_ms = r->get<std::uint64_t>();
    }
}

bool loopback(const std::string& host) {
    if (host == "localhost") {
        return true;
    }
    asio::error_code ec;
    const auto address = asio::ip::make_address(host, ec);
    return !ec && address.is_loopback();
}

class Webhook final : public Performer {
public:
    Webhook(Url url, ClientOptions options, SecureBytes secret)
        : url_(std::move(url)), options_(std::move(options)), secret_(std::move(secret)) {}

    Outcome perform(const Perform& p) override {
        const std::string body = request_document(p);
        const std::string timestamp =
            std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count());
        const auto signature = webhook_signature(secret_.view(), timestamp, body);
        if (!signature) {
            return outcome(p, OutcomeStatus::failed, "unavailable");
        }
        ClientOptions options = options_;
        options.headers = {{"X-CexChain-Request", hex(p.request)},
                           {"X-CexChain-Attempt", std::to_string(p.attempt)},
                           {"X-CexChain-Timestamp", timestamp},
                           {"X-CexChain-Signature", "sha256=" + *signature},
                           {"Idempotency-Key", hex(p.request)}};
        const Client client(Url{url_.tls, url_.host, url_.port, ""}, options);
        const std::string path = url_.base_path.empty() ? "/" : url_.base_path;
        const auto answer =
            client.request("POST", path, as_bytes(std::string_view(body)), "application/json");
        if (!answer) {
            // Nothing reached the receiver, or no answer came: try again.
            return outcome(p, OutcomeStatus::retry,
                           answer.error().code == Errc::verification_failed ? "tls"
                                                                            : "unavailable");
        }
        Outcome o = outcome(p, OutcomeStatus::done);
        const int status = answer->status;
        if (status >= 200 && status < 300) {
            o.status = OutcomeStatus::done;
        } else if (status == 408 || status == 425 || status == 429 || status >= 500) {
            o.status = OutcomeStatus::retry;
            o.reason = "unavailable";
            if (const auto after = answer->header("retry-after")) {
                std::uint64_t seconds = 0;
                const auto [end, ec] =
                    std::from_chars(after->data(), after->data() + after->size(), seconds);
                if (ec == std::errc() && end == after->data() + after->size()) {
                    o.retry_after_ms = std::min<std::uint64_t>(seconds, max_timeout) * 1000;
                }
            }
        } else {
            o.status = OutcomeStatus::failed;
            o.reason = "rejected";
        }
        o.response = Bytes(answer->body.begin(), answer->body.end());
        if (status >= 200 && status < 300) {
            read_reply(answer->body, o);
        } else if (o.status == OutcomeStatus::failed) {
            // A refusal's reason, if it gives one as a code.
            Outcome reasoned = o;
            read_reply(answer->body, reasoned);
            o.reason = reasoned.reason;
            o.result = std::move(reasoned.result);
        }
        if (o.status == OutcomeStatus::failed && !o.reason) {
            o.reason = "rejected";
        }
        return o;
    }

private:
    Url url_;
    ClientOptions options_;
    SecureBytes secret_;
};

class Command final : public Performer {
public:
    Command(std::string program, std::vector<std::string> arguments, std::chrono::seconds timeout,
            std::map<std::string, std::string> secrets)
        : program_(std::move(program)), arguments_(std::move(arguments)), timeout_(timeout),
          secrets_(std::move(secrets)) {}
    Command(const Command&) = delete;
    Command& operator=(const Command&) = delete;
    ~Command() override {
        for (auto& [name, value] : secrets_) {
            secure_wipe(std::span(reinterpret_cast<std::uint8_t*>(value.data()), value.size()));
        }
    }

    Outcome perform(const Perform& p) override {
        std::string input = request_document(p, secrets_);
        auto child = ChildProcess::start(program_, arguments_);
        if (!child) {
            wipe(input);
            return outcome(p, OutcomeStatus::retry, "unavailable");
        }
        const auto run = child->communicate(
            as_bytes(std::string_view(input)),
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout_), max_response);
        wipe(input);
        Outcome o = outcome(p, OutcomeStatus::done);
        o.response = run.output;
        if (!run.exit) {
            o.status = OutcomeStatus::retry;
            o.reason = "timeout";
            return o;
        }
        if (run.exit->success()) {
            read_reply(run.output, o);
        } else if (run.exit->code == ex_tempfail || run.exit->signal != 0) {
            o.status = OutcomeStatus::retry;
            o.reason = run.exit->signal != 0 ? "crashed" : "unavailable";
            read_reply(run.output, o);
            o.status = OutcomeStatus::retry;
        } else {
            o.status = OutcomeStatus::failed;
            read_reply(run.output, o);
            o.status = OutcomeStatus::failed;
            if (!o.reason) {
                o.reason = "rejected";
            }
        }
        return o;
    }

private:
    static void wipe(std::string& text) {
        secure_wipe(std::span(reinterpret_cast<std::uint8_t*>(text.data()), text.size()));
    }
    static std::string request_document(const Perform& p,
                                        const std::map<std::string, std::string>& secrets);

    std::string program_;
    std::vector<std::string> arguments_;
    std::chrono::seconds timeout_;
    std::map<std::string, std::string> secrets_;
};

json document_of(const Perform& p) {
    const auto params = cbor::encode(p.params);
    json o = {{"protocol", protocol_version},
              {"id", hex(p.request)},
              {"kind", p.kind},
              {"params_cbor", params ? to_hex(*params) : std::string()},
              {"deadline", p.deadline},
              {"asked_at", p.asked_at},
              {"home", hex(p.home)},
              {"contract", hex(p.contract)},
              {"instance", hex(p.instance)},
              {"reply", p.reply},
              {"attempt", p.attempt}};
    if (auto as_json = detail::cbor_json(p.params)) {
        o["params"] = std::move(*as_json);
    }
    return o;
}

std::string Command::request_document(const Perform& p,
                                      const std::map<std::string, std::string>& secrets) {
    json o = document_of(p);
    if (!secrets.empty()) {
        o["secrets"] = secrets;
    }
    std::string text = o.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
    if (o.contains("secrets")) {
        for (auto& [name, value] : o["secrets"].items()) {
            wipe(value.get_ref<std::string&>());
        }
    }
    return text;
}

json config_of(const Hello& hello, std::string& error) {
    auto parsed = detail::parse_integral_json(hello.config);
    if (!parsed || !parsed->is_object()) {
        error = "the connector's config is not a JSON object with integers only";
        return nullptr;
    }
    return std::move(*parsed);
}

} // namespace

std::string request_document(const Perform& request) {
    return document_of(request).dump(-1, ' ', false, json::error_handler_t::replace);
}

Result<std::string> webhook_signature(ByteView secret, std::string_view timestamp,
                                      std::string_view body) {
    std::string message;
    message.reserve(timestamp.size() + 1 + body.size());
    message.append(timestamp).append(".").append(body);
    const auto mac = crypto::openssl::hmac(crypto::HashAlg::sha256, secret, as_bytes(message));
    if (!mac) {
        return std::unexpected(mac.error());
    }
    return to_hex(mac->bytes());
}

std::unique_ptr<Performer> make_webhook(const Hello& hello, std::string& error) {
    const json config = config_of(hello, error);
    if (config.is_null()) {
        return nullptr;
    }
    const auto url_text = config.find("url");
    if (url_text == config.end() || !url_text->is_string()) {
        error = "a webhook names its url";
        return nullptr;
    }
    auto url = Url::parse(url_text->get<std::string>());
    if (!url) {
        error = std::format("its url: {}", url.error().detail);
        return nullptr;
    }
    if (!url->tls && !loopback(url->host)) {
        error = "a webhook's url is https:// (http:// only to this computer: 127.0.0.1, ::1, "
                "localhost)";
        return nullptr;
    }
    const auto secret_name = config.find("secret");
    if (secret_name == config.end() || !secret_name->is_string()) {
        error = "a webhook names its secret, the HMAC key it signs with";
        return nullptr;
    }
    const auto secret = hello.secrets.find(secret_name->get<std::string>());
    if (secret == hello.secrets.end() || secret->second.value.empty()) {
        error = std::format("the secret {} did not arrive (executor secret set {})",
                            secret_name->get<std::string>(), secret_name->get<std::string>());
        return nullptr;
    }
    ClientOptions options;
    const auto timeout = timeout_of(config, error);
    if (!timeout) {
        return nullptr;
    }
    options.timeout = *timeout;
    options.follow_redirects = false;
    options.max_body = max_response;
    if (const auto ca = config.find("ca_file"); ca != config.end()) {
        if (!ca->is_string() || !std::filesystem::exists(ca->get<std::string>())) {
            error = "ca_file is a PEM file that exists";
            return nullptr;
        }
        options.ca_file = ca->get<std::string>();
    }
    const ByteView v = secret->second.value.view();
    return std::make_unique<Webhook>(std::move(*url), std::move(options),
                                     SecureBytes(Bytes(v.begin(), v.end())));
}

std::unique_ptr<Performer> make_command(const Hello& hello, std::string& error) {
    const json config = config_of(hello, error);
    if (config.is_null()) {
        return nullptr;
    }
    const auto program = config.find("program");
    if (program == config.end() || !program->is_string() ||
        program->get_ref<const std::string&>().empty()) {
        error = "a command names its program";
        return nullptr;
    }
    std::vector<std::string> arguments;
    if (const auto args = config.find("args"); args != config.end()) {
        if (!args->is_array() ||
            !std::ranges::all_of(*args, [](const json& a) { return a.is_string(); })) {
            error = "args is a list of texts";
            return nullptr;
        }
        for (const json& a : *args) {
            arguments.push_back(a.get<std::string>());
        }
    }
    const auto timeout = timeout_of(config, error);
    if (!timeout) {
        return nullptr;
    }
    std::map<std::string, std::string> secrets;
    if (const auto names = config.find("secrets"); names != config.end()) {
        if (!names->is_array()) {
            error = "secrets is a list of secret names";
            return nullptr;
        }
        for (const json& n : *names) {
            const auto found =
                n.is_string() ? hello.secrets.find(n.get<std::string>()) : hello.secrets.end();
            if (found == hello.secrets.end()) {
                error = "a secret the command names did not arrive (executor secret set NAME)";
                return nullptr;
            }
            const ByteView v = found->second.value.view();
            secrets[found->first] = std::string(v.begin(), v.end());
        }
    }
    return std::make_unique<Command>(program->get<std::string>(), std::move(arguments), *timeout,
                                     std::move(secrets));
}

int serve(const LineIo& io, std::string_view name, std::string_view version,
          const PerformerFactory& make) {
    auto log = [&](LogLevel level, std::string message,
                   std::optional<protocol::Id> request = std::nullopt) {
        return io.write(encode(FromConnector(Log{level, std::move(message), request})));
    };
    std::unique_ptr<Performer> performer;
    while (auto line = io.read()) {
        auto message = decode_to_connector(*line);
        if (!message) {
            if (!log(LogLevel::warn,
                     std::format("a line it cannot read: {}", message.error().detail))) {
                return 0;
            }
            continue;
        }
        if (auto* hello = std::get_if<Hello>(&*message)) {
            if (hello->protocol != protocol_version) {
                log(LogLevel::error, std::format("it speaks protocol {}, not {}", protocol_version,
                                                 hello->protocol));
                return 2;
            }
            std::string error;
            performer = make(*hello, error);
            if (!performer) {
                log(LogLevel::error, error);
                return 2;
            }
            if (!io.write(encode(FromConnector(Ready{protocol_version, std::string(name),
                                                     std::string(version), performer->kinds()})))) {
                return 0;
            }
        } else if (const auto* perform = std::get_if<Perform>(&*message)) {
            if (!performer) {
                log(LogLevel::error, "a request came before hello", perform->request);
                continue;
            }
            if (!io.write(encode(FromConnector(performer->perform(*perform))))) {
                return 0;
            }
        } else if (std::holds_alternative<Stop>(*message)) {
            return 0;
        }
        // A cancel: requests are performed one at a time, so none is in
        // progress when one arrives.
    }
    return 0;
}

} // namespace cexchain::node::connector
