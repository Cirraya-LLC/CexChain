// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <limits>
#include <utility>

#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/node/connector.hpp>

#include "json_cbor.hpp"

namespace cexchain::node {

namespace detail {

std::optional<json> parse_integral_json(std::string_view text) {
    // Nesting first, without recursion, so that nothing below recurses deeper
    // than CBOR allows.
    std::size_t depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (const char c : text) {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
        } else if (c == '"') {
            in_string = true;
        } else if (c == '[' || c == '{') {
            if (++depth > cbor::max_nesting_depth) {
                return std::nullopt;
            }
        } else if ((c == ']' || c == '}') && depth > 0) {
            --depth;
        }
    }
    json parsed = json::parse(text, nullptr, false);
    if (parsed.is_discarded()) {
        return std::nullopt;
    }
    // No floating point: walk without recursion.
    std::vector<const json*> stack{&parsed};
    while (!stack.empty()) {
        const json* v = stack.back();
        stack.pop_back();
        if (v->is_number_float()) {
            return std::nullopt;
        }
        if (v->is_structured()) {
            for (const json& item : *v) {
                stack.push_back(&item);
            }
        }
    }
    return std::optional<json>(std::in_place, std::move(parsed));
}

std::optional<json> cbor_json(const cbor::Value& value, std::size_t depth) {
    if (depth > cbor::max_nesting_depth) {
        return std::nullopt;
    }
    switch (value.type()) {
    case cbor::Type::unsigned_integer:
        return std::optional<json>(std::in_place, *value.as_uint64());
    case cbor::Type::negative_integer:
        if (const auto n = value.as_int64()) {
            return std::optional<json>(std::in_place, *n);
        }
        return std::nullopt;
    case cbor::Type::bytes:
        return std::optional<json>(std::in_place, to_hex(*value.as_bytes()));
    case cbor::Type::text:
        return std::optional<json>(std::in_place, *value.as_text());
    case cbor::Type::array: {
        json out = json::array();
        for (const cbor::Value& item : *value.as_array()) {
            auto converted = cbor_json(item, depth + 1);
            if (!converted) {
                return std::nullopt;
            }
            out.push_back(std::move(*converted));
        }
        return std::optional<json>(std::in_place, std::move(out));
    }
    case cbor::Type::map: {
        json out = json::object();
        for (const cbor::MapEntry& entry : *value.as_map()) {
            const std::string* key = entry.key.as_text();
            auto converted = cbor_json(entry.value, depth + 1);
            if (key == nullptr || !converted || out.contains(*key)) {
                return std::nullopt;
            }
            out[*key] = std::move(*converted);
        }
        return std::optional<json>(std::in_place, std::move(out));
    }
    case cbor::Type::boolean:
        return std::optional<json>(std::in_place, *value.as_bool());
    case cbor::Type::null:
        return std::optional<json>(std::in_place, nullptr);
    case cbor::Type::tag:
        return std::nullopt;
    }
    return std::nullopt;
}

Result<cbor::Value> json_cbor(const json& value, std::size_t depth) {
    if (depth > cbor::max_nesting_depth) {
        return fail(Errc::limit_exceeded, "the JSON is nested too deeply");
    }
    switch (value.type()) {
    case json::value_t::null:
        return cbor::Value::null();
    case json::value_t::boolean:
        return cbor::Value::boolean(value.get<bool>());
    case json::value_t::number_integer:
        return cbor::Value::integer(value.get<std::int64_t>());
    case json::value_t::number_unsigned:
        return cbor::Value::unsigned_integer(value.get<std::uint64_t>());
    case json::value_t::string:
        return cbor::Value::text(value.get<std::string>());
    case json::value_t::array: {
        cbor::Array items;
        for (const json& item : value) {
            auto converted = json_cbor(item, depth + 1);
            if (!converted) {
                return converted;
            }
            items.push_back(std::move(*converted));
        }
        return cbor::Value::array(std::move(items));
    }
    case json::value_t::object: {
        cbor::Map entries;
        for (const auto& [key, item] : value.items()) {
            auto converted = json_cbor(item, depth + 1);
            if (!converted) {
                return converted;
            }
            entries.push_back({cbor::Value::text(key), std::move(*converted)});
        }
        return cbor::Value::map(std::move(entries));
    }
    default:
        return fail(Errc::unsupported, "numbers are integers: no fractions or exponents");
    }
}

std::optional<protocol::Id> id_from_hex(std::string_view hex) {
    if (hex.size() != 64) {
        return std::nullopt;
    }
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto parsed = protocol::to_id(*bytes);
    return parsed ? std::optional<protocol::Id>(*parsed) : std::nullopt;
}

} // namespace detail

namespace connector {

namespace {

using detail::json;

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string line_of(const json& message) {
    return message.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
}

/// The line's JSON object, without its newline.
Result<json> object_of(std::string_view line) {
    if (line.size() > max_line) {
        return fail(Errc::limit_exceeded, "a line is at most 1 MiB");
    }
    if (line.ends_with('\n')) {
        line.remove_suffix(1);
    }
    if (line.ends_with('\r')) {
        line.remove_suffix(1);
    }
    auto parsed = detail::parse_integral_json(line);
    if (!parsed || !parsed->is_object()) {
        return fail(Errc::malformed, "a line is one JSON object, with integers only");
    }
    if (!parsed->contains("type") || !(*parsed)["type"].is_string()) {
        return fail(Errc::malformed, "a message has a type");
    }
    return std::move(*parsed);
}

const json* field(const json& o, std::string_view name) {
    const auto it = o.find(name);
    return it == o.end() || it->is_null() ? nullptr : &*it;
}

Result<std::string> text_field(const json& o, std::string_view name, std::size_t max,
                               std::string_view error) {
    const json* v = field(o, name);
    if (v == nullptr || !v->is_string() || v->get_ref<const std::string&>().size() > max) {
        return std::unexpected(Error{Errc::malformed, error});
    }
    return v->get<std::string>();
}

Result<std::uint64_t> number_field(const json& o, std::string_view name, std::string_view error) {
    const json* v = field(o, name);
    if (v == nullptr || !v->is_number_unsigned()) {
        // Non-negative integers parse as unsigned.
        return std::unexpected(Error{Errc::malformed, error});
    }
    return v->get<std::uint64_t>();
}

Result<protocol::Id> id_field(const json& o, std::string_view name, std::string_view error) {
    const json* v = field(o, name);
    const auto parsed = v != nullptr && v->is_string()
                            ? detail::id_from_hex(v->get_ref<const std::string&>())
                            : std::nullopt;
    if (!parsed) {
        return std::unexpected(Error{Errc::malformed, error});
    }
    return *parsed;
}

#define CEXCHAIN_TRY(var, expr)                                                                    \
    auto var##_result = (expr);                                                                    \
    if (!var##_result) {                                                                           \
        return std::unexpected(var##_result.error());                                              \
    }                                                                                              \
    auto var = std::move(*var##_result)

Result<ToConnector> hello_of(const json& o) {
    Hello hello;
    CEXCHAIN_TRY(version, number_field(o, "protocol", "hello names its protocol version"));
    hello.protocol = version;
    CEXCHAIN_TRY(name, text_field(o, "connector", 64, "hello names the connector"));
    if (!is_name(name)) {
        return fail(Errc::malformed, "hello names the connector");
    }
    hello.connector = std::move(name);
    if (const json* config = field(o, "config")) {
        if (!config->is_object()) {
            return fail(Errc::malformed, "a connector's config is a JSON object");
        }
        hello.config = config->dump();
    }
    if (const json* secrets = field(o, "secrets")) {
        if (!secrets->is_object()) {
            return fail(Errc::malformed, "secrets are an object of texts");
        }
        for (const auto& [key, value] : secrets->items()) {
            if (!is_name(key) || !value.is_string()) {
                return fail(Errc::malformed, "secrets are an object of texts");
            }
            const auto& text = value.get_ref<const std::string&>();
            hello.secrets[key] = Secret{SecureBytes(Bytes(text.begin(), text.end()))};
        }
    }
    return hello;
}

Result<ToConnector> perform_of(const json& o) {
    Perform p;
    CEXCHAIN_TRY(request, id_field(o, "id", "perform names its request (64 hex digits)"));
    p.request = request;
    CEXCHAIN_TRY(kind, text_field(o, "kind", 64, "perform names a request kind"));
    if (!protocol::is_request_kind(kind)) {
        return fail(Errc::malformed, "perform names a request kind");
    }
    p.kind = std::move(kind);
    CEXCHAIN_TRY(params_hex, text_field(o, "params_cbor", 2 * 8192, "perform carries params_cbor"));
    const auto params_bytes = from_hex(params_hex);
    if (!params_bytes) {
        return fail(Errc::malformed, "perform carries params_cbor");
    }
    auto params = cbor::decode(*params_bytes);
    if (!params) {
        return fail(Errc::malformed, "params_cbor is not CBOR");
    }
    p.params = std::move(*params);
    CEXCHAIN_TRY(deadline, number_field(o, "deadline", "perform has a deadline"));
    p.deadline = deadline;
    CEXCHAIN_TRY(asked_at, number_field(o, "asked_at", "perform has asked_at"));
    p.asked_at = asked_at;
    CEXCHAIN_TRY(home, id_field(o, "home", "perform names the home ledger"));
    p.home = home;
    CEXCHAIN_TRY(contract, id_field(o, "contract", "perform names the contract"));
    p.contract = contract;
    CEXCHAIN_TRY(instance, id_field(o, "instance", "perform names the instance"));
    p.instance = instance;
    CEXCHAIN_TRY(reply, text_field(o, "reply", 64, "perform names the reply"));
    p.reply = std::move(reply);
    CEXCHAIN_TRY(attempt, number_field(o, "attempt", "perform counts its attempt"));
    if (attempt == 0 || attempt > std::numeric_limits<std::uint32_t>::max()) {
        return fail(Errc::malformed, "perform counts its attempt");
    }
    p.attempt = static_cast<std::uint32_t>(attempt);
    CEXCHAIN_TRY(timeout, number_field(o, "timeout_ms", "perform has timeout_ms"));
    p.timeout_ms = timeout;
    return p;
}

Result<FromConnector> outcome_of(const json& o) {
    Outcome out;
    CEXCHAIN_TRY(request, id_field(o, "id", "an outcome names its request (64 hex digits)"));
    out.request = request;
    CEXCHAIN_TRY(status,
                 text_field(o, "status", 8, "an outcome's status is done, failed, or retry"));
    if (status == "done") {
        out.status = OutcomeStatus::done;
    } else if (status == "failed") {
        out.status = OutcomeStatus::failed;
    } else if (status == "retry") {
        out.status = OutcomeStatus::retry;
    } else {
        return fail(Errc::malformed, "an outcome's status is done, failed, or retry");
    }
    if (const json* result = field(o, "result")) {
        auto converted = detail::json_cbor(*result);
        if (!converted) {
            return std::unexpected(converted.error());
        }
        const auto encoded = cbor::encode(*converted);
        if (!encoded || encoded->size() > max_result) {
            return fail(Errc::limit_exceeded, "a result is at most 16 KiB of CBOR");
        }
        out.result = std::move(*converted);
    }
    if (field(o, "reason") != nullptr) {
        CEXCHAIN_TRY(reason, text_field(o, "reason", 64, "a reason is a code like a request kind"));
        if (!protocol::is_request_kind(reason)) {
            return fail(Errc::malformed, "a reason is a code like a request kind");
        }
        out.reason = std::move(reason);
    }
    if (field(o, "response") != nullptr) {
        CEXCHAIN_TRY(text, text_field(o, "response", (max_response * 4 + 2) / 3,
                                      "a response is unpadded base64url, at most 512 KiB"));
        auto bytes = from_base64url(text);
        if (!bytes) {
            return fail(Errc::malformed, "a response is unpadded base64url, at most 512 KiB");
        }
        out.response = std::move(*bytes);
    }
    if (field(o, "retry_after_ms") != nullptr) {
        CEXCHAIN_TRY(after, number_field(o, "retry_after_ms", "retry_after_ms is a number"));
        out.retry_after_ms = after;
    }
    return out;
}

Result<FromConnector> ready_of(const json& o) {
    Ready ready;
    CEXCHAIN_TRY(version_number, number_field(o, "protocol", "ready names its protocol version"));
    ready.protocol = version_number;
    CEXCHAIN_TRY(name, text_field(o, "name", 64, "ready names the connector"));
    if (!is_name(name)) {
        return fail(Errc::malformed, "ready names the connector");
    }
    ready.name = std::move(name);
    if (field(o, "version") != nullptr) {
        CEXCHAIN_TRY(version, text_field(o, "version", 64, "a version is at most 64 bytes"));
        ready.version = std::move(version);
    }
    if (const json* kinds = field(o, "kinds")) {
        if (!kinds->is_array() || kinds->size() > 256) {
            return fail(Errc::malformed, "kinds are a list of request kinds");
        }
        for (const json& kind : *kinds) {
            if (!kind.is_string() ||
                !protocol::is_request_kind(kind.get_ref<const std::string&>())) {
                return fail(Errc::malformed, "kinds are a list of request kinds");
            }
            ready.kinds.push_back(kind.get<std::string>());
        }
    }
    return ready;
}

Result<FromConnector> log_of(const json& o) {
    Log log;
    CEXCHAIN_TRY(level, text_field(o, "level", 8, "a log's level is debug, info, warn, or error"));
    if (level == "debug") {
        log.level = LogLevel::debug;
    } else if (level == "info") {
        log.level = LogLevel::info;
    } else if (level == "warn") {
        log.level = LogLevel::warn;
    } else if (level == "error") {
        log.level = LogLevel::error;
    } else {
        return fail(Errc::malformed, "a log's level is debug, info, warn, or error");
    }
    CEXCHAIN_TRY(message, text_field(o, "message", max_log_message,
                                     "a log's message is text of at most 1,024 bytes"));
    log.message = std::move(message);
    if (field(o, "id") != nullptr) {
        CEXCHAIN_TRY(request, id_field(o, "id", "a log names a request by its id"));
        log.request = request;
    }
    return log;
}

#undef CEXCHAIN_TRY

} // namespace

bool is_name(std::string_view text) noexcept {
    return !text.empty() && text.size() <= 64 && std::ranges::all_of(text, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '.' || c == '-' || c == '_';
    });
}

std::string_view status_name(OutcomeStatus status) noexcept {
    switch (status) {
    case OutcomeStatus::done:
        return "done";
    case OutcomeStatus::failed:
        return "failed";
    case OutcomeStatus::retry:
        return "retry";
    }
    return "failed";
}

std::string_view level_name(LogLevel level) noexcept {
    switch (level) {
    case LogLevel::debug:
        return "debug";
    case LogLevel::info:
        return "info";
    case LogLevel::warn:
        return "warn";
    case LogLevel::error:
        return "error";
    }
    return "info";
}

std::string encode(const ToConnector& message) {
    return std::visit(
        [](const auto& m) -> std::string {
            using T = std::decay_t<decltype(m)>;
            if constexpr (std::is_same_v<T, Hello>) {
                json config = json::parse(m.config, nullptr, false);
                json secrets = json::object();
                for (const auto& [name, secret] : m.secrets) {
                    const ByteView v = secret.value.view();
                    secrets[name] = std::string(v.begin(), v.end());
                }
                std::string line =
                    line_of({{"type", "hello"},
                             {"protocol", m.protocol},
                             {"connector", m.connector},
                             {"config", config.is_object() ? config : json::object()},
                             {"secrets", secrets}});
                // The copies the JSON made of the secrets.
                for (auto& [name, value] : secrets.items()) {
                    auto& text = value.get_ref<std::string&>();
                    secure_wipe(
                        std::span(reinterpret_cast<std::uint8_t*>(text.data()), text.size()));
                }
                return line;
            } else if constexpr (std::is_same_v<T, Perform>) {
                const auto params = cbor::encode(m.params);
                json o = {{"type", "perform"},
                          {"id", hex(m.request)},
                          {"kind", m.kind},
                          {"params_cbor", params ? to_hex(*params) : std::string()},
                          {"deadline", m.deadline},
                          {"asked_at", m.asked_at},
                          {"home", hex(m.home)},
                          {"contract", hex(m.contract)},
                          {"instance", hex(m.instance)},
                          {"reply", m.reply},
                          {"attempt", m.attempt},
                          {"timeout_ms", m.timeout_ms}};
                if (auto as_json = detail::cbor_json(m.params)) {
                    o["params"] = std::move(*as_json);
                }
                return line_of(o);
            } else if constexpr (std::is_same_v<T, Cancel>) {
                return line_of({{"type", "cancel"}, {"id", hex(m.request)}, {"reason", m.reason}});
            } else {
                return line_of({{"type", "stop"}});
            }
        },
        message);
}

std::string encode(const FromConnector& message) {
    return std::visit(
        [](const auto& m) -> std::string {
            using T = std::decay_t<decltype(m)>;
            if constexpr (std::is_same_v<T, Ready>) {
                json o = {{"type", "ready"},
                          {"protocol", m.protocol},
                          {"name", m.name},
                          {"version", m.version}};
                if (!m.kinds.empty()) {
                    o["kinds"] = m.kinds;
                }
                return line_of(o);
            } else if constexpr (std::is_same_v<T, Outcome>) {
                json o = {{"type", "outcome"},
                          {"id", hex(m.request)},
                          {"status", std::string(status_name(m.status))}};
                if (m.result) {
                    if (auto as_json = detail::cbor_json(*m.result)) {
                        o["result"] = std::move(*as_json);
                    }
                }
                if (m.reason) {
                    o["reason"] = *m.reason;
                }
                if (m.response) {
                    o["response"] = to_base64url(*m.response);
                }
                if (m.retry_after_ms) {
                    o["retry_after_ms"] = *m.retry_after_ms;
                }
                return line_of(o);
            } else {
                json o = {{"type", "log"},
                          {"level", std::string(level_name(m.level))},
                          {"message", m.message}};
                if (m.request) {
                    o["id"] = hex(*m.request);
                }
                return line_of(o);
            }
        },
        message);
}

Result<ToConnector> decode_to_connector(std::string_view line) {
    auto o = object_of(line);
    if (!o) {
        return std::unexpected(o.error());
    }
    const auto& type = (*o)["type"].get_ref<const std::string&>();
    if (type == "hello") {
        return hello_of(*o);
    }
    if (type == "perform") {
        return perform_of(*o);
    }
    if (type == "cancel") {
        Cancel c;
        auto request = id_field(*o, "id", "cancel names its request (64 hex digits)");
        if (!request) {
            return std::unexpected(request.error());
        }
        c.request = *request;
        if (const json* reason = field(*o, "reason"); reason != nullptr && reason->is_string()) {
            c.reason = reason->get<std::string>().substr(0, 64);
        }
        return c;
    }
    if (type == "stop") {
        return Stop{};
    }
    return fail(Errc::unsupported, "a message of an unknown type");
}

Result<FromConnector> decode_from_connector(std::string_view line) {
    auto o = object_of(line);
    if (!o) {
        return std::unexpected(o.error());
    }
    const auto& type = (*o)["type"].get_ref<const std::string&>();
    if (type == "ready") {
        return ready_of(*o);
    }
    if (type == "outcome") {
        return outcome_of(*o);
    }
    if (type == "log") {
        return log_of(*o);
    }
    return fail(Errc::unsupported, "a message of an unknown type");
}

std::optional<std::string> cbor_to_json(const cbor::Value& value) {
    auto converted = detail::cbor_json(value);
    if (!converted) {
        return std::nullopt;
    }
    return converted->dump(-1, ' ', false, json::error_handler_t::replace);
}

Result<cbor::Value> json_to_cbor(std::string_view text) {
    auto parsed = detail::parse_integral_json(text);
    if (!parsed) {
        return fail(Errc::malformed, "not JSON with integers only, nested at most 64 deep");
    }
    return detail::json_cbor(*parsed);
}

} // namespace connector

} // namespace cexchain::node
