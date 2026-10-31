// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <string>
#include <utility>

#include <cexchain/app/relay.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/common.hpp>

namespace cexchain::app {

namespace {

using cbor::Value;

Value key(std::int64_t k) {
    return Value::integer(k);
}

/// to || from || id.
Bytes associated_data(const protocol::Id& to, const protocol::Id& from, const RelayId& id) {
    Bytes out(to.bytes().begin(), to.bytes().end());
    out.insert(out.end(), from.bytes().begin(), from.bytes().end());
    out.insert(out.end(), id.begin(), id.end());
    return out;
}

ByteView text_bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

Result<protocol::Id> id_from(const Value* v) {
    if (v == nullptr || v->as_bytes() == nullptr) {
        return fail(Errc::malformed, "a relay message names its ledgers by id");
    }
    return protocol::to_id(*v->as_bytes());
}

std::optional<RelayId> relay_id_from(const Value* v) {
    if (v == nullptr || v->as_bytes() == nullptr || v->as_bytes()->size() != RelayId{}.size()) {
        return std::nullopt;
    }
    RelayId out{};
    std::ranges::copy(*v->as_bytes(), out.begin());
    return out;
}

/// The text of map key `k`, if it is text.
const std::string* text_at(const Value& map, std::int64_t k) {
    const Value* v = map.find(k);
    return v == nullptr ? nullptr : v->as_text();
}

const Bytes* bytes_at(const Value& map, std::int64_t k) {
    const Value* v = map.find(k);
    return v == nullptr ? nullptr : v->as_bytes();
}

bool exact_keys(const Value& value, std::size_t n) {
    return value.as_map() != nullptr && value.as_map()->size() == n;
}

} // namespace

Result<Bytes> sign_relay_message(const crypto::Signer& log_key, const RelayEnvelope& e) {
    cbor::Map map{{key(1), Value::bytes(e.to.bytes())},
                  {key(2), Value::bytes(e.from.bytes())},
                  {key(3), Value::bytes(ByteView(e.id))},
                  {key(4), Value::array({Value::bytes(e.sealed.encapsulated_key),
                                         Value::bytes(e.sealed.ciphertext)})}};
    if (e.answers) {
        map.push_back({key(5), Value::bytes(ByteView(*e.answers))});
    }
    auto payload = cbor::encode(Value::map(std::move(map)));
    if (!payload) {
        return std::unexpected(payload.error());
    }
    cose::SignOptions options;
    options.external_aad = text_bytes(relay_message_context);
    return cose::sign(log_key, *payload, options);
}

Result<RelayMessage> parse_relay_message(ByteView message) {
    if (message.size() > max_relay_message) {
        return fail(Errc::limit_exceeded, "a relay message is at most 17 MiB");
    }
    auto signed_message = cose::parse(message);
    if (!signed_message) {
        return std::unexpected(signed_message.error());
    }
    if (!signed_message->payload) {
        return fail(Errc::malformed, "a relay message carries its payload");
    }
    auto value = cbor::decode(*signed_message->payload);
    if (!value) {
        return std::unexpected(value.error());
    }
    const Value* sealed = value->find(4);
    const auto* parts = sealed == nullptr ? nullptr : sealed->as_array();
    const auto id = relay_id_from(value->find(3));
    const Value* answers = value->find(5);
    if (!exact_keys(*value, answers == nullptr ? 4 : 5) || parts == nullptr || parts->size() != 2 ||
        (*parts)[0].as_bytes() == nullptr || (*parts)[1].as_bytes() == nullptr || !id ||
        (answers != nullptr && !relay_id_from(answers))) {
        return fail(Errc::malformed, "not a relay message");
    }
    auto to = id_from(value->find(1));
    auto from = id_from(value->find(2));
    if (!to || !from) {
        return fail(Errc::malformed, "a relay message names its ledgers by id");
    }
    RelayMessage out;
    out.envelope.to = *to;
    out.envelope.from = *from;
    out.envelope.id = *id;
    out.envelope.sealed = {*(*parts)[0].as_bytes(), *(*parts)[1].as_bytes()};
    if (answers != nullptr) {
        out.envelope.answers = relay_id_from(answers);
    }
    out.signed_message = std::move(*signed_message);
    return out;
}

Status verify_relay_message(const crypto::Provider& provider, const RelayMessage& message,
                            const crypto::PublicKey& sender_log_key) {
    return cose::verify(provider, message.signed_message, sender_log_key,
                        text_bytes(relay_message_context));
}

Result<crypto::openssl::HpkeSealed> seal_relay_request(ByteView relay_key, const protocol::Id& to,
                                                       const protocol::Id& from, const RelayId& id,
                                                       const RelayRequest& r) {
    auto plain = cbor::encode(Value::map({{key(1), Value::text(r.method)},
                                          {key(2), Value::text(r.path)},
                                          {key(3), Value::text(r.content_type)},
                                          {key(4), Value::bytes(r.body)},
                                          {key(5), Value::text(r.token)},
                                          {key(6), Value::bytes(r.answer_key)}}));
    if (!plain) {
        return std::unexpected(plain.error());
    }
    return crypto::openssl::hpke_seal(relay_key, text_bytes(relay_request_info),
                                      associated_data(to, from, id), *plain);
}

Result<RelayRequest> open_relay_request(const crypto::openssl::HpkeKey& relay_key,
                                        const RelayEnvelope& e) {
    auto plain = relay_key.open(e.sealed, text_bytes(relay_request_info),
                                associated_data(e.to, e.from, e.id));
    if (!plain) {
        return std::unexpected(plain.error());
    }
    auto value = cbor::decode(plain->view());
    if (!value) {
        return std::unexpected(value.error());
    }
    const auto* method = text_at(*value, 1);
    const auto* path = text_at(*value, 2);
    const auto* type = text_at(*value, 3);
    const auto* body = bytes_at(*value, 4);
    const auto* token = text_at(*value, 5);
    const auto* answer_key = bytes_at(*value, 6);
    if (!exact_keys(*value, 6) || method == nullptr || path == nullptr || type == nullptr ||
        body == nullptr || token == nullptr || answer_key == nullptr ||
        answer_key->size() != crypto::openssl::hpke_public_key_size || !path->starts_with("/v1/")) {
        return fail(Errc::malformed, "not a relayed request");
    }
    return RelayRequest{*method, *path, *type, *body, *token, *answer_key};
}

Result<crypto::openssl::HpkeSealed> seal_relay_answer(const RelayRequest& request,
                                                      const protocol::Id& to,
                                                      const protocol::Id& from, const RelayId& id,
                                                      const RelayAnswer& a) {
    auto plain = cbor::encode(Value::map({{key(1), Value::integer(a.status)},
                                          {key(2), Value::text(a.content_type)},
                                          {key(3), Value::bytes(a.body)}}));
    if (!plain) {
        return std::unexpected(plain.error());
    }
    return crypto::openssl::hpke_seal(request.answer_key, text_bytes(relay_answer_info),
                                      associated_data(to, from, id), *plain);
}

Result<RelayAnswer> open_relay_answer(const crypto::openssl::HpkeKey& answer_key,
                                      const protocol::Id& to, const protocol::Id& from,
                                      const RelayId& id,
                                      const crypto::openssl::HpkeSealed& sealed) {
    auto plain =
        answer_key.open(sealed, text_bytes(relay_answer_info), associated_data(to, from, id));
    if (!plain) {
        return std::unexpected(plain.error());
    }
    auto value = cbor::decode(plain->view());
    if (!value) {
        return std::unexpected(value.error());
    }
    const Value* status = value->find(1);
    const auto* type = text_at(*value, 2);
    const auto* body = bytes_at(*value, 3);
    const auto code = status == nullptr ? std::nullopt : status->as_int64();
    if (!exact_keys(*value, 3) || !code || *code < 100 || *code > 599 || type == nullptr ||
        body == nullptr) {
        return fail(Errc::malformed, "not a relayed answer");
    }
    return RelayAnswer{static_cast<int>(*code), *type, *body};
}

Result<std::string> relay_authorization(const crypto::Signer& log_key, const protocol::Id& ledger,
                                        protocol::Timestamp now) {
    auto payload = cbor::encode(Value::map(
        {{key(1), Value::bytes(ledger.bytes())}, {key(2), Value::unsigned_integer(now)}}));
    if (!payload) {
        return std::unexpected(payload.error());
    }
    cose::SignOptions options;
    options.external_aad = text_bytes(relay_fetch_context);
    auto signed_message = cose::sign(log_key, *payload, options);
    if (!signed_message) {
        return std::unexpected(signed_message.error());
    }
    return "CexChain-Relay " + to_base64url(*signed_message);
}

Result<RelayFetcher> parse_relay_authorization(std::string_view header) {
    constexpr std::string_view scheme = "CexChain-Relay ";
    if (!header.starts_with(scheme) || header.size() > 4096) {
        return fail(Errc::malformed, "send Authorization: CexChain-Relay <signed fetch>");
    }
    auto bytes = from_base64url(header.substr(scheme.size()));
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    auto signed_message = cose::parse(*bytes);
    if (!signed_message) {
        return std::unexpected(signed_message.error());
    }
    if (!signed_message->payload) {
        return fail(Errc::malformed, "a signed fetch carries its payload");
    }
    auto value = cbor::decode(*signed_message->payload);
    if (!value) {
        return std::unexpected(value.error());
    }
    auto ledger = id_from(value->find(1));
    const Value* at = value->find(2);
    if (!exact_keys(*value, 2) || !ledger || at == nullptr || !at->as_uint64()) {
        return fail(Errc::malformed, "not a signed fetch");
    }
    return RelayFetcher{*ledger, *at->as_uint64(), std::move(*signed_message)};
}

Status verify_relay_fetcher(const crypto::Provider& provider, const RelayFetcher& fetcher,
                            const crypto::PublicKey& log_key) {
    return cose::verify(provider, fetcher.signed_message, log_key, text_bytes(relay_fetch_context));
}

} // namespace cexchain::app
