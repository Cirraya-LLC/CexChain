// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The connector protocol (6b, spec/connectors.md): an executor's runtime
// reads lines from connectors, which may be any program, buggy or hostile;
// a connector reads lines from its runtime. Decoding must never crash, and
// what it accepts must be within the protocol's limits and encode to a line
// that decodes to the same message (no floating point either way). The
// first byte chooses the direction; the rest is the line.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <variant>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/node/connector.hpp>

namespace connector = cexchain::node::connector;
namespace cbor = cexchain::cbor;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

std::string encoded(const cbor::Value& value) {
    const auto bytes = cbor::encode(value);
    require(bytes.has_value());
    return cexchain::to_hex(*bytes);
}

void from_connector(std::string_view line) {
    auto decoded = connector::decode_from_connector(line);
    if (!decoded) {
        return;
    }
    const std::string again = connector::encode(*decoded);
    require(again.size() <= connector::max_line + 1024);
    require(again.ends_with('\n') && again.find('\n') == again.size() - 1);
    auto back = connector::decode_from_connector(again);
    require(back.has_value() && back->index() == decoded->index());
    if (const auto* o = std::get_if<connector::Outcome>(&*decoded)) {
        const auto& b = std::get<connector::Outcome>(*back);
        require(o->request == b.request && o->status == b.status && o->reason == b.reason &&
                o->response == b.response && o->retry_after_ms == b.retry_after_ms);
        require(o->result.has_value() == b.result.has_value());
        if (o->result) {
            require(cbor::encode(*o->result)->size() <= connector::max_result);
            require(encoded(*o->result) == encoded(*b.result));
        }
        if (o->reason) {
            require(cexchain::protocol::is_request_kind(*o->reason));
        }
        if (o->response) {
            require(o->response->size() <= connector::max_response);
        }
    } else if (const auto* r = std::get_if<connector::Ready>(&*decoded)) {
        const auto& b = std::get<connector::Ready>(*back);
        require(connector::is_name(r->name) && r->name == b.name && r->kinds == b.kinds);
    } else {
        const auto& l = std::get<connector::Log>(*decoded);
        require(l.message.size() <= connector::max_log_message &&
                l.message == std::get<connector::Log>(*back).message);
    }
}

void to_connector(std::string_view line) {
    auto decoded = connector::decode_to_connector(line);
    if (!decoded) {
        return;
    }
    const std::string again = connector::encode(*decoded);
    auto back = connector::decode_to_connector(again);
    require(back.has_value() && back->index() == decoded->index());
    if (const auto* p = std::get_if<connector::Perform>(&*decoded)) {
        const auto& b = std::get<connector::Perform>(*back);
        require(cexchain::protocol::is_request_kind(p->kind) && p->attempt >= 1);
        require(p->request == b.request && p->deadline == b.deadline &&
                encoded(p->params) == encoded(b.params));
    } else if (const auto* h = std::get_if<connector::Hello>(&*decoded)) {
        const auto& b = std::get<connector::Hello>(*back);
        require(connector::is_name(h->connector) && h->config == b.config &&
                h->secrets.size() == b.secrets.size());
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::string_view line(reinterpret_cast<const char*>(data) + 1, size - 1);
    if ((data[0] & 1) == 0) {
        from_connector(line);
    } else {
        to_connector(line);
    }
    // Any line is also a JSON text to convert.
    if (auto value = connector::json_to_cbor(line)) {
        const auto json = connector::cbor_to_json(*value);
        require(json.has_value());
        auto again = connector::json_to_cbor(*json);
        require(again.has_value() && encoded(*again) == encoded(*value));
    }
    return 0;
}
