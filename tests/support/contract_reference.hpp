// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

// A contract's input and output as the core built and read them before it
// read states as bytes: through CBOR trees. The core now splices encoded states into
// inputs and slices them out of outputs; this reference must agree with it
// byte for byte (tests/core/contract_bytes_test.cpp, fuzz/cbor_validate_fuzz).
// Header-only, for the tests and the fuzz target; needs core/src on the
// include path (protocol/reader.hpp).

#include <optional>
#include <string>
#include <utility>
#include <variant>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contracts.hpp>

#include "protocol/reader.hpp"

namespace cexchain::test::reference {

namespace detail {

using protocol::detail::entry;
using protocol::detail::MapReader;

inline bool text_within(const std::string* text, std::size_t max) {
    return text != nullptr && !text->empty() && text->size() <= max;
}

inline cbor::Value parties_value(const protocol::Parties& parties) {
    cbor::Map map;
    for (const auto& [role, ledger] : parties) {
        map.push_back({cbor::Value::text(role), cbor::Value::bytes(ledger.bytes())});
    }
    return cbor::Value::map(std::move(map));
}

inline Result<protocol::Parties> decode_parties(const cbor::Value& value) {
    const cbor::Map* map = value.as_map();
    if (map == nullptr || map->empty() || map->size() > protocol::max_contract_parties) {
        return fail(Errc::malformed, "a contract's parties are 1 to 64 roles");
    }
    protocol::Parties parties;
    for (const cbor::MapEntry& e : *map) {
        const Bytes* ledger = e.value.as_bytes();
        if (!text_within(e.key.as_text(), protocol::max_function_name) || ledger == nullptr ||
            ledger->size() != protocol::id_size) {
            return fail(Errc::malformed, "a party is a role of 1 to 64 bytes and a ledger id");
        }
        parties.emplace(*e.key.as_text(), *protocol::to_id(*ledger));
    }
    return parties;
}

inline Result<protocol::ContractNeeds> decode_needs(const cbor::Value& value,
                                                    const protocol::Id& home) {
    const cbor::Array* items = value.as_array();
    if (items == nullptr || items->empty() || items->size() > protocol::max_contract_consents) {
        return fail(Errc::malformed, "a contract needs the consents of 1 to 16 ledgers");
    }
    protocol::ContractNeeds needs;
    for (const cbor::Value& item : *items) {
        const Bytes* bytes = item.as_bytes();
        if (bytes == nullptr || bytes->size() != protocol::id_size) {
            return fail(Errc::malformed, "a contract names ledgers by their ids");
        }
        protocol::Id ledger = *protocol::to_id(*bytes);
        if (ledger == home) {
            return fail(Errc::malformed, "a contract never needs its home's consent");
        }
        if (!needs.ledgers.empty() &&
            !std::ranges::lexicographical_compare(needs.ledgers.back().bytes(), ledger.bytes())) {
            return fail(Errc::malformed, "the ledgers a contract needs ascend, each once");
        }
        needs.ledgers.push_back(std::move(ledger));
    }
    return needs;
}

struct InstanceFields {
    cbor::Value state;
    std::optional<std::string> status;
    std::optional<protocol::Parties> parties;
};

inline Result<InstanceFields> decode_instance_fields(MapReader& reader) {
    InstanceFields out;
    auto state = reader.need(1);
    if (!state) {
        return std::unexpected(state.error());
    }
    auto encoded_state = cbor::encode(**state);
    if (!encoded_state) {
        return std::unexpected(encoded_state.error());
    }
    if (encoded_state->size() > protocol::max_contract_value) {
        return fail(Errc::malformed, "an instance's state is at most 65,536 bytes");
    }
    out.state = **state;
    if (const cbor::Value* status = reader.get(2)) {
        if (!text_within(status->as_text(), protocol::max_contract_status)) {
            return fail(Errc::malformed, "an instance's status is 1 to 64 bytes");
        }
        out.status = *status->as_text();
    }
    if (const cbor::Value* parties = reader.get(3)) {
        auto decoded = decode_parties(*parties);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        out.parties = std::move(*decoded);
    }
    return out;
}

/// The tree's encoding, as the state the core keeps.
inline cbor::Encoded encoded(const cbor::Value& value) {
    auto out = cbor::Encoded::encode(value);
    return out ? std::move(*out) : cbor::Encoded();
}

inline Result<protocol::ContractChild> decode_child(const cbor::Value& value) {
    auto reader = MapReader::open(value);
    if (!reader) {
        return fail(Errc::malformed, "a child is a map");
    }
    auto fields = decode_instance_fields(*reader);
    if (!fields) {
        return std::unexpected(fields.error());
    }
    if (!reader->finish()) {
        return fail(Errc::malformed, "a child holds only its state, status, and parties");
    }
    return protocol::ContractChild{encoded(fields->state), std::move(fields->status),
                                   std::move(fields->parties).value_or(protocol::Parties{})};
}

inline Result<protocol::ContractRequest> decode_request(const cbor::Value& value) {
    auto reader = MapReader::open(value);
    if (!reader) {
        return fail(Errc::malformed, "a request is a map");
    }
    const cbor::Value* kind = reader->get(1);
    const cbor::Value* params = reader->get(2);
    const cbor::Value* deadline = reader->get(3);
    const cbor::Value* reply = reader->get(4);
    if (kind == nullptr || params == nullptr || deadline == nullptr || reply == nullptr ||
        !reader->finish()) {
        return fail(Errc::malformed, "a request holds exactly its kind, params, deadline, and "
                                     "reply");
    }
    if (kind->as_text() == nullptr || !protocol::is_request_kind(*kind->as_text())) {
        return fail(Errc::malformed, "a request's kind is 1 to 64 bytes of a-z, 0-9, '.', '_', "
                                     "and '-', starting with a letter");
    }
    auto encoded_params = cbor::encode(*params);
    if (!encoded_params) {
        return std::unexpected(encoded_params.error());
    }
    if (encoded_params->size() > protocol::max_request_params) {
        return fail(Errc::malformed, "a request's params are at most 4,096 bytes");
    }
    if (!deadline->as_uint64()) {
        return fail(Errc::malformed, "a request's deadline is a time in milliseconds");
    }
    if (!text_within(reply->as_text(), protocol::max_function_name)) {
        return fail(Errc::malformed, "a request's reply is a function name of 1 to 64 bytes");
    }
    return protocol::ContractRequest{*kind->as_text(), *params, *deadline->as_uint64(),
                                     *reply->as_text()};
}

inline Result<protocol::ContractAccept> decode_accept(const cbor::Value& value) {
    auto reader = MapReader::open(value);
    if (!reader) {
        return std::unexpected(reader.error());
    }
    protocol::ContractAccept accept;
    auto fields = decode_instance_fields(*reader);
    if (!fields) {
        return std::unexpected(fields.error());
    }
    accept.state = encoded(fields->state);
    accept.status = std::move(fields->status);
    accept.parties = std::move(fields->parties);
    if (const cbor::Value* events = reader->get(4)) {
        const cbor::Array* items = events->as_array();
        if (items == nullptr || items->empty() || items->size() > protocol::max_contract_events) {
            return fail(Errc::malformed, "a call emits 1 to 64 events");
        }
        for (const cbor::Value& item : *items) {
            const cbor::Array* pair = item.as_array();
            if (pair == nullptr || pair->size() != 2 ||
                !text_within((*pair)[0].as_text(), protocol::max_function_name)) {
                return fail(Errc::malformed, "an event is [name of 1 to 64 bytes, data]");
            }
            accept.events.push_back({*(*pair)[0].as_text(), (*pair)[1]});
        }
    }
    if (const cbor::Value* finality = reader->get(5)) {
        if (finality->as_bool() != std::optional(true)) {
            return fail(Errc::malformed, "an instance's finality is encoded only as true");
        }
        accept.final = true;
    }
    if (const cbor::Value* children = reader->get(6)) {
        const cbor::Array* items = children->as_array();
        if (items == nullptr || items->empty() || items->size() > protocol::max_contract_children) {
            return fail(Errc::malformed, "a call creates 1 to 16 children");
        }
        for (const cbor::Value& item : *items) {
            auto child = decode_child(item);
            if (!child) {
                return std::unexpected(child.error());
            }
            accept.children.push_back(std::move(*child));
        }
    }
    if (const cbor::Value* requests = reader->get(7)) {
        const cbor::Array* items = requests->as_array();
        if (items == nullptr || items->empty() || items->size() > protocol::max_contract_requests) {
            return fail(Errc::malformed, "a call makes 1 to 16 requests");
        }
        for (const cbor::Value& item : *items) {
            auto request = decode_request(item);
            if (!request) {
                return std::unexpected(request.error());
            }
            accept.requests.push_back(std::move(*request));
        }
    }
    if (auto s = reader->finish(); !s) {
        return std::unexpected(s.error());
    }
    return accept;
}

} // namespace detail

/// decode_contract_output as it was: the output decoded into a tree, then
/// read; the states are the trees' encodings.
inline Result<protocol::ContractOutput> decode_contract_output(ByteView output,
                                                               const protocol::Id& home) {
    auto value = cbor::decode(output);
    if (!value) {
        return fail(Errc::malformed, "a contract's output is not deterministic CBOR within the "
                                     "limits");
    }
    const cbor::Array* top = value->as_array();
    const auto outcome = top != nullptr && top->size() == 2 ? (*top)[0].as_uint64() : std::nullopt;
    if (outcome == 1U) {
        auto accept = detail::decode_accept((*top)[1]);
        if (!accept) {
            return std::unexpected(accept.error());
        }
        return protocol::ContractOutput(std::move(*accept));
    }
    if (outcome == 2U) {
        auto needs = detail::decode_needs((*top)[1], home);
        if (!needs) {
            return std::unexpected(needs.error());
        }
        return protocol::ContractOutput(std::move(*needs));
    }
    return fail(Errc::malformed, "a contract's output is [1, accept] or [2, needs]");
}

/// encode_contract_input as it was: a tree of the whole input, the
/// instance's state decoded into it, encoded.
inline Result<Bytes> encode_contract_input(const protocol::ContractInput& input) {
    using detail::entry;
    cbor::Map map{
        entry(1, cbor::Value::text(input.function)),
        entry(2, input.arguments),
        entry(3, cbor::Value::bytes(input.home.bytes())),
        entry(4, cbor::Value::bytes(input.contract.bytes())),
        entry(6, cbor::Value::array({cbor::Value::bytes(input.caller.bytes()),
                                     protocol::encode_contract_signer(input.caller_signer)})),
        entry(7, cbor::Value::unsigned_integer(input.time)),
    };
    if (input.instance) {
        const protocol::ContractInstanceView& v = *input.instance;
        cbor::Map view{entry(1, cbor::Value::bytes(v.id.bytes())),
                       entry(2, cbor::Value::unsigned_integer(v.head)), entry(3, v.state.value())};
        if (v.status) {
            view.push_back(entry(4, cbor::Value::text(*v.status)));
        }
        if (!v.parties.empty()) {
            view.push_back(entry(5, detail::parties_value(v.parties)));
        }
        if (v.parent) {
            view.push_back(entry(6, cbor::Value::array({cbor::Value::bytes(v.parent->bytes()),
                                                        cbor::Value::unsigned_integer(v.depth)})));
        }
        map.push_back(entry(5, cbor::Value::map(std::move(view))));
    }
    if (!input.consents.empty()) {
        cbor::Array consents;
        for (const auto& [ledger, signer] : input.consents) {
            consents.push_back(cbor::Value::array(
                {cbor::Value::bytes(ledger.bytes()), protocol::encode_contract_signer(signer)}));
        }
        map.push_back(entry(8, cbor::Value::array(std::move(consents))));
    }
    if (input.request) {
        const protocol::ContractRequestView& r = *input.request;
        map.push_back(entry(
            9, cbor::Value::map({
                   entry(1, cbor::Value::bytes(r.id.bytes())),
                   entry(2, cbor::Value::text(r.kind)),
                   entry(3, r.params),
                   entry(4, cbor::Value::unsigned_integer(r.deadline)),
                   entry(5, cbor::Value::unsigned_integer(r.asked_at)),
                   entry(6, cbor::Value::unsigned_integer(static_cast<std::uint64_t>(r.status))),
               })));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

/// encode_contract_output as it was: a tree, the states decoded into it.
inline Result<Bytes> encode_contract_output(const protocol::ContractOutput& output) {
    using detail::entry;
    if (const auto* needs = std::get_if<protocol::ContractNeeds>(&output)) {
        cbor::Array ledgers;
        for (const protocol::Id& ledger : needs->ledgers) {
            ledgers.push_back(cbor::Value::bytes(ledger.bytes()));
        }
        return cbor::encode(cbor::Value::array(
            {cbor::Value::unsigned_integer(2), cbor::Value::array(std::move(ledgers))}));
    }
    const auto& accept = std::get<protocol::ContractAccept>(output);
    cbor::Map map{entry(1, accept.state.value())};
    if (accept.status) {
        map.push_back(entry(2, cbor::Value::text(*accept.status)));
    }
    if (accept.parties) {
        map.push_back(entry(3, detail::parties_value(*accept.parties)));
    }
    if (!accept.events.empty()) {
        cbor::Array events;
        for (const protocol::ContractEvent& e : accept.events) {
            events.push_back(cbor::Value::array({cbor::Value::text(e.name), e.data}));
        }
        map.push_back(entry(4, cbor::Value::array(std::move(events))));
    }
    if (accept.final) {
        map.push_back(entry(5, cbor::Value::boolean(true)));
    }
    if (!accept.children.empty()) {
        cbor::Array children;
        for (const protocol::ContractChild& child : accept.children) {
            cbor::Map fields{entry(1, child.state.value())};
            if (child.status) {
                fields.push_back(entry(2, cbor::Value::text(*child.status)));
            }
            if (!child.parties.empty()) {
                fields.push_back(entry(3, detail::parties_value(child.parties)));
            }
            children.push_back(cbor::Value::map(std::move(fields)));
        }
        map.push_back(entry(6, cbor::Value::array(std::move(children))));
    }
    if (!accept.requests.empty()) {
        cbor::Array requests;
        for (const protocol::ContractRequest& r : accept.requests) {
            requests.push_back(
                cbor::Value::map({entry(1, cbor::Value::text(r.kind)), entry(2, r.params),
                                  entry(3, cbor::Value::unsigned_integer(r.deadline)),
                                  entry(4, cbor::Value::text(r.reply))}));
        }
        map.push_back(entry(7, cbor::Value::array(std::move(requests))));
    }
    return cbor::encode(
        cbor::Value::array({cbor::Value::unsigned_integer(1), cbor::Value::map(std::move(map))}));
}

} // namespace cexchain::test::reference
