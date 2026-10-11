// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <string>
#include <utility>

#include <cexchain/core/protocol/contracts.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

using detail::entry;
using detail::MapReader;

constexpr std::uint64_t output_accept = 1;
constexpr std::uint64_t output_needs = 2;

cbor::MapEntry text_entry(std::string_view key, cbor::Value value) {
    return {cbor::Value::text(std::string(key)), std::move(value)};
}

bool ascending(const Id& a, const Id& b) {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

bool text_within(const std::string* text, std::size_t max) {
    return text != nullptr && !text->empty() && text->size() <= max;
}

cbor::Value parties_value(const Parties& parties) {
    cbor::Map map;
    for (const auto& [role, ledger] : parties) {
        map.push_back({cbor::Value::text(role), cbor::Value::bytes(ledger.bytes())});
    }
    return cbor::Value::map(std::move(map));
}

Result<Parties> decode_parties(const cbor::Value& value) {
    const cbor::Map* map = value.as_map();
    if (map == nullptr || map->empty() || map->size() > max_contract_parties) {
        return fail(Errc::malformed, "a contract's parties are 1 to 64 roles");
    }
    Parties parties;
    for (const cbor::MapEntry& e : *map) {
        const Bytes* ledger = e.value.as_bytes();
        if (!text_within(e.key.as_text(), max_function_name) || ledger == nullptr ||
            ledger->size() != id_size) {
            return fail(Errc::malformed, "a party is a role of 1 to 64 bytes and a ledger id");
        }
        parties.emplace(*e.key.as_text(), *to_id(*ledger));
    }
    return parties;
}

Result<ContractNeeds> decode_needs(const cbor::Value& value, const Id& home) {
    const cbor::Array* items = value.as_array();
    if (items == nullptr || items->empty() || items->size() > max_contract_consents) {
        return fail(Errc::malformed, "a contract needs the consents of 1 to 16 ledgers");
    }
    ContractNeeds needs;
    for (const cbor::Value& item : *items) {
        const Bytes* bytes = item.as_bytes();
        if (bytes == nullptr || bytes->size() != id_size) {
            return fail(Errc::malformed, "a contract names ledgers by their ids");
        }
        Id ledger = *to_id(*bytes);
        if (ledger == home) {
            return fail(Errc::malformed, "a contract never needs its home's consent");
        }
        if (!needs.ledgers.empty() && !ascending(needs.ledgers.back(), ledger)) {
            return fail(Errc::malformed, "the ledgers a contract needs ascend, each once");
        }
        needs.ledgers.push_back(std::move(ledger));
    }
    return needs;
}

Result<ContractAccept> decode_accept(const cbor::Value& value) {
    CEXCHAIN_TRY(MapReader reader, MapReader::open(value));
    ContractAccept accept;
    CEXCHAIN_TRY(const cbor::Value* state, reader.need(1));
    CEXCHAIN_TRY(Bytes encoded_state, cbor::encode(*state));
    if (encoded_state.size() > max_contract_value) {
        return fail(Errc::malformed, "an instance's state is at most 65,536 bytes");
    }
    accept.state = *state;
    if (const cbor::Value* status = reader.get(2)) {
        if (!text_within(status->as_text(), max_contract_status)) {
            return fail(Errc::malformed, "an instance's status is 1 to 64 bytes");
        }
        accept.status = *status->as_text();
    }
    if (const cbor::Value* parties = reader.get(3)) {
        CEXCHAIN_TRY(accept.parties, decode_parties(*parties));
    }
    if (const cbor::Value* events = reader.get(4)) {
        const cbor::Array* items = events->as_array();
        if (items == nullptr || items->empty() || items->size() > max_contract_events) {
            return fail(Errc::malformed, "a call emits 1 to 64 events");
        }
        for (const cbor::Value& item : *items) {
            const cbor::Array* pair = item.as_array();
            if (pair == nullptr || pair->size() != 2 ||
                !text_within((*pair)[0].as_text(), max_function_name)) {
                return fail(Errc::malformed, "an event is [name of 1 to 64 bytes, data]");
            }
            accept.events.push_back({*(*pair)[0].as_text(), (*pair)[1]});
        }
    }
    if (const cbor::Value* finality = reader.get(5)) {
        if (finality->as_bool() != std::optional(true)) {
            return fail(Errc::malformed, "an instance's finality is encoded only as true");
        }
        accept.final = true;
    }
    CEXCHAIN_CHECK(reader.finish());
    return accept;
}

Result<Id> id_field(const cbor::Value* value) {
    if (value == nullptr || value->as_bytes() == nullptr) {
        return fail(Errc::malformed, "a contract consent lacks an id");
    }
    return to_id(*value->as_bytes());
}

} // namespace

Result<ContractOutput> decode_contract_output(ByteView output, const Id& home) {
    // The default limits are those of spec section 2: 32 levels, 131,072
    // data items.
    auto value = cbor::decode(output);
    if (!value) {
        return fail(Errc::malformed, "a contract's output is not deterministic CBOR within the "
                                     "limits");
    }
    const cbor::Array* top = value->as_array();
    const auto outcome = top != nullptr && top->size() == 2 ? (*top)[0].as_uint64() : std::nullopt;
    if (outcome == output_accept) {
        CEXCHAIN_TRY(ContractAccept accept, decode_accept((*top)[1]));
        return ContractOutput(std::move(accept));
    }
    if (outcome == output_needs) {
        CEXCHAIN_TRY(ContractNeeds needs, decode_needs((*top)[1], home));
        return ContractOutput(std::move(needs));
    }
    return fail(Errc::malformed, "a contract's output is [1, accept] or [2, needs]");
}

Result<Bytes> encode_contract_output(const ContractOutput& output) {
    if (const auto* needs = std::get_if<ContractNeeds>(&output)) {
        cbor::Array ledgers;
        for (const Id& ledger : needs->ledgers) {
            ledgers.push_back(cbor::Value::bytes(ledger.bytes()));
        }
        return cbor::encode(cbor::Value::array(
            {cbor::Value::unsigned_integer(output_needs), cbor::Value::array(std::move(ledgers))}));
    }
    const auto& accept = std::get<ContractAccept>(output);
    cbor::Map map{entry(1, accept.state)};
    if (accept.status) {
        map.push_back(entry(2, cbor::Value::text(*accept.status)));
    }
    if (accept.parties) {
        map.push_back(entry(3, parties_value(*accept.parties)));
    }
    if (!accept.events.empty()) {
        cbor::Array events;
        for (const ContractEvent& e : accept.events) {
            events.push_back(cbor::Value::array({cbor::Value::text(e.name), e.data}));
        }
        map.push_back(entry(4, cbor::Value::array(std::move(events))));
    }
    if (accept.final) {
        map.push_back(entry(5, cbor::Value::boolean(true)));
    }
    return cbor::encode(cbor::Value::array(
        {cbor::Value::unsigned_integer(output_accept), cbor::Value::map(std::move(map))}));
}

Result<Bytes> encode_contract_input(const ContractInput& input) {
    cbor::Map map{
        entry(1, cbor::Value::text(input.function)),
        entry(2, input.arguments),
        entry(3, cbor::Value::bytes(input.home.bytes())),
        entry(4, cbor::Value::bytes(input.contract.bytes())),
        entry(6, cbor::Value::array({cbor::Value::bytes(input.caller.bytes()),
                                     encode_contract_signer(input.caller_signer)})),
        entry(7, cbor::Value::unsigned_integer(input.time)),
    };
    if (input.instance) {
        const ContractInstanceView& v = *input.instance;
        cbor::Map view{entry(1, cbor::Value::bytes(v.id.bytes())),
                       entry(2, cbor::Value::unsigned_integer(v.head)), entry(3, v.state)};
        if (v.status) {
            view.push_back(entry(4, cbor::Value::text(*v.status)));
        }
        if (!v.parties.empty()) {
            view.push_back(entry(5, parties_value(v.parties)));
        }
        map.push_back(entry(5, cbor::Value::map(std::move(view))));
    }
    if (!input.consents.empty()) {
        cbor::Array consents;
        for (const auto& [ledger, signer] : input.consents) {
            consents.push_back(cbor::Value::array(
                {cbor::Value::bytes(ledger.bytes()), encode_contract_signer(signer)}));
        }
        map.push_back(entry(8, cbor::Value::array(std::move(consents))));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<cbor::Value> encode_contract_consent(const ContractConsent& c) {
    if (c.until == 0) {
        return fail(Errc::invalid_argument, "a consent lapses at some time (\"until\")");
    }
    if (c.function.empty() || c.function.size() > max_function_name) {
        return fail(Errc::invalid_argument, "a function name is 1 to 64 bytes");
    }
    if (c.reference && (c.reference->empty() || c.reference->size() > max_contract_reference)) {
        return fail(Errc::invalid_argument, "a consent's reference is 1 to 1024 bytes");
    }
    cbor::Map map{
        text_entry("ledger", cbor::Value::bytes(c.ledger.bytes())),
        text_entry("instance", cbor::Value::bytes(c.instance.bytes())),
        text_entry("function", cbor::Value::text(c.function)),
        text_entry("arguments", cbor::Value::bytes(c.arguments.bytes())),
        text_entry("head", cbor::Value::unsigned_integer(c.head)),
        text_entry("until", cbor::Value::unsigned_integer(c.until)),
    };
    if (c.reference) {
        map.push_back(text_entry("reference", cbor::Value::text(*c.reference)));
    }
    return cbor::Value::map(std::move(map));
}

Result<ContractConsent> decode_contract_consent(const cbor::Value& metadata) {
    const cbor::Map* map = metadata.as_map();
    if (map == nullptr) {
        return fail(Errc::malformed, "a contract consent's metadata is a map");
    }
    constexpr std::array<std::string_view, 7> known{"ledger",   "head",      "until",    "function",
                                                    "instance", "arguments", "reference"};
    const auto get = [&](std::string_view key) -> const cbor::Value* {
        for (const cbor::MapEntry& e : *map) {
            if (const std::string* text = e.key.as_text(); text != nullptr && *text == key) {
                return &e.value;
            }
        }
        return nullptr;
    };
    for (const cbor::MapEntry& e : *map) {
        const std::string* key = e.key.as_text();
        if (key == nullptr || !std::ranges::contains(known, std::string_view(*key))) {
            return fail(Errc::malformed, "a contract consent's metadata has an unknown key");
        }
    }
    ContractConsent c;
    CEXCHAIN_TRY(c.ledger, id_field(get("ledger")));
    CEXCHAIN_TRY(c.instance, id_field(get("instance")));
    CEXCHAIN_TRY(c.arguments, id_field(get("arguments")));
    const cbor::Value* function = get("function");
    const cbor::Value* head = get("head");
    const cbor::Value* until = get("until");
    if (function == nullptr || !text_within(function->as_text(), max_function_name) ||
        head == nullptr || !head->as_uint64() || until == nullptr || !until->as_uint64() ||
        *until->as_uint64() == 0) {
        return fail(Errc::malformed, "a contract consent names a function, a head, and an end");
    }
    c.function = *function->as_text();
    c.head = *head->as_uint64();
    c.until = *until->as_uint64();
    if (const cbor::Value* reference = get("reference")) {
        if (!text_within(reference->as_text(), max_contract_reference)) {
            return fail(Errc::malformed, "a consent's reference is 1 to 1024 bytes");
        }
        c.reference = *reference->as_text();
    }
    return c;
}

Result<Id> contract_arguments_digest(const crypto::Provider& provider, crypto::HashAlg hash,
                                     const cbor::Value& arguments) {
    CEXCHAIN_TRY(Bytes encoded, cbor::encode(arguments));
    return provider.digest(hash, encoded);
}

bool consent_matches(const ContractConsent& consent, const Id& home, const ContractCallBody& call,
                     const Id& arguments_digest) {
    return call.instance && call.head && consent.ledger == home &&
           consent.instance == *call.instance && consent.function == call.function &&
           consent.arguments == arguments_digest && consent.head == *call.head;
}

} // namespace cexchain::protocol
