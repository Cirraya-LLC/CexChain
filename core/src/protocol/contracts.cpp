// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <initializer_list>
#include <limits>
#include <string>
#include <utility>

#include <cexchain/core/protocol/contracts.hpp>

#include "reader.hpp"

namespace cexchain::protocol {

namespace {

constexpr std::uint64_t output_accept = 1;
constexpr std::uint64_t output_needs = 2;

constexpr std::uint8_t major_bytes = 2;
constexpr std::uint8_t major_text = 3;
constexpr std::uint8_t major_array = 4;
constexpr std::uint8_t major_map = 5;
constexpr std::uint8_t major_tag = 6;
constexpr std::uint8_t major_negative = 1;
constexpr std::uint8_t encoded_true = 0xf5;

cbor::MapEntry text_entry(std::string_view key, cbor::Value value) {
    return {cbor::Value::text(std::string(key)), std::move(value)};
}

bool ascending(const Id& a, const Id& b) {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

bool text_within(const std::string* text, std::size_t max) {
    return text != nullptr && !text->empty() && text->size() <= max;
}

bool text_within(const std::optional<std::string_view>& text, std::size_t max) {
    return text && !text->empty() && text->size() <= max;
}

// ---------------------------------------------------------------------------
// Reading an output that cbor::validate accepted
// ---------------------------------------------------------------------------

/// The head of an item in an encoding `cbor::validate` accepted: every
/// read is in bounds, every head in shortest form, simple values only false,
/// true, and null.
struct ItemHead {
    std::uint8_t major;
    std::uint8_t info;
    std::uint64_t argument;
    std::size_t size;
};

ItemHead head_at(ByteView in, std::size_t at) {
    const std::uint8_t initial = in[at];
    const auto info = static_cast<std::uint8_t>(initial & 0x1f);
    ItemHead head{static_cast<std::uint8_t>(initial >> 5), info, info, 1};
    if (info >= 24) {
        const std::size_t width = std::size_t{1} << (info - 24);
        std::uint64_t argument = 0;
        for (std::size_t i = 1; i <= width; ++i) {
            argument = (argument << 8) | in[at + i];
        }
        head.argument = argument;
        head.size = 1 + width;
    }
    return head;
}

/// Where the item at `at` ends.
std::size_t item_end(ByteView in, std::size_t at) {
    std::uint64_t pending = 1;
    do {
        const ItemHead head = head_at(in, at);
        at += head.size;
        --pending;
        if (head.major == major_bytes || head.major == major_text) {
            at += static_cast<std::size_t>(head.argument);
        } else if (head.major == major_array) {
            pending += head.argument;
        } else if (head.major == major_map) {
            pending += 2 * head.argument;
        } else if (head.major == major_tag) {
            ++pending;
        }
    } while (pending > 0);
    return at;
}

/// One item of a validated encoding: exactly its bytes.
class Item {
public:
    explicit Item(ByteView bytes) : bytes_(bytes), head_(head_at(bytes, 0)) {}

    [[nodiscard]] ByteView bytes() const noexcept { return bytes_; }
    [[nodiscard]] bool is_array() const noexcept { return head_.major == major_array; }
    [[nodiscard]] bool is_map() const noexcept { return head_.major == major_map; }
    /// An array's items, or a map's entries.
    [[nodiscard]] std::uint64_t count() const noexcept { return head_.argument; }

    [[nodiscard]] std::optional<std::uint64_t> as_uint() const noexcept {
        return head_.major == 0 ? std::optional(head_.argument) : std::nullopt;
    }
    /// As `cbor::Value::as_int64`.
    [[nodiscard]] std::optional<std::int64_t> as_int64() const noexcept {
        constexpr auto max = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        if (head_.argument > max || (head_.major != 0 && head_.major != major_negative)) {
            return std::nullopt;
        }
        const auto n = static_cast<std::int64_t>(head_.argument);
        return head_.major == 0 ? n : -1 - n;
    }
    [[nodiscard]] std::optional<std::string_view> as_text() const noexcept {
        if (head_.major != major_text) {
            return std::nullopt;
        }
        const ByteView content = bytes_.subspan(head_.size);
        return std::string_view(reinterpret_cast<const char*>(content.data()), content.size());
    }
    [[nodiscard]] std::optional<ByteView> as_bytes() const noexcept {
        return head_.major == major_bytes ? std::optional(bytes_.subspan(head_.size))
                                          : std::nullopt;
    }
    [[nodiscard]] bool is_true() const noexcept {
        return bytes_.size() == 1 && bytes_[0] == encoded_true;
    }
    /// The tree, for the parts of an output kept as trees. A part of a
    /// validated encoding decodes alone within the same limits.
    [[nodiscard]] cbor::Value tree() const {
        auto value = cbor::decode(bytes_);
        return value ? std::move(*value) : cbor::Value::null();
    }

    /// Walks the items inside an array, or a map's keys and values in turn.
    class Inside {
    public:
        explicit Inside(const Item& container)
            : rest_(container.bytes_.subspan(container.head_.size)) {}
        Item next() {
            const std::size_t end = item_end(rest_, 0);
            const Item item(rest_.first(end));
            rest_ = rest_.subspan(end);
            return item;
        }

    private:
        ByteView rest_;
    };

private:
    ByteView bytes_;
    ItemHead head_;
};

/// The values of an integer-keyed protocol map under keys 1 to N, and what
/// `detail::MapReader::finish` would say about the rest once every one of
/// them was read. Canonical order puts unsigned keys first, ascending, so
/// only the entries up to the first key above N need reading.
template <std::size_t N>
struct Fields {
    std::array<std::optional<Item>, N + 1> values;
    /// The first entry of another key, if any: whether that key is an
    /// integer (`as_int64`), since `finish` tells the two apart.
    std::optional<bool> other_is_integer;

    explicit Fields(const Item& map) {
        Item::Inside inside(map);
        for (std::uint64_t i = 0; i < map.count(); ++i) {
            const Item key = inside.next();
            const auto number = key.as_uint();
            if (number && *number >= 1 && *number <= N) {
                values[static_cast<std::size_t>(*number)] = inside.next();
                continue;
            }
            if (!other_is_integer) {
                other_is_integer = key.as_int64().has_value();
            }
            if (!number || *number > N) {
                break;
            }
            static_cast<void>(inside.next());
        }
    }

    [[nodiscard]] const std::optional<Item>& operator[](std::size_t key) const {
        return values[key];
    }
    /// As `detail::MapReader::finish` after keys 1 to N were read.
    [[nodiscard]] Status finish() const {
        if (!other_is_integer) {
            return {};
        }
        return *other_is_integer ? fail(Errc::malformed, "map has an unknown key")
                                 : fail(Errc::malformed, "protocol map keys must be integers");
    }
};

Result<Parties> read_parties(const Item& item) {
    if (!item.is_map() || item.count() == 0 || item.count() > max_contract_parties) {
        return fail(Errc::malformed, "a contract's parties are 1 to 64 roles");
    }
    Parties parties;
    Item::Inside inside(item);
    for (std::uint64_t i = 0; i < item.count(); ++i) {
        const Item role = inside.next();
        const auto ledger = inside.next().as_bytes();
        const auto name = role.as_text();
        if (!text_within(name, max_function_name) || !ledger || ledger->size() != id_size) {
            return fail(Errc::malformed, "a party is a role of 1 to 64 bytes and a ledger id");
        }
        parties.emplace(std::string(*name), *to_id(*ledger));
    }
    return parties;
}

Result<ContractNeeds> read_needs(const Item& item, const Id& home) {
    if (!item.is_array() || item.count() == 0 || item.count() > max_contract_consents) {
        return fail(Errc::malformed, "a contract needs the consents of 1 to 16 ledgers");
    }
    ContractNeeds needs;
    Item::Inside inside(item);
    for (std::uint64_t i = 0; i < item.count(); ++i) {
        const auto bytes = inside.next().as_bytes();
        if (!bytes || bytes->size() != id_size) {
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

/// Keys 1 to 3 of an accept or a child: the state (at most 65,536 bytes
/// encoded), the status (1 to 64 bytes), and the parties.
struct InstanceFields {
    cbor::Encoded state;
    std::optional<std::string> status;
    std::optional<Parties> parties;
};

template <std::size_t N>
Result<InstanceFields> read_instance_fields(const Fields<N>& fields) {
    InstanceFields out;
    if (!fields[1]) {
        return fail(Errc::malformed, "a required map key is missing");
    }
    // Deterministic, so its bytes are the encoding the limit is about.
    if (fields[1]->bytes().size() > max_contract_value) {
        return fail(Errc::malformed, "an instance's state is at most 65,536 bytes");
    }
    out.state = cbor::Encoded::trusted(fields[1]->bytes());
    if (const auto& status = fields[2]) {
        const auto text = status->as_text();
        if (!text_within(text, max_contract_status)) {
            return fail(Errc::malformed, "an instance's status is 1 to 64 bytes");
        }
        out.status = std::string(*text);
    }
    if (const auto& parties = fields[3]) {
        CEXCHAIN_TRY(out.parties, read_parties(*parties));
    }
    return out;
}

/// A child is `{1: state, ? 2: status, ? 3: parties}` and nothing else: no
/// events, never final (v0.7).
Result<ContractChild> read_child(const Item& item) {
    if (!item.is_map()) {
        return fail(Errc::malformed, "a child is a map");
    }
    const Fields<3> fields(item);
    CEXCHAIN_TRY(InstanceFields read, read_instance_fields(fields));
    if (!fields.finish()) {
        return fail(Errc::malformed, "a child holds only its state, status, and parties");
    }
    return ContractChild{std::move(read.state), std::move(read.status),
                         std::move(read.parties).value_or(Parties{})};
}

/// A request is `{1: kind, 2: params, 3: deadline, 4: reply}` and nothing
/// else (v0.8). Its deadline's window and its reply's kind are ledger rules.
Result<ContractRequest> read_request(const Item& item) {
    if (!item.is_map()) {
        return fail(Errc::malformed, "a request is a map");
    }
    const Fields<4> fields(item);
    if (!fields[1] || !fields[2] || !fields[3] || !fields[4] || !fields.finish()) {
        return fail(Errc::malformed, "a request holds exactly its kind, params, deadline, and "
                                     "reply");
    }
    const auto kind = fields[1]->as_text();
    if (!kind || !is_request_kind(*kind)) {
        return fail(Errc::malformed, "a request's kind is 1 to 64 bytes of a-z, 0-9, '.', '_', "
                                     "and '-', starting with a letter");
    }
    if (fields[2]->bytes().size() > max_request_params) {
        return fail(Errc::malformed, "a request's params are at most 4,096 bytes");
    }
    const auto deadline = fields[3]->as_uint();
    if (!deadline) {
        return fail(Errc::malformed, "a request's deadline is a time in milliseconds");
    }
    const auto reply = fields[4]->as_text();
    if (!text_within(reply, max_function_name)) {
        return fail(Errc::malformed, "a request's reply is a function name of 1 to 64 bytes");
    }
    return ContractRequest{std::string(*kind), fields[2]->tree(), *deadline, std::string(*reply)};
}

Result<ContractAccept> read_accept(const Item& item) {
    if (!item.is_map()) {
        return fail(Errc::malformed, "expected a map");
    }
    const Fields<7> fields(item);
    ContractAccept accept;
    CEXCHAIN_TRY(InstanceFields read, read_instance_fields(fields));
    accept.state = std::move(read.state);
    accept.status = std::move(read.status);
    accept.parties = std::move(read.parties);
    if (const auto& events = fields[4]) {
        if (!events->is_array() || events->count() == 0 || events->count() > max_contract_events) {
            return fail(Errc::malformed, "a call emits 1 to 64 events");
        }
        Item::Inside inside(*events);
        for (std::uint64_t i = 0; i < events->count(); ++i) {
            const Item pair = inside.next();
            if (!pair.is_array() || pair.count() != 2) {
                return fail(Errc::malformed, "an event is [name of 1 to 64 bytes, data]");
            }
            Item::Inside parts(pair);
            const auto name = parts.next().as_text();
            if (!text_within(name, max_function_name)) {
                return fail(Errc::malformed, "an event is [name of 1 to 64 bytes, data]");
            }
            accept.events.push_back({std::string(*name), parts.next().tree()});
        }
    }
    if (const auto& finality = fields[5]) {
        if (!finality->is_true()) {
            return fail(Errc::malformed, "an instance's finality is encoded only as true");
        }
        accept.final = true;
    }
    if (const auto& children = fields[6]) {
        if (!children->is_array() || children->count() == 0 ||
            children->count() > max_contract_children) {
            return fail(Errc::malformed, "a call creates 1 to 16 children");
        }
        Item::Inside inside(*children);
        for (std::uint64_t i = 0; i < children->count(); ++i) {
            CEXCHAIN_TRY(ContractChild child, read_child(inside.next()));
            accept.children.push_back(std::move(child));
        }
    }
    if (const auto& requests = fields[7]) {
        if (!requests->is_array() || requests->count() == 0 ||
            requests->count() > max_contract_requests) {
            return fail(Errc::malformed, "a call makes 1 to 16 requests");
        }
        Item::Inside inside(*requests);
        for (std::uint64_t i = 0; i < requests->count(); ++i) {
            CEXCHAIN_TRY(ContractRequest request, read_request(inside.next()));
            accept.requests.push_back(std::move(request));
        }
    }
    CEXCHAIN_CHECK(fields.finish());
    return accept;
}

// ---------------------------------------------------------------------------
// Writing inputs and outputs: heads, with encoded items spliced in
// ---------------------------------------------------------------------------

std::uint64_t count_of(std::initializer_list<bool> present) {
    return static_cast<std::uint64_t>(std::ranges::count(present, true));
}

void put_uint(Bytes& out, std::uint64_t value) {
    cbor::append_head(out, cbor::Major::unsigned_integer, value);
}

void put_raw(Bytes& out, ByteView bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void put_bytes(Bytes& out, ByteView bytes) {
    cbor::append_head(out, cbor::Major::bytes, bytes.size());
    put_raw(out, bytes);
}

/// Fails as cbor::encode does on text that is not UTF-8.
Status put_text(Bytes& out, std::string_view text) {
    if (!cbor::is_valid_utf8(text)) {
        return fail(Errc::invalid_argument, "text string is not valid UTF-8");
    }
    cbor::append_head(out, cbor::Major::text, text.size());
    put_raw(out, as_bytes(text));
    return {};
}

/// Roles in canonical order: a text key's head holds its length, so shorter
/// roles come first, then bytewise.
Status put_parties(Bytes& out, const Parties& parties) {
    std::vector<const Parties::value_type*> sorted;
    sorted.reserve(parties.size());
    for (const auto& party : parties) {
        sorted.push_back(&party);
    }
    std::ranges::sort(sorted, [](const auto* a, const auto* b) {
        return a->first.size() != b->first.size() ? a->first.size() < b->first.size()
                                                  : a->first < b->first;
    });
    cbor::append_head(out, cbor::Major::map, sorted.size());
    for (const auto* party : sorted) {
        CEXCHAIN_CHECK(put_text(out, party->first));
        put_bytes(out, party->second.bytes());
    }
    return {};
}

/// As `encode_contract_signer` writes it.
Status put_signer(Bytes& out, const ContractSigner& signer) {
    cbor::append_head(out, cbor::Major::map,
                      1 + count_of({signer.presence.has_value(), signer.model.has_value()}));
    put_uint(out, 1);
    put_uint(out, signer.kind);
    if (signer.presence) {
        put_uint(out, 2);
        put_uint(out, static_cast<std::uint64_t>(*signer.presence));
    }
    if (signer.model) {
        put_uint(out, 3);
        CEXCHAIN_CHECK(put_text(out, *signer.model));
    }
    return {};
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
    // data items. Checked without building anything; the parts below read
    // the checked bytes.
    if (!cbor::validate(output)) {
        return fail(Errc::malformed, "a contract's output is not deterministic CBOR within the "
                                     "limits");
    }
    const Item top(output);
    if (top.is_array() && top.count() == 2) {
        Item::Inside inside(top);
        const auto outcome = inside.next().as_uint();
        if (outcome == output_accept) {
            CEXCHAIN_TRY(ContractAccept accept, read_accept(inside.next()));
            return ContractOutput(std::move(accept));
        }
        if (outcome == output_needs) {
            CEXCHAIN_TRY(ContractNeeds needs, read_needs(inside.next(), home));
            return ContractOutput(std::move(needs));
        }
    }
    return fail(Errc::malformed, "a contract's output is [1, accept] or [2, needs]");
}

Result<Bytes> encode_contract_output(const ContractOutput& output) {
    Bytes out;
    cbor::append_head(out, cbor::Major::array, 2);
    if (const auto* needs = std::get_if<ContractNeeds>(&output)) {
        put_uint(out, output_needs);
        cbor::append_head(out, cbor::Major::array, needs->ledgers.size());
        for (const Id& ledger : needs->ledgers) {
            put_bytes(out, ledger.bytes());
        }
        return out;
    }
    const auto& accept = std::get<ContractAccept>(output);
    put_uint(out, output_accept);
    // Keys 1 to 7 in order are canonical order. Items inside the output's
    // array and map are at depth 2; an event's data and a request's params
    // at depth 4.
    cbor::append_head(
        out, cbor::Major::map,
        1 + count_of({accept.status.has_value(), accept.parties.has_value(), !accept.events.empty(),
                      accept.final, !accept.children.empty(), !accept.requests.empty()}));
    put_uint(out, 1);
    put_raw(out, accept.state.bytes());
    if (accept.status) {
        put_uint(out, 2);
        CEXCHAIN_CHECK(put_text(out, *accept.status));
    }
    if (accept.parties) {
        put_uint(out, 3);
        CEXCHAIN_CHECK(put_parties(out, *accept.parties));
    }
    if (!accept.events.empty()) {
        put_uint(out, 4);
        cbor::append_head(out, cbor::Major::array, accept.events.size());
        for (const ContractEvent& e : accept.events) {
            cbor::append_head(out, cbor::Major::array, 2);
            CEXCHAIN_CHECK(put_text(out, e.name));
            CEXCHAIN_CHECK(cbor::encode_to(out, e.data, 4));
        }
    }
    if (accept.final) {
        put_uint(out, 5);
        out.push_back(encoded_true);
    }
    if (!accept.children.empty()) {
        put_uint(out, 6);
        cbor::append_head(out, cbor::Major::array, accept.children.size());
        for (const ContractChild& child : accept.children) {
            cbor::append_head(out, cbor::Major::map,
                              1 + count_of({child.status.has_value(), !child.parties.empty()}));
            put_uint(out, 1);
            put_raw(out, child.state.bytes());
            if (child.status) {
                put_uint(out, 2);
                CEXCHAIN_CHECK(put_text(out, *child.status));
            }
            if (!child.parties.empty()) {
                put_uint(out, 3);
                CEXCHAIN_CHECK(put_parties(out, child.parties));
            }
        }
    }
    if (!accept.requests.empty()) {
        put_uint(out, 7);
        cbor::append_head(out, cbor::Major::array, accept.requests.size());
        for (const ContractRequest& r : accept.requests) {
            cbor::append_head(out, cbor::Major::map, 4);
            put_uint(out, 1);
            CEXCHAIN_CHECK(put_text(out, r.kind));
            put_uint(out, 2);
            CEXCHAIN_CHECK(cbor::encode_to(out, r.params, 4));
            put_uint(out, 3);
            put_uint(out, r.deadline);
            put_uint(out, 4);
            CEXCHAIN_CHECK(put_text(out, r.reply));
        }
    }
    return out;
}

Result<Id> child_instance_id(const crypto::Provider& provider, crypto::HashAlg hash, const Id& call,
                             std::uint64_t position) {
    CEXCHAIN_TRY(Bytes encoded,
                 cbor::encode(cbor::Value::array(
                     {cbor::Value::bytes(call.bytes()), cbor::Value::unsigned_integer(position)})));
    return provider.digest(hash, encoded);
}

Result<Id> request_id(const crypto::Provider& provider, crypto::HashAlg hash, const Id& call,
                      std::uint64_t position) {
    CEXCHAIN_TRY(Bytes encoded, cbor::encode(cbor::Value::array(
                                    {cbor::Value::text("request"), cbor::Value::bytes(call.bytes()),
                                     cbor::Value::unsigned_integer(position)})));
    return provider.digest(hash, encoded);
}

Result<Bytes> encode_contract_input(const ContractInput& input) {
    // Keys in ascending order are canonical order (each a one-byte head).
    // Items inside the input's map are at depth 1; a request's params at 2.
    Bytes out;
    out.reserve(256 + (input.instance ? input.instance->state.size() : 0));
    cbor::append_head(out, cbor::Major::map,
                      6 + count_of({input.instance.has_value(), !input.consents.empty(),
                                    input.request.has_value()}));
    put_uint(out, 1);
    CEXCHAIN_CHECK(put_text(out, input.function));
    put_uint(out, 2);
    CEXCHAIN_CHECK(cbor::encode_to(out, input.arguments, 1));
    put_uint(out, 3);
    put_bytes(out, input.home.bytes());
    put_uint(out, 4);
    put_bytes(out, input.contract.bytes());
    if (input.instance) {
        const ContractInstanceView& v = *input.instance;
        put_uint(out, 5);
        cbor::append_head(
            out, cbor::Major::map,
            3 + count_of({v.status.has_value(), !v.parties.empty(), v.parent.has_value()}));
        put_uint(out, 1);
        put_bytes(out, v.id.bytes());
        put_uint(out, 2);
        put_uint(out, v.head);
        put_uint(out, 3);
        put_raw(out, v.state.bytes());
        if (v.status) {
            put_uint(out, 4);
            CEXCHAIN_CHECK(put_text(out, *v.status));
        }
        if (!v.parties.empty()) {
            put_uint(out, 5);
            CEXCHAIN_CHECK(put_parties(out, v.parties));
        }
        if (v.parent) {
            put_uint(out, 6);
            cbor::append_head(out, cbor::Major::array, 2);
            put_bytes(out, v.parent->bytes());
            put_uint(out, v.depth);
        }
    }
    put_uint(out, 6);
    cbor::append_head(out, cbor::Major::array, 2);
    put_bytes(out, input.caller.bytes());
    CEXCHAIN_CHECK(put_signer(out, input.caller_signer));
    put_uint(out, 7);
    put_uint(out, input.time);
    if (!input.consents.empty()) {
        put_uint(out, 8);
        cbor::append_head(out, cbor::Major::array, input.consents.size());
        for (const auto& [ledger, signer] : input.consents) {
            cbor::append_head(out, cbor::Major::array, 2);
            put_bytes(out, ledger.bytes());
            CEXCHAIN_CHECK(put_signer(out, signer));
        }
    }
    if (input.request) {
        const ContractRequestView& r = *input.request;
        put_uint(out, 9);
        cbor::append_head(out, cbor::Major::map, 6);
        put_uint(out, 1);
        put_bytes(out, r.id.bytes());
        put_uint(out, 2);
        CEXCHAIN_CHECK(put_text(out, r.kind));
        put_uint(out, 3);
        CEXCHAIN_CHECK(cbor::encode_to(out, r.params, 2));
        put_uint(out, 4);
        put_uint(out, r.deadline);
        put_uint(out, 5);
        put_uint(out, r.asked_at);
        put_uint(out, 6);
        put_uint(out, static_cast<std::uint64_t>(r.status));
    }
    return out;
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
