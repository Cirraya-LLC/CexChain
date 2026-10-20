// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Instance states kept as encoded CBOR (D-056, P6): contract inputs splice
// encoded states, and outputs are read from their bytes. Nothing on the wire
// changes: canonical CBOR has one encoding per value, so every input and
// output equals what the trees gave (tests/support/contract_reference.hpp,
// the code before P6), on every vector and on random states.

#include <cstdint>
#include <map>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/state.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/contract_reference.hpp"
#include "support/vectors.hpp"

namespace protocol = cexchain::protocol;
namespace crypto = cexchain::crypto;
namespace cbor = cexchain::cbor;
namespace reference = cexchain::test::reference;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using cexchain::to_hex;
using cexchain::test::hex;
using cexchain::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

protocol::Id id(const nlohmann::json& value) {
    return *protocol::to_id(hex(text(value)));
}

/// The same verdict: both succeed, or both fail with the same error.
template <class A, class B>
bool same_verdict(const A& a, const B& b) {
    if (a.has_value() != b.has_value()) {
        return false;
    }
    return a.has_value() ||
           (a.error().code == b.error().code && a.error().detail == b.error().detail);
}

/// Random values with text, integer, and byte keys (distinct by
/// construction), as states hold them.
class Values {
public:
    explicit Values(std::uint64_t seed) : rng_(seed) {}

    std::uint64_t below(std::uint64_t n) {
        return std::uniform_int_distribution<std::uint64_t>(0, n - 1)(rng_);
    }

    cbor::Value value(std::size_t depth = 0) {
        switch (below(depth > 4 ? 6 : 9)) {
        case 0:
            return cbor::Value::unsigned_integer(rng_() >> below(64));
        case 1:
            return cbor::Value::negative(rng_() >> below(64));
        case 2: {
            Bytes bytes(below(40));
            for (auto& b : bytes) {
                b = static_cast<std::uint8_t>(rng_());
            }
            return cbor::Value::bytes(std::move(bytes));
        }
        case 3:
            return cbor::Value::text(word(below(30)) + (below(3) == 0 ? "é水" : ""));
        case 4:
            return cbor::Value::boolean(below(2) == 0);
        case 5:
            return cbor::Value::null();
        case 6: {
            cbor::Array items;
            for (std::uint64_t i = 0, n = below(6); i < n; ++i) {
                items.push_back(value(depth + 1));
            }
            return cbor::Value::array(std::move(items));
        }
        case 7: {
            cbor::Map entries;
            for (std::uint64_t i = 0, n = below(7); i < n; ++i) {
                entries.push_back({key(i), value(depth + 1)});
            }
            return cbor::Value::map(std::move(entries));
        }
        default:
            return cbor::Value::tagged(4 + below(5000), value(depth + 1));
        }
    }

    std::string word(std::uint64_t size) {
        std::string out;
        for (std::uint64_t i = 0; i < size; ++i) {
            out.push_back(static_cast<char>('a' + below(26)));
        }
        return out;
    }

    /// A key distinct from the others of its map (`i` is its position).
    cbor::Value key(std::uint64_t i) {
        switch (below(3)) {
        case 0:
            return cbor::Value::integer(static_cast<std::int64_t>(i * 1000 + below(1000)) - 3000);
        case 1:
            return cbor::Value::text(word(below(4)) + std::to_string(i));
        default:
            return cbor::Value::bytes(Bytes{static_cast<std::uint8_t>(i), 0xEE});
        }
    }

    protocol::Id id() {
        Bytes bytes(32);
        for (auto& b : bytes) {
            b = static_cast<std::uint8_t>(rng_());
        }
        return *protocol::to_id(bytes);
    }

    protocol::Parties parties() {
        protocol::Parties out;
        for (std::uint64_t i = 0, n = below(5); i < n; ++i) {
            out.emplace(word(1 + below(30)) + std::to_string(i), id());
        }
        return out;
    }

    std::optional<std::string> status() {
        return below(3) == 0 ? std::nullopt : std::optional(word(1 + below(63)));
    }

    protocol::ContractSigner signer() {
        protocol::ContractSigner out;
        out.kind = static_cast<std::uint8_t>(below(4));
        if (below(2) == 0) {
            out.presence = static_cast<protocol::PresenceMethod>(1 + below(2));
        }
        if (below(3) == 0) {
            out.model = word(1 + below(20));
        }
        return out;
    }

    cbor::Encoded state() { return *cbor::Encoded::encode(value()); }

private:
    std::mt19937_64 rng_;
};

/// The input from a bo-v1 run's call, as the vectors record it.
protocol::ContractInput bo_input(const nlohmann::json& call) {
    const auto signer = [](const nlohmann::json& s) {
        protocol::ContractSigner out;
        out.kind = s["kind"].get<std::uint8_t>();
        if (!s["presence"].is_null()) {
            out.presence = static_cast<protocol::PresenceMethod>(s["presence"].get<int>());
        }
        if (!s["model"].is_null()) {
            out.model = text(s["model"]);
        }
        return out;
    };
    protocol::ContractInput in;
    in.function = text(call["function"]);
    in.arguments = *cbor::decode(hex(text(call["arguments"])));
    in.home = id(call["home"]);
    in.contract = id(call["contract"]);
    if (const auto& i = call["instance"]; !i.is_null()) {
        protocol::ContractInstanceView view;
        view.id = id(i["id"]);
        view.head = i["head"].get<std::uint64_t>();
        view.state = *cbor::Encoded::from_bytes(hex(text(i["state"])));
        if (!i["status"].is_null()) {
            view.status = text(i["status"]);
        }
        for (const auto& [role, ledger] : i["parties"].items()) {
            view.parties.emplace(role, id(ledger));
        }
        if (i.contains("parent") && !i["parent"].is_null()) {
            view.parent = id(i["parent"]);
            view.depth = i["depth"].get<std::uint32_t>();
        }
        in.instance = std::move(view);
    }
    in.caller = id(call["caller"]);
    in.caller_signer = signer(call["signer"]);
    in.time = call["time"].get<protocol::Timestamp>();
    for (const auto& c : call["consents"]) {
        in.consents.emplace_back(id(c[0]), signer(c[1]));
    }
    if (call.contains("request") && !call["request"].is_null()) {
        const auto& r = call["request"];
        in.request = protocol::ContractRequestView{
            id(r["id"]),
            text(r["kind"]),
            *cbor::decode(hex(text(r["params"]))),
            r["deadline"].get<protocol::Timestamp>(),
            r["asked_at"].get<protocol::Timestamp>(),
            static_cast<protocol::AnswerStatus>(r["status"].get<int>()),
        };
    }
    return in;
}

/// A call's input built from the state, as `run_contract` builds it.
protocol::ContractInput input_of(const protocol::LedgerState& state,
                                 const protocol::SignedStatement& signed_call,
                                 protocol::Timestamp now) {
    const auto& call = std::get<protocol::ContractCallBody>(signed_call.statement.body);
    protocol::ContractInput in;
    in.function = call.function;
    in.arguments = call.arguments;
    in.home = state.ledger_id();
    if (call.instance) {
        const protocol::InstanceState& i = *state.instance(*call.instance);
        in.contract = i.contract.id();
        in.instance = protocol::ContractInstanceView{
            .id = *call.instance,
            .head = i.head,
            .state = i.state,
            .status = i.status,
            .parties = i.parties,
            .parent = i.parent ? std::optional<protocol::Id>(i.parent->id()) : std::nullopt,
            .depth = i.depth,
        };
    } else {
        in.contract = *call.contract;
    }
    in.caller = *signed_call.statement.actor_id;
    in.caller_signer = *state.contract_signer(signed_call.statement);
    in.time = now;
    for (const protocol::ContractConsentRef& c : call.consents) {
        in.consents.emplace_back(c.ledger, c.signer);
    }
    if (call.answer) {
        const protocol::RequestState& r = *state.request(call.answer->request);
        in.request = protocol::ContractRequestView{r.id.id(),  r.kind,     r.params,
                                                   r.deadline, r.asked_at, call.answer->status};
    }
    return in;
}

/// An output read from its bytes and through trees: the same verdict, and
/// the same output, encoding back to the same bytes both ways.
struct Outputs {
    std::size_t read = 0;
    std::size_t accepted = 0;
    std::size_t differing = 0;

    void check(ByteView output, const protocol::Id& home) {
        ++read;
        const auto bytes = protocol::decode_contract_output(output, home);
        const auto trees = reference::decode_contract_output(output, home);
        bool same = same_verdict(bytes, trees) && (!bytes || *bytes == *trees);
        if (same && bytes) {
            ++accepted;
            const auto again = protocol::encode_contract_output(*bytes);
            const auto again_trees = reference::encode_contract_output(*trees);
            same = again && again_trees && *again == *again_trees &&
                   std::ranges::equal(*again, output);
        }
        if (!same && ++differing <= 5) {
            UNSCOPED_INFO("an output read differently: " << to_hex(output));
        }
    }
};

} // namespace

TEST_CASE("contracts: every bo-v1 input, its state spliced, is the tree-built input",
          "[protocol][contracts][vectors]") {
    std::size_t inputs = 0;
    std::size_t with_state = 0;
    Outputs outputs;
    const auto document = load_vectors("bo-v1.json");
    for (const auto& c : document["contracts"]) {
        for (const auto& r : c["runs"]) {
            INFO(text(c["name"]) << ": " << text(r["label"]));
            const Bytes recorded = hex(text(r["input"]));
            if (!r["call"].is_null()) {
                const protocol::ContractInput in = bo_input(r["call"]);
                const auto spliced = protocol::encode_contract_input(in);
                const auto built = reference::encode_contract_input(in);
                REQUIRE(spliced);
                REQUIRE(built);
                CHECK(*spliced == recorded);
                CHECK(*built == recorded);
                ++inputs;
                if (in.instance) {
                    ++with_state;
                }
                outputs.check(recorded, in.home);
            }
            outputs.check(hex(text(r["output"])), id(std::string(64, '1')));
        }
    }
    CHECK(inputs == 761);
    CHECK(with_state > 500);
    CHECK(outputs.accepted > 500);
    CHECK(outputs.differing == 0);
}

TEST_CASE("contracts: every run of the protocol vectors reads and writes as through trees",
          "[protocol][contracts][vectors]") {
    std::size_t calls = 0;
    Outputs outputs;
    for (const char* file :
         {"protocol-v0.6.json", "protocol-v0.7.json", "protocol-v0.8.json", "protocol-v0.9.json"}) {
        const auto document = load_vectors(file);
        const auto t0 = document["t0"].get<protocol::Timestamp>();
        for (const auto& ledger : document["ledgers"]) {
            const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
            const auto& statements = ledger["statements"];
            std::vector<protocol::SignedStatement> parsed;
            for (const auto& st : statements) {
                parsed.push_back(
                    *protocol::parse_statement(provider(), hex(text(st["encoded"])), hash));
            }
            auto state = protocol::LedgerState::from_genesis(provider(), parsed.front());
            REQUIRE(state);
            for (std::size_t i = 1; i < parsed.size(); ++i) {
                INFO(file << " " << text(statements[i]["name"]));
                const protocol::Timestamp at =
                    statements[i].contains("registered_at")
                        ? statements[i]["registered_at"].get<protocol::Timestamp>()
                        : t0 + 1000 + i;
                if (std::holds_alternative<protocol::ContractCallBody>(parsed[i].statement.body)) {
                    ++calls;
                    const auto run = state->run_contract(provider(), parsed[i], at);
                    REQUIRE(run);
                    const protocol::ContractInput in = input_of(*state, parsed[i], at);
                    CHECK(*reference::encode_contract_input(in) == run->input);
                    CHECK(*protocol::encode_contract_input(in) == run->input);
                    outputs.check(run->outcome.output, state->ledger_id());
                    outputs.check(run->input, state->ledger_id());
                }
                REQUIRE(state->validate(provider(), parsed[i], at));
                REQUIRE(state->apply(provider(), parsed[i], i, at));
            }
        }
    }
    CHECK(calls > 50);
    CHECK(outputs.accepted > 40);
    CHECK(outputs.differing == 0);
}

TEST_CASE("contracts: random states and outputs, read and written as through trees",
          "[protocol][contracts][property]") {
    Values random(0xB17E'5000);
    const protocol::Id home = random.id();
    std::size_t inputs = 0;
    Outputs outputs;
    for (int n = 0; n < 1500; ++n) {
        // An input with a random instance, consents, and request.
        protocol::ContractInput in;
        in.function = random.word(1 + random.below(20));
        in.arguments = random.value();
        in.home = home;
        in.contract = random.id();
        if (random.below(4) != 0) {
            in.instance = protocol::ContractInstanceView{random.id(),
                                                         random.below(1'000'000),
                                                         random.state(),
                                                         random.status(),
                                                         random.parties(),
                                                         std::nullopt,
                                                         0};
            if (random.below(3) == 0) {
                in.instance->parent = random.id();
                in.instance->depth = static_cast<std::uint32_t>(1 + random.below(8));
            }
        }
        in.caller = random.id();
        in.caller_signer = random.signer();
        in.time = random.below(std::uint64_t{1} << 50);
        for (std::uint64_t c = 0, count = random.below(3); c < count; ++c) {
            in.consents.emplace_back(random.id(), random.signer());
        }
        if (random.below(5) == 0) {
            in.request = protocol::ContractRequestView{
                random.id(),
                random.word(1 + random.below(10)),
                random.value(),
                random.below(1'000'000),
                random.below(1'000'000),
                static_cast<protocol::AnswerStatus>(1 + random.below(3))};
        }
        const auto spliced = protocol::encode_contract_input(in);
        const auto built = reference::encode_contract_input(in);
        REQUIRE(spliced);
        REQUIRE(built);
        CHECK(*spliced == *built);
        ++inputs;

        // An accept with random states, events, children, and requests, or
        // needs; then the same bytes damaged.
        protocol::ContractOutput output;
        if (random.below(6) == 0) {
            protocol::ContractNeeds needs;
            for (std::uint64_t k = 0, count = 1 + random.below(4); k < count; ++k) {
                needs.ledgers.push_back(random.id());
            }
            std::ranges::sort(needs.ledgers, [](const auto& a, const auto& b) {
                return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
            });
            output = std::move(needs);
        } else {
            protocol::ContractAccept accept;
            accept.state = random.state();
            accept.status = random.status();
            if (random.below(2) == 0) {
                accept.parties = random.parties();
            }
            for (std::uint64_t k = 0, count = random.below(3); k < count; ++k) {
                accept.events.push_back({random.word(1 + random.below(10)), random.value()});
            }
            accept.final = random.below(3) == 0;
            for (std::uint64_t k = 0, count = random.below(3); k < count; ++k) {
                accept.children.push_back({random.state(), random.status(), random.parties()});
            }
            for (std::uint64_t k = 0, count = random.below(2); k < count; ++k) {
                accept.requests.push_back({"a" + random.word(random.below(8)), random.value(),
                                           random.below(1'000'000),
                                           random.word(1 + random.below(10))});
            }
            output = std::move(accept);
        }
        const auto written = protocol::encode_contract_output(output);
        const auto written_trees = reference::encode_contract_output(output);
        REQUIRE(written);
        REQUIRE(written_trees);
        CHECK(*written == *written_trees);
        outputs.check(*written, home);
        for (int m = 0; m < 8; ++m) {
            Bytes damaged = *written;
            const std::size_t at = random.below(damaged.size());
            damaged[at] = static_cast<std::uint8_t>(
                m % 2 == 0 ? random.below(256) : damaged[at] ^ (1U << random.below(8)));
            outputs.check(damaged, home);
        }
    }
    CHECK(inputs == 1500);
    CHECK(outputs.accepted > 1000);
    CHECK(outputs.differing == 0);
}
