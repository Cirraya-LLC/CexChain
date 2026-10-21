// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Contract calls run ahead in parallel (D-056 P7): random mixes of
// statements (creations, calls on shared and distinct instances, children,
// requests and answers, key rotations, revocations, cited consents, repeats,
// records) registered in groups give the results, the log, the state root,
// and every instance and request that registering them one at a time gives;
// and the log opened again, and replayed by core alone, gives the same.

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/log.hpp>
#include <cexchain/core/protocol/state.hpp>

#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

namespace {

using namespace cexchain::test;
using cexchain::Bytes;
using cexchain::ByteView;

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.8.json");
    return document;
}

cbor::Value text(std::string value) {
    return cbor::Value::text(std::move(value));
}

/// Two copies of one ledger: `batch` takes each group with one
/// submit_batch, `single` one statement at a time, at the same time.
struct Pair {
    World batch;
    World single;
    protocol::Id contract;
    protocol::Id oracle;
    /// Devices that may call the contract; one has its key rotated, one is
    /// revoked, at random points.
    std::vector<KeyPair> device_keys;
    std::vector<protocol::Id> devices;
    std::vector<protocol::Id> grants;
    KeyPair rotated = key("device-rotated");
    bool rotation_sent = false;
    bool revocation_sent = false;
    std::mt19937_64 random{20261021};

    Pair() {
        protocol::ContractDeployBody deploy;
        deploy.code = hex_field(vectors()["contract"]);
        for (const auto& [name, kind] : vectors()["interface"].items()) {
            deploy.interface.emplace(name, static_cast<protocol::FunctionKind>(kind.get<int>()));
        }
        deploy.language = "wasm";
        deploy.compiler = "hand-assembled 1";
        contract = setup(batch.org(), batch.statement(batch.org_id(), std::nullopt, deploy));
        // The v0.6 vectors' contract: its state is HASH(input) for arguments
        // that are neither bytes nor text, so a run on a stale input shows.
        protocol::ContractDeployBody hashing;
        hashing.code = hex(load_vectors("protocol-v0.6.json")["contract"].get<std::string>());
        hashing.interface = {{"open", protocol::FunctionKind::create},
                             {"ask", protocol::FunctionKind::call},
                             {"result", protocol::FunctionKind::call}};
        hashing.language = "wasm";
        hashing.compiler = "hand-assembled 1";
        oracle = setup(batch.org(), batch.statement(batch.org_id(), std::nullopt, hashing));
        for (const char* name : {"device-0", "device-1", "device-2"}) {
            device_keys.push_back(key(name));
            devices.push_back(
                setup(batch.org(),
                      batch.statement(batch.org_id(), std::nullopt,
                                      protocol::ActorRegisterBody{protocol::ActorKind::device, name,
                                                                  device_keys.back().public_key(),
                                                                  std::nullopt, std::nullopt})));
            auto s = scope({StatementType::contract_call});
            std::vector<protocol::Id> both{contract, oracle};
            std::ranges::sort(both, [](const protocol::Id& a, const protocol::Id& b) {
                return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
            });
            s.contracts = std::move(both);
            grants.push_back(setup(
                batch.org(), batch.statement(batch.org_id(), std::nullopt,
                                             protocol::DelegationGrantBody{devices.back(), s})));
        }
    }

    /// Registers a statement on both, one at a time.
    protocol::Id setup(const KeyPair& signer, const protocol::Statement& s) {
        auto signed_s = protocol::sign_statement(signer, provider(), batch.hash(), s);
        INFO((signed_s ? std::string() : std::string(signed_s.error().detail)));
        REQUIRE(signed_s);
        const Bytes signed_statement = signed_s->encoded;
        auto a = batch.ledger().submit(signed_statement);
        auto b = single.ledger().submit(signed_statement);
        REQUIRE(a);
        REQUIRE(b);
        REQUIRE(a->statement_id == b->statement_id);
        batch.clock().advance(1000);
        single.clock().advance(1000);
        return a->statement_id;
    }

    std::size_t pick(std::size_t n) { return static_cast<std::size_t>(random() % n); }
    bool chance(unsigned percent) { return random() % 100 < percent; }

    /// An output the request contract writes as given: an accept with a
    /// random state, maybe children, maybe a request.
    cbor::Value output(protocol::Timestamp now) {
        protocol::ContractAccept accept;
        accept.state = *cbor::Encoded::encode(cbor::Value::unsigned_integer(random() % 1000));
        if (chance(30)) {
            accept.status = "s" + std::to_string(pick(3));
        }
        for (std::size_t c = chance(25) ? 1 + pick(2) : 0; c > 0; --c) {
            protocol::ContractChild child;
            child.state = *cbor::Encoded::encode(cbor::Value::unsigned_integer(c));
            accept.children.push_back(std::move(child));
        }
        if (chance(25)) {
            accept.requests.push_back(
                {"provision", cbor::Value::map({{text("n"), text("1")}}), now + day, "result"});
        }
        auto bytes = protocol::encode_contract_output(accept);
        REQUIRE(bytes);
        return cbor::Value::bytes(*bytes);
    }

    /// Arguments: the output itself, or requests to make, or (rarely) an
    /// abort, which the contract refuses.
    cbor::Value arguments(protocol::Timestamp now) {
        if (chance(5)) {
            return text("no");
        }
        if (chance(35)) {
            // The hashing contract's state then depends on its whole input.
            return cbor::Value::unsigned_integer(random() % 100);
        }
        if (chance(25)) {
            return cbor::Value::array({cbor::Value::array(
                {text("suspend"), cbor::Value::map({}), cbor::Value::unsigned_integer(day)})});
        }
        return output(now);
    }

    /// What the generator expects of a group so far: the next index, and
    /// the instances' heads as the group's earlier statements leave them.
    struct Plan {
        std::uint64_t next = 0;
        std::map<protocol::IdKey, std::uint64_t> heads;
        /// Instances and requests made earlier in the group: (instance, id).
        std::vector<protocol::Id> instances;
        std::vector<std::pair<protocol::Id, protocol::Id>> requests;
    };

    /// A contract statement by the organization or a device under its grant
    /// (device 0 with its new key once a rotation was sent).
    std::pair<const KeyPair*, protocol::Statement> by_someone(protocol::Body body) {
        const std::size_t who = pick(devices.size() + 1);
        if (who == devices.size()) {
            return {&batch.org(), batch.statement(batch.org_id(), std::nullopt, std::move(body))};
        }
        const KeyPair* signer = who == 0 && rotation_sent ? &rotated : &device_keys[who];
        return {signer, batch.statement(devices[who], grants[who], std::move(body))};
    }

    /// A call's target: one of a few shared instances, any instance, or one
    /// made earlier in the group; and the head to name: as the group's
    /// earlier statements leave it, or (rarely) stale.
    std::optional<std::pair<protocol::Id, std::uint64_t>> target(const protocol::LedgerState& s,
                                                                 const Plan& plan) {
        std::optional<protocol::Id> id;
        if (!plan.instances.empty() && chance(30)) {
            id = plan.instances[pick(plan.instances.size())];
        } else if (s.instances().size() > 0) {
            const std::size_t n = s.instances().size();
            const std::size_t at = chance(50) ? pick(std::min<std::size_t>(n, 3)) : pick(n);
            std::size_t k = 0;
            for (const auto& [key, instance] : s.instances()) {
                if (k++ == at) {
                    id = instance.id.id();
                    break;
                }
            }
        }
        if (!id) {
            return std::nullopt;
        }
        const auto planned = plan.heads.find(protocol::key_of(*id));
        const protocol::InstanceState* before = s.instance(*id);
        std::uint64_t head = planned != plan.heads.end() ? planned->second : 0;
        if (before != nullptr && (planned == plan.heads.end() || chance(10))) {
            head = before->head;
        }
        return std::pair(*id, head);
    }

    /// Signs a statement and plans as if it is registered: its index, the
    /// head it gives the instance it moves, and the children and the
    /// request it may make (later statements of the group may use them).
    Bytes plan_for(const std::pair<const KeyPair*, protocol::Statement>& made,
                   const std::optional<protocol::Id>& acts_on, Plan& plan) {
        auto signed_made =
            protocol::sign_statement(*made.first, provider(), batch.hash(), made.second);
        INFO((signed_made ? std::string() : std::string(signed_made.error().detail)));
        REQUIRE(signed_made);
        Bytes signed_statement = signed_made->encoded;
        const auto parsed = protocol::parse_statement(provider(), signed_statement, batch.hash());
        REQUIRE(parsed);
        const std::uint64_t index = plan.next++;
        const auto* call = std::get_if<protocol::ContractCallBody>(&made.second.body);
        if (call == nullptr) {
            return signed_statement;
        }
        const protocol::Id moved = acts_on ? *acts_on : parsed->id;
        plan.heads[protocol::key_of(moved)] = index;
        if (!acts_on) {
            plan.instances.push_back(parsed->id);
        }
        for (std::uint64_t position = 0; position < 2; ++position) {
            auto child =
                protocol::child_instance_id(provider(), batch.hash(), parsed->id, position);
            REQUIRE(child);
            plan.instances.push_back(*child);
            plan.heads[protocol::key_of(*child)] = index;
        }
        auto request = protocol::request_id(provider(), batch.hash(), parsed->id, 0);
        REQUIRE(request);
        plan.requests.emplace_back(moved, *request);
        return signed_statement;
    }

    /// A random group of `size` signed statements, made against the state
    /// before it (the same on both copies). `sent` holds every statement
    /// sent before, for repeats.
    std::vector<Bytes> group(std::size_t size, const std::vector<Bytes>& sent) {
        const protocol::LedgerState& s = single.ledger().state();
        const protocol::Timestamp now = single.clock().now();
        Plan plan;
        plan.next = single.ledger().size();
        std::vector<std::pair<protocol::Id, protocol::Id>> open;
        for (const auto& [key, r] : s.requests()) {
            if (r.open()) {
                open.emplace_back(r.instance.id(), r.id.id());
            }
        }
        std::vector<Bytes> out;
        while (out.size() < size) {
            const std::size_t kind = pick(100);
            if (kind >= 85 && (!sent.empty() || !out.empty())) {
                // A repeat, of an earlier group's statement or this one's.
                const std::size_t at = pick(sent.size() + out.size());
                out.push_back(at < sent.size() ? sent[at] : out[at - sent.size()]);
                continue;
            }
            std::optional<std::pair<const KeyPair*, protocol::Statement>> made;
            std::optional<protocol::Id> acts_on; // the instance a call moves
            if (kind < 20) {
                protocol::ContractCallBody b;
                b.contract = chance(50) ? contract : oracle;
                b.function = "open";
                b.arguments = arguments(now);
                made = by_someone(std::move(b));
            } else if (kind < 70) {
                const bool answering = kind >= 55;
                const auto& requests = !plan.requests.empty() && chance(40) ? plan.requests : open;
                auto t = target(s, plan);
                if (answering && !requests.empty()) {
                    const auto& [instance, request] = requests[pick(requests.size())];
                    const auto planned = plan.heads.find(protocol::key_of(instance));
                    const protocol::InstanceState* before = s.instance(instance);
                    t = std::pair(instance, planned != plan.heads.end() ? planned->second
                                            : before != nullptr         ? before->head
                                                                        : 0);
                    protocol::ContractCallBody b;
                    b.instance = instance;
                    b.function = "result";
                    b.arguments = cbor::Value::null();
                    b.head = t->second;
                    b.answer = protocol::ContractAnswer{
                        request,
                        chance(70) ? protocol::AnswerStatus::done : protocol::AnswerStatus::failed};
                    acts_on = instance;
                    made = by_someone(std::move(b));
                } else if (t) {
                    protocol::ContractCallBody b;
                    b.instance = t->first;
                    b.function = "ask";
                    b.arguments = arguments(now);
                    b.head = t->second;
                    if (chance(15)) {
                        // A cited consent: the input shows it.
                        b.consents.push_back({contract, t->first, t->first, {}});
                    }
                    acts_on = t->first;
                    made = by_someone(std::move(b));
                }
            } else if (kind < 74 && !rotation_sent) {
                rotation_sent = true;
                made =
                    std::pair(&batch.org(), batch.statement(batch.org_id(), std::nullopt,
                                                            protocol::ActorRotateKeyBody{
                                                                devices[0], rotated.public_key()}));
            } else if (kind < 77 && !revocation_sent) {
                revocation_sent = true;
                made = std::pair(&batch.org(),
                                 batch.statement(batch.org_id(), std::nullopt,
                                                 protocol::ActorRevokeBody{devices[2], "gone"}));
            } else {
                made = std::pair(&batch.org(), batch.statement(batch.org_id(), std::nullopt,
                                                               batch.record_body(document_type)));
            }
            if (!made) {
                continue;
            }
            out.push_back(plan_for(*made, acts_on, plan));
        }
        return out;
    }
};

/// Every instance and request of `a` is in `b`, the same, and the counts
/// agree.
void same_contracts(const protocol::LedgerState& a, const protocol::LedgerState& b) {
    REQUIRE(a.instances().size() == b.instances().size());
    for (const auto& [key, i] : a.instances()) {
        const protocol::InstanceState* j = b.instance(i.id.id());
        REQUIRE(j != nullptr);
        CHECK(i.head == j->head);
        CHECK(i.state == j->state);
        CHECK(i.status == j->status);
        CHECK(i.parties == j->parties);
        CHECK(i.final == j->final);
        CHECK(i.history == j->history);
        CHECK(i.created_by == j->created_by);
        CHECK(i.depth == j->depth);
        CHECK(i.open_requests == j->open_requests);
    }
    REQUIRE(a.requests().size() == b.requests().size());
    for (const auto& [key, r] : a.requests()) {
        const protocol::RequestState* q = b.request(r.id.id());
        REQUIRE(q != nullptr);
        CHECK(r.instance == q->instance);
        CHECK(r.call == q->call);
        CHECK(r.status == q->status);
        CHECK(r.answered_by == q->answered_by);
        CHECK(r.deadline == q->deadline);
    }
}

/// The same log, entry for entry.
void same_log(const ledger::Ledger& a, const ledger::Ledger& b) {
    REQUIRE(a.size() == b.size());
    for (std::uint64_t i = 0; i < a.size(); ++i) {
        CHECK(*a.entry(i) == *b.entry(i));
    }
}

} // namespace

TEST_CASE("ledger: groups with contract calls run ahead give what one at a time gives",
          "[ledger][contracts][parallel]") {
    Pair p;
    std::vector<Bytes> sent;
    std::size_t refused = 0;
    std::size_t accepted = 0;
    for (int round = 0; round < 40; ++round) {
        INFO("round " << round);
        const std::vector<Bytes> group = p.group(1 + p.pick(24), sent);
        const std::vector<ByteView> views(group.begin(), group.end());
        const auto batched = p.batch.ledger().submit_batch(views);
        REQUIRE(batched.size() == group.size());
        for (std::size_t i = 0; i < group.size(); ++i) {
            INFO("statement " << i);
            const auto one = p.single.ledger().submit(group[i]);
            REQUIRE(batched[i].has_value() == one.has_value());
            if (one) {
                CHECK(batched[i]->index == one->index);
                CHECK(batched[i]->registered_at == one->registered_at);
                CHECK(batched[i]->newly_registered == one->newly_registered);
                ++accepted;
            } else {
                CHECK(batched[i].error().code == one.error().code);
                CHECK(batched[i].error().detail == one.error().detail);
                ++refused;
            }
        }
        sent.insert(sent.end(), group.begin(), group.end());
        p.batch.clock().advance(1 + p.pick(5000));
        p.single.clock().set(p.batch.clock().now());
    }
    same_log(p.batch.ledger(), p.single.ledger());
    same_contracts(p.batch.ledger().state(), p.single.ledger().state());
    // Both kinds of outcome, and runs taken and run again, were seen.
    CHECK(accepted > 100);
    CHECK(refused > 10);
    const auto ahead = p.batch.ledger().runs_ahead();
    CHECK(ahead.taken > 50);
    CHECK(ahead.taken < ahead.made);

    // The state roots agree (a checkpoint commits to the state).
    const auto a = p.batch.ledger().checkpoint(p.batch.log_key());
    const auto b = p.single.ledger().checkpoint(p.single.log_key());
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a->checkpoint.root == b->checkpoint.root);
    REQUIRE(p.batch.ledger().state_commitment());
    CHECK(p.batch.ledger().state_commitment()->state_root ==
          p.single.ledger().state_commitment()->state_root);
    same_log(p.batch.ledger(), p.single.ledger());

    // Opened again (a replay that runs ahead), and replayed by core alone,
    // statement by statement, without runs ahead: the same.
    auto reopened = ledger::Ledger::open(p.batch.fs(), p.batch.clock(), provider());
    REQUIRE(reopened);
    same_log(*reopened, p.single.ledger());
    same_contracts(reopened->state(), p.single.ledger().state());
    CHECK(reopened->runs_ahead().taken > 0);
    std::optional<protocol::LedgerState> plain;
    for (std::uint64_t i = 0; i < reopened->size(); ++i) {
        const auto entry = protocol::decode_log_entry(*reopened->entry(i));
        REQUIRE(entry);
        if (entry->is_state_commitment()) {
            continue;
        }
        const auto st = protocol::parse_statement(provider(), entry->statement, p.batch.hash());
        REQUIRE(st);
        if (!plain) {
            plain.emplace(*protocol::LedgerState::from_genesis(provider(), *st));
            continue;
        }
        REQUIRE(plain->validate(provider(), *st, entry->registered_at));
        REQUIRE(plain->apply(provider(), *st, i, entry->registered_at));
    }
    same_contracts(*plain, p.single.ledger().state());
}

TEST_CASE("ledger: pipelined groups give what one at a time gives, each answered once durable",
          "[ledger][contracts][parallel]") {
    Pair p;
    std::vector<Bytes> sent;
    std::vector<std::vector<Bytes>> groups;
    std::mutex mutex;
    std::vector<std::vector<cexchain::Result<ledger::Registration>>> answers;
    bool durable_first = true;
    std::vector<std::vector<std::optional<std::uint64_t>>> single;
    // A reader alongside: whatever it finds registered is in the log.
    std::atomic<bool> done = false;
    std::atomic<std::size_t> seen = 0;
    std::thread reader([&] {
        while (!done.load()) {
            std::vector<Bytes> copy;
            {
                const std::lock_guard lock(mutex);
                if (!groups.empty()) {
                    copy = groups[groups.size() / 2];
                }
            }
            for (const Bytes& b : copy) {
                const auto st = protocol::parse_statement(provider(), b, p.batch.hash());
                if (const auto index =
                        st ? p.batch.ledger().statement_index(st->id) : std::nullopt) {
                    if (p.batch.ledger().entry(*index)) {
                        ++seen;
                    }
                }
            }
        }
    });
    for (int round = 0; round < 40; ++round) {
        std::vector<Bytes> group = p.group(1 + p.pick(24), sent);
        {
            const std::lock_guard lock(mutex);
            groups.push_back(group);
        }
        const std::vector<ByteView> views(group.begin(), group.end());
        p.batch.ledger().submit_batch_pipelined(
            views, [&, size = group.size()](std::vector<cexchain::Result<ledger::Registration>> r) {
                // Called once its entries are durable: the readers' size
                // covers every one.
                const std::uint64_t durable = p.batch.ledger().size();
                const std::lock_guard lock(mutex);
                for (const auto& one : r) {
                    durable_first = durable_first && (!one || one->index < durable);
                }
                durable_first = durable_first && r.size() == size;
                answers.push_back(std::move(r));
            });
        std::vector<std::optional<std::uint64_t>> indexes;
        for (const Bytes& b : group) {
            const auto one = p.single.ledger().submit(b);
            indexes.push_back(one ? std::optional(one->index) : std::nullopt);
        }
        single.push_back(std::move(indexes));
        sent.insert(sent.end(), group.begin(), group.end());
        p.batch.clock().advance(1 + p.pick(5000));
        p.single.clock().set(p.batch.clock().now());
    }
    p.batch.ledger().wait_durable();
    done = true;
    reader.join();
    CHECK(durable_first);
    REQUIRE(answers.size() == groups.size());
    same_log(p.batch.ledger(), p.single.ledger());
    same_contracts(p.batch.ledger().state(), p.single.ledger().state());
    // Each answer is what registering the statement again gives now: the
    // same index (a repeat), or the same refusal.
    for (std::size_t g = 0; g < groups.size(); ++g) {
        for (std::size_t i = 0; i < groups[g].size(); ++i) {
            const auto again = p.single.ledger().submit(groups[g][i]);
            const auto& answer = answers[g][i];
            CHECK(answer.has_value() == single[g][i].has_value());
            if (answer && single[g][i]) {
                CHECK(answer->index == *single[g][i]);
                REQUIRE(again);
                CHECK(again->index == answer->index);
                CHECK(again->registered_at == answer->registered_at);
            }
        }
    }
    CHECK(seen.load() > 0);
}
