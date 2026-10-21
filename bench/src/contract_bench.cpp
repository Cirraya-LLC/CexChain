// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Contracts in-process (D-056): creations and calls registered on a ledger
// in memory or on disk, where one call's time goes (parsing, the signature,
// validation, the contract run, the VM alone), checkpoints, and replay of a
// contract-heavy log; the evidence of instances (small, long, and deep
// parts) exported and verified; and the keeper's scans for due work, and
// (--record) the server's keeper making the due calls.

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <format>
#include <memory>
#include <print>
#include <ranges>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

#include <cexchain/core/protocol/contract_evidence.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/protocol/evidence.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/ledger/parallel.hpp>
#include <cexchain/node/api.hpp>
#include <cexchain/node/keeper.hpp>

#include "bench.hpp"
#include "fixture.hpp"

namespace cexchain::bench {

namespace {

/// Mean microseconds of `repeat` runs of `f`.
template <class F>
double mean_us(std::uint64_t repeat, F&& f) {
    const auto started = Clock::now();
    for (std::uint64_t i = 0; i < repeat; ++i) {
        f();
    }
    return elapsed_us(started) / static_cast<double>(std::max<std::uint64_t>(repeat, 1));
}

/// Where one call's time goes, on the state as it stands: the call is
/// signed but not registered.
void breakdown(Home& home, const protocol::ContractCallBody& body, std::uint64_t repeat,
               const std::string& p, Results& results) {
    const protocol::SignedStatement call = home.sign(body);
    const protocol::LedgerState& state = home.state();
    const protocol::Timestamp now = home.clock().now();
    const auto& provider = bench::provider();
    const protocol::SignedStatement parsed =
        must(protocol::parse_statement(provider, call.encoded, crypto::HashAlg::sha256), "parse");
    results.add(
        p + "parse statement",
        mean_us(repeat,
                [&] {
                    must(protocol::parse_statement(provider, call.encoded, crypto::HashAlg::sha256),
                         "parse");
                }),
        "us");
    results.add(
        p + "verify signature",
        mean_us(repeat,
                [&] {
                    must(protocol::verify_statement(provider, parsed, home.org().public_key()),
                         "verify");
                }),
        "us");
    const protocol::SignatureCheck checked{home.org().public_key(), {}};
    results.add(
        p + "validate (signature checked before)",
        mean_us(repeat, [&] { must(state.validate(provider, parsed, now, &checked), "validate"); }),
        "us");
    const protocol::ContractRun run = must(state.run_contract(provider, parsed, now), "run");
    if (run.accepted() == nullptr) {
        throw std::runtime_error("the breakdown's call is not accepted");
    }
    const double run_us =
        mean_us(repeat, [&] { must(state.run_contract(provider, parsed, now), "run contract"); });
    const auto& b = std::get<protocol::ContractCallBody>(parsed.statement.body);
    const protocol::Id contract =
        b.instance ? state.instance(*b.instance)->contract.id() : *b.contract;
    const vm::Module& module = *state.contract(contract)->module;
    const double vm_us = mean_us(
        repeat, [&] { must(vm::run(module, run.input, provider, crypto::HashAlg::sha256), "vm"); });
    // The input and the output alone: the input built from the state as
    // run_contract builds it, and the run's output read back.
    const protocol::InstanceState* instance = b.instance ? state.instance(*b.instance) : nullptr;
    const auto input = [&] {
        protocol::ContractInput in;
        in.function = b.function;
        in.arguments = b.arguments;
        in.home = state.ledger_id();
        in.contract = contract;
        if (instance != nullptr) {
            in.instance = protocol::ContractInstanceView{
                .id = *b.instance,
                .head = instance->head,
                .state = instance->state,
                .status = instance->status,
                .parties = instance->parties,
                .parent = instance->parent ? std::optional<protocol::Id>(instance->parent->id())
                                           : std::nullopt,
                .depth = instance->depth,
            };
        }
        in.caller = *parsed.statement.actor_id;
        in.caller_signer = must(state.contract_signer(parsed.statement), "signer");
        in.time = now;
        for (const protocol::ContractConsentRef& c : b.consents) {
            in.consents.emplace_back(c.ledger, c.signer);
        }
        return must(protocol::encode_contract_input(in), "input");
    };
    if (b.answer || input() != run.input) {
        throw std::runtime_error("the breakdown's input differs from the run's");
    }
    const double input_us = mean_us(repeat, input);
    const double output_us = mean_us(repeat, [&] {
        must(protocol::decode_contract_output(run.outcome.output, state.ledger_id()), "output");
    });
    results.add(p + "run contract (input, VM, output)", run_us, "us");
    results.add(p + "  VM run alone", vm_us, "us");
    results.add(p + "  input and output (the rest)", run_us - vm_us, "us");
    results.add(p + "    input alone (from the state)", input_us, "us");
    results.add(p + "    output alone (read back)", output_us, "us");
    results.add(p + "fuel", static_cast<double>(run.outcome.fuel_used), "");
    results.add(p + "input", static_cast<double>(run.input.size()), "bytes");
    results.add(p + "output", static_cast<double>(run.outcome.output.size()), "bytes");
    results.add(p + "statement", static_cast<double>(call.encoded.size()), "bytes");
}

void contracts_of(const std::string& name, const Options& options, Results& results) {
    const std::uint64_t n = options.number("instances", 1000);
    const std::uint64_t k = options.number("calls", 4);
    const std::size_t batch = options.number("batch", 1);
    const std::uint64_t repeat = options.number("repeat", 200);
    const std::string disk = options.text("disk", "");
    const Workload w = make_workload(name, options);
    const std::string p = name + " ";
    Home home("contracts " + name,
              disk.empty() ? std::filesystem::path() : std::filesystem::path(disk) / name);
    results.add(p + "bo build", w.build_ms, "ms");
    results.add(p + "code", static_cast<double>(w.deploy.code.size()), "bytes");
    const protocol::Id contract = home.submit(w.deploy).statement_id;

    std::vector<protocol::Id> instances;
    std::vector<Bytes> statements;
    for (std::uint64_t i = 0; i < n; ++i) {
        protocol::SignedStatement s = home.sign(w.create(contract, home.id()));
        instances.push_back(s.id);
        statements.push_back(std::move(s.encoded));
    }
    Latencies created;
    home.submit_all(statements, batch, &created);
    created.report(results, p + "create", "creations/s");

    Latencies called;
    std::uint64_t rounds = 0;
    for (; rounds < k && (w.max_rounds == 0 || rounds < w.max_rounds); ++rounds) {
        home.clock().advance(1000);
        statements = sign_round(home, w, instances, rounds);
        home.submit_all(statements, batch, &called);
    }
    if (called.size() > 0) {
        called.report(results, p + "call", "calls/s");
    }

    // One more call, on an instance that takes it.
    home.clock().advance(1000);
    protocol::Id target = instances.front();
    std::uint64_t round = rounds;
    if (w.max_rounds != 0) {
        target = home.submit(w.create(contract, home.id())).statement_id;
        round = 0;
    }
    breakdown(home, w.call(target, home.state().instance(target)->head, home.id(), round), repeat,
              p, results);

    auto started = Clock::now();
    must(home.ledger().checkpoint(home.log_key()), "checkpoint");
    results.add(p + "checkpoint", elapsed_ms(started), "ms");
    const auto entries = home.ledger().size();
    // The log's root: the same before and after a change that must not
    // change what is registered.
    std::println(stderr, "{}log root {}", p,
                 to_hex(must(home.ledger().root(entries), "root").bytes()));
    const double open_ms = home.reopen();
    results.add(p + "entries", static_cast<double>(entries), "");
    results.add(p + "open (full replay)", open_ms, "ms");
    results.add(p + "open per entry", open_ms * 1000 / static_cast<double>(entries), "us/entry");
}

} // namespace

int contracts_bench(const Options& options) {
    Results results;
    results.add("threads", static_cast<double>(ledger::parallelism()), "");
    for (const std::string& name : workload_names(options, "small,heavy,split")) {
        contracts_of(name, options, results);
    }
    results.print(options.flag("json"));
    return 0;
}

// --- evidence ---

namespace {

struct Verified {
    double export_ms = 0;
    double verify_ms = 0;
    std::size_t bytes = 0;
};

Verified verify_instance(Home& home, const protocol::Id& instance, std::uint64_t repeat) {
    Verified out;
    auto started = Clock::now();
    const auto bundle = must(home.ledger().export_evidence(home.log_key(), instance), "export");
    out.export_ms = elapsed_ms(started);
    const Bytes encoded_bundle = must(protocol::encode_bundle(bundle), "encode");
    const Bytes evidence =
        must(protocol::encode_contract_evidence({encoded_bundle, {}}), "contract evidence");
    out.bytes = evidence.size();
    protocol::VerifyOptions o;
    o.expected_ledger = home.id();
    out.verify_ms =
        mean_us(
            repeat,
            [&] { must(protocol::verify_contract_evidence(provider(), evidence, o), "verify"); }) /
        1000;
    return out;
}

void add(Results& results, const std::string& p, const Verified& v, std::uint64_t statements) {
    results.add(p + "statements", static_cast<double>(statements), "");
    results.add(p + "evidence", static_cast<double>(v.bytes) / 1024, "KiB");
    results.add(p + "export", v.export_ms, "ms");
    results.add(p + "verify (contract evidence)", v.verify_ms, "ms");
    results.add(p + "  per statement", v.verify_ms * 1000 / static_cast<double>(statements), "us");
}

} // namespace

int evidence_bench(const Options& options) {
    const std::uint64_t history = options.number("history", 1000);
    const std::uint64_t filler = options.number("entries", 10000);
    const std::uint64_t repeat = options.number("repeat", 10);
    Results results;
    Home home("evidence");
    // Other entries, so that proofs have a realistic depth.
    std::vector<Bytes> records;
    for (std::uint64_t i = 0; i < filler; ++i) {
        records.push_back(home.sign(protocol::RecordRegisterBody{
                                        "example.document/1", Bytes(32, 7), 3, {}, std::nullopt})
                              .encoded);
    }
    home.submit_all(records, 512, nullptr);

    const Workload small = make_workload("small", options);
    const protocol::Id lending = home.submit(small.deploy).statement_id;
    auto calls_on = [&](const protocol::Id& instance, std::uint64_t count) {
        for (std::uint64_t r = 0; r < count; ++r) {
            home.clock().advance(1000);
            home.submit(small.call(instance, home.state().instance(instance)->head, home.id(), r));
        }
    };
    const protocol::Id short_one = home.submit(small.create(lending, home.id())).statement_id;
    calls_on(short_one, 2);
    const protocol::Id long_one = home.submit(small.create(lending, home.id())).statement_id;
    calls_on(long_one, history);

    // A part of a part of ...: four splits deep (multi-tier-split stops at
    // tier 5).
    const Workload split = make_workload("split", options);
    const protocol::Id splitting = home.submit(split.deploy).statement_id;
    protocol::Id part = home.submit(split.create(splitting, home.id())).statement_id;
    std::uint64_t amount = 100'000'000;
    std::uint64_t depth = 0;
    for (; depth < 4; ++depth) {
        home.clock().advance(1000);
        protocol::ContractCallBody b =
            split.call(part, home.state().instance(part)->head, home.id(), 0);
        const std::uint64_t first = amount / 10 * 6;
        b.arguments = object(
            {{"parts", cbor::Value::array({number(first), number(amount - first)})},
             {"recipients", cbor::Value::array({id_value(home.id()), id_value(home.id())})}});
        const protocol::Id call = home.submit(b).statement_id;
        part = must(protocol::child_instance_id(provider(), crypto::HashAlg::sha256, call, 0),
                    "child");
        amount = first;
    }
    must(home.ledger().checkpoint(home.log_key()), "checkpoint");

    results.add("ledger entries", static_cast<double>(home.ledger().size()), "");
    add(results, "small instance: ", verify_instance(home, short_one, repeat), 3);
    add(results, "long history: ", verify_instance(home, long_one, repeat), history + 1);
    add(results, std::format("part at depth {}: ", depth), verify_instance(home, part, repeat),
        depth + 1);
    results.print(options.flag("json"));
    return 0;
}

// --- keeper ---

namespace {

struct Scan {
    double ms = 0;
    std::size_t runs = 0;
    std::size_t rules = 0;
    std::size_t expiries = 0;
    std::uint64_t fuel = 0;
};

Scan scan(const Home& home, protocol::Timestamp at) {
    Scan out;
    node::DueOptions o;
    o.now = at;
    o.max_runs = node::max_due_runs;
    const auto started = Clock::now();
    for (;;) {
        const node::DueWork work = must(node::find_due(provider(), home.state(), o), "find due");
        out.runs += work.runs;
        out.rules += work.rules.size();
        out.expiries += work.expiries.size();
        out.fuel += work.fuel;
        if (!work.next) {
            break;
        }
        o.start = *work.next;
    }
    out.ms = elapsed_ms(started);
    return out;
}

void add(Results& results, const std::string& p, const Scan& s, std::uint64_t instances) {
    results.add(p + "scan", s.ms, "ms");
    results.add(p + "runs", static_cast<double>(s.runs), "");
    results.add(p + "per run", s.runs > 0 ? s.ms * 1000 / static_cast<double>(s.runs) : 0, "us");
    results.add(p + "per instance", s.ms * 1000 / static_cast<double>(instances), "us");
    results.add(p + "fuel per run",
                s.runs > 0 ? static_cast<double>(s.fuel) / static_cast<double>(s.runs) : 0, "");
    results.add(p + "due (rules, expiries)", static_cast<double>(s.rules + s.expiries), "");
}

/// The server's keeper (`serve --keeper-key`) making the calls due at `at`
/// on the ledger in `directory`: ticks, each followed by a wait for what it
/// queued, until `expected` calls are in the log, or until 40 ticks in a
/// row add nothing. A seeded nonce source and a manual clock make the run
/// repeatable: the same log, byte for byte, whatever the keeper's threads.
struct Recording {
    double ms = 0;
    std::uint64_t calls = 0;
    std::uint64_t ticks = 0;
    std::string root;
};

Recording record_due(const std::filesystem::path& directory, const std::string& name,
                     protocol::Timestamp at, std::uint64_t expected) {
    using namespace std::chrono_literals;
    ledger::ManualClock clock(at);
    ledger::SeededEntropy entropy(7);
    node::ApiOptions o;
    o.directory = directory;
    o.log_keys = {std::make_shared<const crypto::openssl::KeyPair>(named_key(name + " log"))};
    o.keeper = std::make_shared<const crypto::openssl::KeyPair>(named_key("keeper device"));
    o.keeper_interval = 0s;
    o.clock = &clock;
    o.entropy = &entropy;
    auto api = must(node::LedgerApi::open(o, provider()), "api");
    const std::uint64_t first = api->ledger().size();
    Recording out;
    std::uint64_t idle = 0;
    const auto started = Clock::now();
    while (api->ledger().size() - first < expected && idle < 40) {
        const std::uint64_t before = api->ledger().size();
        api->tick();
        api->stop(); // waits for what the tick queued
        ++out.ticks;
        idle = api->ledger().size() == before ? idle + 1 : 0;
    }
    out.ms = elapsed_ms(started);
    const std::uint64_t size = api->ledger().size();
    out.calls = size - first;
    out.root = to_hex(must(api->ledger().root(size), "root").bytes());
    return out;
}

} // namespace

int keeper_bench(const Options& options) {
    Results results;
    const std::string hosting =
        read_text(examples_directory(options) / "idc-hosting" / "hosting.bo");
    double build_ms = 0;
    const protocol::ContractDeployBody deploy = bo_deploy(hosting, &build_ms);
    const bool recording = options.flag("record");
    bool short_of_due = false;
    const std::filesystem::path scratch =
        options.text("dir", (std::filesystem::temp_directory_path() /
                             std::format("cexchain-bench-keeper-{}", ::getpid()))
                                .string());
    for (const auto part : std::views::split(options.text("instances", "1000,10000,100000"), ',')) {
        const std::uint64_t n = std::stoull(std::string(part.begin(), part.end()));
        // On disk when the server's keeper is to record (it opens the
        // directory), else in memory.
        Home home("keeper", recording ? scratch / std::to_string(n) : std::filesystem::path());
        const protocol::Id contract = home.submit(deploy).statement_id;
        if (recording) {
            // A keeper device: contract calls on the contract, its time
            // rules and its requests' reply only (as `keeper add` grants).
            const protocol::Id keeper =
                home.submit(protocol::ActorRegisterBody{protocol::ActorKind::device,
                                                        "Keeper",
                                                        named_key("keeper device").public_key(),
                                                        {},
                                                        {}})
                    .statement_id;
            protocol::Scope scope;
            scope.statement_types = {protocol::StatementType::contract_call};
            scope.contracts = std::vector<protocol::Id>{contract};
            std::vector<std::string> functions = node::time_rules(*home.state().contract(contract));
            functions.emplace_back("result");
            scope.functions = std::move(functions);
            home.submit(protocol::DelegationGrantBody{keeper, scope});
        }
        // Every instance created and subscribed (the home is both parties):
        // its time rules then look at real dates, and its requests are open.
        const auto started = Clock::now();
        std::vector<protocol::Id> instances;
        std::vector<Bytes> statements;
        for (std::uint64_t i = 0; i < n; ++i) {
            protocol::ContractCallBody b;
            b.contract = contract;
            b.function = "create";
            b.arguments = object({{"fields", object({})},
                                  {"parties", object({{"we", id_value(home.id())},
                                                      {"customer", id_value(home.id())}})}});
            protocol::SignedStatement s = home.sign(std::move(b));
            instances.push_back(s.id);
            statements.push_back(std::move(s.encoded));
        }
        home.submit_all(statements, 512, nullptr);
        home.clock().advance(1000);
        statements.clear();
        for (const protocol::Id& id : instances) {
            protocol::ContractCallBody b;
            b.instance = id;
            b.head = home.state().instance(id)->head;
            b.function = "subscribe";
            b.arguments = object({});
            statements.push_back(home.sign(std::move(b)).encoded);
        }
        home.submit_all(statements, 512, nullptr);
        const std::string p = std::format("{} instances: ", n);
        results.add(p + "setup (create and subscribe)", elapsed_ms(started), "ms");
        const protocol::Timestamp now = home.clock().now();
        const Scan due_now = scan(home, now + 1000);
        add(results, p + "now: ", due_now, n);
        add(results, p + "40 days on: ", scan(home, now + 40 * day), n);
        if (recording) {
            home.close();
            const Recording r = record_due(home.directory(), "keeper", now + 1000,
                                           due_now.rules + due_now.expiries);
            results.add(p + "server's keeper: calls recorded", static_cast<double>(r.calls), "");
            results.add(p + "server's keeper: ticks", static_cast<double>(r.ticks), "");
            results.add(p + "server's keeper: wall", r.ms, "ms");
            results.add(p + "server's keeper: calls/s",
                        r.ms > 0 ? static_cast<double>(r.calls) * 1000 / r.ms : 0, "calls/s");
            std::println(stderr, "{}server's keeper: log root {}", p, r.root);
            short_of_due = short_of_due || r.calls != due_now.rules + due_now.expiries;
            if (!options.flag("keep")) {
                std::filesystem::remove_all(home.directory());
            }
        }
    }
    if (recording && !options.flag("keep")) {
        std::filesystem::remove_all(scratch);
    }
    results.add("hosting bo build", build_ms, "ms");
    results.print(options.flag("json"));
    if (short_of_due) {
        std::println(stderr, "error: the server's keeper did not make every call due");
        return 1;
    }
    return 0;
}

} // namespace cexchain::bench
