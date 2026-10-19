// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"
#include "vm/internal.hpp"

namespace crypto = cexchain::crypto;
namespace vm = cexchain::vm;
using cexchain::Bytes;
using cexchain::ByteView;
using cexchain::Errc;
using cexchain::to_hex;
using cexchain::test::hex_field;
using cexchain::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

crypto::HashAlg hash_by_name(const std::string& name) {
    REQUIRE((name == "sha256" || name == "sm3"));
    return name == "sha256" ? crypto::HashAlg::sha256 : crypto::HashAlg::sm3;
}

/// A module translated two ways: as the interpreter runs it (fused
/// instructions, fuel charged per run) and plainly (one WebAssembly
/// instruction an instruction, each charged before it runs).
struct Translated {
    vm::Module fused;
    vm::Module plain;
};

Translated translate(ByteView wasm) {
    auto fused = vm::load(wasm);
    REQUIRE(fused);
    auto plain = vm::detail::load(wasm, vm::detail::Translation{.fuse = false, .runs = false});
    REQUIRE(plain);
    return {*std::move(fused), *std::move(plain)};
}

/// The ways to run a module, which must all give every run the same outcome.
struct Way {
    const char* name;
    vm::detail::Dispatch dispatch;
    bool plain;
};

constexpr Way ways[] = {
    {"threaded", vm::detail::Dispatch::threaded, false},
    {"table", vm::detail::Dispatch::table, false},
    {"plain, threaded", vm::detail::Dispatch::threaded, true},
    {"plain, table", vm::detail::Dispatch::table, true},
};

vm::Outcome run_way(const Translated& m, const Way& way, ByteView input, crypto::HashAlg hash,
                    std::uint64_t fuel, vm::Arena& arena) {
    auto outcome = vm::detail::run(way.plain ? m.plain : m.fused, input, provider(), hash, fuel,
                                   arena, way.dispatch);
    if (!outcome) {
        FAIL("the run failed");
    }
    return *std::move(outcome);
}

/// A run another engine recorded: the Python reference interpreter, for
/// vm-v1.json and bo-v1.json.
struct Recorded {
    std::string name;
    const Translated* module = nullptr;
    std::string module_name;
    Bytes input;
    std::string hash;
    std::string outcome;
    Bytes output;
    std::uint64_t fuel = 0;
    Bytes reason;
};

/// Every module and run of vm-v1.json and bo-v1.json.
struct Corpus {
    std::map<std::string, Bytes> wasm;
    std::map<std::string, Translated> modules;
    std::vector<Recorded> runs;
};

const Corpus& corpus() {
    static const Corpus instance = [] {
        Corpus out;
        const auto vm_doc = load_vectors("vm-v1.json");
        for (const auto& m : vm_doc.at("modules")) {
            if (m.at("valid").get<bool>()) {
                out.wasm.emplace(m.at("name").get<std::string>(), hex_field(m.at("wasm")));
            }
        }
        for (const auto& r : vm_doc.at("runs")) {
            out.runs.push_back({r.at("name").get<std::string>(), nullptr,
                                r.at("module").get<std::string>(), hex_field(r.at("input")),
                                r.at("hash").get<std::string>(), r.at("outcome").get<std::string>(),
                                hex_field(r.at("output")), r.at("fuel").get<std::uint64_t>(),
                                r.contains("reason") ? hex_field(r.at("reason")) : Bytes{}});
        }
        const auto bo_doc = load_vectors("bo-v1.json");
        for (const auto& c : bo_doc.at("contracts")) {
            const std::string name = "bo " + c.at("name").get<std::string>();
            out.wasm.emplace(name, hex_field(c.at("code")));
            for (const auto& r : c.at("runs")) {
                out.runs.push_back({name + ": " + r.at("label").get<std::string>(), nullptr, name,
                                    hex_field(r.at("input")), "sha256",
                                    r.at("outcome").get<std::string>(), hex_field(r.at("output")),
                                    r.at("fuel").get<std::uint64_t>(), hex_field(r.at("reason"))});
            }
        }
        for (const auto& [name, wasm] : out.wasm) {
            out.modules.emplace(name, translate(wasm));
        }
        for (Recorded& r : out.runs) {
            r.module = &out.modules.at(r.module_name);
        }
        return out;
    }();
    return instance;
}

/// What a run with `limit` fuel gives, from the run recorded with all of it:
/// an instruction that costs more than the fuel left traps, all the fuel
/// used; until then a run with less fuel does exactly what the full run did.
vm::Outcome expected_at(const Recorded& r, std::uint64_t limit) {
    vm::Outcome out;
    if (limit < r.fuel) {
        out.trap = vm::Trap::out_of_fuel;
        out.fuel_used = limit;
        return out;
    }
    if (r.outcome != "ok") {
        for (std::uint8_t t = 1; t <= static_cast<std::uint8_t>(vm::Trap::aborted); ++t) {
            if (vm::name(static_cast<vm::Trap>(t)) == r.outcome) {
                out.trap = static_cast<vm::Trap>(t);
            }
        }
        REQUIRE(out.trap);
    }
    out.output = r.output;
    out.fuel_used = r.fuel;
    out.abort_reason = r.reason;
    return out;
}

bool same(const vm::Outcome& a, const vm::Outcome& b) {
    return a.trap == b.trap && a.output == b.output && a.fuel_used == b.fuel_used &&
           a.abort_reason == b.abort_reason;
}

std::string describe(const vm::Outcome& o) {
    return std::string(o.trap ? vm::name(*o.trap) : "ok") + ", fuel " +
           std::to_string(o.fuel_used) + ", output " + to_hex(o.output) + ", reason " +
           to_hex(o.abort_reason);
}

/// Deterministic choices (splitmix64), the same with every standard library.
struct Choices {
    std::uint64_t state;

    std::uint64_t next() {
        std::uint64_t z = (state += 0x9E37'79B9'7F4A'7C15ULL);
        z = (z ^ (z >> 30U)) * 0xBF58'476D'1CE4'E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D0'49BB'1331'11EBULL;
        return z ^ (z >> 31U);
    }

    /// A value in [0, n).
    std::uint64_t below(std::uint64_t n) { return n == 0 ? 0 : next() % n; }
};

/// The smallest module in the profile: an empty cexchain_call and its memory.
const Bytes& empty_module() {
    static const Bytes wasm =
        cexchain::test::hex("0061736d01000000"                 // header
                            "010401600000"                     // type 0: [] -> []
                            "03020100"                         // function 0 has type 0
                            "0503010001"                       // memory: 1 page, no maximum
                            "071a02"                           // two exports:
                            "066d656d6f72790200"               //   "memory", memory 0
                            "0d636578636861696e5f63616c6c0000" //   "cexchain_call", function 0
                            "0a040102000b");                   // code: no locals, end
    return wasm;
}

} // namespace

TEST_CASE("vm: the reference interpreter's modules load or are refused alike", "[vm][vectors]") {
    const auto doc = load_vectors("vm-v1.json");
    REQUIRE(doc.at("fuel").get<std::uint64_t>() == vm::fuel_limit);
    std::size_t valid = 0;
    std::size_t refused = 0;
    for (const auto& m : doc.at("modules")) {
        const std::string name = m.at("name").get<std::string>();
        INFO(name);
        const auto loaded = vm::load(hex_field(m.at("wasm")));
        if (m.at("valid").get<bool>()) {
            REQUIRE(loaded);
            ++valid;
        } else {
            REQUIRE_FALSE(loaded);
            CHECK((loaded.error().code == Errc::unsupported ||
                   loaded.error().code == Errc::malformed));
            ++refused;
        }
    }
    CHECK(valid > 400);
    CHECK(refused > 30);
}

TEST_CASE("vm: runs match the reference interpreter, fuel included", "[vm][vectors]") {
    const auto doc = load_vectors("vm-v1.json");
    std::map<std::string, vm::Module> modules;
    for (const auto& m : doc.at("modules")) {
        if (m.at("valid").get<bool>()) {
            auto loaded = vm::load(hex_field(m.at("wasm")));
            REQUIRE(loaded);
            modules.emplace(m.at("name").get<std::string>(), *loaded);
        }
    }
    std::map<std::string, std::size_t> outcomes;
    for (const auto& r : doc.at("runs")) {
        const std::string name = r.at("name").get<std::string>();
        INFO(name);
        const auto it = modules.find(r.at("module").get<std::string>());
        REQUIRE(it != modules.end());
        const auto outcome = vm::run(it->second, hex_field(r.at("input")), provider(),
                                     hash_by_name(r.at("hash").get<std::string>()));
        REQUIRE(outcome);
        const std::string expected = r.at("outcome").get<std::string>();
        CHECK(std::string(outcome->trap ? vm::name(*outcome->trap) : "ok") == expected);
        CHECK(to_hex(outcome->output) == r.at("output").get<std::string>());
        CHECK(outcome->fuel_used == r.at("fuel").get<std::uint64_t>());
        if (r.contains("reason")) {
            CHECK(to_hex(outcome->abort_reason) == r.at("reason").get<std::string>());
        } else {
            CHECK(outcome->abort_reason.empty());
        }
        ++outcomes[expected];
    }
    // Every way of running gives every run of vm-v1.json and bo-v1.json the
    // recorded outcome: threaded and switch dispatch, fused and plain code.
    vm::Arena arena;
    for (const Recorded& r : corpus().runs) {
        INFO(r.name);
        for (const Way& way : ways) {
            INFO(way.name);
            const vm::Outcome outcome =
                run_way(*r.module, way, r.input, hash_by_name(r.hash), vm::fuel_limit, arena);
            CHECK(describe(outcome) == describe(expected_at(r, vm::fuel_limit)));
        }
    }
    // The vectors reach every outcome.
    for (const char* expected :
         {"ok", "unreachable", "divide by zero", "integer overflow", "out of bounds",
          "indirect call out of range", "indirect call to null", "indirect call type mismatch",
          "out of fuel", "call depth exceeded", "stack budget exceeded", "output written twice",
          "output too large", "aborted"}) {
        INFO(expected);
        CHECK(outcomes[expected] > 0);
    }
}

TEST_CASE("vm: with less fuel, a run does all it did until an instruction costs more than is "
          "left",
          "[vm][vectors]") {
    // Spec section 14.3: an instruction that costs more than the fuel left
    // traps, all the fuel used; until then a run with less fuel does exactly
    // what the run with all of it did. The interpreter charges each run of
    // straight-line instructions at once (and steps through a run it cannot
    // pay for), so these limits run out at instructions anywhere in a run:
    // every limit for the small vm-v1 runs and the first instructions of one
    // run of each Bo contract, and for every run the last limits and a
    // spread of others. CEXCHAIN_VM_SWEEP=all tries every limit of every run
    // instead, in all four ways (about ten minutes in a release build).
    const char* sweep = std::getenv("CEXCHAIN_VM_SWEEP");
    const bool all = sweep != nullptr && std::string(sweep) == "all";
    Choices choices{0x5EED'F0E1};
    std::set<std::string> swept;
    vm::Arena arena;
    std::size_t limits_tried = 0;
    std::size_t differ = 0;
    for (const Recorded& r : corpus().runs) {
        if (r.fuel >= vm::fuel_limit) {
            continue; // the runs that use it all, checked above
        }
        std::set<std::uint64_t> tried;
        if (all || r.fuel <= 300) {
            for (std::uint64_t l = 0; l <= r.fuel + 1; ++l) {
                tried.insert(l);
            }
        } else {
            if (r.module_name.starts_with("bo ") && swept.insert(r.module_name).second) {
                for (std::uint64_t l = 0; l <= 400; ++l) {
                    tried.insert(l);
                }
            }
            for (const std::uint64_t l :
                 {std::uint64_t{0}, std::uint64_t{1}, r.fuel - 1, r.fuel, r.fuel + 1}) {
                tried.insert(l);
            }
            for (int i = 0; i < 3; ++i) {
                tried.insert(choices.below(r.fuel));
            }
        }
        const crypto::HashAlg hash = hash_by_name(r.hash);
        for (const std::uint64_t limit : tried) {
            const vm::Outcome want = expected_at(r, limit);
            for (const Way& way : ways) {
                // The plain code charges each instruction alone: its own
                // limits are few, unless all are tried.
                if (way.plain && !all && limit + 1 != r.fuel && limit != r.fuel) {
                    continue;
                }
                const vm::Outcome got = run_way(*r.module, way, r.input, hash, limit, arena);
                if (!same(got, want) && ++differ <= 20) {
                    INFO(r.name << ", " << way.name << ", fuel " << limit);
                    CHECK(describe(got) == describe(want));
                }
            }
        }
        limits_tried += tried.size();
    }
    CHECK(differ == 0);
    CHECK(limits_tried > 10'000);
}

// Hidden: CTest vm_fuel_reference_runs writes the runs below, at limits
// across each run, to CEXCHAIN_VM_FUEL_REFERENCE, and vm_fuel_reference has
// the Python reference interpreter (tools/testvectors/wasm_ref.py) run each
// with that fuel and get the same outcome, output, fuel, and reason.
TEST_CASE("vm: runs with less fuel, for the reference interpreter", "[.fuel-reference]") {
    const char* path = std::getenv("CEXCHAIN_VM_FUEL_REFERENCE");
    REQUIRE(path != nullptr);
    Choices choices{0xF0E1'5EED};
    nlohmann::json modules = nlohmann::json::object();
    nlohmann::json runs = nlohmann::json::array();
    std::map<std::string, int> per_module;
    vm::Arena arena;
    for (const Recorded& r : corpus().runs) {
        // The reference needs no SM3 here; three runs of each Bo contract.
        if (r.fuel >= vm::fuel_limit || r.hash != "sha256" ||
            (r.module_name.starts_with("bo ") && ++per_module[r.module_name] > 3)) {
            continue;
        }
        std::set<std::uint64_t> tried{r.fuel - 1, r.fuel};
        const int spread = r.module_name.starts_with("bo ") ? 6 : 1;
        for (int i = 0; i < spread; ++i) {
            tried.insert(choices.below(r.fuel));
        }
        modules[r.module_name] = to_hex(corpus().wasm.at(r.module_name));
        for (const std::uint64_t limit : tried) {
            const vm::Outcome got =
                run_way(*r.module, ways[0], r.input, crypto::HashAlg::sha256, limit, arena);
            CHECK(describe(got) == describe(expected_at(r, limit)));
            runs.push_back({{"module", r.module_name},
                            {"input", to_hex(r.input)},
                            {"outcome", got.trap ? vm::name(*got.trap) : "ok"},
                            {"output", to_hex(got.output)},
                            {"fuel", got.fuel_used},
                            {"reason", to_hex(got.abort_reason)},
                            {"limit", limit}});
        }
    }
    const nlohmann::json doc = {{"format", 1}, {"modules", modules}, {"runs", runs}};
    std::ofstream out(path);
    out << doc.dump() << "\n";
    REQUIRE(out.good());
    CHECK(runs.size() > 1'500);
}

TEST_CASE("vm: a reused arena gives every run the outcome of a fresh one", "[vm][vectors]") {
    // Each run leaves its arena clean, whatever it wrote and however it
    // ended, so runs in any order on one arena equal runs on fresh ones.
    const auto doc = load_vectors("vm-v1.json");
    std::map<std::string, vm::Module> modules;
    for (const auto& m : doc.at("modules")) {
        if (m.at("valid").get<bool>()) {
            modules.emplace(m.at("name").get<std::string>(), *vm::load(hex_field(m.at("wasm"))));
        }
    }
    struct Run {
        const vm::Module* module;
        Bytes input;
        crypto::HashAlg hash;
    };
    std::vector<Run> runs;
    for (const auto& r : doc.at("runs")) {
        runs.push_back({&modules.at(r.at("module").get<std::string>()), hex_field(r.at("input")),
                        hash_by_name(r.at("hash").get<std::string>())});
    }
    const auto same = [](const vm::Outcome& a, const vm::Outcome& b) {
        return a.trap == b.trap && a.output == b.output && a.fuel_used == b.fuel_used &&
               a.abort_reason == b.abort_reason;
    };
    vm::Arena forward;
    vm::Arena backward;
    std::vector<vm::Outcome> fresh;
    for (const Run& r : runs) {
        vm::Arena arena;
        fresh.push_back(*vm::run(*r.module, r.input, provider(), r.hash, arena));
    }
    for (std::size_t i = 0; i < runs.size(); ++i) {
        INFO(i);
        const Run& r = runs[i];
        const auto outcome = vm::run(*r.module, r.input, provider(), r.hash, forward);
        REQUIRE(outcome);
        CHECK(same(*outcome, fresh[i]));
        REQUIRE(forward.clean());
        // Twice in a row on the same arena, too.
        CHECK(same(*vm::run(*r.module, r.input, provider(), r.hash, forward), fresh[i]));
    }
    for (std::size_t i = runs.size(); i-- > 0;) {
        INFO(i);
        const Run& r = runs[i];
        CHECK(same(*vm::run(*r.module, r.input, provider(), r.hash, backward), fresh[i]));
    }
    CHECK(backward.clean());
    // A moved-from arena is empty, and runs again.
    vm::Arena moved = std::move(forward);
    CHECK(same(*vm::run(*runs[0].module, runs[0].input, provider(), runs[0].hash, forward),
               fresh[0]));
    CHECK(moved.clean());
    CHECK(forward.clean());
}

TEST_CASE("vm: the smallest module runs and uses no fuel but its end", "[vm]") {
    const auto module = vm::load(empty_module());
    REQUIRE(module);
    CHECK(Bytes(module->bytes().begin(), module->bytes().end()) == empty_module());
    const auto outcome = vm::run(*module, {}, provider(), crypto::HashAlg::sha256);
    REQUIRE(outcome);
    CHECK(outcome->ok());
    CHECK(outcome->output.empty());
    CHECK(outcome->fuel_used == 0);
}

namespace {

void put_uleb(Bytes& out, std::uint64_t v) {
    do {
        std::uint8_t b = v & 0x7FU;
        v >>= 7U;
        if (v != 0) {
            b |= 0x80U;
        }
        out.push_back(b);
    } while (v != 0);
}

/// A module whose cexchain_call has `body` (instructions, without the final
/// end) and `locals` i32 locals, with one page of memory.
Bytes module_with(const Bytes& body, std::uint32_t locals = 0) {
    Bytes code;
    if (locals == 0) {
        code.push_back(0x00);
    } else {
        code.push_back(0x01);
        put_uleb(code, locals);
        code.push_back(0x7F);
    }
    code.insert(code.end(), body.begin(), body.end());
    code.push_back(0x0B);
    Bytes wasm = cexchain::test::hex("0061736d01000000"                 // header
                                     "010401600000"                     // type 0: [] -> []
                                     "03020100"                         // function 0: type 0
                                     "0503010001"                       // memory: 1 page
                                     "071a02"                           // two exports:
                                     "066d656d6f72790200"               //   "memory"
                                     "0d636578636861696e5f63616c6c0000" //   "cexchain_call"
                                     "0a");                             // code section
    Bytes section;
    section.push_back(0x01);
    put_uleb(section, code.size());
    section.insert(section.end(), code.begin(), code.end());
    put_uleb(wasm, section.size());
    wasm.insert(wasm.end(), section.begin(), section.end());
    return wasm;
}

Bytes repeat(std::initializer_list<std::uint8_t> instructions, std::size_t n) {
    Bytes out;
    for (std::size_t i = 0; i < n; ++i) {
        out.insert(out.end(), instructions);
    }
    return out;
}

/// Runs `wasm` in every way at limits around each of `edges` and at its end,
/// against what the run with all the fuel did.
void check_limits(const Bytes& wasm, std::uint64_t fuel, const std::vector<std::uint64_t>& edges) {
    const Translated m = translate(wasm);
    vm::Arena arena;
    Recorded full;
    full.module = &m;
    full.outcome = "ok";
    full.fuel = fuel;
    for (const Way& way : ways) {
        INFO(way.name);
        CHECK(describe(run_way(m, way, {}, crypto::HashAlg::sha256, vm::fuel_limit, arena)) ==
              describe(expected_at(full, vm::fuel_limit)));
        std::set<std::uint64_t> limits{0, 1, fuel - 1, fuel, fuel + 1};
        for (const std::uint64_t edge : edges) {
            for (std::uint64_t l = edge - 3; l <= edge + 3; ++l) {
                limits.insert(l);
            }
        }
        for (const std::uint64_t limit : limits) {
            INFO("fuel " << limit);
            CHECK(describe(run_way(m, way, {}, crypto::HashAlg::sha256, limit, arena)) ==
                  describe(expected_at(full, limit)));
        }
    }
}

} // namespace

TEST_CASE("vm: long code keeps its fuel exact, and loads in linear time", "[vm]") {
    SECTION("a straight-line run of more fuel than one charge holds") {
        // 40,000 pairs: 80,000 fuel in one run, charged in two parts.
        const Bytes wasm = module_with(repeat({0x41, 0x00, 0x1A}, 40'000)); // i32.const 0; drop
        check_limits(wasm, 80'000, {65'535, 65'536});
    }
    SECTION("more block markers than an instruction carries") {
        // 3,000 empty blocks, then 3,000 nested ones around a nop.
        Bytes body = repeat({0x02, 0x40, 0x0B}, 3'000); // block end
        const Bytes open = repeat({0x02, 0x40}, 1'000); // block
        body.insert(body.end(), open.begin(), open.end());
        body.push_back(0x01);                      // nop
        const Bytes close = repeat({0x0B}, 1'000); // end
        body.insert(body.end(), close.begin(), close.end());
        check_limits(module_with(body), 4'001, {1'024, 2'048, 3'000, 3'072, 4'000});
    }
    SECTION("a long chain of i32.eqz before a branch") {
        // i32.const 0, 50,000 i32.eqz (an even count: 0), if, end.
        Bytes body{0x41, 0x00};
        const Bytes chain = repeat({0x45}, 50'000);
        body.insert(body.end(), chain.begin(), chain.end());
        body.insert(body.end(), {0x04, 0x40, 0x00, 0x0B}); // if; unreachable; end
        check_limits(module_with(body), 50'002, {50'000, 50'001});
    }
}

TEST_CASE("vm: refuses what is not a module", "[vm]") {
    CHECK(vm::load({}).error().code == Errc::malformed);
    Bytes wasm = empty_module();
    wasm[4] = 2; // version
    CHECK(vm::load(wasm).error().code == Errc::malformed);
    wasm = empty_module();
    wasm.push_back(0x00); // a section id with no size
    CHECK(vm::load(wasm).error().code == Errc::malformed);
    wasm = empty_module();
    wasm.pop_back(); // the body's end
    CHECK_FALSE(vm::load(wasm));
    Bytes big(vm::max_module_size + 1, 0);
    CHECK(vm::load(big).error().code == Errc::unsupported);
}

TEST_CASE("vm: needs a 32-byte ledger hash", "[vm]") {
    const auto module = vm::load(empty_module());
    REQUIRE(module);
    CHECK(vm::run(*module, {}, provider(), crypto::HashAlg::sha384).error().code ==
          Errc::unsupported);
    CHECK(vm::run(*module, {}, provider(), crypto::HashAlg::sm3));
}

TEST_CASE("vm: trap names follow the spec", "[vm]") {
    CHECK(vm::name(vm::Trap::unreachable) == "unreachable");
    CHECK(vm::name(vm::Trap::out_of_fuel) == "out of fuel");
    CHECK(vm::name(vm::Trap::indirect_call_type_mismatch) == "indirect call type mismatch");
    CHECK(vm::name(vm::Trap::aborted) == "aborted");
}
