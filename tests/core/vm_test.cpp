// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/core/crypto.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace crypto = cexchain::crypto;
namespace vm = cexchain::vm;
using cexchain::Bytes;
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
