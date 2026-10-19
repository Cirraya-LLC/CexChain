// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Contract modules come from anyone who can deploy one (spec section 14).
// Loading must never crash; a module that loads must run without crashing,
// within its fuel, and the same way every way it can run: with threaded and
// switch dispatch, as fused code charged per run and as plain code charged
// per instruction, on a fresh arena and on one that every earlier input ran
// in (which each run must leave clean). With less fuel (a limit chosen from
// the input), a run must do what it did until an instruction costs more than
// is left (spec section 14.3).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "vm/internal.hpp"

namespace vm = cexchain::vm;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

// Less than the protocol's limit, so that loops do not slow the fuzzer down;
// the fuel accounting is the same.
constexpr std::uint64_t fuzz_fuel = 200'000;

bool same(const vm::Outcome& a, const vm::Outcome& b) {
    return a.trap == b.trap && a.output == b.output && a.fuel_used == b.fuel_used &&
           a.abort_reason == b.abort_reason;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    const std::span<const std::uint8_t> wasm(data, size);
    const auto module = vm::load(wasm);
    if (!module) {
        return 0;
    }
    const auto plain =
        vm::detail::load(wasm, vm::detail::Translation{.fuse = false, .runs = false});
    require(plain.has_value());
    const std::span<const std::uint8_t> input = wasm.first(std::min<std::size_t>(size, 64));
    constexpr auto sha256 = cexchain::crypto::HashAlg::sha256;
    using vm::detail::Dispatch;
    static vm::Arena reused;
    vm::Arena fresh;
    const auto first =
        vm::detail::run(*module, input, provider, sha256, fuzz_fuel, fresh, Dispatch::threaded);
    require(first.has_value());
    require(first->fuel_used <= fuzz_fuel);
    require(first->ok() || first->output.empty());
    require(first->abort_reason.size() <= vm::max_abort_reason);
    const auto second =
        vm::detail::run(*module, input, provider, sha256, fuzz_fuel, reused, Dispatch::table);
    require(second.has_value());
    require(reused.clean());
    require(same(*second, *first));
    const auto third =
        vm::detail::run(*plain, input, provider, sha256, fuzz_fuel, fresh, Dispatch::table);
    require(third.has_value());
    require(fresh.clean());
    require(same(*third, *first));

    // A limit up to the fuel the run used (one more if it did not run out).
    std::uint64_t h = 0xCBF2'9CE4'8422'2325ULL;
    for (const std::uint8_t b : wasm) {
        h = (h ^ b) * 0x100'0000'01B3ULL;
    }
    const bool ran_out = first->trap == vm::Trap::out_of_fuel;
    const std::uint64_t limit = h % (first->fuel_used + (ran_out ? 1 : 2));
    vm::Outcome want;
    if (limit < first->fuel_used) {
        want.trap = vm::Trap::out_of_fuel;
        want.fuel_used = limit;
    } else {
        want = *first;
    }
    const auto fused =
        vm::detail::run(*module, input, provider, sha256, limit, reused, Dispatch::threaded);
    require(fused.has_value() && same(*fused, want));
    const auto stepped =
        vm::detail::run(*plain, input, provider, sha256, limit, fresh, Dispatch::threaded);
    require(stepped.has_value() && same(*stepped, want));
    require(reused.clean() && fresh.clean());
    return 0;
}
