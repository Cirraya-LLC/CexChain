// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Contract modules come from anyone who can deploy one (spec section 14).
// Loading must never crash; a module that loads must run without crashing,
// within its fuel, and the same way twice.

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

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    const std::span<const std::uint8_t> wasm(data, size);
    const auto module = vm::load(wasm);
    if (!module) {
        return 0;
    }
    const std::span<const std::uint8_t> input = wasm.first(std::min<std::size_t>(size, 64));
    const auto first =
        vm::detail::run(*module, input, provider, cexchain::crypto::HashAlg::sha256, fuzz_fuel);
    require(first.has_value());
    require(first->fuel_used <= fuzz_fuel);
    require(first->ok() || first->output.empty());
    require(first->abort_reason.size() <= vm::max_abort_reason);
    const auto second =
        vm::detail::run(*module, input, provider, cexchain::crypto::HashAlg::sha256, fuzz_fuel);
    require(second.has_value());
    require(second->trap == first->trap && second->output == first->output &&
            second->fuel_used == first->fuel_used && second->abort_reason == first->abort_reason);
    return 0;
}
