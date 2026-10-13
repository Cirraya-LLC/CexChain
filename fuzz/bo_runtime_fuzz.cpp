// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The Bo runtime reads every call's input inside the contract, as WebAssembly
// (bo/src/runtime_cbor.cpp): a Bo contract trusts nothing it has not read
// itself. This drives that reader on random bytes through the interpreter,
// in a harness module that copies what it accepts back out item by item
// (tests/bo/runtime_harness.hpp, cbor_copy_module). The reader must accept
// exactly what core's decoder accepts, and give it back unchanged; anything
// else must abort the call with "bo:input".
//
// The emitter that writes the harness is C++26 with reflection and contracts
// (GCC only), and libFuzzer is Clang's. So the module comes from the golden
// tests/bo/golden/runtime/cbor-copy.wasm, which the GCC tests keep equal to
// the emitter's output byte for byte, embedded here at configure time.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace vm = cexchain::vm;

namespace {

constexpr std::uint8_t harness[] = {
#include "cbor-copy.wasm.inc"
};

/// bo::runtime::layout::input_max: the largest input the runtime reads.
constexpr std::size_t input_max = 0x2'8000;

void require(const bool condition) {
    if (!condition) {
        std::abort();
    }
}

const vm::Module& module() {
    static const vm::Module loaded = [] {
        auto m = vm::load(std::span<const std::uint8_t>(harness, sizeof harness));
        require(m.has_value());
        return *m;
    }();
    return loaded;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    const std::span<const std::uint8_t> input(data, size);
    const auto outcome = vm::run(module(), input, provider, cexchain::crypto::HashAlg::sha256);
    require(outcome.has_value());
    require(outcome->fuel_used <= vm::fuel_limit);
    const bool accepted = size <= input_max && cexchain::cbor::decode(input).has_value();
    if (accepted) {
        require(outcome->ok());
        require(outcome->output.size() == size &&
                std::equal(outcome->output.begin(), outcome->output.end(), input.begin()));
    } else {
        constexpr std::string_view reason = "bo:input";
        require(outcome->trap == vm::Trap::aborted);
        require(std::string_view(reinterpret_cast<const char*>(outcome->abort_reason.data()),
                                 outcome->abort_reason.size()) == reason);
    }
    return 0;
}
