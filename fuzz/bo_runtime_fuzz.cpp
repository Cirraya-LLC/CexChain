// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The Bo runtime reads every call's input inside the contract, as WebAssembly
// (bo/src/runtime_cbor.cpp): a Bo contract trusts nothing it has not read
// itself. This drives that reader on random bytes through the interpreter,
// in a harness module that copies what it accepts back out item by item
// (tests/bo/runtime_harness.hpp, cbor_copy_module). The reader must accept
// what core's decoder accepts, and give it back unchanged; anything else must
// abort the call with "bo:input", except that from codegen 2 on the reader
// does not check texts' UTF-8 (the ledger's input holds valid UTF-8 only), so
// an input core refuses for that alone it may accept. And reading alone
// (read_only_module) must cost no more than the bound the compiler counts
// for the input's items and keys (read_bound.hpp, milestone 18).
//
// The emitter that writes the harnesses is C++26 with reflection and
// contracts (GCC only), and libFuzzer is Clang's. So the modules come from
// the goldens tests/bo/golden/runtime/{cbor-copy,read-only}.wasm, which the
// GCC tests keep equal to the emitter's output byte for byte, embedded here
// at configure time.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <span>
#include <string_view>

#include <cexchain/bo/read_bound.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

namespace vm = cexchain::vm;

namespace {

constexpr std::uint8_t harness[] = {
#include "cbor-copy.wasm.inc"
};
constexpr std::uint8_t reader[] = {
#include "read-only.wasm.inc"
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

const vm::Module& reader_module() {
    static const vm::Module loaded = [] {
        auto m = vm::load(std::span<const std::uint8_t>(reader, sizeof reader));
        require(m.has_value());
        return *m;
    }();
    return loaded;
}

/// Counts a value's items and map keys as read_input reads them; false if a
/// key is longer than the bound allows for.
bool count_items(const cexchain::cbor::Value& v, std::uint64_t& items, std::uint64_t& keys) {
    ++items;
    if (const auto* a = v.as_array()) {
        return std::ranges::all_of(*a, [&](const auto& x) { return count_items(x, items, keys); });
    }
    if (const auto* m = v.as_map()) {
        for (const auto& e : *m) {
            ++keys;
            const auto key = cexchain::cbor::encode(e.key);
            if (!key || key->size() > cexchain::bo::runtime::max_key_size + 2 ||
                !count_items(e.key, items, keys) || !count_items(e.value, items, keys)) {
                return false;
            }
        }
        return true;
    }
    if (const auto* t = v.as_tagged()) {
        return count_items(t->item, items, keys);
    }
    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const cexchain::crypto::openssl::Provider provider;
    const std::span<const std::uint8_t> input(data, size);
    const auto outcome = vm::run(module(), input, provider, cexchain::crypto::HashAlg::sha256);
    require(outcome.has_value());
    require(outcome->fuel_used <= vm::fuel_limit);
    std::optional<cexchain::Result<cexchain::cbor::Value>> decoded;
    if (size <= input_max) {
        decoded = cexchain::cbor::decode(input);
    }
    const bool accepted = decoded && decoded->has_value();
    const bool utf8_only = decoded && !decoded->has_value() &&
                           decoded->error().detail.find("UTF-8") != std::string_view::npos;
    if (accepted || (utf8_only && outcome->ok())) {
        require(outcome->ok());
        require(outcome->output.size() == size &&
                std::equal(outcome->output.begin(), outcome->output.end(), input.begin()));
        if (accepted) {
            std::uint64_t items = 0;
            std::uint64_t keys = 0;
            if (count_items(**decoded, items, keys)) {
                const auto read =
                    vm::run(reader_module(), input, provider, cexchain::crypto::HashAlg::sha256);
                require(read.has_value() && read->ok());
                require(read->fuel_used <= cexchain::bo::runtime::read_input_fuel(items, keys));
            }
        }
    } else {
        constexpr std::string_view reason = "bo:input";
        require(outcome->trap == vm::Trap::aborted);
        require(std::string_view(reinterpret_cast<const char*>(outcome->abort_reason.data()),
                                 outcome->abort_reason.size()) == reason);
    }
    return 0;
}
