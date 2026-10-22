// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The Bo runtime: the emitter's modules load and match the validator's
// bookkeeping; each routine, run through a harness module, agrees with core
// (the CBOR decoder and encoder) and with exact arithmetic; the fuel each
// costs is a golden. A hidden case writes every run for the Python reference
// (CTest bo_reference: wasm_ref.py --check), which must give the same
// outcome, output, and fuel.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/runtime.hpp>
#include <cexchain/bo/wasm.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/cbor.hpp>
#include <cexchain/core/protocol/contracts.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

#include "bo/runtime_harness.hpp"
#include "vm/internal.hpp"

namespace {

namespace cbor = cexchain::cbor;
namespace vm = cexchain::vm;
namespace wasm = cexchain::bo::wasm;
namespace rt = cexchain::bo::runtime;
namespace h = cexchain::test::bo_runtime;
using cexchain::Bytes;
using cexchain::ByteView;
using h::MathOp;

__extension__ using int128 = __int128;
__extension__ using uint128 = unsigned __int128;

constexpr std::int64_t int64_min = std::numeric_limits<std::int64_t>::min();
constexpr std::int64_t int64_max = std::numeric_limits<std::int64_t>::max();
constexpr std::int64_t day_ms = 86'400'000;

const std::filesystem::path golden_dir = std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / "runtime";

bool updating_goldens() {
    const char* value = std::getenv("CEXCHAIN_UPDATE_GOLDENS");
    return value != nullptr && std::string_view(value) == "1";
}

Bytes read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void write_file(const std::filesystem::path& path, const ByteView bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

const cexchain::crypto::Provider& provider() {
    static const cexchain::crypto::openssl::Provider instance;
    return instance;
}

/// A harness module, built once by the emitter.
struct Built {
    Bytes bytes;
    vm::Module module;
};

const Built& harness(const std::string_view name) {
    static std::map<std::string, Built, std::less<>> built;
    if (const auto it = built.find(name); it != built.end()) {
        return it->second;
    }
    for (const h::Harness& entry : h::harnesses) {
        if (entry.name == name) {
            Bytes bytes = entry.build();
            auto module = vm::load(bytes);
            REQUIRE(module.has_value());
            return built.emplace(std::string(name), Built{std::move(bytes), *module}).first->second;
        }
    }
    FAIL("no harness " << name);
    throw;
}

struct Run {
    std::string outcome; ///< "ok" or the trap's name
    Bytes output;
    std::uint64_t fuel = 0;
    Bytes reason;

    [[nodiscard]] bool ok() const { return outcome == "ok"; }
    [[nodiscard]] std::string describe() const {
        return std::format("{} (fuel {}, reason \"{}\")", outcome, fuel,
                           std::string(reason.begin(), reason.end()));
    }
    [[nodiscard]] bool aborted(const std::string_view why) const {
        return outcome == "aborted" &&
               std::string_view(reinterpret_cast<const char*>(reason.data()), reason.size()) == why;
    }
};

Run run(const std::string_view module, const ByteView input) {
    auto outcome =
        vm::run(harness(module).module, input, provider(), cexchain::crypto::HashAlg::sha256);
    REQUIRE(outcome.has_value());
    Run r;
    r.outcome = outcome->trap ? std::string(vm::name(*outcome->trap)) : "ok";
    r.output = outcome->output;
    r.fuel = outcome->fuel_used;
    r.reason = outcome->abort_reason;
    return r;
}

/// splitmix64: the same numbers on every platform.
class Random {
public:
    explicit Random(const std::uint64_t seed) : state_(seed) {}
    std::uint64_t next() {
        std::uint64_t z = (state_ += 0x9E37'79B9'7F4A'7C15ULL);
        z = (z ^ (z >> 30U)) * 0xBF58'476D'1CE4'E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D0'49BB'1331'11EBULL;
        return z ^ (z >> 31U);
    }
    std::uint64_t below(const std::uint64_t n) { return n == 0 ? 0 : next() % n; }
    bool chance(const std::uint64_t percent) { return below(100) < percent; }
    std::uint8_t byte() { return static_cast<std::uint8_t>(next()); }

private:
    std::uint64_t state_;
};

/// Unsigned values near every head width's boundaries, or random widths.
std::uint64_t interesting(Random& r) {
    static constexpr std::array<std::uint64_t, 16> edges{0,
                                                         1,
                                                         23,
                                                         24,
                                                         25,
                                                         255,
                                                         256,
                                                         65'535,
                                                         65'536,
                                                         0xFFFF'FFFF,
                                                         0x1'0000'0000,
                                                         0x7FFF'FFFF'FFFF'FFFF,
                                                         0x8000'0000'0000'0000,
                                                         0xFFFF'FFFF'FFFF'FFFF,
                                                         1'000'000,
                                                         86'400'000};
    switch (r.below(6)) {
    case 0:
        return edges.at(r.below(edges.size()));
    case 1:
        return r.below(24);
    case 2:
        return r.below(0x100);
    case 3:
        return r.below(0x1'0000);
    case 4:
        return r.below(0x1'0000'0000);
    default:
        return r.next() >> r.below(64);
    }
}

void append_utf8(std::string& out, const std::uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6U));
        out += static_cast<char>(0x80 | (cp & 0x3FU));
    } else if (cp < 0x1'0000) {
        out += static_cast<char>(0xE0 | (cp >> 12U));
        out += static_cast<char>(0x80 | ((cp >> 6U) & 0x3FU));
        out += static_cast<char>(0x80 | (cp & 0x3FU));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18U));
        out += static_cast<char>(0x80 | ((cp >> 12U) & 0x3FU));
        out += static_cast<char>(0x80 | ((cp >> 6U) & 0x3FU));
        out += static_cast<char>(0x80 | (cp & 0x3FU));
    }
}

std::size_t random_length(Random& r) {
    switch (r.below(8)) {
    case 0:
        return 0;
    case 1:
        return 23 + r.below(3);
    case 2:
        return 250 + r.below(10);
    default:
        return r.below(12);
    }
}

std::string random_text(Random& r) {
    std::string out;
    const std::size_t n = random_length(r);
    for (std::size_t i = 0; i < n; ++i) {
        switch (r.below(8)) {
        case 0:
            append_utf8(out, static_cast<std::uint32_t>(0x80 + r.below(0x780)));
            break;
        case 1: {
            auto cp = static_cast<std::uint32_t>(0x800 + r.below(0xF800));
            append_utf8(out, cp >= 0xD800 && cp < 0xE000 ? cp - 0x800 : cp);
            break;
        }
        case 2:
            append_utf8(out, static_cast<std::uint32_t>(0x1'0000 + r.below(0x10'0000)));
            break;
        default:
            append_utf8(out, static_cast<std::uint32_t>(0x20 + r.below(0x5F)));
        }
    }
    return out;
}

Bytes random_bytes(Random& r, const std::size_t n) {
    Bytes out(n);
    for (auto& b : out) {
        b = r.byte();
    }
    return out;
}

cbor::Value random_value(Random& r, const int depth) {
    const std::uint64_t kind = r.below(depth >= 4 ? 7 : 10);
    switch (kind) {
    case 0:
        return cbor::Value::unsigned_integer(interesting(r));
    case 1:
        return cbor::Value::negative(interesting(r));
    case 2:
        return cbor::Value::bytes(random_bytes(r, random_length(r)));
    case 3:
        return cbor::Value::text(random_text(r));
    case 4: {
        const std::uint64_t which = r.below(3);
        return which == 2 ? cbor::Value::null() : cbor::Value::boolean(which == 1);
    }
    case 5:
        return cbor::Value::integer(static_cast<std::int64_t>(r.next()) >>
                                    static_cast<int>(r.below(64)));
    case 6: {
        std::uint64_t tag = interesting(r);
        if (tag == 2 || tag == 3) {
            tag = 4;
        }
        return cbor::Value::tagged(tag, random_value(r, depth + 1));
    }
    case 7:
    case 8: {
        const std::size_t n = r.chance(10) ? 20 + r.below(10) : r.below(5);
        if (kind == 7) {
            cbor::Array items;
            for (std::size_t i = 0; i < n; ++i) {
                items.push_back(random_value(r, depth + 1));
            }
            return cbor::Value::array(std::move(items));
        }
        cbor::Map entries;
        std::set<Bytes> keys;
        for (std::size_t i = 0; i < n; ++i) {
            cbor::Value key =
                r.chance(50) ? cbor::Value::text(random_text(r)) : random_value(r, depth + 2);
            auto encoded = cbor::encode(key);
            REQUIRE(encoded.has_value());
            if (keys.insert(*encoded).second) {
                entries.push_back({std::move(key), random_value(r, depth + 1)});
            }
        }
        return cbor::Value::map(std::move(entries));
    }
    default:
        return cbor::Value::array({random_value(r, depth + 1), random_value(r, depth + 1)});
    }
}

/// A value as core encodes it (canonical) and as it decodes again (its maps
/// in canonical order).
std::pair<Bytes, cbor::Value> canonical(const cbor::Value& value) {
    auto encoded = cbor::encode(value);
    REQUIRE(encoded.has_value());
    auto decoded = cbor::decode(*encoded);
    REQUIRE(decoded.has_value());
    return {std::move(*encoded), std::move(*decoded)};
}

Bytes mutate(Bytes b, Random& r) {
    static constexpr std::array<std::uint8_t, 22> heads{
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1F, 0x3F, 0x5F, 0x7F, 0x9F, 0xBF,
        0xDF, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFF, 0xC2, 0xC3, 0xE0, 0xF3};
    switch (r.below(6)) {
    case 0:
        if (!b.empty()) {
            b[r.below(b.size())] = r.byte();
        }
        break;
    case 1:
        b.resize(r.below(b.size() + 1));
        break;
    case 2:
        b.push_back(r.byte());
        break;
    case 3:
        b.insert(b.begin() + static_cast<std::ptrdiff_t>(r.below(b.size() + 1)), r.byte());
        break;
    case 4:
        if (!b.empty()) {
            b[r.below(b.size())] ^= static_cast<std::uint8_t>(1U << r.below(8));
        }
        break;
    default:
        if (!b.empty()) {
            b[r.below(b.size())] = heads.at(r.below(heads.size()));
        }
    }
    return b;
}

Bytes hex(const std::string_view text) {
    auto bytes = cexchain::from_hex(text);
    REQUIRE(bytes.has_value());
    return *bytes;
}

Bytes repeat(const std::string_view hex_text, const std::size_t n, const std::string_view tail) {
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        out += hex_text;
    }
    return hex(out + std::string(tail));
}

/// An array of `count` zeros, its head in its shortest form.
Bytes flat_array(const std::uint32_t count) {
    Bytes out;
    if (count < 24) {
        out.push_back(static_cast<std::uint8_t>(0x80 + count));
    } else if (count < 0x100) {
        out = {0x98, static_cast<std::uint8_t>(count)};
    } else if (count < 0x1'0000) {
        out = {0x99, static_cast<std::uint8_t>(count >> 8U), static_cast<std::uint8_t>(count)};
    } else {
        out = {0x9A, static_cast<std::uint8_t>(count >> 24U),
               static_cast<std::uint8_t>(count >> 16U), static_cast<std::uint8_t>(count >> 8U),
               static_cast<std::uint8_t>(count)};
    }
    out.resize(out.size() + count, 0x00);
    return out;
}

// ---------------------------------------------------------------------------
// The cases, the same on every run.
// ---------------------------------------------------------------------------

struct Case {
    std::string module;
    Bytes input;
    /// For wasm_ref.py --check: "cbor-copy", "math", or none.
    std::string oracle;
    /// For the writer: the bytes it must write.
    Bytes expected;
};

/// Inputs on the edges of what core's decoder accepts.
std::vector<Bytes> edge_inputs() {
    std::vector<Bytes> out;
    for (const std::string_view text : {"",
                                        "00",
                                        "17",
                                        "1817",
                                        "1818",
                                        "190017",
                                        "1900ff",
                                        "190100",
                                        "1a0000ffff",
                                        "1a00010000",
                                        "1b00000000ffffffff",
                                        "1b0000000100000000",
                                        "1bffffffffffffffff",
                                        "3bffffffffffffffff",
                                        "3817",
                                        "3818",
                                        "1c",
                                        "1d",
                                        "1e",
                                        "1f",
                                        "3f",
                                        "5f",
                                        "7f",
                                        "9f",
                                        "bf",
                                        "df",
                                        "ff",
                                        "f4",
                                        "f5",
                                        "f6",
                                        "f7",
                                        "f0",
                                        "f3",
                                        "f8",
                                        "f818",
                                        "f820",
                                        "f9",
                                        "f90000",
                                        "fa00000000",
                                        "fb0000000000000000",
                                        "fc",
                                        "fd",
                                        "fe",
                                        "c0",
                                        "c000",
                                        "c100",
                                        "c200",
                                        "c300",
                                        "c400",
                                        "d81800",
                                        "d80400",
                                        "d9ffff00",
                                        "dbffffffffffffffff00",
                                        "40",
                                        "4100",
                                        "41",
                                        "5800",
                                        "5801",
                                        "60",
                                        "6161",
                                        "62c3a9",
                                        "61ff",
                                        "62c0af",
                                        "63eda080",
                                        "63ed9fbf",
                                        "63ee8080",
                                        "64f4908080",
                                        "64f48fbfbf",
                                        "63e0a080",
                                        "63e08080",
                                        "64f0908080",
                                        "64f0808080",
                                        "62c280",
                                        "6180",
                                        "61c2",
                                        "62c2",
                                        "80",
                                        "8100",
                                        "81",
                                        "820000",
                                        "9800",
                                        "9801",
                                        "9a0000000100",
                                        "9bffffffffffffffff",
                                        "a0",
                                        "a10000",
                                        "a20000",
                                        "a2000001",
                                        "a200000100",
                                        "a201000000",
                                        "a200000000",
                                        "a2616100616200",
                                        "a2616200616100",
                                        "a2181800616100",
                                        "a2616100181800",
                                        "a2410000400000",
                                        "a2400000410000",
                                        "a1",
                                        "a100",
                                        "0000",
                                        "8000",
                                        "a0a0",
                                        "a1800000",
                                        "a18000a000",
                                        "a1a00080",
                                        "bf",
                                        "9fff",
                                        "5fff",
                                        "7fff",
                                        "a1f400",
                                        "a2f400f500",
                                        "a2f500f400",
                                        "a1c10000",
                                        "a1fb000000000000000000"}) {
        out.push_back(hex(text));
    }
    // Nesting: 32 levels are allowed, 33 are not; tags count as levels.
    out.push_back(repeat("81", 31, "80"));
    out.push_back(repeat("81", 32, "80"));
    out.push_back(repeat("c1", 31, "80"));
    out.push_back(repeat("c1", 32, "80"));
    out.push_back(repeat("c1", 32, "00"));
    out.push_back(repeat("c1", 33, "00"));
    out.push_back(repeat("a100", 31, "00"));
    out.push_back(repeat("a100", 32, "00"));
    out.push_back(repeat("a100", 31, "a0"));
    out.push_back(repeat("a100", 32, "a0"));
    out.push_back(repeat("8281", 15, "8000"));
    return out;
}

std::vector<Case> reader_cases() {
    std::vector<Case> out;
    for (Bytes& input : edge_inputs()) {
        out.push_back({"cbor-copy", std::move(input), "cbor-copy", {}});
    }
    Random r(0xB0'0001);
    for (int i = 0; i < 200; ++i) {
        auto [bytes, value] = canonical(random_value(r, 0));
        out.push_back({"cbor-copy", bytes, "cbor-copy", {}});
        out.push_back({"cbor-copy", mutate(bytes, r), "cbor-copy", {}});
        out.push_back({"cbor-copy", mutate(mutate(bytes, r), r), "cbor-copy", {}});
    }
    return out;
}

/// The reader's limits, through the read-only module (copying 131,072
/// items back would take more than a call's fuel).
std::vector<Case> reader_limit_cases() {
    std::vector<Case> out;
    // 131,072 items in all are allowed, 131,073 are not.
    out.push_back({"read-only", flat_array(131'071), "cbor-read", {}});
    out.push_back({"read-only", flat_array(131'072), "cbor-read", {}});
    // The largest input that fits, and one byte more.
    for (const std::uint32_t total : {rt::layout::input_max, rt::layout::input_max + 1}) {
        const std::uint32_t n = total - 5;
        Bytes input{0x5A, static_cast<std::uint8_t>(n >> 24U), static_cast<std::uint8_t>(n >> 16U),
                    static_cast<std::uint8_t>(n >> 8U), static_cast<std::uint8_t>(n)};
        input.resize(total, 0x61);
        out.push_back({"read-only", std::move(input), "cbor-read", {}});
    }
    return out;
}

/// [container, key] for the lookup harness: keys present and absent.
std::vector<Case> lookup_cases() {
    std::vector<Case> out;
    Random r(0xB0'0002);
    for (int i = 0; i < 150; ++i) {
        cbor::Map entries;
        std::vector<cbor::Value> keys;
        std::set<Bytes> seen;
        const std::size_t n = r.below(12);
        for (std::size_t k = 0; k < n; ++k) {
            cbor::Value key = r.chance(60)   ? cbor::Value::text(random_text(r))
                              : r.chance(50) ? cbor::Value::unsigned_integer(interesting(r))
                                             : random_value(r, 3);
            const auto encoded = cbor::encode(key);
            REQUIRE(encoded.has_value());
            if (seen.insert(*encoded).second) {
                keys.push_back(key);
                entries.push_back({std::move(key), random_value(r, 2)});
            }
        }
        cbor::Value key = !keys.empty() && r.chance(60) ? keys.at(r.below(keys.size()))
                          : r.chance(50) ? cbor::Value::text(random_text(r))
                                         : cbor::Value::unsigned_integer(interesting(r));
        auto [bytes, value] =
            canonical(cbor::Value::array({cbor::Value::map(std::move(entries)), std::move(key)}));
        out.push_back({"cbor-lookup", std::move(bytes), "", {}});
    }
    for (int i = 0; i < 50; ++i) {
        cbor::Array items;
        const std::size_t n = r.below(20);
        for (std::size_t k = 0; k < n; ++k) {
            items.push_back(random_value(r, 2));
        }
        auto [bytes, value] = canonical(cbor::Value::array(
            {cbor::Value::array(std::move(items)), cbor::Value::unsigned_integer(r.below(n + 3))}));
        out.push_back({"cbor-lookup", std::move(bytes), "", {}});
    }
    // Not a map or an array.
    out.push_back({"cbor-lookup", hex("82616100"), "", {}});
    out.push_back({"cbor-lookup", hex("82c0a000"), "", {}});
    return out;
}

void put_u32(Bytes& out, const std::uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>(v >> (8U * i)));
    }
}

void put_u64(Bytes& out, const std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>(v >> (8U * i)));
    }
}

/// Commands for the writer harness that write `value`, choosing among the
/// routines at random.
void write_commands(Bytes& out, const cbor::Value& value, Random& r) {
    const auto head = [&](const std::uint8_t major, const std::uint64_t arg) {
        out.push_back(0);
        out.push_back(major);
        put_u64(out, arg);
    };
    if (r.chance(5)) {
        const auto encoded = cbor::encode(value);
        REQUIRE(encoded.has_value());
        out.push_back(7);
        put_u32(out, static_cast<std::uint32_t>(encoded->size()));
        out.insert(out.end(), encoded->begin(), encoded->end());
        return;
    }
    switch (value.type()) {
    case cbor::Type::unsigned_integer:
    case cbor::Type::negative_integer: {
        const auto as_int = value.as_int64();
        if (as_int && r.chance(70)) {
            out.push_back(1);
            put_u64(out, static_cast<std::uint64_t>(*as_int));
        } else if (value.type() == cbor::Type::unsigned_integer) {
            head(0, *value.as_uint64());
        } else {
            head(1, value.as_negative()->n);
        }
        return;
    }
    case cbor::Type::bytes:
    case cbor::Type::text: {
        const bool is_text = value.type() == cbor::Type::text;
        const ByteView content =
            is_text ? cexchain::as_bytes(*value.as_text()) : ByteView(*value.as_bytes());
        out.push_back(is_text ? 3 : 2);
        put_u32(out, static_cast<std::uint32_t>(content.size()));
        out.insert(out.end(), content.begin(), content.end());
        return;
    }
    case cbor::Type::boolean:
        out.push_back(4);
        out.push_back(*value.as_bool() ? 21 : 20);
        return;
    case cbor::Type::null:
        out.push_back(4);
        out.push_back(22);
        return;
    case cbor::Type::array:
    case cbor::Type::map:
    case cbor::Type::tag: {
        const std::uint8_t major = value.type() == cbor::Type::array ? 4
                                   : value.type() == cbor::Type::map ? 5
                                                                     : 6;
        const std::uint64_t count = value.type() == cbor::Type::array ? value.as_array()->size()
                                    : value.type() == cbor::Type::map ? value.as_map()->size()
                                                                      : value.as_tagged()->tag;
        const bool late = r.chance(40);
        if (late) {
            out.push_back(5);
        } else {
            head(major, count);
        }
        if (value.type() == cbor::Type::array) {
            for (const auto& item : *value.as_array()) {
                write_commands(out, item, r);
            }
        } else if (value.type() == cbor::Type::map) {
            for (const auto& entry : *value.as_map()) {
                write_commands(out, entry.key, r);
                write_commands(out, entry.value, r);
            }
        } else {
            write_commands(out, value.as_tagged()->item, r);
        }
        if (late) {
            out.push_back(6);
            out.push_back(major);
            put_u64(out, count);
        }
        return;
    }
    }
}

std::vector<Case> writer_cases() {
    std::vector<Case> out;
    Random r(0xB0'0003);
    for (int i = 0; i < 200; ++i) {
        auto [bytes, value] = canonical(random_value(r, 0));
        Bytes commands;
        write_commands(commands, value, r);
        out.push_back({"cbor-write", std::move(commands), "", std::move(bytes)});
    }
    // Every head width, for each major type the writer heads.
    for (const std::uint64_t arg : {0ULL, 23ULL, 24ULL, 255ULL, 256ULL, 65'535ULL, 65'536ULL,
                                    0xFFFF'FFFFULL, 0x1'0000'0000ULL, ~0ULL}) {
        for (const auto& value :
             {cbor::Value::unsigned_integer(arg), cbor::Value::negative(arg),
              cbor::Value::tagged(arg == 2 || arg == 3 ? 4 : arg, cbor::Value::null())}) {
            auto [bytes, canonical_value] = canonical(value);
            Bytes commands;
            write_commands(commands, canonical_value, r);
            out.push_back({"cbor-write", std::move(commands), "", std::move(bytes)});
        }
    }
    // A string of 65,536 bytes, and a container whose head grows to five
    // bytes at its close.
    {
        auto [bytes, value] = canonical(cbor::Value::bytes(Bytes(65'536, 0x5A)));
        Bytes commands;
        write_commands(commands, value, r);
        out.push_back({"cbor-write", std::move(commands), "", std::move(bytes)});
    }
    {
        cbor::Array items(70'000, cbor::Value::unsigned_integer(7));
        auto [bytes, value] = canonical(cbor::Value::array(std::move(items)));
        // The items as one raw command (each is one byte, 0x07).
        Bytes commands{5, 7};
        put_u32(commands, 70'000);
        commands.resize(commands.size() + 70'000, 0x07);
        commands.push_back(6);
        commands.push_back(4);
        put_u64(commands, 70'000);
        out.push_back({"cbor-write", std::move(commands), "", std::move(bytes)});
    }
    return out;
}

Bytes math_input(const MathOp op, const std::vector<std::int64_t>& args) {
    Bytes out{static_cast<std::uint8_t>(op)};
    for (const std::int64_t a : args) {
        put_u64(out, static_cast<std::uint64_t>(a));
    }
    return out;
}

Bytes text_input(const MathOp op, const ByteView a, const ByteView b) {
    Bytes out =
        math_input(op, {static_cast<std::int64_t>(a.size()), static_cast<std::int64_t>(b.size())});
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

std::int64_t random_int(Random& r) {
    switch (r.below(5)) {
    case 0:
        return static_cast<std::int64_t>(r.next());
    case 1:
        return static_cast<std::int64_t>(r.next()) >> r.below(64);
    case 2: {
        static constexpr std::array<std::int64_t, 10> edges{0,
                                                            1,
                                                            -1,
                                                            2,
                                                            int64_max,
                                                            int64_min,
                                                            int64_max - 1,
                                                            int64_min + 1,
                                                            3'037'000'499,
                                                            -3'037'000'500};
        return edges.at(r.below(edges.size()));
    }
    case 3:
        return static_cast<std::int64_t>(r.below(2'000'001)) - 1'000'000;
    default:
        return static_cast<std::int64_t>(r.next() >> 33U) * (r.chance(50) ? 1 : -1);
    }
}

/// Days from 1970-01-01 of a date in years -30,000 to 30,000.
std::int64_t random_day(Random& r) {
    return static_cast<std::int64_t>(r.below(2 * 10'957'500)) - 10'957'500;
}

/// A time, in ms, mostly within the years 1 to 9999.
std::int64_t random_time(Random& r) {
    constexpr std::int64_t first = -62'135'596'800'000;
    constexpr std::int64_t last = 253'402'300'799'999;
    switch (r.below(6)) {
    case 0:
        return r.chance(50) ? first + static_cast<std::int64_t>(r.below(3 * day_ms))
                            : last - static_cast<std::int64_t>(r.below(3 * day_ms));
    case 1:
        return random_int(r);
    default:
        return first + static_cast<std::int64_t>(r.below(static_cast<std::uint64_t>(last - first)));
    }
}

std::int64_t random_offset(Random& r) {
    switch (r.below(6)) {
    case 0:
        return r.chance(50) ? day_ms : -day_ms;
    case 1:
        return random_int(r);
    case 2:
        return 0;
    default:
        return (static_cast<std::int64_t>(r.below(57)) - 24) * 15 * 60'000; // -06:00 to +08:00
    }
}

std::vector<Case> math_cases() {
    std::vector<Case> out;
    Random r(0xB0'0004);
    const auto add = [&](const MathOp op, const std::vector<std::int64_t>& args) {
        out.push_back({"math", math_input(op, args), "math", {}});
    };
    add(MathOp::nop, {});
    for (int i = 0; i < 150; ++i) {
        add(MathOp::add, {random_int(r), random_int(r)});
        add(MathOp::sub, {random_int(r), random_int(r)});
        add(MathOp::mul, {random_int(r), random_int(r)});
        add(MathOp::neg, {random_int(r)});
    }
    for (int i = 0; i < 400; ++i) {
        const auto mode = static_cast<std::int64_t>(r.below(3));
        std::int64_t d = random_int(r);
        if (r.chance(20)) {
            d = static_cast<std::int64_t>(r.below(10)) - 5; // ties and zero
        }
        add(MathOp::muldiv, {random_int(r), random_int(r), d, mode});
    }
    // Ties, each mode, each sign.
    for (const std::int64_t a : {5, 15, 25, -5, -15, -25, 7, -7}) {
        for (const std::int64_t mode : {0, 1, 2}) {
            add(MathOp::muldiv, {a, 1, 10, mode});
            add(MathOp::muldiv, {a, 1, -10, mode});
        }
    }
    for (int i = 0; i < 150; ++i) {
        const std::uint64_t d = r.chance(50) ? r.next() | 1U : (r.next() >> r.below(63)) | 1U;
        const std::uint64_t hi = r.below(d);
        add(MathOp::udiv128, {static_cast<std::int64_t>(hi), static_cast<std::int64_t>(r.next()),
                              static_cast<std::int64_t>(d)});
    }
    for (int i = 0; i < 100; ++i) {
        // Within Python's calendar (years 1 to 9999) for the reference.
        const std::int64_t day = -719'162 + static_cast<std::int64_t>(r.below(3'652'059));
        add(MathOp::civil_from_days, {day});
        const auto ymd = std::chrono::year_month_day{std::chrono::sys_days{std::chrono::days{day}}};
        add(MathOp::days_from_civil,
            {static_cast<int>(ymd.year()), static_cast<unsigned>(ymd.month()),
             static_cast<unsigned>(ymd.day())});
        add(MathOp::days_in_month, {1 + static_cast<std::int64_t>(r.below(9999)),
                                    1 + static_cast<std::int64_t>(r.below(12))});
    }
    for (const std::int64_t y : {1900, 2000, 2024, 2025, 2100, 2400}) {
        add(MathOp::days_in_month, {y, 2});
    }
    for (int i = 0; i < 300; ++i) {
        const std::int64_t months = r.chance(80) ? static_cast<std::int64_t>(r.below(49)) - 24
                                    : r.chance(50)
                                        ? random_int(r)
                                        : static_cast<std::int64_t>(r.below(240'010)) - 120'005;
        add(MathOp::add_months, {random_time(r), months, random_offset(r)});
        add(MathOp::date_parts, {random_time(r), random_offset(r)});
        add(MathOp::date_from_parts,
            {static_cast<std::int64_t>(r.below(10'002)), static_cast<std::int64_t>(r.below(14)),
             static_cast<std::int64_t>(r.below(33)), random_offset(r)});
    }
    // Month ends clamp: 31 January 2027 plus a month, at +08:00, and back.
    constexpr std::int64_t hk = 8 * 3'600'000;
    constexpr std::int64_t jan31 = 1'801'929'600'000 - hk; // 2027-01-31 00:00 +08:00
    for (const std::int64_t months : {1, 2, 13, -1, -11, 12 * 9000}) {
        add(MathOp::add_months, {jan31 + 3'600'000, months, hk});
    }
    for (int i = 0; i < 150; ++i) {
        Bytes a = random_bytes(r, r.below(40));
        Bytes b = r.chance(50) ? a : random_bytes(r, r.below(40));
        if (r.chance(50) && !b.empty()) {
            b.back() = static_cast<std::uint8_t>(b.back() + (r.chance(50) ? 1 : 255));
        }
        if (r.chance(20)) {
            b.resize(r.below(b.size() + 1));
        }
        out.push_back({"math", text_input(MathOp::bytes_cmp, a, b), "math", {}});
        out.push_back({"math", text_input(MathOp::bytes_eq, a, b), "math", {}});
    }
    return out;
}

// ---------------------------------------------------------------------------
// What the math harness must give, from exact integers and std::chrono.
// ---------------------------------------------------------------------------

struct Expected {
    std::optional<std::string> reason;
    std::vector<std::int64_t> results;
};

std::int64_t arg(const ByteView input, const std::size_t i) {
    std::uint64_t v = 0;
    for (unsigned k = 0; k < 8; ++k) {
        v |= std::uint64_t{input[1 + 8 * i + k]} << (8U * k);
    }
    return static_cast<std::int64_t>(v);
}

Expected in_range(const int128 v) {
    if (v < int64_min || v > int64_max) {
        return {"bo:overflow", {}};
    }
    return {std::nullopt, {static_cast<std::int64_t>(v)}};
}

Expected expect_muldiv(const std::int64_t a, const std::int64_t b, const std::int64_t c,
                       const std::int64_t mode) {
    if (c == 0) {
        return {"bo:division-by-zero", {}};
    }
    const int128 product = int128{a} * b;
    const bool negative = (product < 0) != (c < 0);
    const uint128 magnitude = product < 0 ? uint128(-product) : uint128(product);
    const uint128 divisor = c < 0 ? uint128(-int128{c}) : uint128(c);
    uint128 q = magnitude / divisor;
    const uint128 rest = magnitude % divisor;
    if (mode != 2 && rest != 0) {
        const uint128 twice = 2 * rest;
        if (twice > divisor || (twice == divisor && (mode == 0 || (q & 1U) == 1U))) {
            ++q;
        }
    }
    if (q > (uint128{1} << 64U) - 1) {
        return {"bo:overflow", {}};
    }
    return in_range(negative ? -int128(q) : int128(q));
}

using std::chrono::sys_days;
using std::chrono::year_month_day;

std::int64_t days_of(const year_month_day& ymd) {
    return sys_days{ymd}.time_since_epoch().count();
}

year_month_day ymd_of(const std::int64_t day) {
    return year_month_day{sys_days{std::chrono::days{day}}};
}

std::vector<std::int64_t> parts(const year_month_day& ymd) {
    return {static_cast<int>(ymd.year()), static_cast<unsigned>(ymd.month()),
            static_cast<unsigned>(ymd.day())};
}

/// The local day and time of day, or nothing outside the years 1 to 9999
/// (or with an offset beyond a day).
std::optional<std::pair<std::int64_t, std::int64_t>> local(const std::int64_t t,
                                                           const std::int64_t offset) {
    if (offset < -day_ms || offset > day_ms) {
        return std::nullopt;
    }
    const int128 l = int128{t} + offset;
    if (l < -62'135'596'800'000 || l > 253'402'300'799'999) {
        return std::nullopt;
    }
    const auto v = static_cast<std::int64_t>(l);
    const std::int64_t day = (v >= 0 ? v : v - day_ms + 1) / day_ms;
    return std::pair{day, v - day * day_ms};
}

Expected expect_math(const ByteView input) {
    const auto op = static_cast<MathOp>(input[0]);
    const auto a = [&](const std::size_t i) {
        return arg(input, i);
    };
    switch (op) {
    case MathOp::nop:
        return {};
    case MathOp::add:
        return in_range(int128{a(0)} + a(1));
    case MathOp::sub:
        return in_range(int128{a(0)} - a(1));
    case MathOp::mul:
        return in_range(int128{a(0)} * a(1));
    case MathOp::neg:
        return in_range(-int128{a(0)});
    case MathOp::muldiv:
        return expect_muldiv(a(0), a(1), a(2), a(3) & 0xFFFF'FFFF);
    case MathOp::udiv128: {
        const uint128 n =
            (uint128(static_cast<std::uint64_t>(a(0))) << 64U) | static_cast<std::uint64_t>(a(1));
        const auto d = static_cast<std::uint64_t>(a(2));
        return {std::nullopt,
                {static_cast<std::int64_t>(static_cast<std::uint64_t>(n / d)),
                 static_cast<std::int64_t>(static_cast<std::uint64_t>(n % d))}};
    }
    case MathOp::days_from_civil:
        return {std::nullopt,
                {days_of(year_month_day{std::chrono::year{static_cast<int>(a(0))},
                                        std::chrono::month{static_cast<unsigned>(a(1))},
                                        std::chrono::day{static_cast<unsigned>(a(2))}})}};
    case MathOp::civil_from_days:
        return {std::nullopt, parts(ymd_of(a(0)))};
    case MathOp::days_in_month: {
        const std::chrono::year_month_day_last last{
            std::chrono::year{static_cast<int>(a(0))},
            std::chrono::month_day_last{std::chrono::month{static_cast<unsigned>(a(1))}}};
        return {std::nullopt, {static_cast<unsigned>(last.day())}};
    }
    case MathOp::add_months: {
        const auto l = local(a(0), a(2));
        if (!l || a(1) < -120'000 || a(1) > 120'000) {
            return {"bo:date", {}};
        }
        const year_month_day ymd = ymd_of(l->first);
        const std::int64_t total =
            static_cast<int>(ymd.year()) * 12LL + static_cast<unsigned>(ymd.month()) - 1 + a(1);
        if (total < 12 || total >= 120'000) {
            return {"bo:date", {}};
        }
        const std::chrono::year y{static_cast<int>(total / 12)};
        const std::chrono::month m{static_cast<unsigned>(total % 12 + 1)};
        const std::chrono::day last =
            std::chrono::year_month_day_last{y, m / std::chrono::last}.day();
        const year_month_day moved{y, m, std::min(ymd.day(), last)};
        return {std::nullopt, {days_of(moved) * day_ms + l->second - a(2)}};
    }
    case MathOp::date_parts: {
        const auto l = local(a(0), a(1));
        if (!l) {
            return {"bo:date", {}};
        }
        return {std::nullopt, parts(ymd_of(l->first))};
    }
    case MathOp::date_from_parts: {
        if (a(3) < -day_ms || a(3) > day_ms || a(0) < 1 || a(0) > 9999 || a(1) < 1 || a(1) > 12 ||
            a(2) < 1 || a(2) > 31) {
            return {"bo:date", {}};
        }
        const year_month_day ymd{std::chrono::year{static_cast<int>(a(0))},
                                 std::chrono::month{static_cast<unsigned>(a(1))},
                                 std::chrono::day{static_cast<unsigned>(a(2))}};
        if (!ymd.ok()) {
            return {"bo:date", {}};
        }
        return {std::nullopt, {days_of(ymd) * day_ms - a(3)}};
    }
    case MathOp::bytes_cmp:
    case MathOp::bytes_eq: {
        const auto n = static_cast<std::size_t>(a(0));
        const auto m = static_cast<std::size_t>(a(1));
        const ByteView x = input.subspan(17, n);
        const ByteView y = input.subspan(17 + n, m);
        const auto order =
            std::lexicographical_compare_three_way(x.begin(), x.end(), y.begin(), y.end());
        if (op == MathOp::bytes_eq) {
            return {std::nullopt, {order == std::strong_ordering::equal ? 1 : 0}};
        }
        return {std::nullopt, {order < 0 ? -1 : order > 0 ? 1 : 0}};
    }
    }
    return {};
}

Bytes results_bytes(const std::vector<std::int64_t>& results) {
    Bytes out;
    for (const std::int64_t v : results) {
        put_u64(out, static_cast<std::uint64_t>(v));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Checks shared by the visible cases and the reference file.
// ---------------------------------------------------------------------------

/// The reader agrees with core's decoder: what core accepts it accepts and
/// writes back unchanged; what core refuses it refuses, except that from
/// codegen 2 on it does not check texts' UTF-8 (the ledger's input holds
/// valid UTF-8 only), so an input core refuses for that alone it may accept.
void check_reader(const Case& c, const Run& r) {
    INFO("input " << cexchain::to_hex(c.input));
    if (c.input.size() > rt::layout::input_max) {
        CHECK(r.aborted("bo:input"));
        return;
    }
    const auto decoded = cbor::decode(c.input);
    const bool utf8_only = !decoded && decoded.error().detail.find("UTF-8") != std::string::npos;
    if (decoded || (utf8_only && r.ok())) {
        CHECK(r.ok());
        // The copy harness writes it back; the read-only module, nothing.
        CHECK(r.output == (c.module == "cbor-copy" ? c.input : Bytes{}));
    } else {
        CHECK(r.aborted("bo:input"));
    }
}

void check_lookup(const Case& c, const Run& r) {
    INFO("input " << cexchain::to_hex(c.input));
    const auto decoded = cbor::decode(c.input);
    REQUIRE(decoded.has_value());
    const cbor::Array& pair = *decoded->as_array();
    const cbor::Value* found = nullptr;
    if (pair[0].as_map() != nullptr) {
        found = pair[0].find(pair[1]);
    } else if (const cbor::Array* items = pair[0].as_array(); items != nullptr) {
        const auto index = pair[1].as_uint64();
        found = index && *index < items->size() ? &(*items)[*index] : nullptr;
    }
    REQUIRE(r.ok());
    if (found == nullptr) {
        CHECK(r.output.empty());
    } else {
        const auto encoded = cbor::encode(*found);
        REQUIRE(encoded.has_value());
        CHECK(r.output == *encoded);
    }
}

void check_math(const Case& c, const Run& r) {
    INFO("input " << cexchain::to_hex(c.input));
    const Expected e = expect_math(c.input);
    if (e.reason) {
        CHECK(r.aborted(*e.reason));
    } else {
        CHECK(r.ok());
        CHECK(r.output == results_bytes(e.results));
    }
}

/// Builds a module whose cexchain_call writes constants, to check how the
/// builder encodes them.
Bytes constants_module(const std::vector<std::int64_t>& values) {
    wasm::ModuleWriter m(rt::memory_plan());
    const wasm::Func entry = m.declare({});
    wasm::FunctionBuilder b = m.begin(entry);
    std::uint32_t at = rt::layout::output_base;
    for (const std::int64_t v : values) {
        b.u32(at).i64(v).store(wasm::Op::i64_store);
        at += 8;
        if (v >= std::numeric_limits<std::int32_t>::min() &&
            v <= std::numeric_limits<std::int32_t>::max()) {
            b.u32(at).i32(static_cast<std::int32_t>(v)).store(wasm::Op::i32_store);
        }
        at += 8;
    }
    b.u32(rt::layout::output_base).u32(at - rt::layout::output_base);
    b.call(m.host(wasm::Host::output_write));
    m.define(std::move(b));
    m.entry(entry);
    auto bytes = m.finish();
    REQUIRE(bytes.has_value());
    return *bytes;
}

std::string hex_of(const ByteView bytes) {
    return cexchain::to_hex(bytes);
}

/// A typical call's input, as the ledger encodes it.
Bytes typical_input(const bool creation) {
    namespace protocol = cexchain::protocol;
    protocol::ContractInput input;
    input.function = creation ? "create" : "pledge";
    const auto id = [](const std::uint8_t fill) {
        auto out = protocol::Id::from_bytes(Bytes(32, fill));
        REQUIRE(out.has_value());
        return *out;
    };
    cbor::Map arguments;
    arguments.push_back({cbor::Value::text("amount"), cbor::Value::integer(5'000'000)});
    arguments.push_back({cbor::Value::text("to"), cbor::Value::bytes(id(0x22).bytes())});
    input.arguments = cbor::Value::map(std::move(arguments));
    input.home = id(0x01);
    input.contract = id(0x02);
    input.caller = id(0x01);
    input.caller_signer =
        protocol::ContractSigner{1, protocol::PresenceMethod::webauthn, std::nullopt};
    input.time = 1'801'929'600'000;
    if (!creation) {
        protocol::ContractInstanceView instance;
        instance.id = id(0x03);
        instance.head = 41;
        cbor::Map fields;
        fields.push_back({cbor::Value::text("amount"), cbor::Value::integer(5'000'000)});
        fields.push_back({cbor::Value::text("holder"), cbor::Value::bytes(id(0x11).bytes())});
        cbor::Map state;
        state.push_back({cbor::Value::text("fields"), cbor::Value::map(std::move(fields))});
        state.push_back({cbor::Value::text("state"), cbor::Value::text("issued")});
        instance.state = *cbor::Encoded::encode(cbor::Value::map(std::move(state)));
        instance.status = "issued";
        instance.parties = {{"issuer", id(0x01)}, {"supplier", id(0x11)}};
        input.instance = std::move(instance);
        input.consents.push_back(
            {id(0x22),
             protocol::ContractSigner{1, protocol::PresenceMethod::webauthn, std::nullopt}});
    }
    auto bytes = protocol::encode_contract_input(input);
    REQUIRE(bytes.has_value());
    return *bytes;
}

} // namespace

TEST_CASE("bo runtime: the builder's modules load, with the validator's stack heights",
          "[bo][runtime]") {
    for (const h::Harness& entry : h::harnesses) {
        INFO(entry.name);
        const Built& built = harness(entry.name);
        CHECK(built.bytes == entry.build()); // deterministic
        const auto& data = built.module.data();
        REQUIRE(data.imports == wasm::host_count);
        REQUIRE(data.functions.size() > wasm::host_count);
    }
    // The builder's own measure of each function's height, against core's
    // validator.
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    for (std::size_t i = 0; i < rt::routine_count(); ++i) {
        static_cast<void>(runtime.get(static_cast<rt::Routine>(i)));
    }
    const wasm::Func entry = m.declare({});
    wasm::FunctionBuilder b = m.begin(entry);
    b.call(runtime.get(rt::Routine::read_input)).op(wasm::Op::drop);
    m.define(std::move(b));
    m.entry(entry);
    const auto bytes = m.finish();
    REQUIRE(bytes.has_value());
    const auto module = vm::load(*bytes);
    REQUIRE(module.has_value());
    const auto& data = module->data();
    for (std::uint32_t f = wasm::host_count; f < m.function_count(); ++f) {
        INFO("function " << f);
        CHECK(m.max_height(wasm::Func{f}) == data.functions[f].max_height);
    }
    CHECK(runtime.emitted().size() == rt::routine_count());
}

TEST_CASE("bo runtime: constants and stores encode as WebAssembly reads them", "[bo][runtime]") {
    const std::vector<std::int64_t> values{0,
                                           1,
                                           -1,
                                           63,
                                           64,
                                           -64,
                                           -65,
                                           127,
                                           128,
                                           8191,
                                           8192,
                                           -8193,
                                           std::numeric_limits<std::int32_t>::max(),
                                           std::numeric_limits<std::int32_t>::min(),
                                           0x7FFF'FFFF'FFFFLL,
                                           int64_max,
                                           int64_min,
                                           int64_min + 1};
    const Bytes wasm_bytes = constants_module(values);
    const auto module = vm::load(wasm_bytes);
    REQUIRE(module.has_value());
    const auto outcome = vm::run(*module, {}, provider(), cexchain::crypto::HashAlg::sha256);
    REQUIRE(outcome.has_value());
    REQUIRE(outcome->ok());
    Bytes expected;
    for (const std::int64_t v : values) {
        put_u64(expected, static_cast<std::uint64_t>(v));
        const bool fits = v >= std::numeric_limits<std::int32_t>::min() &&
                          v <= std::numeric_limits<std::int32_t>::max();
        put_u64(expected, fits ? static_cast<std::uint32_t>(v) : 0);
    }
    CHECK(outcome->output == expected);
}

TEST_CASE("bo runtime: routines are emitted only when used, with what they call", "[bo][runtime]") {
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    const wasm::Func muldiv = runtime.get(rt::Routine::muldiv);
    CHECK(runtime.get(rt::Routine::muldiv) == muldiv);
    const std::vector<rt::Routine> expected{rt::Routine::muldiv, rt::Routine::fail_division_by_zero,
                                            rt::Routine::fail_overflow, rt::Routine::udiv128};
    CHECK(runtime.emitted() == expected);
    CHECK(muldiv.index == wasm::host_count);
    static_cast<void>(runtime.get(rt::Routine::add));
    CHECK(runtime.emitted().size() == 5); // fail_overflow is there already
    CHECK(rt::name_of(rt::Routine::days_from_civil) == "days_from_civil");
    CHECK(rt::text_of(rt::Reason::division_by_zero) == "bo:division-by-zero");
    CHECK(wasm::name_of(wasm::Op::i64_extend_i32_u) == "i64.extend_i32_u");
    CHECK(wasm::name_of(wasm::Op::memory_copy) == "memory.copy");
    CHECK(wasm::name_of(wasm::Op::select) == "select");
    CHECK(wasm::name_of(wasm::Host::output_write) == "output_write");
}

TEST_CASE("bo runtime: the harness modules match their goldens", "[bo][runtime]") {
    for (const h::Harness& entry : h::harnesses) {
        INFO(entry.name);
        const auto path = golden_dir / (std::string(entry.name) + ".wasm");
        const Bytes& bytes = harness(entry.name).bytes;
        if (updating_goldens()) {
            write_file(path, bytes);
        }
        CHECK(read_file(path) == bytes);
    }
}

TEST_CASE("bo runtime: the CBOR reader accepts exactly what core's decoder accepts",
          "[bo][runtime]") {
    std::size_t accepted = 0;
    std::size_t refused = 0;
    for (const Case& c : reader_cases()) {
        const Run r = run(c.module, c.input);
        check_reader(c, r);
        (r.ok() ? accepted : refused) += 1;
    }
    CHECK(accepted > 300);
    CHECK(refused > 250);
    // More random inputs than the reference file holds.
    Random rand(0xB0'0010);
    for (int i = 0; i < 3000; ++i) {
        auto [bytes, value] = canonical(random_value(rand, 0));
        const Case c{"cbor-copy", rand.chance(50) ? mutate(bytes, rand) : bytes, "", {}};
        check_reader(c, run(c.module, c.input));
    }
    // The limits: items, and the input's size.
    for (const Case& c : reader_limit_cases()) {
        const Run r = run(c.module, c.input);
        check_reader(c, r);
    }
    const auto limits = reader_limit_cases();
    CHECK(run("read-only", limits[0].input).ok());
    CHECK(run("read-only", limits[1].input).aborted("bo:input"));
    CHECK(run("read-only", limits[2].input).ok());
    CHECK(run("read-only", limits[3].input).aborted("bo:input"));
    // A contract's input, as the ledger writes it.
    for (const bool creation : {true, false}) {
        const Bytes input = typical_input(creation);
        const Run r = run("cbor-copy", input);
        CHECK(r.ok());
        CHECK(r.output == input);
    }
}

TEST_CASE("bo runtime: map and array lookups agree with core", "[bo][runtime]") {
    for (const Case& c : lookup_cases()) {
        check_lookup(c, run(c.module, c.input));
    }
}

TEST_CASE("bo runtime: the CBOR writer agrees with core's encoder byte for byte", "[bo][runtime]") {
    for (const Case& c : writer_cases()) {
        const Run r = run(c.module, c.input);
        INFO(r.describe() << " for " << c.input.size() << " bytes of commands");
        REQUIRE(r.ok());
        CHECK(r.output == c.expected);
    }
    // Past the output region (192 KiB): refused.
    wasm::ModuleWriter m(rt::memory_plan());
    rt::Runtime runtime(m);
    const wasm::Func entry = m.declare({});
    wasm::FunctionBuilder b = m.begin(entry);
    for (int i = 0; i < 4; ++i) {
        b.u32(rt::layout::input_base).u32(60'000).call(runtime.get(rt::Routine::out_raw));
    }
    b.call(runtime.get(rt::Routine::out_finish));
    m.define(std::move(b));
    m.entry(entry);
    const auto bytes = m.finish();
    REQUIRE(bytes.has_value());
    const auto module = vm::load(*bytes);
    REQUIRE(module.has_value());
    const auto outcome = vm::run(*module, {}, provider(), cexchain::crypto::HashAlg::sha256);
    REQUIRE(outcome.has_value());
    CHECK(outcome->trap == vm::Trap::aborted);
    CHECK(outcome->abort_reason ==
          Bytes(cexchain::as_bytes("bo:output").begin(), cexchain::as_bytes("bo:output").end()));
}

TEST_CASE("bo runtime: arithmetic, rounding, dates, and texts agree with exact values",
          "[bo][runtime]") {
    for (const Case& c : math_cases()) {
        check_math(c, run(c.module, c.input));
    }
    // Beyond Python's calendar: dates in years -30,000 to 30,000.
    Random r(0xB0'0011);
    for (int i = 0; i < 2000; ++i) {
        const std::int64_t day = random_day(r);
        const Case c{"math", math_input(MathOp::civil_from_days, {day}), "", {}};
        check_math(c, run(c.module, c.input));
        const auto p = parts(ymd_of(day));
        const Case back{"math", math_input(MathOp::days_from_civil, p), "", {}};
        check_math(back, run(back.module, back.input));
    }
    // More of the 128-bit cases.
    for (int i = 0; i < 5000; ++i) {
        const Case c{"math",
                     math_input(MathOp::muldiv, {random_int(r), random_int(r), random_int(r),
                                                 static_cast<std::int64_t>(r.below(3))}),
                     "",
                     {}};
        check_math(c, run(c.module, c.input));
    }
    // Rounding examples: 3.875% of HKD 1,234.56 (rates in millionths), half up.
    const Run rate = run("math", math_input(MathOp::muldiv, {123'456, 38'750, 1'000'000, 0}));
    CHECK(rate.output == results_bytes({4'784})); // 4,783.92 cents
    const Run even = run("math", math_input(MathOp::muldiv, {25, 1, 10, 1}));
    CHECK(even.output == results_bytes({2}));
}

TEST_CASE("bo runtime: the fuel each routine costs", "[bo][runtime]") {
    std::ostringstream text;
    text << "# Fuel of the Bo runtime's routines (codegen " << wasm::codegen_version
         << "), measured by tests/bo/runtime_test.cpp.\n"
         << "# A call has 10,000,000. Rewrite with CEXCHAIN_UPDATE_GOLDENS=1.\n";
    const auto line = [&](const std::string_view what, const std::uint64_t fuel) {
        text << std::format("{:<64} {:>9}\n", what, fuel);
    };
    const auto math_fuel = [&](const MathOp op, const std::vector<std::int64_t>& args) {
        const Run r = run("math", math_input(op, args));
        INFO(r.describe() << " for operation " << static_cast<int>(op));
        REQUIRE(r.ok());
        return r.fuel - run("math", math_input(MathOp::nop, {})).fuel;
    };
    const auto read_fuel = [&](const ByteView input) {
        const Run r = run("read-only", input);
        INFO(r.describe() << " for " << input.size() << " bytes");
        REQUIRE(r.ok());
        return r.fuel;
    };
    for (const bool creation : {true, false}) {
        const Bytes input = typical_input(creation);
        line(std::format("read_input: a contract's input, {} ({} bytes)",
                         creation ? "a creation" : "a call with a consent", input.size()),
             read_fuel(input));
    }
    line("read_input: a 1,000-byte text", [&] {
        Bytes input{0x79, 0x03, 0xE8};
        input.resize(3 + 1'000, 0x61);
        return read_fuel(input);
    }());
    line("read_input: a 60,000-byte byte string", [&] {
        Bytes input{0x59, 0xEA, 0x60};
        input.resize(3 + 60'000, 0x00);
        return read_fuel(input);
    }());
    line("read_input: an array of 1,000 small integers", read_fuel(flat_array(1'000)));
    line("read_input: the largest item count (131,072)", read_fuel(flat_array(131'071)));
    {
        // A lookup in the contract's input map (8 keys), key 7 (the time).
        const auto decoded = cbor::decode(typical_input(false));
        REQUIRE(decoded.has_value());
        auto [pair, unused] = canonical(cbor::Value::array({*decoded, cbor::Value::integer(7)}));
        const Run lookup = run("lookup-only", pair);
        REQUIRE(lookup.ok());
        line("map_get: key 7 of a call's input (8 keys; with the harness's 21)",
             lookup.fuel - run("read-only", pair).fuel);
    }
    {
        const Run out = run("typical-output", {});
        REQUIRE(out.ok());
        line(std::format("out_*: a typical accept output ({} bytes, 23 routine calls)",
                         out.output.size()),
             out.fuel);
    }
    line("add", math_fuel(MathOp::add, {1, 2}));
    line("sub", math_fuel(MathOp::sub, {1, 2}));
    line("mul", math_fuel(MathOp::mul, {123'456, 789}));
    line("neg", math_fuel(MathOp::neg, {5}));
    line("muldiv: a product below 2^64 (an amount times a rate)",
         math_fuel(MathOp::muldiv, {123'456, 38'750, 1'000'000, 0}));
    line("muldiv: a 128-bit product",
         math_fuel(MathOp::muldiv, {int64_max, 1'000'000'007, 3'000'000'017, 1}));
    line("days_from_civil", math_fuel(MathOp::days_from_civil, {2027, 1, 31}));
    line("civil_from_days", math_fuel(MathOp::civil_from_days, {20'849}));
    line("days_in_month", math_fuel(MathOp::days_in_month, {2028, 2}));
    line("add_months: one month at +08:00",
         math_fuel(MathOp::add_months, {1'801'900'800'000, 1, 8 * 3'600'000}));
    line("date_parts", math_fuel(MathOp::date_parts, {1'801'900'800'000, 8 * 3'600'000}));
    line("date_from_parts", math_fuel(MathOp::date_from_parts, {2027, 1, 31, 8 * 3'600'000}));
    const auto text_fuel = [&](const MathOp op, const std::string_view a,
                               const std::string_view b) {
        const Run r = run("math", text_input(op, cexchain::as_bytes(a), cexchain::as_bytes(b)));
        REQUIRE(r.ok());
        return r.fuel - run("math", math_input(MathOp::nop, {})).fuel;
    };
    line("bytes_cmp: two equal 10-byte texts",
         text_fuel(MathOp::bytes_cmp, "proposed01", "proposed01"));
    line("bytes_cmp: two 64-byte texts, the last byte differs",
         text_fuel(MathOp::bytes_cmp, std::string(63, 'a') + "b", std::string(64, 'a')));
    line("bytes_eq: two texts of different lengths",
         text_fuel(MathOp::bytes_eq, "paid", "proposed"));

    const auto path = golden_dir / "fuel.txt";
    if (updating_goldens()) {
        write_file(path, cexchain::as_bytes(text.str()));
    }
    const Bytes golden = read_file(path);
    CHECK(std::string(golden.begin(), golden.end()) == text.str());
}

TEST_CASE("bo runtime: write the runs for the Python reference", "[.reference]") {
    const char* path = std::getenv("CEXCHAIN_BO_REFERENCE");
    REQUIRE(path != nullptr);
    std::vector<Case> cases = reader_cases();
    for (auto* more : {&reader_limit_cases, &lookup_cases, &writer_cases, &math_cases}) {
        for (Case& c : (*more)()) {
            cases.push_back(std::move(c));
        }
    }
    std::ofstream out(path);
    out << "{\"format\": 1, \"codegen\": " << wasm::codegen_version << ",\n \"modules\": {";
    bool first = true;
    for (const h::Harness& entry : h::harnesses) {
        out << (first ? "" : ",") << "\n  \"" << entry.name << "\": \""
            << hex_of(harness(entry.name).bytes) << '"';
        first = false;
    }
    out << "},\n \"runs\": [";
    first = true;
    for (const Case& c : cases) {
        const Run r = run(c.module, c.input);
        // The same checks as the visible cases: the file holds no run that
        // fails them.
        if (c.module == "cbor-copy" || c.module == "read-only") {
            check_reader(c, r);
        } else if (c.module == "cbor-lookup") {
            check_lookup(c, r);
        } else if (c.module == "math") {
            check_math(c, r);
        } else {
            CHECK(r.output == c.expected);
        }
        out << (first ? "" : ",") << "\n  {\"module\": \"" << c.module << "\", \"input\": \""
            << hex_of(c.input) << "\", \"outcome\": \"" << r.outcome << "\", \"output\": \""
            << hex_of(r.output) << "\", \"fuel\": " << r.fuel << ", \"reason\": \""
            << hex_of(r.reason) << '"';
        if (!c.oracle.empty()) {
            out << ", \"oracle\": \"" << c.oracle << '"';
        }
        out << '}';
        first = false;
    }
    out << "\n]}\n";
    REQUIRE(out.good());
}

namespace {

/// A CBOR head in its shortest form.
Bytes cbor_head(const std::uint8_t major, const std::uint64_t n) {
    Bytes out;
    const auto top = static_cast<std::uint8_t>(major << 5U);
    if (n < 24) {
        out.push_back(static_cast<std::uint8_t>(top | n));
        return out;
    }
    int width = 8;
    std::uint8_t info = 27;
    if (n < 0x100) {
        width = 1;
        info = 24;
    } else if (n < 0x1'0000) {
        width = 2;
        info = 25;
    } else if (n < 0x1'0000'0000) {
        width = 4;
        info = 26;
    }
    out.push_back(static_cast<std::uint8_t>(top | info));
    for (int shift = 8 * (width - 1); shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(n >> static_cast<unsigned>(shift)));
    }
    return out;
}

Bytes joined(std::initializer_list<ByteView> parts) {
    Bytes out;
    for (const ByteView p : parts) {
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

/// Counts a value's items and map keys as read_input reads them.
void count_items(const cbor::Value& v, std::uint64_t& items, std::uint64_t& keys) {
    ++items;
    if (const cbor::Array* a = v.as_array()) {
        for (const cbor::Value& x : *a) {
            count_items(x, items, keys);
        }
    } else if (const cbor::Map* m = v.as_map()) {
        for (const cbor::MapEntry& e : *m) {
            ++keys;
            count_items(e.key, items, keys);
            count_items(e.value, items, keys);
        }
    } else if (const cbor::Tagged* t = v.as_tagged()) {
        count_items(t->item, items, keys);
    }
}

} // namespace

TEST_CASE("bo runtime: read_input stays within its bound", "[bo][runtime]") {
    // What reading an input costs, against the bound the
    // compiler counts for its items and keys (read_bound.hpp). Every kind of
    // item, many times over, as array items, map keys (each compared with
    // the one before it), map values, and nested; then inputs at the limits.
    std::vector<Bytes> items;
    for (const std::uint8_t major : {std::uint8_t{0}, std::uint8_t{1}, std::uint8_t{6}}) {
        for (const std::uint64_t arg : {0ULL, 23ULL, 24ULL, 255ULL, 256ULL, 65'535ULL, 65'536ULL,
                                        0xFFFF'FFFFULL, 0x1'0000'0000ULL, ~0ULL}) {
            if (major == 6 && (arg == 2 || arg == 3)) {
                continue;
            }
            items.push_back(major == 6 ? joined({cbor_head(6, arg), Bytes{0x00}})
                                       : cbor_head(major, arg));
        }
    }
    for (const std::uint8_t major : {std::uint8_t{2}, std::uint8_t{3}}) {
        for (const std::uint64_t length : {0U, 1U, 7U, 8U, 9U, 23U, 24U, 255U, 256U}) {
            items.push_back(joined({cbor_head(major, length), Bytes(length, 'a')}));
        }
    }
    for (const std::uint64_t count : {0U, 1U, 2U, 23U, 24U}) {
        items.push_back(joined({cbor_head(4, count), Bytes(count, 0x00)}));
    }
    items.push_back(Bytes{0xA0});
    items.push_back(Bytes{0xA1, 0x00, 0x00});
    items.push_back(Bytes{0xF4});
    items.push_back(Bytes{0xF5});
    items.push_back(Bytes{0xF6});
    // Tags of 8 bytes, nested.
    items.push_back(joined({cbor_head(6, ~0ULL), cbor_head(6, ~0ULL), Bytes{0x00}}));

    std::vector<Bytes> inputs;
    for (const Bytes& item : items) {
        for (const std::uint32_t n : {1U, 60U, 600U}) {
            Bytes input = cbor_head(4, n);
            for (std::uint32_t i = 0; i < n; ++i) {
                input.insert(input.end(), item.begin(), item.end());
            }
            inputs.push_back(std::move(input));
        }
    }
    // Maps whose keys share their first byte, so that each is compared with
    // the one before it: texts and byte strings of 1 to 64 bytes, integers
    // of 1 to 8 bytes; values of every kind above.
    const auto map_of = [](std::uint32_t n, const auto& key, const Bytes& value) {
        Bytes input = cbor_head(5, n);
        for (std::uint32_t i = 0; i < n; ++i) {
            const Bytes k = key(i);
            input.insert(input.end(), k.begin(), k.end());
            input.insert(input.end(), value.begin(), value.end());
        }
        return input;
    };
    for (const std::uint8_t major : {std::uint8_t{2}, std::uint8_t{3}}) {
        for (const std::uint64_t length : {1U, 2U, 7U, 8U, 9U, 16U, 31U, 32U, 33U, 63U, 64U}) {
            const auto key = [&](const std::uint32_t i) {
                Bytes k = joined({cbor_head(major, length), Bytes(length, 'a')});
                k.back() = static_cast<std::uint8_t>(0x21 + i);
                return k;
            };
            for (const Bytes& value : {items.front(), items[9], items.back()}) {
                inputs.push_back(map_of(90, key, value));
            }
        }
    }
    for (const std::uint64_t base : {24ULL, 256ULL, 65'536ULL, 0x1'0000'0000ULL}) {
        const auto key = [&](const std::uint32_t i) {
            return cbor_head(0, base + i);
        };
        inputs.push_back(map_of(200, key, cbor_head(0, ~0ULL)));
    }
    // Nesting 32 deep, of arrays, maps, and tags.
    Bytes arrays;
    Bytes maps;
    Bytes tags;
    for (int i = 0; i < 31; ++i) {
        arrays.push_back(0x81);
        maps.insert(maps.end(), {0xA1, 0x00});
        tags.push_back(0xC0);
    }
    arrays.push_back(0x00);
    maps.push_back(0x00);
    tags.push_back(0x00);
    inputs.push_back(arrays);
    inputs.push_back(maps);
    inputs.push_back(tags);
    // At the limits: the most items, 8-byte integers filling 160 KiB, and
    // maps of 64-byte keys filling it.
    inputs.push_back(flat_array(131'071));
    {
        Bytes input = cbor_head(4, 18'000);
        for (int i = 0; i < 18'000; ++i) {
            const Bytes v = cbor_head(0, ~0ULL);
            input.insert(input.end(), v.begin(), v.end());
        }
        inputs.push_back(std::move(input));
    }
    {
        const auto key = [](const std::uint32_t i) {
            Bytes k = joined({cbor_head(3, 64), Bytes(64, 'a')});
            k[63] = static_cast<std::uint8_t>(0x21 + i / 90);
            k[64] = static_cast<std::uint8_t>(0x21 + i % 90);
            return k;
        };
        inputs.push_back(map_of(2'000, key, cbor_head(0, ~0ULL)));
    }

    std::uint64_t closest = 0;
    for (const Bytes& input : inputs) {
        INFO("input " << cexchain::to_hex(
                 ByteView(input).first(std::min<std::size_t>(input.size(), 40))));
        REQUIRE(input.size() <= rt::layout::input_max);
        const auto value = cbor::decode(input);
        REQUIRE(value.has_value());
        std::uint64_t n_items = 0;
        std::uint64_t n_keys = 0;
        count_items(*value, n_items, n_keys);
        const Run r = run("read-only", input);
        REQUIRE(r.ok());
        const std::uint64_t bound = rt::read_input_fuel(n_items, n_keys);
        INFO("fuel " << r.fuel << ", bound " << bound);
        CHECK(r.fuel <= bound);
        closest = std::max(closest, r.fuel * 1000 / bound);
    }
    // The bound is not loose either: the costliest kinds come within a
    // fifth of it.
    CHECK(closest > 800);
    CHECK(inputs.size() > 250);
}
