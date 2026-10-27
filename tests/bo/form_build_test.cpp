// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The form's goldens built and tested: each sheet's source builds and passes
// its own tests, and the sheet filled in as examples/lending writes code
// byte for byte that of lending.bo.

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/form.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/scenario.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;

namespace {

const std::filesystem::path golden_dir = CEXCHAIN_BO_GOLDEN_DIR;
const std::filesystem::path source_dir = golden_dir.parent_path().parent_path().parent_path();

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

const PackSet& official_set() {
    static const PackSet set = *make_pack_set({}).set;
    return set;
}

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

std::string generated(const std::filesystem::path& dir) {
    const auto sheet = form::parse_sheet(read_text(dir / "sheet.json"));
    REQUIRE(std::holds_alternative<form::Sheet>(sheet));
    return form::generate(std::get<form::Sheet>(sheet)).source;
}

} // namespace

TEST_CASE("bo form: every golden sheet builds and passes its tests", "[bo][form]") {
    std::size_t cases = 0;
    for (const auto& entry : std::filesystem::directory_iterator(golden_dir / "form")) {
        INFO(entry.path().filename().string());
        const std::string source = generated(entry.path());
        const Compiled compiled = compile(source, official_set());
        std::string problems;
        for (const Diagnostic& d : compiled.diagnostics) {
            problems += std::string(d.code) + " ";
        }
        INFO(problems);
        REQUIRE(compiled.build.has_value());
        REQUIRE(compiled.model.has_value());
        const TestResults results = run_tests(*compiled.model, *compiled.build, provider());
        CHECK(results.failed == 0);
        CHECK(results.passed == results.tests.size());
        CHECK(results.passed > 0);
        ++cases;
    }
    CHECK(cases >= 20);
}

TEST_CASE("bo form: the lending sheet writes lending's code", "[bo][form]") {
    const Compiled from_sheet = compile(generated(golden_dir / "form" / "lending"), official_set());
    const Compiled from_source =
        compile(read_text(source_dir / "examples" / "lending" / "lending.bo"), official_set());
    REQUIRE(from_sheet.build.has_value());
    REQUIRE(from_source.build.has_value());
    CHECK(from_sheet.build->code == from_source.build->code);
    CHECK(from_sheet.build->interface == from_source.build->interface);
    // So do the sheets of its Chinese sources.
    for (const char* name : {"lending-zh-hant", "lending-zh-hans"}) {
        INFO(name);
        const Compiled chinese = compile(generated(golden_dir / "form" / name), official_set());
        REQUIRE(chinese.build.has_value());
        CHECK(chinese.build->code == from_source.build->code);
    }
}
