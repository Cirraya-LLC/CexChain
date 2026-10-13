// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Building a source all the way, and rebuilding a deploy from the bo-source
// bundle it carries (milestone 7 of the Bo compiler): a deploy rebuilds when
// its source is its code's; it differs when the compiler it names builds
// something else; another compiler's or version's output is reported as
// such, never as a forgery; a deploy without a usable bundle is malformed.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <cexchain/bo/build.hpp>
#include <cexchain/bo/concepts.hpp>
#include <cexchain/bo/format.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/source.hpp>
#include <cexchain/bo/wasm.hpp>
#include <cexchain/core/bytes.hpp>
#include <cexchain/core/protocol/statement.hpp>
#include <cexchain/core/vm.hpp>
#include <cexchain/crypto/openssl.hpp>

using namespace cexchain;
using namespace cexchain::bo;

namespace {

const std::filesystem::path build_dir = std::filesystem::path(CEXCHAIN_BO_GOLDEN_DIR) / "build";

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

const PackSet& official_set() {
    static const PackSet set = [] {
        PackSetRead read = make_pack_set({});
        REQUIRE(read.set.has_value());
        return std::move(*read.set);
    }();
    return set;
}

std::string agreement(std::string_view language = "en") {
    return read_text(build_dir / ("agreement-" + std::string(language)) / "source.bo");
}

/// What `contract deploy --bo` records for a source.
protocol::ContractDeployBody deploy_of(std::string_view source, const PackSet& set = official_set(),
                                       crypto::HashAlg hash = crypto::HashAlg::sha256) {
    const Compiled compiled = compile(source, set);
    REQUIRE(compiled.build.has_value());
    const auto bundle = make_source_bundle(source, compiled.edition, set, provider(), hash);
    REQUIRE(bundle.has_value());
    const auto bytes = encode_source_bundle(*bundle);
    REQUIRE(bytes.has_value());
    return {compiled.build->code, compiled.build->interface, "bo", compiler_string(), *bytes,
            compiled.name};
}

Rebuild rebuilt(const protocol::ContractDeployBody& deploy,
                crypto::HashAlg hash = crypto::HashAlg::sha256) {
    Rebuild r = rebuild(deploy, provider(), hash);
    INFO(r.detail);
    return r;
}

/// The same compiler string with another codegen version.
std::string other_codegen() {
    CompilerId id = this_compiler();
    id.codegen += 1;
    return format_compiler(id);
}

std::string other_release() {
    CompilerId id = this_compiler();
    id.release += "-other";
    return format_compiler(id);
}

bool mentions(const Rebuild& r, std::string_view text) {
    INFO(r.detail);
    return r.detail.find(text) != std::string::npos;
}

} // namespace

TEST_CASE("the compiler names itself", "[bo][build]") {
    CHECK(this_compiler().codegen == wasm::codegen_version);
    CHECK(this_compiler().edition == edition);
    CHECK(!this_compiler().release.empty());
    CHECK(parse_compiler(compiler_string()) == this_compiler());
    CHECK(compiler_string().starts_with("cexchain-bo "));
}

TEST_CASE("compile builds the agreement, the same code from every language", "[bo][build]") {
    const Compiled en = compile(agreement(), official_set());
    REQUIRE(en.build.has_value());
    CHECK(en.name == "Agreement");
    CHECK(en.edition == 1);
    CHECK(en.comments == 4);
    // The one warning: comments are deployed with the source.
    REQUIRE(en.diagnostics.size() == 1);
    CHECK(en.diagnostics[0].code == "build.comments");
    CHECK(en.diagnostics[0].arg("count") == "4");
    CHECK(vm::load(en.build->code).has_value());
    // The code is the one the codegen goldens pin.
    const std::string golden = read_text(build_dir / "agreement-en" / "build.txt");
    const auto digest = provider().digest(crypto::HashAlg::sha256, en.build->code);
    REQUIRE(digest.has_value());
    CHECK(golden.find("sha256 " + to_hex(digest->bytes())) != std::string::npos);
    for (const std::string_view language : {"zh-hant", "zh-hans", "mixed"}) {
        INFO(language);
        const Compiled other = compile(agreement(language), official_set());
        REQUIRE(other.build.has_value());
        CHECK(other.build->code == en.build->code);
        CHECK(other.build->interface == en.build->interface);
        CHECK(other.name == en.name);
    }
}

TEST_CASE("a source formatted into any language builds to the same code", "[bo][build]") {
    // Every source that builds: the agreement in four spellings, the demo,
    // and any golden of the other passes that is a whole contract.
    const std::filesystem::path golden_dir = build_dir.parent_path();
    std::vector<std::filesystem::path> paths{golden_dir.parent_path().parent_path().parent_path() /
                                             "deploy/demo/supply-agreement.bo"};
    for (const std::filesystem::path& dir : {golden_dir, build_dir, golden_dir / "format"}) {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (std::filesystem::exists(entry.path() / "source.bo")) {
                paths.push_back(entry.path() / "source.bo");
            }
        }
    }
    std::ranges::sort(paths);
    const Lexicon lexicon(official_set());
    const Pack* languages[] = {nullptr, official_set().find("en"),
                               official_set().find("zh-Hant-HK"),
                               official_set().find("zh-Hans-CN")};
    std::size_t built = 0;
    for (const std::filesystem::path& path : paths) {
        const std::string source = read_text(path);
        const Compiled original = compile(source, official_set());
        if (!original.build) {
            continue;
        }
        ++built;
        for (const Pack* language : languages) {
            INFO(path.string() + " in " + (language != nullptr ? language->id : "its own words"));
            const Formatted formatted = format_source(source, official_set(), lexicon, language);
            REQUIRE(formatted.source.has_value());
            const Compiled again = compile(*formatted.source, official_set());
            REQUIRE(again.build.has_value());
            CHECK(again.build->code == original.build->code);
            CHECK(again.build->interface == original.build->interface);
            CHECK(again.name == original.name);
            CHECK(again.comments == original.comments);
        }
    }
    CHECK(built >= 5);
}

TEST_CASE("compile stops at the first stage with errors", "[bo][build]") {
    // A fragment: it checks (with a warning), and lowering refuses it.
    const Compiled fragment = compile("record Terms\n  amount HKD\n", official_set());
    CHECK(!fragment.build.has_value());
    CHECK(std::ranges::any_of(fragment.diagnostics,
                              [](const Diagnostic& d) { return d.code == "build.fragment"; }));
    // A checker error: nothing is lowered.
    const Compiled unchecked =
        compile("contract C\nparties we\nrecord R\n  amount HKD\ncan go\n", official_set());
    CHECK(!unchecked.build.has_value());
    CHECK(std::ranges::none_of(unchecked.diagnostics,
                               [](const Diagnostic& d) { return d.code.starts_with("build."); }));
    // A lexer error: not even checked; problems in source order.
    const Compiled unlexed = compile("contract C\n\tparties we\nover 5,000\n", official_set());
    CHECK(!unlexed.build.has_value());
    REQUIRE(unlexed.diagnostics.size() >= 2);
    CHECK(unlexed.diagnostics[0].span.offset < unlexed.diagnostics[1].span.offset);
    // No comments, no warning.
    const Compiled quiet = compile("contract C\nparties we, customer\nrecord R\n  amount HKD\ncan "
                                   "close by we\n  proposed -> closed\n",
                                   official_set());
    REQUIRE(quiet.build.has_value());
    CHECK(quiet.diagnostics.empty());
}

TEST_CASE("a deploy rebuilds from its source", "[bo][build]") {
    const protocol::ContractDeployBody deploy = deploy_of(agreement());
    Rebuild r = rebuilt(deploy);
    CHECK(r.status == RebuildStatus::rebuilds);
    CHECK(mentions(r, "the source rebuilds to the deployed code"));
    REQUIRE(r.build.has_value());
    CHECK(r.build->code == deploy.code);
    REQUIRE(r.deployed.has_value());
    CHECK(*r.deployed == this_compiler());
    REQUIRE(r.bundle.has_value());
    CHECK(r.bundle->source == agreement());

    // On an SM3 home, with SM3 digests.
    CHECK(
        rebuilt(deploy_of(agreement(), official_set(), crypto::HashAlg::sm3), crypto::HashAlg::sm3)
            .status == RebuildStatus::rebuilds);
    // A deploy without a name still rebuilds; the name is for people.
    protocol::ContractDeployBody unnamed = deploy;
    unnamed.name.reset();
    CHECK(rebuilt(unnamed).status == RebuildStatus::rebuilds);
    // Another codegen version that gives the same bytes rebuilds too.
    protocol::ContractDeployBody newer = deploy;
    newer.compiler = other_codegen();
    CHECK(rebuilt(newer).status == RebuildStatus::rebuilds);
}

TEST_CASE("a deploy whose source is not its code differs", "[bo][build]") {
    const protocol::ContractDeployBody deploy = deploy_of(agreement());
    std::string changed = agreement();
    changed.replace(changed.find("150%"), 4, "200%");
    const protocol::ContractDeployBody other = deploy_of(changed);
    REQUIRE(other.code != deploy.code);

    SECTION("other code") {
        protocol::ContractDeployBody forged = deploy;
        forged.code = other.code;
        const Rebuild r = rebuilt(forged);
        CHECK(r.status == RebuildStatus::differs);
        CHECK(mentions(r, "the source builds to other code"));
        CHECK(mentions(r, "with the compiler the deploy names"));
    }
    SECTION("another interface") {
        protocol::ContractDeployBody forged = deploy;
        forged.interface.erase("amend");
        const Rebuild r = rebuilt(forged);
        CHECK(r.status == RebuildStatus::differs);
        CHECK(mentions(r, "not the deployed close, countersign, create (creates), sign"));
    }
    SECTION("another name") {
        protocol::ContractDeployBody forged = deploy;
        forged.name = "Loan";
        const Rebuild r = rebuilt(forged);
        CHECK(r.status == RebuildStatus::differs);
        CHECK(mentions(r, "the deploy is named \"Loan\", but the contract is Agreement"));
    }
    SECTION("a source that does not build") {
        protocol::ContractDeployBody forged = deploy;
        const auto bundle = make_source_bundle("contract C\ncan go\n", 1, official_set(),
                                               provider(), crypto::HashAlg::sha256);
        REQUIRE(bundle.has_value());
        forged.source = *encode_source_bundle(*bundle);
        const Rebuild r = rebuilt(forged);
        CHECK(r.status == RebuildStatus::differs);
        CHECK(mentions(r, "the source does not build with the compiler the deploy names"));
        CHECK(!r.diagnostics.empty());
    }
    SECTION("an official pack that is not the one this release carries") {
        protocol::ContractDeployBody forged = deploy;
        auto bundle = decode_source_bundle(*deploy.source);
        REQUIRE(bundle.has_value());
        bundle->packs[0].digest[5] ^= 1;
        forged.source = *encode_source_bundle(*bundle);
        const Rebuild r = rebuilt(forged);
        CHECK(r.status == RebuildStatus::differs);
        CHECK(mentions(r, "although the deploy names this compiler"));
        // Another release's official packs may differ (before the first
        // release, packs change without a new version): not a forgery.
        forged.compiler = other_release();
        const Rebuild other_r = rebuilt(forged);
        CHECK(other_r.status == RebuildStatus::other_compiler);
        CHECK(mentions(other_r, "rebuild with cexchain-bo " + this_compiler().release + "-other"));
    }
}

TEST_CASE("another compiler's output is reported as such", "[bo][build]") {
    const protocol::ContractDeployBody deploy = deploy_of(agreement());
    std::string changed = agreement();
    changed.replace(changed.find("150%"), 4, "200%");
    protocol::ContractDeployBody forged = deploy;
    forged.code = deploy_of(changed).code;

    forged.compiler = other_codegen();
    Rebuild r = rebuilt(forged);
    CHECK(r.status == RebuildStatus::other_compiler);
    CHECK(mentions(r, "built with " + other_codegen() + "; this compiler is " + compiler_string() +
                          ", and the source builds to other code"));
    REQUIRE(r.deployed.has_value());
    CHECK(r.deployed->codegen == this_compiler().codegen + 1);

    forged.compiler = "acme-bo 2.1";
    r = rebuilt(forged);
    CHECK(r.status == RebuildStatus::other_compiler);
    CHECK(mentions(r, "built with \"acme-bo 2.1\", which is not cexchain-bo"));
    CHECK(!r.deployed.has_value());

    // An official pack version this compiler does not carry: a newer one.
    protocol::ContractDeployBody newer = deploy;
    newer.compiler = other_codegen();
    auto bundle = decode_source_bundle(*deploy.source);
    REQUIRE(bundle.has_value());
    bundle->packs[2].version = 2;
    newer.source = *encode_source_bundle(*bundle);
    r = rebuilt(newer);
    CHECK(r.status == RebuildStatus::other_compiler);
    CHECK(mentions(r, "zh-Hant-HK version 2; this compiler carries version 1"));
    // A later edition.
    bundle = decode_source_bundle(*deploy.source);
    bundle->edition = edition + 1;
    newer.source = *encode_source_bundle(*bundle);
    CHECK(rebuilt(newer).status == RebuildStatus::other_compiler);
}

TEST_CASE("a deploy without a usable source bundle is malformed", "[bo][build]") {
    const protocol::ContractDeployBody deploy = deploy_of(agreement());
    protocol::ContractDeployBody d = deploy;
    d.source.reset();
    Rebuild r = rebuilt(d);
    CHECK(r.status == RebuildStatus::malformed);
    CHECK(mentions(r, "a Bo deploy carries its source"));
    const std::string_view text = "contract Agreement\n";
    d.source = Bytes(text.begin(), text.end());
    r = rebuilt(d);
    CHECK(r.status == RebuildStatus::malformed);
    CHECK(mentions(r, "not a bo-source bundle"));
    d = deploy;
    d.language = "wasm";
    CHECK(rebuilt(d).status == RebuildStatus::malformed);
    // The edition line changes no code; a bundle whose edition is not the
    // source's is malformed.
    auto bundle = decode_source_bundle(*deploy.source);
    REQUIRE(bundle.has_value());
    const std::string original = bundle->source;
    bundle->source = "bo 1\n" + original;
    d = deploy;
    d.source = *encode_source_bundle(*bundle);
    CHECK(rebuilt(d).status == RebuildStatus::rebuilds);
    bundle->source = "bo 2\n" + original;
    d.source = *encode_source_bundle(*bundle);
    r = rebuilt(d);
    CHECK(r.status == RebuildStatus::malformed);
    CHECK(mentions(r, "the bundle says the source is Bo edition 1, but it is edition 2"));
    // Embedded packs that do not check are never another compiler's doing.
    d = deploy;
    d.compiler = other_codegen();
    bundle = decode_source_bundle(*deploy.source);
    bundle->embedded = {cbor::Value::map({{cbor::Value::text("id"), cbor::Value::text("zz")}})};
    bundle->packs.push_back(PackRef{"zz", 1, Bytes(32)});
    d.source = *encode_source_bundle(*bundle);
    r = rebuilt(d);
    CHECK(r.status == RebuildStatus::malformed);
    CHECK(mentions(r, "the embedded pack zz does not read"));
}

TEST_CASE("a source read with a company's own pack rebuilds from its bundle", "[bo][build]") {
    std::string keywords;
    for (const auto& [concept_id, word] : english_pack().keywords) {
        keywords += (keywords.empty() ? "" : ", ") + std::string("\"") + concept_id + "\": \"" +
                    word.spellings.front() + "\"";
    }
    PackRead read = read_pack(
        "{\"format\": 1, \"id\": \"acme-terms\", \"version\": 3, \"language\": \"en-x-acme\", "
        "\"name\": \"Acme terms\", \"official\": false, \"edition\": 1, \"reading\": "
        "{\"separation\": \"spaces\"}, \"keywords\": {" +
        keywords + "}, \"vocabulary\": {\"role.supplier\": \"vendor\"}}");
    REQUIRE(read.pack.has_value());
    PackSetRead with = make_pack_set({*read.pack});
    REQUIRE(with.set.has_value());
    constexpr std::string_view source =
        "contract Supply\nparties we, vendor\nrecord Order\n  amount HKD\ncan countersign by "
        "vendor\n  proposed -> signed\n";
    // Without the pack, vendor is just a name: another contract.
    const Compiled plain = compile(source, official_set());
    const protocol::ContractDeployBody deploy = deploy_of(source, *with.set);
    REQUIRE(plain.build.has_value());
    CHECK(plain.build->code != deploy.code);
    // The bundle embeds the pack, so anyone rebuilds it without being given it.
    const auto bundle = decode_source_bundle(*deploy.source);
    REQUIRE(bundle.has_value());
    CHECK(bundle->embedded.size() == 1);
    CHECK(rebuilt(deploy).status == RebuildStatus::rebuilds);
    // The same source, written with the official word, gives the same code.
    std::string official_words(source);
    for (std::size_t at = official_words.find("vendor"); at != std::string::npos;
         at = official_words.find("vendor")) {
        official_words.replace(at, 6, "supplier");
    }
    const Compiled spelled = compile(official_words, official_set());
    REQUIRE(spelled.build.has_value());
    CHECK(spelled.build->code == deploy.code);
}
