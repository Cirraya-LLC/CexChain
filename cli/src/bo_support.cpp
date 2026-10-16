// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Checking a Bo deploy's source against its code (bo_support.hpp). With the
// compiler, the source is rebuilt; without it, the front end still checks
// the bundle and its packs, and the report says the code was not rebuilt.

#include <cstdlib>
#include <format>
#include <string>

#include <cexchain/bo/checker.hpp>
#include <cexchain/bo/explain.hpp>
#include <cexchain/bo/lexer.hpp>
#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/parser.hpp>
#include <cexchain/bo/source.hpp>
#if defined(CEXCHAIN_HAVE_BO)
#include <cexchain/bo/build.hpp>
#endif

#include "bo_support.hpp"
#include "commands.hpp"

namespace cexchain::cli {

bool have_bo_compiler() noexcept {
#if defined(CEXCHAIN_HAVE_BO)
    return true;
#else
    return false;
#endif
}

SourceCheck check_bo_source(const protocol::ContractDeployBody& deploy,
                            const crypto::Provider& provider, const crypto::HashAlg hash) {
    SourceCheck check;
#if defined(CEXCHAIN_HAVE_BO)
    bo::Rebuild rebuilt = bo::rebuild(deploy, provider, hash);
    check.status = bo::rebuild_status_names[static_cast<std::size_t>(rebuilt.status)];
    check.detail = std::move(rebuilt.detail);
    check.failed = rebuilt.status == bo::RebuildStatus::differs ||
                   rebuilt.status == bo::RebuildStatus::malformed;
    check.bundle = std::move(rebuilt.bundle);
#else
    // What the front end can check: the bundle, and the packs it names.
    const auto malformed = [&](std::string detail) {
        check.status = "malformed";
        check.detail = std::move(detail);
        check.failed = true;
        return check;
    };
    if (!deploy.source) {
        return malformed("a Bo deploy carries its source, and this one does not: its code "
                         "cannot be checked against a source");
    }
    auto bundle = bo::decode_source_bundle(*deploy.source);
    if (!bundle) {
        return malformed(std::format("the deploy's source is not a bo-source bundle: {}",
                                     bundle.error().detail));
    }
    check.bundle = std::move(*bundle);
    const bo::OpenedSource opened = bo::open_source_bundle(*check.bundle, provider, hash);
    if (opened.problem == bo::OpenProblem::embedded ||
        opened.problem == bo::OpenProblem::conflict ||
        opened.problem == bo::OpenProblem::uses_differ) {
        return malformed(opened.detail);
    }
    check.status = "not-rebuilt";
    check.detail = "this build of cexchain has no Bo compiler (it needs GCC 16), so the source "
                   "was not rebuilt: run contract verify with a build that has it";
    if (opened.problem != bo::OpenProblem::none) {
        check.detail += "; also, " + opened.detail;
    }
#endif
    return check;
}

const bo::Pack* reader_language(const std::optional<std::string>& want,
                                const std::span<const bo::Pack> extra) {
    std::optional<std::string> chosen = want;
    if (!chosen) {
        if (const char* env = std::getenv("CEXCHAIN_LANGUAGE"); env != nullptr && *env != '\0') {
            chosen = env;
        }
    }
    if (!chosen) {
        return &bo::english_pack();
    }
    if (const bo::Pack* pack = bo::find_language(bo::official_packs(), *chosen)) {
        return pack;
    }
    if (const bo::Pack* pack = bo::find_language(extra, *chosen)) {
        return pack;
    }
    throw UsageError{"no pack for the language " + *chosen +
                     " (en, zh-Hant-HK, zh-Hans-CN, or a pack given with --pack)"};
}

const bo::Pack* environment_language() noexcept {
    if (const char* env = std::getenv("CEXCHAIN_LANGUAGE"); env != nullptr && *env != '\0') {
        if (const bo::Pack* pack = bo::find_language(bo::official_packs(), env)) {
            return pack;
        }
    }
    return &bo::english_pack();
}

Json explained_json(const bo::Explained& e) {
    Json sections = Json::array();
    for (const bo::ExplainedSection& s : e.sections) {
        Json clauses = Json::array();
        for (const bo::ExplainedClause& c : s.clauses) {
            Json clause = {
                {"number", c.number}, {"kind", c.kind}, {"text", c.text}, {"rules", Json::array()}};
            for (const std::string_view rule : c.rules) {
                clause["rules"].push_back(rule);
            }
            if (!c.function.empty()) {
                clause["function"] = c.function;
            }
            if (c.requirement != 0) {
                clause["requirement"] = c.requirement;
            }
            clauses.push_back(std::move(clause));
        }
        sections.push_back({{"number", s.number},
                            {"kind", s.kind},
                            {"title", s.title},
                            {"note", s.note},
                            {"clauses", std::move(clauses)}});
    }
    Json rules = Json::array();
    for (const auto& [id, text] : e.rules) {
        rules.push_back({{"id", id}, {"text", text}});
    }
    return {{"language", e.language},
            {"title", e.title},
            {"intro", e.intro},
            {"packs", e.packs},
            {"sections", std::move(sections)},
            {"rules", std::move(rules)},
            {"text", e.text}};
}

DeployText explain_deploy(const protocol::ContractDeployBody& deploy,
                          const crypto::Provider& provider, const crypto::HashAlg hash,
                          const std::optional<std::string>& language) {
    DeployText out;
    out.check = check_bo_source(deploy, provider, hash);
    if (out.check.status != "rebuilds" || !out.check.bundle) {
        return out;
    }
    // Read exactly as the rebuild read it: the packs the bundle names, at
    // their versions, each digest checked.
    const bo::SourceBundle& bundle = *out.check.bundle;
    const bo::OpenedSource opened = bo::open_source_bundle(bundle, provider, hash);
    if (!opened.packs) {
        return out;
    }
    std::vector<bo::Pack> given;
    for (const bo::Pack& pack : opened.packs->packs()) {
        if (!pack.official) {
            given.push_back(pack);
        }
    }
    const bo::Pack* reader = reader_language(language, given);
    const bo::Lexicon lexicon(*opened.packs);
    const bo::Lexed lexed = bo::lex(bundle.source, lexicon);
    const bo::Parsed parsed = bo::parse(bundle.source, lexed);
    bo::Checked checked = bo::check(bundle.source, parsed.file);
    out.explained = bo::explain(checked.model, reader);
    out.model = std::move(checked.model);
    return out;
}

std::string bundle_text(const SourceCheck& check) {
    if (!check.bundle) {
        return "Bo";
    }
    const bo::SourceBundle& b = *check.bundle;
    std::string packs;
    for (const bo::PackRef& ref : b.packs) {
        packs += std::format("{}{} {}", packs.empty() ? "" : ", ", ref.id, ref.version);
    }
    std::string vocabulary;
    for (const bo::PackRef& ref : b.vocabulary) {
        vocabulary += std::format("{}{} {}", vocabulary.empty() ? "" : ", ", ref.id, ref.version);
    }
    return std::format(
        "Bo, edition {}: {} bytes of source; packs {}{}{}", b.edition, b.source.size(), packs,
        b.embedded.empty() ? std::string()
                           : std::format(" ({} embedded, not official)", b.embedded.size()),
        vocabulary.empty() ? std::string() : "; vocabulary packs " + vocabulary);
}

std::string source_check_text(const SourceCheck& check) {
    if (check.status == "rebuilds") {
        return "rebuilds: " + check.detail;
    }
    if (check.status == "differs") {
        return "DOES NOT REBUILD: " + check.detail;
    }
    if (check.status == "malformed") {
        return "MALFORMED: " + check.detail;
    }
    return "not rebuilt: " + check.detail;
}

Json source_check_json(const SourceCheck& check, const protocol::ContractDeployBody& deploy) {
    Json packs = Json::array();
    Json edition = nullptr;
    Json size = nullptr;
    if (check.bundle) {
        for (const bo::PackRef& ref : check.bundle->packs) {
            packs.push_back(
                {{"id", ref.id}, {"version", ref.version}, {"digest", to_hex(ref.digest)}});
        }
        edition = check.bundle->edition;
        size = check.bundle->source.size();
    }
#if defined(CEXCHAIN_HAVE_BO)
    const Json ours = bo::compiler_string();
#else
    const Json ours = nullptr;
#endif
    return {{"status", check.status},
            {"detail", check.detail},
            {"failed", check.failed},
            {"compiler", deploy.compiler},
            {"this_compiler", ours},
            {"edition", edition},
            {"source_size", size},
            {"bundle_size", deploy.source ? Json(deploy.source->size()) : Json(nullptr)},
            {"packs", packs}};
}

#if !defined(CEXCHAIN_HAVE_BO)
BoDeploy bo_deploy_body(const Args&, const std::string&, const crypto::Provider&, crypto::HashAlg) {
    throw CommandError{"this build of cexchain has no Bo compiler (it needs GCC 16): deploy Bo "
                       "contracts with a build that has it"};
}
#endif

} // namespace cexchain::cli
