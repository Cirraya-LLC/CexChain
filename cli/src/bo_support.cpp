// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Checking a Bo deploy's source against its code (bo_support.hpp). With the
// compiler, the source is rebuilt; without it, the front end still checks
// the bundle and its packs, and the report says the code was not rebuilt.

#include <format>
#include <string>

#include <cexchain/bo/pack.hpp>
#include <cexchain/bo/source.hpp>
#if defined(CEXCHAIN_HAVE_BO)
#include <cexchain/bo/build.hpp>
#endif

#include "bo_support.hpp"

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
        opened.problem == bo::OpenProblem::conflict) {
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

std::string bundle_text(const SourceCheck& check) {
    if (!check.bundle) {
        return "Bo";
    }
    const bo::SourceBundle& b = *check.bundle;
    std::string packs;
    for (const bo::PackRef& ref : b.packs) {
        packs += std::format("{}{} {}", packs.empty() ? "" : ", ", ref.id, ref.version);
    }
    return std::format(
        "Bo, edition {}: {} bytes of source; packs {}{}", b.edition, b.source.size(), packs,
        b.embedded.empty() ? std::string()
                           : std::format(" ({} embedded, not official)", b.embedded.size()));
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
