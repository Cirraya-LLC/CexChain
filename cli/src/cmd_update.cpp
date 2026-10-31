// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Update checks, notify only: a signed release manifest says which version
// is newest; `update check` says so, and `update install` downloads this
// platform's package, checks it, and hands it to the platform's installer
// for the person to run. Nothing installs itself.

#include <filesystem>
#include <optional>
#include <print>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cexchain/app/access.hpp>
#include <cexchain/app/updates.hpp>

#include "commands.hpp"
#include "output.hpp"

extern char** environ;

namespace cexchain::cli {

namespace {

#ifndef CEXCHAIN_UPDATE_URL
#define CEXCHAIN_UPDATE_URL ""
#endif

bool is_web(std::string_view source) {
    return source.starts_with("https://") || source.starts_with("http://");
}

/// A file named by a URL or a path, at most `max` bytes. A web server's
/// redirects are followed (a release's "latest" link is one), at most five,
/// never from https to http.
Bytes fetch(const std::string& source, std::size_t max) {
    if (!is_web(source)) {
        if (!std::filesystem::is_regular_file(source)) {
            throw CommandError{"no such file: " + source};
        }
        return read_file(source);
    }
    node::ClientOptions options;
    options.max_body = max;
    options.follow_redirects = false;
    std::string url = source;
    for (int redirects = 0;; ++redirects) {
        // The origin, then the path with any query (a download's is signed).
        const std::size_t path = url.find('/', url.find("://") + 3);
        const std::string origin = url.substr(0, path);
        const std::string target = path == std::string::npos ? "/" : url.substr(path);
        node::Client client(unwrap(node::Url::parse(origin), "reading the URL"), options);
        const auto response = unwrap(client.request("GET", target), "fetching " + url);
        const auto location = response.header("location");
        if ((response.status == 301 || response.status == 302 || response.status == 303 ||
             response.status == 307 || response.status == 308) &&
            location && redirects < 5) {
            if (!location->starts_with("https://") &&
                !(location->starts_with("http://") && url.starts_with("http://"))) {
                throw CommandError{"fetching " + source + ": redirected to " +
                                   std::string(*location)};
            }
            url = std::string(*location);
            continue;
        }
        if (response.status != 200) {
            throw CommandError{"fetching " + url + ": status " + std::to_string(response.status)};
        }
        return response.body;
    }
}

struct Checked {
    app::ReleaseManifest manifest;
    std::string source;
    int compared = 0;
};

/// The manifest, its signature checked, compared with this version; or
/// nothing if this build checks no updates.
std::optional<Checked> checked_manifest(const Args& args) {
    std::optional<crypto::PublicKey> key;
    if (const auto file = args.get("release-key")) {
        key = load_public_key(*file);
    } else {
        key = app::built_in_release_key();
    }
    const std::string source = args.get("manifest").value_or(CEXCHAIN_UPDATE_URL);
    if (!key || source.empty()) {
        return std::nullopt;
    }
    const Bytes manifest = fetch(source, 1024 * 1024);
    const Bytes signature = fetch(source + ".sig", 1024);
    auto read = app::read_release_manifest(shared_provider(), manifest, signature, *key);
    if (!read) {
        throw CommandError{std::string(read.error().detail)};
    }
    const auto compared = app::compare_versions(read->version, CEXCHAIN_VERSION);
    if (!compared) {
        throw CommandError{"the manifest's version is not one: " + read->version};
    }
    return Checked{std::move(*read), source, *compared};
}

/// The kinds of package this computer installs, the first it prefers first.
std::vector<std::string> package_kinds() {
#if defined(__APPLE__)
    return {"pkg", "tar.gz"};
#else
    std::vector<std::string> out;
    if (std::filesystem::exists("/usr/bin/dpkg")) {
        out.emplace_back("deb");
    }
    if (std::filesystem::exists("/usr/bin/rpm")) {
        out.emplace_back("rpm");
    }
    out.emplace_back("tar.gz");
    return out;
#endif
}

int refused(const Args& args, const CommandError& e) {
    if (args.json()) {
        print_json({{"ok", false}, {"error", e.message}});
    } else {
        std::println("NOT VERIFIED: {}", e.message);
    }
    return exit_not_verified;
}

} // namespace

int cmd_update_check(const Args& args) {
    std::optional<Checked> checked;
    try {
        checked = checked_manifest(args);
    } catch (const CommandError& e) {
        if (e.message.find("not signed") != std::string::npos) {
            return refused(args, e);
        }
        throw;
    }
    if (!checked) {
        if (args.json()) {
            print_json({{"checked", false}, {"current", CEXCHAIN_VERSION}});
        } else {
            std::println("this build of cexchain {} checks no updates (no release key or "
                         "manifest built in; see --manifest and --release-key)",
                         CEXCHAIN_VERSION);
        }
        return exit_ok;
    }
    const bool newer = checked->compared > 0;
    const auto file =
        app::release_file_for(checked->manifest, app::this_platform(), package_kinds());
    if (args.json()) {
        print_json({{"checked", true},
                    {"current", CEXCHAIN_VERSION},
                    {"latest", checked->manifest.version},
                    {"newer", newer},
                    {"released", checked->manifest.released},
                    {"notes", checked->manifest.notes},
                    {"platform", app::this_platform()},
                    {"file", file ? Json(file->name) : Json()}});
        return exit_ok;
    }
    if (!newer) {
        std::println("cexchain {} is up to date (the newest is {})", CEXCHAIN_VERSION,
                     checked->manifest.version);
        return exit_ok;
    }
    std::println("cexchain {} is available (released {}; you have {})", checked->manifest.version,
                 checked->manifest.released, CEXCHAIN_VERSION);
    if (!checked->manifest.notes.empty()) {
        std::println("what changed: {}", checked->manifest.notes);
    }
    if (file) {
        std::println("to update: cexchain update install");
    } else {
        std::println("no package for this computer ({}) in this release", app::this_platform());
    }
    return exit_ok;
}

int cmd_update_install(const Args& args) {
    std::optional<Checked> checked;
    try {
        checked = checked_manifest(args);
    } catch (const CommandError& e) {
        if (e.message.find("not signed") != std::string::npos) {
            return refused(args, e);
        }
        throw;
    }
    if (!checked) {
        throw CommandError{"this build checks no updates (no release key or manifest built in)"};
    }
    if (checked->compared <= 0) {
        std::println("cexchain {} is up to date", CEXCHAIN_VERSION);
        return exit_ok;
    }
    const auto file =
        app::release_file_for(checked->manifest, app::this_platform(), package_kinds());
    if (!file) {
        throw CommandError{"no package for this computer (" + app::this_platform() +
                           ") in this release"};
    }
    if (!app::plain_file_name(file->name)) {
        throw CommandError{"the manifest names a package with a path: " + file->name};
    }
    // A relative URL is beside the manifest.
    std::string url = file->url;
    if (!is_web(url) && !std::filesystem::path(url).is_absolute()) {
        url = (std::filesystem::path(checked->source).parent_path() / url).string();
    }
    const Bytes package = fetch(url, static_cast<std::size_t>(file->size) + 1);
    const auto digest =
        unwrap(shared_provider().digest(crypto::HashAlg::sha256, package), "hashing");
    if (package.size() != file->size || to_hex(digest.bytes()) != file->sha256) {
        return refused(args, CommandError{"the package is not the one the manifest names"});
    }
    const std::filesystem::path dir = args.get("dir").value_or(".");
    std::filesystem::create_directories(dir);
    const std::filesystem::path target = dir / file->name;
    write_file(target, package, false);
    std::string how;
    if (file->kind == "deb") {
        how = "sudo apt install " + std::filesystem::absolute(target).string();
    } else if (file->kind == "rpm") {
        how = "sudo dnf install " + std::filesystem::absolute(target).string();
    } else if (file->kind == "pkg") {
        how = "open " + std::filesystem::absolute(target).string();
    } else {
        how = "tar -xzf " + std::filesystem::absolute(target).string() + " -C ~/.local";
    }
    bool opened = false;
    if (file->kind == "pkg" && !args.has("no-open")) {
        // The Installer, for the person to go through.
        std::string program = "open";
        std::string path = target.string();
        char* argv[] = {program.data(), path.data(), nullptr};
        pid_t child = 0;
        if (::posix_spawnp(&child, "open", nullptr, nullptr, argv, environ) == 0) {
            int status = 0;
            ::waitpid(child, &status, 0);
            opened = true;
        }
    }
    if (args.json()) {
        print_json({{"version", checked->manifest.version},
                    {"file", target.string()},
                    {"install", how},
                    {"opened", opened}});
        return exit_ok;
    }
    std::println("downloaded cexchain {} to {} (its size and SHA-256 checked)",
                 checked->manifest.version, target.string());
    if (opened) {
        std::println("the Installer is open: go through it to update");
    } else {
        std::println("to install it: {}", how);
    }
    return exit_ok;
}

int cmd_update_sign(const Args& args) {
    const std::filesystem::path manifest = args.positional().front();
    const Bytes bytes = read_file(manifest);
    // Checked as a manifest first, so that only one is ever signed.
    const auto signer = load_signer(args.need("as"), args);
    Bytes message(app::release_manifest_context.begin(), app::release_manifest_context.end());
    message.push_back(0);
    message.insert(message.end(), bytes.begin(), bytes.end());
    const Bytes signature = unwrap(signer->sign(message), "signing");
    if (!app::read_release_manifest(shared_provider(), bytes, signature, signer->public_key())) {
        throw CommandError{"not a release manifest (product, version, files)"};
    }
    const std::filesystem::path out = args.get("out").value_or(manifest.string() + ".sig");
    write_file(out, signature, false);
    if (args.json()) {
        print_json({{"signature", out.string()}});
    } else {
        std::println("signed {}: {}", manifest.string(), out.string());
    }
    return exit_ok;
}

} // namespace cexchain::cli
