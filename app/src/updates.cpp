// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <system_error>

#include <nlohmann/json.hpp>

#include <cexchain/app/errors.hpp>
#include <cexchain/app/support.hpp>
#include <cexchain/app/updates.hpp>
#include <cexchain/node/client.hpp>

#ifndef CEXCHAIN_RELEASE_KEY
#define CEXCHAIN_RELEASE_KEY ""
#endif
#ifndef CEXCHAIN_UPDATE_URL
#define CEXCHAIN_UPDATE_URL ""
#endif

namespace cexchain::app {

namespace {

bool hex_text(std::string_view text, std::size_t size) {
    return text.size() == size && std::ranges::all_of(text, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

struct Version {
    std::uint64_t major = 0;
    std::uint64_t minor = 0;
    std::uint64_t patch = 0;
    std::string pre;
};

std::optional<Version> parse_version(std::string_view text) {
    if (text.starts_with('v')) {
        text.remove_prefix(1);
    }
    Version v;
    const std::size_t dash = text.find('-');
    if (dash != std::string_view::npos) {
        v.pre = std::string(text.substr(dash + 1));
        if (v.pre.empty()) {
            return std::nullopt;
        }
        text = text.substr(0, dash);
    }
    std::uint64_t* parts[] = {&v.major, &v.minor, &v.patch};
    for (std::size_t i = 0; i < 3; ++i) {
        const std::size_t dot = i < 2 ? text.find('.') : text.size();
        if (dot == std::string_view::npos || dot == 0) {
            return std::nullopt;
        }
        const std::string_view digits = text.substr(0, dot);
        const auto [end, ec] =
            std::from_chars(digits.data(), digits.data() + digits.size(), *parts[i]);
        if (ec != std::errc{} || end != digits.data() + digits.size()) {
            return std::nullopt;
        }
        text = i < 2 ? text.substr(dot + 1) : std::string_view();
    }
    return v;
}

} // namespace

std::optional<crypto::PublicKey> built_in_release_key() {
    constexpr std::string_view hex = CEXCHAIN_RELEASE_KEY;
    if (!hex_text(hex, 64)) {
        return std::nullopt;
    }
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    return crypto::PublicKey{crypto::SigAlg::ed25519, *bytes};
}

std::string built_in_update_url() {
    return CEXCHAIN_UPDATE_URL;
}

Bytes fetch_release_file(const std::string& source, std::size_t max) {
    if (!source.starts_with("https://") && !source.starts_with("http://")) {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(source, ec)) {
            throw ActionError{"no such file: " + source};
        }
        if (std::filesystem::file_size(source, ec) > max) {
            throw ActionError{"too large: " + source};
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
        auto base = node::Url::parse(origin);
        if (!base) {
            throw ActionError{"not a URL: " + url};
        }
        node::Client client(std::move(*base), options);
        auto response = client.request("GET", target);
        if (!response) {
            throw ActionError{"fetching " + url + ": " + std::string(response.error().detail)};
        }
        const auto location = response->header("location");
        const int status = response->status;
        if ((status == 301 || status == 302 || status == 303 || status == 307 || status == 308) &&
            location && redirects < 5) {
            if (!location->starts_with("https://") &&
                !(location->starts_with("http://") && url.starts_with("http://"))) {
                throw ActionError{"fetching " + source + ": redirected to " +
                                  std::string(*location)};
            }
            url = std::string(*location);
            continue;
        }
        if (status != 200) {
            throw ActionError{"fetching " + url + ": status " + std::to_string(status)};
        }
        return std::move(response->body);
    }
}

UpdateCheck check_for_update(const crypto::Provider& provider, const std::string& source,
                             const crypto::PublicKey& key, std::string_view current) {
    const Bytes manifest = fetch_release_file(source, 1024 * 1024);
    const Bytes signature = fetch_release_file(source + ".sig", 1024);
    auto read = read_release_manifest(provider, manifest, signature, key);
    if (!read) {
        if (read.error().code == Errc::verification_failed) {
            throw NotVerified{std::string(read.error().detail)};
        }
        throw ActionError{std::string(read.error().detail)};
    }
    const auto compared = compare_versions(read->version, current);
    if (!compared) {
        throw ActionError{"the manifest's version is not one: " + read->version};
    }
    return UpdateCheck{std::move(*read), source, *compared};
}

Result<ReleaseManifest> read_release_manifest(const crypto::Provider& provider, ByteView manifest,
                                              ByteView signature, const crypto::PublicKey& key) {
    Bytes message(release_manifest_context.begin(), release_manifest_context.end());
    message.push_back(0);
    message.insert(message.end(), manifest.begin(), manifest.end());
    if (!provider.verify(key, message, signature)) {
        return fail(Errc::verification_failed, "the manifest is not signed by the release key");
    }
    const auto j = nlohmann::json::parse(manifest.begin(), manifest.end(), nullptr, false);
    if (!j.is_object() || j.value("product", "") != "cexchain" || !j.contains("version") ||
        !j["version"].is_string() || !compare_versions(j["version"].get<std::string>(), "0.0.0") ||
        !j.contains("files") || !j["files"].is_array()) {
        return fail(Errc::malformed, "not a release manifest");
    }
    ReleaseManifest out;
    out.version = j["version"].get<std::string>();
    out.released = j.value("released", "");
    out.notes = j.value("notes", "");
    for (const auto& f : j["files"]) {
        if (!f.is_object() || !f.contains("url") || !f["url"].is_string() ||
            !f.contains("sha256") || !f["sha256"].is_string() ||
            !hex_text(f["sha256"].get<std::string>(), 64) || !f.contains("size") ||
            !f["size"].is_number_unsigned()) {
            return fail(Errc::malformed, "a release file without its URL, size, or SHA-256");
        }
        out.files.push_back({f.value("platform", ""), f.value("kind", ""), f.value("name", ""),
                             f["url"].get<std::string>(), f["size"].get<std::uint64_t>(),
                             f["sha256"].get<std::string>()});
    }
    return out;
}

std::optional<int> compare_versions(std::string_view a, std::string_view b) {
    const auto x = parse_version(a);
    const auto y = parse_version(b);
    if (!x || !y) {
        return std::nullopt;
    }
    for (const auto& [p, q] : {std::pair{x->major, y->major}, std::pair{x->minor, y->minor},
                               std::pair{x->patch, y->patch}}) {
        if (p != q) {
            return p < q ? -1 : 1;
        }
    }
    if (x->pre == y->pre) {
        return 0;
    }
    if (x->pre.empty() || y->pre.empty()) {
        // A pre-release comes before its release.
        return x->pre.empty() ? 1 : -1;
    }
    return x->pre < y->pre ? -1 : 1;
}

std::string this_platform() {
#if defined(__APPLE__)
    const std::string os = "macos";
#else
    const std::string os = "linux";
#endif
#if defined(__aarch64__) || defined(__arm64__)
    return os + (os == "macos" ? "-arm64" : "-aarch64");
#else
    return os + "-x86_64";
#endif
}

std::optional<ReleaseFile> release_file_for(const ReleaseManifest& manifest,
                                            std::string_view platform,
                                            const std::vector<std::string>& kinds) {
    for (const std::string& kind : kinds) {
        for (const ReleaseFile& f : manifest.files) {
            if (f.platform == platform && f.kind == kind) {
                return f;
            }
        }
    }
    return std::nullopt;
}

} // namespace cexchain::app
