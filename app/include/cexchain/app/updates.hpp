// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <cexchain/core/bytes.hpp>
#include <cexchain/core/crypto.hpp>
#include <cexchain/core/error.hpp>

/// Update checks, notify only: a release manifest, signed by Cirraya's
/// release key, says which version is the newest and where its packages
/// are. The binary trusts the key built into it (CMake
/// -DCEXCHAIN_RELEASE_KEY=<64 hex digits>, an Ed25519 public key); a build
/// without one checks no updates unless given a key to trust. A manifest is
/// JSON:
///   {"product": "cexchain", "version": "0.2.0", "released": "2026-11-15",
///    "notes": URL, "files": [{"platform": "linux-x86_64", "kind": "deb",
///    "name": ..., "url": ..., "size": N, "sha256": hex}, ...]}
/// and its signature (the manifest's URL with ".sig") is the 64 bytes of an
/// Ed25519 signature over "CexChain release manifest v1", a zero byte, and
/// the manifest's bytes.
namespace cexchain::app {

inline constexpr std::string_view release_manifest_context = "CexChain release manifest v1";

struct ReleaseFile {
    std::string platform;
    std::string kind;
    std::string name;
    std::string url;
    std::uint64_t size = 0;
    std::string sha256;
};

struct ReleaseManifest {
    std::string version;
    std::string released;
    std::string notes;
    std::vector<ReleaseFile> files;
};

/// The release key built into this binary, if any.
[[nodiscard]] std::optional<crypto::PublicKey> built_in_release_key();

/// Checks the signature, then reads the manifest; Errc::verification_failed
/// if the signature does not verify, Errc::malformed if it is not one.
[[nodiscard]] Result<ReleaseManifest> read_release_manifest(const crypto::Provider& provider,
                                                            ByteView manifest, ByteView signature,
                                                            const crypto::PublicKey& key);

/// -1, 0, or 1 as `a` is older than, the same as, or newer than `b`
/// ("MAJOR.MINOR.PATCH", optionally "-pre..." which is older than without).
/// nullopt if either is not a version.
[[nodiscard]] std::optional<int> compare_versions(std::string_view a, std::string_view b);

/// This computer's platform, as manifests name it: "linux-x86_64",
/// "linux-aarch64", "macos-arm64", "macos-x86_64".
[[nodiscard]] std::string this_platform();

/// The file for this platform, of the first of `kinds` the manifest has.
[[nodiscard]] std::optional<ReleaseFile> release_file_for(const ReleaseManifest& manifest,
                                                          std::string_view platform,
                                                          const std::vector<std::string>& kinds);

} // namespace cexchain::app
