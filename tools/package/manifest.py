#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""A release manifest for the packages in a directory, for `cexchain update
check` (app/include/cexchain/app/updates.hpp has its form):

    tools/package/manifest.py VERSION DIR [--released YYYY-MM-DD]
        [--notes URL] [--base-url URL] > release-manifest.json

Each file's URL is its name (beside the manifest), or --base-url and its
name. Sign it offline with the release key, then publish both:

    cexchain update sign release-manifest.json --as release.key

Standard library only."""

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import sys

LINUX_ARCH = {"amd64": "x86_64", "arm64": "aarch64", "x86_64": "x86_64", "aarch64": "aarch64"}

# File names as tools/package/linux.sh and macos.sh write them.
PATTERNS = [
    (re.compile(r"^cexchain_(?P<v>[^_]+)_(?P<a>[a-z0-9_]+)\.deb$"), "linux", "deb"),
    (re.compile(r"^cexchain-(?P<v>.+)-1\.(?P<a>[a-z0-9_]+)\.rpm$"), "linux", "rpm"),
    (re.compile(r"^cexchain-(?P<v>.+)-linux-(?P<a>[a-z0-9_]+)\.tar\.gz$"), "linux", "tar.gz"),
    (re.compile(r"^CexChain-(?P<v>.+)-macos-(?P<a>[a-z0-9_]+)\.pkg$"), "macos", "pkg"),
    (re.compile(r"^cexchain-(?P<v>.+)-macos-(?P<a>[a-z0-9_]+)\.tar\.gz$"), "macos", "tar.gz"),
]


def describe(path, version):
    # The packages carry the version without a pre-release part ("-alpha"):
    # CMake's project version.
    for pattern, system, kind in PATTERNS:
        m = pattern.match(path.name)
        if m and m.group("v") == version.split("-")[0]:
            arch = m.group("a")
            arch = LINUX_ARCH.get(arch, arch) if system == "linux" else arch
            return f"{system}-{arch}", kind
    return None


def main():
    parser = argparse.ArgumentParser(
        description="A release manifest for the packages in a directory")
    parser.add_argument("version")
    parser.add_argument("directory", type=pathlib.Path)
    parser.add_argument("--released", default=datetime.date.today().isoformat())
    parser.add_argument("--notes", default="")
    parser.add_argument("--base-url", default="")
    args = parser.parse_args()
    files = []
    for path in sorted(args.directory.iterdir()):
        described = describe(path, args.version) if path.is_file() else None
        if described is None:
            continue
        platform, kind = described
        data = path.read_bytes()
        url = args.base_url.rstrip("/") + "/" + path.name if args.base_url else path.name
        files.append({"platform": platform, "kind": kind, "name": path.name, "url": url,
                      "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    if not files:
        sys.exit(f"no packages of version {args.version} in {args.directory}")
    json.dump({"product": "cexchain", "version": args.version, "released": args.released,
               "notes": args.notes, "files": files}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
