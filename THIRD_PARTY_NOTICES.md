# Third-party notices

CexChain is licensed under the [Apache License, Version 2.0](LICENSE). It is built with the
third-party components below, each under its own license. No third-party source code is copied
into this repository: the build fetches the components it compiles from the sources listed,
pinned by version and checked against a SHA-256 hash (`cmake/CexChainDependencies.cmake`,
`tools/wasm/build-openssl.sh`), or takes them from the system; test tools come from their
package managers.

Where each component ends up:

- **`cexchain`**: the command-line tool and ledger server (one binary), and the Docker image
  that carries it.
- **Browser verifier**: `cexchain-verify.html`, the self-contained page that
  `tools/wasm/build.sh` builds (and its module, `cexchain-verifier.js`). The page lists these
  components, their notices, and the full MIT and Apache 2.0 license texts itself, under
  "Third-party software in this page".
- **Build and test only**: used to build, test, fuzz, or generate test vectors; not part of
  anything CexChain distributes.

## Components that ship

| Component | Version | License | Source | Ships in |
| --- | --- | --- | --- | --- |
| OpenSSL (libcrypto, libssl) | 3.5 or later, from the system (the Docker image: Debian trixie's `libssl3t64`) | Apache-2.0 | <https://github.com/openssl/openssl> | `cexchain` (linked dynamically) |
| OpenSSL (libcrypto only) | 3.5.9 | Apache-2.0 | <https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz> | Browser verifier (compiled in) |
| JSON for Modern C++ (nlohmann/json) | 3.12.0 | MIT | <https://github.com/nlohmann/json> | `cexchain`, browser verifier (header-only, compiled in) |
| Asio (standalone) | 1.38.2 | BSL-1.0 | <https://github.com/chriskohlhoff/asio> | `cexchain` (header-only, compiled in) |
| NuRaft | 3.0.0 | Apache-2.0 | <https://github.com/eBay/NuRaft> | `cexchain` (linked statically) |
| QR Code generator library (C++) | 1.8.0 | MIT | <https://github.com/nayuki/QR-Code-generator> | `cexchain` (linked statically) |
| p11-kit's PKCS #11 header (`pkcs11.h`) | from the system's p11-kit, at build time | Permissive (notice below) | <https://github.com/p11-glue/p11-kit> | `cexchain`, when built with PKCS #11 support (the Docker image is); the header's types and constants only |
| GCC runtime (libstdc++, libgcc) | GCC 16 | GPL-3.0-or-later WITH GCC-exception-3.1 | <https://gcc.gnu.org/> | `cexchain` in the Docker image (linked statically); other builds link the system's C++ runtime dynamically |
| Emscripten runtime and system libraries | 6.0.10 | MIT (or NCSA); musl libc: MIT; LLVM libc++, libc++abi, libunwind, compiler-rt: Apache-2.0 WITH LLVM-exception; dlmalloc: CC0-1.0 | <https://github.com/emscripten-core/emscripten> | Browser verifier (compiled in) |
| Debian trixie (slim) base image and its packages (`ca-certificates`, `libssl3t64`) | trixie | Various, per package (`/usr/share/doc/*/copyright` in the image) | <https://www.debian.org/> | The Docker image only |

## Build and test only

| Component | Version | License | Source | Used for |
| --- | --- | --- | --- | --- |
| Catch2 | 3.16.0 | BSL-1.0 | <https://github.com/catchorg/Catch2> | The C++ tests |
| Playwright | 1.63.0 | Apache-2.0 | <https://github.com/microsoft/playwright> | The browser tests (`tests/browser`, from npm) |
| SoftHSM v2 | from the system's packages | BSD-2-Clause | <https://github.com/softhsm/SoftHSMv2> | Tests of keys on tokens (it stands in for hardware tokens) |
| libFuzzer (LLVM compiler-rt) | with Clang | Apache-2.0 WITH LLVM-exception | <https://llvm.org/> | The fuzz targets (`fuzz/`) |
| cryptography (Python) | 46 or later | Apache-2.0 OR BSD-3-Clause | <https://github.com/pyca/cryptography> | Generating test vectors (`tools/testvectors/`) |
| cbor2 (Python) | 5.6 or later | MIT | <https://github.com/agronholm/cbor2> | Generating test vectors (`tools/testvectors/`) |
| OpenSSL command-line tool | 3.5 or later | Apache-2.0 | <https://github.com/openssl/openssl> | Generating SM2 test vectors |
| Emscripten SDK (emsdk) | 6.0.10 | MIT | <https://github.com/emscripten-core/emsdk> | Building the browser verifier |
| Node.js | | MIT | <https://nodejs.org/> | Running the browser tests |
| GitHub Actions: `actions/checkout`, `actions/upload-artifact` | v7, v4 | MIT | <https://github.com/actions> | CI |
| `gcc:16-trixie` container image | | Various | <https://hub.docker.com/_/gcc> | CI, and the Docker image's build stage (not its final image) |

## Notices

### Apache License 2.0

OpenSSL, NuRaft, and (build and test only) Playwright and the OpenSSL command-line tool are
licensed under the Apache License, Version 2.0, the license of CexChain itself; its full text is
in [`LICENSE`](LICENSE) and at <https://www.apache.org/licenses/LICENSE-2.0>.

- **OpenSSL:** Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
- **NuRaft:** Copyright 2017-present eBay Inc. NuRaft contains code derived from cornerstone
  (<https://github.com/datatechnology/cornerstone>) and latency-collector
  (<https://github.com/greensky00/latency-collector>), under the Apache License 2.0, and from
  crc32 by Stephan Brumme (<https://github.com/stbrumme/crc32>), Copyright 2011-2016 Stephan
  Brumme, under the zlib License (below).
- **JSON for Modern C++** contains parts of Abseil, Copyright 2018 The Abseil Authors, under the
  Apache License 2.0.

The LLVM runtime libraries in the browser verifier (libc++, libc++abi, libunwind, compiler-rt)
are under the Apache License 2.0 with LLVM Exceptions, which waives the license's notice
conditions for portions embedded in compiled code; they are listed for completeness.

### MIT License

- **JSON for Modern C++ (nlohmann/json):** Copyright (c) 2013-2025 Niels Lohmann. It includes
  a UTF-8 decoder, Copyright (c) 2008-2009 Bjoern Hoehrmann, and the Grisu2 algorithm,
  Copyright (c) 2009 Florian Loitsch, both under the MIT License, and Hedley by Evan Nemerson
  under CC0-1.0.
- **QR Code generator library:** Copyright (c) Project Nayuki.
- **Emscripten:** Copyright (c) 2010-2014 Emscripten authors (Emscripten is available under the
  MIT License or the University of Illinois/NCSA Open Source License; CexChain uses it under the
  MIT License).
- **musl libc** (in Emscripten): Copyright (c) 2005-2020 Rich Felker, et al.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Boost Software License 1.0

- **Asio:** Copyright (c) 2003-2026 Christopher M. Kohlhoff.
- **Catch2** (tests only): Copyright Catch2 Authors.

```
Boost Software License - Version 1.0 - August 17th, 2003

Permission is hereby granted, free of charge, to any person or organization
obtaining a copy of the software and accompanying documentation covered by
this license (the "Software") to use, reproduce, display, distribute,
execute, and transmit the Software, and to prepare derivative works of the
Software, and to permit third-parties to whom the Software is furnished to
do so, all subject to the following:

The copyright notices in the Software and this entire statement, including
the above license grant, this restriction and the following disclaimer,
must be included in all copies of the Software, in whole or in part, and
all derivative works of the Software, unless such copies or derivative
works are solely in the form of machine-executable object code generated by
a source language processor.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

### zlib License

- **crc32** (in NuRaft): Copyright 2011-2016 Stephan Brumme.

```
This software is provided 'as-is', without any express or implied
warranty.  In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
```

### p11-kit's PKCS #11 header

```
pkcs11.h
Copyright 2006, 2007 g10 Code GmbH
Copyright 2006 Andreas Jellinghaus
Copyright 2017, 2021-2025 Red Hat, Inc.

This file is free software; as a special exception the author gives
unlimited permission to copy and/or distribute it, with or without
modifications, as long as this notice is preserved.

This file is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY, to the extent permitted by law; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.
```

### GCC runtime library exception

The Docker image's `cexchain` links GCC's C++ runtime (libstdc++ and libgcc) statically. They
are licensed under the GNU General Public License version 3 or later with the GCC Runtime
Library Exception 3.1, which permits distributing the compiled program under terms of the
distributor's choice (<https://www.gnu.org/licenses/gcc-exception-3.1.html>).

### CC0-1.0 (public domain)

Hedley (in JSON for Modern C++) and dlmalloc (in the browser verifier's Emscripten runtime)
are dedicated to the public domain under CC0-1.0
(<https://creativecommons.org/publicdomain/zero/1.0/>).
