# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The kanhe tool and ledger server.
#
#   docker build -t kanhe .
#   docker run --rm -v kanhe:/data kanhe init ...
#   docker run -d -v kanhe:/data -p 8080:8080 kanhe \
#       serve --listen 0.0.0.0:8080 --log-key /data/log.key --passphrase-file /run/secrets/log
#
# The ledger lives in the /data volume ($KANHE_LEDGER=/data/ledger).

FROM gcc:16-trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake ninja-build libssl-dev libp11-kit-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Parallel compile jobs (default: all cores); lower it on small machines.
ARG BUILD_JOBS=
# GCC 16's C++ library is newer than Debian's: link it in. A server's image:
# the chain (kanhe) and the search index beside it (kanhe-index).
RUN cmake --preset gcc-release -DCMAKE_CXX_COMPILER=g++ -DKANHE_BUILD_TESTS=OFF \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
 && cmake --build --preset gcc-release --target kanhe kanhe-index ${BUILD_JOBS:+-j $BUILD_JOBS} \
 && strip build/gcc-release/bin/kanhe build/gcc-release/bin/kanhe-index \
 && build/gcc-release/bin/kanhe version \
 && build/gcc-release/bin/kanhe-index version > /dev/null

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin kanhe \
 && mkdir -p /data && chown kanhe:kanhe /data && chmod 700 /data
COPY --from=build /src/build/gcc-release/bin/kanhe /src/build/gcc-release/bin/kanhe-index /usr/local/bin/
# The license, and the notices of the third-party code compiled into the binary.
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/kanhe/
USER kanhe
ENV KANHE_LEDGER=/data/ledger
VOLUME /data
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["kanhe"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
