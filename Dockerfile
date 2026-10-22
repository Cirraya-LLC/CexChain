# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The cexchain tool and ledger server.
#
#   docker build -t cexchain .
#   docker run --rm -v cexchain:/data cexchain init ...
#   docker run -d -v cexchain:/data -p 8080:8080 cexchain \
#       serve --listen 0.0.0.0:8080 --log-key /data/log.key --passphrase-file /run/secrets/log
#
# The ledger lives in the /data volume ($CEXCHAIN_LEDGER=/data/ledger).

FROM gcc:16-trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake ninja-build libssl-dev libp11-kit-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Parallel compile jobs (default: all cores); lower it on small machines.
ARG BUILD_JOBS=
# GCC 16's C++ library is newer than Debian's: link it in. The preset requires
# the Bo compiler (CEXCHAIN_BO=ON), so the image always has the bo commands.
RUN cmake --preset gcc-release -DCMAKE_CXX_COMPILER=g++ -DCEXCHAIN_BUILD_TESTS=OFF \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
 && cmake --build --preset gcc-release --target cexchain ${BUILD_JOBS:+-j $BUILD_JOBS} \
 && strip build/gcc-release/cli/cexchain \
 && build/gcc-release/cli/cexchain version \
 && build/gcc-release/cli/cexchain bo packs list > /dev/null

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin cexchain \
 && mkdir -p /data && chown cexchain:cexchain /data && chmod 700 /data
COPY --from=build /src/build/gcc-release/cli/cexchain /usr/local/bin/cexchain
# The license, and the notices of the third-party code compiled into the binary.
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/cexchain/
USER cexchain
ENV CEXCHAIN_LEDGER=/data/ledger
VOLUME /data
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["cexchain"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
