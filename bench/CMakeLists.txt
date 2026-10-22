# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# cexchain-bench: where the time goes, measured the same way before and after
# every performance change. Not run in CI as a benchmark;
# built there so it keeps compiling, and its scenarios run at a small scale
# as tests (label "bench").
add_executable(cexchain-bench src/main.cpp src/ledger_bench.cpp src/http_bench.cpp
    src/fixture.cpp src/contract_bench.cpp src/node_bench.cpp src/bo_bench.cpp)
target_link_libraries(cexchain-bench PRIVATE cexchain::ledger cexchain::node cexchain_asio
    nlohmann_json::nlohmann_json)
target_compile_features(cexchain-bench PRIVATE cxx_std_26)
target_compile_definitions(cexchain-bench PRIVATE
    CEXCHAIN_BENCH_EXAMPLES_DIR="${PROJECT_SOURCE_DIR}/examples"
    CEXCHAIN_BENCH_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors"
    # The executor scenario runs the command connector as `cexchain connector
    # command`, a child process, as `executor run` does.
    CEXCHAIN_BENCH_CLI="$<TARGET_FILE:cexchain>")
add_dependencies(cexchain-bench cexchain)
# Contracts are Bo builds: with the compiler (GCC 16) only.
if(TARGET cexchain_bo)
    target_link_libraries(cexchain-bench PRIVATE cexchain::bo)
    target_compile_definitions(cexchain-bench PRIVATE CEXCHAIN_BENCH_BO=1)
endif()
cexchain_target_defaults(cexchain-bench)
