# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# kanhe-bench: where the time goes, measured the same way before and after
# every performance change. Not run in CI as a benchmark;
# built there so it keeps compiling, and its scenarios run at a small scale
# as tests (label "bench").
add_executable(kanhe-bench src/main.cpp src/ledger_bench.cpp src/http_bench.cpp
    src/fixture.cpp src/contract_bench.cpp src/node_bench.cpp src/bo_bench.cpp src/search_bench.cpp)
target_link_libraries(kanhe-bench PRIVATE kanhe::ledger kanhe::node kanhe::search kanhe_asio
    nlohmann_json::nlohmann_json)
target_compile_features(kanhe-bench PRIVATE cxx_std_26)
target_compile_definitions(kanhe-bench PRIVATE
    KANHE_BENCH_EXAMPLES_DIR="${PROJECT_SOURCE_DIR}/examples"
    KANHE_BENCH_TESTVECTORS_DIR="${PROJECT_SOURCE_DIR}/testvectors"
    # The executor scenario runs the command connector as `kanhe connector
    # command`, a child process, as `executor run` does.
    KANHE_BENCH_CLI="$<TARGET_FILE:kanhe>")
add_dependencies(kanhe-bench kanhe)
# Contracts are Bo builds: with the compiler (GCC 16) only.
if(TARGET kanhe_bo)
    target_link_libraries(kanhe-bench PRIVATE kanhe::bo)
    target_compile_definitions(kanhe-bench PRIVATE KANHE_BENCH_BO=1)
endif()
kanhe_target_defaults(kanhe-bench)
