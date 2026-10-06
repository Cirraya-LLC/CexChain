# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# cexchain-bench: where the time goes, measured the same way before and after
# every performance change (D-048). Not run in CI; built there so it keeps
# compiling.
add_executable(cexchain-bench src/main.cpp src/ledger_bench.cpp)
target_link_libraries(cexchain-bench PRIVATE cexchain::ledger cexchain::node)
target_compile_features(cexchain-bench PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain-bench)
