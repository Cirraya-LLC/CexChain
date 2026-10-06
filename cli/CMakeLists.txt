# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

add_executable(cexchain
    src/args.cpp
    src/commands.cpp
    src/main.cpp
    src/support.cpp)
target_link_libraries(cexchain PRIVATE cexchain::ledger)
target_compile_features(cexchain PRIVATE cxx_std_26)
cexchain_target_defaults(cexchain)
