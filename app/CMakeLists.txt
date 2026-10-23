# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The actions behind the command line, shared with the web console (C++26):
# opening a ledger or a server's verified mirror; building, signing, and
# submitting statements; records and their vault; contract calls and
# consents; requests and answers; peers; and the JSON views of ledger
# objects. Nothing here parses a command line, prompts on a terminal, or
# prints: secrets and approvals come in through callbacks.
add_library(cexchain_app
    src/contract_views.cpp
    src/contracts.cpp
    src/peers.cpp
    src/records.cpp
    src/requests.cpp
    src/session.cpp
    src/support.cpp
    src/views.cpp)
add_library(cexchain::app ALIAS cexchain_app)
target_include_directories(cexchain_app PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(cexchain_app
    PUBLIC cexchain::ledger cexchain::node cexchain::verifier cexchain::bo_front
           nlohmann_json::nlohmann_json)
# The tool named in an agent's provenance.
target_compile_definitions(cexchain_app PRIVATE CEXCHAIN_VERSION="${PROJECT_VERSION}")
target_compile_features(cexchain_app PUBLIC cxx_std_26)
cexchain_target_defaults(cexchain_app)
