# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The actions behind the command line, shared with the web console (C++26):
# opening a ledger or a server's verified mirror; building, signing, and
# submitting statements; records and their vault; contract calls and
# consents; requests and answers; peers; and the JSON views of ledger
# objects. Nothing here parses a command line, prompts on a terminal, or
# prints: secrets and approvals come in through callbacks.
add_library(kanhe_client
    src/access.cpp
    src/backups.cpp
    src/claims.cpp
    src/contract_views.cpp
    src/contracts.cpp
    src/peers.cpp
    src/public_witness.cpp
    src/public_witnesses.cpp
    src/network_witnesses.cpp
    src/records.cpp
    src/relay.cpp
    src/relay_client.cpp
    src/relay_server.cpp
    src/requests.cpp
    src/session.cpp
    src/support.cpp
    src/views.cpp
    src/witness.cpp)
add_library(kanhe::client ALIAS kanhe_client)
target_include_directories(kanhe_client PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(kanhe_client
    PUBLIC kanhe::ledger kanhe::node kanhe::verifier
           nlohmann_json::nlohmann_json)
# The tool named in an agent's provenance, and the public witnesses offered
# (none by default).
target_compile_definitions(kanhe_client PRIVATE KANHE_VERSION="${PROJECT_VERSION}"
                                               KANHE_PUBLIC_WITNESSES="${KANHE_PUBLIC_WITNESSES}")
target_compile_features(kanhe_client PUBLIC cxx_std_26)
kanhe_target_defaults(kanhe_client)
