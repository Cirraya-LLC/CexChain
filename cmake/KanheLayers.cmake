# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The dependency direction, checked when the build is configured: the chain
# (its libraries, the kanhe program, and its tests) never links the Bo
# language, an application, or SQLite; the language (with its tests) links
# only the chain's verification layer (the core, the crypto backend, the
# verifier), never a ledger, a node, or the client library. A link against the
# direction fails the configure. So a change to the language or an application
# leaves the chain's tests as they were.

set(_kanhe_chain_targets
    kanhe_core kanhe_crypto_openssl kanhe_crypto_pkcs11 kanhe_verifier kanhe_ledger
    kanhe_node kanhe_client kanhe_cli_base kanhe_cli_chain kanhe kanhe_tests)
set(_kanhe_not_for_the_chain
    kanhe_bo kanhe::bo kanhe_bo_front kanhe::bo_front kanhe_console
    kanhe::console kanhe_search kanhe::search kanhe_sqlite)
set(_kanhe_language_targets kanhe_bo_front kanhe_bo bo kanhe_bo_tests bo_build_fuzz)
set(_kanhe_not_for_the_language
    kanhe_ledger kanhe::ledger kanhe_node kanhe::node kanhe_client kanhe::client
    kanhe_console kanhe::console kanhe_search kanhe::search kanhe_sqlite
    kanhe_cli_chain)

function(_kanhe_refuse_links targets refused what)
    foreach(target IN LISTS targets)
        if(NOT TARGET ${target})
            continue()
        endif()
        get_target_property(links ${target} LINK_LIBRARIES)
        get_target_property(interface ${target} INTERFACE_LINK_LIBRARIES)
        foreach(link IN LISTS links interface)
            if(link IN_LIST refused)
                message(FATAL_ERROR "${target} links ${link}: ${what}")
            endif()
        endforeach()
    endforeach()
endfunction()

function(kanhe_check_layers)
    _kanhe_refuse_links("${_kanhe_chain_targets}" "${_kanhe_not_for_the_chain}"
        "the chain links neither the Bo language, an application, nor SQLite")
    _kanhe_refuse_links("${_kanhe_language_targets}" "${_kanhe_not_for_the_language}"
        "the Bo language links only the chain's core, crypto, and verifier")
endfunction()
