# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The dependency direction, checked when the build is configured: the chain
# (its libraries, the cexchain program, and its tests) never links the Bo
# language, an application, or SQLite; the language (with its tests) links
# only the chain's verification layer (the core, the crypto backend, the
# verifier), never a ledger, a node, or the client library. A link against the
# direction fails the configure. So a change to the language or an application
# leaves the chain's tests as they were.

set(_cexchain_chain_targets
    cexchain_core cexchain_crypto_openssl cexchain_crypto_pkcs11 cexchain_verifier cexchain_ledger
    cexchain_node cexchain_client cexchain_cli_base cexchain_cli_chain cexchain cexchain_tests)
set(_cexchain_not_for_the_chain
    cexchain_bo cexchain::bo cexchain_bo_front cexchain::bo_front cexchain_console
    cexchain::console cexchain_search cexchain::search cexchain_sqlite)
set(_cexchain_language_targets cexchain_bo_front cexchain_bo bo cexchain_bo_tests bo_build_fuzz)
set(_cexchain_not_for_the_language
    cexchain_ledger cexchain::ledger cexchain_node cexchain::node cexchain_client cexchain::client
    cexchain_console cexchain::console cexchain_search cexchain::search cexchain_sqlite
    cexchain_cli_chain)

function(_cexchain_refuse_links targets refused what)
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

function(cexchain_check_layers)
    _cexchain_refuse_links("${_cexchain_chain_targets}" "${_cexchain_not_for_the_chain}"
        "the chain links neither the Bo language, an application, nor SQLite")
    _cexchain_refuse_links("${_cexchain_language_targets}" "${_cexchain_not_for_the_language}"
        "the Bo language links only the chain's core, crypto, and verifier")
endfunction()
