// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <set>
#include <string_view>
#include <utility>
#include <vector>

#include "registry.hpp"

/// Options and option lists the programs' command tables share.
namespace cexchain::cli {

// Options shared by many commands.
inline const OptionSpec ledger_option{"ledger", "DIR",
                                      "Ledger directory (default: $CEXCHAIN_LEDGER)"};
inline const OptionSpec as_option{
    "as", "KEY", "The signer's key file, or a pkcs11: URI for a key on a token", true};
inline const OptionSpec delegation_option{
    "delegation", "ID", "Delegation to act under (default: chosen automatically)"};
inline const OptionSpec model_option{
    "model", "NAME", "AI provenance: model (default: the agent's registered model)"};
inline const OptionSpec model_version_option{"model-version", "VERSION",
                                             "AI provenance: model version"};
inline const OptionSpec inputs_option{
    "inputs", "TEXT", "AI provenance: what the action was based on (only a hash is recorded)"};
inline const OptionSpec log_key_option{"log-key", "KEY", "The ledger's log key file", true};
/// For a party reached through its relay: what goes there is signed.
inline const OptionSpec relay_log_key_option{
    "log-key", "KEY",
    "The ledger's log key file, to reach a party through its relay (it signs what goes there)"};
/// For what the server signs in client mode.
inline const OptionSpec signing_log_key_option{
    "log-key", "KEY",
    "The ledger's log key file (required, except with --server: the server signs)"};
/// Client mode, added to every command that can work through a
/// server.
inline const std::vector<OptionSpec> client_options{
    {"server", "URL",
     "Work on the ledger this API serves, through a verified local mirror (default: "
     "$CEXCHAIN_SERVER)"},
    {"token-file", "FILE", "The API token for --server (default: $CEXCHAIN_TOKEN)"},
    {"ca-file", "FILE", "CA certificates (PEM) to trust for --server, if not the system's"},
    {"cache", "DIR",
     "Where --server keeps its mirror (default: $XDG_CACHE_HOME/cexchain or ~/.cache/cexchain)"},
    {"ledger-id", "ID",
     "With --server: the ledger to expect there (required on first use of an http:// URL)"}};
/// Commands that work on a ledger directory only: they administer the
/// server's files and keys, or peers' exchanges with it.
inline const std::set<std::string_view> local_only{"init",  "serve", "token",  "replica", "backup",
                                                   "vault", "peer",  "access", "cluster"};
/// Single commands of other groups that need the directory (its peers).
inline const std::set<std::pair<std::string_view, std::string_view>> local_only_commands{
    {"contract", "send"}, {"contract", "fetch"}, {"keeper", "due"}};
/// The cluster commands that talk to a member's API.
inline std::vector<OptionSpec> cluster_api(std::vector<OptionSpec> extra) {
    std::vector<OptionSpec> options{
        {"server", "URL", "A member's API (default: $CEXCHAIN_SERVER)"},
        {"token-file", "FILE", "An admin API token (default: $CEXCHAIN_TOKEN)"},
        {"ca-file", "FILE", "CA certificates (PEM) to trust for the member, if not the system's"}};
    options.insert(options.end(), extra.begin(), extra.end());
    return options;
}
inline const OptionSpec member_id_option{"id", "N", "The member's id (1 to 1000)", true};
inline const OptionSpec raft_option{"raft", "HOST:PORT",
                                    "Where the other members reach the member's Raft port", true};
inline const OptionSpec member_api_option{
    "api", "URL", "The member's API, as clients and the other members reach it", true};
inline const OptionSpec reason_option{"reason", "TEXT", "Reason, recorded on the ledger"};
inline const OptionSpec passphrase_file_option{
    "passphrase-file", "FILE",
    "Read key passphrases from FILE (default: $CEXCHAIN_PASSPHRASE or a prompt)"};
inline const OptionSpec vault_key_option{"vault-key", "FILE",
                                         "The vault private key (default: <ledger>/vault.key)"};
inline const OptionSpec presence_option{
    "presence", "", "Prove you are present: confirm with your passkey in the browser"};
inline const OptionSpec presence_key_option{
    "presence-key", "URI", "Prove presence with a hardware key on a token (pkcs11: URI)"};
inline const OptionSpec no_browser_option{
    "no-browser", "", "Do not open the browser; open the printed address yourself"};
inline const OptionSpec args_option{
    "args", "VALUE", "The arguments, in CBOR diagnostic notation (default: null; see below)"};
inline const OptionSpec args_cbor_option{"args-cbor", "FILE",
                                         "The arguments as a file of CBOR, instead of --args"};
inline const OptionSpec dry_run_option{
    "dry-run", "", "Run the contract here and show what it would do; record nothing"};
inline const OptionSpec at_option{
    "at", "TIME",
    "With --dry-run: run as if the ledger registered the call at TIME (YYYY-MM-DD for its UTC "
    "midnight, or YYYY-MM-DDTHH:MM:SSZ), say to see when a time rule applies"};
inline const OptionSpec json_option{"json", "", "Print machine-readable JSON"};

/// How contract commands take arguments.
#define CEXCHAIN_ARGUMENTS_HELP                                                                    \
    "Arguments are any CBOR value, written in CBOR diagnostic notation (RFC 8949, section 8),\n"   \
    "which extends JSON: 42, -1, \"text\" (JSON escapes), true, false, null, [1, 2], and\n"        \
    "{\"a\": 1} as in JSON; plus h'00ff' (a byte string, in hex), {1: \"a\"} (keys of any\n"       \
    "type), 1(1700000000) (a tag), and <<[1, \"a\"]>> (a byte string holding the CBOR\n"           \
    "encoding of [1, \"a\"]). No floating point; maps are put in canonical order. Or give\n"       \
    "the encoded CBOR with --args-cbor FILE. Whoever holds the instance's evidence sees\n"         \
    "the arguments: keep personal data out of them."
inline const OptionSpec help_option{"help", "", "Show help for this command"};
inline std::vector<OptionSpec> with(std::vector<OptionSpec> options) {
    return options;
}

/// The filters of searches and reports (search/query.hpp spells them).
inline std::vector<OptionSpec> record_filters(std::vector<OptionSpec> extra) {
    std::vector<OptionSpec> options{
        ledger_option,
        {"type", "TYPE", "Only records of this type"},
        {"state", "STATE", "Only records in this state"},
        {"registrant", "ACTOR", "Only records this actor registered"},
        {"since", "TIME", "Registered at or after TIME (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, UTC)"},
        {"until", "TIME", "Registered before TIME"},
        {"current", "", "Leave out records a newer version superseded"},
        {"revoked", "yes|any", "Only revoked records, or revoked ones too (left out by default)"},
        {"meta", "KEY=VALUE", "A public metadata value, exactly", false, true},
        {"meta-min", "KEY=N", "A public metadata number of at least N", false, true},
        {"meta-max", "KEY=N", "A public metadata number of at most N", false, true},
        {"text", "TEXT", "Text in the public metadata's values (any part of a word)"}};
    options.insert(options.end(), extra.begin(), extra.end());
    return options;
}

inline std::vector<OptionSpec> instance_filters(std::vector<OptionSpec> extra) {
    std::vector<OptionSpec> options{
        ledger_option,
        {"contract", "CONTRACT", "Only instances of this contract"},
        {"contract-name", "NAME", "Only instances of contracts deployed with this name"},
        {"status", "STATE", "Only instances in this state"},
        {"final", "yes|no", "Only final instances, or only those still open"},
        {"party", "LEDGER", "Only instances with this ledger (its id) among their parties"},
        {"since", "TIME", "Created at or after TIME (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, UTC)"},
        {"until", "TIME", "Created before TIME"},
        {"changed-since", "TIME", "Called at or after TIME"},
        {"reference", "REF", "Created by a call with this reference"},
        {"field", "NAME=VALUE",
         "A field of the instance's state, exactly (yes/no as true or false)", false, true},
        {"field-min", "NAME=N", "A number field of at least N", false, true},
        {"field-max", "NAME=N", "A number field of at most N", false, true}};
    options.insert(options.end(), extra.begin(), extra.end());
    return options;
}

inline const std::vector<OptionSpec> page_options{
    {"limit", "N", "At most N (1 to 1000; default 100)"},
    {"cursor", "CURSOR", "Go on from where an earlier page ended"},
    {"oldest", "", "Oldest first (newest first by default)"}};

inline std::vector<OptionSpec> paged(std::vector<OptionSpec> options) {
    options.insert(options.end(), page_options.begin(), page_options.end());
    return options;
}

inline std::vector<OptionSpec> signing(std::vector<OptionSpec> extra) {
    std::vector<OptionSpec> options{
        ledger_option,        as_option,        delegation_option,      model_option,
        model_version_option, inputs_option,    passphrase_file_option, presence_option,
        presence_key_option,  no_browser_option};
    options.insert(options.end(), extra.begin(), extra.end());
    return options;
}

} // namespace cexchain::cli
