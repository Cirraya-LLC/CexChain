// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "registry.hpp"

#include <algorithm>
#include <cstdio>
#include <format>
#include <map>
#include <print>
#include <set>
#include <span>

#include "commands.hpp"

namespace cexchain::cli {

namespace {

// Options shared by many commands.
const OptionSpec ledger_option{"ledger", "DIR", "Ledger directory (default: $CEXCHAIN_LEDGER)"};
const OptionSpec as_option{"as", "KEY",
                           "The signer's key file, or a pkcs11: URI for a key on a token", true};
const OptionSpec delegation_option{"delegation", "ID",
                                   "Delegation to act under (default: chosen automatically)"};
const OptionSpec model_option{"model", "NAME",
                              "AI provenance: model (default: the agent's registered model)"};
const OptionSpec model_version_option{"model-version", "VERSION", "AI provenance: model version"};
const OptionSpec inputs_option{
    "inputs", "TEXT", "AI provenance: what the action was based on (only a hash is recorded)"};
const OptionSpec log_key_option{"log-key", "KEY", "The ledger's log key file", true};
/// For what the server signs in client mode.
const OptionSpec signing_log_key_option{
    "log-key", "KEY",
    "The ledger's log key file (required, except with --server: the server signs)"};
/// Client mode (D-050), added to every command that can work through a
/// server.
const std::vector<OptionSpec> client_options{
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
const std::set<std::string_view> local_only{"init",  "serve", "token",  "replica", "backup",
                                            "vault", "peer",  "access", "mcp",     "cluster"};
/// Single commands of other groups that need the directory (its peers).
const std::set<std::pair<std::string_view, std::string_view>> local_only_commands{
    {"asset", "send"}, {"asset", "fetch"}, {"contract", "send"}, {"contract", "fetch"}};
/// The cluster commands that talk to a member's API.
std::vector<OptionSpec> cluster_api(std::vector<OptionSpec> extra) {
    std::vector<OptionSpec> options{
        {"server", "URL", "A member's API (default: $CEXCHAIN_SERVER)"},
        {"token-file", "FILE", "An admin API token (default: $CEXCHAIN_TOKEN)"},
        {"ca-file", "FILE", "CA certificates (PEM) to trust for the member, if not the system's"}};
    options.insert(options.end(), extra.begin(), extra.end());
    return options;
}
const OptionSpec member_id_option{"id", "N", "The member's id (1 to 1000)", true};
const OptionSpec raft_option{"raft", "HOST:PORT",
                             "Where the other members reach the member's Raft port", true};
const OptionSpec member_api_option{
    "api", "URL", "The member's API, as clients and the other members reach it", true};
const OptionSpec reason_option{"reason", "TEXT", "Reason, recorded on the ledger"};
const OptionSpec passphrase_file_option{
    "passphrase-file", "FILE",
    "Read key passphrases from FILE (default: $CEXCHAIN_PASSPHRASE or a prompt)"};
const OptionSpec vault_key_option{"vault-key", "FILE",
                                  "The vault private key (default: <ledger>/vault.key)"};
const OptionSpec presence_option{"presence", "",
                                 "Prove you are present: confirm with your passkey in the browser"};
const OptionSpec presence_key_option{"presence-key", "URI",
                                     "Prove presence with a hardware key on a token (pkcs11: URI)"};
const OptionSpec no_browser_option{"no-browser", "",
                                   "Do not open the browser; open the printed address yourself"};
const OptionSpec args_option{
    "args", "VALUE", "The arguments, in CBOR diagnostic notation (default: null; see below)"};
const OptionSpec args_cbor_option{"args-cbor", "FILE",
                                  "The arguments as a file of CBOR, instead of --args"};
const OptionSpec dry_run_option{"dry-run", "",
                                "Run the contract here and show what it would do; record nothing"};
const OptionSpec json_option{"json", "", "Print machine-readable JSON"};

/// How contract commands take arguments.
#define CEXCHAIN_ARGUMENTS_HELP                                                                    \
    "Arguments are any CBOR value, written in CBOR diagnostic notation (RFC 8949, section 8),\n"   \
    "which extends JSON: 42, -1, \"text\" (JSON escapes), true, false, null, [1, 2], and\n"        \
    "{\"a\": 1} as in JSON; plus h'00ff' (a byte string, in hex), {1: \"a\"} (keys of any\n"       \
    "type), 1(1700000000) (a tag), and <<[1, \"a\"]>> (a byte string holding the CBOR\n"           \
    "encoding of [1, \"a\"]). No floating point; maps are put in canonical order. Or give\n"       \
    "the encoded CBOR with --args-cbor FILE. Whoever holds the instance's evidence sees\n"         \
    "the arguments: keep personal data out of them."
const OptionSpec help_option{"help", "", "Show help for this command"};

std::vector<OptionSpec> with(std::vector<OptionSpec> options) {
    return options;
}

std::vector<OptionSpec> signing(std::vector<OptionSpec> extra) {
    std::vector<OptionSpec> options{
        ledger_option,        as_option,        delegation_option,      model_option,
        model_version_option, inputs_option,    passphrase_file_option, presence_option,
        presence_key_option,  no_browser_option};
    options.insert(options.end(), extra.begin(), extra.end());
    return options;
}

std::vector<CommandSpec> build() {
    return {
        // ------------------------------------------------------------------
        {{"version"}, "Print the version", "General", "", 0, 0, {}, cmd_version},
        {{"help"}, "Show help for a command", "General", "[COMMAND...]", 0, 3, {}, cmd_help},
        {{"completion"},
         "Print a shell completion script",
         "General",
         "bash|zsh",
         1,
         1,
         {},
         cmd_completion,
         "Load with: source <(cexchain completion bash)   or   source <(cexchain completion zsh)"},

        // ------------------------------------------------------------------
        {{"key", "generate"},
         "Generate a key pair (encrypted PKCS #8, owner-only permissions)",
         "Keys",
         "",
         0,
         0,
         with(
             {{"out", "FILE", "Where to write the private key", true},
              {"alg", "ALG", "ed25519 (default), esp256, sm2-sm3, ml-dsa-44, ml-dsa-65, ml-dsa-87"},
              {"no-passphrase", "", "Store the key unencrypted (not recommended)"},
              {"pkcs11", "URI", "Generate the key on a token instead; --out gets its public half"},
              passphrase_file_option}),
         cmd_key_generate,
         "A token key (USB key, smart card, HSM) is named by an RFC 7512 URI, e.g.\n"
         "  pkcs11:token=CexChain;object=alice?module-path=/usr/lib/softhsm/libsofthsm2.so\n"
         "Its PIN comes from pin-value= or pin-source= in the URI, $CEXCHAIN_PKCS11_PIN, or a\n"
         "prompt. Commands that take a key file also take such a URI."},
        {{"key", "show"},
         "Show a key's algorithm, public key, and key ids",
         "Keys",
         "FILE",
         1,
         1,
         with({passphrase_file_option}),
         cmd_key_show},
        {{"key", "public"},
         "Export a key's public half for others (verifiers, witnesses)",
         "Keys",
         "FILE",
         1,
         1,
         with({{"out", "FILE", "Write the public key here (default: print it)"},
               passphrase_file_option}),
         cmd_key_public},
        {{"key", "passphrase"},
         "Encrypt, re-encrypt, or decrypt a key file",
         "Keys",
         "FILE",
         1,
         1,
         with({{"remove", "", "Store the key unencrypted"},
               passphrase_file_option,
               {"new-passphrase-file", "FILE",
                "Read the new passphrase from FILE (default: $CEXCHAIN_NEW_PASSPHRASE or a "
                "prompt)"}}),
         cmd_key_passphrase},

        // ------------------------------------------------------------------
        {{"init"},
         "Create a ledger",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option,
               {"org", "NAME", "Organization name", true},
               {"root-key", "KEY", "Organization root key file", true},
               {"log-key", "KEY", "Log key file (signs checkpoints and receipts)", true},
               {"hash", "HASH", "sha256 (default) or sm3"},
               {"vault-public-key", "FILE",
                "Seal private record data to this key (from cexchain vault keygen) instead of "
                "creating <ledger>/vault.key"},
               passphrase_file_option}),
         cmd_init,
         "Creates the ledger and its vault key: private record data (field values and salts)\n"
         "is sealed to <ledger>/vault.pub; reading it needs <ledger>/vault.key, encrypted with\n"
         "your passphrase. Back the vault key up: without it, private data cannot be disclosed."},
        {{"status"},
         "Show the ledger's identity, size, and latest checkpoint",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_status},
        {{"audit"},
         "Re-validate the whole ledger and every stored checkpoint",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_audit,
         "Opening a ledger replays and re-validates every statement under the ledger rules;\n"
         "audit also re-checks every stored checkpoint against the log."},
        {{"log", "list"},
         "List log entries",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option,
               {"from", "INDEX", "First entry to list (default 0)"},
               {"limit", "N", "Maximum number of entries (default 100)"},
               {"type", "TYPE",
                "Only entries of this type (a statement type, or state-commitment)"}}),
         cmd_log_list},
        {{"log", "show"},
         "Show one log entry, decoded",
         "Ledger",
         "INDEX|STATEMENT_ID",
         1,
         1,
         with({ledger_option, {"raw", "", "Also print the statement in CBOR diagnostic notation"}}),
         cmd_log_show},
        {{"log", "export"},
         "Export log entries for an auditor",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option,
               {"out", "FILE", "Output file (CBOR array of encoded log entries)", true},
               {"from", "INDEX", "First entry (default 0)"},
               {"to", "INDEX", "Last entry (default: the end)"}}),
         cmd_log_export},

        {{"ledger", "keys"},
         "Show the organization's root and log keys over time",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_ledger_keys,
         "Each key with the log index of the statement that set it. The log key in effect for a\n"
         "tree of N entries is the one set before index N: it signs checkpoints of that size and\n"
         "receipts against them."},
        {{"ledger", "genesis"},
         "Write the ledger's genesis entry, for witnesses",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option, {"out", "FILE", "Output file (the encoded log entry)", true}}),
         cmd_ledger_genesis,
         "The genesis entry fixes the ledger id, hash, root key, and first log key. A witness\n"
         "added from it (cexchain witness add-log --genesis) can follow key rotations."},
        {{"ledger", "rotate-log-key"},
         "Replace the log key (signed by the organization's root key)",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option,
               {"as", "KEY", "The organization's current root key (file or pkcs11: URI)", true},
               {"new-key", "KEY",
                "The new log key: its public key file, private key file, or pkcs11: URI", true},
               passphrase_file_option}),
         cmd_ledger_rotate_log_key,
         "The new key signs every state commitment, checkpoint, and receipt after the rotation;\n"
         "older checkpoints stay valid under the old key. A key used as a log key before cannot\n"
         "come back. With serve running, start it with both keys (--log-key OLD --log-key NEW)\n"
         "before rotating: it switches at the next checkpoint. Witnesses follow the rotation\n"
         "from the cosign requests."},
        {{"ledger", "rotate-root-key"},
         "Replace the organization's root key (signed by the current one)",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option,
               {"as", "KEY", "The organization's current root key (file or pkcs11: URI)", true},
               {"new-key", "KEY",
                "The new root key: its public key file, private key file, or pkcs11: URI", true},
               passphrase_file_option}),
         cmd_ledger_rotate_root_key,
         "Only the organization rotates its root key, signing with the current one. Keep the new\n"
         "key in an HSM if you can: whoever holds the root key can rotate both keys."},

        // ------------------------------------------------------------------
        {{"actor", "add"},
         "Register a person, AI agent, or device",
         "Actors",
         "",
         0,
         0,
         signing({{"kind", "KIND", "person, agent, or device", true},
                  {"name", "NAME", "Display name", true},
                  {"key", "KEY",
                   "The new actor's public key file (from cexchain key public), or its private key "
                   "file",
                   true},
                  {"responsible", "ACTOR", "Accountable person (required for agents)"},
                  {"runtime", "TEXT", "Agents: the runtime they run in"}}),
         cmd_actor_add,
         "For agents, --model names the model they run; it is recorded in their registration\n"
         "and filled into the provenance of everything they sign."},
        {{"actor", "list"},
         "List actors",
         "Actors",
         "",
         0,
         0,
         with({ledger_option,
               {"kind", "KIND", "Only this kind"},
               {"all", "", "Include revoked actors"}}),
         cmd_actor_list},
        {{"actor", "show"},
         "Show an actor, its key, and its delegations",
         "Actors",
         "ACTOR",
         1,
         1,
         with({ledger_option}),
         cmd_actor_show},
        {{"actor", "revoke"},
         "Revoke an actor",
         "Actors",
         "ACTOR",
         1,
         1,
         signing({reason_option}),
         cmd_actor_revoke},
        {{"actor", "rotate-key"},
         "Replace an actor's key",
         "Actors",
         "ACTOR",
         1,
         1,
         signing(
             {{"new-key", "KEY", "The replacement public key file (or private key file)", true}}),
         cmd_actor_rotate_key,
         "An actor may rotate its own key with --as its current key; otherwise a delegation\n"
         "covering actor-rotate-key is needed."},

        {{"actor", "set-presence"},
         "Register a person's passkeys for proof of presence",
         "Actors",
         "ACTOR",
         1,
         1,
         signing({{"credential", "FILE",
                   "A passkey credential file (from cexchain presence enroll)", false, true},
                  {"add", "", "Keep the passkeys already registered"},
                  {"clear", "", "Remove every passkey"}}),
         cmd_actor_set_presence,
         "Replaces the person's passkeys unless --add is given. The organization, or an actor "
         "with\n"
         "a delegation covering actor-set-presence, may do this; a person may change their own\n"
         "passkeys only with --presence, proving presence with a passkey already registered."},
        {{"presence", "enroll"},
         "Create a passkey, or enroll a hardware key, to prove your presence",
         "Actors",
         "",
         0,
         0,
         with({{"out", "FILE", "Write the credential file (public data) here", true},
               {"name", "NAME", "Your name, as the passkey will show it (passkeys only)"},
               {"label", "TEXT", "A label, e.g. \"MacBook Touch ID\" or \"Bank UKey\""},
               {"pkcs11", "URI", "Enroll this hardware key (a key on a USB key or smart card)"},
               no_browser_option}),
         cmd_presence_enroll,
         "Opens the browser to create a passkey (Touch ID, Windows Hello, a phone, or a security\n"
         "key) for the site \"localhost\"; or, with --pkcs11, enrolls a key on a token (a UKey or\n"
         "smart card), which proves presence by signing after its PIN is entered. Only public\n"
         "data is written to FILE; give it to your administrator to register with\n"
         "cexchain actor set-presence."},

        // ------------------------------------------------------------------
        {{"delegation", "grant"},
         "Grant a delegation",
         "Delegations",
         "",
         0,
         0,
         signing(
             {{"to", "ACTOR", "Grantee", true},
              {"allow", "TYPES", "Comma-separated statement types the grantee may submit", true},
              {"record-types", "TYPES", "Comma-separated record types (default: any)"},
              {"from-date", "DATE", "Valid from (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)"},
              {"until", "DATE", "Valid until"},
              {"days", "N", "Valid for N days from now"},
              {"may-delegate", "", "The grantee may delegate further (only narrower)"},
              {"require-presence", "", "Everything done under it must carry proof of presence"},
              {"contracts", "IDS",
               "Comma-separated contracts its calls and retires may act on (default: any)"}}),
         cmd_delegation_grant,
         "Statement types: actor-register, actor-rotate-key, actor-revoke, actor-set-presence,\n"
         "delegation-grant, delegation-revoke, record-register, record-endorse,\n"
         "record-transition, record-revoke, asset-action, contract-deploy, contract-call,\n"
         "contract-retire. --contracts limits contract-call and contract-retire to those\n"
         "contracts (a call on an instance acts on the instance's contract); a delegation\n"
         "granted under it may name only some of them."},
        {{"delegation", "list"},
         "List delegations",
         "Delegations",
         "",
         0,
         0,
         with({ledger_option,
               {"actor", "ACTOR", "Only delegations granted to or by this actor"},
               {"all", "", "Include revoked delegations"}}),
         cmd_delegation_list},
        {{"delegation", "show"},
         "Show a delegation's scope and chain",
         "Delegations",
         "DELEGATION",
         1,
         1,
         with({ledger_option}),
         cmd_delegation_show},
        {{"delegation", "revoke"},
         "Revoke a delegation",
         "Delegations",
         "DELEGATION",
         1,
         1,
         signing({reason_option}),
         cmd_delegation_revoke},

        // ------------------------------------------------------------------
        {{"record", "issue"},
         "Issue a record",
         "Records",
         "",
         0,
         0,
         signing({{"type", "TYPE", "Record type, e.g. cexchain.certificate/1", true},
                  {"field", "NAME=VALUE", "A field (private until disclosed)", true, true},
                  {"meta", "NAME=VALUE", "Public metadata", false, true},
                  {"attach", "FILE", "Attach a file (committed by hash)", false, true}}),
         cmd_record_issue},
        {{"record", "list"},
         "List records",
         "Records",
         "",
         0,
         0,
         with({ledger_option,
               {"type", "TYPE", "Only this record type"},
               {"state", "STATE", "Only this state"},
               {"all", "", "Include revoked records"}}),
         cmd_record_list},
        {{"record", "show"},
         "Show a record",
         "Records",
         "RECORD",
         1,
         1,
         with({ledger_option}),
         cmd_record_show},
        {{"record", "history"},
         "Show every statement about a record",
         "Records",
         "RECORD",
         1,
         1,
         with({ledger_option}),
         cmd_record_history},
        {{"record", "fields"},
         "Show a record's private field values (from the vault)",
         "Records",
         "RECORD",
         1,
         1,
         with({ledger_option, vault_key_option, passphrase_file_option}),
         cmd_record_fields},
        {{"record", "endorse"},
         "Endorse a record in a role",
         "Records",
         "RECORD",
         1,
         1,
         signing({{"role", "ROLE", "e.g. inspector, receiver, party", true}}),
         cmd_record_endorse},
        {{"record", "transition"},
         "Move a record to a new state",
         "Records",
         "RECORD",
         1,
         1,
         signing({{"to", "STATE", "The new state", true}}),
         cmd_record_transition},
        {{"record", "revoke"},
         "Revoke a record",
         "Records",
         "RECORD",
         1,
         1,
         signing({reason_option}),
         cmd_record_revoke},
        {{"record", "types"},
         "List built-in record types and their lifecycles",
         "Records",
         "",
         0,
         0,
         {},
         cmd_record_types},

        // ------------------------------------------------------------------
        {{"checkpoint", "create"},
         "Sign a checkpoint of the current log",
         "Checkpoints and proofs",
         "",
         0,
         0,
         with({ledger_option, signing_log_key_option, passphrase_file_option}),
         cmd_checkpoint_create},
        {{"checkpoint", "list"},
         "List stored checkpoints",
         "Checkpoints and proofs",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_checkpoint_list},
        {{"checkpoint", "show"},
         "Show a checkpoint (default: the latest)",
         "Checkpoints and proofs",
         "[SIZE]",
         0,
         1,
         with({ledger_option, {"out", "FILE", "Write the signed checkpoint here"}}),
         cmd_checkpoint_show},
        {{"checkpoint", "cosign-request"},
         "Ask a witness to cosign the latest checkpoint",
         "Checkpoints and proofs",
         "",
         0,
         0,
         with({ledger_option,
               {"witness", "PUBKEY", "The witness's public key file"},
               {"peer", "NAME", "A peer that witnesses this ledger (its witness key)"},
               {"out", "FILE", "Write the request here, for the witness"},
               {"send", "", "Send it to the peer's API and store the cosignature it returns"},
               {"from", "SIZE",
                "Prove consistency from this size (default: the witness's last cosigned size)"}}),
         cmd_checkpoint_cosign_request,
         "The request holds the checkpoint and a consistency proof from the last checkpoint the\n"
         "witness cosigned. Send it to the witness (cexchain witness cosign), then store the\n"
         "cosignature it returns with cexchain checkpoint add-cosignature. With --peer and\n"
         "--send, a peer running cexchain serve --witness-dir cosigns it online: two\n"
         "organizations witness each other with no third party."},
        {{"checkpoint", "add-cosignature"},
         "Store a witness's cosignature; exports then include it",
         "Checkpoints and proofs",
         "FILE",
         1,
         1,
         with({ledger_option, {"witness", "PUBKEY", "The witness's public key file", true}}),
         cmd_checkpoint_add_cosignature},
        {{"proof", "inclusion"},
         "Inclusion proof for a log entry",
         "Checkpoints and proofs",
         "INDEX",
         1,
         1,
         with({ledger_option, {"size", "N", "Tree size (default: the current size)"}}),
         cmd_proof_inclusion},
        {{"proof", "state"},
         "Prove an object's complete history against the latest checkpoint",
         "Checkpoints and proofs",
         "ID",
         1,
         1,
         with({ledger_option}),
         cmd_proof_state,
         "ID is an actor, delegation, or record. The proof shows every log entry that created or\n"
         "changed it, as of the latest checkpoint, against that checkpoint's state root: proof\n"
         "that nothing about it, such as a revocation, is missing."},
        {{"proof", "consistency"},
         "Consistency proof between two tree sizes",
         "Checkpoints and proofs",
         "OLD NEW",
         2,
         2,
         with({ledger_option}),
         cmd_proof_consistency},
        {{"receipt"},
         "Write an RFC 9942 receipt for a log entry",
         "Checkpoints and proofs",
         "INDEX",
         1,
         1,
         with({ledger_option,
               signing_log_key_option,
               {"out", "FILE", "Output file", true},
               passphrase_file_option}),
         cmd_receipt},

        // ------------------------------------------------------------------
        {{"export"},
         "Export a record's evidence bundle",
         "Evidence",
         "RECORD",
         1,
         1,
         with({ledger_option,
               signing_log_key_option,
               {"out", "FILE", "Output file", true},
               {"disclose", "FIELDS", "Comma-separated fields to disclose"},
               {"with-attachments", "", "Include attachment openings"},
               {"cosignature", "FILE", "Include a witness cosignature", false, true},
               vault_key_option,
               passphrase_file_option}),
         cmd_export},
        {{"verify"},
         "Verify an evidence bundle offline",
         "Evidence",
         "BUNDLE",
         1,
         1,
         with({{"ledger-id", "ID", "The issuer's ledger id, learned out of band"},
               {"witness", "PUBKEY", "Trust this witness's public key file", false, true},
               {"min-witnesses", "N", "Fail unless at least N trusted witnesses cosigned"},
               {"attachment", "NAME=FILE", "Check an attachment's content", false, true}}),
         cmd_verify},
        {{"qr"},
         "Make a QR code that opens a record's evidence in the browser verifier",
         "Evidence",
         "RECORD",
         1,
         1,
         with({ledger_option,
               {"bundle-url", "URL",
                "Where you publish the record's evidence bundle (from cexchain export)", true},
               {"verifier-url", "URL", "Where you host cexchain-verify.html", true},
               {"out", "FILE", "Write an SVG image (default: draw the code in the terminal)"}}),
         cmd_qr,
         "The code links to the verifier page with the ledger id, the record id, and the bundle's\n"
         "URL. Scanning it verifies the evidence on the scanner's own device; the page refuses\n"
         "evidence about another record or from another ledger. The server that hosts the bundle\n"
         "must allow cross-origin requests from the verifier's origin."},
        {{"inspect"},
         "Decode any CexChain file",
         "Evidence",
         "FILE",
         1,
         1,
         with({{"raw", "", "Also print CBOR diagnostic notation"}}),
         cmd_inspect,
         "Recognizes signed statements, log entries, checkpoints, cosignatures, receipts, and\n"
         "evidence bundles."},

        // ------------------------------------------------------------------
        {{"vault", "status"},
         "Show the vault key and how many records it seals",
         "Vault",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_vault_status},
        {{"vault", "keygen"},
         "Generate a vault key pair to keep off the ledger host",
         "Vault",
         "",
         0,
         0,
         with(
             {{"out", "FILE", "Write the private key to FILE and the public key to FILE.pub", true},
              {"no-passphrase", "", "Store the private key unencrypted (not recommended)"},
              passphrase_file_option}),
         cmd_vault_keygen},
        {{"vault", "rekey"},
         "Re-seal all private record data to a new vault key",
         "Vault",
         "",
         0,
         0,
         with({ledger_option,
               vault_key_option,
               {"new-public-key", "FILE",
                "Re-seal to this public key (default: generate <ledger>/vault.key)"},
               passphrase_file_option,
               {"new-passphrase-file", "FILE",
                "Passphrase for a generated key (default: $CEXCHAIN_NEW_PASSPHRASE or a prompt)"}}),
         cmd_vault_rekey,
         "Use after a vault key may have leaked, when its holders change, or to seal data\n"
         "written before vaults were encrypted. The previous vault, with its key, is kept in\n"
         "<ledger>/vault.old-<time>."},

        // ------------------------------------------------------------------
        {{"witness", "add-log"},
         "Start witnessing a ledger",
         "Witness",
         "",
         0,
         0,
         with({{"dir", "DIR", "The witness's state directory", true},
               {"genesis", "FILE",
                "The ledger's genesis entry (from cexchain ledger genesis): fixes the ledger id "
                "and its keys, so the witness can follow key rotations"},
               {"ledger-id", "ID",
                "The ledger's id (full hex), from its operator: pins --genesis, or goes with "
                "--log-key"},
               {"log-key", "PUBKEY",
                "Instead of --genesis: the ledger's log public key file (cannot follow a "
                "rotation)"},
               {"name", "NAME", "A name for the ledger"}}),
         cmd_witness_add_log,
         "A witness is an independent party (another company, an auditor, a regulator) that\n"
         "cosigns a ledger's checkpoints only if each extends the history it cosigned before.\n"
         "Learn the ledger id from the operator through a channel you trust, and check the\n"
         "genesis entry against it with --ledger-id."},
        {{"witness", "cosign"},
         "Check a cosign request and cosign it if the history is consistent",
         "Witness",
         "REQUEST",
         1,
         1,
         with({{"dir", "DIR", "The witness's state directory", true},
               {"key", "KEY", "The witness's private key file", true},
               {"out", "FILE", "Write the cosignature here, for the operator", true},
               passphrase_file_option}),
         cmd_witness_cosign,
         "Refuses (exit 3) a checkpoint not signed by the ledger's log key, or one whose history\n"
         "does not extend what this witness cosigned: a sign the ledger was rewritten or forked.\n"
         "Refuses (exit 2) a request whose proof starts elsewhere than the witness's last size;\n"
         "the operator can then ask with: cexchain checkpoint cosign-request --from SIZE."},
        {{"witness", "status"},
         "List the ledgers this witness follows",
         "Witness",
         "",
         0,
         0,
         with({{"dir", "DIR", "The witness's state directory", true}}),
         cmd_witness_status},
        {{"witness", "remove-log"},
         "Stop witnessing a ledger",
         "Witness",
         "LEDGER",
         1,
         1,
         with({{"dir", "DIR", "The witness's state directory", true}}),
         cmd_witness_remove_log},

        // ------------------------------------------------------------------
        {{"serve"},
         "Serve the ledger's HTTP API",
         "Server",
         "",
         0,
         0,
         with({ledger_option,
               {"listen", "HOST:PORT",
                "Address to listen on (default: 127.0.0.1:8080; port 0 picks one)"},
               {"log-key", "KEY",
                "The log key (file or pkcs11: URI): enables checkpoints, receipts, and evidence. "
                "Repeat it to hold the old and new key across a rotation",
                false, true},
               {"checkpoint-interval", "SECONDS",
                "Checkpoint when the log grew, this often (default: 60 with --log-key; 0: never)"},
               {"tls-cert", "FILE", "TLS certificate chain (PEM); without it, use a TLS proxy"},
               {"tls-key", "FILE", "TLS private key (PEM)"},
               {"read-only", "", "Refuse every write"},
               {"cluster", "",
                "Serve as a member of this ledger's cluster (cexchain cluster init or join)"},
               {"public-read", "",
                "Serve read routes without a token (a public verification portal; the vault and "
                "metrics still need one)"},
               {"threads", "N", "I/O threads (default: one per core)"},
               {"max-connections", "N", "Concurrent connections (default: 1024)"},
               {"max-connections-per-ip", "N",
                "From one client address (default: no limit; behind a proxy, leave it)"},
               {"max-body", "BYTES", "Largest request body (default: 1048576)"},
               {"quiet", "", "No access log on stderr"},
               {"witness-dir", "DIR", "Also witness peers' ledgers: this witness state directory"},
               {"witness-key", "KEY", "The witness key (file or pkcs11: URI), with --witness-dir"},
               {"registrar-key", "KEY",
                "Take peers' consents to asset actions, and proposed contract calls with the "
                "consents their contracts ask for; record each once all are in, signing as this "
                "actor (file or pkcs11: URI)"},
               passphrase_file_option}),
         cmd_serve,
         "Routes (API v1; binary objects are CBOR or COSE, everything else JSON):\n"
         "  open:    GET /healthz, /v1/checkpoint[?size=N], /v1/consistency?old=&new=\n"
         "  read:    GET /metrics, /v1/status, /v1/entries?start=&count=, /v1/checkpoints,\n"
         "           /v1/cosignatures, /v1/inclusion?index=&size=, /v1/statements/ID,\n"
         "           /v1/receipts/INDEX, /v1/state/ID, /v1/evidence/RECORD,\n"
         "           /v1/vault/public-key, /v1/vault/records/RECORD, /v1/assets/ASSET,\n"
         "           /v1/contracts, /v1/contracts/CONTRACT, /v1/contracts/instances/INSTANCE,\n"
         "           /v1/contracts/calls, /v1/contracts/calls/CALL\n"
         "  submit:  POST /v1/statements (a signed statement, application/cose; or a record's\n"
         "           registration with its sealed private data, or an asset action or a\n"
         "           contract call with its consents' evidence,\n"
         "           application/cexchain-submission+cbor), POST /v1/contracts/calls\n"
         "  admin:   POST /v1/checkpoint, POST /v1/cosignatures ([cosignature, witness key])\n"
         "  peer:    POST /v1/access/requests, GET /v1/access/deliveries/REQUEST,\n"
         "           POST /v1/access/receipts, POST /v1/witness/cosign,\n"
         "           POST /v1/assets/consents, GET /v1/assets/ASSET (the asset's parties),\n"
         "           POST /v1/contracts/calls, GET /v1/contracts/calls[/CALL],\n"
         "           POST /v1/contracts/consents, GET /v1/contracts/instances/INSTANCE\n"
         "           (the instance's parties)\n"
         "Requests send \"Authorization: Bearer TOKEN\" (cexchain token create). Reads run on all\n"
         "I/O threads at once; writes queue for one writer, which commits whatever has queued\n"
         "as a group with one sync. The server holds the ledger's lock only while writing, so\n"
         "other cexchain commands keep working on it.\n"
         "SIGINT or SIGTERM stops it gracefully."},
        {{"cluster", "init"},
         "Make this ledger the first member of a cluster",
         "Clusters",
         "",
         0,
         0,
         with({ledger_option,
               member_id_option,
               raft_option,
               {"raft-port", "PORT", "The port Raft listens on (default: that of --raft)"},
               member_api_option,
               {"secret-file", "FILE", "The cluster's shared secret (default: a new one)"}}),
         cmd_cluster_init,
         "A cluster keeps one ledger on several nodes with Raft: the leader takes the writes,\n"
         "a majority keeps each durably before it is acknowledged, and if the leader fails the\n"
         "others elect a new one within seconds. Three members ride out the loss of one.\n"
         "Each member holds the log key (its own HSM, or a key file) to sign checkpoints when\n"
         "it leads. Every Raft message is authenticated with the cluster's shared secret\n"
         "(<ledger>/cluster/secret): copy it to the other members privately. Members hold the\n"
         "ledger's lock while they run: use the command line with --server.\n"
         "API tokens, peers, and the access inbox are each member's own: copy api-tokens."},
        {{"cluster", "join"},
         "Copy a cluster's ledger here, ready to become a member",
         "Clusters",
         "",
         0,
         0,
         with({ledger_option,
               {"from", "URL", "A member's API", true},
               {"ledger-id", "ID", "The cluster's ledger (full hex id; required for http://)"},
               member_id_option,
               raft_option,
               {"raft-port", "PORT", "The port Raft listens on (default: that of --raft)"},
               member_api_option,
               {"secret-file", "FILE", "A copy of the cluster's shared secret", true},
               {"token-file", "FILE", "A read token for the member (default: $CEXCHAIN_TOKEN)"},
               {"ca-file", "FILE", "CA certificates (PEM) to trust for the member"}}),
         cmd_cluster_join,
         "Copies the ledger up to its latest checkpoint, re-validating it as a replica would.\n"
         "Then run it (cexchain serve --cluster) and add it (cexchain cluster add); Raft\n"
         "brings it the rest."},
        {{"cluster", "add"},
         "Add a running node as a member",
         "Clusters",
         "",
         0,
         0,
         cluster_api({member_id_option, raft_option, member_api_option}),
         cmd_cluster_add},
        {{"cluster", "remove"},
         "Remove a member",
         "Clusters",
         "",
         0,
         0,
         cluster_api({member_id_option}),
         cmd_cluster_remove,
         "The leader cannot be removed: step it down first."},
        {{"cluster", "step-down"},
         "Hand leadership to another member",
         "Clusters",
         "",
         0,
         0,
         cluster_api({}),
         cmd_cluster_step_down},
        {{"cluster", "status"},
         "Show the members, the leader, and Raft's progress",
         "Clusters",
         "",
         0,
         0,
         cluster_api({}),
         cmd_cluster_status},
        {{"token", "create"},
         "Create an API token for the server",
         "Server",
         "NAME",
         1,
         1,
         with({ledger_option,
               {"scope", "SCOPES", "read, submit, admin, comma-separated (default: read)"},
               {"out", "FILE", "Write the token to FILE (owner-only) instead of printing it"}}),
         cmd_token_create,
         "The token is shown once; the ledger keeps only its SHA-256. Scopes: read (the log,\n"
         "proofs, receipts, evidence, sealed vault data, metrics), submit (signed statements),\n"
         "admin (checkpoints, witness cosignatures), peer (another organization's access\n"
         "requests, deliveries, receipts, and witnessing). Name a peer's token after the peer\n"
         "(cexchain peer add NAME): it then reaches only that peer's own exchanges. A token\n"
         "only gates access: what a statement may do is still decided by its signature and\n"
         "the ledger's rules."},
        {{"token", "list"},
         "List API tokens",
         "Server",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_token_list},
        {{"token", "show"},
         "Show an API token's scopes and hash",
         "Server",
         "NAME",
         1,
         1,
         with({ledger_option}),
         cmd_token_show},
        {{"token", "revoke"},
         "Revoke an API token",
         "Server",
         "NAME",
         1,
         1,
         with({ledger_option}),
         cmd_token_revoke},

        // ------------------------------------------------------------------
        {{"replica", "init"},
         "Start a replica of a ledger served elsewhere",
         "Replicas",
         "",
         0,
         0,
         with({ledger_option,
               {"from", "URL", "The primary's API, e.g. https://ledger.example.com", true},
               {"ledger-id", "ID",
                "Replicate only this ledger (full hex id; required for http:// sources)"},
               {"token-file", "FILE", "A read token for the primary (default: $CEXCHAIN_TOKEN)"},
               {"ca", "FILE", "Trust these CA certificates (PEM) for the primary"}}),
         cmd_replica_init,
         "A replica copies the primary's log up to its latest checkpoint, the checkpoints,\n"
         "witness cosignatures, and sealed vault data. Each checkpoint is checked against the\n"
         "log key first, and the entries it covers must lead to its root before any is taken;\n"
         "every entry is re-validated with the ledger's rules. So a replica holds only what the\n"
         "log key signed, and trails the primary by its checkpoint interval. A primary cannot\n"
         "hand it a history that is not the ledger's: copying stops (exit 3) at the first\n"
         "entry that fails. Without TLS, pin the ledger with --ledger-id. Replicas refuse\n"
         "writes; serve one with cexchain serve for reads, back it up, or promote it."},
        {{"replica", "sync"},
         "Copy what is new on the primary",
         "Replicas",
         "",
         0,
         0,
         with({ledger_option,
               {"follow", "", "Keep syncing until interrupted"},
               {"interval", "SECONDS", "With --follow, how often (default: 10)"},
               {"token-file", "FILE", "A read token for the primary (default: $CEXCHAIN_TOKEN)"}}),
         cmd_replica_sync,
         "Exit 3 if the primary's history does not verify or was rolled back. With --follow,\n"
         "network failures are retried with backoff; a failed verification stops it."},
        {{"replica", "status"},
         "Show a replica's source and how far behind it is",
         "Replicas",
         "",
         0,
         0,
         with({ledger_option,
               {"token-file", "FILE", "A read token for the primary (default: $CEXCHAIN_TOKEN)"}}),
         cmd_replica_status},
        {{"replica", "promote"},
         "Make a replica the primary (after the old primary has stopped)",
         "Replicas",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_replica_promote,
         "Stop the old primary first, for good: two primaries would fork the ledger. The new\n"
         "primary needs the log key (keep it in an HSM, reachable from both)."},

        // ------------------------------------------------------------------
        {{"backup", "create"},
         "Back up a ledger to one file",
         "Backups",
         "",
         0,
         0,
         with(
             {ledger_option,
              {"out", "FILE", "Write the backup here", true},
              {"log-key", "KEY", "Sign the backup with the ledger's log key (file or pkcs11: URI)"},
              {"no-vault", "", "Leave out the vault (sealed record data and vault keys)"},
              passphrase_file_option}),
         cmd_backup_create,
         "The backup holds the log, checkpoints, witness cosignatures, API token hashes, and\n"
         "the vault: sealed record data, the vault public key, and the vault private key if it\n"
         "is kept in the ledger directory (encrypted, if it was).\n"
         "Checkpoints vouch for the log they cover. For the rest (entries after the last\n"
         "checkpoint, the tokens, the vault), sign with --log-key: a restore takes them only\n"
         "from a backup the log key signed, and from an unsigned one restores the signed log\n"
         "alone. Take backups from a replica to avoid pausing writes on the primary."},
        {{"backup", "verify"},
         "Check that a backup is complete and restores to a valid ledger",
         "Backups",
         "FILE",
         1,
         1,
         with({}),
         cmd_backup_verify,
         "Restores in memory, re-validating every entry and checkpoint, then audits the\n"
         "result. Exit 3 if anything fails."},
        {{"backup", "restore"},
         "Restore a backup into a new ledger directory",
         "Backups",
         "FILE",
         1,
         1,
         with({ledger_option}),
         cmd_backup_restore,
         "Every entry and checkpoint is re-validated as it is restored, and the ledger is\n"
         "audited at the end. The directory must not hold a ledger already."},

        // ------------------------------------------------------------------
        {{"peer", "add"},
         "Add another organization's ledger as a peer",
         "Other organizations",
         "NAME",
         1,
         1,
         with({ledger_option,
               {"ledger-id", "ID",
                "The peer's ledger id (full hex), learned through a channel you trust", true},
               {"url", "URL", "The peer's API, for online exchange and witnessing"},
               {"token-file", "FILE", "The token the peer issued you for its API"},
               {"ca", "FILE", "Trust these CA certificates (PEM) for the peer"},
               {"witness-key", "PUBKEY",
                "The peer's witness public key, if it witnesses this ledger"}}),
         cmd_peer_add,
         "A peer is pinned by its ledger id, which commits to its genesis, root key, and log\n"
         "key: evidence from any other ledger is refused, however it is signed."},
        {{"peer", "list"},
         "List peers",
         "Other organizations",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_peer_list},
        {{"peer", "show"},
         "Show a peer",
         "Other organizations",
         "NAME",
         1,
         1,
         with({ledger_option}),
         cmd_peer_show},
        {{"peer", "remove"},
         "Remove a peer",
         "Other organizations",
         "NAME",
         1,
         1,
         with({ledger_option}),
         cmd_peer_remove},
        {{"access", "request"},
         "Ask a peer for access to one of its records",
         "Other organizations",
         "",
         0,
         0,
         signing({{"peer", "NAME", "The peer to ask", true},
                  {"record", "ID", "The record on the peer's ledger (full hex id)", true},
                  {"purpose", "TEXT", "Why, recorded on both ledgers", true},
                  {"days", "N", "For how long (default: 30)"},
                  {"fields", "NAMES", "Only these fields, comma-separated (default: all)"},
                  {"attachments", "NAMES", "Only these attachments (default: all)"},
                  log_key_option,
                  {"out", "FILE", "Write the request (its evidence) here, to send"},
                  {"send", "", "Send it to the peer's API"}}),
         cmd_access_request,
         "Records an access request on this ledger, with a key made for it alone (kept\n"
         "sealed in this ledger's vault): the peer seals what it grants to that key."},
        {{"access", "send"},
         "Send an access request to the peer's API",
         "Other organizations",
         "REQUEST",
         1,
         1,
         with({ledger_option, {"peer", "NAME", "The peer", true}}),
         cmd_access_send_request},
        {{"access", "fetch"},
         "Fetch the delivery for a request from the peer's API",
         "Other organizations",
         "",
         0,
         0,
         with({ledger_option,
               {"peer", "NAME", "The peer", true},
               {"request", "ID", "The request", true},
               {"out", "FILE", "Write the delivery here", true}}),
         cmd_access_fetch},
        {{"access", "accept"},
         "Check a delivery, record a receipt, and show what was granted",
         "Other organizations",
         "DELIVERY",
         1,
         1,
         signing({log_key_option,
                  vault_key_option,
                  {"save-dir", "DIR", "Write the delivered attachments here"},
                  {"out", "FILE", "Write the receipt (its evidence) here, to send back"},
                  {"send", "", "Send the receipt to the peer's API"}}),
         cmd_access_accept,
         "Checks the grant against the peer's ledger, this ledger's request, and its key;\n"
         "opens the delivery; and checks the record's evidence, every disclosed field, and\n"
         "every attachment against the record's commitments. Exit 3 if anything fails."},
        {{"access", "inbox"},
         "List access requests received through the API",
         "Other organizations",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_access_inbox},
        {{"access", "grant"},
         "Grant an access request and make the delivery",
         "Other organizations",
         "REQUEST",
         1,
         1,
         signing({log_key_option,
                  vault_key_option,
                  {"fields", "NAMES", "Grant only these of the fields asked for"},
                  {"attachments", "NAMES", "Grant only these of the attachments asked for"},
                  {"attach", "NAME=FILE", "The content of a granted attachment", false, true},
                  {"days", "N", "For at most this long (default: 30, never past the request)"},
                  {"out", "FILE", "Also write the delivery here"}}),
         cmd_access_grant,
         "REQUEST is a request file, or a request in the inbox (by id prefix). The grant is\n"
         "recorded on this ledger; the delivery holds its evidence and the record's, with\n"
         "the granted fields and attachments, sealed to the requester's key. The requester\n"
         "can fetch it from this ledger's API. End a grant with: cexchain record revoke ID."},
        {{"access", "receipt"},
         "Check and keep a peer's receipt for a delivery",
         "Other organizations",
         "FILE",
         1,
         1,
         with({ledger_option}),
         cmd_access_receipt},
        {{"access", "list"},
         "List this ledger's access requests, grants, and receipts",
         "Other organizations",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_access_list},

        // ------------------------------------------------------------------
        {{"asset", "issue"},
         "Issue an ownership asset: a receivable or a warehouse receipt",
         "Ownership assets",
         "KIND",
         1,
         1,
         signing({{"holder", "PEER", "Who holds it: a peer's name or a ledger id", true},
                  {"amount", "AMOUNT", "Receivables: the amount, e.g. 125000.00"},
                  {"currency", "CODE", "Receivables: the ISO 4217 currency (default: CNY)"},
                  {"due", "DATE", "Receivables: when it falls due (YYYY-MM-DD)"},
                  {"quantity", "N", "Warehouse receipts: the quantity held"},
                  {"unit", "UNIT", "Warehouse receipts: the unit, e.g. t, kg, bale"},
                  {"title", "TEXT", "A public title"},
                  {"field", "NAME=VALUE", "A field (private until disclosed)", true, true},
                  {"meta", "NAME=VALUE", "More public metadata", false, true},
                  {"attach", "FILE", "Attach a file (committed by hash)", false, true}}),
         cmd_asset_issue,
         "KIND is receivable or warehouse-receipt. The asset lives on this ledger (its home):\n"
         "it changes only through asset actions, each with the consent of the parties it\n"
         "concerns, given on their own ledgers. The holder, amount (or quantity), and due date\n"
         "are public to whoever holds the asset's evidence; fields stay private until disclosed."},
        {{"asset", "show"},
         "Show an asset: its state, parties, and actions",
         "Ownership assets",
         "ASSET",
         1,
         1,
         with({ledger_option}),
         cmd_asset_show},
        {{"asset", "list"},
         "List this ledger's assets",
         "Ownership assets",
         "",
         0,
         0,
         with({ledger_option,
               {"type", "KIND", "Only receivable or warehouse-receipt"},
               {"state", "STATE", "Only this state, e.g. pledged"},
               {"holder", "PEER", "Only those this peer (or ledger id) holds"}}),
         cmd_asset_list},
        {{"asset", "record"},
         "Record an action on one of this ledger's assets",
         "Ownership assets",
         "ACTION ASSET",
         2,
         2,
         signing({{"to", "PEER", "The counterparty (transfer, pledge): a peer or a ledger id"},
                  {"quantity", "N", "How much (redeem)"},
                  {"reference", "TEXT", "A payment reference, a court order, a reason"},
                  {"consent", "FILE", "A party's consent (its evidence, from asset consent)", false,
                   true}}),
         cmd_asset_record,
         "ACTION is transfer, pledge, release, enforce, redeem, pay, confirm, dispute, freeze,\n"
         "unfreeze, or cancel. Pay, freeze, and unfreeze are this organization's own word; every\n"
         "other action needs the consent of each party it concerns (the holder, the counterparty,\n"
         "the pledgee, the payee), given on their own ledgers and passed here with --consent. A\n"
         "server with --registrar-key collects consents online instead."},
        {{"asset", "evidence"},
         "Write an asset's evidence, with the consents its actions pin",
         "Ownership assets",
         "ASSET",
         1,
         1,
         with({ledger_option,
               signing_log_key_option,
               vault_key_option,
               passphrase_file_option,
               {"fields", "NAMES", "Disclose these fields, comma-separated (* for all)"},
               {"attachments", "NAMES", "Open these attachments (* for all)"},
               {"out", "FILE", "Where to write it", true}}),
         cmd_asset_evidence,
         "Give it to the holder, or to a bank considering the asset: asset verify checks it\n"
         "offline. Disclosures do not depend on the checkpoint, so later evidence can carry them."},
        {{"asset", "consent"},
         "Consent, on this ledger, to an action on an asset on another ledger",
         "Ownership assets",
         "",
         0,
         0,
         signing({{"peer", "NAME", "The asset's home, a peer (or give --home)"},
                  {"home", "ID", "The asset's home ledger id (with --server)"},
                  {"asset", "ID", "The asset (full hex id)", true},
                  {"action", "ACTION",
                   "transfer, pledge, release, enforce, redeem, confirm, "
                   "dispute, or cancel",
                   true},
                  {"to", "PEER", "The counterparty (transfer, pledge): a peer or a ledger id"},
                  {"quantity", "N", "How much (redeem)"},
                  {"head", "N", "The asset's head the consent is to (default: ask the home)"},
                  {"evidence", "FILE", "Take the head from this asset evidence"},
                  {"days", "N", "The consent lapses after this many days (default: 7)"},
                  {"reference", "TEXT", "A financing contract, a registry filing number"},
                  signing_log_key_option,
                  {"out", "FILE", "Write the consent's evidence here"},
                  {"send", "", "Send it to the home's API (needs --peer)"}}),
         cmd_asset_consent,
         "Records a cexchain.asset-consent/1 record naming exact terms, and the asset's head:\n"
         "the consent applies only to the asset as it is now, and only once. The home records\n"
         "the action once every party it needs has consented. Before a pledge, a bank is no\n"
         "party yet: take the head from the evidence the holder gave you (--evidence)."},
        {{"asset", "withdraw"},
         "Withdraw a consent not used yet",
         "Ownership assets",
         "CONSENT",
         1,
         1,
         signing({}),
         cmd_asset_withdraw},
        {{"asset", "send"},
         "Send a consent's evidence to the asset's home",
         "Ownership assets",
         "FILE",
         1,
         1,
         with({ledger_option, {"peer", "NAME", "The asset's home", true}}),
         cmd_asset_send},
        {{"asset", "fetch"},
         "Fetch an asset's evidence from its home, as one of its parties",
         "Ownership assets",
         "",
         0,
         0,
         with({ledger_option,
               {"peer", "NAME", "The asset's home", true},
               {"asset", "ID", "The asset (full hex id)", true},
               {"out", "FILE", "Where to write it", true}}),
         cmd_asset_fetch},
        {{"asset", "verify"},
         "Verify an asset's evidence offline: its state and chain of title",
         "Ownership assets",
         "FILE",
         1,
         1,
         with({{"ledger-id", "ID", "The home's ledger id, learned out of band"},
               {"witness", "PUBKEY", "Trust this witness's public key file", false, true},
               {"min-witnesses", "N", "Fail unless at least N trusted witnesses cosigned"},
               {"require-presence", "", "Fail unless a person proved presence for each consent"},
               {"attachment", "NAME=FILE", "Check an attachment's content", false, true}}),
         cmd_asset_verify,
         "A lender funds only once its pledge is in a checkpoint cosigned by witnesses it trusts\n"
         "(--witness, --min-witnesses): a home that showed another lender a different history\n"
         "would need those witnesses to cosign it too, and a witness cosigns only one history."},

        // ------------------------------------------------------------------
        {{"contract", "deploy"},
         "Deploy a contract: a WebAssembly module that governs instances",
         "Contracts",
         "WASM",
         1,
         1,
         signing({{"function", "NAME=KIND",
                   "A function and its kind: create (makes an instance) or call (acts on one)",
                   true, true},
                  {"compiler", "TEXT", "The compiler and its version, e.g. \"bo 1.0\"", true},
                  {"language", "LANG",
                   "The language it was written in: bo, wasm, ... "
                   "(default: wasm)"},
                  {"source", "FILE", "Its source, so that anyone can rebuild it and compare"},
                  {"name", "TEXT", "A name for people"}}),
         cmd_contract_deploy,
         "WASM is a module in the contract profile (spec section 14): integer-only WebAssembly\n"
         "that exports cexchain_call and imports only from \"cexchain\", at most 512 KiB. It is\n"
         "checked here before it is signed. The contract's id is the deploy statement's id; its\n"
         "code never changes, so a new version is a new deploy. The ledger records a call only\n"
         "if the contract, run on it, accepts it; every verifier runs it again."},
        {{"contract", "show"},
         "Show a contract: its interface, code, and instances",
         "Contracts",
         "CONTRACT",
         1,
         1,
         with({ledger_option,
               {"code-out", "FILE", "Write its module here"},
               {"source-out", "FILE", "Write its source here (if it was deployed with it)"}}),
         cmd_contract_show},
        {{"contract", "list"},
         "List this ledger's contracts",
         "Contracts",
         "",
         0,
         0,
         with({ledger_option, {"active", "", "Only contracts not retired"}}),
         cmd_contract_list},
        {{"contract", "retire"},
         "Retire a contract: it creates no more instances",
         "Contracts",
         "CONTRACT",
         1,
         1,
         signing({reason_option}),
         cmd_contract_retire,
         "Its instances carry on under it until they are final. To change a contract, deploy a\n"
         "new version and create new instances of it."},
        {{"contract", "create"},
         "Create an instance of a contract, such as an agreement or an order",
         "Contracts",
         "CONTRACT FUNCTION",
         2,
         2,
         signing({args_option,
                  args_cbor_option,
                  {"reference", "TEXT", "A reference, such as an order number"},
                  dry_run_option}),
         cmd_contract_create,
         "FUNCTION is one the contract declared to create instances. The instance starts as this\n"
         "ledger's proposal, with the parties the contract names: a creation takes no consents.\n"
         "Each party is bound only once it consents to a later call.\n\n" CEXCHAIN_ARGUMENTS_HELP},
        {{"contract", "call"},
         "Call a function on one of this ledger's instances",
         "Contracts",
         "INSTANCE FUNCTION",
         2,
         2,
         signing({args_option,
                  args_cbor_option,
                  {"reference", "TEXT", "A reference, such as an invoice number"},
                  {"consent", "FILE", "A party's consent (its evidence, from contract consent)",
                   false, true},
                  dry_run_option}),
         cmd_contract_call,
         "The contract runs here first, as the ledger will run it: the call is recorded only if\n"
         "the contract accepts it. If it needs other parties' consents, pass each party's consent\n"
         "with --consent, or propose the call to this ledger's registrar (contract propose), "
         "which\n"
         "collects them online. A consent names the instance's head, so it counts "
         "once.\n\n" CEXCHAIN_ARGUMENTS_HELP},
        {{"contract", "instance"},
         "Show an instance: its status, parties, state, and calls",
         "Contracts",
         "INSTANCE",
         1,
         1,
         with({ledger_option}),
         cmd_contract_instance},
        {{"contract", "instances"},
         "List this ledger's contract instances",
         "Contracts",
         "",
         0,
         0,
         with({ledger_option,
               {"contract", "CONTRACT", "Only instances of this contract"},
               {"status", "STATUS", "Only instances with this status"},
               {"party", "PEER", "Only those where this peer (or ledger id) is a party"},
               {"open", "", "Only instances that are not final"}}),
         cmd_contract_instances},
        {{"contract", "evidence"},
         "Write an instance's evidence, with the consents its calls cite",
         "Contracts",
         "INSTANCE",
         1,
         1,
         with({ledger_option,
               signing_log_key_option,
               passphrase_file_option,
               {"out", "FILE", "Where to write it", true}}),
         cmd_contract_evidence,
         "Checkpoints first if the latest checkpoint does not cover the instance's last call.\n"
         "Give it to the parties or anyone relying on the instance: contract verify checks it\n"
         "offline, running the contract again on every call."},
        {{"contract", "propose"},
         "Propose a call to an instance's home, whose registrar collects the consents",
         "Contracts",
         "INSTANCE FUNCTION",
         2,
         2,
         with({ledger_option,
               {"peer", "NAME", "The instance's home, a peer (to propose as one of its parties)"},
               args_option,
               args_cbor_option,
               {"reference", "TEXT", "A reference, such as an invoice number"},
               {"head", "N", "The instance's head (default: as its home shows it now)"},
               {"days", "N", "The proposal lapses after N days (1 to 30; default: 7)"}}),
         cmd_contract_propose,
         "As one of the instance's parties, propose to its home with --peer (INSTANCE in full);\n"
         "as the home's staff, with --server and a submit token. The home's registrar (serve\n"
         "--registrar-key) runs the call without consents: it refuses a call the contract\n"
         "rejects, or takes as it is (the home's people sign those themselves); otherwise it\n"
         "holds the call and asks the ledgers the contract names to consent (contract pending,\n"
         "contract consent). It records the call once the contract accepts "
         "it.\n\n" CEXCHAIN_ARGUMENTS_HELP},
        {{"contract", "pending"},
         "List the calls a home's registrar holds, waiting for consents",
         "Contracts",
         "[CALL]",
         0,
         1,
         with(
             {ledger_option,
              {"peer", "NAME", "Ask this peer, the home, for the calls that concern this ledger"}}),
         cmd_contract_pending,
         "With --peer, the calls on that peer's instances that concern this ledger: as a party,\n"
         "as a ledger whose consent the contract asks for, or as one that consented. With\n"
         "--server, every call the server holds (a read token). Otherwise, the calls this\n"
         "ledger's own registrar holds, from its files. CALL (in full) shows one."},
        {{"contract", "consent"},
         "Consent, on this ledger, to a call on an instance on another ledger",
         "Contracts",
         "",
         0,
         0,
         signing({{"peer", "NAME", "The instance's home, a peer (or give --home)"},
                  {"home", "ID", "The home's ledger id (with --server)"},
                  {"call", "ID", "A call the home's registrar holds: take the terms from it"},
                  {"instance", "ID", "The instance (full hex id), without --call"},
                  {"function", "NAME", "The function called, without --call"},
                  args_option,
                  args_cbor_option,
                  {"head", "N", "The instance's head the consent is to (default: ask the home)"},
                  {"evidence", "FILE", "Take the head and the home's hash from this evidence"},
                  {"hash", "HASH", "The home's hash, sha256 or sm3 (default: learned from it)"},
                  {"days", "N", "The consent lapses after N days (default: 7)"},
                  {"reference", "TEXT", "A reference of yours, such as an approval number"},
                  signing_log_key_option,
                  {"out", "FILE", "Write the consent's evidence here"},
                  {"send", "", "Send it to the home's registrar (needs --peer)"}}),
         cmd_contract_consent,
         "Records a cexchain.contract-consent/1 record naming exact terms: the home, the\n"
         "instance, the function, a digest of the arguments (under the home's hash), and the\n"
         "instance's head. It applies to that one call only, once, until it lapses. With --call\n"
         "the terms come from the call the home's registrar holds (contract pending shows it;\n"
         "the terms are printed). Otherwise name them, as for contract call. Prove presence\n"
         "(--presence) if the contract wants a person to have approved in "
         "person.\n\n" CEXCHAIN_ARGUMENTS_HELP},
        {{"contract", "withdraw"},
         "Withdraw a contract consent not used yet",
         "Contracts",
         "CONSENT",
         1,
         1,
         signing({}),
         cmd_contract_withdraw},
        {{"contract", "send"},
         "Send a consent's evidence to the instance's home",
         "Contracts",
         "FILE",
         1,
         1,
         with({ledger_option, {"peer", "NAME", "The instance's home", true}}),
         cmd_contract_send},
        {{"contract", "fetch"},
         "Fetch an instance's evidence from its home, as one of its parties",
         "Contracts",
         "",
         0,
         0,
         with({ledger_option,
               {"peer", "NAME", "The instance's home", true},
               {"instance", "ID", "The instance (full hex id)", true},
               {"out", "FILE", "Where to write it", true}}),
         cmd_contract_fetch},
        {{"contract", "verify"},
         "Verify an instance's evidence offline: every call, its outcome, and its consents",
         "Contracts",
         "FILE",
         1,
         1,
         with({{"ledger-id", "ID", "The home's ledger id, learned out of band"},
               {"witness", "PUBKEY", "Trust this witness's public key file", false, true},
               {"min-witnesses", "N", "Fail unless at least N trusted witnesses cosigned"},
               {"require-presence", "", "Fail unless a person proved presence for each consent"}}),
         cmd_contract_verify,
         "Replays the instance's calls, running the contract again on each, and checks every\n"
         "consent a call cites on the consenting party's own ledger, with who gave it: a person\n"
         "present, a key alone, or an AI agent and its model."},
        // ------------------------------------------------------------------
        {{"mcp"},
         "Run an MCP server (stdio) for an AI agent",
         "AI agents",
         "",
         0,
         0,
         with({ledger_option,
               {"as", "KEY", "The agent's key file", true},
               {"log-key", "KEY",
                "The ledger's log key file: lets the agent's contract consents travel as "
                "evidence"},
               passphrase_file_option}),
         cmd_mcp,
         "Serves one AI agent over stdio (Model Context Protocol, revision 2026-07-28, and\n"
         "earlier revisions). Every write is signed with the agent's key, refused unless its\n"
         "delegations cover it, and recorded with provenance: the agent's model, a hash of the\n"
         "inputs it names, and the digest of the tool it used.\n\n"
         "Tools:\n"
         "  cexchain_whoami, cexchain_ledger_status, cexchain_record_types\n"
         "  cexchain_get_record, cexchain_issue_record, cexchain_endorse_record,\n"
         "  cexchain_transition_record, cexchain_verify_evidence\n"
         "  cexchain_list_assets, cexchain_get_asset, cexchain_verify_asset_evidence\n"
         "  cexchain_list_contracts, cexchain_get_instance, cexchain_verify_contract_evidence\n"
         "  cexchain_call_contract           create or call an instance on this ledger\n"
         "  cexchain_list_pending_calls      calls a home's registrar holds for this ledger\n"
         "  cexchain_fetch_instance          an instance from its home, verified\n"
         "  cexchain_propose_contract_call   propose a call to a home's registrar\n"
         "  cexchain_consent_contract_call   consent to a held call, and send the consent\n\n"
         "Contract tools reach other organizations as this ledger's peers (peer add). Consents\n"
         "travel as evidence, which needs a checkpoint: give --log-key to let the agent consent.\n"
         "Contract arguments are CBOR diagnostic notation; a JSON value works as well. MCP\n"
         "clients start the server without a terminal: give key passphrases with\n"
         "--passphrase-file or $CEXCHAIN_PASSPHRASE."},
    };
}

#undef CEXCHAIN_ARGUMENTS_HELP

void add_global_options(std::vector<CommandSpec>& specs) {
    for (CommandSpec& spec : specs) {
        auto has = [&](std::string_view name) {
            return std::ranges::any_of(spec.options,
                                       [&](const OptionSpec& o) { return o.name == name; });
        };
        const bool local =
            local_only.contains(spec.path.front()) ||
            (spec.path.size() > 1 && local_only_commands.contains({spec.path[0], spec.path[1]}));
        if (has("ledger") && !local) {
            for (const OptionSpec& option : client_options) {
                if (!has(option.name)) {
                    spec.options.push_back(option);
                }
            }
        }
        spec.options.push_back(json_option);
        spec.options.push_back(help_option);
    }
}

std::string join_path(const CommandSpec& spec) {
    std::string out;
    for (const std::string_view part : spec.path) {
        out += (out.empty() ? "" : " ") + std::string(part);
    }
    return out;
}

const OptionSpec* find_option(const CommandSpec& spec, std::string_view name) {
    const auto it = std::ranges::find(spec.options, name, &OptionSpec::name);
    return it == spec.options.end() ? nullptr : &*it;
}

} // namespace

const std::vector<CommandSpec>& registry() {
    static const std::vector<CommandSpec> specs = [] {
        auto built = build();
        add_global_options(built);
        return built;
    }();
    return specs;
}

std::string command_help(const CommandSpec& spec) {
    std::string out = std::format("cexchain {} - {}\n\nUsage: cexchain {}{}{} [options]\n",
                                  join_path(spec), spec.summary, join_path(spec),
                                  spec.arguments.empty() ? "" : " ", spec.arguments);
    if (!spec.details.empty()) {
        out += "\n" + std::string(spec.details) + "\n";
    }
    out += "\nOptions:\n";
    for (const OptionSpec& option : spec.options) {
        std::string left = "  --" + std::string(option.name);
        if (!option.value.empty()) {
            left += " " + std::string(option.value);
        }
        std::string notes;
        if (option.required) {
            notes += " [required]";
        }
        if (option.repeatable) {
            notes += " [repeatable]";
        }
        out += std::format("{:<30} {}{}\n", left, option.help, notes);
    }
    return out;
}

std::string overview_help() {
    std::string out =
        "cexchain - verifiable records for business, built for the age of AI agents\n\n"
        "Usage: cexchain COMMAND [arguments] [options]\n"
        "Every command accepts --help and --json. Set CEXCHAIN_LEDGER to skip --ledger.\n"
        "IDs may be abbreviated to any unique prefix of 8 or more hex digits.\n"
        "Private keys are encrypted; passphrases come from --passphrase-file, "
        "$CEXCHAIN_PASSPHRASE,\n"
        "or a prompt. Exit codes: 0 success, 1 usage error, 2 failure, 3 verification failed.\n";
    std::string group;
    for (const CommandSpec& spec : registry()) {
        if (spec.alias) {
            continue;
        }
        if (spec.group != group) {
            group = spec.group;
            out += "\n" + group + ":\n";
        }
        std::string name = join_path(spec);
        if (!spec.arguments.empty()) {
            name += " " + std::string(spec.arguments);
        }
        out += std::format("  {:<34} {}\n", name, spec.summary);
    }
    return out;
}

std::string completion_script(std::string_view shell) {
    // Words that may follow each command prefix, and options per full command.
    std::map<std::string, std::set<std::string>> next;
    std::map<std::string, std::vector<std::string>> options;
    for (const CommandSpec& spec : registry()) {
        std::string prefix;
        for (const std::string_view part : spec.path) {
            next[prefix].insert(std::string(part));
            prefix += (prefix.empty() ? "" : " ") + std::string(part);
        }
        for (const OptionSpec& option : spec.options) {
            options[prefix].push_back("--" + std::string(option.name));
        }
    }
    std::string cases;
    for (const auto& [prefix, words] : next) {
        std::string list;
        for (const std::string& w : words) {
            list += (list.empty() ? "" : " ") + w;
        }
        cases += std::format("        \"{}\") words=\"{}\" ;;\n", prefix, list);
    }
    std::string option_cases;
    for (const auto& [command, names] : options) {
        std::string list;
        for (const std::string& n : names) {
            list += (list.empty() ? "" : " ") + n;
        }
        option_cases += std::format("        \"{}\") opts=\"{}\" ;;\n", command, list);
    }
    std::string script = std::format(R"(# cexchain completion
_cexchain() {{
    local cur prefix words opts i w
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prefix=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        w="${{COMP_WORDS[i]}}"
        [[ "$w" == -* ]] && break
        prefix="${{prefix:+$prefix }}$w"
    done
    words=""
    case "$prefix" in
{}    esac
    opts=""
    case "$prefix" in
{}    esac
    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    elif [[ -n "$words" ]]; then
        COMPREPLY=($(compgen -W "$words" -- "$cur"))
    else
        COMPREPLY=($(compgen -f -- "$cur"))
    fi
}}
)",
                                     cases, option_cases);
    if (shell == "zsh") {
        return "autoload -U +X bashcompinit && bashcompinit\n" + script +
               "complete -o filenames -F _cexchain cexchain\n";
    }
    if (shell == "bash") {
        return script + "complete -o filenames -F _cexchain cexchain\n";
    }
    throw UsageError{"shell must be bash or zsh"};
}

int dispatch(int argc, const char* const* argv) {
    std::vector<std::string> tokens(argv + 1, argv + argc);
    // The command is the longest registered path matching the leading words.
    const CommandSpec* spec = nullptr;
    for (const CommandSpec& candidate : registry()) {
        if (candidate.path.size() > tokens.size()) {
            continue;
        }
        const bool matches =
            std::ranges::equal(candidate.path, std::span(tokens).first(candidate.path.size()),
                               [](std::string_view a, const std::string& b) { return a == b; });
        if (matches && (spec == nullptr || candidate.path.size() > spec->path.size())) {
            spec = &candidate;
        }
    }
    if (spec == nullptr) {
        if (tokens.empty() || tokens[0] == "--help" || tokens[0] == "-h") {
            std::print("{}", overview_help());
            return tokens.empty() ? 1 : 0;
        }
        if (tokens[0] == "--version") {
            return cmd_version(Args(registry().front(), {}, {}));
        }
        // A command group without a subcommand: list the group.
        std::string group;
        std::string suggestion;
        for (const CommandSpec& candidate : registry()) {
            if (candidate.path.size() > 1 && candidate.path.front() == tokens[0]) {
                group +=
                    std::format("  cexchain {:<30} {}\n", join_path(candidate), candidate.summary);
            }
            if (candidate.path.back() == tokens[0]) {
                suggestion += (suggestion.empty() ? "" : "' or 'cexchain ") + join_path(candidate);
            }
        }
        if (!group.empty()) {
            const bool asked = tokens.size() > 1 && (tokens[1] == "--help" || tokens[1] == "-h");
            std::print("{}", group);
            if (!asked && tokens.size() > 1) {
                throw UsageError{"unknown command '" + tokens[0] + " " + tokens[1] + "'"};
            }
            return asked ? 0 : 1;
        }
        throw UsageError{
            "unknown command '" + tokens[0] + "'" +
            (suggestion.empty() ? "" : "; did you mean 'cexchain " + suggestion + "'?") +
            " Run cexchain --help"};
    }

    std::vector<std::string> positional;
    std::multimap<std::string, std::string, std::less<>> options;
    for (std::size_t i = spec->path.size(); i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        if (!token.starts_with("--")) {
            positional.push_back(token);
            continue;
        }
        std::string name = token.substr(2);
        std::optional<std::string> value;
        if (const auto eq = name.find('='); eq != std::string::npos) {
            value = name.substr(eq + 1);
            name.resize(eq);
        }
        const OptionSpec* option = find_option(*spec, name);
        if (option == nullptr) {
            throw UsageError{"unknown option --" + name + " for 'cexchain " + join_path(*spec) +
                             "'; run it with --help"};
        }
        if (option->value.empty()) {
            if (value) {
                throw UsageError{"option --" + name + " takes no value"};
            }
            value = "";
        } else if (!value) {
            if (i + 1 >= tokens.size()) {
                throw UsageError{"option --" + name + " needs a value (" +
                                 std::string(option->value) + ")"};
            }
            value = tokens[++i];
        }
        if (!option->repeatable && options.contains(name)) {
            throw UsageError{"option --" + name + " given more than once"};
        }
        options.emplace(name, *value);
    }
    if (options.contains("help")) {
        std::print("{}", command_help(*spec));
        return 0;
    }
    for (const OptionSpec& option : spec->options) {
        if (option.required && !options.contains(option.name)) {
            throw UsageError{"missing required option --" + std::string(option.name) +
                             " for 'cexchain " + join_path(*spec) + "'"};
        }
    }
    if (positional.size() < spec->min_arguments || positional.size() > spec->max_arguments) {
        throw UsageError{"usage: cexchain " + join_path(*spec) +
                         (spec->arguments.empty() ? "" : " " + std::string(spec->arguments)) +
                         " [options]"};
    }
    return spec->run(Args(*spec, std::move(positional), std::move(options)));
}

} // namespace cexchain::cli
