// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// kanhe's commands: the table the registry dispatches, documents, and
// completes from.

#include "commands.hpp"
#include "registry_options.hpp"

namespace kanhe::cli {

std::vector<CommandSpec> chain_commands() {
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
         "Load with: source <(kanhe completion bash)   or   source <(kanhe completion zsh)"},

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
         "  pkcs11:token=Kanhe;object=alice?module-path=/usr/lib/softhsm/libsofthsm2.so\n"
         "Its PIN comes from pin-value= or pin-source= in the URI, $KANHE_PKCS11_PIN, or a\n"
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
                "Read the new passphrase from FILE (default: $KANHE_NEW_PASSPHRASE or a "
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
               {"name", "NAME",
                "Whose ledger it is: a person's or an organization's name (required; or --org)"},
               {"org", "NAME", "The same as --name"},
               {"root-key", "KEY", "The owner's root key file", true},
               {"log-key", "KEY", "Log key file (signs checkpoints and receipts)", true},
               {"hash", "HASH", "sha256 (default) or sm3"},
               {"vault-public-key", "FILE",
                "Seal private record data to this key (from kanhe vault keygen) instead of "
                "creating <ledger>/vault.key"},
               passphrase_file_option}),
         cmd_init,
         "Creates the ledger and its vault key: private record data (field values and salts)\n"
         "is sealed to <ledger>/vault.pub; reading it needs <ledger>/vault.key, encrypted with\n"
         "your passphrase. Back the vault key up: without it, private data cannot be disclosed.\n"
         "\n"
         "A ledger belongs to one owner, a person or an organization, named by --name and\n"
         "identified by its root key, which registers the people, AI agents, and devices who\n"
         "act on it. Keep the root key offline and act with keys it delegates to."},
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
         "audit also re-checks every stored checkpoint against the log. Opened from a\n"
         "snapshot, it replays the whole log as well, and requires the same state."},
        {{"ledger", "snapshot", "create"},
         "Write a snapshot of the state, for opens to start from",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_ledger_snapshot_create,
         "Right after a checkpoint (kanhe checkpoint create), with nothing logged after it.\n"
         "Opens then take the state from the newest snapshot that checks against the log, and\n"
         "replay only what follows; a server opened from one replays the whole log in the\n"
         "background and compares, and kanhe audit does too. A snapshot is a cache, kept\n"
         "in two files beside the log (snapshot-a, snapshot-b), never sent anywhere. One is\n"
         "written by itself after a checkpoint once the log has grown 100,000 entries since\n"
         "the last (serve --snapshot-interval)."},
        {{"ledger", "snapshot", "show"},
         "Show the newest snapshot, and whether this open started from it",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_ledger_snapshot_show},
        {{"ledger", "snapshot", "remove"},
         "Remove the snapshots: opens replay the whole log",
         "Ledger",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_ledger_snapshot_remove},
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
         "added from it (kanhe witness add-log --genesis) can follow key rotations."},
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
                   "The new actor's public key file (from kanhe key public), or its private key "
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
         signing({{"credential", "FILE", "A passkey credential file (from kanhe presence enroll)",
                   false, true},
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
               {"label", "TEXT", "A label, e.g. \"MacBook Touch ID\" or \"Office UKey\""},
               {"pkcs11", "URI", "Enroll this hardware key (a key on a USB key or smart card)"},
               no_browser_option}),
         cmd_presence_enroll,
         "Opens the browser to create a passkey (Touch ID, Windows Hello, a phone, or a security\n"
         "key) for the site \"localhost\"; or, with --pkcs11, enrolls a key on a token (a UKey or\n"
         "smart card), which proves presence by signing after its PIN is entered. Only public\n"
         "data is written to FILE; give it to your administrator to register with\n"
         "kanhe actor set-presence."},

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
               "Comma-separated contracts its calls and retires may act on (default: any)"},
              {"functions", "NAMES",
               "Comma-separated functions its contract calls may name (default: any)"},
              {"request-kinds", "KINDS",
               "Its contract calls may only answer requests of these kinds, comma-separated"}}),
         cmd_delegation_grant,
         "Statement types: actor-register, actor-rotate-key, actor-revoke, actor-set-presence,\n"
         "delegation-grant, delegation-revoke, record-register, record-endorse,\n"
         "record-transition, record-revoke, contract-deploy, contract-call, contract-retire.\n"
         "--contracts limits contract-call and contract-retire to those contracts (a call on\n"
         "an instance acts on the instance's contract); --functions limits contract calls to\n"
         "those functions, creations included; --request-kinds makes its contract calls\n"
         "answers to requests of those kinds, nothing else (an executor's delegation: see\n"
         "executor add). A delegation granted under it may name only some of them.\n\n"
         "  kanhe delegation grant --to 5d0e7a21 --allow contract-call --contracts 3f2a9c1e \\\n"
         "      --functions result --request-kinds notify --as root.key"},
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
         signing(
             {{"type", "TYPE", "Record type: a name of your own, e.g. example.org.photo/1", true},
              {"field", "NAME=VALUE", "A field (private until disclosed)", true, true},
              {"meta", "NAME=VALUE", "Public metadata", false, true},
              {"attach", "FILE", "Attach a file (committed by hash)", false, true},
              {"keep-files", "",
               "Also keep the attached files with the record, sealed to the vault key (16 MiB "
               "each at most)"},
              {"supersedes", "RECORD",
               "The record this one replaces, as its new version (the old one then shows as "
               "superseded)"}}),
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
               {"current", "", "Leave out records a newer version superseded"},
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
        {{"claim", "issue"},
         "Confirm a condition on a record's fields, without them",
         "Claims",
         "RECORD",
         1,
         1,
         signing({{"if", "CONDITION",
                   "FIELD OP VALUE: OP is >, >=, <, <=, =, !=, between (LOW and HIGH), in (A,B), "
                   "or exists",
                   true, true},
                  {"subject", "TEXT", "Whom or what the record is about, as you name them"},
                  {"until", "DATE", "The claim lapses then (YYYY-MM-DD or an ISO time)"},
                  {"allow-no", "", "Issue it even if the condition does not hold, saying so"},
                  vault_key_option}),
         cmd_claim_issue,
         "Checks the condition against RECORD's private data (opened with the vault key) and\n"
         "registers a kanhe.claim/1 record saying that it holds, as of now. Values: money\n"
         "as HKD 30000.00, dates as YYYY-MM-DD, numbers, and text (quoted if it looks like\n"
         "one of those). Several --if must all hold. If the condition does not hold, no claim\n"
         "is issued unless --allow-no: by default asking reveals nothing more than silence.\n"
         "The claim's evidence shows the condition and the answer, and whether RECORD was\n"
         "revoked or replaced since, but none of its fields; record publish gives it an\n"
         "address for a QR code."},
        {{"claim", "list"},
         "List the claims on the ledger",
         "Claims",
         "",
         0,
         0,
         with({ledger_option, {"source", "RECORD", "Only claims about this record"}}),
         cmd_claim_list,
         "Each with its status: standing, lapsed, withdrawn, or its source revoked or\n"
         "replaced since."},
        {{"claim", "show"},
         "Show a claim",
         "Claims",
         "CLAIM",
         1,
         1,
         with({ledger_option}),
         cmd_claim_show},
        {{"claim", "revoke"},
         "Withdraw a claim (its record is revoked)",
         "Claims",
         "CLAIM",
         1,
         1,
         signing({reason_option}),
         cmd_claim_revoke},
        {{"credential", "key", "add"},
         "Register a credential key: a device that signs records' W3C credentials",
         "Credentials",
         "NAME",
         1,
         1,
         signing({{"key", "KEY",
                   "Its key (esp256): a public key file, private key file, or pkcs11: URI"},
                  {"key-out", "FILE", "Make a new esp256 key for it here instead (encrypted)"},
                  {"types", "TYPES",
                   "The record types whose credentials it issues, comma-separated (default: any)"},
                  {"days", "N", "Its delegation is valid for N days from now"},
                  {"until", "DATE", "Its delegation is valid until DATE"}}),
         cmd_credential_key_add,
         "Registers a device with an ECDSA P-256 key (esp256, which wallets accept), and grants\n"
         "it a delegation to endorse records and nothing else. It issues a credential by\n"
         "endorsing the record as credential/N/I (its status list entry), so the ledger shows\n"
         "every credential issued, by which key, and when (spec/credentials.md).\n\n"
         "  kanhe credential key add Credentials --key-out credentials.key --as root.key"},
        {{"credential", "key", "list"},
         "List the credential keys, with the credentials each issued",
         "Credentials",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_credential_key_list},
        {{"credential", "key", "revoke"},
         "Revoke a credential key: its keys leave the DID document",
         "Credentials",
         "ACTOR",
         1,
         1,
         signing({reason_option}),
         cmd_credential_key_revoke,
         "For a key that was lost or stolen. Credentials it signed then fail a standard\n"
         "verifier's check; issue them again with another credential key."},
        {{"credential", "issue"},
         "Issue a published record's W3C Verifiable Credential",
         "Credentials",
         "TOKEN",
         1,
         1,
         signing({{"url", "URL",
                   "The base URL your server is reached at, which the credential names "
                   "(default: --server's)"},
                  {"name", "TEXT", "The credential's name, e.g. Diploma in Nursing"},
                  {"metadata", "KEYS",
                   "Public metadata entries to claim too, comma-separated (the fields the "
                   "address discloses always are)"},
                  {"out", "FILE", "Write the credential here (default: print it)"},
                  signing_log_key_option}),
         cmd_credential_issue,
         "TOKEN is a published record's (record publish, certificate issue). The credential\n"
         "claims exactly what its address discloses, from the record's evidence, verified\n"
         "here: a W3C Verifiable Credential (VCDM 2.0) secured with JOSE (application/vc+jwt),\n"
         "signed as --as, a credential key (credential key add). The first time, the key\n"
         "endorses the record as credential/N/I, its status list entry; issued again, the\n"
         "credential keeps that entry and is signed with the key's current key.\n"
         "The issuer is the did:web of --url: serve --credential-key and --credential-url\n"
         "there, so that wallets find its DID document and status lists.\n\n"
         "  kanhe credential issue Xq3... --as credentials.key --url https://ledger.example.com "
         "\\\n"
         "      --name \"Diploma in Nursing\" --out diploma.jwt --log-key log.key"},
        {{"credential", "list"},
         "List the credentials the ledger shows, with each record's status",
         "Credentials",
         "",
         0,
         0,
         with({ledger_option, {"type", "TYPE", "Only records of this type"}}),
         cmd_credential_list,
         "Each record endorsed as credential/N/I: live, revoked, or replaced."},
        {{"credential", "show"},
         "Show a record's credentials: status entry, issuer, status",
         "Credentials",
         "RECORD",
         1,
         1,
         with({ledger_option}),
         cmd_credential_show},
        {{"credential", "revoke"},
         "Revoke a credential: its record is revoked",
         "Credentials",
         "RECORD",
         1,
         1,
         signing({reason_option}),
         cmd_credential_revoke,
         "A credential is revoked with its record: the status lists then say so, and the\n"
         "record's evidence too. A newer version of the record (record register --supersedes)\n"
         "also sets its old credentials' bits."},
        {{"credential", "status"},
         "Show a status list, or write it signed for a static host",
         "Credentials",
         "[N]",
         0,
         1,
         with({ledger_option,
               {"out", "FILE", "Write the signed status list credential here (with --as, --url)"},
               {"as", "KEY", "The credential key that signs it (with --out)"},
               {"url", "URL", "The base URL (with --out; default: --server's)"},
               passphrase_file_option}),
         cmd_credential_status,
         "A status list is computed from the ledger: bit I of list N is set when a record\n"
         "endorsed as credential/N/I is revoked or replaced. serve --credential-key serves\n"
         "them at /status/N as the ledger is when asked; --out writes one for a static host."},
        {{"credential", "did-document"},
         "Print the issuer's DID document (did:web), or write it for a static host",
         "Credentials",
         "",
         0,
         0,
         with({ledger_option,
               {"url", "URL", "The base URL (default: --server's)"},
               {"key", "KEY", "Include this credential key, even before it issued anything"},
               {"out", "FILE", "Write it here"},
               passphrase_file_option}),
         cmd_credential_did_document,
         "Every key of every unrevoked credential key that issued a credential, current and\n"
         "earlier, and the ledger id as its KanheLedger service. serve --credential-key serves\n"
         "it at /.well-known/did.json (and /did.json, for a base URL with a path)."},
        {{"credential", "verify"},
         "Verify a W3C credential, and the record behind it on the issuer's ledger",
         "Credentials",
         "FILE",
         1,
         1,
         with({{"ledger-id", "ID", "The issuer's ledger id, learned out of band"},
               {"evidence", "FILE", "The record's evidence (default: fetched from the credential)"},
               {"did-document", "FILE", "The issuer's DID document (default: fetched)"},
               {"status-list", "FILE", "The status list credential (default: fetched)"},
               {"offline", "", "Fetch nothing: check only what the files give (--evidence needed)"},
               {"no-fetch", "", "Fetch only the evidence, not the DID document or status list"},
               {"allow-http", "", "Fetch http:// addresses (tests and local servers only)"},
               {"ca-file", "FILE", "CA certificates (PEM) to trust when fetching"},
               {"witness", "PUBKEY", "Trust this witness's public key file", false, true},
               {"tsa-root", "FILE",
                "Trust time-stamp authorities under this root certificate (PEM or DER)", false,
                true}}),
         cmd_credential_verify,
         "Checks the credential as a standard verifier would (the signature, the DID document,\n"
         "the status list), and then the record behind it: its evidence verifies, the record\n"
         "was endorsed as this credential by the device whose key signed it, and every claim,\n"
         "the issuer's name, and the date are what the evidence shows. A status list that\n"
         "disagrees with the ledger fails. Exit status 3 when it does not verify."},
        {{"trust", "member", "add"},
         "Register a membership: your word that a ledger belongs to whom you name",
         "Trust nodes",
         "LEDGER",
         1,
         1,
         signing({{"name", "NAME", "The name you checked, or a person's display name", true},
                  {"kind", "KIND", "organization (default) or person"},
                  {"verified", "", "You checked who they are (else: self-declared)"},
                  {"registration", "TEXT", "A company or registry number"},
                  {"jurisdiction", "CODE", "ISO 3166: HK, or CN-44 for a subdivision"},
                  {"until", "DATE", "The membership lapses after it (YYYY-MM-DD or an ISO time)"},
                  {"note", "TEXT", "How you checked them, kept sealed with the membership"}}),
         cmd_trust_member_add,
         "Registers a kanhe.membership/1 record naming LEDGER as a member: this ledger acts\n"
         "as a trust node. A verifier who chose this trust node then sees, in the member's\n"
         "evidence, whom the member is, as you checked them. The member fetches its proof\n"
         "from your server (GET /m/LEDGER, served to anyone) with trust node fetch."},
        {{"trust", "member", "list"},
         "List the memberships this trust node registered",
         "Trust nodes",
         "",
         0,
         0,
         with({ledger_option, {"member", "LEDGER", "Only memberships naming this ledger"}}),
         cmd_trust_member_list,
         "Each with its status: active, suspended, ended, lapsed, or revoked."},
        {{"trust", "member", "show"},
         "Show a membership",
         "Trust nodes",
         "MEMBERSHIP",
         1,
         1,
         with({ledger_option}),
         cmd_trust_member_show},
        {{"trust", "member", "suspend"},
         "Suspend a membership (resume it later)",
         "Trust nodes",
         "MEMBERSHIP",
         1,
         1,
         signing({}),
         cmd_trust_member_suspend},
        {{"trust", "member", "resume"},
         "Resume a suspended membership",
         "Trust nodes",
         "MEMBERSHIP",
         1,
         1,
         signing({}),
         cmd_trust_member_resume},
        {{"trust", "member", "end"},
         "End a membership: the member left, or did not renew",
         "Trust nodes",
         "MEMBERSHIP",
         1,
         1,
         signing({}),
         cmd_trust_member_end},
        {{"trust", "member", "revoke"},
         "Revoke a membership for cause",
         "Trust nodes",
         "MEMBERSHIP",
         1,
         1,
         signing({reason_option}),
         cmd_trust_member_revoke},
        {{"trust", "node", "add"},
         "List a trust node this ledger belongs to, to fetch its proof from",
         "Trust nodes",
         "NAME",
         1,
         1,
         with({ledger_option,
               {"ledger-id", "ID", "The trust node's ledger id, learned out of band", true},
               {"url", "URL", "The trust node's server", true}}),
         cmd_trust_node_add,
         "At most 16. On the ledger's own directory: a server adds the proofs kept here to\n"
         "the evidence it serves (/v1/evidence, /c/TOKEN), and export adds them too."},
        {{"trust", "node", "list"},
         "List the trust nodes this ledger belongs to, with the proof kept from each",
         "Trust nodes",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_trust_node_list},
        {{"trust", "node", "remove"},
         "Stop listing a trust node; its proof no longer goes with the evidence",
         "Trust nodes",
         "NAME",
         1,
         1,
         with({ledger_option}),
         cmd_trust_node_remove},
        {{"trust", "node", "fetch"},
         "Fetch this ledger's membership proofs from its trust nodes",
         "Trust nodes",
         "[NAME]",
         0,
         1,
         with({ledger_option}),
         cmd_trust_node_fetch,
         "From each trust node listed (or NAME): its newest membership naming this ledger,\n"
         "checked, kept in place of the one before. A proof shows the membership as of its\n"
         "checkpoint, so fetch again from time to time (a suspension shows only then)."},
        {{"record", "publish"},
         "Publish a record at a private address: its evidence as it is, with chosen fields",
         "Records",
         "RECORD",
         1,
         1,
         with({ledger_option,
               {"disclose", "FIELDS",
                "Comma-separated fields shown at the address (those printed on the paper)"},
               {"url", "URL",
                "The server's public address, to print the whole address (default: the "
                "server's, in client mode)"},
               vault_key_option,
               passphrase_file_option}),
         cmd_record_publish,
         "The ledger's server answers GET /c/TOKEN, from anyone and any page, with the\n"
         "record's evidence as it is then (revoked or replaced since, it says so) and the\n"
         "fields named here disclosed. TOKEN is random: nobody finds the address without\n"
         "being given it, so give it only where those fields may be seen. Put it in a QR\n"
         "code: kanhe qr RECORD --bundle-url ADDRESS --verifier-url\n"
         "https://kanhe.cirraya.com/verify/. Not yet on a cluster's members."},
        {{"record", "published"},
         "List the records published at private addresses",
         "Records",
         "",
         0,
         0,
         with({ledger_option,
               {"url", "URL", "The server's public address, to print whole addresses"}}),
         cmd_record_published},
        {{"record", "unpublish"},
         "Take a published record's address down (the record stays on the ledger)",
         "Records",
         "TOKEN",
         1,
         1,
         with({ledger_option}),
         cmd_record_unpublish},
        {{"record", "versions"},
         "Show a record's versions, oldest first: those it superseded, and those that "
         "superseded it",
         "Records",
         "RECORD",
         1,
         1,
         with({ledger_option}),
         cmd_record_versions},
        {{"record", "fields"},
         "Show a record's private field values (from the vault)",
         "Records",
         "RECORD",
         1,
         1,
         with({ledger_option, vault_key_option, passphrase_file_option}),
         cmd_record_fields},
        {{"record", "file", "list"},
         "List a record's attached files, and which are kept",
         "Records",
         "RECORD",
         1,
         1,
         with({ledger_option}),
         cmd_record_file_list},
        {{"record", "file", "get"},
         "Write a record's kept file, checked against the record",
         "Records",
         "RECORD NAME",
         2,
         2,
         with({ledger_option,
               {"out", "FILE", "Where to write it", true},
               vault_key_option,
               passphrase_file_option}),
         cmd_record_file_get,
         "NAME is the attachment's name (or its index). The kept copy is opened with the vault\n"
         "key and must be the file the record committed to."},
        {{"record", "file", "add"},
         "Keep a copy of a record's attached file, sealed to the vault key",
         "Records",
         "RECORD FILE",
         2,
         2,
         with({ledger_option,
               {"name", "NAME", "The attachment it is (default: the file's name)"},
               vault_key_option,
               passphrase_file_option}),
         cmd_record_file_add,
         "The file must be the one the record committed to; a copy is kept once, and another\n"
         "file is refused for the same attachment."},
        {{"record", "file", "remove"},
         "Remove a record's kept file (the record still commits to it)",
         "Records",
         "RECORD NAME",
         2,
         2,
         with({ledger_option}),
         cmd_record_file_remove},
        {{"record", "endorse"},
         "Endorse a record in a role",
         "Records",
         "RECORD",
         1,
         1,
         signing({{"role", "ROLE", "Any role name, e.g. author, reviewer, approver", true}}),
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
         "List the protocol's own record types and their lifecycles",
         "Records",
         "",
         0,
         0,
         {},
         cmd_record_types,
         "Any other type is the registrant's own: a record's type is a name you choose\n"
         "(such as example.org.photo/1), with the generic lifecycle. This command lists the\n"
         "protocol's own types, which carry access requests, grants, and receipts, and\n"
         "consents to contract calls."},

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
         with({relay_log_key_option,
               ledger_option,
               {"witness", "PUBKEY", "The witness's public key file"},
               {"peer", "NAME", "A peer that witnesses this ledger (its witness key)"},
               {"out", "FILE", "Write the request here, for the witness"},
               {"send", "", "Send it to the peer's API and store the cosignature it returns"},
               {"from", "SIZE",
                "Prove consistency from this size (default: the witness's last cosigned size)"}}),
         cmd_checkpoint_cosign_request,
         "The request holds the checkpoint and a consistency proof from the last checkpoint the\n"
         "witness cosigned. Send it to the witness (kanhe witness cosign), then store the\n"
         "cosignature it returns with kanhe checkpoint add-cosignature. With --peer and\n"
         "--send, a peer running kanhe serve --witness-dir cosigns it online: two\n"
         "organizations witness each other with no third party."},
        {{"checkpoint", "add-cosignature"},
         "Store a witness's cosignature; exports then include it",
         "Checkpoints and proofs",
         "FILE",
         1,
         1,
         with({ledger_option, {"witness", "PUBKEY", "The witness's public key file", true}}),
         cmd_checkpoint_add_cosignature},
        {{"checkpoint", "timestamp"},
         "Ask a time-stamp authority to stamp a checkpoint (default: the latest)",
         "Checkpoints and proofs",
         "",
         0,
         0,
         with({ledger_option,
               {"tsa", "URL", "The time-stamp authority's URL (RFC 3161 over HTTP)", true},
               {"size", "N", "Stamp the latest checkpoint of this size"},
               {"ca-file", "FILE", "Trust these CA certificates (PEM) for an https:// authority"},
               {"out", "FILE", "Also write the token here"}}),
         cmd_checkpoint_timestamp,
         "The authority signs, at its own time, a digest of the checkpoint. Whoever trusts it\n"
         "then knows that everything the checkpoint covers existed by that time, and verifiers\n"
         "refuse evidence whose ledger dates such an entry later (spec v0.11). Exports carry\n"
         "the tokens (verify --tsa-root). kanhe serve --tsa URL asks by itself."},
        {{"checkpoint", "add-timestamp"},
         "Store a time-stamp token got another way; exports then include it",
         "Checkpoints and proofs",
         "FILE",
         1,
         1,
         with({ledger_option,
               {"size", "N", "The size of the checkpoint it stamps (default: the latest)"}}),
         cmd_checkpoint_add_timestamp,
         "FILE is an RFC 3161 TimeStampToken (DER) over the checkpoint: its message imprint is\n"
         "the timestamp_imprint that kanhe checkpoint show --json gives, under the ledger's\n"
         "hash (for example: openssl ts -query -digest IMPRINT -sha256 -cert)."},
        {{"checkpoint", "timestamps"},
         "List the time-stamp tokens over checkpoints",
         "Checkpoints and proofs",
         "",
         0,
         0,
         with({ledger_option,
               {"size", "N", "Only those over checkpoints of this size"},
               {"tsa-root", "FILE", "Say whether each chains to this root certificate (PEM or DER)",
                false, true}}),
         cmd_checkpoint_timestamps},
        {{"checkpoint", "note"},
         "Print a checkpoint as an open network's checkpoint note (default: the latest)",
         "Checkpoints and proofs",
         "",
         0,
         0,
         with({ledger_option,
               {"size", "N", "The latest checkpoint of this size"},
               {"note-key", "KEY", "Sign it with this note key (Ed25519; file or pkcs11: URI)"}}),
         cmd_checkpoint_note,
         "The note an open witness network cosigns (spec v0.13, c2sp.org/tlog-checkpoint):\n"
         "the ledger's origin, cirraya.com/kanhe/<ledger id>, the tree size, and the root\n"
         "in base64. With --note-key, signed as a log signs it, as add-checkpoint sends it.\n"
         "SHA-256 ledgers only."},
        {{"checkpoint", "network-cosign"},
         "Ask the open-network witnesses listed here to cosign a checkpoint (default: the latest)",
         "Checkpoints and proofs",
         "",
         0,
         0,
         with({ledger_option,
               {"note-key", "KEY", "The ledger's note key (Ed25519; file or pkcs11: URI)", true},
               {"size", "N", "The latest checkpoint of this size"},
               {"witness", "NAME", "Ask only this one"},
               {"ca-file", "FILE", "Trust these CA certificates (PEM) for https:// witnesses"}}),
         cmd_checkpoint_network_cosign,
         "Each witness listed with kanhe witness register URL --vkey VKEY gets the\n"
         "checkpoint's note, signed with the note key, and a consistency proof from the size\n"
         "it cosigned last (c2sp.org/tlog-witness add-checkpoint). Its cosignature is kept,\n"
         "and exports carry it (verify --witness-vkey). A witness that cosigned a larger tree\n"
         "of this ledger is reported, not asked again: a fork, or a restore from an old\n"
         "backup. kanhe serve --note-key asks by itself."},
        {{"checkpoint", "network-cosignatures"},
         "List the open-network witnesses' cosignatures of checkpoints",
         "Checkpoints and proofs",
         "",
         0,
         0,
         with({ledger_option, {"size", "N", "Only those of checkpoints of this size"}}),
         cmd_checkpoint_network_cosignatures},
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
         with(
             {{"ledger-id", "ID", "The issuer's ledger id, learned out of band"},
              {"witness", "PUBKEY", "Trust this witness's public key file", false, true},
              {"witness-vkey", "VKEY",
               "Trust this open network's witness, by its verifier key (spec v0.13); it counts "
               "toward --min-witnesses",
               false, true},
              {"min-witnesses", "N", "Fail unless at least N trusted witnesses cosigned"},
              {"tsa-root", "FILE",
               "Trust time-stamp authorities under this root certificate (PEM or DER)", false,
               true},
              {"min-timestamps", "N",
               "Fail unless at least N trusted time-stamp authorities stamped it"},
              {"attachment", "NAME=FILE", "Check an attachment's content", false, true},
              {"trust-node", "LEDGER=NAME",
               "Believe this trust node's memberships, naming it NAME (spec v0.16)", false, true}}),
         cmd_verify},
        {{"qr"},
         "Make a QR code that opens a record's or an instance's evidence in the browser verifier",
         "Evidence",
         "RECORD|INSTANCE",
         1,
         1,
         with({ledger_option,
               {"bundle-url", "URL",
                "Where you publish the evidence (from kanhe export, or contract evidence)", true},
               {"verifier-url", "URL", "Where you host kanhe-verify.html", true},
               {"out", "FILE", "Write an SVG image (default: draw the code in the terminal)"}}),
         cmd_qr,
         "The code links to the verifier page with the ledger id, the record id, and the bundle's\n"
         "URL. Scanning it verifies the evidence on the scanner's own device; the page refuses\n"
         "evidence about another record or from another ledger. The server that hosts the bundle\n"
         "must allow cross-origin requests from the verifier's origin."},
        {{"inspect"},
         "Decode any Kanhe file",
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
        {{"relay", "key", "init"},
         "Generate the key a ledger's parties seal requests to when it is reached through a relay",
         "Relays",
         "",
         0,
         0,
         with({{"out", "FILE", "Write the private key here", true},
               {"no-passphrase", "", "Store the private key unencrypted (not recommended)"},
               passphrase_file_option}),
         cmd_relay_key_init},
        {{"relay", "use"},
         "Be reached through a relay: parties' requests wait there, sealed, for this ledger",
         "Relays",
         "URL",
         1,
         1,
         with({ledger_option,
               {"relay-key", "FILE", "This ledger's relay key (relay key init)", true},
               {"witness-key", "PUBKEY",
                "The relay's witness key, if this ledger is not registered with it yet (a public "
                "key file or its hex, as its operator publishes it)"},
               passphrase_file_option}),
         cmd_relay_use,
         "For a ledger that no party reaches directly (a laptop). The relay is the server of a\n"
         "public witness (serve --witness-public --relay-dir); this ledger registers with that\n"
         "witness if it has not. From then on, invitation codes (peer invite) carry the relay\n"
         "and the relay key, and serve --relay-key FILE answers the requests that come for this\n"
         "ledger with its own API, as if they had come directly: the peer token in each decides.\n"
         "The relay learns who writes to whom, when, and how much; never what."},
        {{"relay", "show"},
         "Show the relay this ledger is reached through, and what waits in its mailbox",
         "Relays",
         "",
         0,
         0,
         with({ledger_option,
               {"log-key", "KEY", "The ledger's log key file, to look in the mailbox"},
               passphrase_file_option}),
         cmd_relay_show},
        {{"relay", "stop"},
         "Stop being reached through a relay (new invitation codes carry none)",
         "Relays",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_relay_stop},
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
                "Passphrase for a generated key (default: $KANHE_NEW_PASSPHRASE or a prompt)"}}),
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
                "The ledger's genesis entry (from kanhe ledger genesis): fixes the ledger id "
                "and its keys, so the witness can follow key rotations"},
               {"ledger-id", "ID",
                "The ledger's id (full hex), from its operator: pins --genesis, or goes with "
                "--log-key"},
               {"log-key", "PUBKEY",
                "Instead of --genesis: the ledger's log public key file (cannot follow a "
                "rotation)"},
               {"name", "NAME", "A name for the ledger"}}),
         cmd_witness_add_log,
         "A witness is an independent party (another person or organization, an auditor) that\n"
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
         "the operator can then ask with: kanhe checkpoint cosign-request --from SIZE."},
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
        {{"witness", "register"},
         "Register this ledger with a public witness, which then cosigns its checkpoints",
         "Witness",
         "URL",
         1,
         1,
         with({ledger_option,
               {"witness-key", "PUBKEY",
                "The witness's public key, as its operator publishes it: a public key file, or "
                "its hex (GET URL/v1/witness shows it; check it elsewhere)"},
               {"vkey", "VKEY",
                "Instead, an open network's witness (c2sp.org/tlog-witness): its verifier key, "
                "as its about page gives it; URL is then its add-checkpoint URL"},
               {"name", "NAME", "What to call it here (default: its name, or its host)"}}),
         cmd_witness_register,
         "Sends the genesis entry and a cosign request of the latest checkpoint to\n"
         "URL/v1/witness/register; the witness follows the ledger only if it cosigns, which\n"
         "proves this ledger holds its log key. The cosignature is kept, and the witness is\n"
         "listed in witnesses.json: serve (and the console) then ask it to cosign every new\n"
         "checkpoint, and exports carry its cosignatures (verify --witness --min-witnesses).\n"
         "The witness learns the ledger id, the genesis entry's keys, each checkpoint's size,\n"
         "root, and time, and this computer's address: never statements, records, fields,\n"
         "parties, or files. Refuses a witness whose key is not the one given.\n\n"
         "With --vkey, an open network's witness (spec v0.13) is listed in\n"
         "network-witnesses.json, and nothing is sent: it cosigns once the network's\n"
         "maintainers list this ledger (kanhe witness network-entry prints the entry to\n"
         "send them). serve --note-key and checkpoint network-cosign ask it."},
        {{"witness", "network-entry"},
         "Print this ledger's entry for an open witness network's list of logs",
         "Witness",
         "",
         0,
         0,
         with({ledger_option,
               {"note-key", "KEY", "The ledger's note key (Ed25519; file or pkcs11: URI)", true},
               {"contact", "TEXT", "How the network's maintainers reach the operator", true},
               {"qpd", "N",
                "The add-checkpoint requests a day it may make (default: 24, one an hour)"}}),
         cmd_witness_network_entry,
         "The lines a network's list takes (vkey, qpd, contact; the witness-network log-list\n"
         "format). The verifier key's name is the ledger's origin,\n"
         "cirraya.com/kanhe/<ledger id>. Send the entry to the network's maintainers\n"
         "yourself: they add logs by hand. Keep the note key as safe as the log key, and back\n"
         "it up: a network never updates a log's key. SHA-256 ledgers only."},
        {{"witness", "registered"},
         "List the public witnesses this ledger registered with, or show one",
         "Witness",
         "[NAME]",
         0,
         1,
         with({ledger_option}),
         cmd_witness_registered},
        {{"witness", "unregister"},
         "Stop asking a public witness to cosign this ledger's checkpoints",
         "Witness",
         "NAME",
         1,
         1,
         with({ledger_option}),
         cmd_witness_unregister,
         "What it cosigned stays valid, and the witness keeps following the ledger (its state\n"
         "is about 200 bytes); registering again carries on from there."},

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
               {"tsa", "URL",
                "Ask this time-stamp authority (RFC 3161) to stamp the latest checkpoint at start "
                "and then every --timestamp-interval"},
               {"timestamp-interval", "SECONDS", "How often to ask (default: 3600)"},
               {"note-key", "KEY",
                "Sign checkpoint notes with this Ed25519 key, and ask the open-network witnesses "
                "listed here (witness register --vkey) to cosign the latest checkpoint at start "
                "and then every --network-interval"},
               {"network-interval", "SECONDS",
                "How often to ask network witnesses (default: 3600; keep within the qpd their "
                "list gives this ledger)"},
               {"snapshot-interval", "ENTRIES",
                "Write a snapshot of the state after a checkpoint once the log grew this much "
                "(default: 100000; 0: never)"},
               {"tls-cert", "FILE", "TLS certificate chain (PEM); without it, use a TLS proxy"},
               {"tls-key", "FILE", "TLS private key (PEM)"},
               {"read-only", "", "Refuse every write"},
               {"cluster", "",
                "Serve as a member of this ledger's cluster (kanhe cluster init or join)"},
               {"public-read", "",
                "Serve read routes without a token (a public verification portal; the vault, "
                "metrics, requests, and what is due still need one)"},
               {"threads", "N", "I/O threads (default: one per core)"},
               {"max-connections", "N", "Concurrent connections (default: 1024)"},
               {"max-connections-per-ip", "N",
                "From one client address (default: no limit; behind a proxy, leave it)"},
               {"max-body", "BYTES", "Largest request body (default: 1048576)"},
               {"quiet", "", "No access log on stderr"},
               {"witness-dir", "DIR", "Also witness peers' ledgers: this witness state directory"},
               {"witness-key", "KEY", "The witness key (file or pkcs11: URI), with --witness-dir"},
               {"witness-public", "",
                "A public witness: any ledger registers and asks for cosignatures with no token, "
                "within quotas (serve TLS yourself, so quotas see callers' addresses)"},
               {"witness-name", "NAME", "Who runs this public witness, as GET /v1/witness says"},
               {"witness-max-ledgers", "N", "Ledgers a public witness follows (default: 100000)"},
               {"witness-registrations-per-day", "N",
                "New ledgers from one address in a day (default: 10)"},
               {"witness-cosign-interval", "SECONDS",
                "Between two cosignatures of one ledger (default: 60)"},
               {"relay-key", "FILE",
                "Answer the requests parties send this ledger through its relay (relay use), "
                "with this relay key (needs --log-key)"},
               {"relay-dir", "DIR",
                "Also a relay, keeping mailboxes here: ledgers this public witness follows send "
                "each other sealed messages through it (with --witness-public)"},
               {"registrar-key", "KEY",
                "Take proposed contract calls with the consents their contracts ask for; record "
                "each once all are in, signing as this actor (file or pkcs11: URI)"},
               {"keeper-key", "KEY",
                "Fire the time rules that are due and expire overdue requests, signing as this "
                "keeper (keeper add; file or pkcs11: URI); in a cluster, the leader does"},
               {"keeper-interval", "SECONDS", "How often the keeper looks (default: 60)"},
               {"credential-key", "KEY",
                "Serve the issuer's DID document and credential status lists, signing them as "
                "this credential key (credential key add; file or pkcs11: URI)"},
               {"credential-url", "URL",
                "The base URL credentials name, where this server is reached (with "
                "--credential-key)"},
               {"expiry-grace", "SECONDS",
                "The keeper expires a request this long after its deadline (default: 900)"},
               {"allow-clock-offset", "",
                "Serve with $KANHE_CLOCK_OFFSET set, the ledger's clock ahead (demonstrations "
                "and tests only)"},
               passphrase_file_option}),
         cmd_serve,
         "Routes (API v1; binary objects are CBOR or COSE, everything else JSON):\n"
         "  open:    GET /healthz, /v1/checkpoint[?size=N], /v1/consistency?old=&new=,\n"
         "           /c/TOKEN (a published record's evidence: record publish),\n"
         "           /m/LEDGER (a membership), and with --credential-key\n"
         "           /.well-known/did.json, /did.json, /status/N (credential issue)\n"
         "  read:    GET /metrics, /v1/status, /v1/entries?start=&count=, /v1/checkpoints,\n"
         "           /v1/cosignatures, /v1/inclusion?index=&size=, /v1/statements/ID,\n"
         "           /v1/receipts/INDEX, /v1/state/ID, /v1/evidence/RECORD,\n"
         "           /v1/vault/public-key, /v1/vault/records/RECORD, /v1/contracts,\n"
         "           /v1/contracts/CONTRACT, /v1/contracts/instances/INSTANCE,\n"
         "           /v1/contracts/calls, /v1/contracts/calls/CALL, /v1/requests,\n"
         "           /v1/contracts/due (below)\n"
         "  submit:  POST /v1/statements (a signed statement, application/cose; or a record's\n"
         "           registration with its sealed private data, or a contract call with its\n"
         "           consents' evidence, application/kanhe-submission+cbor),\n"
         "           POST /v1/contracts/calls\n"
         "  admin:   POST /v1/checkpoint, POST /v1/cosignatures ([cosignature, witness key]),\n"
         "           GET, POST /v1/published, DELETE /v1/published/TOKEN\n"
         "  peer:    POST /v1/access/requests, GET /v1/access/deliveries/REQUEST,\n"
         "           POST /v1/access/receipts, POST /v1/witness/cosign,\n"
         "           POST /v1/contracts/calls, GET /v1/contracts/calls[/CALL],\n"
         "           POST /v1/contracts/consents, GET /v1/contracts/instances/INSTANCE\n"
         "           (the instance's parties)\n"
         "  executor: GET /v1/requests, GET /v1/contracts/instances/INSTANCE, and\n"
         "           POST /v1/statements for answers to requests only\n"
         "  with --witness-public, open: GET /v1/witness, POST /v1/witness/register\n"
         "           ({1: genesis entry, 2: cosign request}), POST /v1/witness/cosign\n"
         "  with --relay-dir, open: POST /v1/relay/messages (signed by the sender's log key),\n"
         "           GET /v1/relay/messages?to=LEDGER[&wait=S], DELETE\n"
         "           /v1/relay/messages/ID?to=LEDGER (both signed by the mailbox's ledger)\n"
         "The server asks each public witness the ledger registered with (witness register)\n"
         "to cosign every new checkpoint, and keeps the cosignatures.\n"
         "GET /v1/requests?state=&kind=&contract=&instance=&after=&limit=&wait= lists requests\n"
         "made by contract calls, for executors: open ones by default, oldest change first, with\n"
         "a cursor for the next after=; with wait=S (up to 25 seconds) it waits until one\n"
         "matches. It is a hint: executors check a request in the instance's evidence.\n"
         "GET /v1/contracts/due?at=&grace=&keeper=&contract=&instance=&start=&limit= (read)\n"
         "lists what a keeper would do: the time rules due and the requests to expire.\n"
         "With --keeper-key, the server is that keeper: every --keeper-interval it fires what\n"
         "is due, one call per instance at a time, queued with the other writes.\n"
         "Requests send \"Authorization: Bearer TOKEN\" (kanhe token create). Reads run on all\n"
         "I/O threads at once; writes queue for one writer, which commits whatever has queued\n"
         "as a group with one sync. The server holds the ledger's lock only while writing, so\n"
         "other kanhe commands keep working on it.\n"
         "With $KANHE_CLOCK_OFFSET set, the ledger's clock runs ahead and what it records\n"
         "keeps the later times: serve refuses to start unless --allow-clock-offset is given\n"
         "(demonstrations and tests only), and /v1/status shows clock_offset_ms.\n"
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
               {"token-file", "FILE", "A read token for the member (default: $KANHE_TOKEN)"},
               {"ca-file", "FILE", "CA certificates (PEM) to trust for the member"}}),
         cmd_cluster_join,
         "Copies the ledger up to its latest checkpoint, re-validating it as a replica would.\n"
         "Then run it (kanhe serve --cluster) and add it (kanhe cluster add); Raft\n"
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
               {"scope", "SCOPES",
                "read, submit, admin, peer, executor, comma-separated (default: read)"},
               {"out", "FILE", "Write the token to FILE (owner-only) instead of printing it"}}),
         cmd_token_create,
         "The token is shown once; the ledger keeps only its SHA-256. Scopes: read (the log,\n"
         "proofs, receipts, evidence, sealed vault data, metrics), submit (signed statements),\n"
         "admin (checkpoints, witness cosignatures), peer (another organization's access\n"
         "requests, deliveries, receipts, and witnessing), executor (the requests contract\n"
         "calls make, instances' evidence, and answers to requests, no other statements; add\n"
         "read for request commands with --server). Name a peer's token after the peer\n"
         "(kanhe peer add NAME): it then reaches only that peer's own exchanges. A token\n"
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
               {"token-file", "FILE", "A read token for the primary (default: $KANHE_TOKEN)"},
               {"ca", "FILE", "Trust these CA certificates (PEM) for the primary"}}),
         cmd_replica_init,
         "A replica copies the primary's log up to its latest checkpoint, the checkpoints,\n"
         "witness cosignatures, and sealed vault data. Each checkpoint is checked against the\n"
         "log key first, and the entries it covers must lead to its root before any is taken;\n"
         "every entry is re-validated with the ledger's rules. So a replica holds only what the\n"
         "log key signed, and trails the primary by its checkpoint interval. A primary cannot\n"
         "hand it a history that is not the ledger's: copying stops (exit 3) at the first\n"
         "entry that fails. Without TLS, pin the ledger with --ledger-id. Replicas refuse\n"
         "writes; serve one with kanhe serve for reads, back it up, or promote it."},
        {{"replica", "sync"},
         "Copy what is new on the primary",
         "Replicas",
         "",
         0,
         0,
         with({ledger_option,
               {"follow", "", "Keep syncing until interrupted"},
               {"interval", "SECONDS", "With --follow, how often (default: 10)"},
               {"token-file", "FILE", "A read token for the primary (default: $KANHE_TOKEN)"}}),
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
               {"token-file", "FILE", "A read token for the primary (default: $KANHE_TOKEN)"}}),
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
              {"console", "",
               "Also the web console's folder, peers, and access boxes (party tokens in the clear: "
               "prefer console backup now, which seals them)"},
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
        {{"peer", "invite"},
         "Invite another organization to become a peer: a code for them",
         "Other organizations",
         "NAME",
         1,
         1,
         with({ledger_option,
               {"url", "URL", "This ledger's API, as the peer reaches it (for online exchange)"},
               {"witness-key", "PUBKEY",
                "The public key of the witness this ledger's server runs for its peers"}}),
         cmd_peer_invite,
         "Issues an API token named NAME with the peer scope, and prints a code (khp_...) that\n"
         "carries this ledger's id, its organization's name, the URL, the token, and the\n"
         "witness key if given (serve --witness-dir --witness-key): send it to\n"
         "that party only, by a channel you trust. Compare the fingerprint it shows with them\n"
         "by voice. They accept it (peer accept), and invite you back; accept their code under\n"
         "the same NAME, so that their calls with your token reach their own exchanges only.\n"
         "Revoke the token (token revoke NAME) to end it."},
        {{"peer", "accept"},
         "Accept another organization's invitation: add it as a peer",
         "Other organizations",
         "CODE",
         1,
         1,
         with({ledger_option,
               {"name", "NAME", "What to call the peer here", true},
               {"token-dir", "DIR",
                "Keep its token here (default: peer-tokens in the ledger directory)"}}),
         cmd_peer_accept,
         "Adds the peer the code names, pinned by its ledger id, with its API's URL and the token\n"
         "it issued you (kept owner-only). Compare the fingerprint with the inviter by voice: a\n"
         "code changed on the way names another ledger."},
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
         "Ask a peer for one of its records, or whether a condition holds in it",
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
                  {"if", "CONDITION",
                   "Ask only whether FIELD OP VALUE holds, as claim issue takes it (repeat: all "
                   "must hold)",
                   false, true},
                  log_key_option,
                  {"out", "FILE", "Write the request (its evidence) here, to send"},
                  {"send", "", "Send it to the peer's API"}}),
         cmd_access_request,
         "Records an access request on this ledger, with a key made for it alone (kept\n"
         "sealed in this ledger's vault): the peer seals what it grants to that key.\n\n"
         "With --if, the request asks only whether the condition holds in the record, and\n"
         "the peer answers with a claim (access answer): what it says, never the fields.\n\n"
         "  kanhe access request --peer employer --record ID --purpose 'Eligibility check' \\\n"
         "    --if 'monthly_salary > HKD 30000' --send --as clerk.key --log-key log.key"},
        {{"access", "send"},
         "Send an access request to the peer's API",
         "Other organizations",
         "REQUEST",
         1,
         1,
         with({relay_log_key_option, ledger_option, {"peer", "NAME", "The peer", true}}),
         cmd_access_send_request},
        {{"access", "fetch"},
         "Fetch the answer to a request (a delivery, or a claim) from the peer's API",
         "Other organizations",
         "",
         0,
         0,
         with({relay_log_key_option,
               ledger_option,
               {"peer", "NAME", "The peer", true},
               {"request", "ID", "The request", true},
               {"out", "FILE", "Write the answer here", true}}),
         cmd_access_fetch},
        {{"access", "accept"},
         "Check an answer, record a receipt, and show what was granted or confirmed",
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
         "every attachment against the record's commitments. For a request with --if, the\n"
         "answer is a claim: it must answer that request, about that record, with that\n"
         "condition, and be live. Exit 3 if anything fails."},
        {{"access", "inbox"},
         "List access requests received through the API",
         "Other organizations",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_access_inbox},
        {{"access", "dismiss"},
         "Remove a request from the inbox without granting it",
         "Other organizations",
         "REQUEST",
         1,
         1,
         with({ledger_option}),
         cmd_access_dismiss,
         "REQUEST is the request's id, or at least its first 8 hex digits, as the inbox\n"
         "lists it. Nothing is recorded on either ledger: the peer can ask again."},
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
         "can fetch it from this ledger's API. End a grant with: kanhe record revoke ID."},
        {{"access", "answer"},
         "Answer a request that asks whether a condition holds",
         "Other organizations",
         "REQUEST",
         1,
         1,
         signing({log_key_option,
                  vault_key_option,
                  {"subject", "TEXT", "Whom or what the record is about, as you name them"},
                  {"until", "DATE", "The answer lapses then (YYYY-MM-DD or an ISO time)"},
                  {"allow-no", "", "Answer even if the condition does not hold, saying so"},
                  {"out", "FILE", "Also write the answer (the claim's evidence) here"}}),
         cmd_access_answer,
         "REQUEST is a request file, or a request in the inbox (by id prefix), made with\n"
         "access request --if. The condition is checked against the record's private data\n"
         "(opened with the vault key) and a claim is registered that answers the request:\n"
         "the condition and whether it holds, never the fields. The peer fetches it from this\n"
         "ledger's API. If the condition does not hold, nothing is answered unless\n"
         "--allow-no, so that a refusal looks like silence; access dismiss takes the request\n"
         "away. Withdraw an answer with: kanhe record revoke CLAIM."},
        {{"access", "receipt"},
         "Check and keep a peer's receipt for a delivery",
         "Other organizations",
         "FILE",
         1,
         1,
         with({relay_log_key_option, ledger_option}),
         cmd_access_receipt},
        {{"access", "list"},
         "List this ledger's access requests, grants, answers, and receipts",
         "Other organizations",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_access_list},

        // ------------------------------------------------------------------
        {{"contract", "deploy"},
         "Deploy a contract: a deploy file, or a WebAssembly module",
         "Contracts",
         "FILE",
         1,
         1,
         signing(
             {{"function", "NAME=KIND",
               "With a module: a function and its kind, create (makes an instance) or call "
               "(acts on one)",
               false, true},
              {"compiler", "TEXT", "With a module: the compiler and its version (required)"},
              {"language", "LANG", "With a module: the language it was written in (default: wasm)"},
              {"source", "FILE",
               "With a module: its source, so that anyone can rebuild it and compare"},
              {"name", "TEXT", "With a module: a name for people"}}),
         cmd_contract_deploy,
         "FILE is a deploy file, as a compiler writes one (bo build --out writes FILE.boc) or\n"
         "contract export does: the code, the interface, the language, the compiler, the source\n"
         "if any, the name, and the hash its source's digests use, which must be this ledger's.\n"
         "Or it is a module, with its interface and compiler given as options.\n\n"
         "A module is in the contract profile (spec section 14): integer-only WebAssembly that\n"
         "exports kanhe_call and imports only from \"kanhe\", at most 512 KiB. It is\n"
         "checked here before it is signed. The contract's id is the deploy statement's id; its\n"
         "code never changes, so a new version is a new deploy. The ledger records a call only\n"
         "if the contract, run on it, accepts it; every verifier runs it again. A source\n"
         "recorded with the code lets anyone rebuild the code and compare, with the language's\n"
         "own tools (bo rebuild, for Bo).\n\n"
         "  bo build lending.bo --out lending.boc && kanhe contract deploy lending.boc --as "
         "root.key\n"
         "  kanhe contract deploy rules.wasm --function propose=create \\\n"
         "      --function sign=call --compiler \"mytool 1.2\" --as root.key"},
        {{"contract", "show"},
         "Show a contract: its interface, code, and instances",
         "Contracts",
         "CONTRACT",
         1,
         1,
         with({ledger_option,
               {"code-out", "FILE", "Write its module here"},
               {"source-out", "FILE",
                "Write its source here, as deployed (if it was deployed with it)"}}),
         cmd_contract_show,
         "The source is kept as deployed, in its language's form (for Bo, a bo-source bundle):\n"
         "contract export writes the whole deploy, for the language's tools to rebuild the code\n"
         "from it and compare (bo rebuild)."},
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
         "Create an instance of a contract: one thing its rules govern",
         "Contracts",
         "CONTRACT FUNCTION",
         2,
         2,
         signing({args_option,
                  args_cbor_option,
                  {"reference", "TEXT", "A reference of your own, such as a file number"},
                  dry_run_option,
                  at_option}),
         cmd_contract_create,
         "FUNCTION is one the contract declared to create instances. The instance starts as this\n"
         "ledger's proposal, with the parties the contract names: a creation takes no consents.\n"
         "Each party is bound only once it consents to a later call.\n\n" KANHE_ARGUMENTS_HELP},
        {{"contract", "call"},
         "Call a function on one of this ledger's instances",
         "Contracts",
         "INSTANCE FUNCTION",
         2,
         2,
         signing(
             {args_option,
              args_cbor_option,
              {"reference", "TEXT", "A reference of your own, such as a file number"},
              {"consent", "FILE",
               "A party's consent: its consent file, or its evidence (repeatable)", false, true},
              dry_run_option,
              at_option}),
         cmd_contract_call,
         "The contract runs here first, as the ledger will run it: the call is recorded only if\n"
         "the contract accepts it. If it needs other parties' consents, pass each party's consent\n"
         "with --consent, or propose the call to this ledger's registrar (contract propose), "
         "which\n"
         "collects them online. A consent names the instance's head, so it counts "
         "once.\n\n"
         "A Bo contract's time rules are functions too (when.suspend, ...): a keeper, such as a\n"
         "device whose delegation names the contract (delegation grant --contracts), calls them\n"
         "on a schedule; one whose time has not come is refused, and nothing is recorded. Try\n"
         "one first with --dry-run --at TIME.\n\n" KANHE_ARGUMENTS_HELP},
        {{"contract", "instance"},
         "Show an instance: its status, state, calls, parts, and requests",
         "Contracts",
         "INSTANCE",
         1,
         1,
         with({ledger_option,
               {"state-out", "FILE", "Write its state here, as CBOR (for bo explain --state)"}}),
         cmd_contract_instance,
         "A call may create instances of its contract, its parts (such as one thing divided\n"
         "among several holders): a part shows its parent, its position among the parts its\n"
         "parent's call created, its depth (at most 8), and its ancestors, oldest first; an\n"
         "instance whose calls created parts lists them. A part is an instance like any other:\n"
         "call it, propose calls on it, and fetch or verify its evidence, which carries its\n"
         "ancestors' calls.\n\n"
         "A call may also make requests (v0.8), work for executors outside the ledger: the\n"
         "instance lists them, the open ones first, and each call the requests it made and the\n"
         "request it answers (request show tells more)."},
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
               {"parent", "INSTANCE", "Only the parts calls on this instance created"},
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
        {{"contract", "proposal"},
         "Write a proposal file: ask other ledgers, by any channel, to consent to a call",
         "Contracts",
         "INSTANCE FUNCTION",
         2,
         2,
         signing({args_option,
                  args_cbor_option,
                  signing_log_key_option,
                  passphrase_file_option,
                  {"note", "TEXT", "A note for the people who read it (1 to 1000 bytes)"},
                  {"out", "FILE", "Where to write it (FILE.kanhe)", true}}),
         cmd_contract_proposal,
         "For ledgers that do not reach each other's APIs. The call runs first, as for a dry\n"
         "run: it must wait for other parties' consents (a call the contract accepts as it is,\n"
         "or refuses, is said so instead). The file carries the call's terms (the instance, its\n"
         "head, the function, the arguments, this ledger's hash), the ledgers whose consents it\n"
         "waits for, and the instance's evidence as of a new checkpoint, so that each party\n"
         "verifies the instance and reads the contract before consenting: contract consent\n"
         "--proposal FILE writes the consent file back, and contract call --consent FILE\n"
         "records the call (its arguments taken from the file).\n\n"
         "  kanhe contract proposal 3f2a9c1e lend --args '{\"counterparty\": h'\''8d01...'\''}' "
         "\\\n"
         "      --as owner.key --log-key log.key --out lend.kanhe\n\n" KANHE_ARGUMENTS_HELP},
        {{"contract", "file", "show"},
         "Show a proposal or consent file, verified",
         "Contracts",
         "FILE",
         1,
         1,
         with({}),
         cmd_contract_file_show,
         "A proposal's evidence is verified for the home it names, and its instance and head\n"
         "must be the evidence's; a consent's bundle is verified for the ledger it comes from,\n"
         "and its record's terms must be the file's. Shows the call, the home or the consenting\n"
         "ledger, the ledgers a proposal waits for, and its note."},
        {{"contract", "propose"},
         "Propose a call to an instance's home, whose registrar collects the consents",
         "Contracts",
         "INSTANCE FUNCTION",
         2,
         2,
         with({relay_log_key_option,
               ledger_option,
               {"peer", "NAME", "The instance's home, a peer (to propose as one of its parties)"},
               args_option,
               args_cbor_option,
               {"reference", "TEXT", "A reference of your own, such as a file number"},
               {"head", "N", "The instance's head (default: as its home shows it now)"},
               {"days", "N", "The proposal lapses after N days (1 to 30; default: 7)"}}),
         cmd_contract_propose,
         "As one of the instance's parties, propose to its home with --peer (INSTANCE in full);\n"
         "as the home's staff, with --server and a submit token. The home's registrar (serve\n"
         "--registrar-key) runs the call without consents: it refuses a call the contract\n"
         "rejects, or takes as it is (the home's people sign those themselves); otherwise it\n"
         "holds the call and asks the ledgers the contract names to consent (contract pending,\n"
         "contract consent). It records the call once the contract accepts "
         "it.\n\n" KANHE_ARGUMENTS_HELP},
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
                  {"proposal", "FILE", "A proposal file: take the terms from it, verified"},
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
                  {"out", "FILE",
                   "Write the consent's evidence here (with --proposal, as a consent file)"},
                  {"send", "", "Send it to the home's registrar (needs --peer)"}}),
         cmd_contract_consent,
         "Records a kanhe.contract-consent/1 record naming exact terms: the home, the\n"
         "instance, the function, a digest of the arguments (under the home's hash), and the\n"
         "instance's head. It applies to that one call only, once, until it lapses. With --call\n"
         "the terms come from the call the home's registrar holds (contract pending shows it;\n"
         "the terms are printed); with --proposal they come from a proposal file, whose\n"
         "evidence is verified first, and --out writes the consent file to send back. Otherwise\n"
         "name them, as for contract call. Prove presence (--presence) if the contract wants a\n"
         "person to have approved in person.\n\n" KANHE_ARGUMENTS_HELP},
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
         with({relay_log_key_option, ledger_option, {"peer", "NAME", "The instance's home", true}}),
         cmd_contract_send},
        {{"contract", "fetch"},
         "Fetch an instance's evidence from its home, as one of its parties",
         "Contracts",
         "",
         0,
         0,
         with({relay_log_key_option,
               ledger_option,
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
               {"witness-vkey", "VKEY",
                "Trust this open network's witness, by its verifier key (spec v0.13); it counts "
                "toward --min-witnesses",
                false, true},
               {"min-witnesses", "N", "Fail unless at least N trusted witnesses cosigned"},
               {"tsa-root", "FILE",
                "Trust time-stamp authorities under this root certificate (PEM or DER)", false,
                true},
               {"min-timestamps", "N",
                "Fail unless at least N trusted time-stamp authorities stamped it"},
               {"require-presence", "", "Fail unless a person proved presence for each consent"},
               {"require-answered", "",
                "Fail if a request is still open past its deadline at the checkpoint's time"},
               {"deploy-out", "FILE",
                "Write the deploy the evidence carries here, as a deploy file (bo rebuild)"}}),
         cmd_contract_verify,
         "Replays the instance's calls, running the contract again on each, and checks every\n"
         "consent a call cites on the consenting party's own ledger, with who gave it: a person\n"
         "present, a key alone, or an AI agent and its model. Requests the calls made (v0.8)\n"
         "are derived the same way, so none is left out: each with its answer (done, failed,\n"
         "or expired; who gave it, how late), and the open ones, OVERDUE when the checkpoint's\n"
         "time has passed their deadline. --require-answered fails such evidence; open\n"
         "requests not yet due are work in progress and pass.\n\n"
         "The code is checked as run, not against its source: --deploy-out writes the deploy\n"
         "the evidence carries, and bo rebuild checks that a Bo contract's source builds to its\n"
         "code.\n\n"
         "  kanhe contract verify deal.cbor --ledger-id 98ae652f --deploy-out deal.boc\n"
         "  bo rebuild deal.boc"},
        {{"contract", "export"},
         "Write a deployed contract as a deploy file, for its language's tools",
         "Contracts",
         "CONTRACT",
         1,
         1,
         with({ledger_option, {"out", "FILE", "Write the deploy file here", true}}),
         cmd_contract_export,
         "The deploy file holds what the deploy recorded (the code, the interface, the language,\n"
         "the compiler, the source if any, the name) and this ledger's hash, as a compiler\n"
         "writes one: bo rebuild checks a Bo contract's source against its code from it, and bo\n"
         "explain writes its contract text.\n\n"
         "  kanhe contract export 3f2a9c1e --out lending.boc && bo rebuild lending.boc"},
        // ------------------------------------------------------------------
        {{"request", "list"},
         "List the requests contract calls made to executors",
         "Requests",
         "",
         0,
         0,
         with({ledger_option,
               {"open", "", "Only open requests"},
               {"answered", "", "Only answered requests"},
               {"failed", "", "Only requests answered failed or expired"},
               {"overdue", "", "Only open requests past their deadline (by this computer's clock)"},
               {"kind", "KINDS", "Only requests of these kinds, comma-separated"},
               {"contract", "CONTRACT", "Only requests on instances of this contract"},
               {"instance", "INSTANCE", "Only this instance's requests"},
               {"answered-by", "ACTOR", "Only requests this actor answered"},
               {"since", "TIME",
                "Only requests asked or answered since TIME (YYYY-MM-DD or "
                "YYYY-MM-DDTHH:MM:SSZ)"}}),
         cmd_request_list,
         "A contract's accepted call may make requests (spec v0.8): work for an executor\n"
         "outside the ledger, such as sending a notice or calling another system. Each has a\n"
         "kind, params, a deadline, and a reply (the function an answer calls), and stays open\n"
         "until one answer closes it: done, failed, or expired. Requests are derived from the\n"
         "log, so the list is the ledger's own (with --server, the verified mirror's).\n\n"
         "  kanhe request list --open --kind notify\n"
         "  kanhe request list --answered-by 3f2a9c1e --since 2026-10-01 --json"},
        {{"request", "show"},
         "Show a request: what was asked, its deadline, and its answer",
         "Requests",
         "REQUEST",
         1,
         1,
         with({ledger_option}),
         cmd_request_show,
         "The answer shows who gave it (the actor, its kind, the delegation it acted under, an\n"
         "AI agent's model, a person's presence), when, how late, and its arguments."},
        {{"request", "answer"},
         "Answer a request: done, failed, or expired",
         "Requests",
         "REQUEST",
         1,
         1,
         signing({{"done", "", "The work was done"},
                  {"failed", "", "The work was not done"},
                  {"expired", "", "Nobody answered in time (valid once the deadline has come)"},
                  args_option,
                  args_cbor_option,
                  {"reason", "CODE",
                   "With --failed or --expired: a reason code, such as unavailable, added to "
                   "the arguments as \"reason\""},
                  {"reference", "TEXT", "A reference of your own, such as a ticket number"},
                  dry_run_option,
                  at_option}),
         cmd_request_answer,
         "The answer is a call on the request's instance, at its head, of the request's reply,\n"
         "naming the request and what became of it. Its arguments carry the result as the\n"
         "contract defines it: codes, ids, amounts, and salted digests, never personal data or\n"
         "an outside system's raw text. The contract runs here first: an answer it does not take\n"
         "is not recorded, and the request stays open. A request takes one answer; a late one\n"
         "is recorded as late. Who may answer is the delegations' choice: a person by hand, an\n"
         "executor (whose delegation names the kinds it answers), or a keeper expiring an\n"
         "overdue request.\n\n"
         "  kanhe request answer 9b1c40aa --done --args '{\"ref\": \"T-1001\"}' --as clerk.key\n"
         "  kanhe request answer 9b1c40aa --failed --reason unavailable --as "
         "device.key\n\n" KANHE_ARGUMENTS_HELP},
        {{"request", "cancel"},
         "Cancel a request: answer it failed, with the reason cancelled",
         "Requests",
         "REQUEST",
         1,
         1,
         signing({{"reason", "CODE", "Another reason code (default: cancelled)"},
                  {"reference", "TEXT", "A reference of your own, such as a ticket number"},
                  dry_run_option}),
         cmd_request_cancel,
         "A request cannot be withdrawn: the call that made it is in the log. Cancelling answers\n"
         "it failed, with {\"reason\": \"cancelled\"} as the arguments, like request answer\n"
         "--failed --reason cancelled. The contract reacts as to any failure, and may refuse the\n"
         "answer, which leaves the request open. Executors stop work on a request once it is\n"
         "answered."},
        {{"request", "wait"},
         "Wait for requests at a server, as executors do (a hint)",
         "Requests",
         "",
         0,
         0,
         with({{"server", "URL", "The server (default: $KANHE_SERVER)"},
               {"token-file", "FILE",
                "An API token with the read or executor scope (default: $KANHE_TOKEN)"},
               {"ca-file", "FILE",
                "CA certificates (PEM) to trust for --server, if not the system's"},
               {"state", "STATE", "open (default), answered, or all"},
               {"kind", "KINDS", "Only requests of these kinds, comma-separated"},
               {"contract", "ID", "Only requests on instances of this contract (full id)"},
               {"instance", "ID", "Only this instance's requests (full id)"},
               {"after", "CURSOR", "Only what came after the cursor an earlier answer printed"},
               {"limit", "N", "At most N requests (1 to 1000; default: 100)"},
               {"timeout", "SECONDS",
                "If none matches yet, wait this long for one (0 to 25; default: 25)"}}),
         cmd_request_wait,
         "Asks the server's GET /v1/requests: the requests that match at once, or the first\n"
         "that come within the timeout. Pass the cursor it prints as --after to wait for what\n"
         "comes next. The server's list is a hint: before acting on a request, check it in the\n"
         "instance's evidence (contract evidence or fetch, then contract verify)."},

        // ------------------------------------------------------------------
        {{"executor", "add"},
         "Register an executor: an actor that answers requests of some kinds",
         "Executors",
         "NAME",
         1,
         1,
         signing({{"contract", "CONTRACT", "The contract whose requests it answers", true},
                  {"kinds", "KINDS", "The request kinds it answers, comma-separated", true},
                  {"functions", "FUNCTIONS",
                   "The functions its answers call (default: result, if the contract has it)"},
                  {"key", "KEY", "Its key: a public key file, private key file, or pkcs11: URI"},
                  {"key-out", "FILE",
                   "Make a new key for it here instead (encrypted with the passphrase)"},
                  {"alg", "ALG", "With --key-out: ed25519 (default), esp256, sm2-sm3, ml-dsa-65"},
                  {"agent", "",
                   "Register an AI agent instead of a device (with --model and --responsible)"},
                  {"responsible", "ACTOR", "The person accountable for it"},
                  {"days", "N", "Its delegation is valid for N days from now"},
                  {"until", "DATE", "Its delegation is valid until DATE"},
                  {"config-out", "FILE",
                   "Write the config executor run needs here (its ids; add connectors with "
                   "executor connector add)"}}),
         cmd_executor_add,
         "Registers the actor, then grants it a delegation for calls on CONTRACT only (scope\n"
         "key 7), calling only FUNCTIONS (key 8), and answering only requests of KINDS (key 9):\n"
         "its key can do nothing else. Its answers are a machine's: it never proves presence.\n"
         "With --agent, --model and --model-version describe the agent. Two statements are\n"
         "recorded, signed with --as: the organization's key, or an actor's whose delegation\n"
         "covers actor-register and delegation-grant and may delegate.\n\n"
         "  kanhe executor add Notifier --contract 3f2a9c1e --kinds notify \\\n"
         "      --key-out notifier.key --config-out notifier.json --as root.key"},
        {{"executor", "list"},
         "List executors: actors whose delegations answer requests",
         "Executors",
         "",
         0,
         0,
         with({ledger_option,
               {"contract", "CONTRACT", "Only executors for this contract"},
               {"kind", "KINDS", "Only executors that answer these kinds"},
               {"all", "", "Include revoked executors"}}),
         cmd_executor_list},
        {{"executor", "show"},
         "Show an executor: its delegations, answers, and open work",
         "Executors",
         "ACTOR",
         1,
         1,
         with({ledger_option}),
         cmd_executor_show},
        {{"executor", "revoke"},
         "Revoke an executor: its delegations, then the actor",
         "Executors",
         "ACTOR",
         1,
         1,
         signing({reason_option,
                  {"keep-actor", "",
                   "Revoke only the delegations; the actor stays (to be granted anew)"}}),
         cmd_executor_revoke,
         "It answers nothing more from then on. Its past answers stay, attributed to it: request\n"
         "list --answered-by ACTOR lists them."},
        {{"executor", "run"},
         "Run an executor: find its requests, verify them, act through connectors, answer",
         "Executors",
         "",
         0,
         0,
         with({{"config", "FILE", "The executor's config: its ids and its connectors", true},
               {"state", "DIR", "Its state: journal, cursor, lease name, and sealed secrets", true},
               {"server", "URL", "The home's API", true},
               {"token-file", "FILE", "An executor API token (default: $KANHE_TOKEN)"},
               {"ca-file", "FILE",
                "CA certificates (PEM) to trust for --server, if not the system's"},
               {"as", "KEY", "The executor's key: a private key file or a pkcs11: URI", true},
               passphrase_file_option,
               {"secrets-key", "FILE", "The key that opens its secrets (default: DIR/secrets.key)"},
               {"once", "",
                "One round: what is open now, then exit (retries wait for the next run)"},
               {"wait", "S", "How long each poll waits for new requests (0 to 25; default: 25)"},
               {"lease-ttl", "S",
                "How long its lease outlives its last poll (5 to 300; default: 60)"},
               {"concurrency", "N",
                "How many requests it works at once (1 to 256; default: the number of cores)"}}),
         cmd_executor_run,
         "Polls the home's server (GET /v1/requests, long polls) for open requests of the kinds\n"
         "its connectors serve. The list is a hint: before acting, it fetches the instance's\n"
         "contract evidence and verifies it for the home ledger (the config's ledger_id); a\n"
         "request that is not open there is never acted on. Each request is journaled in\n"
         "DIR/journal, synced before its connector is asked to act; the connector's outcome is\n"
         "journaled before the answer is signed (with --as, under the config's delegation) and\n"
         "sent. The answer carries the connector's result, a failure's reason code, and the\n"
         "salted digest of the outside system's response; the response and its salt stay in\n"
         "the journal (executor journal show).\n\n"
         "Transient failures are retried, 1 s doubling to 5 min with jitter, until the\n"
         "request's deadline; work that could end after the deadline is answered failed, with\n"
         "the reason deadline. A request answered elsewhere meanwhile (a keeper's expiry, a\n"
         "person by hand) is closed in the journal, and its own answer is not sent. After a\n"
         "crash it resumes from the journal: an outcome already journaled is answered, not\n"
         "acted on again.\n\n"
         "It works up to --concurrency requests at once, never two of one instance (an answer\n"
         "names the instance's head), oldest first; each copy of a connector performs one at a\n"
         "time (executor connector add --concurrency limits its copies). The evidence a request\n"
         "was verified in also builds its answer: if the instance changed meanwhile, the ledger\n"
         "refuses it and the answer is built again on fresh evidence.\n\n"
         "One copy of an executor acts at a time: by the server's lease (a standby with the same\n"
         "key and its own DIR takes over once the active copy stops polling), and by a lock on\n"
         "DIR. SIGINT or SIGTERM finishes the requests in hand, stops the connectors, and exits\n"
         "0. It logs requests, kinds, and outcomes; never params, results, responses, or\n"
         "secrets.\n\n"
         "  kanhe executor run --config notifier.json --state /var/lib/notifier \\\n"
         "      --server https://ledger.example.com --token-file executor.token --as notifier.key"},
        {{"executor", "check"},
         "Check an executor's config: start each connector and greet it",
         "Executors",
         "",
         0,
         0,
         with({{"config", "FILE", "The executor's config", true},
               {"state", "DIR", "Its state, to hand the connectors their secrets"},
               passphrase_file_option,
               {"secrets-key", "FILE",
                "The key that opens its secrets (default: DIR/secrets.key)"}}),
         cmd_executor_check,
         "Exits 0 if every connector starts and answers hello with ready for its kinds, 2\n"
         "otherwise. Without --state, connectors that need secrets do not start."},
        {{"executor", "connector", "add"},
         "Add a connector to an executor's config",
         "Executors",
         "NAME",
         1,
         1,
         with({{"config", "FILE", "The executor's config", true},
               {"type", "TYPE", "webhook, command, or program", true},
               {"kinds", "KINDS", "The request kinds it serves, comma-separated", true},
               {"contracts", "IDS", "Only on these contracts (full ids, comma-separated)"},
               {"timeout", "S", "The longest one action takes (1 to 300; default: 30)"},
               {"url", "URL", "webhook: where it POSTs (https://, or http:// to this computer)"},
               {"secret", "NAME", "webhook: the secret it signs with (HMAC-SHA-256)"},
               {"ca-file", "FILE", "webhook: CA certificates (PEM) to trust, if not the system's"},
               {"program", "PATH", "command, program: what it runs"},
               {"arg", "VALUE", "command, program: an argument for the program", false, true},
               {"secrets", "NAMES", "command, program: secrets it is handed, comma-separated"},
               {"connector-config", "JSON", "program: its own configuration, a JSON object"},
               {"concurrency", "N",
                "How many of its requests run at once, one copy of it each (1 to 256)"}}),
         cmd_executor_connector_add,
         "A webhook POSTs each request as JSON to --url, signed with HMAC-SHA-256 under the\n"
         "secret --secret (executor secret set NAME). A command runs --program with the --arg\n"
         "values (never through a shell: params never reach its arguments), the request as one\n"
         "JSON line on its stdin, with the secrets --secrets names. A program is any connector\n"
         "that speaks the connector protocol (spec/connectors.md), in any language. A connector\n"
         "serves --kinds on --contracts, or on any contract; one for some contracts takes them\n"
         "over from one for any. Two that serve the same kind on the same contracts are\n"
         "refused. executor run starts copies of a connector as requests need them, each\n"
         "performing one request at a time: up to --concurrency of them; by default, as many\n"
         "as executor run works at once for a webhook or a command, and one for a program\n"
         "(which may keep state of its own).\n\n"
         "  kanhe executor connector add notices --config notifier.json --type webhook \\\n"
         "      --kinds notify --url https://hooks.example.com/ledger --secret hook-key\n"
         "  kanhe executor connector add script --config notifier.json --type command \\\n"
         "      --kinds http.post --program /usr/local/bin/post-request --timeout 60"},
        {{"executor", "connector", "list"},
         "List the connectors in an executor's config",
         "Executors",
         "",
         0,
         0,
         with({{"config", "FILE", "The executor's config", true}}),
         cmd_executor_connector_list},
        {{"executor", "connector", "show"},
         "Show a connector in an executor's config",
         "Executors",
         "NAME",
         1,
         1,
         with({{"config", "FILE", "The executor's config", true}}),
         cmd_executor_connector_show},
        {{"executor", "connector", "remove"},
         "Remove a connector from an executor's config",
         "Executors",
         "NAME",
         1,
         1,
         with({{"config", "FILE", "The executor's config", true}}),
         cmd_executor_connector_remove},
        {{"executor", "secret", "set"},
         "Seal a secret for an executor's connectors (read from a file or stdin)",
         "Executors",
         "NAME",
         1,
         1,
         with(
             {{"state", "DIR", "The executor's state directory", true},
              {"from-file", "FILE", "Read the value from FILE (default: stdin)"},
              passphrase_file_option,
              {"secrets-key", "FILE", "Where its private key is made (default: DIR/secrets.key)"}}),
         cmd_executor_secret_set,
         "The value is read from --from-file or stdin, never from the command line (process\n"
         "listings would show it); one trailing newline is dropped. It is sealed with HPKE\n"
         "(X25519, HKDF-SHA256, AES-256-GCM), as the vault seals records, to DIR/secrets.pub,\n"
         "bound to its name, in DIR/secrets/NAME.sealed. The first secret makes the key pair:\n"
         "the private key, DIR/secrets.key (or --secrets-key), is encrypted with the\n"
         "passphrase. executor run opens the secrets its connectors name and hands each\n"
         "connector its own in the protocol's hello, over a pipe: never in arguments, the\n"
         "environment, the config, a log, or the journal. It never prints a value."},
        {{"executor", "secret", "list"},
         "List an executor's secrets (names only)",
         "Executors",
         "",
         0,
         0,
         with({{"state", "DIR", "The executor's state directory", true}}),
         cmd_executor_secret_list},
        {{"executor", "secret", "remove"},
         "Remove an executor's secret",
         "Executors",
         "NAME",
         1,
         1,
         with({{"state", "DIR", "The executor's state directory", true}}),
         cmd_executor_secret_remove},
        {{"executor", "journal", "list"},
         "List what an executor's journal holds: each request, its stage, and its outcome",
         "Executors",
         "",
         0,
         0,
         with({{"state", "DIR", "The executor's state directory", true},
               {"open", "", "Only requests still in its hands"},
               {"final", "", "Only requests it is done with (answered or closed)"}}),
         cmd_executor_journal_list,
         "Stages: seen (listed by the server), unverified (not open in the signed evidence:\n"
         "never acted on), verified (waiting for an attempt), acting, outcome, answering, and\n"
         "the final answered (its answer is recorded) and closed (answered elsewhere, refused by\n"
         "the ledger, or no connector serves it)."},
        {{"executor", "journal", "show"},
         "Show a request in an executor's journal, and check its response's digest",
         "Executors",
         "REQUEST",
         1,
         1,
         with({{"state", "DIR", "The executor's state directory", true},
               {"response-out", "FILE", "Write the outside system's response here"}}),
         cmd_executor_journal_show,
         "The answer committed to the response by HASH(salt || response), under the home's\n"
         "hash; this checks the journal's response and salt against that digest, so that the\n"
         "response can be disclosed later with proof (--response-out writes it)."},
        {{"connector", "webhook"},
         "A connector that POSTs requests to a URL (executor run starts it)",
         "Executors",
         "",
         0,
         0,
         {},
         cmd_connector_webhook,
         "executor run starts it as 'kanhe connector webhook' and speaks the connector\n"
         "protocol (spec/connectors.md) with it over stdin and stdout: there is no need to run\n"
         "it by hand. Each request is POSTed as JSON with the header fields X-Kanhe-Request\n"
         "(its id, also sent as Idempotency-Key: act once per id), X-Kanhe-Attempt,\n"
         "X-Kanhe-Timestamp (milliseconds), and X-Kanhe-Signature: sha256=HEX, the\n"
         "HMAC-SHA-256 under the shared secret of the timestamp, a dot, and the body. A 2xx is\n"
         "done; 408, 425, 429, 5xx, or no answer: try again (Retry-After is honoured); anything\n"
         "else: failed. A body may say {\"status\": \"failed\", \"reason\": CODE} and give\n"
         "{\"result\": ...}, the only part of it the answer publishes; all of it is the\n"
         "response, committed by digest. TLS certificates and host names are verified;\n"
         "redirects are not followed."},
        {{"connector", "command"},
         "A connector that runs a program per request (executor run starts it)",
         "Executors",
         "",
         0,
         0,
         {},
         cmd_connector_command,
         "executor run starts it as 'kanhe connector command' and speaks the connector\n"
         "protocol (spec/connectors.md) with it over stdin and stdout. For each request it runs\n"
         "the configured program without a shell, with the request as one JSON line on its\n"
         "stdin (with \"secrets\" if the config names some), and no KANHE_* environment\n"
         "variables. Exit 0: done; 75 (EX_TEMPFAIL), a signal, or the timeout: try again; any\n"
         "other: failed. Its stdout is the response, committed by digest; if it is a JSON\n"
         "object, its \"result\" is published and its \"reason\" names a failure."},

        // ------------------------------------------------------------------
        {{"keeper", "add"},
         "Register a keeper: a device that fires time rules and expires requests",
         "Keepers",
         "NAME",
         1,
         1,
         signing({{"contracts", "CONTRACTS", "The contracts it keeps, comma-separated", true},
                  {"functions", "FUNCTIONS",
                   "The functions it may call (default: the contracts' time rules, when.*, and "
                   "result if they have it)"},
                  {"key", "KEY", "Its key: a public key file, private key file, or pkcs11: URI"},
                  {"key-out", "FILE",
                   "Make a new key for it here instead (encrypted with the passphrase)"},
                  {"alg", "ALG", "With --key-out: ed25519 (default), esp256, sm2-sm3, ml-dsa-65"},
                  {"days", "N", "Its delegation is valid for N days from now"},
                  {"until", "DATE", "Its delegation is valid until DATE"}}),
         cmd_keeper_add,
         "A ledger acts only on calls: a contract's time rules (functions when.*, which Bo\n"
         "compiles each when rule to) apply once a keeper calls them, and a request left open\n"
         "past its deadline closes once a keeper expires it. Registers a device, then grants it\n"
         "a delegation for calls on CONTRACTS only (scope key 7), calling only FUNCTIONS (key 8)\n"
         "and answering no request kinds (no key 9): it can fire the rules and expire requests\n"
         "through their reply, and nothing else, never the actions that are the home's own\n"
         "word. Give its key to serve --keeper-key (the server's keeper) or to keeper run.\n\n"
         "  kanhe keeper add Keeper --contracts 3f2a9c1e --key-out keeper.key --as root.key"},
        {{"keeper", "list"},
         "List keepers: devices whose delegations call time rules",
         "Keepers",
         "",
         0,
         0,
         with({ledger_option,
               {"contract", "CONTRACT", "Only keepers that may act on this contract"},
               {"all", "", "Include revoked keepers"}}),
         cmd_keeper_list,
         "A keeper is an actor with a delegation for contract calls only, narrowed to some\n"
         "functions (scope key 8), that answers no request kinds (no key 9)."},
        {{"keeper", "show"},
         "Show a keeper: its delegations, the calls it made, and what is due for it",
         "Keepers",
         "ACTOR",
         1,
         1,
         with({ledger_option}),
         cmd_keeper_show},
        {{"keeper", "revoke"},
         "Revoke a keeper: its delegations, then the actor",
         "Keepers",
         "ACTOR",
         1,
         1,
         signing({reason_option,
                  {"keep-actor", "",
                   "Revoke only the delegations; the actor stays (to be granted anew)"}}),
         cmd_keeper_revoke,
         "It calls nothing more from then on; a server running with its key logs that it is\n"
         "idle. Its past calls stay, attributed to it."},
        {{"keeper", "due"},
         "List what is due: time rules to fire and requests to expire",
         "Keepers",
         "",
         0,
         0,
         with(
             {ledger_option,
              {"keeper", "ACTOR", "Only what this keeper's delegations let it call"},
              {"contract", "CONTRACT", "Only instances of this contract"},
              {"instance", "INSTANCE", "Only this instance"},
              {"at", "TIME",
               "As if at TIME (YYYY-MM-DD for its UTC midnight, or YYYY-MM-DDTHH:MM:SSZ)"},
              {"grace", "SECONDS", "A request expires this long after its deadline (default: 900)"},
              {"limit", "N", "At most N contract runs (1 to 100000; default: 10000)"},
              {"start", "N", "Skip the first N instances (where an earlier answer stopped)"},
              {"server", "URL",
               "Ask this server instead (GET /v1/contracts/due; default: $KANHE_SERVER)"},
              {"token-file", "FILE", "An API token with the read scope (default: $KANHE_TOKEN)"},
              {"ca-file", "FILE",
               "CA certificates (PEM) to trust for --server, if not the system's"}}),
         cmd_keeper_due,
         "Finds what a keeper would do, by dry runs that record nothing: a time rule is due if\n"
         "its contract accepts the call (no arguments) and the call would change something; a\n"
         "request is due to expire once its deadline plus the grace has passed and its contract\n"
         "takes the expiry. Each item names the keepers whose delegations cover it. With\n"
         "--server, the server finds them, by its own clock.\n\n"
         "  kanhe keeper due\n"
         "  kanhe keeper due --keeper Keeper --at 2027-07-03 --json"},
        {{"keeper", "run"},
         "Fire what is due as a keeper: once, or every so often",
         "Keepers",
         "",
         0,
         0,
         with(
             {ledger_option,
              as_option,
              passphrase_file_option,
              {"every", "SECONDS", "Run again every SECONDS until stopped (1 to 86400)"},
              {"rounds", "N", "With --every: stop after N rounds"},
              {"grace", "SECONDS", "A request expires this long after its deadline (default: 900)"},
              {"limit", "N", "At most N contract runs per scan (1 to 100000; default: 10000)"}}),
         cmd_keeper_run,
         "Signs with --as, a keeper's key, the calls that are due for it (as keeper due --keeper\n"
         "lists them): each time rule, and an expiry for each request open past its deadline\n"
         "plus the grace. One call per instance at a time, since each moves the instance's\n"
         "head; then it looks again. The ledger's registration time decides: a rule fires late,\n"
         "never early, and its event says how late. On a server, serve --keeper-key does this\n"
         "itself; keeper run is for a ledger without one (or, with --server, from another\n"
         "computer). With --every and --json, it prints one line of JSON a round.\n\n"
         "  kanhe keeper run --as keeper.key\n"
         "  kanhe keeper run --as keeper.key --every 60"},

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
         "  kanhe_whoami, kanhe_ledger_status, kanhe_record_types\n"
         "  kanhe_get_record, kanhe_issue_record, kanhe_endorse_record,\n"
         "  kanhe_transition_record, kanhe_verify_evidence\n"
         "  kanhe_list_contracts, kanhe_get_instance, kanhe_verify_contract_evidence\n"
         "  kanhe_call_contract           create or call an instance on this ledger\n"
         "  kanhe_list_pending_calls      calls a home's registrar holds for this ledger\n"
         "  kanhe_fetch_instance          an instance from its home, verified\n"
         "  kanhe_propose_contract_call   propose a call to a home's registrar\n"
         "  kanhe_consent_contract_call   consent to a held call, and send the consent\n"
         "  kanhe_list_requests, kanhe_get_request\n"
         "                                   requests contract calls made, and their answers\n"
         "  kanhe_answer_request          answer a request as its executor (done, failed,\n"
         "                                   or expired), under the agent's delegation\n\n"
         "Contract tools reach other organizations as this ledger's peers (peer add). Consents\n"
         "travel as evidence, which needs a checkpoint: give --log-key to let the agent consent.\n"
         "With --server, the agent works on the ledger a server (or a cluster) serves, through a\n"
         "verified local mirror, as every command does; the tools that reach other organizations\n"
         "then refuse, since peers belong to a ledger directory.\n"
         "Contract arguments are CBOR diagnostic notation; a JSON value works as well. MCP\n"
         "clients start the server without a terminal: give key passphrases with\n"
         "--passphrase-file or $KANHE_PASSPHRASE."},
    };
}

} // namespace kanhe::cli
