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
const OptionSpec as_option{"as", "KEY", "Key file of the actor who signs", true};
const OptionSpec delegation_option{"delegation", "ID",
                                   "Delegation to act under (default: chosen automatically)"};
const OptionSpec model_option{"model", "NAME",
                              "AI provenance: model (default: the agent's registered model)"};
const OptionSpec model_version_option{"model-version", "VERSION", "AI provenance: model version"};
const OptionSpec inputs_option{
    "inputs", "TEXT", "AI provenance: what the action was based on (only a hash is recorded)"};
const OptionSpec log_key_option{"log-key", "KEY", "The ledger's log key file", true};
const OptionSpec reason_option{"reason", "TEXT", "Reason, recorded on the ledger"};
const OptionSpec passphrase_file_option{
    "passphrase-file", "FILE",
    "Read key passphrases from FILE (default: $CEXCHAIN_PASSPHRASE or a prompt)"};
const OptionSpec vault_key_option{"vault-key", "FILE",
                                  "The vault private key (default: <ledger>/vault.key)"};
const OptionSpec json_option{"json", "", "Print machine-readable JSON"};
const OptionSpec help_option{"help", "", "Show help for this command"};

std::vector<OptionSpec> with(std::vector<OptionSpec> options) {
    return options;
}

std::vector<OptionSpec> signing(std::vector<OptionSpec> extra) {
    std::vector<OptionSpec> options{
        ledger_option,        as_option,     delegation_option,     model_option,
        model_version_option, inputs_option, passphrase_file_option};
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
              passphrase_file_option}),
         cmd_key_generate},
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
               {"type", "TYPE", "Only statements of this type"}}),
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
              {"may-delegate", "", "The grantee may delegate further (only narrower)"}}),
         cmd_delegation_grant,
         "Statement types: actor-register, actor-rotate-key, actor-revoke, delegation-grant,\n"
         "delegation-revoke, record-register, record-endorse, record-transition, record-revoke."},
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
         with({ledger_option, log_key_option, passphrase_file_option}),
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
               {"witness", "PUBKEY", "The witness's public key file", true},
               {"out", "FILE", "Write the request here, for the witness", true},
               {"from", "SIZE",
                "Prove consistency from this size (default: the witness's last cosigned size)"}}),
         cmd_checkpoint_cosign_request,
         "The request holds the checkpoint and a consistency proof from the last checkpoint the\n"
         "witness cosigned. Send it to the witness (cexchain witness cosign), then store the\n"
         "cosignature it returns with cexchain checkpoint add-cosignature."},
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
               log_key_option,
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
               log_key_option,
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
         "written before vaults were encrypted. The previous key is kept as vault.key.old."},

        // ------------------------------------------------------------------
        {{"witness", "add-log"},
         "Start witnessing a ledger",
         "Witness",
         "",
         0,
         0,
         with({{"dir", "DIR", "The witness's state directory", true},
               {"ledger-id", "ID", "The ledger's id (full hex), from its operator", true},
               {"log-key", "PUBKEY", "The ledger's log public key file, from its operator", true},
               {"name", "NAME", "A name for the ledger"}}),
         cmd_witness_add_log,
         "A witness is an independent party (another company, an auditor, a regulator) that\n"
         "cosigns a ledger's checkpoints only if each extends the history it cosigned before.\n"
         "Learn the ledger id and log key from the operator through a channel you trust."},
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
        {{"mcp"},
         "Run an MCP server (stdio) for an AI agent",
         "AI agents",
         "",
         0,
         0,
         with({ledger_option, {"as", "KEY", "The agent's key file", true}, passphrase_file_option}),
         cmd_mcp},
    };
}

void add_global_options(std::vector<CommandSpec>& specs) {
    for (CommandSpec& spec : specs) {
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
                suggestion = join_path(candidate);
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
