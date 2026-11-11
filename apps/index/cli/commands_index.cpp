// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// kanhe-index's commands: the table the registry dispatches, documents, and
// completes from.

#include "index_commands.hpp"
#include "registry_options.hpp"

namespace kanhe::cli {

std::vector<CommandSpec> index_commands() {
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
        {{"search", "records"},
         "Find records by type, state, who registered them, when, and public metadata",
         "Search",
         "",
         0,
         0,
         paged(record_filters({})),
         cmd_search_records,
         "Searches the search index kept beside the ledger (search.sqlite in its\n"
         "directory, or in a server's mirror), which this command first brings up to date\n"
         "with the log. It holds what the ledger holds in the clear: types, states,\n"
         "registrants, times, versions, and public metadata. Private field values are never\n"
         "indexed; they stay sealed in the vault. Text matches any part of a metadata value\n"
         "(three characters or more use the full-text index). A page ends with the cursor\n"
         "of the next one. The index is a hint, not evidence: export and verify a record to\n"
         "rely on it.\n\n"
         "  kanhe-index search records --type example.school.application/1 --since 2026-11-01\n"
         "  kanhe-index search records --meta class=S5B --current --json\n"
         "  kanhe-index search records --text 走讀 --limit 20"},
        {{"search", "instances"},
         "Find things under contracts by contract, state, party, time, and their fields",
         "Search",
         "",
         0,
         0,
         paged(instance_filters({})),
         cmd_search_instances,
         "Searches the search index (see search records) for contract instances: by\n"
         "contract or its name, state, a party's ledger, when they were created or last\n"
         "called, the reference of the call that created them, and the fields of their state\n"
         "(a Bo contract's thing), exactly or as a number range.\n\n"
         "  kanhe-index search instances --contract-name DayStudent --status "
         "counsellor_approved\n"
         "  kanhe-index search instances --field class=S5B --field-min fee=500 --json"},
        {{"report", "records"},
         "Count records, grouped by type, state, registrant, day, week, or month",
         "Search",
         "",
         0,
         0,
         record_filters({{"by", "GROUPS",
                          "What to group by, comma-separated: type, state, "
                          "registrant, day, week, month (at most four)"},
                         {"utc-offset", "+HH:MM", "Days, weeks, and months in this UTC offset"},
                         {"csv", "", "Write CSV instead of a table"}}),
         cmd_report_records,
         "Counts the records the filters select (as search records takes them), in groups.\n"
         "Without --by, one count. Time groups are ordered by time; others by count, largest\n"
         "first. Weeks start on Monday, named by that day.\n\n"
         "  kanhe-index report records --by type,state\n"
         "  kanhe-index report records --type example.school.application/1 --by day "
         "--utc-offset "
         "+08:00\n"
         "  kanhe-index report records --by month --csv > months.csv"},
        {{"report", "instances"},
         "Count things under contracts, grouped by contract, state, day, week, or month",
         "Search",
         "",
         0,
         0,
         instance_filters(
             {{"by", "GROUPS",
               "What to group by, comma-separated: contract, state, day, week, "
               "month (at most four)"},
              {"sum", "FIELD", "Also the total, least, and greatest of this number field"},
              {"utc-offset", "+HH:MM", "Days, weeks, and months in this UTC offset"},
              {"csv", "", "Write CSV instead of a table"}}),
         cmd_report_instances,
         "Counts the instances the filters select (as search instances takes them), in\n"
         "groups, and with --sum adds the total, least, and greatest of a number field of\n"
         "their state where it has one.\n\n"
         "  kanhe-index report instances --by contract,state\n"
         "  kanhe-index report instances --contract-name Membership --by month --sum fee --csv"},
        {{"serve"},
         "Serve a ledger read-only, with its search index",
         "Index",
         "",
         0,
         0,
         with({ledger_option,
               {"listen", "HOST:PORT",
                "Address to listen on (default: 127.0.0.1:8090; port 0 picks one)"},
               {"tls-cert", "FILE", "TLS certificate chain (PEM); without it, use a TLS proxy"},
               {"tls-key", "FILE", "TLS private key (PEM)"},
               {"public-read", "", "Serve read routes without a token (a public portal)"},
               {"threads", "N", "I/O threads (default: one per core)"},
               {"max-connections", "N", "Concurrent connections (default: 1024)"},
               {"quiet", "", "No access log on stderr"}}),
         cmd_index_serve,
         "The ledger's read routes (kanhe serve --help), read-only, and the index's:\n"
         "  GET /v1/records, /v1/records/ID, /v1/records/ID/versions, /v1/instances,\n"
         "      /v1/reports/records, /v1/reports/instances (the options of search and report)\n"
         "The index is derived from the log and kept beside the ledger (search.sqlite): its\n"
         "answers are hints, each with the log size it reflects (as_of), never evidence. Run it\n"
         "beside the primary on the same directory (it catches up with what the primary writes\n"
         "before each read), or on a replica (kanhe replica sync --follow), as an explorer\n"
         "runs beside a node. Tokens are the ledger's (kanhe token create)."},
        {{"status"},
         "Show the search index: how far it reached in the log, and what it holds",
         "Index",
         "",
         0,
         0,
         with({ledger_option, {"update", "", "Bring it up to date first"}}),
         cmd_index_status,
         "The search index is derived from the log and kept beside it (search.sqlite).\n"
         "Searches and reports bring it up to date first, and serve follows the log as it\n"
         "grows. Removing the file loses nothing: it is rebuilt."},
        {{"rebuild"},
         "Rebuild the search index from the log",
         "Index",
         "",
         0,
         0,
         with({ledger_option}),
         cmd_index_rebuild},
    };
}

} // namespace kanhe::cli
