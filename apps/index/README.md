# The search index

An application on the chain: `kanhe-index` keeps a search index beside a ledger
(`search.sqlite`, in SQLite, rebuilt from the log whenever it is missing), which finds records
and things under contracts at scale and counts them:

```sh
kanhe-index search records --type example.school.application/1 --since 2026-11-01 --current
kanhe-index search records --meta class=S5B --text 走讀 --limit 20
kanhe-index search instances --contract-name DayStudent --status counsellor_approved --field-min fee=500
kanhe-index report records --by type,state
kanhe-index report instances --by month --sum total --utc-offset +08:00 --csv > totals.csv
kanhe-index status                       # how far it reached in the log, and what it holds
kanhe-index rebuild                      # made again from the log
```

It holds only what the ledger holds in the clear: types, states, registrants, times, versions,
public metadata, and instances' contracts, states, parties, and fields. Private field values are
never indexed. Searches page with `--limit` and `--cursor`; text matches any part of a metadata
value, Chinese included. Answers are hints, each with the log size it reflects; evidence is what
to rely on.

`kanhe-index serve` serves the ledger read-only, with the index's routes beside the ledger's
read routes: `GET /v1/records`, `/v1/records/{id}/versions`, `/v1/instances`, and
`/v1/reports/records|instances`, under the ledger's read tokens. Run it beside the primary on the
same directory (it catches up with what the primary writes before each read) or on a replica, as
an explorer runs beside a node. An AI agent searches through it (`kanhe mcp --server URL`, the
tools `kanhe_search_records`, `kanhe_search_instances`, and `kanhe_report`), and the
[web console](../console/README.md) reads the index on its Things and Reports screens.

| Path | What it holds |
|---|---|
| `src/` | The index (`index.cpp`), its queries (`query.cpp`), and its routes as an extension of the chain's node (`served.cpp`), which follows the log on a thread of its own |
| `cli/` | The `kanhe-index` program |

The chain knows nothing of it: the node offers extensions their routes and the log, and the
index is one. SQLite is compiled in.
