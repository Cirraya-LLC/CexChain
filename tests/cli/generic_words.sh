#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# CexChain is generic: it registers, moves, and proves any thing, under any
# rules, among any parties, and what a thing is, its users define. Industry
# stories (supply-chain finance, a supply agreement) live in examples/ and the
# docs, never in the product's own texts. This test keeps industry words out
# of what the product says about itself:
#   - every command's --help, the overview, and help --json;
#   - the shell completion scripts (bash and zsh);
#   - the MCP server's instructions and every tool's description and schema;
#   - the browser verifier's page: its HTML and script, and the verifier's
#     sources whose texts the page shows;
#   - the web console's page, its script, and its three catalogs.
# Exemptions are exact phrases, each with the reason it may stay and the
# milestone that removes it; an exemption that no longer matches fails too,
# so none outlives its reason.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
export CEXCHAIN_PASSPHRASE="generic words test"
unset CEXCHAIN_LEDGER CEXCHAIN_SERVER CEXCHAIN_TOKEN

run() { "$CEXCHAIN" "$@"; }
id_from() { grep -oE '[0-9a-f]{64}' | sed -n 1p; }
mkdir texts

# --- The command line: every command's help, and the completion scripts ------
run --help > texts/overview.txt
run help --json > texts/help.json
python3 -c 'import json, sys; [print(c["command"]) for c in json.load(open(sys.argv[1]))]' \
    texts/help.json > commands.txt
count=0
while IFS= read -r command; do
    # The command's words, split on spaces (no command word has others).
    read -r -a words <<< "$command"
    run "${words[@]}" --help < /dev/null > "texts/help-$(printf '%s' "$command" | tr ' ' '-').txt"
    count=$((count + 1))
done < commands.txt
[ "$count" -gt 40 ] || { echo "FAIL: only $count commands"; exit 1; }
run completion bash > texts/completion.bash
run completion zsh > texts/completion.zsh

# --- The MCP server: its instructions and its tools -----------------------------
for k in root log person agent; do run key generate --out "$k.key" > /dev/null; done
run init --ledger ledger --name "Words Test" --root-key root.key --log-key log.key > /dev/null
PERSON="$(run actor add --ledger ledger --as root.key --kind person --name "A Person" \
    --key person.key | id_from)"
run actor add --ledger ledger --as root.key --kind agent --name "An Agent" --key agent.key \
    --responsible "$PERSON" --model a-model > /dev/null
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}'
cat > requests.jsonl << JSON
{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{$META}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{$META}}
{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"words","version":"1"}}}
JSON
run mcp --ledger ledger --as agent.key < requests.jsonl > texts/mcp.jsonl 2> /dev/null
python3 - texts/mcp.jsonl << 'EOF'
import json, sys
responses = [json.loads(line) for line in open(sys.argv[1])]
assert len(responses) == 3, "three responses"
tools = responses[1]["result"]["tools"]
assert len(tools) > 10, "the tools are listed"
assert any("instructions" in r["result"] for r in responses), "the instructions are given"
EOF

# --- The browser verifier's page ---------------------------------------------
for f in "$SOURCE"/verifier/wasm/page.html "$SOURCE"/verifier/wasm/verifier-api.js \
    "$SOURCE"/verifier/wasm/verifier_wasm.cpp "$SOURCE"/verifier/src/*.cpp \
    "$SOURCE"/verifier/include/cexchain/verifier/*.hpp; do
    cp "$f" "texts/page-$(basename "$f")"
done

# --- The web console's page and its three catalogs --------------------------------
for f in "$SOURCE"/console/web/*.html "$SOURCE"/console/web/*.js "$SOURCE"/console/web/i18n/*.json; do
    cp "$f" "texts/console-$(basename "$f")"
done

# --- The scan ------------------------------------------------------------------
BO="$(run version --json | python3 -c 'import json, sys; print(json.load(sys.stdin)["bo"] is not None)')"
python3 - texts "$BO" << 'EOF'
import json, os, re, sys

directory, has_bo = sys.argv[1], sys.argv[2] == "True"

# Words that name an industry's documents, roles, or products rather than a
# mechanism: finance (receivables, pledges, banks, factoring, loans), trade
# (purchase orders, invoices, warehouses, bills of lading, suppliers, supply
# chains, customers), taxes, and hosting (VPS, VDS, IDC). "Asset" too: native
# assets left the protocol (spec v0.9), and things are what users define.
# Generic words stay allowed: contract, party, holder, transfer, amount,
# money, record, organization, certificate (TLS), order (as in "in order").
ENGLISH = [
    r"receivables?", r"warehouses?", r"purchase[- ]orders?", r"invoic\w*", r"pledg\w*",
    r"bills? of lading", r"factoring", r"loans?", r"lenders?", r"banks?", r"banking",
    r"suppliers?", r"core enterprises?", r"supply[- ]chains?", r"customers?", r"VAT",
    r"tax", r"taxes", r"taxation", r"VPS", r"VDS", r"IDC", r"quality certificates?",
    r"assets?",
]
# The same in the official packs' Chinese: receivable, warehouse receipt,
# pledge, invoice, tax, bank, supplier, purchase, factoring.
CHINESE = ["應收", "应收", "倉單", "仓单", "質押", "质押", "發票", "发票", "稅", "税",
           "銀行", "银行", "供應商", "供应商", "採購", "采购", "保理"]
pattern = re.compile(r"(?i)(?<!\w)(?:" + "|".join(ENGLISH) + r")(?!\w)|" +
                     "|".join(CHINESE))

# Exemptions: exact phrases (whitespace collapsed), where they may appear,
# and why. Each must still match somewhere, or it is stale.
EXEMPT = [
]

def strings(value):
    """Every key and string in a JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)

def scan(name, text):
    text = " ".join(text.split())
    for file, phrase, _ in EXEMPT:
        if file == name and phrase in text:
            used.add(phrase)
            text = text.replace(phrase, " ")
    found = []
    for m in pattern.finditer(text):
        found.append(f"{name}: '{m.group(0)}' in ...{text[max(0, m.start() - 50):m.end() + 50]}...")
    return found

# The scanner itself: it must find what it is meant to.
used = set()
probe = scan("probe", "A Receivable pledged\nto the bank; 可質押 an ASSET. Syntax, taxi, orders.")
assert [f.split("'")[1] for f in probe] == ["Receivable", "pledged", "bank", "質押", "ASSET"], probe

used = set()
problems = []
for name in sorted(os.listdir(directory)):
    path = os.path.join(directory, name)
    if name.endswith(".json") or name.endswith(".jsonl"):
        lines = open(path, encoding="utf-8").read().splitlines()
        values = [json.loads(line) for line in lines] if name.endswith(".jsonl") else [json.load(open(path))]
        text = "\n".join(s for v in values for s in strings(v))
    else:
        text = open(path, encoding="utf-8").read()
    problems += scan(name, text)

for file, phrase, needs_bo in EXEMPT:
    if phrase not in used and (has_bo or not needs_bo):
        problems.append(f"stale exemption ({file}): '{phrase}' no longer appears; remove it")

if problems:
    print("Industry words in the product's own texts (the product is generic: things are what users define;")
    print("industry stories belong in examples/ and the docs):")
    for p in problems:
        print("  " + p)
    sys.exit(1)
print(f"generic: {len(os.listdir(directory))} texts, {len(used)} exemptions in use")
EOF
