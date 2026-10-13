#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The Bo commands, end to end (D-053, step 6): the official language packs and
# their digests, a company's own pack, and packs that are refused (a missing
# keyword, one spelling with two meanings, a word an attaching rule could
# split), with messages in each official language.
# Usage: bo.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GOLDEN="$SOURCE/tests/bo/golden/pack-digests.txt"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
unset CEXCHAIN_LANGUAGE

run() { "$CEXCHAIN" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    "$CEXCHAIN" "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

echo "== help and completion"
for command in "bo packs list" "bo packs show" "bo packs check"; do
    # shellcheck disable=SC2086
    run $command --help > out.txt
    contains -F "cexchain $command" out.txt || fail "help for $command"
    contains -F "GCC 16" out.txt || fail "help for $command names the build it needs"
done
run --help > out.txt
contains -F "bo packs list" out.txt || fail "overview lists bo"
run completion bash > out.txt
contains -F '"bo") words="packs"' out.txt || fail "completion: bo"
contains -F '"bo packs") words="check list show"' out.txt || fail "completion: bo packs"
contains -F -- "--section" out.txt || fail "completion: options"
run version --json | json 'd["bo"]["edition"]' > out.txt
contains -x 1 out.txt || fail "version names the edition"

echo "== the official packs, and their digests"
run bo packs list > out.txt
contains -F "zh-Hant-HK   version 1   official   繁體中文（香港）" out.txt || fail "list"
run bo packs list --json > list.json
json 'len(d)' < list.json > out.txt
contains -x 3 out.txt || fail "three official packs"
# The digests match the goldens the C++ tests keep.
for hash in SHA-256 SM3; do
    option=sha256
    [ "$hash" = SM3 ] && option=sm3
    run bo packs list --json --hash "$option" |
        json "'\\n'.join(p['id'] + ' ' + str(p['version']) + ' ' + p['hash'] + ' ' + p['digest'] for p in d)" > digests.txt
    grep -F " $hash " "$GOLDEN" > expected.txt
    diff expected.txt digests.txt > /dev/null || fail "digests ($hash) differ from $GOLDEN"
done
json 'd[1]["keywords"], d[1]["words"], d[1]["official"], d[1]["separation"]' < list.json > out.txt
contains -Fx "18 123 True none" out.txt || fail "facts"

run bo packs show zh-Hant-HK > out.txt
contains -F "prefixes     可 (kw.can), 須 (kw.requires), 當 (kw.when), 如 (kw.if)" out.txt || fail "prefixes"
contains -F "U+3000→space" out.txt || fail "the ideographic space"
contains -F "multipliers  億 ×100000000, 萬 ×10000" out.txt || fail "multipliers"
contains -E "^    cond.consent_of +經 … 同意$" out.txt || fail "the argument's place"
contains -E "^    actor.ai_agent +AI 代理, AI代理$" out.txt || fail "alternatives"
run bo packs show en --section vocabulary > out.txt
contains -E "^    act.pay +pay \(gerund: paying, third: pays\)$" out.txt || fail "forms"
contains -F "Keywords" out.txt && fail "--section shows one part"
run bo packs show zh-Hans-CN --json > show.json
json 'd["keywords"]["kw.each"], d["vocabulary"]["unit.item"]["category"], d["reading"]["multipliers"]["万"]' < show.json > out.txt
contains -Fx "['逐个'] unit 10000" out.txt || fail "show --json"
json 'len(d["messages"]), len(d["sentences"])' < show.json > out.txt
contains -Fx "40 10" out.txt || fail "messages and sentences"
expect_exit 1 bo packs show fr
contains -F "no pack fr" out.txt || fail "unknown pack"
expect_exit 1 bo packs show en --section nope

echo "== a company's own pack"
# Its own words for some concepts, the official ones for the rest. Keywords
# are spelled the official way (the same spelling, the same meaning).
cat > company.pack <<'EOF'
# Our own terms, beside the official packs.
{
  "format": 1, "id": "acme-terms", "version": 3, "language": "en-x-acme",
  "name": "Acme terms", "official": false, "edition": 1,
  "reading": {"separation": "spaces"},
  "keywords": {
    "kw.contract": "contract", "kw.parties": "parties", "kw.can": "can", "kw.by": "by",
    "kw.to": "to", "kw.with": "with", "kw.requires": "requires", "kw.when": "when",
    "kw.if": "if", "kw.otherwise": "otherwise", "kw.and": "and", "kw.or": "or",
    "kw.not": "not", "kw.each": "each", "kw.in": "in", "kw.reject": "reject",
    "kw.test": "test", "kw.use": "use"
  },
  "vocabulary": {
    "act.pledge": ["lodge", "pledge"],    / "pledge" as English has it /
    "role.supplier": "vendor",
    "unit.item": {"word": "unit", "forms": {"plural": "units"}}
  },
  "messages": {"pack.missing-keyword": "{pack} lacks {concept}"}
}
EOF
run bo packs check company.pack > out.txt
contains -F "warning: pack acme-terms does not spell 120 of the 123 words" out.txt || fail "partial"
contains -F "company.pack: pack acme-terms version 3 (community): 18 keywords, 3 words" out.txt || fail "check ok"
contains -F "ok: the packs read" out.txt || fail "ok"
run bo packs list --pack company.pack > out.txt
contains -F "acme-terms   version 3   community  Acme terms" out.txt || fail "list --pack"
run bo packs show company.pack --section vocabulary > out.txt
contains -E "^    act.pledge +lodge, pledge$" out.txt || fail "show FILE"
run bo packs show acme-terms --pack company.pack --json | json 'd["official"], d["version"]' > out.txt
contains -Fx "False 3" out.txt || fail "show ID --pack"

echo "== refused: a missing keyword"
sed '/"kw.use": "use"/s/"kw.use": "use"/"kw.uze": "use"/' company.pack > missing.pack
expect_exit 2 bo packs check missing.pack
contains -F "keywords: kw.uze is not a concept of Bo edition 1 (pack.unknown-concept)" out.txt || fail "unknown concept"
contains -F "pack acme-terms does not spell the keyword kw.use; every pack spells every keyword (pack.missing-keyword)" out.txt || fail "missing keyword"
contains -F "failed" out.txt || fail "failed"
# In the reader's language (the pack's own text for that code is only its own).
expect_exit 2 bo packs check missing.pack --language zh-Hant-HK
contains -F "語言包 acme-terms 未拼寫關鍵字 kw.use；每個語言包均須拼寫所有關鍵字" out.txt || fail "zh-Hant"
CEXCHAIN_LANGUAGE=zh-Hans expect_exit 2 bo packs check missing.pack
contains -F "语言包 acme-terms 没有拼写关键字 kw.use；每个语言包都必须拼写全部关键字" out.txt || fail "zh-Hans"
expect_exit 2 bo packs check missing.pack --json
json 'd["ok"], d["packs"][0]["ok"], [x["code"] for x in d["packs"][0]["diagnostics"] if x["severity"] == "error"]' < out.txt > codes.txt
contains -Fx "False False ['pack.unknown-concept', 'pack.missing-keyword']" codes.txt || fail "check --json"
expect_exit 1 bo packs check missing.pack --language fr
# Other commands refuse such a pack too.
expect_exit 2 bo packs list --pack missing.pack
contains -F "a pack does not read" out.txt || fail "list --pack refuses"

echo "== refused: one spelling, two meanings"
sed 's/"role.supplier": "vendor"/"role.supplier": "bank"/' company.pack > conflict.pack
expect_exit 2 bo packs check conflict.pack
contains -F "bank means role.bank in pack en but role.supplier in pack acme-terms; one spelling cannot have two meanings (pack.conflict)" out.txt || fail "conflict"
# Two given packs against each other.
sed -e 's/"acme-terms"/"other-terms"/' -e 's/"role.supplier": "vendor"/"role.customer": "vendor"/' company.pack > other.pack
expect_exit 2 bo packs check company.pack other.pack --language zh-Hans-CN
contains -F "vendor 在语言包 acme-terms 中表示 role.supplier，在语言包 other-terms 中却表示 role.customer" out.txt || fail "two packs"
expect_exit 2 bo packs list --pack company.pack --pack other.pack
contains -F "packs: error: vendor means role.supplier" out.txt || fail "list refuses a conflict"
# Within one pack.
sed 's/"role.supplier": "vendor"/"role.supplier": "lodge"/' company.pack > twice.pack
expect_exit 2 bo packs check twice.pack
contains -F "pack acme-terms gives lodge two meanings: act.pledge and role.supplier (pack.duplicate-spelling)" out.txt || fail "twice"

echo "== refused: a word an attaching rule could split"
# The draft's 每个 for "each" reads as 每 (per) + 个 (item) in zh-Hans-CN.
sed 's/"kw.each": "each"/"kw.each": "每个"/' company.pack > each.pack
expect_exit 2 bo packs check each.pack
contains -F "每个 (kw.each) could also be read as 每 + 个" out.txt || fail "attachment"

echo "== refused: other problems, each reported"
cat > broken.pack <<'EOF'
{"format": 1, "id": "broken", "version": 0, "language": "x", "name": "Broken",
 "official": true, "edition": 1, "reading": {"separation": "tabs"},
 "keywords": {}, "vocabulary": {"unit.GB": "ＧＢ", "cond.over": "over"}}
EOF
expect_exit 2 bo packs check broken.pack
for code in pack.bad-version pack.bad-language pack.bad-value pack.bad-character pack.needs-hole pack.missing-keyword; do
    contains -F "($code)" out.txt || fail "broken: $code"
done
contains -F "U+FF27 (Ｇ)" out.txt || fail "the character, by code point"
printf '{"format": 1,' > syntax.pack
expect_exit 2 bo packs check syntax.pack
contains -F "(pack.syntax)" out.txt || fail "syntax"
# An official pack's file is the official pack; a changed copy is not.
cp "$SOURCE/bo/packs/en.pack" en.pack
run bo packs check en.pack > out.txt
sed 's/"name": "English"/"name": "Anglais"/' en.pack > fake.pack
expect_exit 2 bo packs check fake.pack
contains -F "pack en says it is official, but it is not one of the official packs this compiler carries" out.txt || fail "false official"
expect_exit 1 bo packs check
expect_exit 2 bo packs check no-such.pack

echo "bo: all checks passed"
