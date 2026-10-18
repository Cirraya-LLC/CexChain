#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The Bo commands, end to end (D-053, step 6): the official language packs and
# their digests, a company's own pack, and packs that are refused (a missing
# keyword, one spelling with two meanings, a word an attaching rule could
# split), with messages in each official language; checking source, its
# tokens (the lexer), its tree (the parser), and its model (the checker), in
# each language and mixed; building it (bo build) and deploying it
# (contract deploy --bo), then a Bo agreement through a ledger and its
# registrar, with a consent from a ledger on SM3, verified offline with the
# rebuild check; the contract text (bo explain, contract explain) in each
# language, the same from every spelling; and deploys whose source is not
# their code; the source laid out canonically and written in each language
# (bo fmt), which builds to the same code and explains to the same text; and
# the test blocks run as a ledger runs calls (bo test), with the same results
# from every language; the standard library (bo stdlib) and a receivable
# built with it, through four ledgers: pledged to a bank with the consents of
# the supplier and the bank, released, sold to a factor, paid, and confirmed;
# time rules (3 days overdue, suspend) and the IP pool, tested, built, and
# explained; a keeper (keeper add), a device whose delegation names one
# contract's time rules, firing a rule on a ledger once its time has come
# (keeper due, keeper run); and lists and charges:
# the spec's VAT, tested on both sides of its rate change, explained in each
# language, and billed on a ledger, where a bill keeps the rate it was made
# with.
# Usage: bo.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GOLDEN="$SOURCE/tests/bo/golden/pack-digests.txt"
GOLDENS="$SOURCE/tests/bo/golden"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
unset CEXCHAIN_LANGUAGE CEXCHAIN_LEDGER CEXCHAIN_TOKEN CEXCHAIN_SERVER
export CEXCHAIN_PASSPHRASE="bo test"

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
start_server() {
    local out="$1"; shift
    "$CEXCHAIN" serve --listen 127.0.0.1:0 --json --quiet "$@" > "$out" 2> "$out.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        if [ -s "$out" ] && python3 -c "import json; json.load(open('$out'))" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
    done
    cat "$out.log"
    fail "the server did not start"
}

echo "== help and completion"
for command in "bo check" "bo build" "bo explain" "bo fmt" "bo test" "bo packs list" "bo packs show" "bo packs check" "bo stdlib list" "bo stdlib show" "bo vocab list" "bo vocab show" "bo vocab check"; do
    # shellcheck disable=SC2086
    run $command --help > out.txt
    contains -F "cexchain $command" out.txt || fail "help for $command"
    contains -F "GCC 16" out.txt || fail "help for $command names the build it needs"
done
run --help > out.txt
contains -F "bo packs list" out.txt || fail "overview lists bo"
run completion bash > out.txt
contains -F '"bo") words="build check explain fmt packs stdlib test vocab"' out.txt || fail "completion: bo"
contains -F '"bo vocab") words="check list show"' out.txt || fail "completion: bo vocab"
contains -F '"bo stdlib") words="list show"' out.txt || fail "completion: bo stdlib"
contains -F -- "--write" out.txt || fail "completion: bo fmt"
contains -F 'deploy evidence explain fetch' out.txt || fail "completion: contract explain"
contains -F -- "--bundle-out" out.txt || fail "completion: bo build"
contains -F -- "--fuel" out.txt || fail "completion: bo build --fuel"
contains -F -- "--require-rebuild" out.txt || fail "completion: contract verify"
contains -F -- "--stage" out.txt || fail "completion: --stage"
contains -F '"bo packs") words="check list show"' out.txt || fail "completion: bo packs"
contains -F -- "--section" out.txt || fail "completion: options"
run contract explain --help > out.txt
contains -F "cexchain contract explain CONTRACT|INSTANCE" out.txt || fail "help for contract explain"
contains -F "only if that source rebuilds" out.txt || fail "help: contract explain needs a rebuild"
run version --json | json 'd["bo"]["edition"]' > out.txt
contains -x 1 out.txt || fail "version names the edition"

echo "== the official packs, and their digests"
run bo packs list > out.txt
contains -F "zh-Hant-HK   version 6   official   繁體中文（香港）" out.txt || fail "list"
run bo packs list --json > list.json
json 'len(d)' < list.json > out.txt
contains -x 3 out.txt || fail "three official packs"
# The digests match the goldens the C++ tests keep.
for hash in SHA-256 SM3; do
    option=sha256
    [ "$hash" = SM3 ] && option=sm3
    run bo packs list --json --hash "$option" |
        json "'\\n'.join(p['id'] + ' ' + str(p['version']) + ' ' + p['hash'] + ' ' + p['digest'] for p in d)" > digests.txt
    grep -E "^(en|zh-Hant-HK|zh-Hans-CN) 6 $hash " "$GOLDEN" > expected.txt
    diff expected.txt digests.txt > /dev/null || fail "digests ($hash) differ from $GOLDEN"
    # The vocabulary packs too.
    run bo vocab list --json --hash "$option" |
        json "'\\n'.join(p['id'] + ' ' + str(p['version']) + ' ' + p['hash'] + ' ' + p['digest'] for p in d if p['digest'])" > digests.txt
    grep -E "^(commerce 3|finance 2|services 3) $hash " "$GOLDEN" > expected.txt
    diff expected.txt digests.txt > /dev/null || fail "vocabulary digests ($hash) differ from $GOLDEN"
done
json 'd[1]["keywords"], d[1]["words"], d[1]["official"], d[1]["separation"]' < list.json > out.txt
contains -Fx "22 145 True none" out.txt || fail "facts"

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
contains -Fx "265 274" out.txt || fail "messages and sentences"
expect_exit 1 bo packs show fr
contains -F "no pack fr" out.txt || fail "unknown pack"
expect_exit 1 bo packs show en --section nope

echo "== Bo's core and its vocabulary packs"
run bo vocab list > out.txt
contains -E "^core +- +core +84 words, +5 built-in actions +\(every source\)$" out.txt || fail "vocab list: core"
contains -E "^finance +version 2 +finance +24 words, 10 built-in actions  SHA-256 [0-9a-f]{64}$" out.txt || fail "vocab list: finance"
contains -E "^commerce +version 3 +commerce +23 words, +0 built-in actions" out.txt || fail "vocab list: commerce"
contains -E "^services +version 3 +services +14 words, +6 built-in actions" out.txt || fail "vocab list: services"
run bo vocab list --language zh-Hant-HK > out.txt
contains -F "金融" out.txt || fail "vocab list: names in the reader's language"
run bo vocab list --json > vocab.json
json 'sum(p["words"] for p in d), [p["id"] for p in d], d[2]["actions"]' < vocab.json > out.txt
contains -Fx "145 ['core', 'commerce', 'finance', 'services'] ['pledge', 'release', 'enforce', 'redeem', 'pay', 'confirm_payment', 'dispute', 'freeze', 'unfreeze', 'split']" out.txt || fail "vocab list --json"
run bo vocab show core > out.txt
contains -E "^  kind +kind.thing +thing$" out.txt || fail "vocab show: the core's kind"
contains -E "^  field +field.holder +holder  party; taking \(R31\)$" out.txt || fail "vocab show: a field's facts"
contains -Fx "  transfer" out.txt || fail "vocab show: the core's actions"
run bo vocab show finance --language zh-Hans-CN > out.txt
contains -E "^  field +field.pledgee +质权人  party; added \(R20\); taking \(R31\)$" out.txt || fail "vocab show: a pack's field"
run bo vocab show services --json > show.json
json 'd["id"], d["version"], len(d["words"]), d["actions"], d["canonical"][:2]' < show.json > out.txt
contains -Fx "services 3 14 ['allocate', 'reclaim', 'subscribe', 'renew', 'upgrade', 'downgrade'] a7" out.txt || fail "vocab show --json"
json '[r["id"] for r in d["rules"]]' < show.json > out.txt
contains -Fx "['R11', 'R23', 'R34', 'R35']" out.txt || fail "vocab show --json: the pack's rules"
run bo vocab show commerce > out.txt
contains -E "^  R26  bill$" out.txt || fail "vocab show: the pack's rules"
expect_exit 1 bo vocab show acme
contains -F "no vocabulary pack acme" out.txt || fail "vocab show: unknown pack"
# A pack's word without its use line is refused, in the reader's language;
# with it, the source checks.
printf 'contract C\nparties we, bank\nthing T\n  holder we\ncan pledge to bank\n' > nouse.bo
expect_exit 2 bo check nouse.bo --language zh-Hant-HK
contains -F "nouse.bo:2:13: error: bank 屬於 finance 詞彙包，但原始碼沒有使用該詞彙包：請在開首寫 使用 finance (check.pack-not-used)" out.txt || fail "check: a pack not used"
{ printf 'use finance\n'; cat nouse.bo; } > used.bo
run bo check used.bo --stage model > out.txt
contains -Fx "packs finance" out.txt || fail "check --stage model lists the packs"
printf 'use acme\ncontract C\n' > acme.bo
expect_exit 2 bo check acme.bo
contains -F "(check.unknown-pack)" out.txt || fail "check: an unknown pack"
# bo fmt writes use lines first, sorted, in the output language.
printf 'contract C\nuse services\nuse finance\nparties we\n' > order.bo
run bo fmt order.bo --language zh-Hans-CN > out.txt
[ "$(cat out.txt)" = "$(printf '使用 finance\n使用 services\n\n合约 C\n参与方 我方')" ] || fail "fmt: use lines first"
run bo stdlib list finance > out.txt
[ "$(wc -l < out.txt)" -eq 10 ] || fail "stdlib list finance: ten actions"
expect_exit 1 bo stdlib list acme

echo "== vocabulary packs of your own (G6): checked, shown, used, and refused"
EVENTS="$SOURCE/examples/events/events.vocab"
TICKETS="$SOURCE/examples/events/tickets.bo"
run bo vocab check "$EVENTS" > out.txt
contains -F "events.vocab: vocabulary pack events version 1: 9 words (2 actions, 1 unit, 3 fields, 2 states, 1 role); terms for 2 actions; spelled in en, zh-Hans-CN, zh-Hant-HK" out.txt || fail "vocab check"
contains -Fx "ok: the vocabulary packs read, alone and with the official packs" out.txt || fail "vocab check: ok"
run bo vocab check "$EVENTS" --json > check.json
json 'd["ok"], d["packs"][0]["pack"]["id"], d["packs"][0]["pack"]["categories"]["field"], d["packs"][0]["pack"]["actions"], d["packs"][0]["pack"]["languages"]' < check.json > out.txt
contains -Fx "True events 3 ['reserve', 'check_in'] ['en', 'zh-Hans-CN', 'zh-Hant-HK']" out.txt || fail "vocab check --json"
run bo vocab show "$EVENTS" --language zh-Hant-HK > out.txt
contains -F "events version 1 (活動, yours): use events" out.txt || fail "vocab show FILE"
contains -E "^  field +events:field.guest +來賓  party; added \(R20\); taking \(R31\)$" out.txt || fail "vocab show FILE: a field"
contains -E "^  unit +events:unit.ticket +張  count, 1 of its smallest unit$" out.txt || fail "vocab show FILE: a unit"
run bo vocab show events --vocab "$EVENTS" --json > show.json
json 'd["id"], d["official"], len(d["words"]), d["languages"], d["rules"]' < show.json > out.txt
contains -Fx "events False 9 ['en', 'zh-Hans-CN', 'zh-Hant-HK'] []" out.txt || fail "vocab show ID --vocab --json"
run bo vocab list --vocab "$(dirname "$EVENTS")" > out.txt
contains -E "^events +version 1 +events +9 words, +2 built-in actions  SHA-256 [0-9a-f]{64}  \(yours\)$" out.txt || fail "vocab list --vocab DIR"
run bo vocab list --vocab "$EVENTS" --json > vocab.json
json '[p["id"] for p in d], d[-1]["official"]' < vocab.json > out.txt
contains -Fx "['core', 'commerce', 'finance', 'services', 'events'] False" out.txt || fail "vocab list --vocab --json"
run bo stdlib list events --vocab "$EVENTS" > out.txt
contains -F "check_in         events    check in: started by the guest; reserved → checked in" out.txt || fail "stdlib list a pack of your own"
run bo stdlib show reserve --vocab "$EVENTS" --language zh-Hans-CN > out.txt
contains -Fx "使用 events" out.txt || fail "stdlib show: the pack's use line"
contains -Fx "可预留 给 相对方" out.txt || fail "stdlib show: the terms in the reader's language"
contains -Fx "  来宾 = 相对方" out.txt || fail "stdlib show: the pack's field in the reader's language"
# The contract that uses it: checked, tested, built (the bundle embeds the
# pack), and, without the pack, a note says which one is missing.
run bo check "$TICKETS" --vocab "$EVENTS" > out.txt
contains -F "checked: 1 party, 5 fields" out.txt || fail "check with --vocab"
run bo test "$TICKETS" --vocab "$EVENTS" > out.txt
contains -Fx "3 tests: 3 passed, 0 failed." out.txt || fail "test with --vocab"
run bo build "$TICKETS" --vocab "$EVENTS" --out tickets.boc > out.txt 2>&1
contains -F "and the vocabulary packs events 1 (embedded) (SHA-256 digests)" out.txt || fail "build: the pack embedded"
run bo build "$TICKETS" --vocab "$EVENTS" --json > build.json 2> /dev/null
json 'd["vocabulary"][0]["id"], d["vocabulary"][0]["official"]' < build.json > out.txt
contains -Fx "events False" out.txt || fail "build --json: the pack embedded"
expect_exit 2 bo check "$TICKETS"
contains -F "note: use events names no vocabulary pack read here" out.txt || fail "check without --vocab: the note"
run bo explain "$TICKETS" --vocab "$EVENTS" --language zh-Hant-HK > out.txt
contains -F "活動詞彙包（第 1 版）" out.txt || fail "explain: the pack's name in the reader's language"
run bo fmt "$TICKETS" --vocab "$EVENTS" --language zh-Hant-HK > tickets-zh.bo
contains -Fx "可入場登記" tickets-zh.bo || fail "fmt: the pack's words in Chinese"
run bo test tickets-zh.bo --vocab "$EVENTS" > out.txt
contains -Fx "3 tests: 3 passed, 0 failed." out.txt || fail "fmt: the Chinese source tests the same"
# Refused, each with its code: a pack that does not read, a word Bo has,
# an official id, a concept of the compiler's, terms that are not terms.
sed 's/"version": 1/"version": 0/' "$EVENTS" > bad-version.vocab
expect_exit 2 bo vocab check bad-version.vocab
contains -F "(pack.bad-version)" out.txt || fail "vocab check: version 0"
sed 's/"act.reserve": "預留"/"act.reserve": "轉讓"/' "$EVENTS" > clash.vocab
expect_exit 2 bo vocab check clash.vocab
contains -F "轉讓, a word of the vocabulary pack events, already means act.transfer: spell it otherwise (vocab.conflict)" out.txt || fail "vocab check: a spelling Bo has"
sed 's/"id": "events"/"id": "finance"/' "$EVENTS" > official.vocab
expect_exit 2 bo vocab check official.vocab
contains -F "(vocab.official-id)" out.txt || fail "vocab check: an official id"
sed 's/"role.organizer": {"category": "role"}/"role.organizer": {"category": "role"}, "kind.event": {"category": "kind"}/' "$EVENTS" > kind.vocab
expect_exit 2 bo vocab check kind.vocab
contains -F "(vocab.category)" out.txt || fail "vocab check: a kind"
sed 's/    "can check in by guest",/    "can transfer",/' "$EVENTS" > terms.vocab
expect_exit 2 bo vocab check terms.vocab --json
json 'd["ok"], [x["code"] for x in d["set"]["diagnostics"]]' < out.txt > codes.txt
contains -Fx "False ['vocab.terms-clause']" codes.txt || fail "vocab check --json: terms"
expect_exit 2 bo check "$TICKETS" --vocab bad-version.vocab
contains -F "a vocabulary pack does not read" out.txt || fail "--vocab: a pack that does not read"

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
contains -F "warning: pack acme-terms does not spell 83 of the 84 words" out.txt || fail "partial"
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

echo "== bo check: the spec's VPS example, in each language"
for language in zh-hant zh-hans en mixed; do
    cp "$GOLDENS/example-vps-$language/source.bo" "vps-$language.bo"
    run bo check "vps-$language.bo" > out.txt 2> warnings.txt
    contains -Fx "vps-$language.bo: ok: 79 tokens, 3 comments, 10 clauses, edition 1" out.txt || fail "check $language"
    contains -Fx "vps-$language.bo: checked: 2 parties, 7 fields, 0 charges, 3 states, 5 actions, 3 time rules; 0 warnings" out.txt || fail "checked $language"
    # --stage lex prints the tokens the lexer's goldens keep.
    run bo check "vps-$language.bo" --stage lex > tokens.txt
    sed '$d' tokens.txt > printed.txt
    diff "$GOLDENS/example-vps-$language/tokens.txt" printed.txt > /dev/null || fail "tokens ($language)"
    # --stage parse prints the tree the parser's goldens keep: the same tree
    # in every language.
    run bo check "vps-$language.bo" --stage parse > tree.txt
    sed '$d' tree.txt > printed.txt
    diff "$GOLDENS/example-vps-$language/ast.txt" printed.txt > /dev/null || fail "tree ($language)"
    diff "$GOLDENS/example-vps-zh-hant/ast.txt" printed.txt > /dev/null || fail "the same tree ($language)"
    # It builds since E9, to the same code in every language.
    run bo build "vps-$language.bo" --json 2> /dev/null | json 'd["code_hash"]' > "code-$language.txt"
done
for language in zh-hans en mixed; do
    diff code-zh-hant.txt "code-$language.txt" > /dev/null || fail "the same code ($language)"
done
contains -F "4:4 name VPS服務 | VPS服務" "$GOLDENS/example-vps-zh-hant/tokens.txt" || fail "golden"
run bo check vps-zh-hant.bo --stage lex --json > lex.json
json 'd["ok"], d["edition"], d["stage"], len(d["tokens"]), len(d["comments"])' < lex.json > out.txt
contains -Fx "True 1 lex 79 3" out.txt || fail "check --json"
# 可訂購: the prefix keyword and the action, each with its place.
json '[(t["kind"], t["concept"], t["span"]["line"], t["span"]["column"], t["source"]) for t in d["tokens"] if t.get("concept") in ("kw.can", "act.subscribe")][:2]' < lex.json > out.txt
contains -Fx "[('word', 'kw.can', 13, 1, '可'), ('word', 'act.subscribe', 13, 2, '訂購')]" out.txt || fail "prefix in json"
json '[(t["value"], t["unit"]) for t in d["tokens"] if t["kind"] == "money"]' < lex.json > out.txt
contains -Fx "[('120', 'cur.HKD'), ('0.10', 'cur.HKD')]" out.txt || fail "money in json"
run bo check vps-en.bo --json > out.txt
json '"tokens" in d, d["stage"], d["checked"], d["diagnostics"]' < out.txt > keys.txt
contains -Fx "False check True []" keys.txt || fail "check --json without --stage"
# Its tests (E9): executors answer the subscription, its invoices, and its
# collections; the keeper fires the reminder, the suspension, and the
# termination. In English and in Traditional Chinese.
cp "$GOLDENS/test/vps/source.bo" vps-tests.bo
cp "$GOLDENS/test/vps-zh-hant/source.bo" vps-tests-zh-hant.bo
run bo test vps-tests.bo > out.txt
contains -Fx "5 tests: 5 passed, 0 failed." out.txt || fail "vps tests"
contains -F "Requests made: collect, to be answered by 2027-02-09." out.txt || fail "vps: a collection from the due date"
run bo test vps-tests-zh-hant.bo --language zh-Hant-HK > out.txt
contains -Fx "共 5 個測試：5 個通過，0 個失敗。" out.txt || fail "vps tests in zh-Hant"
run bo test vps-tests.bo --json | json 'd["passed"], d["failed"]' > out.txt
contains -Fx "5 0" out.txt || fail "vps tests --json"
# The contract text states each request, the bills, and the payments.
run bo explain vps-en.bo > out.txt
contains -F "It asks an executor for collect for the customer, outside the ledger, to be answered within 30 days of the due date" out.txt || fail "explain: the collection"
contains -F "[R34]" out.txt || fail "explain: R34"
contains -F "[R35]" out.txt || fail "explain: R35"
run bo explain vps-zh-hant.bo --language zh-Hant-HK > out.txt
contains -F "已付費至" out.txt || fail "explain in zh-Hant: paid until"

echo "== bo check: one line, any language, the same concepts"
printf 'can pledge to bank\n可質押 予 銀行\n可质押 给 银行\n可pledge 予 bank\n' > lines.bo
run bo check lines.bo --stage lex --json |
    json '"\n".join(" ".join(t.get("concept", t["kind"]) for t in d["tokens"] if t["span"]["line"] == n) for n in range(1, 5))' > out.txt
[ "$(sort -u out.txt | wc -l | tr -d ' ')" = 1 ] || fail "the same concepts in each language"
contains -Fx "kw.can act.pledge kw.to role.bank newline" out.txt || fail "concepts"

echo "== bo check: errors, with places, in the reader's language"
printf 'contract X\n\tparties we\nover 5,000\n100 HKD 200\n' > bad.bo
expect_exit 2 bo check bad.bo
contains -F "bad.bo:2:1: error: a tab is not allowed; indent and separate words with spaces (lex.tab)" out.txt || fail "tab"
contains -F "bad.bo:3:6: error: 5,000: a comma never groups digits; write 5_000 (lex.digit-comma)" out.txt || fail "comma"
contains -F "(lex.ambiguous-money)" out.txt || fail "money"
contains -Fx "bad.bo: 3 errors" out.txt || fail "count"
expect_exit 2 bo check bad.bo --language zh-Hant-HK
contains -F "bad.bo:3:6: error: 5,000：逗號不可用作數字分組；請寫 5_000 (lex.digit-comma)" out.txt || fail "zh-Hant"
CEXCHAIN_LANGUAGE=zh-Hans expect_exit 2 bo check bad.bo
contains -F "不能使用制表符（Tab）" out.txt || fail "zh-Hans"
expect_exit 2 bo check bad.bo --json
json '[(x["code"], x["span"]["line"], x["span"]["column"]) for x in d["diagnostics"]]' < out.txt > codes.txt
contains -Fx "[('lex.tab', 2, 1), ('lex.digit-comma', 3, 6), ('lex.ambiguous-money', 4, 1)]" codes.txt || fail "check --json errors"
# Invisible characters are refused, and shown by code point.
printf 'contract a\xe2\x80\x8bb\n' > invisible.bo
expect_exit 2 bo check invisible.bo
contains -F "invisible.bo:1:11: error: the invisible character U+200B is not allowed" out.txt || fail "invisible"
printf 'contract \xff\n' > utf8.bo
expect_exit 2 bo check utf8.bo
contains -F "utf8.bo:1:10: error: the source is not valid UTF-8 here (lex.utf8)" out.txt || fail "utf8"
expect_exit 1 bo check vps-en.bo --stage nope
contains -F -- "--stage must be lex (the tokens), parse (the tree), or model (the checked model)" out.txt || fail "stage"
expect_exit 1 bo check
expect_exit 2 bo check no-such.bo

echo "== bo check: the tree, one clause in any language"
for language in en zh-hant zh-hans mixed; do
    cp "$GOLDENS/example-receivable-$language/source.bo" "receivable-$language.bo"
    run bo check "receivable-$language.bo" --stage parse --json > "receivable-$language.json"
    json 'd["tree"]' < "receivable-$language.json" > "receivable-$language.tree"
    diff receivable-en.tree "receivable-$language.tree" > /dev/null || fail "the same tree ($language)"
done
contains -Fx "can act.pledge to=role.bank" receivable-en.tree || fail "tree: can"
contains -Fx "  requires cond.in_person guard=(cond.over 5000000)" receivable-en.tree || fail "tree: guard"
# The tree as objects, member by member, with places in the source as written.
json 'd["ok"], d["stage"], d["clauses"], [c["node"] for c in d["ast"]["clauses"]]' < receivable-zh-hant.json > out.txt
contains -Fx "True parse 6 ['contract', 'parties', 'block', 'can', 'can', 'when']" out.txt || fail "parse --json"
json 'd["ast"]["clauses"][3]["action"]["concept"], d["ast"]["clauses"][3]["to"]["concept"], d["ast"]["clauses"][3]["body"][0]["guard"]["concept"], d["ast"]["clauses"][3]["span"]' < receivable-zh-hant.json > out.txt
contains -Fx "act.pledge role.bank cond.over {'line': 10, 'column': 1, 'offset': 158, 'length': 20}" out.txt || fail "parse --json members"
json 'd["ast"]["clauses"][5]["actions"][0]["subject"]["concept"], d["ast"]["clauses"][5]["actions"][0]["action"]["concept"]' < receivable-en.json > out.txt
contains -Fx "role.issuer act.pay" out.txt || fail "when: the party before the action"

echo "== bo check: the parser's errors, with places, in the reader's language"
printf 'contract X\ncan pledge bank\n  requires a < b < c\nparties use\n可提款 由 客戶\n' > parse.bo
expect_exit 2 bo check parse.bo
contains -F "parse.bo:2:12: error: bank cannot follow the action here: write by PARTY, to PARTY, or with INPUTS, each at most once (parse.can)" out.txt || fail "can"
contains -F "parse.bo:4:9: error: use declares a vocabulary pack on a line of its own, outside any block: use finance (parse.reserved)" out.txt || fail "use"
contains -F "parse.bo:5:1: error: 可提款 is one name here, since nothing declares 提款; to begin the line with 可, write 可 提款 with a space (parse.undeclared-split)" out.txt || fail "split"
contains -Fx "parse.bo: 3 errors" out.txt || fail "count (the block under a failed line is skipped)"
expect_exit 2 bo check parse.bo --language zh-Hant-HK
contains -F "parse.bo:2:12: error: bank 不可接在此動作之後：可寫 由 訂約方、予 訂約方 或 連同 輸入項，每項最多一次 (parse.can)" out.txt || fail "zh-Hant"
CEXCHAIN_LANGUAGE=zh-Hans expect_exit 2 bo check parse.bo --stage parse
contains -F "parse.bo:4:9: error: use 用于声明词汇包，须在任何代码块之外单独成行：使用 finance (parse.reserved)" out.txt || fail "zh-Hans"
contains -Fx "contract X" out.txt || fail "the tree of what parsed"
expect_exit 2 bo check parse.bo --json
json '[(x["code"], x["span"]["line"], x["span"]["column"]) for x in d["diagnostics"]]' < out.txt > codes.txt
contains -Fx "[('parse.can', 2, 12), ('parse.reserved', 4, 9), ('parse.undeclared-split', 5, 1)]" codes.txt || fail "parse errors in json"
# The lexer's problems and the parser's together, in source order; a line
# the lexer refused gets no second message from the parser.
printf 'can pledge @@ bank\n  requires a < b < c\n' > both.bo
expect_exit 2 bo check both.bo --json
json '[x["code"] for x in d["diagnostics"]]' < out.txt > codes.txt
contains -Fx "['lex.bad-character', 'lex.bad-character']" codes.txt || fail "lexer first, parser quiet"

echo "== bo check: the model, the same in every language"
for language in en zh-hant zh-hans mixed; do
    cp "$GOLDENS/example-receivable-$language/source.bo" "receivable-$language.bo"
    run bo check "receivable-$language.bo" --stage model > model.txt
    sed '$d' model.txt | sed '$d' > "receivable-$language.model"
    diff "$GOLDENS/example-receivable-en/check.txt" "receivable-$language.model" > /dev/null || fail "model ($language)"
done
contains -Fx "party role.bank bound=act.pledge{R3}" receivable-en.model || fail "model: the bank, bound by the pledge"
contains -Fx "  requires cond.in_person{R13} guard=(cond.over (money cur.HKD 5000000){R6})" receivable-en.model || fail "model: threshold"
contains -Fx "  do subject=role.issuer act.pay obligation{R9}" receivable-en.model || fail "model: duty"
run bo check receivable-zh-hant.bo --stage model --json > model.json
json 'd["ok"], d["stage"], d["checked"], d["model"]["name"], d["model"]["parties"][2]["bound_by"], d["model"]["fields"][0]["type"]' < model.json > out.txt
contains -Fx "True model True ReceivableFinancing act.pledge money cur.HKD" out.txt || fail "model --json"
json 'd["model"]["actions"][0]["body"][0]["guard"]["operands"][0]["rule"], d["model"]["actions"][0]["body"][0]["span"]["line"]' < model.json > out.txt
contains -Fx "R6 11" out.txt || fail "model --json: the rule and the place"
json 'd["dump"].splitlines()[0]' < model.json > out.txt
contains -Fx "edition 1" out.txt || fail "model --json: the text"

echo "== bo check, test, explain: a counterparty made holder or pledgee consents (R31)"
cp "$GOLDENS/check-role-taking/source.bo" role-taking.bo
run bo check role-taking.bo --stage model > model.txt
contains -Fx "  consent role.bank{R31}" model.txt || fail "R31: the model"
run bo test role-taking.bo > out.txt
contains -Fx "3 tests: 3 passed, 0 failed." out.txt || fail "R31: the tests"
run bo explain role-taking.bo --language zh-Hant-HK > out.txt
contains -F "每次調用均須經銀行同意，因為此動作令銀行成為質權人。〔R31〕" out.txt || fail "R31: the text"
run bo explain role-taking.bo --json > out.json
json "[c['function'] for s in d['sections'] for c in s['clauses'] if 'R31' in c['rules']], d['rules'][-1]['id']" < out.json > out.txt
contains -Fx "['pledge', 'transfer', 'lodge'] R31" out.txt || fail "R31: the text, as JSON"
# A fragment: the spec's VAT, with the field that holds its bill.
printf 'use commerce\nthing Sale\n  invoice list CNY\n\ncharge 增值税\n  rate 6%%\n  applies to customer location = 中国内地\n  added\n  according to invoice half up\n  from 2027-01-01 on rate 9%%\n' > fragment.bo
run bo check fragment.bo > out.txt 2> warnings.txt
contains -Fx "fragment.bo: checked: 0 parties, 2 fields, 1 charge, 1 state, 0 actions, 0 time rules; 1 warning" out.txt || fail "fragment"
contains -F "fragment.bo: warning: there is no contract line, so this file is checked as a fragment" warnings.txt || fail "fragment warning"

echo "== bo check: the checker's errors, in the reader's language"
printf 'use finance\ncontract C\nparties issuer, supplier\nasset A\n  amount HKD\n  holder HKD\ncan pledge to bank\n  over USD 5 requires in person\ncan go\n' > model.bo
expect_exit 2 bo check model.bo
contains -F "model.bo:6:10: error: holder holds a party, not money in HKD (check.field-type)" out.txt || fail "field type"
contains -F "model.bo:7:15: error: bank is not one of the contract's parties: add it to the parties line (check.unknown-party)" out.txt || fail "party"
contains -F "model.bo:8:8: error: money in USD and money in HKD are in different currencies; Bo never converts one into the other (check.mixed-currencies)" out.txt || fail "currencies"
contains -F "model.bo:9:5: error: who starts go? An action of your own needs by PARTY (check.needs-by)" out.txt || fail "by"
contains -Fx "model.bo: 4 errors" out.txt || fail "count"
expect_exit 2 bo check model.bo --language zh-Hant-HK
contains -F "model.bo:6:10: error: 持有人 存放的是訂約方，而非港元金額 (check.field-type)" out.txt || fail "zh-Hant"
contains -F "model.bo:8:8: error: 美元金額與港元金額是不同貨幣；Bo 從不換算貨幣 (check.mixed-currencies)" out.txt || fail "zh-Hant currencies"
CEXCHAIN_LANGUAGE=zh-Hans expect_exit 2 bo check model.bo --stage model
contains -F "model.bo:7:15: error: 银行 不是此合约的参与方：请把它加入 参与方 一行 (check.unknown-party)" out.txt || fail "zh-Hans"
contains -Fx "contract C" out.txt || fail "the model of what checked"
expect_exit 2 bo check model.bo --json
json '[(x["code"], x["span"]["line"], x["args"].get("type", "")) for x in d["diagnostics"]]' < out.txt > codes.txt
contains -Fx "[('check.field-type', 6, 'money cur.HKD'), ('check.unknown-party', 7, ''), ('check.mixed-currencies', 8, ''), ('check.needs-by', 9, '')]" codes.txt || fail "checker errors in json"
# A source the lexer or the parser refuses is not checked.
printf 'contract C\ncan pledge to bank bank\n' > unparsed.bo
expect_exit 2 bo check unparsed.bo --json
json 'd["checked"], [x["code"] for x in d["diagnostics"]]' < out.txt > codes.txt
contains -Fx "False ['parse.can']" codes.txt || fail "no check after a parse error"

echo "== bo check: with a company's own pack"
printf 'can lodge to bank\n可lodge 予 vendor\n' > own.bo
expect_exit 0 bo check own.bo --pack company.pack --stage lex
contains -F "1:5 word act.pledge | lodge" out.txt || fail "own word"
contains -F "2:2 word act.pledge | lodge" out.txt || fail "prefix with own word"
contains -F "2:10 word role.supplier | vendor" out.txt || fail "own role"
run bo check own.bo --stage lex > out.txt
contains -F "1:5 name lodge | lodge" out.txt || fail "without the pack, a name"
expect_exit 2 bo check own.bo --pack missing.pack

echo "== bo build: the agreement, in any language, to the same code"
BUILDS="$GOLDENS/build"
cp "$BUILDS/agreement-en/source.bo" agreement.bo
# The code's hash and size, as the codegen goldens keep them.
GOLDEN_HASH="$(sed -n 2p "$BUILDS/agreement-en/build.txt" | sed 's/.*sha256 \([0-9a-f]*\),.*/\1/')"
GOLDEN_SIZE="$(sed -n 2p "$BUILDS/agreement-en/build.txt" | sed 's/^code: \([0-9]*\) bytes.*/\1/')"
COMPILER="$(run version --json | json 'd["bo"]["compiler"]')"
contains -E "^cexchain-bo [0-9.]+; codegen 3; edition 1$" <<< "$COMPILER" || fail "the compiler string"
run bo build agreement.bo > out.txt 2> warnings.txt
contains -Fx "agreement.bo: built contract Agreement (Bo edition 1)" out.txt || fail "build"
contains -F "functions  amend, close, countersign, create (creates), sign" out.txt || fail "functions"
contains -F "code       $GOLDEN_SIZE bytes, SHA-256 $GOLDEN_HASH" out.txt || fail "code"
contains -F "compiler   $COMPILER" out.txt || fail "compiler"
contains -F "the packs en 6, zh-Hans-CN 6, zh-Hant-HK 6, and the vocabulary packs commerce 3 (SHA-256 digests)" out.txt || fail "packs"
contains -F "wrote" out.txt && fail "nothing written without --out"
# The highest fuel and output bounds (milestone 18), as the golden keeps them.
AMEND_FUEL="$(sed -n 's/^bound amend: fuel \([0-9]*\),.*/\1/p' "$BUILDS/agreement-en/build.txt")"
AMEND_GROUPED="$(python3 -c "print(f'{$AMEND_FUEL:,}')")"
contains -F "fuel       at most $AMEND_GROUPED a call (amend), of 10,000,000; output at most" out.txt || fail "the fuel bound"
contains -E "^  function +fuel +reading +output$" out.txt && fail "the table only with --fuel"
run bo build agreement.bo --fuel > out.txt 2> /dev/null
contains -E "^  function +fuel +reading +output$" out.txt || fail "--fuel: the table"
contains -E "^  amend +$AMEND_GROUPED +[0-9,]+ +[0-9,]+$" out.txt || fail "--fuel: amend's bound"
for function in close countersign create sign; do
    contains -E "^  $function +[0-9,]+ +[0-9,]+ +[0-9,]+$" out.txt || fail "--fuel: $function"
done
# Comments are published with the source: a warning says so.
contains -F "agreement.bo: warning: the source is deployed with its comments (4 lines)" warnings.txt || fail "comments"
run bo build agreement.bo --json > build.json
json 'd["ok"], d["contract"], d["code_size"], d["code_hash"], d["compiler"], d["edition"], d["comments"]' < build.json > out.txt
contains -Fx "True Agreement $GOLDEN_SIZE $GOLDEN_HASH $COMPILER 1 4" out.txt || fail "build --json"
# The source as written (its tests included), and the bundle a deploy records.
SOURCE_SIZE="$(wc -c < agreement.bo | tr -d ' ')"
BUNDLE_SIZE="$(json 'd["bundle_size"]' < build.json)"
json 'd["source_size"]' < build.json | contains -Fx "$SOURCE_SIZE" || fail "build --json: the source's size"
json 'd["functions"]["create"], d["functions"]["sign"], [p["id"] for p in d["packs"] if p["official"]]' < build.json > out.txt
contains -Fx "create call ['en', 'zh-Hans-CN', 'zh-Hant-HK']" out.txt || fail "functions and packs in json"
json 'sorted(d["bounds"]) == sorted(d["functions"]), d["bounds"]["amend"]["fuel"], d["fuel_limit"], d["output_limit"], all(b["input"] < b["fuel"] and b["output"] > 0 for b in d["bounds"].values())' < build.json > out.txt
contains -Fx "True $AMEND_FUEL 10000000 196608 True" out.txt || fail "build --json: the bounds"
# The packs' digests are those bo packs list shows.
run bo packs list --json | json '" ".join(p["id"] + "=" + p["digest"] for p in sorted(d, key=lambda p: p["id"]))' > listed.txt
json '" ".join(p["id"] + "=" + p["digest"] for p in d["packs"])' < build.json > digests.txt
diff listed.txt digests.txt > /dev/null || fail "bundle digests are the packs' digests"
for language in zh-hant zh-hans mixed; do
    cp "$BUILDS/agreement-$language/source.bo" "agreement-$language.bo"
    run bo build "agreement-$language.bo" --json 2> /dev/null | json 'd["code_hash"]' > out.txt
    contains -Fx "$GOLDEN_HASH" out.txt || fail "the same code from $language"
done
run bo build agreement.bo --hash sm3 --out agreement-sm3.boc --code-out agreement.wasm \
    --bundle-out agreement-sm3.bundle > out.txt 2> /dev/null
contains -F "(SM3 digests)" out.txt || fail "SM3 digests"
contains -F "wrote      agreement-sm3.boc" out.txt || fail "wrote the .boc"
[ "$(wc -c < agreement.wasm | tr -d ' ')" = "$GOLDEN_SIZE" ] || fail "the module"
run bo build agreement.bo --bundle-out agreement.bundle > /dev/null 2>&1
cmp -s agreement.bundle agreement-sm3.bundle && fail "the digests depend on the hash"
# In the reader's language.
run bo build agreement.bo --language zh-Hant-HK > /dev/null 2> warnings.txt
contains -F "原始碼會連同其註釋（4 行）一併部署" warnings.txt || fail "zh-Hant warning"

echo "== bo build: what does not build"
expect_exit 2 bo build fragment.bo
contains -F "this file has no contract line, so it is a fragment" out.txt || fail "fragment"
contains -Fx "fragment.bo: 1 error" out.txt || fail "fragment count"
# notify is a request (R10), not an action of the contract's.
printf 'contract Notice\nparties we, reader\nthing Note\ncan notify by we\n' > notify.bo
expect_exit 2 bo build notify.bo
contains -F "(build.executor)" out.txt || fail "notify as an action"
expect_exit 2 bo build model.bo --json
json 'd["ok"], "code_hash" in d, d["diagnostics"][0]["code"]' < out.txt > codes.txt
contains -Fx "False False check.field-type" codes.txt || fail "check errors stop the build"
# A call that could run out of fuel: every row against every column, a
# million comparisons. Lists of 100 build.
cat > grid.bo <<'EOF'
contract Grid
parties we

thing Grid
  rows list number at most 1000
  columns list number at most 1000

can check by we
  each r in rows
    each c in columns
      requires r < c or r >= c
EOF
expect_exit 2 bo build grid.bo
contains -F "(build.fuel)" out.txt || fail "the fuel bound refuses"
contains -F "check could use up to" out.txt || fail "the fuel bound's function"
expect_exit 2 bo build grid.bo --json
json 'd["ok"], [x["code"] for x in d["diagnostics"]]' < out.txt > codes.txt
contains -Fx "False ['build.fuel']" codes.txt || fail "build.fuel in json"
expect_exit 2 bo build grid.bo --language zh-Hant-HK
contains -F "燃料" out.txt || fail "build.fuel in zh-Hant"
sed 's/1000/100/' grid.bo > grid100.bo
run bo build grid100.bo > out.txt 2> /dev/null || fail "lists of 100 build"
# An output that could exceed the code's region builds, with a warning: a
# part repeats its parent's fields, a text of up to 64 KiB among them.
cat > notes.bo <<'EOF'
use finance
contract Notes
parties issuer, supplier

asset Receivable
  amount CNY
  tier number
  note text
  holder supplier

can split
EOF
run bo build notes.bo > out.txt 2> warnings.txt || fail "an output bound only warns"
contains -F "notes.bo: warning: split could write up to" warnings.txt || fail "build.output"
contains -F "(build.output)" warnings.txt || fail "build.output code"
contains -F "warning: issue" warnings.txt && fail "build.output for a function without parts"
expect_exit 1 bo build agreement.bo --hash sha384
expect_exit 1 bo build
expect_exit 2 bo build no-such.bo

echo "== bo explain: the contract text, the same from every spelling"
TEXTS="$GOLDENS/explain"
for language in en zh-Hant-HK zh-Hans-CN; do
    file="$(tr 'A-Z' 'a-z' <<< "$language" | sed 's/-hk$//; s/-cn$//')"
    for spelling in en zh-hant zh-hans mixed; do
        cp "$BUILDS/agreement-$spelling/source.bo" "agreement-$spelling.bo"
        run bo explain "agreement-$spelling.bo" --language "$language" > text.txt 2> warnings.txt
        diff "$TEXTS/agreement/$file.txt" text.txt > /dev/null || fail "text ($language from $spelling)"
        [ -s warnings.txt ] && fail "no problems for a source that builds"
    done
done
run bo explain agreement.bo > text.txt
contains -Fx "Contract Agreement" text.txt || fail "title"
contains -Fx "  4.2.2 Requirement 1: if the amount is over HKD 1,000,000, the customer must prove presence in person, with a passkey or a hardware key. [R6, R13]" text.txt || fail "an inferred clause, marked"
contains -F "[R6] Over N compares N with the action's one amount" text.txt || fail "the rule explained"
CEXCHAIN_LANGUAGE=zh-Hans run bo explain agreement.bo > text.txt
diff "$TEXTS/agreement/zh-hans.txt" text.txt > /dev/null || fail "\$CEXCHAIN_LANGUAGE"
run bo explain agreement.bo --language zh-Hant > text.txt
contains -F "  4.2.2 要求 1：如金額超過港元 1,000,000，客戶須以通行密鑰或硬件密鑰證明本人親身在場。〔R6、R13〕" text.txt || fail "zh-Hant"
# The demo's agreement, in Simplified Chinese.
run bo explain "$SOURCE/examples/supply-agreement/supply-agreement.bo" --language zh-Hans-CN > text.txt
diff "$TEXTS/supply-agreement/zh-hans.txt" text.txt > /dev/null || fail "the demo's text"
# --json: the clauses, their rules, requirements numbered as refusals name
# them (bo:requires sign 2), and the rules' texts.
run bo explain agreement.bo --json > explain.json
json 'd["ok"], d["language"], d["title"], [s["kind"] for s in d["sections"]]' < explain.json > out.txt
contains -Fx "True en Contract Agreement ['parties', 'instance', 'states', 'actions']" out.txt || fail "explain --json"
json '[(c["function"], c["requirement"], c["rules"]) for s in d["sections"] for c in s["clauses"] if c["kind"] == "requirement"]' < explain.json > out.txt
contains -Fx "[('amend', 1, ['R7']), ('amend', 2, []), ('amend', 3, []), ('sign', 1, ['R6', 'R13']), ('sign', 2, []), ('close', 1, [])]" out.txt || fail "requirements in json"
json '[r["id"] for r in d["rules"]], d["text"] == open("'"$TEXTS"'/agreement/en.txt").read()' < explain.json > out.txt
contains -Fx "['R3', 'R4', 'R5', 'R6', 'R7', 'R13', 'R14', 'R17', 'R25'] True" out.txt || fail "rules in json"
# R18: a name compared with a text is that text, shown in quotation marks.
run bo explain fragment.bo > text.txt 2> warnings.txt
contains -F '  2.2.2 It applies when the customer location is "中国内地". [R18]' text.txt || fail "R18 in quotes"
contains -F "(check.fragment)" warnings.txt || fail "warnings on stderr"
run bo explain fragment.bo --language zh-Hant-HK 2> /dev/null | contains -F "適用條件：客戶所在地為「中国内地」。〔R18〕" || fail "R18 in zh-Hant"
# The VPS states its requests (E9), from any spelling.
run bo explain vps-zh-hant.bo > text.txt 2> warnings.txt
diff "$TEXTS/vps/en.txt" text.txt > /dev/null || fail "the VPS text"
[ ! -s warnings.txt ] || fail "the VPS checks clean"
# A source that does not check has no text; its problems in the reader's language.
expect_exit 2 bo explain model.bo
contains -F "model.bo: 4 errors: there is no contract text until it checks" out.txt || fail "no text"
expect_exit 2 bo explain model.bo --language zh-Hant-HK
contains -F "持有人 存放的是訂約方，而非港元金額 (check.field-type)" out.txt || fail "errors in zh-Hant"
expect_exit 2 bo explain model.bo --json
json 'd["ok"], "text" in d, d["diagnostics"][0]["code"]' < out.txt > codes.txt
contains -Fx "False False check.field-type" codes.txt || fail "explain --json without a text"
expect_exit 1 bo explain agreement.bo --language fr
expect_exit 1 bo explain
expect_exit 2 bo explain no-such.bo

echo "== bo fmt: the source laid out canonically, and in one language"
# The demo's agreement, written in English, is formatted; into each language
# it gives the same tree, the same code, and the same text, and formatting it
# again changes nothing.
cp "$SOURCE/examples/supply-agreement/supply-agreement.bo" supply.bo
run bo fmt supply.bo > out.txt
cmp -s out.txt supply.bo || fail "the demo is formatted"
run bo fmt supply.bo --check > out.txt
contains -Fx "supply.bo: formatted" out.txt || fail "--check: formatted"
SUPPLY_HASH="$(run bo build supply.bo --json 2> /dev/null | json 'd["code_hash"]')"
run bo explain supply.bo > supply-text.txt
run bo check supply.bo --stage parse | sed '$d' > supply-tree.txt
for language in zh-Hant-HK zh-Hans-CN en; do
    run bo fmt supply.bo --language "$language" > "supply-$language.bo"
    run bo build "supply-$language.bo" --json 2> /dev/null | json 'd["code_hash"]' > out.txt
    contains -Fx "$SUPPLY_HASH" out.txt || fail "fmt --language $language: the same code"
    run bo explain "supply-$language.bo" > text.txt
    diff supply-text.txt text.txt > /dev/null || fail "fmt --language $language: the same text"
    run bo check "supply-$language.bo" --stage parse | sed '$d' > tree.txt
    diff supply-tree.txt tree.txt > /dev/null || fail "fmt --language $language: the same tree"
    run bo fmt "supply-$language.bo" --language "$language" --check > out.txt
    contains -Fx "supply-$language.bo: formatted in $language" out.txt || fail "fmt --language $language again"
done
contains -Fx "訂約方 我方, 供應商, 銀行" supply-zh-Hant-HK.bo || fail "zh-Hant: parties"
contains -Fx "可 sign 由 我方" supply-zh-Hant-HK.bo || fail "zh-Hant: names stay"
contains -Fx "  須經 供應商 同意" supply-zh-Hant-HK.bo || fail "zh-Hant: words joined as Chinese writes them"
contains -Fx "  须经 银行 同意" supply-zh-Hans-CN.bo || fail "zh-Hans"
contains -Fx "# A supply agreement between a core enterprise (we), its supplier, and its" supply-zh-Hans-CN.bo || fail "comments stay"
cmp -s supply-en.bo supply.bo || fail "into its own language: unchanged"
run bo fmt supply-zh-Hant-HK.bo --language en > out.txt
cmp -s out.txt supply.bo || fail "from Traditional Chinese back to English"
# The compiled agreement, from each spelling into each language: one code.
for spelling in en zh-hant zh-hans mixed; do
    cp "$BUILDS/agreement-$spelling/source.bo" "agreement-$spelling.bo"
    for language in en zh-Hant-HK zh-Hans-CN; do
        run bo fmt "agreement-$spelling.bo" --language "$language" > formatted.bo
        run bo build formatted.bo --json 2> /dev/null | json 'd["code_hash"]' > out.txt
        contains -Fx "$GOLDEN_HASH" out.txt || fail "the agreement from $spelling in $language: the same code"
    done
done
# The formatter's goldens.
for case in layout pieces dates-numbers; do
    run bo fmt "$GOLDENS/format/$case/source.bo" > out.txt
    cmp -s out.txt "$GOLDENS/format/$case/keep.bo" || fail "fmt $case"
    for language in en zh-Hant-HK zh-Hans-CN; do
        file="$(tr 'A-Z' 'a-z' <<< "$language" | sed 's/-hk$//; s/-cn$//')"
        run bo fmt "$GOLDENS/format/$case/source.bo" --language "$language" > out.txt
        cmp -s out.txt "$GOLDENS/format/$case/$file.bo" || fail "fmt $case --language $language"
    done
done
# --check, --json, --write.
printf 'use commerce\ncontract  A\nparties   we ,customer\n' > loose.bo
expect_exit 3 bo fmt loose.bo --check
contains -Fx "loose.bo: would change when formatted" out.txt || fail "--check: not formatted"
expect_exit 3 bo fmt supply.bo --check --language zh-Hans
contains -Fx "supply.bo: would change when formatted in zh-Hans-CN" out.txt || fail "--check --language"
run bo fmt loose.bo --json > fmt.json
json 'd["ok"], d["changed"], d["written"], d["language"], repr(d["source"]), d["diagnostics"]' < fmt.json > out.txt
contains -Fx "True True False None 'use commerce\ncontract A\nparties we, customer\n' []" out.txt || fail "fmt --json"
run bo fmt loose.bo --write > out.txt
contains -Fx "loose.bo: formatted" out.txt || fail "--write"
[ "$(cat loose.bo)" = "$(printf 'use commerce\ncontract A\nparties we, customer')" ] || fail "--write wrote the file"
run bo fmt loose.bo --write > out.txt
contains -Fx "loose.bo: already formatted" out.txt || fail "--write again"
run bo fmt loose.bo --write --language zh-Hant-HK --json | json 'd["written"], d["language"]' > out.txt
contains -Fx "True zh-Hant-HK" out.txt || fail "--write --language --json"
contains -Fx "訂約方 我方, 客戶" loose.bo || fail "written in Traditional Chinese"
# Source with errors is not formatted, nor written; problems in the reader's
# language.
printf 'contract A\n\tparties we\n' > tab.bo
cp tab.bo tab-before.bo
expect_exit 2 bo fmt tab.bo --write
contains -F "tab.bo:2:1: error: " out.txt || fail "fmt: the problem"
contains -Fx "tab.bo: not formatted" out.txt || fail "fmt: not formatted"
cmp -s tab.bo tab-before.bo || fail "a file with errors is not written"
CEXCHAIN_LANGUAGE=zh-Hant expect_exit 2 bo fmt tab.bo
contains -F "(lex.tab)" out.txt || fail "fmt: the code"
contains -F "縮排" out.txt || fail "fmt: the problem in Traditional Chinese"
expect_exit 2 bo fmt tab.bo --json
json 'd["ok"], d["changed"], "source" in d, d["diagnostics"][0]["code"]' < out.txt > codes.txt
contains -Fx "False False False lex.tab" codes.txt || fail "fmt --json with errors"
# A company's pack in which two words side by side read as a third: the
# formatter refuses rather than change what the line says.
sed -e 's/"acme-terms"/"collide"/' -e 's/"en-x-acme"/"en-x-collide"/' \
    -e 's|"role.supplier": "vendor",|"role.supplier": "vendor", "act.release": "lodge to",|' company.pack > collide.pack
printf '使用 finance\n合約 C\n訂約方 本公司, 銀行\n\n可質押 予 銀行\n' > pledge.bo
expect_exit 2 bo fmt pledge.bo --pack collide.pack --language collide
contains -F "pledge.bo:5:1: error: written in collide, the source would read differently here" out.txt || fail "fmt.unstable"
contains -F "(fmt.unstable)" out.txt || fail "fmt.unstable: the code"
run bo fmt pledge.bo --pack company.pack --language en-x-acme > out.txt
contains -Fx "can lodge to bank" out.txt || fail "a company's pack: its words"
expect_exit 1 bo fmt loose.bo --check --write
expect_exit 1 bo fmt loose.bo --language fr
expect_exit 1 bo fmt
expect_exit 2 bo fmt no-such.bo

echo "== bo test: the test blocks, run as a ledger runs calls"
# The demo's agreement carries two tests: signed by all three and closed; and
# nobody signs alone. Each runs on an instance of its own.
cp "$SOURCE/examples/supply-agreement/supply-agreement.bo" supply.bo
run bo test supply.bo > report.txt
contains -Fx 'Test "signed by all three, then closed": passed' report.txt || fail "test: passed"
contains -Fx '  Step 2 (line 27) passed: we sign -> signed' report.txt || fail "test: a step as written"
contains -Fx '    Result: accepted with the consent of the supplier and the bank, and the instance is signed.' report.txt || fail "test: implicit consents"
contains -Fx '    Result: the call waits for the consent of the bank.' report.txt || fail "test: a consent withheld"
contains -Fx '    Result: the call waits for us to make it.' report.txt || fail "test: the home starts sign"
contains -Fx '    The contract text, 4.2.3: If the instance is signed, it becomes closed; otherwise the call is refused.' report.txt || fail "test: the clause of a refusal"
contains -Fx "2 tests: 2 passed, 0 failed." report.txt || fail "test: the count"
# In each language, the same results: the report in the reader's language.
run bo test supply.bo --language zh-Hant-HK > report.txt
contains -Fx '測試 「nobody signs alone」：通過' report.txt || fail "test: zh-Hant"
contains -Fx '    結果：調用正等待銀行同意。' report.txt || fail "test: zh-Hant waits"
CEXCHAIN_LANGUAGE=zh-Hans run bo test supply.bo > report.txt
contains -Fx '共 2 个测试：2 个通过，0 个失败。' report.txt || fail "test: \$CEXCHAIN_LANGUAGE"
run bo test supply.bo --json > test.json
for language in zh-Hant-HK zh-Hans-CN; do
    run bo fmt supply.bo --language "$language" > "supply-$language.bo"
    run bo test "supply-$language.bo" --json > other.json
    python3 - test.json other.json <<'PY' || fail "test: the same results in $language"
import json, sys
a, b = (json.load(open(f)) for f in sys.argv[1:3])
strip = lambda d: [[(s["status"], s["result"]["outcome"], s["calls"]) for s in t["steps"]] for t in d["tests"]]
assert strip(a) == strip(b) and a["ledgers"] == b["ledgers"]
PY
done
json 'd["ok"], d["built"], d["total"], d["passed"], d["failed"], sorted(d["ledgers"])' < test.json > out.txt
contains -Fx "True True 2 2 0 ['bank', 'supplier', 'we']" out.txt || fail "test --json"
json '[(s["subject"], s["action"], s["result"]["outcome"], s["result"].get("parties")) for s in d["tests"][1]["steps"]]' < test.json > out.txt
contains -Fx "[('we', 'create', 'accepted', None), ('we', 'sign', 'waits', ['bank']), ('supplier', 'sign', 'waits', ['we']), ('we', 'close', 'refused', None)]" out.txt || fail "test --json: steps"
json 'd["tests"][1]["steps"][3]["result"]["reason"], d["tests"][1]["steps"][3]["result"]["clause"]["number"], len(d["tests"][0]["steps"][1]["calls"]), d["tests"][0]["steps"][1]["calls"][1]["consents"]' < test.json > out.txt
contains -Fx "bo:state close 4.2.3 2 ['supplier', 'bank']" out.txt || fail "test --json: reason, clause, calls"
# The agreement's tests, from each spelling: the same results.
for spelling in en zh-hant zh-hans mixed; do
    run bo test "$BUILDS/agreement-$spelling/source.bo" --json | json 'd["passed"], d["failed"]' > out.txt
    contains -Fx "3 0" out.txt || fail "test: the agreement in $spelling"
done
# A failing test: exit status 3, what was expected and what happened.
expect_exit 3 bo test "$GOLDENS/test/failing/source.bo"
contains -Fx '  Step 2 (line 21) FAILED: customer accept -> withdrawn' out.txt || fail "test: a failing step"
contains -Fx '    Expected: the call is accepted, and the instance is withdrawn.' out.txt || fail "test: expected"
contains -Fx '  Step 3 (line 22) not run: we withdraw' out.txt || fail "test: stops at the first failure"
contains -Fx "5 tests: 1 passed, 4 failed." out.txt || fail "test: failures counted"
diff "$GOLDENS/test/failing/en.txt" out.txt > /dev/null || fail "test: the golden report"
expect_exit 3 bo test "$GOLDENS/test/failing/source.bo" --json
json 'd["ok"], d["failed"], [t["passed"] for t in d["tests"]]' < out.txt > result.txt
contains -Fx "False 4 [False, False, False, False, True]" result.txt || fail "test --json: failing"
# A source that does not build runs no tests: exit status 2, the problems
# in the reader's language; a test block's own problems come from the checker.
printf 'contract A\nparties we\n\nthing R\n  amount HKD\n\ncan go by we\n  -> active\n\ntest\n  we go\n' > nostart.bo
expect_exit 2 bo test nostart.bo
contains -F "nostart.bo:11:3: error: a test begins by creating its instance" out.txt || fail "test: check.test-start"
contains -Fx "nostart.bo: 1 error: the tests run once the contract builds" out.txt || fail "test: not run"
CEXCHAIN_LANGUAGE=zh-Hant expect_exit 2 bo test nostart.bo
contains -F "測試須以建立實例開始" out.txt || fail "test: the problem in Traditional Chinese"
expect_exit 2 bo test nostart.bo --json
json 'd["ok"], d["built"], "tests" in d, d["diagnostics"][0]["code"]' < out.txt > codes.txt
contains -Fx "False False False check.test-start" codes.txt || fail "test --json: not built"
printf 'use commerce\nuse finance\ncontract A\nparties we\n\nasset R\n  amount HKD\n  holder we\n\ncan refund by we\n' > refund.bo
expect_exit 2 bo test refund.bo
contains -F "(build.standard-action)" out.txt || fail "test: a contract that does not build"
# A file without tests: nothing to run.
printf 'contract A\nparties we\n\ncan go by we\n  -> active\n' > notests.bo
run bo test notests.bo > out.txt
contains -F "This file has no tests" out.txt || fail "test: none"
expect_exit 1 bo test notests.bo --language fr
expect_exit 1 bo test
expect_exit 2 bo test no-such.bo

echo "== contract deploy --bo: two organizations, the customer's ledger on SM3"
D="$WORK/core"; S="$WORK/customer"
d() { run "$@" --ledger "$D"; }
s() { run "$@" --ledger "$S"; }
run key generate --out d-root.key > /dev/null
run key generate --out d-log.key > /dev/null
run key generate --alg sm2-sm3 --out s-root.key > /dev/null
run key generate --alg sm2-sm3 --out s-log.key > /dev/null
run init --org "Core Enterprise" --root-key d-root.key --log-key d-log.key --ledger "$D" > /dev/null
run init --org "Customer" --root-key s-root.key --log-key s-log.key --hash sm3 --ledger "$S" > /dev/null
D_ID="$(d status --json | json 'd["ledger_id"]')"
S_ID="$(s status --json | json 'd["ledger_id"]')"
d peer add customer --ledger-id "$S_ID" > /dev/null
d contract deploy --bo agreement.bo --as d-root.key --json > deploy.json 2> warnings.txt
contains -F "(build.comments)" warnings.txt || fail "deploy warns about comments"
C="$(json 'd["contract"]["id"]' < deploy.json)"
json 'd["contract"]["language"], d["contract"]["compiler"], d["contract"]["name"], d["contract"]["code_hash"], d["build"]["edition"]' < deploy.json > out.txt
contains -Fx "bo $COMPILER Agreement $GOLDEN_HASH 1" out.txt || fail "deploy records the build"
d contract show "$C" > show.txt
contains -Fx "language:   bo (compiler: $COMPILER)" show.txt || fail "show: compiler"
contains -F "            Bo, edition 1: $SOURCE_SIZE bytes of source; packs en 6, zh-Hans-CN 6, zh-Hant-HK 6; vocabulary packs commerce 3" show.txt || fail "show: bundle"
contains -F "rebuild:    rebuilds: the source rebuilds to the deployed code ($GOLDEN_SIZE bytes, SHA-256 ${GOLDEN_HASH:0:16}) with $COMPILER" show.txt || fail "show: rebuild"
d contract show "$C" --json | json 'd["bo"]["status"], d["bo"]["failed"], d["bo"]["edition"], len(d["bo"]["packs"])' > out.txt
contains -Fx "rebuilds False 1 3" out.txt || fail "show --json"
d contract show "$C" --source-out back.bo --bundle-out back.bundle --code-out back.wasm > /dev/null
cmp agreement.bo back.bo || fail "the source as written"
cmp agreement.bundle back.bundle || fail "the bundle"
cmp agreement.wasm back.wasm || fail "the code"
# A .boc built for SM3 deploys here with SHA-256 digests, made again from
# the same packs; it rebuilds here first.
C2="$(d contract deploy --bo agreement-sm3.boc --as d-root.key --json 2> /dev/null | json 'd["contract"]["id"]')"
d contract show "$C2" --bundle-out c2.bundle | contains -F "rebuild:    rebuilds" || fail ".boc deploy"
cmp agreement.bundle c2.bundle || fail ".boc: the bundle under this ledger's hash"
python3 -c "b = bytearray(open('agreement-sm3.boc', 'rb').read()); b[40] ^= 1; open('bad.boc', 'wb').write(b)"
expect_exit 2 contract deploy --bo bad.boc --as d-root.key --ledger "$D"
contains -F "bad.boc" out.txt || fail "a damaged .boc"
expect_exit 1 contract deploy --bo agreement.bo --function create=create --as d-root.key --ledger "$D"
contains -F -- "--bo fills in --function" out.txt || fail "--bo fills in"
expect_exit 1 contract deploy agreement.wasm --bo agreement.bo --as d-root.key --ledger "$D"
expect_exit 1 contract deploy agreement.wasm --function create=create --compiler x --pack company.pack \
    --as d-root.key --ledger "$D"
expect_exit 1 contract deploy --as d-root.key --ledger "$D"
expect_exit 2 contract deploy --bo fragment.bo --as d-root.key --ledger "$D"
contains -F "fragment.bo does not build" out.txt || fail "deploy refuses what does not build"

echo "== the agreement: created, signed through the registrar, verified with the rebuild check"
# Terms of HKD 250,000.00 (below the presence threshold) starting 2030-01-01.
STARTS=1893427200000
CREATE="{\"fields\": {\"amount\": 25000000, \"starts\": $STARTS, \"terms\": \"100 t of steel, monthly\"}, \"parties\": {\"customer\": h'$S_ID', \"we\": h'$D_ID'}}"
d contract create "$C" create --args "$CREATE" --as d-root.key --json > created.json
I="$(json 'd["instance"]["id"]' < created.json)"
FUEL_CREATE="$(json 'd["fuel_used"]' < created.json)"
json 'd["instance"]["status"], d["instance"]["parties"]["customer"] == "'"$S_ID"'"' < created.json > out.txt
contains -Fx "proposed True" out.txt || fail "created"
# Signing is the customer's: the contract asks for its consent.
d contract call "$I" sign --as d-root.key --dry-run --json > dry.json
json 'd["verdict"], d["needs"]' < dry.json > out.txt
contains -Fx "needs ['$S_ID']" out.txt || fail "sign needs the customer"
d contract call "$I" countersign --as d-root.key --dry-run | contains -F "bo:state countersign" || fail "countersign too early"
CEXCHAIN_LANGUAGE=zh-Hant-HK d contract call "$I" countersign --as d-root.key --dry-run |
    contains -F "實例目前的狀態不容許 countersign (bo:state countersign)" || fail "a refusal in the reader's language"
# The home's registrar.
run key generate --out registrar.key > /dev/null
run key public registrar.key --out registrar.pub > /dev/null
REGISTRAR="$(d actor add --as d-root.key --kind device --name "Contract Registrar" \
    --key registrar.pub --json | json 'd["actor"]["id"]')"
d delegation grant --as d-root.key --to "$REGISTRAR" --allow contract-call --contracts "$C" > /dev/null
d token create customer --scope peer --out customer.token > /dev/null
start_server core.json --ledger "$D" --log-key d-log.key --registrar-key registrar.key
D_URL="$(json 'd["url"]' < core.json)"
s peer add core --ledger-id "$D_ID" --url "$D_URL" --token-file customer.token > /dev/null
# The customer proposes signing; the registrar holds it for the customer's consent.
s contract propose "$I" sign --peer core --json > proposed.json
json 'd["status"], d["missing"]' < proposed.json > out.txt
contains -Fx "waiting ['$S_ID']" out.txt || fail "the registrar waits for the customer"
CALL="$(json 'd["call"]' < proposed.json)"
s contract consent --peer core --call "$CALL" --as s-root.key --log-key s-log.key --out sign.cbor > /dev/null
d contract call "$I" sign --consent sign.cbor --as d-root.key --dry-run --json > dry.json
FUEL_SIGN="$(json 'd["fuel_used"]' < dry.json)"
json 'd["verdict"], d["status"]' < dry.json | contains -Fx "accept signed" || fail "sign with the consent"
s contract send sign.cbor --peer core > /dev/null
d contract instance "$I" --json | json 'd["status"], d["calls"][1]["by"]["name"]' > out.txt
contains -Fx "signed Contract Registrar" out.txt || fail "the registrar recorded the signature"
d contract call "$I" countersign --as d-root.key --json > countersigned.json
FUEL_COUNTERSIGN="$(json 'd["fuel_used"]' < countersigned.json)"
json 'd["instance"]["status"]' < countersigned.json | contains -Fx effective || fail "effective"
# Offline: the customer fetches the evidence; anyone verifies it, and the
# code is rebuilt from the source the deploy carries.
s contract fetch --peer core --instance "$I" --out e1.cbor > /dev/null
run contract verify e1.cbor --ledger-id "$D_ID" > verify.txt
contains -F "  Contract     bo, compiled with $COMPILER" verify.txt || fail "verify: the contract"
contains -F "  Status       effective" verify.txt || fail "verify: status"
contains -F "consent of Customer (SM3)" verify.txt || fail "verify: the consent on SM3"
contains -F "  Source       Bo, edition 1: $SOURCE_SIZE bytes of source; packs en 6, zh-Hans-CN 6, zh-Hant-HK 6; vocabulary packs commerce 3" verify.txt || fail "verify: the source"
contains -F "               rebuilds: the source rebuilds to the deployed code ($GOLDEN_SIZE bytes, SHA-256 ${GOLDEN_HASH:0:16})" verify.txt || fail "verify: rebuilds"
contains -F "VERIFICATION FAILED" verify.txt && fail "verify: verified"
run contract verify e1.cbor --ledger-id "$D_ID" --json > verify.json
json 'd["verified"], d["source"]["status"], d["source"]["compiler"] == d["source"]["this_compiler"], d["source"]["bundle_size"]' < verify.json > out.txt
contains -Fx "True rebuilds True $BUNDLE_SIZE" out.txt || fail "verify --json"
run contract verify e1.cbor --ledger-id "$D_ID" --require-rebuild > /dev/null
# Closing, with the customer's consent carried as a file.
HEAD="$(d contract instance "$I" --json | json 'd["head"]')"
s contract consent --home "$D_ID" --hash sha256 --instance "$I" --function close --head "$HEAD" \
    --as s-root.key --log-key s-log.key --out close.cbor > /dev/null
d contract call "$I" close --as d-root.key --dry-run --json | json 'd["verdict"]' | contains -Fx needs || fail "close needs the customer"
d contract call "$I" close --consent close.cbor --as d-root.key --json > closed.json
FUEL_CLOSE="$(json 'd["fuel_used"]' < closed.json)"
json 'd["instance"]["status"], d["instance"]["final"]' < closed.json | contains -Fx "closed True" || fail "closed"
expect_exit 2 contract call "$I" amend --args '{"new_amount": 1, "new_start": 1}' --as d-root.key --ledger "$D"
contains -F "final" out.txt || fail "a final instance takes no calls"
d contract evidence "$I" --log-key d-log.key --out e2.cbor > /dev/null
run contract verify e2.cbor --ledger-id "$D_ID" > verify.txt
contains -F "FINAL: it takes no more calls" verify.txt || fail "verify: final"
contains -F "rebuilds: the source rebuilds" verify.txt || fail "verify: rebuilds once closed"
echo "   module $GOLDEN_SIZE bytes; fuel: create $FUEL_CREATE, sign $FUEL_SIGN (dry run with the consent)," \
    "countersign $FUEL_COUNTERSIGN, close $FUEL_CLOSE"

echo "== contract explain: the text of the code that runs"
# The deployed agreement's text, from the source its deploy carries: the
# same text bo explain writes, in each language.
d contract explain "$C" > explained.txt
contains -F "contract:  $C (Agreement)" explained.txt || fail "contract explain: the contract"
contains -F "rebuild:   rebuilds: the source rebuilds to the deployed code" explained.txt || fail "contract explain: rebuilds"
sed '1,/^$/d' explained.txt > text.txt
diff "$TEXTS/agreement/en.txt" text.txt > /dev/null || fail "contract explain: the text"
for language in zh-Hant-HK zh-Hans-CN; do
    file="$(tr 'A-Z' 'a-z' <<< "$language" | sed 's/-hk$//; s/-cn$//')"
    d contract explain "$C" --language "$language" | sed '1,/^$/d' > text.txt
    diff "$TEXTS/agreement/$file.txt" text.txt > /dev/null || fail "contract explain ($language)"
done
CEXCHAIN_LANGUAGE=zh-Hans d contract explain "${C:0:12}" | sed '1,/^$/d' > text.txt
diff "$TEXTS/agreement/zh-hans.txt" text.txt > /dev/null || fail "contract explain: \$CEXCHAIN_LANGUAGE"
# An instance: its status, parties, and state, then its contract's text.
d contract explain "$I" > explained.txt
contains -F "instance:  $I" explained.txt || fail "contract explain: the instance"
contains -F "status:    closed (final: it takes no more calls)" explained.txt || fail "contract explain: status"
contains -F "customer: customer (" explained.txt || fail "contract explain: parties"
contains -F "we: Core Enterprise (this ledger" explained.txt || fail "contract explain: this ledger"
# Its fields in the text's words: money in HKD, the date at +08:00, the text in quotes.
contains -Fx "state:     closed" explained.txt || fail "contract explain: the state"
contains -Fx 'fields:    terms: "100 t of steel, monthly"' explained.txt || fail "contract explain: a text"
contains -Fx "           amount: HKD 250,000.00" explained.txt || fail "contract explain: money"
contains -Fx "           starts: 1 January 2030" explained.txt || fail "contract explain: a date"
d contract explain "$I" --language zh-Hant-HK > explained-hant.txt
contains -Fx "           金額: 港元 250,000.00" explained-hant.txt || fail "contract explain: money in zh-Hant"
contains -Fx "           starts: 2030年1月1日" explained-hant.txt || fail "contract explain: a date in zh-Hant"
sed '1,/^$/d' explained.txt > text.txt
diff "$TEXTS/agreement/en.txt" text.txt > /dev/null || fail "contract explain INSTANCE: the text"
d contract explain "$I" --json > explained.json
json 'd["explained"], d["source"]["status"], d["instance"]["status"], d["contract"] == "'"$C"'", d["language"], d["text"] == open("'"$TEXTS"'/agreement/en.txt").read()' < explained.json > out.txt
contains -Fx "True rebuilds closed True en True" out.txt || fail "contract explain --json"
json '[(f["field"], f["value"]) for f in d["instance"]["fields"]]' < explained.json > out.txt
contains -Fx "[('terms', '\"100 t of steel, monthly\"'), ('amount', 'HKD 250,000.00'), ('starts', '1 January 2030')]" out.txt || fail "contract explain --json: fields"
expect_exit 1 contract explain "$C" --language fr --ledger "$D"
expect_exit 2 contract explain 00000000 --ledger "$D"

echo "== deploys whose source is not their code"
# Another contract's code with the agreement's source: the same compiler
# builds other code from it, so the source is not the code's.
sed 's/150%/200%/' agreement.bo > other.bo
run bo build other.bo --code-out other.wasm > /dev/null 2>&1
deploy_raw() { # CODE COMPILER SOURCE: a deploy that says it is Bo
    d contract deploy "$1" --function create=create --function amend=call --function sign=call \
        --function countersign=call --function close=call --language bo --compiler "$2" \
        --source "$3" --name Agreement --as d-root.key --json | json 'd["contract"]["id"]'
}
X="$(deploy_raw other.wasm "$COMPILER" agreement.bundle)"
d contract show "$X" > show.txt
contains -F "rebuild:    DOES NOT REBUILD: the source builds to other code (" show.txt || fail "show: differs"
contains -F "with the compiler the deploy names" show.txt || fail "show: differs with this compiler"
d contract show "$X" --json | json 'd["bo"]["status"], d["bo"]["failed"]' | contains -Fx "differs True" || fail "show --json: differs"
# No text for a source that is not the code's: it would not be what runs.
expect_exit 3 contract explain "$X" --ledger "$D"
contains -F "no contract text: its source does not rebuild to its code" out.txt || fail "explain: differs"
contains -F "rebuild:  DOES NOT REBUILD" out.txt || fail "explain: says why"
expect_exit 3 contract explain "$X" --ledger "$D" --json
json 'd["explained"], d["source"]["status"], "text" in d' < out.txt | contains -Fx "False differs False" || fail "explain --json: differs"
J="$(d contract create "$X" create --args "$CREATE" --as d-root.key --json | json 'd["instance"]["id"]')"
d contract evidence "$J" --log-key d-log.key --out x.cbor > /dev/null
expect_exit 3 contract verify x.cbor --ledger-id "$D_ID"
contains -F "DOES NOT REBUILD" out.txt || fail "verify: differs"
contains -Fx "VERIFICATION FAILED: the contract's source does not rebuild to its code" out.txt || fail "verify fails"
expect_exit 3 contract verify x.cbor --ledger-id "$D_ID" --json
json 'd["verified"], d["source"]["status"], d["error"]' < out.txt > result.txt
contains -Fx "False differs the contract's source does not rebuild to its code" result.txt || fail "verify --json: differs"
# The same, said to be built by another codegen version: reported as such,
# not as a forgery.
NEWER="$(sed 's/codegen 3/codegen 4/' <<< "$COMPILER")"
Y="$(deploy_raw other.wasm "$NEWER" agreement.bundle)"
d contract show "$Y" > show.txt
contains -F "rebuild:    not rebuilt: built with $NEWER; this compiler is $COMPILER, and the source builds to other code" show.txt || fail "show: other codegen"
d contract show "$Y" --json | json 'd["bo"]["status"], d["bo"]["failed"]' | contains -Fx "other-compiler False" || fail "show --json: other codegen"
expect_exit 2 contract explain "$Y" --ledger "$D"
contains -F "no contract text: its source was not rebuilt to its code here" out.txt || fail "explain: other codegen"
contains -F "not rebuilt: built with $NEWER" out.txt || fail "explain: names the compiler"
# The agreement's own code, said to be built by another codegen version: the
# bytes are the same, so it rebuilds.
Z="$(deploy_raw agreement.wasm "$NEWER" agreement.bundle)"
d contract show "$Z" | contains -F "rebuild:    rebuilds" || fail "the same bytes rebuild"
# Not a bundle, no source, another compiler's name.
printf 'not a bundle' > junk.bundle
W="$(deploy_raw agreement.wasm "$COMPILER" junk.bundle)"
d contract show "$W" | contains -F "rebuild:    MALFORMED: the deploy's source is not a bo-source bundle" || fail "malformed"
expect_exit 3 contract explain "$W" --ledger "$D"
contains -F "MALFORMED" out.txt || fail "explain: malformed"
d contract explain "$Z" | sed '1,/^$/d' > text.txt
diff "$TEXTS/agreement/en.txt" text.txt > /dev/null || fail "explain: the same bytes, said to be another codegen's, rebuild"
d contract deploy agreement.wasm --function create=create --language bo --compiler "$COMPILER" \
    --as d-root.key --json > nosource.json
d contract show "$(json 'd["contract"]["id"]' < nosource.json)" | contains -F "MALFORMED: a Bo deploy carries its source" || fail "no source"
V="$(deploy_raw other.wasm "acme-bo 2.1" agreement.bundle)"
d contract show "$V" | contains -F "not rebuilt: built with \"acme-bo 2.1\", which is not cexchain-bo" || fail "another compiler"
# A contract not written in Bo: nothing to rebuild, so --require-rebuild fails.
U="$(d contract deploy agreement.wasm --function create=create --function close=call --compiler x \
    --as d-root.key --json | json 'd["contract"]["id"]')"
d contract show "$U" | contains -F "rebuild:" && fail "a wasm contract has no rebuild line"
expect_exit 2 contract explain "$U" --ledger "$D"
contains -F "is written in wasm, not Bo" out.txt || fail "explain: wasm"
K="$(d contract create "$U" create --args "$CREATE" --as d-root.key --json | json 'd["instance"]["id"]')"
d contract evidence "$K" --log-key d-log.key --out u.cbor > /dev/null
run contract verify u.cbor --ledger-id "$D_ID" --json | json '"source" in d, d["verified"]' | contains -Fx "False True" || fail "wasm: no source check"
expect_exit 3 contract verify u.cbor --ledger-id "$D_ID" --require-rebuild
contains -F "not Bo" out.txt || fail "--require-rebuild on wasm"
for fn in d s; do "$fn" audit | contains 'audit passed' || fail "audit"; done

echo "== bo stdlib: the built-in actions, written in Bo"
run bo stdlib list > out.txt
[ "$(wc -l < out.txt)" -eq 21 ] || fail "stdlib list: twenty-one actions"
contains -Fx "pledge           finance   pledge: started by the holder; to a counterparty, who consents; active → pledged" out.txt || fail "stdlib list: pledge"
contains -Fx "pay              finance   pay: started by the home ledger, on its own word; active, pledged, disputed → paid" out.txt || fail "stdlib list: pay"
contains -Fx "unfreeze         finance   unfreeze: started by the home ledger, on its own word; frozen → previous state" out.txt || fail "stdlib list: unfreeze"
contains -Fx "transfer         core      transfer: started by the holder; to a counterparty, who consents; active → active" out.txt || fail "stdlib list: a core action"
run bo stdlib list --language zh-Hant-HK > out.txt
contains -Fx "pledge           finance   質押: 由持有人發起；予相對方，須經其同意；正常 → 已質押" out.txt || fail "stdlib list: zh-Hant"
CEXCHAIN_LANGUAGE=zh-Hans run bo stdlib list --json > list.json
json '[(a["function"], a["word"], a["starter"], a["counterparty"], a["from"], a["to"]) for a in d][8]' < list.json > out.txt
contains -Fx "('redeem', '赎回', 'field.holder', False, ['state.active', 'state.pledged'], ['state.redeemed'])" out.txt || fail "stdlib list --json"
run bo stdlib show pledge > out.txt
contains -Fx "can pledge to counterparty by holder" out.txt || fail "stdlib show: the source"
contains -Fx "use finance" out.txt || fail "stdlib show: the pack's use line"
contains -Fx "  pledgee = counterparty" out.txt || fail "stdlib show: the pledgee"
contains -Fx "The standard terms of pledge:" out.txt || fail "stdlib show: the terms"
contains -Fx "  Started by the holder, whose agreement it needs. [R19]" out.txt || fail "stdlib show: the starter"
contains -Fx "  If the instance is active, it becomes pledged; otherwise the call is refused. [R19]" out.txt || fail "stdlib show: the state change"
run bo stdlib show 質押 --language zh-Hant-HK > out.txt
contains -Fx "使用 finance" out.txt || fail "stdlib show: the use line in zh-Hant"
contains -Fx "可質押 予 相對方 由 持有人" out.txt || fail "stdlib show: zh-Hant source"
contains -Fx "  須經相對方同意；每次調用均須指明其賬本（參數 counterparty）。〔R21〕" out.txt || fail "stdlib show: zh-Hant terms"
run bo stdlib show confirm_payment --json > show.json
json 'd["function"], d["pack"], d["action"], d["source"], [c["rules"] for c in d["terms"]][0]' < show.json > out.txt
contains -F "confirm_payment finance act.confirm_payment can confirm payment by payee" out.txt || fail "stdlib show --json"
expect_exit 1 bo stdlib show refund
contains -F "no built-in action refund" out.txt || fail "stdlib show: no terms"
expect_exit 1 bo stdlib show
expect_exit 1 bo stdlib list --language fr
# A built-in action copied under a name of the contract's own, and changed:
# the contract's own action, built like any other.
{ printf 'use finance\ncontract Lodging\nparties issuer, supplier\n\nasset Receivable\n  amount HKD\n  holder supplier\n\n'
  run bo stdlib show pledge --json | json 'd["source"].replace("can pledge", "can lodge", 1)'
  printf '  requires in person\n\ntest\n  issuer issue with amount = HKD 10\n'
  printf '  supplier lodge to bank1 -> refused "bo:in-person lodge"\n'
  printf '  supplier lodge to bank1 in person -> pledged\n'; } > lodging.bo
run bo check lodging.bo --stage model > out.txt
contains -F "can lodge own by=field.holder to=role.counterparty{R21}" out.txt || fail "the copy is the contract's own"
run bo test lodging.bo | contains -Fx "1 test: 1 passed, 0 failed." || fail "the copy runs"

echo "== the standard library: a receivable through four ledgers"
# The issuer's ledger is the receivable's home; the supplier holds it; the
# bank lends against it; a factor buys it. The bank's ledger is on SM3.
cat > receivable.bo <<'EOF'
use finance
contract ReceivableFinancing
parties issuer, supplier, bank

asset Receivable
  amount HKD
  due date
  holder supplier

can pledge to bank
  over 5_000_000 requires in person
can release
can transfer
can pay
can confirm payment
when due issuer pays
EOF
run bo test receivable.bo | contains -F "This file has no tests" || fail "receivable: no tests"
H="$WORK/issuer"; P="$WORK/supplier"; B="$WORK/bank"; F="$WORK/factor"
h() { run "$@" --ledger "$H"; }
for org in issuer supplier factor; do
    run key generate --out "$org-root.key" > /dev/null
    run key generate --out "$org-log.key" > /dev/null
done
run key generate --alg sm2-sm3 --out bank-root.key > /dev/null
run key generate --alg sm2-sm3 --out bank-log.key > /dev/null
run init --org "Issuer" --root-key issuer-root.key --log-key issuer-log.key --ledger "$H" > /dev/null
run init --org "Supplier" --root-key supplier-root.key --log-key supplier-log.key --ledger "$P" > /dev/null
run init --org "Bank" --root-key bank-root.key --log-key bank-log.key --hash sm3 --ledger "$B" > /dev/null
run init --org "Factor" --root-key factor-root.key --log-key factor-log.key --ledger "$F" > /dev/null
H_ID="$(h status --json | json 'd["ledger_id"]')"
P_ID="$(run status --ledger "$P" --json | json 'd["ledger_id"]')"
B_ID="$(run status --ledger "$B" --json | json 'd["ledger_id"]')"
F_ID="$(run status --ledger "$F" --json | json 'd["ledger_id"]')"
RC="$(h contract deploy --bo receivable.bo --as issuer-root.key --json 2> /dev/null | json 'd["contract"]["id"]')"
h contract show "$RC" | contains -F "rebuild:    rebuilds" || fail "receivable: deployed"
# HKD 3,000,000.00, due on 30 June 2027 (+08:00).
DUE="$(python3 -c 'import datetime as t; print(int(t.datetime(2027, 6, 30, tzinfo=t.timezone(t.timedelta(hours=8))).timestamp() * 1000))')"
RI="$(h contract create "$RC" issue --args "{\"fields\": {\"amount\": 300000000, \"due\": $DUE}, \"parties\": {\"issuer\": h'$H_ID', \"supplier\": h'$P_ID'}}" \
    --as issuer-root.key --json | json 'd["instance"]["id"]')"
h contract instance "$RI" --json | json 'd["status"], sorted(d["parties"])' | contains -Fx "active ['holder', 'issuer', 'supplier']" || fail "receivable: issued"
run key generate --out issuer-registrar.key > /dev/null
run key public issuer-registrar.key --out issuer-registrar.pub > /dev/null
RR="$(h actor add --as issuer-root.key --kind device --name "Registrar" --key issuer-registrar.pub --json | json 'd["actor"]["id"]')"
h delegation grant --as issuer-root.key --to "$RR" --allow contract-call --contracts "$RC" > /dev/null
dir_of() { case "$1" in supplier) echo "$P" ;; bank) echo "$B" ;; factor) echo "$F" ;; esac; }
id_of() { case "$1" in supplier) echo "$P_ID" ;; bank) echo "$B_ID" ;; factor) echo "$F_ID" ;; esac; }
for org in supplier bank factor; do
    h peer add "$org" --ledger-id "$(id_of "$org")" > /dev/null
    h token create "$org" --scope peer --out "$org.token" > /dev/null
done
start_server issuer.json --ledger "$H" --log-key issuer-log.key --registrar-key issuer-registrar.key
H_URL="$(json 'd["url"]' < issuer.json)"
for org in supplier bank factor; do
    run peer add issuer --ledger-id "$H_ID" --url "$H_URL" --token-file "$org.token" --ledger "$(dir_of "$org")" > /dev/null
done
# org CALL: the organization consents to the held call, on its own ledger, and sends it.
consent_to() {
    local org="$1" call="$2"
    run contract consent --peer issuer --call "$call" --as "$org-root.key" --log-key "$org-log.key" \
        --out "$org-$call.cbor" --ledger "$(dir_of "$org")" > /dev/null
    run contract send "$org-$call.cbor" --peer issuer --ledger "$(dir_of "$org")" > /dev/null
}
status_of() { h contract instance "$RI" --json | json 'd["status"]'; }
# The supplier pledges it to its bank: the registrar waits for both consents.
run contract propose "$RI" pledge --args "{\"bank\": h'$B_ID'}" --peer issuer --ledger "$P" --json > proposed.json
json 'd["status"], sorted(d["missing"]) == sorted(["'"$P_ID"'", "'"$B_ID"'"])' < proposed.json | contains -Fx "waiting True" || fail "pledge: both consents"
CALL="$(json 'd["call"]' < proposed.json)"
consent_to supplier "$CALL"
[ "$(status_of)" = active ] || fail "pledge: not without the bank"
consent_to bank "$CALL"
[ "$(status_of)" = pledged ] || fail "pledge: recorded"
h contract instance "$RI" --json | json 'd["parties"]["pledgee"] == "'"$B_ID"'", d["parties"]["bank"] == "'"$B_ID"'"' | contains -Fx "True True" || fail "pledge: the pledgee"
# No second pledge, and no transfer while pledged.
h contract call "$RI" pledge --args "{\"bank\": h'$B_ID'}" --as issuer-root.key --dry-run | contains -F "bo:state pledge" || fail "no second pledge"
h contract call "$RI" transfer --args "{\"counterparty\": h'$F_ID'}" --as issuer-root.key --dry-run | contains -F "bo:state transfer" || fail "no transfer while pledged"
# The bank releases its pledge.
CALL="$(run contract propose "$RI" release --peer issuer --ledger "$B" --json | json 'd["call"]')"
consent_to bank "$CALL"
[ "$(status_of)" = active ] || fail "release"
h contract instance "$RI" --json | json '"pledgee" in d["parties"]' | contains -Fx False || fail "release: no pledgee"
# The supplier sells it to the factor: both consent.
CALL="$(run contract propose "$RI" transfer --args "{\"counterparty\": h'$F_ID'}" --peer issuer --ledger "$P" --json | json 'd["call"]')"
consent_to supplier "$CALL"
consent_to factor "$CALL"
h contract instance "$RI" --json | json 'd["status"], d["parties"]["holder"] == "'"$F_ID"'"' | contains -Fx "active True" || fail "transfer: the factor holds it"
# The issuer pays, on its own word; the factor, the payee, confirms.
h contract call "$RI" pay --as issuer-root.key --json | json 'd["instance"]["status"], d["instance"]["parties"]["payee"] == "'"$F_ID"'"' | contains -Fx "paid True" || fail "pay: to the holder"
CALL="$(run contract propose "$RI" confirm_payment --peer issuer --ledger "$F" --json | json 'd["call"]')"
consent_to factor "$CALL"
[ "$(status_of)" = settled ] || fail "confirm payment"
# The factor verifies the whole history offline: the code rebuilds from its source.
run contract fetch --peer issuer --instance "$RI" --out receivable.cbor --ledger "$F" > /dev/null
run contract verify receivable.cbor --ledger-id "$H_ID" > verify.txt
contains -F "  Status       settled" verify.txt || fail "verify: settled"
contains -F "FINAL: it takes no more calls" verify.txt || fail "verify: final"
contains -F "rebuilds: the source rebuilds to the deployed code" verify.txt || fail "verify: rebuilds"
contains -F "VERIFICATION FAILED" verify.txt && fail "verify: verified"
run contract explain "$RC" --ledger "$H" | contains -F "4.1.5 Requirement 2: the bank is not the holder. [R19]" || fail "explain: the standard terms"
for dir in "$H" "$P" "$B" "$F"; do run audit --ledger "$dir" | contains 'audit passed' || fail "audit"; done

echo "== splitting: parts through the registrar, a recipient that is no party yet"
# The standard library's split (milestone 17): the supplier splits a
# receivable, keeping a part and passing one to the factor, which is no
# party of this contract yet: it sees the held call (it is asked for its
# consent) and consents on its own ledger. Each part is an instance of its
# own, one tier down; the factor verifies its part offline, ancestors
# included, and the contract's code rebuilds from its source.
cat > split.bo <<'EOF'
use finance
contract Split
parties issuer, supplier

asset Receivable
  amount HKD
  due date
  tier number
  holder supplier

can split
  requires tier < 5
can pledge
can pay
when due issuer pays
EOF
SC="$(h contract deploy --bo split.bo --as issuer-root.key --json 2> /dev/null | json 'd["contract"]["id"]')"
h delegation grant --as issuer-root.key --to "$RR" --allow contract-call --contracts "$SC" > /dev/null
SI="$(h contract create "$SC" issue --args "{\"fields\": {\"amount\": 300000000, \"due\": $DUE, \"tier\": 1}, \"parties\": {\"issuer\": h'$H_ID', \"supplier\": h'$P_ID'}}" \
    --as issuer-root.key --json | json 'd["instance"]["id"]')"
# Parts that do not add up are refused with the contract's reason.
h contract call "$SI" split --args "{\"parts\": [180000000, 100000000], \"recipients\": [h'$F_ID', h'$P_ID']}" \
    --as issuer-root.key --dry-run | contains -F "bo:requires split 5" || fail "split: the parts add up"
PARTS="{\"parts\": [180000000, 120000000], \"recipients\": [h'$F_ID', h'$P_ID']}"
run contract propose "$SI" split --args "$PARTS" --peer issuer --ledger "$P" --json > split.json
json 'd["status"], sorted(d["missing"]) == sorted(["'"$P_ID"'", "'"$F_ID"'"])' < split.json | contains -Fx "waiting True" || fail "split: the holder and the recipient"
CALL="$(json 'd["call"]' < split.json)"
# The factor sees the call it is asked to consent to, and consents.
run contract pending --peer issuer --ledger "$F" --json | json '[c["call"] for c in d]' | contains -F "$CALL" || fail "split: the recipient sees the call"
consent_to supplier "$CALL"
[ "$(h contract instance "$SI" --json | json 'd["status"]')" = active ] || fail "split: not without the recipient"
consent_to factor "$CALL"
h contract instance "$SI" --json | json 'd["status"], d["final"], len(d["children"])' | contains -Fx "divided True 2" || fail "split: divided"
SP1="$(h contract instances --parent "$SI" --json | json 'd[0]["id"]')"
SP2="$(h contract instances --parent "$SI" --json | json 'd[1]["id"]')"
# A part's state is the contract's, in diagnostic notation: its amount, its tier.
h contract instance "$SP1" --json | json 'd["depth"], "\"amount\": 180000000" in d["state"], "\"tier\": 2" in d["state"], d["parties"]["holder"] == "'"$F_ID"'"' \
    | contains -Fx "1 True True True" || fail "split: the factor's part"
h contract instance "$SP2" --json | json '"\"amount\": 120000000" in d["state"], d["parties"]["holder"] == "'"$P_ID"'"' \
    | contains -Fx "True True" || fail "split: the part kept"
# The factor fetches its part and verifies it offline.
run contract fetch --peer issuer --instance "$SP1" --out part.cbor --ledger "$F" > /dev/null
run contract verify part.cbor --ledger-id "$H_ID" > part.txt
contains -F "Part of      ${SI:0:12}" part.txt || fail "verify: part of"
contains -F "rebuilds: the source rebuilds to the deployed code" part.txt || fail "verify: rebuilds"
contains -F "consent of Factor (SHA-256)" part.txt || fail "verify: the recipient's consent"
contains -F "consent of Supplier (SHA-256)" part.txt || fail "verify: the holder's consent"
contains -F "VERIFICATION FAILED" part.txt && fail "verify: verified"
# The part's contract text says what a part is.
h contract explain "$SP1" | contains -F "Each of the parts becomes an instance of this contract of its own" || fail "explain: parts"
h contract explain "$SP1" --language zh-Hans-CN | contains -F "各部分中的每一部分各自成为本合约的一个实例" || fail "explain: parts, zh-Hans"
# bo test names the part each step acts on, and counts the parts a call made.
run bo test "$GOLDENS/test/split/source.bo" --json > split-test.json
json 'd["passed"], [s["part"] for s in d["tests"][0]["steps"]][:5], d["tests"][0]["steps"][1]["result"]["parts"]' < split-test.json \
    | contains -Fx "6 [None, None, '1', '1.1', '1.2'] 2" || fail "bo test --json: parts"
run bo test "$GOLDENS/test/split/source.bo" --language zh-Hant-HK | contains -F "處理部分 1.1。" || fail "bo test: parts, zh-Hant"
# A part splits again, one tier down; at tier 5 the contract's own rule refuses.
h contract call "$SP2" split --args "{\"parts\": [120000000], \"recipients\": [h'$P_ID']}" --as issuer-root.key --dry-run \
    | contains -F "consent of" || fail "split again: the holder's consent"
for dir in "$H" "$P" "$B" "$F"; do run audit --ledger "$dir" | contains 'audit passed' || fail "audit"; done

echo "== time rules: functions a keeper calls once their time has come"
# The spec's "3 days overdue, suspend": its tests, its code, and its text.
cp "$GOLDENS/test/time/source.bo" hosting.bo
run bo test hosting.bo > out.txt
contains -Fx "5 tests: 5 passed, 0 failed." out.txt || fail "time: the tests"
contains -F "Result: refused, since when.suspend does not apply yet: its time has not come, or its conditions do not hold (bo:when when.suspend)." out.txt || fail "time: refused before its time"
contains -F "The contract text, 5.2: When the instance is 3 days overdue or more (counted from its due date):" out.txt || fail "time: the rule's clause"
run bo test hosting.bo --json | json '[e for t in d["tests"] for s in t["steps"] for e in s["result"].get("events", []) if e.startswith("when:")]' > out.txt
contains -F "'when:when.suspend late=604800000'" out.txt || fail "time: how late the keeper came"
CEXCHAIN_LANGUAGE=zh-Hant-HK run bo test hosting.bo | contains -F "when.suspend 尚未適用：其時間未到，或其條件不成立（bo:when when.suspend）" || fail "time: zh-Hant"
run bo build hosting.bo | contains -F "functions  create (creates), extend, reopen, settle, when.suspend, when.terminate" || fail "time: the functions"
run bo explain hosting.bo > text.txt
diff "$TEXTS/time/en.txt" text.txt > /dev/null || fail "time: the text"
contains -Fx "  5.2.1 Function when.suspend: a keeper calls it once this time has come. An earlier call is refused; the rule applies once for each such time, and its event records how late the call came. [R24]" text.txt || fail "time: the keeper's clause"
run bo explain hosting.bo --language zh-Hans-CN | contains -F "函数 when.suspend：时间一到，调度器就会调用。" || fail "time: zh-Hans"
for language in zh-Hant-HK zh-Hans-CN; do
    run bo fmt hosting.bo --language "$language" > hosting-other.bo
    run bo test hosting-other.bo | contains -Fx "5 tests: 5 passed, 0 failed." || fail "time: tests in $language"
done
# The spec's IP pool: it builds, explains, and its tests pass. Nothing yet
# stops one address being in two instances (unique keys come later).
cp "$GOLDENS/test/ip-pool/source.bo" pool.bo
run bo test pool.bo | contains -Fx "3 tests: 3 passed, 0 failed." || fail "pool: the tests"
run bo build pool.bo | contains -F "functions  allocate, create (creates), reclaim" || fail "pool: the functions"
run bo explain pool.bo --language zh-Hans-CN > out.txt
contains -Fx "1.2 客户：由每次分配确定账本，并须经客户同意。〔R3、R23〕" out.txt || fail "pool: R23"
contains -Fx "    4.1.4.1 要求 1：实例上次转换状态至今已满冷却期。〔R19〕" out.txt || fail "pool: the cooling period"
# Errors in the reader's language.
printf 'contract T\nparties we\nthing R\n  due date\n  UTC offset "8"\nwhen due\n  -> closed\n\ntest\n  we create with due = 2027-01-01\n  keeper fly\n' > time-errors.bo
expect_exit 2 bo check time-errors.bo
contains -F "(check.utc-offset)" out.txt || fail "errors: the offset"
contains -F "no when rule does fly" out.txt || fail "errors: the keeper's step"

echo "== a keeper, end to end: a device whose delegation names only the contract"
K="$WORK/hosting"
k() { run "$@" --ledger "$K"; }
run key generate --out k-root.key > /dev/null
run key generate --out k-log.key > /dev/null
run init --org "Hosting Company" --root-key k-root.key --log-key k-log.key --ledger "$K" > /dev/null
K_ID="$(k status --json | json 'd["ledger_id"]')"
KC="$(k contract deploy --bo hosting.bo --as k-root.key --json 2> /dev/null | json 'd["contract"]["id"]')"
# Due on 1 March 2026 (+08:00), long past: 3 days later it is suspended.
DUE="$(python3 -c 'import datetime as t; print(int(t.datetime(2026, 3, 1, tzinfo=t.timezone(t.timedelta(hours=8))).timestamp() * 1000))')"
CUSTOMER="$(python3 -c 'print("c5" * 32)')"
create_hosting() {
    k contract create "$1" create --args "{\"fields\": {\"due\": $DUE}, \"parties\": {\"customer\": h'$CUSTOMER', \"we\": h'$K_ID'}}" \
        --as k-root.key --json | json 'd["instance"]["id"]'
}
KI="$(create_hosting "$KC")"
# Before its time, a dry run says so; --at asks when the rule applies.
k contract call "$KI" when.suspend --as k-root.key --dry-run --at 2026-03-03 | contains -F "(bo:when when.suspend)" || fail "keeper: refused before its time"
k contract call "$KI" when.suspend --as k-root.key --dry-run --at 2026-03-04 --json > dry.json
json 'd["verdict"], d["status"], d["events"][0]["name"], d["events"][0]["data"]' < dry.json > out.txt
contains -Fx "accept suspended when {\"late\": 28800000, \"rule\": \"when.suspend\", \"time\": 1772553600000}" out.txt || fail "keeper: --at"
expect_exit 1 contract call "$KI" when.suspend --as k-root.key --at 2026-03-04 --ledger "$K"
contains -F -- "--at needs --dry-run" out.txt || fail "keeper: --at without --dry-run"
run contract call --help | contains -F "with --dry-run --at TIME" || fail "keeper: help"
# The keeper: a device whose delegation covers this contract's time rules
# only (scope keys 7 and 8, no key 9). keeper due finds what is due by dry
# runs; keeper run calls it. A rule whose time has not come is refused, and
# nothing is recorded.
KEEPER="$(k keeper add Keeper --contracts "$KC" --key-out keeper.key --as k-root.key --json | json 'd["actor"]["id"]')"
k keeper show "$KEEPER" --json | json '",".join(d["functions"])' | contains -Fx "when.suspend,when.terminate" || fail "keeper: the time rules"
HEAD_BEFORE="$(k contract instance "$KI" --json | json 'd["head"]')"
expect_exit 2 contract call "$KI" when.terminate --as keeper.key --ledger "$K"
contains -F "(bo:when when.terminate)" out.txt || fail "keeper: terminate is not due"
[ "$(k contract instance "$KI" --json | json 'd["head"]')" = "$HEAD_BEFORE" ] || fail "keeper: nothing recorded"
k keeper due --keeper "$KEEPER" --json | json '[r["function"] for r in d["rules"]]' | contains -Fx "['when.suspend']" || fail "keeper: due"
k keeper run --as keeper.key > out.txt
contains -F "fired when.suspend on ${KI:0:12}" out.txt || fail "keeper: run"
k contract instance "$KI" --json | json 'd["status"]' | contains -Fx suspended || fail "keeper: suspended"
k contract instance "$KI" --json | json 'd["calls"][-1]["function"], d["calls"][-1]["by"]["name"]' | contains -Fx "when.suspend Keeper" || fail "keeper: its call"
k keeper run --as keeper.key | contains -F "nothing due" || fail "keeper: nothing more due"
expect_exit 2 contract call "$KI" when.suspend --as keeper.key --ledger "$K"
contains -F "(bo:fired when.suspend)" out.txt || fail "keeper: once for each time"
# Its delegation names this contract only: another contract's rules are not its to call.
KC2="$(k contract deploy --bo hosting.bo --as k-root.key --json 2> /dev/null | json 'd["contract"]["id"]')"
KI2="$(create_hosting "$KC2")"
expect_exit 2 contract call "$KI2" when.suspend --as keeper.key --ledger "$K"
contains -iF "delegation" out.txt || fail "keeper: scope key 7"
# Offline: the evidence shows the keeper's call, its event, and the code rebuilt.
k contract evidence "$KI" --log-key k-log.key --out hosting.cbor > /dev/null
run contract verify hosting.cbor --ledger-id "$K_ID" > verify.txt
contains -F "  Status       suspended" verify.txt || fail "keeper: verify status"
contains -F "when.suspend" verify.txt || fail "keeper: verify the call"
contains -F "rebuilds: the source rebuilds to the deployed code" verify.txt || fail "keeper: verify rebuilds"
contains -F "VERIFICATION FAILED" verify.txt && fail "keeper: verified"
run audit --ledger "$K" | contains 'audit passed' || fail "keeper: audit"

echo "== lists and charges: bills computed on a document's lines"
# The spec's VAT in a whole contract (bo-1.0, section 7): its tests on both
# sides of the rate change, its code, and its text in three languages.
cp "$GOLDENS/test/tax/source.bo" tax.bo
run bo test tax.bo > out.txt
contains -Fx "6 tests: 6 passed, 0 failed." out.txt || fail "tax: the tests"
run bo test tax.bo --json | json '[e for t in d["tests"] for s in t["steps"] for e in s["result"].get("events", [])].count("invoice")' > out.txt
contains -Fx "8" out.txt || fail "tax: the bills made"
run bo build tax.bo > out.txt 2> /dev/null
contains -F "functions  create (creates), 结算, 重开" out.txt || fail "tax: the functions"
TAX_HASH="$(run bo build tax.bo --json 2> /dev/null | json 'd["code_hash"]')"
run bo explain tax.bo > out.txt
contains -F "3.1 The charges below are computed on invoice, the lines of a bill, each time it is set" out.txt || fail "tax: the bill's clause"
contains -Fx "  3.2.5 From 1 January 2027, its rate is 9%. [R28]" out.txt || fail "tax: the rate change"
contains -F "[R27] Charges are computed in the order written" out.txt || fail "tax: R27"
run bo explain tax.bo --language zh-Hant-HK | contains -F "以下費用按發票（單據的各行）計算" || fail "tax: zh-Hant"
run bo explain tax.bo --language zh-Hans-CN | contains -Fx "  3.2.5 自 2027年1月1日起，比率为 9%。〔R28〕" || fail "tax: zh-Hans"
for language in en zh-Hant-HK; do
    run bo fmt tax.bo --language "$language" > tax-other.bo
    run bo test tax-other.bo | contains -Fx "6 tests: 6 passed, 0 failed." || fail "tax: tests in $language"
    [ "$(run bo build tax-other.bo --json 2> /dev/null | json 'd["code_hash"]')" = "$TAX_HASH" ] || fail "tax: the code in $language"
done
# Every kind of charge on one bill; lists.
cp "$GOLDENS/test/charges/source.bo" dinner.bo
run bo test dinner.bo | contains -Fx "3 tests: 3 passed, 0 failed." || fail "charges: the tests"
run bo explain dinner.bo | contains -Fx "  3.4.3 It is computed on the price and gratuity. [R27]" || fail "charges: on a charge"
cp "$GOLDENS/test/lists/source.bo" lists.bo
run bo test lists.bo | contains -Fx "2 tests: 2 passed, 0 failed." || fail "lists: the tests"
run bo build lists.bo 2> /dev/null | contains -F "functions  check, create (creates), load, mark" || fail "lists: the functions"
# Errors, in the reader's language.
cp "$GOLDENS/check-error-bills/source.bo" bills-errors.bo
expect_exit 2 bo check bills-errors.bo
contains -F "Fee is a fixed amount, which is never rounded: give it no rounding mode (check.charge-rounding)" out.txt || fail "errors: a fixed amount"
contains -F "(check.charge-on)" out.txt || fail "errors: on a charge"
CEXCHAIN_LANGUAGE=zh-Hant-HK "$CEXCHAIN" bo check bills-errors.bo > out.txt 2>&1 || true
contains -F "Fee 是定額，不會捨入：請勿為其寫捨入方式" out.txt || fail "errors: zh-Hant"
printf 'contract L\nparties we\nthing R\n  names list text\ncan go by we\n  each n in names\n    active -> gone\n' > each-errors.bo
expect_exit 2 bo check each-errors.bo
contains -F "(check.each-body)" out.txt || fail "errors: a state change in each"

echo "== a bill on a ledger: the rate in force when it is made, kept"
SHOP="$WORK/shop"
sh_() { run "$@" --ledger "$SHOP"; }
run key generate --out sale-root.key > /dev/null
run key generate --out sale-log.key > /dev/null
run init --org "Shop" --root-key sale-root.key --log-key sale-log.key --ledger "$SHOP" > /dev/null
SHOP_ID="$(sh_ status --json | json 'd["ledger_id"]')"
SC="$(sh_ contract deploy --bo tax.bo --as sale-root.key --json 2> /dev/null | json 'd["contract"]["id"]')"
BUYER="$(python3 -c 'print("b7" * 32)')"
SALE_ARGS="{\"fields\": {\"customer_location\": \"中国内地\", \"invoice\": [10000, 1005]}, \"parties\": {\"customer\": h'$BUYER', \"we\": h'$SHOP_ID'}}"
# A dry run dated 2027 bills at 9%; made now (2026), the bill is at 6%.
sh_ contract create "$SC" create --args "$SALE_ARGS" --as sale-root.key --dry-run --at 2027-01-02 --json > dry.json
json 'd["events"][1]["name"], d["events"][1]["data"]' < dry.json > out.txt
contains -F 'invoice {"time": 1798848000000, "price": 11005, "total": 11995, "charges": {"增值税": {"rate": 90000, "amount": 990}}}' out.txt || fail "bill: at 9% in 2027"
SI="$(sh_ contract create "$SC" create --args "$SALE_ARGS" --as sale-root.key --json | json 'd["instance"]["id"]')"
sh_ contract instance "$SI" --json | json 'd["state"]' > out.txt
contains -F '"price": 11005, "total": 11665, "charges": {"增值税": {"rate": 60000, "amount": 660}}' out.txt || fail "bill: kept at 6%"
sh_ contract explain "$SI" > out.txt
contains -F "invoice: (CNY 100.00, CNY 10.05)" out.txt || fail "bill: the instance's lines in its text"
# Settled with the bill's total: the customer's consent, through the registrar.
sh_ contract call "$SI" 结算 --args '{"付款": 11666}' --as sale-root.key --dry-run --at 2027-03-01 | contains -F "(bo:requires 结算 1)" || fail "bill: a wrong payment"
sh_ contract call "$SI" 结算 --args '{"付款": 11665}' --as sale-root.key --dry-run --at 2027-03-01 --json | json 'd["verdict"]' | contains -Fx needs || fail "bill: the old bill's total, in 2027"
# Offline: the evidence verifies, and the source rebuilds.
sh_ contract evidence "$SI" --log-key sale-log.key --out sale.cbor > /dev/null
run contract verify sale.cbor --ledger-id "$SHOP_ID" > verify.txt
contains -F "rebuilds: the source rebuilds to the deployed code" verify.txt || fail "bill: verify rebuilds"
contains -F "VERIFICATION FAILED" verify.txt && fail "bill: verified"

echo "== measures (G5b): durations divided, defaults, temperatures, negatives, field tests"
cp "$GOLDENS/test/measures/source.bo" measures.bo
run bo test measures.bo > report.txt
contains -Fx "6 tests: 6 passed, 0 failed." report.txt || fail "measures: the tests"
run bo explain measures.bo > text.txt
contains -F "It sets days_late to (the time of the call − the due date) ÷ 1 day, in whole times (the rest dropped). [R32]" text.txt || fail "measures: R32's clause"
contains -F "[R32] A duration divided by a duration is the number of whole times" text.txt || fail "measures: R32's text"
contains -Fx "2.5 fee: money in HKD; each instance starts with HKD 0 unless its creation gives another." text.txt || fail "measures: a default"
contains -Fx "2.6 lowest: -2.5 °C, the same for every instance." text.txt || fail "measures: a temperature below zero"
run bo explain measures.bo --language zh-Hant-HK | contains -F "÷ 1 日（按完整倍數計算，餘數捨去）。〔R32〕" || fail "measures: R32 in zh-Hant"
run bo fmt measures.bo --language zh-Hans-CN > fmt.txt
contains -Fx "  lowest -2.5 °C" fmt.txt || fail "measures: fmt keeps °C and the sign"
contains -Fx "  fee 港元 = 港元 0" fmt.txt || fail "measures: fmt writes the default"
run bo check measures.bo --stage model | contains -F "field coldest instance quantity temperature default (quantity unit.celsius 100)" || fail "measures: the model"
# A step expecting other values fails, and says both sides.
sed 's/days_late = 13, fee = HKD 26_000/days_late = 13, fee = HKD 5_000/' measures.bo > wrong.bo
expect_exit 3 bo test wrong.bo
contains -F "Expected: the call is accepted, and the instance is delivered; then days_late is 13 and fee is HKD 5,000.00." out.txt || fail "measures: the expected values"
contains -F "but fee is HKD 26,000.00." out.txt || fail "measures: the values held"
"$CEXCHAIN" bo test wrong.bo --json > wrong.json || true
json '[(s["expected"].get("fields"), s["result"].get("differing")) for t in d["tests"] for s in t["steps"] if s["status"] == "failed"]' < wrong.json > out.txt
contains -F "[({'days_late': 13, 'fee': 500000}, {'fee': 2600000})]" out.txt || fail "measures: --json gives the values"
# A default needs an instance field and a value written out.
printf 'contract C\nparties we\nthing T\n  lowest 2 °C = 3 °C\n  count number = 1 + 1\n' > defaults.bo
CEXCHAIN_LANGUAGE=zh-Hans expect_exit 2 bo check defaults.bo
contains -F "lowest 不能设默认值" out.txt || fail "measures: check.default-field in zh-Hans"
contains -F "(check.default-value)" out.txt || fail "measures: check.default-value"

echo "== requests (E8): request KIND ... within N, and when KIND done, fails, or expires"
cp "$GOLDENS/check-requests/source.bo" requests.bo
run bo test requests.bo > report.txt
contains -Fx "3 tests: 3 passed, 0 failed." report.txt || fail "requests: the tests"
contains -F "Requests made: notify, to be answered by 2027-03-09." report.txt || fail "requests: a request made"
contains -F "refused by the ledger: the request notify expires only at 2027-03-09." report.txt || fail "requests: an early expiry"
contains -F "refused by the ledger: the instance has no open request notify." report.txt || fail "requests: no request"
CEXCHAIN_LANGUAGE=zh-Hant run bo test requests.bo | contains -F "發出的請求：通知，須於 2027-03-09 前答覆。" || fail "requests: the report in zh-Hant"
run bo test requests.bo --json > tests.json
json 'd["tests"][0]["steps"][1]["result"]["requests"], d["tests"][0]["steps"][2]["answer"], d["tests"][0]["steps"][2]["result"]["events"]' < tests.json > out.txt
contains -Fx "[{'kind': 'notify', 'deadline': 1804521600000}] {'kind': 'notify', 'outcome': 'done'} ['answer:notify:done']" out.txt || fail "requests: test --json"
json 'd["tests"][2]["steps"][3]["result"]["outcome"], d["tests"][2]["steps"][3]["result"]["deadline"]' < tests.json > out.txt
contains -Fx "early 1804521600000" out.txt || fail "requests: an early expiry in --json"
# The reply function is in the interface; the text states each request,
# its deadline, and what happens if it fails.
run bo build requests.bo > out.txt
contains -F "functions  close, create (creates), deliver, result, when.remind" out.txt || fail "requests: the interface"
run bo explain requests.bo > text.txt
contains -F "It asks an executor for notify for consignee, outside the ledger, to be answered within 1 day of the call (its deadline)." text.txt || fail "requests: the request's clause"
contains -F "If it fails, or expires, the rule for a failed notify applies (see the answers to requests). [R33]" text.txt || fail "requests: on failure"
contains -F "If it expires, the rule for an expired remind applies (see the answers to requests); if it fails, nothing more happens" text.txt || fail "requests: on expiry only"
contains -Fx "6. Answers to requests" text.txt || fail "requests: the section"
contains -F "When a request notify fails, or expires: [R33]" text.txt || fail "requests: the rule for failures"
contains -F "It sets note to the answer's reason." text.txt || fail "requests: the answer's reason"
run bo explain requests.bo --language zh-Hans-CN | contains -F "向执行器请求通知（对象：consignee），在账本之外办理，须在调用后 1 天内答复（即其期限）。" || fail "requests: the text in zh-Hans"
# One tree in three languages: done, result, and reason stay names
# elsewhere (the state done).
for language in zh-Hant-HK zh-Hans-CN; do
    run bo fmt requests.bo --language "$language" > "requests-$language.bo"
    run bo test "requests-$language.bo" | contains -Fx "3 tests: 3 passed, 0 failed." || fail "requests: tests in $language"
done
run bo fmt requests-zh-Hant-HK.bo --language en > back.bo
diff <(grep -v '^#' requests.bo) <(grep -v '^#' back.bo) > /dev/null || fail "requests: fmt round trip"
contains -Fx "  delivered -> done" back.bo || fail "requests: done stays a state's name"
# What a request may not be.
cp "$GOLDENS/check-error-requests/source.bo" bad-requests.bo
expect_exit 2 bo check bad-requests.bo
for code in request-kind request-within request-value request-count answer-twice answer-unasked answer-line test-answer; do
    contains -F "(check.$code)" out.txt || fail "requests: check.$code"
done
CEXCHAIN_LANGUAGE=zh-Hant expect_exit 2 bo check bad-requests.bo
contains -F "答覆永不被拒絕" out.txt || fail "requests: check.answer-line in zh-Hant"

echo "bo: all checks passed"
