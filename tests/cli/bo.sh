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
# their code; and the source laid out canonically and written in each
# language (bo fmt), which builds to the same code and explains to the same
# text.
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
for command in "bo check" "bo build" "bo explain" "bo fmt" "bo packs list" "bo packs show" "bo packs check"; do
    # shellcheck disable=SC2086
    run $command --help > out.txt
    contains -F "cexchain $command" out.txt || fail "help for $command"
    contains -F "GCC 16" out.txt || fail "help for $command names the build it needs"
done
run --help > out.txt
contains -F "bo packs list" out.txt || fail "overview lists bo"
run completion bash > out.txt
contains -F '"bo") words="build check explain fmt packs"' out.txt || fail "completion: bo"
contains -F -- "--write" out.txt || fail "completion: bo fmt"
contains -F 'deploy evidence explain fetch' out.txt || fail "completion: contract explain"
contains -F -- "--bundle-out" out.txt || fail "completion: bo build"
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
contains -Fx "18 125 True none" out.txt || fail "facts"

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
contains -Fx "169 152" out.txt || fail "messages and sentences"
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
contains -F "warning: pack acme-terms does not spell 122 of the 125 words" out.txt || fail "partial"
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
    contains -Fx "vps-$language.bo: ok: 86 tokens, 2 comments, 10 clauses, edition 1" out.txt || fail "check $language"
    contains -Fx "vps-$language.bo: checked: 2 parties, 5 fields, 0 charges, 1 state, 4 actions, 3 time rules; 6 warnings" out.txt || fail "checked $language"
    # The executor clauses are marked: they come in step 6b.
    [ "$(grep -c "(check.needs-executor)" warnings.txt)" = 6 ] || fail "executors marked ($language)"
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
done
contains -F "2:4 name VPS服務 | VPS服務" "$GOLDENS/example-vps-zh-hant/tokens.txt" || fail "golden"
run bo check vps-zh-hant.bo --stage lex --json > lex.json
json 'd["ok"], d["edition"], d["stage"], len(d["tokens"]), len(d["comments"])' < lex.json > out.txt
contains -Fx "True 1 lex 86 2" out.txt || fail "check --json"
# 可訂購: the prefix keyword and the action, each with its place.
json '[(t["kind"], t["concept"], t["span"]["line"], t["span"]["column"], t["source"]) for t in d["tokens"] if t.get("concept") in ("kw.can", "act.subscribe")][:2]' < lex.json > out.txt
contains -Fx "[('word', 'kw.can', 11, 1, '可'), ('word', 'act.subscribe', 11, 2, '訂購')]" out.txt || fail "prefix in json"
json '[(t["value"], t["unit"]) for t in d["tokens"] if t["kind"] == "money"]' < lex.json > out.txt
contains -Fx "[('120', 'cur.HKD'), ('0.10', 'cur.HKD'), ('100', 'cur.HKD')]" out.txt || fail "money in json"
run bo check vps-en.bo --json > out.txt
json '"tokens" in d, d["stage"], d["checked"], sorted(set(x["code"] for x in d["diagnostics"])), [x["severity"] for x in d["diagnostics"]].count("warning")' < out.txt > keys.txt
contains -Fx "False check True ['check.needs-executor'] 6" keys.txt || fail "check --json without --stage"

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
contains -Fx "act.pledge role.bank cond.over {'line': 9, 'column': 1, 'offset': 143, 'length': 20}" out.txt || fail "parse --json members"
json 'd["ast"]["clauses"][5]["actions"][0]["subject"]["concept"], d["ast"]["clauses"][5]["actions"][0]["action"]["concept"]' < receivable-en.json > out.txt
contains -Fx "role.issuer act.pay" out.txt || fail "when: the party before the action"

echo "== bo check: the parser's errors, with places, in the reader's language"
printf 'contract X\ncan pledge bank\n  requires a < b < c\nuse modules\n可提款 由 客戶\n' > parse.bo
expect_exit 2 bo check parse.bo
contains -F "parse.bo:2:12: error: bank cannot follow the action here: write by PARTY, to PARTY, or with INPUTS, each at most once (parse.can)" out.txt || fail "can"
contains -F "parse.bo:4:1: error: use is reserved for modules, in a later edition of Bo (parse.reserved)" out.txt || fail "use"
contains -F "parse.bo:5:1: error: 可提款 is one name here, since nothing declares 提款; to begin the line with 可, write 可 提款 with a space (parse.undeclared-split)" out.txt || fail "split"
contains -Fx "parse.bo: 3 errors" out.txt || fail "count (the block under a failed line is skipped)"
expect_exit 2 bo check parse.bo --language zh-Hant-HK
contains -F "parse.bo:2:12: error: bank 不可接在此動作之後：可寫 由 訂約方、予 訂約方 或 連同 輸入項，每項最多一次 (parse.can)" out.txt || fail "zh-Hant"
CEXCHAIN_LANGUAGE=zh-Hans expect_exit 2 bo check parse.bo --stage parse
contains -F "parse.bo:4:1: error: use 已保留给以后版本的模块使用 (parse.reserved)" out.txt || fail "zh-Hans"
contains -Fx "contract X" out.txt || fail "the tree of what parsed"
expect_exit 2 bo check parse.bo --json
json '[(x["code"], x["span"]["line"], x["span"]["column"]) for x in d["diagnostics"]]' < out.txt > codes.txt
contains -Fx "[('parse.can', 2, 12), ('parse.reserved', 4, 1), ('parse.undeclared-split', 5, 1)]" codes.txt || fail "parse errors in json"
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
contains -Fx "R6 10" out.txt || fail "model --json: the rule and the place"
json 'd["dump"].splitlines()[0]' < model.json > out.txt
contains -Fx "edition 1" out.txt || fail "model --json: the text"
cp "$GOLDENS/example-tax-en/source.bo" tax.bo
run bo check tax.bo > out.txt 2> warnings.txt
contains -Fx "tax.bo: checked: 0 parties, 1 field, 1 charge, 1 state, 0 actions, 0 time rules; 1 warning" out.txt || fail "fragment"
contains -F "tax.bo: warning: there is no contract line, so this file is checked as a fragment" warnings.txt || fail "fragment warning"

echo "== bo check: the checker's errors, in the reader's language"
printf 'contract C\nparties issuer, supplier\nasset A\n  amount HKD\n  holder HKD\ncan pledge to bank\n  over USD 5 requires in person\ncan go\n' > model.bo
expect_exit 2 bo check model.bo
contains -F "model.bo:5:10: error: holder holds a party, not money in HKD (check.field-type)" out.txt || fail "field type"
contains -F "model.bo:6:15: error: bank is not one of the contract's parties: add it to the parties line (check.unknown-party)" out.txt || fail "party"
contains -F "model.bo:7:8: error: money in USD and money in HKD are in different currencies; Bo never converts one into the other (check.mixed-currencies)" out.txt || fail "currencies"
contains -F "model.bo:8:5: error: who starts go? An action of your own needs by PARTY (check.needs-by)" out.txt || fail "by"
contains -Fx "model.bo: 4 errors" out.txt || fail "count"
expect_exit 2 bo check model.bo --language zh-Hant-HK
contains -F "model.bo:5:10: error: 持有人 存放的是訂約方，而非港元金額 (check.field-type)" out.txt || fail "zh-Hant"
contains -F "model.bo:7:8: error: 美元金額與港元金額是不同貨幣；Bo 從不換算貨幣 (check.mixed-currencies)" out.txt || fail "zh-Hant currencies"
CEXCHAIN_LANGUAGE=zh-Hans expect_exit 2 bo check model.bo --stage model
contains -F "model.bo:6:15: error: 银行 不是此合约的参与方：请把它加入 参与方 一行 (check.unknown-party)" out.txt || fail "zh-Hans"
contains -Fx "contract C" out.txt || fail "the model of what checked"
expect_exit 2 bo check model.bo --json
json '[(x["code"], x["span"]["line"], x["args"].get("type", "")) for x in d["diagnostics"]]' < out.txt > codes.txt
contains -Fx "[('check.field-type', 5, 'money cur.HKD'), ('check.unknown-party', 6, ''), ('check.mixed-currencies', 7, ''), ('check.needs-by', 8, '')]" codes.txt || fail "checker errors in json"
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
contains -E "^cexchain-bo [0-9.]+; codegen 1; edition 1$" <<< "$COMPILER" || fail "the compiler string"
run bo build agreement.bo > out.txt 2> warnings.txt
contains -Fx "agreement.bo: built contract Agreement (Bo edition 1)" out.txt || fail "build"
contains -F "functions  amend, close, countersign, create (creates), sign" out.txt || fail "functions"
contains -F "code       $GOLDEN_SIZE bytes, SHA-256 $GOLDEN_HASH" out.txt || fail "code"
contains -F "compiler   $COMPILER" out.txt || fail "compiler"
contains -F "the packs en 1, zh-Hans-CN 1, zh-Hant-HK 1 (SHA-256 digests)" out.txt || fail "packs"
contains -F "wrote" out.txt && fail "nothing written without --out"
# Comments are published with the source: a warning says so.
contains -F "agreement.bo: warning: the source is deployed with its comments (4 lines)" warnings.txt || fail "comments"
run bo build agreement.bo --json > build.json
json 'd["ok"], d["contract"], d["code_size"], d["code_hash"], d["compiler"], d["edition"], d["comments"]' < build.json > out.txt
contains -Fx "True Agreement $GOLDEN_SIZE $GOLDEN_HASH $COMPILER 1 4" out.txt || fail "build --json"
json 'd["functions"]["create"], d["functions"]["sign"], [p["id"] for p in d["packs"] if p["official"]]' < build.json > out.txt
contains -Fx "create call ['en', 'zh-Hans-CN', 'zh-Hant-HK']" out.txt || fail "functions and packs in json"
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
expect_exit 2 bo build tax.bo
contains -F "this file has no contract line, so it is a fragment" out.txt || fail "fragment"
contains -Fx "tax.bo: 2 errors" out.txt || fail "fragment count"
expect_exit 2 bo build vps-en.bo
contains -F "(build.executor)" out.txt || fail "executors"
expect_exit 2 bo build model.bo --json
json 'd["ok"], "code_hash" in d, d["diagnostics"][0]["code"]' < out.txt > codes.txt
contains -Fx "False False check.field-type" codes.txt || fail "check errors stop the build"
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
run bo explain "$SOURCE/deploy/demo/supply-agreement.bo" --language zh-Hans-CN > text.txt
diff "$TEXTS/supply-agreement/zh-hans.txt" text.txt > /dev/null || fail "the demo's text"
# --json: the clauses, their rules, requirements numbered as refusals name
# them (bo:requires sign 2), and the rules' texts.
run bo explain agreement.bo --json > explain.json
json 'd["ok"], d["language"], d["title"], [s["kind"] for s in d["sections"]]' < explain.json > out.txt
contains -Fx "True en Contract Agreement ['parties', 'instance', 'states', 'actions']" out.txt || fail "explain --json"
json '[(c["function"], c["requirement"], c["rules"]) for s in d["sections"] for c in s["clauses"] if c["kind"] == "requirement"]' < explain.json > out.txt
contains -Fx "[('amend', 1, ['R7']), ('amend', 2, []), ('amend', 3, []), ('sign', 1, ['R6', 'R13']), ('sign', 2, []), ('close', 1, [])]" out.txt || fail "requirements in json"
json '[r["id"] for r in d["rules"]], d["text"] == open("'"$TEXTS"'/agreement/en.txt").read()' < explain.json > out.txt
contains -Fx "['R3', 'R4', 'R5', 'R6', 'R7', 'R13', 'R14', 'R17'] True" out.txt || fail "rules in json"
# R18: a name compared with a text is that text, shown in quotation marks.
run bo explain tax.bo > text.txt 2> warnings.txt
contains -F '  2.1.2 It applies when the customer location is "中国内地". [R18]' text.txt || fail "R18 in quotes"
contains -F "(check.fragment)" warnings.txt || fail "warnings on stderr"
run bo explain tax.bo --language zh-Hant-HK 2> /dev/null | contains -F "適用條件：客戶所在地為「中国内地」。〔R18〕" || fail "R18 in zh-Hant"
# A contract that needs executors explains (it does not build yet).
run bo explain vps-zh-hant.bo > text.txt 2> warnings.txt
diff "$TEXTS/vps/en.txt" text.txt > /dev/null || fail "the VPS text"
[ "$(grep -c "(check.needs-executor)" warnings.txt)" = 6 ] || fail "executors marked"
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
cp "$SOURCE/deploy/demo/supply-agreement.bo" supply.bo
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
contains -Fx "訂約方 本公司, 供應商, 銀行" supply-zh-Hant-HK.bo || fail "zh-Hant: parties"
contains -Fx "可 sign 由 本公司" supply-zh-Hant-HK.bo || fail "zh-Hant: names stay"
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
printf 'contract  A\nparties   we ,customer\n' > loose.bo
expect_exit 3 bo fmt loose.bo --check
contains -Fx "loose.bo: would change when formatted" out.txt || fail "--check: not formatted"
expect_exit 3 bo fmt supply.bo --check --language zh-Hans
contains -Fx "supply.bo: would change when formatted in zh-Hans-CN" out.txt || fail "--check --language"
run bo fmt loose.bo --json > fmt.json
json 'd["ok"], d["changed"], d["written"], d["language"], repr(d["source"]), d["diagnostics"]' < fmt.json > out.txt
contains -Fx "True True False None 'contract A\nparties we, customer\n' []" out.txt || fail "fmt --json"
run bo fmt loose.bo --write > out.txt
contains -Fx "loose.bo: formatted" out.txt || fail "--write"
[ "$(cat loose.bo)" = "$(printf 'contract A\nparties we, customer')" ] || fail "--write wrote the file"
run bo fmt loose.bo --write > out.txt
contains -Fx "loose.bo: already formatted" out.txt || fail "--write again"
run bo fmt loose.bo --write --language zh-Hant-HK --json | json 'd["written"], d["language"]' > out.txt
contains -Fx "True zh-Hant-HK" out.txt || fail "--write --language --json"
contains -Fx "訂約方 本公司, 客戶" loose.bo || fail "written in Traditional Chinese"
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
printf '合約 C\n訂約方 本公司, 銀行\n\n可質押 予 銀行\n' > pledge.bo
expect_exit 2 bo fmt pledge.bo --pack collide.pack --language collide
contains -F "pledge.bo:4:1: error: written in collide, the source would read differently here" out.txt || fail "fmt.unstable"
contains -F "(fmt.unstable)" out.txt || fail "fmt.unstable: the code"
run bo fmt pledge.bo --pack company.pack --language en-x-acme > out.txt
contains -Fx "can lodge to bank" out.txt || fail "a company's pack: its words"
expect_exit 1 bo fmt loose.bo --check --write
expect_exit 1 bo fmt loose.bo --language fr
expect_exit 1 bo fmt
expect_exit 2 bo fmt no-such.bo

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
contains -F "            Bo, edition 1: 898 bytes of source; packs en 1, zh-Hans-CN 1, zh-Hant-HK 1" show.txt || fail "show: bundle"
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
expect_exit 2 contract deploy --bo tax.bo --as d-root.key --ledger "$D"
contains -F "tax.bo does not build" out.txt || fail "deploy refuses what does not build"

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
contains -F "  Source       Bo, edition 1: 898 bytes of source; packs en 1, zh-Hans-CN 1, zh-Hant-HK 1" verify.txt || fail "verify: the source"
contains -F "               rebuilds: the source rebuilds to the deployed code ($GOLDEN_SIZE bytes, SHA-256 ${GOLDEN_HASH:0:16})" verify.txt || fail "verify: rebuilds"
contains -F "VERIFICATION FAILED" verify.txt && fail "verify: verified"
run contract verify e1.cbor --ledger-id "$D_ID" --json > verify.json
json 'd["verified"], d["source"]["status"], d["source"]["compiler"] == d["source"]["this_compiler"], d["source"]["bundle_size"]' < verify.json > out.txt
contains -Fx "True rebuilds True 1042" out.txt || fail "verify --json"
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
NEWER="$(sed 's/codegen 1/codegen 2/' <<< "$COMPILER")"
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

echo "bo: all checks passed"
