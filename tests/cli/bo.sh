#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# The Bo commands, end to end (D-053, step 6): the official language packs and
# their digests, a company's own pack, and packs that are refused (a missing
# keyword, one spelling with two meanings, a word an attaching rule could
# split), with messages in each official language; checking source, its
# tokens (the lexer), its tree (the parser), and its model (the checker), in
# each language and mixed.
# Usage: bo.sh CEXCHAIN
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO (from lines ${BASH_LINENO[*]}): $BASH_COMMAND" >&2' ERR

CEXCHAIN="$1"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GOLDEN="$SOURCE/tests/bo/golden/pack-digests.txt"
GOLDENS="$SOURCE/tests/bo/golden"
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
for command in "bo check" "bo packs list" "bo packs show" "bo packs check"; do
    # shellcheck disable=SC2086
    run $command --help > out.txt
    contains -F "cexchain $command" out.txt || fail "help for $command"
    contains -F "GCC 16" out.txt || fail "help for $command names the build it needs"
done
run --help > out.txt
contains -F "bo packs list" out.txt || fail "overview lists bo"
run completion bash > out.txt
contains -F '"bo") words="check packs"' out.txt || fail "completion: bo"
contains -F -- "--stage" out.txt || fail "completion: --stage"
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
contains -Fx "166 49" out.txt || fail "messages and sentences"
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

echo "bo: all checks passed"
