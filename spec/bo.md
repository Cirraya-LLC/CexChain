# The Bo language

Bo 1.0, edition 1 (draft).

Bo is the language contracts on CexChain are written in. This document defines how a Bo source is read (sections 2 and 3), its grammar (4), its types (5), what a contract means (6 to 11), what its compiled code does when it is called (12), and the tools that test, explain, format, and rebuild it (13 to 16). It goes with:

- [`README.md`](README.md), the protocol, whose sections 14 and 15 define the contract profile, fuel, a call's input and output, instances created by a call, and the `bo-source` bundle a deploy carries;
- [`cexchain.cddl`](cexchain.cddl), where `bo-source` and the contract input and output are defined;
- the official language packs, [`../bo/packs/`](../bo/packs) (with every earlier version in [`../bo/packs/history/`](../bo/packs/history)), the official vocabulary packs (3.9), and the standard library, [`../bo/stdlib/`](../bo/stdlib) (the core's terms and each vocabulary pack's), which are part of edition 1;
- [`../testvectors/bo-v1.json`](../testvectors/bo-v1.json), the conformance suite (section 18).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as in RFC 2119.

**What is normative.** Behaviour is normative:

- which sources are accepted, and the codes of the errors a refused source gets (the wording of messages and the places they point to are informative);
- what a contract means: its parties, fields, states, actions, consents, requirements, time rules, charges, and parts;
- what its compiled code does on every call: the outcome (accepted, waiting for consents, or refused), the state, status, parties, events, finality, and parts an accepted call writes, the ledgers whose consents a call lacks (`[2, needs]`), and the exact reason of a refusal (`bo:CODE ...`, or the text of a `reject`).

Code bytes are informative. A conforming compiler MAY emit any module in the contract profile that behaves as this document says. CexChain's own compiler, `cexchain-bo`, emits exactly the bytes its codegen version fixes (section 16), which the conformance suite pins; fuel figures in this document are that compiler's. The official packs, the vocabulary packs, and the standard library are normative data: where this text and those files, or the conformance suite, disagree, the files win.

## Contents

1. [Overview](#1-overview)
2. [Source text](#2-source-text)
3. [Language packs](#3-language-packs)
4. [Grammar](#4-grammar)
5. [Types and values](#5-types-and-values)
6. [The model](#6-the-model)
7. [Recognition rules](#7-recognition-rules)
8. [The standard library](#8-the-standard-library)
9. [Time rules and keepers](#9-time-rules-and-keepers)
10. [Lists, charges, and bills](#10-lists-charges-and-bills)
11. [Splitting and parts](#11-splitting-and-parts)
12. [Compiled contracts](#12-compiled-contracts)
13. [Tests](#13-tests)
14. [The contract text](#14-the-contract-text)
15. [Formatting](#15-formatting)
16. [The bo-source bundle and rebuilding](#16-the-bo-source-bundle-and-rebuilding)
17. [Limits and fuel](#17-limits-and-fuel)
18. [Conformance](#18-conformance)

Appendices: [A. Keywords](#appendix-a-keywords), [B. Vocabulary](#appendix-b-vocabulary), [C. Diagnostic codes](#appendix-c-diagnostic-codes).

## 1. Overview

### 1.1 What a contract is

A Bo source describes one contract: its parties; the one kind of thing it governs (a `thing`, or a kind a vocabulary pack brings: an asset, a service, a resource) and that thing's fields; its states; the actions the parties may take on it; the rules that apply to it as time passes; and, with the commerce pack, the charges (taxes, fees) computed on its bills. Compiled, it is a module in the contract profile (spec section 14), deployed on a ledger, its *home*. Each thing it governs is an *instance* (spec section 15), created by one function of the module and acted on by the others.

```
contract Lending
parties owner

thing Item
  name text
  holder owner

can lend to counterparty by owner
  active -> lent
  holder = counterparty
can bring_back by holder
  lent -> active
  holder = owner
```

The same contract in Traditional Chinese (Hong Kong usage) and in Simplified Chinese; the names it gives stay as written:

```
合約 Lending                                 合约 Lending
訂約方 owner                                 参与方 owner

物件 Item                                    物件 Item
  name 文字                                    name 文本
  持有人 owner                                 持有人 owner

可 lend 予 相對方 由 owner                     可 lend 给 相对方 由 owner
  正常 -> lent                                 正常 -> lent
  持有人 = 相對方                               持有人 = 相对方
可 bring_back 由 持有人                        可 bring_back 由 持有人
  lent -> 正常                                 lent -> 正常
  持有人 = owner                               持有人 = owner
```

The owner lends the item to whoever each call names after `to` (the counterparty), who consents on its own ledger and becomes its holder (R21, R31); only the holder brings it back; while it is lent, a second loan is refused, since `lend` starts only from `active`. Every word here is one of Bo's core (1.2).

Words of particular fields come in vocabulary packs (3.9), which a source declares at its top. With the finance pack, a receivable that its holder pledges to a bank:

```
use finance
contract ReceivableFinancing
parties issuer, supplier, bank

asset Receivable
  amount HKD
  due date
  holder supplier

can pledge to bank
  over 5_000_000 requires in person
can transfer
when due issuer pays
```

`pledge` and `transfer` are built-in actions: the standard library gives them their terms (who starts them, whose consent they need, which states they start from and lead to; section 8), `transfer` the core's and `pledge` the finance pack's. The contract adds one line to the pledge: above HKD 5,000,000 the holder proves presence in person (a passkey or a hardware key). The bank is bound to a ledger by the first pledge, with its consent. `when due issuer pays` states the issuer's duty, which says when the receivable is due.

A ledger never acts on the world outside it, but a contract may ask: a *request* names what is asked, for whom, with what, and by when, and an *executor* (a device, an AI agent, or a person of the home) carries it out and answers on the ledger. The contract states what each answer does (6.11):

```
can deliver by carrier
  in_transit -> delivered
  request notify to consignee with message = "delivered" within 1 day

when notify done
  notified = yes
when notify fails
  request notify to shipper with message = "notice failed" within 1 day
```

### 1.2 One contract, any language

Bo has 22 keywords (Appendix A) and a vocabulary of 142 words (Appendix B): kinds, actions, conditions, prices, charges, time words, units, currencies, rounding modes, documents, types, values, fields, states, actors, roles, and expressions. Each is a *concept* with an id (`kw.can`, `act.transfer`, `cur.HKD`). Eighty-four of the words are Bo's *core*, which every source reads: the kind `thing`, actions every kind of thing may need (issue, create, transfer, cancel, suspend, resume, terminate, approve, propose, notify), conditions, time, units, currencies, rounding, types, values, and common fields, states, actors, roles, and expressions. The others belong to the three official *vocabulary packs* (3.9): `finance` (24 words), `commerce` (22), and `services` (12), which a source uses by declaring them (`use finance`). *Language packs* (section 3) give each concept its spellings in one language, and the reading rules of that language. Three official packs come with edition 1: English (`en`), Traditional Chinese in Hong Kong usage (`zh-Hant-HK`), and Simplified Chinese in mainland usage (`zh-Hans-CN`).

The compiler works on concepts, never on spellings. A source may mix the three languages, even within a line (`可pledge 予 bank`), and the same contract written in any language, or mixed, gives the same tree, the same checked model, the same compiled code byte for byte, and the same contract text in each output language. Names the contract gives (its own parties, fields, states, actions, charges) are never translated: they stay as written, and compiled code uses them as written.

### 1.3 Bo never guesses

Bo reads, and infers, only by fixed rules of the edition:

- **Reading.** A run of characters that two rules could read differently (`可用率` as one name, or as `可` + `用率`) is read one way only, or it is an error asking for a space. One spelling never has two meanings across the packs a source is read with.
- **Grammar.** What could be grouped two ways is an error asking for parentheses (`monthly HKD 120 * 12`, `a < b < c`).
- **Meaning.** What Bo infers rather than reads (a field's type, the state an instance starts in, a consent an action needs, a threshold's currency), it infers by one of the edition's thirty-two *recognition rules*, R1 to R32 (section 7). Where no rule applies, the checker reports an error. Every clause a rule inferred is marked with the rule's id in the contract text (section 14), so the parties see it before they sign.

### 1.4 Editions

A source may begin with `bo 1`, the edition it is written in; a source without it is edition 1. An edition fixes the keywords, the vocabulary, the recognition rules, and the standard library. Later editions only add: once an edition is released, nothing in it changes meaning. Deployed code never changes.

### 1.5 Tools

*This section is informative.* The `cexchain` command line reads Bo sources:

| Command | What it does |
|---|---|
| `bo check FILE [--stage lex\|parse\|model]` | problems as `FILE:LINE:COLUMN: error: message (code)`; with a stage, the tokens, the tree, or the checked model |
| `bo build FILE [--out FILE.boc]` | the code, its interface, the compiler string, and the `bo-source` bundle (section 16) |
| `bo explain FILE [--language L]` | the contract text (section 14) |
| `bo fmt FILE [--language L] [--check\|--write]` | the source in canonical layout, in one language on request (section 15) |
| `bo test FILE` | runs the source's `test` blocks (section 13) |
| `bo packs list\|show\|check` | the official language packs and others given with `--pack` (section 3) |
| `bo vocab list\|show PACK\|FILE` | the core and the vocabulary packs, yours given with `--vocab`: their words, field facts, actions, and digests (3.9) |
| `bo vocab check FILE...` | checks vocabulary packs of your own, alone and with the official packs (3.9) |
| `bo stdlib list [PACK]\|show ACTION` | the standard library's built-in actions, by pack (section 8) |
| `contract deploy --bo FILE` | builds and deploys, recording the source bundle |
| `contract explain CONTRACT\|INSTANCE` | the contract text of a deploy whose source rebuilds |
| `contract verify EVIDENCE` | replays an instance's evidence and rebuilds its code from the source |

Messages follow `--language`, or the environment variable `CEXCHAIN_LANGUAGE`, else English. Every command takes `--json`. Every `bo` command, and `contract deploy --bo`, reads vocabulary packs of your own with `--vocab FILE` (a `.vocab` file, or a directory's), language packs with `--pack FILE`.

## 2. Source text

### 2.1 Encoding and lines

- A source MUST be valid UTF-8 (`lex.utf8`) of at most 262,144 bytes (`lex.too-large`). It is read exactly as written and never normalized.
- A line ends with LF, or with CR LF. A CR not followed by LF is an invisible character (2.4).
- One clause or statement per line. A line never continues on the next one.

### 2.2 Indentation and blocks

- Lines are indented with spaces (U+0020) only. A tab is refused anywhere but in a comment (`lex.tab`); another separator in the indentation, such as U+3000 IDEOGRAPHIC SPACE (which separates words, 2.13), is `lex.indent-character`.
- A line indented more than the line before opens a block under that line, whatever the number of spaces. A line indented less closes blocks down to the enclosing block indented as it is. A line whose indentation matches no enclosing block is `lex.dedent`, and it stays in the block it fell back to.
- Blank lines and lines holding only a comment neither open nor close blocks.
- Blocks nest at most 32 deep (`lex.too-deep`).

### 2.3 Comments

`#` begins a comment, which runs to the end of the line, except inside a text (2.12). A comment may hold tabs, but no other invisible character. Comments are part of the source a deploy publishes: every party, and anyone who verifies the contract, reads them (`build.comments`).

### 2.4 Characters refused everywhere

A source MUST NOT contain, anywhere (code, texts, and comments), an invisible or format character (`lex.invisible`), so that the source reads as it looks and no bidirectional control can make code appear other than it runs:

| Range | What |
|---|---|
| U+0000 to U+001F, except LF, the CR of a CR LF, and the tab (2.2) | C0 controls |
| U+007F to U+00A0 | DEL, C1 controls, NO-BREAK SPACE |
| U+00AD | SOFT HYPHEN |
| U+034F, U+061C | COMBINING GRAPHEME JOINER, ARABIC LETTER MARK |
| U+115F, U+1160, U+3164, U+FFA0 | Hangul fillers |
| U+1680 | OGHAM SPACE MARK |
| U+17B4, U+17B5 | Khmer inherent vowels |
| U+180B to U+180F | Mongolian variation selectors and vowel separator |
| U+2000 to U+200F | spaces, zero-width characters, directional marks |
| U+2028 to U+202F | line and paragraph separators, bidirectional embeddings and overrides, NARROW NO-BREAK SPACE |
| U+205F to U+206F | MEDIUM MATHEMATICAL SPACE, invisible operators, bidirectional isolates |
| U+FE00 to U+FE0F | variation selectors |
| U+FEFF | ZERO WIDTH NO-BREAK SPACE (byte order mark) |
| U+1D173 to U+1D17A | musical format characters |
| U+E0000 and above | tags, variation selectors supplement, private use planes |

U+3000 IDEOGRAPHIC SPACE is allowed: the official Chinese packs read it as a space (2.13), so it separates words, in texts and comments too, but it cannot indent. Outside texts and comments, a character that is part of no word, number, text, or symbol is `lex.bad-character`.

### 2.5 Words and runs

A *run* is a maximal sequence of word characters, `_`, and digits that begins with a word character or `_` (a digit begins a number, 2.9). *Word characters* are the ASCII letters and digits, and every other character except noncharacters and those in these ranges:

| Ranges refused in words | What they hold |
|---|---|
| U+0080–U+00BF, U+00D7, U+00F7 | C1 controls, Latin-1 punctuation and symbols, `×`, `÷` |
| U+02B0–U+02FF, U+1D2C–U+1D6A, U+1D78, U+1D9B–U+1DBF | modifier letters |
| U+034F, U+061C, U+115F–U+1160, U+1680, U+17B4–U+17B5, U+180B–U+180F | invisible characters (2.4) |
| U+2000–U+2BFF | spaces, format characters, punctuation, super- and subscripts, symbols, letterlike and number forms, arrows, operators, shapes, braille |
| U+2E00–U+2FFF | supplemental punctuation, CJK and Kangxi radicals |
| U+3000–U+3004, U+3008–U+3030, U+3036–U+303A, U+303D–U+303F | ideographic space, CJK punctuation, brackets, and symbols |
| U+309B–U+309C, U+30A0, U+30FB | spacing kana voicing marks, katakana double hyphen and middle dot |
| U+3130–U+319F, U+31C0–U+31EF, U+3200–U+33FF, U+4DC0–U+4DFF | Hangul compatibility jamo, kanbun, CJK strokes, enclosed and compatibility forms, hexagram symbols |
| U+D800–U+F8FF, U+F900–U+FAFF, U+2F800–U+2FA1F | surrogates, private use, CJK compatibility ideographs |
| U+FB00–U+FDFF, U+FE00–U+FE6F, U+FE70–U+FFFF | ligatures, presentation forms, variation selectors, vertical and small forms, full-width and half-width forms, specials |
| U+1D100–U+1D1FF, U+1D400–U+1D7FF, U+1F000–U+1FFFF, U+E0000–U+10FFFF | musical symbols, mathematical alphanumerics, symbols and emoji, tags and private use |

So letters, marks, and digits of every script are word characters; compatibility forms that Unicode's NFKC would fold into other characters are not, and two words that look alike are never different words.

A run is read as one of these, and each reading is collected:

1. **A spelling** of the pack set (section 3): the run, with the runs after it on the line that only spaces separate from it, as one spelling of one to four words. Where spellings share a beginning, the longest is read (`in person`, never `in` + `person`; `AI 代理`; `yes or no`). A spelling is never read across punctuation, a number, or a text.
2. **A prefix keyword joined to a word** (2.7): `可質押` is `可` + `質押`.
3. **An attaching word joined to its neighbour** (2.7): `每GB` is `每` + `GB`.
4. **A name** (2.6), if none of the above reads it.

A run with two readings is `lex.ambiguous`, which names both. Matching is exact, case included: the type word is `date`, never `Date`. A word's forms (3.3) read as the word itself: `pays` is `pay`, `the customer` is `customer`, `us` is `we`, `days` is `day`.

### 2.6 Names

A run that reads as no spelling is a name: the name of the contract, of a party, a block, a field, an action, an input, a state, a charge, or an item of `each`. A name:

- MUST NOT start with `_` (`lex.bad-name`; a digit begins a number); `_` may appear after the first character (`late_fee`);
- MUST consist of word characters and `_` (`lex.bad-character`);
- MUST NOT contain a character that Unicode normalization (NFC) would change (`lex.not-normalized`): combining diacritical marks (U+0300–U+036F, U+1AB0–U+1AFF, U+1DC0–U+1DFF; write `é` as U+00E9), conjoining Hangul jamo (U+1100–U+11FF; write syllables whole), combining kana voicing marks (U+3099–U+309A), Arabic madda and hamza (U+0653–U+0655), the canonical singletons U+0374, U+037E, U+0387, Greek letters with oxia (U+1F71, U+1F73, U+1F75, U+1F77, U+1F79, U+1F7B, U+1F7D, U+1FBB, U+1FBE, U+1FC9, U+1FCB, U+1FD3, U+1FDB, U+1FE3, U+1FEB, U+1FEE, U+1FEF, U+1FF9, U+1FFB, U+1FFD), and the composition exclusions of Devanagari (U+0958–U+095F), Bengali (U+09DC, U+09DD, U+09DF), Gurmukhi (U+0A33, U+0A36, U+0A59–U+0A5B, U+0A5E), Oriya (U+0B5C, U+0B5D), and Tibetan (U+0F43, U+0F4D, U+0F52, U+0F57, U+0F5C, U+0F69, U+0F73, U+0F75, U+0F76, U+0F78, U+0F81, U+0F93, U+0F9D, U+0FA2, U+0FA7, U+0FAC, U+0FB9);
- MUST NOT mix letters of two of the Latin, Greek, and Cyrillic scripts (`lex.mixed-script`);
- MUST NOT look like another name of the source or a word of the pack set without being it (`lex.confusable`). Two texts look alike when they are equal once each Greek and Cyrillic letter that resembles a Latin letter is replaced by that letter: Greek Ϳ Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ α ι κ ν ο ρ υ χ ϲ ϳ Ϲ as J A B E Z H I K M N O P T Y X a i k v o p u x c j C, and Cyrillic Ѕ І Ј А В Е К М Н О Р С Т У Х а е о р с у х ѕ і ј Ѵ ѵ Ү ү һ Ӏ ӏ ԁ Ԛ ԛ Ԝ ԝ as S I J A B E K M H O P C T Y X a e o p c y x s i j V v Y y h I l d Q q W w. So a Cyrillic `рау` is refused beside `pay`;
- MUST be at most 128 bytes (`lex.name-too-long`); compiled code takes names of at most 64 bytes (`build.name-too-long`, section 17).

A currency or a unit run into the number after it (`HKD100`) is not a name but `lex.needs-space`. Since the official packs are always read, every spelling of every concept in the three languages is reserved: no name can be spelled as one. Five words are *contextual*, added after names had used them (E8): the outcomes of a request, `done`, `fails`, and `expires`, are keywords only after a request's kind, in a `when` line or a test step (`when notify done`, `executor notify done`), and an answer's `result` and `reason` are words only in a rule for answers (unless the contract declares a name so spelled) and in a test step's answer. Everywhere else they are names (`delivered -> done`), as sources written before them used them.

Two kinds of look-alikes are not detected in edition 1: Indic two-part vowels written in pieces, and variant Han characters (說 and 説).

### 2.7 Prefix keywords and attaching words

A pack may let some keywords attach to the start of the next word, and some words attach to their neighbours, as languages written without spaces do. The official Chinese packs declare:

| Words | Rule | Joined to | Examples |
|---|---|---|---|
| `可` (can), `須`/`须` (requires), `當`/`当` (when), `如`/`如果` (if) | prefix keywords | the start of the next word: a word of the vocabulary, the opening words of a word with an argument, or a name the contract declares | `可質押`, `須親身確認`, `須經`, `當逾期`, `如逾期` |
| `每` (`price.per`) | attaches before | a unit or a currency | `每GB`, `每港元` |
| `按` (`charge.by`) | attaches before | a document or a field | `按發票`, `按客戶所在地` |
| `內`/`内` (`cond.within`, the words after its argument) | attaches after | a time word or a unit | `30日內`, `3個月內` |

A prefix keyword joined to a word of the vocabulary is read by the lexer. Joined to a name (`可提款`), it depends on the names the contract declares, which the parser knows: the name is read as the keyword followed by the rest (`可` + `提款`) when the contract declares the rest and does not declare the whole; if it declares both, it is `parse.ambiguous-name`; if neither, the whole is one name (`可用率` stays a name), and a line that such a name cannot begin is `parse.undeclared-split`. *Declared* means named as the contract, a party, a block, a field, an action after `can`, an input after `with`, or an item of `each`.

### 2.8 Words with an argument

Ten concepts take an argument, and each spelling marks the argument's place with `…` (U+2026), since languages put it on different sides:

| Concept | English | 繁體中文（香港） | 简体中文 |
|---|---|---|---|
| `cond.over` | `over …` | `超過 …` | `超过 …` |
| `cond.consent_of` | `consent of …` | `經 … 同意` | `经 … 同意` |
| `cond.before_due` | `… before due` | `到期前 …` | `到期前 …` |
| `cond.within` | `within …` | `… 內` | `… 内` |
| `charge.applies_to` | `applies to …` | `適用 …` | `适用 …` |
| `charge.from` | `from … on` | `從 … 起` | `从 … 起` |
| `time.at` | `at …` | `時間 …` | `时间 …` |
| `expr.sum_of` | `sum of …` | `… 總和` | `… 总和` |
| `expr.count_of` | `count of …` | `… 數目` | `… 数目` |
| `expr.at_most` | `at most …` | `最多 …` | `最多 …` |

The lexer reads the words before the place as a *head* and the words after it as a *tail*; when a spelling has words on both sides, they are an *open* and a *close* piece (`經` … `同意`). The parser joins each piece with its argument (4.5). An open piece may be closed by another pack's close piece of the same concept: mixing is allowed everywhere.

### 2.9 Numbers

A number is ASCII digits (or full-width digits, which the official packs read as ASCII), with `_` only between digits and at most one decimal point between digits:

```
number = digits { "_" digits } [ "." digits { "_" digits } ]
```

- A comma never groups digits: `5,000` is `lex.digit-comma`, which suggests `5_000`. Any other misplaced `_` or `.` is `lex.bad-number`.
- The value is exact, as written: `0.10` is ten hundredths. At most 18 decimal places, and at most 18,446,744,073,709,551,615 counting every digit without the decimal point (`lex.number-too-large`).
- **Multipliers.** A pack may define multipliers, powers of ten (the official Chinese packs: `萬`/`万` 10^4 and `億`/`亿` 10^8). One multiplier may follow a number, joined (`500萬`) or after a space (`500 萬`). Decimal places absorb it: `1.5萬` is 15,000. A multiplier anywhere else is `lex.multiplier`; one that makes the number too large, `lex.number-too-large`.
- **What may follow a number directly.** Without a space, a number may be followed by, in order and each optional: one multiplier; one unit, time unit, or currency spelled as one word; and a word that attaches after a unit or time unit (2.7). `2TB`, `30日`, `500萬港元`, `30日內`. Anything else is `lex.number-suffix`; a suffix that reads two ways, `lex.ambiguous`.
- **Rates.** `%` (or a pack's alias, `％`) directly after a number makes a rate, in percent: `5%`, `3.875%`. `%` anywhere else is `lex.percent`.
- **No subtraction of dates.** Digits joined by `-` twice or more are a date or an error (2.11), never a subtraction: `2027-1-6` is `lex.bad-date`. `10-3` is a subtraction.
- **Negative numbers.** A `-` directly before a number's first digit makes the number negative where a value begins: at the start of a line's code, after a space, or directly after a symbol that ends no value (`(`, `,`, `=`, `<`, `>`, `+`, `-`, `*`, `/`, `×`, `÷`, `:`). So `-18 °C`, `HKD -5`, `x = -1`, `(1, -2)`, and `a * -2` hold negative numbers. Directly after a word, a number, a text, `%`, or `)`, it subtracts (`10-3`, `x-3`), and with a space after it, it is the operator (`x - 3`). `x -3` is a name and a negative number side by side, a phrase, which no expression reads (`check.phrase`): Bo never guesses which was meant. A date has no sign.

### 2.10 Money, quantities, and durations

After reading a line's words, the lexer joins numbers with the words that measure them:

- **A quantity** is a number with a unit after it, joined or spaced: `2TB`, `100 Mbps`, `3 噸`, `1個`, `4.5 °C`.
- **The degree symbol.** `°C` (U+00B0 followed by `C`, ending the run) and `℃` (U+2103) read as the unit `unit.celsius` in every language, wherever the pack set spells that unit (the official packs from version 3); joined to its number or spaced: `4.5°C`, `4.5 °C`, `-18℃`. The packs also spell it in words: `degree Celsius` (plural `degrees Celsius`), `攝氏度`, `摄氏度`. Tools write `°C`.
- **A duration** is a number with a time unit after it (`day`, `week`, `month`, `year`): `30 days`, `30日`, `3 個月`. A recurrence such as `monthly` or `每月` is a word, not a duration.
- **Money** is a number with a currency beside it, on either side, spaced or (after the number) joined: `HKD 0.10`, `120 HKD`, `500萬港元`. A currency between two numbers, or a number between two currencies, is `lex.ambiguous-money`: which belongs to which would be a guess.

### 2.11 Dates

Every pack reads ISO dates, `YYYY-MM-DD`, exactly: a four-digit year, a two-digit month, and a two-digit day (`2027-01-06`). A pack may add forms it reads (the official Chinese packs: `{Y}年{M}月{D}日`, with a year of up to four digits and a month and a day of up to two: `2027年1月6日`). A date's year is 1 to 9999, its month 1 to 12, and its day one that month has in the proleptic Gregorian calendar (`lex.bad-date`). A date names a day; its value is the moment that day begins at the contract's UTC offset (5.5).

### 2.12 Texts

A text is written between double quotes (`"`, or a pack's alias of it) on one line. There are no escapes: everything between the quotes, spaces included, is the text. A text is at most 1,000 bytes (`lex.text-too-long`), may not hold a tab or an invisible character (2.4), and needs its closing quote on its line (`lex.unterminated-text`). A `#` in a text is part of it.

### 2.13 Symbols

| Symbol | Also written | Meaning |
|---|---|---|
| `,` | `，` `、` | separates parties, field parts, inputs, list items, a step's values |
| `(` `)` | `（` `）` | group, and make lists (4.6) |
| `=` | | sets a field at the start of a line; compares elsewhere (4.7) |
| `<` `<=` `>` `>=` | | compare |
| `+` `-` | | add, subtract |
| `*` `/` | `×` `÷` | multiply, divide |
| `->` | | a state change; a test's expectation |
| `°C` | `℃` | the unit of temperature, in every language (2.10) |
| `:` | `：` | read, but used by no construct of edition 1 |

There is no `!=`: write `not a = b`. The official Chinese packs also read `％` as `%`, U+3000 as a space, and the full-width digits `０` to `９` as ASCII digits. A pack's punctuation alias is one character that no word may contain, so it can never change how a word reads.

### 2.14 The edition line

The first line that has any token MAY name the edition: `bo` followed by a whole number and nothing else, at indentation 0 (`bo 1`). A first line that begins with `bo` but is not so shaped is `lex.bad-edition`; an edition other than 1 is `lex.edition`.

## 3. Language packs

### 3.1 Concepts

Edition 1 has 157 concepts: 18 keywords, which every pack spells, and 139 words of the vocabulary, 81 of them in Bo's core and the others in the vocabulary packs (3.9). A concept's id is its category, a dot, and its name. Categories decide where a word may stand, and packs name them in their reading rules:

| Category | Id prefix | Concepts | Examples |
|---|---|---|---|
| keyword | `kw.` | 18 | `kw.can`, `kw.requires` |
| kind | `kind.` | 4 | `kind.thing`, `kind.asset` |
| action | `act.` | 28 | `act.transfer`, `act.suspend` |
| condition | `cond.` | 6 | `cond.in_person`, `cond.overdue` |
| pricing | `price.` | 6 | `price.price`, `price.per` |
| charge | `charge.` | 10 | `charge.tax`, `charge.rate` |
| time | `time.` | 11 | `time.day`, `time.monthly`, `time.now` |
| unit | `unit.` | 12 | `unit.GB`, `unit.kg`, `unit.celsius` |
| currency | `cur.` | 5 | `cur.HKD`, `cur.CNY` |
| rounding | `round.` | 3 | `round.half_up` |
| document | `doc.` | 3 | `doc.invoice` |
| type | `type.` | 5 | `type.date`, `type.list` |
| value | `val.` | 5 | `val.yes`, `val.none` |
| field | `field.` | 13 | `field.holder`, `field.due` |
| state | `state.` | 14 | `state.active`, `state.pledged` |
| actor | `actor.` | 5 | `actor.ai_agent`, `actor.keeper`, `actor.executor` |
| role | `role.` | 6 | `role.we`, `role.bank` |
| expression | `expr.` | 6 | `expr.sum_of`, `expr.previous_state`, `expr.result` |

The ten concepts that take an argument are listed in 2.8. Appendix B lists every word with its pack and its spellings in the official packs.

Two concepts are *retired*: `kind.record`, the kind word that `kind.thing` replaced, and `act.merge`, which never had a meaning. Only the official packs of before vocabulary packs (version 1, 3.7) spell them, so that the sources deployed with those packs rebuild; any other pack that spells one is `pack.unknown-concept`.

### 3.2 The pack format

A pack is a file in CBOR diagnostic notation (RFC 8949 section 8; JSON is a subset), which may hold comments: `/ ... /` (RFC 8610 appendix G.6) and `#` to the end of a line. Its *canonical CBOR* is its value encoded as deterministic CBOR (RFC 8949 section 4.2.1); comments and layout are not part of it. A pack, as text or as CBOR, is at most 1 MiB (`pack.too-large`). It is a map with these keys (any other is `pack.unknown-key`):

| Key | Required | Value |
|---|---|---|
| `format` | yes | `1`, the pack format (`pack.format`) |
| `edition` | yes | `1`, the Bo edition it spells (`pack.edition`) |
| `id` | yes | ASCII letters, digits, and single hyphens, beginning with a letter and not ending with a hyphen, 1 to 64 bytes (`pack.bad-id`) |
| `version` | yes | 1 or more (`pack.bad-version`); raised on any change |
| `language` | yes | a BCP 47 tag: a language subtag of 2 to 8 letters, then subtags of 1 to 8 letters or digits, at most 64 bytes (`pack.bad-language`) |
| `name` | yes | the pack's name for people, 1 to 200 bytes without control characters |
| `official` | yes | `true` only for a pack that is byte for byte one a compiler carries (3.7) |
| `reading` | yes | the reading rules (3.4) |
| `keywords` | yes | every `kw.*` concept, each with its spellings (`pack.missing-keyword`) |
| `vocabulary` | no | any other concepts, each with its spellings; a pack that spells fewer than all of them gets the warning `pack.partial`, and its missing words are read and shown in English |
| `messages` | no | texts of diagnostic codes (Appendix C), by code |
| `sentences` | no | texts of the contract text and of reports (section 14), by sentence id |

`format` and `edition` are read first: a pack of another format or edition is not read further. Every problem found is reported (at most 100, then `bo.truncated`), and a pack with any error is not used.

### 3.3 Spellings and forms

A concept's spellings are a text, or a list of 1 to 8 texts, the first being the one tools write. In `vocabulary`, a concept may instead have a map `{"word": SPELLINGS, "forms": {NAME: SPELLING, ...}}`, with at most 8 forms, whose names are lowercase ASCII letters, at most 16 (`pack.bad-form`).

A spelling is one to four words separated by single spaces, each 1 to 64 bytes not beginning with a digit (`pack.bad-spelling`), of word characters only (2.5; `pack.bad-character`), plus the argument's place `…`, exactly once for a concept that takes an argument and never for another (`pack.needs-hole`, `pack.unexpected-hole`).

*Forms* are further spellings with a grammatical name, which the contract text's sentences ask for (`{party.object}`) and which a source may also use: they read as the concept itself, and the tree keeps no trace of them. The official English pack's forms are `third` (`pays`), `gerund` (`paying`), `plural` (`days`), `indefinite` (`a thing`), `subject` (`the customer`), and `object` (`the customer`, `us`).

### 3.4 Reading rules

`reading` is a map:

| Key | Required | Value |
|---|---|---|
| `separation` | yes | `"spaces"` or `"none"`: whether the language separates words with spaces in running text, which the formatter and the contract text follow |
| `prefixes` | no | at most 16 keyword ids whose spellings (one word each) may attach to the start of the next word (2.7) |
| `attach` | no | at most 16 maps `{"word": ID, "before": [CATEGORY, ...]}` or `{"word": ID, "after": [CATEGORY, ...]}`: a word of the vocabulary, spelled in this pack as one word (with `…`, if it takes an argument, only on the side away from its neighbour), that attaches before or after a word of those categories (`pack.bad-attach`, `pack.unknown-category`; `keyword` is no such category) |
| `punctuation` | no | at most 64 entries mapping one character, outside ASCII and outside words, to the ASCII character it stands for: one of `, : ( ) % " = < > + - * / . _`, a digit, or a space (`pack.bad-punctuation`) |
| `multipliers` | no | at most 16 entries mapping a one-word spelling to a power of ten from 10 to 10^18 (`pack.bad-multiplier`) |
| `dates` | no | `{? "read": [PATTERN, ...], "write": PATTERN, ? "months": [NAME, ...]}`: up to 8 forms the pack reads besides ISO, and the form it writes (`pack.bad-date`) |

A date pattern is at most 64 bytes and holds the fields `{Y}`, `{M}`, and `{D}` once each, in braces, with literal text between them that holds no digit; a pattern to read holds no space; the pattern to write may use `{MONTH}` instead of `{M}`, and then `months` gives the twelve month names (each 1 to 64 bytes), and only then. The official English pack writes `{D} {MONTH} {Y}` and reads no form besides ISO; the official Chinese packs read and write `{Y}年{M}月{D}日`.

### 3.5 Messages and sentences

A message or sentence is 1 to 1,000 bytes without control characters. Its placeholders, `{name}`, name parameters of its code or sentence (`pack.bad-placeholder`); a sentence's placeholder may ask for a form of the word it receives, `{party.object}`, which falls back to the word's first spelling. An unknown code or sentence id is `pack.unknown-message` or `pack.unknown-sentence`. Where a pack lacks a message or a sentence, tools use the English pack's.

### 3.6 Pack sets

A source is read with a *pack set*: the official packs, always, and any others given (`--pack FILE`, or the packs a bundle embeds, section 16). In a pack set, Bo never guesses:

- a spelling, a form, a multiplier, or a punctuation alias has one meaning in the whole set: two meanings in one pack are `pack.duplicate-spelling`, across packs `pack.conflict`. The same meaning given by several packs is no conflict (`可` is `kw.can` in both Chinese packs);
- a one-word spelling that a prefix keyword or an attaching word could split into two other words of the set is `pack.ambiguous-attachment` (`每个` would read both as a word for *each* and as `每` + `个`, *per item*, so the Simplified Chinese pack spells *each* `逐个`);
- two packs with one id are `pack.duplicate-id`;
- a pack that says it is official MUST be byte for byte one the compiler carries; else it is `pack.false-official`.

### 3.7 Official packs and digests

The official packs of edition 1 are `en`, `zh-Hant-HK`, and `zh-Hans-CN`, version 5 each, every one complete: every concept of the core but the retired ones, every message, and every sentence but the retired ones (the official vocabulary packs' names, which their files give, 3.9). The official vocabulary packs spell their own words in these languages (3.9), and a pack set holds those words in the language packs of their languages. A pack's *digest* is the hash of its canonical CBOR under a ledger's hash algorithm (SHA-256 or SM3); [`../tests/bo/golden/pack-digests.txt`](../tests/bo/golden/pack-digests.txt) lists those of the official packs, earlier versions included, and of the vocabulary packs. A released version of an official pack never changes: a change is a new version, and a compiler MUST carry every released version of each official pack, so that every source deployed with one rebuilds (section 16).

Version 1 of the three, from before vocabulary packs, is carried in [`../bo/packs/history/`](../bo/packs/history). Version 2 spells the core's kind word `thing` (`物件` in both Chinese packs), spells `we` `我方` first in both Chinese packs (`本公司` remains a second spelling, so `我方` is what tools write), drops the retired concepts, and adds the messages and sentences of vocabulary packs. Version 3 adds the core's unit of temperature (`unit.celsius`, 2.10) and the messages and sentences of field defaults, durations divided by durations (R32), and tests that expect fields' values; version 2 is carried beside version 1. Version 4 spells the core's words alone: the official vocabulary packs' words, commerce's two attaching rules, and the packs' names moved into the packs' files (3.9); it adds the messages of vocabulary pack files (`vocab.*`) and of `check.pack-requires`; version 3 is carried beside versions 1 and 2. Version 5 adds requests (E8): the keywords `request`, `done`, `fails`, and `expires`, the words `executor`, `result`, and `reason`, rule R33, and their messages and sentences; version 4 is carried beside versions 1 to 3, and reads like version 5 but for requests. A keyword added after the first versions (Concept `since`: 5 for these four) is spelled by the official packs from that version on; the official packs of before it, and others' packs, may lack it, and are read and written in English for it, so that the packs embedded in earlier deploys still read. A pack set is built on the official packs of one *release* (3.6): today's (version 5, which reads with version 2 of the official vocabulary packs), version 4 (the same, without requests), version 3 or 2 (which spell the vocabulary packs' words themselves and read with version 1 of those packs), or version 1, from before vocabulary packs. A source read with version 1 uses every vocabulary pack without declaring it (`use` did not exist), and its `record` is today's `thing`; a source read with version 2 reads as today's, but spells no temperature; a source read with version 3 reads as today's. Each compiles to the code it compiled to then.

Anyone MAY write a pack for another language, dialect, or a company's own terms. Such a pack MUST spell every keyword of the first versions, SHOULD spell those added later, and SHOULD spell the vocabulary; it is read beside the official packs, and a deploy embeds it in full.

### 3.8 One tree from any pack

A language pack changes how a source reads and how text is written, never what runs. Every spelling becomes its concept; forms are dropped; names stay as written. So the tree, the model, the code, and the contract text of a source do not depend on which packs, or which languages within them, it was written with, as long as they read it. Since a pack decides how a source reads, a deploy pins the packs its source was read with by their digests (section 16).

### 3.9 Vocabulary packs

A *vocabulary pack* says which concepts exist beyond Bo's core: their categories, the type a field's word gives the field (R1) and whether it is *added* (R20) or *taking* (R31), a unit's dimension and scale, how each language spells them, and the standard terms of its built-in actions (section 8). Unlike a language pack, it changes what runs, so a deploy pins each one it uses by version and digest, and embeds those that are not official in full (section 16). Edition 1 has three official vocabulary packs, version 2 each, compiled in from [`../bo/vocab/`](../bo/vocab):

| Pack | Words | Built-in actions |
|---|---|---|
| `finance` | 24: `asset`; pledge, release, enforce, redeem, split, pay, confirm payment, dispute, freeze, unfreeze; tier, pledgee, payee, portion; pledged, paid, settled, disputed, redeemed, frozen; bank, issuer, supplier | the ten actions, in [`../bo/vocab/finance.vocab`](../bo/vocab/finance.vocab) |
| `commerce` | 22: price, usage, overage, per, setup fee; the ten charge words; invoice, credit note, receipt; refund, credit; customer location; customer | none yet |
| `services` | 12: `service`, `resource`; subscribe, renew, upgrade, downgrade, allocate, reclaim; allocated, cooling; cooling period; traffic | allocate, reclaim, in [`../bo/vocab/services.vocab`](../bo/vocab/services.vocab) |

Appendix B gives every word's pack; `cexchain bo vocab show PACK` lists them with their field facts.

**The pack format.** A vocabulary pack is a file in CBOR diagnostic notation, like a language pack (3.2), whose digest is the hash of its canonical CBOR under the ledger's hash (comments and layout do not count):

```
{"format": 1, "id": "events", "version": 1, "edition": 1,
 ? "requires": ["commerce"],
 "concepts": {"act.reserve": {"category": "action"},
              "field.guest": {"category": "field", "type": "party", "added": true, "taking": true},
              "unit.ticket": {"category": "unit", "dimension": "count", "scale": 1}, ...},
 ? "terms": ["bo 1", "use events", "can reserve to counterparty", "  active -> reserved", ...],
 "languages": {"en": {"name": "events", "words": {"act.reserve": "reserve", ...}, ? "attach": [...]},
               "zh-Hant-HK": {"name": "活動", "words": {"act.reserve": "預留", ...}}, ...}}
```

- `id` is a Bo name in ASCII (lowercase letters, digits, and `_`, starting with a letter, at most 32), as `use` lines write it; `version` is 1 or more; `edition` is the edition the pack is of;
- `requires` lists packs a source using this one MUST use too (`check.pack-requires`), official ones or users', at most 8, none twice, not the pack itself;
- `concepts` holds 1 to 256 concepts, each keyed by its category's prefix and a name of ASCII letters, digits, and `_` (`act.reserve`), with its `category`, which MUST be the prefix's; `"argument": true` for one that takes an argument; a field's `type` (`party`, `date`, `number`, `text`, `duration`, `parties` (a list of at most 16 parties), each fixed by the word; or `quantity`, `list`, `amount`, what the word accepts once a type is given; the official packs also give `offset` and `portion`, which mechanisms read); a party field's flags `added` and `taking`; and a unit's `dimension` (one of the core's: `data`, `bandwidth`, `count`, `mass`, `temperature`) and `scale`, how many of the dimension's smallest unit it is, 1 to 10^15. Flags are written only when true;
- `terms` is a Bo source, as a text or as its lines (none holding a line break), at most 64 KiB: the standard terms of the pack's actions. Read with the pack set, it MUST lex and parse without errors, use the pack and only the packs it requires, use only words of the core, the pack, and those packs, and hold only `can` clauses, each the terms of one of the pack's own actions, once (`vocab.terms`, `vocab.terms-clause`);
- `languages` spells every concept in each language, keyed by a language pack's id, as a language pack's `vocabulary` does (3.3: spellings, forms, `…` for an argument), with the pack's `name` in that language and, for a language written without spaces, `attach` rules for its own words (3.4). Each language MUST spell every concept (`vocab.unspelled`); one spelling has one meaning in the pack (`vocab.duplicate-spelling`).

The official packs' files are of this format; their concept ids are written as they are (`act.pledge`), and only they may define kinds, prices, charges, documents, and words with an argument, which the compiler's mechanisms read. Version 1 of each, from before pack files, is carried in [`../bo/vocab/history/`](../bo/vocab/history): its canonical CBOR is G5's, without `languages` (the official language packs of its release spell its words), and its terms are version 2's.

**Packs of your own.** Anyone MAY write a vocabulary pack for words of their own ("we preset, users customize"): a company's, a field's, an association's. Such a pack MUST NOT have the id `core`, `user`, or an official pack's (`vocab.official-id`); it defines actions (with or without terms), fields, states, roles, and units of the core's dimensions, nothing else (`vocab.category`, `vocab.argument`). Its concepts' ids carry its id (`events:act.reserve`); compiled code names a concept by its plain name (`reserve`), which MUST NOT be that of a core or official word of its category (`vocab.shadows`). A source reads it when it is given (`--vocab FILE`, or embedded in a bundle) and named by a `use` line. In a pack set (3.6), a user's pack's words join the language packs of the languages it spells (a language the set has no pack for is warned of, `vocab.no-language`, and its spellings are not read); each of its spellings and forms MUST be new to the set (`vocab.conflict`); two packs with one id are `vocab.duplicate-id`; each pack it requires MUST be official or given (`vocab.unknown-requires`), and none may require itself through others (`vocab.cycle`). Every problem of a pack file is reported with its code (`vocab.*`, and the shared shapes of `pack.*`): never the first only.

**Using a pack.** A source uses a pack with a line `use ID` outside any block, one line per pack, before or after its other clauses (`bo fmt` writes them first, after `bo N`, by id). The keyword is spelled in any language (`使用 finance`); the id stays as written, ASCII, whatever the token reads as in the packs (`use services`, although `services` is a form of `service`). An id given twice is `parse.duplicate`; `use` anywhere else is `parse.reserved`. An id that names no pack the set reads is `check.unknown-pack`.

**Words of a pack.** A word of a pack the source does not use is `check.pack-not-used`, reported once for each such pack, at its first word, naming the pack: the error tells the reader what to write. A pack's words stay reserved where the pack is not used: Bo never guesses, so `pledge` never silently becomes a name of the contract's own. A built-in action's terms use the core's words, their own pack's, and those of the packs it requires; a contract that declares the action has used its pack. Recognition rules that only a pack's words can reach apply only with that pack (section 7); a user's pack's added fields (R20) and taking fields (R31) work as the official ones do.

## 4. Grammar

The grammar works on tokens (section 2), whose words are concepts, so it is the same in every language. It is written here with English spellings; any spelling of the same concept, in any pack, stands for it.

### 4.1 Summary

```
file        = [ "bo" NUMBER NEWLINE ] { use | clause }
use         = "use" PACK NEWLINE                                (3.9)
clause      = contract | parties | block | can | when | answer | test

contract    = "contract" NAME NEWLINE
parties     = "parties" party { "," party } NEWLINE
party       = ROLE-WORD | NAME
block       = KIND NAME NEWLINE [ INDENT { field NEWLINE } DEDENT ]
KIND        = "thing" | "asset" | "service" | "resource" | "charge" | "tax"
field       = operand [ sum ] { "," sum } [ "=" sum ]           (a default, 6.3)

can         = "can" action { "by" operand | "to" operand | "with" input { "," input } }
              NEWLINE [ body ]
input       = operand [ sum ]
action      = ACTION-WORD | NAME
when        = "when" condition [ do { "and" do } ] NEWLINE [ body ]
answer      = "when" kind OUTCOME [ request | do { "and" do } ] NEWLINE [ body ]   (6.11)
kind        = ACTION-WORD | NAME
OUTCOME     = "done" | "fails" | "expires"                    (contextual, 2.6)
test        = "test" [ NAME | TEXT ] NEWLINE INDENT { step } DEDENT

body        = INDENT { statement } DEDENT
statement   = "if" condition [ inline ] NEWLINE [ body ] { otherwise }
            | "each" NAME "in" condition NEWLINE body
            | condition "requires" condition NEWLINE           (a guarded requirement)
            | condition "can" action NEWLINE                   (AI agent can propose)
            | simple NEWLINE
otherwise   = "otherwise" "if" condition [ inline ] NEWLINE [ body ]
            | "otherwise" [ simple ] NEWLINE [ body ]
inline      = "requires" condition | "reject" TEXT | "->" operand | do { "and" do }
simple      = "requires" condition
            | "reject" TEXT
            | [ condition { "," condition } ] "->" operand      (a state change)
            | do { "and" do }
            | request                                          (6.11)
            | target "=" condition                             (sets a field)
request     = "request" kind { "to" operand
                             | "with" target "=" condition { "," target "=" condition }
                             | WITHIN }                        (each part once; WITHIN required)
WITHIN      = the word `within` with its duration ("within 1 day", "1日內")
target      = NAME | WORD
do          = [ party ] action { operand | "to" operand | "by" operand
                                 | "with" target "=" condition { "," target "=" condition } }

step        = operand action [ OUTCOME ] { operand | "to" operand | "by" operand
                               | "with" target "=" condition { "," target "=" condition } }
              [ expect ] NEWLINE
            | expect NEWLINE                                    (the expectation of the step above)
expect      = "->" operand [ TEXT ] [ "," target "=" condition { "," target "=" condition } ]
            | "->" target "=" condition { "," target "=" condition }   (values of fields, 13.1)

condition   = conjunction { "or" conjunction }
conjunction = negation { "and" negation }
negation    = "not" negation | comparison
comparison  = sum [ ( "=" | "<" | "<=" | ">" | ">=" | "in" ) sum ]
sum         = product { ( "+" | "-" ) product }
product     = phrase { ( "*" | "/" ) phrase }
phrase      = operand { operand }
operand     = ( LITERAL | NAME | WORD
              | HEAD operand | "applies to" condition | OPEN operand CLOSE
              | "(" condition { "," condition } ")" ) { TAIL }
```

`NEWLINE`, `INDENT`, and `DEDENT` come from the lexer (2.2). `LITERAL` is a number, money, a quantity, a duration, a rate, a date, or a text (section 2). `WORD` is a word of the vocabulary (not a keyword); `ROLE-WORD` and `ACTION-WORD` are words of the categories role and action. `HEAD`, `TAIL`, `OPEN`, and `CLOSE` are the pieces of a word with an argument (2.8). The rules the summary cannot show follow.

### 4.2 Clauses

A line outside any block begins a clause (`parse.top-level` otherwise):

- **`contract NAME`** names the contract, once (`parse.duplicate`). A source without it is a *fragment*: it checks with the warning `check.fragment`, and it does not build (`build.fragment`).
- **`parties`** lists the roles, once: role words (`we`, `counterparty`; with their packs `customer`, `supplier`, `bank`, `issuer`) or names of the contract's own.
- **A kind block**, `thing NAME` (or, with their packs, `asset NAME`, `service NAME`, `resource NAME`), describes the instances: one field per line. A contract has one kind block (`check.one-kind`); the kind word is required.
- **A charge block**, `charge NAME` or `tax NAME`, describes a charge: one line per property (section 10).
- **`can ACTION`** declares an action: a word of the vocabulary (a built-in action) or a name (an action of the contract's own), then, in any order and each at most once (`parse.can`, `parse.duplicate`), `by PARTY` (who starts it), `to PARTY` (its counterparty), and `with INPUT, ...` (what each call gives: a name or a field word, then a type), then its block.
- **`when EVENT`** is a time rule: an event (section 9), then the actions it does on the line, joined by `and`, and/or a block (`parse.empty-block` if neither). The event ends where an action begins (4.8); a line whose event is missing is `parse.when`.
- **`when KIND done`**, **`when KIND fails`**, **`when KIND expires`** is a rule for the answers to the contract's requests of KIND (6.11): a `when` line whose second word is a request's kind (an action's word or a name) and whose third is an outcome.
- **`test`**, with an optional name or text, then a block of steps (section 13).

- **`use PACK`** declares a vocabulary pack the source uses (3.9); `use` anywhere else is `parse.reserved`.

### 4.3 Statements

A line in a `can`, `when`, `if`, `otherwise`, or `each` block is a statement (`parse.statement` otherwise):

| Statement | Meaning |
|---|---|
| `requires COND` | a requirement: the call is refused unless COND holds; `requires consent of X` asks for X's consent; `requires in person` asks the starter to prove presence (section 6) |
| `GUARD requires COND` | a requirement that applies only when GUARD holds: `over 5_000_000 requires in person` |
| `AI agent can propose` | AI agents may only propose this action (6.9); the only line of this kind in edition 1 (`check.permit`) |
| `if COND` … `otherwise` … | a choice; a `requires`, a `reject`, a `-> STATE`, or an action may follow the condition on its line (any statement may follow a plain `otherwise`); `otherwise if` chains; `otherwise` must follow an `if` block at the same indentation (`parse.otherwise`) |
| `each NAME in LIST` | the block, once for each item of a bounded list (10.1) |
| `reject TEXT` | refuses the call with the text as its reason |
| `FIELD = VALUE` | sets a field of the instance |
| `FROM, ... -> TO` | a state change: from one of the states FROM, else the call is refused; `-> TO` changes from any state; `-> previous state` returns to the state before the current one |
| `ACTION ...` | does an action (a time rule's block), issues parts (`issue PARTS to RECIPIENTS`, section 11), or asks an executor (section 6.11) |
| `request KIND [to PARTY] [with NAME = VALUE, ...] within N` | asks an executor to act outside the ledger, to be answered within N (6.11) |

A condition alone on a line does nothing and is `parse.bare-condition`. A line with an error adds nothing to the tree; the parser goes on with the next line, and says nothing on a line the lexer already found an error on.

### 4.4 Expressions and precedence

From the loosest to the tightest:

| Level | Operators | Notes |
|---|---|---|
| 1 | `or` | left to right |
| 2 | `and` | left to right |
| 3 | `not` | prefix |
| 4 | `=` `<` `<=` `>` `>=` `in` | at most one per comparison: `a < b < c` is `parse.chained-comparison` |
| 5 | `+` `-` | left to right |
| 6 | `*` `/` | left to right |
| 7 | words side by side (a *phrase*) | `monthly HKD 120`, `overdue 3 days`, `suspended 30 days` |
| 8 | operands, with the words of 2.8 around them | |

A phrase is never an operand of an arithmetic or comparison operator: `monthly HKD 120 * 12` is `parse.phrase-operator`, since which words `*` takes would be a guess; parentheses say which. (`and`, `or`, and `not` may join phrases: `when overdue 3 days and active`.) Parentheses group; nesting (parentheses, operators in a row, `otherwise if` chains) is at most 100 deep on a line (`parse.too-deep`). There is no unary minus on an expression: write `0 - x`; a number written with a `-` directly before its digits is negative (2.9).

### 4.5 Words with an argument

A head or open piece takes exactly one operand as its argument; a tail piece wraps the operand before it. So `consent of bank` and `經 銀行 同意` are one tree, and so are `7 days before due` and `到期前 7日`. An open piece needs its close piece after the operand (`parse.missing-tail`); a close piece without its open piece is `parse.missing-head`; a tail with nothing before it is `parse.missing-argument`. `applies to` alone takes a whole condition (`applies to customer location = 中国内地`). To give a word a list or an expression, use parentheses: `consent of (supplier, bank)`, `(30 days + 2 weeks) before due`.

### 4.6 Lists

`(a, b, c)` is a list. `(a)` only groups, so a list of one item cannot be written; where a list is needed, one value is a list of that one item (R29).

### 4.7 The `=` rule

`=` sets a field when it follows a name or a word at the start of a statement line (`holder = bank`), or a target in a `with` of a step or an action done (`with amount = HKD 100`). At the end of a field's line in a block it gives the field's default (`count number = 0`, 6.3), and after a test's `->` it names a field's value the step expects (`-> delivered, fee = HKD 4_000`, 13.1). Everywhere else it compares (`requires holder = bank`, `if payee = none`).

### 4.8 Where an action begins

An action begins at a word of the category action, or at a name a `can` declares; a party (a role word, or a name in `parties`) just before it is its subject. So in `when due issuer pays` the event is `due`, and `issuer pays` is an action with a subject: a party's duty (R9). Inside a `can` block only the contract acts: a subject there is `check.subject`. A test step always begins with its party (section 13).

## 5. Types and values

### 5.1 Types

Every expression has a type, and every value is kept exactly, as a whole number of its smallest unit within a signed 64-bit integer. There is no floating point anywhere.

| Type | Declared as | Literals | Kept as |
|---|---|---|---|
| number | `number` | `5`, `5_000_000`, `1.5萬` | a whole number |
| money | a currency: `HKD`, `CNY`, `USD`, `SGD`, `EUR` | `HKD 0.10`, `120 HKD`, `500萬港元` | the currency's minor unit (cents: every edition-1 currency has two decimals) |
| quantity | a unit: `MB` `GB` `TB` `MiB` `GiB` `TiB`, `Mbps` `Gbps`, `item`, `kg` `tonne`, `°C` | `2TB`, `100 Mbps`, `1 item`, `3 噸`, `-18.5 °C` | its dimension's base unit (5.3) |
| rate | (no type word: constants and expressions only) | `5%`, `3.875%` | millionths: 1% is 10,000, 100% is 1,000,000 |
| date | `date` | `2027-01-06`, `2027年1月6日` | milliseconds since 1970-01-01T00:00:00Z |
| duration | `day` or `week` (fixed); `month` or `year` (calendar) | `30 days`, `2 weeks`, `1 month`, `3 個月` | fixed: milliseconds; calendar: months (a year is 12) |
| text | `text` | `"203.0.113.7"` | UTF-8 |
| yes or no | `yes or no` (`是否`) | `yes`, `no` | false or true |
| party | (a field that holds a party: 6.3) | roles, party fields, `none` | a 32-byte ledger id; `none` is no party |
| list | `list T [at most N]` | `(HKD 1, HKD 2)` | a list of at most N items of T (5.8) |
| state | (the states of the contract) | state words and names | used as conditions (R7) |
| unit price | (a field's value) | `per GB HKD 0.10` | money per unit, to six decimals |
| recurring amount | (a field's value) | `monthly HKD 120`, `monthly 2TB` | an amount each day, week, month, or year |
| basis | (a charge or tax field) | `according to customer location` | what a charge depends on |

Unit prices, recurring amounts, and bases are checked and explained, but this version of the compiler does not compile a contract that uses them as values (`build.unsupported`): they describe services, whose billing needs executors.

### 5.2 Money

Money is in one currency, kept in its minor unit: `HKD 1.5` is 150. Money of different currencies never mixes (`check.mixed-currencies`): Bo never converts. A literal finer than the minor unit (`HKD 0.001`) is `check.precision`, never a rounding.

### 5.3 Quantities

A quantity has a dimension, and units of one dimension convert exactly:

| Dimension | Base unit | Units |
|---|---|---|
| data | byte | MB = 10^6, GB = 10^9, TB = 10^12, MiB = 2^20, GiB = 2^30, TiB = 2^40 bytes |
| bandwidth | bit per second | Mbps = 10^6, Gbps = 10^9 |
| count | item | item = 1 |
| mass | gram | kg = 10^3, tonne = 10^6 grams |
| temperature | a hundredth of a degree Celsius | °C = 100 hundredths (4.5 °C is 450) |

`2TB = 2_000 GB` holds; TB and TiB are different sizes; quantities of two dimensions never mix (`check.mixed-units`). A quantity finer than its base unit (`0.5 item`, `4.567 °C`) is `check.precision`.

A temperature is kept exactly, like money: to a hundredth of a degree, so readings in tenths (`4.2 °C`) or hundredths (`4.25 °C`) compare, add, and subtract exactly, below zero too (`-18.5 °C`). It is a quantity of its own dimension, so it never mixes with another; like any quantity it may be multiplied or divided by a number or a rate. Bo has no other temperature scale: a Fahrenheit reading is not a multiple of a Celsius one, so it would be a dimension of its own.

### 5.4 Rates

A rate is a percentage kept in millionths, so it holds up to four decimal places of a percent (`3.875%` is 38,750; `0.00001%` is `check.precision`). A share is written as a rate (`150%`), never as a decimal number (`check.whole-number`).

### 5.5 Dates, times, and the UTC offset

A date literal is the moment its day begins at the contract's UTC offset. The offset is fixed for the contract, all year, with no daylight saving: `UTC offset "+09:00"` (`UTC 時差`, `UTC 时差`) in the kind's block, a text of the form `+HH:MM` or `-HH:MM`, minutes at most 59, at most 14:00 either way (`check.utc-offset`); without it, +08:00 (R25). The offset may be given once (`check.duplicate`).

- `now` is the call's registration time (input key 7, spec section 15); `today` is the moment the call's day began at the offset.
- Dates are in the years 1 to 9999 at the offset: computing a date outside them refuses the call (`bo:date`).
- Dates compare and subtract (`date - date` is a fixed duration).

### 5.6 Durations

Days and weeks are fixed durations, kept in milliseconds (a day is 86,400,000). Months and years are calendar durations, kept in months: they have no fixed length, so they never mix with fixed durations, in arithmetic or comparisons (`check.calendar`). A duration literal is a whole number of its unit (`check.whole-number`); a calendar one is at most 120,000 months (10,000 years).

A duration divided by a duration of the same kind (both fixed, or both calendar) is a number: how many whole times the second fits in the first, the rest dropped toward zero (R32). So `(now - due) / 1 day` is the whole days since the due date, 2 for two days and twenty hours; before the due date it is negative or 0, never rounded away from zero. Divided by a duration of the other kind, it is `check.calendar`.

Adding a calendar duration to a date (or a time) moves its local date at the contract's offset by whole months and keeps its time of day; if the new month lacks the day, the day is the month's last: 31 January plus a month is the last day of February. Adding a fixed duration adds its milliseconds.

### 5.7 Texts, yes or no, parties

- A text compares only for equality (and membership: `in`). An undeclared name compared with a text is that text (R18).
- Yes or no values are conditions; `not`, `and`, and `or` combine them.
- A party is a role of the contract or a field that holds one; its value is a ledger id. Parties compare for equality only. `none` is no party: a party field may hold none (6.3), and `none` equals only a field that holds none.

### 5.8 Lists

A list type is written `list T` (or `T list`), with `at most N` anywhere among its words (`codes list text at most 3`, `发票 列表 人民币 最多 20`); T is a type word, a currency, a unit, or a time unit, never a list. A list holds at most 16 items unless `at most N` says otherwise (R16); N is 1 to 1,000 (`check.list-bound`). A list written out, `(a, b)`, has items of one type (`check.list-items`) and is a list of that many items, at most 1,000. One value where a list is needed is a list of that one item (R29). Lists of parties have no type word: the field `recipients` is one (R1). Section 10 says what lists do.

### 5.9 Literals are exact

A literal MUST be a whole number of its type's smallest unit (`check.precision`, `check.whole-number` for numbers and durations) and MUST fit a signed 64-bit integer there (`check.overflow`). A literal `0` beside money, a quantity, a rate, or a duration, in `+`, `-`, or a comparison, is zero of it (R22): `requires portion > 0`. A literal may be negative (2.9): `-18 °C`, `HKD -5`; a list's bound may not (`check.list-bound`).

### 5.10 Operators

| Expression | Operands | Type | Computed |
|---|---|---|---|
| `a + b`, `a - b` | two of one type: number, money (one currency), quantity (one dimension), rate, duration (both fixed or both calendar) | that type | checked addition |
| `d + t`, `t + d`, `d - t` | a date `d` and a duration `t` | date | fixed: milliseconds added; calendar: months added (5.6) |
| `d - e` | two dates | fixed duration | checked subtraction |
| `n * x`, `x * n` | a number `n`, and a number, money, a quantity, a rate, or a duration `x` | x's type | checked multiplication, exact |
| `r * x`, `x * r` | a rate `r`, and money, a quantity, or a rate `x` | x's type | x × r ÷ 1,000,000, rounded half up (R17) |
| `x / n` | a number, money, a quantity, a rate, or a fixed duration `x`, by a number `n` | x's type | x ÷ n, rounded half up (R17) |
| `x / y` | money by money of one currency, or a quantity by a quantity of one dimension | rate | x × 1,000,000 ÷ y, rounded half up (R17) |
| `d / e` | two durations of one kind (fixed, or calendar) | number | d ÷ e, the rest dropped toward zero (R32) |
| `p * q`, `q * p` | a unit price and a quantity of its dimension | money | checked, not compiled (5.1) |
| `a = b` | two of one type: any type but a unit price, a recurring amount, or a basis | yes or no | numbers, texts, and ledger ids by value; lists by their encodings |
| `a < b`, `<=`, `>`, `>=` | two of one ordered type: number, money, quantity, rate, duration, date | yes or no | signed comparison |
| `x in L` | a value and a list of its type | yes or no | true if some item equals x |
| `not a`, `a and b`, `a or b` | yes or no (a state reads as the condition that the instance is in it, R7) | yes or no | `and` and `or` evaluate their right side only when needed |

Every other combination is `check.operands` (or `check.mixed-currencies`, `check.mixed-units`, `check.calendar`). A literal divisor 0 is `check.zero-division`.

### 5.11 Arithmetic

Expressions evaluate left to right, by precedence. Every step is exact or checked:

- Additions, subtractions, multiplications, and list sums whose result is outside the signed 64-bit range refuse the call (`bo:overflow`); so does an intermediate result, even if the whole would fit.
- Products with a rate and quotients compute `a × b ÷ c` with a 128-bit product, then round to a whole number of the smallest unit. Unless a charge says otherwise (10.4), they round *half up*: to the nearest, and a half away from zero (2.5 → 3, −2.5 → −3). Charges may also round *half even* (to the nearest, a half to the even neighbour) or *down* (toward zero). A divisor 0 refuses the call (`bo:division-by-zero`); a result outside the range, `bo:overflow`.
- Values may be negative (money taken away, a credit line, a temperature below zero), and so may literals (2.9). A duration divided by a duration drops the rest toward zero (R32).

## 6. The model

The checker reads a tree into a *model*: the contract's parties, the one kind of instance and its fields, its charges, states, actions, time rules, and tests, with every name resolved and every expression typed. The model holds concepts and names, never spellings. Everything a recognition rule inferred carries the rule's id. Sections 6 to 11 define the model; section 12 defines the code compiled from it.

### 6.1 Names

Every name is declared once (`check.duplicate`): the contract's parties, fields, actions, inputs, states, charges, and the items of `each` (which also may not reuse a declared name) share one namespace. A name used but not declared is `check.unknown-name` (or `check.unknown-party`, `check.unknown-field`, `check.unknown-input`). A contract with actions or time rules needs a `parties` line (`check.no-parties`).

### 6.2 Parties and roles

The parties are the roles of the `parties` line: role words or names of the contract's own. Each role is bound to a ledger:

- **at creation:** the call that creates an instance names its ledger (12.4);
- **by an action**, if the contract first names the role as the counterparty of an action (R3): that action's first call names the ledger, under the role's name, and the role consents; later calls of that action may leave it out or name the same ledger (`bo:argument ROLE` otherwise). A role that the standard library's `allocate` binds is bound again by every allocation, whose argument is then required (R23).

A role stands for the ledger it is bound to. A role used while not yet bound refuses the call (`bo:party ROLE`). A role bound to the home's own ledger agrees through the calls the home makes: the home never consents to its own calls (spec section 15).

### 6.3 The kind and its fields

The core's kind is `thing`; the vocabulary packs add `asset` (finance), `service`, and `resource` (services). The kinds differ only in this: an asset's instances are created by `issue`, every other kind's by `create` (12.2, 11.1, 13.1); on a service, the actions that change a subscription ask executors (R10), and a recurring price makes it due each period (R11); a resource that a built-in action gives a holder gets the field `holder` (R20). The kind block (`thing`, `asset`, `service`, or `resource`, then a name) declares the instances' fields, one per line, `HEAD [VALUE] {, PART}`:

| The line gives | The field is |
|---|---|
| a type: `amount HKD`, `due date`, `codes list text at most 3` | an *instance field*: each instance holds its own value, given when the instance is created, and actions may set it |
| a type, then `=` and a value: `count number = 0`, `late_charge HKD = HKD 0`, `lowest_seen °C = 100 °C` | an instance field with a *default*: each instance starts with the value unless its creation gives the field, which it may (12.4) |
| a party: `holder supplier` | an instance field holding a party, which each instance starts with and actions may change (R2); not given at creation; the party MUST be one bound at creation (`build.late-party`) |
| another value: `IP 1 item`, `cooling period 30 days`, `fee_rate 3%` | a *constant*, the same for every instance; no action can set it (`check.set-constant`) |
| nothing, for a field of the vocabulary that has a type of its own | that type (R1), or for `parts` a list of amounts (R15) |

**Defaults.** A default is a value written out, of the field's type: a number, money, a quantity, a date, a duration, a rate, a text, yes or no, or a list of them (`codes list text at most 3 = ("a", "b")`; one value for a list is a list of one, R29); a negative number is written so (`-18 °C`). An expression is no default (`check.default-value`). A vocabulary field whose type R1 gives may take one without a type (`due = 2027-01-01`). A constant, a party field (which starts with its party, R2), a bill's field (R26), and a charge's line take none (`check.default-field`). The contract text says each: "count: a number; each instance starts with 0 unless its creation gives another."

A field's head is a name of the contract's own, a field word (`amount`, `due`, `holder`, ...), a price word (`price`, `traffic`, `usage`, `overage`, `setup fee`), a document word (`invoice`, `credit note`, `receipt`: the field that holds a bill, R26), or `charge` or `tax` followed by a basis (`tax according to customer location`); anything else is `check.field-head`. A field without type or value is `check.field-needs-type`. Parts after commas are labelled prices only (`traffic monthly 2TB, overage per GB HKD 0.10`; `check.field-values`).

Fields of the vocabulary hold what the vocabulary says (`check.field-type`):

| Field | Holds |
|---|---|
| `holder`, `pledgee`, `payee` | a party (R1 when no type is given) |
| `due` | a date (R1) |
| `tier` | a number (R1) |
| `customer location` | a text (R1); used without a declaration, each instance holds it, given at creation (R12) |
| `cooling period` | a duration (R1: in days or weeks when no value is given) |
| `recipients` | a list of at most 16 parties (R1) |
| `amount`, `portion` | money or a quantity, with its currency or unit |
| `quantity` | a quantity |
| `parts` | a list of amounts in the unit of `amount` (R15) |
| `price` | money, or a recurring amount of money |
| `setup fee` | money |
| `traffic`, `usage` | a quantity, or a recurring quantity |
| `overage` | a unit price |

`UTC offset` in the kind's block is no field: it is the contract's offset (5.5).

**Fields Bo adds.** The pledgee and the payee, and a resource's holder, that an action uses (its own lines or a built-in action's terms) but the contract does not declare are instance fields holding a party, which hold no party until an action sets them (R20); they are not given at creation.

**Fields that may hold no party.** A party field that some action sets to `none` (`pledgee = none`), and one R20 adds, may hold no party. While it holds none, it is null in the instance's state (12.5), it is no party of the instance (12.6), nobody's consent is asked for it, `= none` holds for it, and where a party is needed (`by pledgee`, setting another field to it) the call is refused: `bo:empty FIELD`.

### 6.4 States

An instance is always in one state. The states are those the contract's state changes name, as FROM or TO (R5); the states the standard library's terms name that an instance can reach join them (R19). A state is a word of the vocabulary (`active`, `pledged`) or a name of the contract's own (`signed`).

- **The first state** (R4) is the one state that the contract's own state changes leave from and that no state change leads to. If there is none, it is `active` (added if no state change names it). If several states qualify, it is `check.initial-state`: Bo never guesses.
- **Reachable.** Every state MUST be reachable from the first state through the state changes (`check.unreachable-state`); so MUST a state word used in a condition.
- **`previous state`**, only as the target of a state change (`frozen -> previous state`), returns the instance to the state it was in before its current one. The instance keeps that state (12.5); if it has none, the call is refused (`bo:state ACTION`).
- A state used as a condition holds when the instance is in it (R7); a state the terms name but no instance reaches reads as false.

### 6.5 Actions

`can ACTION` declares an action, of one of two sorts:

- **A built-in action**, a word of the vocabulary: it gets the standard library's terms (R19, section 8), and the lines the contract writes under it come first and add to them. A built-in action without terms in edition 1 is checked but does not build (`build.standard-action`); one that asks an executor (R10) neither (`build.executor`).
- **An action of the contract's own**, a name: it MUST say who starts it, `by PARTY` (`check.needs-by`), and states its own consents and state changes.

An action's parts:

- **`by PARTY`**, its *starter*: a role, or a field that holds a party (`by holder`). The starter agrees by its consent; the home agrees by its call. A built-in action whose terms name no starter is the home's own word (8.1).
- **`to PARTY`**, its *counterparty*: a role, which the action may bind (R3), or `counterparty`, which the contract does not declare: each call then names it, as the input `counterparty`, and it consents (R21). A counterparty that the action makes the holder, the pledgee, or the payee consents to every call, however its role was bound (R31).
- **`with INPUT, ...`**: what each call gives. An input is a name or a field word followed by its type (`with new_amount HKD, new_start date`), by an instance field it is typed like (`with portion quantity`), or nothing, for a field word whose type the vocabulary fixes (`with parts`). A contract may restate an input of a built-in action's terms, with the same type.
- **Its block**: requirements, choices, `each`, refusals, fields set, state changes, and parts issued (section 11), in order.

An action of the contract's own MUST NOT lead back to itself through actions it does (`check.recursion`). Doing an action inside an action is checked, but this version of the compiler does not compile it (`build.unsupported`); time rules do actions (section 9).

### 6.6 Consents

A call of an action needs the agreement of:

1. **its starter** (`by`): the home through the call itself, another ledger through its consent;
2. **the role it binds** (R3), **the counterparty its call names** (R21), or **the counterparty it makes the holder, the pledgee, or the payee** (R31), when that counterparty is a role bound at creation or by another action, or a party field (nobody if it holds none);
3. **the party that a party field held before the call**, for each party field the action's own lines set, unless the action's starter is that field (R8); nobody, if the field held none. R8 adds no consent to a built-in action's terms, which state their own;
4. **every party a `requires consent of X` the call reaches names**: a role, a party field (nobody if it holds none), or a list of parties, each of whom consents.

A counterparty that the action neither binds nor makes the holder, the pledgee, or the payee (a role bound at creation that an action of the contract's own only names, say) adds no consent by itself: if the contract wants it, it writes `requires consent of`. The home never consents (6.2). A consent missing is not a refusal: the call *waits* for it. A call that nothing refuses but that lacks consents ends with `[2, needs]`, naming the ledgers (12.7); a refusal wins over missing consents, so the home learns of a refusal without asking anyone.

### 6.7 Requirements and thresholds

`requires COND` refuses the call unless COND holds (`bo:requires ACTION N`, 12.10). `GUARD requires COND` applies only when GUARD holds. `requires consent of X` asks for consents (6.6), and `requires in person` asks for presence (6.8): neither is a plain condition.

`over N`, only in an action, compares the action's one amount with N, strictly: it holds when the amount is more than N (R6). The action's amount is its one input of money or a quantity; with no such input, the instance's `amount` if that is money or a quantity. A bare number N is in that amount's currency or unit: with an amount in HKD, `over 5_000_000` is over HKD 5,000,000. An action with several such inputs, or none and no amount, has no one amount (`check.threshold-amount`).

### 6.8 Presence

`in person` asks the action's starter to be a person who proves presence with a passkey or a hardware key (R13): the signer of the call when the starter is the home, else the signer of the starter's consent, MUST be of kind 1 (a person) with a presence method (spec section 15, the signer). `requires in person` refuses otherwise (`bo:in-person ACTION`). While the starter's consent is missing, it holds: the call needs that consent anyway, and is checked again when it comes. As a condition (`if in person`), it reads the same way. A time rule never asks presence (`check.when-person`): a keeper calls it.

### 6.9 AI agents and proposals

An AI agent (a signer of kind 2) may start an action within its delegation, as the ledger rules allow (R14). An action whose block says `AI agent can propose` lets agents only propose it:

- A call of the action whose starter's signer is an AI agent (the call's signer, for an action the home starts; else the signer of the starter's consent) is kept as a *proposal* in the instance's `pending` list (12.5), with the event `[propose, ACTION]`; the instance does not change otherwise. Before that, the call is checked for the action's entry states and depth, its arguments, and its starter's agreement; while the starter's consent is missing, the call is an ordinary one, which needs it. An instance keeps at most 16 proposals (`bo:pending`).
- The function `approve` takes `{"function": NAME, "arguments": ARGS}`, finds the first proposal with that function and those arguments (byte for byte), and runs it as the action, every requirement checked then. The approval's starter signer (the caller's, for an action the home starts; else the signer of the starter's consent to the approval) MUST be a person who proves presence (`bo:approve ACTION`); while that consent is missing, the approval needs it. The proposal is removed, and the event `[approve, ACTION]` comes before the state changes. No proposal matching is `bo:proposal`.

Proposals do not lapse and cannot be withdrawn in edition 1.

### 6.10 Final states

A state is *final* when no action can start from it and no time rule can apply in it. An action's *entry states* are read from its block's top-level lines in order, until the first line that may change the state: the FROM states of its first state change, narrowed by each `requires STATE` (or `requires STATE or STATE ...`, without a guard) before it. An action with neither can start from any state, and then no state is final. A time rule that compiles to a function (9.2) can apply in the entry states of the first action it does (or, if it does none, of its block read as an action's), narrowed to the held state its event names (9.1); a rule with neither can apply in any state, and then no state is final. An instance that reaches a final state is final: it takes no more calls (spec section 15). An instance that issues parts ends too (section 11).

### 6.11 Requests and answers

A contract decides, but never acts on the world outside its ledger: replay could not repeat that. It asks instead (E8, spec section 15, "Requests and answers"):

```
request KIND [to PARTY] [with NAME = VALUE, ...] within DURATION
```

- **Where.** In the block of an action, of a time rule, or of a rule for answers (below), anywhere a statement stands but in an `each` block (`check.each-body`): a call makes at most 16 requests, counted over every branch of the function it runs (`check.request-count`; for a time rule, with the actions it does; for the reply, the most of any one rule).
- **KIND** is what is asked: a name (`sync`, `notify_v2`) or an action's word, whose compiled name it takes (`notify`, or `通知` in Chinese, is `notify`). The ledger takes kinds of 1 to 64 bytes, a lowercase ASCII letter then lowercase letters, digits, `.`, `_`, or `-`; a Bo name holds no `.` or `-`, so a kind written in Bo is a lowercase letter then lowercase letters, digits, or `_` (`check.request-kind`). Executors' connectors serve kinds by name; Bo gives them no meaning.
- **`to PARTY`** names the party the request concerns: params key `to`, its ledger id, or null for a party that holds none.
- **`with NAME = VALUE, ...`** gives the request's values, by name (each once, never `to`: `check.duplicate`), computed when the statement runs. Values have a JSON form: numbers, money, quantities, rates, dates, durations (as compiled code keeps them, 12.3), texts, yes or no, parties (ledger ids, which connectors see as hex), and lists of them (`check.request-value`). Together with `to` they are the request's params, a map with text keys, at most 4,096 bytes encoded: a call whose params would exceed it is refused, `bo:request KIND` (a text or a list longer than 4,096 bytes is refused before it is written). Spec section 15 lists what requests may carry: kinds, ledger ids, values the contract holds, amounts, dates, and record and request ids, never names, addresses, or documents' content.
- **`within DURATION`**, a duration written out, from 1 day to 366 days or 12 months (`check.request-within`), sets the deadline: the call's registration time plus the duration (by the calendar for months, 5.6). An executor never starts work after it; a keeper may expire the request once it has passed.

The request goes into the call's accept, key 7, as `{1: KIND, 2: params, 3: deadline, 4: "result"}`, in the order the statements ran; a call that waits for consents makes none. The ledger opens it, with an id it derives from the call (spec section 15), and keeps it open until an answer comes; an instance has at most 64 open requests, and a call that would leave more is refused by the ledger.

**Answers.** Every answer calls one function the compiler adds to a contract that makes requests, `result` (kind 2, R24's keeper may call it too): an executor's (done or failed), a person's by hand, or a keeper's once the deadline has passed (expired). The function takes only answers, which carry the request in input key 9 (`bo:answer` otherwise), and arguments that are null or a map (`bo:arguments`): it reads the answer's `result` and `reason`, texts if the map gives them as texts, else empty texts. It records the event `["answer", {"kind": KIND, "request": ID, "status": "done" / "failed" / "expired"}]`, then runs the rule for the answer, if the contract has one:

```
when KIND done      the request was carried out
when KIND fails     it failed (and, without a rule for expiry, it expired: R33)
when KIND expires   no answer came by its deadline
```

A rule for answers is a `when` line whose event is a request's kind and an outcome, with a block (or a request on its line). One rule for each kind and outcome (`check.answer-twice`); a rule for a kind the contract never requests never applies (`check.answer-unasked`, a warning). In its block, `result` and `reason` are the answer's (2.6): `notice = result`. The ledger records an answer only if the contract accepts it, without consents, or the request stays open; so a rule for answers never refuses and asks no consent: it has no `requires`, `reject`, or action, sets no field that holds a party (R8), and changes the state only with `-> STATE` or `if STATE -> STATE`, never from named states (`check.answer-line`). An answer to an instance that has ended (6.10) is still recorded and its rule still sets fields, but it changes no state and makes no request, as spec section 15 asks. An instance that issues parts makes no requests in this version (`build.unsupported`): its end is not in its state, so an answer could not tell.

**The R10 actions.** `notify`, and on a service `subscribe`, `upgrade`, `downgrade`, `suspend`, `resume`, `terminate`, `allocate`, and `reclaim`, would ask an executor by themselves (R10): such clauses are checked with the warning `check.needs-executor` and explained, but do not build (`build.executor`); a contract writes a `request` instead. The services pack's own requests come with its next version.

**Executors in practice** (*informative*). The home registers an executor (`cexchain executor add NAME --contract C --kinds notify`): an actor whose delegation lets it call `result` on that contract (scope key 8) and answer only those kinds (key 9). `cexchain executor run` finds open requests at the home's server, verifies each in the instance's signed evidence before acting, runs the connector configured for the kind (a `webhook`, a `command`; [`connectors.md`](connectors.md)), and answers with the connector's result, a reason on failure, and a salted digest of the response. `examples/shipment` runs one.

## 7. Recognition rules

Bo infers by the thirty-three rules of edition 1 and by nothing else. Each rule has an id and a name; each official pack gives its text as the sentence `rule-ID`, which the contract text quotes (section 14). The checked model marks what each rule inferred (`{R3}` in `bo check --stage model`), and the contract text marks each clause so inferred (`[R3]` in English, `〔R3〕` in Chinese). A rule never changes meaning once its edition is released.

| Rule | Name | What Bo infers |
|---|---|---|
| R1 | field-meaning | A field of the vocabulary declared without a type has the type its pack gives it (3.9; the core's own fields are the core's): `holder`, `pledgee`, and `payee` a party; `due` a date; `tier` a number; `customer location` a text; `cooling period` a duration in days or weeks; `recipients` a list of at most 16 parties. |
| R2 | party-field | A field given a party (`holder supplier`) holds a party: each instance starts with that party, and actions may change it. |
| R3 | role-binding | A role the contract first names as an action's counterparty (after `to`) is bound to a ledger by that action's first call, with the role's consent; every other role is bound when an instance is created. *First* is in the order of the clauses: the kind block, charges, `can`, and `when` clauses count; the `parties` line and tests do not. |
| R4 | first-state | An instance starts in the one state that the contract's own state changes leave from and none leads to; if there is none, in `active`. |
| R5 | states | The states of an instance are those its state changes name. |
| R6 | threshold | `over N` compares N with the action's one amount (its one input of money or a quantity, else the instance's `amount`); a bare number N is in that amount's currency or unit. |
| R7 | state-condition | A state used as a condition means the instance is in that state. |
| R8 | consent-taken | Setting a field that holds a party takes it from that party, so it needs that party's consent (the party the field held before the call), unless the field is the action's starter. It applies to an action's own lines and a time rule's block, never to a built-in action's terms. |
| R9 | obligation | In a time rule, an action with a subject (`when due issuer pays`) is that party's duty: it says when an instance is due and overdue, and nothing is called. A rule that only states duties compiles to no function. |
| R10 | executor | `notify`, and on a service `subscribe`, `upgrade`, `downgrade`, `suspend`, `resume`, `terminate`, `allocate`, and `reclaim`, ask an executor to act outside the ledger (6.11); they do not build, and a contract writes a `request` instead. |
| R11 | service-due | A service with a recurring price in money is due at the end of each paid period. Rules that count from it are checked and explained but do not build (`build.time-rule`). |
| R12 | customer-location | `customer location` used without a declaration is a text each instance holds, given at creation. |
| R13 | presence | `in person` asks the party that starts the action to prove presence (6.8). |
| R14 | agents | An AI agent may start an action within its delegation, unless the action says `AI agent can propose`; then the agent only proposes, and a person approves (6.9). |
| R15 | parts | `parts` is a list of amounts in the unit of the instance's `amount`. |
| R16 | list-bound | A list holds at most 16 items, unless `at most N` says otherwise. |
| R17 | rounding | A product with a rate, and a quotient, is rounded to the smallest unit, half up (away from zero); so is a charge that names no rounding mode. |
| R18 | bare-text | A name that nothing declares, compared with a text (or listed after `in` with a text on its left), is that text: `客户所在地 = 中国内地` reads `中国内地` as a text. |
| R19 | standard-terms | A built-in action has the standard library's terms (section 8): its starter, its counterparty, its consents, the states it starts from and leads to, and what it changes. The contract's own lines come first and add to them. The terms' states that an instance can reach become the contract's. |
| R20 | standard-fields | The fields a pack marks as *added* (the pledgee and the payee), and a resource's holder, used by an action but not declared, are fields of each instance, holding no party until an action sets them. |
| R21 | counterparty | An action whose counterparty is `counterparty`, a party the contract does not declare, takes its counterparty from each call (the input `counterparty`) and needs its consent; so does a built-in action with a counterparty when the contract writes no `to`. |
| R22 | zero | A bare `0` compared with, added to, or taken from money, a quantity, a rate, or a duration is zero of it. |
| R23 | each-allocation | A role that `allocate` binds is bound again by each allocation, with its consent: a resource goes to one holder at a time, and each allocation names it. |
| R24 | keeper | Each time rule that does something is a function that anyone the home delegates may call, a *keeper*; it applies only once its time has come, once for each such time, and as the contract's own word (section 9). |
| R25 | utc-offset | A contract that names no UTC offset counts dates and days at UTC+08:00. |
| R26 | bill | A field named by a document (`invoice`, `credit note`, `receipt`) holds the lines of a bill. Each time it is set, the charges are computed on it at the time of that call; the instance keeps the bill, and the call records it as an event (section 10). |
| R27 | charges | Charges are computed in the order written, each on the price (each line's amount, or the whole bill's for a charge computed once per bill) unless `according to` names what it is computed on: the price and charges written before it. Added: the base times the rate, added to the total; included: taken out of the price, the price times the rate divided by 100% plus the rates of the included charges that apply. A fixed amount is charged once per bill, or on each line. A charge that does not apply, or has no rate in force, is not charged. |
| R28 | rate-in-force | A charge's rate is the one in force at the bill's time: the rate from the latest date on or before it (from that day's start at the contract's offset), else its own rate. A bill keeps the rate it was made with. |
| R29 | one-item | One value where a list is needed is a list of that one item. |
| R30 | issue-parts | `issue PARTS to RECIPIENTS` makes each part an instance of its own, of the same contract, created by the call; its amount is the part and its holder its recipient; the instance that issued them ends; a part may be split again, at most eight levels down (section 11). |
| R31 | role-taking | An action that makes its counterparty (after `to`) a party field its pack marks as *taking* (the core's holder; finance's pledgee and payee) (`holder = bank`, as the terms of `transfer`, `pledge`, and `allocate` do) needs the counterparty's consent at every call, even when its role was bound when the instance was created or by another action; where the action binds the role (R3), each call names it (R21), or it is a party field the action's own lines set (R8), those rules already ask it. An action that names no counterparty adds none: `enforce` makes its own starter, the pledgee, the holder, and `pay` makes the pledgee or the holder the payee. |
| R32 | whole-times | A duration divided by a duration of the same kind is the number of whole times the second fits in the first; the rest is dropped, toward zero (`(now - due) / 1 day` is 2 two days and twenty hours after the due date). The contract text says so where it divides: "(the time of the call − the due date) ÷ 1 day, in whole times (the rest dropped)". |

| R33 | expired-fails | An answer that a request expired (no answer by its deadline) runs the contract's rule for that kind's failures, unless the contract has a rule for its expiry (6.11). |

The rule texts in the packs are plain-language summaries of the rows above; the rows, sections 6 to 11, and the conformance suite define the rules.

Rules belong to the core, except those that only a vocabulary pack's words can reach, which apply only in a source that uses the pack: R10's service half (the services pack's actions on a service), R11, and R23 (`services`); R12 and R26 to R28 (`commerce`). R1, R20, and R31 read their facts from the packs (3.9). Rule ids do not change with packs, so contract texts keep their marks.

## 8. The standard library

### 8.1 Built-in actions

The standard library is Bo sources of edition 1 in English, which every compiler carries: one `can` clause per built-in action, its *terms*, in one source for the core and one in each vocabulary pack with terms (its `terms`, 3.9):

- [`core.bo`](../bo/stdlib/core.bo): `transfer` and `cancel`, and `suspend`, `resume`, and `terminate`, which end or pause any instance;
- the terms of [`finance.vocab`](../bo/vocab/finance.vocab), the `finance` pack (they begin `use finance`): `pledge`, `release`, `enforce`, `redeem`, `pay`, `confirm payment`, `dispute`, `freeze`, `unfreeze`, and `split`, with the semantics that CexChain's native assets had in spec revisions v0.5 to v0.8 (v0.9 removed native assets; spec section 13 now says when a party may rely on an instance's state);
- the terms of [`services.vocab`](../bo/vocab/services.vocab), the `services` pack: `allocate` and `reclaim`, which allocate a resource to one holder at a time.

The `commerce` pack's actions have no terms yet. A user's vocabulary pack brings the terms of its own actions the same way (3.9). A pack's terms use the core's words, its own, and those of the packs it requires; they are part of its canonical CBOR, so its digest covers them (3.9). A contract that declares a built-in action (`can transfer to buyer`) gets a copy of its terms (R19):

- **Counterparty.** The contract's `to` takes the place of `counterparty` in the terms. Without `to`, `counterparty` stays, which the contract does not declare: each call names it (the input `counterparty`) and it consents (R21). The contract MUST NOT give `to` to an action whose terms have no counterparty (`check.standard-to`).
- **Starter.** The terms' `by` is the action's starter; the contract MAY repeat it but MUST NOT name another (`check.standard-by`). An action whose terms name no starter is *the home's own word*: the home starts it, nobody's consent is needed for that, and the signer of the call stands for the starter (for presence and proposals).
- **Order.** The contract's own lines under `can ACTION` come first, then the terms'. The contract's lines MUST NOT change the state, nor set a field the terms set (`check.standard-change`). Requirements are numbered through both, the contract's first (12.10).
- **Inputs.** The terms' inputs are the action's; the contract MAY restate one with the same type (`can split with parts`), and MAY add its own.
- **Fields.** Every field the terms use, other than their inputs and the fields Bo adds (R20), MUST be a field of the instance, and one the terms set MUST be an instance field (`check.standard-field`); one they only read may be a constant (a resource's `cooling period`).
- **States.** The terms assume an instance starts `active`. The states their state changes name that an instance can reach from the first state become the contract's (R19); the others are none of the contract's: they are dropped from the terms' FROM lists and read as false in conditions. An action whose terms can start only from states no instance reaches is `check.standard-unreachable`.
- **Consents.** The terms state their own, and their counterparty consents by R3, R21, or R31; R8 adds none to them.
- **Refusal first by state.** A call of a built-in action in a state it cannot start from is refused before its arguments are read or anyone is asked: `bo:state ACTION` (12.8). An action of the contract's own is refused by its state change, where it stands in its block.

A time rule may do a built-in action that no `can` declares (`when overdue 3 days suspend`): the action then has its terms, but no function of its own, and only the contract's time rules do it.

### 8.2 The terms

The terms of edition 1, as the library writes them (its comments are informative), each file without its opening comment. The core's (`core.bo`):

```
# The holder hands the thing over: the counterparty becomes its holder. Both
# consent to every transfer, the holder by starting it (the counterparty by
# R3, R21, or R31). Only an active thing is handed over (so not while
# pledged, under the finance pack).
can transfer to counterparty by holder
  requires not counterparty = holder
  active -> active
  holder = counterparty

# The holder cancels the thing.
can cancel by holder
  active -> cancelled

# The home suspends the instance on its own word, such as when it is overdue
# (when overdue 3 days suspend).
can suspend
  active -> suspended

# The home resumes a suspended instance.
can resume
  suspended -> active

# The home ends the instance, active or suspended: nothing can start from
# terminated.
can terminate
  active, suspended -> terminated
```

The `finance` pack's (its terms, in `finance.vocab`, which begin `bo 1` and `use finance`):

```
# The holder pledges the asset to the counterparty, which becomes its pledgee.
# Both consent to every pledge. Only an active asset can be pledged: no second
# pledge.
can pledge to counterparty by holder
  requires not counterparty = holder
  active -> pledged
  pledgee = counterparty

# The pledgee gives its pledge up.
can release by pledgee
  pledged -> active
  pledgee = none

# The pledgee takes the asset: it becomes the holder. The holder agreed to
# this when it pledged the asset, so only the pledgee consents.
can enforce by pledgee
  pledged -> active
  holder = pledgee
  pledgee = none

# The holder takes goods out (a warehouse receipt); the pledgee consents while
# the receipt is pledged. When nothing remains, it is redeemed.
can redeem by holder with portion quantity
  requires active or pledged
  if pledged requires consent of pledgee
  requires portion > 0
  requires portion <= quantity
  quantity = quantity - portion
  if quantity = 0
    pledgee = none
    -> redeemed

# The debtor says it paid (a receivable), on the home's own word: the payee is
# the pledgee if there is one, else the holder, and stays the same when the
# debtor pays again after a dispute.
can pay
  active, pledged, disputed -> paid
  if payee = none
    if pledgee = none
      payee = holder
    otherwise
      payee = pledgee

# The payee confirms it was paid.
can confirm payment by payee
  paid, disputed -> settled

# The payee says it was not paid.
can dispute by payee
  paid -> disputed

# The home freezes the asset on its own word, such as under a court order.
can freeze
  active, pledged, paid, disputed -> frozen

# The home unfreezes it: it returns to the state it was frozen in.
can unfreeze
  frozen -> previous state

# The holder splits the asset into parts, one for each recipient, so that its
# own suppliers can hold, pledge, and be paid each part (multi-tier transfer).
# The parts add up to the amount, each at least the currency's smallest unit;
# the holder may keep a part. The holder and every recipient consent: at most
# 15 recipients besides the holder, as a call cites at most 16 consents. Each
# part becomes an instance of its own, held by its recipient, one tier down
# (R30); the asset ends, divided. Only an active asset splits, so not while
# pledged; a part at depth 8 splits no further.
can split by holder with parts, recipients
  requires count of recipients = count of parts
  requires count of recipients <= 15 or holder in recipients
  each part in parts
    requires part > 0
  requires sum of parts = amount
  requires consent of recipients
  active -> divided
  issue parts to recipients with tier = tier + 1
```

The `services` pack's (its terms, in `services.vocab`, which begin `bo 1` and `use services`):

```
# The home allocates the resource to the counterparty, which becomes its holder
# and consents to every allocation (R31 if its role was bound before); one the
# allocation binds is named by each allocation (R23). After a reclaim the
# resource cools: it is allocated again only once its cooling period has passed
# since the reclaim.
can allocate to counterparty
  if cooling requires not within cooling period
  active, cooling -> allocated
  holder = counterparty

# The home takes the resource back from its holder; it then cools.
can reclaim
  allocated -> cooling
  holder = none
```

### 8.3 In short

| Action | Pack | Function | Starter | Counterparty | From | To |
|---|---|---|---|---|---|---|
| transfer | core | `transfer` | the holder | consents, every time | active | active (the holder becomes the counterparty) |
| cancel | core | `cancel` | the holder | | active | cancelled |
| suspend | core | `suspend` | the home | | active | suspended |
| resume | core | `resume` | the home | | suspended | active |
| terminate | core | `terminate` | the home | | active, suspended | terminated |
| pledge | finance | `pledge` | the holder | consents, every time | active | pledged (the pledgee is the counterparty) |
| release | finance | `release` | the pledgee | | pledged | active (no pledgee) |
| enforce | finance | `enforce` | the pledgee | | pledged | active (the pledgee becomes the holder) |
| redeem | finance | `redeem` | the holder | | active, pledged | unchanged, or redeemed when nothing remains |
| pay | finance | `pay` | the home | | active, pledged, disputed | paid (a payee not yet set becomes the pledgee, else the holder) |
| confirm payment | finance | `confirm_payment` | the payee | | paid, disputed | settled |
| dispute | finance | `dispute` | the payee | | paid | disputed |
| freeze | finance | `freeze` | the home | | active, pledged, paid, disputed | frozen |
| unfreeze | finance | `unfreeze` | the home | | frozen | the state before |
| split | finance | `split` | the holder | | active | divided (section 11) |
| allocate | services | `allocate` | the home | consents, every time (R23) | active, cooling | allocated (the holder is the counterparty) |
| reclaim | services | `reclaim` | the home | | allocated | cooling (no holder) |

Each built-in action's starter, if it is not the home, consents by starting it; its counterparty consents to every call, as with the native assets: through R3 (a role the action binds), R21 (a counterparty each call names), or R31 (a role bound at creation or by another action, which the action makes the holder or the pledgee). With `can pledge to bank`, the bank is bound by the first pledge (R3), so a later pledge, after a release, goes to the same bank, which consents again; with `can pledge`, each pledge names its pledgee (R21), as the native assets do; with a bank bound at creation (a field `banker bank`, say), each pledge to it asks its consent (R31). `enforce` names no counterparty: the pledgee starts it and takes the asset with its own consent alone, since the holder agreed when it pledged the asset, as with the native assets; `pay` names none either, and the home pays on its own word. Unlike the native assets, the terms do not refuse a counterparty that is the home itself.

The other actions of the vocabulary (the core's `issue`, `create`, `approve`, `propose`, and `notify`; commerce's `refund` and `credit`; services' `subscribe`, `renew`, `upgrade`, and `downgrade`) have no terms in edition 1: a `can` of one is checked, but does not build (`build.standard-action`, or `build.executor` for an executor's). `issue` and `create` are the creation words: of tests (13.1) and of parts (section 11).

### 8.4 Changing a built-in action

A built-in word always means its terms plus what the contract adds, never anything else. To change a built-in action, a contract copies its terms under a name of its own; it is then the contract's own action, checked, compiled, and explained like any other. `cexchain bo stdlib show ACTION [--language L]` prints the terms in any language, to copy:

```
can lodge to counterparty by holder
  requires not counterparty = holder
  active -> pledged
  pledgee = counterparty
```

`lodge` then acts as `pledge` does, call for call (the counterparty, named by each call, consents by R21; the pledgee is a field Bo adds by R20).

### 8.5 Stability

The standard library is part of its edition: once edition 1 is released, the core's terms never change what a built-in action means, and a pack's terms change only with a new version of the pack, which a compiler carries beside the earlier ones. A later edition may add terms (for actions that have none yet) and actions.

## 9. Time rules and keepers

A ledger acts only on calls. A `when` rule therefore compiles to a function, which anyone the home delegates may call: a *keeper*, usually a device of the home that calls it on a schedule (R24). The ledger's registration time decides whether the rule applies.

### 9.1 Events

A rule's event MUST name exactly one time (`check.when-event`), one of:

| Event | Its time | Example |
|---|---|---|
| a date | the date's value | `when due`, `when due + 1 month`, `when 2027-12-31` |
| N before due | the due date less N | `when 7 days before due` |
| overdue | the day after the due date: the due date plus a day | `when overdue` |
| overdue N | the due date plus N | `when overdue 3 days` |
| a state held N | N after the instance last changed state, while it is in that state | `when suspended 30 days` |

The time MAY be joined to other conditions with `and` (`when 7 days before due and active`): the rule applies only while they hold. It MUST NOT be inside `or` or `not`, and an event names no second time. `now`, `today`, `within`, and recurrences (`monthly`) name no time a rule can wait for, and a date in an event MUST NOT use them. A date is an operand of `and` only in an event. N is a duration; calendar durations move by months (5.6).

*Due* is the instance's `due` field, a date (`check.needs-due` without one). For a service with a recurring price, due is the end of each paid period (R11): such rules are checked and explained but do not build (`build.time-rule`), since executors keep what was paid.

Example: with a due date of 30 June, `overdue` begins on 1 July, `overdue 3 days` on 3 July, and `7 days before due` on 23 June, each at the start of the day at the contract's offset.

### 9.2 Functions

Every rule that does something (an action on its line, a block, or a consent it asks) compiles to a function of kind 2. Its name is `when.` followed by the function name of the first action it does (`when.suspend`); if it does none, the kind of the first request it makes (`when.remind`, 6.11); else the name of the state its first state change leads to (`when.closed`; `when.previous` for `previous state`); else `when.rule`. A name an earlier rule took gets `.2`, `.3`, and so on (`when.suspend.2`). A rule that only states duties (9.6) has no function.

### 9.3 When a rule applies

A call of a rule's function is checked in this order:

1. its arguments MUST be null or an empty map (`bo:arguments`);
2. for a held state: the instance MUST be in that state (`bo:when RULE`);
3. the rule's time MUST be at or before the call's registration time (`bo:when RULE`);
4. each condition joined to the time MUST hold (`bo:when RULE`);
5. the rule MUST NOT have applied for that same time already (`bo:fired RULE`).

RULE is the function's name: `bo:when when.suspend`. The instance keeps, for each rule, the time it last applied for (12.5), so a rule applies once for each time: if the time moves (a due date extended), the rule applies again at the new time. A refused call records nothing, so a keeper that calls early does no harm.

### 9.4 What a rule does

A rule is the contract's own word: no starter agrees, and the actions it does need no starter's consent. Once it applies, in order:

1. its consents (R8, for party fields its block sets) are asked;
2. each action on its line, then its block in order (an action in the block runs where it stands). An action a rule does runs under that action's own clauses: a built-in action is first refused in a state it cannot start from (`bo:state ACTION`); then the action's R8 consents are asked; then its block runs, its requirements numbered as the action's (`bo:requires suspend 1`);
3. requirements in the rule's own block are numbered from 1 for the rule: `bo:requires when.suspend 1`;
4. the time it applied for is recorded.

An action a rule does MUST NOT name a counterparty or take inputs, and the rule MUST NOT give it `to`, `by`, `with`, or arguments (`check.when-action`): a keeper's call gives no arguments. Nothing in a rule asks presence, and no rule lets agents propose (`check.when-person`). A rule never issues parts (`check.parts-place`).

### 9.5 The event and the state

An accepted call of a rule reports, before its state changes, the event

```
["when", {"late": LATE, "rule": "when.suspend", "time": TIME}]
```

where TIME is the rule's time and LATE the registration time less TIME, in milliseconds: how late the keeper came. The instance's state holds `"fired": {FUNCTION: TIME or null, ...}` for every rule with a function, and, for a contract that asks how long a state has been held (`within N`, or a held state), `"since"`: the time of the instance's last change of state, its creation included.

For a thing due on 2027-06-30 (UTC+08:00) and `when overdue 3 days suspend`, a keeper's call registered at 2027-07-03T00:00+08:00 is accepted with the events `["when", {"late": 0, "rule": "when.suspend", "time": 1814544000000}]` and `["suspended", null]`; one registered a day earlier is refused, `bo:when when.suspend`; a second call for the same due date, `bo:fired when.suspend`.

### 9.6 Duties

An action with a subject in a time rule, `when due issuer pays`, states that party's duty (R9): it says when the instance is due and overdue, the contract text states it, and nothing is called. A rule that only states duties has no function.

### 9.7 Conditions on time in actions

In actions and rules:

| Condition | Holds when |
|---|---|
| `within N` | less than N has passed since the instance last changed state: now < since + N |
| `not within N` | N or more has passed since then |
| `overdue` | now ≥ due + 1 day |
| `overdue N` | now ≥ due + N |
| `N before due` | now ≥ due − N |
| `STATE N` | the instance is in STATE, and now ≥ since + N |

*now* is the call's registration time. `within` and held states need `since`, which compiled code then keeps.

### 9.8 Keepers in practice

*This section is informative.* A keeper is a device actor of the home with a delegation for contract calls, limited to the contract by scope key 7 (spec section 15). It calls `contract call INSTANCE when.RULE` on a schedule; `contract call --dry-run --at TIME` asks whether a rule's time has come without recording anything. A keeper on a computer that is sometimes off fires late, never early, and the event shows how late.

## 10. Lists, charges, and bills

### 10.1 Lists

A field, an input, or a constant may be a list (5.8); so may a list written out in an expression.

- **Reading.** A list given as an argument or at creation MUST be an array of at most its bound of items, each of its item type; otherwise the call is refused, `bo:argument NAME`. An empty array is a list of no items. (A list written out holds at least one item.)
- **`each NAME in LIST`** runs its block once for each item, in order, with NAME standing for the item. The block MAY hold requirements, choices, refusals, and fields set; it MUST NOT change the state or do an action (`check.each-body`), since it runs once per item. Its requirements are numbered once, as the block is written (12.10). Loops nest; each is bounded by its list.
- **`sum of LIST`** is the checked sum of its items (money, quantities, numbers, rates, or durations), 0 for no items. **`count of LIST`** is the number of its items, a number.
- **`X in LIST`** holds when some item equals X; a party field that holds none is in no list.
- **`=`** compares two lists of one item type by their encodings: the same items in the same order.
- **Storing a list.** A list field MAY be set from an input, from another list field, or from a list written out of literals and `yes`/`no`. A list built at run time from other values (`signers = (customer, bank)`) does not build in this version (`build.unsupported`). A list written out MAY hold any values where it is read item by item: after `in`, `each`, `sum of`, `count of`, and `consent of`.
- Lists of parties are the `recipients` field or input (R1), or written out of roles and party fields.

### 10.2 Bills

A field of the kind's block named by a document, `invoice`, `credit note`, or `receipt`, holds the *lines of a bill*: it MUST be a list of money in one currency, and a contract has at most one (`check.document`):

```
use commerce

thing Table
  invoice list HKD at most 10
```

Each time the field is set, a bill is made (R26): when an instance is created (the field is given then), and whenever an action or a time rule sets it. The bill is made at the call's registration time, on the lines just set, with the instance as it is at that point of the call; the instance keeps it as it was made, and a later rate never changes it. Only new lines make a new bill. A contract with charges MUST have a bill (`check.charge-document`).

### 10.3 Charges

Taxes, fees, commissions, and surcharges are *charges*, which the contract defines: there are no built-in tax templates. A charge is a block, `charge NAME` or `tax NAME` (the two differ only in how the contract text names them), of lines:

| Line | Meaning |
|---|---|
| `rate R` | its rate |
| `from DATE on rate R` | its rate from the start of that day on (R28); the date MUST be written out, and each date once |
| `amount M` | a fixed amount, money in the bill's currency |
| `applies to COND` | it applies only when COND holds |
| `included` or `added` | it is included in the price (taken out of it) or added to it: exactly one (`check.charge-included`) |
| `per line [MODE]` | computed (and, for a fixed amount, charged) on each line: the default for a rate |
| `per document [MODE]` | computed once per bill: the default for a fixed amount |
| `according to DOCUMENT [MODE]` | once per bill; DOCUMENT MUST be the bill's (`check.charge-bill`) |
| `MODE` | its rounding mode, on each line: `half up` (the default, R17), `half even`, or `down` |
| `according to price, NAME, ...` | what it is computed on: the price, and charges written before it (R27) |

A charge has a rate (its plain rate, dated rates, or both) or a fixed amount, not both (`check.charge-rate`). Each kind of line is said once (`check.charge-twice`); `per line`, `per document`, `according to DOCUMENT`, and a mode alone are one kind, the rounding. A fixed amount is never rounded (`check.charge-rounding`) and is computed on nothing (`check.charge-on`). An included charge is computed on the price only, and a charge computed on each line only on charges computed on each line (`check.charge-on`). Any other line is `check.charge-field`. Charge names are names of the contract (6.1); a contract has at most 64 charges (`build.too-many-charges`).

### 10.4 How a bill is computed

Given the lines L1 … Ln (in minor units) and the call's registration time T, a bill is computed as follows, in this order. All arithmetic is checked (5.11); `round(a × b ÷ c)` is the exact product and quotient rounded in the charge's mode.

1. **Applies, and the rate in force.** For each charge, in the order written: it *applies* if it has no `applies to`, or its condition holds on the instance. Its rate is its plain rate; then, for each `from DATE on rate R` in date order whose day starts (at the contract's offset) at or before T, R. A charge with only dated rates, none of which is in force, does not apply (R28).
2. **The divisor.** D = 100% + the rates of the included charges with a rate that apply (100% is 1,000,000).
3. **The price.** P = L1 + … + Ln.
4. **Charges on each line.** For each line Li, for each charge computed on each line, in the order written: if it does not apply, 0; a fixed amount, its amount; otherwise round(B × rate ÷ C), where C is 100% for an added charge and D for an included one, and the base B is Li if the charge is computed on the price (the default), plus the line's amounts of the earlier charges it names. A charge's amount on the bill is the sum of its line amounts.
5. **Charges once per bill.** Then, for each charge computed once per bill, in the order written: if it does not apply, 0; a fixed amount, its amount; otherwise round(B × rate ÷ C), with C as above and B the price P (if computed on the price) plus the bill's amounts of the earlier charges it names.
6. **The total.** The price plus the amount of every added charge. Included charges are part of the price already.

The price in an added charge's base is the price as written, even when included charges are in it; included charges on the same price share one divisor, which is right for taxes on the same net price.

### 10.5 The bill in the state, and its event

The instance's state holds the bill (12.5) as

```
"bill": {"time": T, ? "lines": [{CHARGE: AMOUNT, ...}, ...], "price": P, "total": TOTAL,
         "charges": {CHARGE: {? "rate": RATE, "amount": AMOUNT}, ...}}
```

- `time`: the registration time it was made at, in milliseconds;
- `lines`: present when the contract has a charge computed on each line: one map per line, in line order, each charge on each line that applies with its amount on that line;
- `price`, `total`: as computed (10.4), in minor units;
- `charges`: each charge that applies, by name, with `rate` (in millionths, the rate in force) for a charge with a rate, and `amount`, its amount on the bill.

Keys are in canonical order (`time`, `lines`, `price`, `total`, `charges`; charges by their encodings). A call that makes a bill reports it as the event `[DOCUMENT, BILL]` after its state changes, where DOCUMENT is the bill field's name in compiled code (`invoice`, `credit_note`, or `receipt`) and BILL the same map as the state's. A call that does not make one keeps the bill as it was, byte for byte.

### 10.6 Charges in expressions

In an action or a time rule, a charge's name is its amount on the instance's bill, in the bill's currency: as made in this call if the call has made one so far, else as kept; 0 when it does not apply. So a payment can be required to equal the total:

```
can settle by customer with payment HKD
  requires payment = sum of invoice + gratuity + levy + vat + surcharge + green
  active -> settled
```

### 10.7 Example

```
use commerce
contract Dinner
parties we, customer

thing Table
  invoice list HKD at most 10

charge gratuity
  rate 10%
  added
  per line half even

charge levy
  amount HKD 2
  added

tax vat
  rate 5%
  added
  according to price, gratuity
  according to invoice down

charge surcharge
  rate 7%
  added
  according to vat
  per document

tax tourism
  rate 3%
  included

charge green
  from 2027-07-01 on rate 1%
  applies to count of invoice >= 3
  added
```

Lines of HKD 12.35 and 8.45 (1,235 and 845 cents; a price of 2,080), billed on 30 June 2027:

- gratuity, 10% on each line, half even: 123.5 → 124, 84.5 → 84; 208 in all;
- levy: 200, once;
- vat, 5% of the price and the gratuity (2,288), once, down: 114.4 → 114;
- surcharge, 7% of the vat, half up: 7.98 → 8;
- tourism, 3% included, on each line: 1,235 × 3% ÷ 103% = 35.97 → 36, and 845 × 3% ÷ 103% = 24.61 → 25 (in the price, not added);
- green: no rate before 1 July 2027, so it does not apply;
- total: 2,080 + 208 + 200 + 114 + 8 = 2,610 (HKD 26.10).

The state keeps `"bill": {"time": ..., "lines": [{"tourism": 36, "gratuity": 124}, {"tourism": 25, "gratuity": 84}], "price": 2080, "total": 2610, "charges": {"vat": {"rate": 50000, "amount": 114}, "levy": {"amount": 200}, "tourism": {"rate": 30000, "amount": 61}, "gratuity": {"rate": 100000, "amount": 208}, "surcharge": {"rate": 70000, "amount": 8}}}`. [`../tests/bo/golden/test/charges/`](../tests/bo/golden/test/charges) and [`test/tax/`](../tests/bo/golden/test/tax) hold such contracts with their arithmetic.

## 11. Splitting and parts

### 11.1 Issuing parts

An action may make *parts* of its instance, each an instance of the same contract created by the call (spec section 15, "Instances created by a call"; R30):

```
issue PARTS to RECIPIENTS [with FIELD = VALUE, ...]
```

- The word is the kind's creation word: `issue` for an asset, `create` otherwise.
- It MUST stand in an action's own block, once, never under `if` or `each`, and never in a time rule (`check.parts-place`).
- PARTS MUST be a list of amounts in the unit of the instance's amount, and RECIPIENTS a list of parties of at most 16, each named by an input or a field; `with` MAY set fields of the instance other than `amount` and `holder` (`check.parts-shape`).
- The instance MUST have an instance field `amount` (money or a quantity) and an instance field `holder` (a party), and no bill (`check.parts-instance`).

When the statement runs, PARTS and RECIPIENTS MUST be equally long and not empty, else the call is refused, `bo:parts ACTION`. The `with` values are computed then, on this instance.

### 11.2 What happens

An accepted call that issued parts ends its instance: the output says it is final (key 5), whatever its state. Its key 6 lists one child per part, in the order of PARTS, each `{1: state, 2: status, ? 3: parties}` (spec section 15; key 3 when the part has any party), where the part's state is in the format of 12.5 and holds:

- the instance's fields as they are at the end of the call, except: `amount`, the part; `holder`, the recipient in the same place; the fields `with` sets, their values as computed; and the fields Bo adds (R20), none;
- the first state; `since` (if kept), the call's registration time; every rule unfired; no proposals; no previous state.

A part's status is its state's name, and its parties are the roles bound at creation and its party fields; roles bound by actions are unbound in a part (a tier-3 holder pledges to its own bank). A part's id derives from the call's id and its position (spec section 15).

### 11.3 Depth

An instance created by a creation has depth 0, a part its parent's depth plus 1, at most 8. An action that issues parts reads the instance view's `[parent, depth]` (input key 5, key 6) right after its entry states, and on a part at depth 8 the call is refused, `bo:depth ACTION`, before its arguments are read or anyone is asked. The ledger refuses such a call too.

### 11.4 The library's split

`can split` gives an asset the standard library's split (8.2). A call of it is checked in this order:

1. the instance is `active`, else `bo:state split`;
2. it is no part at depth 8, else `bo:depth split`;
3. its arguments are `{"parts": [...], "recipients": [...]}`, else `bo:arguments`, `bo:argument parts`, or `bo:argument recipients`;
4. the holder agrees (its consent, or the home's call);
5. the contract's own lines under `can split`, numbered from 1 (`requires tier < 5` is requirement 1);
6. the terms' requirements: as many recipients as parts; at most 15 recipients unless the holder is one of them (a call cites at most 16 consents); each part more than 0; the parts add up to the amount; then every recipient's consent is asked;
7. the instance becomes `divided`, and the parts are issued, each one tier down (`tier = tier + 1`).

Refusals win over missing consents: a call whose parts do not add up is refused, `bo:requires split N`, without asking anyone.

### 11.5 Privacy

Whoever holds or verifies a part sees the history of every instance it came from, up to the call that split it: the other parts of each split, their holders, and their amounts included (spec section 17). The contract text states it.

### 11.6 Example

```
use finance
contract MultiTierReceivable
parties issuer, supplier

asset Receivable
  amount CNY
  due date
  tier number
  holder supplier

can split
  requires tier < 5
can transfer
can pledge
  over 5_000_000 requires in person
can release
can pay
can confirm payment
when due issuer pays

test "split across three tiers, financed by a bank, paid at maturity"
  issuer issue with amount = CNY 1_000_000, due = 2027-06-30, tier = 1
  supplier split with parts = (CNY 600_000, CNY 400_000), recipients = (gears, castings) -> divided
  gears split with parts = (CNY 250_000, CNY 350_000), recipients = (forge, gears) -> divided
  forge pledge to bank1 -> pledged
  issuer pay forge at 2027-06-30 -> paid
  bank1 confirm payment -> settled
```

The supplier splits the receivable between two of its own suppliers; one of them splits its part again, keeping a share; the forge pledges its tier-3 part to a bank; the issuer pays it at maturity, to the bank, which confirms.

## 12. Compiled contracts

A contract compiles to a module in the contract profile (spec section 14.1) that reads the call's input and writes its output as spec section 15 defines them. This section says what that code does; any conforming compiler's code MUST do the same.

### 12.1 Names in compiled code

Compiled code names a concept by its id without the category (`act.pledge` is `pledge`, `act.confirm_payment` `confirm_payment`, `field.customer_location` `customer_location`, `role.we` `we`, `state.active` `active`, `doc.invoice` `invoice`), and a name of the contract's own as written (`sign`, `结算`). These names are the same whatever language the source is written in. Each is 1 to 64 bytes (`build.name-too-long`), and they MUST be distinct (`build.name-taken`) among the functions; among the fields; among the roles and the fields that hold a party (which share the parties map, 12.6); among an action's inputs and the role it binds; and among the states.

### 12.2 The interface

| Function | Kind | When |
|---|---|---|
| `issue` for an asset, `create` for any other kind | 1 (creates an instance) | always |
| each action a `can` declares, by its name (12.1) | 2 (acts on one) | always, but for actions only time rules do |
| `approve` | 2 | when some action lets AI agents only propose it (6.9) |
| `when.X`, `when.X.2`, ... | 2 | for each time rule with code (9.2) |
| `result` | 2 | when the contract makes requests: every answer calls it (6.11) |

A call naming any other function is refused, `bo:function`. A contract has at most 256 functions (`build.too-many-functions`).

### 12.3 Values

Arguments and the instance's state hold values as deterministic CBOR:

| Type | Encoded as |
|---|---|
| number | an integer |
| money | an integer: minor units (cents) |
| quantity | an integer: base units (bytes, bits per second, items, grams, hundredths of a degree Celsius: 4.5 °C is 450, -18 °C is -1800) |
| rate | an integer: millionths (5% is 50000) |
| date | an integer: milliseconds since 1970-01-01T00:00:00Z |
| duration | an integer: milliseconds (days, weeks), or months (months, years) |
| text | a text string |
| yes or no | `false` or `true` |
| party | a byte string of 32 bytes: a ledger id |
| list | an array of at most its bound of items, each encoded as its type |
| a party field holding none | `null` (in the state only) |

Integers MUST lie in the signed 64-bit range. Any other shape is refused: `bo:argument NAME` in arguments, `bo:input` in the state.

### 12.4 Arguments

**Creation** takes a map with the key `"fields"` if the contract has fields given at creation, and `"parties"` if it has roles bound at creation, and no other key (`bo:arguments`):

- `"fields"`: a map of the fields given at creation, by name: every instance field except a party field that starts with a party (R2) and the fields Bo adds (R20); a field with a default (6.3) may be left out, and then holds its default. The map has every field without a default, any of those with one, and no other key (`bo:argument fields` if it is missing, has fewer or more keys, or a key that names no such field; `bo:argument FIELD` for a field missing or not of its type). It is present whenever the contract has fields given at creation, even if all have defaults (then it may be empty);
- `"parties"`: a map with exactly the roles bound at creation, by name, each to its ledger id (`bo:argument parties`, `bo:argument ROLE`).

With neither, the arguments are null or an empty map. For the agreement of 12.11:

```
{"fields": {"terms": "100 t of steel, monthly", "amount": 150000000, "starts": 1798732800000},
 "parties": {"we": h'1111...11', "customer": h'2222...22'}}
```

**An action** takes a map of exactly its inputs, by name, plus, for an action that binds a role (R3), the role's ledger under the role's name: required while the role is unbound, and on every call of an action that binds it again each time (R23); otherwise optional, and then it MUST name the ledger the role is bound to. The map has no other key: a map with another number of keys, or arguments that are neither a map nor null, are `bo:arguments`; an input missing or not of its type, or the role's ledger missing or another, is `bo:argument NAME`. An action with no inputs and no role to bind takes null or an empty map. A counterparty each call names is the input `counterparty` (R21). For the library's split: `{"parts": [60000000, 40000000], "recipients": [h'...', h'...']}`.

**`approve`** takes `{"function": NAME, "arguments": ARGS}`, exactly (`bo:arguments`): NAME a text (`bo:argument function`), ARGS present (`bo:argument arguments`), compared byte for byte with a kept proposal's.

**A time rule's function** takes null or an empty map (`bo:arguments`).

**`result`**, the reply, takes null or a map (`bo:arguments`): an executor's `{"result": ..., "reason": ..., "response": ...}`, or anything a person gives by hand; it reads `"result"` and `"reason"` when they are texts (6.11).

### 12.5 The instance's state

An accepted call writes the instance's state (output key 1) as a map, in canonical key order:

```
{? "bill": BILL,                        when the contract has a bill (10.5)
 ? "fired": {RULE: TIME / null, ...},   when it has time rules with code (9.5)
 ? "since": TIME,                       when it reads how long a state is held (9.7)
 "state": STATE,                        the current state's name
 "fields": {FIELD: VALUE, ...},         every instance field, by name (12.3)
 ? "pending": [[FUNCTION, ARGS], ...],  when an action lets AI agents only propose (6.9)
 ? "previous": STATE / null}            when the contract uses previous state (6.4)
```

Which keys are present depends on the contract only, never on the call. Constants are not kept. `pending` holds the kept proposals in the order they came, each its function's name and its arguments as given; `previous` is the state before the current one, or null. A state MUST be at most 65,536 bytes encoded: a call that would write more is refused, `bo:output`.

Compiled code reads the state the ledger gives it back (input key 5, spec section 15) and refuses a call whose state lacks a key or a value this format requires, or names a state the contract does not have, `bo:input`. The instance's parties (input key 5, key 5) tell it which roles are bound, and to which ledgers.

### 12.6 The accept

```
[1, {1: STATE, 2: STATUS, ? 3: PARTIES, ? 4: EVENTS, ? 5: true, ? 6: PARTS, ? 7: REQUESTS}]
```

- **1**, the state (12.5).
- **2**, the status: the state's name, always.
- **3**, the parties: each role bound so far, and each field that holds a party (except one that holds none), by name, to its ledger id; absent when there are none. The ledger replaces the instance's parties with it, so the current holder, pledgee, and payee may propose calls and consent.
- **4**, the events, absent when there are none, in this order:
  1. `["propose", ACTION]` or `["approve", ACTION]`, for a proposal kept or approved (6.9);
  2. `["when", {"late": LATE, "rule": RULE, "time": TIME}]`, for a time rule (9.5); or `["answer", {"kind": KIND, "status": STATUS, "request": ID}]`, for an answer (6.11), STATUS `"done"`, `"failed"`, or `"expired"`;
  3. `[STATE, null]` for each state change, in the order they happen, a change to the same state included; a creation's first state is one;
  4. `[DOCUMENT, BILL]`, for a bill made (10.5).
- **5**, `true` when the instance is final: its new state is final (6.10), or the call issued parts.
- **6**, the parts the call issued (section 11).
- **7**, the requests the call made, in the order their statements ran, each `{1: KIND, 2: PARAMS, 3: DEADLINE, 4: "result"}` (6.11); absent when there are none, and always for a call that waits for consents. Compiled code drafts each where the output goes when its statement runs, writes the accept after the drafts, and copies them into key 7.

A call of an action that changes no state, makes no bill, and keeps or approves no proposal writes no events. An accept that does not fit the output region of 196,608 bytes is refused, `bo:output`. One call reports at most 64 events (`build.too-many-events`, counting an action's or a rule's state changes, a proposal's, an approval's, or a rule's event, and the event of a bill it makes).

### 12.7 Consents and needs

Compiled code reads consents from the call (input key 8, `[ledger, signer]` each) and the home's agreement from the call itself: a party bound to the home ledger (input key 3) agrees through the caller's signer (input key 6). Asking for a ledger's consent (6.6) either finds it, and with it the signer of that consent, or adds the ledger to the call's *needs*, once. A call that ends without a refusal and with needs writes

```
[2, [LEDGER, ...]]
```

the ledgers in ascending byte order, each once, never the home. A call that would need more than 16 is refused, `bo:consents`. Consents the call cites but the contract does not ask for are ignored. A creation never needs consents.

### 12.8 The order of a call's checks

A call stops at its first refusal; a refusal anywhere wins over needs found before it. Every call first reads its input: it MUST be deterministic CBOR within the limits of spec section 2, a map, at most 163,840 bytes (`bo:input`). (The ledger's inputs always are, with valid UTF-8 in every text; codegen 1 checks that UTF-8 again, codegens 2 and 3 do not, 16.3.) Then its function is found by name (`bo:function`).

**Creation:**

1. the arguments (12.4), the fields in the order they are declared, then the roles;
2. each party field that starts with a party takes that party's ledger (R2); the instance is in the first state, which is an event; `since`, if kept, is the call's time; each rule is unfired; there are no proposals and no previous state;
3. the bill, if the contract has one, is made (10.4);
4. the accept.

**An action** (its own function; an action that AI agents may only propose runs the same steps):

1. the instance's state is read (`bo:input`);
2. a built-in action: its entry states (`bo:state ACTION`);
3. an action that issues parts: the depth (`bo:depth ACTION`);
4. the arguments (`bo:arguments`, `bo:argument NAME`);
5. the starter's agreement: its consent, or the home's call; for a built-in action without a starter, the home's (8.1). A role not yet bound refuses, `bo:party ROLE`; a party field holding none, `bo:empty FIELD`;
6. an action AI agents may only propose: a call whose starter's signer is an AI agent becomes a proposal and is accepted now (`bo:pending` if 16 are kept); an approval requires the starter's signer to be a person who proves presence (`bo:approve ACTION`), when that signer is known;
7. the consents the action records, in order: the role it binds (R3), its counterparty named by the call (R21), or the counterparty it makes the holder, the pledgee, or the payee (R31), then the parties of the party fields its own lines set (R8);
8. its block, in order (6.5, 12.10): requirements (`bo:requires ACTION N`, `bo:in-person ACTION`), consents asked (`requires consent of`), choices, `each`, `reject TEXT`, fields set, state changes (`bo:state ACTION` from another state, or for `previous state` with none), parts (`bo:parts ACTION`), and anything an expression refuses (`bo:party`, `bo:empty`, `bo:overflow`, `bo:division-by-zero`, `bo:date`);
9. needs, if any (12.7); else the accept (`bo:output`).

**`approve`:** the state is read; its arguments (12.4); the first kept proposal with that function and those arguments (`bo:proposal`); then the proposed action from step 2 on, with the proposal's arguments, as an approval; the proposal is removed.

**A time rule's function:** the state is read; then 9.3 and 9.4; then needs or the accept.

**`result`:** the state is read; the arguments, null or a map (`bo:arguments`); the request, input key 9 (`bo:answer` without it; `bo:input` if it is not a request view); the answer's `result` and `reason`; the event; the rule for the answer, if any, its block in order (on an instance whose state is final, its state changes and requests are skipped); then the accept.

### 12.9 Refusals

A compiled contract refuses a call by aborting (spec section 14.4) with a reason: the compiler's own, `bo:CODE` and its values separated by spaces, or the text of a `reject`. Tools render a `bo:` reason through the packs as the message `run.CODE` with the values as its parameters, in order (Appendix C), spelling words of the vocabulary in the reader's language; a `reject` text is shown as written.

| Reason | Refused because |
|---|---|
| `bo:input` | the input is not deterministic CBOR within the limits, is longer than 163,840 bytes, or is not a map; or the instance's state is not as the contract writes it |
| `bo:overflow` | a result is outside the signed 64-bit range |
| `bo:division-by-zero` | a division by zero |
| `bo:date` | a date outside the years 1 to 9999 at the contract's offset, or a calendar shift of more than 10,000 years |
| `bo:output` | the state would exceed 65,536 bytes, or the output its 196,608-byte region |
| `bo:consents` | the call would need the consents of more than 16 ledgers |
| `bo:function` | the contract has no such function |
| `bo:arguments` | the arguments are not the map the function takes |
| `bo:argument NAME` | the argument NAME is missing, or not of its type |
| `bo:state ACTION` | ACTION cannot start, or change state, from the instance's state |
| `bo:requires ACTION N` | requirement N of ACTION does not hold |
| `bo:in-person ACTION` | ACTION needs its starter to be a person who proves presence |
| `bo:party ROLE` | ROLE is not bound to a ledger yet |
| `bo:empty FIELD` | FIELD holds no party, where a party is needed |
| `bo:pending` | the instance already keeps 16 proposals |
| `bo:proposal` | no kept proposal has that function and those arguments |
| `bo:approve ACTION` | ACTION was proposed by an AI agent, and only a person who proves presence approves it |
| `bo:when RULE` | the rule's time has not come, or its conditions do not hold, or the instance is not in its held state |
| `bo:fired RULE` | the rule has applied for this time already |
| `bo:depth ACTION` | ACTION would issue parts from a part at depth 8 |
| `bo:parts ACTION` | the parts and the recipients differ in number, or there are none |
| `bo:request KIND` | a request of KIND would carry params of more than 4,096 bytes |
| `bo:answer` | `result` was called with no request to answer (input key 9) |

ACTION, ROLE, FIELD, RULE, and KIND are names in compiled code (12.1); N is a decimal number. For an action a time rule does, ACTION is that action's name. The ledger's own refusals (a final instance, a wrong head, a missing delegation) are not the contract's: see spec section 15.

**`reject TEXT`** refuses with TEXT as written. TEXT MUST NOT start with `bo:` (`build.reject-text`), so a reason is the compiler's exactly when it starts with `bo:`.

### 12.10 Requirement numbers

N in `bo:requires ACTION N` counts the `requires` lines of ACTION from 1: every `requires`, with or without a guard, `requires consent of` and `requires in person` included, in the order written, depth first (an `if` block before its `otherwise`, and into `each` blocks), the contract's own lines first and then a built-in action's terms. The block of an `each` is numbered once, whatever the number of items it runs for. A time rule numbers its own block from 1, under its function's name; an action it does keeps its own numbers and name. The contract text numbers requirements the same way (section 14), so `bo:requires sign 2` is the clause "Requirement 2" of *sign*.

### 12.11 Example

```
use commerce
contract Agreement
parties we, customer

thing Terms
  terms text
  amount HKD
  starts date

can amend by we with new_amount HKD, new_start date
  requires proposed
  requires consent of customer
  requires new_amount > HKD 0
  if new_amount > amount * 150%
    reject "an amendment may raise the amount by half at most"
  otherwise
    amount = new_amount
  starts = new_start
can sign by customer
  over 1_000_000 requires in person
  requires now < starts
  proposed -> signed
can countersign by we
  signed -> effective
can close by we
  requires consent of customer
  effective -> closed
```

Its interface is `amend`, `close`, `countersign`, `create` (kind 1), and `sign`. With we on ledger `h'1111...11'` (the home) and the customer on `h'2222...22'`:

| Call | Arguments | Output or reason |
|---|---|---|
| `create` | 12.4's example | `[1, {1: {"state": "proposed", "fields": {"terms": "100 t of steel, monthly", "amount": 150000000, "starts": 1798732800000}}, 2: "proposed", 3: {"we": h'11..', "customer": h'22..'}, 4: [["proposed", null]]}]` |
| `countersign` | null | `bo:state countersign` |
| `amend` | `{"new_start": 1799337600000, "new_amount": 300000000}` | `an amendment may raise the amount by half at most` |
| `amend` | `{"new_start": 1799337600000, "new_amount": 200000000}` | `[2, [h'22..']]`: the customer's consent is needed |
| the same, citing the customer's consent | | `[1, {1: {... "amount": 200000000, "starts": 1799337600000 ...}, 2: "proposed", 3: {...}}]`: no state change, no events |
| `sign`, called by the home on the customer's consent, signed by the organization | null | `bo:in-person sign` |
| `sign`, the consent signed by a person with a passkey | null | `[1, {..., 2: "signed", ..., 4: [["signed", null]]}]` |
| `close` once effective, with the customer's consent | null | `[1, {..., 2: "closed", ..., 4: [["closed", null]], 5: true}]` |

The amount is HKD 1,500,000 in cents; the dates are local midnights at +08:00; `amount * 150%` is the amount × 1,500,000 ÷ 1,000,000, rounded half up.

## 13. Tests

A contract carries its own tests: `test` blocks of steps, each a party, an action, and what should happen. Tests are part of the source (they are deployed with it, and checked with it) but not of the code. Their syntax and checks are normative; how they run (13.2 to 13.6) is the meaning of a test, which a tool that runs Bo tests SHOULD follow, as `cexchain bo test` does.

### 13.1 Steps

```
test "nobody signs alone"
  we create with goods = "Bearings 6204-2RS", pieces = 20_000, price = CNY 1_250_000, deliver_by = 2026-12-01
  we sign -> consent of bank
  supplier sign -> consent of we
  we close -> refused "bo:state close"
```

A step is

```
PARTY ACTION [HOLDER] [to PARTY] [with NAME = VALUE, ...] [at DATE] [in person] [by AI agent] [-> EXPECTATION]
```

with its expectation on its line or alone on the next line (`-> ...`). A test has an optional name, a text or a name, unique in the source (`check.duplicate`).

- **The first step creates the instance** (`check.test-start`), and no other does (`check.test-again`): `issue` for an asset, `create` otherwise (`check.test-creation`), with `with FIELD = VALUE` for every field given at creation (`check.test-missing`); a field with a default may be left out. Its party is the home, the ledger that runs the contract; a contract that has the role `we` MUST name it (`check.test-home`).
- **Other steps** do an action the contract declares with `can` (`check.test-action`), `approve` a proposal (13.5), or are a keeper's (13.5). `with` gives the action's inputs, each once (`check.unknown-input`, `check.duplicate`, `check.test-missing`).
- **Parties** are the contract's parties or names that only tests use, each a ledger of its own (`bank1`); anything else is `check.test-party`.
- **`to PARTY`** only for an action with a counterparty (`check.test-to`): the ledger a role the action binds is bound to, or the counterparty each call names, which a step MUST then give (`check.test-needs-to`). For a counterparty bound at creation, the step names that role itself (`check.test-counterparty`).
- **Values** are written out: a number, money, a quantity, a date, a duration, a rate, a text, yes or no, or a list of them (`check.test-value`); a party, or a list of parties, for an input or a field that holds them (`recipients = (gears, castings)`), by role or by a test's ledger name. They are typed against the inputs (or the fields, at creation) as the contract types them.
- **`at DATE`**: the step happens at the start of that day at the contract's offset. The date is on or after 1970-01-01 (`check.test-time`) and never before a step before it (`check.test-time-back`).
- **`in person`**: the party is a person who proves presence; **`by AI agent`**: its signer is an AI agent; not both, and `by` names nothing else (`check.test-signer`). Other words on a step are `check.test-step`.
- **HOLDER**, a party after the action, names the part the step acts on by its holder (`issuer pay forge`), in a contract whose instances have a `holder` (`check.test-part`).
- **An answer** (E8): `executor KIND done`, `executor KIND fails`, `keeper KIND expires`, or a party's answer by hand (`we KIND done in person`), with at most `with result = TEXT, reason = TEXT` and `at DATE` (`check.test-answer`, `check.test-value`). KIND is a kind the contract requests (`check.test-answer`). It answers the instance's oldest open request of that kind, as the ledger takes answers: a call of `result` with the request in input key 9 and no consents, signed by the executor or the keeper as the home's devices (kind 3), or by the party. The ledger refuses an answer when no request of the kind is open, an expiry before the deadline, and an accept that would leave the instance more than 64 open requests; a final instance takes answers and stays final. A step that makes requests reports them; their ids derive from a call id of the SHA-256 of `cexchain-bo-test call ` followed by the instance's id in hex, a space, and its head before the call.

Expectations (`check.test-expect`; one per step, right after it: `check.test-expect-step`):

| Expectation | The step passes when |
|---|---|
| none | the call is accepted |
| `-> STATE` | the call is accepted and the instance is then in STATE, a state of the contract |
| `-> refused` | the call is refused: by the contract, or by the ledger because the instance is final or was never created, or, for an answer, because no request of its kind is open, the deadline has not come, or more than 64 would be open |
| `-> refused "REASON"` | the contract refuses the call with exactly REASON: a `bo:` reason or a `reject` text, never a worded message, so a test means the same in every language |
| `-> consent of PARTY`, `-> consent of (A, B)` | the call waits for the consents of exactly those ledgers |
| `-> pending approval` | the call is kept as a proposal; only for a step `by AI agent` of an action AI agents may only propose (`check.test-proposal`) |

Only `refused` takes a reason (`check.test-reason`).

**Values of fields.** An expectation of an accepted call may also name values that instance fields hold after it: after a comma (`-> delivered, late_charge = HKD 4_000, holder = consignee`), or alone, the call then expected to be accepted (`-> excursions = 2`). Each names an instance field once (`check.test-field`, `check.duplicate`) and gives a value as a step does: written out and of the field's type, a party (by role or a test's ledger name) for a party field, or `none` for a party field that holds none (`check.test-value`, `check.type`). Only an expectation of an accepted call takes them (`check.test-fields`: not of `refused`, `consent of`, or `pending approval`). The step passes only if every field named holds that value, compared as compiled code keeps it (12.3); a failing step's report gives both, in the reader's language ("Expected: ...; then fee is HKD 5,000.00." / "Result: ..., but fee is HKD 4,000.00.").

### 13.2 Ledgers and time

Every party a test names is a ledger of its own, whose id is the SHA-256 of the UTF-8 text `cexchain-bo-test ledger ` followed by the party's key: a role word's concept id (`role.supplier`), or a name as written (`bank1`, or a party the contract names). So ids are the same in every language. Roles bound at creation are bound to their own ledgers; a role an action binds, to the ledger the step's `to` names. Once bound, a role in a step stands for its ledger. The contract's id is the SHA-256 of `cexchain-bo-test contract`, the home's acting actor the SHA-256 of `cexchain-bo-test actor`, the instance the SHA-256 of `cexchain-bo-test instance`, and a part's id the child id of spec section 15 under SHA-256.

A test starts at 2026-01-01, at the start of that day at the contract's offset, or on its first `at` date if that is earlier. A step without `at` happens at the time of the step before it.

### 13.3 Signers and consents

The step's party signs as a person who proves presence with a passkey (`in person`: kind 1, presence 1), as an AI agent (`by AI agent`: kind 2, the model `bo-test-agent`), or as the organization (kind 0). When the step's party is the home, that is the call's signer; otherwise the home's registrar makes the call (signed by the organization), and the step's party signs its consent.

A step's call runs first without consents, as the home does to learn whom to ask. Then every ledger the call needs consents (the step's party with its own signer, any other as its organization), the consents cited in ascending order of ledger, and the call runs again, until it is accepted, refused, or waits only for ledgers that do not consent. Those are the ledgers the expectation names, and the action's starter (a role or a party field, read from the instance) when the step's party is not the starter. The home agrees only by making the call: a step by another party of an action the home starts waits for the home ("the call waits for us to make it"), and `-> consent of we` expects that.

### 13.4 Steps on parts

Before any split, every step acts on the test's instance. Once a call has made parts (section 11), a step acts on the instance its party holds, or is pledgee or payee of (any field holding a party), or, with a HOLDER, the instance that party holds: of those, the one that still takes calls, else the one final instance. A step with no single such instance fails. A keeper's step acts the same way, for the home. Reports name parts by path: part `1.2` is the second part of the first part.

### 13.5 Keepers and approvals

- **`keeper ACTION [at DATE] [-> ...]`** calls, as the home's keeper (a device, kind 3), the time rule whose function is `when.` and ACTION's name (`keeper suspend` calls `when.suspend`; `check.test-rule` if there is none), with no arguments. Nothing else may be on the step (`check.test-keeper`). Nothing fires by itself: each call of a rule is a step, so a test shows a rule refused before its time and accepted after. A second rule doing the same action (`when.suspend.2`) cannot be named in edition 1, nor a rule that does no action and leads to a state of the vocabulary.
- **`PARTY approve [in person]`** approves the first proposal the instance keeps: its arguments are that proposal's function and arguments. The approval is started by the proposed action's starter.

```
test "a receipt pledged, released, and redeemed"
  we issue with quantity = 600 kg
  depositor pledge to bank1 in person -> pledged
  bank1 release by AI agent -> pending approval
  bank1 approve in person -> active
  depositor redeem with portion = 600 kg -> redeemed
```

### 13.6 Results

A test passes when every step does; it stops at its first failing step, and the steps after it are not run. `cexchain bo test` reports each step as written, what it expected when it failed, what happened (worded in the reader's language), and, for a refusal, the clause of the contract text it comes from (14.3); it exits with status 3 when a test fails and 2 when the source does not build.

## 14. The contract text

### 14.1 What it says

What the parties read and confirm before they sign is the *contract text*, which Bo writes from the checked model in the language of a pack (`bo explain`, `contract explain`). It states what the compiled code does, and nothing else:

1. the title and an introduction, then, for a contract that uses vocabulary packs, a sentence naming each (its name in the reader's language and its version);
2. **Parties**: each role, and when it is bound to a ledger (at creation, by the first call of an action, or by each, R23);
3. **Each instance**: the kind; each field (given at creation, given at creation or else its default, the party it starts with, none at first, or a constant's value); how an instance is created (by which function, needing no consent); the UTC offset, for a contract with dates, calendar durations, or time rules;
4. **Charges**, if any: the bill, and each charge's lines (section 10);
5. **States**: the first, all of them, the final ones (6.10), and that each change of state is an event;
6. **Actions**: each action with its function, whether it is built-in (with the standard terms, naming the vocabulary pack that gives them, if one does) or the home's own word, its starter, counterparty, inputs, the consents it needs, its block in order (requirements numbered as compiled code numbers them, 12.10; choices, `each`, refusals, fields set, state changes, parts, and their depth and privacy), and what AI agents may do; and `approve`, if there are proposals;
7. **Time rules**, if any: what is due, and for each rule its time, its function (R24), its consents, the actions it does, and its block; duties (R9) and executors (R10);
8. **Answers to requests**, for a contract that makes requests: the reply function and what it does with every answer, then each rule for answers with its block. Each request, where it is made, states its kind, its party, its values, its deadline, and what happens if it fails or expires (the rule for that answer, R33, or nothing more than the event);
9. **Rules Bo applied**: the text of each recognition rule the clauses above use.

Clauses are numbered by section, item, and sub-item (`4.2.3`). A clause that states what a rule inferred ends with a mark naming its rules, in the order of their ids: `[R6, R13]` in English, `〔R6、R13〕` in Chinese. Every text value is shown in the pack's quotation marks (`"中国内地"`, `「中国内地」`, `“中国内地”`), a name read as text by R18 included.

```
4.2 sign
  4.2.1 Started by the customer, whose agreement it needs.
  4.2.2 Requirement 1: if the amount is over HKD 1,000,000, the customer must prove presence in
        person, with a passkey or a hardware key. [R6, R13]
  4.2.3 Requirement 2: the time of the call is before starts.
  4.2.4 If the instance is proposed, it becomes signed; otherwise the call is refused.
  4.2.5 An AI agent may start it within its delegation. [R14]
```

### 14.2 One text for one contract

The text depends on the model and on the pack it is written with, never on the language the source was written in, its layout, or its comments: one contract gives the same text, byte for byte, through any spelling of it, and the same model and pack versions always give the same text. A party can therefore compute again, from the deploy's source, exactly the text it confirmed. The sentences are the pack's (a pack without one uses the English pack's); so are the words, else English. `contract explain` writes the text of a deploy only if its source rebuilds to its code (section 16), so that the text is that of the code that runs; for an instance, it writes the instance's state and fields first, in the same words.

### 14.3 Conformance of the text

The wording is the packs'. A conforming implementation that writes a contract text MUST state every clause of the model, MUST mark each inferred clause with the rules that inferred it, and MUST number requirements as compiled code does, so that a refusal `bo:requires ACTION N` names the clause *Requirement N* of ACTION, `bo:in-person ACTION` its requirement asking presence, and `bo:state ACTION` its state change. CexChain's text, written with the official packs, is the reference ([`../tests/bo/golden/explain/`](../tests/bo/golden/explain)).

## 15. Formatting

*This section is informative, but for its last paragraph.* `bo fmt` writes a source in canonical layout and, with `--language`, with every keyword and word of the vocabulary in one language. It works on the tokens, line by line, so every clause stays on its line and every comment in its place.

**Layout.**

- Each line is indented by two spaces per block. A comment on a line of its own is indented as the block it sits in (by its column, between the lines around it); a comment after code follows it after two spaces; comments keep their text (trailing spaces go).
- Runs of blank lines become one, with none at the start or end; lines end with LF, and the file with one.
- `use` lines come first, after `bo N` if there is one, sorted by pack id, then a blank line; if they already precede every other code line in that order, they stay where they are (comments may come before them).
- Tokens are separated by one space, but none before `,` `:` `)` or after `(`. Where two words written in a language without spaces meet and the packs' rules join them, they are joined: a prefix keyword and the word after it (`可質押`, `須親身確認`, `須經`), an attaching word and its neighbour (`按發票`, `30日內`). Latin words and numbers stand apart from Chinese by a space (`每 GB`, `可 subscribe`), but a number takes its multiplier and a Chinese unit or currency directly (`500萬港元`, `30日`, `1個`).
- Punctuation stays as written (ASCII, `×` and `÷`, or the full-width marks a pack reads, with no space on either side of those, except a comma before a digit); in a language that does not read a full-width mark, it becomes ASCII. Digits are written in ASCII, with `_` as written.

**Languages.** Without `--language`, every word keeps its spelling. With one, a word already spelled in that language (any spelling or form: `pays`, `費率`) keeps it; any other takes the language's first spelling, a unit or time unit after a number other than 1 in its plural form (`30 days`). A word with an argument moves to the side the language spells it on (`7 days before due`, `到期前 7日`), with parentheses where its new place would take another argument. A multiplier the language lacks becomes one of equal value (`萬` becomes `万`), else is written out (`5_000_000`). A date stays ISO; a pack's date form stays if the language reads it, else becomes the language's form, else ISO. Names, texts, and comments never change.

**What round-trips.** The contract, not the characters: written into another language and back, a source gives the same tree, model, code, and contract text, but forms and other spellings become first spellings (`pays`, then `支付`, then `pay`), multipliers stay written out, and the layout is canonical.

**Safety.** The formatter refuses a source with any lexer or parser error. Before it returns a result, it reads it again: the result MUST give the same tree and the same comments as the source (without a language, the same tokens too). If joining words would change that, the line is written with spaces instead; where words still read together as another word of the target language (`於 真人` as `in person`), a value word is put in parentheses (`in (person)`); if that cannot help (a name the contract gives reads together with the words around it), nothing is written and `fmt.unstable` names the line. `fmt.internal` reports a formatter bug.

## 16. The bo-source bundle and rebuilding

### 16.1 What a Bo deploy records

A contract written in Bo is deployed (spec section 15, statement type 21) with:

| Field | Value |
|---|---|
| code | the module |
| interface | its functions and kinds (12.2) |
| language | `bo` |
| compiler | `cexchain-bo RELEASE; codegen N; edition E` for CexChain's compiler |
| source | a `bo-source` bundle |
| name | the name after `contract` |

### 16.2 The bundle

The bundle is deterministic CBOR, `bo-source` in [`cexchain.cddl`](cexchain.cddl), at most 262,144 bytes (a deploy's source):

```
{1: 1, 2: EDITION, 3: SOURCE, 4: [+ [ID, VERSION, DIGEST]], ? 5: [+ PACK], ? 6: [+ [ID, VERSION, DIGEST]],
 ? 7: [+ VOCABULARY-PACK]}
```

- **1**, the bundle format, 1;
- **2**, the source's edition (1 or more), which MUST be the source's own (`bo N`, or 1);
- **3**, the source as written, comments included;
- **4**, every language pack the source was read with, the official ones included, 1 to 64, strictly ascending by id: its id (3.2), its version (1 or more), and its digest under the home's hash (32 bytes, 3.7);
- **5**, the packs that are not official, in full, each as its canonical CBOR (a map), strictly ascending by id, each one a pack key 4 names. A reference without an embedded pack names an official pack;
- **6**, every vocabulary pack the source uses (3.9), 1 to 64, strictly ascending by id: its id, its version, and its digest under the home's hash (the hash of its canonical CBOR); absent if the source has no `use` line;
- **7**, the vocabulary packs of key 6 that are not official (users' packs, 3.9), in full, each as its canonical CBOR (a map), strictly ascending by id, each one a pack key 6 names; absent if there are none. A key-6 reference without an embedded pack names an official vocabulary pack. So whoever verifies a deploy rebuilds it with nothing but the deploy.

Opening a bundle finds its packs: each embedded pack MUST read without errors (3.2), MUST NOT call itself official, and MUST have the version and the digest its reference names; each other reference MUST name an official pack at a version the compiler carries, with that digest, and all of them MUST be of one release (today's, or those of before vocabulary packs, 3.7); every official pack of that release MUST be referenced; the packs MUST read together (3.6); each embedded vocabulary pack MUST read without errors as a user's pack (3.9) and MUST have the version and the digest its key-6 reference names; each other key-6 reference MUST name an official vocabulary pack at a version the compiler carries, with that digest, of the language packs' release (version 2 with today's language packs, version 1 with versions 2 and 3); a bundle on the official packs of before vocabulary packs MUST NOT have key 6, and a bundle on the official packs of an earlier release MUST NOT have key 7; the packs, the embedded vocabulary packs included, MUST read together (3.6, 3.9); and the source's `use` lines MUST name exactly the packs key 6 names. The source is then read with exactly those packs: with the official packs of before vocabulary packs, it uses every vocabulary pack without declaring it.

### 16.3 The compiler string and codegen versions

`cexchain-bo RELEASE; codegen N; edition E` names the compiler, its release, its codegen version, and the edition it reads; for example `cexchain-bo 0.0.1; codegen 3; edition 1`. The codegen version fixes the code: the same codegen version builds the same bytes from the same source, in any language and on any machine. It goes up whenever any byte the compiler emits for some contract changes. A construct that no earlier compiler read (a word, a form, or an operation added since, such as the field defaults, durations divided by durations, temperatures, and negative numbers of the official packs version 3) does not raise it: no deploy of a source using it was built by an older lowering, and older sources build to the same bytes as before. A compiler carries the lowerings of the codegen versions before its own, so that a deploy built with an older one still rebuilds: CexChain's compiler is at codegen 3, and rebuilds deploys of codegens 1 and 2. Codegen 2 changed two things, and nothing a call does:

- the code reads a call's input without checking again that its texts are UTF-8, which the ledger's inputs always are (the ledger's decoder refuses anything else): checking cost up to 50 fuel per byte of text that is not ASCII, so that a call's input of 160 KiB could take more fuel to read than a call has. Every module's bytes changed with it;
- a function shares two scratch locals among its comparisons of parties that may be none, and its `consent of` a list, where codegen 1 took two new ones for each: thousands of them could exceed the 4,096 locals a function may have (spec section 14.1).

Codegen 3 asks the consents of R31, which edition 1 gained before its release (a counterparty that an action makes the holder, the pledgee, or the payee consents to every call, even when its role was bound before): codegens 1 and 2 never ask them, so their code accepts such a call without that consent. Only modules of contracts with such an action changed; for every other contract, codegens 2 and 3 write the same bytes. A deploy that names codegen 1 or 2 rebuilds with the code that codegen wrote, and its contract text, which this compiler writes from the source, states R31 although that code does not ask it; after the first release, a change of meaning comes in a new edition instead.

Codegen 1 code has no fuel bounds; codegen 2 and 3 code has (17.2).

### 16.4 Rebuilding

A verifier SHOULD rebuild a Bo deploy (spec section 15): decode the bundle, open its packs under the home's hash, build the source with the codegen version the compiler string names, and compare the module, the interface, and the name (if the deploy has one) with the deploy's. It reports one of:

| Outcome | When |
|---|---|
| **rebuilds** | the source builds to the deployed code, interface, and name |
| **differs** | the deploy names a codegen version and edition this compiler carries (and, for a problem with an official pack, its release), and the source builds to something else or does not build: the source is not the code's. The verifier SHOULD fail the evidence |
| **malformed** | the language is not `bo`, there is no source, it is not a bundle, an embedded pack (of key 5 or key 7) does not check, differs from its reference, or conflicts, its official packs are of two releases, it names vocabulary packs beside the official packs of before vocabulary packs (or official vocabulary packs of another release, or embeds vocabulary packs beside an earlier release), the source's `use` lines are not its key 6, or the bundle's edition is not the source's. The verifier SHOULD fail the evidence |
| **another compiler** | another compiler, or a release or codegen version this one does not reproduce, or an official language or vocabulary pack version this one does not carry, built it: the verifier names it, and MAY require a rebuild with that compiler; it never reports this as a forgery |

A deploy made before vocabulary packs (its bundle names version 1 of the official packs and has no key 6) rebuilds: its source is read with those packs, every vocabulary pack in use, and compiles to the code it compiled to then, since concept ids, rule ids, and the code they lower to did not change.

A rebuild compares bytes only: it does not refuse code for its fuel or output bounds (17.2, 17.3), which the deploy's build checked. The ledger rules do not rebuild: a home that deploys a source that is not its code is caught by every verifier that rebuilds.

### 16.5 Built files

*Informative.* `bo build --out FILE.boc` writes the deploy's fields ready to deploy, `{1: code, 2: interface, 3: "bo", 4: compiler, 5: bundle, 6: name, 7: hash}`, keyed as `contract-deploy-body` keys them, plus the COSE algorithm id of the hash the bundle's digests were made with (SHA-256 −16, SM3 −65538); at most 1 MiB. A `.boc` must rebuild before it is deployed, and its digests are made again under the home's hash.

## 17. Limits and fuel

### 17.1 Limits

**Source and packs.**

| Limit | Value | Code |
|---|---|---|
| a source | 262,144 bytes of UTF-8 | `lex.too-large` |
| a text | 1,000 bytes | `lex.text-too-long` |
| a name | 128 bytes; 64 in compiled code | `lex.name-too-long`, `build.name-too-long` |
| blocks | 32 deep | `lex.too-deep` |
| nesting within a line | 100 (parentheses, operators, `otherwise if`) | `parse.too-deep` |
| a number | at most 18 decimal places, and 18,446,744,073,709,551,615 counting every digit | `lex.number-too-large` |
| a value | a signed 64-bit integer of its smallest unit | `check.overflow`, `bo:overflow` |
| a calendar duration | 120,000 months | `check.overflow`, `bo:date` |
| a date | the years 1 to 9999 | `lex.bad-date`, `bo:date` |
| the UTC offset | −14:00 to +14:00 | `check.utc-offset` |
| a list | 16 items unless `at most N`; N at most 1,000; a list written out, 1 to 1,000 items | `check.list-bound`, `bo:argument NAME` |
| `recipients` | 16 parties | `check.list-bound`, `bo:argument recipients` |
| problems reported by one reading | 100, then `bo.truncated` | |
| a pack | 1 MiB, as text or CBOR | `pack.too-large` |
| a pack's spellings | 1 to 8 per concept, 1 to 4 words of at most 64 bytes; at most 8 forms | `pack.too-many`, `pack.bad-spelling` |
| a pack's texts | names 200 bytes, month names 64, messages and sentences 1,000 | `pack.bad-text` |
| a pack's reading rules | 16 prefixes, 16 attaching words, 64 punctuation aliases, 16 multipliers, 8 date forms of at most 64 bytes | `pack.too-many`, `pack.bad-date` |
| a bundle | 262,144 bytes, 1 to 64 packs | |
| a `.boc` file | 1 MiB | |

**Compiled contracts.**

| Limit | Value | Code |
|---|---|---|
| functions | 256 (spec section 15) | `build.too-many-functions` |
| parties: roles and fields that hold a party | 64 (spec section 15) | `build.too-many-parties` |
| instance fields | 256 | `build.too-many-fields` |
| an action's inputs | 256 | `build.too-many-inputs` |
| events of one call | 64 (spec section 15) | `build.too-many-events` |
| charges | 64 | `build.too-many-charges` |
| the module's globals | 1,024 (spec section 14.1) | `build.too-large` |
| constants: names, texts, reasons, lists written out | CexChain's static region: 32 KiB of memory, less a 1 KiB margin | `build.too-large` |
| a function's body | CexChain's compiler stops at 100 KiB, within the profile's 131,072 bytes | `build.too-large` |
| requests one call makes | 16, counted over every branch (spec section 15) | `check.request-count` |
| a request's params | 4,096 bytes encoded (spec section 15) | `bo:request KIND` |
| a request's deadline | 1 day to 366 days, or 1 to 12 months, after the call (spec section 15) | `check.request-within` |
| open requests of an instance | 64 (spec section 15): the ledger refuses a call that would leave more | |

**At run time.** These limits are behaviour (section 12), and a conforming compiler's code MUST refuse as CexChain's does:

| Limit | Value | Refusal |
|---|---|---|
| a call's input | 163,840 bytes; deterministic CBOR within spec section 2 (32 levels, 131,072 items) | `bo:input` |
| the arguments | 65,536 bytes, of any shape (spec section 15) | the ledger's |
| the instance's state, and each part's | 65,536 bytes encoded | `bo:output` |
| a call's output | 196,608 bytes (192 KiB): the output region of compiled code, within the profile's 1 MiB | `bo:output` |
| ledgers a call needs | 16 | `bo:consents` |
| proposals kept | 16 | `bo:pending` |
| parts one call issues | 16 | (the bound of `recipients`) |
| a part's depth | 8 | `bo:depth ACTION` |
| a reason | 1,024 bytes (spec section 14.4); a `reject` text is at most 1,000 | |

### 17.2 Fuel

A call has 10,000,000 fuel (spec section 14.3); code that runs out traps, and the call is refused. Bo bounds every loop by what the language bounds, and has no recursion, so the fuel a call can use has a bound that the compiler computes from the code's structure.

For each function of the interface, time rules and `approve` included, CexChain's compiler computes a static worst-case fuel bound from the code it writes: each instruction's fuel (spec section 14.3), the more costly arm of each choice, and each loop's body times the most times it can run.

- **Loops** run as often as the language allows: a list's bound (nested `each` loops multiply), a bill's lines and the charges on each, a split's parts and the consents of its recipients, at most 16 consents a call cites, 16 ledgers it asks, and 16 proposals kept.
- **Sizes.** A comparison of texts reads at most the shorter text, which is at most a text written in the contract, an item of a list the loop walks (the items of one list add up to the list), or else 64 KiB, the most an argument or a state holds; copying a value into the output costs by its size the same way; a search of a map reads at most the entries the map can have (an argument map has the action's inputs; a state's map the contract's fields).
- **Reading the input.** The code reads and indexes the whole input before anything else. CexChain's reader takes at most 3,000 fuel, plus 240 per item of the input and 160 per map key (whose names are at most 64 bytes); the bound counts the items an input can hold: the arguments of the function's shape (each input of its type, lists within their bounds), the state the contract writes (its fields, at most 16 proposals, a bill's lines and charges), and the rest of the input as the ledger encodes it (spec section 15: the instance's parties, at most 16 consents).

The bound holds for every call whose arguments are of the function's shape: a map of its inputs, each of its type, lists within their bounds (or null when it has none). Any other arguments are refused (`bo:arguments`, `bo:argument NAME`); a caller who sends far larger ones, up to the 64 KiB a call's arguments may take, may make the code run out of fuel reading them first, which refuses the call too. Nothing another party does can make a call run out of fuel: a state is at most 64 KiB, and the bound counts the largest state the contract can write.

`bo build` refuses a contract any of whose functions has a bound above 10,000,000 (`build.fuel`), and shows the highest bound; `bo build --fuel` shows each function's, and `bo build --json` gives them all (`bounds`: for each function its `fuel`, the part reading the input takes, `input`, the items and keys that part counts, `input_items` and `input_keys`, and its `output`; with `fuel_limit` and `output_limit`). For the agreement of 12.11:

```
$ cexchain bo build agreement.bo --fuel
  ...
  fuel       at most 226,042 a call (amend), of 10,000,000; output at most 65,771 bytes (amend), of 196,608
  function               fuel       reading     output
  amend               226,042        63,080     65,771
  close               220,650        61,800     65,771
  countersign         203,679        61,800     65,771
  create               86,980        66,280     65,771
  sign                207,117        61,800     65,771
```

Most of an action's bound is reading the largest input it can meet (about 62,000) and the worst case of asking for consents (up to 16 ledgers, sorted: about 66,000); a trivial action's bound is about 195,000. The calls of 12.11, on the input each had, used 7,151 to 11,041 fuel. Calls at the language's limits come closer (CexChain's goldens, `tests/bo/golden/build/`, show each call's fuel next to the bound for the input it had):

| Call | Fuel | Bound for its input |
|---|---|---|
| an action on a state with 1,000 numbers and 1,000 texts of 40 bytes, checking a text against every one (`x in names`) | 1,052,930 | 1,855,938 |
| `each` over those 1,000 texts, comparing each | 909,410 | 2,259,130 |
| a bill of 1,000 lines with 16 charges (two on each line), made at creation | 1,788,529 | 3,740,401 |
| the same bill made again by an action, from new lines | 2,747,579 | 5,877,958 |
| a split into 16 parts at depth 7, with its 16 consents | 84,298 | 528,673 |

Two lists of 1,000 numbers compared item by item (`each` within `each`) could need a million comparisons, more than a call's fuel: such a contract does not build (`build.fuel`), and lists of 100 items do.

The bound is an upper bound, which a conforming compiler need not reproduce: it is informative, and so is the fuel any call uses. A CexChain build never deploys code whose bound exceeds the limit (a rebuild compares bytes only, 16.4). A conforming compiler SHOULD likewise ensure that no function of its code can run out of fuel on arguments of its shape.

### 17.3 Output

An accepted call's output MUST fit the output region of compiled code, 196,608 bytes, else the call is refused, `bo:output`; and each state it writes, the instance's and each part's, MUST be at most 65,536 bytes encoded. Since a part repeats its parent's fields, a parent whose state is near 64 KiB cannot be split into many parts: the parent's state and sixteen parts' would be seventeen states, which do not fit 192 KiB. CexChain's compiler computes, for each function, a bound on its output from the same structure as the fuel bound: each state counts at most 64 KiB (the code refuses more), a bill made in the call is written twice (in the state and as its event), and a function that issues parts writes up to 16 more states. `bo build` shows the output bounds with the fuel bounds, and warns when a function's exceeds the region (`build.output`); such a contract builds, but a call that would write too much is refused. A receivable with a text field, for example, warns for `split`: sixteen parts with texts of up to 64 KiB each would not fit, and a parent whose state is small splits into sixteen parts without trouble. The agreement of 12.11 writes at most 65,771 bytes a call; the demo's receivable (`examples/multi-tier-split/multi-tier-split.bo`), which has no text, at most 9,478, splitting included.

## 18. Conformance

### 18.1 What conforms

A **conforming compiler**:

- MUST read the official language packs and the official vocabulary packs, at every released version, and MAY read other language packs (section 3);
- MUST accept a source exactly when this document accepts it, and MUST refuse every other source. For a refused source, the codes of its errors are normative: it MUST report the codes CexChain's compiler reports, given that the checker reads only a tree without lexer or parser errors, and that lowering reads only a model without checker errors (and that one reading reports at most 100 problems). The wording of messages, and the places they point to, are informative;
- MUST build, from an accepted source, code whose interface is that of section 12.2 and whose every call behaves as section 12 says: for every input, the same outcome (an accept, needs, or a refusal), the same output, byte for byte (outputs are deterministic CBOR, so equal values are equal bytes), and the same reason, byte for byte;
- MAY emit other code bytes, and use other fuel; it SHOULD bound its functions' fuel below the limit of a call (17.2).

A tool that writes **the contract text** conforms as section 14.3 says; one that **formats** sources MUST keep the tree and the comments (section 15); one that **runs tests** SHOULD run them as section 13 says. A **verifier** that rebuilds deploys follows section 16.

### 18.2 The conformance suite

[`../testvectors/bo-v1.json`](../testvectors/bo-v1.json) binds every Bo compiler, CexChain's and anyone's. For each contract it holds:

- its source, in each language it is written in (English, Traditional Chinese, Simplified Chinese, and mixed, for some), and its name (`contract`);
- its interface (`interface`: each function, `create` or `call`);
- the `bo-source` bundle a deploy records (`bundle`, and its SHA-256), with the official packs' SHA-256 digests (version 5) and those of the vocabulary packs its `use` lines name (key 6, version 2), and the compiler string it was built with (`compiler`);
- `earlier`: the bundles its deploys recorded with earlier releases of the official packs, oldest first (version 1, before vocabulary packs: no `use` lines, its kind word `record`; version 2, before temperatures and field defaults; version 3, before vocabulary pack files, with version 1 of the vocabulary packs), each with the compiler string and the SHA-256 of the code it deployed, which is `code_sha256`: each such deploy rebuilds to the same code (16.4);
- the code `cexchain-bo` built from it (`code`, `code_sha256`), the SHA-256 of the code codegens 1 and 2 built from it (`codegen1_sha256`, `codegen2_sha256`), and each function's fuel and output bounds (`bounds`): all informative;
- runs: each call, as its parts (function, arguments, home, contract, instance view, caller and signer, time, consents) and as the contract input the ledger encodes from them (spec section 15), with the outcome, the output or the reason, and the fuel the code used. The runs include every step of the contract's own test blocks.

It also holds sources that must not build (`errors`): each with its name, its text (or, for one that is not UTF-8, its bytes in hex), and the error codes a compiler reports, in source order, with their lines. The codes are normative; the lines are CexChain's.

`tools/testvectors/bo_vectors.py` writes the suite from the runs CexChain's tests record, and checks each before writing it: it encodes the input again from the call's parts with its own deterministic CBOR encoder, runs the code on the independent reference interpreter `tools/testvectors/wasm_ref.py` (which MUST give the same outcome, output, fuel, and reason as the ledger's interpreter), decodes the output as `contract-output`, and decodes each bundle, requiring the source as written, the digest of each official pack, which it computes from the packs' text (`bo/packs/`, and `bo/packs/history/` for the earlier bundles) with its own reader of their diagnostic notation, and key 6 equal to the source's `use` lines with the digests of the vocabulary packs' canonical CBOR, which it computes from their files (`bo/vocab/`, and `bo/vocab/history/` for the earlier bundles), each equal to the C++ reader's. Sources read with users' vocabulary packs are tested by CexChain's tests (`tests/bo/vocab_test.cpp`, the goldens with `.vocab` files, `examples/events`), not by this suite, which names official packs only. CexChain's tests rebuild every source to the pinned code, bundle, interface, and bounds, rebuild every earlier bundle to the same code, replay every run, and compile every source that must not build to the same errors.

To check a compiler against the suite: build each source (in every language given); require the interface; run the code on each run's input under the contract profile (spec section 14); require the outcome, the output, and the reason; and compile each source that must not build, requiring its error codes. The code, its hash and size, and the fuel are informative: they match exactly only for `cexchain-bo` at the codegen version the suite names. To check a rebuild, open each bundle (16.2) and compare the build with the pinned code.

### 18.3 Goldens

[`../tests/bo/golden/`](../tests/bo/golden) holds CexChain's goldens for every pass: tokens (`tokens.txt`), trees (`ast.txt`), models and their errors (`check.txt`), contract texts in three languages (`explain/`), formatted sources (`format/`), test results (`test/`), built code and fuel (`build/`), and the digests of the official packs (earlier versions included) and of the vocabulary packs. They are informative, and show what a conforming implementation reports: the error goldens (`error-*`, `parse-error-*`, `check-error-*`) give the codes each refused source gets.

## Appendix A. Keywords

Every official pack spells every keyword (from the version that brought it), and every spelling of the official packs is reserved in every source, except the contextual outcomes (2.6).

| Keyword | English | 繁體中文（香港） | 简体中文 | Use |
|---|---|---|---|---|
| `kw.contract` | `contract` | `合約` | `合约` | names the contract |
| `kw.parties` | `parties` | `訂約方` | `参与方` | lists the roles |
| `kw.can` | `can` | `可` | `可` | declares an action; `AI agent can propose` |
| `kw.by` | `by` | `由` | `由` | who starts an action; `by AI agent` in a test |
| `kw.to` | `to` | `予` | `给` | the counterparty; the recipients of parts |
| `kw.with` | `with` | `連同` | `附带` | an action's inputs; values given |
| `kw.requires` | `requires` | `須` | `须` | a requirement, a consent, presence |
| `kw.when` | `when` | `當` | `当` | a time rule |
| `kw.if` | `if` | `如` | `如果` | a choice |
| `kw.otherwise` | `otherwise` | `否則` | `否则` | the other branch |
| `kw.and` | `and` | `及` | `且` | logic; actions on one line |
| `kw.or` | `or` | `或` | `或` | logic |
| `kw.not` | `not` | `非` | `非` | logic |
| `kw.each` | `each` | `逐一` | `逐个` | a loop over a bounded list |
| `kw.in` | `in` | `於` | `在` | membership; `each NAME in LIST` |
| `kw.reject` | `reject` | `拒絕` | `拒绝` | refuses a call, with a text |
| `kw.test` | `test` | `測試` | `测试` | a test |
| `kw.use` | `use` | `使用` | `使用` | declares a vocabulary pack the source uses (3.9) |
| `kw.request` | `request` | `請求` | `请求` | asks an executor to act outside the ledger (6.11; packs version 5) |
| `kw.done` | `done` | `完成` | `完成` | an answer's outcome: carried out (contextual, 2.6) |
| `kw.fails` | `fails` | `失敗` | `失败` | an answer's outcome: failed (contextual) |
| `kw.expires` | `expires` | `過期` | `过期` | an answer's outcome: no answer by the deadline (contextual) |

## Appendix B. Vocabulary

The words of edition 1, by category, with the vocabulary pack each belongs to (`core` for Bo's core, 3.9), as the official packs spell them. Where a pack gives several spellings, the first is the one tools write, and the others read the same. The English forms read as the word too (3.3). The packs are the reference: [`../bo/packs/`](../bo/packs).

**Kinds** (`kind.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `kind.asset` | finance | `asset` | `資產` | `资产` | plural `assets`, indefinite `an asset` |
| `kind.resource` | services | `resource` | `資源` | `资源` | plural `resources`, indefinite `a resource` |
| `kind.service` | services | `service` | `服務` | `服务` | plural `services`, indefinite `a service` |
| `kind.thing` | core | `thing` | `物件` | `物件` | plural `things`, indefinite `a thing` |

**Actions** (`act.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `act.allocate` | services | `allocate` | `分配` | `分配` | third `allocates`, gerund `allocating` |
| `act.approve` | core | `approve` | `批准` | `批准` | third `approves`, gerund `approving` |
| `act.cancel` | core | `cancel` | `註銷` | `注销` | third `cancels`, gerund `cancelling` |
| `act.confirm_payment` | finance | `confirm payment` | `確認收款` | `确认收款` | third `confirms payment`, gerund `confirming payment` |
| `act.create` | core | `create` | `建立` | `创建` | third `creates`, gerund `creating` |
| `act.credit` | commerce | `credit` | `抵扣` | `抵扣` | third `credits`, gerund `crediting` |
| `act.dispute` | finance | `dispute` | `提出爭議` | `提出争议` | third `disputes`, gerund `disputing` |
| `act.downgrade` | services | `downgrade` | `降級` | `降级` | third `downgrades`, gerund `downgrading` |
| `act.enforce` | finance | `enforce` | `執行質權` | `实现质权` | third `enforces`, gerund `enforcing` |
| `act.freeze` | finance | `freeze` | `凍結` | `冻结` | third `freezes`, gerund `freezing` |
| `act.issue` | core | `issue` | `發出` | `签发` | third `issues`, gerund `issuing` |
| `act.notify` | core | `notify` | `通知` | `通知` | third `notifies`, gerund `notifying` |
| `act.pay` | finance | `pay` | `支付` | `支付` | third `pays`, gerund `paying` |
| `act.pledge` | finance | `pledge` | `質押` | `质押` | third `pledges`, gerund `pledging` |
| `act.propose` | core | `propose` | `提議` | `提议` | third `proposes`, gerund `proposing` |
| `act.reclaim` | services | `reclaim` | `收回` | `收回` | third `reclaims`, gerund `reclaiming` |
| `act.redeem` | finance | `redeem` | `贖回` | `赎回` | third `redeems`, gerund `redeeming` |
| `act.refund` | commerce | `refund` | `退款` | `退款` | third `refunds`, gerund `refunding` |
| `act.release` | finance | `release` | `解除質押` | `解除质押` | third `releases`, gerund `releasing` |
| `act.renew` | services | `renew` | `續期` | `续费` | third `renews`, gerund `renewing` |
| `act.resume` | core | `resume` | `恢復` | `恢复` | third `resumes`, gerund `resuming` |
| `act.split` | finance | `split` | `拆分` | `拆分` | third `splits`, gerund `splitting` |
| `act.subscribe` | services | `subscribe` | `訂購` | `订购` | third `subscribes`, gerund `subscribing` |
| `act.suspend` | core | `suspend` | `暫停` | `暂停` | third `suspends`, gerund `suspending` |
| `act.terminate` | core | `terminate` | `終止` | `终止` | third `terminates`, gerund `terminating` |
| `act.transfer` | core | `transfer` | `轉讓` | `转让` | third `transfers`, gerund `transferring` |
| `act.unfreeze` | finance | `unfreeze` | `解凍` | `解冻` | third `unfreezes`, gerund `unfreezing` |
| `act.upgrade` | services | `upgrade` | `升級` | `升级` | third `upgrades`, gerund `upgrading` |

**Conditions** (`cond.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 |
|---|---|---|---|---|
| `cond.before_due` | core | `… before due` | `到期前 …` | `到期前 …` |
| `cond.consent_of` | core | `consent of …` | `經 … 同意` | `经 … 同意` |
| `cond.in_person` | core | `in person` | `親身確認` | `本人确认` |
| `cond.over` | core | `over …` | `超過 …` | `超过 …` |
| `cond.overdue` | core | `overdue` | `逾期` | `逾期` |
| `cond.within` | core | `within …` | `… 內` | `… 内` |

**Prices and usage** (`price.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `price.overage` | commerce | `overage` | `超出` | `超出` | |
| `price.per` | commerce | `per` | `每` | `每` | |
| `price.price` | commerce | `price` | `價格` | `价格` | plural `prices` |
| `price.setup_fee` | commerce | `setup fee` | `開通費` | `开通费` | plural `setup fees` |
| `price.traffic` | services | `traffic` | `流量` | `流量` | |
| `price.usage` | commerce | `usage` | `用量` | `用量` | |

**Charges** (`charge.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `charge.added` | commerce | `added` | `另計` | `另计` | |
| `charge.applies_to` | commerce | `applies to …` | `適用 …` | `适用 …` | |
| `charge.by` | commerce | `according to` | `按` | `按` | |
| `charge.charge` | commerce | `charge` | `費用` | `费用` | plural `charges` |
| `charge.from` | commerce | `from … on` | `從 … 起` | `从 … 起` | |
| `charge.included` | commerce | `included` | `內含` | `含税`, `内含` | |
| `charge.per_document` | commerce | `per document` | `按單據` | `按单据` | |
| `charge.per_line` | commerce | `per line` | `逐行` | `逐行` | |
| `charge.rate` | commerce | `rate` | `稅率`, `費率` | `税率`, `费率` | plural `rates` |
| `charge.tax` | commerce | `tax` | `稅` | `税` | plural `taxes` |

**Time** (`time.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `time.at` | core | `at …` | `時間 …` | `时间 …` | |
| `time.daily` | core | `daily` | `每日` | `每天` | |
| `time.day` | core | `day` | `日` | `天` | plural `days` |
| `time.month` | core | `month` | `個月` | `个月` | plural `months` |
| `time.monthly` | core | `monthly` | `每月` | `每月` | |
| `time.now` | core | `now` | `現時` | `现在` | |
| `time.today` | core | `today` | `今日` | `今天` | |
| `time.week` | core | `week` | `週` | `周` | plural `weeks` |
| `time.weekly` | core | `weekly` | `每週` | `每周` | |
| `time.year` | core | `year` | `年` | `年` | plural `years` |
| `time.yearly` | core | `yearly` | `每年` | `每年` | |

**Units** (`unit.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `unit.GB` | core | `GB` | `GB` | `GB` | |
| `unit.Gbps` | core | `Gbps` | `Gbps` | `Gbps` | |
| `unit.GiB` | core | `GiB` | `GiB` | `GiB` | |
| `unit.MB` | core | `MB` | `MB` | `MB` | |
| `unit.Mbps` | core | `Mbps` | `Mbps` | `Mbps` | |
| `unit.MiB` | core | `MiB` | `MiB` | `MiB` | |
| `unit.TB` | core | `TB` | `TB` | `TB` | |
| `unit.TiB` | core | `TiB` | `TiB` | `TiB` | |
| `unit.item` | core | `item` | `個` | `个` | plural `items` |
| `unit.kg` | core | `kg` | `公斤` | `公斤` | |
| `unit.tonne` | core | `tonne` | `噸` | `吨` | plural `tonnes` |
| `unit.celsius` | core | `degree Celsius` | `攝氏度` | `摄氏度` | plural `degrees Celsius`; written `°C` (also read `℃`) in every language (2.10) |

**Currencies** (`cur.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 |
|---|---|---|---|---|
| `cur.CNY` | core | `CNY` | `人民幣` | `人民币` |
| `cur.EUR` | core | `EUR` | `歐元` | `欧元` |
| `cur.HKD` | core | `HKD` | `港元` | `港元` |
| `cur.SGD` | core | `SGD` | `新加坡元` | `新加坡元` |
| `cur.USD` | core | `USD` | `美元` | `美元` |

**Rounding modes** (`round.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 |
|---|---|---|---|---|
| `round.down` | core | `down` | `捨去` | `舍去` |
| `round.half_even` | core | `half even` | `四捨六入五成雙` | `四舍六入五成双` |
| `round.half_up` | core | `half up` | `四捨五入` | `四舍五入` |

**Documents** (`doc.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `doc.credit_note` | commerce | `credit note` | `貸項通知單` | `红字发票` | plural `credit notes` |
| `doc.invoice` | commerce | `invoice` | `發票` | `发票` | plural `invoices` |
| `doc.receipt` | commerce | `receipt` | `收據` | `收据` | plural `receipts` |

**Types** (`type.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 |
|---|---|---|---|---|
| `type.date` | core | `date` | `日期` | `日期` |
| `type.list` | core | `list` | `清單` | `列表` |
| `type.number` | core | `number` | `數值` | `数值` |
| `type.text` | core | `text` | `文字` | `文本` |
| `type.yes_no` | core | `yes or no` | `是否` | `是否` |

**Values** (`val.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 |
|---|---|---|---|---|
| `val.no` | core | `no` | `否` | `否` |
| `val.none` | core | `none` | `無` | `无` |
| `val.pending_approval` | core | `pending approval` | `待批准` | `待批准` |
| `val.refused` | core | `refused` | `被拒絕` | `被拒绝` |
| `val.yes` | core | `yes` | `是` | `是` |

**Fields** (`field.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `field.amount` | core | `amount` | `金額` | `金额` | object `the amount` |
| `field.cooling_period` | services | `cooling period` | `冷卻期` | `冷却期` | object `the cooling period` |
| `field.customer_location` | commerce | `customer location` | `客戶所在地` | `客户所在地` | object `the customer location` |
| `field.due` | core | `due` | `到期日` | `到期日` | object `the due date` |
| `field.holder` | core | `holder` | `持有人` | `持有人` | subject `the holder`, object `the holder` |
| `field.parts` | core | `parts` | `各部分` | `各部分` | object `the parts` |
| `field.payee` | finance | `payee` | `收款人` | `收款人` | subject `the payee`, object `the payee` |
| `field.pledgee` | finance | `pledgee` | `質權人` | `质权人` | subject `the pledgee`, object `the pledgee` |
| `field.portion` | finance | `portion` | `部分` | `部分` | object `the portion` |
| `field.quantity` | core | `quantity` | `數量` | `数量` | object `the quantity` |
| `field.recipients` | core | `recipients` | `各接收方` | `各接收方` | subject `the recipients`, object `the recipients` |
| `field.tier` | finance | `tier` | `層級` | `层级` | object `the tier` |
| `field.utc_offset` | core | `UTC offset` | `UTC 時差`, `UTC時差` | `UTC 时差`, `UTC时差` | object `the UTC offset` |

**States** (`state.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 |
|---|---|---|---|---|
| `state.active` | core | `active` | `正常` | `正常` |
| `state.allocated` | services | `allocated` | `已分配` | `已分配` |
| `state.cancelled` | core | `cancelled` | `已註銷` | `已注销` |
| `state.cooling` | services | `cooling` | `冷卻中` | `冷却中` |
| `state.disputed` | finance | `disputed` | `爭議中` | `争议中` |
| `state.divided` | core | `divided` | `已拆分` | `已拆分` |
| `state.frozen` | finance | `frozen` | `已凍結` | `已冻结` |
| `state.paid` | finance | `paid` | `已支付` | `已支付` |
| `state.pledged` | finance | `pledged` | `已質押` | `已质押` |
| `state.proposed` | core | `proposed` | `已提議` | `已提议` |
| `state.redeemed` | finance | `redeemed` | `已贖回` | `已赎回` |
| `state.settled` | finance | `settled` | `已結清` | `已结清` |
| `state.suspended` | core | `suspended` | `已暫停` | `已暂停` |
| `state.terminated` | core | `terminated` | `已終止` | `已终止` |

**Actors** (`actor.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `actor.ai_agent` | core | `AI agent` | `AI 代理`, `AI代理` | `AI 代理`, `AI代理` | plural `AI agents` |
| `actor.device` | core | `device` | `裝置` | `设备` | plural `devices` |
| `actor.keeper` | core | `keeper` | `排程器` | `调度器` | plural `keepers` |
| `actor.executor` | core | `executor` | `執行器` | `执行器` | plural `executors` |
| `actor.person` | core | `person` | `真人` | `真人` | plural `people` |

**Roles** (`role.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 | English forms |
|---|---|---|---|---|---|
| `role.bank` | finance | `bank` | `銀行` | `银行` | subject `the bank`, object `the bank` |
| `role.counterparty` | core | `counterparty` | `相對方` | `相对方` | subject `the counterparty`, object `the counterparty` |
| `role.customer` | commerce | `customer` | `客戶` | `客户` | subject `the customer`, object `the customer` |
| `role.issuer` | finance | `issuer` | `發行人` | `发行人` | subject `the issuer`, object `the issuer` |
| `role.supplier` | finance | `supplier` | `供應商` | `供应商` | subject `the supplier`, object `the supplier` |
| `role.we` | core | `we` | `我方`, `本公司` | `我方`, `本公司` | object `us` |

**Expressions** (`expr.*`)

| Concept | Pack | English | 繁體中文（香港） | 简体中文 |
|---|---|---|---|---|
| `expr.at_most` | core | `at most …` | `最多 …` | `最多 …` |
| `expr.count_of` | core | `count of …` | `… 數目` | `… 数目` |
| `expr.previous_state` | core | `previous state` | `原先狀態` | `原先状态` |
| `expr.result` | core | `result` | `結果` | `结果` |
| `expr.reason` | core | `reason` | `原因` | `原因` |
| `expr.sum_of` | core | `sum of …` | `… 總和` | `… 总和` |

## Appendix C. Diagnostic codes

Every problem the compiler reports has a code, a severity, and parameters, which a pack's message names in braces (`{path}`); the English pack's messages are below. An error refuses the source (or the pack); a warning does not. The `run.*` codes are the messages of compiled contracts' refusals: the reason `bo:CODE VALUES` is the message `run.CODE` with the values as its parameters, in order (12.9). The official packs give each message in all three languages.

### Packs (`pack.*`)

| Code | Severity | English message |
|---|---|---|
| `pack.syntax` | error | the pack is not valid CBOR diagnostic notation: {detail} |
| `pack.too-large` | error | the pack is {size} bytes; the limit is {limit} |
| `pack.expected-map` | error | {path} must be a map |
| `pack.expected-text` | error | {path} must be a text string |
| `pack.expected-list` | error | {path} must be a list |
| `pack.expected-integer` | error | {path} must be an unsigned integer |
| `pack.expected-boolean` | error | {path} must be true or false |
| `pack.unknown-key` | error | {path} has an unknown key {key} |
| `pack.missing-key` | error | {path} needs the key {key} |
| `pack.format` | error | pack format {value} is not supported; this compiler reads format 1 |
| `pack.edition` | error | Bo edition {value} is not supported; this compiler knows edition 1 |
| `pack.bad-id` | error | {value} is not a valid pack id: letters, digits, and single hyphens, starting with a letter, at most 64 |
| `pack.bad-language` | error | {value} is not a valid language tag (BCP 47, such as zh-Hant-HK) |
| `pack.bad-version` | error | the version must be 1 or more, not {value} |
| `pack.bad-text` | error | {path} must be 1 to 200 bytes (64 for month names, 1,000 for messages and sentences), without control characters |
| `pack.bad-value` | error | {path} cannot be {value} |
| `pack.too-many` | error | {path} has more than {limit} entries |
| `pack.unknown-concept` | error | {path}: {concept} is not a concept of Bo edition 1 |
| `pack.wrong-category` | error | {path}: {concept} is in the category {category}, which does not belong here |
| `pack.missing-keyword` | error | pack {pack} does not spell the keyword {concept}; every pack spells every keyword |
| `pack.partial` | warning | pack {pack} does not spell {missing} of the {total} words; those are read and shown in English |
| `pack.bad-spelling` | error | {path}: {spelling} is not a valid spelling: one to four words separated by single spaces, none longer than 64 bytes or starting with a digit |
| `pack.bad-character` | error | {path}: {spelling} contains {character}, which no word may contain |
| `pack.needs-hole` | error | {path}: {spelling} must mark the place of {concept}'s argument with … (once) |
| `pack.unexpected-hole` | error | {path}: {spelling} may not contain …: {concept} takes no argument |
| `pack.bad-form` | error | {path}: {form} is not a valid form name (lowercase letters, at most 16) |
| `pack.duplicate-spelling` | error | pack {pack} gives {spelling} two meanings: {concept} and {other} |
| `pack.conflict` | error | {spelling} means {meaning} in pack {pack} but {other} in pack {other_pack}; one spelling cannot have two meanings |
| `pack.ambiguous-attachment` | error | {spelling} ({meaning}) could also be read as {first} + {second}; change a spelling or narrow the attaching rule |
| `pack.bad-attach` | error | {path}: {concept} cannot attach: it must be spelled in this pack as one word, with … only on the side away from its neighbour |
| `pack.unknown-category` | error | {path}: {category} is not a category a word may attach to |
| `pack.bad-punctuation` | error | {path}: {character} cannot be a punctuation alias: one character that no word contains, for one of , : ( ) % " = < > + - \* / . \_ a digit or a space |
| `pack.bad-multiplier` | error | {path}: {value} is not a power of ten from 10 to 10^18 |
| `pack.bad-date` | error | {path}: {pattern} is not a valid date pattern: the fields Y, M (or MONTH, to write, with twelve month names), and D, each once and in braces, with text between them |
| `pack.unknown-message` | error | {path}: {code} is not a message code |
| `pack.unknown-sentence` | error | {path}: {id} is not a sentence id |
| `pack.bad-placeholder` | error | {path}: {placeholder} is not a placeholder this text may use |
| `pack.false-official` | error | pack {pack} says it is official, but it is not one of the official packs this compiler carries |
| `pack.duplicate-id` | error | two packs have the id {pack} |

### Reading a source (`lex.*`)

| Code | Severity | English message |
|---|---|---|
| `lex.too-large` | error | the source is {size} bytes; the limit is {limit} |
| `lex.utf8` | error | the source is not valid UTF-8 here |
| `lex.invisible` | error | the invisible character {character} is not allowed: the source must read as it looks |
| `lex.tab` | error | a tab is not allowed; indent and separate words with spaces |
| `lex.indent-character` | error | indent with spaces only, not {character} |
| `lex.dedent` | error | this line's indentation matches no enclosing block |
| `lex.too-deep` | error | blocks nest more than {limit} deep |
| `lex.bad-character` | error | {character} cannot appear here: it is not part of a word, a number, or an operator |
| `lex.bad-number` | error | {text} is not a number: digits, with \_ only between digits and at most one decimal point between digits (5_000, 0.10) |
| `lex.digit-comma` | error | {text}: a comma never groups digits; write {suggestion} |
| `lex.number-too-large` | error | {text} has more digits than Bo keeps: at most 18446744073709551615 without the decimal point, and 18 decimal places |
| `lex.number-suffix` | error | {suffix} cannot follow the number in {text}: a number may be followed directly by a multiplier (萬), then a unit, a time unit, or a currency (2TB, 30日, 500萬港元), then a word such as 內 |
| `lex.multiplier` | error | {word} multiplies the number just before it: 500萬 or 500 萬 |
| `lex.percent` | error | % must follow its number directly: 5% |
| `lex.bad-date` | error | {text} is not a date: write YYYY-MM-DD with a year from 1 to 9999, a month from 01 to 12, and a day the month has (2027-01-06) |
| `lex.unterminated-text` | error | the text has no closing quote on this line |
| `lex.text-too-long` | error | the text is longer than {limit} bytes |
| `lex.edition` | error | Bo edition {value} is not supported; this compiler reads edition 1 |
| `lex.bad-edition` | error | the first line names the edition: bo followed by its number alone (bo 1) |
| `lex.ambiguous` | error | {text} can be read as {first} or as {second}; Bo never guesses: add a space where the words divide |
| `lex.ambiguous-money` | error | in {text}, a currency stands between two numbers, or a number between two currencies, so which belongs to which is unclear: keep each amount with its currency, and separate the amounts |
| `lex.needs-space` | error | {text}: write {first} and {second} apart, with a space |
| `lex.bad-name` | error | {name} is not a name: a name starts with a letter, followed by letters, marks, digits, or \_ |
| `lex.name-too-long` | error | {name} is longer than {limit} bytes |
| `lex.not-normalized` | error | {character} would change under Unicode normalization: write the composed character instead, so that names that look alike are the same name |
| `lex.mixed-script` | error | {name} mixes Latin, Greek, or Cyrillic letters, which look alike: write a name in one of these scripts |
| `lex.confusable` | error | {name} looks like {other} but is not the same: write it one way, or choose a name that looks different |

### Parsing (`parse.*`)

| Code | Severity | English message |
|---|---|---|
| `parse.top-level` | error | {found} cannot start a line here: outside any block, a line starts with use, contract, parties, a kind (thing; asset, service, or resource with their packs), charge or tax, can, when, or test |
| `parse.statement` | error | {found} cannot start a line in an action's block: write requires, if, otherwise, each, reject, a field set (holder = bank), a state change (active -> suspended), an action (notify customer), or who may propose (AI agent can propose) |
| `parse.field` | error | {found} cannot appear in a field: a block's line names a field, then its type or value (amount HKD, IP 1 item), with commas between parts |
| `parse.step` | error | {found} cannot start a step: a test's lines are steps, the party first (supplier pledge to bank, optionally at DATE, in person, by AI agent), and expectations (-> pledged, -> refused) |
| `parse.trailing` | error | the line is complete before {found}: remove it, or start a new line |
| `parse.unexpected-block` | error | these lines are indented, but the line before them opens no block |
| `parse.empty-block` | error | {word} needs what it governs: an indented block under it, or for when, if, and otherwise, a statement on the same line |
| `parse.otherwise` | error | {word} must follow an if block at the same indentation |
| `parse.duplicate` | error | {word} is given twice; give it once |
| `parse.reserved` | error | {word} declares a vocabulary pack on a line of its own, outside any block: use finance |
| `parse.too-deep` | error | this line nests more than {limit} levels deep (parentheses, operators, or otherwise if) |
| `parse.expected-name` | error | a name of your own must follow {after}: keywords and words of the vocabulary cannot be names |
| `parse.expected-action` | error | an action must follow {after}: a word of the vocabulary (pledge, transfer) or a name of your own |
| `parse.expected-party` | error | a party must follow {after}: a role (issuer, bank, customer) or a name of your own |
| `parse.expected-value` | error | a value must follow {after} |
| `parse.expected-text` | error | a text in double quotes must follow {after} |
| `parse.expected-state` | error | a state must follow {after}: a word such as pledged, a name of your own, or refused in a test |
| `parse.expected-set` | error | a field and its value must follow {after}: amount = HKD 100, with commas between them |
| `parse.can` | error | {found} cannot follow the action here: write by PARTY, to PARTY, or with INPUTS, each at most once |
| `parse.when` | error | when needs an event before its action: when overdue 3 days suspend, when 7 days before due notify customer |
| `parse.request` | error | a request is written request KIND [to PARTY] [with NAME = VALUE, ...] within DURATION, its kind a name or an action's word; found {found} |
| `parse.each` | error | each is written each NAME in LIST, with the lines to repeat in a block under it |
| `parse.bare-condition` | error | a condition alone does nothing: write requires or if before it; to set a field, write FIELD = VALUE |
| `parse.unclosed` | error | this ( is not closed on its line |
| `parse.missing-head` | error | {text} ends {concept}, but the word that begins it is missing |
| `parse.missing-tail` | error | {text} begins {concept}, but the word that ends it is missing after the value |
| `parse.missing-argument` | error | {text} ({concept}) needs its value before it, as in 7 days before due |
| `parse.chained-comparison` | error | comparisons do not chain: write a < b and b < c, not a < b < c (at {operator}) |
| `parse.phrase-operator` | error | words side by side cannot be combined with {operator}: put them in parentheses |
| `parse.ambiguous-name` | error | {name} could be the name {name} or {prefix} followed by {rest}, since both are declared; Bo never guesses: write {prefix} {rest} with a space, or rename one of them |
| `parse.undeclared-split` | error | {name} is one name here, since nothing declares {rest}; to begin the line with {prefix}, write {prefix} {rest} with a space |

### Checking (`check.*`)

| Code | Severity | English message |
|---|---|---|
| `check.fragment` | warning | there is no contract line, so this file is checked as a fragment; bo build will need contract NAME |
| `check.no-parties` | error | the contract has actions but no parties line: write parties, then its roles (parties issuer, supplier, bank) |
| `check.unknown-pack` | error | use {pack}: Bo has no such vocabulary pack; its packs are commerce, finance, and services |
| `check.pack-not-used` | error | {word} is a word of the {pack} vocabulary pack, which the source does not use: write use {pack} at its top |
| `check.duplicate` | error | {name} is declared twice; a name has one meaning in a contract |
| `check.one-kind` | error | a contract describes one kind of instance; {name} would be a second: write another contract for it |
| `check.unknown-name` | error | {name} is not declared: it is not a party, a field, an input, a state, or a name each gives |
| `check.unknown-party` | error | {party} is not one of the contract's parties: add it to the parties line |
| `check.unknown-field` | error | the instance has no field {field}: declare it in the kind's block (amount HKD, due date) |
| `check.unknown-input` | error | {action} has no input {name} |
| `check.field-head` | error | {text} cannot name a field: use a name of your own, or a field or price word (amount, due, holder, price) |
| `check.field-needs-type` | error | {field} needs its type or its value: amount HKD, due date, IP 1 item |
| `check.field-type` | error | {field} holds {expected_type}, not {type} |
| `check.default-field` | error | {field} cannot have a default: only an instance field given at creation has one; a constant has its value, a party field starts with its party, and a bill is made from its lines |
| `check.default-value` | error | {text} is no default: a default is a value written out, of the field's type: 0, HKD 0, no, "none yet", 2027-01-01, or a list of them |
| `check.field-values` | error | {field} takes one type or value; further parts after commas must be labelled prices (overage per GB HKD 0.10) |
| `check.not-a-value` | error | {text} is not a value here: a value is a number, an amount, a date, a text, a party, a field, an input, or a condition where one may stand |
| `check.phrase` | error | Bo reads no value in {text}: words side by side form a recurring amount (monthly HKD 120), a unit price (per GB HKD 0.10), a labelled price (overage per GB HKD 0.10), overdue N, or according to a field |
| `check.type` | error | {text} is {type}, but {expected_type} is needed here |
| `check.operands` | error | {operator} cannot combine {left_type} with {right_type} |
| `check.mixed-currencies` | error | {left_type} and {right_type} are in different currencies; Bo never converts one into the other |
| `check.mixed-units` | error | {left_type} and {right_type} measure different things, which never mix |
| `check.calendar` | error | {text} mixes months or years with days or weeks: a month has no fixed number of days, so Bo neither compares nor adds them |
| `check.precision` | error | {text} is finer than Bo keeps: money to the currency's cent, unit prices to six decimal places, rates to 0.0001%, quantities to whole bytes, bits per second, items, or grams, temperatures to hundredths of a degree |
| `check.whole-number` | error | {text} must be a whole number here (for a share, write a rate: 150%) |
| `check.overflow` | error | {text} is too large: Bo keeps every value as a whole number of its smallest unit, in 64 bits |
| `check.zero-division` | error | {text} divides by zero |
| `check.list-items` | error | the items of {text} are not all of one type |
| `check.list-bound` | error | {text}: a list holds from 1 to {limit} items |
| `check.each-body` | error | {text}: the block of each runs once for each item, so it cannot change the state, do an action, or make a request; move it out of each |
| `check.set-constant` | error | {field} is a constant (the block gives its value), so no action can change it; to let actions change it, declare its type instead (tier number) |
| `check.set-target` | error | {text} cannot be set: only a field of the instance can |
| `check.initial-state` | error | an instance could start in any of {states}, since no state change leads to them; Bo never guesses: an instance starts in the one state nothing leads to, otherwise in active |
| `check.unreachable-state` | error | no state change leads to {state} from the state an instance starts in, so no instance can ever reach it |
| `check.needs-by` | error | who starts {action}? An action of your own needs by PARTY |
| `check.recursion` | error | {action} leads back to itself through the actions it does; a contract never recurses |
| `check.permit` | error | {text}: the only line of this kind in edition 1 is AI agent can propose |
| `check.subject` | error | {text}: inside an action only the contract acts; a party's duty belongs in a when rule (when due issuer pays) |
| `check.threshold-amount` | error | {text} compares the amount of {action}, which has no one amount: give it one input of money (with amount HKD) or the instance an amount field, or compare a field instead (requires amount > HKD 100) |
| `check.standard-by` | error | {action} is a built-in action, started by {party} under its standard terms; to have another party start it, copy it under a name of your own (cexchain bo stdlib show {action}) |
| `check.standard-to` | error | {action} has no counterparty under its standard terms, so it takes no to; to give it one, copy it under a name of your own (cexchain bo stdlib show {action}) |
| `check.standard-change` | error | {text}: the state changes of {action}, and the fields its standard terms change, are the standard terms'; to change them, copy it under a name of your own (cexchain bo stdlib show {action}) |
| `check.standard-field` | error | the standard terms of {action} use the field {field}, which each instance must hold and actions may change: declare it in the kind's block, with its type |
| `check.standard-unreachable` | error | {action} can never start: under its standard terms it starts only from {states}, which no instance of this contract ever reaches |
| `check.when-event` | error | {text} is not a time: a when rule fires at a date (when due, when due + 3 days), N before due, overdue or overdue N, or once the instance has been in a state for N (when suspended 30 days), with other conditions joined by and |
| `check.when-person` | error | {text} asks for a person, but a keeper (a device) calls a when rule: nobody confirms it in person or proposes it |
| `check.needs-due` | error | {text} counts from a due date, which the instance does not have: declare due date in the kind's block (a service with a recurring price is due at the end of each period) |
| `check.when-action` | error | {action} cannot be done by a when rule: the keeper's call gives no arguments, and {action} names a counterparty or takes inputs |
| `check.utc-offset` | error | {text} is not a UTC offset: write a text such as "+08:00" or "-05:30", from -14:00 to +14:00 |
| `check.charge-field` | error | {text} is not a line a charge has: rate, amount, applies to, included or added, per line, per document, according to a document, a rounding mode, or from DATE on with a rate |
| `check.charge-rate` | error | the charge {name} needs a rate (rate 5%) or an amount (amount HKD 20), and not both |
| `check.charge-included` | error | say whether {name} is included in the price or added to it: write included or added, once |
| `check.document` | error | {field} holds the lines of a bill: declare one such field, in the kind's block, as a list of money in one currency (invoice list HKD) |
| `check.charge-document` | error | the charge {name} is computed on a bill, but no field holds one: declare a field named by a document, such as invoice list HKD |
| `check.charge-twice` | error | {text}: the charge {name} already says this; say it once |
| `check.charge-on` | error | {name} cannot be computed on {other}: a charge is computed on the price and on charges written before it (one on each line only on charges on each line), and an included charge or a fixed amount only on the price |
| `check.charge-rounding` | error | {name} is a fixed amount, which is never rounded: give it no rounding mode |
| `check.charge-bill` | error | {name} is rounded once per {document}, but the contract's bill is another document |
| `check.needs-executor` | warning | {action} asks an executor to act outside the ledger, which comes in step 6b: bo check accepts it, and bo build will refuse it until then |
| `check.request-kind` | error | {text} is not a request kind: write a name of lowercase Latin letters, digits, and _, starting with a letter (at most 64 bytes), or an action's word |
| `check.request-value` | error | {name}: a request carries numbers, money, quantities, rates, dates, durations, texts, yes or no, parties, and lists of them, not {type} |
| `check.request-within` | error | {text}: a request names its deadline, within a duration written out, from 1 day to 366 days (12 months) |
| `check.request-count` | error | {function} can make {count} requests in one call; a call makes at most 16 |
| `check.answer-twice` | error | a second rule for {text}: one rule for each kind and outcome |
| `check.answer-unasked` | warning | the contract makes no request {kind}, so this rule never applies |
| `check.answer-line` | error | {text}: an answer is never refused and cites no consent, so a rule for answers does no action, refuses nothing, and sets no party; it sets fields, changes the state with -> STATE (or if STATE -> STATE), and makes requests |
| `check.test-start` | error | a test begins by creating its instance: PARTY {action} with FIELD = VALUE, ...; the party that creates it is the home, whose ledger runs the contract |
| `check.test-again` | error | a test creates its instance once, in its first step |
| `check.test-creation` | error | {text}: an instance of this contract is created with {action} (issue for an asset, create otherwise) |
| `check.test-home` | error | an instance is created by its home, {party}: the role {party} names the ledger that runs the contract |
| `check.test-action` | error | {action} is not an action of this contract: a step does one of the actions it declares (can ...), or creates the instance |
| `check.test-party` | error | {text} is not a party: a step names one of the contract's parties, or a ledger that only tests name (bank1) |
| `check.test-to` | error | {action} has no counterparty, so a step that does it names none: drop to |
| `check.test-counterparty` | error | the counterparty of {action} is {party}, bound to a ledger when the instance is created: write to {party} |
| `check.test-signer` | error | {text}: a step is by AI agent (an agent signs it) or in person (a person proves presence), not both, and by names nobody else |
| `check.test-step` | error | {text}: besides to and with, a step takes at DATE, in person, and by AI agent, each once |
| `check.test-time` | error | {text}: at takes a date after 1970-01-01 (at 2027-01-06) |
| `check.test-time-back` | error | {text} is earlier than a step before it: time never goes back in a test |
| `check.test-value` | error | {text}: a test gives each value as written: a number, an amount, a quantity, a date, a duration, a rate, a text, or yes or no |
| `check.test-missing` | error | {action} needs {name}: give it with {name} = VALUE |
| `check.test-expect` | error | {text} is not an outcome a step can expect: write a state of the contract (-> signed), refused (-> refused, or with its reason in quotes), or the consent the call waits for (-> consent of bank); values of fields follow a comma (-> signed, fee = HKD 5) |
| `check.test-field` | error | {name} is no field an instance holds: a step expects the values of instance fields after its call (-> delivered, fee = HKD 4_000), and a constant never changes |
| `check.test-fields` | error | {text}: values of fields are expected only of a call that is accepted (-> delivered, fee = HKD 4_000, or -> fee = HKD 0), not of one refused, waiting for consents, or kept as a proposal |
| `check.test-expect-step` | error | an expectation (->) follows the step it is about, once |
| `check.test-reason` | error | {text}: only refused takes a reason |
| `check.test-proposal` | error | -> pending approval: only a call by AI agent to an action an AI agent may only propose (AI agent can propose) is kept as a proposal, and {action} is not such an action |
| `check.test-needs-to` | error | {action} takes its counterparty from each call: write to PARTY (supplier transfer to factor1) |
| `check.test-rule` | error | no when rule does {action}: a keeper step names the action a when rule does (keeper suspend) |
| `check.test-part` | error | {text}: a step names the instance it acts on by the party that holds it (issuer pay smith1): one party, in a contract whose instances have a holder |
| `check.parts-place` | error | {text}: an action issues parts once, in its own block (not under if or each), and a when rule never does |
| `check.parts-shape` | error | {text}: issue PARTS to RECIPIENTS [with FIELD = VALUE, ...]: the parts a list of amounts in the unit of the instance's amount, the recipients a list of parties, and with sets fields of the instance other than the amount and the holder |
| `check.parts-instance` | error | {action} issues parts, so each instance needs an amount (money or a quantity) and a holder, and no bill |
| `check.test-keeper` | error | {text}: the keeper calls a when rule with nothing else: no to, with, in person, or by AI agent |
| `check.test-answer` | error | {text}: a step answers a request the contract makes, as executor KIND done, fails, or expires, giving at most a result and a reason, both texts |

### Building (`build.*`)

| Code | Severity | English message |
|---|---|---|
| `build.fragment` | error | this file has no contract line, so it is a fragment: only a contract (contract NAME) compiles |
| `build.standard-action` | error | {action} is a built-in action: its template comes with the standard library, in a later version of the compiler; for now, declare an action of your own (can NAME by PARTY) |
| `build.executor` | error | {action} asks an executor to act outside the ledger, which comes in step 6b: deployed code never changes, so it cannot be compiled before then |
| `build.time-rule` | error | {text}: this when rule cannot be compiled yet: a service is due at the end of each paid period, which its executors (step 6b) track |
| `build.unsupported` | error | {text} uses {feature}, which this version of the compiler does not compile yet |
| `build.name-taken` | error | two parts of the compiled contract would have the name {name} (functions, fields, parties, or inputs): rename one |
| `build.name-too-long` | error | {name} is too long for compiled code: at most {limit} bytes |
| `build.too-many-functions` | error | the contract has more actions than a compiled contract allows ({limit} functions) |
| `build.too-many-parties` | error | the contract has more parties and party fields than a compiled contract allows ({limit}) |
| `build.too-many-fields` | error | the contract has more fields than a compiled contract allows ({limit}) |
| `build.too-many-inputs` | error | {action} has more inputs than a compiled action allows ({limit}) |
| `build.too-many-events` | error | {action} changes state more often than one call may report ({limit} events) |
| `build.too-many-charges` | error | the contract has more charges than a compiled contract may hold ({limit}) |
| `build.too-large` | error | the compiled contract would be too large: an action's code, or the texts, names, and reasons it holds, exceed what a contract allows |
| `build.reject-text` | error | {text}: a refusal's text cannot start with bo:, which marks the compiler's own reasons |
| `build.late-party` | error | {field} starts with {party}, but an action binds {party} only later: give {field} a party bound at creation |
| `build.fuel` | error | {function} could use up to {bound} fuel in one call, more than the {limit} a call has: give its lists smaller bounds (at most N), or do less in one action |
| `build.output` | warning | {function} could write up to {bound} bytes in one call, more than the {limit} compiled code has for its output: such a call is refused (bo:output). A part repeats its parent's fields, so an instance whose state is large cannot be split into many parts |
| `build.comments` | warning | the source is deployed with its comments ({count} lines): every party, and anyone who verifies the contract, can read them |

### Refusals of compiled contracts (`run.*`)

| Code | Reason | English message |
|---|---|---|
| `run.input` | `bo:input` | the call's input is not what a contract reads: deterministic CBOR within the limits |
| `run.overflow` | `bo:overflow` | a value went beyond what Bo keeps: a whole number of its smallest unit, in 64 bits |
| `run.division-by-zero` | `bo:division-by-zero` | a division by zero |
| `run.date` | `bo:date` | a date outside the years 1 to 9999 |
| `run.output` | `bo:output` | the result is too large: an instance's state holds at most 64 KiB, and a call's output 192 KiB |
| `run.consents` | `bo:consents` | the call would need the consents of more than 16 ledgers |
| `run.function` | `bo:function` | the contract has no such function |
| `run.arguments` | `bo:arguments` | the arguments are not the map of inputs the function takes |
| `run.argument` | `bo:argument NAME` | the argument {name} is missing, or not of its type |
| `run.state` | `bo:state ACTION` | {action} is not possible in the instance's current state |
| `run.requires` | `bo:requires ACTION N` | requirement {number} of {action} is not met |
| `run.in-person` | `bo:in-person ACTION` | {action} needs a person who proves presence (a passkey or a hardware key) |
| `run.party` | `bo:party ROLE` | {party} is not bound to a ledger yet |
| `run.empty` | `bo:empty FIELD` | there is no {party} now |
| `run.pending` | `bo:pending` | the instance already keeps 16 proposals awaiting approval |
| `run.proposal` | `bo:proposal` | no proposal awaiting approval has that function and those arguments |
| `run.approve` | `bo:approve ACTION` | {action} was proposed by an AI agent: a person who proves presence must approve it |
| `run.when` | `bo:when RULE` | {rule} does not apply yet: its time has not come, or its conditions do not hold |
| `run.fired` | `bo:fired RULE` | {rule} has already applied for this time |
| `run.depth` | `bo:depth ACTION` | {action} creates parts, but this instance is a part at depth 8, the deepest the ledger allows |
| `run.parts` | `bo:parts ACTION` | {action} issues one part to each recipient: give as many parts as recipients, one at least |
| `run.request` | `bo:request KIND` | the request {kind} carries more than 4,096 bytes |
| `run.answer` | `bo:answer` | function result takes only the answers to the contract's requests |

### Formatting and reporting (`fmt.*`, `bo.*`)

| Code | Severity | English message |
|---|---|---|
| `fmt.unstable` | error | written in {language}, the source would read differently here: a name the contract gives, or a word, would read together with the words around it as another word of {language}; nothing was formatted: rename the name or reword the line, or format into another language |
| `fmt.internal` | error | laid out canonically, the source would read differently here, so nothing was formatted; this is a bug in the formatter: please report it |
| `bo.truncated` | warning | more problems were found; only the first {limit} are shown |
