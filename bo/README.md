# Bo

Bo is the language CexChain's contracts are written in, and `bo` is its compiler. The chain
knows no contract language: a ledger runs a contract's WebAssembly code and keeps the source its
deploy carries, as given. `bo` does the rest: it checks and builds a contract, runs the tests it
carries, writes its contract text in English, Traditional Chinese, or Simplified Chinese, draws
forms from it, and rebuilds a deployed contract from its source, which shows that the source is
the code's.

```sh
bo check lending.bo                       # problems, as FILE:LINE:COLUMN: error: message (code)
bo test lending.bo                        # the tests the contract carries
bo explain lending.bo                     # the contract text the parties read
bo build lending.bo --out lending.boc     # a deploy file, for cexchain contract deploy
cexchain contract export <contract> --out deployed.boc
bo rebuild deployed.boc                   # its source rebuilt and compared with its code
bo reason 'bo:state countersign'          # a refusal, as the ledger gives it, in words
```

The reference is [`spec/bo.md`](../spec/bo.md), with the conformance suite
[`testvectors/bo-v1.json`](../testvectors/bo-v1.json). Every command takes `--help` and
`--json`, and `bo completion bash` (or `zsh`) completes them.

## In this directory

| Path | What it holds |
|---|---|
| `src/front/` | What reads source: the language and vocabulary packs, the lexer, the parser, the checker, the contract text, the formatter, forms, and calls' arguments. It also builds with Clang, so that libFuzzer fuzzes it |
| `src/` | Building: the checked model lowered (`lower.cpp`) to WebAssembly (`wasm.cpp`) with its runtime (`runtime*.cpp`), each function's fuel and output bounds (`cost.cpp`), and the contract's tests run on its code (`scenario.cpp`) |
| `packs/` | The official language packs (`en`, `zh-Hant-HK`, `zh-Hans-CN`), with every released version in `packs/history/` |
| `vocab/` | The official vocabulary packs (`finance`, `commerce`, `services`), with earlier versions in `vocab/history/` |
| `stdlib/` | The standard terms of the built-in actions |
| `cli/` | The `bo` program |

The compiler is C++26 with static reflection and contracts, built with GCC 16 (`CEXCHAIN_BO`,
in [Building](../README.md#building)). It links only the chain's verification layer (the core,
the crypto backend, and the verifier), never a ledger or a node; the build checks this.

## The language

Bo is the language contracts are written in: a few keywords in English, Traditional Chinese (Hong
Kong usage), and Simplified Chinese, freely mixed, and a built-in vocabulary of words with fixed
meanings. Its core, which every contract reads, holds 84 generic words: kinds of things (`thing`),
common actions (transfer, suspend, cancel), conditions, time words, units (a temperature among
them, `°C`), currencies, types, and common fields, states, and roles. Words of particular fields live in three official *vocabulary
packs*, each with the standard terms of its built-in actions: `finance` (24 words: pledges,
payments, freezes, splits), `commerce` (22: prices, charges such as taxes, bills), and `services`
(12: services and resources allocated to one holder at a time). A contract declares the packs it
uses, one line each at its top (`use finance`; `使用 finance` in Chinese), and a deploy records each
one's version and digest; a pack's word in a contract that does not use its pack is an error, never
a name of the contract's own. Its reference is [`spec/bo.md`](../spec/bo.md), with the conformance suite `testvectors/bo-v1.json`. The
compiler reads every source through *language packs*, then lexes, parses, checks, and compiles it
to contract code, which deploys with its source (`bo build --out`, then `contract deploy`). Each pack maps Bo's
concepts (`kw.can`, `act.transfer`, `unit.GB`) to one language's spellings, with its reading rules
(words that attach without a space, as in `可轉讓` or `30日內`; full-width punctuation; `萬` and `億`;
date forms), its messages, and the sentences of the contract text. A pack never changes what runs:
the same contract compiles to the same code through any of them.

```sh
bo vocab list                          # the core and the vocabulary packs, with digests
bo vocab show finance                  # a pack's words, field types, and built-in actions
bo vocab check events.vocab            # a vocabulary pack of your own
bo check tickets.bo --vocab events.vocab   # a source that uses it
bo packs list                          # the official language packs and their digests
bo packs show zh-Hant-HK               # its reading rules, keywords, and words
bo packs check company.pack            # a pack of your own, alone and with the official ones
bo packs check company.pack --language zh-Hant-HK   # messages in Traditional Chinese
bo check contract.bo                   # problems, as FILE:LINE:COLUMN: error: message (code)
bo check contract.bo --stage lex       # its tokens: 可轉讓 is kw.can + act.transfer
bo check contract.bo --stage parse     # its tree, the same in every language
bo check contract.bo --stage model     # its checked model, with what each rule inferred
```

The lexer reads a word only by the packs' fixed rules and never guesses: a run of characters
with two readings is an error asking for a space. So `可轉讓`, `can transfer`, and `可transfer`
give the same concepts; `可用率` stays one name; `500萬` is 5,000,000, `HKD 0.10` exact money, and
`5,000` an error (write `5_000`). Invisible characters are refused, and so are names that only
look alike (`оwner`, its first letter Cyrillic), so the text the parties read is the text that
runs.

The parser turns the tokens into a tree of concepts and names, so a contract gives the same tree
whatever language it is written in. Words whose argument sits on different sides in different
languages meet there: `7 days before due` and `到期前 7日`, `consent of counterparty` and
`經 相對方 同意`.

```
can transfer to counterparty           可轉讓 予 相對方
  over 50_000 requires in person         超過 50_000 須親身確認

can act.transfer to=role.counterparty  (the tree of both)
  requires cond.in_person guard=(cond.over 50000)
```

Clauses are `use`, `contract`, `parties`, a kind and its fields (`thing Item`), `can` with `by`,
`to`, and `with`, `when`, and `test`; an action's block holds `requires`, `if`/`otherwise`,
`each`, `reject`, `FIELD = VALUE`, and state changes (`active -> suspended`). `=` sets a field at
the start of an action's line and compares inside a condition. Ambiguity is an error, never a
guess: `a < b < c`, or `monthly HKD 120 * 12` (which words does `*` take?), ask for a rewrite, and
`可借出` is read as `可` + `借出` only when the contract declares `借出` and not `可借出`.

The checker reads the tree into a model: the parties, the one kind of instance and its fields,
the states, the actions, and the time rules, with every name resolved and every expression typed.
Money never mixes currencies, quantities never mix dimensions (TB and GB convert; TB and items do
not), months never mix with days, and every value is exact in its smallest unit (cents, bytes,
millionths of a rate): `HKD 0.001` is an error, never a rounding. Lists are bounded, actions never
recurse, and every state must be reachable. Whatever Bo infers rather than reads carries the id of
the fixed rule that inferred it, which the contract text spells out:

```
thing Item                             field field.holder instance party = owner{R2}
  amount HKD                           state state.active first{R4}
  holder owner                         can act.transfer standard by=field.holder{R19} to=role.counterparty{R21} agents=delegation{R14}
can transfer to counterparty             consent role.counterparty{R21}
  over 50_000 requires in person         requires cond.in_person{R13} guard=(cond.over (money cur.HKD 50000){R6})
```

The transfer takes the standard library's terms (R19), so the holder starts it; each call names
the counterparty, who consents (R21); the holder starts as the owner and may change (R2);
`over 50_000` takes the unit of the action's one amount (R6); in person asks the starter's
presence (R13); an AI agent may act within its delegation unless the action says it only
proposes (R14). Clauses that ask the outside world to act (notify, say) are accepted with a
warning: executors come in a later step.

Packs are files in CBOR diagnostic notation; `bo/packs/` holds the official language packs and
`bo/vocab/` the official vocabulary packs (their words, spelled in each language, and the
standard terms of their actions). A pack's digest is the hash of its canonical CBOR, and a deploy
records the packs its source was read with, so anyone can rebuild the contract from the source
and compare. Anyone can write a vocabulary pack of their own, in the same format, for words they
use in many contracts: `--vocab FILE` reads it on every `bo` command,
and the deploy embeds it whole, so whoever verifies the contract needs no copy
([`examples/events`](../examples/events)). Bo never guesses: one spelling with
two meanings, in one pack or across the packs a source is read with, is an error, and so is a
word that an attaching rule could split into two others.

The compiler uses C++26 static reflection and contracts, which GCC 16 builds and Clang does not
yet. The `bo` program therefore exists only in builds made with GCC 16 (the `gcc-*` presets and
the release build); `bo version` names it. The
browser verifier never needs the compiler: verifying a contract replays its code.

Compiled contracts are WebAssembly modules in the contract profile, written by the compiler's own
emitter, with a small runtime it adds as needed: reading the call's input (checked inside the
contract to be deterministic CBOR within the limits, as core decodes it; from codegen 2 on,
texts are not checked again for UTF-8, which the ledger's input always is), writing the output, checked 64-bit
arithmetic (an overflow refuses the call), multiply-divide on 128 bits with the rounding modes
half up, half even, and down, civil dates at a fixed UTC offset with month ends clamped, and text
comparison. Every routine runs to the same outcome, output, and fuel on the ledger's interpreter
and on the independent Python interpreter (`ctest -R bo_reference`, with Python 3);
`tests/bo/golden/runtime/fuel.txt` lists what each costs of a call's 10 million fuel.

The compiler lowers Bo to such modules: creation, the contract's own
actions with their inputs, fields, states, `requires` (with a guard such as `over 1_000_000`),
`if` and `otherwise`, `reject`, consents, and `in person`, over numbers, money, quantities,
rates, dates, durations, texts, yes or no, and parties. Each action is a function named by its
concept or as written (the same name in every language), and creation is `create` (`issue` for
the vocabulary's assets). Arguments are a map: `{"fields": {...}, "parties": {role: ledger}}` to create, the
action's inputs by name otherwise (money in cents, rates in millionths, dates in milliseconds).
A compiled contract asks for the consents an action needs (of its starter, of a role it binds,
of a counterparty it makes the holder (or another party field a built-in action sets) at every
call, however that role was bound, of a party a changed field held, and of every `requires consent of`) with
`[2, needs]`, the
home's own consent being the call itself; it keeps `{"state": NAME, "fields": {...}}`, reports
the state as the status, the parties and every field holding one, each state change as an
event, and the instance as final once no action can leave its state; and it refuses with the
text of a `reject` or with `bo:CODE` (`bo:requires sign 2`), which tools show in the reader's
language. The same contract in English, Traditional Chinese, Simplified Chinese, or mixed
compiles to the same bytes; `tests/bo/golden/build/` holds a two-party contract in each, and the
fuel of each of its calls. The vocabulary's built-in actions compile
with the standard library's terms, `when` rules compile to functions a keeper calls, and lists
and charges compute bills (all below). What later steps bring (executors, and the built-in
actions whose terms come later) is refused with a message for now. `testvectors/bo-v1.json`
(`tools/testvectors/bo_vectors.py`) pins sources, bo-source bundles, interfaces, code, fuel
bounds, and outcomes, checked on both interpreters, and the errors of sources that must not
build.

```sh
bo build contract.bo                            # code, hash, compiler, and the source bundle
bo build contract.bo --out contract.boc         # a deploy file (--hash sm3 for an SM3 ledger)
cexchain contract deploy contract.boc --as root.key
cexchain contract export <contract> --out deployed.boc    # a deployed contract, as a file
bo rebuild deployed.boc                         # its source rebuilt and compared with its code
cexchain contract verify evidence.cbor --ledger-id <home> --deploy-out deployed.boc
```

A Bo deploy records the code, its interface, the language `bo`, the compiler (`cexchain-bo
RELEASE; codegen N; edition E`), the contract's name, and its source as a *bo-source bundle*
(spec section 15): the source as written, comments included (`bo build` warns that they are
published), its edition, and each language pack it was read with, by id, version, and digest
under the home's hash, the packs that are not official embedded in full. The chain keeps it as
given and hands the deploy on as a file (`contract export`, or `contract verify --deploy-out`
from evidence alone); `bo rebuild` rebuilds the code from it and compares the bytes:
"rebuilds"; "DOES NOT REBUILD" when the compiler the deploy names builds something else (the
source is not the code's: exit 3); "MALFORMED" when there is no usable bundle; or "not rebuilt"
when another compiler, release, or codegen version built it (named, never called a forgery;
`--require` fails it too). Codegen 4 is the first released; from it on, the compiler keeps
writing the released codegens before its own, so their deploys still rebuild.

## Fuel

A call has 10 million fuel. For each function, `bo build` computes the most fuel a call can use
from the code's structure: each loop as often as the contract's bounds allow (lists, a bill's
lines and charges, a split's parts and consents), each comparison and copy as large as the
input allows, and reading the input as many items as the function's arguments, the state the
contract writes, and the ledger's other fields can hold. The bound holds for every call whose
arguments are of the function's shape. A contract a call could run out of fuel in does not build
(`build.fuel`: two lists of 1,000 items compared item by item, say); one whose output could
exceed what the code has for it (192 KiB: a large state split into many parts) builds with a
warning (`build.output`). `bo build` shows the highest bound, `--fuel` each function's:

```
$ bo build contract.bo --fuel
  ...
  fuel       at most 226,042 a call (amend), of 10,000,000; output at most 65,771 bytes (amend), of 196,608
  function               fuel       reading     output
  amend               226,042        63,080     65,771
  ...
```

Every test of the compiler checks each call's fuel against its bound; calls at the language's
limits use 40 to 70 percent of it (`tests/bo/golden/build/fuel-bounds.txt`).

## The contract text

What the parties read and confirm before they sign is the *contract text*, which Bo writes from
the contract in English, Traditional Chinese (Hong Kong usage), or Simplified Chinese: the
parties and when each is bound to a ledger, what each instance records, the states (the first,
the final ones, and the events), each action (who starts it, the consents it needs, its
requirements, numbered as a refusal such as `bo:requires sign 2` names them, its state changes,
and what AI agents may do), the time rules, and the rules Bo applied. Whatever Bo inferred
instead of reading it is spelled out in its clause and marked with its rule (`[R3]`, `〔R3〕`), and
the last section explains each rule used. Texts are always shown in quotation marks, including a
name Bo read as a text (R18: `颜色 = 红色` reads as `颜色 is "红色"`). One contract gives the same text, byte for byte, whatever language its source was
written in; `tests/bo/golden/explain/` holds the text of each example in each language.

```sh
bo explain contract.bo                          # before a deploy
bo explain contract.bo --language zh-Hant-HK    # or set CEXCHAIN_LANGUAGE
bo explain deployed.boc                         # from the deploy, only if it rebuilds
bo explain deployed.boc --state state.cbor      # an instance's state (contract instance --state-out)
```

```
4.1 lend
  4.1.1 Started by owner, whose agreement it needs.
  4.1.2 The call gives counterparty (a party). [R21]
  4.1.3 It needs the consent of the counterparty, whose ledger each call names (the argument
        counterparty). [R21]
  4.1.4 It needs the consent of whichever party is the holder before the call, since the action
        changes the holder. [R8]
  4.1.5 If the instance is active, it becomes lent; otherwise the call is refused.
  4.1.6 It sets the holder to the counterparty.
  4.1.7 An AI agent may start it within its delegation. [R14]
```

`bo explain` of a deploy file reads the source it carries exactly as `bo rebuild` does (with
the language packs it names, at their versions) and writes the text only if that source rebuilds
to the deployed code, so the text is the text of the code that runs; otherwise it says why. With
`--state`, it shows an instance's state and fields in the same words first (`amount: HKD
250,000.00`, `starts: 1 January 2030`). Messages follow `--language` or `CEXCHAIN_LANGUAGE`
everywhere the compiler reports; the chain shows a compiled contract's refusal as the contract
gives it (`bo:state countersign`), and `bo reason` says it in words.

## A contract from a form

`bo form` writes a source from a *rules sheet*, the JSON a form fills in: the parties, the kind and
its fields, each action (who starts it, with whom, its inputs, requirements, consents, presence and
a threshold for it, whether AI agents may only propose it, its state change, the fields it sets,
its requests), the time rules, the rules for answers, and the tests. Whatever is not a choice of
the form is a piece of Bo as written (names in any language, types such as `HKD`, values, events
such as `overdue 30 days`); the generator adds only the keywords around them, then the compiler
checks the result, each problem named by its place in the sheet. `--from` reads a source back
into a sheet when every construct fits the form (no choices, loops, refusals, or lines in another
order), and writing that sheet again gives the same tree.

```sh
bo form --from examples/lending/lending.bo --out lending.json
bo form lending.json --language zh-Hant-HK      # the same contract, in Chinese
```

`bo calls` lists what each call of a contract takes, for a form: the creation (the fields given at
creation, required or with their defaults, and the roles bound at creation), each action (its
inputs, the role it binds, whether AI agents only propose it, its clauses of the contract text),
and the time rules, each value labelled and typed in the reader's language. `bo args` builds a
call's arguments from values a person writes: a text as typed, yes or no, a party's ledger id, a
list, and numbers, money, quantities, dates, and durations as Bo writes them, in any language
(`HKD 1_250.50`, `500萬港元`, `2027年1月6日`, `3日`), each checked against its declared type (a
plain number in a money field is in its currency). Each problem names its value and a code. Both
read a source or a built contract (`.boc`), and the console draws its forms from them.

```sh
bo calls lending.bo --language zh-Hant-HK
bo args lending.bo create --set "name=Camera X100" --set owner=$LEDGER_ID   # for contract create --args
```

## One contract, any language

`bo fmt` lays a source out canonically (two spaces per block, one space between words, comments
where they were) and, with `--language`, writes every keyword and word in one language. Names the
contract gives, texts in quotes, and comments stay as written. A contract written in Chinese can
so go to an English-speaking counterparty as English source: it parses to the same tree, checks
to the same model, builds to the same code, and explains to the same text.

```sh
bo fmt contract.bo --check                      # is it formatted? (exit 3 if not)
bo fmt contract.bo --language en                # the English source, on stdout
bo fmt contract.bo --language zh-Hant-HK --write
```

```
requires consent of counterparty        須經 相對方 同意           须经 相对方 同意
when 7 days before due notify holder    當到期前 7日 通知 持有人    当到期前 7天 通知 持有人
```

Chinese is written as Chinese is: a keyword joined to the word after it (`可轉讓`, `須經`), a
number to its Chinese unit (`30日`, `500萬港元`); Latin words stand apart (`每 GB`). A word whose
argument sits on the other side in another language (`7 days before due`, `到期前 7日`) moves
around it, with parentheses where it would otherwise take a different argument. The text is not
reversible, though the contract is: a multiplier English lacks is written out (`500萬` is
`5_000_000`), and words become each language's first spelling (`transfers`, then `轉讓`, then `transfer`).
Before printing anything, `bo fmt` reads its result again; if words would read together in the
new language as another word, it says where and changes nothing.

## Tests

A contract carries its own tests: `test` blocks of steps, each a party, an action, and
optionally what it gives, when, and how it is signed, then what should happen.

```
test "nothing is lent twice, and only the holder brings it back"
  owner create with name = "Camera X100"
  owner lend to friend1 -> lent                      # friend1 consents, then it is lent
  owner lend to friend2 -> refused "bo:state lend"   # not while it is lent
  friend2 bring_back -> consent of friend1           # the holder starts it: friend2 cannot
  friend1 bring_back at 2027-01-05 -> active
```

`bo test` builds the contract and runs each test on an instance of its own, exactly as a ledger
runs calls: every party a test names is a ledger of its own (a name the contract does not
declare, such as `friend1`, is a ledger only the test names, which `to friend1` names or binds
a role to);
the first step creates the instance, and its party is the home. A call runs first without
consents; every party the contract asks then consents, except those the step expects it to wait
for and, when the step's party does not start the action, the party that does. `in person` signs
as a person who proves presence, `by AI agent` as an agent; `at DATE` moves time on (a test
starts on 2026-01-01). Expectations are a state (`-> signed`), a refusal (`-> refused`, or with
the contract's reason in quotes), or a wait (`-> consent of friend1`); a step without one expects
an accept. The report shows each step as written and what happened, worded in `--language`, and
for a refusal the clause of the contract text it comes from; the results are the same whatever
language the contract and its tests are written in. Exit status 3 if a test fails.

```sh
bo test lending.bo
bo test lending.bo --language zh-Hans-CN --json
```

## Requests

A contract asks the outside world for something with `request`: a kind (a name, or an action's
or a document's word such as `notify` or `invoice`), the party it concerns, values, and a
deadline. `notify PARTY` is short for `request notify to PARTY within 1 day`. The answers come back
through one function, `result`, and the contract says what each does; `result` and `reason` are
the answer's texts there:

```
can deliver by carrier
  in_transit -> delivered
  request notify to consignee with message = "delivered" within 1 day

when notify done
  notified = yes
  notice = result
when notify fails
  request notify to shipper with message = "notice failed" within 1 day
```

The same in Traditional Chinese (`bo fmt --language zh-Hant-HK`):

```
可 deliver 由 carrier
  in_transit -> delivered
  請求 通知 予 consignee 連同 message = "delivered" 1日內

當通知 完成
  notified = 是
  notice = 結果
當通知 失敗
  請求 通知 予 shipper 連同 message = "notice failed" 1日內
```

A failed request and one no answer reaches by its deadline (expired) take the rule for failures,
unless one is written for expiry (`when notify expires`). An answer is never refused, so these
rules ask no consent and refuse nothing; an instance that has ended takes its answers but asks
nothing more. The contract text states every request, its deadline, and what happens if it fails.
Tests answer requests as an executor, a keeper, or a person would:

```
executor notify done with result = "RCPT-1" -> notified = yes
executor notify fails with reason = "unreachable" -> notice = "unreachable"
keeper notify expires at 2027-03-11
```

An executor (`executor add NAME --kinds notify`, then `executor run`) carries requests out through
connectors and answers on the ledger; `examples/shipment` runs one.

## A service's periods

With the `services` and `commerce` vocabulary packs, a `service` with a recurring price is paid
until a date and billed until a date, which Bo adds; it is due on the date it is paid until.
Subscribing and renewing bill one period: an executor is asked to `invoice` it, and once it is
invoiced, to `collect` it; a collection done pays the period, and resumes a suspended service no
longer overdue. On a service, `subscribe`, `upgrade`, `downgrade`, `suspend`, `resume`, and
`terminate` also ask an executor to act. The rest is the contract's:

```
use commerce
use services
contract Hosting
parties we, customer

service Plan
  price monthly HKD 120

can subscribe by customer
when 14 days before due renew
when overdue 3 days suspend
when overdue 30 days terminate
when collect fails notify we
```

The contract text states each request and what its answers do (rules R34 and R35); tests answer
them (`executor invoice done with result = "INV-1"`, `executor collect done`, `keeper suspend at
2027-01-13`). `spec/bo.md` section 6.12 has the details and the spec's VPS example.

## The standard library

The built-in actions are written in Bo itself, in a standard library compiled into the compiler:
the core's transfer and cancel, and suspend, resume, and terminate, on the home's own word
(`bo/stdlib/core.bo`); then the vocabulary packs' actions, in their pack files (`bo/vocab/`), which
a contract gets after its `use` line: finance's pledge, release, enforce, redeem, pay, confirm
payment, dispute, freeze, unfreeze, and split, which keep the semantics of the native assets that
spec v0.5 to v0.8 had (`tests/bo/finance_terms_test.cpp` holds those verdicts as goldens and
checks the pack's terms against them, call by call), and services' allocate and reclaim, and
subscribe, renew, upgrade, and downgrade. A
vocabulary pack of your own brings the terms of its own actions the same way. A contract that
writes `can transfer to counterparty` gets the library's transfer: the holder starts it, the
holder and the counterparty consent, only an active instance is transferred, and the
counterparty becomes the holder. The lines a contract writes under a built-in action add to its
terms and are checked first (`over 50_000 requires in person`); without `to`, each call names the
counterparty, who consents. A counterparty that a built-in action makes the holder (or puts in
another party field) consents to every such call, even when its role was bound when the instance
was created (R31). The contract text states every standard term, marked R19. To change a
built-in action, copy it under a name of your own: it is then the contract's own action.

```sh
bo stdlib list                                  # who starts each, its pack, its states
bo stdlib list finance                          # one pack's (or core)
bo stdlib show transfer                         # its source, to copy, and its text
bo stdlib show 轉讓 --language zh-Hant-HK
```

```
can transfer to counterparty by holder
  requires not counterparty = holder
  active -> active
  holder = counterparty
```

### Splitting a thing into parts

`issue PARTS to RECIPIENTS` (R30) makes each part an instance of the contract with the
instance's fields, its amount the part and its holder the recipient in the same place, `with`
setting others; fields Bo adds start empty, and the part starts in the first state. A part's
evidence carries the history of the instances it came from, the other parts of each split
included, which the contract text states. The library's `split` uses it: the holder divides the
instance among recipients, each part held by its recipient, and the instance ends (`divided`).
The holder and every recipient consent (so at most 15 recipients besides the holder), each part
is at least the currency's smallest unit, the parts add up to the amount, and only an active
instance splits. A part at depth 8 splits no further (`bo:depth split`). The template ends with
the statement that makes the parts, which a copy of it can change:

```
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

In tests, a step acts on the part its party holds (or names the holder: `we cancel maker1`), and
the report names parts by path (part 1.2).
[`examples/multi-tier-split`](../examples/multi-tier-split/) splits a receivable down a supply
chain across six organizations, an example from supply-chain finance.

```sh
cexchain contract propose <instance> split --peer home \
    --args "{\"parts\": [60000000, 40000000], \"recipients\": [h'<ledger A>', h'<ledger B>']}"
cexchain contract pending --peer home            # a recipient sees the call it is asked to consent to
cexchain contract consent --peer home --call <call> --as root.key --log-key log.key --send
```

An action can let AI agents only propose it (`AI agent can propose`): an agent's call is then
kept with the instance as a proposal, and a person who proves presence approves it with the
function `approve`, which runs it with every requirement checked. In a test, `owner lend to
friend1 by AI agent -> pending approval`, then `owner approve in person -> lent`.

## Time rules and keepers

A ledger acts only on calls, so a `when` rule compiles to a function of its own, `when.ACTION`
(`when.suspend`), that anyone the home delegates may call: a *keeper*, usually a device of the
home that calls it on a schedule. The rule applies only once the ledger's registration time
reaches the rule's time, and once for each such time; an earlier call is refused, and nothing
is recorded. The rule is the contract's own word: the actions it does need only the consents the
contract states, not their starters'. Its event records the time it applied at and how late the
call came. A rule fires at:

| Event | Fires | Example |
|---|---|---|
| a date | on that day | `when due + 1 month` (month ends clamp: 31 January plus a month is the end of February) |
| N before due | from N before the due date | `when 7 days before due` |
| overdue, overdue N | the day after the due date; N after it | `when overdue 3 days suspend` |
| a state held N | N after the instance entered the state | `when suspended 30 days terminate` |

Any of these may be joined to other conditions with `and` (`when 7 days before due and active`).
`when due borrower bring_back` names a party's duty: it says when an instance is due and
overdue, and nothing is called. In actions, `within 14 days` means less than 14 days since the instance last
changed state; `overdue`, `overdue N`, and `N before due` hold from those times on. Dates and days
are counted at a fixed offset from UTC, all year: `UTC offset "-05:00"` in the kind's block, or
+08:00 (R25).

```sh
# The keeper: a device whose delegation covers these contracts' time rules (and result) only.
cexchain keeper add Keeper --contracts <contract> --key-out keeper.key --as root.key
# What is due now, or at a later time? Dry runs; nothing is recorded.
cexchain keeper due
cexchain keeper due --at 2027-07-03
# The server's keeper fires what is due every minute (on the leader, in a cluster) ...
cexchain serve --log-key log.key --keeper-key keeper.key
# ... or, for a ledger without a server, fire it now, or every minute.
cexchain keeper run --as keeper.key
cexchain keeper run --as keeper.key --every 60
```

A keeper finds what is due by dry runs: a rule is due if its contract accepts the call and the
call would change something. It also expires requests left open 15 minutes past their deadline
(`--expiry-grace`). Its delegation covers contract calls of the time rules and the replies
only, never the actions that are the home's own word; `keeper list`, `keeper show`, and
`keeper revoke` manage keepers, and `GET /v1/contracts/due` answers what is due.
A keeper that is sometimes off (a personal computer) fires late, never early, and the event
shows how late. In tests, the keeper is a step: `keeper suspend at 2027-07-02 -> refused
"bo:when when.suspend"`, then `keeper suspend at 2027-07-03 -> suspended`; it calls, as a device
of the home, the rule that does that action (for a rule that does none, the state its first state
change leads to, such as `keeper closed`).
Nothing yet keeps a field's value unique across a contract's instances: unique keys come later.

To try time rules on a real ledger without waiting, set `CEXCHAIN_CLOCK_OFFSET` (such as `30d`,
`12h`, or `90m`; at most 3660 days): every command, the server and its keeper included, runs its
clock that far ahead. It is for demonstrations and tests only. A ledger keeps the times it
records, so `serve` refuses to start with an offset unless it is given `--allow-clock-offset`,
then prints it and shows it in `/v1/status` (`clock_offset_ms`); a client ahead of its ledger
is refused (a statement may not claim to be issued in the future). `examples/idc-hosting`
moves a month this way.

## Lists and charges

A field or an input may be a list, of at most 16 items unless `at most N` says otherwise (1,000
at most): `codes list text at most 3`. A list given as an argument is checked when it is read
(longer ones are refused), `each n in rows` runs its block once for each item (requirements,
choices, refusals, and fields set; no state change), and `sum of rows`, `count of rows`, and
`"x" in codes` read it. One value where a list is needed is a list of that one item (R29).

Fees, commissions, surcharges, and taxes are *charges*, which a contract defines: nothing about
them is built in, rates included. A field named by a document word holds the lines of a bill;
each time it is set, the charges are computed on its lines at the time of that call, and the
instance keeps the bill as it was made (R26): a later rate never changes a bill already made. A
charge is a rate (in millionths) or a fixed amount; it applies always or when a condition holds;
it is `included` in the price or `added` to it; it is rounded per line or per bill, half up, half
even, or down; it may be computed on charges written before it (R27); and its rate is the one in
force at the bill's time (R28). The words for bills and charges belong to the `commerce`
vocabulary pack: a contract that uses them starts with `use commerce`. The spec ([`spec/bo.md`](../spec/bo.md)) works through a
value-added tax on both sides of a rate change; `tests/bo/golden/test/charges/` and
`tests/bo/golden/build/vat-amounts.txt` hold the arithmetic, which the Python reference computes
again with its own integers.

## Known limits

What the language and its compiler do not do yet, as of this version:

- **Parts and requests.** A Bo contract that splits an instance into parts makes no requests:
  the compiler refuses a `request` in such a contract (`build.unsupported`), since an instance
  that issued parts has ended and an answer could not tell.
- **Request kinds in Bo** are lowercase letters, digits, and `_` (`notify`, `http_post`): the
  ledger also takes dotted kinds (`http.post`), which Bo cannot write, so a connector for a
  dotted kind needs a Bo-writable kind beside it.
- **A service's bills** bill one period of the price on subscribing and on each renewal. Charges
  and usage on a service's bills, proration (upgrading or downgrading mid-period), refunds (a
  service terminated with a period paid ahead gets nothing back), and paying ahead (one bill is
  open at a time) are not built.
- **A payment answered by hand** (`request answer` on a `collect`) pays the period on the
  ledger, but nothing posts it to the billing system: post it there too, by hand or by a
  connector of your own.
- **The first "N days before due" reminder** applies at the subscription: the first due date is
  the subscription day, so a rule such as `when 7 days before due` fires at once.
