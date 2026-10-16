# Receivable financing

An example from supply-chain finance: a core enterprise owes its supplier CNY 1,250,000,
payable at maturity. The supplier pledges this receivable to a bank for a loan, repays it,
and sells the receivable to a factoring company, which the core enterprise pays at
maturity. Five organizations, five ledgers, talking over HTTP.

What it shows:

- **A thing with an owner, under rules.** The receivable is an instance of
  [`receivable-financing.bo`](receivable-financing.bo), kept on the core enterprise's ledger
  (its home). It uses Bo's `finance` vocabulary pack (`use finance`), whose actions
  (`pledge`, `release`, `pay`, `confirm payment`) and the core's `transfer` take their
  standard terms: the holder starts a pledge and the bank consents; only an active receivable
  can be pledged, so never twice at once.
- **Consents on each party's own ledger.** The supplier and the bank each consent on their
  own ledgers; the bank first verifies the receivable offline, from evidence the supplier
  fetched.
- **Witnesses.** A regulator witnesses the core enterprise's ledger, and the bank lends only
  once the pledge is in a checkpoint the regulator cosigned (`--witness --min-witnesses 1`).
- **Refusals.** A second pledge, to another bank, is refused by the contract
  (`bo:state pledge`).
- **The whole history, offline.** Issue, pledge, release, sale, payment, and confirmation
  verify offline, with the contract's code rebuilt from its source.

```sh
cexchain bo test examples/receivable-financing/receivable-financing.bo
examples/receivable-financing/receivable-financing.sh [CEXCHAIN] [DIR]   # CTest: demo_receivable_financing
```
