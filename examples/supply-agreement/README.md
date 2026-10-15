# A supply agreement

An example from trade: a core enterprise proposes an agreement to its supplier and its bank,
and it takes effect only once both have consented, each on its own ledger; once the goods
are delivered, it is closed. Three organizations, three ledgers, talking over HTTP.

What it shows:

- **Rules of the contract's own.** [`supply-agreement.bo`](supply-agreement.bo) declares
  its parties, what an agreement records (goods, pieces, price, a delivery date), and two
  actions: `sign`, which needs the consent of the supplier and of the bank, and `close`,
  which needs the supplier's. Nothing about agreements is built into CexChain.
- **A registrar.** The home's server holds a proposed call until every party the contract
  names has consented, then records it: never on its own word.
- **People and AI agents.** At the supplier a person (a sales manager) consents; at the
  bank an AI agent with its own key consents through MCP, under a delegation, with its
  model recorded and a person accountable for it.
- **Mixed cryptography.** The bank's ledger hashes with SM3 and signs with SM2.
- **Offline verification.** The supplier fetches the agreement's evidence and verifies it:
  every call run again, every consent checked on the ledger that gave it, the contract's
  code rebuilt from its source. The same file opens in the browser verifier.

```sh
cexchain bo test examples/supply-agreement/supply-agreement.bo
examples/supply-agreement/supply-agreement.sh [CEXCHAIN] [DIR]    # CTest: demo_supply_agreement
```
