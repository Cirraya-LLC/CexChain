# Examples

CexChain itself knows nothing about cameras, agreements, or receivables. A record is a
document of a type you name; a contract, written in [Bo](../spec/bo.md), says what may
happen to a thing and who must agree; and anyone can verify what happened, offline. These
examples show what that looks like for particular uses. They are examples, not features:
copy one, change its words and its rules, or write your own.

Each example is a directory with:

- its contract in Bo, with the tests the contract carries (`bo test` runs them);
- a script that runs the whole story on one computer, narrated step by step, each party
  with a ledger of its own;
- a short README: what it shows, and how to run it.

| Example | What it shows | Ledgers |
|---|---|---|
| [lending](lending/) | A camera lent between two people: rules of a dozen lines, the borrower's consent on his own ledger, a private record for the details, and the history verified offline. No server, no platform | 2 people |
| [supply-agreement](supply-agreement/) | An agreement proposed by one organization and signed once two others consent: a person at one, an AI agent (through MCP) at the other; a registrar collects the consents online; one ledger uses the Chinese SM2 and SM3 algorithms | 3 organizations |
| [receivable-financing](receivable-financing/) | Supply-chain finance: a receivable pledged to a bank, a second pledge refused, released, sold to a factoring company, and paid; a regulator witnesses the home ledger, and the bank lends only once the pledge is witnessed | 5 organizations |
| [multi-tier-split](multi-tier-split/) | Multi-tier supply-chain finance: a receivable split down a supply chain, each part an instance of its own, a part pledged to a bank that verifies the whole chain offline first | 6 organizations |

## Running one

Every script needs a `cexchain` built with the Bo compiler (GCC 16: the `gcc-*` presets,
the release build, and the Docker image have it):

```sh
cmake --preset gcc-release && cmake --build --preset gcc-release --target cexchain
examples/lending/lending.sh build/gcc-release/cli/cexchain                  # in a temporary directory
examples/lending/lending.sh build/gcc-release/cli/cexchain ./lending-demo   # keep the ledgers
```

The scripts are also tests: `ctest -R demo_` runs every one (`demo_lending`,
`demo_supply_agreement`, `demo_receivable_financing`, `demo_multi_tier_split`), so they keep
working as CexChain changes.

## Industry words

The finance examples use words that Bo's vocabulary currently builds in (pledge, pay,
split, with the standard library's terms for each). They are planned to move into optional
vocabulary packs that a contract declares when it needs them, so that the language's core,
like the rest of CexChain, stays free of any one industry. An example's own words (its
parties, fields, states, and actions) are always its own.
