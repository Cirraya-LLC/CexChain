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
| [shipment](shipment/) | A chain of custody: goods kept cold, handed from a shipper to a carrier, a transit warehouse, and a consignee. The driver signs each handover in person with a hardware key, a data logger (a device) posts readings, readings in tenths of a degree (°C), a keeper marks the shipment late, delivery charges each whole day late and asks for a notice that an executor sends (a request, answered on the ledger), the consignee checks a QR code and claims from an insurer; one ledger uses SM2 and SM3 | 5 organizations |
| [events](events/) | A concert ticket in the words of a vocabulary pack of the organizer's own (`events.vocab`: reserve, check in, guest, in three languages, with standard terms): the pack checked, the contract deployed with it, the fan's consent, and the history verified offline by someone without the pack file, since the deploy carries it | 2 (an organizer, a fan) |

## Running one

Every script needs a `cexchain` built with the Bo compiler (GCC 16: the `gcc-*` presets,
the release build, and the Docker image have it):

```sh
cmake --preset gcc-release && cmake --build --preset gcc-release --target cexchain
examples/lending/lending.sh build/gcc-release/cli/cexchain                  # in a temporary directory
examples/lending/lending.sh build/gcc-release/cli/cexchain ./lending-demo   # keep the ledgers
```

The scripts are also tests: `ctest -R demo_` runs every one (`demo_lending`,
`demo_supply_agreement`, `demo_receivable_financing`, `demo_multi_tier_split`,
`demo_events`, `demo_shipment`), so they keep working as CexChain changes. The shipment also needs SoftHSM,
which stands in for its driver's hardware key (`brew install softhsm`, or `apt install
softhsm2`).

## Industry words

Bo's core holds generic words only; words of particular fields live in official vocabulary
packs, which a contract declares at its top (`cexchain bo vocab list` shows them). The finance
examples use the `finance` pack (`use finance`: pledge, pay, split, with the standard terms of
each), and the supply agreement its role words for a supplier and a bank and, from the
`commerce` pack, its price (`use commerce`, `use finance`). The lending and shipment contracts
use core words only. An example's own words (its parties, fields, states, and actions) are
always its own.

Words you use in many contracts can go into a vocabulary pack of your own, a file like the
official ones: your concepts, their spellings in each language, and the standard terms of
your actions in Bo. The `events` example has one; `cexchain bo vocab check FILE` checks a
pack, and `--vocab FILE` on every `bo` command (and on `contract deploy --bo`) reads it. A
deploy embeds the whole pack in the contract's source bundle, so whoever verifies the
contract rebuilds it without the file.
