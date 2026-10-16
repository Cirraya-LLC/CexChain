# Multi-tier split

An example from supply-chain finance: a core enterprise owes its tier-1 supplier
CNY 1,000,000, payable at maturity. Small suppliers deep in a supply chain rarely get credit
on their own; here they borrow against the core enterprise's promise instead. Six
organizations, six ledgers (two of them on SM3 and SM2), talking over HTTP.

What it shows:

- **Parts.** A call may divide an instance into parts, each an instance of its own with its
  own holder. The tier-1 supplier splits the receivable between two tier-2 suppliers, who
  are parties of nothing yet; one of them splits its part again, down to tier 3. The
  contract, [`multi-tier-split.bo`](multi-tier-split.bo), uses Bo's `finance` vocabulary
  pack (`use finance`) and its `split` (the holder starts it, every recipient consents, the
  parts add up to the amount), and adds its own rule: parts go down to tier 5.
- **Consent from newcomers.** Each recipient sees the call it is asked to agree to and
  consents on its own ledger.
- **Verifying a chain.** Before it agrees to a pledge, a bank verifies the tier-3 part
  offline: its whole chain, from the core enterprise's receivable down, every consent
  included.
- **Paying the parts.** At maturity the core enterprise pays each part, the pledged one to
  the bank, and each payee confirms.

```sh
cexchain bo test examples/multi-tier-split/multi-tier-split.bo
examples/multi-tier-split/multi-tier-split.sh [CEXCHAIN] [DIR]   # CTest: demo_multi_tier_split
```
