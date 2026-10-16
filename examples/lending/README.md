# Lending

Alice lends her camera to Bob. Two people, each with a ledger of their own on one computer,
and a contract of a dozen lines that says what may happen and who must agree. The same steps
record a book, a tool, or a key lent; nothing in them is about business.

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

What it shows:

- **Rules you write.** `lend` and `bring_back` are the contract's own actions: the owner
  lends to whoever each call names, who must agree (the counterparty consents); only the
  holder brings it back. The contract refuses a second loan while the camera is lent.
- **Consent on your own ledger.** Bob checks the camera's evidence offline, then consents
  on his own ledger. His consent is a file naming that one call, which Alice's ledger records
  the call with. No server is needed; the files can travel by any channel.
- **Private details.** The serial number and a photo go into a record of a type Alice names
  herself (`example.alice.belonging/1`): their values stay sealed on her ledger, and only
  commitments are recorded.
- **Verified by anyone.** The camera's history verifies offline: every call is run again,
  Bob's consents are checked on his ledger, and the contract's code is rebuilt from its
  source.

Files: [`lending.bo`](lending.bo), the contract and its tests; [`lending.sh`](lending.sh),
the narrated run.

```sh
cexchain bo test examples/lending/lending.bo        # its three tests
cexchain bo explain examples/lending/lending.bo     # the contract text the parties read
examples/lending/lending.sh [CEXCHAIN] [DIR]        # the whole story (CTest: demo_lending)
```
