# Events: a vocabulary pack of your own

A concert ticket, kept on the organizer's ledger. Bo's core has words for a holder and a
transfer, but none for a ticket's guest or for checking in at the door, and no official pack
has them either. The organizer writes them once, as a vocabulary pack of its own
([`events.vocab`](events.vocab)): the concepts (two actions, three fields, two states, a role,
and a unit of count), how English, Traditional Chinese (Hong Kong), and Simplified Chinese
spell them, and the standard terms of the two actions, in Bo. Any contract that writes
`use events` then reads those words, in any of the three languages.

[`tickets.bo`](tickets.bo) is such a contract: a ticket reserved for a fan, who agrees on
their own ledger and then checks in; the core's `cancel` lets the organizer cancel a ticket
no one has reserved. Its tests run with `bo test`.

[`events.sh`](events.sh) runs the story:

1. the organizer and a fan, each with a ledger;
2. the pack checked (`bo vocab check`) and shown in Chinese (`bo vocab show`);
3. the contract tested and deployed with the pack (`--vocab events.vocab`); without it, the
   source does not read, and the note says which pack is missing;
4. a ticket created;
5. reserved for the fan, who first verifies the ticket's history offline, with no pack file:
   the deploy embedded the pack in the contract's source bundle, so the contract rebuilds
   from its source anyway; then consents on their own ledger;
6. the fan checks in;
7. anyone verifies the whole history offline.

```sh
examples/events/events.sh build/gcc-release/cli/cexchain
cexchain bo vocab check examples/events/events.vocab
cexchain bo test examples/events/tickets.bo --vocab examples/events/events.vocab
cexchain bo fmt examples/events/tickets.bo --vocab examples/events/events.vocab --language zh-Hant-HK
```

A pack's words may not take the plain name of a core or official word of the same category
(compiled code names them so), its spellings must be new to Bo, and only the official packs
bind the compiler's own mechanisms (kinds, prices, charges, bills). A change to a pack is a
new version; every deploy keeps the version it was built with.
