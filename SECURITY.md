# Security policy

CexChain is software for proving things: a flaw that lets evidence verify when it should not,
leaks private data, or lets someone act without authority matters to everyone who relies on it.
Thank you for helping keep it sound.

## Reporting a vulnerability

Please report vulnerabilities privately. Do not open a public issue, pull request, or
discussion for them.

- **Preferred:** GitHub's private vulnerability reporting. Open the repository's **Security**
  tab and choose **Report a vulnerability** (available once enabled for this repository). The
  report stays private between you and the maintainers.
- **Or email** [tech@cirraya.com](mailto:tech@cirraya.com) with "Security" in the subject.

### What to include

- The affected part: the protocol (`spec/`), the core verification library, a crypto backend,
  the `cexchain` tool, the ledger server or its HTTP API, replicas and backups, clusters, the
  browser verifier, the Bo compiler or runtime, the MCP server, or the deploy files.
- The version or commit, the platform, and the build (compiler and preset).
- What is wrong and its impact: which guarantee it breaks (for example, evidence that verifies
  but should not, a signature or delegation accepted when it should be refused, private data
  disclosed, a server that can be stopped or exhausted).
- Steps to reproduce, with the smallest input that shows it (an evidence bundle, a statement, a
  Bo source, an HTTP request) or a proof-of-concept program.
- Whether the issue is known to anyone else, and how you would like to be credited, if at all.

## What to expect

- **Acknowledgement.** We aim to acknowledge a report within five working days, and to tell you
  whether we can reproduce it and what we plan to do.
- **Coordinated disclosure.** We work on a fix privately and keep you informed. We agree a
  disclosure date with you; unless we agree otherwise, we ask for up to 90 days from the report.
  We then publish a fix and a GitHub security advisory that describes the issue and, if you
  wish, credits you.
- **No bounty.** There is no bug bounty program, and reports are not paid.

## Supported versions

CexChain is an alpha: pre-release software whose protocol specification is a draft and may
change, and which has not been audited. Security fixes go to the latest alpha release and to
the `main` branch only.

| Version | Security fixes |
| --- | --- |
| Latest alpha release (0.x) and `main` | Yes |
| Earlier alpha releases | No: upgrade to the latest |

## Verification code is open source

Everything that verifies evidence is open source in this repository: the core library, the
crypto backends, the `cexchain verify` and `contract verify` commands, and the browser verifier.
The protocol is defined by its specification ([`spec/`](spec/)) and the test vectors in
[`testvectors/`](testvectors/), which come from implementations independent of CexChain.
Nobody needs to trust a service run by Cirraya to check evidence: anyone can build the verifier
from source and check evidence offline.

## Security model and known items

[Section 17 of the specification](spec/README.md#17-security-considerations) (security
considerations) states what evidence proves and what it does not, and the protocol's assumptions
about time, keys, privacy, contracts, requests, connectors, and keepers. A report that shows one
of those statements to be false is in scope.

Known open items are listed in the README under
[Known security items](README.md#known-security-items); there is no need to report them again,
but new ways to exploit them are welcome.

Vulnerabilities in third-party components ([`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md))
belong with their projects; please tell us too if CexChain is affected.
