# The web console

An application on the chain: a web console for a ledger, for one person on their computer or a
company on its server. `cexchain-console` serves it beside the ledger's API, as an extension of
the chain's node. It builds what it signs with the chain's client library, and the ledger applies
its own rules to it, so what someone may do on the ledger stays in their delegations; each
statement is approved with a passkey, checked in the browser before the tap. Its Things and
Reports screens read the [search index](../index/README.md), and its rules editor runs the `bo`
compiler beside it.

`cexchain-console run` serves a web console for the ledger on this computer, at
`http://localhost:7470/console/` (or the next free port, remembered), beside the ledger's API;
`cexchain-console status`, `open`, and `stop` manage it. A company serves it on its server with
`cexchain-console run --listen 0.0.0.0:443 --tls-cert … --public-url https://ledger.example.com`
(beyond this computer only over TLS, here or by a proxy in front). It sets a ledger up for
one person or a team, signs people in, registers documents with their fields and files, shows a
thing's page, shares and verifies proof, writes, tests, and deploys rules, creates things under
them and acts on them, connects with other organizations (consents, documents, witnessing each
other, public witnesses, relays), runs machines and AI agents, backs itself up, and approves each
statement with a passkey. Not yet: Windows.

| Path | What it holds |
|---|---|
| `src/` | The console's routes, beside the node's: setup, sign-in, documents and kinds, things and rules, parties, people, automation, backups, the witness, and the relay |
| `web/` | The page (`index.html`, `console.js`, `console.css`) and its catalogs in three languages (`web/i18n/`) |
| `wasm/` | Its checks in the browser, built to WebAssembly (`tools/wasm/build.sh`) and embedded when `CEXCHAIN_CONSOLE_WASM_DIR` names them |
| `cli/` | The `cexchain-console` program |

## What it does

```sh
cexchain-console run --ledger ./ledger   # an empty directory: the browser opens the setup page
cexchain-console user add Bob --role member   # a link for Bob to register his own passkey
cexchain-console user list
cexchain-console settings show
```

- **The first run.** On a directory with no ledger, `console run` opens a one-time setup page
  (valid for an hour; also in `console/setup-link` in the ledger directory). The person gives a
  name (a nickname works; it also names the ledger) and creates a passkey; the console makes the
  ledger, its root and log keys, and the person's own key, all sealed, and registers the person
  as the owner: acting in person with that passkey, under a delegation of every statement type
  but the ledger's key rotations, which requires presence. It also registers the console's
  *machine* (a device, its key sealed too) with a delegation for contract calls only: while the
  console is unlocked, the node runs it as the ledger's registrar, which holds calls proposed
  online until their consents come in, and as its keeper, which fires the time rules that come
  due. Then the recovery sheet (the
  recovery code, shown once, to print or save) and a backup folder, and Home. For scripts,
  `console setup --name NAME --credential FILE` does the same with a passkey from
  `presence enroll`.
- **A lost passkey.** "Lost your passkey?" on the sign-in page takes the recovery code and a
  new passkey: the root key makes the new passkey the owner's only one on the ledger, the lost
  one stops signing in, approving, and unlocking, and the owner's other sessions end. A few
  wrong codes a minute are tried at most.
- **A ledger of your own** (the quick start's, with its keys in files) opens in the console once
  its log key is sealed: `console key init`, `console key import log log.key`, then
  `console setup-link` for the owner's passkey, and `console user link` to act as a person.
- **Documents.** Kinds are the console's forms for registering records (`console kind add FILE`,
  or the Kinds screen): a record type, its fields (text, number, date, yes or no; private ones
  committed by salted hash, public ones in the metadata), and its files, optional, required, or
  none, kept with the record or not. "Register a document" uploads the files, and the page then
  checks, in WebAssembly, that the registration commits to exactly the values and files it shows
  before the passkey approves it; the record's private data and files are sealed to the ledger's
  vault key, whose private key the console holds sealed (`console key import vault FILE` for a
  ledger made from files).
- **A thing's page** shows what the ledger holds about it, and its private fields and files to
  those allowed: owners and admins, and members for the documents they registered or may
  register. **Share proof** makes the evidence file with the fields you disclose and the files'
  openings, as `cexchain export` would; **Verify** checks a proof and its files in the browser,
  with a report in the reader's language, as `cexchain verify` and the standalone page do.
  **New version** registers a document's replacement with one tap: the old one's page then says
  a newer version replaced it and links the latest, its versions are listed, Things hides old
  versions until asked, and its proof, wherever it is checked, says it was superseded.
- **Certificates.** A kind whose sheet lists `"printed": [fields]` is a certificate: the fields
  on paper. `console certificate issue TYPE --csv FILE --as KEY --out ISSUED.csv` issues a
  record per row of a table (a spreadsheet saved as CSV) and publishes each at a private
  address (`cexchain record publish`): whoever scans its QR code gets the record as it is then,
  revoked or replaced included, with the printed fields disclosed and the others sealed.
  `--out` lists what was issued, so a run that stops carries on without issuing anything twice.
  `certificate print --type TYPE --out DIR --url URL` writes a page per certificate (an A4
  template in English or Chinese, or your own HTML with `{{name}}`, `{{qr}}`, ...) to print or
  save as PDF; `certificate list`, `show`, and `withdraw` (the address down, the record kept).

  The **Certificates** screen does the same in the browser. A table of hundreds cannot be one tap
  each, so the console's machine signs them: an owner first lets it issue a kind (one tap: the
  organization grants the machine a delegation for that record type only; `certificate allow`),
  then an owner or admin checks a table and approves the batch with one passkey tap, and follows
  it as the machine issues and publishes each row (`certificate issue --machine`). The ledger shows
  those certificates as issued by the organization's device, and the activity log who started the
  batch. A certificate registered one at a time with "Register a document" is the person's own, in
  person, and is published as soon as it is registered. Each certificate shows its QR code and
  link, its page to print in the console's language, and Withdraw.

  ```sh
  cexchain-console kind add diploma.json      # ... "printed": ["name", "degree", "year"]
  cexchain-console certificate allow example.org.diploma/1
  cexchain-console certificate issue example.org.diploma/1 --csv class-of-2026.csv \
      --machine --out issued.csv --url https://ledger.example.com
  cexchain-console certificate print --type example.org.diploma/1 --out pages \
      --url https://ledger.example.com --language zh-Hant
  ```
- **Claims.** "Confirm a condition" on a document's page confirms that its fields meet a
  condition without showing them ("monthly_salary is above HKD 30,000.00", not the salary): the
  console checks the conditions against the document's private data, the page checks the claim's
  bytes in WebAssembly, and a passkey tap approves it, as `cexchain claim issue` does. A condition
  that does not hold gets no claim unless asked for one that says so. The claim's page, its proof,
  and the verifier page show the condition, the answer, and whether the document was revoked or
  replaced since.
- **Rules.** The Rules screen lists the contracts on the ledger and retires them; "Write
  rules" is an editor with two views of the same rules: a form (parties, the thing and its
  fields, actions with their conditions, consents, presence, what AI agents may do, the state
  change, fields set, and requests; time rules, rules for answers, and tests; vocabulary packs as
  boxes to tick) and the Bo text, with its keywords in any of the three languages. The form
  writes Bo as `bo form` does, and a source opens in the form when it fits (`bo form
  --from`); otherwise it stays text, and the page says where. Each problem the compiler finds
  shows on the form field it belongs to. "Read as a contract" shows the contract's text in
  English, Traditional Chinese, and Simplified Chinese side by side; "Run the tests" runs the
  rules' tests. Deploying and retiring are approved with a passkey, and the page checks the
  code's size and SHA-256 digest in the bytes it signs. The compiler is the `bo` program beside
  `cexchain-console`, run in a child process, never in the node: one run at a time per session, at most 30 seconds, 1 GiB of
  memory, and 8 MiB of output, on at most 256 KiB of rules; only owners and admins write rules.
  Open the examples' `.bo` files (or a sheet saved with "Download") to start from them; the
  editor keeps its draft in the browser tab, so a reload does not lose it.
- **Things with rules.** "Create a thing" under deployed rules opens a form drawn from the
  contract (`bo calls`): each field and party it takes, typed, in the reader's language. A thing's
  page shows its state and fields as the contract text writes them, its parties, and its history,
  each call with who made it and whether in person; the actions the rules offer, each a form; the
  time rules that are due (the keeper fires them; "Run it now" does at once); and the requests
  waiting for an answer, which a person
  may answer by hand (done, failed, or expired, with a reason). Every call is built from what the
  person filled in (`bo args`, in the child process) and run on the ledger's state before any
  tap: a value that does not fit is shown on its field, a call the rules refuse says why in the
  reader's words, and one that needs another ledger's consent says whose, and offers to ask
  for it by file. Otherwise the page checks, in WebAssembly, that the bytes it approves are
  the call it shows. "Share proof" gives the thing's contract evidence, which `cexchain contract
  verify` and the Verify screen check.
- **Consents by file.** "Ask for consent by file" writes a proposal (`.cexchain`, as `contract
  proposal` does) with a note; the other party opens it from Home ("Open a proposal or consent
  file"), where it is verified against the thing's history and shown with the call's clauses and
  the thing's fields, consents with a tap on its own ledger, and gets the consent file to send
  back; opening that on the first console records the call, citing the consent, with a tap. The
  page checks the consent's terms and the cited consents in the bytes it approves, and a consent
  to a step the thing has left is refused. "Propose online" gives the call to the console's own
  registrar instead, which records it once the parties' consents come in through its API; the
  thing's page lists the calls it holds.
- **Parties.** The Parties screen connects two consoles with one code each way: "Make an
  invitation code" (as `peer invite`, with the console's own URL), and on the other console
  "Accept", which adds the party and shows a code to send back. Each node then asks its parties'
  registrars, every minute while unlocked and whenever Home opens, for calls waiting on its
  consent; Home lists them ("Waiting for your consent"). Reading one fetches the thing's evidence
  from its home (a home shows it to the ledgers a call it holds asks), verifies it, and shows it
  as a proposal; the consent, given with a tap, goes to the home's registrar, which records the
  call. Each console is also a witness of its parties' ledgers: its code carries its witness key,
  it follows each party's ledger from its genesis entry (`GET /v1/genesis`, pinned to the
  ledger id), and cosigns only checkpoints that extend what it cosigned before; and it asks each
  party to cosign its own latest checkpoint, keeping the cosignatures with its ledger, so its
  proofs carry them. The Parties table shows how far each side has cosigned the other, and a
  refusal (a ledger rewritten, or shown differently to different parties) as an alert.
- **Documents between parties.** "Ask for a document" on the Parties screen asks a party for one
  of its records by id (as `access request --send`): the reason, the fields wanted (or all), and
  whether its files too, approved with a tap; the request's key is kept sealed to the vault key.
  The party's Home lists what is asked of it ("Asked of you"); its page shows who asks and why,
  and the fields and kept files to share, those not asked left out. "Grant with your passkey"
  records the grant and makes the delivery (as `access grant`), which waits in its outbox for the
  asker; "Dismiss" removes a request without granting it (`access dismiss`). The asker's node
  fetches deliveries for its open requests when it asks its parties; Home lists them ("Delivered
  to you"), and opening one checks it as `access accept` does (the grant against the request,
  the record's evidence at the grant's checkpoint, exactly the fields and files granted) before
  showing the fields and offering the files. "Accept with your passkey" records the receipt and
  sends it back, and the granter sees the delivery acknowledged. A grant is withdrawn with a tap
  (its record revoked), after which its delivery is no longer handed out.
- **Questions between parties.** "Ask whether a condition holds" asks a party only whether
  conditions hold in one of its records (as `access request --if`): no key is made, since nothing
  is sealed to the asker. The party's page for the question shows the condition and whether it
  holds as the record stands; "Answer with your passkey" registers a claim that names the
  question (as `access answer`), kept for the asker; one that does not hold is answered only if
  the person ticks "Answer that it does not hold", and otherwise dismissing it looks like
  silence. The asker reads the answer verified (the claim against the question, its record, and
  its condition), never the fields, and acknowledges it with a tap; the party sees it under
  "Answered for them", where an answer is withdrawn with a tap. A kind may list fields under
  `"answers"` (a box per field in the kind form): once an owner taps "Let the console answer by
  itself" (or runs `cexchain-console answers allow`), the console's machine answers, at each
  poll, a question whose every term is about those fields, on the record's latest version, when
  it holds, valid as long as the question was asked for; a question about other fields, and
  every one that does not hold, waits for a person. Each such answer is in the activity log.
- **Settings** show the ledger and its folder, the language new browsers start in, and the
  backup folder (`console settings show|set` from the command line).
- **In the background.** `cexchain-console open` starts the console if it is not running (in
  the background, its log in the console's folder) and opens it in the browser;
  `console open FILE` opens a proposal or consent file there.
  `cexchain-console service install` runs it from each login: a LaunchAgent on macOS, a systemd
  user unit elsewhere, restarted if it fails; `console service status|uninstall`. Without
  `--ledger`, the console's commands use this computer's place for a person's ledger
  (`~/Library/Application Support/CexChain/ledger` on macOS, `$XDG_DATA_HOME/cexchain/ledger`
  elsewhere); `console status` shows it.
- **Backups.** Once a day while the console is unlocked (and on "Back up now"), it writes a
  backup into the backup folder: the ledger's backup, signed by its log key, with the console's
  folder (its sealed keys, users, kinds, settings, the witness's state, party tokens), checked by
  restoring it in memory, then sealed so that the folder (an external disk, a synced folder)
  learns only the ledger's id and the time: only the recovery code opens it. The folder keeps the
  newest seven and one a week for four weeks; Home shows the last backup, and warns after two
  days without one. `cexchain-console restore FILE --ledger DIR` restores the ledger and its
  console on any computer with the recovery code; `console backup now|list` do the rest from the
  command line.

- **People.** Each user has a role (owner, admin, member, or viewer) and one or more passkeys.
  Roles gate the console, never the ledger: what someone may do on the ledger stays in their
  delegations. An invitation is a one-time code, valid for a day, kept only as a hash; it
  registers a passkey for the console's own name (never an address), made on the console's own
  page. The first owner's comes from `console setup-link`, which works only while the console
  has no owner. The **People** screen (owners and admins change it) makes an invitation link,
  shows each person's role, passkeys, and what they may do on the ledger in plain words, and
  approves someone who registered a passkey in up to three taps: their person on the ledger,
  with a key the console keeps for them; their passkeys as that person's presence; and a
  delegation of what they may do, chosen as words (register documents, of some kinds or all;
  endorse; revoke; act under rules, some or all; deploy rules; manage people, for admins), always
  in person, optionally until a date (`console user approve NAME --as KEY` does the same from the
  command line). The page checks each step's bytes before its tap. Withdrawing what someone may
  do revokes their delegation with a tap; removing them ends their sessions. Settings show the
  **API tokens** for programs (made once and shown once, revoked, as `token create|list|revoke`)
  and the console's **activity log** (`console activity`): who invited, approved, changed a
  role, made a token, saved a kind, connected a party, changed a setting, or locked the console,
  and when.
- **A company's console** runs on its own host name: `console run --public-url
  https://ledger.example.com`, behind a TLS proxy or with `--tls-cert FILE --tls-key FILE`, answers
  for that name only; its setup link, invitations, and party codes carry it, and its passkeys
  are for that host name. Passkeys made for one host name do not work on another.
- **Automation** lists the requests waiting for an answer, what the console's machine (its
  keeper) fires or expires next, and the ledger's machines with what each may do. "Add an
  executor" registers a device and grants it calls on one set of rules, answering requests of the
  kinds named and nothing else; "Add an AI agent" registers an agent answering to a person, with
  what it may do in the People screen's words. Each takes two taps: the machine's registration,
  the approving person's in person, then its delegation, which only the organization can grant
  (a person's in-person delegation cannot grant presence-free work), signed with the root key the
  console holds, by an owner, after the owner's passkey, and recorded in the activity log. Then
  its key is handed out once, encrypted with a passphrase typed on the page (the console keeps no
  machine's key), with an API token and the `executor run` config and command, or the MCP client
  setup for an agent (`cexchain mcp --server URL --token-file FILE --as KEY`).
- **Action links.** Each action on a thing's page offers a link to it (`/console/#/act/THING/ACTION`)
  and its QR code, to print or show: whoever opens it signs in and sees that action's form,
  checked and approved as any other, so the link holds no secret. The page fits a phone's screen
  (one column, targets of 44 px), and passkeys on the phone itself approve.
- **Signing in** takes a passkey assertion over a fresh challenge from the console, used once
  within five minutes, with the person verified (a PIN or a biometric). A session is a bearer
  token that the node keeps only as a hash, in memory; it ends after 30 idle minutes, after 12
  hours at most, on signing out, when the console stops, or with
  `cexchain-console session revoke ID` (`console session list` shows them).
- **Sealed keys, unlocked by a passkey.** `console key init` makes the console's node key and
  prints its recovery code once; `console key import NAME FILE` seals a key in the console. The
  node key is stored only wrapped: under the recovery code, a passphrase or an unlock file
  (`console run --unlock-file`), and each owner's or admin's passkey (its PRF output). A
  console starts locked and signs nothing until a passkey's sign-in, a passphrase, or the
  recovery code unlocks it.
- **Approving: one tap per statement.** `console user link NAME --actor ID --key KEY` lets a user
  act as a person of the ledger; `console user passkeys NAME --out DIR` writes their passkeys
  for `actor set-presence`. The console then prepares what the person asks for (registering,
  endorsing, or revoking a record; deploying or retiring rules; creating a thing under rules,
  acting on it, or answering its request), shows exactly what will be signed, and signs only after the
  person's passkey approves it; with a delegation that requires presence, the ledger itself
  refuses it otherwise, and the evidence shows the person was present.
- **Every request** first passes the console's checks: a Content-Security-Policy with nothing
  inline and nothing from elsewhere, and no framing, sniffing, referrers, or caching; answers
  only for the console's own names, so a page on another name that resolves to this address
  cannot reach it; and a request from another site's page is refused, while one that changes
  something must come from the console's own page.
