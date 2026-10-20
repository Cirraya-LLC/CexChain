# The connector protocol

Version 1 (draft). Informative: it is not part of the ledger's protocol, and nothing here changes what a ledger accepts or a verifier checks.

An **executor** carries out the requests contracts make (the protocol, [`README.md`](README.md) section 15) and answers them with signed calls. CexChain's executor runtime, `cexchain executor run`, does everything on the ledger's side: it finds requests, verifies each in the instance's evidence, keeps a journal, and signs and submits answers. What it does in the outside world it leaves to **connectors**: programs, in any language, that speak one outside system's API. This document defines how the runtime and a connector talk, what an answer carries, and how secrets reach a connector. It also describes the two connectors CexChain ships, `webhook` and `command`.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as in RFC 2119.

## 1. Roles

| Part | What it does | What it never does |
|---|---|---|
| Runtime | polls the home's server for requests (a hint); verifies each request open in the instance's contract evidence for the home ledger; journals; routes each request to a connector by its contract and kind; signs and submits the answer; retries; holds the lease | act on a request the signed evidence does not show open |
| Connector | carries out one request in an outside system and reports the outcome | see the signing key; sign anything; see requests routed to other connectors, or their secrets |

A buggy or hostile connector can misreport its own requests' outcomes. It cannot answer anything itself: the runtime signs, under a delegation that names the contract (scope key 7), the reply function (key 8), and the request kinds (key 9).

## 2. Transport

A connector is a child process of the runtime. They exchange **JSON lines** over the connector's stdin (runtime to connector) and stdout (connector to runtime): one JSON object per line, UTF-8, ending in a newline, at most 1 MiB per line. The connector's stderr is the runtime's; it MUST NOT carry secrets.

The runtime starts a connector without a shell (the program and its arguments as configured), in a process group of its own, with the default signal dispositions, and with its own environment minus every variable whose name starts with `CEXCHAIN_`. CexChain's runtime runs its first-party connectors as `cexchain connector webhook` and `cexchain connector command`.

**Numbers are integers.** A number with a fraction or an exponent, or beyond 64 bits, makes the whole line invalid: amounts travel in minor units. Nesting is at most 64 deep. Unknown fields MUST be ignored; a message of an unknown `type` SHOULD be ignored (a later version's), and a line that is not a message MAY be logged and skipped.

## 3. Messages

### 3.1 Runtime to connector

**`hello`**, first, once:

```json
{"type": "hello", "protocol": 1, "connector": "notices",
 "config": {"url": "https://hooks.example.com/ledger", "secret": "hook-key", "timeout": 10},
 "secrets": {"hook-key": "..."}}
```

`connector` is its name in the executor's config; `config` its configuration (a JSON object, without secrets); `secrets` the secrets its configuration names, and only those (section 5). A connector that cannot work with its configuration writes a `log` of level `error` saying why and exits with a non-zero status.

**`perform`**: carry out a request.

```json
{"type": "perform", "id": "9c1e...", "kind": "notify",
 "params": {"about": "welcome"}, "params_cbor": "a165616...",
 "deadline": 1792180311918, "asked_at": 1792176711918,
 "home": "3f2a...", "contract": "77a1...", "instance": "c0de...", "reply": "result",
 "attempt": 1, "timeout_ms": 10000}
```

- `id` is the request's id (64 hex digits). It is the **idempotency key**: a request may be performed more than once (a retry, or after the runtime restarts), and the outside system MUST act once per id.
- `params` are the request's params as JSON (byte strings as hex text); absent if they have no JSON form (a tag, a map key that is not text). `params_cbor` is their exact CBOR, in hex.
- `deadline` and `asked_at` are milliseconds since the epoch; `home` is the home ledger's id; `reply` is the function the answer calls.
- `attempt` counts from 1. `timeout_ms` is how long the runtime waits for the outcome; a connector that does not answer in time is stopped and restarted, and the attempt counts as one to retry.
- The runtime sends a connector one `perform` at a time: the next only after the outcome of the last. To work several requests at once it starts several copies of a connector, each greeted with its own `hello` (section 4, **Concurrency**).

**`cancel`** `{"type": "cancel", "id": "...", "reason": "answered"}`: stop working on a request (answered elsewhere, or expired). A connector that performs one request at a time MAY ignore it.

**`stop`** `{"type": "stop"}`: finish and exit. The runtime then closes the connector's stdin, and stops it if it has not exited within two seconds.

### 3.2 Connector to runtime

**`ready`**, the answer to `hello`:

```json
{"type": "ready", "protocol": 1, "name": "webhook", "version": "0.9.0", "kinds": ["notify"]}
```

`kinds` lists the request kinds it serves; absent or empty, any. The runtime refuses to start if the connector's configured kinds are not among them, or if `protocol` is not one it speaks. It waits 10 seconds for `ready`.

**`outcome`**, one per `perform`:

```json
{"type": "outcome", "id": "9c1e...", "status": "done",
 "result": {"ref": "N-1001"}, "response": "eyJvayI6dHJ1ZX0"}
```

- `status`: `done`, `failed` (a permanent failure: a refusal, a mapping the connector cannot make), or `retry` (a transient one: a timeout, the outside system busy or down).
- `result` (optional): what the answer publishes (section 4), at most 16 KiB of CBOR. Under the protocol's privacy rule (P8, [`README.md`](README.md) section 15) it MAY carry external ids, statuses, amounts, and reason codes, and MUST NOT carry names, e-mail addresses, phone numbers, postal addresses, document content, secrets, or raw error texts from outside systems.
- `reason` (optional): a code written like a request kind (`[a-z][a-z0-9._-]*`, at most 64 bytes), such as `rejected`, `unmapped`, `unavailable`.
- `response` (optional): the outside system's response, unpadded base64url, at most 512 KiB. The runtime keeps it in its journal; the answer carries only its salted digest.
- `retry_after_ms` (optional, with `retry`): wait at least this long.

**`log`** `{"type": "log", "level": "warn", "message": "slow answer", "id": "9c1e..."}`: a line for the runtime's log; `level` is `debug`, `info`, `warn`, or `error`; `message` at most 1,024 bytes; `id` optional. It MUST NOT carry secrets.

## 4. What the runtime does with an outcome

- **Before acting**, the runtime fetches the instance's contract evidence (`GET /v1/contracts/instances/{instance}`), verifies it completely for the home ledger, and finds the request open in it. The list from `GET /v1/requests` is a hint only; a request it cannot find open in verified evidence is never acted on. Kind, params, deadline, and reply are taken from the evidence.
- **Journal.** Each request has an entry in the runtime's state directory, synced before every outside action: seen, verified, acting (the attempt), outcome (status, result, reason, the response and its salt), answering (the signed answer), and finally answered or closed.
- **Retries.** `retry` backs off from 1 second, doubling to 5 minutes, with jitter of 20 per cent, and at least `retry_after_ms`. No attempt starts unless it can end before the deadline (now plus the connector's timeout); past that, the runtime answers `failed` with the reason `deadline`. Trouble with the ledger's server (it cannot be reached, a member restarts, a cluster elects a leader or has no quorum) backs off the same way to 30 seconds at most, so that an answer goes out soon after the server is back; while the server cannot be reached at all, the runtime asks it again every 5 seconds.
- **The answer** is a contract call on the instance, at the head the verified evidence shows, calling the request's reply, with body key 8 `[request, status]`: 1 (done) or 2 (failed). Its arguments are a map, or null when empty:

  | Key | When | Value |
  |---|---|---|
  | `"result"` | the outcome has one | the result, as CBOR |
  | `"reason"` | failed | the reason code (default `rejected`) |
  | `"response"` | the outcome has a response | `HASH(salt ‖ response)` under the home's hash, with a fresh 16-byte salt |

  The response and its salt stay in the journal, so the response can be disclosed later with proof (`executor journal show --response-out`).
- **Refusals.** If the ledger refuses the answer, the runtime fetches the evidence again: a request now closed was answered elsewhere (a keeper's expiry, a person by hand, another copy), and the entry is closed, its own answer never sent again; a request still open on a newer head gets a new answer on that head; a request still open on the same head means the contract or a ledger rule refuses this answer, and the entry is closed (the request stays open for others).
- **Restarts.** After a crash the runtime resumes from the journal: an outcome already journaled is answered, not acted on again; an attempt journaled as acting is performed again (the idempotency key makes that harmless).
- **Concurrency.** The runtime works several requests at once (`executor run --concurrency`, by default as many as the computer has cores), oldest first, and never two requests of one instance at once: an answer names the instance's head, which the other's answer would move. Each copy of a connector performs one request at a time; the runtime starts copies as requests need them, up to the connector's `concurrency` in the executor's config: by default as many as the runtime works at once for `webhook` and `command`, which keep nothing between requests, and one for a `program`, which may keep state of its own (`executor connector add --concurrency N` allows more). The answer is built on the evidence the request was verified in; if the instance changed in between, the ledger refuses the answer and it is built again on fresh evidence (as under **Refusals**).

## 5. Secrets

Secrets (webhook keys, API tokens) never appear in a connector's config, its arguments, its environment, a log, or the journal. The runtime keeps them sealed with HPKE (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM: the vault's suite) to a key pair of its own, each bound to its name; it opens those a connector's config names and sends them in `hello`, over the pipe, as text. A connector SHOULD keep them in memory only, and MUST NOT write them anywhere.

## 6. One copy at a time

Several copies of one executor (the same actor) take turns through the server's lease (`README.md` section 16, "Executors' leases"): a copy acts only while its polls are granted the lease, and renews it before every attempt. A copy that stops polling loses it after its time to live, and another takes over. On one machine, the runtime also locks its state directory. A lapse can briefly let two copies act on one request; the idempotency key and the ledger's at-most-once answer keep that harmless.

## 7. First-party connectors

### 7.1 `webhook`

Config: `url` (`https://`; `http://` only to `127.0.0.1`, `::1`, or `localhost`), `secret` (the name of the shared secret), `timeout` (seconds, 1 to 300; default 30), `ca_file` (optional PEM file of CA certificates to trust instead of the system's).

Each `perform` becomes a `POST` to the URL, with the body the perform's fields as JSON (`protocol`, `id`, `kind`, `params`, `params_cbor`, `deadline`, `asked_at`, `home`, `contract`, `instance`, `reply`, `attempt`) and these header fields:

| Field | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-CexChain-Request`, `Idempotency-Key` | the request's id |
| `X-CexChain-Attempt` | the attempt |
| `X-CexChain-Timestamp` | milliseconds since the epoch |
| `X-CexChain-Signature` | `sha256=` and the hex of HMAC-SHA-256(secret, timestamp ‖ `.` ‖ body) |

A receiver SHOULD check the signature in constant time and refuse timestamps more than five minutes away from its clock. TLS certificates and host names are verified; redirects are not followed. Each copy of the connector keeps its connection to the receiver open between requests (HTTP/1.1 keep-alive); a request sent on a connection the receiver had closed, and never answered, is sent once more on a new connection, with the same `Idempotency-Key`.

| Answer | Outcome |
|---|---|
| 2xx | `done`; a JSON object body may say `"status": "failed"` or `"retry"`, give a `"reason"` code, and give the `"result"`, the only part of it the answer publishes |
| 408, 425, 429, 5xx | `retry`, after `Retry-After` seconds if given (at most 300) |
| none (unreachable, timed out) | `retry`, reason `unavailable`; an untrusted certificate: reason `tls` |
| anything else | `failed`, reason `rejected` or the body's `"reason"` |

The body of the answer is the outcome's `response`.

### 7.2 `command`

Config: `program` (a path, or a name looked up in `PATH`), `args` (a list of texts), `timeout` (seconds, 1 to 300; default 30), `secrets` (names of secrets to hand it).

Each `perform` runs the program once, without a shell, with the configured arguments only (params never reach them), and writes the request to its stdin as one JSON line: the webhook's body, plus `"secrets"` (an object of the secrets its config names) if any. Its stdout (at most 512 KiB) is the outcome's `response`.

| Ending | Outcome |
|---|---|
| exit 0 | `done` |
| exit 75 (`EX_TEMPFAIL`), a signal, or the timeout (the process group is killed) | `retry` |
| any other exit | `failed`, reason `rejected` |

If its stdout is a JSON object, its `"result"`, `"reason"`, `"status"`, and `"retry_after_ms"` are read as a webhook's are; nothing else of it is published.

## 8. Writing a connector

A connector in any language reads lines from stdin, answers `hello` with `ready`, and each `perform` with one `outcome`, then exits on `stop` or at the end of its input. Configure it with `cexchain executor connector add NAME --type program --program PATH [--arg ...] --kinds ... [--secrets ...] [--connector-config JSON]`, and check it with `cexchain executor check`.
