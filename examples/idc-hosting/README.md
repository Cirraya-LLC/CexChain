# Server hosting

A hosting provider rents a server to a customer, billed each month. The customer subscribes;
the provider's control panel provisions the server and its billing system invoices the first
month; the customer pays and later renews; the second bill is paid only in part, so three days
after the due date the server is suspended; the rest is paid in cash, and the server resumes;
then the customer ends the service, and the panel deletes the server and takes its address back.
The provider's AI agent sends the customer the notices the contract asks for, through MCP; a
clerk records the cash payment by hand. Anyone can verify the whole history offline.

CexChain knows nothing about servers, panels, or invoices. The contract,
[`hosting.bo`](hosting.bo), declares the `services` and `commerce` vocabulary packs and adds a
few lines of its own:

```
service Server
  price monthly HKD 800
  machine text = ""

can subscribe by customer
can renew by customer
can terminate by customer
  request reclaim with machine = machine within 1 day

when subscribe done
  machine = result
when 7 days before due
  requires active or suspended
  notify customer
when overdue 3 days suspend
when overdue 30 days terminate
when suspend fails notify we
when collect fails notify we
```

The packs bring the rest (Bo's rules R10, R11, R34, R35): a server with a monthly price is paid
until a date and billed until a date; subscribing and each renewal bill one month, asking an
executor for an `invoice` and, once it is done, a `collect`; a collection done pays the month
and resumes a suspended server; `subscribe`, `suspend`, `resume`, and `terminate` each ask an
executor to do the same outside the ledger. The contract decides; it never acts on the world
outside its ledger, it asks. Every party reads the same text in its own language, Bo's lines
marked with their rules (`bo explain --language zh-Hant-HK`, in part):

```
4.1 訂購（函數 subscribe）
  4.1.2 由客戶發起，須經其同意。
  4.1.5 將已付費至改為調用當日。〔R19〕
  4.1.7 將已出賬至改為已出賬至 + 1 個月。〔R34〕
  4.1.8 向執行器請求發票（對象：客戶），在賬本以外辦理，須於調用後 7 日內答覆（即其期限）。〔R34〕
    4.1.8.1 請求附帶金額：港元 800；已付費至：已付費至；已出賬至：已出賬至。
  4.1.9 向執行器請求訂購，在賬本以外辦理，須於調用後 1 日內答覆（即其期限）。〔R10〕
```

## Who is who

| Who | What it is | What it may do |
|---|---|---|
| Harbour Hosting Ltd. | the provider: the contract's home, its ledger on a cluster of three servers | create instances and make calls with the customer's consent |
| Kowloon Design Studio | the customer, with a ledger of its own | consent to subscribe, renew, and terminate, after checking the evidence |
| Operations | the provider's executor (a device) | answer `subscribe`, `suspend`, `resume`, `terminate`, `reclaim`, `invoice`, and `collect` requests of this contract |
| Keeper | the provider's keeper (a device), inside each cluster member (`serve --keeper-key`); the leader's acts | call the contract's time rules once they are due |
| Support Agent | the provider's AI agent, an MCP client; Mei Chan is responsible for it | answer `notify` requests of this contract |
| Mei Chan | a clerk (a person) | answer `collect` requests of this contract by hand |
| [`panel.py`](panel.py), [`billing.py`](billing.py) | fake systems on this computer, reached by webhooks | nothing on the ledger: they hold no key |

## What each step shows

1. **Two ledgers.** The provider and the customer each create a ledger and learn the other's id.
2. **The rules.** The provider tests the contract (`bo test`: six tests) and deploys its source;
   the ledger compiles it, and its text states the requests Bo added.
3. **Who acts.** The executor, the keeper, the clerk, and the AI agent are actors with keys of
   their own, each with a delegation naming this contract, the reply function, and the request
   kinds it may answer (`executor add`, `keeper add`, `delegation grant --request-kinds`).
4. **A cluster.** The provider's ledger is founded as a three-member Raft cluster; from here on
   the staff, the executor, and the agent work through any member's API, each with a verified
   mirror (`--server`).
5. **Connectors.** The executor's config routes `subscribe`, `suspend`, `resume`, `terminate`,
   and `reclaim` to the panel's webhook and `invoice` and `collect` to the billing system's
   (`executor connector add --type webhook`); the shared secrets are sealed in the executor's
   state (`executor secret set`), and every request it posts is signed with HMAC.
6. **Subscribe.** The customer checks the instance's evidence and consents on its own ledger; the
   provider's call cites the consent. The call asks for `subscribe` and `invoice`. The
   executor's run verifies each request in the signed evidence before acting, posts it, and
   answers: the panel names the new server `srv-0001` (its address stays in the panel), which
   the contract keeps; billing issues INV-0001, and the contract asks for its collection.
7. **A notice through MCP.** Seven days before the due date the contract asks to notify the
   customer; before the first payment the due date is the day of the subscription, so the
   keeper fires the rule at once. The AI agent lists the open request, reads the instance, and
   answers done, signed with its own key, its model and a hash of its notice recorded.
8. **Paid.** The bank reports the transfer to billing; the executor's collection is done, and
   the server is paid for a month.
9. **Renewed.** The clocks move three weeks ahead; the keeper fires the reminder, the agent sends
   it, and the customer renews. The new invoice is paid only in part (HKD 500.00 of 800.00), so
   billing answers "retry" (`awaiting-payment`), and the collection stays open.
10. **Suspended.** Three days after the due date the keeper suspends the server and the contract
    asks the panel to suspend it; billing still waits.
11. **Paid by hand.** The customer pays the rest in cash at the counter, which billing never
    sees. The clerk answers the collection herself (`request answer --done`): a person's
    answer. The server is paid for another month and no longer overdue, so the contract makes
    it active and asks the panel to resume it. The executor's next run finds the collection
    answered elsewhere and drops its own attempt.
12. **Terminated.** The customer ends the service. The instance is final, but the answers to the
    requests its last call made are still recorded: the panel deletes the server and takes its
    address back into its pool.
13. **Verified offline.** `contract verify` replays every call and checks every consent on the
    customer's own ledger: 11 requests made, 11 answered, 0 open; who answered each (the
    executor, the agent with its model and the MCP tool, the clerk, the keeper). The same file
    opens in the browser verifier (`cexchain-verify.html`), and both ledgers audit clean.

## The address

The server's address is the panel's: the contract keeps only the panel's name for the server,
from its answer to `subscribe`, and terminating it (by the customer, or by the keeper 30 days
overdue) also asks the panel to `reclaim` the address of that server
(`request reclaim with machine = machine within 1 day`, in the termination's own block, so the
keeper's termination makes the request too). One contract, the reclaim tied to the termination
in its text, and its answer on the record; requests carry no addresses (spec section 15).

A provider that wants its ledger to be the registry of its addresses would instead keep an
address pool contract (the spec's IP pool example: a `resource` of the services pack, with
`allocate` to one customer at a time and `reclaim` with a cooling period), and allocate and
reclaim an address there when the panel answers. That is a second instance for each address,
and the customer's consent at each allocation (R3).

## Time

A month cannot pass in a test. Every `cexchain` command reads `CEXCHAIN_CLOCK_OFFSET` (such as
`30d` or `2067754s`) and runs its clock that far ahead; the script sets it and restarts the
cluster to move time on, and the customer, the executor, and the agent move with the provider.
It is for demonstrations and tests only: a ledger keeps the times it records, and a client whose
clock runs ahead of its ledger's is refused (a statement from the future).

## Running it

```sh
cexchain bo test examples/idc-hosting/hosting.bo                           # its six tests
cexchain bo explain examples/idc-hosting/hosting.bo --language zh-Hans-CN   # the contract text
examples/idc-hosting/idc-hosting.sh [CEXCHAIN] [DIR]                       # CTest: demo_idc_hosting
```

The script needs a `cexchain` built with the Bo compiler (GCC 16; the release build and the
Docker image have it) and `python3`, which runs the fake panel and billing system. It takes
about a minute. Give a `DIR` to keep the ledgers, the executor's journal, and the fake systems'
files, and look around afterwards. In production the executor runs as a service of its own
(`executor run` without `--once`); here it runs once after each step, so that the story is told
in order.

## Words

The contract uses the `services` pack (the kind word `service`, `subscribe`, `renew`, the paid
and billed dates, the bills) and the `commerce` pack (`collect`, money); `suspend`, `resume`,
`terminate`, `notify`, and `request` are core words. `reclaim` is used here as a request kind,
which the panel's connector serves; `machine` is the contract's own field.

## Limitations

What this example could not say with today's Bo and CLI, each a candidate for a later milestone:

- **Charges and usage on a service's bills.** A bill holds the month's price only: no setup fee,
  no tax line, no traffic beyond the plan (a service with a bill field of its own is refused,
  `check.service-bill`), and usage reported from outside cannot be billed yet.
- **Proration.** `upgrade` and `downgrade` ask the panel to change the plan, but the contract's
  price stays and no part of a month is billed or credited.
- **Refunds.** Terminated while paid for a month ahead, the customer gets nothing back: the
  `commerce` pack's refund has no terms, and no request carries an amount back.
- **Paying ahead.** One bill is open at a time, so several months cannot be paid at once.
- **The first reminder.** Before the first payment the due date is the subscription's day, so
  "7 days before due" applies at once: the welcome notice is that reminder.
- **Payments outside billing.** The clerk's answer records the cash payment on the ledger, but
  the billing system does not learn of it; a connector that records it there too, or a
  `request answer` that also posts to billing, would.
- **Final states and rule blocks.** A time rule that does an action on its own line
  (`when overdue 30 days terminate`) lets Bo see that `terminated` is final; written as a block
  (`terminate` on the next line), it does not yet, so the contract would never end. The
  termination's reclaim therefore lives in the action's block.
- **MCP and other organizations.** Through `--server` (a cluster) the agent can answer requests
  and make calls, but not reach other organizations' ledgers: peers belong to a ledger
  directory.
