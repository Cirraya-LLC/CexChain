# Shipment

A chain of custody. A shipper sends twelve cartons of a vaccine, to be kept between 2 and 8
degrees Celsius, to a clinic. A carrier picks them up, leaves them overnight at a transit
warehouse, picks them up again, and delivers them, two days after the deadline; on the way, the
shipper's data logger records two readings above 8 degrees, and the clinic claims from the
insurer. Five organizations, five ledgers on one computer (the carrier's on the Chinese SM2 and
SM3 algorithms); consents travel as files. At delivery the contract asks for a notice to the
clinic's system, which an executor of the shipper's sends and answers on the ledger.

CexChain knows nothing about shipments, carriers, or temperatures. The parties, the fields, the
states, and the actions are the contract's own words, in
[`shipment.bo`](shipment.bo), written with Bo's core words only. Its heart is a handover the
driver signs in person:

```
can drop_off by carrier
  requires in person
  requires in_transit or late
  requires holder = carrier
  requires consent of warehouse
  holder = warehouse
```

The carrier starts it, and its driver must prove presence; the carrier must have the goods; the
warehouse consents to take them; and since the holder changes, whoever held them consents to give
them up (R8). The text every party reads, in Simplified Chinese (`bo explain --language
zh-Hans-CN`):

```
4.3 drop_off
  4.3.1 由 carrier 发起，须经其同意。
  4.3.2 须经调用前作为持有人的参与方同意，因为此动作会更改持有人。〔R8〕
  4.3.3 要求 1：carrier 须以通行密钥或硬件密钥证明本人在场。〔R13〕
  4.3.4 要求 2：实例处于 in_transit 或 late 状态。〔R7〕
  4.3.5 要求 3：持有人为 carrier。
  4.3.6 要求 4：须经 warehouse 同意。
  4.3.7 将持有人改为 warehouse。
  4.3.8 AI 代理可在其授权范围内发起此动作。〔R14〕
```

(An AI agent may start it within its delegation, R14; it would then be refused, since it proves
no presence.)

Delivery counts the whole days late and charges for each; the contract text says how it rounds,
here in Traditional Chinese (`--language zh-Hant-HK`), with rule R32 explained at its end:

```
  4.4.8 如實例已逾期（已過到期日）：
    4.4.8.1 將 days_late 改為（調用時間 − 到期日） ÷ 1 日（按完整倍數計算，餘數捨去）。〔R32〕
    4.4.8.2 將 late_charge 改為 penalty_per_day × days_late。
```

Delivery also asks the outside world for something: a delivery notice to the consignee's
system, which the ledger cannot send itself. The contract states the request, its deadline,
and what happens when it is answered:

```
can deliver by carrier
  ...
  request notify to consignee with message = "delivered", late_charge = late_charge within 1 day

when notify done
  notified = yes
  notice = result

when notify fails
  notice = reason
  request notify to shipper with message = "notice failed" within 1 day
```

An executor, a program of the shipper's with a key of its own, sends the notice and answers:
done, with a receipt the contract keeps (`result`), or failed, with a reason; a request no
answer reaches within the day expires, and counts as failed (rule R33). The text, in
Traditional Chinese:

```
  4.4.9 向執行器請求通知（對象：consignee），在賬本以外辦理，須於調用後 1 日內答覆（即其期限）。
    4.4.9.1 請求附帶 message：「delivered」；late_charge：late_charge。
    4.4.9.2 如請求失敗或過期，即適用請求通知失敗時的規則（見「請求的答覆」）。〔R33〕
...
6.2 請求通知完成時：
  6.2.1 將 notified 改為是。
  6.2.2 將 notice 改為答覆的結果。
6.3 請求通知失敗或過期時：〔R33〕
  6.3.1 將 notice 改為答覆的原因。
  6.3.2 向執行器請求通知（對象：shipper），在賬本以外辦理，須於調用後 1 日內答覆（即其期限）。
```

## What each step shows

1. **Five organizations, each with a ledger of its own.** Each keeps the others' ledger ids;
   the carrier signs with SM2 and hashes with SM3, the others with the defaults.
2. **Rules the shipper writes.** It tests the contract (`bo test`: ten tests, which check the
   state and the fields after each step, such as `-> delivered, days_late = 2, late_charge = HKD
   4_000`, and answer its notice as an executor would: `executor notify done with result =
   "RCPT-1"`, `executor notify fails with reason = "unreachable"`, `keeper notify expires at
   2027-03-11`) and deploys it on its ledger, the shipment's home; every party reads the same contract
   text in its own language.
3. **Who signs.** The carrier registers its driver, a person who signs with a key of his own
   and proves presence with a hardware key (SoftHSM stands in for a USB key; a passkey in a
   browser does the same), under a delegation that lets him consent for the carrier only in
   person. The shipper registers a data logger, a device whose delegation lets it call one
   function of this contract, `measure`, and a keeper, a device that calls the contract's time
   rules.
4. **Booking.** The packing list (product, batch, cartons) is a record of the shipper's own
   type, `example.shipper.packing-list/1`: its values stay sealed on the shipper's ledger. The
   shipment is an instance of the contract, created with the parties' ledgers, the deadline,
   the insured amount, and the charge per day late (the days late, the late charge, and the
   excursions start at 0, their defaults); its creation names the packing list.
5. **A receipt in person.** A pickup consented to with the carrier's key alone is refused
   (`bo:in-person pick_up`); the driver's consent, with his hardware key, is accepted, and
   the carrier holds the goods.
6. **A device, and a keeper.** The data logger posts its readings, signed with its own key, in
   tenths of a degree (`4.2 °C`; the arguments carry hundredths, `420`); two are out of range. The deadline has passed: the keeper asks what is due (`keeper
   due`), then fires `when.late`, and the event records how late it came.
7. **Custody, and a refusal.** The driver leaves the goods at the warehouse and picks them up
   again, in person each time, with the warehouse's consent. The warehouse and the consignee
   both consent to a delivery straight from the warehouse, and the contract refuses it
   (`bo:requires deliver 2`): only the carrier delivers what it holds.
8. **QR verification at delivery.** `cexchain qr` draws the code on the cartons
   (`label-qr.svg`): it opens the packing list's evidence in the browser verifier,
   `cexchain-verify.html`, which checks it on the phone itself. The shipper discloses the
   product and the cartons; the batch stays sealed. The consignee checks the same evidence on
   the command line (`cexchain verify`), then the chain of custody (`contract verify`: every
   call run again, every consent checked on its own ledger, the contract rebuilt from its
   source), and consents to receive the goods. The contract counts the whole days late, `(now -
   due) / 1 day`, two, and charges HKD 2,000 for each: HKD 4,000. The delivery makes a
   request: a notice to the consignee, to be answered within a day.
9. **An executor sends the notice.** The shipper registers an executor (`executor add
   Notices --contract ... --kinds notify`): a device whose delegation lets it answer this
   contract's `notify` requests and nothing else. Its connector is a command, a script run
   without a shell, that drops the notice in the consignee's inbox (a `webhook` to the clinic's
   system works the same). The shipper's server runs while the executor works: `executor run
   --once` finds the request there, verifies it in the shipment's signed evidence before
   acting, runs the command, and answers done with its receipt, `INBOX-1`. The contract's rule
   for a done notice records it: `notified` is yes, `notice` holds the receipt.
10. **A claim.** The consignee claims the excursion within 7 days of delivery; the insurer
    checks the evidence, readings included, and pays HKD 120,000 (at most the insured amount).
    The shipment is final.
11. **Anyone verifies the whole history offline**, and sees who signed each step: the data
    logger, the keeper, and the executor (devices), the driver (a person, present with a
    hardware key), the organizations with their own keys; and every request with its answer
    (`1 made by its calls, 1 answered, 0 open`).

To show lateness without waiting days, the script books the shipment with a deadline two days
before today: a ledger registers each call at its own clock. (`contract call --dry-run --at`
and `keeper due --at` ask what would happen at another time, recording nothing.)

## Running it

```sh
cexchain bo test examples/shipment/shipment.bo                           # its ten tests
cexchain bo explain examples/shipment/shipment.bo --language zh-Hant-HK   # the contract text
examples/shipment/shipment.sh [CEXCHAIN] [DIR] [PKCS11_MODULE]           # CTest: demo_shipment
```

The script needs a `cexchain` built with the Bo compiler (GCC 16; the release build and the
Docker image have it) and SoftHSM (`brew install softhsm`, or `apt install softhsm2`), found
where Homebrew and Linux distributions install it, or given as `PKCS11_MODULE`. Give a `DIR` to
keep the ledgers and look around afterwards.

## Words

The contract uses Bo's core words only (`holder`, `due`, `amount`, `overdue`, `within`, `in
person`, `consent of`, `request`, money, dates, temperatures in `°C`, lists); no finance or
commerce words. `notify` is a request kind, which an executor's connector serves; any name of
lowercase letters works as one (`http.post`, `sync`).
The days late are a duration divided by a duration, which counts whole days and drops the rest
(rule R32, stated in the contract text). The late charge is a field the contract computes, not a
`charge` on a bill, which needs the `commerce` pack. The kind word is the core's `thing`.

## Limitations

What this example could not say with today's Bo and CLI, each a candidate for a generic feature:

- **Charges that accrue day by day.** The late charge is computed once, at delivery, from the
  whole days late. A keeper cannot add a day's charge each day: a rule applies once for each
  time, and a second rule doing the same thing cannot be named in a test.
- **Who may sign.** A contract can ask for a person in person, or let AI agents only propose,
  but cannot ask for a device: the data logger's delegation limits it to `measure`, yet any
  signer the shipper authorizes could call it too. The evidence shows who signed each call.
- **Presence of others.** `in person` asks only the party that starts an action, so the
  handovers are the carrier's actions; the warehouse's and the consignee's consents cannot be
  required in person. `contract verify --require-presence` asks it of every consent, so it
  fails here.
- **Readings from another party's device.** The data logger is the shipper's, the home's. A
  sensor of the carrier's would need the carrier's consent to each reading, or evidence from
  another ledger as an input, which Bo does not read yet.
- **QR codes for instances.** `cexchain qr` draws codes for records only, so the code opens the
  packing list. The browser verifier already checks an instance that a link names
  (`#l=LEDGER&r=INSTANCE&b=URL`), which the script prints; no command draws it.

Four limitations of the first version are gone: days late are a number
(`(now - due) / 1 day`), counters start at 0 without being given, readings are temperatures to
a tenth of a degree (or a hundredth), and tests expect the fields' values.

## Executors

The delivery notice is the example's one request. Others fit the same pattern, each a few lines
of Bo and a connector configured by the organization that runs it, not built into CexChain:

- **Notices along the way:** a `notify` request when the goods are picked up, or when the keeper
  marks the shipment late.
- **Syncing a transport or warehouse system:** each handover requests a post of the new holder
  to the carrier's transport management system or the warehouse's system (a `webhook`), and a
  rule reacts if it fails.
- **The claim:** a request to the insurer's claims system when the consignee claims, answered
  by the insurer's staff by hand (`cexchain request answer`) until a connector exists.

The services vocabulary pack's own requests (a VPS suspended when overdue, a renewal's
invoice) come next.
