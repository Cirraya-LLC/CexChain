# Shipment

A chain of custody. A shipper sends twelve cartons of a vaccine, to be kept between 2 and 8
degrees Celsius, to a clinic. A carrier picks them up, leaves them overnight at a transit
warehouse, picks them up again, and delivers them, two days after the deadline; on the way, the
shipper's data logger records two readings above 8 degrees, and the clinic claims from the
insurer. Five organizations, five ledgers on one computer (the carrier's on the Chinese SM2 and
SM3 algorithms), no server: consents travel as files.

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

## What each step shows

1. **Five organizations, each with a ledger of its own.** Each keeps the others' ledger ids;
   the carrier signs with SM2 and hashes with SM3, the others with the defaults.
2. **Rules the shipper writes.** It tests the contract (`bo test`: seven tests) and deploys it
   on its ledger, the shipment's home; every party reads the same contract text in its own
   language.
3. **Who signs.** The carrier registers its driver, a person who signs with a key of his own
   and proves presence with a hardware key (SoftHSM stands in for a USB key; a passkey in a
   browser does the same), under a delegation that lets him consent for the carrier only in
   person. The shipper registers a data logger, a device whose delegation lets it call one
   function of this contract, `measure`, and a keeper, a device that calls the contract's time
   rules.
4. **Booking.** The packing list (product, batch, cartons) is a record of the shipper's own
   type, `example.shipper.packing-list/1`: its values stay sealed on the shipper's ledger. The
   shipment is an instance of the contract, created with the parties' ledgers, the deadline,
   the insured amount, and the charge per day late; its creation names the packing list.
5. **A receipt in person.** A pickup consented to with the carrier's key alone is refused
   (`bo:in-person pick_up`); the driver's consent, with his hardware key, is accepted, and
   the carrier holds the goods.
6. **A device, and a keeper.** The data logger posts its readings, signed with its own key;
   two are out of range. The deadline has passed: the keeper asks what is due (`keeper
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
   source), and consents to receive the goods. Two days late, the contract charges HKD 4,000.
9. **A claim.** The consignee claims the excursion within 7 days of delivery; the insurer
   checks the evidence, readings included, and pays HKD 120,000 (at most the insured amount).
   The shipment is final.
10. **Anyone verifies the whole history offline**, and sees who signed each step: the data
    logger and the keeper (devices), the driver (a person, present with a hardware key), the
    organizations with their own keys.

To show lateness without waiting days, the script books the shipment with a deadline two days
before today: a ledger registers each call at its own clock. (`contract call --dry-run --at`
and `keeper due --at` ask what would happen at another time, recording nothing.)

## Running it

```sh
cexchain bo test examples/shipment/shipment.bo                           # its seven tests
cexchain bo explain examples/shipment/shipment.bo --language zh-Hant-HK   # the contract text
examples/shipment/shipment.sh [CEXCHAIN] [DIR] [PKCS11_MODULE]           # CTest: demo_shipment
```

The script needs a `cexchain` built with the Bo compiler (GCC 16; the release build and the
Docker image have it) and SoftHSM (`brew install softhsm`, or `apt install softhsm2`), found
where Homebrew and Linux distributions install it, or given as `PKCS11_MODULE`. Give a `DIR` to
keep the ledgers and look around afterwards.

## Words

The contract uses Bo's core words only (`holder`, `due`, `amount`, `overdue`, `within`, `in
person`, `consent of`, money, dates, lists); no finance or commerce words. The late charge is a
field the contract computes, not a `charge` on a bill, which needs the `commerce` pack. The kind
word is the core's `thing`.

## Limitations

What this example could not say with today's Bo and CLI, each a candidate for a generic feature:

- **Days as a number.** A duration cannot be divided by a duration (`(now - due) / 1 day` is
  `check.operands`), so a charge per day late is a chain of `overdue N days` conditions, capped
  here at three days. A keeper cannot add a day's charge each day either: a rule applies once
  for each time, and a second rule doing the same thing cannot be named in a test.
- **Starting values.** Every instance field is given at creation: the counters `late_charge`
  and `excursions` are passed as 0.
- **Measurements.** Bo has no unit of temperature, and plain numbers are whole: readings are
  whole degrees (tenths would have to be numbers in tenths).
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
- **Tests see states, not values.** `bo test` cannot expect a field's value: the tests show a
  late delivery accepted, and the script checks the charge in the instance's state.
- **QR codes for instances.** `cexchain qr` draws codes for records only, so the code opens the
  packing list. The browser verifier already checks an instance that a link names
  (`#l=LEDGER&r=INSTANCE&b=URL`), which the script prints; no command draws it.

## After executors

*Not possible yet: executors are being built (Phase 6b). This section says what the example will
add then.* An executor is a device or an AI agent that acts outside the ledger when a contract
asks, and answers on the ledger. Once a contract's own actions can make requests (milestone E8)
and the executor runtime runs connectors (E5: `webhook`, `command`):

- **Notify the consignee** when the goods are picked up and when they are late: the deadline
  rule asks a `notify` executor, and its answer, done or failed, is recorded.
- **Sync a transport or warehouse system:** each handover asks a `webhook` executor to post
  the new holder to the carrier's transport management system or the warehouse's system, and
  the contract sees the answer.
- **The claim:** asking the insurer's claims system when the consignee claims, through the
  same connectors, with the insurer's staff answering by hand until a connector exists.

The contract, its parties, and its rules stay generic: the executors are configured per
organization, not built into CexChain.
