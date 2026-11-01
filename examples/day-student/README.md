# Day student: one application, four offices, a form that keeps changing

A student applies to live off campus and come in by day. Four offices sign
in turn: the counsellor, the student affairs office, the dormitory, and
security. The form changes three times a month. On paper, a student who
picked up the form last week walks it to the third office and is sent back:
"this is the old form". Then round the offices again.

Here the form's steps are the school's rules on its own ledger, and every
office works on the same application, not on its own copy:

- **No old form can be started.** When the school changes the form, it
  deploys the new rules (`day-student-v2.bo`) and retires the old ones
  (`day-student.bo`). A new application on the old form is refused.
- **What was started is finished.** An application already under way goes
  on to the end on the form it began with; no office can send it back for
  being on the old one. The ledger shows which form each application is on.
- **Each office takes only its own step, in order.** Who may take which step
  is a delegation on the school's ledger (the counsellor may approve as
  counsellor, and nothing else); the rules give the order. A step out of
  turn, or by the wrong office, is refused.
- **What a new form asks for is enforced.** Version 2 asks for an emergency
  contact: the counsellor cannot approve an application on it without one.
- **Sent back, it says why.** Any office can send an application back with
  what to fix; once corrected it goes through again from the counsellor.
- **Nothing personal is on the ledger.** The filled-in form (name, address,
  guardian, reason) is a record whose values stay sealed in the school's
  vault; only salted commitments are on the ledger. The application names
  the record. Security is shown only the student's name and class, proven
  against the record's commitment; the rest stays sealed.
- **Anyone verifies the history offline.** Which form, every step, who took
  it, and when, checked against the school's ledger id alone, the rules
  rebuilt from their source.

| File | What it is |
|---|---|
| [`day-student.bo`](day-student.bo) | The form, version 1: the application (the filled-in form's record, whether the guardian signed) and the steps |
| [`day-student-v2.bo`](day-student-v2.bo) | Version 2: the same, and an emergency contact the counsellor requires |
| [`day-student.sh`](day-student.sh) | The story, narrated step by step |

## Run it

```sh
examples/day-student/day-student.sh path/to/cexchain            # in a temporary directory
examples/day-student/day-student.sh path/to/cexchain ./school   # keep the ledger to look at
```

It needs a `cexchain` built with the Bo compiler (GCC 16; the release build
and the Docker image have it). The same rules work in the web console: open
`day-student.bo` under Rules, deploy it, and retire it there when version 2
is deployed; each office's staff, as console users with delegations for
their step, approve with a passkey tap, on a computer or a phone.

## What a real school would add

- Students filling the form in themselves: on the console, or a page that
  takes the filled-in form and starts the application in one step.
- Telling the next office when an application reaches it, or the student
  when it is sent back: a request in the rules that an executor sends on to
  a messaging system (see [`shipment`](../shipment/) and
  [`idc-hosting`](../idc-hosting/)).
- Signing in with the school's own accounts, for many students.
