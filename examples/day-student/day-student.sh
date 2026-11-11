#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# A student applies to be a day student (to live off campus), narrated step
# by step. The form changes three times a month, and four offices sign in
# turn: the counsellor, the student affairs office, the dormitory, and
# security. On paper, a student who picked up the form last week is sent back
# by the third office for having the old one. Here the form's steps are the
# school's rules on its own ledger, and a filled-in form is a record whose
# values stay sealed in the school's vault:
#   - the school deploys the form (day-student.bo), and publishes the blank
#     form itself as a record; each office's staff may take only their own
#     step, by a delegation;
#   - Li Ming applies; the counsellor approves;
#   - the school changes the form (day-student-v2.bo asks for an emergency
#     contact): it deploys the new rules and retires the old ones, and
#     publishes the new blank form as superseding the old one. A new
#     application can no longer start on the old form; Li Ming's, already
#     started, goes on to the end on the form it began with;
#   - Chan Wing applies on the new form; the office sends it back to be
#     fixed, it is corrected and goes through;
#   - no step out of turn, no office taking another's step, no approval of
#     a new-form application without an emergency contact;
#   - anyone verifies an application's whole history offline: which form,
#     who approved, when, the rules rebuilt from their source; and security
#     sees only the student's name and class from the form, nothing else;
#   - a printed copy of the old blank form, checked by anyone, says a newer
#     version replaced it, and which.
# It needs a kanhe built with the Bo compiler (GCC 16; the release build
# and the Docker image have it). The web console shows the same: Rules lists
# both forms (the old one retired), Things each application with its steps.
#
# Usage: day-student.sh [KANHE] [DIR]
#   KANHE  the command-line tool (default: kanhe on the PATH)
#   DIR       where to keep the ledger (default: a temporary directory,
#             removed at the end; give one to look around afterwards)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="${1:-kanhe}"
case "$KANHE" in */*) KANHE="$(cd "$(dirname "$KANHE")" && pwd)/$(basename "$KANHE")" ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${2:-}" ]; then
    WORK="$2"; KEEP=1; mkdir -p "$WORK"
else
    WORK="$(mktemp -d)"; KEEP=0
fi
WORK="$(cd "$WORK" && pwd)"
cleanup() {
    [ "$KEEP" = 0 ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
cd "$WORK"
export KANHE_PASSPHRASE="demo only: use real passphrases or hardware keys"
unset KANHE_LEDGER KANHE_SERVER KANHE_TOKEN

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
say() { printf '   %s\n' "$*"; }
# A command line as typed: bo, kanhe-console, and kanhe-index are the
# programs beside kanhe.
run() {
    case "$1" in
    bo | kanhe-console | kanhe-index) "$(dirname "$KANHE")/$1" "${@:2}" ;;
    *) "$KANHE" "$@" ;;
    esac
}
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
indent() { sed 's/^/   /'; }
check() {
    if ! grep -F -- "$2" "$1" > /dev/null; then
        echo "expected \"$2\" in $1:" >&2
        cat "$1" >&2
        exit 1
    fi
}
# refused FILE TEXT CMD...: the command must fail, saying TEXT.
refused() {
    local out="$1" text="$2"; shift 2
    if run "$@" > "$out" 2>&1; then
        echo "expected a refusal: $*" >&2
        cat "$out" >&2
        exit 1
    fi
    check "$out" "$text"
}

if [ ! -x "$(dirname "$KANHE")/bo" ]; then
    echo "this kanhe was built without the Bo compiler (GCC 16 builds it)" >&2
    exit 2
fi
SCHOOL="$WORK/school"

step "1. The school's ledger"
run key generate --out school-root.key > /dev/null
run key generate --out school-log.key > /dev/null
run init --name "Example School" --root-key school-root.key --log-key school-log.key \
    --ledger "$SCHOOL" > /dev/null
SCHOOL_ID="$(run status --ledger "$SCHOOL" --json | field '["ledger_id"]')"
say "Example School  ledger ${SCHOOL_ID:0:16}..."

step "2. The form, as rules: tested, then deployed"
cp "$HERE/day-student.bo" "$HERE/day-student-v2.bo" .
run bo test day-student.bo | tail -n 1 | indent
run bo build day-student.bo --out day-student.boc > /dev/null
V1="$(run contract deploy day-student.boc --as school-root.key --ledger "$SCHOOL" --json \
    2> /dev/null | field '["contract"]["id"]')"
say "Form, version 1: rules ${V1:0:16}..."
# The blank form as handed out, published as a record: its text committed,
# its version and rules public.
publish() {
    local version="$1" rules="$2"; shift 2
    printf 'Day student application, version %s\n' "$version" > "blank-v$version.txt"
    run record issue --type example.school.blank-form/1 --field "text=day student form $version" \
        --meta "title=Day student application" --meta "version=$version" --meta "rules=$rules" \
        --attach "blank-v$version.txt" "$@" --as school-root.key --ledger "$SCHOOL" --json |
        field '["record"]["id"]'
}
BLANK1="$(publish 1 "$V1")"
say "The blank form, version 1: record ${BLANK1:0:12}..."

step "3. Who may take which step: one delegation each"
# The desk enters applications (for the student, or the student does on the
# console); each office takes only its own step, and may send one back.
staff() {
    local name="$1" key="$2" functions="$3" more="${4:-}"
    run key generate --out "$key.key" > /dev/null
    local id
    id="$(run actor add --kind person --name "$name" --key "$key.key" --as school-root.key \
        --ledger "$SCHOOL" --json | field '["actor"]["id"]')"
    run delegation grant --to "$id" --allow contract-call --functions "$functions" --days 365 \
        --as school-root.key --ledger "$SCHOOL" > /dev/null
    if [ -n "$more" ]; then
        # shellcheck disable=SC2086
        run delegation grant --to "$id" --allow $more --days 365 --as school-root.key \
            --ledger "$SCHOOL" > /dev/null
    fi
    say "$name: $functions${more:+ (and registers filled-in forms)}"
}
staff "Student desk" desk create,correct,resubmit,withdraw \
    "record-register --record-types example.school.day-student-form/1,example.school.day-student-form/2"
staff "Counsellor Wong" counsellor counsellor_approves,send_back
staff "Student Affairs Office" office office_approves,send_back
staff "Dormitory" dormitory dormitory_checks_out,send_back
staff "Security" security security_registers,send_back

step "4. Li Ming applies on the form of the day; the counsellor approves"
# The filled-in form: a record whose values stay sealed in the school's vault
# (only their salted commitments are on the ledger). The application names it.
form() {
    local version="$1"; shift
    local args=()
    for f in "$@"; do args+=(--field "$f"); done
    run record issue --type "example.school.day-student-form/$version" "${args[@]}" \
        --as desk.key --ledger "$SCHOOL" --json | field '["record"]["id"]'
}
apply() {
    local rules="$1" fields="$2"
    run contract create "$rules" create \
        --args "{\"fields\": {$fields}, \"parties\": {\"school\": h'$SCHOOL_ID'}}" \
        --as desk.key --ledger "$SCHOOL" --json | field '["instance"]["id"]'
}
LI_FORM="$(form 1 "student=Li Ming" student_number=2025-0142 class_name=S5B \
    "address=12 Hill Road, Sha Tin" "guardian=Li Hua" "guardian_phone=5555 0101" \
    "reason=lives with family")"
LI="$(apply "$V1" "\"details\": \"record $LI_FORM\", \"guardian_agrees\": true")"
run contract call "$LI" counsellor_approves --args "{}" --as counsellor.key --ledger "$SCHOOL" \
    > li1.txt
check li1.txt 'status: counsellor_approved'
say "Li Ming's form: record ${LI_FORM:0:12}... (its values sealed)"
say "Li Ming's application: counsellor_approved, on form version 1"

step "5. The school changes the form: new rules deployed, the old ones retired"
run bo build day-student-v2.bo --out day-student-v2.boc > /dev/null
V2="$(run contract deploy day-student-v2.boc --as school-root.key --ledger "$SCHOOL" --json \
    2> /dev/null | field '["contract"]["id"]')"
run contract retire "$V1" --reason "replaced by the form of 8 November" --as school-root.key \
    --ledger "$SCHOOL" | indent
say "Form, version 2 (asks for an emergency contact): rules ${V2:0:16}..."
BLANK2="$(publish 2 "$V2" --supersedes "$BLANK1")"
run record versions "$BLANK1" --ledger "$SCHOOL" > versions.txt
check versions.txt '[latest]'
indent < versions.txt
say "The blank form, version 2: record ${BLANK2:0:12}..., superseding version 1."
# No one starts on the old form any more.
refused old.txt 'retired' contract create "$V1" create \
    --args "{\"fields\": {\"details\": \"record 0\", \"guardian_agrees\": true}, \"parties\": {\"school\": h'$SCHOOL_ID'}}" \
    --as desk.key --ledger "$SCHOOL"
say "A new application on version 1: refused (the rules are retired)."

step "6. Li Ming's application goes on, on the form it began with"
for who_step in office:office_approves dormitory:dormitory_checks_out \
    security:security_registers; do
    run contract call "$LI" "${who_step#*:}" --args "{}" --as "${who_step%%:*}.key" \
        --ledger "$SCHOOL" > step.txt
    say "${who_step%%:*}: $(grep -o 'status: [a-z_]*' step.txt)"
done
check step.txt 'status: approved'
say "Approved. No office sent Li Ming back for having the old form."

step "7. Chan Wing applies on the new form; it is sent back, fixed, and goes on"
# Without an emergency contact the new form is not complete: the counsellor
# cannot approve it.
CHAN_FORM="$(form 2 "student=Chan Wing" student_number=2025-0077 class_name=S4A "address=Flat 3" \
    "guardian=Chan Mei" "guardian_phone=5555 0202" "reason=closer to the family shop")"
CHAN="$(apply "$V2" "\"details\": \"record $CHAN_FORM\", \"guardian_agrees\": true, \"emergency_contact_given\": false")"
refused contact.txt 'bo:requires counsellor_approves' contract call "$CHAN" counsellor_approves --args "{}" \
    --as counsellor.key --ledger "$SCHOOL"
say "The counsellor approving it without an emergency contact: refused."
run contract call "$CHAN" withdraw --args "{}" --as desk.key --ledger "$SCHOOL" > /dev/null
CHAN_FORM="$(form 2 "student=Chan Wing" student_number=2025-0077 class_name=S4A "address=Flat 3" \
    "guardian=Chan Mei" "guardian_phone=5555 0202" "reason=closer to the family shop" \
    "emergency_contact=Chan Mei 5555 0202")"
CHAN="$(apply "$V2" "\"details\": \"record $CHAN_FORM\", \"guardian_agrees\": true, \"emergency_contact_given\": true")"
say "Withdrawn, and filled in again with the contact."
# Steps out of turn, and an office taking another's step, are refused.
refused turn.txt 'security_registers' contract call "$CHAN" security_registers --args "{}" \
    --as security.key --ledger "$SCHOOL"
say "Security before the others: refused."
refused other.txt 'delegation' contract call "$CHAN" counsellor_approves --args "{}" \
    --as dormitory.key --ledger "$SCHOOL"
say "The dormitory taking the counsellor's step: refused (not its delegation)."
run contract call "$CHAN" counsellor_approves --args "{}" --as counsellor.key \
    --ledger "$SCHOOL" > /dev/null
run contract call "$CHAN" send_back \
    --args '{"what": "the address needs the building and the district"}' \
    --as office.key --ledger "$SCHOOL" > back.txt
check back.txt 'status: returned'
say "The office sends it back: the address needs the building and the district."
FIXED_FORM="$(form 2 "student=Chan Wing" student_number=2025-0077 class_name=S4A \
    "address=Flat 3, 8 Sea View Building, Sha Tin" "guardian=Chan Mei" "guardian_phone=5555 0202" \
    "reason=closer to the family shop" "emergency_contact=Chan Mei 5555 0202")"
run contract call "$CHAN" correct \
    --args "{\"new_details\": \"record $FIXED_FORM\", \"guardian_signed\": true, \"contact_given\": true}" \
    --as desk.key --ledger "$SCHOOL" > /dev/null
run contract call "$CHAN" resubmit --args "{}" --as desk.key --ledger "$SCHOOL" > /dev/null
for who_step in counsellor:counsellor_approves office:office_approves; do
    run contract call "$CHAN" "${who_step#*:}" --args "{}" --as "${who_step%%:*}.key" \
        --ledger "$SCHOOL" > step.txt
done
check step.txt 'status: office_approved'
say "Corrected, resubmitted, and approved by the counsellor and the office again."

step "8. Every application, on its own form"
run contract instances --ledger "$SCHOOL" | indent

step "9. Anyone verifies Li Ming's application offline"
run contract evidence "$LI" --log-key school-log.key --out li-ming.cbor --ledger "$SCHOOL" \
    > /dev/null
run contract verify li-ming.cbor --ledger-id "$SCHOOL_ID" --deploy-out contract.boc > verify.txt
run bo rebuild contract.boc >> verify.txt
check verify.txt 'rebuilds'
check verify.txt 'security_registers'
indent < verify.txt
say "Which form, each step and who took it, and when: checked against the school's"
say "ledger id alone, the rules rebuilt from their source. Nothing personal is in it."

step "10. Security sees only the name and class from Li Ming's form"
run export "$LI_FORM" --log-key school-log.key --disclose student,class_name --out pass.cbor \
    --ledger "$SCHOOL" > /dev/null
run verify pass.cbor --ledger-id "$SCHOOL_ID" > pass.txt
check pass.txt 'Li Ming'
check pass.txt 'S5B'
if grep -F 'Hill Road' pass.txt > /dev/null; then
    echo "the address was disclosed" >&2
    exit 1
fi
indent < pass.txt
say "The address, the guardian, and the reason stay sealed."

step "11. A printed copy of the old blank form, checked by anyone"
run export "$BLANK1" --log-key school-log.key --out old-form.cbor --ledger "$SCHOOL" > /dev/null
run verify old-form.cbor --ledger-id "$SCHOOL_ID" > old-form.txt
check old-form.txt "Superseded   by a newer version, id ${BLANK2:0:12}"
grep -F -e 'Record' -e 'Superseded' -e 'superseded by' old-form.txt | indent
say "The old form is genuine, and says a newer version replaced it: take that one."
if [ "$KEEP" = 1 ]; then
    say ""
    say "The ledger is in $SCHOOL: kanhe-console run --ledger $SCHOOL"
fi
echo
echo "day student: all steps done"
