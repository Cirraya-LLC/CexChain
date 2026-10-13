// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The runtime's arithmetic: checked 64-bit operations, a 128-bit multiply
// and divide with rounding (U5), civil dates at a fixed offset (U6), and
// bytewise comparison of texts.

#include <cstdint>
#include <limits>

#include <cexchain/bo/runtime.hpp>
#include <cexchain/bo/wasm.hpp>

#include "runtime_parts.hpp"

namespace cexchain::bo::runtime::detail {

namespace {

using enum wasm::Op;
using wasm::Label;
using wasm::Local;
constexpr auto I32 = wasm::ValType::i32;
constexpr auto I64 = wasm::ValType::i64;

constexpr std::int64_t int64_min = std::numeric_limits<std::int64_t>::min();
constexpr std::int64_t low32 = 0xFFFF'FFFF;
constexpr std::int64_t base32 = 0x1'0000'0000;

constexpr std::int64_t day_ms = 86'400'000;
/// Days from 1970-01-01 to 0001-01-01, and to 10000-01-01.
constexpr std::int64_t first_day = -719'162;
constexpr std::int64_t last_day_after = 2'932'897;
constexpr std::int64_t first_local = first_day * day_ms;
constexpr std::int64_t last_local = last_day_after * day_ms - 1;

/// Pushes |v| as an unsigned 64-bit value (|INT64_MIN| is 2^63).
void magnitude(FunctionBuilder& b, const Local v) {
    b.i64(0).get(v).op(i64_sub).get(v).get(v).i64(0).op(i64_lt_s).op(select);
}

/// Aborts with bo:date unless the offset is within a day either way.
void check_offset(Runtime& rt, FunctionBuilder& b, const Local offset) {
    b.get(offset).i64(day_ms).op(i64_add).i64(2 * day_ms).op(i64_gt_u);
    fail_if(rt, b, Reason::date);
}

/// One quotient digit of the 128-by-64 division (Hacker's Delight, divlu):
/// while q >= 2^32 or q * vn0 > (rhat << 32 | un), take one off q and add
/// vn1 to rhat, as long as rhat stays below 2^32.
void correct_digit(FunctionBuilder& b, const Local q, const Local rhat, const Local vn1,
                   const Local vn0, const Local un) {
    const Label again = b.loop();
    b.get(q).i64(base32).op(i64_ge_u);
    const Label too_big = b.if_(I32);
    b.i32(1);
    b.else_(too_big);
    b.get(q).get(vn0).op(i64_mul);
    b.get(rhat).i64(32).op(i64_shl).get(un).op(i64_or);
    b.op(i64_gt_u);
    b.end(too_big);
    const Label adjust = b.if_();
    b.get(q).i64(1).op(i64_sub).set(q);
    b.get(rhat).get(vn1).op(i64_add).tee(rhat).i64(base32).op(i64_lt_u).br_if(again);
    b.end(adjust);
    b.end(again);
}

} // namespace

void define_add(Runtime& rt, FunctionBuilder& b) {
    const Local a = b.param(0);
    const Local c = b.param(1);
    const Local r = b.local(I64);
    b.get(a).get(c).op(i64_add).set(r);
    // Overflow: both operands' signs differ from the result's.
    b.get(a).get(r).op(i64_xor).get(c).get(r).op(i64_xor).op(i64_and).i64(0).op(i64_lt_s);
    fail_if(rt, b, Reason::overflow);
    b.get(r);
}

void define_sub(Runtime& rt, FunctionBuilder& b) {
    const Local a = b.param(0);
    const Local c = b.param(1);
    const Local r = b.local(I64);
    b.get(a).get(c).op(i64_sub).set(r);
    // Overflow: the operands' signs differ, and the result's differs from a's.
    b.get(a).get(c).op(i64_xor).get(a).get(r).op(i64_xor).op(i64_and).i64(0).op(i64_lt_s);
    fail_if(rt, b, Reason::overflow);
    b.get(r);
}

void define_mul(Runtime& rt, FunctionBuilder& b) {
    const Local a = b.param(0);
    const Local c = b.param(1);
    const Local r = b.local(I64);
    b.get(a).op(i64_eqz);
    {
        const Label zero = b.if_();
        b.i64(0).return_();
        b.end(zero);
    }
    b.get(a).i64(-1).op(i64_eq);
    {
        const Label minus_one = b.if_();
        b.get(c).i64(int64_min).op(i64_eq);
        fail_if(rt, b, Reason::overflow);
        b.i64(0).get(c).op(i64_sub).return_();
        b.end(minus_one);
    }
    // With a neither 0 nor -1, r / a gives back c exactly when a * c fits.
    b.get(a).get(c).op(i64_mul).set(r);
    b.get(r).get(a).op(i64_div_s).get(c).op(i64_ne);
    fail_if(rt, b, Reason::overflow);
    b.get(r);
}

void define_neg(Runtime& rt, FunctionBuilder& b) {
    const Local a = b.param(0);
    b.get(a).i64(int64_min).op(i64_eq);
    fail_if(rt, b, Reason::overflow);
    b.i64(0).get(a).op(i64_sub);
}

void define_muldiv(Runtime& rt, FunctionBuilder& b) {
    const Local a = b.param(0);
    const Local c = b.param(1);
    const Local d = b.param(2);
    const Local mode = b.param(3);
    const Local negative = b.local(I32);
    const Local ua = b.local(I64);
    const Local uc = b.local(I64);
    const Local ud = b.local(I64);
    const Local a0 = b.local(I64);
    const Local a1 = b.local(I64);
    const Local c0 = b.local(I64);
    const Local c1 = b.local(I64);
    const Local p00 = b.local(I64);
    const Local p01 = b.local(I64);
    const Local p10 = b.local(I64);
    const Local mid = b.local(I64);
    const Local hi = b.local(I64);
    const Local lo = b.local(I64);
    const Local q = b.local(I64);
    const Local r = b.local(I64);
    const Local rest = b.local(I64);

    b.get(d).op(i64_eqz);
    fail_if(rt, b, Reason::division_by_zero);
    b.get(a).i64(0).op(i64_lt_s).get(c).i64(0).op(i64_lt_s).op(i32_xor);
    b.get(d).i64(0).op(i64_lt_s).op(i32_xor).set(negative);
    magnitude(b, a);
    b.set(ua);
    magnitude(b, c);
    b.set(uc);
    magnitude(b, d);
    b.set(ud);

    // The 128-bit product (hi, lo) of ua and uc, from 32-bit halves.
    b.get(ua).i64(low32).op(i64_and).set(a0).get(ua).i64(32).op(i64_shr_u).set(a1);
    b.get(uc).i64(low32).op(i64_and).set(c0).get(uc).i64(32).op(i64_shr_u).set(c1);
    b.get(a0).get(c0).op(i64_mul).set(p00);
    b.get(a0).get(c1).op(i64_mul).set(p01);
    b.get(a1).get(c0).op(i64_mul).set(p10);
    b.get(p00).i64(32).op(i64_shr_u).get(p01).i64(low32).op(i64_and).op(i64_add);
    b.get(p10).i64(low32).op(i64_and).op(i64_add).set(mid);
    b.get(mid).i64(32).op(i64_shl).get(p00).i64(low32).op(i64_and).op(i64_or).set(lo);
    b.get(a1).get(c1).op(i64_mul).get(p01).i64(32).op(i64_shr_u).op(i64_add);
    b.get(p10).i64(32).op(i64_shr_u).op(i64_add).get(mid).i64(32).op(i64_shr_u).op(i64_add);
    b.set(hi);

    // The quotient and remainder, in 64 bits when the product fits.
    b.get(hi).op(i64_eqz);
    const Label fits = b.if_();
    b.get(lo).get(ud).op(i64_div_u).set(q);
    b.get(lo).get(ud).op(i64_rem_u).set(r);
    b.else_(fits);
    b.get(hi).get(ud).op(i64_ge_u);
    fail_if(rt, b, Reason::overflow);
    b.get(hi).get(lo).get(ud).call(rt.get(Routine::udiv128)).set(r).set(q);
    b.end(fits);

    // Rounding the magnitude: up when the remainder is past half the
    // divisor, or at half unless rounding down, or half even and q is even.
    const Label rounded = b.block();
    b.get(mode).u32(static_cast<std::uint32_t>(Rounding::down)).op(i32_eq).br_if(rounded);
    b.get(r).op(i64_eqz).br_if(rounded);
    b.get(ud).get(r).op(i64_sub).set(rest);
    b.get(r).get(rest).op(i64_lt_u).br_if(rounded);
    b.get(r).get(rest).op(i64_eq);
    b.get(mode).u32(static_cast<std::uint32_t>(Rounding::half_even)).op(i32_eq).op(i32_and);
    {
        const Label tie = b.if_();
        b.get(q).i64(1).op(i64_and).op(i64_eqz).br_if(rounded);
        b.end(tie);
    }
    b.get(q).i64(1).op(i64_add).tee(q).op(i64_eqz);
    fail_if(rt, b, Reason::overflow);
    b.end(rounded);

    // The sign, within range: at most 2^63 below zero, 2^63 - 1 above.
    b.get(negative);
    const Label sign = b.if_(I64);
    b.get(q).i64(int64_min).op(i64_gt_u);
    fail_if(rt, b, Reason::overflow);
    b.i64(0).get(q).op(i64_sub);
    b.else_(sign);
    b.get(q).i64(0).op(i64_lt_s);
    fail_if(rt, b, Reason::overflow);
    b.get(q);
    b.end(sign);
}

void define_udiv128(Runtime&, FunctionBuilder& b) {
    // Hacker's Delight (2nd edition), figure 9-3, divlu, in 64-bit words:
    // normalize the divisor, then two 32-bit quotient digits.
    const Local hi = b.param(0);
    const Local lo = b.param(1);
    const Local v = b.param(2);
    const Local s = b.local(I64);
    const Local vn1 = b.local(I64);
    const Local vn0 = b.local(I64);
    const Local un32 = b.local(I64);
    const Local un10 = b.local(I64);
    const Local un1 = b.local(I64);
    const Local un0 = b.local(I64);
    const Local q1 = b.local(I64);
    const Local q0 = b.local(I64);
    const Local rhat = b.local(I64);
    const Local un21 = b.local(I64);

    b.get(v).op(i64_clz).set(s);
    b.get(v).get(s).op(i64_shl).set(v);
    b.get(v).i64(32).op(i64_shr_u).set(vn1);
    b.get(v).i64(low32).op(i64_and).set(vn0);
    // un32 = hi << s | lo >> (64 - s), the second part dropped when s is 0
    // (WebAssembly takes shift counts modulo 64).
    b.get(hi).get(s).op(i64_shl);
    b.get(lo).i64(64).get(s).op(i64_sub).op(i64_shr_u);
    b.i64(0).get(s).op(i64_sub).i64(63).op(i64_shr_s).op(i64_and);
    b.op(i64_or).set(un32);
    b.get(lo).get(s).op(i64_shl).set(un10);
    b.get(un10).i64(32).op(i64_shr_u).set(un1);
    b.get(un10).i64(low32).op(i64_and).set(un0);

    b.get(un32).get(vn1).op(i64_div_u).set(q1);
    b.get(un32).get(q1).get(vn1).op(i64_mul).op(i64_sub).set(rhat);
    correct_digit(b, q1, rhat, vn1, vn0, un1);
    b.get(un32).i64(32).op(i64_shl).get(un1).op(i64_or).get(q1).get(v).op(i64_mul).op(i64_sub);
    b.set(un21);

    b.get(un21).get(vn1).op(i64_div_u).set(q0);
    b.get(un21).get(q0).get(vn1).op(i64_mul).op(i64_sub).set(rhat);
    correct_digit(b, q0, rhat, vn1, vn0, un0);

    b.get(q1).i64(32).op(i64_shl).get(q0).op(i64_or);
    b.get(un21).i64(32).op(i64_shl).get(un0).op(i64_or).get(q0).get(v).op(i64_mul).op(i64_sub);
    b.get(s).op(i64_shr_u);
}

void define_days_from_civil(Runtime&, FunctionBuilder& b) {
    // Howard Hinnant's days_from_civil.
    const Local y = b.param(0);
    const Local m = b.param(1);
    const Local d = b.param(2);
    const Local era = b.local(I64);
    const Local yoe = b.local(I64);
    const Local mp = b.local(I64);
    const Local doe = b.local(I64);
    b.get(y).get(m).i64(2).op(i64_le_s).op(i64_extend_i32_u).op(i64_sub).set(y);
    b.get(y).get(y).i64(399).op(i64_sub).get(y).i64(0).op(i64_ge_s).op(select);
    b.i64(400).op(i64_div_s).set(era);
    b.get(y).get(era).i64(400).op(i64_mul).op(i64_sub).set(yoe);
    b.get(m).i64(3).op(i64_sub).get(m).i64(9).op(i64_add).get(m).i64(2).op(i64_gt_s).op(select);
    b.set(mp);
    // doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * mp + 2) / 5 + d - 1
    b.get(yoe).i64(365).op(i64_mul).get(yoe).i64(4).op(i64_div_u).op(i64_add);
    b.get(yoe).i64(100).op(i64_div_u).op(i64_sub);
    b.get(mp).i64(153).op(i64_mul).i64(2).op(i64_add).i64(5).op(i64_div_u).op(i64_add);
    b.get(d).op(i64_add).i64(1).op(i64_sub).set(doe);
    b.get(era).i64(146'097).op(i64_mul).get(doe).op(i64_add).i64(719'468).op(i64_sub);
}

void define_civil_from_days(Runtime&, FunctionBuilder& b) {
    // Howard Hinnant's civil_from_days.
    const Local z = b.param(0);
    const Local era = b.local(I64);
    const Local doe = b.local(I64);
    const Local yoe = b.local(I64);
    const Local doy = b.local(I64);
    const Local mp = b.local(I64);
    const Local d = b.local(I64);
    const Local m = b.local(I64);
    b.get(z).i64(719'468).op(i64_add).set(z);
    b.get(z).get(z).i64(146'096).op(i64_sub).get(z).i64(0).op(i64_ge_s).op(select);
    b.i64(146'097).op(i64_div_s).set(era);
    b.get(z).get(era).i64(146'097).op(i64_mul).op(i64_sub).set(doe);
    // yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
    b.get(doe).get(doe).i64(1460).op(i64_div_u).op(i64_sub);
    b.get(doe).i64(36'524).op(i64_div_u).op(i64_add);
    b.get(doe).i64(146'096).op(i64_div_u).op(i64_sub).i64(365).op(i64_div_u).set(yoe);
    // doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
    b.get(doe).get(yoe).i64(365).op(i64_mul).get(yoe).i64(4).op(i64_div_u).op(i64_add);
    b.get(yoe).i64(100).op(i64_div_u).op(i64_sub).op(i64_sub).set(doy);
    b.get(doy).i64(5).op(i64_mul).i64(2).op(i64_add).i64(153).op(i64_div_u).set(mp);
    b.get(doy).get(mp).i64(153).op(i64_mul).i64(2).op(i64_add).i64(5).op(i64_div_u);
    b.op(i64_sub).i64(1).op(i64_add).set(d);
    b.get(mp).i64(3).op(i64_add).get(mp).i64(9).op(i64_sub).get(mp).i64(10).op(i64_lt_u);
    b.op(select).set(m);
    b.get(yoe).get(era).i64(400).op(i64_mul).op(i64_add);
    b.get(m).i64(2).op(i64_le_u).op(i64_extend_i32_u).op(i64_add);
    b.get(m).get(d);
}

void define_days_in_month(Runtime&, FunctionBuilder& b) {
    const Local y = b.param(0);
    const Local m = b.param(1);
    b.get(m).i64(2).op(i64_eq);
    const Label february = b.if_(I64);
    // 28, plus one in a leap year.
    b.i64(28);
    b.get(y).i64(4).op(i64_rem_s).op(i64_eqz);
    b.get(y).i64(100).op(i64_rem_s).op(i64_eqz).op(i32_eqz).op(i32_and);
    b.get(y).i64(400).op(i64_rem_s).op(i64_eqz).op(i32_or);
    b.op(i64_extend_i32_u).op(i64_add);
    b.else_(february);
    // 31 for January, March, May, July, August, October, December.
    b.i64(30).get(m).get(m).i64(3).op(i64_shr_u).op(i64_add).i64(1).op(i64_and).op(i64_add);
    b.end(february);
}

void define_local_days(Runtime& rt, FunctionBuilder& b) {
    const Local t = b.param(0);
    const Local offset = b.param(1);
    const Local local = b.local(I64);
    check_offset(rt, b, offset);
    // Within a day of the range, a sum that wraps lands far outside it.
    b.get(t).get(offset).op(i64_add).set(local);
    b.get(local).i64(first_local).op(i64_lt_s);
    fail_if(rt, b, Reason::date);
    b.get(local).i64(last_local).op(i64_gt_s);
    fail_if(rt, b, Reason::date);
    // Floor division from the first day, which is a whole number of days.
    b.get(local).i64(first_local).op(i64_sub).tee(local).i64(day_ms).op(i64_div_u);
    b.i64(first_day).op(i64_add);
    b.get(local).i64(day_ms).op(i64_rem_u);
}

void define_add_months(Runtime& rt, FunctionBuilder& b) {
    const Local t = b.param(0);
    const Local months = b.param(1);
    const Local offset = b.param(2);
    const Local days = b.local(I64);
    const Local ms = b.local(I64);
    const Local y = b.local(I64);
    const Local m = b.local(I64);
    const Local d = b.local(I64);
    const Local total = b.local(I64);
    const Local length = b.local(I64);
    b.get(t).get(offset).call(rt.get(Routine::local_days)).set(ms).set(days);
    b.get(days).call(rt.get(Routine::civil_from_days)).set(d).set(m).set(y);
    // At most 10,000 years either way, so the months below cannot overflow.
    b.get(months).i64(120'000).op(i64_add).i64(240'000).op(i64_gt_u);
    fail_if(rt, b, Reason::date);
    // total = y * 12 + m - 1 + months, in years 1 to 9999.
    b.get(y).i64(12).op(i64_mul).get(m).op(i64_add).i64(1).op(i64_sub).get(months).op(i64_add);
    b.tee(total).i64(12).op(i64_lt_s);
    fail_if(rt, b, Reason::date);
    b.get(total).i64(120'000).op(i64_ge_s);
    fail_if(rt, b, Reason::date);
    b.get(total).i64(12).op(i64_div_u).set(y);
    b.get(total).i64(12).op(i64_rem_u).i64(1).op(i64_add).set(m);
    // The day, clamped to the month's length.
    b.get(y).get(m).call(rt.get(Routine::days_in_month)).set(length);
    b.get(y).get(m).get(d).get(length).get(d).get(length).op(i64_lt_s).op(select);
    b.call(rt.get(Routine::days_from_civil));
    b.i64(day_ms).op(i64_mul).get(ms).op(i64_add).get(offset).op(i64_sub);
}

void define_date_parts(Runtime& rt, FunctionBuilder& b) {
    b.get(b.param(0)).get(b.param(1)).call(rt.get(Routine::local_days)).op(drop);
    b.call(rt.get(Routine::civil_from_days));
}

void define_date_from_parts(Runtime& rt, FunctionBuilder& b) {
    const Local y = b.param(0);
    const Local m = b.param(1);
    const Local d = b.param(2);
    const Local offset = b.param(3);
    check_offset(rt, b, offset);
    b.get(y).i64(1).op(i64_sub).i64(9999).op(i64_ge_u);
    fail_if(rt, b, Reason::date);
    b.get(m).i64(1).op(i64_sub).i64(12).op(i64_ge_u);
    fail_if(rt, b, Reason::date);
    b.get(d).i64(1).op(i64_lt_s);
    fail_if(rt, b, Reason::date);
    b.get(d).get(y).get(m).call(rt.get(Routine::days_in_month)).op(i64_gt_s);
    fail_if(rt, b, Reason::date);
    b.get(y).get(m).get(d).call(rt.get(Routine::days_from_civil));
    b.i64(day_ms).op(i64_mul).get(offset).op(i64_sub);
}

void define_bytes_cmp(Runtime&, FunctionBuilder& b) {
    const Local p = b.param(0);
    const Local n = b.param(1);
    const Local q = b.param(2);
    const Local m = b.param(3);
    const Local k = b.local(I32);
    const Local i = b.local(I32);
    const Local x = b.local(I32);
    const Local y = b.local(I32);
    b.get(n).get(m).get(n).get(m).op(i32_lt_u).op(select).set(k);
    // Eight bytes at a time while they are equal; the bytes then find the
    // first difference.
    {
        const Label tail = b.block();
        const Label chunk = b.loop();
        b.get(k).get(i).op(i32_sub).i32(8).op(i32_lt_u).br_if(tail);
        b.get(p).get(i).op(i32_add).load(i64_load);
        b.get(q).get(i).op(i32_add).load(i64_load).op(i64_ne).br_if(tail);
        b.get(i).i32(8).op(i32_add).set(i).br(chunk);
        b.end(chunk);
        b.end(tail);
    }
    {
        const Label equal = b.block();
        const Label next = b.loop();
        b.get(i).get(k).op(i32_eq).br_if(equal);
        b.get(p).get(i).op(i32_add).load(i32_load8_u).tee(x);
        b.get(q).get(i).op(i32_add).load(i32_load8_u).tee(y).op(i32_ne);
        const Label differ = b.if_();
        b.i32(-1).i32(1).get(x).get(y).op(i32_lt_u).op(select).return_();
        b.end(differ);
        b.get(i).i32(1).op(i32_add).set(i).br(next);
        b.end(next);
        b.end(equal);
    }
    // One is a prefix of the other: the shorter comes first.
    b.get(n).get(m).op(i32_gt_u).get(n).get(m).op(i32_lt_u).op(i32_sub);
}

void define_bytes_eq(Runtime& rt, FunctionBuilder& b) {
    const Local n = b.param(1);
    const Local m = b.param(3);
    b.get(n).get(m).op(i32_ne);
    const Label lengths = b.if_();
    b.i32(0).return_();
    b.end(lengths);
    b.get(b.param(0)).get(n).get(b.param(2)).get(m).call(rt.get(Routine::bytes_cmp)).op(i32_eqz);
}

} // namespace cexchain::bo::runtime::detail
