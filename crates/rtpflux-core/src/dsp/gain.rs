//! Gain and peak limiting.
//!
//! Gains are fixed-point multipliers: Q8 (256 = unity, 0 dB) for coarse
//! per-participant volume, Q16 (65536 = unity) from the dB table for
//! −60..=+24 dB in 1 dB steps. Every result saturates to `i16`: a gain
//! never wraps a sample around.
//!
//! [`Limiter`] brings a wider signal (the `i32` sum of several talkers)
//! back into `i16` without hard clipping: a peak envelope follows the
//! signal, and while it is above the threshold the signal is scaled by
//! threshold / envelope.

use super::{Rate, sat16};

/// The lowest gain [`db_to_q16`] gives, in dB.
pub const DB_MIN: i32 = -60;
/// The highest gain [`db_to_q16`] gives, in dB.
pub const DB_MAX: i32 = 24;

/// Unity gain in Q8.
pub const UNITY_Q8: u16 = 256;
/// Unity gain in Q16.
pub const UNITY_Q16: u32 = 65536;

/// Entries of [`DB_Q16`]: one per dB from [`DB_MIN`] to [`DB_MAX`].
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
const DB_STEPS: usize = (DB_MAX - DB_MIN + 1) as usize;

/// 10^(dB/20) in Q16 for dB = −60..=+24, built at compile time by
/// stepping 10^(1/20) from 10^(−3).
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
const fn db_table() -> [u32; DB_STEPS] {
    // 10^(1/20).
    const STEP: f64 = 1.122_018_454_301_963_3;
    let mut t = [0u32; DB_STEPS];
    let mut g = 0.001f64;
    let mut i = 0;
    while i < DB_STEPS {
        t[i] = super::round(g * 65536.0) as u32;
        g *= STEP;
        i += 1;
    }
    t
}

/// 10^(dB/20) in Q16, index 0 being [`DB_MIN`].
static DB_Q16: [u32; DB_STEPS] = db_table();

/// The linear gain of `db` decibels in Q16 (65536 = 0 dB), with `db`
/// clamped to [`DB_MIN`]..=[`DB_MAX`] (−60 dB gives 66, +24 dB 1 038 676).
#[must_use]
pub fn db_to_q16(db: i32) -> u32 {
    let i = db.clamp(DB_MIN, DB_MAX).wrapping_sub(DB_MIN);
    usize::try_from(i)
        .ok()
        .and_then(|i| DB_Q16.get(i))
        .copied()
        .unwrap_or(UNITY_Q16)
}

/// Scale `frame` in place by `gain_q8` / 256, rounding to nearest and
/// saturating to `i16`.
pub fn apply_gain_q8(frame: &mut [i16], gain_q8: u16) {
    if gain_q8 == UNITY_Q8 {
        return;
    }
    let g = i32::from(gain_q8);
    for s in frame {
        // |s·g| < 2^31: no overflow.
        let v = i32::from(*s).wrapping_mul(g).wrapping_add(128) >> 8;
        *s = sat16(i64::from(v));
    }
}

/// Scale `frame` in place by `gain_q16` / 65536 (see [`db_to_q16`]),
/// rounding to nearest and saturating to `i16`.
pub fn apply_gain_q16(frame: &mut [i16], gain_q16: u32) {
    if gain_q16 == UNITY_Q16 {
        return;
    }
    let g = i64::from(gain_q16);
    for s in frame {
        // |s·g| < 2^47: no overflow.
        let v = i64::from(*s).wrapping_mul(g).wrapping_add(1 << 15) >> 16;
        *s = sat16(v);
    }
}

/// Scale `frame` in place by `db` decibels (clamped to −60..=+24).
pub fn apply_gain_db(frame: &mut [i16], db: i32) {
    apply_gain_q16(frame, db_to_q16(db));
}

/// A peak limiter from `i32` to `i16`.
///
/// The envelope follows |x| sample by sample: it rises toward a larger
/// peak with the attack coefficient and decays toward a smaller one with
/// the release coefficient (one-pole, coefficient 1/n for a time constant
/// of n samples). While the envelope is above the threshold, the sample is
/// scaled by threshold / envelope. With an instant attack (the default),
/// the envelope is never below |x|, so the output never exceeds the
/// threshold; with a slower attack, the overshoot of a sudden peak is
/// saturated to `i16`.
#[derive(Debug, Clone, Copy)]
pub struct Limiter {
    /// Peak envelope (≥ 0).
    env: i32,
    /// Output ceiling, > 0.
    threshold: i32,
    /// Attack and release coefficients in Q16 (65536 = follow at once).
    attack_q16: i32,
    release_q16: i32,
}

impl Limiter {
    /// Default ceiling: 32 000 (−0.2 dBFS).
    pub const THRESHOLD: i16 = 32_000;
    /// Default release time, in milliseconds.
    pub const RELEASE_MS: u32 = 50;

    /// A limiter for `rate` with the defaults: ceiling [`Self::THRESHOLD`],
    /// instant attack, release over [`Self::RELEASE_MS`].
    #[must_use]
    pub const fn new(rate: Rate) -> Self {
        Self::with_params(Self::THRESHOLD, 0, rate.samples(Self::RELEASE_MS))
    }

    /// A limiter with ceiling `threshold` (clamped to 1..=32767), and
    /// attack and release time constants in samples (0 or 1: instant).
    #[must_use]
    pub const fn with_params(threshold: i16, attack_samples: u32, release_samples: u32) -> Self {
        let threshold = if threshold < 1 { 1 } else { threshold as i32 };
        Limiter {
            env: 0,
            threshold,
            attack_q16: coef(attack_samples),
            release_q16: coef(release_samples),
        }
    }

    /// The current envelope.
    #[must_use]
    pub const fn envelope(&self) -> i32 {
        self.env
    }

    /// Forget the envelope (a new stream).
    pub fn reset(&mut self) {
        self.env = 0;
    }

    /// Limit `input` into `out`, sample by sample; returns the samples
    /// written: the shorter of the two lengths.
    pub fn process(&mut self, input: &[i32], out: &mut [i16]) -> usize {
        let mut n = 0usize;
        for (&x, o) in input.iter().zip(out.iter_mut()) {
            *o = self.sample(x);
            n = n.wrapping_add(1);
        }
        n
    }

    /// Limit one sample.
    #[inline]
    fn sample(&mut self, x: i32) -> i16 {
        let a = i32::try_from(x.unsigned_abs()).unwrap_or(i32::MAX);
        let env = i64::from(self.env);
        let coef = if a > self.env {
            self.attack_q16
        } else {
            self.release_q16
        };
        // env + (a − env)·coef, all within i64.
        let step = (i64::from(a).wrapping_sub(env)).wrapping_mul(i64::from(coef)) >> 16;
        let mut next = env.wrapping_add(step);
        // Never stall above a falling signal for want of resolution.
        if a < self.env && next == env {
            next = env.wrapping_sub(1);
        }
        self.env = i32::try_from(next.clamp(0, i64::from(i32::MAX))).unwrap_or(i32::MAX);
        if self.env <= self.threshold {
            return sat16(i64::from(x));
        }
        let y = i64::from(x)
            .wrapping_mul(i64::from(self.threshold))
            .checked_div(i64::from(self.env))
            .unwrap_or(0);
        sat16(y)
    }
}

/// One-pole coefficient in Q16 for a time constant of `n` samples.
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
const fn coef(n: u32) -> i32 {
    if n <= 1 {
        65536
    } else {
        // 1/n, at least 1 (n ≥ 2: the quotient is below 2^15).
        match 65536u32.checked_div(n) {
            Some(0) | None => 1,
            Some(c) => c as i32,
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::large_stack_arrays)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn db_table_matches_powers_of_ten() {
        for db in DB_MIN..=DB_MAX {
            let want = 10f64.powf(f64::from(db) / 20.0) * 65536.0;
            let got = f64::from(db_to_q16(db));
            assert!((got - want).abs() <= 1.0, "{db}: {got} vs {want}");
        }
        assert_eq!(db_to_q16(0), UNITY_Q16);
        assert_eq!(db_to_q16(-1000), db_to_q16(DB_MIN));
        assert_eq!(db_to_q16(i32::MAX), db_to_q16(DB_MAX));
        assert_eq!(db_to_q16(i32::MIN), db_to_q16(DB_MIN));
        assert_eq!(db_to_q16(-6), 32_846);
    }

    #[test]
    fn q8_against_reference() {
        let mut x: [i16; 7] = [0, 1, -1, 1000, -1000, i16::MAX, i16::MIN];
        let orig = x;
        for g in [0u16, 1, 128, 255, 256, 257, 512, 1000, u16::MAX] {
            x = orig;
            apply_gain_q8(&mut x, g);
            for (&o, &y) in orig.iter().zip(x.iter()) {
                let r = ((f64::from(o) * f64::from(g) / 256.0) + 0.5).floor();
                let r = r.clamp(-32768.0, 32767.0) as i16;
                assert_eq!(y, r, "{o}·{g}");
            }
        }
        apply_gain_q8(&mut [], 1000);
    }

    #[test]
    fn q16_and_db() {
        let mut x = [10000i16, -10000, i16::MAX, i16::MIN];
        apply_gain_db(&mut x, 0);
        assert_eq!(x, [10000, -10000, i16::MAX, i16::MIN]);
        apply_gain_db(&mut x, -6);
        assert_eq!(x[0], 5012);
        assert_eq!(x[1], -5012);
        let mut y = [20000i16, -20000];
        apply_gain_db(&mut y, 24);
        assert_eq!(y, [i16::MAX, i16::MIN]);
        let mut z = [1000i16];
        apply_gain_q16(&mut z, 0);
        assert_eq!(z, [0]);
        apply_gain_q16(&mut z, u32::MAX);
        assert_eq!(z, [0]);
    }

    #[test]
    fn limiter_passes_quiet_audio_unchanged() {
        let mut l = Limiter::new(Rate::Hz8000);
        let input: std::vec::Vec<i32> = (-200..200).map(|v| v * 80).collect();
        let mut out = [0i16; 400];
        assert_eq!(l.process(&input, &mut out), 400);
        for (&i, &o) in input.iter().zip(out.iter()) {
            assert_eq!(i32::from(o), i);
        }
    }

    #[test]
    fn limiter_bounds_loud_and_extreme_input() {
        let mut l = Limiter::new(Rate::Hz48000);
        let mut out = [0i16; 960];
        let input: std::vec::Vec<i32> = (0..960)
            .map(|i| match i % 4 {
                0 => i32::MAX,
                1 => i32::MIN,
                2 => 64 * 32767,
                _ => -64 * 32768,
            })
            .collect();
        assert_eq!(l.process(&input, &mut out), 960);
        assert!(out.iter().all(|&o| i32::from(o).abs() <= 32_000));
        // Sign preserved.
        assert!(out[0] > 0 && out[1] < 0);
        // Mismatched lengths: the shorter wins.
        assert_eq!(l.process(&input[..10], &mut out), 10);
        assert_eq!(l.process(&input, &mut out[..3]), 3);
        assert_eq!(l.process(&[], &mut out), 0);
    }

    #[test]
    fn limiter_releases_after_a_peak() {
        let mut l = Limiter::new(Rate::Hz8000);
        let mut out = [0i16; 1];
        l.process(&[100_000], &mut out);
        assert_eq!(out[0], 32_000);
        assert_eq!(l.envelope(), 100_000);
        // 1 s of quiet: the envelope falls below the ceiling again.
        let quiet = [1000i32; 8000];
        let mut o = [0i16; 8000];
        l.process(&quiet, &mut o);
        assert!(l.envelope() <= 32_000);
        assert_eq!(*o.last().unwrap(), 1000);
        // Gain reduction right after the peak.
        assert!(o[0] < 1000);
        l.reset();
        assert_eq!(l.envelope(), 0);
    }

    #[test]
    fn slow_attack_overshoot_saturates() {
        let mut l = Limiter::with_params(10_000, 400, 400);
        let mut out = [0i16; 100];
        let input = [1_000_000i32; 100];
        l.process(&input, &mut out);
        assert_eq!(out[0], i16::MAX);
        assert!(out.iter().all(|&o| o > 0));
        let l = Limiter::with_params(-5, 0, 0);
        assert_eq!(l.threshold, 1);
    }
}
