//! Tone generation: one or two sine waves (dial and ring tones, DTMF
//! digits) at a level in dBm0, phase-continuous from frame to frame.
//!
//! A direct digital synthesiser: each component has a 32-bit phase
//! accumulator advanced by f · 2³² / rate per sample, read through a
//! 1024-entry sine table (computed at compile time) with linear
//! interpolation, which keeps spurious products below −100 dBc. The
//! frequency resolution is rate / 2³² (under 12 µHz at 48 kHz).
//!
//! Levels follow G.711: a sine of +3.17 dBm0 is full scale, so 0 dBm0 is a
//! peak of [`DBM0_PEAK`].

use super::Rate;
use super::gain::db_to_q16;

/// Peak amplitude of a 0 dBm0 sine (32768 / 10^(3.17/20)).
pub const DBM0_PEAK: i32 = 22_749;
/// The lowest level, in dBm0; lower levels are clamped to it.
pub const LEVEL_MIN: i32 = -60;
/// The highest level, in dBm0 (near full scale); higher levels are
/// clamped to it.
pub const LEVEL_MAX: i32 = 3;

/// Table size (a power of two): phase bits 31..22 index it.
const TABLE_BITS: u32 = 10;
const TABLE_LEN: usize = 1 << TABLE_BITS;

/// One cycle of sine in Q15 (peak 32767), plus the first entry again so
/// interpolation never wraps.
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]
const fn sine_table() -> [i16; TABLE_LEN + 1] {
    let mut t = [0i16; TABLE_LEN + 1];
    let mut i = 0;
    while i <= TABLE_LEN {
        let x = core::f64::consts::TAU * i as f64 / TABLE_LEN as f64;
        t[i] = super::round(super::sin(x) * 32767.0) as i16;
        i += 1;
    }
    t
}

static SINE: [i16; TABLE_LEN + 1] = sine_table();

/// sin(2π · phase / 2³²) in Q15.
#[inline]
fn sine(phase: u32) -> i32 {
    let i = (phase >> (32 - TABLE_BITS)) as usize;
    let frac = i32::try_from((phase >> (16 - TABLE_BITS)) & 0xffff).unwrap_or(0);
    let a = i32::from(SINE.get(i).copied().unwrap_or(0));
    let b = i32::from(SINE.get(i.wrapping_add(1)).copied().unwrap_or(0));
    // |b − a| ≤ 202, frac < 2^16.
    a.wrapping_add(b.wrapping_sub(a).wrapping_mul(frac) >> 16)
}

/// Why a tone was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToneError {
    /// A frequency at or above half the sample rate.
    AboveNyquist,
}

/// A one- or two-frequency tone generator.
#[derive(Debug, Clone, Copy)]
pub struct Tone {
    inc: [u32; 2],
    phase: [u32; 2],
    /// Peak amplitude of each component (0 for an absent one).
    amp: [i32; 2],
}

impl Tone {
    /// A single sine of `freq` Hz at `level` dBm0 (clamped to
    /// [`LEVEL_MIN`]..=[`LEVEL_MAX`]).
    ///
    /// # Errors
    ///
    /// [`ToneError::AboveNyquist`] if `freq` ≥ rate / 2.
    pub fn single(rate: Rate, freq: u32, level: i32) -> Result<Tone, ToneError> {
        Ok(Tone {
            inc: [increment(rate, freq)?, 0],
            phase: [0; 2],
            amp: [amplitude(level), 0],
        })
    }

    /// The sum of two sines (`f1` Hz at `level1` dBm0, `f2` Hz at
    /// `level2` dBm0), as DTMF and most call-progress tones are; the sum
    /// saturates to `i16`.
    ///
    /// # Errors
    ///
    /// [`ToneError::AboveNyquist`] if either frequency is ≥ rate / 2.
    pub fn dual(rate: Rate, f1: u32, level1: i32, f2: u32, level2: i32) -> Result<Tone, ToneError> {
        Ok(Tone {
            inc: [increment(rate, f1)?, increment(rate, f2)?],
            phase: [0; 2],
            amp: [amplitude(level1), amplitude(level2)],
        })
    }

    /// Back to phase 0 (a new burst).
    pub fn reset(&mut self) {
        self.phase = [0; 2];
    }

    /// Write the next `out.len()` samples (continuing from the previous
    /// call).
    pub fn fill(&mut self, out: &mut [i16]) {
        for o in out {
            let mut v = 0i32;
            for ((p, &inc), &amp) in self.phase.iter_mut().zip(&self.inc).zip(&self.amp) {
                // |sine · amp| < 2^30.
                v = v.wrapping_add(sine(*p).wrapping_mul(amp) >> 15);
                *p = p.wrapping_add(inc);
            }
            *o = super::sat16(i64::from(v));
        }
    }
}

/// Phase increment per sample for `freq` Hz.
fn increment(rate: Rate, freq: u32) -> Result<u32, ToneError> {
    let hz = rate.hz();
    if u64::from(freq).saturating_mul(2) >= u64::from(hz) {
        return Err(ToneError::AboveNyquist);
    }
    // freq < hz / 2: the quotient is below 2^31.
    let inc = (u64::from(freq) << 32)
        .checked_div(u64::from(hz))
        .unwrap_or(0);
    u32::try_from(inc).map_err(|_| ToneError::AboveNyquist)
}

/// Peak amplitude for `level` dBm0.
fn amplitude(level: i32) -> i32 {
    let g = i64::from(db_to_q16(level.clamp(LEVEL_MIN, LEVEL_MAX)));
    // ≤ 22749 · 1.42.
    i32::try_from(i64::from(DBM0_PEAK).wrapping_mul(g).wrapping_add(1 << 15) >> 16).unwrap_or(0)
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
mod tests {
    extern crate std;
    use super::super::testutil::goertzel;
    use super::*;
    use crate::dtmf_inband;

    #[test]
    fn table_against_std() {
        for (i, &v) in SINE.iter().enumerate() {
            let want = (std::f64::consts::TAU * i as f64 / 1024.0).sin() * 32767.0;
            assert!((f64::from(v) - want).abs() <= 0.5, "{i}");
        }
        // Interpolated values between entries.
        for k in 0..100_000u32 {
            let ph = k.wrapping_mul(42_949_673);
            let want = (std::f64::consts::TAU * f64::from(ph) / 4_294_967_296.0).sin() * 32767.0;
            assert!((f64::from(sine(ph)) - want).abs() <= 2.0, "{ph}");
        }
    }

    #[test]
    fn frequency_and_level() {
        let mut t = Tone::single(Rate::Hz8000, 1000, 0).unwrap();
        let mut x = [0i16; 8000];
        t.fill(&mut x);
        let a = goertzel(&x, 1000.0, 8000.0).sqrt();
        assert!((a - f64::from(DBM0_PEAK)).abs() < 20.0, "{a}");
        assert!(goertzel(&x, 1100.0, 8000.0).sqrt() < 1.0);
        // −20 dB is a tenth.
        let mut t = Tone::single(Rate::Hz48000, 440, -20).unwrap();
        let mut y = std::vec![0i16; 48000];
        t.fill(&mut y);
        let a = goertzel(&y, 440.0, 48000.0).sqrt();
        assert!((a - 2274.9).abs() < 5.0, "{a}");
    }

    #[test]
    fn phase_continuous_across_frames() {
        let mut whole = Tone::dual(Rate::Hz16000, 350, -13, 440, -13).unwrap();
        let mut parts = whole;
        let mut a = [0i16; 1600];
        whole.fill(&mut a);
        let mut b = [0i16; 1600];
        for c in b.chunks_mut(7) {
            parts.fill(c);
        }
        assert_eq!(a, b);
        parts.reset();
        let mut c = [0i16; 1600];
        parts.fill(&mut c);
        assert_eq!(a, c);
    }

    #[test]
    fn dtmf_digits_are_detected() {
        for (row, &fr) in dtmf_inband::ROWS.iter().enumerate() {
            for (col, &fc) in dtmf_inband::COLS.iter().enumerate() {
                let mut t = Tone::dual(Rate::Hz8000, fr, -7, fc, -5).unwrap();
                let mut x = [0i16; dtmf_inband::FRAME];
                t.fill(&mut x);
                assert!(dtmf_inband::key_of(&x).is_some(), "{row},{col}");
            }
        }
    }

    #[test]
    fn boundaries() {
        assert_eq!(
            Tone::single(Rate::Hz8000, 4000, 0).unwrap_err(),
            ToneError::AboveNyquist
        );
        assert_eq!(
            Tone::dual(Rate::Hz8000, 400, 0, u32::MAX, 0).unwrap_err(),
            ToneError::AboveNyquist
        );
        assert!(Tone::single(Rate::Hz8000, 3999, 0).is_ok());
        // Clamped levels; two full-level components saturate, never wrap.
        let mut t = Tone::dual(Rate::Hz8000, 1000, i32::MAX, 1000, i32::MAX).unwrap();
        let mut x = [0i16; 160];
        t.fill(&mut x);
        assert!(x.contains(&i16::MAX) && x.contains(&i16::MIN));
        let mut q = Tone::single(Rate::Hz8000, 1000, i32::MIN).unwrap();
        q.fill(&mut x);
        assert!(x.iter().all(|&v| v.abs() <= 23));
        q.fill(&mut []);
        // 0 Hz is silence.
        let mut z = Tone::single(Rate::Hz8000, 0, 0).unwrap();
        z.fill(&mut x);
        assert_eq!(x, [0; 160]);
    }
}
