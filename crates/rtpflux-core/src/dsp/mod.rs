//! PCM and DSP kernels for media that is decoded rather than relayed:
//! jitter buffering, loss concealment, gain and limiting, voice activity,
//! resampling, conference mixing and tone generation.
//!
//! Audio is signed 16-bit linear PCM, mono (`i16`), in frames of 10 or
//! 20 ms at 8, 16, 24 or 48 kHz: at most [`MAX_FRAME`] samples. Every
//! structure here has a fixed size (fixed arrays or const generics) and
//! nothing allocates; time is passed in by the caller, never read from a
//! clock, so every kernel is a deterministic function of its inputs.

pub mod gain;
pub mod jitter;
pub mod mix;
pub mod plc;
pub mod resample;
pub mod tone;
pub mod vad;

/// The most samples in one frame: 20 ms at 48 kHz.
pub const MAX_FRAME: usize = 960;

/// A sample rate the kernels support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rate {
    /// 8000 Hz (G.711, narrowband).
    Hz8000,
    /// 16000 Hz (G.722's audio, wideband).
    Hz16000,
    /// 24000 Hz.
    Hz24000,
    /// 48000 Hz (Opus, fullband).
    Hz48000,
}

/// A sample rate that is not one of [`Rate`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateError;

impl Rate {
    /// The rate of `hz` samples per second.
    ///
    /// # Errors
    ///
    /// [`RateError`] for anything but 8000, 16000, 24000 or 48000.
    pub const fn from_hz(hz: u32) -> Result<Rate, RateError> {
        match hz {
            8000 => Ok(Rate::Hz8000),
            16000 => Ok(Rate::Hz16000),
            24000 => Ok(Rate::Hz24000),
            48000 => Ok(Rate::Hz48000),
            _ => Err(RateError),
        }
    }

    /// Samples per second.
    #[must_use]
    pub const fn hz(self) -> u32 {
        match self {
            Rate::Hz8000 => 8000,
            Rate::Hz16000 => 16000,
            Rate::Hz24000 => 24000,
            Rate::Hz48000 => 48000,
        }
    }

    /// Samples per millisecond (8, 16, 24 or 48).
    #[must_use]
    pub const fn per_ms(self) -> u32 {
        match self {
            Rate::Hz8000 => 8,
            Rate::Hz16000 => 16,
            Rate::Hz24000 => 24,
            Rate::Hz48000 => 48,
        }
    }

    /// Samples in `ms` milliseconds (saturating).
    #[must_use]
    pub const fn samples(self, ms: u32) -> u32 {
        ms.saturating_mul(self.per_ms())
    }
}

/// sin(x) for the tables built at compile time (`core` has no `f64::sin`):
/// the argument is reduced to [−π, π] and a Taylor series summed to well
/// below the precision of the Q15 tables it feeds.
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
pub(crate) const fn sin(x: f64) -> f64 {
    const TAU: f64 = core::f64::consts::TAU;
    const PI: f64 = core::f64::consts::PI;
    // Truncation toward zero, then into [−π, π].
    let mut r = x - (x / TAU) as i64 as f64 * TAU;
    if r > PI {
        r -= TAU;
    } else if r < -PI {
        r += TAU;
    }
    let r2 = r * r;
    let mut term = r;
    let mut sum = r;
    let mut k = 1.0;
    while k < 40.0 {
        term = -term * r2 / ((2.0 * k) * (2.0 * k + 1.0));
        sum += term;
        k += 1.0;
    }
    sum
}

/// Round to the nearest integer (halves away from zero).
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn round(x: f64) -> i64 {
    if x >= 0.0 {
        (x + 0.5) as i64
    } else {
        (x - 0.5) as i64
    }
}

/// Clamp to the range of `i16`.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn sat16(v: i64) -> i16 {
    if v > i16::MAX as i64 {
        i16::MAX
    } else if v < i16::MIN as i64 {
        i16::MIN
    } else {
        v as i16
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]
pub(crate) mod testutil {
    extern crate std;

    /// Goertzel power of `x` at `freq` Hz, normalised so a sine of peak
    /// amplitude `a` gives about `a²` (whole number of cycles in `x`).
    pub fn goertzel(x: &[i16], freq: f64, rate: f64) -> f64 {
        let k = 2.0 * (2.0 * std::f64::consts::PI * freq / rate).cos();
        let (mut s1, mut s2) = (0f64, 0f64);
        for &v in x {
            let s = f64::from(v) + k * s1 - s2;
            s2 = s1;
            s1 = s;
        }
        let p = s1 * s1 + s2 * s2 - k * s1 * s2;
        let n = x.len() as f64;
        p * 4.0 / (n * n)
    }

    /// Fill `out` with a sine of peak `amp` at `freq` Hz, starting at
    /// sample `start`.
    pub fn sine(out: &mut [i16], freq: f64, rate: f64, amp: f64, start: usize) {
        for (i, o) in out.iter_mut().enumerate() {
            let t = (start + i) as f64 / rate;
            *o = (amp * (2.0 * std::f64::consts::PI * freq * t).sin()).round() as i16;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn const_sin_matches_std() {
        let mut x = -20.0f64;
        while x < 20.0 {
            assert!((sin(x) - x.sin()).abs() < 1e-12, "{x}");
            x += 0.013;
        }
    }

    #[test]
    fn rates() {
        for hz in [8000, 16000, 24000, 48000] {
            let r = Rate::from_hz(hz).unwrap();
            assert_eq!(r.hz(), hz);
            assert_eq!(r.per_ms() * 1000, hz);
        }
        assert_eq!(Rate::from_hz(44100), Err(RateError));
        assert_eq!(Rate::from_hz(0), Err(RateError));
        assert_eq!(Rate::Hz48000.samples(20) as usize, MAX_FRAME);
        assert_eq!(Rate::Hz8000.samples(u32::MAX), u32::MAX);
    }

    #[test]
    fn saturation() {
        assert_eq!(sat16(40000), i16::MAX);
        assert_eq!(sat16(-40000), i16::MIN);
        assert_eq!(sat16(-5), -5);
        assert_eq!(round(2.5), 3);
        assert_eq!(round(-2.5), -3);
    }
}
