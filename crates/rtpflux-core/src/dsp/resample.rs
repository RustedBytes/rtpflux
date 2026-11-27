//! Rational-ratio resampling among 8000, 16000, 24000 and 48000 Hz.
//!
//! A conversion from `from` to `to` Hz upsamples by L and downsamples by M
//! (L/M = to/from in lowest terms: 2/1, 3/1, 6/1, 3/2 and their inverses),
//! through one low-pass FIR run in polyphase form: each output sample is a
//! dot product of the last T input samples with one of the L phases of
//! the filter, so no zero-stuffed samples are ever computed.
//!
//! # Filter
//!
//! A Kaiser-windowed sinc (β = [`BETA`]) of 32·max(L, M) taps at the
//! upsampled rate (16 zero crossings each side at the lower rate's
//! Nyquist frequency), cut off at [`CUTOFF`] × the lower rate's Nyquist
//! frequency (3600 Hz between 8 and 48 kHz). Measured between 48 and
//! 8 kHz (relative to the lower rate's Nyquist frequency, 4 kHz): flat
//! within 0.01 dB up to 0.75 (3000 Hz), −1.8 dB at 0.85 (3400 Hz), −6 dB
//! at 0.9, −35 dB at 1.0; aliases and images from 1.05 (4200 Hz) up are
//! at least 62 dB down, from 1.12 (4500 Hz) up at least 75 dB. The other
//! pairs scale with their rates. The coefficients are computed at compile
//! time (`const fn`, no floating point at run time) in Q15, and each phase
//! is normalised to sum to exactly 32768, so DC passes with gain 1 at
//! every phase. The delay is (taps − 1) / 2 samples at the upsampled rate,
//! about 2 ms for every pair.
//!
//! The history of the last T − 1 input samples is kept between calls, so
//! a stream converted frame by frame gives exactly the output of the whole
//! stream converted at once.

use super::{MAX_FRAME, Rate, RateError, sat16};

/// Kaiser window parameter.
pub const BETA: f64 = 8.0;
/// Cut-off as a fraction of the lower rate's Nyquist frequency.
pub const CUTOFF: f64 = 0.9;
/// Taps per zero crossing span: the prototype has `ZEROS` × 2 × max(L, M)
/// taps.
const ZEROS: usize = 16;
/// The most taps per phase (48 → 8 kHz: L = 1, 192 taps).
const MAX_TAPS: usize = 2 * ZEROS * 6;

/// sqrt(x) by Newton's method, for the tables (`core` has no `f64::sqrt`).
#[allow(clippy::arithmetic_side_effects)]
const fn sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut g = if x > 1.0 { x } else { 1.0 };
    let mut i = 0;
    while i < 60 {
        g = f64::midpoint(g, x / g);
        i += 1;
    }
    g
}

/// The modified Bessel function I0, by its power series.
const fn bessel_i0(x: f64) -> f64 {
    let h = x / 2.0;
    let mut term = 1.0;
    let mut sum = 1.0;
    let mut k = 1.0;
    while k < 60.0 {
        term = term * h / k * h / k;
        sum += term;
        k += 1.0;
    }
    sum
}

/// The polyphase filter for upsampling by `L` with `T` taps per phase,
/// cut off for a ratio whose larger factor is `d`: phase p, tap m
/// multiplies the input sample T − 1 − m before the newest one.
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names
)]
const fn design<const L: usize, const T: usize>(d: usize) -> [[i32; T]; L] {
    let len = L * T;
    // Cut-off in cycles per upsampled sample.
    let fc = CUTOFF / (2.0 * d as f64);
    let center = (len as f64 - 1.0) / 2.0;
    let i0b = bessel_i0(BETA);
    let mut h = [[0f64; T]; L];
    let mut n = 0;
    while n < len {
        let t = n as f64 - center;
        let x = core::f64::consts::PI * 2.0 * fc * t;
        let sinc = if x.abs() < 1e-12 {
            1.0
        } else {
            super::sin(x) / x
        };
        let r = 2.0 * n as f64 / (len as f64 - 1.0) - 1.0;
        let w = bessel_i0(BETA * sqrt(1.0 - r * r)) / i0b;
        h[n % L][n / L] = 2.0 * fc * sinc * w;
        n += 1;
    }
    let mut out = [[0i32; T]; L];
    let mut p = 0;
    while p < L {
        let mut sum = 0.0;
        let mut k = 0;
        while k < T {
            sum += h[p][k];
            k += 1;
        }
        let mut total = 0i64;
        let mut big = 0;
        k = 0;
        while k < T {
            let c = super::round(h[p][k] / sum * 32768.0);
            out[p][T - 1 - k] = c as i32;
            total += c;
            if c.abs() > out[p][T - 1 - big].abs() as i64 {
                big = k;
            }
            k += 1;
        }
        // Put the rounding residue on the largest tap: the phase sums to
        // exactly 32768.
        out[p][T - 1 - big] += (32768 - total) as i32;
        p += 1;
    }
    out
}

static UP2: [[i32; 32]; 2] = design::<2, 32>(2);
static DOWN2: [[i32; 64]; 1] = design::<1, 64>(2);
static UP3: [[i32; 32]; 3] = design::<3, 32>(3);
static DOWN3: [[i32; 96]; 1] = design::<1, 96>(3);
static UP6: [[i32; 32]; 6] = design::<6, 32>(6);
static DOWN6: [[i32; MAX_TAPS]; 1] = design::<1, MAX_TAPS>(6);
static UP2DOWN3: [[i32; 48]; 2] = design::<2, 48>(3);

/// A resampler for one stream.
#[derive(Debug, Clone)]
pub struct Resampler {
    /// Upsampling and downsampling factors.
    l: usize,
    m: usize,
    /// Taps per phase (0: same rate, a copy).
    taps: usize,
    /// `l` phases of `taps` coefficients (Q15), phase after phase.
    coefs: &'static [i32],
    /// The last `taps − 1` input samples, then the chunk being converted.
    buf: [i16; MAX_TAPS + MAX_FRAME],
    /// Upsampled time of the next output, from the start of the chunk.
    pos: usize,
}

impl Resampler {
    /// A resampler from `from` Hz to `to` Hz, both one of 8000, 16000,
    /// 24000 or 48000; history starts as silence.
    ///
    /// # Errors
    ///
    /// [`RateError`] for any other rate.
    pub fn new(from: u32, to: u32) -> Result<Resampler, RateError> {
        let from = Rate::from_hz(from)?;
        let to = Rate::from_hz(to)?;
        Ok(Self::between(from, to))
    }

    /// A resampler from `from` to `to`.
    #[must_use]
    pub fn between(from: Rate, to: Rate) -> Resampler {
        use Rate::{Hz8000, Hz16000, Hz24000, Hz48000};
        let (l, m, coefs): (usize, usize, &'static [i32]) = match (from, to) {
            (Hz8000, Hz16000) | (Hz24000, Hz48000) => (2, 1, UP2.as_flattened()),
            (Hz16000, Hz8000) | (Hz48000, Hz24000) => (1, 2, DOWN2.as_flattened()),
            (Hz8000, Hz24000) | (Hz16000, Hz48000) => (3, 1, UP3.as_flattened()),
            (Hz24000, Hz8000) | (Hz48000, Hz16000) => (1, 3, DOWN3.as_flattened()),
            (Hz8000, Hz48000) => (6, 1, UP6.as_flattened()),
            (Hz48000, Hz8000) => (1, 6, DOWN6.as_flattened()),
            (Hz16000, Hz24000) => (3, 2, UP3.as_flattened()),
            (Hz24000, Hz16000) => (2, 3, UP2DOWN3.as_flattened()),
            _ => (1, 1, &[]),
        };
        let taps = coefs.len().checked_div(l).unwrap_or(0);
        Resampler {
            l,
            m,
            taps,
            coefs,
            buf: [0; MAX_TAPS + MAX_FRAME],
            pos: 0,
        }
    }

    /// The upsampling and downsampling factors (L, M): L/M = to/from.
    #[must_use]
    pub const fn ratio(&self) -> (usize, usize) {
        (self.l, self.m)
    }

    /// Taps per output sample (0 for the same-rate copy).
    #[must_use]
    pub const fn taps(&self) -> usize {
        self.taps
    }

    /// Back to silent history (a new stream).
    pub fn reset(&mut self) {
        self.buf.fill(0);
        self.pos = 0;
    }

    /// Exactly how many samples the next [`process`](Self::process) of
    /// `in_len` input samples writes, given the current phase: never more
    /// than ⌈`in_len` · L / M⌉. A 10 or 20 ms frame gives exactly the
    /// same duration at the output rate (e.g. 160 at 8 kHz → 960 at
    /// 48 kHz), so with whole frames `output` can be sized
    /// `in_len · to / from`.
    #[must_use]
    pub fn out_len(&self, in_len: usize) -> usize {
        if self.taps == 0 {
            return in_len;
        }
        let span = in_len.saturating_mul(self.l);
        // ⌈(span − pos) / m⌉.
        span.checked_sub(self.pos)
            .and_then(|d| d.checked_add(self.m.saturating_sub(1)))
            .and_then(|d| d.checked_div(self.m))
            .unwrap_or(0)
    }

    /// Convert `input` (the next samples of the stream) into `output`;
    /// returns the samples written, [`out_len`](Self::out_len)`(input.len())`
    /// when `output` is long enough. If it is shorter, the samples that do
    /// not fit are lost (the stream still advances by all of `input`).
    pub fn process(&mut self, input: &[i16], output: &mut [i16]) -> usize {
        if self.taps == 0 {
            let n = input.len().min(output.len());
            if let (Some(o), Some(i)) = (output.get_mut(..n), input.get(..n)) {
                o.copy_from_slice(i);
            }
            return n;
        }
        let hist = self.taps.saturating_sub(1);
        let mut written = 0usize;
        for chunk in input.chunks(MAX_FRAME) {
            let c = chunk.len();
            let end = hist.saturating_add(c);
            if let Some(dst) = self.buf.get_mut(hist..end) {
                dst.copy_from_slice(chunk);
            }
            let span = c.saturating_mul(self.l);
            while self.pos < span {
                let i = self.pos.checked_div(self.l).unwrap_or(0);
                let p = self.pos.checked_rem(self.l).unwrap_or(0);
                let start = p.saturating_mul(self.taps);
                let phase = self
                    .coefs
                    .get(start..start.saturating_add(self.taps))
                    .unwrap_or(&[]);
                let window = self.buf.get(i..i.saturating_add(self.taps)).unwrap_or(&[]);
                let acc = phase.iter().zip(window).fold(0i64, |a, (&c, &x)| {
                    a.wrapping_add(i64::from(c).wrapping_mul(i64::from(x)))
                });
                if let Some(o) = output.get_mut(written) {
                    *o = sat16(acc.wrapping_add(1 << 14) >> 15);
                    written = written.wrapping_add(1);
                }
                self.pos = self.pos.saturating_add(self.m);
            }
            self.pos = self.pos.saturating_sub(span);
            // Keep the last `hist` samples as the next chunk's history.
            if c > 0 {
                self.buf.copy_within(c..end, 0);
            }
        }
        written
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::many_single_char_names
)]
mod tests {
    extern crate std;
    use super::super::testutil::{goertzel, sine};
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const RATES: [u32; 4] = [8000, 16000, 24000, 48000];

    fn run(r: &mut Resampler, input: &[i16], frame: usize) -> Vec<i16> {
        let mut out = Vec::new();
        for f in input.chunks(frame) {
            let mut o = vec![0i16; r.out_len(f.len())];
            let n = r.process(f, &mut o);
            assert_eq!(n, o.len());
            out.extend_from_slice(&o);
        }
        out
    }

    #[test]
    fn rejects_other_rates() {
        assert_eq!(Resampler::new(44100, 8000).unwrap_err(), RateError);
        assert_eq!(Resampler::new(8000, 0).unwrap_err(), RateError);
        assert!(Resampler::new(8000, 48000).is_ok());
    }

    #[test]
    fn phases_sum_to_unity() {
        for &from in &RATES {
            for &to in &RATES {
                let r = Resampler::new(from, to).unwrap();
                let (l, m) = r.ratio();
                assert_eq!(l as u32 * from, m as u32 * to);
                if from == to {
                    assert_eq!(r.taps(), 0);
                    continue;
                }
                assert!(r.taps() <= MAX_TAPS);
                for ph in r.coefs.chunks(r.taps()) {
                    assert_eq!(ph.iter().sum::<i32>(), 32768, "{from}->{to}");
                }
            }
        }
    }

    #[test]
    fn frame_sizes_and_dc_gain() {
        for &from in &RATES {
            for &to in &RATES {
                let mut r = Resampler::new(from, to).unwrap();
                let fin = (from / 50) as usize;
                let fout = (to / 50) as usize;
                let input = vec![10000i16; fin];
                for k in 0..10 {
                    assert_eq!(r.out_len(fin), fout);
                    let mut out = vec![0i16; fout];
                    assert_eq!(r.process(&input, &mut out), fout);
                    if k > 2 {
                        for &v in &out {
                            assert!((i32::from(v) - 10000).abs() <= 1, "{from}->{to}: {v}");
                        }
                    }
                }
                // 10 ms frames too.
                let mut o10 = vec![0i16; fout / 2];
                assert_eq!(r.out_len(fin / 2), fout / 2);
                assert_eq!(r.process(&input[..fin / 2], &mut o10), fout / 2);
            }
        }
    }

    #[test]
    fn continuous_across_frames() {
        for &(from, to) in &[(8000, 48000), (48000, 8000), (16000, 24000), (24000, 16000)] {
            let mut x = vec![0i16; 4800];
            let mut s = 7u32;
            for v in &mut x {
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *v = (s >> 16) as i16;
            }
            let whole = run(&mut Resampler::new(from, to).unwrap(), &x, 4800);
            for frame in [1, 7, 160, 960, 1000] {
                let parts = run(&mut Resampler::new(from, to).unwrap(), &x, frame);
                assert_eq!(parts, whole, "{from}->{to} by {frame}");
            }
            assert_eq!(whole.len(), 4800 * to as usize / from as usize);
        }
    }

    #[test]
    fn sine_round_trip_8k_48k_8k() {
        // 1 kHz at amplitude 10000, 1 s.
        let mut x = vec![0i16; 8000];
        sine(&mut x, 1000.0, 8000.0, 10000.0, 0);
        let mut up = Resampler::new(8000, 48000).unwrap();
        let mut down = Resampler::new(48000, 8000).unwrap();
        let mid = run(&mut up, &x, 160);
        let back = run(&mut down, &mid, 960);
        assert_eq!(mid.len(), 48000);
        assert_eq!(back.len(), 8000);
        // Steady state: the last half second.
        let tail = &back[4000..];
        let p = goertzel(tail, 1000.0, 8000.0).sqrt();
        assert!((p - 10000.0).abs() < 100.0, "amplitude {p}");
        // Frequency kept: nearly nothing elsewhere.
        for f in [500.0, 1500.0, 2000.0, 3000.0] {
            let q = goertzel(tail, f, 8000.0).sqrt();
            assert!(q < 10.0, "{f} Hz: {q}");
        }
        // At 48 kHz: the 1 kHz tone, and its 7 kHz image at least 60 dB
        // down.
        let mt = &mid[24000..];
        let a = goertzel(mt, 1000.0, 48000.0).sqrt();
        assert!((a - 10000.0).abs() < 100.0, "mid amplitude {a}");
        let img = goertzel(mt, 7000.0, 48000.0).sqrt();
        assert!(img < 10.0, "image {img}");
    }

    #[test]
    fn decimation_rejects_aliases() {
        // 6 kHz at 48 kHz would alias to 2 kHz at 8 kHz: at least 70 dB
        // down.
        let mut x = vec![0i16; 48000];
        sine(&mut x, 6000.0, 48000.0, 20000.0, 0);
        let back = run(&mut Resampler::new(48000, 8000).unwrap(), &x, 960);
        let alias = goertzel(&back[4000..], 2000.0, 8000.0).sqrt();
        assert!(alias < 20000.0 * 10f64.powf(-70.0 / 20.0), "alias {alias}");
    }

    #[test]
    fn extremes_and_short_output() {
        let mut r = Resampler::new(8000, 48000).unwrap();
        let full = [i16::MAX, i16::MIN].repeat(400);
        let mut out = vec![0i16; 4800];
        assert_eq!(r.process(&full, &mut out), 4800);
        // Short output: only what fits, the stream still advances.
        let mut small = [0i16; 5];
        assert_eq!(r.process(&full[..160], &mut small), 5);
        assert_eq!(r.out_len(160), 960);
        assert_eq!(r.process(&[], &mut out), 0);
        assert_eq!(r.process(&full[..10], &mut []), 0);
        // Same rate: a copy of the shorter length.
        let mut same = Resampler::new(16000, 16000).unwrap();
        let mut o = [0i16; 3];
        assert_eq!(same.process(&[1, 2, 3, 4], &mut o), 3);
        assert_eq!(o, [1, 2, 3]);
        assert_eq!(same.out_len(77), 77);
        r.reset();
        let mut z = [1i16; 6];
        assert_eq!(r.process(&[0], &mut z), 6);
        assert_eq!(z, [0; 6]);
    }

    #[test]
    fn against_direct_form_reference() {
        // The polyphase output equals the textbook form: zero-stuff by L,
        // filter with the whole prototype, keep every M-th sample.
        for &(from, to) in &[(16000u32, 24000u32), (24000, 16000), (8000, 48000)] {
            let mut r = Resampler::new(from, to).unwrap();
            let (l, m) = r.ratio();
            let t = r.taps();
            // Rebuild the prototype h[n] = phase p, tap (T − 1 − k), n = p + kL.
            let mut h = vec![0i64; l * t];
            for (p, ph) in r.coefs.chunks(t).enumerate() {
                for (j, &c) in ph.iter().enumerate() {
                    h[p + (t - 1 - j) * l] = i64::from(c);
                }
            }
            let mut x = vec![0i16; 480];
            sine(&mut x, 440.0, f64::from(from), 12000.0, 0);
            let got = run(&mut r, &x, 480);
            let mut up = vec![0i64; x.len() * l];
            for (i, &v) in x.iter().enumerate() {
                up[i * l] = i64::from(v);
            }
            let want: Vec<i16> = (0..up.len())
                .step_by(m)
                .map(|u| {
                    let acc: i64 = (0..h.len())
                        .filter(|&n| n <= u)
                        .map(|n| h[n] * up[u - n])
                        .sum();
                    sat16((acc + (1 << 14)) >> 15)
                })
                .collect();
            assert_eq!(got, want, "{from}->{to}");
        }
    }
}
