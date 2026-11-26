//! ITU-T G.722: 7 kHz wideband audio at 64 kbit/s (sub-band ADPCM), as
//! carried by RTP (RFC 3551 §4.5.2: payload type 9, one octet per pair of
//! 16 kHz samples; the RTP clock is 8000 Hz although the audio is
//! sampled at 16000 Hz, an error in the original specification kept for
//! compatibility).
//!
//! Mode 1 (64 kbit/s, six low-band and two high-band bits per octet) only,
//! which is what RTP uses. No allocation: the caller gives the buffers.
//!
//! The algorithm follows the ITU reference as written by Steve Underwood
//! for `SpanDSP` (who placed his work in the public domain) on the CMU
//! single-channel codec by Chengxiang Lu and Alex Hauptmann (Copyright (c)
//! 1993 Carnegie Mellon University; "use of this program, for any research
//! or commercial purpose, is completely unrestricted"), the code that
//! Asterisk and `FreeSWITCH` use. The tests check it bit for bit against the
//! same algorithm's other Rust translation, `ezk-g722`.

// Table indices are codes or step-size bits: masked or shifted out of
// non-negative values, never negative.
#![allow(clippy::cast_sign_loss)]

/// The QMF filter coefficients (G.722 §2.2.2, Table 11).
const QMF: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];

/// Log-step adaptation of the low band (Table 7 / `WL`) and its index
/// table (`RL42`).
const WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
const RL42: [i32; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
/// The inverse logarithmic table (Table 9 / `ILB`).
const ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];
/// Log-step adaptation of the high band (`WH`, `RH2`).
const WH: [i32; 3] = [0, -214, 798];
const RH2: [i32; 4] = [2, 1, 2, 1];
/// Inverse quantizer outputs: 2-bit high band, 4-bit (adaptation) and
/// 6-bit (output) low band.
const QM2: [i32; 4] = [-7408, -1616, 7408, 1616];
const QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];
const QM6: [i32; 64] = [
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192, -10232,
    -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576, -3168, -2776,
    -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704, 14984, 13512, 12280,
    11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944, 4464, 4008, 3576, 3168, 2776,
    2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
];
/// The low-band quantizer's decision levels (`Q6`) and codes for negative
/// and positive differences (`ILN`, `ILP`).
const Q6: [i32; 32] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
];
const ILN: [i32; 32] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 0,
];
const ILP: [i32; 32] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 0,
];
/// The high-band codes for negative and positive differences.
const IHN: [i32; 3] = [0, 1, 0];
const IHP: [i32; 3] = [0, 3, 2];

fn saturate(v: i32) -> i32 {
    v.clamp(i32::from(i16::MIN), i32::from(i16::MAX))
}

// The reference's 32-bit arithmetic. Its values stay far inside `i32` (the
// operands are saturated to 16 bits or bounded by the tables), so these
// never wrap; they are spelled out so that no input could make them panic.
const fn add(a: i32, b: i32) -> i32 {
    a.wrapping_add(b)
}

const fn sub(a: i32, b: i32) -> i32 {
    a.wrapping_sub(b)
}

const fn mul(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b)
}

/// Entry `i` of a table (the reference's indices are always in range:
/// masked codes or bounded counters; out of range gives 0).
fn tab<const N: usize>(t: &[i32; N], i: i32) -> i32 {
    usize::try_from(i)
        .ok()
        .and_then(|i| t.get(i))
        .copied()
        .unwrap_or(0)
}

/// One sub-band's ADPCM state (the predictor and the step size).
#[derive(Debug, Clone, Copy, Default)]
struct Band {
    s: i32,
    sp: i32,
    sz: i32,
    r: [i32; 3],
    a: [i32; 3],
    ap: [i32; 3],
    p: [i32; 3],
    d: [i32; 7],
    b: [i32; 7],
    bp: [i32; 7],
    sg: [i32; 7],
    nb: i32,
    det: i32,
}

impl Band {
    /// Blocks 3L/3H, SCALEL/SCALEH: the step size from `nb`; `shift` is 8
    /// for the low band, 10 for the high band.
    fn scale(&mut self, shift: i32) {
        let wd1 = (self.nb >> 6) & 31;
        let wd2 = sub(shift, self.nb >> 11);
        let base = tab(&ILB, wd1);
        let wd3 = if wd2 < 0 {
            base.wrapping_shl(wd2.unsigned_abs())
        } else {
            base.wrapping_shr(wd2.unsigned_abs())
        };
        self.det = wd3.wrapping_shl(2);
    }

    /// Block 4: reconstruction, the pole and zero predictor updates, and
    /// the next prediction, from the quantized difference `d`.
    #[allow(clippy::similar_names)]
    fn block4(&mut self, d: i32) {
        // RECONS, PARREC
        self.d[0] = d;
        self.r[0] = saturate(add(self.s, d));
        self.p[0] = saturate(add(self.sz, d));

        // UPPOL2
        for (sg, p) in self.sg.iter_mut().zip(self.p) {
            *sg = p >> 15;
        }
        let wd1 = saturate(self.a[1].wrapping_shl(2));
        let wd2 = if self.sg[0] == self.sg[1] {
            wd1.wrapping_neg()
        } else {
            wd1
        }
        .min(32767);
        let wd3 = add(
            add(wd2 >> 7, if self.sg[0] == self.sg[2] { 128 } else { -128 }),
            mul(self.a[2], 32512) >> 15,
        );
        self.ap[2] = wd3.clamp(-12288, 12288);

        // UPPOL1
        self.sg[0] = self.p[0] >> 15;
        self.sg[1] = self.p[1] >> 15;
        let wd1 = if self.sg[0] == self.sg[1] { 192 } else { -192 };
        let wd2 = mul(self.a[1], 32640) >> 15;
        self.ap[1] = saturate(add(wd1, wd2));
        // `ap[2]` is within ±12288: the bound is positive.
        let wd3 = saturate(sub(15360, self.ap[2]));
        self.ap[1] = self.ap[1].clamp(wd3.wrapping_neg(), wd3);

        // UPZERO
        let wd1: i32 = if d == 0 { 0 } else { 128 };
        self.sg[0] = d >> 15;
        let sg0 = self.sg[0];
        for (((sg, &dd), &b), bp) in self.sg[1..]
            .iter_mut()
            .zip(&self.d[1..])
            .zip(&self.b[1..])
            .zip(&mut self.bp[1..])
        {
            *sg = dd >> 15;
            let wd2 = if *sg == sg0 { wd1 } else { wd1.wrapping_neg() };
            let wd3 = mul(b, 32640) >> 15;
            *bp = saturate(add(wd2, wd3));
        }

        // DELAYA
        self.d.copy_within(0..6, 1);
        self.b[1..].copy_from_slice(&self.bp[1..]);
        self.r.copy_within(0..2, 1);
        self.p.copy_within(0..2, 1);
        self.a[1..].copy_from_slice(&self.ap[1..]);

        // FILTEP
        let wd1 = mul(self.a[1], saturate(add(self.r[1], self.r[1]))) >> 15;
        let wd2 = mul(self.a[2], saturate(add(self.r[2], self.r[2]))) >> 15;
        self.sp = saturate(add(wd1, wd2));

        // FILTEZ (a sum: the order does not matter)
        let sz = self.b[1..]
            .iter()
            .zip(&self.d[1..])
            .fold(0, |acc, (&b, &d)| {
                add(acc, mul(b, saturate(add(d, d))) >> 15)
            });
        self.sz = saturate(sz);

        // PREDIC
        self.s = saturate(add(self.sp, self.sz));
    }

    /// Blocks 3L (LOGSCL, SCALEL) and 4 of the low band, after the
    /// quantized difference `dlow` of code `il` (its top four bits).
    fn adapt_low(&mut self, ril: i32, dlow: i32) {
        let il4 = tab(&RL42, ril);
        self.nb = add(mul(self.nb, 127) >> 7, tab(&WL, il4)).clamp(0, 18432);
        self.scale(8);
        self.block4(dlow);
    }

    /// Blocks 3H (LOGSCH, SCALEH) and 4 of the high band.
    fn adapt_high(&mut self, ih: i32, dhigh: i32) {
        let ih2 = tab(&RH2, ih);
        self.nb = add(mul(self.nb, 127) >> 7, tab(&WH, ih2)).clamp(0, 22528);
        self.scale(10);
        self.block4(dhigh);
    }
}

/// The QMF sums over the 24-sample history: even-indexed samples with the
/// coefficients in order, odd-indexed ones with them reversed.
fn qmf(x: &[i32; 24]) -> (i32, i32) {
    let (mut forward, mut reversed) = (0, 0);
    for ((pair, &q), &qr) in x.as_chunks::<2>().0.iter().zip(&QMF).zip(QMF.iter().rev()) {
        forward = add(forward, mul(pair[0], q));
        reversed = add(reversed, mul(pair[1], qr));
    }
    (forward, reversed)
}

/// A G.722 encoder: 16 kHz linear PCM to one octet per two samples.
#[derive(Debug, Clone, Default)]
pub struct Encoder {
    x: [i32; 24],
    band: [Band; 2],
}

impl Encoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode `pcm` (16 kHz, an even number of samples) into `out`, one
    /// octet per two samples; returns the octets written (fewer when `out`
    /// is short, a trailing odd sample is left out).
    pub fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> usize {
        let mut n = 0usize;
        for (pair, o) in pcm.as_chunks::<2>().0.iter().zip(out.iter_mut()) {
            // Transmit QMF: shift in two samples, keep every other output.
            self.x.copy_within(2.., 0);
            self.x[22] = i32::from(pair[0]);
            self.x[23] = i32::from(pair[1]);
            let (odd, even) = qmf(&self.x);
            let xlow = add(even, odd) >> 14;
            let xhigh = sub(even, odd) >> 14;

            // Low band: SUBTRA, QUANTL, INVQAL.
            let low = &mut self.band[0];
            let el = saturate(sub(xlow, low.s));
            // |el|, one less for a negative difference (as the reference).
            let wd = if el >= 0 { el } else { !el };
            // The first decision level (from 1, below 30) above |el|.
            let det = low.det;
            let i = Q6
                .get(1..30)
                .unwrap_or_default()
                .iter()
                .position(|&q| wd < mul(q, det) >> 12)
                .map_or(30, |p| p.wrapping_add(1));
            let codes = if el < 0 { &ILN } else { &ILP };
            let ilow = codes.get(i).copied().unwrap_or(0);
            let ril = ilow >> 2;
            let dlow = mul(low.det, tab(&QM4, ril)) >> 15;
            low.adapt_low(ril, dlow);

            // High band: SUBTRA, QUANTH, INVQAH.
            let high = &mut self.band[1];
            let eh = saturate(sub(xhigh, high.s));
            let wd = if eh >= 0 { eh } else { !eh };
            let mih = if wd >= mul(564, high.det) >> 12 { 2 } else { 1 };
            let ihigh = if eh < 0 {
                tab(&IHN, mih)
            } else {
                tab(&IHP, mih)
            };
            let dhigh = mul(high.det, tab(&QM2, ihigh)) >> 15;
            high.adapt_high(ihigh, dhigh);

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                *o = (ihigh.wrapping_shl(6) | ilow) as u8;
            }
            // At most `out.len()`.
            n = n.wrapping_add(1);
        }
        n
    }
}

/// A G.722 decoder: one octet to two samples of 16 kHz linear PCM.
#[derive(Debug, Clone, Default)]
pub struct Decoder {
    x: [i32; 24],
    band: [Band; 2],
}

impl Decoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode `codes` into `out` (two samples per octet); returns the
    /// samples written (fewer when `out` is short).
    pub fn decode(&mut self, codes: &[u8], out: &mut [i16]) -> usize {
        let mut n = 0usize;
        for (&code, pair) in codes.iter().zip(out.as_chunks_mut::<2>().0) {
            let code = i32::from(code);
            let ilow = code & 0x3f;
            let ihigh = (code >> 6) & 0x03;

            // Low band: INVQBL, RECONS, LIMIT, then the adaptation from the
            // code's top four bits (INVQAL).
            let low = &mut self.band[0];
            let rlow = add(low.s, mul(low.det, tab(&QM6, ilow)) >> 15).clamp(-16384, 16383);
            let ril = ilow >> 2;
            let dlowt = mul(low.det, tab(&QM4, ril)) >> 15;
            low.adapt_low(ril, dlowt);

            // High band: INVQAH, RECONS, LIMIT.
            let high = &mut self.band[1];
            let dhigh = mul(high.det, tab(&QM2, ihigh)) >> 15;
            let rhigh = add(dhigh, high.s).clamp(-16384, 16383);
            high.adapt_high(ihigh, dhigh);

            // Receive QMF.
            self.x.copy_within(2.., 0);
            self.x[22] = add(rlow, rhigh);
            self.x[23] = sub(rlow, rhigh);
            let (x2, x1) = qmf(&self.x);
            #[allow(clippy::cast_possible_truncation)]
            {
                pair[0] = saturate(x1 >> 11) as i16;
                pair[1] = saturate(x2 >> 11) as i16;
            }
            // Two samples per octet, at most `out.len()`.
            n = n.wrapping_add(2);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A deterministic test signal: speech-like tones, a sweep, silence,
    /// full-scale extremes and noise.
    fn signal(len: usize) -> Vec<i16> {
        let mut seed = 0x1234_5678u32;
        (0..len)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                let t = i as f64 / 16000.0;
                let tone = 9000.0 * (2.0 * core::f64::consts::PI * 440.0 * t).sin()
                    + 4000.0 * (2.0 * core::f64::consts::PI * (300.0 + 3000.0 * t) * t).sin();
                #[allow(clippy::cast_possible_truncation)]
                match (i / 4000) % 4 {
                    0 => tone as i16,
                    1 => 0,
                    2 => {
                        if i % 2 == 0 {
                            i16::MAX
                        } else {
                            i16::MIN
                        }
                    }
                    _ => (seed >> 16) as i16,
                }
            })
            .collect()
    }

    /// Bit for bit what the other translation of the same reference code
    /// produces, encoding and decoding, over every kind of input.
    #[test]
    fn matches_the_reference_translation() {
        use ezk_g722::libg722::{Bitrate, decoder, encoder};
        let pcm = signal(64_000);
        let mut ours = Encoder::new();
        let mut codes = std::vec![0u8; pcm.len() / 2];
        assert_eq!(ours.encode(&pcm, &mut codes), codes.len());
        let mut theirs = encoder::Encoder::new(Bitrate::Mode1_64000, false, false);
        assert_eq!(codes, theirs.encode(&pcm));

        let mut ours = Decoder::new();
        let mut out = std::vec![0i16; codes.len() * 2];
        assert_eq!(ours.decode(&codes, &mut out), out.len());
        let mut theirs = decoder::Decoder::new(Bitrate::Mode1_64000, false, false);
        assert_eq!(out, theirs.decode(&codes));

        // Every code value, decoded from a fresh state, both ways.
        let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut out = std::vec![0i16; all.len() * 2];
        Decoder::new().decode(&all, &mut out);
        assert_eq!(
            out,
            decoder::Decoder::new(Bitrate::Mode1_64000, false, false).decode(&all)
        );
    }

    /// A tone survives the round trip (after the codec's delay).
    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn a_tone_round_trips() {
        let pcm: Vec<i16> = (0..16_000)
            .map(|i| {
                #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                let s =
                    8000.0 * (2.0 * core::f64::consts::PI * 1000.0 * f64::from(i) / 16000.0).sin();
                #[allow(clippy::cast_possible_truncation)]
                {
                    s as i16
                }
            })
            .collect();
        let mut codes = std::vec![0u8; 8000];
        Encoder::new().encode(&pcm, &mut codes);
        let mut out = std::vec![0i16; 16_000];
        Decoder::new().decode(&codes, &mut out);
        // Energy within 1 dB of the input's, past the start-up.
        let energy =
            |s: &[i16]| s.iter().map(|&v| f64::from(v).powi(2)).sum::<f64>() / s.len() as f64;
        let ratio = energy(&out[1000..]) / energy(&pcm[1000..]);
        assert!((0.79..1.26).contains(&ratio), "{ratio}");
    }

    #[test]
    fn short_buffers_and_odd_input() {
        let mut codes = [0u8; 2];
        assert_eq!(Encoder::new().encode(&[1, 2, 3, 4, 5], &mut codes), 2);
        assert_eq!(Encoder::new().encode(&[1, 2, 3], &mut [0u8; 8]), 1);
        let mut out = [0i16; 3];
        assert_eq!(Decoder::new().decode(&[1, 2, 3], &mut out), 2);
    }
}
