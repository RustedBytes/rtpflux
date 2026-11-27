//! Packet loss concealment for PCM frames.
//!
//! The last good frame is kept. A lost frame is replaced by that frame
//! repeated (cyclically, continuing where the previous concealed frame
//! stopped), attenuated: the first lost frame at full level, then −6 dB
//! per further lost frame, the gain ramping linearly across each frame so
//! there is no step; once [`SILENCE_MS`] of audio has been concealed in a
//! row the output is silence. The first good frame after a loss is
//! cross-faded from the concealment over [`FADE_MS`] (a linear ramp), so
//! the switch back does not click.

use super::{MAX_FRAME, Rate, sat16};

/// After this much concealed audio in a row (milliseconds), silence.
pub const SILENCE_MS: u32 = 60;
/// Length of the cross-fade into the first good frame after a loss, in
/// milliseconds (shortened to the frame if the frame is shorter).
pub const FADE_MS: u32 = 5;

/// Unity in the Q15 gains used here.
const ONE: i32 = 1 << 15;

/// Concealment state of one stream.
#[derive(Debug, Clone)]
pub struct Plc {
    rate: Rate,
    /// The last good frame (its first `len` samples).
    last: [i16; MAX_FRAME],
    len: usize,
    /// Read position in `last` for the next concealed sample.
    pos: usize,
    /// Frames lost in a row.
    lost: u32,
    /// Samples concealed in a row.
    concealed: u32,
    /// Gain (Q15) at the end of the last concealed frame.
    gain: i32,
}

impl Plc {
    /// Concealment for a stream at `rate`, with no good frame yet (a loss
    /// before any audio is silence).
    #[must_use]
    pub const fn new(rate: Rate) -> Self {
        Plc {
            rate,
            last: [0; MAX_FRAME],
            len: 0,
            pos: 0,
            lost: 0,
            concealed: 0,
            gain: ONE,
        }
    }

    /// Frames lost in a row so far (0 after a good frame).
    #[must_use]
    pub const fn lost_in_a_row(&self) -> u32 {
        self.lost
    }

    /// Forget the stream (a new source).
    pub fn reset(&mut self) {
        *self = Plc::new(self.rate);
    }

    /// One concealed sample at gain `g` (Q15), advancing the read position.
    #[inline]
    fn next_sample(&mut self, g: i32) -> i16 {
        let Some(&s) = self.last.get(self.pos) else {
            return 0;
        };
        self.pos = self.pos.wrapping_add(1);
        if self.pos >= self.len {
            self.pos = 0;
        }
        sat16(i64::from(s).wrapping_mul(i64::from(g)) >> 15)
    }

    /// A good frame: cross-faded in place from the concealment if frames
    /// were lost just before, then kept for concealing later losses (the
    /// first [`MAX_FRAME`] samples of it, as received, before the fade).
    pub fn good(&mut self, frame: &mut [i16]) {
        let keep = frame.len().min(MAX_FRAME);
        let mut saved = [0i16; MAX_FRAME];
        if let (Some(dst), Some(src)) = (saved.get_mut(..keep), frame.get(..keep)) {
            dst.copy_from_slice(src);
        }
        if self.lost > 0 && self.len > 0 && self.concealed < self.silence_after() {
            let ramp = frame.len().min(self.rate.samples(FADE_MS) as usize);
            let g = self.gain;
            // ramp ≤ 240: the products stay far inside i64.
            let r = i64::try_from(ramp).unwrap_or(1).max(1);
            for (i, s) in (0i64..).zip(frame.iter_mut().take(ramp)) {
                let c = i64::from(self.next_sample(g));
                let v = c
                    .wrapping_mul(r.wrapping_sub(i))
                    .wrapping_add(i64::from(*s).wrapping_mul(i))
                    .checked_div(r)
                    .unwrap_or(0);
                *s = sat16(v);
            }
        } else if self.lost > 0 {
            // From silence: fade in.
            let ramp = frame.len().min(self.rate.samples(FADE_MS) as usize);
            let r = i64::try_from(ramp).unwrap_or(1).max(1);
            for (i, s) in (0i64..).zip(frame.iter_mut().take(ramp)) {
                *s = sat16(i64::from(*s).wrapping_mul(i).checked_div(r).unwrap_or(0));
            }
        }
        self.last = saved;
        self.len = keep;
        self.pos = 0;
        self.lost = 0;
        self.concealed = 0;
        self.gain = ONE;
    }

    /// Samples of concealment after which the output is silence.
    const fn silence_after(&self) -> u32 {
        self.rate.samples(SILENCE_MS)
    }

    /// Fill `out` (any length) for a lost frame.
    pub fn conceal(&mut self, out: &mut [i16]) {
        let n = u32::try_from(out.len()).unwrap_or(u32::MAX);
        let limit = self.silence_after();
        if self.len == 0 || self.concealed >= limit {
            out.fill(0);
            self.lost = self.lost.saturating_add(1);
            self.concealed = self.concealed.saturating_add(n);
            self.gain = 0;
            return;
        }
        // Frame k (0-based) of the loss ramps from the gain the previous
        // one ended at to ONE >> k.
        let start = self.gain;
        let end = ONE.checked_shr(self.lost).unwrap_or(0);
        let len = i64::try_from(out.len()).unwrap_or(i64::MAX).max(1);
        let span = i64::from(end.wrapping_sub(start));
        for (i, o) in (1i64..).zip(out.iter_mut()) {
            if self.concealed >= limit {
                *o = 0;
                continue;
            }
            // start + span·i/len: |span| ≤ 2^15, i ≤ len.
            let g =
                i64::from(start).wrapping_add(span.wrapping_mul(i).checked_div(len).unwrap_or(0));
            *o = self.next_sample(i32::try_from(g).unwrap_or(0));
            self.concealed = self.concealed.saturating_add(1);
        }
        self.gain = if self.concealed >= limit { 0 } else { end };
        self.lost = self.lost.saturating_add(1);
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
mod tests {
    use super::*;

    fn peak(x: &[i16]) -> i32 {
        x.iter().map(|&v| i32::from(v).abs()).max().unwrap_or(0)
    }

    #[test]
    fn loss_before_any_audio_is_silence() {
        let mut p = Plc::new(Rate::Hz8000);
        let mut out = [5i16; 160];
        p.conceal(&mut out);
        assert!(out.iter().all(|&v| v == 0));
        // Fade in from silence.
        let mut f = [1000i16; 160];
        p.good(&mut f);
        assert_eq!(f[0], 0);
        assert!(f[1] > 0 && f[1] < 1000);
        assert_eq!(f[40], 1000);
        assert_eq!(f[159], 1000);
    }

    #[test]
    fn first_loss_repeats_then_attenuates_then_silence() {
        let mut p = Plc::new(Rate::Hz8000);
        let mut frame = [0i16; 160];
        for (i, v) in frame.iter_mut().enumerate() {
            *v = (i as i16 - 80) * 100;
        }
        let orig = frame;
        p.good(&mut frame);
        // A good frame without a loss before it is untouched.
        assert_eq!(frame, orig);
        let mut out = [0i16; 160];
        p.conceal(&mut out);
        assert_eq!(out, orig);
        p.conceal(&mut out);
        // Second lost frame ramps 1 → 0.5.
        assert_eq!(out[159], orig[159] / 2);
        p.conceal(&mut out);
        assert_eq!(p.lost_in_a_row(), 3);
        assert!(peak(&out) <= peak(&orig) / 2 + 1);
        // 3 × 20 ms = 60 ms concealed: silence from now on.
        p.conceal(&mut out);
        assert!(out.iter().all(|&v| v == 0));
        p.conceal(&mut out);
        assert!(out.iter().all(|&v| v == 0));
    }

    #[test]
    fn gain_never_rises_during_a_loss() {
        let mut p = Plc::new(Rate::Hz16000);
        let mut frame = [10000i16; 160];
        p.good(&mut frame);
        let mut prev = i32::MAX;
        for _ in 0..12 {
            let mut out = [0i16; 160];
            p.conceal(&mut out);
            for &v in &out {
                assert!(i32::from(v) <= prev);
                prev = i32::from(v);
            }
        }
        assert_eq!(prev, 0);
    }

    #[test]
    fn cross_fade_back_into_good_audio() {
        let mut p = Plc::new(Rate::Hz8000);
        let mut f = [8000i16; 160];
        p.good(&mut f);
        let mut out = [0i16; 160];
        p.conceal(&mut out);
        p.conceal(&mut out);
        // Concealment ended at 4000; the new frame is −8000.
        let mut g = [-8000i16; 160];
        p.good(&mut g);
        assert_eq!(g[0], 4000);
        for w in g[..40].windows(2) {
            assert!(w[1] <= w[0]);
        }
        assert_eq!(g[40], -8000);
        assert_eq!(p.lost_in_a_row(), 0);
        // And the kept frame is the received one, not the faded one.
        p.conceal(&mut out);
        assert!(out.iter().all(|&v| v == -8000));
    }

    #[test]
    fn mismatched_and_extreme_lengths() {
        let mut p = Plc::new(Rate::Hz48000);
        let mut f = [1i16, 2, 3];
        p.good(&mut f);
        let mut out = [0i16; 7];
        p.conceal(&mut out);
        assert_eq!(out, [1, 2, 3, 1, 2, 3, 1]);
        // Continues the cycle.
        let mut o2 = [0i16; 2];
        p.conceal(&mut o2);
        assert!(o2[0] == 2 || o2[0] == 1);
        p.conceal(&mut []);
        p.good(&mut []);
        // An empty good frame leaves nothing to repeat.
        let mut o3 = [9i16; 4];
        p.conceal(&mut o3);
        assert_eq!(o3, [0; 4]);
        // Longer than MAX_FRAME: kept up to MAX_FRAME, output any length.
        let mut big = [i16::MIN; 2000];
        p.good(&mut big);
        let mut o4 = [0i16; 2000];
        p.conceal(&mut o4);
        assert!(o4.iter().all(|&v| v == i16::MIN));
        p.reset();
        p.conceal(&mut o4);
        assert!(o4.iter().all(|&v| v == 0));
    }
}
