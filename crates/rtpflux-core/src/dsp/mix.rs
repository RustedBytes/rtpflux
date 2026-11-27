//! N − 1 conference mixing: every participant hears the sum of everyone
//! else.
//!
//! Per frame: [`Mixer::begin`] sets the frame length and clears the sum,
//! [`Mixer::add`] adds each participant's frame (scaled by its gain) into
//! an `i32` sum and keeps its contribution, and [`Mixer::output_for`]
//! gives a participant the sum minus its own contribution, brought into
//! `i16` by that listener's [`Limiter`]. Nothing is clipped before the
//! subtraction, so the own contribution is removed exactly. A participant
//! that adds nothing (absent, muted, or its packet lost) contributes
//! silence.
//!
//! The sum cannot overflow: |sample · gain| ≤ 32768 · 65535 / 256 < 2^23,
//! and `P` ≤ 128 such terms stay below 2^30.

use super::MAX_FRAME;
use super::gain::{Limiter, UNITY_Q8};

/// Why a mixer call was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixError {
    /// Participant index not below `P`.
    NoSuchParticipant,
    /// Frame length not the one given to [`Mixer::begin`] (or an output
    /// buffer shorter than it).
    LengthMismatch,
    /// The participant already added a frame since [`Mixer::begin`].
    AlreadyAdded,
    /// Frame longer than [`MAX_FRAME`].
    TooLong,
}

/// A mixer for up to `P` participants (1 ≤ `P` ≤ 128); about
/// `P` × 2 KiB.
#[derive(Debug, Clone)]
pub struct Mixer<const P: usize> {
    sum: [i32; MAX_FRAME],
    /// Each participant's frame as added (before gain).
    own: [[i16; MAX_FRAME]; P],
    added: [bool; P],
    gain_q8: [u16; P],
    muted: [bool; P],
    len: usize,
}

impl<const P: usize> Mixer<P> {
    const CHECK: () = assert!(P >= 1 && P <= 128, "Mixer needs 1..=128 participants");

    /// A mixer with every participant at unity gain, unmuted, and a frame
    /// length of 0 (call [`begin`](Self::begin)).
    #[must_use]
    pub const fn new() -> Self {
        let () = Self::CHECK;
        Mixer {
            sum: [0; MAX_FRAME],
            own: [[0; MAX_FRAME]; P],
            added: [false; P],
            gain_q8: [UNITY_Q8; P],
            muted: [false; P],
            len: 0,
        }
    }

    /// Start a frame of `len` samples: the sum is cleared and nobody has
    /// added yet.
    ///
    /// # Errors
    ///
    /// [`MixError::TooLong`] if `len` > [`MAX_FRAME`].
    pub fn begin(&mut self, len: usize) -> Result<(), MixError> {
        let sum = self.sum.get_mut(..len).ok_or(MixError::TooLong)?;
        sum.fill(0);
        self.added = [false; P];
        self.len = len;
        Ok(())
    }

    /// The frame length set by [`begin`](Self::begin).
    #[must_use]
    pub const fn frame_len(&self) -> usize {
        self.len
    }

    /// Set a participant's gain (Q8: 256 = unity), applied from its next
    /// [`add`](Self::add).
    ///
    /// # Errors
    ///
    /// [`MixError::NoSuchParticipant`], or [`MixError::AlreadyAdded`]
    /// between its `add` and the next `begin`.
    pub fn set_gain_q8(&mut self, participant: usize, gain_q8: u16) -> Result<(), MixError> {
        let added = *self
            .added
            .get(participant)
            .ok_or(MixError::NoSuchParticipant)?;
        if added {
            // This frame's contribution was added at the old gain: keep its
            // subtraction exact.
            return Err(MixError::AlreadyAdded);
        }
        if let Some(g) = self.gain_q8.get_mut(participant) {
            *g = gain_q8;
        }
        Ok(())
    }

    /// Mute a participant (others stop hearing it from its next
    /// [`add`](Self::add); it still hears them) or unmute it.
    ///
    /// # Errors
    ///
    /// [`MixError::NoSuchParticipant`].
    pub fn set_muted(&mut self, participant: usize, muted: bool) -> Result<(), MixError> {
        let m = self
            .muted
            .get_mut(participant)
            .ok_or(MixError::NoSuchParticipant)?;
        *m = muted;
        Ok(())
    }

    /// One sample of a participant's contribution: `x` at gain `g`.
    #[inline]
    fn scaled(x: i16, g: u16) -> i32 {
        // < 2^23 in magnitude.
        i32::from(x).wrapping_mul(i32::from(g)) >> 8
    }

    /// Add a participant's frame for this period. A muted participant's
    /// frame is accepted and ignored.
    ///
    /// # Errors
    ///
    /// [`MixError::NoSuchParticipant`], [`MixError::LengthMismatch`] (not
    /// the length given to `begin`), [`MixError::AlreadyAdded`].
    pub fn add(&mut self, participant: usize, pcm: &[i16]) -> Result<(), MixError> {
        let added = self
            .added
            .get_mut(participant)
            .ok_or(MixError::NoSuchParticipant)?;
        if *added {
            return Err(MixError::AlreadyAdded);
        }
        if pcm.len() != self.len {
            return Err(MixError::LengthMismatch);
        }
        if self.muted.get(participant).copied().unwrap_or(true) {
            return Ok(());
        }
        let g = self.gain_q8.get(participant).copied().unwrap_or(0);
        let own = self
            .own
            .get_mut(participant)
            .and_then(|o| o.get_mut(..pcm.len()))
            .ok_or(MixError::NoSuchParticipant)?;
        own.copy_from_slice(pcm);
        *added = true;
        for (s, &x) in self.sum.iter_mut().zip(pcm) {
            *s = s.wrapping_add(Self::scaled(x, g));
        }
        Ok(())
    }

    /// What `participant` hears: the sum without its own contribution,
    /// limited into `out` (the first `frame_len` samples). Each listener
    /// needs its own `limiter`, kept across frames.
    ///
    /// # Errors
    ///
    /// [`MixError::NoSuchParticipant`], or [`MixError::LengthMismatch`]
    /// if `out` is shorter than the frame.
    pub fn output_for(
        &self,
        participant: usize,
        out: &mut [i16],
        limiter: &mut Limiter,
    ) -> Result<(), MixError> {
        self.output_for_with(participant, (&[], UNITY_Q8), out, limiter)
    }

    /// [`Mixer::output_for`] with `extra` (at gain `extra.1`, Q8) added
    /// for this listener only, before its limiter: what only it hears (a
    /// supervisor's whisper, kept out of the sum). An `extra` shorter than
    /// the frame is followed by silence.
    ///
    /// # Errors
    ///
    /// As [`Mixer::output_for`].
    pub fn output_for_with(
        &self,
        participant: usize,
        extra: (&[i16], u16),
        out: &mut [i16],
        limiter: &mut Limiter,
    ) -> Result<(), MixError> {
        let added = *self
            .added
            .get(participant)
            .ok_or(MixError::NoSuchParticipant)?;
        let out = out.get_mut(..self.len).ok_or(MixError::LengthMismatch)?;
        let sum = self.sum.get(..self.len).unwrap_or(&[]);
        let mut others = [0i32; MAX_FRAME];
        let others = others.get_mut(..self.len).unwrap_or(&mut []);
        others.copy_from_slice(sum);
        if added {
            let g = self.gain_q8.get(participant).copied().unwrap_or(0);
            let own = self
                .own
                .get(participant)
                .map_or(&[][..], <[i16; MAX_FRAME]>::as_slice);
            for (o, &x) in others.iter_mut().zip(own) {
                *o = o.wrapping_sub(Self::scaled(x, g));
            }
        }
        for (o, &x) in others.iter_mut().zip(extra.0) {
            *o = o.wrapping_add(Self::scaled(x, extra.1));
        }
        limiter.process(others, out);
        Ok(())
    }

    /// The raw `i32` sum of every contribution this frame.
    #[must_use]
    pub fn sum(&self) -> &[i32] {
        self.sum.get(..self.len).unwrap_or(&[])
    }
}

impl<const P: usize> Default for Mixer<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    #[test]
    fn a_whisper_reaches_only_its_listener() {
        let mut m: Mixer<3> = Mixer::new();
        m.begin(4).unwrap();
        // 0 talks, 1 listens; the supervisor's frame is the extra, not
        // added to the sum.
        m.add(0, &[1000; 4]).unwrap();
        m.add(1, &[0; 4]).unwrap();
        let whisper = [500i16; 4];
        let mut lim = Limiter::with_params(32000, 1, 1);
        let mut out = [0i16; 4];
        m.output_for_with(1, (&whisper, UNITY_Q8), &mut out, &mut lim)
            .unwrap();
        assert_eq!(out, [1500; 4], "the agent hears the talker and the whisper");
        let mut lim0 = Limiter::with_params(32000, 1, 1);
        m.output_for(0, &mut out, &mut lim0).unwrap();
        assert_eq!(out, [0; 4], "the talker does not hear the whisper");
    }

    extern crate std;
    use super::super::Rate;
    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;

    fn lim() -> Limiter {
        Limiter::new(Rate::Hz8000)
    }

    #[test]
    fn two_participants_hear_each_other() {
        let mut m: Mixer<2> = Mixer::new();
        m.begin(4).unwrap();
        m.add(0, &[1, 2, 3, 4]).unwrap();
        m.add(1, &[-10, 20, -30, 40]).unwrap();
        let mut out = [0i16; 4];
        m.output_for(0, &mut out, &mut lim()).unwrap();
        assert_eq!(out, [-10, 20, -30, 40]);
        m.output_for(1, &mut out, &mut lim()).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(m.sum(), &[-9, 22, -27, 44]);
    }

    #[test]
    fn three_with_one_missing() {
        let mut m: Mixer<3> = Mixer::new();
        m.begin(3).unwrap();
        m.add(0, &[100, 100, 100]).unwrap();
        m.add(2, &[5, 6, 7]).unwrap();
        let mut out = [0i16; 3];
        m.output_for(1, &mut out, &mut lim()).unwrap();
        assert_eq!(out, [105, 106, 107]);
        m.output_for(0, &mut out, &mut lim()).unwrap();
        assert_eq!(out, [5, 6, 7]);
        m.output_for(2, &mut out, &mut lim()).unwrap();
        assert_eq!(out, [100, 100, 100]);
    }

    #[test]
    fn n_participants_against_reference() {
        const P: usize = 9;
        let mut m: Box<Mixer<P>> = Box::default();
        let mut seed = 3u32;
        let frames: Vec<Vec<i16>> = (0..P)
            .map(|_| {
                (0..160)
                    .map(|_| {
                        seed = seed.wrapping_mul(69069).wrapping_add(1);
                        (seed >> 20) as i16 - 2048
                    })
                    .collect()
            })
            .collect();
        m.set_gain_q8(3, 128).unwrap();
        m.set_muted(5, true).unwrap();
        m.begin(160).unwrap();
        for (p, f) in frames.iter().enumerate() {
            m.add(p, f).unwrap();
        }
        for me in 0..P {
            let mut out = [0i16; 160];
            m.output_for(me, &mut out, &mut lim()).unwrap();
            for i in 0..160 {
                let want: i32 = (0..P)
                    .filter(|&p| p != me && p != 5)
                    .map(|p| {
                        let g = if p == 3 { 128 } else { 256 };
                        (i32::from(frames[p][i]) * g) >> 8
                    })
                    .sum();
                assert_eq!(i32::from(out[i]), want, "listener {me} sample {i}");
            }
        }
    }

    #[test]
    fn full_scale_64_no_overflow_and_limited() {
        const P: usize = 64;
        let mut m: Box<Mixer<P>> = Box::default();
        m.begin(MAX_FRAME).unwrap();
        let loud = [i16::MIN; MAX_FRAME];
        for p in 0..P {
            m.set_gain_q8(p, u16::MAX).unwrap();
            m.add(p, &loud).unwrap();
        }
        let want = i64::from(i16::MIN) * i64::from(u16::MAX) / 256 * P as i64;
        assert!(m.sum().iter().all(|&s| i64::from(s) == want));
        let mut out = [0i16; MAX_FRAME];
        let mut l = lim();
        m.output_for(0, &mut out, &mut l).unwrap();
        assert!(out.iter().all(|&v| (-32_000..0).contains(&v)));
        // Self excluded exactly, even at full scale: a lone talker hears
        // exact silence.
        let mut m2: Box<Mixer<P>> = Box::default();
        m2.begin(MAX_FRAME).unwrap();
        m2.add(7, &loud).unwrap();
        m2.output_for(7, &mut out, &mut lim()).unwrap();
        assert!(out.iter().all(|&v| v == 0));
    }

    #[test]
    fn errors() {
        let mut m: Mixer<2> = Mixer::new();
        assert_eq!(m.begin(MAX_FRAME + 1), Err(MixError::TooLong));
        m.begin(2).unwrap();
        assert_eq!(m.frame_len(), 2);
        assert_eq!(m.add(2, &[0, 0]), Err(MixError::NoSuchParticipant));
        assert_eq!(m.add(0, &[0]), Err(MixError::LengthMismatch));
        assert_eq!(m.add(0, &[0, 0, 0]), Err(MixError::LengthMismatch));
        m.add(0, &[1, 1]).unwrap();
        assert_eq!(m.add(0, &[1, 1]), Err(MixError::AlreadyAdded));
        assert_eq!(m.set_gain_q8(0, 3), Err(MixError::AlreadyAdded));
        assert_eq!(m.set_gain_q8(9, 3), Err(MixError::NoSuchParticipant));
        assert_eq!(m.set_muted(9, true), Err(MixError::NoSuchParticipant));
        let mut short = [0i16; 1];
        assert_eq!(
            m.output_for(1, &mut short, &mut lim()),
            Err(MixError::LengthMismatch)
        );
        assert_eq!(
            m.output_for(2, &mut [0; 2], &mut lim()),
            Err(MixError::NoSuchParticipant)
        );
        // A longer output buffer: only the frame is written.
        let mut long = [9i16; 4];
        m.output_for(1, &mut long, &mut lim()).unwrap();
        assert_eq!(long, [1, 1, 9, 9]);
        // Empty frames.
        m.begin(0).unwrap();
        m.add(0, &[]).unwrap();
        m.output_for(0, &mut [], &mut lim()).unwrap();
        // Next frame clears the sum.
        m.begin(2).unwrap();
        assert_eq!(m.sum(), &[0, 0]);
        let _: Mixer<1> = Mixer::default();
    }
}
