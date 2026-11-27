//! Energy-based voice activity detection with an adaptive noise floor and
//! hangover.
//!
//! Each frame's energy is its mean square (sample²). A frame is *active*
//! when its energy is at least [`VadParams::ratio`] times the noise floor
//! and at least [`VadParams::min_energy`]. The noise floor follows the
//! quiet: a frame below it pulls it halfway down at once, any other frame
//! lets it rise slowly (by a factor of e^(t/[`VadParams::rise_s`]) over t
//! seconds of audio), so a lasting change of background level is learnt
//! within seconds while speech is not. Speech starts after
//! [`VadParams::onset_ms`] of active frames in a row, and ends after
//! [`VadParams::hangover_ms`] of inactive frames in a row; the times are
//! counted in samples, so frames of any length work.

use super::Rate;

/// Detector tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VadParams {
    /// Active audio needed to start speech, in milliseconds (default 30).
    pub onset_ms: u32,
    /// Inactive audio needed to end speech, in milliseconds (default 300).
    pub hangover_ms: u32,
    /// Energy over noise floor for an active frame, as a power ratio
    /// (default 8: about 9 dB).
    pub ratio: u32,
    /// The least mean square of an active frame (default 10 000: RMS 100,
    /// about −50 dBFS), so near-silence never counts.
    pub min_energy: u64,
    /// Time constant of the noise floor's rise, in seconds (default 5:
    /// about +0.9 dB per second).
    pub rise_s: u32,
}

impl VadParams {
    /// The defaults.
    pub const DEFAULT: VadParams = VadParams {
        onset_ms: 30,
        hangover_ms: 300,
        ratio: 8,
        min_energy: 10_000,
        rise_s: 5,
    };
}

impl Default for VadParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a frame changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadEvent {
    /// No change.
    None,
    /// Speech started with this frame.
    SpeechStarted,
    /// Speech ended with this frame (the hangover ran out).
    SpeechEnded,
}

/// Voice activity state of one stream.
#[derive(Debug, Clone, Copy)]
pub struct Vad {
    params: VadParams,
    rate: u32,
    /// Noise floor (mean square); `None` before the first frame.
    floor: Option<u64>,
    speech: bool,
    /// Samples of active audio in a row (while silent) or of inactive
    /// audio in a row (while speaking).
    run: u64,
    onset: u64,
    hangover: u64,
}

impl Vad {
    /// A detector for audio at `rate`, with [`VadParams::DEFAULT`].
    #[must_use]
    pub const fn new(rate: Rate) -> Self {
        Self::with_params(rate, VadParams::DEFAULT)
    }

    /// A detector with the given tuning.
    #[must_use]
    pub const fn with_params(rate: Rate, params: VadParams) -> Self {
        Vad {
            params,
            rate: rate.hz(),
            floor: None,
            speech: false,
            run: 0,
            onset: rate.samples(params.onset_ms) as u64,
            hangover: rate.samples(params.hangover_ms) as u64,
        }
    }

    /// Whether speech is going on.
    #[must_use]
    pub const fn speaking(&self) -> bool {
        self.speech
    }

    /// The noise floor (mean square), once a frame has been seen.
    #[must_use]
    pub const fn noise_floor(&self) -> Option<u64> {
        self.floor
    }

    /// Forget the stream.
    pub fn reset(&mut self) {
        self.floor = None;
        self.speech = false;
        self.run = 0;
    }

    /// The mean square of `pcm` (0 when empty).
    #[must_use]
    pub fn energy(pcm: &[i16]) -> u64 {
        let sum = pcm.iter().fold(0u64, |a, &v| {
            let v = u64::from(v.unsigned_abs());
            a.saturating_add(v.wrapping_mul(v))
        });
        sum.checked_div(pcm.len() as u64).unwrap_or(0)
    }

    /// Feed one frame (any length; an empty one changes nothing).
    pub fn frame(&mut self, pcm: &[i16]) -> VadEvent {
        if pcm.is_empty() {
            return VadEvent::None;
        }
        let n = pcm.len() as u64;
        let e = Self::energy(pcm);
        // Before the first frame the floor is the least active energy's:
        // a stream that starts with speech is heard as speech, not taken
        // for its noise.
        let floor = self.floor.unwrap_or(self.params.min_energy);
        let active =
            e >= self.params.min_energy && e >= floor.saturating_mul(u64::from(self.params.ratio));
        // Adapt the floor: halfway down at once, slowly up.
        let floor = if e < floor {
            floor.wrapping_sub(floor.wrapping_sub(e) / 2)
        } else {
            let span = u64::from(self.rate).saturating_mul(u64::from(self.params.rise_s));
            let up = floor
                .saturating_mul(n)
                .checked_div(span)
                .unwrap_or(0)
                .max(1);
            floor.saturating_add(up).min(e)
        };
        self.floor = Some(floor);
        if active == self.speech {
            self.run = 0;
            return VadEvent::None;
        }
        self.run = self.run.saturating_add(n);
        if !self.speech && self.run >= self.onset {
            self.speech = true;
            self.run = 0;
            return VadEvent::SpeechStarted;
        }
        if self.speech && self.run >= self.hangover {
            self.speech = false;
            self.run = 0;
            return VadEvent::SpeechEnded;
        }
        VadEvent::None
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
    extern crate std;
    use super::super::testutil::sine;
    use super::*;

    fn noise(out: &mut [i16], amp: i32, seed: &mut u32) {
        for v in out {
            *seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            *v = ((((*seed >> 16) & 0x7fff) as i32 - 16384) * amp / 16384) as i16;
        }
    }

    #[test]
    fn speech_in_noise_starts_and_ends() {
        let mut v = Vad::new(Rate::Hz8000);
        let mut seed = 1;
        let mut f = [0i16; 160];
        // 1 s of background noise (RMS ~ 115).
        for _ in 0..50 {
            noise(&mut f, 200, &mut seed);
            assert_eq!(v.frame(&f), VadEvent::None);
        }
        assert!(!v.speaking());
        // Speech-level tone: onset 30 ms = second 20 ms frame.
        let mut events = std::vec::Vec::new();
        for k in 0..25 {
            sine(&mut f, 440.0, 8000.0, 8000.0, k * 160);
            events.push(v.frame(&f));
        }
        assert_eq!(events[0], VadEvent::None);
        assert_eq!(events[1], VadEvent::SpeechStarted);
        assert!(events[2..].iter().all(|&e| e == VadEvent::None));
        assert!(v.speaking());
        // Back to noise: ends after 300 ms (15 frames).
        let mut ended = None;
        for k in 0..30 {
            noise(&mut f, 200, &mut seed);
            if v.frame(&f) == VadEvent::SpeechEnded {
                ended = Some(k);
                break;
            }
        }
        assert_eq!(ended, Some(14));
        assert!(!v.speaking());
    }

    #[test]
    fn short_bursts_and_short_pauses_are_ignored() {
        let mut v = Vad::new(Rate::Hz16000);
        let quiet = [0i16; 160];
        let mut loud = [0i16; 160];
        sine(&mut loud, 300.0, 16000.0, 10000.0, 0);
        for _ in 0..10 {
            v.frame(&quiet);
        }
        // 10 ms frames: a 20 ms burst is below the 30 ms onset.
        v.frame(&loud);
        v.frame(&loud);
        v.frame(&quiet);
        assert!(!v.speaking());
        assert_eq!(v.frame(&loud), VadEvent::None);
        assert_eq!(v.frame(&loud), VadEvent::None);
        assert_eq!(v.frame(&loud), VadEvent::SpeechStarted);
        // A 200 ms pause does not end it.
        for _ in 0..20 {
            assert_eq!(v.frame(&quiet), VadEvent::None);
        }
        assert_eq!(v.frame(&loud), VadEvent::None);
        assert!(v.speaking());
    }

    #[test]
    fn floor_learns_a_louder_background() {
        let mut v = Vad::new(Rate::Hz8000);
        let mut seed = 5;
        let mut f = [0i16; 160];
        noise(&mut f, 100, &mut seed);
        v.frame(&f);
        // A steady, louder noise: at first speech, then learnt as floor.
        let mut ended = false;
        for _ in 0..2000 {
            noise(&mut f, 2000, &mut seed);
            if v.frame(&f) == VadEvent::SpeechEnded {
                ended = true;
                break;
            }
        }
        assert!(ended);
        assert!(v.noise_floor().unwrap() > 100_000);
    }

    #[test]
    fn boundaries() {
        let mut v = Vad::new(Rate::Hz48000);
        assert_eq!(v.frame(&[]), VadEvent::None);
        assert_eq!(v.noise_floor(), None);
        assert_eq!(Vad::energy(&[]), 0);
        assert_eq!(Vad::energy(&[i16::MIN; 960]), 1 << 30);
        // Full scale from the start is active (the floor starts at the
        // least active energy): speech once the onset has passed, once.
        let f = [i16::MIN; 960];
        let started = (0..100)
            .filter(|_| v.frame(&f) == VadEvent::SpeechStarted)
            .count();
        assert_eq!(started, 1);
        // Silence never speaks.
        let mut s = Vad::with_params(
            Rate::Hz8000,
            VadParams {
                onset_ms: 0,
                ..VadParams::default()
            },
        );
        for _ in 0..10 {
            assert_eq!(s.frame(&[0; 160]), VadEvent::None);
        }
        s.reset();
        assert!(!s.speaking());
    }
}

#[cfg(test)]
mod start_tests {
    use super::*;

    #[test]
    fn a_stream_that_starts_with_speech_is_speech() {
        let mut v = Vad::new(Rate::Hz8000);
        let loud: [i16; 160] = core::array::from_fn(|i| if i % 2 == 0 { 8000 } else { -8000 });
        let events: [VadEvent; 3] = core::array::from_fn(|_| v.frame(&loud));
        assert!(events.contains(&VadEvent::SpeechStarted), "{events:?}");
    }
}
