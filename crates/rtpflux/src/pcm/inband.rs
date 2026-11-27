//! Key presses in decoded audio (in-band DTMF), for the endpoints whose
//! audio a PCM stream or a mixer decodes anyway: the audio is brought to
//! 8 kHz, cut into 20 ms frames and run through the Goertzel detector of
//! `rtpflux_core::dtmf_inband`. A key is reported when it ends. Detection
//! takes two frames to start and two to end: a key is reported 40 ms after
//! it is released (plus the jitter buffer's delay), and keys shorter than
//! 40 ms are not seen.

use rtpflux_core::dsp::resample::Resampler;
use rtpflux_core::dtmf_inband::{Change, Detector, FRAME};

/// A key press that ended: its event code and how long it was held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub code: u8,
    pub duration_ms: u32,
}

/// One endpoint's in-band key detection.
pub struct Keys {
    narrow: Option<Resampler>,
    buf: Vec<i16>,
    pending: Vec<i16>,
    detector: Detector,
    /// The key held, and for how many frames.
    held: Option<(u8, u32)>,
}

impl Keys {
    /// Detection on audio at `rate` (8, 16, 24 or 48 kHz); `None` for
    /// another rate.
    #[must_use]
    pub fn new(rate: u32) -> Option<Self> {
        let narrow = if rate == 8000 {
            None
        } else {
            Some(Resampler::new(rate, 8000).ok()?)
        };
        Some(Keys {
            narrow,
            buf: vec![0; 4 * 960],
            pending: Vec::with_capacity(4 * FRAME),
            detector: Detector::new(),
            held: None,
        })
    }

    /// Feed `pcm` (at the rate given); the keys that ended in it.
    pub fn feed(&mut self, pcm: &[i16], ended: &mut Vec<Key>) {
        match &mut self.narrow {
            Some(r) => {
                for chunk in pcm.chunks(960) {
                    let n = r.process(chunk, &mut self.buf);
                    self.pending.extend_from_slice(&self.buf[..n]);
                }
            }
            None => self.pending.extend_from_slice(pcm),
        }
        while self.pending.len() >= FRAME {
            match self.detector.frame(&self.pending[..FRAME]) {
                Some(Change::Start(code)) => self.held = Some((code, 2)),
                Some(Change::End) => {
                    if let Some((code, frames)) = self.held.take() {
                        ended.push(Key {
                            code,
                            duration_ms: frames.saturating_mul(20),
                        });
                    }
                }
                None => {
                    if let Some((_, f)) = &mut self.held {
                        *f += 1;
                    }
                }
            }
            self.pending.drain(..FRAME);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tones of `code` (RFC 4733), `ms` long, at `rate`.
    fn tones(code: u8, ms: u32, rate: u32) -> Vec<i16> {
        let (row, col) = match code {
            5 => (770.0, 1336.0),
            11 => (941.0, 1477.0),
            _ => unreachable!(),
        };
        (0..rate / 1000 * ms)
            .map(|i| {
                let t = f64::from(i) / f64::from(rate);
                let v = 6000.0 * (2.0 * std::f64::consts::PI * row * t).sin()
                    + 6000.0 * (2.0 * std::f64::consts::PI * col * t).sin();
                #[allow(clippy::cast_possible_truncation)]
                let s = v as i16;
                s
            })
            .collect()
    }

    #[test]
    fn keys_are_found_at_every_rate_once_each() {
        for rate in [8000, 16_000, 48_000] {
            let mut k = Keys::new(rate).unwrap();
            let mut ended = Vec::new();
            let silence = vec![0i16; (rate / 1000 * 100) as usize];
            k.feed(&silence, &mut ended);
            k.feed(&tones(5, 200, rate), &mut ended);
            k.feed(&silence, &mut ended);
            k.feed(&tones(11, 100, rate), &mut ended);
            k.feed(&silence, &mut ended);
            let codes: Vec<u8> = ended.iter().map(|e| e.code).collect();
            assert_eq!(codes, [5, 11], "at {rate} Hz");
            assert!(
                (160..=260).contains(&ended[0].duration_ms),
                "{:?}",
                ended[0]
            );
        }
        assert!(Keys::new(11_025).is_none());
    }
}
