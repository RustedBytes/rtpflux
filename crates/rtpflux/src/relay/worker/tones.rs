//! `play DTMF`: telephone events (RFC 4733) or in-band dual tones (G.711)
//! sent to one side of a call, as if the other side had pressed the keys.
//!
//! Like an announcement ([`super::features`]), the tones go out on the
//! slot's own RTP stream (its SSRC, sequence numbers and timestamps go on
//! from one announcement or set of tones to the next, so SRTP never
//! encrypts twice at one index), paced at 20 ms, while the other side's
//! media to that slot is held back.
//!
//! An event (RFC 4733 §2.5.1): one timestamp for the whole tone, the
//! marker bit on its first packet, a packet every 20 ms with the duration
//! so far, and the end bit on three final packets. In-band (RFC 3551 §4.5.14
//! G.711): the key's two frequencies (ITU-T Q.23), half the level each,
//! then silence for the pause.

use super::features::{BLOCK_PLAY, Kind, PLAY_FRAME, PlayStream};
#[allow(clippy::wildcard_imports)]
use super::*;
use rtpflux_core::rtp::Pt;

/// How the tones reach the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToneMode {
    /// Telephone events of payload type `pt`, RTP clock `rate`.
    Event { pt: Pt, rate: u32 },
    /// Dual tones in the listener's audio: payload type `pt` of `codec`
    /// (G.711 as it is, any other codec the relay encodes through its
    /// encoder).
    Inband { pt: Pt, codec: crate::relay::Codec },
}

/// The encoder of tones in a codec other than G.711: 8 kHz tones, made
/// 16 kHz for a wideband codec.
struct ToneCoder {
    encoder: crate::codec::Encoder,
    up: Option<crate::codec::Resampler>,
}

impl core::fmt::Debug for ToneCoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ToneCoder({:?})", self.encoder)
    }
}

impl ToneCoder {
    /// For tones in `codec`; `None` for G.711 (encoded directly) or a codec
    /// the relay does not encode.
    fn new(codec: crate::relay::Codec) -> Option<Box<Self>> {
        use crate::relay::Codec;
        if matches!(codec, Codec::Pcmu | Codec::Pcma) {
            return None;
        }
        let encoder = crate::codec::Encoder::new(codec, 8000)?;
        let up = match encoder.rate() {
            8000 => None,
            rate => Some(crate::codec::Resampler::new(8000, rate)?),
        };
        Some(Box::new(ToneCoder { encoder, up }))
    }

    /// Encode 20 ms of 8 kHz `pcm` into `out`.
    fn encode(&mut self, pcm: &[i16; PLAY_FRAME], out: &mut [u8]) -> Option<usize> {
        match &mut self.up {
            None => self.encoder.encode(pcm, out),
            Some(up) => {
                let mut wide = [0i16; 2 * PLAY_FRAME];
                let n = up.process(pcm, &mut wide)?;
                self.encoder.encode(&wide[..n], out)
            }
        }
    }
}

/// Keys to play: event codes (0–9, 10 `*`, 11 `#`, 12–15 A–D), each
/// `duration_ms` long and `pause_ms` from the next, at `volume` (the level
/// below 0 dBm0, 0–63).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tones {
    pub codes: Vec<u8>,
    pub duration_ms: u32,
    pub pause_ms: u32,
    pub volume: u8,
    pub mode: ToneMode,
    /// The frequency (Hz) of the sine code (17) in `codes`.
    pub sine_hz: u16,
}

/// A code of [`Tones`] that is silence (in-band), not a key.
pub const SILENCE: u8 = 16;
/// A code of [`Tones`] that is one sine at [`Tones::sine_hz`] (in-band).
pub const SINE: u8 = 17;

/// End packets per event (RFC 4733 §2.5.1.4: three).
const ENDS: u8 = 3;

/// Tones in progress towards RTP slot `slot`; `other`'s media to it is
/// held back meanwhile.
#[derive(Debug)]
pub(super) struct TonePlayback {
    pub(super) call: CallId,
    pub(super) slot: Slot,
    other: Slot,
    tones: Tones,
    /// The key being played, and how far into it (with its pause).
    key: usize,
    elapsed_ms: u32,
    ends_sent: u8,
    /// The current event's timestamp.
    event_ts: u32,
    pub(super) next_ms: u64,
    /// A key held for as long as the source holds it (DTMF transcoding):
    /// its length is set when it is released.
    live: bool,
    /// Tones in a codec other than G.711: its encoder.
    coder: Option<Box<ToneCoder>>,
}

impl TonePlayback {
    /// Keys played as audio (not as telephone events), with some still to
    /// send.
    pub(super) fn inband(&self) -> bool {
        matches!(self.tones.mode, ToneMode::Inband { .. }) && self.key < self.tones.codes.len()
    }

    /// The clock rate of what it sends.
    fn clock(&self) -> u32 {
        match self.tones.mode {
            ToneMode::Event { rate, .. } => rate,
            ToneMode::Inband { codec, .. } => codec.clock(),
        }
    }
}

/// A live key's length until it is released.
const HELD_MS: u32 = 60_000;

/// The two frequencies of an event code (ITU-T Q.23), if a key.
#[must_use]
pub fn frequencies(code: u8) -> Option<(f64, f64)> {
    const LOW: [f64; 4] = [697.0, 770.0, 852.0, 941.0];
    const HIGH: [f64; 4] = [1209.0, 1336.0, 1477.0, 1633.0];
    // (row, column) of each code: 0-9, *, #, A-D.
    let (r, c) = match code {
        0 => (3, 1),
        1..=9 => ((code - 1) / 3, (code - 1) % 3),
        10 => (3, 0),
        11 => (3, 2),
        12..=15 => (code - 12, 3),
        _ => return None,
    };
    Some((LOW[usize::from(r)], HIGH[usize::from(c)]))
}

impl Worker {
    /// Start playing `tones` to leg `leg` of `call`, replacing
    /// any tones already playing to it.
    pub(super) fn play_tones(&mut self, call: CallId, leg: CallLeg, tones: Tones) {
        let Some(c) = self.calls.get(&call) else {
            return;
        };
        let (to, other) = if leg == CallLeg::B {
            (c.slots[2], c.slots[0])
        } else {
            (c.slots[0], c.slots[2])
        };
        self.start_tones(call, to, other, tones, false);
    }

    /// Start a key held at slot `other` towards slot `to` (DTMF
    /// transcoding), until [`Worker::live_tone_end`].
    pub(super) fn live_tone_start(
        &mut self,
        call: CallId,
        to: Slot,
        other: Slot,
        code: u8,
        volume: u8,
        mode: ToneMode,
    ) {
        self.live_sound_start(call, (to, other), (code, 0), volume, mode);
    }

    /// As [`Worker::live_tone_start`], for a key or [`SILENCE`], or
    /// [`SINE`] at `sine_hz`.
    pub(super) fn live_sound_start(
        &mut self,
        call: CallId,
        (to, other): (Slot, Slot),
        (code, sine_hz): (u8, u16),
        volume: u8,
        mode: ToneMode,
    ) {
        let tones = Tones {
            codes: vec![code],
            duration_ms: HELD_MS,
            pause_ms: 0,
            volume: volume.min(63),
            mode,
            sine_hz,
        };
        self.start_tones(call, to, other, tones, true);
    }

    /// Play `tones` from slot `other` towards slot `to` (DTMF delay).
    pub(super) fn tones_to(&mut self, call: CallId, (to, other): (Slot, Slot), tones: Tones) {
        self.start_tones(call, to, other, tones, false);
    }

    /// The key held towards slot `to` was released: it ends now (at least
    /// 40 ms long; an event gets its end packets).
    pub(super) fn live_tone_end(&mut self, to: Slot) {
        for t in self
            .tone_plays
            .iter_mut()
            .filter(|t| t.slot == to && t.live)
        {
            t.tones.duration_ms = t.elapsed_ms.div_ceil(20).max(2) * 20;
            t.live = false;
        }
    }

    fn start_tones(&mut self, call: CallId, to: Slot, other: Slot, tones: Tones, live: bool) {
        if tones.codes.is_empty() {
            return;
        }
        self.tone_plays.retain(|t| t.slot != to);
        self.hold.start(Kind::Keys, to.index());
        if let Some(b) = self.blocked.get_mut(other) {
            *b |= BLOCK_PLAY;
        }
        self.refresh_offload(call);
        let now = self.now_ms();
        if let Some(s) = self.play_streams.get_mut(to)
            && s.is_none()
        {
            *s = Some(super::features::random_stream(now));
        }
        // Set at each key's first packet.
        let event_ts = 0;
        // In-band keys over an announcement take its place in time: they
        // start at its next packet (it has sent this instant's already).
        let inband = matches!(tones.mode, ToneMode::Inband { .. });
        let next_ms = self
            .playbacks
            .iter()
            .find(|p| p.slot == to && inband)
            .map_or(now, |p| p.next_ms.max(now));
        let coder = match tones.mode {
            ToneMode::Inband { codec, .. } => ToneCoder::new(codec),
            ToneMode::Event { .. } => None,
        };
        self.tone_plays.push(TonePlayback {
            call,
            slot: to,
            other,
            tones,
            key: 0,
            elapsed_ms: 0,
            ends_sent: 0,
            event_ts,
            next_ms,
            live,
            coder,
        });
    }

    /// Send the tone packets that are due; finish what has played out.
    pub(super) fn tones_due(&mut self, now: u64) {
        let mut k = 0;
        while k < self.tone_plays.len() {
            if self.tone_plays[k].next_ms > now {
                k += 1;
                continue;
            }
            if self.tone_plays[k].key >= self.tone_plays[k].tones.codes.len() {
                let t = self.tone_plays.swap_remove(k);
                // An announcement to the same slot keeps the hold.
                self.end_play(Kind::Keys, t.slot, t.other, t.call);
                continue;
            }
            let slot = self.tone_plays[k].slot;
            let due = self.tone_plays[k].next_ms;
            let per_ms = self.tone_plays[k].clock() / 1000;
            let Some(Some(s)) = self.play_streams.get_mut(slot) else {
                let t = self.tone_plays.swap_remove(k);
                self.end_play(Kind::Keys, t.slot, t.other, t.call);
                continue;
            };
            s.advance(due, per_ms.max(1));
            let stream = *s;
            if self.tone_plays[k].elapsed_ms == 0 {
                // A key's events carry the time it started (RFC 4733 §2.5.1.2).
                self.tone_plays[k].event_ts = stream.ts;
            }
            let len = self.tone_packet(k, stream);
            if len.is_some()
                && let Some(Some(s)) = self.play_streams.get_mut(slot)
            {
                s.take_seq();
            }
            let t = &mut self.tone_plays[k];
            let total = t.tones.duration_ms + t.tones.pause_ms;
            t.elapsed_ms += 20;
            let event_done = matches!(t.tones.mode, ToneMode::Inband { .. }) || t.ends_sent >= ENDS;
            if t.elapsed_ms >= total && event_done {
                t.key += 1;
                t.elapsed_ms = 0;
                t.ends_sent = 0;
            }
            // Paced at 20 ms; after a stall, start again from now.
            t.next_ms = if now > t.next_ms + 100 {
                now + 20
            } else {
                t.next_ms + 20
            };
            k += 1;
            let Some(len) = len else {
                continue;
            };
            let Some(dst) = self
                .legs
                .get(slot)
                .copied()
                .flatten()
                .and_then(|l| l.latch.target())
            else {
                continue;
            };
            let (send_slot, len) = self.outbound(slot, 0, len);
            if let Some(len) = len {
                self.send(send_slot, &[(slot, Some(dst), 0, len)]);
            }
        }
    }

    /// Write tone playback `k`'s next packet at the start of the buffers;
    /// its length, or `None` when nothing is sent this time (an event's
    /// pause).
    fn tone_packet(&mut self, k: usize, stream: PlayStream) -> Option<usize> {
        let play = &mut self.tone_plays[k];
        let code = play.tones.codes[play.key];
        let (duration_ms, elapsed) = (play.tones.duration_ms, play.elapsed_ms);
        let buf = &mut self.bufs[..12 + PLAY_FRAME];
        buf[0] = 0x80;
        buf[2..4].copy_from_slice(&stream.seq.to_be_bytes());
        buf[8..12].copy_from_slice(&stream.ssrc.to_be_bytes());
        match play.tones.mode {
            ToneMode::Event { pt, rate } => {
                let end = elapsed >= duration_ms;
                if end && play.ends_sent >= ENDS {
                    return None;
                }
                let ms = if end { duration_ms } else { elapsed + 20 };
                let duration =
                    u16::try_from(u64::from(rate) * u64::from(ms) / 1000).unwrap_or(u16::MAX);
                buf[1] = pt.header_octet(elapsed == 0);
                buf[4..8].copy_from_slice(&play.event_ts.to_be_bytes());
                buf[12] = code;
                buf[13] = (play.tones.volume & 0x3f) | if end { 0x80 } else { 0 };
                buf[14..16].copy_from_slice(&duration.to_be_bytes());
                if end {
                    play.ends_sent += 1;
                }
                Some(16)
            }
            ToneMode::Inband { pt, .. } => {
                buf[1] = pt.header_octet(elapsed == 0 && play.key == 0);
                buf[4..8].copy_from_slice(&stream.ts.to_be_bytes());
                let tone = if elapsed >= duration_ms {
                    None
                } else if code == SINE {
                    // One sine: both "halves" at its frequency.
                    let hz = f64::from(play.tones.sine_hz);
                    Some((hz, hz))
                } else {
                    frequencies(code)
                };
                // 20 ms at 8 kHz: the key's two frequencies, or silence.
                let mut pcm = [0i16; PLAY_FRAME];
                if let Some((f1, f2)) = tone {
                    // Each frequency half the level: `volume` below 0 dBm0
                    // together (0 dBm0 is 3.17 dB below a full-scale sine).
                    let amp =
                        32_768.0 * 10f64.powf((-f64::from(play.tones.volume) - 3.17 - 6.02) / 20.0);
                    for (i, v) in pcm.iter_mut().enumerate() {
                        #[allow(clippy::cast_precision_loss)]
                        let s = f64::from(elapsed * 8) + i as f64;
                        let x = s / 8000.0 * 2.0 * core::f64::consts::PI;
                        #[allow(clippy::cast_possible_truncation)]
                        let sample = (amp * ((f1 * x).sin() + (f2 * x).sin())) as i16;
                        *v = sample;
                    }
                }
                if let Some(coder) = play.coder.as_mut() {
                    let n = coder.encode(&pcm, &mut self.bufs[12..12 + 4 * PLAY_FRAME])?;
                    return Some(12 + n);
                }
                let codes = &mut buf[12..12 + PLAY_FRAME];
                for (c, &v) in codes.iter_mut().zip(&pcm) {
                    *c = if pt == rtpflux_core::g711::PT_PCMA {
                        rtpflux_core::g711::linear_to_alaw(v)
                    } else {
                        rtpflux_core::g711::linear_to_ulaw(v)
                    };
                }
                Some(12 + PLAY_FRAME)
            }
        }
    }

    pub(super) fn next_tone_ms(&self) -> Option<u64> {
        self.tone_plays.iter().map(|t| t.next_ms).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_their_frequencies() {
        assert_eq!(frequencies(1), Some((697.0, 1209.0)));
        assert_eq!(frequencies(5), Some((770.0, 1336.0)));
        assert_eq!(frequencies(9), Some((852.0, 1477.0)));
        assert_eq!(frequencies(0), Some((941.0, 1336.0)));
        assert_eq!(frequencies(10), Some((941.0, 1209.0)), "*");
        assert_eq!(frequencies(11), Some((941.0, 1477.0)), "#");
        assert_eq!(frequencies(12), Some((697.0, 1633.0)), "A");
        assert_eq!(frequencies(15), Some((941.0, 1633.0)), "D");
        assert_eq!(frequencies(16), None);
    }

    /// 20 ms of key `code` at `volume` dB below 0 dBm0 through G.711 μ-law,
    /// as the tone player makes it.
    fn frame(code: u8, volume: f64, at: usize) -> [i16; 160] {
        let (f1, f2) = frequencies(code).unwrap();
        let amp = 32_768.0 * 10f64.powf((-volume - 3.17 - 6.02) / 20.0);
        let mut out = [0i16; 160];
        for (i, o) in out.iter_mut().enumerate() {
            #[allow(clippy::cast_precision_loss)]
            let x = (at * 160 + i) as f64 / 8000.0 * 2.0 * core::f64::consts::PI;
            #[allow(clippy::cast_possible_truncation)]
            let v = (amp * ((f1 * x).sin() + (f2 * x).sin())) as i16;
            *o = rtpflux_core::g711::ulaw_to_linear(rtpflux_core::g711::linear_to_ulaw(v));
        }
        out
    }

    #[test]
    fn inband_keys_are_detected() {
        use rtpflux_core::dtmf_inband::{Change, Detector, key_of};
        for code in 0..16 {
            for volume in [0.0, 8.0, 20.0, 30.0] {
                assert_eq!(
                    key_of(&frame(code, volume, 3)),
                    Some(code),
                    "{code} at -{volume}"
                );
            }
        }
        // Two frames to start, two to end.
        let mut d = Detector::new();
        assert_eq!(d.frame(&frame(5, 8.0, 0)), None);
        assert_eq!(d.frame(&frame(5, 8.0, 1)), Some(Change::Start(5)));
        assert_eq!(d.frame(&frame(5, 8.0, 2)), None);
        assert_eq!(d.frame(&[0; 160]), None);
        assert_eq!(d.frame(&[0; 160]), Some(Change::End));
        // A single tone, noise or silence is no key.
        let single: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let v = (8000.0
                    * (f64::from(i) / 8000.0 * 2.0 * core::f64::consts::PI * 770.0).sin())
                    as i16;
                v
            })
            .collect();
        assert_eq!(key_of(&single), None);
        let mut seed = 7u32;
        let noise: Vec<i16> = (0..160)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let v = (seed >> 16) as i16 / 4;
                v
            })
            .collect();
        assert_eq!(key_of(&noise), None);
        assert_eq!(key_of(&[0; 160]), None);
    }
}
