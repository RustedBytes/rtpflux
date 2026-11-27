//! What an endpoint sends, as linear audio at a chosen rate: its RTP
//! packets through a jitter buffer (reordering, duplicates, a 40 ms
//! target delay), its decoder, loss concealment, and a resampler. Used by
//! the threads of PCM streams and of mixers, never by a media worker.

use super::stream::RtpCopy;
use rtpflux_core::dsp::Rate;
use rtpflux_core::dsp::jitter::{JitterBuffer, Pop};
use rtpflux_core::dsp::plc::Plc;
use rtpflux_core::dsp::resample::Resampler;
use rtpflux_core::sdp::Codec;

/// The jitter buffer's slots, and its target delay (ms).
const SLOTS: usize = 64;
pub const DELAY_MS: u32 = 40;
/// The most samples one payload decodes to (120 ms at 48 kHz).
const MAX_DECODED: usize = 5760;

/// One endpoint's receive pipeline.
pub struct Receive {
    /// The audio's payload type: other packets are not audio.
    pt: u8,
    clock: u32,
    jitter: Box<JitterBuffer<SLOTS>>,
    decoder: crate::codec::Decoder,
    plc: Plc,
    resampler: Resampler,
    decoded: Vec<i16>,
    resampled: Vec<i16>,
    last_len: usize,
    ssrc: Option<u32>,
    /// Set when the stream restarted (another source): the next audio is
    /// discontinuous.
    pub restarted: bool,
}

impl Receive {
    /// A pipeline for `codec` (payload type `pt`) on RTP clock `clock`,
    /// giving audio at `rate`; `None` when the codec is not decoded or the
    /// rate is not one of 8, 16, 24 and 48 kHz.
    #[must_use]
    pub fn new(codec: Codec, clock: u32, rate: u32, pt: u8) -> Option<Self> {
        let decoder = crate::codec::Decoder::new(codec, 48_000)?;
        let from = Rate::from_hz(decoder.rate()).ok()?;
        let to = Rate::from_hz(rate).ok()?;
        let last_len = (decoder.rate() / 50) as usize;
        Some(Receive {
            pt,
            clock,
            jitter: Box::new(JitterBuffer::new(clock / 1000 * DELAY_MS)),
            decoder,
            plc: Plc::new(from),
            resampler: Resampler::between(from, to),
            decoded: vec![0; MAX_DECODED],
            resampled: vec![0; MAX_DECODED * 6],
            last_len,
            ssrc: None,
            restarted: true,
        })
    }

    /// A packet arrived (taken only if it is audio).
    pub fn push(&mut self, p: &RtpCopy) {
        if p.pt != self.pt {
            return;
        }
        if self.ssrc.is_some_and(|s| s != p.ssrc) {
            self.jitter.reset();
            self.plc.reset();
            self.restarted = true;
        }
        self.ssrc = Some(p.ssrc);
        let _ = self.jitter.push(p.seq, p.ts, p.marker, p.payload());
    }

    /// The audio due by `elapsed_ms` (since the pipeline's clock started),
    /// appended to `out`. Each call gives every packet due: a loss is
    /// concealed with one packet's worth.
    pub fn pull(&mut self, elapsed_ms: u64, out: &mut Vec<i16>) {
        let clock =
            u32::try_from(elapsed_ms.wrapping_mul(u64::from(self.clock)) / 1000 % (1 << 32))
                .unwrap_or(0);
        loop {
            let n = match self.jitter.pop(clock) {
                Pop::Packet { payload, .. } => {
                    let Some(n) = self.decoder.decode(payload, &mut self.decoded) else {
                        continue;
                    };
                    self.plc.good(&mut self.decoded[..n]);
                    self.last_len = n.max(1);
                    n
                }
                Pop::Missing { .. } => {
                    let n = self.last_len.min(self.decoded.len());
                    self.plc.conceal(&mut self.decoded[..n]);
                    n
                }
                Pop::Empty => break,
            };
            let m = self
                .resampler
                .process(&self.decoded[..n], &mut self.resampled);
            out.extend_from_slice(&self.resampled[..m]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G.711 packets in, out of order: the audio comes out in order, at the
    /// rate asked for, once the delay has passed.
    #[test]
    fn packets_become_audio_in_order() {
        let mut r = Receive::new(Codec::Pcmu, 8000, 16_000, 0).unwrap();
        let level = |k: u16| rtpflux_core::g711::linear_to_ulaw(i16::try_from(k).unwrap() * 1000);
        for k in [1u16, 0, 3, 2] {
            r.push(&RtpCopy::new(
                0,
                (k, u32::from(k) * 160),
                false,
                5,
                &[level(k + 1); 160],
            ));
        }
        // Not audio: ignored.
        for k in 0..4u16 {
            r.push(&RtpCopy::new(
                101,
                (k, u32::from(k) * 160),
                false,
                5,
                &[5, 0x80, 0, 160],
            ));
        }
        let mut out = Vec::new();
        r.pull(0, &mut out);
        assert!(out.is_empty(), "the delay first");
        r.pull(200, &mut out);
        assert_eq!(out.len(), 4 * 320);
        // Rising levels, frame by frame (after the resampler's ramp).
        let mean = |f: &[i16]| f.iter().map(|&s| i64::from(s)).sum::<i64>() / 320;
        let means: Vec<i64> = out.chunks(320).map(mean).collect();
        assert!(means.windows(2).all(|w| w[0] < w[1]), "{means:?}");
    }
}
