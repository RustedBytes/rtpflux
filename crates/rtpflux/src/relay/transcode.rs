//! Transcoding of one side's RTP: G.711 law to law by table; any other
//! pair through linear PCM ([`crate::codec`]): decode, resample 8 ⇄ 16 kHz
//! where the codecs' audio rates differ, encode. Opus runs at the other
//! codec's rate (8 or 16 kHz).
//!
//! Each transcoding leg owns its codec state, made when the leg is set up;
//! a packet is converted in place in its buffer with no allocation (AMR's
//! payload packing aside). Only packets of the transcoded payload type
//! change (telephone events and others pass). Timestamps follow the RTP
//! clocks (Opus 48000 Hz, AMR-WB 16000 Hz, the others 8000 Hz, G.722
//! included): scaled, keeping their differences; sequence numbers, SSRC
//! and the marker bit stay.

use super::Transcode;
use crate::codec::{self, Decoder, Encoder, MAX_SAMPLES, Resampler};
use rtpflux_core::g711;

/// The state of one transcoding leg.
pub(super) struct Transcoder {
    pub(super) config: Transcode,
    path: Path,
    /// Output clock ticks per input tick, or input ticks per output tick
    /// (`up`): the clocks' ratio.
    ratio: u32,
    up: bool,
    /// Timestamp mapping: (last input, last output).
    ts: Option<(u32, u32)>,
}

enum Path {
    Table(&'static [u8; 256]),
    Pcm(Box<Pcm>),
}

/// Decode, resample, encode.
struct Pcm {
    decoder: Decoder,
    encoder: Encoder,
    resampler: Option<Resampler>,
    decoded: [i16; MAX_SAMPLES],
    resampled: [i16; MAX_SAMPLES],
}

impl core::fmt::Debug for Transcoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Transcoder")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Transcoder {
    /// The state for `config`; `None` when it is not a conversion the
    /// relay makes (the same codec, or one this build lacks), or a codec
    /// refuses.
    pub(super) fn new(config: Transcode) -> Option<Self> {
        let (from, to) = (config.from.1, config.to.1);
        if from == to || !codec::supported(from) || !codec::supported(to) {
            return None;
        }
        let path = match (from.static_pt(), to.static_pt()) {
            (Some(a), Some(b)) if g711::converter(a, b).is_some() => {
                Path::Table(g711::converter(a, b)?)
            }
            _ => {
                // Opus takes the other side's rate.
                let from_rate = codec::rate(from, codec::rate(to, 8000));
                let to_rate = codec::rate(to, from_rate);
                let resampler = if from_rate == to_rate {
                    None
                } else {
                    Some(Resampler::new(from_rate, to_rate)?)
                };
                let mut encoder = Encoder::new(to, to_rate)?;
                if let Some(bps) = config.bitrate {
                    encoder.set_bitrate(bps);
                }
                Path::Pcm(Box::new(Pcm {
                    decoder: Decoder::new(from, from_rate)?,
                    encoder,
                    resampler,
                    decoded: [0; MAX_SAMPLES],
                    resampled: [0; MAX_SAMPLES],
                }))
            }
        };
        let (cf, ct) = (from.clock(), to.clock());
        Some(Transcoder {
            config,
            path,
            ratio: cf.max(ct) / cf.min(ct),
            up: ct > cf,
            ts: None,
        })
    }

    /// The output timestamp of `ts`: to a faster clock, multiplied
    /// (wrapping keeps differences); to a slower one, the difference to the
    /// last input divided, added to the last output (no jump when the input
    /// wraps); the same clock, unchanged.
    fn timestamp(&mut self, ts: u32) -> u32 {
        let out = if self.ratio == 1 {
            ts
        } else if self.up {
            ts.wrapping_mul(self.ratio)
        } else {
            match self.ts {
                Some((last_in, last_out)) => {
                    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
                    let step = (ts.wrapping_sub(last_in) as i32 / self.ratio.cast_signed()) as u32;
                    last_out.wrapping_add(step)
                }
                None => ts / self.ratio,
            }
        };
        self.ts = Some((ts, out));
        out
    }

    /// Convert the RTP packet `buf[..len]` in place (`buf` is its whole
    /// buffer); returns the new length, or `None` to drop it (malformed,
    /// undecodable, or of a length that splits into no frames of the
    /// target codec).
    pub(super) fn packet(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        let (start, payload_len, ts) = match rtpflux_core::rtp::Packet::parse(buf.get(..len)?) {
            // An empty payload has nothing to convert: dropped.
            Ok(p) if p.payload().is_empty() => return None,
            Ok(p) if p.payload_type() == self.config.from.0 => (
                p.as_bytes().len() - p.payload().len() - p.padding(),
                p.payload().len(),
                p.timestamp(),
            ),
            Ok(_) => return Some(len),
            Err(_) => return None,
        };
        let out_len = match &mut self.path {
            Path::Table(table) => {
                g711::transcode(table, buf.get_mut(start..start + payload_len)?);
                payload_len
            }
            Path::Pcm(p) => {
                let n = p
                    .decoder
                    .decode(buf.get(start..start + payload_len)?, &mut p.decoded)?;
                let pcm = match &mut p.resampler {
                    Some(r) => {
                        let m = r.process(&p.decoded[..n], &mut p.resampled)?;
                        &p.resampled[..m]
                    }
                    None => &p.decoded[..n],
                };
                p.encoder.encode(pcm, buf.get_mut(start..)?)?
            }
        };
        // No padding after the new payload.
        buf[0] &= !0x20;
        let ts = self.timestamp(ts);
        if !rtpflux_core::rtp::set_timestamp(buf, ts)
            || !rtpflux_core::rtp::set_payload_type(buf, self.config.to.0)
        {
            return None;
        }
        Some(start + out_len)
    }
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss)]
mod tests {
    use super::*;
    use rtpflux_core::rtp::Pt;

    fn pt(n: u8) -> Pt {
        Pt::new(n).unwrap()
    }
    use rtpflux_core::sdp::Codec;

    fn rtp(pt: u8, ts: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, pt, 0, 1];
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&7u32.to_be_bytes());
        p.extend_from_slice(payload);
        p.resize(1500, 0);
        p
    }

    /// 20 ms of a 400 Hz tone in μ-law.
    fn tone(frame: usize) -> Vec<u8> {
        (0..160)
            .map(|i| {
                let t = (frame * 160 + i) as f64 / 8000.0;
                #[allow(clippy::cast_possible_truncation)]
                let s = (8000.0 * (2.0 * std::f64::consts::PI * 400.0 * t).sin()) as i16;
                g711::linear_to_ulaw(s)
            })
            .collect()
    }

    fn energy(codes: &[u8]) -> f64 {
        codes
            .iter()
            .map(|&c| f64::from(g711::ulaw_to_linear(c)).powi(2))
            .sum::<f64>()
            / codes.len() as f64
    }

    #[test]
    fn empty_payloads_are_dropped() {
        for to in [(pt(8), Codec::Pcma), (pt(111), Codec::Opus)] {
            let mut t = Transcoder::new(Transcode {
                from: (pt(0), Codec::Pcmu),
                to,
                bitrate: None,
            })
            .unwrap();
            let mut p = rtp(0, 160, &[]);
            assert_eq!(t.packet(&mut p, 12), None, "{to:?}");
            // A payload of one sample still converts.
            let mut p = rtp(0, 320, &[0xff]);
            assert!(t.packet(&mut p, 13).is_some() || to.1 == Codec::Opus);
        }
    }

    #[test]
    fn pcmu_to_opus_and_back() {
        let t = |from: (Pt, Codec), to: (Pt, Codec)| {
            Transcoder::new(Transcode {
                from,
                to,
                bitrate: None,
            })
            .unwrap()
        };
        let mut enc = t((pt(0), Codec::Pcmu), (pt(111), Codec::Opus));
        let mut dec = t((pt(111), Codec::Opus), (pt(0), Codec::Pcmu));
        let mut last = Vec::new();
        for frame in 0..25 {
            let ts = 1000 + u32::try_from(frame * 160).unwrap();
            let mut p = rtp(0, ts, &tone(frame));
            let n = enc.packet(&mut p, 12 + 160).expect("encoded");
            // At most 24 kbit/s (60 octets per 20 ms) and some slack.
            assert!(n > 12 && n <= 12 + 80, "{n}");
            assert_eq!(p[1], 111);
            assert_eq!(&p[4..8], &(ts * 6).to_be_bytes());
            let n = dec.packet(&mut p, n).expect("decoded");
            assert_eq!(n, 12 + 160);
            assert_eq!(p[1], 0);
            assert_eq!(&p[4..8], &ts.to_be_bytes());
            last = p[12..n].to_vec();
        }
        // After the codec's start-up, the tone comes through.
        let ratio = energy(&last) / energy(&tone(24));
        assert!((0.3..3.0).contains(&ratio), "{ratio}");
        // Other payload types pass.
        let mut p = rtp(101, 5, &[1, 2, 3, 4]);
        assert_eq!(enc.packet(&mut p, 16), Some(16));
        assert_eq!(p[1], 101);
        // 30 ms (no Opus frame size): three 10 ms frames in one packet,
        // which decodes back to 240 samples.
        let mut p = rtp(0, 5, &tone(1).repeat(2)[..240]);
        let n = enc
            .packet(&mut p, 12 + 240)
            .expect("encoded as three frames");
        assert_eq!(p[12] & 0x03, 3, "a code 3 packet");
        assert_eq!(p[13] & 0x3f, 3, "of three frames");
        assert_eq!(dec.packet(&mut p, n), Some(12 + 240));
        // A length that splits into no frames is dropped.
        let mut p = rtp(0, 5, &[0xff; 250]);
        assert_eq!(enc.packet(&mut p, 12 + 250), None);
    }

    #[test]
    fn timestamps_from_opus_keep_their_steps_across_the_wrap() {
        let mut dec = Transcoder::new(Transcode {
            from: (pt(111), Codec::Opus),
            to: (pt(8), Codec::Pcma),
            bitrate: None,
        })
        .unwrap();
        let first = u32::MAX - 959;
        let a = dec.timestamp(first);
        let b = dec.timestamp(first.wrapping_add(960));
        let c = dec.timestamp(first.wrapping_add(1920));
        assert_eq!((b.wrapping_sub(a), c.wrapping_sub(b)), (160, 160));
    }

    /// G.711 to G.722 and back: twice the samples (16 kHz), the same
    /// timestamps (both clocks are 8000 Hz), one octet per sample pair.
    #[test]
    fn pcmu_to_g722_and_back() {
        let t = |from: (Pt, Codec), to: (Pt, Codec)| {
            Transcoder::new(Transcode {
                from,
                to,
                bitrate: None,
            })
            .unwrap()
        };
        let mut up = t((pt(0), Codec::Pcmu), (pt(9), Codec::G722));
        let mut down = t((pt(9), Codec::G722), (pt(0), Codec::Pcmu));
        let mut last = Vec::new();
        for frame in 0..25 {
            let ts = 7000 + u32::try_from(frame * 160).unwrap();
            let mut p = rtp(0, ts, &tone(frame));
            let n = up.packet(&mut p, 12 + 160).expect("to G.722");
            // 20 ms of G.722: 320 samples, 160 octets.
            assert_eq!((n, p[1]), (12 + 160, 9));
            assert_eq!(&p[4..8], &ts.to_be_bytes());
            let n = down.packet(&mut p, n).expect("back");
            assert_eq!((n, p[1]), (12 + 160, 0));
            last = p[12..n].to_vec();
        }
        let ratio = energy(&last) / energy(&tone(24));
        assert!((0.5..2.0).contains(&ratio), "{ratio}");
    }

    /// G.711 to G.729 and back: 10 octets per 10 ms; a G.729 packet with a
    /// SID frame decodes too.
    #[test]
    fn pcma_to_g729_and_back() {
        let t = |from: (Pt, Codec), to: (Pt, Codec)| {
            Transcoder::new(Transcode {
                from,
                to,
                bitrate: None,
            })
            .unwrap()
        };
        let mut to = t((pt(0), Codec::Pcmu), (pt(18), Codec::G729));
        let mut back = t((pt(18), Codec::G729), (pt(0), Codec::Pcmu));
        let mut last = Vec::new();
        for frame in 0..25 {
            let mut p = rtp(0, 160 * u32::try_from(frame).unwrap(), &tone(frame));
            let n = to.packet(&mut p, 12 + 160).expect("to G.729");
            assert_eq!((n, p[1]), (12 + 20, 18));
            let n = back.packet(&mut p, n).expect("back");
            assert_eq!(n, 12 + 160);
            last = p[12..n].to_vec();
        }
        let ratio = energy(&last) / energy(&tone(24));
        assert!((0.3..3.0).contains(&ratio), "{ratio}");
        let mut p = rtp(18, 0, &[0; 12]);
        assert_eq!(
            back.packet(&mut p, 12 + 12),
            Some(12 + 160),
            "one voice frame and a SID"
        );
        // 25 ms is no whole number of G.729 frames.
        let mut p = rtp(0, 0, &[0xff; 200]);
        assert_eq!(to.packet(&mut p, 12 + 200), None);
    }

    /// G.722 to Opus runs Opus at 16 kHz (no resampling); the clocks are
    /// 8000 and 48000 Hz.
    #[test]
    fn g722_to_opus_is_wideband() {
        let mut x = Transcoder::new(Transcode {
            from: (pt(9), Codec::G722),
            to: (pt(111), Codec::Opus),
            bitrate: None,
        })
        .unwrap();
        let mut p = rtp(9, 100, &[0x55; 160]);
        let n = x.packet(&mut p, 12 + 160).expect("encoded");
        assert!(n > 12 && n < 12 + 200, "{n}");
        assert_eq!(&p[4..8], &600u32.to_be_bytes());
        // The same codec, or one this build lacks: no transcoder.
        assert!(
            Transcoder::new(Transcode {
                from: (pt(9), Codec::G722),
                to: (pt(9), Codec::G722),
                bitrate: None,
            })
            .is_none()
        );
        if !crate::codec::supported(Codec::Amr) {
            assert!(
                Transcoder::new(Transcode {
                    from: (pt(0), Codec::Pcmu),
                    to: (pt(96), Codec::Amr),
                    bitrate: None,
                })
                .is_none()
            );
        }
    }

    #[test]
    fn law_to_law_by_table() {
        let mut x = Transcoder::new(Transcode {
            from: (pt(0), Codec::Pcmu),
            to: (pt(8), Codec::Pcma),
            bitrate: None,
        })
        .unwrap();
        let mut p = rtp(0, 9, &[0xff; 160]);
        assert_eq!(x.packet(&mut p, 172), Some(172));
        assert_eq!((p[1], p[12]), (8, g711::linear_to_alaw(0)));
        assert_eq!(&p[4..8], &9u32.to_be_bytes());
    }
}
