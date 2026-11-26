//! Turning a recording's packets into the two parties' audio, aligned.
//!
//! Each party's RTP is grouped by SSRC (a stream). A stream is placed on the
//! output timeline at its first packet's arrival time, and its packets by
//! their RTP timestamps from there (in sequence order, duplicates dropped),
//! so jitter does not stretch the audio and lost packets leave silence.
//! Each codec is decoded ([`crate::codec`]) and raised to the output rate;
//! Opus is decoded at the output rate. Wideband audio (G.722, AMR-WB, 16
//! kHz) keeps its band at 16 and 48 kHz outputs; at 8 and 24 kHz it goes
//! through 8 kHz. Telephone events, comfort noise and RTCP are skipped.
//!
//! The output is pulled in blocks ([`Mixer::fill`]): only packets that start
//! before the block's end are decoded, so memory stays small however long
//! the call.

use super::read::Frame;
use super::resample::Upsampler;
use super::settings::Channels;
use crate::codec::{self, MAX_OPUS_SAMPLES};
use rtpflux_core::rtp::{Pt, Ssrc};
use rtpflux_core::sdp::Codec;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::os::unix::fs::FileExt as _;

/// Who sent a stream: the caller (left) or the callee (right).
const SIDES: usize = 2;

/// A stream's decoder, and how its audio reaches the output rate: down to 8
/// kHz first (16 kHz audio for an 8 or 24 kHz output), then up by a whole
/// factor.
struct Decoder {
    codec: codec::Decoder,
    down: Option<codec::Resampler>,
    up: Upsampler,
}

impl Decoder {
    fn new(codec: Codec, rate: u32) -> Option<Self> {
        let codec = codec::Decoder::new(codec, rate)?;
        let from = codec.rate();
        let (down, from) = if rate.is_multiple_of(from) {
            (None, from)
        } else {
            (Some(codec::Resampler::new(from, 8000)?), 8000)
        };
        Some(Decoder {
            codec,
            down,
            up: Upsampler::new((rate / from) as usize),
        })
    }
}

struct Stream {
    side: usize,
    decoder: Decoder,
}

/// One packet's place on the timeline.
#[derive(Debug, Clone, Copy)]
struct Event {
    /// Output frame index of its first sample.
    pos: u64,
    stream: usize,
    frame: usize,
}

/// What one party sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct SideStats {
    /// Audio packets placed on the timeline.
    pub packets: u64,
    /// Sequence numbers that never arrived.
    pub lost: u64,
    /// Streams (SSRCs) seen.
    pub streams: usize,
}

/// The aligned audio of a recording, pulled block by block.
pub(super) struct Mixer {
    file: File,
    frames: Vec<Frame>,
    streams: Vec<Stream>,
    events: Vec<Event>,
    next: usize,
    /// Frames already given out.
    base: u64,
    sides: [VecDeque<i16>; SIDES],
    channels: Channels,
    /// Unix time (µs) of output frame 0.
    pub start_us: u64,
    pub stats: [SideStats; SIDES],
    scratch: Vec<u8>,
    decoded: Vec<i16>,
    /// One packet decoded, and taken down to 8 kHz.
    pcm: Vec<i16>,
    down: Vec<i16>,
}

/// The codec of an RTP payload type, given the dialog's dynamic ones, if
/// this build decodes it.
fn codec_of(pt: Pt, dynamic: &[(Pt, Codec)]) -> Option<Codec> {
    Codec::of_static(pt)
        .or_else(|| dynamic.iter().find(|d| d.0 == pt).map(|d| d.1))
        .filter(|&c| codec::supported(c))
}

impl Mixer {
    /// The audio of `frames` (read from `file`): packets to `left_port`
    /// are the caller's, packets to any other port the callee's.
    pub(super) fn new(
        file: File,
        frames: Vec<Frame>,
        left_port: u16,
        dynamic: &[(Pt, Codec)],
        channels: Channels,
        rate: u32,
    ) -> Self {
        // (side, ssrc) -> stream; per stream: (frame, seq, timestamp).
        let mut index: HashMap<(usize, Ssrc), usize> = HashMap::new();
        let mut packets: Vec<Vec<(usize, u16, u32)>> = Vec::new();
        let mut kinds: Vec<(usize, Codec)> = Vec::new();
        for (i, f) in frames.iter().enumerate() {
            let h = f.head;
            let rtcp = (192..=223).contains(&h[1]);
            if f.len <= 12 || h[0] >> 6 != 2 || rtcp {
                continue;
            }
            let Some(codec) = codec_of(Pt::of_header(h[1]), dynamic) else {
                continue;
            };
            let side = usize::from(f.dst_port != left_port);
            let ssrc = Ssrc::from_be_bytes([h[8], h[9], h[10], h[11]]);
            let s = *index.entry((side, ssrc)).or_insert_with(|| {
                packets.push(Vec::new());
                kinds.push((side, codec));
                packets.len() - 1
            });
            packets[s].push((
                i,
                u16::from_be_bytes([h[2], h[3]]),
                u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
            ));
        }
        let start_us = packets
            .iter()
            .flatten()
            .map(|&(i, _, _)| frames[i].time_us)
            .min()
            .unwrap_or(0);
        let mut stats = [SideStats::default(); SIDES];
        let mut events = Vec::new();
        let mut streams = Vec::new();
        for (s, list) in packets.iter().enumerate() {
            let (side, codec) = kinds[s];
            let clock = u64::from(codec.clock());
            stats[side].streams += 1;
            for segment in segments(list, &frames, clock) {
                // Extend sequence numbers and timestamps across their wraps,
                // in arrival order.
                let mut ext: Vec<(i64, i64, usize)> = Vec::with_capacity(segment.len());
                let (mut seq, mut ts) = (0i64, 0i64);
                for (k, &(frame, s16, t32)) in segment.iter().enumerate() {
                    if k > 0 {
                        let (ps, pt) = (segment[k - 1].1, segment[k - 1].2);
                        seq += i64::from(s16.wrapping_sub(ps).cast_signed());
                        ts += i64::from(t32.wrapping_sub(pt).cast_signed());
                    }
                    ext.push((seq, ts, frame));
                }
                ext.sort_by_key(|&(q, _, _)| q);
                ext.dedup_by_key(|e| e.0);
                let Some(&(first_seq, first_ts, first_frame)) = ext.first() else {
                    continue;
                };
                let last_seq = ext.last().map_or(first_seq, |e| e.0);
                let st = &mut stats[side];
                st.packets += ext.len() as u64;
                st.lost += u64::try_from(last_seq - first_seq + 1).unwrap_or(0) - ext.len() as u64;
                let anchor = (frames[first_frame].time_us - start_us) * u64::from(rate) / 1_000_000;
                let stream = streams.len();
                for (_, t, frame) in ext {
                    // Within a segment, timestamps agree with arrival; a
                    // packet before the segment's first (reordered) is
                    // placed at its start.
                    let offset = u64::try_from(t - first_ts).unwrap_or(0) * u64::from(rate) / clock;
                    events.push(Event {
                        pos: anchor + offset,
                        stream,
                        frame,
                    });
                }
                let Some(decoder) = Decoder::new(codec, rate) else {
                    continue;
                };
                streams.push(Stream { side, decoder });
            }
        }
        // By position; a stream's packets keep their order.
        events.sort_by_key(|e| (e.pos, e.stream));
        Mixer {
            file,
            frames,
            streams,
            events,
            next: 0,
            base: 0,
            sides: Default::default(),
            channels,
            start_us,
            stats,
            scratch: Vec::new(),
            decoded: Vec::new(),
            pcm: vec![0; MAX_OPUS_SAMPLES],
            down: vec![0; MAX_OPUS_SAMPLES],
        }
    }

    /// Decode one event's packet into `self.decoded`.
    fn decode(&mut self, event: Event) {
        self.decoded.clear();
        let frame = self.frames[event.frame];
        self.scratch.resize(frame.len, 0);
        if self
            .file
            .read_exact_at(&mut self.scratch, frame.offset)
            .is_err()
        {
            return;
        }
        let Ok(packet) = rtpflux_core::rtp::Packet::parse(&self.scratch) else {
            return;
        };
        let payload = packet.payload();
        let d = &mut self.streams[event.stream].decoder;
        let Some(n) = d.codec.decode(payload, &mut self.pcm) else {
            return;
        };
        let pcm = match &mut d.down {
            Some(r) => match r.process(&self.pcm[..n], &mut self.down) {
                Some(m) => &self.down[..m],
                None => return,
            },
            None => &self.pcm[..n],
        };
        d.up.process(pcm, &mut self.decoded);
    }

    /// Write `self.decoded` at `pos` on `side`'s timeline.
    fn place(&mut self, side: usize, pos: u64) {
        let n = self.decoded.len() as u64;
        if pos + n <= self.base {
            return;
        }
        let skip = usize::try_from(self.base.saturating_sub(pos)).unwrap_or(usize::MAX);
        let at = usize::try_from(pos.saturating_sub(self.base)).unwrap_or(usize::MAX);
        let buf = &mut self.sides[side];
        let samples = &self.decoded[skip.min(self.decoded.len())..];
        if buf.len() < at + samples.len() {
            buf.resize(at + samples.len(), 0);
        }
        for (k, &s) in samples.iter().enumerate() {
            buf[at + k] = s;
        }
    }

    /// Append up to `frames` frames to `out` (interleaved for stereo);
    /// returns how many. 0: the recording is over.
    pub(super) fn fill(&mut self, frames: usize, out: &mut Vec<i16>) -> usize {
        let end = self.base + frames as u64;
        while let Some(&e) = self.events.get(self.next).filter(|e| e.pos < end) {
            self.next += 1;
            self.decode(e);
            let side = self.streams[e.stream].side;
            self.place(side, e.pos);
        }
        let n = if self.next < self.events.len() {
            frames
        } else {
            frames.min(self.sides.iter().map(VecDeque::len).max().unwrap_or(0))
        };
        for i in 0..n {
            let l = self.sides[0].get(i).copied().unwrap_or(0);
            let r = self.sides[1].get(i).copied().unwrap_or(0);
            match self.channels {
                Channels::Stereo => out.extend_from_slice(&[l, r]),
                Channels::Mono => out.push(l.saturating_add(r)),
            }
        }
        for s in &mut self.sides {
            s.drain(..n.min(s.len()));
        }
        self.base += n as u64;
        n
    }

    /// Whether there is no audio at all (a video section, or no packets of
    /// a codec the relay decodes).
    pub(super) fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Frames given out so far.
    pub(super) fn position(&self) -> u64 {
        self.base
    }
}

/// How far a stream's RTP timestamps may run ahead of or behind its
/// arrival times before it is cut (microseconds), and how far its
/// sequence numbers may jump.
const MAX_DRIFT_US: i64 = 1_000_000;
const MAX_SEQ_JUMP: i32 = 1_000;

/// A stream's packets (`(frame, seq, timestamp)`, in arrival order) cut
/// where its timestamps stop following its arrival times (a sender that
/// re-based them on hold or transfer, keeping its SSRC) or its sequence
/// numbers jump (a restart): each segment is placed on its own arrival.
/// Otherwise a jump of up to 2^31 would place the rest of the stream hours
/// away (and fill the gap with silence) or pile it at the start.
fn segments<'a>(
    list: &'a [(usize, u16, u32)],
    frames: &[Frame],
    clock: u64,
) -> impl Iterator<Item = &'a [(usize, u16, u32)]> {
    let clock = i64::try_from(clock).unwrap_or(8000).max(1);
    let breaks = list.windows(2).enumerate().filter_map(move |(k, w)| {
        let ((fa, sa, ta), (fb, sb, tb)) = (w[0], w[1]);
        let arrival = i64::try_from(frames[fb].time_us).unwrap_or(i64::MAX)
            - i64::try_from(frames[fa].time_us).unwrap_or(i64::MAX);
        let media = i64::from(tb.wrapping_sub(ta).cast_signed()) * 1_000_000 / clock;
        let seq = i32::from(sb.wrapping_sub(sa).cast_signed());
        ((media - arrival).abs() > MAX_DRIFT_US || seq.abs() > MAX_SEQ_JUMP).then_some(k + 1)
    });
    let mut start = 0;
    let mut cuts = breaks.chain(std::iter::once(list.len()));
    std::iter::from_fn(move || {
        let end = cuts.next()?;
        let seg = &list[start..end];
        start = end;
        Some(seg)
    })
}

#[cfg(test)]
mod tests {
    use super::super::{file_header, frame, read};
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    /// An RTP packet of 160 μ-law codes of `code`.
    fn rtp(pt: u8, seq: u16, ts: u32, ssrc: u32, code: u8) -> Vec<u8> {
        let mut p = vec![0x80, pt];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend(std::iter::repeat_n(code, 160));
        p
    }

    /// A pcap of `packets`: (arrival ms, relay port, datagram).
    fn mixer(name: &str, packets: &[(u64, u16, Vec<u8>)], channels: Channels) -> Mixer {
        mixer_at(name, packets, channels, 8000)
    }

    /// [`mixer`] at output `rate`.
    fn mixer_at(
        name: &str,
        packets: &[(u64, u16, Vec<u8>)],
        channels: Channels,
        rate: u32,
    ) -> Mixer {
        let dir = std::env::temp_dir().join(format!("rtpflux-mix-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.pcap");
        let mut bytes = file_header().to_vec();
        for (ms, port, p) in packets {
            let when = UNIX_EPOCH + Duration::from_millis(1_000_000 + ms);
            let dst = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), *port);
            frame(&mut bytes, "127.0.0.1:4000".parse().unwrap(), dst, p, when);
        }
        std::fs::write(&path, &bytes).unwrap();
        let frames = read::frames(&path).unwrap();
        let m = Mixer::new(
            std::fs::File::open(&path).unwrap(),
            frames,
            30000,
            &[],
            channels,
            rate,
        );
        std::fs::remove_dir_all(&dir).unwrap();
        m
    }

    fn all(m: &mut Mixer) -> Vec<i16> {
        let mut out = Vec::new();
        while m.fill(1000, &mut out) > 0 {}
        out
    }

    #[test]
    fn reordered_duplicated_lost_and_wrapping() {
        // The caller: 0, 2, 1 (late), 1 again, then 4 (3 is lost), across
        // a timestamp wrap. μ-law 0x80 is a loud sample.
        let start = u32::MAX - 159;
        let ts = |k: u32| start.wrapping_add(k * 160);
        let packets = [
            (0, 30000, rtp(0, 10, ts(0), 1, 0x80)),
            (40, 30000, rtp(0, 12, ts(2), 1, 0x80)),
            (45, 30000, rtp(0, 11, ts(1), 1, 0x80)),
            (46, 30000, rtp(0, 11, ts(1), 1, 0x80)),
            (80, 30000, rtp(0, 14, ts(4), 1, 0x80)),
            // RTCP, telephone events and unknown types are skipped.
            (90, 30000, [&[0x80, 200][..], &[0; 30]].concat()),
            (95, 30000, rtp(101, 15, ts(5), 1, 0)),
            (96, 30002, rtp(96, 1, 0, 2, 0)),
        ];
        let mut m = mixer("order", &packets, Channels::Mono);
        let out = all(&mut m);
        assert_eq!(out.len(), 5 * 160, "five 20 ms packets' worth");
        let loud =
            |range: core::ops::Range<usize>| out[range].iter().all(|&s| s.unsigned_abs() > 20_000);
        assert!(loud(0..480), "packets 0, 1, 2 in place");
        assert!(
            out[480..640].iter().all(|&s| s == 0),
            "packet 3 lost: silence"
        );
        assert!(loud(640..800));
        assert_eq!(
            m.stats[0],
            SideStats {
                packets: 4,
                lost: 1,
                streams: 1
            }
        );
        assert_eq!(
            m.stats[1],
            SideStats::default(),
            "nothing audio from the callee"
        );
    }

    #[test]
    fn the_callee_is_placed_when_it_starts_talking() {
        // The callee's first packet arrives 100 ms after the caller's.
        let packets = [
            (0, 30000, rtp(0, 1, 1000, 1, 0x80)),
            (100, 30002, rtp(8, 7, 99_999, 2, 0x2A)),
        ];
        let mut m = mixer("place", &packets, Channels::Stereo);
        let out = all(&mut m);
        let frames = out.len() / 2;
        assert_eq!(frames, 800 + 160, "100 ms in, then 20 ms");
        let (left, right): (Vec<i16>, Vec<i16>) = out.chunks(2).map(|f| (f[0], f[1])).unzip();
        assert!(left[..160].iter().all(|&s| s != 0));
        assert!(right[..800].iter().all(|&s| s == 0));
        assert!(
            right[800..].iter().all(|&s| s != 0),
            "A-law, decoded as such"
        );
        assert_eq!(m.position(), 960);
        assert!(!m.is_empty());
        let video = [(0, 30000, rtp(96, 1, 0, 1, 0))];
        assert!(mixer("video", &video, Channels::Mono).is_empty());
    }

    #[test]
    fn a_stream_rebased_mid_call_stays_in_place() {
        // 1 s of audio, then the sender re-bases its timestamps by 2^30
        // (keeping SSRC and sequence), then 1 s more; arrival is steady.
        let mut packets = Vec::new();
        for k in 0..100u16 {
            let base: u32 = if k < 50 { 0 } else { 1 << 30 };
            let ts = base.wrapping_add(u32::from(k % 50) * 160);
            packets.push((u64::from(k) * 20, 30000, rtp(0, k, ts, 1, 0x80)));
        }
        let mut m = mixer("rebase", &packets, Channels::Mono);
        let out = all(&mut m);
        assert_eq!(out.len(), 100 * 160, "two seconds, not hours");
        assert!(out.iter().all(|&s| s.unsigned_abs() > 20_000), "no gap");
        // Timestamps going backwards are placed by arrival too.
        let mut packets = Vec::new();
        for k in 0..100u16 {
            let ts = if k < 50 {
                1_000_000 + u32::from(k) * 160
            } else {
                u32::from(k - 50) * 160
            };
            packets.push((u64::from(k) * 20, 30000, rtp(0, k, ts, 1, 0x80)));
        }
        let mut m = mixer("back", &packets, Channels::Mono);
        assert_eq!(all(&mut m).len(), 100 * 160);
    }

    /// G.722 (16 kHz) and G.729 (8 kHz) recordings: half a second of a
    /// 1 kHz tone comes out at every output rate, of the right length.
    #[test]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn g722_and_g729_at_every_rate() {
        use crate::codec::Encoder;
        for (codec, pt, rate_in) in [(Codec::G722, 9u8, 16_000u32), (Codec::G729, 18, 8000)] {
            let mut enc = Encoder::new(codec, rate_in).unwrap();
            let frame = rate_in as usize / 50;
            let mut packets = Vec::new();
            for k in 0..25u16 {
                let pcm: Vec<i16> = (0..frame)
                    .map(|i| {
                        let t = (usize::from(k) * frame + i) as f64 / f64::from(rate_in);
                        (8000.0 * (2.0 * std::f64::consts::PI * 1000.0 * t).sin()) as i16
                    })
                    .collect();
                let mut payload = [0u8; 400];
                let n = enc.encode(&pcm, &mut payload).unwrap();
                let mut p = vec![0x80, pt];
                p.extend_from_slice(&k.to_be_bytes());
                p.extend_from_slice(&(160 * u32::from(k)).to_be_bytes());
                p.extend_from_slice(&7u32.to_be_bytes());
                p.extend_from_slice(&payload[..n]);
                packets.push((20 * u64::from(k), 30_000, p));
            }
            for rate in crate::recording::settings::SAMPLE_RATES {
                let mut m = mixer_at(&format!("{codec:?}-{rate}"), &packets, Channels::Mono, rate);
                let out = all(&mut m);
                // 500 ms, give or take the last packet.
                let want = rate as usize / 2;
                assert!(
                    out.len().abs_diff(want) <= rate as usize / 50,
                    "{codec:?} at {rate}: {} samples",
                    out.len()
                );
                // The tone, past the start: correlation with 1 kHz.
                let tail = &out[out.len() / 2..];
                let w = 2.0 * std::f64::consts::PI * 1000.0 / f64::from(rate);
                let (mut c, mut si, mut e) = (0.0, 0.0, 0.0);
                for (i, &v) in tail.iter().enumerate() {
                    c += f64::from(v) * (w * i as f64).cos();
                    si += f64::from(v) * (w * i as f64).sin();
                    e += f64::from(v).powi(2);
                }
                let amp = 2.0 * (c * c + si * si).sqrt() / tail.len() as f64;
                let rms = (e / tail.len() as f64).sqrt();
                assert!(
                    amp / (rms * std::f64::consts::SQRT_2) > 0.9,
                    "{codec:?} at {rate}: not the tone"
                );
                assert!(rms > 2000.0, "{codec:?} at {rate}: level {rms}");
            }
        }
    }
}
