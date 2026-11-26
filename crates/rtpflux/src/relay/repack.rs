//! Repacketisation (`ptime`): the audio of one RTP stream regrouped into
//! packets of a set duration, for codecs whose payload can be cut and
//! joined at any frame boundary: G.711 (PCMU, PCMA) and G.722 at 8 octets a
//! millisecond, G.729 in 10-octet frames of 10 ms.
//!
//! Packets of other payload types (telephone events, comfort noise, a codec
//! that cannot be cut) pass in order, after the audio held so far.
//! Sequence numbers are the repacketiser's own, from the stream's first;
//! the SSRC stays; timestamps follow the audio. A gap in the input
//! (timestamps that do not follow on, a new talkspurt, another SSRC or
//! payload type) sends what is held as a shorter packet first.
//!
//! Opus cannot be cut: with its payload type given
//! ([`Repacker::with_opus`]), its packets are decoded (48 kHz, its RTP
//! clock) and the audio encoded again in packets of one Opus frame: the
//! longest of 10, 20, 40 or 60 ms (RFC 6716 §2.1.4) not over the duration;
//! a gap sends what is held padded with silence to a whole 10 ms.
//!
//! Everything is preallocated when the repacketiser is made; when its
//! queue of ready packets is full the oldest is dropped and counted.

use rtpflux_core::rtp::{FIXED_HEADER_LEN, Packet, Pt};

/// Packet durations a repacketiser makes, in milliseconds (multiples of
/// 10).
pub const MIN_MS: u16 = 10;
pub const MAX_MS: u16 = 200;

/// Most audio octets in one packet made (200 ms of G.711).
const MAX_PAYLOAD: usize = 8 * MAX_MS as usize;
/// One queued packet: a made one, or one passed through.
const SLOT: usize = FIXED_HEADER_LEN + MAX_PAYLOAD;
/// Packets ready to send.
const RING: usize = 8;
/// Audio held: less than a packet, and one input payload.
const PENDING: usize = MAX_PAYLOAD + SLOT;

/// How a codec's payload is cut: octets per 10 ms, the frame size in
/// octets, and RTP clock ticks per octet.
const fn layout(pt: Pt) -> Option<(usize, usize, u32)> {
    match pt.get() {
        // G.711 and G.722 (whose RTP clock is 8000 Hz, RFC 3551 §4.5.2).
        0 | 8 | 9 => Some((80, 1, 1)),
        18 => Some((10, 10, 8)),
        _ => None,
    }
}

/// Whether `pt`'s audio can be repacketised.
#[must_use]
pub const fn repacketises(pt: Pt) -> bool {
    layout(pt).is_some()
}

/// The audio being gathered into the next packet.
#[derive(Debug, Clone, Copy)]
struct Held {
    pt: Pt,
    ssrc: [u8; 4],
    marker: bool,
    /// The timestamp of the first octet held.
    ts: u32,
}

/// Opus at 48 kHz: samples per millisecond, and the audio held (120 ms
/// to make a packet of, and one input packet of up to 120 ms).
const OPUS_PER_MS: usize = 48;
const OPUS_HELD: usize = 240 * OPUS_PER_MS;
/// Opus frame durations the relay encodes (one frame a packet).
const OPUS_FRAMES_MS: [u16; 4] = [60, 40, 20, 10];

/// The Opus path: payload type, codec state and the audio held.
struct OpusRepack {
    pt: Pt,
    decoder: crate::codec::Decoder,
    encoder: crate::codec::Encoder,
    pcm: Box<[i16]>,
    len: usize,
    out: Box<[u8; MAX_PAYLOAD]>,
}

pub struct Repacker {
    ms: u16,
    opus: Option<Box<OpusRepack>>,
    pending: Box<[u8; PENDING]>,
    pending_len: usize,
    held: Option<Held>,
    /// The input timestamp that would follow on from the audio held.
    next_in_ts: Option<u32>,
    /// The next sequence number out (from the first packet's).
    seq: Option<u16>,
    ring: Box<[u8; RING * SLOT]>,
    lens: [usize; RING],
    head: usize,
    count: usize,
    /// Packets dropped: malformed, too large to pass, or a full queue.
    pub dropped: u64,
}

impl core::fmt::Debug for Repacker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Repacker")
            .field("ms", &self.ms)
            .field("held", &self.pending_len)
            .field("ready", &self.count)
            .finish_non_exhaustive()
    }
}

impl Repacker {
    /// A repacketiser to packets of `ms` milliseconds (a multiple of 10
    /// from [`MIN_MS`] to [`MAX_MS`]).
    #[must_use]
    pub fn new(ms: u16) -> Option<Self> {
        ((MIN_MS..=MAX_MS).contains(&ms) && ms.is_multiple_of(10)).then(|| Repacker {
            ms,
            opus: None,
            pending: Box::new([0; PENDING]),
            pending_len: 0,
            held: None,
            next_in_ts: None,
            seq: None,
            ring: Box::new([0; RING * SLOT]),
            lens: [0; RING],
            head: 0,
            count: 0,
            dropped: 0,
        })
    }

    /// The same, also for Opus of payload type `pt` (decoded and encoded
    /// again); `None` when the codec cannot be made.
    #[must_use]
    pub fn with_opus(mut self, pt: Pt) -> Option<Self> {
        use crate::codec::{Decoder, Encoder};
        use rtpflux_core::sdp::Codec;
        self.opus = Some(Box::new(OpusRepack {
            pt,
            decoder: Decoder::new(Codec::Opus, 48_000)?,
            encoder: Encoder::new(Codec::Opus, 48_000)?,
            pcm: vec![0; OPUS_HELD].into_boxed_slice(),
            len: 0,
            out: Box::new([0; MAX_PAYLOAD]),
        }));
        Some(self)
    }

    #[must_use]
    pub fn ms(&self) -> u16 {
        self.ms
    }

    /// The Opus payload type it repacketises, if any.
    #[must_use]
    pub fn opus(&self) -> Option<Pt> {
        self.opus.as_ref().map(|o| o.pt)
    }

    /// Whether a packet is ready.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.count > 0
    }

    /// Take in one RTP packet (in clear).
    pub fn push(&mut self, pkt: &[u8]) {
        let Ok(p) = Packet::parse(pkt) else {
            self.dropped += 1;
            return;
        };
        let pt = p.payload_type();
        let payload = p.payload();
        let ssrc = p.ssrc().get().to_be_bytes();
        let ts = p.timestamp();
        if self.seq.is_none() {
            self.seq = Some(p.sequence());
        }
        if self.opus.as_ref().is_some_and(|o| o.pt == pt) && !payload.is_empty() {
            self.push_opus(pt, ssrc, (ts, p.marker()), payload);
            return;
        }
        let Some((per_10ms, frame, ticks)) =
            layout(pt).filter(|&(_, frame, _)| !payload.is_empty() && payload.len() % frame == 0)
        else {
            // Not audio this repacketiser cuts: in order, after what is
            // held.
            self.flush();
            self.pass(pkt);
            return;
        };
        let follows = self.held.is_some_and(|h| {
            h.pt == pt && h.ssrc == ssrc && self.next_in_ts == Some(ts) && !p.marker()
        });
        if !follows {
            self.flush();
        }
        if self.pending_len == 0 {
            self.held = Some(Held {
                pt,
                ssrc,
                marker: p.marker(),
                ts,
            });
        }
        let Some(room) = self
            .pending
            .get_mut(self.pending_len..self.pending_len + payload.len())
        else {
            self.dropped += 1;
            return;
        };
        room.copy_from_slice(payload);
        self.pending_len += payload.len();
        let ticks_in = u32::try_from(payload.len()).unwrap_or(u32::MAX) * ticks;
        self.next_in_ts = Some(ts.wrapping_add(ticks_in));
        let target = usize::from(self.ms / 10) * per_10ms;
        debug_assert!(target.is_multiple_of(frame));
        while self.pending_len >= target {
            self.emit(target, ticks);
        }
    }

    /// Send what is held as a (shorter) packet.
    fn flush(&mut self) {
        if self.pending_len > 0
            && let Some((_, _, ticks)) = self.held.and_then(|h| layout(h.pt))
        {
            self.emit(self.pending_len, ticks);
        }
        if self.opus.as_ref().is_some_and(|o| o.len > 0) {
            // A whole 10 ms, padded with silence.
            let n = self.opus.as_ref().map_or(0, |o| o.len.div_ceil(480) * 480);
            if let Some(o) = self.opus.as_mut() {
                o.pcm[o.len..n].fill(0);
                o.len = n;
            }
            self.emit_opus(n);
        }
        self.pending_len = 0;
        self.held = None;
        self.next_in_ts = None;
    }

    /// Take in an Opus packet: its audio decoded and held, packets of the
    /// duration made of it.
    fn push_opus(&mut self, pt: Pt, ssrc: [u8; 4], (ts, marker): (u32, bool), payload: &[u8]) {
        let follows = self.held.is_some_and(|h| {
            h.pt == pt && h.ssrc == ssrc && self.next_in_ts == Some(ts) && !marker
        });
        if !follows {
            self.flush();
        }
        let Some(o) = self.opus.as_mut() else {
            return;
        };
        let Some(n) = o.decoder.decode(payload, &mut o.pcm[o.len..]) else {
            self.dropped += 1;
            return;
        };
        if o.len == 0 {
            self.held = Some(Held {
                pt,
                ssrc,
                marker,
                ts,
            });
        }
        o.len += n;
        self.next_in_ts = Some(ts.wrapping_add(u32::try_from(n).unwrap_or(u32::MAX)));
        let ms = OPUS_FRAMES_MS
            .into_iter()
            .find(|&f| f <= self.ms)
            .unwrap_or(10);
        let target = usize::from(ms) * OPUS_PER_MS;
        while self.opus.as_ref().is_some_and(|o| o.len >= target) {
            self.emit_opus(target);
        }
    }

    /// Queue an Opus packet of the first `n` samples held.
    fn emit_opus(&mut self, n: usize) {
        let Some(h) = self.held else {
            return;
        };
        let Some(o) = self.opus.as_mut() else {
            return;
        };
        let encoded = o.encoder.encode(&o.pcm[..n], &mut o.out[..]);
        o.pcm.copy_within(n..o.len, 0);
        o.len -= n;
        self.held = Some(Held {
            marker: false,
            ts: h.ts.wrapping_add(u32::try_from(n).unwrap_or(u32::MAX)),
            ..h
        });
        let Some(len) = encoded.filter(|&l| FIXED_HEADER_LEN + l <= SLOT) else {
            self.dropped += 1;
            return;
        };
        let seq = self.next_seq();
        let at = self.slot();
        let Some(o) = self.opus.as_ref() else {
            return;
        };
        let slot = &mut self.ring[at..at + SLOT];
        slot[0] = 0x80;
        slot[1] = h.pt.header_octet(h.marker);
        slot[2..4].copy_from_slice(&seq.to_be_bytes());
        slot[4..8].copy_from_slice(&h.ts.to_be_bytes());
        slot[8..12].copy_from_slice(&h.ssrc);
        slot[12..12 + len].copy_from_slice(&o.out[..len]);
        self.commit(FIXED_HEADER_LEN + len);
    }

    /// Queue a packet of the first `n` octets held.
    fn emit(&mut self, n: usize, ticks: u32) {
        let Some(h) = self.held else {
            return;
        };
        let seq = self.next_seq();
        let at = self.slot();
        let slot = &mut self.ring[at..at + SLOT];
        slot[0] = 0x80;
        slot[1] = h.pt.header_octet(h.marker);
        slot[2..4].copy_from_slice(&seq.to_be_bytes());
        slot[4..8].copy_from_slice(&h.ts.to_be_bytes());
        slot[8..12].copy_from_slice(&h.ssrc);
        slot[12..12 + n].copy_from_slice(&self.pending[..n]);
        self.commit(FIXED_HEADER_LEN + n);
        self.pending.copy_within(n..self.pending_len, 0);
        self.pending_len -= n;
        self.held = Some(Held {
            marker: false,
            ts: h
                .ts
                .wrapping_add(u32::try_from(n).unwrap_or(u32::MAX) * ticks),
            ..h
        });
    }

    /// Queue `pkt` as it is but for its sequence number.
    fn pass(&mut self, pkt: &[u8]) {
        if pkt.len() > SLOT {
            self.dropped += 1;
            return;
        }
        let seq = self.next_seq();
        let at = self.slot();
        let slot = &mut self.ring[at..at + SLOT];
        slot[..pkt.len()].copy_from_slice(pkt);
        slot[2..4].copy_from_slice(&seq.to_be_bytes());
        self.commit(pkt.len());
    }

    fn next_seq(&mut self) -> u16 {
        let s = self.seq.unwrap_or(0);
        self.seq = Some(s.wrapping_add(1));
        s
    }

    /// Where in the ring the next packet goes (the oldest is dropped when
    /// the queue is full).
    fn slot(&mut self) -> usize {
        if self.count == RING {
            self.head = (self.head + 1) % RING;
            self.count -= 1;
            self.dropped += 1;
        }
        (self.head + self.count) % RING * SLOT
    }

    fn commit(&mut self, len: usize) {
        let i = (self.head + self.count) % RING;
        self.lens[i] = len;
        self.count += 1;
    }

    /// The oldest ready packet, written to `out`; its length.
    pub fn pop(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let i = self.head;
        let len = self.lens[i];
        self.head = (self.head + 1) % RING;
        self.count -= 1;
        let dst = out.get_mut(..len)?;
        dst.copy_from_slice(&self.ring[i * SLOT..i * SLOT + len]);
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtp(pt: u8, seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, pt | if marker { 0x80 } else { 0 }];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    /// (payload type, marker, sequence, timestamp, payload) of each ready
    /// packet.
    fn drain(r: &mut Repacker) -> Vec<(u8, bool, u16, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut buf = [0u8; SLOT];
        while let Some(n) = r.pop(&mut buf) {
            let p = Packet::parse(&buf[..n]).unwrap();
            assert_eq!(p.ssrc().get(), 0x1234_5678);
            out.push((
                p.payload_type().get(),
                p.marker(),
                p.sequence(),
                p.timestamp(),
                p.payload().to_vec(),
            ));
        }
        out
    }

    /// 20 ms of G.711, octets numbered from `n`.
    fn g711(n: u8) -> Vec<u8> {
        (0..160u32)
            .map(|i| n.wrapping_add(u8::try_from(i % 256).unwrap()))
            .collect()
    }

    #[test]
    fn durations_are_checked() {
        assert!(Repacker::new(20).is_some() && Repacker::new(200).is_some());
        for ms in [0, 5, 25, 210] {
            assert!(Repacker::new(ms).is_none(), "{ms}");
        }
    }

    #[test]
    fn twenty_ms_packets_are_joined_into_forty() {
        let mut r = Repacker::new(40).unwrap();
        r.push(&rtp(0, 100, 8000, true, &g711(0)));
        assert!(!r.ready(), "half a packet held");
        r.push(&rtp(0, 101, 8160, false, &g711(7)));
        let out = drain(&mut r);
        assert_eq!(out.len(), 1);
        let (pt, marker, seq, ts, payload) = &out[0];
        assert_eq!((*pt, *marker, *seq, *ts), (0, true, 100, 8000));
        assert_eq!(payload[..160], g711(0)[..]);
        assert_eq!(payload[160..], g711(7)[..]);
        r.push(&rtp(0, 102, 8320, false, &g711(1)));
        r.push(&rtp(0, 103, 8480, false, &g711(2)));
        let out = drain(&mut r);
        assert_eq!(
            (out[0].1, out[0].2, out[0].3, out[0].4.len()),
            (false, 101, 8320, 320)
        );
    }

    #[test]
    fn forty_ms_packets_are_cut_into_twenty_and_thirty_regroups() {
        let mut r = Repacker::new(20).unwrap();
        let forty: Vec<u8> = [g711(0), g711(9)].concat();
        r.push(&rtp(8, 7, 0, false, &forty));
        let out = drain(&mut r);
        assert_eq!(out.len(), 2);
        assert_eq!((out[0].2, out[0].3, &out[0].4[..]), (7, 0, &g711(0)[..]));
        assert_eq!((out[1].2, out[1].3, &out[1].4[..]), (8, 160, &g711(9)[..]));

        // 20 ms in, 30 ms out: two packets from three.
        let mut r = Repacker::new(30).unwrap();
        for k in 0..3u16 {
            r.push(&rtp(0, k, u32::from(k) * 160, false, &g711(0)));
        }
        let out = drain(&mut r);
        assert_eq!(
            out.iter().map(|o| (o.3, o.4.len())).collect::<Vec<_>>(),
            [(0, 240), (240, 240)]
        );
    }

    #[test]
    fn a_gap_or_an_event_sends_what_is_held_first() {
        let mut r = Repacker::new(40).unwrap();
        r.push(&rtp(0, 1, 0, false, &g711(0)));
        // A lost packet: the timestamps jump.
        r.push(&rtp(0, 3, 320, false, &g711(1)));
        let out = drain(&mut r);
        assert_eq!(
            out.iter()
                .map(|o| (o.2, o.3, o.4.len()))
                .collect::<Vec<_>>(),
            [(1, 0, 160)]
        );
        // A telephone event passes, after the audio held, renumbered.
        r.push(&rtp(101, 9, 480, true, &[1, 0x0a, 0, 160]));
        let out = drain(&mut r);
        assert_eq!(
            out.iter().map(|o| (o.0, o.1, o.2, o.3)).collect::<Vec<_>>(),
            [(0, false, 2, 320), (101, true, 3, 480)]
        );
        // A new talkspurt (marker) starts a new packet.
        r.push(&rtp(0, 10, 2000, false, &g711(0)));
        r.push(&rtp(0, 11, 2160, true, &g711(0)));
        r.push(&rtp(0, 12, 2320, false, &g711(0)));
        let out = drain(&mut r);
        assert_eq!(
            out.iter()
                .map(|o| (o.1, o.3, o.4.len()))
                .collect::<Vec<_>>(),
            [(false, 2000, 160), (true, 2160, 320)]
        );
    }

    #[test]
    fn g729_is_cut_in_frames_and_its_sid_passes() {
        let mut r = Repacker::new(40).unwrap();
        r.push(&rtp(18, 0, 0, false, &[1; 20]));
        r.push(&rtp(18, 1, 160, false, &[2; 20]));
        let out = drain(&mut r);
        assert_eq!((out.len(), out[0].3, out[0].4.len()), (1, 0, 40));
        // A comfort-noise frame (2 octets) is not cut.
        r.push(&rtp(18, 2, 320, false, &[3; 2]));
        let out = drain(&mut r);
        assert_eq!((out.len(), out[0].4.len()), (1, 2));
    }

    #[test]
    fn a_full_queue_drops_the_oldest() {
        let mut r = Repacker::new(10).unwrap();
        let long: Vec<u8> = vec![0; 80 * 10];
        r.push(&rtp(0, 0, 0, false, &long));
        assert_eq!(r.dropped, 2, "ten packets, room for eight");
        let out = drain(&mut r);
        assert_eq!((out.len(), out[0].3), (8, 160));
        r.push(&[0x80]);
        assert_eq!(r.dropped, 3, "malformed");
    }

    /// `ms` of a 440 Hz tone at 48 kHz, from sample `at`, Opus-encoded.
    fn opus_packet(enc: &mut crate::codec::Encoder, at: usize, ms: usize) -> Vec<u8> {
        let pcm: Vec<i16> = (at..at + ms * 48)
            .map(|i| {
                #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                let s = (8000.0 * (2.0 * core::f64::consts::PI * 440.0 * i as f64 / 48_000.0).sin())
                    as i16;
                s
            })
            .collect();
        let mut out = [0u8; 1500];
        let n = enc.encode(&pcm, &mut out).unwrap();
        out[..n].to_vec()
    }

    #[test]
    fn opus_is_decoded_and_encoded_again() {
        use crate::codec::{Decoder, Encoder};
        use rtpflux_core::sdp::Codec;
        let mut enc = Encoder::new(Codec::Opus, 48_000).unwrap();
        let mut dec = Decoder::new(Codec::Opus, 48_000).unwrap();
        let samples = |dec: &mut Decoder, payload: &[u8]| {
            let mut pcm = [0i16; 6000];
            dec.decode(payload, &mut pcm).unwrap()
        };
        // Three 20 ms packets: one of 60 ms.
        let mut r = Repacker::new(60)
            .unwrap()
            .with_opus(Pt::new(111).unwrap())
            .unwrap();
        for k in 0..3u16 {
            let payload = opus_packet(&mut enc, usize::from(k) * 960, 20);
            r.push(&rtp(
                111,
                40 + k,
                1000 + u32::from(k) * 960,
                k == 0,
                &payload,
            ));
        }
        assert_eq!(r.dropped, 0, "nothing dropped");
        let out = drain(&mut r);
        assert_eq!(out.len(), 1);
        let (pt, marker, seq, ts, payload) = &out[0];
        assert_eq!((*pt, *marker, *seq, *ts), (111, true, 40, 1000));
        assert_eq!(samples(&mut dec, payload), 2880, "60 ms");
        // One 40 ms packet: two of 20 ms; G.711 still passes through the
        // byte path, events in order.
        let mut r = Repacker::new(20)
            .unwrap()
            .with_opus(Pt::new(111).unwrap())
            .unwrap();
        r.push(&rtp(111, 5, 0, false, &opus_packet(&mut enc, 0, 40)));
        let out = drain(&mut r);
        assert_eq!(
            out.iter().map(|o| (o.2, o.3)).collect::<Vec<_>>(),
            [(5, 0), (6, 960)]
        );
        for o in &out {
            assert_eq!(samples(&mut dec, &o.4), 960, "20 ms");
        }
        // 30 ms: one Opus frame of 20 ms (the longest not over it).
        let mut r = Repacker::new(30)
            .unwrap()
            .with_opus(Pt::new(111).unwrap())
            .unwrap();
        for k in 0..3u32 {
            r.push(&rtp(111, 0, k * 480, false, &opus_packet(&mut enc, 0, 10)));
        }
        let out = drain(&mut r);
        assert_eq!(out.len(), 1);
        assert_eq!(samples(&mut dec, &out[0].4), 960, "20 ms");
        assert_eq!(r.dropped, 0);
    }
}
