//! Call features applied per packet: blocking, recording and
//! announcements (`play media`).

#[allow(clippy::wildcard_imports)]
use super::*;

/// Blocked: all RTP of the side.
pub(super) const BLOCK_MEDIA: u8 = 1;

/// Blocked: its telephone events.
pub(super) const BLOCK_DTMF: u8 = 2;

/// Held back: the other side hears an announcement.
pub(super) const BLOCK_PLAY: u8 = 4;

/// Silenced: its audio replaced by silence (G.711), or held back (other
/// codecs); telephone events pass.
pub(super) const BLOCK_SILENCE: u8 = 8;

/// Its copies (subscriptions, directional `connect`, injections) blocked:
/// `all: except-offer-answer`.
pub(super) const BLOCK_COPIES: u8 = 16;

/// Its copies silenced (G.711; other audio not copied).
pub(super) const BLOCK_COPIES_SILENCE: u8 = 32;

/// Codes per announcement packet: 20 ms at 8 kHz.
pub(super) const PLAY_FRAME: usize = 160;

/// An announcement: G.711 codes of payload type `pt`, played `repeat`
/// times.
#[derive(Debug, Clone)]
pub struct Playing {
    pub codes: std::sync::Arc<[u8]>,
    pub pt: Pt,
    pub repeat: u32,
    /// Codes already played (of all the repetitions): the playback starts
    /// there (an announcement going on after a restart).
    pub skip: usize,
    /// Codes to play in all (of all the repetitions, counting `skip`): it
    /// stops there even within a repetition (`repeat-duration`).
    pub limit: Option<usize>,
}

/// An announcement in progress towards the peer of RTP slot `slot`;
/// `other` is the slot whose media is held back meanwhile.
#[derive(Debug)]
pub(super) struct Playback {
    pub(super) call: CallId,
    pub(super) slot: Slot,
    pub(super) other: Slot,
    pub(super) media: Playing,
    /// Where it is (`relay::play`).
    pub(super) cursor: crate::relay::play::Cursor,
    pub(super) next_ms: u64,
    /// No packet sent yet: the first carries the marker bit.
    pub(super) first: bool,
}

/// The RTP stream announcements and keys are sent in, per slot
/// (`relay::stream`). Random at the slot's first announcement or keys
/// (RFC 3550 §5.1), forgotten when the slot's call ends.
pub(super) use crate::relay::hold::Kind;
pub(super) use crate::relay::stream::PlayStream;
use rtpflux_core::rtp::Pt;

/// Ticks a millisecond of an announcement's clock (G.711, 8 kHz).
const PLAY_PER_MS: u32 = 8;

pub(super) fn random_stream(now_ms: u64) -> PlayStream {
    PlayStream::new(
        rtpflux_core::rtp::Ssrc::new(rand::random()),
        rand::random(),
        rand::random(),
        now_ms,
    )
}

/// What blocking stops (`Relay::block`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// All RTP the side sends (telephone events included).
    Media,
    /// Only its telephone events (RFC 4733).
    Dtmf,
    /// Its audio, replaced by silence where it is G.711 (the stream goes on:
    /// sequence numbers, timestamps and SSRC); other audio is held back.
    /// Telephone events pass.
    Silence,
    /// The copies of all its RTP (subscriptions, directional `connect`,
    /// injections), its own relayed media going on (rtpengine's `all:
    /// except-offer-answer`).
    Copies,
    /// The copies of its audio, silenced as [`Blocked::Silence`] does.
    CopiesSilence,
}

impl Blocked {
    /// Every kind.
    pub const ALL: [Blocked; 5] = [
        Blocked::Media,
        Blocked::Dtmf,
        Blocked::Silence,
        Blocked::Copies,
        Blocked::CopiesSilence,
    ];

    /// Its bit in a [`Blocks`] (as the state file has them).
    const fn bit(self) -> u8 {
        match self {
            Blocked::Media => 1,
            Blocked::Dtmf => 2,
            Blocked::Silence => 4,
            Blocked::Copies => 8,
            Blocked::CopiesSilence => 16,
        }
    }
}

/// What is blocked of a leg: a set of [`Blocked`] kinds, kept in the state
/// file as one octet (media 1, telephone events 2, silenced 4, copies 8,
/// copies silenced 16). The worker's own bits (`BLOCK_MEDIA`, …) are
/// another matter: they are set through [`Blocked`], never from these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Blocks(u8);

impl Blocks {
    #[must_use]
    pub const fn contains(self, what: Blocked) -> bool {
        self.0 & what.bit() != 0
    }

    /// Add (`on`) or take away `what`.
    pub fn set(&mut self, what: Blocked, on: bool) {
        if on {
            self.0 |= what.bit();
        } else {
            self.0 &= !what.bit();
        }
    }

    /// Whether nothing is blocked.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The kinds in the set.
    pub fn kinds(self) -> impl Iterator<Item = Blocked> {
        Blocked::ALL.into_iter().filter(move |&w| self.contains(w))
    }
}

impl Worker {
    /// Start or stop playing to leg `leg` of `call`. While it
    /// plays, the other side's RTP towards it is held back (by the kernel
    /// too, for a call in the fast path: its flow drops it).
    pub(super) fn play(&mut self, call: CallId, leg: CallLeg, media: Option<Playing>) {
        let Some(c) = self.calls.get_mut(&call) else {
            return;
        };
        let (to, other) = if leg == CallLeg::B {
            (c.slots[2], c.slots[0])
        } else {
            (c.slots[0], c.slots[2])
        };
        self.playbacks.retain(|p| p.slot != to);
        // Where to start: after the frames already played (a restart).
        let Some((media, cursor)) = media.and_then(|m| {
            crate::relay::play::Cursor::start(m.codes.len(), m.repeat, m.limit, m.skip)
                .map(|c| (m, c))
        }) else {
            // Stopped: the other side's audio is let through again, unless
            // keys still play to the same side (they keep the hold).
            if !self.hold.finish(Kind::Announcement, to.index())
                && let Some(b) = self.blocked.get_mut(other)
            {
                *b &= !BLOCK_PLAY;
            }
            self.refresh_offload(call);
            return;
        };
        self.hold.start(Kind::Announcement, to.index());
        if let Some(b) = self.blocked.get_mut(other) {
            *b |= BLOCK_PLAY;
        }
        self.refresh_offload(call);
        let now = self.now_ms();
        if let Some(s) = self.play_streams.get_mut(to)
            && s.is_none()
        {
            *s = Some(random_stream(now));
        }
        self.playbacks.push(Playback {
            call,
            slot: to,
            other,
            media,
            cursor,
            next_ms: self.now_ms(),
            first: true,
        });
    }

    pub(super) fn next_playback_ms(&self) -> Option<u64> {
        self.playbacks.iter().map(|p| p.next_ms).min()
    }

    /// What played of `kind` to `slot` ended: the other side's audio is let
    /// through again unless something else still plays there.
    pub(super) fn end_play(&mut self, kind: Kind, slot: Slot, other: Slot, call: CallId) {
        if !self.hold.finish(kind, slot.index())
            && let Some(b) = self.blocked.get_mut(other)
        {
            *b &= !BLOCK_PLAY;
        }
        self.refresh_offload(call);
    }

    /// Send the packets that are due; finish what has played out.
    pub(super) fn play_due(&mut self, now: u64) {
        let mut k = 0;
        while k < self.playbacks.len() {
            let p = &mut self.playbacks[k];
            if p.next_ms > now {
                k += 1;
                continue;
            }
            let Some((at, n)) = p.cursor.next_frame() else {
                let (slot, other, call) = (p.slot, p.other, p.call);
                self.playbacks.swap_remove(k);
                self.end_play(Kind::Announcement, slot, other, call);
                self.emit_media(
                    slot,
                    crate::relay::media_events::MediaEventKind::PlaybackEnded,
                );
                continue;
            };
            let (slot, dst) = (
                p.slot,
                self.legs
                    .get(p.slot)
                    .copied()
                    .flatten()
                    .and_then(|l| l.latch.target()),
            );
            let len = 12 + PLAY_FRAME;
            let due = self.playbacks[k].next_ms;
            // In-band keys to the same slot are audio too: while they play,
            // the announcement goes on underneath, unsent.
            let keys = self.tone_plays.iter().any(|t| t.slot == slot && t.inband());
            let Some(Some(stream)) = self.play_streams.get_mut(slot) else {
                let p = self.playbacks.swap_remove(k);
                self.end_play(Kind::Announcement, p.slot, p.other, p.call);
                continue;
            };
            stream.advance(due, PLAY_PER_MS);
            let stamp = (!keys).then(|| (stream.ssrc, stream.take_seq(), stream.ts));
            if let Some((ssrc, seq, ts)) = stamp {
                let p = &self.playbacks[k];
                let buf = &mut self.bufs[..len];
                buf[0] = 0x80;
                buf[1] = p.media.pt.header_octet(p.first);
                buf[2..4].copy_from_slice(&seq.to_be_bytes());
                buf[4..8].copy_from_slice(&ts.to_be_bytes());
                buf[8..12].copy_from_slice(&ssrc.to_be_bytes());
                let chunk = &p.media.codes[at..at + n];
                buf[12..12 + chunk.len()].copy_from_slice(chunk);
                buf[12 + chunk.len()..].fill(crate::media_file::silence(p.media.pt));
            }
            let p = &mut self.playbacks[k];
            if stamp.is_some() {
                p.first = false;
            }
            // Paced at 20 ms; after a stall, start again from now.
            p.next_ms = if now > p.next_ms + 100 {
                now + 20
            } else {
                p.next_ms + 20
            };
            k += 1;
            let (Some(dst), Some(_)) = (dst, stamp) else {
                continue;
            };
            let (send_slot, len) = self.outbound(slot, 0, len);
            if let Some(len) = len {
                self.send(send_slot, &[(slot, Some(dst), 0, len)]);
            }
        }
    }

    /// Start (into `path`) or stop recording `call`. A call in the fast
    /// path stays there: the kernel copies its packets to the relay
    /// (`Command::Recorded`).
    pub(super) fn record(&mut self, call: CallId, spec: Option<crate::recording::Spec>) {
        let Some(c) = self.calls.get_mut(&call) else {
            return;
        };
        let slots = c.slots;
        let Some(spec) = spec else {
            if let Some(r) = self.recorders.remove(&call) {
                r.finish(true);
            }
            for s in slots {
                if let Some(r) = self.record_to.get_mut(s) {
                    *r = None;
                }
            }
            self.refresh_offload(call);
            return;
        };
        let path = spec.path.as_path();
        match crate::recording::Recorder::open(path) {
            Ok(r) => {
                let r = r.writing_on(self.rec_writer.clone());
                let r = match spec.conversion {
                    Some(c) => r.converting(c, self.jobs.clone()),
                    None => r,
                };
                // Recording again into another file: the first one ends
                // (and is converted) rather than being dropped unfinished.
                if let Some(old) = self.recorders.insert(call, r)
                    && old.path() != path
                {
                    old.finish(true);
                }
                log::info!("call {call}: recording to {}", path.display());
            }
            Err(e) => {
                log::warn!("call {call}: recording to {}: {e}", path.display());
                self.media_events.emit(
                    crate::relay::media_events::Subject::Call(call),
                    crate::relay::media_events::MediaEventKind::Failed {
                        what: "recording",
                        reason: e.kind().to_string(),
                    },
                );
                return;
            }
        }
        for s in slots {
            let local = self
                .sockets
                .get(s)
                .and_then(Option::as_ref)
                .and_then(|k| k.local_addr().ok());
            if let (Some(r), Some(local)) = (self.record_to.get_mut(s), local) {
                *r = Some((call, local));
            }
        }
        self.refresh_offload(call);
    }

    /// Pause or resume recording `call`: its packets stop or start being
    /// written; the file stays open.
    pub(super) fn pause_record(&mut self, call: CallId, paused: bool) {
        let Some(c) = self.calls.get(&call) else {
            return;
        };
        if !self.recorders.contains_key(&call) {
            return;
        }
        for s in c.slots {
            let local = self
                .sockets
                .get(s)
                .and_then(Option::as_ref)
                .and_then(|k| k.local_addr().ok());
            if let Some(r) = self.record_to.get_mut(s) {
                *r = if paused {
                    None
                } else {
                    local.map(|l| (call, l))
                };
            }
        }
        self.refresh_offload(call);
    }

    /// Set or clear what is blocked of one side's RTP. A call in the
    /// kernel stays there: its flows drop what is blocked.
    pub(super) fn block(&mut self, call: CallId, leg: CallLeg, what: Blocked, on: bool) {
        let Some(c) = self.calls.get_mut(&call) else {
            return;
        };
        let slot = c.slots[leg.rtp_slot()];
        let bit = match what {
            Blocked::Media => BLOCK_MEDIA,
            Blocked::Dtmf => BLOCK_DTMF,
            Blocked::Silence => BLOCK_SILENCE,
            Blocked::Copies => BLOCK_COPIES,
            Blocked::CopiesSilence => BLOCK_COPIES_SILENCE,
        };
        if let Some(b) = self.blocked.get_mut(slot) {
            if on {
                *b |= bit;
            } else {
                *b &= !bit;
            }
        }
        self.refresh_offload(call);
    }

    /// Look at a packet the relay decided to forward from `leg`: read its
    /// RTCP reports, transcode it, and say what is relayed: its length, or
    /// `None` when it is held back (blocked: received, counted and its
    /// events detected, but not relayed) or cannot be transcoded.
    pub(super) fn inspect(
        &mut self,
        leg: Slot,
        decision: Decision,
        (at, len): (usize, usize),
        src: SocketAddr,
        now: u64,
    ) -> Option<usize> {
        let Decision::Forward { out_slot, dst } = decision else {
            return Some(len);
        };
        let pkt = &self.bufs[at..at + len];
        if let Some(Some((call, local))) = self.record_to.get(leg).copied()
            && let Some(r) = self.recorders.get_mut(&call)
        {
            r.packet(src, local, pkt);
        }
        // RTCP (muxed RTCP was demultiplexed onto the RTCP leg).
        if leg.is_rtcp() {
            observe_rtcp(&mut self.rtcp, leg, out_slot, pkt, now);
            return Some(len);
        }
        if self.held_back(leg, pkt) {
            return None;
        }
        if self
            .blocked
            .get(leg)
            .is_some_and(|b| b & BLOCK_SILENCE != 0)
            && !self.is_event(leg, pkt)
        {
            self.silence(at, len)?;
        }
        // Echoed (`media echo`): back to the sender as it sent it, in its
        // own codec and packet time.
        if out_slot == leg && self.echoing.get(leg).copied().unwrap_or(false) {
            return Some(len);
        }
        let pkt = &self.bufs[at..at + len];
        let passes =
            |pt: Pt, t: &crate::relay::transcode::Transcoder| pt == t.config.from.0 || pt == Pt::CN;
        match self.transcode.get(leg) {
            // Being transcoded, the receiver only knows the codec it was
            // given: the sender's own codec is converted, its telephone
            // events and comfort noise pass, anything else is dropped.
            Some(Some(t))
                if !pkt.get(1).is_some_and(|&b| passes(Pt::of_header(b), t))
                    && !self.is_event(leg, pkt) =>
            {
                None
            }
            Some(Some(_)) => {
                let len = self
                    .transcode
                    .get_mut(leg)?
                    .as_mut()?
                    .packet(&mut self.bufs[at..at + self.packet_buffer], len)?;
                self.repacked(leg, (at, len), (out_slot, dst), now)
            }
            _ => self.repacked(leg, (at, len), (out_slot, dst), now),
        }
    }

    /// Whether the RTP packet `pkt` arriving on `slot` is held back.
    pub(super) fn held_back(&self, slot: Slot, pkt: &[u8]) -> bool {
        let b = self.blocked.get(slot).copied().unwrap_or(0);
        if b == 0 || slot.is_rtcp() {
            return false;
        }
        b & (BLOCK_MEDIA | BLOCK_PLAY) != 0 || (b & BLOCK_DTMF != 0 && self.is_event(slot, pkt))
    }

    /// Whether `pkt` from `slot` is a telephone event of the side.
    pub(super) fn is_event(&self, slot: Slot, pkt: &[u8]) -> bool {
        pkt.get(1).is_some_and(|&m| {
            self.dtmf
                .get(slot)
                .and_then(Option::as_ref)
                .is_some_and(|d| d.pt == Pt::of_header(m))
        })
    }

    /// Replace the G.711 audio of the RTP packet at `bufs[at..at + len]` by
    /// silence; `None` (held back) for other payloads.
    pub(super) fn silence(&mut self, at: usize, len: usize) -> Option<()> {
        let (start, n, pt) = match rtpflux_core::rtp::Packet::parse(self.bufs.get(at..at + len)?) {
            Ok(p) => (
                p.as_bytes().len() - p.payload().len() - p.padding(),
                p.payload().len(),
                p.payload_type(),
            ),
            Err(_) => return None,
        };
        if pt != rtpflux_core::g711::PT_PCMU && pt != rtpflux_core::g711::PT_PCMA {
            return None;
        }
        self.bufs
            .get_mut(at + start..at + start + n)?
            .fill(crate::media_file::silence(pt));
        Some(())
    }
}
