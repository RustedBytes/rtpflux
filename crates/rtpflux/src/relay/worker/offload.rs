//! Moving settled calls into the XDP fast path.

use super::features::{BLOCK_MEDIA, BLOCK_PLAY, BLOCK_SILENCE};
#[allow(clippy::wildcard_imports)]
use super::*;

/// Packets each RTP leg must have relayed before its call is offered to XDP.
pub(super) const OFFLOAD_MIN_PACKETS: u64 = 10;

/// Delay before offering a refused call again.
pub(super) const OFFLOAD_RETRY_MS: u64 = 10_000;
/// How long an offer to the kernel may wait for its answer (which can be
/// lost when the worker's queue is full) before the call is taken back
/// and offered again later.
pub(super) const OFFLOAD_ANSWER_MS: u64 = 10_000;

impl Worker {
    /// What the kernel does with what `slot`'s peer sends, besides relaying
    /// it: its telephone events go up when they are detected (and then
    /// relayed or blocked here), it is dropped while blocked or held back
    /// for an announcement, and copied up while recorded. Returns (flags,
    /// event payload type).
    fn kernel_flags(&self, slot: Slot) -> (u8, u8) {
        use rtpflux_xdp_common::flags;
        let mut f = 0;
        let mut event_pt = 0;
        if let Some(Some(d)) = self.dtmf.get(slot) {
            f |= flags::EVENTS_UP;
            // The kernel's flow action: the payload type as an octet.
            event_pt = d.pt.get();
        }
        if self
            .blocked
            .get(slot)
            .is_some_and(|&b| b & (BLOCK_MEDIA | BLOCK_PLAY) != 0)
        {
            f |= flags::DROP;
        }
        if self.record_to.get(slot).is_some_and(Option::is_some) {
            f |= flags::RECORD;
        }
        (f, event_pt)
    }

    /// The two RTP directions of a call, if both are settled, of one address
    /// family and have carried traffic.
    pub(super) fn offload_dirs(&self, c: &CallSlots, now: u64) -> Option<[Dir; 2]> {
        let (sa, sb) = (c.slots[0], c.slots[2]);
        let a = self.legs.get(sa).copied().flatten()?;
        let b = self.legs.get(sb).copied().flatten()?;
        // Silence rewrites payloads: userspace only.
        let silenced = |slot: Slot| {
            self.blocked
                .get(slot)
                .is_some_and(|b| b & BLOCK_SILENCE != 0)
        };
        if silenced(sa) || silenced(sb) {
            return None;
        }
        let has_srtp = |slot: Slot| self.crypto.get(slot).is_some_and(Option::is_some);
        // The fast path relays port to port: no SRTP, and RTCP must take the
        // same kind of port on both sides.
        let bundled = |slot: Slot| {
            self.via.get(slot).is_some_and(Option::is_some)
                || self.routes.get(slot).is_some_and(Option::is_some)
        };
        // Transcoding happens here: such legs stay. (Telephone events,
        // blocking, announcements and recording are flags of the kernel's
        // flows: `kernel_flags`.)
        let detects = |slot: Slot| {
            self.transcode.get(slot).is_some_and(Option::is_some)
                || self.repack.get(slot).is_some_and(Option::is_some)
                || self.pcm_legs.get(slot).is_some_and(Option::is_some)
        };
        if has_srtp(sa)
            || has_srtp(sb)
            || bundled(sa)
            || bundled(sb)
            || detects(sa)
            || detects(sb)
            || self.tapped(sa)
            || self.tapped(sb)
            || self.secured(sa)
            || self.secured(sb)
            || self.is_sink(sa)
        {
            return None;
        }
        // Where each side's media goes: the call's other side, or (after
        // `connect` or `media echo`) another leg of this worker, the side
        // itself, or nowhere (dropped in the kernel).
        let route = |own: Leg, s: Slot| {
            if own.partner == super::connect::DETACHED {
                (s, true)
            } else {
                (own.partner, false)
            }
        };
        let (pa, drop_a) = route(a, sa);
        let (pb, drop_b) = route(b, sb);
        let local = |slot: Slot| self.sockets.get(slot)?.as_ref()?.local_addr().ok();
        let ((out_a, target_a), (out_b, target_b)) =
            (self.flow_out(sa, pa, now)?, self.flow_out(sb, pb, now)?);
        // Traffic both ways, or (`unidirectional`) one way; a side whose
        // media is dropped needs none. Both sides settled all the same, so
        // the kernel never sends to an address that may still change.
        let oneway = |s: Slot| self.oneway.get(s).copied().unwrap_or(false);
        let (sent_a, sent_b) = (
            drop_a || a.packets >= OFFLOAD_MIN_PACKETS,
            drop_b || b.packets >= OFFLOAD_MIN_PACKETS,
        );
        let carried = if oneway(sa) || oneway(sb) {
            sent_a || sent_b
        } else {
            sent_a && sent_b
        };
        if !carried || !a.latch.settled(now) || !b.latch.settled(now) {
            return None;
        }
        let (peer_a, peer_b) = (a.latch.target()?, b.latch.target()?);
        let (local_a, local_b) = (local(sa)?, local(sb)?);
        // The frame keeps its header layout: one family throughout.
        let v4 = peer_a.is_ipv4();
        if [peer_b, local_a, local_b, out_a, out_b, target_a, target_b]
            .iter()
            .any(|x| x.is_ipv4() != v4)
        {
            return None;
        }
        let ((flags_a, pt_a), (flags_b, pt_b)) = (self.kernel_flags(sa), self.kernel_flags(sb));
        let dropped = |drop: bool| {
            if drop {
                rtpflux_xdp_common::flags::DROP
            } else {
                0
            }
        };
        Some([
            Dir {
                peer: peer_a,
                local: local_a,
                out_local: out_a,
                target: target_a,
                flags: flags_a | dropped(drop_a),
                event_pt: pt_a,
            },
            Dir {
                peer: peer_b,
                local: local_b,
                out_local: out_b,
                target: target_b,
                flags: flags_b | dropped(drop_b),
                event_pt: pt_b,
            },
        ])
    }

    /// Where the kernel sends what slot `s`'s peer sends, its media going
    /// to partner slot `p`: (relay address, target). A leg connected to
    /// another worker: what that worker published (only for a settled,
    /// plain leg with the same kind of RTCP port). A partner here: settled,
    /// plain, the same kind of RTCP port, nothing converted.
    fn flow_out(&self, s: Slot, p: Slot, now: u64) -> Option<(SocketAddr, SocketAddr)> {
        let muxed = |slot: Slot| self.muxed.get(slot).copied().unwrap_or(false);
        if self.remote.get(s).is_some_and(Option::is_some) {
            let (relay, target, theirs_muxed) = self.remote_target(s)?;
            return (theirs_muxed == muxed(s)).then_some((relay, target));
        }
        let to = self.legs.get(p).copied().flatten()?;
        let plain = self.crypto.get(p).is_none_or(Option::is_none);
        let converts = self.transcode.get(p).is_some_and(Option::is_some)
            || self.repack.get(p).is_some_and(Option::is_some);
        let bundled = self.via.get(p).is_some_and(Option::is_some)
            || self.routes.get(p).is_some_and(Option::is_some);
        if !plain || muxed(s) != muxed(p) || converts || bundled || !to.latch.settled(now) {
            return None;
        }
        let local = self.sockets.get(p)?.as_ref()?.local_addr().ok()?;
        Some((local, to.latch.target()?))
    }

    /// Offer settled calls to the XDP controller.
    pub(super) fn offer_settled(&mut self, now: u64) {
        let Some(tx) = self.offload.clone() else {
            return;
        };
        self.sweep_remote(now);
        // Offers whose answer never came: taken back (in case they were
        // installed after all), offered again later.
        for (&call, c) in &mut self.calls {
            if let OffloadState::Pending(t) = c.offload
                && now.saturating_sub(t) >= OFFLOAD_ANSWER_MS
            {
                let _ = tx.send(OffloadMsg::Remove { call });
                c.offload = OffloadState::RetryAt(now + OFFLOAD_RETRY_MS);
            }
        }
        let mut offered = Vec::new();
        for (&call, c) in &self.calls {
            let due = match c.offload {
                OffloadState::No => true,
                OffloadState::RetryAt(t) => now >= t,
                OffloadState::Pending(_) | OffloadState::Active => false,
            };
            if due && let Some(dirs) = self.offload_dirs(c, now) {
                offered.push((call, dirs));
            }
        }
        let active = self
            .calls
            .values()
            .filter(|c| matches!(c.offload, OffloadState::Active))
            .count();
        self.stats
            .offloaded_calls
            .store(active as u64, std::sync::atomic::Ordering::Relaxed);
        for (call, dirs) in offered {
            if tx
                .send(OffloadMsg::Install {
                    call,
                    shard: self.index,
                    dirs: Box::new(dirs),
                })
                .is_ok()
                && let Some(c) = self.calls.get_mut(&call)
            {
                c.offload = OffloadState::Pending(now);
            }
        }
    }

    /// A call in the kernel changed (blocking, an announcement): give the
    /// kernel its new flows, or take it back to userspace when it cannot
    /// stay.
    pub(super) fn refresh_offload(&mut self, call: CallId) {
        let now = self.now_ms();
        let Some(c) = self.calls.get(&call) else {
            return;
        };
        if !matches!(c.offload, OffloadState::Pending(_) | OffloadState::Active) {
            return;
        }
        let dirs = self.offload_dirs(c, now);
        let Some(tx) = self.offload.clone() else {
            return;
        };
        if let Some(dirs) = dirs {
            let _ = tx.send(OffloadMsg::Update {
                call,
                dirs: Box::new(dirs),
            });
        } else {
            let _ = tx.send(OffloadMsg::Remove { call });
            if let Some(c) = self.calls.get_mut(&call) {
                c.offload = OffloadState::No;
            }
        }
    }

    /// Report `kind` about the leg of `slot` to the control thread (a scan
    /// for its call: for rare events only).
    pub(super) fn emit_media(&self, slot: Slot, kind: crate::relay::media_events::MediaEventKind) {
        let rtp = slot.rtp();
        // Legs come as A-RTP, A-RTCP, B-RTP, B-RTCP.
        let found = self.calls.iter().find_map(|(&id, c)| {
            c.slots
                .iter()
                .position(|&s| s == rtp)
                .map(|i| (id, if i < 2 { CallLeg::A } else { CallLeg::B }))
        });
        if let Some((call, leg)) = found {
            self.media_events
                .emit(crate::relay::media_events::Subject::Leg(call, leg), kind);
        }
    }

    /// Report key presses that finished on `slot`.
    pub(super) fn report_dtmf(&self, slot: Slot, events: [Option<crate::relay::DtmfEvent>; 4]) {
        for e in events.into_iter().flatten() {
            self.emit_media(
                slot,
                crate::relay::media_events::MediaEventKind::Dtmf {
                    code: e.code,
                    duration_ms: e.duration_ms,
                    rtp_timestamp: e.ts,
                    inband: false,
                },
            );
        }
    }

    /// The call `slot` belongs to (a scan: for rare events only).
    pub(super) fn call_of(&self, slot: Slot) -> Option<CallId> {
        self.calls
            .iter()
            .find(|(_, c)| c.slots.contains(&slot))
            .map(|(&id, _)| id)
    }
}
