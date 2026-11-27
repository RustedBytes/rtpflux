//! The hot path: receiving a batch, deciding, protecting and sending.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Where a received datagram goes.
pub(super) enum Demux {
    /// RTP or RTCP of this leg.
    Media(Slot),
    /// ZRTP of this leg, or any datagram of a leg that is not RTP (T.38's
    /// UDPTL): relayed untouched (no SRTP, RTP parsing, DTMF, recording or
    /// transcoding).
    Opaque(Slot),
    /// STUN or DTLS, answered here.
    Handled,
    Dropped,
}

impl Worker {
    /// Read and relay everything waiting on `slot`'s socket.
    pub(super) fn drain(&mut self, slot: Slot, now: u64) {
        let Some(fd) = self
            .sockets
            .get(slot)
            .and_then(Option::as_ref)
            .map(AsRawFd::as_raw_fd)
        else {
            return;
        };
        for _ in 0..MAX_ROUNDS {
            // (length, source) of each received datagram; `None` = unusable.
            let mut meta: [Option<(usize, SocketAddr)>; MAX_BATCH] = [None; MAX_BATCH];
            let received = {
                let size = self.packet_buffer;
                let mut chunks = self.bufs[..self.batch * size].chunks_mut(size);
                let mut iovs: [[IoSliceMut<'_>; 1]; MAX_BATCH] =
                    core::array::from_fn(|_| [IoSliceMut::new(chunks.next().unwrap_or_default())]);
                match recvmmsg(
                    fd,
                    &mut self.recv_hdr,
                    iovs.iter_mut().take(self.batch),
                    MsgFlags::MSG_DONTWAIT,
                    None,
                ) {
                    Ok(results) => {
                        let mut k = 0;
                        for m in results {
                            if k < MAX_BATCH {
                                meta[k] = (!m.flags.contains(MsgFlags::MSG_TRUNC))
                                    .then(|| {
                                        m.address.as_ref().and_then(to_std).map(|a| (m.bytes, a))
                                    })
                                    .flatten();
                                k += 1;
                            }
                        }
                        k
                    }
                    Err(Errno::EAGAIN | Errno::EINTR) => 0,
                    Err(e) => {
                        log::debug!("media worker {}: recvmmsg on slot {slot}: {e}", self.index);
                        0
                    }
                }
            };
            if received == 0 {
                return;
            }
            self.relay_batch(slot, &meta[..received], now);
            if received < self.batch {
                return;
            }
        }
    }

    /// Relay the datagrams the `AF_XDP` receive threads queued for this
    /// worker, as if their slots' sockets had received them: runs of one
    /// slot go through [`Worker::relay_batch`] together.
    pub(super) fn drain_xsk(&mut self, now: u64) {
        let size = self.packet_buffer;
        for _ in 0..MAX_ROUNDS {
            let mut meta: [Option<(usize, SocketAddr)>; MAX_BATCH] = [None; MAX_BATCH];
            let mut slot = None;
            let mut n = 0;
            let mut rest = None;
            {
                let Some(rx) = &self.xsk else {
                    return;
                };
                while n < self.batch {
                    let Ok(d) = rx.try_recv() else {
                        break;
                    };
                    if slot.is_some_and(|s| s != d.slot) {
                        // Another slot: relayed in the next run.
                        rest = Some(d);
                        break;
                    }
                    slot = Some(d.slot);
                    let len = usize::from(d.len);
                    if len > size || len > d.data.len() {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    self.bufs[n * size..n * size + len].copy_from_slice(&d.data[..len]);
                    meta[n] = Some((len, d.src));
                    n += 1;
                }
            }
            if let Some(s) = slot {
                self.relay_run(s, &meta[..n], now);
            }
            match rest {
                // Its run starts the next round.
                Some(d) => self.requeue_xsk(&d, now),
                None if n < self.batch => return,
                None => {}
            }
        }
        // Out of rounds with datagrams perhaps left: come back to them
        // after the sockets (no wake-up of their own may follow).
        let _ = self.wake.write(1);
    }

    /// Relay one run of datagrams that arrived for `slot` other than by its
    /// socket (`AF_XDP`, `io_uring`), in the batch buffers; none when the
    /// slot has no socket (the call is gone).
    pub(super) fn relay_run(&mut self, slot: Slot, meta: &[Option<(usize, SocketAddr)>], now: u64) {
        if meta.is_empty() {
            return;
        }
        if self.sockets.get(slot).is_some_and(Option::is_some) {
            self.relay_batch(slot, meta, now);
        } else {
            self.stats
                .dropped
                .fetch_add(meta.len() as u64, Ordering::Relaxed);
        }
    }

    /// Relay one datagram taken off the queue ahead of its run.
    fn requeue_xsk(&mut self, d: &super::super::xsk::XskDatagram, now: u64) {
        let len = usize::from(d.len);
        if len > self.packet_buffer || len > d.data.len() {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.bufs[..len].copy_from_slice(&d.data[..len]);
        self.relay_run(d.slot, &[Some((len, d.src))], now);
    }

    /// Prepare `bufs[at..at + len]` for leg `out_slot`: encrypt it with the
    /// leg's keys (a bundled member: its own SDES keys, else the shared
    /// transport's) and pick the socket: a bundled member's is the shared
    /// port's, a muxed side's RTCP leaves through its RTP socket. `None`
    /// length: no room for the SRTP trailer, not RTP/RTCP, or keys pending.
    pub(super) fn outbound(
        &mut self,
        out_slot: Slot,
        at: usize,
        len: usize,
    ) -> (Slot, Option<usize>) {
        let via = self.via.get(out_slot).copied().flatten();
        let own = self.crypto.get(out_slot).is_some_and(Option::is_some);
        let crypto_slot = match via {
            // The shared port's RTP or RTCP leg, as this one is.
            Some(p) if !own => {
                if out_slot.is_rtcp() {
                    p.rtcp()
                } else {
                    p
                }
            }
            _ => out_slot,
        };
        let buf = &mut self.bufs[at..at + self.packet_buffer];
        let len = match self.crypto.get_mut(crypto_slot).and_then(Option::as_mut) {
            None => Some(len),
            Some(c) => c.protect(buf, len),
        };
        (self.send_slot(out_slot), len)
    }

    /// The socket a packet for `out_slot` leaves from: a BUNDLE group's
    /// shared port, the RTP port for muxed RTCP, or its own.
    pub(super) fn send_slot(&self, out_slot: Slot) -> Slot {
        if let Some(p) = self.via.get(out_slot).copied().flatten() {
            p
        } else if out_slot.is_rtcp() && self.muxed.get(out_slot).copied().unwrap_or(false) {
            out_slot.rtp()
        } else {
            out_slot
        }
    }

    /// Where ZRTP (or a non-RTP datagram) from `src` on `leg`, at
    /// `bufs[at..at + len]`, goes (socket slot, destination):
    /// latched and forwarded as it is where the call is a plain relay;
    /// `None` (dropped) where the relay changes the media, or the leg
    /// drops it (wrong source, no destination yet). ZRTP of a recorded
    /// call is recorded too: it marks the recording as encrypted end to
    /// end, which is then not converted.
    pub(super) fn opaque(
        &mut self,
        leg: Slot,
        src: SocketAddr,
        (at, len): (usize, usize),
        now: u64,
    ) -> Option<(Slot, SocketAddr)> {
        if self.transforms(leg) {
            return None;
        }
        match relay::on_packet(self.legs.as_mut_slice(), leg, src, len, now) {
            Decision::Forward { out_slot, dst } => {
                if !self.opaque.get(leg).copied().unwrap_or(false) {
                    self.stats.zrtp.fetch_add(1, Ordering::Relaxed);
                    if let Some(Some((call, local))) = self.record_to.get(leg).copied()
                        && let Some(r) = self.recorders.get_mut(&call)
                    {
                        r.packet(src, local, &self.bufs[at..at + len]);
                    }
                }
                Some((self.send_slot(out_slot), dst))
            }
            Decision::Drop(_) => None,
        }
    }

    /// Whether the relay changes the media between `leg` and its partner:
    /// it terminates SRTP (SDES or DTLS) on either side, transcodes, or
    /// sorts a BUNDLE group. End-to-end ZRTP cannot work across such a
    /// call (the SDP's `a=zrtp-hash` was removed for the same reason).
    pub(super) fn transforms(&self, leg: Slot) -> bool {
        let Some(partner) = self.legs.get(leg).copied().flatten().map(|l| l.partner) else {
            return true;
        };
        [leg, leg.rtp(), partner, partner.rtp()]
            .into_iter()
            .any(|s| {
                self.crypto.get(s).is_some_and(Option::is_some)
                    || self.dtls.get(s).is_some_and(Option::is_some)
                    || self.transcode.get(s).is_some_and(Option::is_some)
                    || self.routes.get(s).is_some_and(Option::is_some)
                    || self.via.get(s).copied().flatten().is_some()
            })
    }

    /// What the datagram at `bufs[at..at + len]` on `slot` is (RFC 5764
    /// §5.1.2): STUN and DTLS are handled here; RTP and RTCP go on, RTCP on
    /// an RTP port (RFC 5761) as the RTCP leg's.
    pub(super) fn demux(
        &mut self,
        slot: Slot,
        at: usize,
        len: usize,
        src: SocketAddr,
        now: u64,
    ) -> Demux {
        let Some(packet) = self.bufs.get(at..at + len) else {
            return Demux::Dropped;
        };
        // An empty datagram is legal UDP and says nothing.
        let Some(&first) = packet.first() else {
            return Demux::Dropped;
        };
        // Not RTP (T.38's UDPTL…): its first octet means nothing here.
        if self.opaque.get(slot).copied().unwrap_or(false) {
            return Demux::Opaque(slot);
        }
        let kind = stun::classify(first);
        // A full ICE agent towards the side takes its STUN.
        if matches!(kind, Kind::Stun) && self.ice_stun(slot, (at, len), src, now) {
            return Demux::Handled;
        }
        let Some(packet) = self.bufs.get(at..at + len) else {
            return Demux::Dropped;
        };
        match kind {
            Kind::Rtp if !slot.is_rtcp() && stun::is_muxed_rtcp(packet) => {
                Demux::Media(slot.rtcp())
            }
            Kind::Rtp => Demux::Media(slot),
            Kind::Stun => {
                let target = |legs: &PerSlot<Option<Leg>>| {
                    legs.get(slot)
                        .copied()
                        .flatten()
                        .and_then(|l| l.latch.target())
                };
                let before = target(&self.legs);
                let mut t = IceLegs {
                    ice: &self.ice,
                    muxed: &self.muxed,
                    sockets: &self.sockets,
                    legs: &mut self.legs,
                };
                answer_stun(&mut t, slot, packet, src, &mut self.stun_out);
                // ICE moved the side: a call in the kernel gets its flows
                // again (to the new address), or comes back.
                if target(&self.legs) != before
                    && let Some(call) = self.call_of(slot)
                {
                    self.refresh_offload(call);
                }
                Demux::Handled
            }
            Kind::Dtls => {
                let mut t = DtlsTables {
                    dtls: &mut self.dtls,
                    crypto: &mut self.crypto,
                    legs: &mut self.legs,
                    sockets: &self.sockets,
                    muxed: &self.muxed,
                    identity: &self.identity,
                    stats: &self.stats,
                    done: None,
                };
                t.datagram(slot, packet, src, now);
                let done = t.done;
                self.report_dtls(done);
                Demux::Handled
            }
            // On an RTP port (or its RTCP twin); ZRTP has no RTCP.
            Kind::Zrtp => Demux::Opaque(slot),
            Kind::Drop => Demux::Dropped,
        }
    }

    /// Decide every datagram of a batch and send the accepted ones, one
    /// `sendmmsg` per run of datagrams with the same outgoing socket.
    ///
    /// On an RTP port, the first octet tells STUN (answered when the side
    /// uses ICE), DTLS (not terminated: dropped) and RTP/RTCP apart (RFC
    /// 5764 §5.1.2); RTCP arriving on an RTP port (RFC 5761) is handled as
    /// the RTCP leg's.
    pub(super) fn relay_batch(
        &mut self,
        slot: Slot,
        meta: &[Option<(usize, SocketAddr)>],
        now: u64,
    ) {
        // (outgoing socket slot, destination, buffer index, length); only
        // the first `n` are filled.
        let mut out: [(Slot, Option<SocketAddr>, usize, usize); MAX_BATCH] =
            [(Slot::new(0), None, 0, 0); MAX_BATCH];
        let mut n = 0;
        let mut dropped = 0u64;
        let mut rejected = 0u64;
        let size = self.packet_buffer;
        for (i, m) in meta.iter().enumerate() {
            let Some((len, src)) = *m else {
                dropped += 1;
                continue;
            };
            let leg = match self.demux(slot, i * size, len, src, now) {
                Demux::Media(leg) => leg,
                Demux::Opaque(leg) => {
                    if let Some((send_slot, dst)) = self.opaque(leg, src, (i * size, len), now) {
                        out[n] = (send_slot, Some(dst), i, len);
                        n += 1;
                    } else {
                        dropped += 1;
                    }
                    continue;
                }
                Demux::Handled => continue,
                Demux::Dropped => {
                    dropped += 1;
                    continue;
                }
            };
            let buf = &mut self.bufs[i * size..(i + 1) * size];
            // A BUNDLE group's shared port: sort into the member by the
            // header (in clear under SRTP too).
            let arrived = leg;
            let Some(leg) = super::bundle::sort(&self.routes, arrived, &buf[..len]) else {
                dropped += 1;
                continue;
            };
            // SRTP in, with the member's own keys (SDES is per section) or
            // the shared transport's (DTLS): only authentic packets reach
            // the latch.
            let key_slot = if self.crypto.get(leg).is_some_and(Option::is_some) {
                leg
            } else {
                arrived
            };
            let len = match self.crypto.get_mut(key_slot).and_then(Option::as_mut) {
                None => len,
                Some(c) => {
                    if let Some(l) = c.unprotect(buf, len) {
                        l
                    } else {
                        rejected += 1;
                        continue;
                    }
                }
            };
            if leg != arrived
                && !leg.is_rtcp()
                && let Some(route) = self.routes.get_mut(arrived.rtp()).and_then(Option::as_mut)
            {
                route.learn(&buf[..len], leg);
            }
            self.sync_via(leg);
            let decision = relay::on_packet(self.legs.as_mut_slice(), leg, src, len, now);
            if !self.pcm_slots.is_empty() {
                self.pcm_in(leg, (i * size, len));
            }
            if self.subscriptions_in(leg, decision, (i * size, len), now) {
                continue;
            }
            if self.dtmf_in(leg, decision, (i * size, len), now) {
                continue;
            }
            let Some(len) = self.inspect(leg, decision, (i * size, len), src, now) else {
                continue;
            };
            if matches!(decision, Decision::Forward { .. })
                && self.forward_remote(leg, (i * size, len))
            {
                continue;
            }
            match decision {
                Decision::Forward { out_slot, dst } => {
                    let (send_slot, len) = self.outbound(out_slot, i * size, len);
                    if let Some(len) = len {
                        out[n] = (send_slot, Some(dst), i, len);
                        n += 1;
                    } else {
                        // No room for the SRTP trailer, or not RTP/RTCP.
                        dropped += 1;
                    }
                }
                Decision::Drop(_) => dropped += 1,
            }
        }
        if dropped > 0 {
            self.stats.dropped.fetch_add(dropped, Ordering::Relaxed);
        }
        if rejected > 0 {
            self.stats
                .srtp_rejected
                .fetch_add(rejected, Ordering::Relaxed);
        }
        self.send_grouped(&out[..n]);
        if !self.wake_peers.is_empty() {
            self.wake_peers();
        }
    }

    /// [`Self::send`] each run of `items` that leaves by the same socket,
    /// keeping their order.
    pub(super) fn send_grouped(&mut self, items: &[(Slot, Option<SocketAddr>, usize, usize)]) {
        let mut start = 0;
        while start < items.len() {
            let os = items[start].0;
            let mut end = start + 1;
            while end < items.len() && items[end].0 == os {
                end += 1;
            }
            self.send(os, &items[start..end]);
            start = end;
        }
    }

    pub(super) fn send(
        &mut self,
        out_slot: Slot,
        items: &[(Slot, Option<SocketAddr>, usize, usize)],
    ) {
        let Some(fd) = self
            .sockets
            .get(out_slot)
            .and_then(Option::as_ref)
            .map(AsRawFd::as_raw_fd)
        else {
            self.stats
                .dropped
                .fetch_add(items.len() as u64, Ordering::Relaxed);
            return;
        };
        let size = self.packet_buffer;
        let n = items.len().min(MAX_BATCH);
        // Only this batch's destinations are written (into the worker's
        // array, not a fresh one of MAX_BATCH per send).
        for (a, it) in self.send_addrs.iter_mut().zip(&items[..n]) {
            *a = it.1.map(SockaddrStorage::from);
        }
        let bufs = &self.bufs;
        let iovs: [[IoSlice<'_>; 1]; MAX_BATCH] = core::array::from_fn(|k| {
            let s = items
                .get(k)
                .map_or(&[][..], |&(_, _, i, len)| &bufs[i * size..i * size + len]);
            [IoSlice::new(s)]
        });
        let cmsgs: [ControlMessage<'_>; 0] = [];
        let sent = match sendmmsg(
            fd,
            &mut self.send_hdr,
            iovs[..n].iter(),
            &self.send_addrs[..n],
            cmsgs,
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(results) => results.count(),
            Err(e) => {
                log::trace!(
                    "media worker {}: sendmmsg on slot {out_slot}: {e}",
                    self.index
                );
                0
            }
        };
        self.stats
            .forwarded
            .fetch_add(sent as u64, Ordering::Relaxed);
        let bytes: usize = items[..sent.min(n)].iter().map(|it| it.3).sum();
        self.stats
            .forwarded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if sent < n {
            self.stats
                .send_errors
                .fetch_add((n - sent) as u64, Ordering::Relaxed);
        }
    }
}
