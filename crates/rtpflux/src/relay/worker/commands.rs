//! Commands from the control side: adding, updating, closing and
//! querying calls, and the kernel's activity reports.

#[allow(clippy::wildcard_imports)]
use super::*;

impl Worker {
    /// A command that joins, copies or secures legs (`connect`, `media
    /// echo`, copies, DTMF security).
    fn apply_joining(&mut self, cmd: Command) {
        match cmd {
            Command::ConnectLocal { x, y, transcode } => self.connect_local(x, y, transcode),
            Command::ConnectRemote(end) => self.connect_remote(*end),
            Command::Detach { slot } => self.detach(slot),
            Command::Barrier { reply } => {
                let _ = reply.try_send(());
            }
            Command::Pcm { call, slot, end } => self.pcm(call, slot, end.map(|e| *e)),
            Command::Echo { slots, modes } => self.echo(slots, modes),
            Command::SecureDtmf {
                call,
                leg,
                security,
            } => self.secure_dtmf(call, leg, security.map(|s| *s)),
            Command::Listen {
                source,
                dest,
                on,
                transcode,
            } => self.listen_local(source, dest, on, transcode),
            Command::ListenRemote(l) => self.listen_remote(*l),
            Command::ListenIncoming(end) => self.listen_incoming(*end),
            Command::Unlisten {
                source,
                worker,
                peer,
            } => self.unlisten_remote(source, worker, peer),
            _ => {}
        }
    }

    /// Apply queued commands; `false` on shutdown.
    pub(super) fn apply_commands(&mut self) -> bool {
        loop {
            match self.commands.try_recv() {
                Ok(Command::AddCall {
                    call,
                    legs,
                    timeout_ms,
                }) => self.add_call(call, *legs, timeout_ms),
                Ok(Command::RemoveCall { call }) => self.close_call(call, false),
                Ok(Command::Touch {
                    call,
                    packets,
                    octets,
                }) => self.touch(call, packets, octets),
                Ok(Command::Recorded { call, frames }) => {
                    if let Some(r) = self.recorders.get_mut(&call) {
                        r.append(&frames);
                    }
                }
                Ok(Command::Bundle { primary, members }) => self.bundle(primary, &members),
                Ok(
                    cmd @ (Command::ConnectLocal { .. }
                    | Command::ConnectRemote(_)
                    | Command::Detach { .. }
                    | Command::Pcm { .. }
                    | Command::Barrier { .. }
                    | Command::Echo { .. }
                    | Command::SecureDtmf { .. }
                    | Command::Listen { .. }
                    | Command::ListenRemote(_)
                    | Command::ListenIncoming(_)
                    | Command::Unlisten { .. }),
                ) => self.apply_joining(cmd),
                Ok(Command::Query { call, reply }) => {
                    let _ = reply.try_send(self.query(call));
                }
                Ok(Command::UpdatePeer {
                    call,
                    leg,
                    latches,
                    media,
                }) => self.update_peer(call, leg, latches[0], latches[1], &media),
                Ok(Command::Block {
                    call,
                    leg,
                    what,
                    on,
                }) => self.block(call, leg, what, on),
                Ok(Command::Record { call, spec }) => self.record(call, spec.map(|s| *s)),
                Ok(Command::PauseRecord { call, paused }) => self.pause_record(call, paused),
                Ok(Command::Sink { call }) => self.sink(call),
                Ok(Command::Tap {
                    source,
                    source_leg,
                    sub,
                    sub_leg,
                    on,
                }) => self.tap(source, source_leg, sub, sub_leg, on),
                Ok(Command::AwaitAnswer { call, within_ms }) => {
                    self.await_answer(call, within_ms);
                }
                Ok(Command::SetTimeout { call, timeout_ms }) => {
                    if let Some(c) = self.calls.get_mut(&call) {
                        c.timeout_ms = timeout_ms;
                    }
                }
                Ok(Command::Play { call, leg, media }) => self.play(call, leg, media.map(|m| *m)),
                Ok(Command::PlayTones { call, leg, tones }) => self.play_tones(call, leg, *tones),
                Ok(Command::IceStart { call, leg, start }) => self.ice_start(call, leg, &start),
                Ok(Command::IceCandidates {
                    call,
                    leg,
                    candidates,
                    end_of_candidates,
                }) => self.ice_candidates(call, leg, &candidates, end_of_candidates),
                Ok(Command::Offloaded { call, ok }) => {
                    let now = self.now_ms();
                    let pending = self
                        .calls
                        .get(&call)
                        .is_some_and(|c| matches!(c.offload, OffloadState::Pending(_)));
                    if pending && let Some(c) = self.calls.get_mut(&call) {
                        c.offload = if ok {
                            OffloadState::Active
                        } else {
                            OffloadState::RetryAt(now + OFFLOAD_RETRY_MS)
                        };
                    } else if ok && let Some(tx) = &self.offload {
                        // Taken back (or gone) meanwhile: the kernel must
                        // not go on relaying it.
                        let _ = tx.send(OffloadMsg::Remove { call });
                    }
                }
                Ok(Command::Shutdown) | Err(TryRecvError::Disconnected) => return false,
                Err(TryRecvError::Empty) => {
                    self.stats
                        .calls
                        .store(self.calls.len() as u64, Ordering::Relaxed);
                    return true;
                }
            }
        }
    }

    pub(super) fn add_call(&mut self, call: CallId, legs: [LegInit; 4], timeout_ms: u64) {
        let now = self.now_ms();
        let slots = legs.each_ref().map(|l| l.slot);
        for leg in legs {
            let slot = leg.slot;
            if self.legs.get(slot).is_none() {
                log::error!("media worker {}: slot {slot} outside the shard", self.index);
                continue;
            }
            if !self.uring_arm(slot, leg.socket.as_fd())
                && let Err(e) = self.epoll.add(
                    leg.socket.as_fd(),
                    EpollEvent::new(EpollFlags::EPOLLIN, u64::from(slot.get())),
                )
            {
                log::error!("media worker {}: epoll add: {e}", self.index);
                self.media_events.emit(
                    crate::relay::media_events::Subject::Call(call),
                    crate::relay::media_events::MediaEventKind::Failed {
                        what: "media",
                        reason: format!("a socket cannot be watched: {e}"),
                    },
                );
            }
            self.legs[slot] = Some(Leg::new(leg.latch, leg.partner, now));
            // Legs come as A-RTP, A-RTCP, B-RTP, B-RTCP.
            let rtcp = slot.is_rtcp();
            self.crypto[slot] = LegCrypto::new(leg.media.srtp, rtcp, leg.media.dtls.is_some());
            // One association per component; a muxed side's RTCP uses RTP's.
            self.dtls[slot] = leg
                .media
                .dtls
                .filter(|_| !(rtcp && leg.media.rtcp_mux))
                .map(|side| {
                    Box::new(DtlsLeg {
                        side,
                        assoc: None,
                        started_ms: now,
                    })
                });
            self.ice[slot] = leg.media.ice;
            self.dtmf[slot] = leg
                .media
                .dtmf
                .filter(|_| !slot.is_rtcp())
                .map(|(pt, rate)| DtmfLeg::new(pt, rate));
            self.xcode[slot] = leg
                .media
                .dtmf_xcode
                .filter(|_| !slot.is_rtcp())
                .map(|x| Box::new(dtmf_xcode::XcodeState::new(x)));
            self.muxed[slot] = leg.media.rtcp_mux;
            self.opaque[slot] = leg.media.opaque;
            self.transcode[slot] = leg
                .media
                .transcode
                .filter(|_| !slot.is_rtcp())
                .and_then(crate::relay::transcode::Transcoder::new);
            self.set_repack(slot, leg.media.repack);
            self.oneway[slot] = leg.media.unidirectional;
            self.sockets[slot] = Some(leg.socket);
        }
        self.calls.insert(
            call,
            CallSlots {
                slots,
                timeout_ms,
                offload: OffloadState::No,
                answer_by: None,
            },
        );
        self.start_dtls_clients(now, &slots);
    }

    pub(super) fn close_call(&mut self, call: CallId, timed_out: bool) {
        let Some(c) = self.calls.remove(&call) else {
            return;
        };
        if let Some(r) = self.recorders.remove(&call) {
            r.finish(true);
        }
        self.playbacks.retain(|p| p.call != call);
        self.tone_plays.retain(|t| t.call != call);
        self.ice_close(&c.slots);
        self.untap(&c.slots);
        self.pcm_forget(&c.slots);
        if matches!(c.offload, OffloadState::Pending(_) | OffloadState::Active)
            && let Some(tx) = &self.offload
        {
            let _ = tx.send(OffloadMsg::Remove { call });
        }
        // Before the slots are cleared: BUNDLE links to other calls, and
        // `connect`ions.
        self.unbundle(c.slots[0]);
        self.disconnect_call(call, &c.slots);
        self.secure_slots.retain(|s| !c.slots.contains(s));
        for slot in c.slots {
            self.uring_disarm(slot);
            if let Some(sock) = self.sockets.get_mut(slot).and_then(Option::take) {
                let _ = self.epoll.delete(sock.as_fd());
            }
            if let Some(l) = self.legs.get_mut(slot) {
                *l = None;
            }
            if let Some(c) = self.crypto.get_mut(slot) {
                *c = None;
            }
            if let Some(i) = self.ice.get_mut(slot) {
                *i = None;
            }
            if let Some(d) = self.dtls.get_mut(slot) {
                *d = None;
            }
            if let Some(v) = self.via.get_mut(slot) {
                *v = None;
            }
            if let Some(d) = self.dtmf.get_mut(slot) {
                *d = None;
            }
            if let Some(x) = self.xcode.get_mut(slot) {
                *x = None;
            }
            if let Some(s) = self.secure.get_mut(slot) {
                *s = None;
            }
            if let Some(x) = self.copy_xcode.get_mut(slot) {
                x.clear();
            }
            if let Some(c) = self.copied.get_mut(slot) {
                *c = [0; 2];
            }
            if let Some(b) = self.blocked.get_mut(slot) {
                *b = 0;
            }
            if let Some(r) = self.rtcp.get_mut(slot) {
                *r = RtcpLeg::default();
            }
            if let Some(t) = self.transcode.get_mut(slot) {
                *t = None;
            }
            self.set_repack(slot, None);
            if let Some(r) = self.record_to.get_mut(slot) {
                *r = None;
            }
            if let Some(r) = self.routes.get_mut(slot) {
                *r = None;
            }
            if let Some(s) = self.play_streams.get_mut(slot) {
                *s = None;
            }
            self.hold.forget(slot.index());
        }
        if timed_out {
            self.stats.calls_ended.fetch_add(1, Ordering::Relaxed);
        }
        self.stats
            .calls
            .store(self.calls.len() as u64, Ordering::Relaxed);
        let _ = self.events.send(Event::Closed { call, timed_out });
    }

    /// Replace one side's latches; the call leaves the fast path until it
    /// settles again (the controller is told to drop its flows).
    pub(super) fn update_peer(
        &mut self,
        call: CallId,
        leg: CallLeg,
        rtp: Latch,
        rtcp: Latch,
        media: &Media,
    ) {
        let srtp = media.srtp;
        let Some(c) = self.calls.get_mut(&call) else {
            return;
        };
        let (s_rtp, s_rtcp) = if leg == CallLeg::B {
            (c.slots[2], c.slots[3])
        } else {
            (c.slots[0], c.slots[1])
        };
        for (slot, latch, is_rtcp) in [(s_rtp, rtp, false), (s_rtcp, rtcp, true)] {
            if let Some(Some(leg)) = self.legs.get_mut(slot) {
                leg.latch = latch;
            }
            if let Some(i) = self.ice.get_mut(slot) {
                *i = media.ice;
            }
            if let Some(m) = self.muxed.get_mut(slot) {
                *m = media.rtcp_mux;
            }
            if let Some(o) = self.opaque.get_mut(slot) {
                *o = media.opaque;
            }
            if !is_rtcp
                && let Some(t) = self.transcode.get_mut(slot)
                && t.as_ref().map(|t| t.config) != media.transcode
            {
                // A new conversion starts with fresh codec state.
                *t = media
                    .transcode
                    .and_then(crate::relay::transcode::Transcoder::new);
            }
            if !is_rtcp {
                self.set_repack(slot, media.repack);
            }
            if let Some(o) = self.oneway.get_mut(slot) {
                *o = media.unidirectional;
            }
            if !is_rtcp && let Some(d) = self.dtmf.get_mut(slot) {
                match (d.as_ref().map(|l| (l.pt, l.rate)), media.dtmf) {
                    (old, new) if old == new => {}
                    (_, new) => *d = new.map(|(pt, rate)| DtmfLeg::new(pt, rate)),
                }
            }
            if !is_rtcp && let Some(x) = self.xcode.get_mut(slot) {
                match (x.as_ref().and_then(|s| s.x), media.dtmf_xcode) {
                    (old, new) if old == new => {}
                    (_, new) => *x = new.map(|x| Box::new(dtmf_xcode::XcodeState::new(x))),
                }
            }
            if let Some(side) = media.dtls {
                // RFC 5763 §6.7.1: the same role keeps the association (and
                // its keys); new fingerprints are checked against it.
                let kept = matches!(self.dtls.get(slot), Some(Some(l)) if l.side.role == side.role);
                let wanted = !(is_rtcp && media.rtcp_mux);
                if kept {
                    let progress = self.dtls[slot].as_mut().and_then(|l| {
                        l.side = side;
                        l.assoc.as_mut().map(|a| a.set_remote(side.remote))
                    });
                    if let Some(p) = progress {
                        let mut t = self.dtls_tables();
                        t.install(slot, p, None);
                        let done = t.done;
                        self.report_dtls(done);
                    }
                } else if let Some(d) = self.dtls.get_mut(slot) {
                    *d = wanted.then(|| {
                        Box::new(DtlsLeg {
                            side,
                            assoc: None,
                            started_ms: 0,
                        })
                    });
                    if let Some(c) = self.crypto.get_mut(slot) {
                        *c = LegCrypto::new(srtp, is_rtcp, true);
                    }
                }
                continue;
            }
            if let Some(d) = self.dtls.get_mut(slot) {
                *d = None;
            }
            // Only a changed key replaces its direction's context
            // (sequence, index and replay state); no DTLS hold any more.
            if let Some(c) = self.crypto.get_mut(slot) {
                LegCrypto::update(c, srtp, is_rtcp, false);
            }
        }
        // The full agent towards the side decides where its media goes.
        self.ice_apply(s_rtp, true);
        let now = self.now_ms();
        self.start_dtls_clients(now, &[s_rtp, s_rtcp]);
        let Some(c) = self.calls.get_mut(&call) else {
            return;
        };
        if matches!(c.offload, OffloadState::Pending(_) | OffloadState::Active) {
            if let Some(tx) = &self.offload {
                let _ = tx.send(OffloadMsg::Remove { call });
            }
            c.offload = OffloadState::No;
        }
    }

    pub(super) fn query(&self, call: CallId) -> QueryReply {
        let c = self.calls.get(&call)?;
        let now = self.now_ms();
        let in_kernel = matches!(c.offload, OffloadState::Active);
        Some(c.slots.map(|slot| {
            let leg = self.legs.get(slot).copied().flatten();
            let dtls = self.dtls.get(slot).and_then(Option::as_ref).map(|_| {
                let keyed = self
                    .crypto
                    .get(slot)
                    .and_then(Option::as_ref)
                    .is_some_and(|c| c.inbound.is_some() && !c.hold);
                if keyed { "keyed" } else { "handshaking" }
            });
            let component = if slot.is_rtcp() { 2 } else { 1 };
            let ice = self
                .ice_agents
                .get(slot.rtp())
                .and_then(Option::as_ref)
                .map(|s| super::super::IceLegState {
                    controlling: s.agent.role() == rtpflux_core::ice::Role::Controlling,
                    state: match s.agent.state() {
                        rtpflux_core::ice::ListState::Running => "running",
                        rtpflux_core::ice::ListState::Completed => "completed",
                        rtpflux_core::ice::ListState::Failed => "failed",
                    },
                    selected: s.agent.selected(component),
                    consent_lost: s.agent.consent_lost(component),
                });
            LegStats {
                settled: leg.is_some_and(|l| l.latch.settled(now)),
                dtls,
                ice,
                in_kernel,
                local_port: self
                    .sockets
                    .get(slot)
                    .and_then(Option::as_ref)
                    .and_then(|s| s.local_addr().ok())
                    .map_or(0, |a| a.port()),
                peer: leg.and_then(|l| l.latch.target()),
                packets: leg.map_or(0, |l| l.packets),
                octets: leg.map_or(0, |l| l.octets),
                dropped: leg.map_or(0, |l| l.dropped),
                dtmf: self
                    .dtmf
                    .get(slot)
                    .and_then(Option::as_ref)
                    .map_or_else(Vec::new, |d| d.events.clone()),
                rtcp: self
                    .rtcp
                    .get(slot)
                    .map_or_else(RtcpStats::default, |r| r.stats),
                copied: self.copied.get(slot).copied().unwrap_or_default(),
            }
        }))
    }

    /// The kernel relayed packets of `call`: mark its RTP legs active and
    /// count what it relayed on them.
    pub(super) fn touch(&mut self, call: CallId, packets: [u64; 2], octets: [u64; 2]) {
        let now = self.now_ms();
        self.stats
            .kernel_packets
            .fetch_add(packets[0] + packets[1], Ordering::Relaxed);
        self.stats
            .kernel_bytes
            .fetch_add(octets[0] + octets[1], Ordering::Relaxed);
        if let Some(c) = self.calls.get(&call) {
            for (d, slot) in [c.slots[0], c.slots[2]].into_iter().enumerate() {
                if let Some(Some(leg)) = self.legs.get_mut(slot) {
                    leg.last_active_ms = now;
                    leg.packets += packets[d];
                    leg.octets += octets[d];
                }
            }
        }
    }

    /// Waiting for an answer (until `within_ms` from now), or answered:
    /// the media timeout then counts from now, so a call that rang long
    /// without media is not ended the moment it is answered.
    pub(super) fn await_answer(&mut self, call: CallId, within_ms: Option<u64>) {
        let now = self.now_ms();
        let Some(c) = self.calls.get_mut(&call) else {
            return;
        };
        c.answer_by = within_ms.map(|t| now.saturating_add(t));
        if within_ms.is_none() {
            for slot in c.slots {
                if let Some(Some(l)) = self.legs.get_mut(slot) {
                    l.last_active_ms = l.last_active_ms.max(now);
                }
            }
        }
    }
}
