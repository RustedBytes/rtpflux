//! ICE on media ports (RFC 8445): the ICE-lite responder, and the full
//! agents towards sides that use them.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::relay::{IceCandidate, IcePeer, IceStart};
use rtpflux_core::ice::{Agent, Config as AgentConfig, RemoteCandidate, Role};
use rtpflux_core::latch::Learning;

/// The worker tables an ICE check touches.
pub(super) struct IceLegs<'a> {
    pub(super) ice: &'a PerSlot<Option<IceCreds>>,
    pub(super) muxed: &'a PerSlot<bool>,
    pub(super) sockets: &'a PerSlot<Option<UdpSocket>>,
    pub(super) legs: &'a mut PerSlot<Option<Leg>>,
}

/// Answer an ICE check that arrived on `slot` (RFC 8445 §7.3, as a lite
/// agent). An authenticated one confirms the side's address for that leg,
/// and for its RTCP leg too when RTCP is muxed onto the RTP port.
pub(super) fn answer_stun(
    t: &mut IceLegs<'_>,
    slot: Slot,
    packet: &[u8],
    src: SocketAddr,
    out: &mut [u8],
) {
    let Some(creds) = t.ice.get(slot).copied().flatten() else {
        return;
    };
    let creds = Credentials {
        ufrag: &creds.ufrag,
        pwd: &creds.pwd,
    };
    let Answer::Reply {
        len,
        checked,
        nominated,
    } = stun::ice_lite(packet, creds, src, out)
    else {
        return;
    };
    log::debug!("ice: check from {src} on slot {slot}: checked {checked}, nominated {nominated}");
    if let Some(sock) = t.sockets.get(slot).and_then(Option::as_ref)
        && let Err(e) = sock.send_to(&out[..len], src)
    {
        log::debug!("STUN response to {src}: {e}");
    }
    if checked {
        let also_rtcp = !slot.is_rtcp() && t.muxed.get(slot).copied().unwrap_or(false);
        for s in [Some(slot), also_rtcp.then_some(slot.rtcp())]
            .into_iter()
            .flatten()
        {
            if let Some(Some(leg)) = t.legs.get_mut(s) {
                leg.latch.confirm(src, nominated);
            }
        }
    }
}

/// The relay's full ICE agent towards one side (RFC 8445), on the side's
/// RTP slot; its second component, if any, is the RTCP slot after it.
pub(super) struct IceSlot {
    pub(super) call: CallId,
    pub(super) agent: Agent,
    /// What was last applied to each component's leg (`None`: held), once
    /// something was (`set`).
    applied: [Option<SocketAddr>; 2],
    set: [bool; 2],
    /// The agent's counters already added to the worker's.
    counted: rtpflux_core::ice::Stats,
}

fn remote_candidates(peer: &IcePeer) -> Vec<RemoteCandidate<'_>> {
    peer.candidates
        .iter()
        .map(|c| RemoteCandidate {
            foundation: &c.foundation,
            component: c.component,
            priority: c.priority,
            addr: c.addr,
        })
        .collect()
}

impl Worker {
    /// The RTP slot of leg `leg` of `call`.
    fn rtp_slot(&self, call: CallId, leg: CallLeg) -> Option<Slot> {
        let c = self.calls.get(&call)?;
        Some(c.slots[leg.rtp_slot()])
    }

    /// Start, restart or update the full agent towards one side.
    pub(super) fn ice_start(&mut self, call: CallId, leg: CallLeg, start: &IceStart) {
        let Some(rtp) = self.rtp_slot(call, leg) else {
            return;
        };
        let cands = remote_candidates(&start.peer);
        let existing = self.ice_agents.get_mut(rtp).and_then(Option::as_mut);
        match existing {
            Some(s) if !start.restart => {
                s.agent.add_remotes(&cands);
            }
            Some(s) => {
                if !s.agent.restart(
                    &start.local.ufrag,
                    &start.local.pwd,
                    &start.peer.ufrag,
                    &start.peer.pwd,
                ) {
                    // Credentials it cannot take: the agent goes on with
                    // the generation it has.
                    log::warn!("ice: call {call}: restart refused (credentials)");
                }
                s.agent.add_remotes(&cands);
            }
            None => {
                let v6 = self
                    .sockets
                    .get(rtp)
                    .and_then(Option::as_ref)
                    .and_then(|s| s.local_addr().ok())
                    .is_some_and(|a| a.is_ipv6());
                let cfg = AgentConfig {
                    role: if start.controlling {
                        Role::Controlling
                    } else {
                        Role::Controlled
                    },
                    tiebreaker: rand::random(),
                    local_ufrag: &start.local.ufrag,
                    local_pwd: &start.local.pwd,
                    remote_ufrag: &start.peer.ufrag,
                    remote_pwd: &start.peer.pwd,
                    components: if self.muxed.get(rtp).copied().unwrap_or(true) {
                        1
                    } else {
                        2
                    },
                    v6,
                    ta_ms: start.pacing_ms,
                };
                let Some(mut agent) = Agent::new(&cfg) else {
                    log::warn!("ice: call {call}: credentials too long");
                    return;
                };
                agent.add_remotes(&cands);
                if let Some(s) = self.ice_agents.get_mut(rtp) {
                    *s = Some(Box::new(IceSlot {
                        call,
                        agent,
                        applied: [None; 2],
                        set: [false; 2],
                        counted: rtpflux_core::ice::Stats::default(),
                    }));
                    self.ice_slots.push(rtp);
                }
            }
        }
        if start.peer.end_of_candidates
            && let Some(Some(s)) = self.ice_agents.get_mut(rtp)
        {
            s.agent.end_of_candidates();
        }
        // The side's own checks answer for it from now on.
        for s in [rtp, rtp.rtcp()] {
            if let Some(i) = self.ice.get_mut(s) {
                *i = None;
            }
        }
        self.ice_apply(rtp, true);
        let now = self.now_ms();
        self.ice_flush(rtp, now);
    }

    /// Candidates trickled by one side (RFC 8838), and its
    /// end-of-candidates.
    pub(super) fn ice_candidates(
        &mut self,
        call: CallId,
        leg: CallLeg,
        cands: &[IceCandidate],
        eoc: bool,
    ) {
        let Some(rtp) = self.rtp_slot(call, leg) else {
            return;
        };
        let Some(Some(s)) = self.ice_agents.get_mut(rtp) else {
            return;
        };
        for c in cands {
            s.agent.add_remote(&RemoteCandidate {
                foundation: &c.foundation,
                component: c.component,
                priority: c.priority,
                addr: c.addr,
            });
        }
        if eoc {
            s.agent.end_of_candidates();
        }
        let now = self.now_ms();
        self.ice_flush(rtp, now);
    }

    /// A STUN datagram (`bufs[at..at + len]`) on `slot` for a full agent;
    /// false when no agent takes it (the ICE-lite path answers instead).
    pub(super) fn ice_stun(
        &mut self,
        slot: Slot,
        (at, len): (usize, usize),
        src: SocketAddr,
        now: u64,
    ) -> bool {
        let has = |k: Slot| self.ice_agents.get(k).is_some_and(Option::is_some);
        let (rtp, component) = if has(slot) {
            (slot, 1)
        } else if slot.is_rtcp() && has(slot.rtp()) {
            (slot.rtp(), 2)
        } else {
            return false;
        };
        let (Some(Some(s)), Some(packet)) =
            (self.ice_agents.get_mut(rtp), self.bufs.get(at..at + len))
        else {
            return false;
        };
        if let Some(len) = s
            .agent
            .on_stun(now, component, src, packet, &mut self.stun_out)
            && let Some(sock) = self.sockets.get(slot).and_then(Option::as_ref)
            && let Err(e) = sock.send_to(&self.stun_out[..len], src)
        {
            log::debug!("ice: STUN to {src}: {e}");
        }
        self.ice_flush(rtp, now);
        true
    }

    /// Send what the agent on `rtp` has due, and apply its targets.
    fn ice_flush(&mut self, rtp: Slot, now: u64) {
        let Some(Some(s)) = self.ice_agents.get_mut(rtp) else {
            return;
        };
        while let Some(t) = s
            .agent
            .poll(now, &mut self.stun_out, &mut |b: &mut [u8]| rand::fill(b))
        {
            let slot = if t.component == 2 { rtp.rtcp() } else { rtp };
            if let Some(sock) = self.sockets.get(slot).and_then(Option::as_ref)
                && let Err(e) = sock.send_to(&self.stun_out[..t.len], t.dst)
            {
                log::debug!("ice: check to {}: {e}", t.dst);
            }
        }
        let st = s.agent.stats;
        let c = &mut s.counted;
        let add = |a: &std::sync::atomic::AtomicU64, now: u64, before: &mut u64| {
            a.fetch_add(now - *before, Ordering::Relaxed);
            *before = now;
        };
        add(&self.stats.ice_checks, st.checks_sent, &mut c.checks_sent);
        add(
            &self.stats.ice_nominations,
            st.nominations,
            &mut c.nominations,
        );
        add(
            &self.stats.ice_role_conflicts,
            st.role_conflicts,
            &mut c.role_conflicts,
        );
        add(
            &self.stats.ice_consent_lost,
            st.consent_lost,
            &mut c.consent_lost,
        );
        add(&self.stats.ice_restarts, st.restarts, &mut c.restarts);
        self.ice_apply(rtp, false);
        self.ice_next = self
            .ice_slots
            .iter()
            .filter_map(|&k| self.ice_next_of(k))
            .min();
    }

    fn ice_next_of(&self, rtp: Slot) -> Option<u64> {
        self.ice_agents.get(rtp)?.as_ref()?.agent.next_ms()
    }

    /// Media towards the side goes where the agent says, and nowhere
    /// without a valid pair and consent (RFC 8445 §12, RFC 7675 §5.1).
    pub(super) fn ice_apply(&mut self, rtp: Slot, force: bool) {
        let Some(Some(s)) = self.ice_agents.get_mut(rtp) else {
            return;
        };
        let call = s.call;
        let one = s.agent.components() == 1;
        let mut changed = false;
        for k in 0..2 {
            let component = if one {
                1
            } else {
                u8::try_from(k + 1).unwrap_or(1)
            };
            let target = s.agent.target(component);
            if !force && s.set[k] && s.applied[k] == target {
                continue;
            }
            s.applied[k] = target;
            s.set[k] = true;
            changed = true;
            let slot = if k == 1 { rtp.rtcp() } else { rtp };
            if let Some(Some(leg)) = self.legs.get_mut(slot) {
                let mut latch = Latch::new(None, Learning::Off, leg.latch.strict_source());
                if let Some(addr) = target {
                    latch.confirm(addr, true);
                }
                leg.latch = latch;
            }
        }
        if changed {
            log::debug!(
                "ice: call {call}: slot {rtp} now to {:?}",
                self.legs
                    .get(rtp)
                    .copied()
                    .flatten()
                    .and_then(|l| l.latch.target())
            );
            self.refresh_offload(call);
            let now = self.now_ms();
            self.start_dtls_clients(now, &[rtp, rtp.rtcp()]);
        }
    }

    /// The agents due now.
    pub(super) fn ice_due(&mut self, now: u64) {
        let mut k = 0;
        while k < self.ice_slots.len() {
            let rtp = self.ice_slots[k];
            if self.ice_next_of(rtp).is_some_and(|t| t <= now) {
                self.ice_flush(rtp, now);
            }
            k += 1;
        }
        self.ice_next = self
            .ice_slots
            .iter()
            .filter_map(|&k| self.ice_next_of(k))
            .min();
    }

    /// Drop the agents of a closing call's slots.
    pub(super) fn ice_close(&mut self, slots: &[Slot]) {
        for &s in slots {
            if let Some(a) = self.ice_agents.get_mut(s) {
                *a = None;
            }
        }
        self.ice_slots.retain(|k| !slots.contains(k));
        self.ice_next = self
            .ice_slots
            .iter()
            .filter_map(|&k| self.ice_next_of(k))
            .min();
    }
}
