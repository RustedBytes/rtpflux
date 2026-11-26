//! The relay's full ICE agents towards endpoints (RFC 8445): what each
//! endpoint's SDP says about its ICE, starting and restarting the agents
//! when a section is answered, and candidates trickled through `offer`
//! with the `fragment` flag (RFC 8840).
//!
//! Towards the offerer the relay is the controlled agent (the offerer
//! controls), unless the offerer is a lite agent; towards the answerer it
//! offered to, it controls. An endpoint that changes both its ufrag and
//! password restarts ICE (RFC 8839 §4.4.1.1.1): the relay answers with new
//! credentials of its own and its agent restarts.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::trickle::Fragment;
use rtpflux_core::sdp::ice::{Candidate, SectionIce, section_ice};
use std::fmt::Write as _;

/// A grammatical UDP candidate with a literal address, as the relay keeps
/// it (others are ignored: RFC 8839 §5.1 FQDNs, other transports).
pub(super) fn candidate_of(c: &Candidate<'_>) -> Option<IceCandidate> {
    if !c.is_udp() {
        return None;
    }
    let ip: IpAddr = core::str::from_utf8(c.addr).ok()?.parse().ok()?;
    Some(IceCandidate {
        foundation: c.foundation.to_vec(),
        component: u8::try_from(c.component).ok()?,
        priority: c.priority,
        addr: SocketAddr::new(ip, c.port),
    })
}

fn peer_from(s: &SectionIce<'_>) -> Option<IcePeer> {
    Some(IcePeer {
        ufrag: s.ufrag?.to_vec(),
        pwd: s.pwd?.to_vec(),
        lite: s.lite,
        trickle: s.trickle,
        candidates: s.candidates().filter_map(|c| candidate_of(&c)).collect(),
        end_of_candidates: s.end_of_candidates,
    })
}

/// The ICE of media section `index` of `sdp`, if the endpoint uses ICE
/// there.
pub(super) fn peer_of(sdp: &[u8], index: usize) -> Option<IcePeer> {
    peer_from(&section_ice(sdp, index)?)
}

impl Control {
    /// Remember the endpoint ICE of relay call `id`'s leg `leg`; on a
    /// re-offer, whether it restarts ICE (new ufrag and password while the
    /// relay's agent runs).
    pub(super) fn ice_offered(&mut self, id: CallId, leg: CallLeg, peer: Option<IcePeer>) -> bool {
        let Some(peer) = peer else {
            self.ice.remove(&(id, leg));
            return false;
        };
        let e = self.ice.entry((id, leg)).or_default();
        let restart = e
            .running
            .as_ref()
            .is_some_and(|(u, p, _)| *u != peer.ufrag && *p != peer.pwd);
        e.peer = peer;
        restart
    }

    /// Whether the endpoint on relay call `id`'s leg trickles.
    pub(super) fn ice_trickles(&self, id: CallId, leg: CallLeg) -> bool {
        self.ice.get(&(id, leg)).is_some_and(|e| e.peer.trickle)
    }

    /// Start (or restart, or give new candidates to) the relay's full
    /// agent on leg `leg` of call `id`, towards `party`, whose credentials
    /// are `creds`.
    pub(super) fn ice_answered(
        &mut self,
        id: CallId,
        leg: CallLeg,
        creds: Option<IceCreds>,
        party: Party,
    ) {
        let Some(local) = creds.filter(|c| !c.lite) else {
            return;
        };
        let Some(e) = self.ice.get_mut(&(id, leg)) else {
            return;
        };
        let generation = (e.peer.ufrag.clone(), e.peer.pwd.clone(), local.ufrag);
        let restart = e.running.as_ref().is_some_and(|r| *r != generation);
        e.running = Some(generation);
        let start = IceStart {
            local,
            peer: e.peer.clone(),
            // The offerer (party A) controls unless it is lite; towards the
            // answerer the relay (its offerer) does.
            controlling: party == Party::B || e.peer.lite,
            restart,
            pacing_ms: self.ice_pacing_ms,
        };
        if let Err(e) = self.relay.ice_start(id, leg, start) {
            log::warn!("ice: call {id}: {e}");
        }
    }

    /// Section `i` (`st`) was answered, the answerer's ICE being `peer`:
    /// the relay's agents towards both endpoints start (or restart, or
    /// learn new candidates) now that the answerer's ICE is known, and
    /// whether RTCP is muxed. A bundled member's side is its group's.
    pub(super) fn ice_section_answered(
        &mut self,
        i: usize,
        st: &MediaState,
        peer: Option<IcePeer>,
    ) {
        let id = st.ports.id;
        if !(st.b_bundled() && st.bundled_member(i)) {
            self.ice_offered(id, st.leg(Party::B), peer);
            self.ice_answered(id, st.leg(Party::B), st.ice_b, Party::B);
        }
        if !(st.a_bundled() && st.bundled_member(i)) {
            self.ice_answered(id, st.leg(Party::A), st.ice_a, Party::A);
        }
    }

    /// A restored section's endpoint ICE (`m`'s sides): the relay's agents
    /// start again when the dialog was answered.
    pub(super) fn ice_restored(&mut self, st: &MediaState, m: &state::SavedMedia, answered: bool) {
        let (a, b) = (m.a.ice_peer.as_ref(), m.b.ice_peer.as_ref());
        let id = st.ports.id;
        for (party, saved, creds) in [(Party::A, a, st.ice_a), (Party::B, b, st.ice_b)] {
            let peer = saved.and_then(state::SavedIcePeer::peer);
            if peer.is_some() {
                self.ice_offered(id, st.leg(party), peer);
                if answered {
                    self.ice_answered(id, st.leg(party), creds, party);
                }
            }
        }
    }

    /// Forget the ICE of relay call `id`.
    pub(super) fn ice_forget(&mut self, id: CallId) {
        self.ice.remove(&(id, CallLeg::A));
        self.ice.remove(&(id, CallLeg::B));
    }

    /// Candidates trickled by `from-tag`'s endpoint (an `offer` with the
    /// `fragment` flag, its body `application/trickle-ice-sdpfrag`):
    /// handed to the relay's agents towards it. The reply is a fragment for
    /// the other endpoint: the relay's credentials towards it and
    /// end-of-candidates (the relay sends all its candidates in the SDP).
    pub(super) fn fragment(&mut self, req: &Dict<'_>) -> Result<usize, Error> {
        let call_id = required(req, "call-id")?;
        let tag = required(req, "from-tag")?;
        let body = required(req, "sdp")?;
        // The sender is the dialog's offerer (its from-tag keys it) or its
        // answerer (its to-tag).
        let (states, sender_is_a) =
            if let Some(s) = self.sessions.get(&(call_id.to_vec(), tag.to_vec())) {
                (s.media.clone(), true)
            } else {
                let s = self
                    .sessions
                    .iter()
                    .find(|(k, s)| k.0 == call_id && s.to_tag.as_deref() == Some(tag))
                    .map(|(_, s)| s)
                    .ok_or(Error::UnknownCallOrTag)?;
                (s.media.clone(), false)
            };
        let frag = Fragment::parse(body);
        let mut out = String::new();
        for sec in &frag.sections {
            let Some(st) = states
                .iter()
                .flatten()
                .find(|st| st.mid.as_ref().map(Mid::as_bytes) == Some(sec.mid))
            else {
                continue;
            };
            let leg = st.leg(if sender_is_a { Party::A } else { Party::B });
            let Some(e) = self.ice.get_mut(&(st.ports.id, leg)) else {
                continue;
            };
            let current = |u: Option<&[u8]>, p: Option<&[u8]>| {
                u.or(frag.ufrag) == Some(&e.peer.ufrag[..])
                    && p.or(frag.pwd) == Some(&e.peer.pwd[..])
            };
            if !current(sec.ufrag, sec.pwd) {
                // RFC 8840 §4.4: another generation's candidates.
                continue;
            }
            let mut fresh = Vec::new();
            for c in sec.candidates.iter().filter_map(candidate_of) {
                let known = |k: &IceCandidate| k.addr == c.addr && k.component == c.component;
                if !e.peer.candidates.iter().any(known) && !fresh.iter().any(known) {
                    fresh.push(c);
                }
            }
            let eoc = sec.end_of_candidates || frag.end_of_candidates;
            e.peer.candidates.extend(fresh.iter().cloned());
            e.peer.end_of_candidates |= eoc;
            if e.running.is_some()
                && let Err(err) = self.relay.ice_candidates(st.ports.id, leg, fresh, eoc)
            {
                log::warn!("ice: call {}: {err}", st.ports.id);
            }
            // The other endpoint's view: the relay's credentials towards it
            // (media level, as in the relay's SDP).
            let other = if sender_is_a { st.ice_b } else { st.ice_a };
            if let Some(c) = other {
                let _ = write!(
                    out,
                    "m=audio 9 RTP/AVP 0\r\na=mid:{}\r\na=ice-ufrag:{}\r\na=ice-pwd:{}\r\na=end-of-candidates\r\n",
                    String::from_utf8_lossy(sec.mid),
                    String::from_utf8_lossy(&c.ufrag),
                    String::from_utf8_lossy(&c.pwd)
                );
            }
        }
        let n = out.len().min(self.sdp_buf.len());
        self.sdp_buf[..n].copy_from_slice(&out.as_bytes()[..n]);
        Ok(n)
    }
}
