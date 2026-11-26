//! What the web UI asks the control thread: the dialogs (one row each,
//! from the control plane's own state, no worker round trip) and one
//! dialog's details (with each leg's counters, from the workers). The UI's
//! threads send a [`WebQuery`] and wake the control thread, which answers
//! between `ng` requests.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::relay::LegStats;
use nix::sys::eventfd::{EfdFlags, EventFd};
use serde_json::{Value, json};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

/// Questions waiting for the control thread, at most.
const QUEUE: usize = 64;
/// How long the UI waits for an answer.
const WAIT: Duration = Duration::from_secs(2);

/// A question for the control thread.
#[derive(Debug)]
pub enum WebQuery {
    /// Every dialog, one row each.
    Calls(SyncSender<Value>),
    /// One dialog in detail (`Value::Null`: unknown).
    Call {
        call_id: String,
        from_tag: String,
        reply: SyncSender<Value>,
    },
    /// A call's parties, dialogs, links and subscriptions (`Value::Null`:
    /// unknown).
    Parties {
        call_id: String,
        reply: SyncSender<Value>,
    },
    /// Which dialog and media section each relay call is (by relay call
    /// number).
    RelayCalls(SyncSender<Value>),
}

/// The UI's end: asks and waits for the answer.
#[derive(Debug, Clone)]
pub struct WebLink {
    tx: SyncSender<WebQuery>,
    wake: Arc<EventFd>,
}

/// Why the control thread did not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unanswered {
    /// Too many questions waiting.
    Busy,
    /// No answer in time, or the control thread is gone.
    Timeout,
}

impl WebLink {
    /// A link no control thread answers (tests of the API's other paths).
    ///
    /// # Panics
    ///
    /// When no eventfd can be made.
    #[cfg(test)]
    #[must_use]
    pub fn unanswered() -> Self {
        let (tx, _) = sync_channel(QUEUE);
        WebLink {
            tx,
            wake: Arc::new(
                EventFd::from_flags(EfdFlags::EFD_NONBLOCK).unwrap_or_else(|e| panic!("{e}")),
            ),
        }
    }

    /// Ask, and wait for the answer.
    ///
    /// # Errors
    ///
    /// [`Unanswered`] when the queue is full or no answer comes in time.
    pub fn ask(
        &self,
        make: impl FnOnce(SyncSender<Value>) -> WebQuery,
    ) -> Result<Value, Unanswered> {
        let (reply, answer) = sync_channel(1);
        match self.tx.try_send(make(reply)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(Unanswered::Busy),
            Err(TrySendError::Disconnected(_)) => return Err(Unanswered::Timeout),
        }
        let _ = self.wake.write(1);
        answer.recv_timeout(WAIT).map_err(|_| Unanswered::Timeout)
    }
}

/// The control thread's end.
#[derive(Debug)]
pub(super) struct WebInbox {
    rx: Receiver<WebQuery>,
    pub(super) wake: Arc<EventFd>,
}

/// The security of one side: plain, SDES or DTLS-SRTP.
fn security(srtp: &Srtp, dtls: Option<&DtlsSide>) -> &'static str {
    if dtls.is_some() {
        "DTLS-SRTP"
    } else if srtp.is_plain() {
        "plain"
    } else {
        "SDES-SRTP"
    }
}

fn leg_json(leg: &LegStats) -> Value {
    let rtcp = &leg.rtcp;
    json!({
        "settled": leg.settled,
        "dtls": leg.dtls,
        "ice": leg.ice.map(|i| json!({
            "role": if i.controlling { "controlling" } else { "controlled" },
            "state": i.state,
            "selected": i.selected.map(|a| a.to_string()),
            "consent_lost": i.consent_lost,
        })),
        "local_port": leg.local_port,
        "peer": leg.peer.map(|p| p.to_string()),
        "packets": leg.packets,
        "octets": leg.octets,
        "dropped": leg.dropped,
        "dtmf": leg.dtmf.iter().map(|e| json!({
            "event": dtmf_name(e.code),
            "duration_ms": e.duration_ms,
        })).collect::<Vec<_>>(),
        "rtcp_reports": rtcp.reports,
        "rtt_ms": rtcp.rtt_ms,
        "loss_percent": rtcp.block.map(|b| f64::from(b.fraction) * 100.0 / 256.0),
        "lost": rtcp.block.map(|b| b.lost),
        "jitter": rtcp.block.map(|b| b.jitter),
    })
}

/// A telephone event's key (RFC 4733 §3.2).
fn dtmf_name(code: u8) -> String {
    match code {
        0..=9 => char::from(b'0' + code).to_string(),
        10 => "*".to_owned(),
        11 => "#".to_owned(),
        12..=15 => char::from(b'A' + code - 12).to_string(),
        n => format!("event {n}"),
    }
}

impl Control {
    /// The UI's link to this control thread (made once; later calls share
    /// it).
    ///
    /// # Errors
    ///
    /// When the eventfd cannot be created.
    pub fn web_link(&mut self) -> Result<WebLink, nix::Error> {
        let (tx, rx) = sync_channel(QUEUE);
        let wake = Arc::new(EventFd::from_flags(
            EfdFlags::EFD_NONBLOCK | EfdFlags::EFD_CLOEXEC,
        )?);
        self.web = Some(WebInbox {
            rx,
            wake: Arc::clone(&wake),
        });
        Ok(WebLink { tx, wake })
    }

    /// Answer the waiting questions.
    pub(super) fn answer_web(&mut self) {
        let Some(inbox) = &self.web else {
            return;
        };
        let _ = inbox.wake.read();
        let questions: Vec<WebQuery> = inbox.rx.try_iter().collect();
        for q in questions {
            match q {
                WebQuery::Calls(reply) => {
                    let _ = reply.try_send(self.web_calls());
                }
                WebQuery::Call {
                    call_id,
                    from_tag,
                    reply,
                } => {
                    let _ = reply.try_send(self.web_call(&call_id, &from_tag));
                }
                WebQuery::Parties { call_id, reply } => {
                    let _ = reply.try_send(self.web_parties(&call_id));
                }
                WebQuery::RelayCalls(reply) => {
                    let _ = reply.try_send(self.web_relay_calls());
                }
            }
        }
    }

    /// What links each call to others or to more parties, by call-id:
    /// `multi-party` (more than one dialog), `joined` (`connect`),
    /// `copies` (directional `connect`, `inject`, `mesh`) and `subscribed`
    /// (subscriptions), in that order.
    fn call_links(&self) -> HashMap<&[u8], Vec<&'static str>> {
        let mut dialogs: HashMap<&[u8], usize> = HashMap::new();
        for k in self.sessions.keys() {
            *dialogs.entry(k.0.as_slice()).or_default() += 1;
        }
        let mut out: HashMap<&[u8], Vec<&'static str>> = HashMap::new();
        let mut mark = |kind: &'static str, id| {
            let v: &mut Vec<&str> = out.entry(id).or_default();
            if !v.contains(&kind) {
                v.push(kind);
            }
        };
        for (id, n) in &dialogs {
            if *n > 1 {
                mark("multi-party", *id);
            }
        }
        for (a, b) in &self.connections {
            mark("joined", a.0.as_slice());
            mark("joined", b.0.as_slice());
        }
        for (from, to, _) in &self.copies {
            mark("copies", from.0.as_slice());
            mark("copies", to.0.as_slice());
        }
        for k in self.subscriptions.keys() {
            mark("subscribed", k.0.as_slice());
        }
        let order = ["multi-party", "joined", "copies", "subscribed"];
        for v in out.values_mut() {
            v.sort_by_key(|k| order.iter().position(|o| o == k));
        }
        out
    }

    /// One row of a dialog; `links` as [`Control::call_links`] gives them
    /// for its call.
    fn web_row(
        &self,
        (call_id, from_tag): &(Vec<u8>, Vec<u8>),
        s: &Session,
        links: &[&str],
    ) -> Value {
        let now = unix_now();
        let name = |i: InterfaceId| {
            self.interfaces
                .get(i.get())
                .map_or("?", |x| x.name.as_str())
        };
        let media: Vec<&MediaState> = s.media.iter().flatten().collect();
        let mut kinds: Vec<&str> = media
            .iter()
            .flat_map(|m| {
                [
                    security(&m.a, m.a_dtls.as_ref()),
                    security(&m.b, m.b_dtls.as_ref()),
                ]
            })
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        let extras: Vec<&state::SavedExtras> = media
            .iter()
            .filter_map(|m| self.extras.get(&m.ports.id))
            .collect();
        json!({
            "call_id": String::from_utf8_lossy(call_id),
            // The offerer's tag; `key` names the dialog for its details (a
            // dialog between two parties of other dialogs is stored under
            // a pair key, which is not a tag).
            "from_tag": String::from_utf8_lossy(super::base_tag(from_tag)),
            "key": String::from_utf8_lossy(from_tag),
            "to_tag": s.to_tag.as_deref().map(String::from_utf8_lossy),
            "state": if s.to_tag.is_some() { "answered" } else { "offered" },
            "created": s.created,
            "age": now.saturating_sub(s.created),
            "interfaces": format!("{} → {}", name(s.dir[0]), name(s.dir[1])),
            "sections": media.len(),
            "security": kinds.join(", "),
            "recording": extras.iter().any(|e| e.recording.is_some()),
            "blocked": extras.iter().any(|e| e.blocked.iter().any(|b| !b.is_empty())),
            "playing": extras.iter().any(|e| e.playing.iter().any(Option::is_some)),
            "links": links,
        })
    }

    /// What will end the dialog stored under `key`, in seconds from now:
    /// an unanswered offer (`offer_timeout`), `final_timeout`, and a
    /// `delete-delay` under way.
    fn web_timers(&self, key: &SessionKey, s: &Session) -> Value {
        let now = unix_now();
        let left = |at: u64| at.saturating_sub(now);
        let unanswered = s
            .to_tag
            .is_none()
            .then(|| left(s.created.saturating_add(self.offer_timeout.as_secs())));
        let final_ =
            (self.final_timeout > 0).then(|| left(s.created.saturating_add(self.final_timeout)));
        let instant = Instant::now();
        let deleting = self
            .delayed_deletes
            .pending()
            .filter(|(_, sel)| sel.matches(key, s))
            .map(|(at, _)| at.saturating_duration_since(instant).as_secs())
            .min();
        json!({
            "unanswered_ends_in_s": unanswered,
            "final_timeout_in_s": final_,
            "deleting_in_s": deleting,
        })
    }

    /// `{"<relay call>": {call_id, from_tag, key, section}}` for every
    /// dialog's media sections.
    fn web_relay_calls(&self) -> Value {
        let mut out = serde_json::Map::new();
        for (k, s) in &self.sessions {
            for (i, m) in s.media.iter().enumerate() {
                if let Some(m) = m {
                    out.insert(
                        m.ports.id.to_string(),
                        json!({
                            "call_id": String::from_utf8_lossy(&k.0),
                            "from_tag": String::from_utf8_lossy(super::base_tag(&k.1)),
                            "key": String::from_utf8_lossy(&k.1),
                            "section": i + 1,
                        }),
                    );
                }
            }
        }
        Value::Object(out)
    }

    fn web_calls(&self) -> Value {
        let links = self.call_links();
        Value::Array(
            self.sessions
                .iter()
                .map(|(k, s)| {
                    let l = links.get(k.0.as_slice()).map_or(&[][..], Vec::as_slice);
                    self.web_row(k, s, l)
                })
                .collect(),
        )
    }

    /// A party's first audio codec, as negotiated.
    fn party_codec(&self, call_id: &[u8], tag: &[u8]) -> Option<&'static str> {
        self.party_legs(call_id, tag)?
            .into_iter()
            .flatten()
            .find_map(|(_, audio)| audio)
            .map(|(_, codec)| codec.name())
    }

    /// `call_id`'s parties (tag, label, codec, the parties it is in dialogs
    /// with), its dialogs, what links its parties to others (`connect`ed
    /// parties, copies; either end may be in another call, and a codec
    /// conversion is named), and its subscriptions.
    fn web_parties(&self, call_id: &str) -> Value {
        let cid = call_id.as_bytes();
        let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let mut keys: Vec<&SessionKey> = self.sessions.keys().filter(|k| k.0 == cid).collect();
        keys.sort();
        let touches = |k: &SessionKey| k.0 == cid;
        let linked = self
            .connections
            .iter()
            .any(|(a, b)| touches(a) || touches(b))
            || self.copies.iter().any(|(a, b, _)| touches(a) || touches(b));
        let subs: Vec<_> = {
            let mut v: Vec<_> = self
                .subscriptions
                .iter()
                .filter(|(k, _)| k.0 == cid)
                .collect();
            v.sort_by(|a, b| a.0.cmp(b.0));
            v
        };
        if keys.is_empty() && subs.is_empty() && !linked {
            return Value::Null;
        }
        let (parties, dialogs) = self.web_dialogs(&keys);
        let links = self.web_links(cid);
        let subscriptions: Vec<Value> = subs
            .iter()
            .map(|((_, tag), sub)| {
                let (sources, answered, profile, created, inactive) = sub.summary();
                json!({
                    "tag": lossy(tag),
                    "label": self.label_of(cid, tag).map(lossy),
                    "sources": sources.into_iter().map(lossy).collect::<Vec<_>>(),
                    "answered": answered,
                    "profile": profile,
                    "created": created,
                    "inactive": inactive,
                })
            })
            .collect();
        json!({
            "call_id": call_id,
            "parties": parties.iter().map(|p| json!({
                "tag": lossy(p.tag),
                "label": self.label_of(cid, p.tag).map(lossy),
                "codec": self.party_codec(cid, p.tag),
                "in_dialogue_with": p.peers.iter().map(|x| lossy(x)).collect::<Vec<_>>(),
                "created": p.created,
            })).collect::<Vec<_>>(),
            "dialogs": dialogs,
            "links": links,
            "subscriptions": subscriptions,
        })
    }

    /// The parties of the dialogs stored under `keys` (in order of first
    /// appearance, with the parties each is in dialogs with), and the
    /// dialogs as the parties view lists them.
    fn web_dialogs<'a>(&'a self, keys: &[&'a SessionKey]) -> (Vec<PartyRow<'a>>, Vec<Value>) {
        let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let mut parties: Vec<PartyRow<'a>> = Vec::new();
        let mut dialogs = Vec::new();
        for k in keys {
            let s = &self.sessions[*k];
            let a = parties::tag_of(k, s, Party::A);
            let b = parties::tag_of(k, s, Party::B);
            for (me, peer) in [(a, b), (b, a)] {
                let Some(me) = me else { continue };
                match parties.iter_mut().find(|p| p.tag == me) {
                    Some(p) => {
                        p.created = p.created.min(s.created);
                        if let Some(peer) = peer.filter(|x| !p.peers.contains(x)) {
                            p.peers.push(peer);
                        }
                    }
                    None => parties.push(PartyRow {
                        tag: me,
                        peers: peer.into_iter().collect(),
                        created: s.created,
                    }),
                }
            }
            let row = self.web_row(k, s, &[]);
            dialogs.push(json!({
                "key": lossy(&k.1),
                "a": a.map(lossy),
                "b": b.map(lossy),
                "state": row["state"],
                "age": row["age"],
                "sections": row["sections"],
                "security": row["security"],
            }));
        }
        (parties, dialogs)
    }

    /// What links parties of `cid` to others: `connect`ed pairs and
    /// copies, either end possibly in another call, with the codec
    /// conversion when there is one.
    fn web_links(&self, cid: &[u8]) -> Vec<Value> {
        let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let touches = |k: &SessionKey| k.0 == cid;
        let end = |(c, t): &SessionKey| {
            json!({
                "call_id": lossy(c),
                "tag": lossy(t),
                "label": self.label_of(c, t).map(lossy),
                "here": c.as_slice() == cid,
            })
        };
        let convert = |from: &SessionKey, to: &SessionKey, both: bool| {
            let (x, y) = (
                self.party_codec(&from.0, &from.1),
                self.party_codec(&to.0, &to.1),
            );
            match (x, y) {
                (Some(x), Some(y)) if x != y => {
                    Some(format!("{x} {} {y}", if both { "⇄" } else { "→" }))
                }
                _ => None,
            }
        };
        let joined = self
            .connections
            .iter()
            .filter(|(a, b)| touches(a) || touches(b))
            .map(|(a, b)| (a, b, true, "joined"));
        let copied = self
            .copies
            .iter()
            .filter(|(a, b, _)| touches(a) || touches(b))
            .map(|(a, b, both)| (a, b, *both, "copy"));
        joined
            .chain(copied)
            .map(|(a, b, both, kind)| {
                json!({
                    "kind": kind,
                    "from": end(a),
                    "to": end(b),
                    "both": both,
                    "convert": convert(a, b, both),
                })
            })
            .collect()
    }

    fn web_call(&mut self, call_id: &str, from_tag: &str) -> Value {
        let key = (call_id.as_bytes().to_vec(), from_tag.as_bytes().to_vec());
        let Some(s) = self.sessions.get(&key) else {
            return Value::Null;
        };
        let links = self.call_links();
        let mut row = self.web_row(
            &key,
            s,
            links.get(key.0.as_slice()).map_or(&[][..], Vec::as_slice),
        );
        row["timers"] = self.web_timers(&key, s);
        row["via_branch"] = json!(s.via_branch.as_deref().map(String::from_utf8_lossy));
        // Each party's latest SDP, for the directions it asked for.
        let dirs = [
            sdp_directions(&key, s, Party::A),
            sdp_directions(&key, s, Party::B),
        ];
        let media: Vec<(usize, MediaState)> = s
            .media
            .iter()
            .enumerate()
            .filter_map(|(i, m)| m.map(|m| (i, m)))
            .collect();
        let mut sections = Vec::new();
        for (i, m) in media {
            let legs = self.relay.query(m.ports.id);
            let extras = self.extras.get(&m.ports.id);
            let side = |b: bool| {
                let k = usize::from(b);
                side_json(&m, b, legs.as_ref(), extras, dirs[k].get(i).copied())
            };
            let in_kernel = legs.as_ref().is_some_and(|l| l.iter().any(|x| x.in_kernel));
            sections.push(json!({
                "index": i + 1,
                "relay_call": m.ports.id,
                "rtcp_mux": m.mux,
                "bundle": m.group.is_some(),
                "mid": m.mid.as_ref().map(|x| String::from_utf8_lossy(x.as_bytes()).into_owned()),
                "in_kernel": in_kernel,
                "passthrough": m.passthrough.is_some(),
                "a": side(false),
                "b": side(true),
                "recording": extras.and_then(|e| e.recording.clone()),
                "blocked": extras.map(|e| e.blocked),
                "playing": extras.map(|e| [e.playing[0].is_some(), e.playing[1].is_some()]),
            }));
        }
        row["media"] = Value::Array(sections);
        row
    }
}

/// A party of a call as the parties view gathers it.
struct PartyRow<'a> {
    tag: &'a [u8],
    /// The parties it is in dialogs with.
    peers: Vec<&'a [u8]>,
    /// When its first dialog was offered.
    created: u64,
}

/// The direction each media section of party `party`'s latest SDP asks for
/// (`held (c=0.0.0.0)` for a held address).
fn sdp_directions(key: &SessionKey, s: &Session, party: Party) -> Vec<&'static str> {
    use rtpflux_core::sdp::Direction as D;
    let Some(tag) = parties::tag_of(key, s, party) else {
        return Vec::new();
    };
    let Some((_, sdp)) = s.sdps.iter().find(|(t, _)| t == tag) else {
        return Vec::new();
    };
    let mut media = [rtpflux_core::sdp::Media::EMPTY; MAX_MEDIA];
    let n = rtpflux_core::sdp::read_media(sdp, &mut media).unwrap_or(0);
    media
        .iter()
        .take(n)
        .map(
            |m| match (m.direction, m.address.is_some_and(|a| a.is_unspecified())) {
                (_, true) => "held (c=0.0.0.0)",
                (D::SendRecv, _) => "sendrecv",
                (D::SendOnly, _) => "sendonly",
                (D::RecvOnly, _) => "recvonly",
                (D::Inactive, _) => "inactive",
            },
        )
        .collect()
}

/// One side (`b`: side B) of a media section as the call detail shows it:
/// its profile and security, what it receives and how what it sends is
/// converted, ptime, the direction its SDP asks for, latching, DTLS and
/// ICE, and its two legs.
fn side_json(
    m: &MediaState,
    b: bool,
    legs: Option<&[LegStats; 4]>,
    extras: Option<&state::SavedExtras>,
    direction: Option<&str>,
) -> Value {
    let (protocol, srtp, dtls, port, relay_side) = if b {
        (m.b_transport, &m.b, m.b_dtls.as_ref(), m.ports.b, &m.b_side)
    } else {
        (m.a_transport, &m.a, m.a_dtls.as_ref(), m.ports.a, &m.a_side)
    };
    let k = usize::from(b);
    let leg = m.leg(if b { Party::B } else { Party::A }).rtp_slot();
    let stats = legs.and_then(|l| Some((l.get(leg)?, l.get(leg + 1)?)));
    let codec = |(pt, c): (Pt, rtpflux_core::sdp::Codec)| format!("{} ({pt})", c.name());
    json!({
        "protocol": protocol.name().unwrap_or("?"),
        "security": security(srtp, dtls),
        "relay": port.to_string(),
        // What this side receives, as negotiated, and the conversion of
        // what it sends.
        "codec": m.audio[k].map(codec),
        "transcode": relay_side.transcode.map(|t| format!("{} → {}", t.from.1.name(), t.to.1.name())),
        "ptime_ms": m.ptime[k],
        "direction": direction,
        "latching": match relay_side.learning {
            rtpflux_core::latch::Learning::Off => "off",
            rtpflux_core::latch::Learning::Immediate => "immediate",
            rtpflux_core::latch::Learning::Heuristic => "heuristic",
        },
        "strict_source": relay_side.strict_source,
        "handover": relay_side.handover,
        "opaque": relay_side.opaque,
        "dtls_role": dtls.map(|d| match d.role {
            crate::relay::DtlsRole::Client => "client",
            crate::relay::DtlsRole::Server => "server",
        }),
        "ice": relay_side.ice.is_some(),
        "dtmf_security": extras.is_some_and(|e| e.dtmf_security[k].is_some()),
        "rtp": stats.map(|(rtp, _)| leg_json(rtp)),
        "rtcp": stats.map(|(_, rtcp)| leg_json(rtcp)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telephone_events_are_named() {
        let names: Vec<String> = (0..17).map(dtmf_name).collect();
        assert_eq!(names[..12].concat(), "0123456789*#");
        assert_eq!(names[12..16].concat(), "ABCD");
        assert_eq!(names[16], "event 16");
    }
}
