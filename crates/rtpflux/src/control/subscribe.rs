//! Media subscriptions, as rtpengine's `subscribe request`, `subscribe
//! answer` and `unsubscribe`: a third party (a SIPREC recorder, say)
//! receives copies of what parties of a call send.
//!
//! `subscribe request` names the call and its sources: one party
//! (`from-tag`), several (`from-tags`) or all of them (flag `all`). The
//! reply's SDP offers the subscriber one send-only media section per source
//! section, with the formats (and their `a=rtpmap`/`a=fmtp` lines) the
//! source party offered or answered with, and gives the subscription's tag
//! (`to-tag`: the request's, or a new one). With the flag `siprec` each
//! section gets an `a=label` and the reply says which tag and section each
//! label is (`tag-medias`, `media-labels`). `subscribe answer` gives the
//! subscriber's SDP; copies start then. `unsubscribe` ends it. The
//! subscription ends with its call too.
//!
//! The subscriber receives media as the sources send it (no transcoding:
//! its answer must keep at least one offered format), over RTP or SRTP
//! with SDES (the relay's own key per section).
//!
//! `publish` (rtpengine's) takes an offer from a party that only sends
//! (a WebRTC client publishing its camera, say) and answers it receive-only
//! for the relay itself; others then subscribe to it by its tag. It ends
//! with `delete`.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::subscription::{Answered, Offered, Pick, SelectError, check_answer};

/// One media section of the subscription: a copy of one source section.
#[derive(Debug, Clone)]
pub(super) struct SubStream {
    /// The source: its dialog (by its offerer's tag), media section and
    /// side (logical B?) — what a restart keeps — and its relay call and
    /// leg.
    origin: (Vec<u8>, usize, Party),
    source: (CallId, CallLeg),
    /// The subscription's relay call (index in `sinks`, and id) and the leg
    /// that sends the copy.
    sink_index: usize,
    sink: (CallId, CallLeg),
    /// The interface the copy leaves from.
    interface: InterfaceId,
    /// The relay's SRTP key for the copy (SDES), if any.
    key: Option<MasterKey>,
    /// The source's tag, media type and formats.
    tag: Vec<u8>,
    kind: String,
    formats: Vec<Pt>,
}

/// A subscription's relay call for one source section: its ports, and its
/// two halves as the relay knows them (the subscriber's address once
/// answered, the relay's SRTP key).
#[derive(Debug, Clone)]
pub(super) struct SinkCall {
    ports: CallPorts,
    sides: [Side; 2],
}

/// A subscription (by `call-id` and its own tag).
#[derive(Debug, Clone)]
pub(super) struct Subscription {
    streams: Vec<SubStream>,
    /// When it was requested (seconds since the Unix epoch), and the
    /// profile offered.
    created: u64,
    proto: &'static str,
    /// The subscriber answered.
    answered: bool,
    /// Its relay calls.
    sinks: Vec<SinkCall>,
    /// Offered inactive (flag `inactive`): nothing is copied.
    inactive: bool,
}

impl Subscription {
    /// What the web UI shows of it: the source parties' tags (each once,
    /// in order), whether the subscriber answered, the profile offered,
    /// when it was requested, and whether it was offered inactive.
    pub(super) fn summary(&self) -> (Vec<&[u8]>, bool, &'static str, u64, bool) {
        let mut sources: Vec<&[u8]> = Vec::new();
        for s in &self.streams {
            if !sources.contains(&s.tag.as_slice()) {
                sources.push(&s.tag);
            }
        }
        (
            sources,
            self.answered,
            self.proto,
            self.created,
            self.inactive,
        )
    }
}

/// A media section of a party's SDP, as the subscriber is offered it.
#[derive(Debug, Default)]
struct Section {
    kind: String,
    port: u16,
    formats: Vec<Pt>,
    /// `a=rtpmap`, `a=fmtp`, `a=ptime` and `a=maxptime` lines.
    lines: Vec<String>,
    direction: Option<String>,
}

/// The options of a `subscribe request`.
#[allow(clippy::struct_excessive_bools)]
struct SubOpts {
    proto: &'static str,
    /// SRTP (SDES) towards the subscriber.
    srtp: bool,
    /// DTLS-SRTP with ICE towards the subscriber (a WebRTC client).
    dtls: bool,
    siprec: bool,
    inactive: bool,
    /// The interface the copies leave from (`direction`), if given.
    interface: Option<InterfaceId>,
    learning: Learning,
}

/// A subscription being made, and its reply.
struct Building {
    sub: Subscription,
    /// (session, section) → the subscription's relay call for it.
    sinks: HashMap<(SessionKey, usize), usize>,
    /// The offer's media sections.
    sdp: String,
    /// The relay is an ICE-lite agent towards the subscriber.
    ice_lite: bool,
    labels: Vec<(Vec<u8>, B)>,
    tag_medias: Vec<(Vec<u8>, Vec<B>)>,
}

impl Building {
    /// Write the offer's section `index` (from 1): a copy of `sec` from the
    /// relay's `at`.
    fn section(
        &mut self,
        so: &SubOpts,
        sec: &Section,
        (at, side, fingerprint): (SocketAddr, &Side, &str),
        index: usize,
    ) {
        use std::fmt::Write as _;
        let key = side.srtp.outbound.filter(|_| side.dtls.is_none());
        let fmts: Vec<String> = sec.formats.iter().map(Pt::to_string).collect();
        let _ = write!(
            self.sdp,
            "m={} {} {} {}\r\nc=IN {} {}\r\n",
            sec.kind,
            at.port(),
            so.proto,
            fmts.join(" "),
            addr_type(at.ip()),
            at.ip()
        );
        for l in &sec.lines {
            self.sdp.push_str(l);
            self.sdp.push_str("\r\n");
        }
        if let Some(k) = key {
            let _ = write!(
                self.sdp,
                "a=crypto:1 {} inline:{}\r\n",
                k.suite.name(),
                crate::ngstream::base64(k.bytes())
            );
        }
        let _ = write!(self.sdp, "a=rtcp:{}\r\n", at.port() + 1);
        if let Some(ice) = side.ice {
            // The relay as an ICE-lite agent: its credentials and host
            // candidates (RTP, and RTCP unless the subscriber muxes).
            self.ice_lite = true;
            let _ = write!(
                self.sdp,
                "a=ice-ufrag:{}\r\na=ice-pwd:{}\r\n\
                 a=candidate:1 1 UDP 2130706431 {ip} {} typ host\r\n\
                 a=candidate:1 2 UDP 2130706430 {ip} {} typ host\r\na=end-of-candidates\r\n",
                String::from_utf8_lossy(&ice.ufrag),
                String::from_utf8_lossy(&ice.pwd),
                at.port(),
                at.port() + 1,
                ip = at.ip()
            );
        }
        if side.dtls.is_some() {
            let _ = write!(
                self.sdp,
                "a=setup:actpass\r\na=fingerprint:{fingerprint}\r\na=rtcp-mux\r\n"
            );
        }
        let _ = write!(self.sdp, "a=mid:{index}\r\n");
        if so.siprec {
            let _ = write!(self.sdp, "a=label:{index}\r\n");
        }
        self.sdp.push_str(if so.inactive {
            "a=inactive\r\n"
        } else {
            "a=sendonly\r\n"
        });
    }

    /// The reply to the `subscribe request`.
    fn reply(
        &mut self,
        tag: &[u8],
        sources: &[(SessionKey, Party, Vec<u8>)],
        siprec: bool,
    ) -> Vec<(Vec<u8>, B)> {
        let origin = self
            .sub
            .sinks
            .first()
            .map_or(IpAddr::from([127, 0, 0, 1]), |c| c.ports.a.ip());
        let sdp = format!(
            "v=0\r\no=- {} 1 IN {} {origin}\r\ns=rtpflux\r\nt=0 0\r\n{}{}",
            unix_now(),
            addr_type(origin),
            if self.ice_lite { "a=ice-lite\r\n" } else { "" },
            self.sdp
        );
        let from_tags: Vec<B> = sources
            .iter()
            .map(|(_, _, t)| B::Bytes(t.clone()))
            .collect();
        let mut fields = vec![
            (b"sdp".to_vec(), B::Bytes(sdp.into_bytes())),
            (b"to-tag".to_vec(), B::Bytes(tag.to_vec())),
            (b"from-tags".to_vec(), B::List(from_tags)),
        ];
        if let [(_, _, t)] = sources {
            fields.push((b"from-tag".to_vec(), B::Bytes(t.clone())));
        }
        if siprec {
            let tm = std::mem::take(&mut self.tag_medias)
                .into_iter()
                .map(|(t, medias)| B::dict(&[("tag", B::Bytes(t)), ("medias", B::List(medias))]))
                .collect();
            fields.push((b"tag-medias".to_vec(), B::List(tm)));
            fields.push((
                b"media-labels".to_vec(),
                B::Dict(std::mem::take(&mut self.labels)),
            ));
        }
        fields
    }
}

const DIRECTIONS: [&str; 4] = ["sendrecv", "sendonly", "recvonly", "inactive"];

/// The media sections of `sdp`.
fn sections(sdp: &[u8]) -> Vec<Section> {
    let text = String::from_utf8_lossy(sdp);
    let mut out: Vec<Section> = Vec::new();
    for line in text.lines().map(str::trim_end) {
        if let Some(m) = line.strip_prefix("m=") {
            let mut f = m.split_ascii_whitespace();
            let kind = f.next().unwrap_or("audio").to_owned();
            let port = f
                .next()
                .and_then(|p| p.split('/').next())
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);
            let _proto = f.next();
            out.push(Section {
                kind,
                port,
                formats: f.filter_map(|p| Pt::from_decimal(p.as_bytes())).collect(),
                ..Section::default()
            });
            continue;
        }
        let Some(s) = out.last_mut() else {
            continue;
        };
        let Some(a) = line.strip_prefix("a=") else {
            continue;
        };
        if DIRECTIONS.contains(&a) {
            s.direction = Some(a.to_owned());
            continue;
        }
        let pt_of = |rest: &str| {
            rest.split([' ', '\t'])
                .next()
                .and_then(|p| Pt::from_decimal(p.as_bytes()))
        };
        let keep = if let Some(r) = a
            .strip_prefix("rtpmap:")
            .or_else(|| a.strip_prefix("fmtp:"))
        {
            pt_of(r).is_some_and(|pt| s.formats.contains(&pt))
        } else {
            a.starts_with("ptime:") || a.starts_with("maxptime:")
        };
        if keep {
            s.lines.push(line.to_owned());
        }
    }
    out
}

/// The SDP's network type and address type of `ip`.
fn addr_type(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "IP4" } else { "IP6" }
}

impl Control {
    /// The sources a `subscribe request` names: (session, logical side B,
    /// tag) in the request's order.
    fn sources(
        &self,
        call_id: &[u8],
        req: &Dict<'_>,
    ) -> Result<Vec<(SessionKey, Party, Vec<u8>)>, Error> {
        let mut keys: Vec<&SessionKey> = self.sessions.keys().filter(|k| k.0 == call_id).collect();
        keys.sort();
        if keys.is_empty() {
            return Err(Error::UnknownCall);
        }
        let dialogs: Vec<(&[u8], Option<&[u8]>)> = keys
            .iter()
            .map(|k| (super::base_tag(&k.1), self.sessions[*k].to_tag.as_deref()))
            .collect();
        // One source by tag or label (`label`, `from-label`).
        let one = self.party(req, call_id, super::parties::Which::From)?;
        let pick = if super::parties::all_parties(req) {
            Pick::All
        } else if let Some(Value::List(_)) = req.get(b"from-tags") {
            Pick::Tags(super::args::strings(req.get(b"from-tags")))
        } else if let Some(t) = one.as_deref() {
            Pick::One(t)
        } else {
            Pick::Missing
        };
        let chosen = crate::subscription::select(&dialogs, &pick).map_err(|e| match e {
            SelectError::UnknownCall => Error::UnknownCall,
            SelectError::NoFromTag => Error::Missing("from-tag".to_owned()),
            SelectError::NoSource => Error::Request(RequestError::NoSource),
            SelectError::UnknownTag(tag) => Error::Request(RequestError::UnknownTag(
                String::from_utf8_lossy(&tag).into_owned(),
            )),
        })?;
        Ok(chosen
            .into_iter()
            .filter(|(_, _, tag)| !super::create::is_creator(tag))
            .map(|(k, b, tag)| (keys[k].clone(), Party::of_b(b), tag))
            .collect())
    }

    /// The options of a `subscribe request`.
    fn sub_opts(&self, req: &Dict<'_>) -> Result<SubOpts, Error> {
        let proto = match req.get_bytes(b"transport-protocol") {
            None | Some(b"RTP/AVP") => "RTP/AVP",
            Some(b"RTP/AVPF") => "RTP/AVPF",
            Some(b"RTP/SAVP") => "RTP/SAVP",
            Some(b"RTP/SAVPF") => "RTP/SAVPF",
            Some(b"UDP/TLS/RTP/SAVP") => "UDP/TLS/RTP/SAVP",
            Some(b"UDP/TLS/RTP/SAVPF") => "UDP/TLS/RTP/SAVPF",
            Some(other) => {
                return Err(Error::Request(RequestError::SubscribeTransport(
                    String::from_utf8_lossy(other).into_owned(),
                )));
            }
        };
        let interface = req
            .get(b"direction")
            .is_some()
            .then(|| self.directions(req).map(|d| d[0]))
            .transpose()?;
        Ok(SubOpts {
            proto,
            srtp: proto.starts_with("RTP/SAVP"),
            dtls: proto.starts_with("UDP/TLS/"),
            siprec: list_contains(req, b"flags", b"siprec"),
            inactive: list_contains(req, b"flags", b"inactive"),
            interface,
            learning: opts(req)?.learning,
        })
    }

    pub(super) fn subscribe_request(&mut self, req: &Dict<'_>) -> Result<Vec<(Vec<u8>, B)>, Error> {
        let call_id = required(req, "call-id")?.to_vec();
        let so = self.sub_opts(req)?;
        let sources = self.sources(&call_id, req)?;
        let tag = if let Some(t) = req.get_bytes(b"to-tag") {
            t.to_vec()
        } else {
            self.subscription_seq += 1;
            format!("rtpflux-sub-{}-{}", unix_now(), self.subscription_seq).into_bytes()
        };
        if let Some(old) = self.subscriptions.remove(&(call_id.clone(), tag.clone())) {
            self.end_subscription(&old);
        }
        let mut b = Building {
            sub: Subscription {
                streams: Vec::new(),
                created: unix_now(),
                proto: so.proto,
                answered: false,
                sinks: Vec::new(),
                inactive: so.inactive,
            },
            sinks: HashMap::new(),
            sdp: String::new(),
            ice_lite: false,
            labels: Vec::new(),
            tag_medias: Vec::new(),
        };
        let made = sources
            .iter()
            .try_for_each(|(key, party, src)| self.add_source(&mut b, &so, (key, *party, src)));
        if let Err(e) = made {
            self.end_subscription(&b.sub);
            return Err(e);
        }
        if b.sub.streams.is_empty() {
            self.end_subscription(&b.sub);
            return Err(Error::Request(RequestError::NothingToSubscribe));
        }
        // The subscriber's label (`set-label`, or `to-label`).
        if let Some(l) = req
            .get_bytes(b"set-label")
            .or_else(|| req.get_bytes(b"to-label"))
        {
            self.set_label(&call_id, &tag, l);
        }
        let fields = b.reply(&tag, &sources, so.siprec);
        log::info!(
            "call {}: subscription {} to {} section(s)",
            String::from_utf8_lossy(&call_id),
            String::from_utf8_lossy(&tag),
            b.sub.streams.len()
        );
        self.subscriptions.insert((call_id, tag), b.sub);
        Ok(fields)
    }

    /// Add the sections of the source party tagged `src` (logical side
    /// `party` of session `key`) to the subscription being made.
    fn add_source(
        &mut self,
        b: &mut Building,
        so: &SubOpts,
        (key, party, src): (&SessionKey, Party, &[u8]),
    ) -> Result<(), Error> {
        let session = &self.sessions[key];
        let Some((_, text)) = session.sdps.iter().find(|(t, _)| t == src) else {
            return Err(Error::Request(RequestError::NoSdpFrom(
                String::from_utf8_lossy(src).into_owned(),
            )));
        };
        let secs = sections(text);
        let dir = session.dir;
        let states = session.media.clone();
        let mut medias = Vec::new();
        for (i, st) in states.iter().enumerate() {
            let (Some(st), Some(sec)) = (st, secs.get(i)) else {
                continue;
            };
            if sec.port == 0 || sec.formats.is_empty() {
                continue;
            }
            let source = (st.ports.id, st.leg(party));
            let sink_index = if let Some(&k) = b.sinks.get(&(key.clone(), i)) {
                k
            } else {
                let c = self.make_sink(st, dir, so)?;
                b.sub.sinks.push(c);
                b.sinks.insert((key.clone(), i), b.sub.sinks.len() - 1);
                b.sub.sinks.len() - 1
            };
            let sink_call = &b.sub.sinks[sink_index];
            let ports = sink_call.ports;
            let at = if source.1 == CallLeg::B {
                ports.b
            } else {
                ports.a
            };
            let half = sink_call.sides[source.1.index()];
            let srtp_key = half.srtp.outbound.filter(|_| half.dtls.is_none());
            let index = b.sub.streams.len() + 1;
            let fingerprint = self.relay.dtls_fingerprint().to_owned();
            b.section(so, sec, (at, &half, &fingerprint), index);
            let entry = |with_tag: bool| {
                let mut e = vec![
                    ("index", B::int(index as u64)),
                    ("type", B::Bytes(sec.kind.clone().into_bytes())),
                    ("label", B::Bytes(index.to_string().into_bytes())),
                    (
                        "mode",
                        B::Bytes(
                            sec.direction
                                .as_deref()
                                .unwrap_or("sendrecv")
                                .as_bytes()
                                .to_vec(),
                        ),
                    ),
                ];
                if with_tag {
                    e.push(("tag", B::Bytes(src.to_vec())));
                }
                B::dict(&e)
            };
            medias.push(entry(false));
            b.labels.push((index.to_string().into_bytes(), entry(true)));
            b.sub.streams.push(SubStream {
                origin: (key.1.clone(), i, party),
                source,
                sink_index,
                sink: (ports.id, source.1),
                interface: so.interface.unwrap_or(dir[party.index()]),
                key: srtp_key,
                tag: src.to_vec(),
                kind: sec.kind.clone(),
                formats: sec.formats.clone(),
            });
        }
        b.tag_medias.push((src.to_vec(), medias));
        Ok(())
    }

    /// A subscription's relay call for section `st`, next to its relay
    /// call: half A faces the copy of its A leg, half B of its B leg.
    fn make_sink(
        &mut self,
        st: &MediaState,
        dir: [InterfaceId; 2],
        so: &SubOpts,
    ) -> Result<SinkCall, Error> {
        let keys = if so.srtp {
            [
                Some(self.new_key(Suite::AesCm128HmacSha1_80)?),
                Some(self.new_key(Suite::AesCm128HmacSha1_80)?),
            ]
        } else {
            [None, None]
        };
        // Towards a WebRTC subscriber: ICE-lite credentials, and DTLS (the
        // relay the server until the answer says otherwise).
        let ice = if so.dtls {
            [Some(self.new_ice()?), Some(self.new_ice()?)]
        } else {
            [None, None]
        };
        let dtls = so.dtls.then_some(DtlsSide {
            role: DtlsRole::Server,
            remote: [None; MAX_FINGERPRINTS],
        });
        let half = |leg: CallLeg| Side {
            interface: so
                .interface
                .unwrap_or(dir[usize::from(leg.is_b() != st.flipped)]),
            rtp: None,
            rtcp: None,
            learning: so.learning,
            strict_source: false,
            handover: false,
            unidirectional: false,
            srtp: if so.dtls {
                DTLS_PENDING
            } else {
                Srtp {
                    inbound: Inbound::Plain,
                    outbound: keys[leg.index()],
                }
            },
            rtcp_mux: false,
            ice: ice[leg.index()],
            dtls,
            dtmf: None,
            transcode: None,
            opaque: false,
            dtmf_xcode: None,
            repack: None,
        };
        let sides = [half(CallLeg::A), half(CallLeg::B)];
        let p = self
            .relay
            .create_call_near(sides[0], sides[1], Some(st.ports.id))
            .map_err(Error::Relay)?;
        if let Err(e) = self.relay.sink(p.id) {
            Self::logged(
                "ending an unusable sink",
                p.id,
                self.relay.delete_call(p.id),
            );
            return Err(Error::Relay(e));
        }
        Ok(SinkCall { ports: p, sides })
    }

    pub(super) fn subscribe_answer(&mut self, req: &Dict<'_>) -> Result<(), Error> {
        let key = (
            required(req, "call-id")?.to_vec(),
            required(req, "to-tag")?.to_vec(),
        );
        let sdp = required(req, "sdp")?;
        let opt = opts(req)?;
        let (media, count) = Self::read(sdp)?;
        let Some(sub) = self.subscriptions.get(&key).cloned() else {
            return Err(Error::UnknownCall);
        };
        let offered: Vec<Offered<'_>> = sub
            .streams
            .iter()
            .map(|s| Offered {
                dtls: sub.sinks[s.sink_index].sides[s.sink.1.index()]
                    .dtls
                    .is_some(),
                key: s.key.is_some(),
                formats: &s.formats,
            })
            .collect();
        let answered: Vec<Answered<'_>> = media[..count]
            .iter()
            .map(|m| Answered {
                port: m.port,
                dtls: m.transport.is_dtls() && m.fingerprints.iter().any(Option::is_some),
                sdes: m.transport.is_sdes() && m.crypto.is_some(),
                formats: m.payload_types.as_slice(),
            })
            .collect();
        let taps = check_answer(&offered, &answered).map_err(|(k, r)| {
            Error::Sdp(SdpError::Refused {
                section: k,
                why: r,
                kind: sub.streams[k - 1].kind.clone(),
            })
        })?;
        drop(offered);
        for k in taps {
            let s = &sub.streams[k];
            let m = &media[k];
            let mut side = Self::side(
                InterfaceId::new(0),
                m,
                &opt,
                Srtp {
                    inbound: Inbound::Plain,
                    outbound: s.key,
                },
            );
            side.dtmf = None;
            side.opaque = false;
            side.interface = s.interface;
            let half = sub.sinks[s.sink_index].sides[s.sink.1.index()];
            if half.dtls.is_some() {
                side.srtp = DTLS_PENDING;
                // The subscriber was offered `actpass`.
                side.dtls = Some(Self::answer_dtls(m, Setup::Actpass)?);
                side.ice = half.ice;
                side.rtcp_mux = m.rtcp_mux;
            }
            self.relay
                .update_side(s.sink.0, s.sink.1, &side)
                .map_err(Error::Relay)?;
            if let Some(c) = self
                .subscriptions
                .get_mut(&key)
                .and_then(|x| x.sinks.get_mut(s.sink_index))
            {
                c.sides[s.sink.1.index()] = side;
            }
            if !sub.inactive {
                self.relay
                    .tap(s.source, s.sink, true)
                    .map_err(Error::Relay)?;
            }
        }
        if let Some(sub) = self.subscriptions.get_mut(&key) {
            sub.answered = true;
        }
        log::info!(
            "call {}: subscription {} answered",
            String::from_utf8_lossy(&key.0),
            String::from_utf8_lossy(&key.1)
        );
        Ok(())
    }

    pub(super) fn unsubscribe(&mut self, req: &Dict<'_>) -> Result<(), Error> {
        let call_id = required(req, "call-id")?.to_vec();
        let tag = self
            .party(req, &call_id, super::parties::Which::To)?
            .ok_or_else(|| Error::Missing("to-tag".to_owned()))?;
        let key = (call_id, tag);
        // A `connect` destination (`directional`): its copies stop.
        if !self.subscriptions.contains_key(&key) && self.stop_copies_to(&key) {
            return Ok(());
        }
        let sub = self.subscriptions.remove(&key).ok_or(Error::UnknownCall)?;
        self.end_subscription(&sub);
        Ok(())
    }

    /// End a subscription's relay calls.
    pub(super) fn end_subscription(&mut self, sub: &Subscription) {
        for id in sub.sinks.iter().map(|c| c.ports.id) {
            if let Err(e) = self.relay.delete_call(id) {
                log::warn!("deleting relay call {id}: {e}");
            }
        }
    }

    /// End the subscriptions that copy from, or use, these relay calls.
    pub(super) fn end_subscriptions_of(&mut self, ids: &[CallId]) {
        let gone: Vec<(Vec<u8>, Vec<u8>)> = self
            .subscriptions
            .iter()
            .filter(|(_, s)| {
                s.sinks.iter().any(|c| ids.contains(&c.ports.id))
                    || s.streams.iter().any(|t| ids.contains(&t.source.0))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in gone {
            if let Some(s) = self.subscriptions.remove(&k) {
                self.end_subscription(&s);
            }
        }
    }
}

/// Write `v` with `e`.
fn encode_value(e: &mut Encoder<'_>, v: Value<'_>) -> Result<(), rtpflux_ng::bencode::Overflow> {
    match v {
        Value::Int(n) => e.int(n),
        Value::Bytes(b) => e.bytes(b),
        Value::List(l) => {
            e.list()?;
            for x in l {
                encode_value(e, x)?;
            }
            e.end()
        }
        Value::Dict(d) => {
            e.dict()?;
            for (k, x) in d {
                e.bytes(k)?;
                encode_value(e, x)?;
            }
            e.end()
        }
    }
}

/// `req` with the entries `set` replacing (or adding to) its own, as a
/// bencoded dictionary (keys in order).
pub(super) fn with_entries(
    req: &Dict<'_>,
    set: &[(&[u8], &[u8])],
    drop: &[&[u8]],
) -> Result<Vec<u8>, Error> {
    /// A value kept from the request, or a byte string set.
    enum Entry<'a> {
        Kept(Value<'a>),
        Set(&'a [u8]),
    }
    let mut keys: Vec<(&[u8], Entry<'_>)> = req
        .iter()
        .filter(|(k, _)| !set.iter().any(|(s, _)| s == k) && !drop.contains(k))
        .map(|(k, v)| (k, Entry::Kept(v)))
        .collect();
    keys.extend(set.iter().map(|(k, v)| (*k, Entry::Set(v))));
    keys.sort_by(|a, b| a.0.cmp(b.0));
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut e = Encoder::new(&mut buf);
    let full = || Error::Request(RequestError::TooLarge);
    e.dict().map_err(|_| full())?;
    for (k, v) in keys {
        e.bytes(k).map_err(|_| full())?;
        match v {
            Entry::Kept(v) => encode_value(&mut e, v).map_err(|_| full())?,
            Entry::Set(b) => e.bytes(b).map_err(|_| full())?,
        }
    }
    e.end().map_err(|_| full())?;
    let n = e.len();
    buf.truncate(n);
    Ok(buf)
}

impl Control {
    /// `publish`: answer a sending party's offer receive-only for the relay;
    /// its media can then be subscribed to. Returns the answer's length in
    /// `sdp_buf`.
    pub(super) fn publish(&mut self, req: &Dict<'_>) -> Result<usize, Error> {
        let call_id = required(req, "call-id")?.to_vec();
        let from_tag = required(req, "from-tag")?.to_vec();
        required(req, "sdp")?;
        // The relay's side towards no one is plain RTP.
        let offer = with_entries(req, &[(b"transport-protocol", b"RTP/AVP")], &[])?;
        let Ok(Value::Dict(od)) = rtpflux_ng::bencode::decode(&offer) else {
            return Err(Error::Request(RequestError::BadPublish));
        };
        let n = self.offer(&od)?;
        let answer_sdp = crate::publish::sink_answer(&self.sdp_buf[..n]);
        // The answer from no one: its address is taken as written (not
        // the publisher's `received-from`), and nothing is learned.
        let answer = {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let mut e = Encoder::new(&mut buf);
            let full = |_| Error::Request(RequestError::TooLarge);
            e.dict().map_err(full)?;
            for (k, v) in [
                (&b"call-id"[..], &call_id[..]),
                (b"endpoint-learning", b"off"),
            ] {
                e.bytes(k).map_err(full)?;
                e.bytes(v).map_err(full)?;
            }
            e.bytes(b"flags").map_err(full)?;
            e.list().map_err(full)?;
            e.bytes(b"trust-address").map_err(full)?;
            e.end().map_err(full)?;
            for (k, v) in [(&b"from-tag"[..], &from_tag[..]), (b"sdp", &answer_sdp[..])] {
                e.bytes(k).map_err(full)?;
                e.bytes(v).map_err(full)?;
            }
            e.end().map_err(full)?;
            let n = e.len();
            buf.truncate(n);
            buf
        };
        let Ok(Value::Dict(ad)) = rtpflux_ng::bencode::decode(&answer) else {
            return Err(Error::Request(RequestError::BadPublish));
        };
        match self.answer(&ad) {
            Ok(n) => {
                log::info!(
                    "call {}: {} publishes",
                    String::from_utf8_lossy(&call_id),
                    String::from_utf8_lossy(&from_tag)
                );
                Ok(n)
            }
            Err(e) => {
                if let Some(s) = self.sessions.remove(&(call_id, from_tag)) {
                    self.end_session(&s);
                }
                Err(e)
            }
        }
    }
}

/// (source tag, subscriber tag) pairs.
pub(super) type Links = Vec<(Vec<u8>, Vec<u8>)>;

/// Who subscribes to `tag`, in rtpengine's `query` form.
pub(super) fn subscribers_of(links: &Links, tag: &[u8]) -> B {
    B::List(
        links
            .iter()
            .filter(|(src, _)| src.as_slice() == tag)
            .map(|(_, sub)| link(sub, b"pub/sub"))
            .collect(),
    )
}

/// One entry of `subscriptions` or `subscribers`.
pub(super) fn link(tag: &[u8], kind: &[u8]) -> B {
    B::dict(&[
        ("tag", B::Bytes(tag.to_vec())),
        ("type", B::Bytes(kind.to_vec())),
    ])
}

impl Control {
    /// The subscriptions of `call_id` for `query` (with `from-tag`: the one
    /// of that tag, or those of that source): each as a tag of the call,
    /// its media's streams counting the copies sent, and the tags it
    /// receives from; and, per source tag, its subscribers.
    pub(super) fn query_subscriptions(
        &mut self,
        call_id: &[u8],
        from_tag: Option<&[u8]>,
    ) -> (Vec<(Vec<u8>, B)>, Links) {
        let mut subs: Vec<(Vec<u8>, Subscription)> = self
            .subscriptions
            .iter()
            .filter(|((c, t), s)| {
                c.as_slice() == call_id
                    && from_tag
                        .is_none_or(|f| f == t.as_slice() || s.streams.iter().any(|x| x.tag == f))
            })
            .map(|((_, t), s)| (t.clone(), s.clone()))
            .collect();
        subs.sort_by(|a, b| a.0.cmp(&b.0));
        let mut tags = Vec::new();
        // (source tag, subscriber tag)
        let mut links = Vec::new();
        for (tag, sub) in subs {
            let mut medias = Vec::new();
            let mut sources: Vec<Vec<u8>> = Vec::new();
            for (k, s) in sub.streams.iter().enumerate() {
                if !sources.contains(&s.tag) {
                    sources.push(s.tag.clone());
                }
                let Some(legs) = self.relay.query(s.sink.0) else {
                    continue;
                };
                let leg = s.sink.1.rtp_slot();
                let streams = legs[leg..leg + 2]
                    .iter()
                    .map(|l| {
                        stream_dict(&crate::relay::LegStats {
                            packets: l.copied[0],
                            octets: l.copied[1],
                            dropped: 0,
                            ..l.clone()
                        })
                    })
                    .collect();
                medias.push(B::dict(&[
                    ("index", B::int(k as u64 + 1)),
                    ("type", B::Bytes(s.kind.clone().into_bytes())),
                    ("protocol", B::Bytes(sub.proto.as_bytes().to_vec())),
                    ("streams", B::List(streams)),
                ]));
            }
            let subscriptions = sources
                .iter()
                .map(|t| {
                    B::dict(&[
                        ("tag", B::Bytes(t.clone())),
                        ("type", B::Bytes(b"pub/sub".to_vec())),
                    ])
                })
                .collect();
            links.extend(sources.into_iter().map(|t| (t, tag.clone())));
            tags.push((
                tag.clone(),
                B::dict(&[
                    ("tag", B::Bytes(tag)),
                    ("created", B::int(sub.created)),
                    ("answered", B::int(u64::from(sub.answered))),
                    ("medias", B::List(medias)),
                    ("subscriptions", B::List(subscriptions)),
                ]),
            ));
        }
        (tags, links)
    }

    /// The subscriptions for `list`: call-id, the subscription's tag and its
    /// sources.
    pub(super) fn list_subscriptions(&self) -> B {
        let mut subs: Vec<(&SessionKey, &Subscription)> = self.subscriptions.iter().collect();
        subs.sort_by(|a, b| a.0.cmp(b.0));
        B::List(
            subs.into_iter()
                .map(|((c, t), s)| {
                    let mut from: Vec<B> = Vec::new();
                    for x in &s.streams {
                        if !from.iter().any(|f| matches!(f, B::Bytes(b) if *b == x.tag)) {
                            from.push(B::Bytes(x.tag.clone()));
                        }
                    }
                    B::dict(&[
                        ("call-id", B::Bytes(c.clone())),
                        ("to-tag", B::Bytes(t.clone())),
                        ("from-tags", B::List(from)),
                    ])
                })
                .collect(),
        )
    }
}

impl Control {
    /// The subscriptions as the state file keeps them, with the addresses
    /// the subscribers' legs learned.
    pub(super) fn saved_subscriptions(&mut self) -> Vec<state::SavedSubscription> {
        let mut keys: Vec<SessionKey> = self.subscriptions.keys().cloned().collect();
        keys.sort();
        let mut out = Vec::new();
        for key in keys {
            let Some(sub) = self.subscriptions.get(&key).cloned() else {
                continue;
            };
            let sinks = sub
                .sinks
                .iter()
                .map(|c| {
                    let legs = self.relay.query(c.ports.id);
                    let peer = |i: usize| legs.as_ref().and_then(|l| l[i].peer);
                    state::SavedSink {
                        port_a: c.ports.a.port(),
                        port_b: c.ports.b.port(),
                        a: state::SavedSide::of(&c.sides[0], (peer(0), peer(1))),
                        b: state::SavedSide::of(&c.sides[1], (peer(2), peer(3))),
                    }
                })
                .collect();
            let streams = sub
                .streams
                .iter()
                .map(|x| state::SavedSubStream {
                    dialog: state::hex(&x.origin.0),
                    media: x.origin.1,
                    logical_b: x.origin.2.is_b(),
                    sink: x.sink_index,
                    half_b: x.sink.1.is_b(),
                    tag: state::hex(&x.tag),
                    kind: x.kind.clone(),
                    formats: x.formats.iter().map(|p| p.get()).collect(),
                    interface: x.interface.get(),
                })
                .collect();
            out.push(state::SavedSubscription {
                call_id: state::hex(&key.0),
                to_tag: state::hex(&key.1),
                created: sub.created,
                proto: sub.proto.to_owned(),
                answered: sub.answered,
                inactive: sub.inactive,
                sinks,
                streams,
            });
        }
        out
    }

    /// Restore a subscription after its dialogs: its relay calls on their
    /// ports (so on their sources' workers), copying again if it was
    /// answered.
    pub(super) fn restore_subscription(
        &mut self,
        s: &state::SavedSubscription,
    ) -> Result<(), Error> {
        let bad = || Error::State(StateError::UnreadableSubscription);
        let key = (
            state::unhex(&s.call_id).ok_or_else(bad)?,
            state::unhex(&s.to_tag).ok_or_else(bad)?,
        );
        let proto = ["RTP/AVP", "RTP/AVPF", "RTP/SAVP", "RTP/SAVPF"]
            .into_iter()
            .find(|p| *p == s.proto)
            .ok_or_else(bad)?;
        // The sources first: the dialogs must be back.
        let mut sources = Vec::with_capacity(s.streams.len());
        for x in &s.streams {
            let dialog = (key.0.clone(), state::unhex(&x.dialog).ok_or_else(bad)?);
            let st = self
                .sessions
                .get(&dialog)
                .and_then(|d| d.media.get(x.media).copied().flatten())
                .ok_or_else(|| Error::State(StateError::CallGone))?;
            if x.sink >= s.sinks.len() || x.interface >= self.interfaces.len() {
                return Err(bad());
            }
            sources.push(((st.ports.id, st.leg(Party::of_b(x.logical_b))), dialog.1));
        }
        let mut sinks: Vec<SinkCall> = Vec::with_capacity(s.sinks.len());
        let restored = (|| -> Result<(), Error> {
            for k in &s.sinks {
                let sides = [k.a.side().ok_or_else(bad)?, k.b.side().ok_or_else(bad)?];
                if sides
                    .iter()
                    .any(|x| x.interface.get() >= self.interfaces.len())
                {
                    return Err(bad());
                }
                let ports = self
                    .relay
                    .restore_call(sides[0], sides[1], k.port_a, k.port_b)
                    .map_err(Error::Relay)?;
                sinks.push(SinkCall { ports, sides });
                self.relay.sink(ports.id).map_err(Error::Relay)?;
            }
            Ok(())
        })();
        let mut sub = Subscription {
            streams: Vec::new(),
            created: s.created,
            proto,
            answered: s.answered,
            sinks,
            inactive: s.inactive,
        };
        if let Err(e) = restored {
            self.end_subscription(&sub);
            return Err(e);
        }
        for (x, (source, dialog)) in s.streams.iter().zip(sources) {
            let c = &sub.sinks[x.sink];
            sub.streams.push(SubStream {
                origin: (dialog, x.media, Party::of_b(x.logical_b)),
                source,
                sink_index: x.sink,
                sink: (c.ports.id, CallLeg::of_b(x.half_b)),
                interface: InterfaceId::new(x.interface),
                key: c.sides[usize::from(x.half_b)].srtp.outbound,
                tag: state::unhex(&x.tag).ok_or_else(bad)?,
                kind: x.kind.clone(),
                formats: x.formats.iter().copied().filter_map(Pt::new).collect(),
            });
        }
        if sub.answered && !sub.inactive {
            for x in &sub.streams {
                if let Err(e) = self.relay.tap(x.source, x.sink, true) {
                    self.end_subscription(&sub);
                    return Err(Error::Relay(e));
                }
            }
        }
        log::info!(
            "state: call {}: subscription {} restored ({} section(s))",
            String::from_utf8_lossy(&key.0),
            String::from_utf8_lossy(&key.1),
            sub.streams.len()
        );
        self.subscriptions.insert(key, sub);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_keep_the_formats_lines() {
        let sdp = b"v=0\r\nm=audio 4000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\n\
                    a=rtpmap:96 opus/48000/2\r\na=sendrecv\r\na=crypto:1 x\r\n\
                    m=video 0 RTP/AVP 96\r\n";
        let s = sections(sdp);
        assert_eq!(s.len(), 2);
        assert_eq!(
            (s[0].kind.as_str(), s[0].port, s[0].formats.as_slice()),
            ("audio", 4000, &[Pt::PCMU, Pt::new(101).unwrap()][..])
        );
        assert_eq!(
            s[0].lines,
            [
                "a=rtpmap:0 PCMU/8000",
                "a=rtpmap:101 telephone-event/8000",
                "a=fmtp:101 0-15",
                "a=ptime:20"
            ]
        );
        assert_eq!(s[0].direction.as_deref(), Some("sendrecv"));
        assert_eq!((s[1].kind.as_str(), s[1].port), ("video", 0));
    }
}
