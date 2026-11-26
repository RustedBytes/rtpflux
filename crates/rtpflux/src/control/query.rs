//! `list`, `query` and `statistics`.

#[allow(clippy::wildcard_imports)]
use super::*;
use parties::{Which, side_of, tag_of};

/// The relay's traffic per second, over the latest second sampled: user
/// space packets, octets and errors (dropped and unsent), the XDP fast
/// path's packets and octets.
#[derive(Debug, Default)]
pub(super) struct Rates {
    last: Option<(Instant, [u64; 5])>,
    per_second: [u64; 5],
}

impl Rates {
    /// Take the counters `now`: at least a second after the last sample,
    /// the rates over that time.
    fn sample(&mut self, now: Instant, t: &crate::relay::Totals) {
        let counts = [
            t.forwarded,
            t.forwarded_bytes,
            t.dropped + t.send_errors,
            t.kernel_packets,
            t.kernel_bytes,
        ];
        match self.last {
            Some((at, prev)) => {
                let ms = u64::try_from(now.duration_since(at).as_millis()).unwrap_or(u64::MAX);
                if ms < 1000 {
                    return;
                }
                for ((r, c), p) in self.per_second.iter_mut().zip(counts).zip(prev) {
                    *r = c.saturating_sub(p).saturating_mul(1000) / ms;
                }
                self.last = Some((now, counts));
            }
            None => self.last = Some((now, counts)),
        }
    }
}

impl Control {
    /// Sample the relay's counters for `statistics`' rates (at most once a
    /// second; the control loop calls it on every turn).
    pub fn sample_rates(&mut self) {
        let now = Instant::now();
        if self
            .rates
            .last
            .is_some_and(|(at, _)| now.duration_since(at) < Duration::from_secs(1))
        {
            return;
        }
        let t = self.relay.totals();
        self.rates.sample(now, &t);
    }

    /// `list`: the call-ids of the active dialogs (at most `limit`).
    pub(super) fn list(&self, d: &Dict<'_>) -> Vec<(Vec<u8>, B)> {
        let limit = match d.get(b"limit") {
            Some(Value::Int(n)) => usize::try_from(n).unwrap_or(0),
            _ => usize::MAX,
        };
        let mut ids: Vec<&Vec<u8>> = self.sessions.keys().map(|(c, _)| c).collect();
        ids.sort();
        ids.dedup();
        vec![
            (
                b"calls".to_vec(),
                B::List(
                    ids.into_iter()
                        .take(limit)
                        .map(|c| B::Bytes(c.clone()))
                        .collect(),
                ),
            ),
            (b"subscriptions".to_vec(), self.list_subscriptions()),
        ]
    }

    /// `statistics`: the relay's counters in rtpengine's form, under
    /// `statistics`: `currentstatistics` (sessions now: all own, none
    /// foreign; media sections being transcoded; relay calls),
    /// `totalstatistics` (uptime; packets relayed, dropped and failing to
    /// send, by the userspace workers; calls ended by the media timeout;
    /// SRTP packets rejected; ZRTP packets relayed) and `controlstatistics`
    /// (ng requests per command, errors, retransmissions).
    pub(super) fn statistics(&mut self) -> Vec<(Vec<u8>, B)> {
        let int = |v: u64| B::Int(i64::try_from(v).unwrap_or(i64::MAX));
        let entry = |k: &str, v: B| (k.as_bytes().to_vec(), v);
        let t = self.relay.totals();
        let sessions = self.sessions.len() as u64;
        let transcoded = self
            .sessions
            .values()
            .flat_map(|s| s.media.iter().flatten())
            .filter(|st| st.a_side.transcode.is_some() || st.b_side.transcode.is_some())
            .count() as u64;
        let [up, ub, ue, kp, kb] = self.rates.per_second;
        let current = B::Dict(vec![
            entry("sessionsown", int(sessions)),
            entry("sessionsforeign", int(0)),
            entry("sessionstotal", int(sessions)),
            entry("transcodedmedia", int(transcoded)),
            entry("calls", int(t.active_calls as u64)),
            // Per second, over the latest second sampled.
            entry("packetrate", int(up + kp)),
            entry("byterate", int(ub + kb)),
            entry("errorrate", int(ue)),
            entry("packetrate_user", int(up)),
            entry("byterate_user", int(ub)),
            entry("errorrate_user", int(ue)),
            entry("packetrate_kernel", int(kp)),
            entry("byterate_kernel", int(kb)),
            entry("errorrate_kernel", int(0)),
        ]);
        let total = B::Dict(vec![
            entry("uptime", int(self.started.elapsed().as_secs())),
            entry("relayedpackets", int(t.forwarded)),
            entry("relayedbytes", int(t.forwarded_bytes)),
            entry("relayedpackets_kernel", int(t.kernel_packets)),
            entry("relayedbytes_kernel", int(t.kernel_bytes)),
            entry("droppedpackets", int(t.dropped)),
            entry("relayedpacketerrors", int(t.send_errors)),
            entry("timeoutsessions", int(t.calls_ended)),
            entry("srtprejected", int(t.srtp_rejected)),
            entry("zrtppackets", int(t.zrtp)),
        ]);
        let requests = crate::metrics::COMMANDS
            .iter()
            .zip(&self.stats.requests)
            .map(|(name, n)| entry(name, int(n.load(Ordering::Relaxed))))
            .collect();
        let control = B::Dict(vec![
            entry("requests", B::Dict(requests)),
            entry("errors", int(self.stats.errors.load(Ordering::Relaxed))),
            entry(
                "retransmissions",
                int(self.stats.retransmissions.load(Ordering::Relaxed)),
            ),
        ]);
        vec![entry(
            "statistics",
            B::Dict(vec![
                entry("currentstatistics", current),
                entry("totalstatistics", total),
                entry("controlstatistics", control),
            ]),
        )]
    }

    /// The dialogs of `call_id` (with a tag: those that party is in).
    fn dialogs(&self, call_id: &[u8], tag: Option<&[u8]>) -> Vec<SessionKey> {
        let mut keys: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter(|(k, s)| {
                k.0.as_slice() == call_id && tag.is_none_or(|t| side_of(k, s, t).is_some())
            })
            .map(|(k, _)| k.clone())
            .collect();
        keys.sort();
        keys
    }

    /// `query`: per-dialog counters in rtpengine's form: `created`,
    /// `totals` (RTP and RTCP packets, bytes, errors) and, per party (tag),
    /// its label, the party it is in dialogue with, and its media in every
    /// dialog it is in, with their streams (local port, peer endpoint,
    /// counters). `to-tag` or `from-tag` (or `to-label`, `label`) limit it
    /// to the dialogs of that party.
    pub(super) fn query(&mut self, d: &Dict<'_>) -> Result<Vec<(Vec<u8>, B)>, Error> {
        let call_id = required(d, "call-id")?.to_vec();
        let from_tag = match self.party(d, &call_id, Which::To)? {
            Some(t) => Some(t),
            None => self.party(d, &call_id, Which::From)?,
        };
        let keys = self.dialogs(&call_id, from_tag.as_deref());
        let (sub_tags, links) = self.query_subscriptions(&call_id, from_tag.as_deref());
        if keys.is_empty() && sub_tags.is_empty() {
            return Err(Error::UnknownCall);
        }
        let mut created = u64::MAX;
        let mut totals = [[0u64; 3]; 2]; // [RTP, RTCP] x [packets, bytes, errors]
        let mut parties: Vec<PartyEntry> = Vec::new();
        for key in keys {
            let Some(session) = self.sessions.get(&key) else {
                continue;
            };
            created = created.min(session.created);
            let media: Vec<(usize, MediaState)> = session
                .media
                .iter()
                .enumerate()
                .filter_map(|(i, m)| m.map(|m| (i, m)))
                .collect();
            // Per side: the media of that side's tag.
            let mut sides: [Vec<(usize, B)>; 2] = [Vec::new(), Vec::new()];
            for (i, st) in media {
                let Some(legs) = self.relay.query(st.ports.id) else {
                    continue;
                };
                for (side, protocol) in [(0, st.a_transport), (1, st.b_transport)] {
                    let mut streams = Vec::new();
                    let leg = st
                        .leg(if side == 1 { Party::B } else { Party::A })
                        .rtp_slot();
                    for (k, leg) in legs[leg..leg + 2].iter().enumerate() {
                        let t = &mut totals[k];
                        t[0] += leg.packets;
                        t[1] += leg.octets;
                        t[2] += leg.dropped;
                        streams.push(stream_dict(leg));
                    }
                    sides[side].push((
                        i,
                        B::dict(&[
                            (
                                "protocol",
                                B::Bytes(protocol.name().unwrap_or("?").as_bytes().to_vec()),
                            ),
                            ("streams", B::List(streams)),
                        ]),
                    ));
                }
            }
            let [a_media, b_media] = sides;
            let a = tag_of(&key, session, Party::A).unwrap_or_default().to_vec();
            let b = session.to_tag.clone();
            PartyEntry::add(&mut parties, &a, session.created, b.as_deref(), a_media);
            if let Some(b) = b {
                PartyEntry::add(&mut parties, &b, session.created, Some(&a), b_media);
            }
        }
        let mut tags: Vec<(Vec<u8>, B)> = parties
            .into_iter()
            .map(|p| {
                let label = self.label_of(&call_id, &p.tag).map(<[u8]>::to_vec);
                p.into_dict(label, &links)
            })
            .collect();
        // Subscribers, with their labels.
        for (tag, mut entry) in sub_tags {
            if let (Some(l), B::Dict(fields)) = (self.label_of(&call_id, &tag), &mut entry) {
                fields.push((b"label".to_vec(), B::Bytes(l.to_vec())));
            }
            tags.push((tag, entry));
        }
        Ok(vec![
            (b"created".to_vec(), B::int(created)),
            (
                b"totals".to_vec(),
                B::dict(&[
                    ("RTP", stats(totals[0][0], totals[0][1], totals[0][2])),
                    ("RTCP", stats(totals[1][0], totals[1][1], totals[1][2])),
                ]),
            ),
            (b"tags".to_vec(), B::Dict(tags)),
        ])
    }
}

/// A party of a `query` reply, gathered over the dialogs it is in.
struct PartyEntry {
    tag: Vec<u8>,
    created: u64,
    /// The parties it is in dialogue with, in the order met.
    peers: Vec<Vec<u8>>,
    /// Its media sections (section index in its dialog, the section).
    medias: Vec<(usize, B)>,
}

impl PartyEntry {
    /// Add a dialog's side of party `tag` (created at `created`, with the
    /// party `peer`, if answered) to `parties`.
    fn add(
        parties: &mut Vec<PartyEntry>,
        tag: &[u8],
        created: u64,
        peer: Option<&[u8]>,
        medias: Vec<(usize, B)>,
    ) {
        // A created party's hidden offerer is no party.
        if super::create::is_creator(tag) {
            return;
        }
        let peer = peer.filter(|p| !super::create::is_creator(p));
        let at = if let Some(at) = parties.iter().position(|p| p.tag == tag) {
            at
        } else {
            parties.push(PartyEntry {
                tag: tag.to_vec(),
                created,
                peers: Vec::new(),
                medias: Vec::new(),
            });
            parties.len() - 1
        };
        let p = &mut parties[at];
        p.created = p.created.min(created);
        if let Some(peer) = peer.filter(|t| !p.peers.iter().any(|x| x == t)) {
            p.peers.push(peer.to_vec());
        }
        p.medias.extend(medias);
    }

    /// Its entry of the reply's `tags`: `tag`, `label`, `created`, `in
    /// dialogue with` (the first party it is in a dialog with; all of
    /// them in `subscriptions`), `medias` (numbered over all its dialogs)
    /// and `subscribers`.
    fn into_dict(self, label: Option<Vec<u8>>, links: &subscribe::Links) -> (Vec<u8>, B) {
        let medias = self
            .medias
            .into_iter()
            .enumerate()
            .map(|(n, (_, m))| match m {
                B::Dict(mut fields) => {
                    fields.insert(0, (b"index".to_vec(), B::int(n as u64 + 1)));
                    B::Dict(fields)
                }
                other => other,
            })
            .collect();
        let mut fields = vec![
            (b"tag".to_vec(), B::Bytes(self.tag.clone())),
            (b"created".to_vec(), B::int(self.created)),
        ];
        if let Some(l) = label {
            fields.push((b"label".to_vec(), B::Bytes(l)));
        }
        if let Some(first) = self.peers.first() {
            fields.push((b"in dialogue with".to_vec(), B::Bytes(first.clone())));
        }
        fields.extend([
            (b"medias".to_vec(), B::List(medias)),
            (
                b"subscriptions".to_vec(),
                B::List(
                    self.peers
                        .iter()
                        .map(|t| subscribe::link(t, b"offer/answer"))
                        .collect(),
                ),
            ),
            (
                b"subscribers".to_vec(),
                subscribe::subscribers_of(links, &self.tag),
            ),
        ]);
        (self.tag, B::Dict(fields))
    }
}
