//! `connect` with `directional`: what one or more parties send is also
//! copied to another party, which keeps its own media (it hears its
//! dialog's other party and the sources); with `bidirectional`, what the
//! destination sends is copied back to each source too. The sources keep
//! their own media as well: nobody is detached. Copies are converted to
//! the destination's codec when they differ and the relay converts both
//! (else they are as sent, and the reply warns). They are kept in the
//! state, end when either party's dialog does, and `unsubscribe` naming
//! the destination (`to-tag`, `to-label`) stops them.

use super::parties::{Which, all_parties, side_of};
use super::{Control, Error, RequestError, SessionKey, list_contains, required};
use rtpflux_ng::bencode::{Dict, Value};

/// A party's copies to another: (source, destination, also back).
pub(super) type Copy = (SessionKey, SessionKey, bool);

/// A `mesh` pair: (from, its destinations).
type MeshPair = (SessionKey, Vec<SessionKey>);

impl Control {
    /// `mesh` (rtpengine's): `calls` (call-ids) and `tags`, a list of
    /// `{from, to: [...]}`: each `to` party gets what the `from` party
    /// sends (both ways with `bidirectional`), as directional copies. With
    /// `unsubscribe`, each `from` party first stops hearing anyone (its
    /// dialog's other party, copies to it), and with `bidirectional`
    /// anyone hearing it. Tags are looked up in the listed calls (a tag in
    /// two of them is refused); everything is checked before anything is
    /// changed. Without `tags` there is nothing to do (rtpengine merges
    /// the calls into one; here parties are named by call and tag).
    pub(super) fn mesh(&mut self, d: &Dict<'_>) -> Result<(), Error> {
        let calls = super::args::strings(d.get(b"calls"));
        if calls.is_empty() {
            return Err(Error::Missing("calls".to_owned()));
        }
        if !calls
            .iter()
            .all(|c| self.sessions.keys().any(|k| k.0 == *c))
        {
            return Err(Error::UnknownCall);
        }
        let party = |c: &Self, tag: &[u8], what: &str| -> Result<SessionKey, Error> {
            let mut found = calls.iter().filter(|call| c.knows(call, tag));
            match (found.next(), found.next()) {
                (Some(call), None) => Ok((call.to_vec(), tag.to_vec())),
                (Some(_), Some(_)) => Err(Error::unsupported(format!(
                    "mesh: tag {} in several calls",
                    String::from_utf8_lossy(tag)
                ))),
                (None, _) => Err(Error::unsupported(format!(
                    "mesh: {what} {} not found",
                    String::from_utf8_lossy(tag)
                ))),
            }
        };
        let mut pairs: Vec<MeshPair> = Vec::new();
        if let Some(Value::List(tags)) = d.get(b"tags") {
            for t in &tags {
                let Value::Dict(t) = t else {
                    return Err(Error::unsupported("mesh: tags is a list of {from, to}"));
                };
                let from = t
                    .get_bytes(b"from")
                    .ok_or_else(|| Error::unsupported("mesh: tags is a list of {from, to}"))?;
                let from = party(self, from, "from-tag")?;
                let mut to = Vec::new();
                let list = super::args::strings_or_one(t.get(b"to"));
                for tag in list {
                    let k = party(self, tag, "to-tag")?;
                    if k != from {
                        to.push(k);
                    }
                }
                pairs.push((from, to));
            }
        }
        let both = list_contains(d, b"flags", b"bidirectional");
        if list_contains(d, b"flags", b"unsubscribe") {
            for (from, _) in &pairs {
                self.unsubscribe_party(from, both);
            }
        }
        for (from, to) in &pairs {
            for t in to {
                self.copy_party(from, t, both)?;
            }
        }
        Ok(())
    }

    /// Party `p` stops hearing anyone: its dialogs' other parties' media to
    /// it is blocked, copies to it end; with `both`, nobody hears it
    /// either (its own media to its dialogs blocked, its copies ended).
    /// Copies made after this (a mesh's) still reach it and go from it.
    fn unsubscribe_party(&mut self, p: &SessionKey, both: bool) {
        self.stop_copies_to(p);
        if both {
            self.stop_copies(|f, _| f == p);
        }
        let mut legs = Vec::new();
        for (key, s) in &self.sessions {
            if key.0 != p.0 {
                continue;
            }
            let Some(party) = side_of(key, s, &p.1) else {
                continue;
            };
            for st in s.media.iter().flatten() {
                legs.push((st.ports.id, st.leg(party.other())));
                if both {
                    legs.push((st.ports.id, st.leg(party)));
                }
            }
        }
        let what = crate::relay::Blocked::Media;
        for (id, leg) in legs {
            Self::logged(
                "mesh: unsubscribing",
                id,
                self.relay.block(id, leg, what, true),
            );
            self.extras.entry(id).or_default().blocked[leg.index()].set(what, true);
        }
        self.mark_dirty();
    }

    /// `inject start` (`on`) or `inject stop`: what party `source-tag` (of
    /// `source-call-id`, default the same call) sends is copied to party
    /// `to-tag` of `call-id`, one way, as a stream of its own (rtpengine
    /// mixes it into the destination's audio; the relay has no mixer).
    pub(super) fn inject(&mut self, d: &Dict<'_>, on: bool) -> Result<(), Error> {
        let call_id = required(d, "call-id")?;
        let to = required(d, "to-tag")?;
        let source = required(d, "source-tag")?;
        let source_call = d.get_bytes(b"source-call-id").unwrap_or(call_id);
        let (from, to) = (
            (source_call.to_vec(), source.to_vec()),
            (call_id.to_vec(), to.to_vec()),
        );
        if from == to {
            return Err(Error::unsupported("inject: a party to itself"));
        }
        if on {
            self.copy_party(&from, &to, false)
        } else if self.stop_copy(&from, &to) {
            Ok(())
        } else {
            Err(Error::UnknownCallOrTag)
        }
    }

    /// `connect` with `directional` (or several sources, `from-tags` or
    /// `all`, which need it).
    pub(super) fn connect_directional(&mut self, d: &Dict<'_>) -> Result<(), Error> {
        let call_id = required(d, "call-id")?;
        let to_call = d.get_bytes(b"to-call-id").unwrap_or(call_id);
        let dest = self
            .party(d, to_call, Which::To)?
            .ok_or_else(|| Error::Missing("to-tag".to_owned()))?;
        let several = all_parties(d) || d.get(b"from-tags").is_some();
        if several && !list_contains(d, b"flags", b"directional") {
            return Err(Error::unsupported(
                "connect: several sources need flags: directional".to_owned(),
            ));
        }
        let sources: Vec<Vec<u8>> = if all_parties(d) {
            self.parties_of(call_id)
                .into_iter()
                .filter(|t| !(call_id == to_call && *t == dest))
                .collect()
        } else if d.get(b"from-tags").is_some() {
            super::args::strings(d.get(b"from-tags"))
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect()
        } else {
            vec![
                self.party(d, call_id, Which::From)?
                    .ok_or_else(|| Error::Missing("from-tag".to_owned()))?,
            ]
        };
        if sources.is_empty() {
            return Err(Error::Request(RequestError::NoSource));
        }
        let both = list_contains(d, b"flags", b"bidirectional");
        let to = (to_call.to_vec(), dest);
        for s in sources {
            let from = (call_id.to_vec(), s);
            if from == to {
                return Err(Error::unsupported("connect: a party to itself".to_owned()));
            }
            self.copy_party(&from, &to, both)?;
        }
        Ok(())
    }

    /// The parties (tags) of `call_id`'s dialogs, in their dialogs' order.
    fn parties_of(&self, call_id: &[u8]) -> Vec<Vec<u8>> {
        let mut keys: Vec<&SessionKey> = self.sessions.keys().filter(|k| k.0 == call_id).collect();
        keys.sort();
        let mut out: Vec<Vec<u8>> = Vec::new();
        for k in keys {
            let s = &self.sessions[k];
            for t in [Some(super::base_tag(&k.1)), s.to_tag.as_deref()]
                .into_iter()
                .flatten()
            {
                if side_of(k, s, t).is_some()
                    && !super::create::is_creator(t)
                    && !out.iter().any(|x| x == t)
                {
                    out.push(t.to_vec());
                }
            }
        }
        out
    }

    /// Copy what party `from` sends to party `to` (and back, with `both`),
    /// section by section, and keep it.
    pub(super) fn copy_party(
        &mut self,
        from: &SessionKey,
        to: &SessionKey,
        both: bool,
    ) -> Result<(), Error> {
        let x = self
            .party_legs(&from.0, &from.1)
            .ok_or(Error::UnknownCallOrTag)?;
        let y = self
            .party_legs(&to.0, &to.1)
            .ok_or(Error::UnknownCallOrTag)?;
        for (x, y) in x.into_iter().zip(y).filter_map(|(x, y)| Some((x?, y?))) {
            // Copies in the receiver's codec, where they differ: converted
            // when the relay converts both, else as sent (and said so).
            let (ab, ba) = match (x.1, y.1) {
                (Some(ax), Some(ay)) if ax.1 != ay.1 => {
                    if crate::codec::converts(ax.1) && crate::codec::converts(ay.1) {
                        let t = |from, to| crate::relay::Transcode {
                            from,
                            to,
                            bitrate: None,
                        };
                        (Some(t(ax, ay)), Some(t(ay, ax)))
                    } else {
                        self.warnings.push(format!(
                            "connect: copies are not transcoded: {} sends {}, {} receives {}",
                            String::from_utf8_lossy(&from.1),
                            ax.1.name(),
                            String::from_utf8_lossy(&to.1),
                            ay.1.name()
                        ));
                        (None, None)
                    }
                }
                _ => (None, None),
            };
            if !self.relay.listen(x.0, y.0, true, ab).map_err(Error::from)? {
                return Err(Error::UnknownCallOrTag);
            }
            if both && !self.relay.listen(y.0, x.0, true, ba).map_err(Error::from)? {
                return Err(Error::UnknownCallOrTag);
            }
        }
        self.copies.retain(|(f, t, _)| !(f == from && t == to));
        self.copies.push((from.clone(), to.clone(), both));
        self.mark_dirty();
        Ok(())
    }

    /// Stop the copies to party `to` (and back from it); whether there
    /// were any.
    pub(super) fn stop_copies_to(&mut self, to: &SessionKey) -> bool {
        self.stop_copies(|_, t| t == to)
    }

    /// Stop the copies (and those back) from party `from` to party `to`;
    /// whether there were any.
    pub(super) fn stop_copy(&mut self, from: &SessionKey, to: &SessionKey) -> bool {
        self.stop_copies(|f, t| f == from && t == to)
    }

    /// Stop the copies `which` selects (by source and destination).
    fn stop_copies(&mut self, which: impl Fn(&SessionKey, &SessionKey) -> bool) -> bool {
        let (gone, kept): (Vec<Copy>, Vec<Copy>) = std::mem::take(&mut self.copies)
            .into_iter()
            .partition(|(f, t, _)| which(f, t));
        self.copies = kept;
        for (from, to, both) in &gone {
            let (Some(x), Some(y)) = (
                self.party_legs(&from.0, &from.1),
                self.party_legs(&to.0, &to.1),
            ) else {
                continue;
            };
            for (x, y) in x.into_iter().zip(y).filter_map(|(x, y)| Some((x?, y?))) {
                let mut r = self.relay.listen(x.0, y.0, false, None);
                if *both {
                    r = r.and(self.relay.listen(y.0, x.0, false, None));
                }
                if let Err(e) = r {
                    log::warn!("call {}: stopping copies: {e}", x.0.0);
                }
            }
        }
        if !gone.is_empty() {
            self.mark_dirty();
        }
        !gone.is_empty()
    }
}
