//! `create` and `create answer` (rtpengine's): the relay makes an SDP
//! offer itself, for a new party of a call whose media is at the endpoint
//! that answers it (a media server, a conference leg), with no SIP
//! endpoint on the other side. The proxy sends the offer, and hands the
//! answer back with `create answer`. The party then exists like any other
//! (its tag is `from-tag`, made up when missing); its media goes nowhere
//! until it is joined to others (`connect`, a subscription, `play media`).
//!
//! The offer is made from a template: one audio section per entry of
//! `medias` (or one), with the formats asked for (`codec: offer`, a
//! section's `codecs`; PCMA and PCMU by default), through the usual offer
//! path, so `transport-protocol`, `SDES`, `DTLS`, `ICE`, `direction` and
//! the other options of an offer apply. Inside, the offer is made by a
//! hidden party ([`CREATOR`] and the tag) whose side is never advertised;
//! the created party is its answerer.
//!
//! `create from offer` (rtpflux's own) is the other direction: a party's
//! endpoint offers (an inbound call to a media endpoint, with no second
//! party yet), and the relay answers it. The party is the offerer of a
//! dialog whose answerer is the hidden party, which answers the offer
//! through the usual answer path with every offered format and each
//! section's direction mirrored. The reply's `sdp` is the answer to the
//! party's offer; its media then goes nowhere until it is joined to
//! others, as a created party's. A later `create from offer` with the same
//! tags is a re-offer of that dialog (the party's re-INVITE): same ports.

use super::{Control, Error, RequestError, required, unix_now};
use core::fmt::Write as _;
use rtpflux_ng::bencode::{Dict, Encoder, Value, decode};

/// The hidden offerer of a created party's dialog: this and its tag.
pub(super) const CREATOR: &[u8] = b"rtpflux-create:";

/// Whether `tag` is a created party's hidden offerer.
pub(super) fn is_creator(tag: &[u8]) -> bool {
    tag.starts_with(CREATOR)
}

/// The formats of a codec the template offers: payload type, `a=rtpmap`
/// value and `a=fmtp`, if any.
fn format(name: &[u8]) -> Option<(u8, &'static str, Option<&'static str>)> {
    let name = String::from_utf8_lossy(name).to_ascii_uppercase();
    Some(match name.split('/').next()? {
        "PCMU" => (0, "PCMU/8000", None),
        "PCMA" => (8, "PCMA/8000", None),
        "G722" => (9, "G722/8000", None),
        "G729" => (18, "G729/8000", Some("annexb=no")),
        "CN" => (13, "CN/8000", None),
        "OPUS" => (96, "opus/48000/2", None),
        "AMR" => (97, "AMR/8000", Some("octet-align=1")),
        "AMR-WB" => (98, "AMR-WB/16000", Some("octet-align=1")),
        "TELEPHONE-EVENT" => (101, "telephone-event/8000", Some("0-16")),
        _ => return None,
    })
}

/// The template's sections: each one's codec names.
fn sections<'a>(d: &Dict<'a>) -> Vec<Vec<&'a [u8]>> {
    let offer = match d.get(b"codec") {
        Some(Value::Dict(c)) => super::args::strings(c.get(b"offer")),
        _ => Vec::new(),
    };
    let default = || -> Vec<&'a [u8]> {
        if offer.is_empty() {
            vec![b"PCMA", b"PCMU"]
        } else {
            offer.clone()
        }
    };
    match d.get(b"medias") {
        Some(Value::List(l)) => l
            .iter()
            .map(|m| match m {
                Value::Dict(m) => {
                    let c = super::args::strings(m.get(b"codecs"));
                    if c.is_empty() { default() } else { c }
                }
                _ => default(),
            })
            .collect(),
        _ => vec![default()],
    }
}

/// The template SDP: audio sections with `codecs`, at no address.
fn template(sections: &[Vec<&[u8]>]) -> Result<String, Error> {
    let mut sdp = format!(
        "v=0\r\no=- {} 1 IN IP4 0.0.0.0\r\ns=rtpflux\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n",
        unix_now()
    );
    for codecs in sections {
        let mut formats = Vec::new();
        for c in codecs {
            let f = format(c).ok_or_else(|| {
                Error::unsupported(format!("create: codec {}", String::from_utf8_lossy(c)))
            })?;
            if !formats.iter().any(|(pt, _, _)| *pt == f.0) {
                formats.push(f);
            }
        }
        let pts: Vec<String> = formats.iter().map(|f| f.0.to_string()).collect();
        let _ = write!(sdp, "m=audio 9 RTP/AVP {}\r\n", pts.join(" "));
        for (pt, map, fmtp) in &formats {
            let _ = write!(sdp, "a=rtpmap:{pt} {map}\r\n");
            if let Some(f) = fmtp {
                let _ = write!(sdp, "a=fmtp:{pt} {f}\r\n");
            }
        }
        sdp.push_str("a=sendrecv\r\n");
    }
    Ok(sdp)
}

impl Control {
    /// The request's `call-id` and `from-tag`, each made up when missing
    /// (32 and 16 hex digits).
    fn made_up_ids(&mut self, req: &Dict<'_>) -> (Vec<u8>, Vec<u8>) {
        self.created_seq += 1;
        let seq = self.created_seq;
        let random = |n: u32| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&(std::process::id(), unix_now(), n, seq), &mut h);
            format!("{:016x}", std::hash::Hasher::finish(&h))
        };
        let call_id = match req.get_bytes(b"call-id") {
            Some(c) => c.to_vec(),
            None => format!("{}{}", random(1), random(2)).into_bytes(),
        };
        let tag = match req.get_bytes(b"from-tag") {
            Some(t) => t.to_vec(),
            None => random(3).into_bytes(),
        };
        (call_id, tag)
    }

    /// `create`: the offer to the created party's endpoint. The reply has
    /// `call-id`, `from-tag` (the party's) and `sdp`.
    pub(super) fn create(&mut self, req: &Dict<'_>) -> Result<(Vec<u8>, Vec<u8>, usize), Error> {
        let (call_id, tag) = self.made_up_ids(req);
        if is_creator(&tag) {
            return Err(Error::unsupported(
                "create: a tag of the relay's own".to_owned(),
            ));
        }
        let sdp = template(&sections(req))?;
        let creator = [CREATOR, &tag].concat();
        // A party created before (from either side's offer): a re-offer of
        // its dialog (its ports), whoever offered last.
        let again = self.created_dialog(&call_id, &tag).is_some();
        let mut set: Vec<(&[u8], &[u8])> = vec![
            (b"call-id", &call_id),
            (b"from-tag", &creator),
            (b"sdp", sdp.as_bytes()),
        ];
        if again {
            set.push((b"to-tag", &tag));
        }
        let offer = super::subscribe::with_entries(req, &set, &[b"medias", b"codec", b"command"])?;
        let Ok(Value::Dict(od)) = decode(&offer) else {
            return Err(Error::Request(RequestError::TooLarge));
        };
        let n = self.offer(&od)?;
        // Nothing reaches the hidden side, and the party's media goes
        // nowhere until it is joined to someone.
        let key = self
            .created_dialog(&call_id, &tag)
            .unwrap_or((call_id.clone(), creator));
        self.park_or_rejoin(&key, &(call_id.clone(), tag.clone()));
        if let Some(l) = req
            .get_bytes(b"set-label")
            .or_else(|| req.get_bytes(b"label"))
        {
            self.set_label(&call_id, &tag, l);
        }
        log::info!(
            "call {}: party {} created",
            String::from_utf8_lossy(&call_id),
            String::from_utf8_lossy(&tag)
        );
        Ok((call_id, tag, n))
    }

    /// `create from offer`: answer the offer `sdp` of a new party
    /// `from-tag` (made up when missing) of `call-id` (likewise), with no
    /// other party. The reply has `call-id`, `from-tag` and `sdp` (the
    /// answer).
    pub(super) fn create_from_offer(
        &mut self,
        req: &Dict<'_>,
    ) -> Result<(Vec<u8>, Vec<u8>, usize), Error> {
        required(req, "sdp")?;
        let (call_id, tag) = self.made_up_ids(req);
        if is_creator(&tag) {
            return Err(Error::unsupported(
                "create from offer: a tag of the relay's own".to_owned(),
            ));
        }
        let creator = [CREATOR, &tag].concat();
        let key = (call_id.clone(), tag.clone());
        // The party's dialog with the hidden side, made before (from either
        // side's offer): a re-offer, whoever offered last.
        let again = self.created_dialog(&call_id, &tag).is_some();
        if !again && self.sessions.contains_key(&key) {
            // The tag offers in a dialog of another kind: not taken over.
            return Err(Error::unsupported(
                "create from offer: the tag already offered in this call".to_owned(),
            ));
        }
        // The relay's side towards no one is plain RTP.
        let mut set: Vec<(&[u8], &[u8])> = vec![
            (b"call-id", &call_id),
            (b"from-tag", &tag),
            (b"transport-protocol", b"RTP/AVP"),
        ];
        if again {
            set.push((b"to-tag", &creator));
        }
        let offer = super::subscribe::with_entries(req, &set, &[b"command"])?;
        let Ok(Value::Dict(od)) = decode(&offer) else {
            return Err(Error::Request(RequestError::TooLarge));
        };
        let n = self.offer(&od)?;
        let hidden = crate::publish::mirror_answer(&self.sdp_buf[..n]);
        // The hidden side's answer: its address taken as written, nothing
        // learned.
        let answer = {
            let mut buf = vec![0u8; super::MAX_DATAGRAM];
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
            for (k, v) in [
                (&b"from-tag"[..], &tag[..]),
                (b"sdp", &hidden[..]),
                (b"to-tag", &creator[..]),
            ] {
                e.bytes(k).map_err(full)?;
                e.bytes(v).map_err(full)?;
            }
            e.end().map_err(full)?;
            let n = e.len();
            buf.truncate(n);
            buf
        };
        let Ok(Value::Dict(ad)) = decode(&answer) else {
            return Err(Error::Request(RequestError::TooLarge));
        };
        let n = match self.answer(&ad) {
            Ok(n) => n,
            Err(e) => {
                // A new party that cannot be answered leaves nothing.
                if !again && let Some(s) = self.sessions.remove(&key) {
                    self.end_session(&s);
                }
                return Err(e);
            }
        };
        // Nothing reaches the hidden side, and the party's media goes
        // nowhere until it is joined to someone.
        let dialog = self.created_dialog(&call_id, &tag).unwrap_or(key.clone());
        self.park_or_rejoin(&dialog, &key);
        if let Some(l) = req
            .get_bytes(b"set-label")
            .or_else(|| req.get_bytes(b"label"))
        {
            self.set_label(&call_id, &tag, l);
        }
        log::info!(
            "call {}: party {} created from its offer",
            String::from_utf8_lossy(&call_id),
            String::from_utf8_lossy(&tag)
        );
        Ok((call_id, tag, n))
    }

    /// The dialog of created party `tag` of `call` with its hidden side,
    /// whichever offered last (the dialog is under the last offerer's key).
    pub(super) fn created_dialog(&self, call: &[u8], tag: &[u8]) -> Option<super::SessionKey> {
        let creator = [CREATOR, tag].concat();
        let by_relay = (call.to_vec(), creator.clone());
        // (Not answered yet, it has no to-tag: the key is the party's own.)
        if self
            .sessions
            .get(&by_relay)
            .is_some_and(|s| s.to_tag.as_deref().is_none_or(|t| t == tag))
        {
            return Some(by_relay);
        }
        let by_party = (call.to_vec(), tag.to_vec());
        self.sessions
            .get(&by_party)
            .is_some_and(|s| s.to_tag.as_deref() == Some(&creator[..]))
            .then_some(by_party)
    }

    /// After an offer of the created party `party` (in the dialog under
    /// `key`): a party joined to another (`connect`) is joined again (a
    /// re-offer may have changed its sections); any other is parked: its
    /// media goes nowhere, and nothing reaches the hidden side.
    pub(super) fn park_or_rejoin(&mut self, key: &super::SessionKey, party: &super::SessionKey) {
        let peer = self.connections.iter().find_map(|(a, b)| {
            if a == party {
                Some(b.clone())
            } else if b == party {
                Some(a.clone())
            } else {
                None
            }
        });
        if let Some(peer) = peer {
            if let Err(e) = self.connect_parties(party, &peer) {
                self.warnings
                    .push(format!("the connection could not be made again: {e}"));
            }
            return;
        }
        if let Some(s) = self.sessions.get(key) {
            let states = s.media.clone();
            self.apply_echo(&states, Some([crate::relay::Echo::Discard; 2]), true);
        }
    }

    /// `create answer`: `call-id`, `from-tag` (the created party's) and
    /// `sdp` (its endpoint's answer).
    pub(super) fn create_answer(&mut self, req: &Dict<'_>) -> Result<(), Error> {
        let call_id = required(req, "call-id")?;
        let tag = required(req, "from-tag")?;
        required(req, "sdp")?;
        let creator = [CREATOR, tag].concat();
        if !self.sessions.keys().any(|k| k.0 == call_id) {
            return Err(Error::UnknownCall);
        }
        // The relay's offer is the one waiting: the dialog is under the
        // hidden side's key (it offered last).
        if self.created_dialog(call_id, tag) != Some((call_id.to_vec(), creator.clone())) {
            return Err(Error::Request(RequestError::UnknownTag(
                String::from_utf8_lossy(tag).into_owned(),
            )));
        }
        let answer = super::subscribe::with_entries(
            req,
            &[(b"from-tag", &creator), (b"to-tag", tag)],
            &[b"command"],
        )?;
        let Ok(Value::Dict(ad)) = decode(&answer) else {
            return Err(Error::Request(RequestError::TooLarge));
        };
        self.answer(&ad)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_template_has_the_formats_asked_for() {
        let t = template(&[vec![b"PCMA", b"opus", b"telephone-event", b"PCMA"]]).unwrap();
        assert!(t.contains("m=audio 9 RTP/AVP 8 96 101\r\n"), "{t}");
        assert!(t.contains("a=rtpmap:96 opus/48000/2\r\n"));
        assert!(t.contains("a=fmtp:101 0-16\r\n"));
        let two = template(&[vec![b"PCMU"], vec![b"G722"]]).unwrap();
        assert_eq!(two.matches("m=audio").count(), 2);
        assert!(template(&[vec![b"frob"]]).is_err());
    }
}
