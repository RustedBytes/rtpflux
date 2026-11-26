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

use super::{Control, Error, RequestError, required, unix_now};
use core::fmt::Write as _;
use rtpflux_ng::bencode::{Dict, Value, decode};

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
    /// `create`: the offer to the created party's endpoint. The reply has
    /// `call-id`, `from-tag` (the party's) and `sdp`.
    pub(super) fn create(&mut self, req: &Dict<'_>) -> Result<(Vec<u8>, Vec<u8>, usize), Error> {
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
        if is_creator(&tag) {
            return Err(Error::unsupported(
                "create: a tag of the relay's own".to_owned(),
            ));
        }
        let sdp = template(&sections(req))?;
        let creator = [CREATOR, &tag].concat();
        // A party created before: a re-offer of its dialog (its ports).
        let again = self
            .sessions
            .contains_key(&(call_id.clone(), creator.clone()));
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
        let key = (call_id.clone(), creator);
        if let Some(s) = self.sessions.get(&key) {
            let states = s.media.clone();
            self.apply_echo(&states, Some([crate::relay::Echo::Discard; 2]), true);
        }
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
        if !self
            .sessions
            .contains_key(&(call_id.to_vec(), creator.clone()))
        {
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
