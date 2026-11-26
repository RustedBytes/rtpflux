//! Calls with more than two parties: one `call-id` holds several parties
//! (tags), each in one or more dialogs with the others, and each may have
//! a label.
//!
//! - **Dialogs between any two parties.** A dialog is stored under its
//!   offerer's tag. An offer from a party that already has a dialog with
//!   another one, naming a third party known in the call as its `to-tag`,
//!   is a dialog of its own between those two, stored under a *pair key*
//!   (the offerer's tag, [`PAIR`], the other's tag). So the same party can
//!   be in a dialog with two others at once (a consultation, a three-way
//!   call made by a B2BUA in one call-id).
//! - **Labels** (`label`, `set-label` on an offer or answer: the party that
//!   sent the SDP) name a party, so other commands can select it by
//!   `label`/`from-label` instead of `from-tag`, and by `to-label` instead
//!   of `to-tag`. They are kept per call and saved with the state.

use super::{Control, Error, RequestError, Session, SessionKey, base_tag};
use crate::control::media::Party;
use rtpflux_ng::bencode::Dict;

/// What separates the offerer's tag of a dialog's pair key from the other
/// party's (no SIP tag holds a NUL).
pub(super) const PAIR: &[u8] = b"\0to:";

/// The key of the dialog between the offerer of `key` and party `peer`.
pub(super) fn pair_key((c, f): &SessionKey, peer: &[u8]) -> SessionKey {
    (c.clone(), [base_tag(f), PAIR, peer].concat())
}

/// The other party a pair key names.
pub(super) fn peer_of_key(f: &[u8]) -> Option<&[u8]> {
    let at = f.windows(PAIR.len()).position(|w| w == PAIR)?;
    Some(&f[at + PAIR.len()..])
}

/// The side of the dialog stored under `key` that the party `tag` is, if
/// it is in it.
pub(super) fn side_of(key: &SessionKey, s: &Session, tag: &[u8]) -> Option<Party> {
    if base_tag(&key.1) == tag {
        Some(Party::A)
    } else if s.to_tag.as_deref() == Some(tag) {
        Some(Party::B)
    } else {
        None
    }
}

/// The tag of side `party` of the dialog stored under `key`.
pub(super) fn tag_of<'a>(key: &'a SessionKey, s: &'a Session, party: Party) -> Option<&'a [u8]> {
    if party == Party::A {
        Some(base_tag(&key.1))
    } else {
        s.to_tag.as_deref()
    }
}

/// `all` (the flag, or `all: all`): every party of the call.
pub(super) fn all_parties(d: &Dict<'_>) -> bool {
    super::list_contains(d, b"flags", b"all") || d.get_bytes(b"all") == Some(b"all")
}

/// Each call's labels: (tag, label), one label per party and one party per
/// label.
pub(super) type Labels = std::collections::HashMap<Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>>;

/// Which of a request's parties to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Which {
    /// `from-tag`, else `label` or `from-label`.
    From,
    /// `to-tag`, else `to-label`.
    To,
}

impl Control {
    /// Label the party `tag` of `call_id`; a label another party had moves
    /// to this one.
    pub(super) fn set_label(&mut self, call_id: &[u8], tag: &[u8], label: &[u8]) {
        let list = self.labels.entry(call_id.to_vec()).or_default();
        list.retain(|(t, l)| t != tag && l != label);
        list.push((tag.to_vec(), label.to_vec()));
        self.mark_dirty();
    }

    /// The label of party `tag` of `call_id`.
    pub(super) fn label_of(&self, call_id: &[u8], tag: &[u8]) -> Option<&[u8]> {
        self.labels
            .get(call_id)?
            .iter()
            .find(|(t, _)| t == tag)
            .map(|(_, l)| l.as_slice())
    }

    /// The party of `call_id` labelled `label`.
    fn tag_of_label(&self, call_id: &[u8], label: &[u8]) -> Option<&[u8]> {
        self.labels
            .get(call_id)?
            .iter()
            .find(|(_, l)| l == label)
            .map(|(t, _)| t.as_slice())
    }

    /// The party (tag) of `call_id` a request selects as its first party
    /// (`from-tag`, `label`, `from-label`) or its second (`to-tag`,
    /// `to-label`); `None` when it names none. A label no party has is
    /// refused.
    pub(super) fn party(
        &self,
        d: &Dict<'_>,
        call_id: &[u8],
        which: Which,
    ) -> Result<Option<Vec<u8>>, Error> {
        let (tag, labels): (&[u8], &[&[u8]]) = match which {
            Which::From => (b"from-tag", &[b"label", b"from-label"]),
            Which::To => (b"to-tag", &[b"to-label"]),
        };
        if let Some(t) = d.get_bytes(tag) {
            return Ok(Some(t.to_vec()));
        }
        let Some(label) = labels.iter().find_map(|k| d.get_bytes(k)) else {
            return Ok(None);
        };
        self.tag_of_label(call_id, label)
            .map(|t| Some(t.to_vec()))
            .ok_or_else(|| {
                Error::Request(RequestError::UnknownLabel(
                    String::from_utf8_lossy(label).into_owned(),
                ))
            })
    }

    /// `label` (or `set-label`) of an offer or answer: the label of the
    /// party that sent the SDP, whose tag is under `tag_key` (`from-tag`
    /// of an offer, `to-tag` of an answer).
    pub(super) fn label_sdp_sender(&mut self, d: &Dict<'_>, tag_key: &[u8]) {
        let label = d.get_bytes(b"set-label").or_else(|| d.get_bytes(b"label"));
        if let (Some(call_id), Some(tag), Some(label)) =
            (d.get_bytes(b"call-id"), d.get_bytes(tag_key), label)
        {
            self.set_label(call_id, tag, label);
        }
    }

    /// Whether `tag` is a party of `call_id` (in a dialog of it).
    pub(super) fn knows(&self, call_id: &[u8], tag: &[u8]) -> bool {
        self.sessions
            .iter()
            .any(|(k, s)| k.0 == call_id && side_of(k, s, tag).is_some())
    }

    /// The dialog an offer from the offerer of `key` with `to-tag` `peer`
    /// is for: theirs under a pair key when there is one; the offerer's
    /// own when it is with `peer` (or not answered yet), or when `peer`
    /// is no party of the call (an answerer's tag the dialog learns);
    /// else a new dialog between the two, under their pair key.
    pub(super) fn dialog_key(&self, key: SessionKey, peer: &[u8]) -> SessionKey {
        let pair = pair_key(&key, peer);
        if self.sessions.contains_key(&pair) {
            return pair;
        }
        let elsewhere = self
            .sessions
            .get(&key)
            .is_some_and(|s| s.to_tag.as_deref().is_some_and(|t| t != peer));
        if elsewhere && self.knows(&key.0, peer) {
            pair
        } else {
            key
        }
    }

    /// The dialog between the parties `offerer` and `peer` of `call_id`
    /// stored with `peer` as its offerer, if any.
    pub(super) fn reversed_key(
        &self,
        call_id: &[u8],
        offerer: &[u8],
        peer: Option<&[u8]>,
    ) -> Option<SessionKey> {
        self.sessions
            .iter()
            .find(|(k, s)| {
                k.0 == call_id
                    && s.to_tag.as_deref() == Some(offerer)
                    && peer.is_none_or(|p| base_tag(&k.1) == p)
            })
            .map(|(k, _)| k.clone())
    }

    /// The other party of a pair key's dialog, for a reversal.
    pub(super) fn peer_of(key: &SessionKey) -> Option<&[u8]> {
        peer_of_key(&key.1)
    }

    /// Forget the labels of calls that have no dialog or subscription,
    /// and the connections and copies of a party no dialog has any more.
    pub(super) fn prune_parties(&mut self) {
        if self.labels.is_empty() && self.connections.is_empty() && self.copies.is_empty() {
            return;
        }
        if !self.connections.is_empty() || !self.copies.is_empty() {
            // Every party of every dialog, once.
            let parties: std::collections::HashSet<(&[u8], &[u8])> = self
                .sessions
                .iter()
                .flat_map(|(k, s)| {
                    [Some(base_tag(&k.1)), s.to_tag.as_deref()]
                        .into_iter()
                        .flatten()
                        .map(|t| (k.0.as_slice(), t))
                })
                .collect();
            let live =
                |(call, tag): &SessionKey| parties.contains(&(call.as_slice(), tag.as_slice()));
            self.connections.retain(|(a, b)| live(a) && live(b));
            self.copies.retain(|(a, b, _)| live(a) && live(b));
        }
        if self.labels.is_empty() {
            return;
        }
        let live: std::collections::HashSet<&[u8]> = self
            .sessions
            .keys()
            .map(|k| k.0.as_slice())
            .chain(self.subscriptions.keys().map(|k| k.0.as_slice()))
            .collect();
        let gone: Vec<Vec<u8>> = self
            .labels
            .keys()
            .filter(|c| !live.contains(c.as_slice()))
            .cloned()
            .collect();
        for c in gone {
            self.labels.remove(&c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_keys_name_both_parties() {
        let key = (b"c".to_vec(), b"alice".to_vec());
        let pair = pair_key(&key, b"carol");
        assert_eq!(base_tag(&pair.1), b"alice");
        assert_eq!(peer_of_key(&pair.1), Some(&b"carol"[..]));
        assert_eq!(peer_of_key(b"alice"), None);
        // Of a pair key, the offerer's tag only.
        assert_eq!(pair_key(&pair, b"dave").1, b"alice\0to:dave");
    }
}
