//! `rollback` (rtpengine's): a re-offer of an answered dialog made with
//! `track-state` can be taken back while it waits for its answer (the
//! answerer rejected the re-INVITE, say): the dialog returns to its last
//! agreed state, as if the re-offer had not come.
//!
//! The re-offer keeps a *checkpoint*: the dialog as last agreed, with the
//! key it was stored under (a re-offer by the answerer stores the dialog
//! under the other tag). Offers before the answer share it. While it is
//! kept, relay calls it has are not ended (a section the re-offer
//! removed). The answer commits: calls only the checkpoint had end. A
//! rollback ends calls only the re-offer made, sets the checkpoint's sides
//! on the relay calls again (a re-offer changes side A only; side B changes
//! with the answer), and puts the checkpoint back.

use super::media::Party;
use super::parties::side_of;
use super::reply::B;
use super::{Control, Error, RequestError, SessionKey, required};
use rtpflux_ng::bencode::Dict;

impl Control {
    /// The answer of dialog `key` was taken: its checkpoint, if any, is
    /// committed.
    pub(super) fn commit_checkpoint(&mut self, key: &SessionKey) {
        let Some(s) = self.sessions.get_mut(key) else {
            return;
        };
        let Some(c) = s.checkpoint.take() else {
            return;
        };
        let only = Self::only_in(&c.1.media, &s.media);
        self.end_media(&only);
    }

    /// `rollback`: `call-id`, `from-tag` and `to-tag` (or `via-branch`)
    /// name the dialog. The reply's `rolled-back` is 1 when a pending
    /// re-offer was taken back, 0 when there was none.
    pub(super) fn rollback(&mut self, d: &Dict<'_>) -> Result<Vec<(Vec<u8>, B)>, Error> {
        let call_id = required(d, "call-id")?;
        let from = required(d, "from-tag")?;
        let to = d.get_bytes(b"to-tag");
        let via = d.get_bytes(b"via-branch");
        if to.is_none() && via.is_none() {
            return Err(Error::Missing("to-tag".to_owned()));
        }
        if !self.sessions.keys().any(|k| k.0 == call_id) {
            return Err(Error::UnknownCall);
        }
        let key = self
            .sessions
            .iter()
            .find(|(k, s)| {
                k.0 == call_id
                    && side_of(k, s, from).is_some()
                    && to.is_none_or(|t| side_of(k, s, t).is_some())
                    && via.is_none_or(|v| s.via_branch.as_deref() == Some(v))
            })
            .map(|(k, _)| k.clone())
            .ok_or_else(|| Error::Request(RequestError::UnknownDialogue))?;
        let rolled = self.roll_back(&key);
        Ok(vec![(b"rolled-back".to_vec(), B::int(u64::from(rolled)))])
    }

    /// Put dialog `key` back as its checkpoint has it; whether it had one.
    fn roll_back(&mut self, key: &SessionKey) -> bool {
        if self
            .sessions
            .get(key)
            .is_none_or(|s| s.checkpoint.is_none())
        {
            return false;
        }
        let Some(mut now) = self.sessions.remove(key) else {
            return false;
        };
        let Some(c) = now.checkpoint.take() else {
            return false;
        };
        let (cp_key, cp) = *c;
        // The re-offer's own calls end; the checkpoint's sides come back.
        let only = Self::only_in(&now.media, &cp.media);
        self.end_media(&only);
        // The dialog is put back whatever happens; what the media workers
        // could not take is reported in the reply's `warning`.
        let mut failed = 0usize;
        for st in cp.media.iter().flatten() {
            for party in [Party::A, Party::B] {
                let side = if party == Party::A {
                    &st.a_side
                } else {
                    &st.b_side
                };
                if let Err(e) = self.relay.update_side(st.ports.id, st.leg(party), side) {
                    log::warn!("call {}: rolling back: {e}", st.ports.id);
                    failed += 1;
                }
            }
        }
        if let Err(e) = self.rebundle(&cp.media) {
            log::warn!(
                "call {}: rollback: BUNDLE: {e}",
                String::from_utf8_lossy(&cp_key.0)
            );
            failed += 1;
        }
        if failed > 0 {
            self.warnings.push(format!(
                "rollback: {failed} media update(s) failed; media may not match the SDP"
            ));
        }
        log::info!(
            "call {}: re-offer rolled back",
            String::from_utf8_lossy(&cp_key.0)
        );
        self.sessions.insert(cp_key.clone(), cp);
        self.update_holds(&cp_key);
        self.mark_dirty();
        true
    }
}
