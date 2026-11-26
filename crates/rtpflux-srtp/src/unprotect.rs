//! Unprotecting what the relay receives: SRTP and SRTCP, with
//! authentication before anything else and replay checks.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Receiving side: authenticates and decrypts the packets of the sources of
/// one direction.
#[derive(Clone)]
pub struct Unprotect {
    pub(super) suite: Suite,
    pub(super) policy: Policy,
    pub(super) rtp: SessionKeys,
    pub(super) rtcp: SessionKeys,
    pub(super) sources: Sources,
}

impl Unprotect {
    /// A context for `key`.
    #[must_use]
    pub fn from_key(key: &MasterKey) -> Self {
        Unprotect {
            suite: key.suite,
            policy: key.policy,
            rtp: SessionKeys::derive(key, 0),
            rtcp: SessionKeys::derive(key, 3),
            sources: Sources::default(),
        }
    }

    /// A context for the master key and salt (as in SDES).
    ///
    /// # Panics
    ///
    /// If `master` is not [`Suite::master_len`] octets.
    #[must_use]
    pub fn new(suite: Suite, master: &[u8]) -> Self {
        Self::from_key(&master_key(suite, master))
    }

    #[must_use]
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// Authenticate and decrypt the SRTP packet `buf[..len]` in place;
    /// returns the length of the RTP packet (without the tag). Nothing is
    /// changed when it fails: only an authenticated packet creates or
    /// updates its source's state.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] (also for `len` beyond `buf`), [`Error::Auth`],
    /// [`Error::Replay`] or [`Error::TooManySources`].
    pub fn rtp(&mut self, buf: &mut [u8], len: usize) -> Result<usize, Error> {
        let tag_len = if self.policy.unauthenticated_srtp {
            0
        } else {
            self.suite.rtp_tag_len()
        };
        let buf = buf.get_mut(..len).ok_or(Error::Malformed)?;
        let body = len.checked_sub(tag_len).ok_or(Error::Malformed)?;
        let (pkt, tag_in) = buf.split_at_mut_checked(body).ok_or(Error::Malformed)?;
        let hdr = rtp_header_len(pkt)?;
        let seq = be16(pkt, 2).ok_or(Error::Malformed)?;
        let ssrc = ssrc_at(pkt, 8).ok_or(Error::Malformed)?;
        let (at, mut source) = self.sources.lookup(ssrc, seq)?;
        if source.seq.ssrc.is_none() {
            // Known from SRTCP only: this is its first RTP packet.
            source.seq = SeqState::default().for_source(ssrc, seq);
        }
        let v = source.seq.guess(seq);
        let idx = index(v, seq);
        if !source.replay.fresh(idx) {
            return Err(Error::Replay);
        }
        match &self.rtp {
            SessionKeys::Cm { cipher, salt, mac } => {
                if tag_len > 0 && !SessionKeys::verify(mac, &[pkt, &v.to_be_bytes()], tag_in) {
                    return Err(Error::Auth);
                }
                if !self.policy.unencrypted_srtp {
                    let payload = pkt.get_mut(hdr..).ok_or(Error::Malformed)?;
                    SessionKeys::crypt(cipher, salt, ssrc, idx, payload);
                }
            }
            SessionKeys::Gcm { aead, salt } => {
                let tag: [u8; 16] = (*tag_in).try_into().map_err(|_| Error::Malformed)?;
                let (head, payload) = pkt.split_at_mut_checked(hdr).ok_or(Error::Malformed)?;
                if !aead.open(&rtp_iv(salt, ssrc, v, seq), head, payload, tag) {
                    return Err(Error::Auth);
                }
            }
        }
        source.seq.update(seq, v);
        source.replay.accept(idx);
        self.sources.commit(at, ssrc, source);
        Ok(body)
    }

    /// Authenticate and decrypt the SRTCP packet `buf[..len]` in place;
    /// returns the length of the RTCP compound packet. The replay window is
    /// the sender SSRC's.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::Auth`] or [`Error::Replay`].
    pub fn rtcp(&mut self, buf: &mut [u8], len: usize) -> Result<usize, Error> {
        let trailer = self.suite.srtcp_trailer();
        let buf = buf.get_mut(..len).ok_or(Error::Malformed)?;
        let body = len.checked_sub(trailer).ok_or(Error::Malformed)?;
        let head: [u8; 8] = *buf.first_chunk::<8>().ok_or(Error::Malformed)?;
        if body < 8 || head[0] >> 6 != 2 {
            return Err(Error::Malformed);
        }
        let ssrc = ssrc_at(&head, 4).ok_or(Error::Malformed)?;
        let (at, mut source) = self.sources.lookup(ssrc, 0)?;
        if at.is_none() {
            source.seq = SeqState::default();
        }
        // Counter mode: E ‖ index right after the packet; GCM: after the tag.
        let word_at = if self.suite.is_aead() {
            len.checked_sub(4).ok_or(Error::Malformed)?
        } else {
            body
        };
        let word: [u8; 4] = *at_chunk(buf, word_at).ok_or(Error::Malformed)?;
        let e_index = u32::from_be_bytes(word);
        let idx = u64::from(e_index & 0x7fff_ffff);
        if !source.rtcp_replay.fresh(idx) {
            return Err(Error::Replay);
        }
        let encrypted = e_index & 0x8000_0000 != 0;
        // The packet with its E ‖ index word (counter mode signs both).
        let signed = body.checked_add(4).ok_or(Error::Malformed)?;
        match &self.rtcp {
            SessionKeys::Cm { cipher, salt, mac } => {
                let (data, tag) = buf.split_at_mut_checked(signed).ok_or(Error::Malformed)?;
                if !SessionKeys::verify(mac, &[data], tag) {
                    return Err(Error::Auth);
                }
                if encrypted {
                    let payload = data.get_mut(8..body).ok_or(Error::Malformed)?;
                    SessionKeys::crypt(cipher, salt, ssrc, idx, payload);
                }
            }
            SessionKeys::Gcm { aead, salt } => {
                let tag: [u8; 16] = *at_chunk(buf, body).ok_or(Error::Malformed)?;
                let iv = rtcp_iv(salt, ssrc, e_index);
                if encrypted {
                    let mut aad = [0u8; 12];
                    let (a, w) = aad.split_at_mut(8);
                    a.copy_from_slice(&head);
                    w.copy_from_slice(&word);
                    let payload = buf.get_mut(8..body).ok_or(Error::Malformed)?;
                    if !aead.open(&iv, &aad, payload, tag) {
                        return Err(Error::Auth);
                    }
                } else {
                    // RFC 7714 §9.3: the whole packet and the E ‖ index
                    // word are the AAD. Make them contiguous in place, put
                    // the tag back if it does not match.
                    let room = at_chunk_mut::<4>(buf, body).ok_or(Error::Malformed)?;
                    *room = word;
                    let aad = buf.get(..signed).ok_or(Error::Malformed)?;
                    if !aead.open(&iv, aad, &mut [], tag) {
                        if let Some(room) = at_chunk_mut::<16>(buf, body) {
                            *room = tag;
                        }
                        return Err(Error::Auth);
                    }
                }
            }
        }
        source.rtcp_replay.accept(idx);
        self.sources.commit(at, ssrc, source);
        Ok(body)
    }
}
