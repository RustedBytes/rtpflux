//! Protecting what the relay sends: SRTP and SRTCP.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Sending side: protects the packets of the sources of one direction.
#[derive(Clone)]
pub struct Protect {
    pub(super) suite: Suite,
    pub(super) policy: Policy,
    pub(super) rtp: SessionKeys,
    pub(super) rtcp: SessionKeys,
    pub(super) sources: Sources,
}

impl Protect {
    /// A context for `key`.
    #[must_use]
    pub fn from_key(key: &MasterKey) -> Self {
        Protect {
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

    /// Protect the RTP packet `buf[..len]` in place; returns the new length
    /// (`len` + tag).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a non-RTP packet, [`Error::BufferTooSmall`]
    /// when `buf` has no room for the tag, [`Error::Replay`] for a packet
    /// index already used under this key (a duplicate sequence number, or
    /// one far behind): encrypting at it again would reuse its keystream.
    pub fn rtp(&mut self, buf: &mut [u8], len: usize) -> Result<usize, Error> {
        let pkt = buf.get(..len).ok_or(Error::Malformed)?;
        let hdr = rtp_header_len(pkt)?;
        let seq = be16(pkt, 2).ok_or(Error::Malformed)?;
        let ssrc = ssrc_at(pkt, 8).ok_or(Error::Malformed)?;
        let tag_len = if self.policy.unauthenticated_srtp {
            0
        } else {
            self.suite.rtp_tag_len()
        };
        let end = len.checked_add(tag_len).ok_or(Error::BufferTooSmall)?;
        let buf = buf.get_mut(..end).ok_or(Error::BufferTooSmall)?;
        let (pkt, tag_out) = buf.split_at_mut_checked(len).ok_or(Error::Malformed)?;
        let (at, mut source) = self.sources.lookup(ssrc, seq)?;
        let v = source.seq.guess(seq);
        let packet_index = index(v, seq);
        if !source.replay.fresh(packet_index) {
            return Err(Error::Replay);
        }
        match &self.rtp {
            SessionKeys::Cm { cipher, salt, mac } => {
                if !self.policy.unencrypted_srtp {
                    let payload = pkt.get_mut(hdr..).ok_or(Error::Malformed)?;
                    SessionKeys::crypt(cipher, salt, ssrc, packet_index, payload);
                }
                if tag_len > 0 {
                    let tag = SessionKeys::tag(mac, &[pkt, &v.to_be_bytes()]);
                    tag_out.copy_from_slice(tag.get(..tag_len).ok_or(Error::Malformed)?);
                }
            }
            SessionKeys::Gcm { aead, salt } => {
                let (head, payload) = pkt.split_at_mut_checked(hdr).ok_or(Error::Malformed)?;
                let tag = aead
                    .seal(&rtp_iv(salt, ssrc, v, seq), head, payload)
                    .ok_or(Error::Malformed)?;
                tag_out.copy_from_slice(tag.get(..tag_len).ok_or(Error::Malformed)?);
            }
        }
        source.seq.update(seq, v);
        source.replay.accept(packet_index);
        self.sources.commit(at, ssrc, source);
        Ok(end)
    }

    /// Protect the RTCP compound packet `buf[..len]` in place (encrypted,
    /// E = 1); returns the new length (`len` + [`Suite::srtcp_trailer`]).
    /// Each sender SSRC has its own SRTCP index.
    ///
    /// # Errors
    ///
    /// As [`Protect::rtp`].
    pub fn rtcp(&mut self, buf: &mut [u8], len: usize) -> Result<usize, Error> {
        let head: [u8; 8] = *buf.first_chunk::<8>().ok_or(Error::Malformed)?;
        if len < 8 || buf.len() < len || head[0] >> 6 != 2 {
            return Err(Error::Malformed);
        }
        let trailer = self.suite.srtcp_trailer();
        let end = len.checked_add(trailer).ok_or(Error::BufferTooSmall)?;
        let buf = buf.get_mut(..end).ok_or(Error::BufferTooSmall)?;
        let ssrc = ssrc_at(&head, 4).ok_or(Error::Malformed)?;
        let (at, mut source) = self.sources.lookup(ssrc, 0)?;
        let idx = source.rtcp_index & 0x7fff_ffff;
        // Past 2^31 - 1 the index would wrap back to used ones: refused.
        if !source.rtcp_replay.fresh(u64::from(idx)) {
            return Err(Error::Replay);
        }
        // E: encrypted, unless UNENCRYPTED_SRTCP (counter mode only).
        let clear = self.policy.unencrypted_srtcp;
        let word = if clear { idx } else { idx | 0x8000_0000 }.to_be_bytes();
        let (data, out) = buf.split_at_mut_checked(len).ok_or(Error::Malformed)?;
        let payload = data.get_mut(8..).ok_or(Error::Malformed)?;
        match &self.rtcp {
            SessionKeys::Cm { cipher, salt, mac } => {
                if !clear {
                    SessionKeys::crypt(cipher, salt, ssrc, u64::from(idx), payload);
                }
                let (w, tag_out) = out.split_at_mut_checked(4).ok_or(Error::Malformed)?;
                w.copy_from_slice(&word);
                let tag = SessionKeys::tag(mac, &[data, w]);
                tag_out.copy_from_slice(tag.get(..tag_out.len()).ok_or(Error::Malformed)?);
            }
            SessionKeys::Gcm { aead, salt } => {
                // RFC 7714 §9.2: AAD = first 8 octets ‖ E ‖ index; the tag,
                // then the E ‖ index word in clear.
                let mut aad = [0u8; 12];
                let (a, w) = aad.split_at_mut(8);
                a.copy_from_slice(&head);
                w.copy_from_slice(&word);
                let tag = aead
                    .seal(&rtcp_iv(salt, ssrc, idx), &aad, payload)
                    .ok_or(Error::Malformed)?;
                let (t, w) = out.split_at_mut_checked(16).ok_or(Error::Malformed)?;
                t.copy_from_slice(&tag);
                w.copy_from_slice(&word);
            }
        }
        source.rtcp_index = idx.wrapping_add(1) & 0x7fff_ffff;
        source.rtcp_replay.accept(u64::from(idx));
        if at.is_none() {
            // An RTCP-only source: no RTP seen yet, so no sequence state.
            source.seq = SeqState::default();
        }
        self.sources.commit(at, ssrc, source);
        Ok(end)
    }
}
