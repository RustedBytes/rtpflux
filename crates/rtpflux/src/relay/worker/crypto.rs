//! SRTP and SRTCP of one leg: decrypting what its peer sends and
//! encrypting what the relay sends to it.

#[allow(clippy::wildcard_imports)]
use super::*;

/// SRTP contexts of one leg.
pub(super) struct LegCrypto {
    pub(super) config: Srtp,
    /// RTCP leg: SRTCP framing.
    pub(super) rtcp: bool,
    /// Waiting for DTLS keys: outbound packets are dropped.
    pub(super) hold: bool,
    pub(super) inbound: Option<Unprotect>,
    pub(super) outbound: Option<Protect>,
}

impl LegCrypto {
    /// Contexts for `config`, or `None` for plain RTP both ways. `hold`:
    /// keys will come from DTLS; until then nothing leaves for this leg.
    pub(super) fn new(config: Srtp, rtcp: bool, hold: bool) -> Option<Box<Self>> {
        if config.is_plain() && !hold {
            return None;
        }
        Some(Box::new(LegCrypto {
            config,
            rtcp,
            hold,
            inbound: match config.inbound {
                Inbound::Key(k) => Some(Unprotect::from_key(&k)),
                Inbound::Plain | Inbound::Pending => None,
            },
            outbound: config.outbound.as_ref().map(Protect::from_key),
        }))
    }

    /// Change `leg`'s keys to `config` (`hold`: keys will come from DTLS).
    /// Each direction is rebuilt only when its key changes: an unchanged
    /// outbound key keeps its context, whose packet indices must never
    /// repeat under that key (a re-INVITE often brings the peer a new key
    /// while the relay's own stays). An unchanged inbound key keeps its
    /// replay state.
    pub(super) fn update(leg: &mut Option<Box<Self>>, config: Srtp, rtcp: bool, hold: bool) {
        let Some(cur) = leg.as_mut() else {
            *leg = Self::new(config, rtcp, hold);
            return;
        };
        if config.is_plain() && !hold {
            *leg = None;
            return;
        }
        if cur.config.inbound != config.inbound {
            cur.inbound = match config.inbound {
                Inbound::Key(k) => Some(Unprotect::from_key(&k)),
                Inbound::Plain | Inbound::Pending => None,
            };
        }
        if cur.config.outbound != config.outbound {
            cur.outbound = config.outbound.as_ref().map(Protect::from_key);
        }
        cur.config = config;
        cur.rtcp = rtcp;
        cur.hold = hold;
    }

    /// Authenticate and decrypt an arriving packet in place.
    pub(super) fn unprotect(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        match (self.config.inbound, &mut self.inbound) {
            (Inbound::Plain, _) => Some(len),
            (Inbound::Key(_), Some(ctx)) => if self.rtcp {
                ctx.rtcp(buf, len)
            } else {
                ctx.rtp(buf, len)
            }
            .ok(),
            _ => None,
        }
    }

    /// Encrypt a departing packet in place.
    pub(super) fn protect(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        match &mut self.outbound {
            None if self.hold => None,
            None => Some(len),
            Some(ctx) => if self.rtcp {
                ctx.rtcp(buf, len)
            } else {
                ctx.rtp(buf, len)
            }
            .ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtpflux_srtp::{MasterKey, Suite};

    fn key(fill: u8) -> MasterKey {
        let s = Suite::AesCm128HmacSha1_80;
        MasterKey::new(s, &vec![fill; s.master_len()]).unwrap()
    }

    /// The SRTCP index (E flag cleared) of a protected packet of `len`.
    fn index(buf: &[u8], len: usize) -> u32 {
        let t = len - 10 - 4; // 80-bit tag, then the E|index word before it
        u32::from_be_bytes([buf[t], buf[t + 1], buf[t + 2], buf[t + 3]]) & 0x7fff_ffff
    }

    #[test]
    fn a_new_inbound_key_keeps_the_outbound_context() {
        let rr = [0x80, 201, 0, 1, 0, 0, 0, 7]; // an empty receiver report
        let srtp = |inbound| Srtp {
            inbound: Inbound::Key(key(inbound)),
            outbound: Some(key(9)),
        };
        let mut leg = LegCrypto::new(srtp(1), true, false);
        let mut buf = [0u8; 64];
        let mut send = |leg: &mut Option<Box<LegCrypto>>| {
            buf[..rr.len()].copy_from_slice(&rr);
            let n = leg.as_mut().unwrap().protect(&mut buf, rr.len()).unwrap();
            index(&buf, n)
        };
        assert_eq!(send(&mut leg), 0);
        // A re-INVITE: the peer's key changes, the relay's does not.
        LegCrypto::update(&mut leg, srtp(2), true, false);
        assert_eq!(send(&mut leg), 1, "the index goes on: no reuse under key 9");
        // A new outbound key starts a new context.
        let mut changed = srtp(2);
        changed.outbound = Some(key(10));
        LegCrypto::update(&mut leg, changed, true, false);
        assert_eq!(send(&mut leg), 0);
        // Plain without a DTLS hold: no contexts at all.
        LegCrypto::update(&mut leg, Srtp::default(), true, false);
        assert!(leg.is_none());
    }

    #[test]
    fn a_dtls_leg_turned_plain_relays_again() {
        let mut leg = LegCrypto::new(Srtp::default(), false, true);
        let mut pkt = [0x80u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7];
        assert_eq!(leg.as_mut().unwrap().protect(&mut pkt, 12), None, "held");
        LegCrypto::update(&mut leg, Srtp::default(), false, false);
        assert!(leg.is_none(), "plain: passed through unchanged");
    }
}
