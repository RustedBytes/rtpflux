//! The ciphers and key derivation: AES counter mode and AES-GCM, the
//! session keys derived from a master key (RFC 3711 §4.3) and the IVs.

use crate::Ssrc;

#[allow(clippy::wildcard_imports)]
use super::*;

/// AES with a 128- or 256-bit key.
#[derive(Clone)]
pub(super) enum Aes {
    A128(Aes128),
    A256(Aes256),
}

impl Aes {
    pub(super) fn new(key: &[u8]) -> Self {
        if key.len() == 32 {
            Aes::A256(Aes256::new_from_slice(key).unwrap_or_else(|_| unreachable!("32-octet key")))
        } else {
            Aes::A128(Aes128::new_from_slice(key).unwrap_or_else(|_| unreachable!("16-octet key")))
        }
    }

    /// XOR `data` with the counter-mode keystream from block `iv`.
    pub(super) fn ctr(&self, iv: [u8; 16], data: &mut [u8]) {
        match self {
            Aes::A128(c) => {
                ctr::Ctr128BE::<Aes128>::from_core(ctr::CtrCore::inner_iv_init(
                    c.clone(),
                    &iv.into(),
                ))
                .apply_keystream(data);
            }
            Aes::A256(c) => {
                ctr::Ctr128BE::<Aes256>::from_core(ctr::CtrCore::inner_iv_init(
                    c.clone(),
                    &iv.into(),
                ))
                .apply_keystream(data);
            }
        }
    }
}

/// AES-GCM with a 128- or 256-bit key.
#[derive(Clone)]
pub(super) enum Gcm {
    A128(Aes128Gcm),
    A256(Aes256Gcm),
}

impl Gcm {
    pub(super) fn new(key: &[u8]) -> Self {
        if key.len() == 32 {
            Gcm::A256(
                Aes256Gcm::new_from_slice(key).unwrap_or_else(|_| unreachable!("32-octet key")),
            )
        } else {
            Gcm::A128(
                Aes128Gcm::new_from_slice(key).unwrap_or_else(|_| unreachable!("16-octet key")),
            )
        }
    }

    /// Encrypt in place and return the tag; `None` when the cipher refuses
    /// (a message beyond GCM's length limit, not reachable for a packet),
    /// never a made-up tag.
    pub(super) fn seal(&self, iv: &[u8; 12], aad: &[u8], data: &mut [u8]) -> Option<[u8; 16]> {
        let tag = match self {
            Gcm::A128(g) => g.encrypt_inout_detached(iv.into(), aad, data.into()),
            Gcm::A256(g) => g.encrypt_inout_detached(iv.into(), aad, data.into()),
        };
        tag.ok().map(Into::into)
    }

    /// Verify and decrypt; `data` is unchanged when the tag does not match.
    pub(super) fn open(&self, iv: &[u8; 12], aad: &[u8], data: &mut [u8], tag: [u8; 16]) -> bool {
        let tag = tag.into();
        match self {
            Gcm::A128(g) => g
                .decrypt_inout_detached(iv.into(), aad, data.into(), &tag)
                .is_ok(),
            Gcm::A256(g) => g
                .decrypt_inout_detached(iv.into(), aad, data.into(), &tag)
                .is_ok(),
        }
    }
}

/// Session keys of one direction of SRTP or SRTCP (RFC 3711 §4.3.1).
#[derive(Clone)]
pub(super) enum SessionKeys {
    Cm {
        cipher: Aes,
        salt: [u8; 14],
        mac: HmacSha1,
    },
    Gcm {
        aead: Gcm,
        salt: [u8; 12],
    },
}

/// The AES-CM PRF (RFC 3711 §4.3.3): `out.len()` octets of keystream of the
/// master key at input x·2^16, x = (label ‖ r) ⊕ master salt, the salt
/// zero-padded on the right to 112 bits.
pub(super) fn prf(master: &Aes, salt: &[u8], label: u8, out: &mut [u8]) {
    let mut iv = [0u8; 16];
    // At most 14 octets of salt; the rest stays zero.
    for (b, s) in iv.iter_mut().zip(salt) {
        *b = *s;
    }
    // key_id = label ‖ (index DIV kdr) with kdr = 0: the label sits at
    // octet 7 (just left of the 48-bit r).
    iv[7] ^= label;
    out.fill(0);
    master.ctr(iv, out);
}

impl SessionKeys {
    /// Derive the session keys for labels `base`, `base + 1`, `base + 2`
    /// (SRTP 0..2, SRTCP 3..5).
    pub(super) fn derive(key: &MasterKey, base: u8) -> Self {
        let suite = key.suite;
        let (mk, ms) = key.bytes().split_at(suite.key_len());
        let master = Aes::new(mk);
        let mut enc = [0u8; 32];
        let (enc, _) = enc.split_at_mut(suite.key_len().min(32));
        prf(&master, ms, base, enc);
        if suite.is_aead() {
            let mut salt = [0u8; 12];
            prf(&master, ms, base.wrapping_add(2), &mut salt);
            return SessionKeys::Gcm {
                aead: Gcm::new(enc),
                salt,
            };
        }
        let mut auth = [0u8; 20];
        prf(&master, ms, base.wrapping_add(1), &mut auth);
        let mut salt = [0u8; 14];
        prf(&master, ms, base.wrapping_add(2), &mut salt);
        SessionKeys::Cm {
            cipher: Aes::new(enc),
            salt,
            mac: <HmacSha1 as KeyInit>::new_from_slice(&auth)
                .unwrap_or_else(|_| unreachable!("HMAC accepts any key length")),
        }
    }

    /// Counter mode: apply the keystream for (ssrc, index) to `data`.
    pub(super) fn crypt(cipher: &Aes, salt: &[u8; 14], ssrc: Ssrc, index: u64, data: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(salt);
        for (b, s) in iv[4..8].iter_mut().zip(ssrc.to_be_bytes()) {
            *b ^= s;
        }
        for (b, s) in iv[8..14].iter_mut().zip(&index.to_be_bytes()[2..]) {
            *b ^= s;
        }
        cipher.ctr(iv, data);
    }

    pub(super) fn tag(mac: &HmacSha1, parts: &[&[u8]]) -> [u8; 20] {
        let mut m = mac.clone();
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }

    /// Constant-time check of a truncated tag.
    pub(super) fn verify(mac: &HmacSha1, parts: &[&[u8]], tag: &[u8]) -> bool {
        let mut m = mac.clone();
        for p in parts {
            m.update(p);
        }
        m.verify_truncated_left(tag).is_ok()
    }
}

/// The GCM IV (RFC 7714 §8.1, §9.1): the salt XOR `fields`.
pub(super) fn gcm_iv(salt: &[u8; 12], fields: [u8; 12]) -> [u8; 12] {
    let mut iv = *salt;
    for (b, f) in iv.iter_mut().zip(fields) {
        *b ^= f;
    }
    iv
}

/// SRTP: 0 0 ‖ SSRC ‖ ROC ‖ SEQ.
pub(super) fn rtp_iv(salt: &[u8; 12], ssrc: Ssrc, roc: u32, seq: u16) -> [u8; 12] {
    let mut f = [0u8; 12];
    f[2..6].copy_from_slice(&ssrc.to_be_bytes());
    f[6..10].copy_from_slice(&roc.to_be_bytes());
    f[10..12].copy_from_slice(&seq.to_be_bytes());
    gcm_iv(salt, f)
}

/// SRTCP: 0 0 ‖ SSRC ‖ 0 0 ‖ 0 ‖ index (31 bits).
pub(super) fn rtcp_iv(salt: &[u8; 12], ssrc: Ssrc, index: u32) -> [u8; 12] {
    let mut f = [0u8; 12];
    f[2..6].copy_from_slice(&ssrc.to_be_bytes());
    f[8..12].copy_from_slice(&(index & 0x7fff_ffff).to_be_bytes());
    gcm_iv(salt, f)
}
