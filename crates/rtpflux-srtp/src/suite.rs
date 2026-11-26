//! The SRTP protection suites and master keys (RFC 3711, RFC 6188,
//! RFC 7714).

#[allow(clippy::wildcard_imports)]
use super::*;

/// The supported crypto suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    AesCm128HmacSha1_80,
    AesCm128HmacSha1_32,
    AesCm256HmacSha1_80,
    AesCm256HmacSha1_32,
    AeadAes128Gcm,
    AeadAes256Gcm,
}

impl Suite {
    /// The SDP name (RFC 4568 §6.2, RFC 6188 §4, RFC 7714 §14.1).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Suite::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Suite::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
            Suite::AesCm256HmacSha1_80 => "AES_256_CM_HMAC_SHA1_80",
            Suite::AesCm256HmacSha1_32 => "AES_256_CM_HMAC_SHA1_32",
            Suite::AeadAes128Gcm => "AEAD_AES_128_GCM",
            Suite::AeadAes256Gcm => "AEAD_AES_256_GCM",
        }
    }

    /// The suite with this SDP name.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        [
            Suite::AesCm128HmacSha1_80,
            Suite::AesCm128HmacSha1_32,
            Suite::AesCm256HmacSha1_80,
            Suite::AesCm256HmacSha1_32,
            Suite::AeadAes128Gcm,
            Suite::AeadAes256Gcm,
        ]
        .into_iter()
        .find(|s| s.name().as_bytes() == name)
    }

    /// Master (and session) key length in octets.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Suite::AesCm128HmacSha1_80 | Suite::AesCm128HmacSha1_32 | Suite::AeadAes128Gcm => 16,
            Suite::AesCm256HmacSha1_80 | Suite::AesCm256HmacSha1_32 | Suite::AeadAes256Gcm => 32,
        }
    }

    /// Master (and session) salt length in octets.
    #[must_use]
    pub const fn salt_len(self) -> usize {
        if self.is_aead() { 12 } else { 14 }
    }

    /// Master key and salt together.
    #[must_use]
    pub const fn master_len(self) -> usize {
        // At most 32 + 14.
        self.key_len().wrapping_add(self.salt_len())
    }

    /// An AEAD (GCM) suite.
    #[must_use]
    pub const fn is_aead(self) -> bool {
        matches!(self, Suite::AeadAes128Gcm | Suite::AeadAes256Gcm)
    }

    /// SRTP authentication tag length in octets.
    #[must_use]
    pub const fn rtp_tag_len(self) -> usize {
        match self {
            Suite::AesCm128HmacSha1_80 | Suite::AesCm256HmacSha1_80 => 10,
            Suite::AesCm128HmacSha1_32 | Suite::AesCm256HmacSha1_32 => 4,
            Suite::AeadAes128Gcm | Suite::AeadAes256Gcm => 16,
        }
    }

    /// What SRTCP adds to an RTCP packet: tag and E ‖ index.
    #[must_use]
    pub const fn srtcp_trailer(self) -> usize {
        if self.is_aead() {
            16 + 4
        } else {
            SRTCP_TRAILER
        }
    }
}

/// A suite with its master key and salt: what one `a=crypto` line carries.
///
/// It is `Copy` and not wiped when dropped, by design: keys are signalled
/// in clear SDP (RFC 4568), kept in the call state and its state file, and
/// copied into each leg's command; wiping one copy would protect nothing.
/// Keys from DTLS are wiped where they are exported (the relay's `dtls`
/// module); their derived session keys live in the cipher contexts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MasterKey {
    pub suite: Suite,
    /// Master key followed by master salt, zero beyond
    /// [`Suite::master_len`].
    pub key: [u8; MAX_MASTER_LEN],
    /// What SDES session parameters leave out (none by default).
    pub policy: Policy,
}

/// The SDES session parameters that switch protection off (RFC 4568
/// §6.3.3 to §6.3.5): RTP not encrypted, SRTCP not encrypted (E = 0), RTP
/// not authenticated. Only counter-mode suites have them: an AEAD suite
/// (RFC 7714) always encrypts and authenticates together.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    pub unencrypted_srtp: bool,
    pub unencrypted_srtcp: bool,
    pub unauthenticated_srtp: bool,
}

impl Policy {
    /// Full protection.
    pub const NONE: Policy = Policy {
        unencrypted_srtp: false,
        unencrypted_srtcp: false,
        unauthenticated_srtp: false,
    };

    /// Whether everything is protected.
    #[must_use]
    pub const fn is_none(self) -> bool {
        !self.unencrypted_srtp && !self.unencrypted_srtcp && !self.unauthenticated_srtp
    }

    /// Its session parameters, as `a=crypto` writes them.
    pub fn params(self) -> impl Iterator<Item = &'static str> {
        [
            (self.unencrypted_srtp, "UNENCRYPTED_SRTP"),
            (self.unencrypted_srtcp, "UNENCRYPTED_SRTCP"),
            (self.unauthenticated_srtp, "UNAUTHENTICATED_SRTP"),
        ]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
    }

    /// The policy one more session parameter makes; `None` for another
    /// parameter.
    #[must_use]
    pub fn with_param(mut self, param: &[u8]) -> Option<Self> {
        match param {
            b"UNENCRYPTED_SRTP" => self.unencrypted_srtp = true,
            b"UNENCRYPTED_SRTCP" => self.unencrypted_srtcp = true,
            b"UNAUTHENTICATED_SRTP" => self.unauthenticated_srtp = true,
            _ => return None,
        }
        Some(self)
    }
}

impl MasterKey {
    /// A key of `suite` from its master key and salt (exactly
    /// [`Suite::master_len`] octets).
    #[must_use]
    pub fn new(suite: Suite, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != suite.master_len() {
            return None;
        }
        let mut key = [0u8; MAX_MASTER_LEN];
        key.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(MasterKey {
            suite,
            key,
            policy: Policy::NONE,
        })
    }

    /// The same key under `policy`; `None` for an AEAD suite with anything
    /// switched off.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Option<Self> {
        if self.suite.is_aead() && !policy.is_none() {
            return None;
        }
        self.policy = policy;
        Some(self)
    }

    /// The master key and salt.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.key
            .split_at(self.suite.master_len().min(MAX_MASTER_LEN))
            .0
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        write!(f, "MasterKey({}, ..)", self.suite.name())
    }
}

/// The master key of `suite` from `master` (its exact length).
///
/// # Panics
///
/// If `master` is not [`Suite::master_len`] octets.
pub(super) fn master_key(suite: Suite, master: &[u8]) -> MasterKey {
    MasterKey::new(suite, master).unwrap_or_else(|| {
        panic!(
            "{} needs a {}-octet master key and salt",
            suite.name(),
            suite.master_len()
        )
    })
}
