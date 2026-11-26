//! The DTLS-SRTP decisions that do not need cryptography (RFC 5763,
//! RFC 5764, RFC 4572): who is the DTLS client, the `a=fingerprint`
//! syntax, and which half of the exported keying material protects which
//! direction. The handshake itself and the hashing live in the daemon.

/// `a=setup` (RFC 4145 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    Active,
    Passive,
    Actpass,
    Holdconn,
}

impl Setup {
    /// The attribute value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Setup::Active => "active",
            Setup::Passive => "passive",
            Setup::Actpass => "actpass",
            Setup::Holdconn => "holdconn",
        }
    }

    /// The setup named by an attribute value (exact, lower case).
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"active" => Some(Setup::Active),
            b"passive" => Some(Setup::Passive),
            b"actpass" => Some(Setup::Actpass),
            b"holdconn" => Some(Setup::Holdconn),
            _ => None,
        }
    }
}

/// RFC 4145 §4.1: the answers an offer allows (`actpass` ⇒ `active` or
/// `passive`, `active` ⇒ `passive`, `passive` ⇒ `active`, `holdconn` ⇒
/// `holdconn`).
#[must_use]
pub const fn compatible(offer: Setup, answer: Setup) -> bool {
    matches!(
        (offer, answer),
        (Setup::Actpass, Setup::Active | Setup::Passive)
            | (Setup::Active, Setup::Passive)
            | (Setup::Passive, Setup::Active)
            | (Setup::Holdconn, Setup::Holdconn)
    )
}

/// RFC 5763 §5: "whichever party is active MUST initiate a DTLS handshake".
/// `Some(true)`: the offerer is the DTLS client; `Some(false)`: the answerer.
#[must_use]
pub const fn client_is_offerer(answer: Setup) -> Option<bool> {
    match answer {
        Setup::Active => Some(false),
        Setup::Passive => Some(true),
        Setup::Actpass | Setup::Holdconn => None,
    }
}

/// Hash functions whose fingerprints the relay checks. MD2 and MD5 (RFC
/// 4572 Figure 3) never match: RFC 8122 §5 deprecates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFn {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl HashFn {
    /// The hash named in an attribute (case-insensitive), if checked.
    #[must_use]
    pub fn parse(name: &[u8]) -> Option<Self> {
        let mut lower = [0u8; 8];
        let n = name.len();
        if n > lower.len() {
            return None;
        }
        for (l, c) in lower.iter_mut().zip(name) {
            *l = c.to_ascii_lowercase();
        }
        match lower.get(..n)? {
            b"sha-1" => Some(HashFn::Sha1),
            b"sha-224" => Some(HashFn::Sha224),
            b"sha-256" => Some(HashFn::Sha256),
            b"sha-384" => Some(HashFn::Sha384),
            b"sha-512" => Some(HashFn::Sha512),
            _ => None,
        }
    }

    /// The digest's length in octets.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            HashFn::Sha1 => 20,
            HashFn::Sha224 => 28,
            HashFn::Sha256 => 32,
            HashFn::Sha384 => 48,
            HashFn::Sha512 => 64,
        }
    }

    /// The attribute name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            HashFn::Sha1 => "sha-1",
            HashFn::Sha224 => "sha-224",
            HashFn::Sha256 => "sha-256",
            HashFn::Sha384 => "sha-384",
            HashFn::Sha512 => "sha-512",
        }
    }
}

/// Longest digest (SHA-512).
pub const MAX_DIGEST: usize = 64;

/// A certificate fingerprint from `a=fingerprint` (RFC 4572 §5).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub hash: HashFn,
    digest: [u8; MAX_DIGEST],
    len: u8,
}

impl core::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fingerprint({}, {} octets)", self.hash.name(), self.len)
    }
}

fn upper_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'A'..=b'F' => c.checked_sub(b'A' - 10),
        _ => None,
    }
}

impl Fingerprint {
    /// `hash-func SP fingerprint` with the fingerprint as upper-case hex
    /// octets separated by colons (RFC 4572 §5, `UHEX`). `None` when
    /// malformed or the hash is not one the relay checks.
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<Self> {
        let sp = value.iter().position(|&c| c == b' ')?;
        let (name, rest) = value.split_at_checked(sp)?;
        let rest = rest.get(1..)?;
        if name.is_empty() || name.contains(&b':') {
            return None;
        }
        let hash = HashFn::parse(name)?;
        let mut digest = [0u8; MAX_DIGEST];
        let mut len = 0;
        for octet in rest.split(|&c| c == b':') {
            let &[hi, lo] = octet else { return None };
            // Two hex digits, each below 16.
            *digest.get_mut(len)? = (upper_hex(hi)? << 4) | upper_hex(lo)?;
            // At most MAX_DIGEST (`get_mut` above).
            len = len.wrapping_add(1);
        }
        // As long as the hash's digest: a short one could never match, and
        // would take a slot from a usable fingerprint.
        if len != hash.digest_len() {
            return None;
        }
        Some(Fingerprint {
            hash,
            digest,
            len: u8::try_from(len).ok()?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &[u8] {
        // `len` <= MAX_DIGEST (set by `parse` and `new`).
        self.digest.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// A fingerprint of `digest` (at most 64 octets).
    #[must_use]
    pub fn new(hash: HashFn, digest: &[u8]) -> Option<Self> {
        let mut d = [0u8; MAX_DIGEST];
        d.get_mut(..digest.len())?.copy_from_slice(digest);
        Some(Fingerprint {
            hash,
            digest: d,
            len: u8::try_from(digest.len()).ok()?,
        })
    }
}

use rtpflux_srtp::{MAX_MASTER_LEN, MasterKey, Suite};

/// The DTLS role of one end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// SRTP master keys for each direction from the material exported with
/// "EXTRACTOR-dtls_srtp" (RFC 5764 §4.2: client key, server key, client
/// salt, server salt; 2·(key + salt) octets of `suite`): `(send, receive)`
/// for an end in `role`. Each side uses its own write key to send and the
/// peer's to receive. `None` when `material` has the wrong length.
#[must_use]
pub fn split_keys(material: &[u8], suite: Suite, role: Role) -> Option<(MasterKey, MasterKey)> {
    let (k, s) = (suite.key_len(), suite.salt_len());
    let (client_key, rest) = material.split_at_checked(k)?;
    let (server_key, rest) = rest.split_at_checked(k)?;
    let (client_salt, server_salt) = rest.split_at_checked(s)?;
    // 2·(key + salt) octets, no more.
    if server_salt.len() != s {
        return None;
    }
    let half = |key: &[u8], salt: &[u8]| {
        let mut bytes = [0u8; MAX_MASTER_LEN];
        let (kb, sb) = bytes.split_at_mut_checked(key.len())?;
        kb.copy_from_slice(key);
        sb.get_mut(..salt.len())?.copy_from_slice(salt);
        MasterKey::new(suite, bytes.get(..key.len().checked_add(salt.len())?)?)
    };
    let client = half(client_key, client_salt)?;
    let server = half(server_key, server_salt)?;
    Some(match role {
        Role::Client => (client, server),
        Role::Server => (server, client),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_syntax() {
        extern crate std;
        let hex = |octets: &[u8]| -> std::string::String {
            octets
                .iter()
                .map(|o| std::format!("{o:02X}"))
                .collect::<std::vec::Vec<_>>()
                .join(":")
        };
        let mut d256 = [0x11u8; 32];
        d256[..3].copy_from_slice(&[0xAB, 0x01, 0xFF]);
        let fp = Fingerprint::parse(std::format!("sha-256 {}", hex(&d256)).as_bytes()).unwrap();
        assert_eq!((fp.hash, fp.digest()), (HashFn::Sha256, &d256[..]));
        let sha1 = std::format!("SHA-1 {}", hex(&[0; 20]));
        assert_eq!(
            Fingerprint::parse(sha1.as_bytes()).unwrap().hash,
            HashFn::Sha1
        );
        // A digest of another length than the hash's is no fingerprint.
        for bad in [
            &b"sha-256 AB:01:FF"[..],
            b"SHA-1 00",
            b"sha-256 ab:01",
            b"sha-256 AB:",
            b"sha-256 ABC",
            b"sha-256",
            b"sha-256 ",
            b"md5 AB",
            b"sha:256 AB",
        ] {
            assert_eq!(
                Fingerprint::parse(bad),
                None,
                "{}",
                core::str::from_utf8(bad).unwrap()
            );
        }
    }

    #[test]
    fn roles() {
        assert!(compatible(Setup::Actpass, Setup::Active));
        assert!(!compatible(Setup::Actpass, Setup::Actpass));
        assert_eq!(client_is_offerer(Setup::Active), Some(false));
        assert_eq!(client_is_offerer(Setup::Passive), Some(true));
    }

    #[test]
    fn names_and_edge_cases() {
        extern crate std;
        for s in [
            Setup::Active,
            Setup::Passive,
            Setup::Actpass,
            Setup::Holdconn,
        ] {
            assert_eq!(Setup::parse(s.name().as_bytes()), Some(s));
        }
        assert_eq!(Setup::parse(b"sideways"), None);
        for h in [
            HashFn::Sha1,
            HashFn::Sha224,
            HashFn::Sha256,
            HashFn::Sha384,
            HashFn::Sha512,
        ] {
            assert_eq!(HashFn::parse(h.name().to_uppercase().as_bytes()), Some(h));
        }
        assert_eq!(
            HashFn::parse(b"sha-1024-long"),
            None,
            "longer than any name"
        );
        let f = Fingerprint::new(HashFn::Sha256, &[0xab; 32]).unwrap();
        assert_eq!(f.digest(), &[0xab; 32]);
        assert_eq!(
            std::format!("{f:?}"),
            "Fingerprint(sha-256, 32 octets)",
            "the digest itself is not printed"
        );
        assert_eq!(Fingerprint::new(HashFn::Sha512, &[0; 65]), None);
        assert_eq!(
            split_keys(&[0; 59], Suite::AesCm128HmacSha1_80, Role::Client),
            None,
            "the wrong length"
        );
    }
}
