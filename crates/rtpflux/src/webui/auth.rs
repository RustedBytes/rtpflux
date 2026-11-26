//! HTTP Basic authentication: one user and a password hash, compared in
//! constant time; repeated failures from one address are refused for a
//! while.
//!
//! The hash, made by `rtpflux --webui-hash`, is
//! `pbkdf2-sha256:<iterations>:<salt>:<hex>` (PBKDF2-HMAC-SHA256, RFC
//! 8018): slow to brute-force should the configuration leak. The older
//! `sha256:<salt>:<hex of sha256(salt ‖ password)>` is still accepted. A
//! login once checked is remembered (its header's SHA-256), so the UI's
//! polling does not pay for PBKDF2 on every request.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Failures allowed per address within [`WINDOW`] before it is refused.
const MAX_FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(60);
/// Addresses the throttle tracks at most.
const MAX_TRACKED: usize = 10_000;
/// PBKDF2 iterations of a new hash.
pub const ITERATIONS: u32 = 100_000;

/// How the password is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// PBKDF2-HMAC-SHA256 with this many iterations.
    Pbkdf2(u32),
    /// sha256(salt ‖ password) (older hashes).
    Sha256,
}

/// The one login.
#[derive(Debug)]
pub struct Credentials {
    user: String,
    scheme: Scheme,
    salt: Vec<u8>,
    digest: [u8; 32],
    /// SHA-256 of the last `Authorization` value that checked out.
    verified: Mutex<Option<[u8; 32]>>,
}

/// Why `[webui] user` and `password_hash` cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsError {
    /// The hash is not of one of the two forms.
    Hash,
    /// The user is empty or has a `:`.
    User,
}

impl std::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CredentialsError::Hash => {
                "must look like pbkdf2-sha256:<iterations>:<salt>:<64 hex digits> \
                 (rtpflux --webui-hash)"
            }
            CredentialsError::User => "the user must be non-empty and contain no ':'",
        })
    }
}

impl std::error::Error for CredentialsError {}

impl Credentials {
    /// From `[webui] user` and `password_hash`.
    ///
    /// # Errors
    ///
    /// A hash not of one of the two forms, or an empty user or one with
    /// `:`.
    pub fn new(user: &str, hash: &str) -> Result<Self, CredentialsError> {
        let bad = || CredentialsError::Hash;
        let (scheme, rest) = if let Some(rest) = hash.strip_prefix("pbkdf2-sha256:") {
            let (n, rest) = rest.split_once(':').ok_or_else(bad)?;
            let n: u32 = n.parse().ok().filter(|&n| n >= 1).ok_or_else(bad)?;
            (Scheme::Pbkdf2(n), rest)
        } else if let Some(rest) = hash.strip_prefix("sha256:") {
            (Scheme::Sha256, rest)
        } else {
            return Err(bad());
        };
        let (salt, hex) = rest.split_once(':').ok_or_else(bad)?;
        let digest = from_hex(hex).ok_or_else(bad)?;
        if salt.is_empty() {
            return Err(bad());
        }
        if user.is_empty() || user.contains(':') {
            return Err(CredentialsError::User);
        }
        Ok(Credentials {
            user: user.to_owned(),
            scheme,
            salt: salt.as_bytes().to_vec(),
            digest,
            verified: Mutex::new(None),
        })
    }

    /// Whether an `Authorization` header value carries the login.
    #[must_use]
    pub fn check(&self, header: Option<&str>) -> bool {
        let Some(value) = header else {
            return false;
        };
        let seen: [u8; 32] = Sha256::digest(value.as_bytes()).into();
        let mut verified = self.verified.lock().unwrap_or_else(PoisonError::into_inner);
        if verified.is_some_and(|v| ct_eq(&v, &seen)) {
            return true;
        }
        let ok = self.check_slowly(value);
        if ok {
            *verified = Some(seen);
        }
        ok
    }

    /// [`Credentials::check`] without the remembered login.
    fn check_slowly(&self, header: &str) -> bool {
        let Some(b64) = header
            .strip_prefix("Basic ")
            .or_else(|| header.strip_prefix("basic "))
        else {
            return false;
        };
        let Some(raw) = base64_decode(b64.trim()) else {
            return false;
        };
        let Some(colon) = raw.iter().position(|&b| b == b':') else {
            return false;
        };
        let (user, pass) = (&raw[..colon], &raw[colon + 1..]);
        // Both comparisons always run: the time does not say which failed.
        let user_ok = ct_eq(user, self.user.as_bytes());
        let computed = match self.scheme {
            Scheme::Pbkdf2(n) => pbkdf2_sha256(pass, &self.salt, n),
            Scheme::Sha256 => hash_password(&self.salt, pass),
        };
        let pass_ok = ct_eq(&computed, &self.digest);
        user_ok & pass_ok
    }
}

/// sha256(salt ‖ password) (the older hash form).
#[must_use]
pub fn hash_password(salt: &[u8], password: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(password);
    h.finalize().into()
}

/// PBKDF2-HMAC-SHA256 (RFC 8018 §5.2) of one 32-octet block.
#[must_use]
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    use hmac::{KeyInit as _, Mac as _};
    type HmacSha256 = hmac::Hmac<Sha256>;
    // HMAC takes keys of any length.
    let prf = HmacSha256::new_from_slice(password).unwrap_or_else(|_| unreachable!());
    let mut u: [u8; 32] = {
        let mut m = prf.clone();
        m.update(salt);
        m.update(&1u32.to_be_bytes());
        m.finalize().into_bytes().into()
    };
    let mut out = u;
    for _ in 1..iterations {
        let mut m = prf.clone();
        m.update(&u);
        u = m.finalize().into_bytes().into();
        for (o, x) in out.iter_mut().zip(u) {
            *o ^= x;
        }
    }
    out
}

/// A `password_hash` value for `password`: PBKDF2-HMAC-SHA256 with
/// [`ITERATIONS`] and a fresh random salt.
#[must_use]
pub fn make_hash(password: &[u8]) -> String {
    let salt: [u8; 12] = rand::random();
    let salt = hex(&salt);
    format!(
        "pbkdf2-sha256:{ITERATIONS}:{salt}:{}",
        hex(&pbkdf2_sha256(password, salt.as_bytes(), ITERATIONS))
    )
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Constant-time equality (the length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nib = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(b.as_chunks::<2>().0) {
        *o = (nib(pair[0])? << 4) | nib(pair[1])?;
    }
    Some(out)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let s = s.trim_end_matches('=').as_bytes();
    if s.len() > 1024 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

/// The address a failure counts against: IPv6 by its /64, which one host
/// can rotate through (IPv4 as is).
fn client(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => IpAddr::V6(std::net::Ipv6Addr::from(
            u128::from(a) & !u128::from(u64::MAX),
        )),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Failed logins per address (IPv6: per /64): after `MAX_FAILURES`
/// within `WINDOW`, the address is refused until the window has passed.
/// At most `MAX_TRACKED` addresses are tracked (the oldest go first).
#[derive(Debug, Default)]
pub struct Throttle {
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Throttle {
    #[must_use]
    pub fn blocked(&self, ip: IpAddr) -> bool {
        let g = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        g.get(&client(ip))
            .is_some_and(|&(n, since)| n >= MAX_FAILURES && since.elapsed() < WINDOW)
    }

    pub fn failed(&self, ip: IpAddr) {
        let ip = client(ip);
        let mut g = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        if g.len() >= MAX_TRACKED && !g.contains_key(&ip) {
            g.retain(|_, (_, since)| since.elapsed() < WINDOW);
            // Still full of recent failures: the oldest goes.
            if g.len() >= MAX_TRACKED
                && let Some(oldest) = g.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k)
            {
                g.remove(&oldest);
            }
        }
        let e = g.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= WINDOW {
            *e = (0, Instant::now());
        }
        e.0 = e.0.saturating_add(1);
    }

    pub fn succeeded(&self, ip: IpAddr) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&client(ip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth() {
        let h = format!("sha256:s4lt:{}", hex(&hash_password(b"s4lt", b"secret")));
        let c = Credentials::new("admin", &h).unwrap();
        // "admin:secret", "admin:wrong", "root:secret"
        assert!(c.check(Some("Basic YWRtaW46c2VjcmV0")));
        assert!(!c.check(Some("Basic YWRtaW46d3Jvbmc=")));
        assert!(!c.check(Some("Basic cm9vdDpzZWNyZXQ=")));
        assert!(!c.check(None));
        assert!(!c.check(Some("Bearer x")));
        assert!(!c.check(Some("Basic !!!")));
        let e = |u: &str, h: &str| Credentials::new(u, h).err();
        assert_eq!(e("admin", "md5:x:y"), Some(CredentialsError::Hash));
        assert_eq!(e("admin", "sha256::00"), Some(CredentialsError::Hash));
        assert_eq!(
            e("admin", "pbkdf2-sha256:0:s:00"),
            Some(CredentialsError::Hash)
        );
        assert_eq!(e("a:b", &h), Some(CredentialsError::User));
        assert_eq!(e("", &h), Some(CredentialsError::User));
    }

    #[test]
    fn made_hashes_check_and_are_remembered() {
        let h = make_hash(b"pa ss");
        assert!(h.starts_with(&format!("pbkdf2-sha256:{ITERATIONS}:")));
        assert_ne!(h, make_hash(b"pa ss"), "salted");
        let c = Credentials::new("admin", &h).unwrap();
        // "admin:pa ss", twice: the second is remembered (much faster).
        let t = Instant::now();
        assert!(c.check(Some("Basic YWRtaW46cGEgc3M=")));
        let first = t.elapsed();
        let t = Instant::now();
        assert!(c.check(Some("Basic YWRtaW46cGEgc3M=")));
        assert!(t.elapsed() < first, "{:?} then {:?}", first, t.elapsed());
        // A wrong login is not let in by the remembered one.
        assert!(!c.check(Some("Basic YWRtaW46d3Jvbmc=")));
    }

    #[test]
    fn pbkdf2_matches_rfc_7914() {
        // RFC 7914 §11: PBKDF2-HMAC-SHA256 (P="passwd", S="salt", c=1).
        assert_eq!(
            hex(&pbkdf2_sha256(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        // RFC 7914 §11 (P="Password", S="NaCl", c=80000), first 32 octets.
        assert_eq!(
            hex(&pbkdf2_sha256(b"Password", b"NaCl", 80_000)),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
    }

    #[test]
    fn base64() {
        assert_eq!(base64_decode("YWRtaW46c2VjcmV0").unwrap(), b"admin:secret");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert!(base64_decode("YWJjZ").is_none());
    }

    #[test]
    fn throttle() {
        let t = Throttle::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(!t.blocked(ip));
            t.failed(ip);
        }
        assert!(t.blocked(ip));
        t.succeeded(ip);
        assert!(!t.blocked(ip));
    }

    #[test]
    fn throttling_groups_ipv6_by_64_and_stays_bounded() {
        let t = Throttle::default();
        for i in 0..MAX_FAILURES {
            t.failed(format!("2001:db8::{}", i + 1).parse().unwrap());
        }
        assert!(
            t.blocked("2001:db8::ffff".parse().unwrap()),
            "the whole /64"
        );
        assert!(!t.blocked("2001:db8:0:1::1".parse().unwrap()));
        for i in 0..u32::try_from(MAX_TRACKED).unwrap() + 5 {
            t.failed(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)));
        }
        assert!(t.failures.lock().unwrap().len() <= MAX_TRACKED);
    }
}
