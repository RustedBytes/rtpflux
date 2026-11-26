//! DTLS-SRTP (RFC 5763, RFC 5764): the DTLS 1.2 handshake on a media port,
//! run by `dimpl` (a Sans-IO DTLS implementation over `RustCrypto`), keys
//! SRTP; media is then protected by `rtpflux-srtp` like SDES media.
//!
//! The relay has one self-signed ECDSA P-256 certificate ([`Identity`]),
//! whose SHA-256 fingerprint it puts into its SDP. The peer's certificate is
//! accepted when its fingerprint matches one the peer signalled (RFC 4572
//! §6.2, RFC 5763 §5); no PKI validation applies. After the handshake, the
//! keying material exported with "EXTRACTOR-dtls_srtp" gives each
//! direction's master keys and salts ([`rtpflux_core::dtls::split_keys`]).
//!
//! The handshake allocates (the engine's flights and queues); it runs once
//! per media component, not per packet.

use rtpflux_core::dtls::{Fingerprint, HashFn, Role, split_keys};
use rtpflux_core::sdp::{MasterKey, Suite};
use sha2::Digest as _;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The largest DTLS datagram the relay sends.
const MTU: usize = 1200;
/// The largest DTLS datagram accepted from a peer (real ones stay near the
/// MTU); larger ones are ignored.
const MAX_DATAGRAM: usize = 2048;
/// Datagrams the engine keeps while it reassembles a handshake message.
const MAX_QUEUE_RX: usize = 16;
/// The engine's output buffer: room for the largest peer certificate it
/// can reassemble from the queued datagrams. (dimpl asserts, so panics,
/// when a certificate does not fit, instead of asking for more room.)
const OUT_BUF: usize = MAX_QUEUE_RX * MAX_DATAGRAM + 1024;
/// Fingerprints kept per peer.
pub const MAX_FINGERPRINTS: usize = 2;
/// How long the relay's certificate is valid, and how far back from its
/// creation it starts: a relay runs for months on one certificate (made at
/// start), and peers' clocks may lag. Peers pin it by fingerprint
/// (RFC 5763); validity only matters to stacks that check it anyway.
const VALIDITY: Duration = Duration::from_hours(400 * 24);
const BACKDATE: Duration = Duration::from_hours(24);

/// Why the relay's DTLS identity or an association could not be made.
#[derive(Debug)]
pub struct DtlsError(String);

impl std::fmt::Display for DtlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DtlsError {}

#[allow(clippy::needless_pass_by_value)]
fn dtls_error(e: impl std::fmt::Display) -> DtlsError {
    DtlsError(e.to_string())
}

/// The relay's certificate and the DTLS configuration built on it.
#[derive(Clone)]
pub struct Identity {
    config: Arc<dimpl::Config>,
    certificate: dimpl::DtlsCertificate,
    fingerprint: String,
    /// The fingerprint under each hash (`DTLS-fingerprint`).
    fingerprints: [String; 5],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.fingerprint)
    }
}

/// `sha-256 XX:XX:…` of DER octets.
fn fingerprint_text(der: &[u8]) -> String {
    fingerprint_with(der, HashFn::Sha256)
}

/// The `a=fingerprint` value of a certificate (DER) under `hash`.
fn fingerprint_with(der: &[u8], hash: HashFn) -> String {
    let digest: Vec<u8> = match hash {
        HashFn::Sha1 => sha1::Sha1::digest(der).to_vec(),
        HashFn::Sha224 => sha2::Sha224::digest(der).to_vec(),
        HashFn::Sha256 => sha2::Sha256::digest(der).to_vec(),
        HashFn::Sha384 => sha2::Sha384::digest(der).to_vec(),
        HashFn::Sha512 => sha2::Sha512::digest(der).to_vec(),
    };
    let mut s = format!("{} ", hash.name());
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// A self-signed end-entity certificate with no extensions, as WebRTC
/// endpoints use: only its key and fingerprint matter.
struct SelfSigned(x509_cert::name::Name);

impl x509_cert::builder::profile::BuilderProfile for SelfSigned {
    fn get_issuer(&self, subject: &x509_cert::name::Name) -> x509_cert::name::Name {
        subject.clone()
    }

    fn get_subject(&self) -> x509_cert::name::Name {
        self.0.clone()
    }

    fn build_extensions(
        &self,
        _spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
        Ok(Vec::new())
    }
}

/// A self-signed certificate (DER) for a fresh P-256 key, and the key
/// (PKCS #8 DER). The serial number is random: Firefox rejects a repeated
/// issuer and serial.
fn self_signed() -> Result<(Vec<u8>, Vec<u8>), DtlsError> {
    self_signed_as("rtpflux")
}

/// [`self_signed`], with this common name.
fn self_signed_as(common_name: &str) -> Result<(Vec<u8>, Vec<u8>), DtlsError> {
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::EncodePrivateKey as _;
    use std::str::FromStr as _;
    use x509_cert::builder::{Builder as _, CertificateBuilder};
    use x509_cert::der::Encode as _;

    let mut rng = rand::rng();
    let key = SigningKey::generate_from_rng(&mut rng);
    let mut serial: [u8; 16] = rand::random();
    serial[0] &= 0x7f; // a positive INTEGER
    let name = x509_cert::name::Name::from_str(&format!("CN={common_name}")).map_err(dtls_error)?;
    let builder = CertificateBuilder::new(
        SelfSigned(name),
        x509_cert::serial_number::SerialNumber::new(&serial).map_err(dtls_error)?,
        {
            let now = std::time::SystemTime::now();
            x509_cert::time::Validity::new(
                x509_cert::time::Time::try_from(now - BACKDATE).map_err(dtls_error)?,
                x509_cert::time::Time::try_from(now + VALIDITY).map_err(dtls_error)?,
            )
        },
        x509_cert::spki::SubjectPublicKeyInfo::from_key(key.verifying_key()).map_err(dtls_error)?,
    )
    .map_err(dtls_error)?;
    let cert = builder.build::<_, DerSignature>(&key).map_err(dtls_error)?;
    let key_der = key.to_pkcs8_der().map_err(dtls_error)?;
    Ok((
        cert.to_der().map_err(dtls_error)?,
        key_der.as_bytes().to_vec(),
    ))
}

impl Identity {
    /// A fresh self-signed ECDSA P-256 certificate (30 days) and a DTLS
    /// configuration requiring the peer's certificate. The SRTP profiles
    /// offered are the AES-GCM ones, then `SRTP_AES128_CM_SHA1_80`
    /// (RFC 5764 §4.1.2, RFC 7714 §14.2).
    ///
    /// # Errors
    ///
    /// When the certificate or the configuration cannot be made.
    pub fn generate() -> Result<Self, DtlsError> {
        Self::with_certificate(self_signed()?)
    }

    fn with_certificate((certificate, private_key): (Vec<u8>, Vec<u8>)) -> Result<Self, DtlsError> {
        let config = dimpl::Config::builder()
            .mtu(MTU)
            .max_queue_rx(MAX_QUEUE_RX)
            .require_client_certificate(true)
            .build()
            .map_err(dtls_error)?;
        Ok(Identity {
            fingerprint: fingerprint_text(&certificate),
            fingerprints: HASHES.map(|h| fingerprint_with(&certificate, h)),
            config: Arc::new(config),
            certificate: dimpl::DtlsCertificate {
                certificate,
                private_key,
            },
        })
    }

    /// The `a=fingerprint` value of the relay's certificate.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The same under `hash`.
    #[must_use]
    pub fn fingerprint_with(&self, hash: HashFn) -> &str {
        let i = HASHES.iter().position(|&h| h == hash).unwrap_or(2);
        &self.fingerprints[i]
    }
}

/// The hashes a fingerprint can be written with.
const HASHES: [HashFn; 5] = [
    HashFn::Sha1,
    HashFn::Sha224,
    HashFn::Sha256,
    HashFn::Sha384,
    HashFn::Sha512,
];

/// Whether the certificate (DER) matches one of the signalled fingerprints
/// of the strongest hash among them (RFC 8122 §5: the set of the most
/// preferred hash function; a weaker one, such as SHA-1, signalled too
/// does not count). Hashes are ordered by digest length.
#[must_use]
pub fn matches(fingerprints: &[Fingerprint], cert_der: &[u8]) -> bool {
    let Some(best) = fingerprints.iter().map(|f| f.hash.digest_len()).max() else {
        return false;
    };
    let mut strongest = fingerprints.iter().filter(|f| f.hash.digest_len() == best);
    strongest.any(|f| {
        let digest = f.digest();
        match f.hash {
            HashFn::Sha1 => sha1::Sha1::digest(cert_der)[..] == *digest,
            HashFn::Sha224 => sha2::Sha224::digest(cert_der)[..] == *digest,
            HashFn::Sha256 => sha2::Sha256::digest(cert_der)[..] == *digest,
            HashFn::Sha384 => sha2::Sha384::digest(cert_der)[..] == *digest,
            HashFn::Sha512 => sha2::Sha512::digest(cert_der)[..] == *digest,
        }
    })
}

/// RFC 5705 with the TLS 1.2 PRF (RFC 5246 §5, `P_SHA256`), no context:
/// `out.len()` octets of keying material, as RFC 5764 §4.2 exports
/// 2·(key + salt) of them. The DTLS engine computes the same internally;
/// this one is checked against the reference model.
pub fn exporter(master: &[u8], client_random: &[u8], server_random: &[u8], out: &mut [u8]) {
    use hmac::{KeyInit as _, Mac as _};
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mac = |parts: &[&[u8]]| {
        // HMAC takes keys of any length.
        let mut m = HmacSha256::new_from_slice(master).unwrap_or_else(|_| unreachable!());
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes()
    };
    let seed: &[&[u8]] = &[b"EXTRACTOR-dtls_srtp", client_random, server_random];
    let mut a = mac(seed);
    let mut filled = 0;
    while filled < out.len() {
        let mut parts: Vec<&[u8]> = vec![&a];
        parts.extend_from_slice(seed);
        let block = mac(&parts);
        let n = block.len().min(out.len() - filled);
        out[filled..filled + n].copy_from_slice(&block[..n]);
        filled += n;
        a = mac(&[&a]);
    }
}

/// The outcome of feeding an association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// Still handshaking (or established and waiting for the peer's
    /// fingerprint from its SDP).
    Pending,
    /// Keys for SRTP: what the peer sends is decrypted with `inbound`, what
    /// the relay sends to it is encrypted with `outbound`. Reported once.
    Keyed {
        inbound: MasterKey,
        outbound: MasterKey,
    },
    /// The handshake failed or the certificate did not match.
    Failed,
}

/// One DTLS association (one media component of one side).
pub struct Association {
    role: Role,
    dtls: dimpl::Dtls,
    outbox: Vec<Vec<u8>>,
    /// The engine's output buffer ([`OUT_BUF`]), allocated once; the
    /// keying material passes through it, so it is wiped when dropped.
    out: zeroize::Zeroizing<Vec<u8>>,
    /// When the engine wants [`dimpl::Dtls::handle_timeout`] next.
    timer: Option<Instant>,
    established: bool,
    failed: bool,
    keyed: bool,
    peer_cert: Option<Vec<u8>>,
    /// The exported keying material and its suite, until keyed.
    material: Option<(zeroize::Zeroizing<Vec<u8>>, Suite)>,
    remote: [Option<Fingerprint>; MAX_FINGERPRINTS],
}

impl std::fmt::Debug for Association {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Association({:?}, established {}, failed {}, keyed {})",
            self.role, self.established, self.failed, self.keyed
        )
    }
}

/// The SRTP suite of a negotiated DTLS-SRTP profile.
fn suite_of(profile: dimpl::SrtpProfile) -> Option<Suite> {
    match profile {
        dimpl::SrtpProfile::AES128_CM_SHA1_80 => Some(Suite::AesCm128HmacSha1_80),
        dimpl::SrtpProfile::AEAD_AES_128_GCM => Some(Suite::AeadAes128Gcm),
        dimpl::SrtpProfile::AEAD_AES_256_GCM => Some(Suite::AeadAes256Gcm),
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

impl Association {
    /// Start an association in `role`; a client's first flight (the
    /// `ClientHello`) is ready in [`Association::take_output`] right away.
    ///
    /// # Errors
    ///
    /// When the engine cannot start the handshake.
    pub fn new(
        identity: &Identity,
        role: Role,
        remote: [Option<Fingerprint>; MAX_FINGERPRINTS],
    ) -> Result<Self, DtlsError> {
        let now = Instant::now();
        let mut dtls = dimpl::Dtls::new_12(
            Arc::clone(&identity.config),
            identity.certificate.clone(),
            now,
        );
        if role == Role::Client {
            dtls.set_active(true);
        }
        let mut a = Association {
            role,
            dtls,
            outbox: Vec::new(),
            out: zeroize::Zeroizing::new(vec![0; OUT_BUF]),
            timer: None,
            established: false,
            failed: false,
            keyed: false,
            peer_cert: None,
            material: None,
            remote,
        };
        // The engine starts when first driven: a client sends its
        // ClientHello, a server sets up its random.
        a.dtls.handle_timeout(now).map_err(dtls_error)?;
        a.drain();
        Ok(a)
    }

    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    #[must_use]
    pub fn remote(&self) -> &[Option<Fingerprint>; MAX_FINGERPRINTS] {
        &self.remote
    }

    /// Whether SRTP keys were handed out.
    #[must_use]
    pub fn keyed(&self) -> bool {
        self.keyed
    }

    /// Whether the handshake failed (or the engine gave up).
    #[must_use]
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Whether the handshake is still running.
    #[must_use]
    pub fn handshaking(&self) -> bool {
        !self.established && !self.failed
    }

    /// Collect what the engine produced, up to its next timer.
    fn drain(&mut self) {
        let buf = &mut self.out;
        loop {
            match self.dtls.poll_output(buf) {
                dimpl::Output::Packet(p) => self.outbox.push(p.to_vec()),
                dimpl::Output::BufferTooSmall { needed } => buf.resize(needed, 0),
                dimpl::Output::Timeout(t) => {
                    self.timer = Some(t);
                    break;
                }
                dimpl::Output::Connected => self.established = true,
                dimpl::Output::PeerCert(der) => self.peer_cert = Some(der.to_vec()),
                dimpl::Output::KeyingMaterial(km, profile) => {
                    if let Some(suite) = suite_of(profile) {
                        self.material = Some((zeroize::Zeroizing::new(km.to_vec()), suite));
                    }
                }
                dimpl::Output::CloseNotify => {
                    log::debug!("dtls: the peer closed the association");
                    break;
                }
                _ => {}
            }
        }
    }

    /// Run the engine's retransmission timer if it is due.
    fn tick(&mut self, now: Instant) {
        if self.failed || self.timer.is_none_or(|t| t > now) {
            return;
        }
        if let Err(e) = self.dtls.handle_timeout(now) {
            log::debug!("dtls: handshake failed: {e}");
            self.failed = true;
            return;
        }
        self.drain();
    }

    /// Feed one received DTLS datagram.
    pub fn receive(&mut self, datagram: &[u8]) -> Progress {
        if datagram.len() > MAX_DATAGRAM {
            log::debug!("dtls: a {}-octet datagram ignored", datagram.len());
            return self.progress();
        }
        if !self.failed {
            match self.dtls.handle_packet(datagram) {
                Ok(()) => self.drain(),
                Err(e) => {
                    log::debug!("dtls: handshake failed: {e}");
                    self.failed = true;
                }
            }
        }
        self.progress()
    }

    /// The peer's fingerprints arrived (an SDP answer after the handshake).
    pub fn set_remote(&mut self, remote: [Option<Fingerprint>; MAX_FINGERPRINTS]) -> Progress {
        self.remote = remote;
        self.progress()
    }

    /// Datagrams to send to the peer, including retransmissions that are
    /// due by now.
    pub fn take_output(&mut self) -> Vec<Vec<u8>> {
        self.tick(Instant::now());
        std::mem::take(&mut self.outbox)
    }

    fn fail(&mut self) -> Progress {
        self.failed = true;
        Progress::Failed
    }

    fn progress(&mut self) -> Progress {
        if self.failed {
            return Progress::Failed;
        }
        if !self.established || self.keyed {
            return Progress::Pending;
        }
        let remote: Vec<Fingerprint> = self.remote.iter().flatten().copied().collect();
        if remote.is_empty() {
            return Progress::Pending;
        }
        if !self
            .peer_cert
            .as_deref()
            .is_some_and(|der| matches(&remote, der))
        {
            log::info!("dtls: the peer's certificate does not match its fingerprint");
            return self.fail();
        }
        let Some((material, suite)) = self.material.take() else {
            log::info!("dtls: no SRTP profile negotiated");
            return self.fail();
        };
        let Some((outbound, inbound)) = split_keys(&material, suite, self.role) else {
            return self.fail();
        };
        self.keyed = true;
        log::debug!("dtls: keyed with {}", suite.name());
        Progress::Keyed { inbound, outbound }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp_of(identity: &Identity) -> [Option<Fingerprint>; MAX_FINGERPRINTS] {
        [Fingerprint::parse(identity.fingerprint().as_bytes()), None]
    }

    /// Two associations talking to each other in memory.
    fn handshake(a: &mut Association, b: &mut Association) -> (Progress, Progress) {
        let (mut pa, mut pb) = (Progress::Pending, Progress::Pending);
        for _ in 0..20 {
            for d in a.take_output() {
                let p = b.receive(&d);
                if p != Progress::Pending {
                    pb = p;
                }
            }
            for d in b.take_output() {
                let p = a.receive(&d);
                if p != Progress::Pending {
                    pa = p;
                }
            }
        }
        (pa, pb)
    }

    #[test]
    fn only_the_strongest_hash_counts() {
        use sha2::Digest as _;
        let der = [7u8; 300];
        let fp = |name: &str, digest: &[u8]| {
            let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
            Fingerprint::parse(format!("{name} {}", hex.join(":")).as_bytes()).unwrap()
        };
        let sha1 = fp("sha-1", &sha1::Sha1::digest(der));
        let sha256 = fp("sha-256", &sha2::Sha256::digest(der));
        let mut wrong = sha2::Sha256::digest(der);
        wrong[0] ^= 1;
        let wrong256 = fp("sha-256", &wrong);
        assert!(matches(&[sha1], &der));
        assert!(matches(&[sha1, sha256], &der));
        // A matching SHA-1 beside a wrong SHA-256: the SHA-256 one decides.
        assert!(!matches(&[sha1, wrong256], &der));
        assert!(matches(&[wrong256, sha256], &der));
        assert!(!matches(&[], &der));
    }

    #[test]
    fn handshake_keys_both_directions() {
        let (ca, cb) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let mut client = Association::new(&ca, Role::Client, fp_of(&cb)).unwrap();
        let mut server = Association::new(&cb, Role::Server, fp_of(&ca)).unwrap();
        let (pc, ps) = handshake(&mut client, &mut server);
        let (
            Progress::Keyed {
                inbound: ci,
                outbound: co,
            },
            Progress::Keyed {
                inbound: si,
                outbound: so,
            },
        ) = (pc, ps)
        else {
            panic!("not keyed: {pc:?} {ps:?}");
        };
        assert_eq!(co, si, "what the client sends, the server receives");
        assert_eq!(so, ci);
        assert_ne!(co, so);
        assert_eq!(co.suite, Suite::AeadAes256Gcm, "GCM is preferred");
    }

    #[test]
    fn the_certificate_is_self_signed_p256_with_a_random_serial() {
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        assert!(a.fingerprint().starts_with("sha-256 "));
        assert_ne!(a.fingerprint(), b.fingerprint());
        let fps: Vec<Fingerprint> = fp_of(&a).into_iter().flatten().collect();
        assert!(matches(&fps, &a.certificate.certificate));
        assert!(!matches(&fps, &b.certificate.certificate));
    }

    #[test]
    fn a_wrong_fingerprint_fails_and_a_late_one_keys() {
        let (ca, cb, other) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let mut client = Association::new(&ca, Role::Client, fp_of(&cb)).unwrap();
        let mut server = Association::new(&cb, Role::Server, fp_of(&other)).unwrap();
        let (_, ps) = handshake(&mut client, &mut server);
        assert_eq!(ps, Progress::Failed);
        // The server learns the client's fingerprint only after the handshake.
        let mut client = Association::new(&ca, Role::Client, fp_of(&cb)).unwrap();
        let mut server = Association::new(&cb, Role::Server, [None, None]).unwrap();
        let (pc, ps) = handshake(&mut client, &mut server);
        assert!(matches!(pc, Progress::Keyed { .. }));
        assert_eq!(ps, Progress::Pending);
        assert!(matches!(
            server.set_remote(fp_of(&ca)),
            Progress::Keyed { .. }
        ));
    }

    /// A peer certificate of several kilobytes keys normally; one larger
    /// than the engine can reassemble fails the handshake. Neither panics
    /// (dimpl asserts that its output buffer holds the peer's certificate).
    #[test]
    fn large_peer_certificates_never_panic() {
        let server_id = Identity::generate().unwrap();
        for (cn_len, keys) in [(4000, true), (40_000, false)] {
            let big =
                Identity::with_certificate(self_signed_as(&"A".repeat(cn_len)).unwrap()).unwrap();
            assert!(big.certificate.certificate.len() > cn_len);
            let mut client = Association::new(&big, Role::Client, fp_of(&server_id)).unwrap();
            let mut server = Association::new(&server_id, Role::Server, fp_of(&big)).unwrap();
            let (_, ps) = handshake(&mut client, &mut server);
            assert_eq!(
                matches!(ps, Progress::Keyed { .. }),
                keys,
                "a {}-octet certificate: {ps:?}",
                big.certificate.certificate.len()
            );
        }
    }

    /// The CPU cost of one handshake on each side (run with `--ignored
    /// --nocapture` in release mode).
    #[test]
    #[ignore = "measurement, not a check"]
    fn handshake_cost() {
        let (ca, cb) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let n = 200;
        let start = std::time::Instant::now();
        for _ in 0..n {
            let mut client = Association::new(&ca, Role::Client, fp_of(&cb)).unwrap();
            let mut server = Association::new(&cb, Role::Server, fp_of(&ca)).unwrap();
            let (pc, ps) = handshake(&mut client, &mut server);
            assert!(matches!(
                (pc, ps),
                (Progress::Keyed { .. }, Progress::Keyed { .. })
            ));
        }
        let per = start.elapsed() / n;
        println!(
            "DTLS-SRTP handshake, client and server together: {per:?} per handshake ({:.0}/s on one core)",
            1.0 / per.as_secs_f64()
        );
    }

    #[test]
    fn errors_name_dtls() {
        let e = crate::relay::RelayError::Dtls(DtlsError("no certificate".to_owned()));
        assert_eq!(e.to_string(), "DTLS: no certificate");
    }
}
