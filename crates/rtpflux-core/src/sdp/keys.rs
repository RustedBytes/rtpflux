//! SDES keys (RFC 4568): reading `a=crypto` lines and writing the relay's
//! own key in base64.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) const B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The value of a standard base64 character (RFC 4648 §4).
pub(super) fn b64_value(c: u8) -> Option<u32> {
    B64.iter()
        .position(|&b| b == c)
        .and_then(|v| u32::try_from(v).ok())
}

/// Canonical base64 (RFC 4648 §4) into `out`; `None` unless it decodes to
/// exactly `out.len()` octets with exactly the padding that length needs
/// and zero unused bits (§3.5).
pub(super) fn b64_decode(text: &[u8], out: &mut [u8]) -> Option<()> {
    let pad = text.iter().rev().take_while(|&&c| c == b'=').count();
    let body = text.get(..text.len().saturating_sub(pad))?;
    if body.len() % 4 == 1 {
        return None;
    }
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for &c in body {
        acc = ((acc << 6) | b64_value(c)?) & 0x00ff_ffff;
        // `bits` stays below 14.
        bits = bits.wrapping_add(6);
        if let Some(left) = bits.checked_sub(8) {
            bits = left;
            *out.get_mut(n)? = u8::try_from((acc >> bits) & 0xff).ok()?;
            // At most `out.len()` (`get_mut` above).
            n = n.wrapping_add(1);
        }
    }
    let canonical = acc & 1u32.wrapping_shl(bits).wrapping_sub(1) == 0;
    // The padding a length needs: none, or what completes the last group.
    let needed = match n % 3 {
        0 => 0,
        r => 3usize.wrapping_sub(r),
    };
    (n == out.len() && canonical && pad == needed).then_some(())
}

/// RFC 4568 §6.1 `lifetime` (`2^n` or a decimal number of packets), within
/// the suites' maximum of 2^48 packets (§6.2.1).
pub(super) fn lifetime_ok(text: &[u8]) -> bool {
    match text.strip_prefix(b"2^") {
        Some(n) => decimal(n, 49).is_some(),
        None => decimal(text, (1 << 48) + 1).is_some(),
    }
}

/// Base64 (RFC 4648 §4, with padding) of a master key and salt; returns
/// the buffer and the length used.
pub(super) fn b64_key(key: &[u8]) -> ([u8; 64], usize) {
    let mut out = [0u8; 64];
    let mut n = 0usize;
    // Three octets make four characters (a master key and salt is at most
    // 46 octets: 64 characters hold it).
    for (dst, chunk) in out.as_chunks_mut::<4>().0.iter_mut().zip(key.chunks(3)) {
        let mut group = [0u8; 3];
        for (g, b) in group.iter_mut().zip(chunk) {
            *g = *b;
        }
        let v = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        for (k, (o, shift)) in dst.iter_mut().zip([18, 12, 6, 0]).enumerate() {
            let sextet = usize::try_from((v >> shift) & 0x3f).unwrap_or(0);
            *o = if k <= chunk.len() {
                B64.get(sextet).copied().unwrap_or(b'=')
            } else {
                b'='
            };
        }
        n = n.wrapping_add(4);
    }
    (out, n)
}

/// `<tag> <suite> inline:<key||salt>[|<lifetime>]` (RFC 4568 §9.1, fields
/// separated by single spaces), or `None` when the relay cannot use it:
/// malformed, an unsupported suite, a key that is not the suite's master
/// key and salt in canonical base64, a lifetime above 2^48, an MKI, several keys, or
/// session parameters.
/// An `a=crypto` line as [`parse_crypto`] reads it, except that it may
/// also carry the session parameters that switch protection off
/// (`UNENCRYPTED_SRTP`, `UNENCRYPTED_SRTCP`, `UNAUTHENTICATED_SRTP`): the
/// key then has that [`Policy`](rtpflux_srtp::Policy). Any other session
/// parameter, or one of these with an AEAD suite, makes it unusable.
pub(super) fn parse_crypto_declared(value: &[u8]) -> Option<Crypto> {
    // The end of the third field (and the space after it).
    let mut end = 0usize;
    for _ in 0..3 {
        let rest = value.get(end..)?;
        let next = match rest.iter().position(|&b| b == b' ') {
            Some(p) => end.checked_add(p)?,
            None => value.len(),
        };
        end = next.checked_add(1)?;
    }
    let base = value.get(..end.checked_sub(1)?)?;
    let c = parse_crypto(base)?;
    let mut policy = rtpflux_srtp::Policy::NONE;
    for p in value.get(end..).unwrap_or_default().split(|&b| b == b' ') {
        if !p.is_empty() {
            policy = policy.with_param(p)?;
        }
    }
    Some(Crypto {
        key: c.key.with_policy(policy)?,
        ..c
    })
}

pub(super) fn parse_crypto(value: &[u8]) -> Option<Crypto> {
    let mut f = value.split(|&b| b == b' ');
    let tag = u32::try_from(decimal(f.next()?, 1_000_000_000)?).ok()?;
    let suite = Suite::from_name(f.next()?)?;
    let params = f.next()?;
    if f.next().is_some() || params.contains(&b';') {
        return None;
    }
    let mut parts = params.strip_prefix(b"inline:")?.split(|&b| b == b'|');
    let encoded = parts.next()?;
    match (parts.next(), parts.next()) {
        (None, _) => {}
        (Some(lifetime), None) if !lifetime.contains(&b':') && lifetime_ok(lifetime) => {}
        _ => return None, // MKI, or a malformed lifetime
    }
    Some(Crypto {
        tag,
        key: decode_key(suite, encoded)?,
    })
}

/// A master key and salt of `suite` from base64 (as `inline:` writes
/// it), if exactly its length.
#[must_use]
pub fn decode_key(suite: Suite, text: &[u8]) -> Option<MasterKey> {
    let mut key = [0u8; rtpflux_srtp::MAX_MASTER_LEN];
    let key = key.get_mut(..suite.master_len())?;
    b64_decode(text, key)?;
    MasterKey::new(suite, key)
}
