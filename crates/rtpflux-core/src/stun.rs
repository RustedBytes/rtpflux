//! STUN (RFC 8489) for ICE (RFC 8445): checking and answering connectivity
//! checks, sending them and reading their responses, plain Binding for
//! learning a server-reflexive address, and the demultiplexing of one media
//! port (RFC 5764 §5.1.2).
//!
//! An agent answers Binding requests that carry its username fragment and
//! are protected with its password (short-term credentials, §9.1). In
//! order ([`check_request`], [`ice_lite`]):
//!
//! 1. A datagram whose FINGERPRINT (§14.7) does not verify is not STUN:
//!    ignored. Only well-formed Binding requests are answered.
//! 2. §9.1.3: no MESSAGE-INTEGRITY or no USERNAME ⇒ 400; a USERNAME not
//!    starting with `<ufrag>:` or a wrong MESSAGE-INTEGRITY ⇒ 401. These
//!    errors are not authenticated (FINGERPRINT only).
//! 3. §6.3.1: an unknown comprehension-required attribute ⇒ 420 with
//!    UNKNOWN-ATTRIBUTES.
//! 4. Otherwise a success response with XOR-MAPPED-ADDRESS (§14.2).
//!
//! Responses to authenticated requests carry MESSAGE-INTEGRITY and
//! FINGERPRINT. A full agent also resolves role conflicts (RFC 8445
//! §7.3.1.1: [`on_role_request`], a 487 with [`write_role_conflict`]).
//!
//! As a client ([`write_check`], [`read_response`]): a check carries
//! USERNAME, PRIORITY, ICE-CONTROLLING or ICE-CONTROLLED with the
//! tie-breaker, USE-CANDIDATE when nominating, MESSAGE-INTEGRITY with the
//! peer's password and FINGERPRINT, in that order; a response counts only
//! when its MESSAGE-INTEGRITY verifies (RFC 8489 §9.1.4: otherwise it is
//! discarded as if never received).
//!
//! Everything is written into the caller's buffer; nothing is allocated.

use core::net::{IpAddr, SocketAddr};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

/// The STUN magic cookie (§5).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER: usize = 20;
const BINDING: u16 = 0x0001;
const USERNAME: u16 = 0x0006;
const MESSAGE_INTEGRITY: u16 = 0x0008;
const ERROR_CODE: u16 = 0x0009;
const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const PRIORITY: u16 = 0x0024;
const USE_CANDIDATE: u16 = 0x0025;
const MAPPED_ADDRESS: u16 = 0x0001;
const ICE_CONTROLLED: u16 = 0x8029;
const ICE_CONTROLLING: u16 = 0x802A;
/// Role Conflict (RFC 8445 §7.3.1.1).
pub const ROLE_CONFLICT: u16 = 487;
const FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR: u32 = 0x5354_554e;
/// Most distinct unknown attributes reported in one 420.
const MAX_UNKNOWN: usize = 16;

/// What the first octet of a datagram on a media port says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Stun,
    Dtls,
    /// RTP or RTCP.
    Rtp,
    /// ZRTP (RFC 6189): the endpoints' own key agreement, which a relay
    /// passes through untouched where it does not transform the media.
    Zrtp,
    Drop,
}

/// RFC 7983 §7 (updating RFC 5764 §5.1.2): `127 < B < 192` RTP/RTCP,
/// `19 < B < 64` DTLS, `15 < B < 20` ZRTP, `B < 4` STUN; anything else,
/// TURN channel data (`63 < B < 80`, which a relay without TURN never
/// expects) included, is dropped.
#[must_use]
pub const fn classify(first: u8) -> Kind {
    match first {
        128..=191 => Kind::Rtp,
        20..=63 => Kind::Dtls,
        16..=19 => Kind::Zrtp,
        0..=3 => Kind::Stun,
        _ => Kind::Drop,
    }
}

/// RFC 5761 §4: with `rtcp-mux`, an RTP-port packet whose second octet
/// (RTCP packet type, or RTP marker + payload type) is 192–223 is RTCP.
#[must_use]
pub fn is_muxed_rtcp(packet: &[u8]) -> bool {
    packet.get(1).is_some_and(|&pt| (192..=223).contains(&pt))
}

/// The relay's ICE credentials for one side (`a=ice-ufrag`, `a=ice-pwd`).
#[derive(Debug, Clone, Copy)]
pub struct Credentials<'a> {
    pub ufrag: &'a [u8],
    pub pwd: &'a [u8],
}

/// What to do with a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Not a STUN request for us: nothing to send.
    Ignore,
    /// Send `out[..len]` back to the source.
    Reply {
        len: usize,
        /// An authenticated, successful check: the source is a valid
        /// address of the peer.
        checked: bool,
        /// The check carried USE-CANDIDATE (the controlling peer nominates
        /// this pair).
        nominated: bool,
    },
}

// Evaluated at compile time: an out-of-range index or an overflow would be
// a build error, never a panic at run time.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        #[allow(clippy::cast_possible_truncation)]
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC_TABLE: [u32; 256] = crc_table();

/// CRC-32 (ISO 3309 / ITU-T V.42, as FINGERPRINT uses it).
fn crc32(parts: &[&[u8]]) -> u32 {
    let mut c = !0u32;
    for p in parts {
        for &b in *p {
            // An index below 256: the lookup always succeeds.
            #[allow(clippy::cast_possible_truncation)]
            let i = usize::from((c as u8) ^ b);
            c = CRC_TABLE.get(i).copied().unwrap_or(0) ^ (c >> 8);
        }
    }
    !c
}

/// The `N` octets at `b[at..]` (`None` past the end).
fn chunk<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..)?.first_chunk::<N>().copied()
}

fn rd16(b: &[u8], at: usize) -> Option<u16> {
    chunk(b, at).map(u16::from_be_bytes)
}

/// Padding to a multiple of four: (4 − n mod 4) mod 4.
fn pad(n: usize) -> usize {
    n.wrapping_neg() & 3
}

/// The header fields of a message: its type, its length (the datagram's
/// less the header), whether the first two bits are zero and the magic
/// cookie is there, and the transaction id.
fn header(msg: &[u8]) -> Option<Header> {
    let h = msg.first_chunk::<HEADER>()?;
    let mut tid = [0u8; 12];
    tid.copy_from_slice(&h[8..20]);
    Some(Header {
        kind: u16::from_be_bytes([h[0], h[1]]),
        length_ok: usize::from(u16::from_be_bytes([h[2], h[3]])) == msg.len().wrapping_sub(HEADER),
        stun: h[0] & 0xC0 == 0 && u32::from_be_bytes([h[4], h[5], h[6], h[7]]) == MAGIC_COOKIE,
        tid,
    })
}

struct Header {
    kind: u16,
    length_ok: bool,
    stun: bool,
    tid: [u8; 12],
}

/// The message type of a method and class (§5).
fn msg_type(method: u16, class: u16) -> u16 {
    (method & 0x000F)
        | ((method & 0x0070) << 1)
        | ((method & 0x0F80) << 2)
        | ((class & 1) << 4)
        | ((class & 2) << 7)
}

/// One attribute: type and value.
#[derive(Clone, Copy)]
struct Attr<'a> {
    kind: u16,
    value: &'a [u8],
}

/// Attributes of a message whose header has been checked.
fn attrs(msg: &[u8]) -> impl Iterator<Item = Option<Attr<'_>>> {
    let mut rest = msg.get(HEADER..).unwrap_or_default();
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let next = || {
            let (hdr, after) = rest.split_first_chunk::<4>()?;
            let kind = u16::from_be_bytes([hdr[0], hdr[1]]);
            let len = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
            let value = after.get(..len)?;
            // The padding must be there too.
            let rest = after.get(len.checked_add(pad(len))?..)?;
            Some((Attr { kind, value }, rest))
        };
        // A malformed attribute ends the walk (`None`, once).
        let (a, r) = next().map_or((None, &[][..]), |(a, r)| (Some(a), r));
        rest = r;
        Some(a)
    })
}

/// FINGERPRINT is the last attribute and matches (§14.7).
fn fingerprint_ok(msg: &[u8]) -> bool {
    let Some(at) = msg.len().checked_sub(8).filter(|&at| at >= HEADER) else {
        return false;
    };
    let Some((body, tail)) = msg.split_at_checked(at) else {
        return false;
    };
    tail.first_chunk::<8>().is_some_and(|t| {
        u16::from_be_bytes([t[0], t[1]]) == FINGERPRINT
            && u16::from_be_bytes([t[2], t[3]]) == 4
            && u32::from_be_bytes([t[4], t[5], t[6], t[7]]) == crc32(&[body]) ^ FINGERPRINT_XOR
    })
}

/// Header checks (§6.3): first two bits zero, magic cookie, length a
/// multiple of 4 that matches the datagram, well-formed attributes.
fn well_formed(msg: &[u8]) -> bool {
    header(msg).is_some_and(|h| h.stun && h.length_ok)
        && msg.len().wrapping_sub(HEADER).is_multiple_of(4)
        && attrs(msg).all(|a| a.is_some())
}

/// MESSAGE-INTEGRITY is the attribute before FINGERPRINT and is the HMAC
/// of the message up to it, with the header length covering it (§14.5).
fn integrity_ok(msg: &[u8], key: &[u8]) -> bool {
    integrity_matches(msg, key).unwrap_or(false)
}

fn integrity_matches(msg: &[u8], key: &[u8]) -> Option<bool> {
    // MESSAGE-INTEGRITY (24 octets), then FINGERPRINT (8).
    let mi = msg.len().checked_sub(8 + 24).filter(|&mi| mi >= HEADER)?;
    let attr = chunk::<24>(msg, mi)?;
    if u16::from_be_bytes([attr[0], attr[1]]) != MESSAGE_INTEGRITY
        || u16::from_be_bytes([attr[2], attr[3]]) != 20
    {
        return Some(false);
    }
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(key).ok()?;
    // The length as if MESSAGE-INTEGRITY ended the message.
    let len = mi.checked_sub(HEADER)?.checked_add(24)?;
    let len = u16::try_from(len).unwrap_or(u16::MAX);
    mac.update(msg.get(..2)?);
    mac.update(&len.to_be_bytes());
    mac.update(msg.get(4..mi)?);
    Some(mac.verify_slice(&attr[4..24]).is_ok())
}

/// Writes a response into `out`.
struct Writer<'b> {
    out: &'b mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn start<'o>(out: &'o mut [u8], method: u16, class: u16, tid: &[u8; 12]) -> Option<Writer<'o>> {
        let hdr = out.first_chunk_mut::<HEADER>()?;
        hdr[..2].copy_from_slice(&msg_type(method, class).to_be_bytes());
        hdr[2..4].fill(0);
        hdr[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        hdr[8..20].copy_from_slice(tid);
        Some(Writer { out, pos: HEADER })
    }

    /// An attribute of `value_len` octets, which `fill` writes (it gets
    /// exactly that many), then its padding.
    fn attr(&mut self, kind: u16, value_len: usize, fill: impl FnOnce(&mut [u8])) -> Option<()> {
        let total = value_len.checked_add(pad(value_len))?.checked_add(4)?;
        let end = self.pos.checked_add(total)?;
        let dst = self.out.get_mut(self.pos..end)?;
        let (hdr, value) = dst.split_first_chunk_mut::<4>()?;
        hdr[..2].copy_from_slice(&kind.to_be_bytes());
        hdr[2..].copy_from_slice(&u16::try_from(value_len).ok()?.to_be_bytes());
        value.fill(0);
        fill(value.get_mut(..value_len)?);
        self.pos = end;
        Some(())
    }

    fn error_code(&mut self, code: u16) -> Option<()> {
        #[allow(clippy::cast_possible_truncation)]
        self.attr(ERROR_CODE, 4, |v| {
            v.copy_from_slice(&[0, 0, (code / 100) as u8, (code % 100) as u8]);
        })
    }

    fn set_length(&mut self, end: usize) {
        let len = u16::try_from(end.saturating_sub(HEADER)).unwrap_or(u16::MAX);
        if let Some(field) = self.out.get_mut(2..4) {
            field.copy_from_slice(&len.to_be_bytes());
        }
    }

    fn integrity(&mut self, key: &[u8]) -> Option<()> {
        self.set_length(self.pos.checked_add(24)?);
        let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(key).ok()?;
        mac.update(self.out.get(..self.pos)?);
        let tag = mac.finalize().into_bytes();
        self.attr(MESSAGE_INTEGRITY, 20, |v| v.copy_from_slice(&tag))
    }

    fn finish(mut self) -> Option<usize> {
        self.set_length(self.pos.checked_add(8)?);
        let crc = crc32(&[self.out.get(..self.pos)?]) ^ FINGERPRINT_XOR;
        self.attr(FINGERPRINT, 4, |v| v.copy_from_slice(&crc.to_be_bytes()))?;
        Some(self.pos)
    }
}

/// The XOR-MAPPED-ADDRESS value of `src` into `v` (8 octets for IPv4, 20
/// for IPv6, as `write_success` sizes it).
fn xor_mapped(v: &mut [u8], src: SocketAddr, tid: &[u8; 12]) {
    #[allow(clippy::cast_possible_truncation)]
    let xport = (src.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes();
    // The address is XORed with the cookie, then (IPv6) the transaction id.
    let mask = MAGIC_COOKIE.to_be_bytes().into_iter().chain(*tid);
    let (family, octets): (u8, &[u8]) = match src.ip() {
        IpAddr::V4(a) => (1, &a.octets()),
        IpAddr::V6(a) => (2, &a.octets()),
    };
    let Some((hdr, addr)) = v.split_first_chunk_mut::<4>() else {
        return;
    };
    *hdr = [0, family, xport[0], xport[1]];
    for ((o, b), m) in addr.iter_mut().zip(octets).zip(mask) {
        *o = b ^ m;
    }
}

/// An ICE role (RFC 8445 §6.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Controlling,
    Controlled,
}

impl Role {
    #[must_use]
    pub const fn other(self) -> Role {
        match self {
            Role::Controlling => Role::Controlled,
            Role::Controlled => Role::Controlling,
        }
    }
}

/// An authenticated connectivity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    pub tid: [u8; 12],
    /// PRIORITY: the priority of the peer-reflexive candidate the check
    /// would make.
    pub priority: Option<u32>,
    /// USE-CANDIDATE: the controlling agent nominates this pair.
    pub use_candidate: bool,
    /// ICE-CONTROLLING or ICE-CONTROLLED, with the sender's tie-breaker.
    pub role: Option<(Role, u64)>,
}

/// What a received datagram is, for an agent answering checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Not a STUN Binding request: nothing to send.
    Ignore,
    /// Rejected (400, 401 or 420): send `out[..len]` back to the source.
    Rejected { len: usize },
    /// An authenticated check: answer it (success or 487).
    Check(Check),
}

/// Check a Binding request against the agent's credentials (see the module
/// documentation); a rejection is written into `out`.
#[must_use]
pub fn check_request(msg: &[u8], creds: Credentials<'_>, out: &mut [u8]) -> Request {
    check_request_inner(msg, creds, out).unwrap_or(Request::Ignore)
}

fn check_request_inner(msg: &[u8], creds: Credentials<'_>, out: &mut [u8]) -> Option<Request> {
    if !fingerprint_ok(msg) || !well_formed(msg) {
        return None;
    }
    let h = header(msg)?;
    let (class, method) = class_method(h.kind);
    if class != 0 || method != BINDING {
        return None;
    }
    let tid = &h.tid;
    let user = attrs(msg)
        .flatten()
        .find(|a| a.kind == USERNAME)
        .map(|a| a.value);
    let has_mi = attrs(msg).flatten().any(|a| a.kind == MESSAGE_INTEGRITY);
    let user_ok = user.is_some_and(|u| {
        u.iter()
            .position(|&c| c == b':')
            .is_some_and(|i| u.get(..i) == Some(creds.ufrag))
    });
    // §9.1.3, in this order.
    let reject = if !(has_mi && user.is_some()) {
        Some(400u16)
    } else if !user_ok || !integrity_ok(msg, creds.pwd) {
        Some(401)
    } else {
        None
    };
    if let Some(code) = reject {
        let mut w = Writer::start(out, BINDING, 0b11, tid)?;
        w.error_code(code)?;
        let len = w.finish()?;
        return Some(Request::Rejected { len });
    }
    // §6.3.1: unknown comprehension-required attributes, first occurrences.
    let mut unknown = [0u16; MAX_UNKNOWN];
    let mut n_unknown = 0;
    for a in attrs(msg).flatten() {
        let known = matches!(
            a.kind,
            USERNAME | MESSAGE_INTEGRITY | PRIORITY | USE_CANDIDATE
        );
        let seen = unknown.get(..n_unknown).unwrap_or_default();
        if a.kind < 0x8000
            && !known
            && !seen.contains(&a.kind)
            && let Some(slot) = unknown.get_mut(n_unknown)
        {
            *slot = a.kind;
            // At most MAX_UNKNOWN.
            n_unknown = n_unknown.wrapping_add(1);
        }
    }
    let unknown = unknown.get(..n_unknown).unwrap_or_default();
    if !unknown.is_empty() {
        let mut w = Writer::start(out, BINDING, 0b11, tid)?;
        w.error_code(420)?;
        // At most MAX_UNKNOWN types of two octets.
        w.attr(UNKNOWN_ATTRIBUTES, unknown.len().wrapping_mul(2), |v| {
            for (dst, t) in v.as_chunks_mut::<2>().0.iter_mut().zip(unknown) {
                *dst = t.to_be_bytes();
            }
        })?;
        w.integrity(creds.pwd)?;
        let len = w.finish()?;
        return Some(Request::Rejected { len });
    }
    let mut check = Check {
        tid: *tid,
        priority: None,
        use_candidate: false,
        role: None,
    };
    for a in attrs(msg).flatten() {
        match (a.kind, a.value.len()) {
            (PRIORITY, 4) => check.priority = Some(u32::from_be_bytes(a.value.try_into().ok()?)),
            (USE_CANDIDATE, _) => check.use_candidate = true,
            (ICE_CONTROLLING, 8) => {
                check.role = Some((
                    Role::Controlling,
                    u64::from_be_bytes(a.value.try_into().ok()?),
                ));
            }
            (ICE_CONTROLLED, 8) => {
                check.role = Some((
                    Role::Controlled,
                    u64::from_be_bytes(a.value.try_into().ok()?),
                ));
            }
            _ => {}
        }
    }
    Some(Request::Check(check))
}

/// The success response to check `tid` from `src`: XOR-MAPPED-ADDRESS,
/// MESSAGE-INTEGRITY with the agent's password, FINGERPRINT.
#[must_use]
pub fn write_success(out: &mut [u8], tid: &[u8; 12], src: SocketAddr, pwd: &[u8]) -> Option<usize> {
    let mut w = Writer::start(out, BINDING, 0b10, tid)?;
    let addr_len = if src.is_ipv4() { 8 } else { 20 };
    w.attr(XOR_MAPPED_ADDRESS, addr_len, |v| xor_mapped(v, src, tid))?;
    w.integrity(pwd)?;
    w.finish()
}

/// An error response with `code` to check `tid`, authenticated with `pwd`.
#[must_use]
pub fn write_error(out: &mut [u8], tid: &[u8; 12], code: u16, pwd: &[u8]) -> Option<usize> {
    let mut w = Writer::start(out, BINDING, 0b11, tid)?;
    w.error_code(code)?;
    w.integrity(pwd)?;
    w.finish()
}

/// The 487 (Role Conflict) error response to check `tid`, authenticated.
#[must_use]
pub fn write_role_conflict(out: &mut [u8], tid: &[u8; 12], pwd: &[u8]) -> Option<usize> {
    let mut w = Writer::start(out, BINDING, 0b11, tid)?;
    w.error_code(ROLE_CONFLICT)?;
    w.integrity(pwd)?;
    w.finish()
}

/// What an agent in `role` with tie-breaker `tiebreaker` does with a check
/// claiming `peer` with `peer_tiebreaker` (RFC 8445 §7.3.1.1): its role
/// afterwards, and whether it answers 487 instead of success.
#[must_use]
pub fn on_role_request(
    role: Role,
    tiebreaker: u64,
    peer: Role,
    peer_tiebreaker: u64,
) -> (Role, bool) {
    match (role, peer) {
        (Role::Controlling, Role::Controlling) => {
            if tiebreaker >= peer_tiebreaker {
                (Role::Controlling, true)
            } else {
                (Role::Controlled, false)
            }
        }
        (Role::Controlled, Role::Controlled) => {
            if tiebreaker >= peer_tiebreaker {
                (Role::Controlling, false)
            } else {
                (Role::Controlled, true)
            }
        }
        _ => (role, false),
    }
}

/// The role after a reply to a check sent claiming `claimed` (RFC 8445
/// §7.2.5.1): a 487 switches to the other role; anything else keeps
/// `current`.
#[must_use]
pub const fn on_role_reply(claimed: Role, current: Role, conflict: bool) -> Role {
    if conflict { claimed.other() } else { current }
}

/// The ICE-lite answer to `msg` from `src` (see the module documentation).
#[must_use]
pub fn ice_lite(msg: &[u8], creds: Credentials<'_>, src: SocketAddr, out: &mut [u8]) -> Answer {
    match check_request(msg, creds, out) {
        Request::Ignore => Answer::Ignore,
        Request::Rejected { len } => Answer::Reply {
            len,
            checked: false,
            nominated: false,
        },
        Request::Check(c) => match write_success(out, &c.tid, src, creds.pwd) {
            Some(len) => Answer::Reply {
                len,
                checked: true,
                nominated: c.use_candidate,
            },
            None => Answer::Ignore,
        },
    }
}

/// A connectivity check to send (RFC 8445 §7.2.2).
#[derive(Debug, Clone, Copy)]
pub struct CheckRequest<'a> {
    /// `<peer's ufrag>:<own ufrag>`.
    pub username: &'a [u8],
    /// The peer's password.
    pub pwd: &'a [u8],
    /// The priority of the peer-reflexive candidate the check would make.
    pub priority: u32,
    pub role: Role,
    pub tiebreaker: u64,
    pub use_candidate: bool,
}

/// Write the check `req` with transaction id `tid` into `out`.
#[must_use]
pub fn write_check(out: &mut [u8], tid: &[u8; 12], req: &CheckRequest<'_>) -> Option<usize> {
    let mut w = Writer::start(out, BINDING, 0, tid)?;
    w.attr(USERNAME, req.username.len(), |v| {
        v.copy_from_slice(req.username);
    })?;
    w.attr(PRIORITY, 4, |v| {
        v.copy_from_slice(&req.priority.to_be_bytes());
    })?;
    let kind = match req.role {
        Role::Controlling => ICE_CONTROLLING,
        Role::Controlled => ICE_CONTROLLED,
    };
    w.attr(kind, 8, |v| {
        v.copy_from_slice(&req.tiebreaker.to_be_bytes());
    })?;
    if req.use_candidate && req.role == Role::Controlling {
        w.attr(USE_CANDIDATE, 0, |_| {})?;
    }
    w.integrity(req.pwd)?;
    w.finish()
}

/// A response to a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// Success: the address the peer saw the check come from.
    Success { mapped: SocketAddr },
    /// An error response with its code.
    Error { code: u16 },
}

/// The transaction id of a STUN response, if `msg` looks like one (to find
/// the transaction before checking it with the right password).
#[must_use]
pub fn response_tid(msg: &[u8]) -> Option<[u8; 12]> {
    if !fingerprint_ok(msg) || !well_formed(msg) {
        return None;
    }
    let h = header(msg)?;
    let (class, method) = class_method(h.kind);
    (method == BINDING && class >= 0b10).then_some(h.tid)
}

/// Read an authenticated response to a check, protected with the peer's
/// password `pwd`: its transaction id and outcome. Unauthenticated or
/// malformed responses give `None`.
#[must_use]
pub fn read_response(msg: &[u8], pwd: &[u8]) -> Option<([u8; 12], Response)> {
    let tid = response_tid(msg)?;
    if !integrity_ok(msg, pwd) {
        return None;
    }
    let (class, _) = class_method(header(msg)?.kind);
    if class == 0b10 {
        let mapped = mapped_address(msg, &tid)?;
        Some((tid, Response::Success { mapped }))
    } else {
        let code = attrs(msg).flatten().find_map(|a| match *a.value {
            // Class (0 to 7) × 100 + number: no overflow.
            [_, _, class, number, ..] if a.kind == ERROR_CODE => Some(
                u16::from(class & 7)
                    .wrapping_mul(100)
                    .wrapping_add(u16::from(number)),
            ),
            _ => None,
        })?;
        Some((tid, Response::Error { code }))
    }
}

/// A Binding request to a STUN server (RFC 8489 §6, no authentication),
/// for learning the server-reflexive address of the sending socket.
#[must_use]
pub fn write_binding(out: &mut [u8], tid: &[u8; 12]) -> Option<usize> {
    Writer::start(out, BINDING, 0, tid)?.finish()
}

/// The reflexive address in a STUN server's success response to `tid`
/// (XOR-MAPPED-ADDRESS, or MAPPED-ADDRESS from an older server).
#[must_use]
pub fn read_binding(msg: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    let h = header(msg)?;
    if !h.stun
        || !h.length_ok
        || !attrs(msg).all(|a| a.is_some())
        || &h.tid != tid
        || class_method(h.kind) != (0b10, BINDING)
    {
        return None;
    }
    mapped_address(msg, tid)
}

/// The class and method of message type `t` (§5).
fn class_method(t: u16) -> (u16, u16) {
    (
        (t >> 4 & 1) | (t >> 7 & 2),
        (t & 0xF) | (t >> 1 & 0x70) | (t >> 2 & 0xF80),
    )
}

fn mapped_address(msg: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let xor = attrs(msg)
        .flatten()
        .find(|a| a.kind == XOR_MAPPED_ADDRESS)
        .map(|a| (a, true));
    let (a, xored) = xor.or_else(|| {
        attrs(msg)
            .flatten()
            .find(|a| a.kind == MAPPED_ADDRESS)
            .map(|a| (a, false))
    })?;
    let v = a.value;
    let mut port = rd16(v, 2)?;
    if xored {
        #[allow(clippy::cast_possible_truncation)]
        let x = (MAGIC_COOKIE >> 16) as u16;
        port ^= x;
    }
    // XORed with the cookie, then (IPv6) the transaction id.
    let mask = cookie
        .into_iter()
        .chain(*tid)
        .map(|m| if xored { m } else { 0 });
    let raw = v.get(4..)?;
    match (*v.get(1)?, v.len()) {
        (1, 8) => {
            let mut o = [0u8; 4];
            for ((b, r), m) in o.iter_mut().zip(raw).zip(mask) {
                *b = r ^ m;
            }
            Some(SocketAddr::new(IpAddr::from(o), port))
        }
        (2, 20) => {
            let mut o = [0u8; 16];
            for ((b, r), m) in o.iter_mut().zip(raw).zip(mask) {
                *b = r ^ m;
            }
            Some(SocketAddr::new(IpAddr::from(o), port))
        }
        _ => None,
    }
}

/// The ICE priority of a host candidate (RFC 8445 §5.1.2.1, type
/// preference 126, local preference 65535) for `component` (1 RTP, 2 RTCP;
/// a `u8`, so the result never overflows).
#[must_use]
pub const fn host_priority(component: u8) -> u32 {
    // The two preferences occupy separate bits: OR is their sum.
    let base: u32 = (126 << 24) | (65_535 << 8);
    base.wrapping_add(256u32.wrapping_sub(component as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
    }

    #[test]
    fn demux_and_mux() {
        assert_eq!(classify(0x80), Kind::Rtp);
        assert_eq!(classify(0x16), Kind::Dtls);
        assert_eq!(classify(0x00), Kind::Stun);
        assert_eq!(classify(0x03), Kind::Stun, "RFC 7983");
        assert_eq!(classify(0x04), Kind::Drop);
        assert_eq!(
            classify(0x10),
            Kind::Zrtp,
            "ZRTP's first octet (RFC 6189 §5)"
        );
        assert_eq!(
            (classify(15), classify(19), classify(20)),
            (Kind::Drop, Kind::Zrtp, Kind::Dtls)
        );
        assert_eq!(classify(0x40), Kind::Drop, "TURN channel data");
        assert!(is_muxed_rtcp(&[0x81, 200]));
        assert!(!is_muxed_rtcp(&[0x80, 0x00]));
        assert!(!is_muxed_rtcp(&[0x80, 0xe0]), "marker + PT 96");
    }

    #[test]
    fn message_type_bits() {
        assert_eq!(msg_type(BINDING, 0), 0x0001);
        assert_eq!(msg_type(BINDING, 0b10), 0x0101);
        assert_eq!(msg_type(BINDING, 0b11), 0x0111);
    }

    #[test]
    fn the_crc_table_matches_its_definition() {
        assert_eq!(crc_table(), CRC_TABLE);
    }
}
