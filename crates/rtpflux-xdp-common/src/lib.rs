//! Shared between the XDP program (`rtpflux-xdp-ebpf`) and its userspace
//! loader (`rtpflux-xdp`): the forwarding map's key and value layout, and
//! the per-packet arithmetic of the fast path.
//!
//! The fast path relays UDP datagrams of established media streams without
//! leaving the driver: a datagram arriving on a relay port is looked up by
//! its destination (relay address and port) and source (peer address and
//! port); on a hit, its addresses, ports and MAC addresses are rewritten
//! and it is transmitted back out of the same device (`XDP_TX`) or
//! redirected to another one (`XDP_REDIRECT`). Everything else goes up the
//! stack to the userspace relay (`XDP_PASS`).
//!
//! IPv4 (without options or fragments) and IPv6 (UDP directly after the
//! fixed header, with a UDP checksum) are relayed; addresses are kept as 16
//! octets, an IPv4 address as its IPv4-mapped IPv6 form (RFC 4291
//! §2.5.5.2), so one map serves both. A stream is relayed within one
//! family: the frame keeps its header layout.

// No `unsafe` here, and no way to allow it (AGENTS.md §5).
#![forbid(unsafe_code)]
// Frames from the network go through here (the `AF_XDP` path reads them
// with these functions): no unchecked indexing or arithmetic that could
// panic on them (AGENTS.md §5). Tests may.
#![cfg_attr(
    not(test),
    deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]
#![no_std]

/// Map key: the five-tuple of an incoming media datagram (UDP only).
/// Addresses (IPv4-mapped for IPv4) and ports in network byte order, as
/// read from the packet.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

/// Map value: how to rewrite and send a matching datagram. Addresses (of
/// the key's family) and ports in network byte order.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowAction {
    pub new_src_addr: [u8; 16],
    pub new_dst_addr: [u8; 16],
    pub new_src_port: u16,
    pub new_dst_port: u16,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    /// The device to send from: the arrival device (or 0) transmits back
    /// out (`XDP_TX`), another one redirects (`XDP_REDIRECT`).
    pub ifindex: u32,
    /// [`flags`]: what the program does besides relaying.
    pub flags: u8,
    /// The flow's telephone-event payload type (RFC 4733), for
    /// [`flags::EVENTS_UP`].
    pub event_pt: u8,
    /// Zero; keeps the value free of padding.
    pub reserved: [u8; 2],
}

/// What a flow's datagrams get besides relaying ([`FlowAction::flags`]).
pub mod flags {
    /// Drop them (still counted): a blocked side, or one held back while
    /// an announcement plays to the other.
    pub const DROP: u8 = 1;
    /// Send its telephone events ([`super::FlowAction::event_pt`]) up to
    /// the userspace relay, which detects (and relays or blocks) them; the
    /// rest of the flow stays in the kernel.
    pub const EVENTS_UP: u8 = 2;
    /// Copy each datagram's payload to the recording ring
    /// ([`super::RECORD_MAP`]) before relaying or dropping it.
    pub const RECORD: u8 = 4;
}

/// What the fast path does with a datagram that matched a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// To the stack, and so to the userspace relay.
    Up,
    /// Dropped (and counted).
    Drop,
    /// Rewritten and sent.
    Forward,
}

/// The decision for a matching datagram whose payload's second octet
/// (RTP marker and payload type) is `second` (`None`: the payload is
/// shorter). The program and the userspace reference use this one
/// function.
#[must_use]
pub const fn decide(action: &FlowAction, second: Option<u8>) -> Decision {
    if action.flags & flags::EVENTS_UP != 0
        && let Some(b) = second
        && b & 0x7f == action.event_pt
    {
        return Decision::Up;
    }
    if action.flags & flags::DROP != 0 {
        Decision::Drop
    } else {
        Decision::Forward
    }
}

/// Name of the recording ring buffer in the XDP object.
pub const RECORD_MAP: &str = "RTPFLUX_RECORD";
/// Size of the recording ring buffer, in octets (a power of two).
pub const RECORD_RING: u32 = 1 << 22;
/// The most payload octets one record carries.
pub const RECORD_MAX: usize = 1504;

/// One recorded datagram in the ring: the flow it matched (its peer and the
/// relay address it arrived at), when (`bpf_ktime_get_ns`,
/// `CLOCK_MONOTONIC`), and its UDP payload, cut at [`RECORD_MAX`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RecordSample {
    pub key: FlowKey,
    /// Payload octets in `data`.
    pub len: u16,
    pub reserved: u16,
    pub time_ns: u64,
    pub data: [u8; RECORD_MAX],
}

/// Offsets of [`RecordSample`]'s fields, for reading it back as bytes.
pub mod record_layout {
    pub const KEY: usize = 0;
    pub const LEN: usize = 36;
    pub const TIME: usize = 40;
    pub const DATA: usize = 48;
    pub const SIZE: usize = DATA + super::RECORD_MAX;
}
const _: () = assert!(core::mem::size_of::<RecordSample>() == record_layout::SIZE);
const _: () = assert!(core::mem::offset_of!(RecordSample, len) == record_layout::LEN);
const _: () = assert!(core::mem::offset_of!(RecordSample, time_ns) == record_layout::TIME);
const _: () = assert!(core::mem::offset_of!(RecordSample, data) == record_layout::DATA);

/// A record read back from the ring's bytes: the key, the time and the
/// payload; `None` when the bytes are not a whole record.
#[must_use]
pub fn parse_record(bytes: &[u8]) -> Option<(FlowKey, u64, &[u8])> {
    use record_layout::{DATA, KEY, LEN, SIZE, TIME};
    if bytes.len() < SIZE {
        return None;
    }
    let key = FlowKey {
        src_addr: chunk(bytes, KEY)?,
        dst_addr: chunk(bytes, KEY + 16)?,
        src_port: port(bytes, KEY + 32)?,
        dst_port: port(bytes, KEY + 34)?,
    };
    let len = usize::from(u16::from_ne_bytes(chunk(bytes, LEN)?)).min(RECORD_MAX);
    let time = u64::from_ne_bytes(chunk(bytes, TIME)?);
    Some((key, time, bytes.get(DATA..)?.get(..len)?))
}

/// The IPv4-mapped IPv6 prefix (`::ffff:0:0/96`).
pub const V4_MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// An IPv4 address as 16 octets (IPv4-mapped).
#[must_use]
pub const fn mapped(v4: [u8; 4]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[10] = 0xff;
    a[11] = 0xff;
    a[12] = v4[0];
    a[13] = v4[1];
    a[14] = v4[2];
    a[15] = v4[3];
    a
}

/// The IPv4 address of an IPv4-mapped one.
#[must_use]
pub fn unmapped(a: &[u8; 16]) -> Option<[u8; 4]> {
    (a[..12] == V4_MAPPED).then(|| [a[12], a[13], a[14], a[15]])
}

/// How a matching frame leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Egress {
    /// Back out of the arrival device.
    Tx,
    /// Out of this other device.
    Redirect(u32),
}

/// The action's device against the arrival device.
#[must_use]
pub const fn egress(action_ifindex: u32, ingress_ifindex: u32) -> Egress {
    if action_ifindex == 0 || action_ifindex == ingress_ifindex {
        Egress::Tx
    } else {
        Egress::Redirect(action_ifindex)
    }
}

/// Name of the forwarding map in the XDP object.
pub const FLOW_MAP: &str = "RTPFLUX_FLOWS";

/// Capacity of the forwarding map (each relayed direction is one entry).
pub const FLOW_MAP_ENTRIES: u32 = 1 << 16;

/// Per-flow counters kept by the XDP program for every packet it relays,
/// so userspace can account for media it never sees (activity for idle
/// timeouts, statistics). Same key as the forwarding map.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    /// `bpf_ktime_get_ns()` (`CLOCK_MONOTONIC`) of the last relayed packet.
    pub last_ns: u64,
}

/// Name of the counters map in the XDP object.
pub const STATS_MAP: &str = "RTPFLUX_STATS";

/// Fold a 32-bit one's-complement accumulator into 16 bits.
#[must_use]
pub const fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        // At most 0xffff + 0xffff: no overflow.
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
    }
    // The loop leaves `sum <= 0xffff`.
    #[allow(clippy::cast_possible_truncation)]
    {
        sum as u16
    }
}

/// Incremental update of an Internet checksum when one 16-bit field changes
/// from `old` to `new` (RFC 1624 eqn. 3: `HC' = ~(~HC + ~m + m')`).
#[must_use]
pub const fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
    // Three 16-bit values: no overflow.
    !fold(
        (!check as u32)
            .wrapping_add(!old as u32)
            .wrapping_add(new as u32),
    )
}

/// Incremental update when a 32-bit field (an IPv4 address) changes: two
/// 16-bit replacements.
#[must_use]
pub const fn csum_replace4(check: u16, old: u32, new: u32) -> u16 {
    #[allow(clippy::cast_possible_truncation)]
    let c = csum_replace2(check, (old >> 16) as u16, (new >> 16) as u16);
    #[allow(clippy::cast_possible_truncation)]
    csum_replace2(c, old as u16, new as u16)
}

/// Whether the first two octets of a UDP payload look like RTP or RTCP
/// version 2 (RFC 3550 §5.1, §6.4). The fast path relays both alike; the
/// check only keeps non-media traffic (e.g. STUN, whose first two bits are
/// zero, RFC 8489 §5) on the slow path.
#[must_use]
pub const fn is_rtp_v2(first: u8) -> bool {
    first >> 6 == 2
}

/// TTL the relay gives the datagrams it sends: it originates them rather
/// than routing them.
pub const FRESH_TTL: u8 = 64;

/// Offsets in an Ethernet + IPv4 (no options) or IPv6 (no extension
/// headers) + UDP frame.
pub mod offsets {
    pub const ETH_LEN: usize = 14;
    pub const IPV4_LEN: usize = 20;
    pub const IPV6_LEN: usize = 40;
    pub const UDP_LEN: usize = 8;
    pub const PAYLOAD: usize = ETH_LEN + IPV4_LEN + UDP_LEN;
    pub const PAYLOAD6: usize = ETH_LEN + IPV6_LEN + UDP_LEN;
    pub const ETH_P_IPV4: u16 = 0x0800;
    pub const ETH_P_IPV6: u16 = 0x86dd;
}

/// What the fast path does with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not a candidate (not IPv4/UDP without options or fragments, not
    /// IPv6 with UDP right after the fixed header and a UDP checksum, or not
    /// RTP/RTCP v2): hand it to the stack.
    Pass,
    /// A candidate with this key: look it up.
    Lookup(FlowKey),
}

/// Ethernet + IP + UDP header octets of a frame of `key`'s family.
#[must_use]
pub fn headers_len(key: &FlowKey) -> usize {
    if unmapped(&key.src_addr).is_some() {
        offsets::PAYLOAD
    } else {
        offsets::PAYLOAD6
    }
}

/// The `N` octets at `b[i..]` (`None` past the end).
fn chunk<const N: usize>(b: &[u8], i: usize) -> Option<[u8; N]> {
    b.get(i..)?.first_chunk::<N>().copied()
}

fn byte(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}

fn rd16(b: &[u8], i: usize) -> Option<u16> {
    chunk(b, i).map(u16::from_be_bytes)
}

fn rd32(b: &[u8], i: usize) -> Option<u32> {
    chunk(b, i).map(u32::from_be_bytes)
}

/// A port as read (network byte order kept).
fn port(b: &[u8], i: usize) -> Option<u16> {
    chunk(b, i).map(u16::from_ne_bytes)
}

/// Write `v` at `b[i..]` (`None`, nothing written, past the end).
fn put<const N: usize>(b: &mut [u8], i: usize, v: [u8; N]) -> Option<()> {
    *b.get_mut(i..)?.first_chunk_mut::<N>()? = v;
    Some(())
}

/// Reference classification of a frame, the safe counterpart of the XDP
/// program's checks (same conditions, same order).
#[must_use]
pub fn classify(frame: &[u8]) -> Verdict {
    classify_key(frame).map_or(Verdict::Pass, Verdict::Lookup)
}

fn classify_key(frame: &[u8]) -> Option<FlowKey> {
    use offsets::{ETH_LEN, ETH_P_IPV4, ETH_P_IPV6, IPV4_LEN, IPV6_LEN, PAYLOAD, PAYLOAD6};
    const IP: usize = ETH_LEN;
    match rd16(frame, 12)? {
        ETH_P_IPV4 => {
            const UDP: usize = ETH_LEN + IPV4_LEN;
            if frame.len() < PAYLOAD + 1
                || byte(frame, IP)? != 0x45
                || byte(frame, IP + 9)? != 17
                || rd16(frame, IP + 6)? & 0x3fff != 0
                || !is_rtp_v2(byte(frame, PAYLOAD)?)
            {
                return None;
            }
            Some(FlowKey {
                src_addr: mapped(chunk(frame, IP + 12)?),
                dst_addr: mapped(chunk(frame, IP + 16)?),
                src_port: port(frame, UDP)?,
                dst_port: port(frame, UDP + 2)?,
            })
        }
        ETH_P_IPV6 => {
            const UDP: usize = ETH_LEN + IPV6_LEN;
            if frame.len() < PAYLOAD6 + 1
                || byte(frame, IP)? >> 4 != 6
                || byte(frame, IP + 6)? != 17
                || rd16(frame, UDP + 6)? == 0
                || !is_rtp_v2(byte(frame, PAYLOAD6)?)
            {
                return None;
            }
            let (src, dst): ([u8; 16], [u8; 16]) = (chunk(frame, IP + 8)?, chunk(frame, IP + 24)?);
            // An IPv4-mapped source or destination never appears on the
            // wire (RFC 4291 §2.5.5.2); keeping them out keeps the families
            // apart in the map.
            if unmapped(&src).is_some() || unmapped(&dst).is_some() {
                return None;
            }
            Some(FlowKey {
                src_addr: src,
                dst_addr: dst,
                src_port: port(frame, UDP)?,
                dst_port: port(frame, UDP + 2)?,
            })
        }
        _ => None,
    }
}

/// Name of the map of `AF_XDP` sockets in the XDP object (`XSKMAP`, by
/// receive queue).
pub const XSK_MAP: &str = "RTPFLUX_XSKS";
/// How many receive queues a device can have sockets on.
pub const XSK_QUEUES: u32 = 64;
/// Name of the steering map: the relay's addresses (IPv4-mapped for IPv4)
/// and the port range whose datagrams go to its `AF_XDP` sockets.
pub const STEER_MAP: &str = "RTPFLUX_STEER";
/// How many addresses the steering map holds.
pub const STEER_ENTRIES: u32 = 64;

/// The relay ports of one address whose datagrams are steered to `AF_XDP`
/// (host order, inclusive).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SteerRange {
    pub min_port: u16,
    pub max_port: u16,
    /// The device whose queues have the sockets: datagrams arriving on
    /// another stay with the stack (the kernel would drop a redirect to a
    /// socket of another device).
    pub ifindex: u32,
}

/// Whether a datagram to `port` of an address with `range`, arriving on
/// device `ifindex`, is steered.
#[must_use]
pub const fn steered(range: &SteerRange, port: u16, ifindex: u32) -> bool {
    range.ifindex == ifindex && range.min_port <= port && port <= range.max_port
}

/// One UDP datagram in an Ethernet frame, as the `AF_XDP` path reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// Addresses (IPv4-mapped for IPv4) and ports (host order).
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    /// Where the UDP payload lies in the frame.
    pub payload: core::ops::Range<usize>,
}

/// The destination of a frame the steering applies to: an IPv4 (no
/// options, not fragmented) or IPv6 (UDP next) UDP datagram, any payload.
/// The program's checks, in the same order.
#[must_use]
pub fn steer_key(frame: &[u8]) -> Option<([u8; 16], u16)> {
    use offsets::{ETH_LEN, ETH_P_IPV4, ETH_P_IPV6, IPV4_LEN, IPV6_LEN};
    match rd16(frame, 12)? {
        ETH_P_IPV4 => {
            const UDP: usize = ETH_LEN + IPV4_LEN;
            if frame.len() < UDP + 8
                || byte(frame, ETH_LEN)? != 0x45
                || byte(frame, ETH_LEN + 9)? != 17
                || rd16(frame, ETH_LEN + 6)? & 0x3fff != 0
            {
                return None;
            }
            Some((mapped(chunk(frame, ETH_LEN + 16)?), rd16(frame, UDP + 2)?))
        }
        ETH_P_IPV6 => {
            const UDP: usize = ETH_LEN + IPV6_LEN;
            if frame.len() < UDP + 8
                || byte(frame, ETH_LEN)? >> 4 != 6
                || byte(frame, ETH_LEN + 6)? != 17
            {
                return None;
            }
            let dst: [u8; 16] = chunk(frame, ETH_LEN + 24)?;
            if unmapped(&dst).is_some() {
                return None;
            }
            Some((dst, rd16(frame, UDP + 2)?))
        }
        _ => None,
    }
}

/// Ones' complement sum of `b` (odd length: a zero octet appended), added
/// to `sum`.
fn sum16(mut sum: u32, b: &[u8]) -> u32 {
    let (pairs, rest) = b.as_chunks::<2>();
    for &pair in pairs {
        sum = add1c(sum, u32::from(u16::from_be_bytes(pair)));
    }
    if let [last] = rest {
        sum = add1c(sum, u32::from(u16::from_be_bytes([*last, 0])));
    }
    sum
}

/// Ones' complement addition: a carry out of the 32 bits comes back in
/// (2^32 ≡ 1 modulo 0xffff, so the folded sum is the same), and no length
/// of input overflows.
const fn add1c(sum: u32, x: u32) -> u32 {
    let (s, carry) = sum.overflowing_add(x);
    // With a carry, `s` < `x` <= 0xffff_ffff: adding 1 does not overflow.
    s.wrapping_add(carry as u32)
}

/// A steered frame read back as the stack would accept it: the headers
/// [`steer_key`] checks, lengths that fit the frame (Ethernet padding
/// left out), and valid checksums (the IPv4 header's; the UDP one's when
/// present, which IPv6 requires). `None`: the stack would drop it.
#[must_use]
pub fn datagram(frame: &[u8]) -> Option<Datagram> {
    use offsets::{ETH_LEN, ETH_P_IPV4, IPV4_LEN, IPV6_LEN};
    steer_key(frame)?;
    let v4 = rd16(frame, 12)? == ETH_P_IPV4;
    let (udp, src, dst, ip_payload_len) = if v4 {
        let ip = frame.get(ETH_LEN..ETH_LEN + IPV4_LEN)?;
        if fold(sum16(0, ip)) != 0xffff {
            return None;
        }
        let total = usize::from(rd16(frame, ETH_LEN + 2)?);
        // The packet the header describes must be in the frame.
        if ETH_LEN.checked_add(total)? > frame.len() {
            return None;
        }
        (
            ETH_LEN + IPV4_LEN,
            mapped(chunk(frame, ETH_LEN + 12)?),
            mapped(chunk(frame, ETH_LEN + 16)?),
            total.checked_sub(IPV4_LEN)?,
        )
    } else {
        let src: [u8; 16] = chunk(frame, ETH_LEN + 8)?;
        // Never on the wire (RFC 4291 §2.5.5.2), as for the destination.
        if unmapped(&src).is_some() {
            return None;
        }
        (
            ETH_LEN + IPV6_LEN,
            src,
            chunk(frame, ETH_LEN + 24)?,
            usize::from(rd16(frame, ETH_LEN + 4)?),
        )
    };
    // `udp` is 34 or 54: its fields' offsets do not overflow.
    let field = |at: usize| udp.wrapping_add(at);
    let udp_len = usize::from(rd16(frame, field(4))?);
    let end = udp.checked_add(udp_len)?;
    if udp_len < 8 || udp_len > ip_payload_len || end > frame.len() {
        return None;
    }
    let check = rd16(frame, field(6))?;
    if v4 && check == 0 {
        // No checksum (IPv4 only).
    } else if check == 0 {
        return None;
    } else {
        // The pseudo-header: addresses, protocol and UDP length.
        let (s, d) = if v4 {
            (&src[12..], &dst[12..])
        } else {
            (&src[..], &dst[..])
        };
        let mut sum = sum16(sum16(0, s), d);
        sum = add1c(sum, 17);
        #[allow(clippy::cast_possible_truncation)]
        {
            sum = add1c(sum, udp_len as u32);
        }
        if fold(sum16(sum, frame.get(udp..end)?)) != 0xffff {
            return None;
        }
    }
    Some(Datagram {
        src,
        dst,
        src_port: rd16(frame, udp)?,
        dst_port: rd16(frame, field(2))?,
        payload: field(8)..end,
    })
}

/// Replace a 16-octet address in a checksum, word by word.
#[must_use]
pub fn csum_replace16(mut check: u16, old: &[u8; 16], new: &[u8; 16]) -> u16 {
    let (old, _) = old.as_chunks::<2>();
    let (new, _) = new.as_chunks::<2>();
    for (o, n) in old.iter().zip(new) {
        check = csum_replace2(check, u16::from_be_bytes(*o), u16::from_be_bytes(*n));
    }
    check
}

/// The UDP checksum `check` after the address and port change of `action`
/// (the pseudo-header addresses and both ports). Zero (for IPv4: no
/// checksum) stays zero; a computed zero is sent as 0xffff (RFC 768,
/// RFC 8200 §8.1). For IPv4 the mapped prefix is the same on both sides
/// and drops out.
#[must_use]
pub fn udp_check_update(check: u16, key: &FlowKey, action: &FlowAction) -> u16 {
    if check == 0 {
        return 0;
    }
    let mut c = csum_replace16(check, &key.src_addr, &action.new_src_addr);
    c = csum_replace16(c, &key.dst_addr, &action.new_dst_addr);
    c = csum_replace2(
        c,
        u16::from_be(key.src_port),
        u16::from_be(action.new_src_port),
    );
    c = csum_replace2(
        c,
        u16::from_be(key.dst_port),
        u16::from_be(action.new_dst_port),
    );
    if c == 0 { 0xffff } else { c }
}

/// Reference rewrite of a frame that `classify` mapped to `key`, the safe
/// counterpart of the XDP program's rewrite: MACs, TTL / hop limit,
/// addresses, ports, and the checksums updated incrementally (RFC 1624).
/// A frame shorter than its headers is left as it is.
pub fn rewrite(frame: &mut [u8], key: &FlowKey, action: &FlowAction) {
    use offsets::{PAYLOAD, PAYLOAD6};
    let v4 = unmapped(&action.new_src_addr).zip(unmapped(&action.new_dst_addr));
    // All the headers there, or nothing is written.
    if frame.len() < if v4.is_some() { PAYLOAD } else { PAYLOAD6 } {
        return;
    }
    let _ = rewrite_headers(frame, key, action, v4);
}

/// [`rewrite`] of a frame with all its headers (checked there).
fn rewrite_headers(
    frame: &mut [u8],
    key: &FlowKey,
    action: &FlowAction,
    v4: Option<([u8; 4], [u8; 4])>,
) -> Option<()> {
    use offsets::{ETH_LEN, IPV4_LEN, IPV6_LEN};
    const IP: usize = ETH_LEN;
    put(frame, 0, action.dst_mac)?;
    put(frame, 6, action.src_mac)?;
    let udp = if let Some((new_src, new_dst)) = v4 {
        let mut ip_check = rd16(frame, IP + 10)?;
        let old_ttl_proto = rd16(frame, IP + 8)?;
        let new_ttl_proto = (u16::from(FRESH_TTL) << 8) | 0x11; // protocol 17 (UDP)
        ip_check = csum_replace2(ip_check, old_ttl_proto, new_ttl_proto);
        put(frame, IP + 8, new_ttl_proto.to_be_bytes())?;
        let (old_src, old_dst) = (rd32(frame, IP + 12)?, rd32(frame, IP + 16)?);
        ip_check = csum_replace4(ip_check, old_src, u32::from_be_bytes(new_src));
        ip_check = csum_replace4(ip_check, old_dst, u32::from_be_bytes(new_dst));
        put(frame, IP + 12, new_src)?;
        put(frame, IP + 16, new_dst)?;
        put(frame, IP + 10, ip_check.to_be_bytes())?;
        ETH_LEN + IPV4_LEN
    } else {
        // IPv6: no header checksum; the hop limit is not in the UDP one.
        put(frame, IP + 7, [FRESH_TTL])?;
        put(frame, IP + 8, action.new_src_addr)?;
        put(frame, IP + 24, action.new_dst_addr)?;
        ETH_LEN + IPV6_LEN
    };
    // `udp` is 34 or 54: its fields' offsets do not overflow.
    let field = |at: usize| udp.wrapping_add(at);
    let c = udp_check_update(rd16(frame, field(6))?, key, action);
    put(frame, field(6), c.to_be_bytes())?;
    put(frame, udp, action.new_src_port.to_ne_bytes())?;
    put(frame, field(2), action.new_dst_port.to_ne_bytes())
}

#[cfg(test)]
mod tests;
