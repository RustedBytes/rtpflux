//! The rtpflux XDP fast path.
//!
//! For every IPv4/UDP datagram without options or fragments, and every
//! IPv6 datagram whose next header is UDP with a checksum, whose first
//! payload octet says RTP/RTCP version 2, look up its five-tuple in
//! `RTPFLUX_FLOWS` (IPv4 addresses IPv4-mapped). On a hit, rewrite the MAC
//! addresses, IP addresses and UDP ports as the entry says, give the packet
//! a fresh TTL / hop limit (the relay originates it, it does not route it),
//! update the checksums incrementally (RFC 1624) and send it back out of
//! the same interface (`XDP_TX`) or out of the entry's device
//! (`bpf_redirect`, `XDP_REDIRECT`). Anything else, including misses, goes
//! to the kernel stack (`XDP_PASS`) and so to the userspace relay.
//!
//! An entry's flags (`rtpflux_xdp_common::flags`) can send the flow's
//! telephone events up to the userspace relay (which detects them), drop
//! the flow (a blocked side, one held back for an announcement; still
//! counted), and copy each datagram's payload into the recording ring
//! (`RTPFLUX_RECORD`) before it is relayed or dropped. The decision is
//! `rtpflux_xdp_common::decide`, shared with the userspace reference.
//!
//! A datagram no flow relays, sent to a steered relay port (`RTPFLUX_STEER`:
//! address and port range), goes to the relay's `AF_XDP` socket on its
//! receive queue (`RTPFLUX_XSKS`); without one, to the stack. This carries
//! encrypted, WebRTC and BUNDLE calls to the relay without the stack's UDP
//! receive path.
//!
//! Every packet access is bounds-checked against `data_end`, as the eBPF
//! verifier requires.

#![no_std]
#![no_main]
// The program must be inlined into one function: the verifier then follows
// every packet pointer from its bounds check to its use, and the program
// makes no BPF-to-BPF calls.
#![allow(
    clippy::inline_always,
    reason = "eBPF: everything is inlined into the program"
)]
// Every `unsafe` says why it is sound: here, that each packet access lies
// inside a region `at` checked against `data_end` (AGENTS.md §5).
#![deny(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::{HashMap, PerCpuHashMap, RingBuf, XskMap},
    macros::{btf_map, xdp},
    programs::XdpContext,
};
use rtpflux_xdp_common::{
    Decision, Egress, FlowAction, FlowKey, FlowStats, RECORD_MAX, RecordSample, SteerRange,
    V4_MAPPED, csum_replace2, csum_replace4, decide, egress, flags, is_rtp_v2, mapped, steered,
    udp_check_update,
};

/// The forwarding map, BTF-defined (`.maps` section) so that libbpf-based
/// tools (`bpftool`) and the aya loader both understand it. Its capacity is
/// `rtpflux_xdp_common::FLOW_MAP_ENTRIES` (checked below).
#[btf_map(name = "RTPFLUX_FLOWS")]
static FLOWS: HashMap<FlowKey, FlowAction, 65_536> = HashMap::new();

/// Per-flow counters (same keys as `FLOWS`), one copy per CPU so updates
/// need no atomics; userspace sums the copies. Userspace creates the entry
/// with the flow; the program only updates it.
#[btf_map(name = "RTPFLUX_STATS")]
static STATS: PerCpuHashMap<FlowKey, FlowStats, 65_536> = PerCpuHashMap::new();

const _: () = assert!(65_536 == rtpflux_xdp_common::FLOW_MAP_ENTRIES as usize);

/// Recorded datagrams for the userspace relay (flows with
/// `flags::RECORD`): `RecordSample`s.
#[btf_map(name = "RTPFLUX_RECORD")]
static RECORD: RingBuf<RecordSample, { 1 << 22 }> = RingBuf::new();

const _: () = assert!(1 << 22 == rtpflux_xdp_common::RECORD_RING as usize);

/// `AF_XDP` sockets of the userspace relay, by receive queue.
#[btf_map(name = "RTPFLUX_XSKS")]
static XSKS: XskMap<64> = XskMap::new();

/// The relay's addresses and the port range steered to its `AF_XDP` sockets.
#[btf_map(name = "RTPFLUX_STEER")]
static STEER: HashMap<[u8; 16], SteerRange, 64> = HashMap::new();

const _: () = assert!(64 == rtpflux_xdp_common::XSK_QUEUES as usize);
const _: () = assert!(64 == rtpflux_xdp_common::STEER_ENTRIES as usize);

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const IPV6_LEN: usize = 40;
const UDP_LEN: usize = 8;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_UDP: u8 = 17;
const FRESH_TTL: u8 = 64;

#[xdp]
#[allow(
    clippy::needless_pass_by_value,
    reason = "the #[xdp] macro passes the context by value"
)]
pub fn rtpflux(ctx: XdpContext) -> u32 {
    match try_relay(&ctx) {
        Some(action) => action,
        None => steer(&ctx),
    }
}

/// A datagram no flow relays: to the relay's `AF_XDP` socket on this
/// receive queue when it is for a steered relay port, else (or with no
/// socket on the queue) to the stack.
#[inline(always)]
fn steer(ctx: &XdpContext) -> u32 {
    let Some((addr, port)) = steer_key(ctx) else {
        return xdp_action::XDP_PASS;
    };
    // SAFETY: the map value is only read.
    let Some(range) = (unsafe { STEER.get(&addr) }) else {
        return xdp_action::XDP_PASS;
    };
    #[allow(clippy::cast_possible_truncation)]
    if !steered(range, port, ctx.ingress_ifindex() as u32) {
        return xdp_action::XDP_PASS;
    }
    match XSKS.redirect(ctx.rx_queue_index(), u64::from(xdp_action::XDP_PASS)) {
        Ok(action) | Err(action) => action,
    }
}

/// The destination address (IPv4-mapped for IPv4) and port (host order) of
/// a UDP datagram, as `rtpflux_xdp_common::steer_key` reads it.
#[inline(always)]
fn steer_key(ctx: &XdpContext) -> Option<([u8; 16], u16)> {
    let eth = at(ctx, 0, ETH_LEN)?;
    // SAFETY: `at` checked ETH_LEN (14) octets at `eth`; 12 + 2 <= 14.
    match u16::from_be(unsafe { read_u16(eth.add(12)) }) {
        ETH_P_IPV4 => {
            let ip = at(ctx, ETH_LEN, IPV4_LEN + UDP_LEN)?;
            // SAFETY: `at` checked IPV4_LEN + UDP_LEN (28) octets at `ip`;
            // 0, 9 and 6 + 2 are inside.
            let (vihl, proto, frag) =
                unsafe { (*ip, *ip.add(9), u16::from_be(read_u16(ip.add(6))) & 0x3fff) };
            if vihl != 0x45 || proto != IPPROTO_UDP || frag != 0 {
                return None;
            }
            // SAFETY: as above; 16..20 is inside.
            let d = unsafe { [*ip.add(16), *ip.add(17), *ip.add(18), *ip.add(19)] };
            // SAFETY: as above; IPV4_LEN + 2 + 2 <= 28.
            let port = u16::from_be(unsafe { read_u16(ip.add(IPV4_LEN + 2)) });
            Some((mapped(d), port))
        }
        ETH_P_IPV6 => {
            let ip = at(ctx, ETH_LEN, IPV6_LEN + UDP_LEN)?;
            // SAFETY: `at` checked IPV6_LEN + UDP_LEN (48) octets at `ip`;
            // 0 and 6 are inside.
            if unsafe { *ip } >> 4 != 6 || unsafe { *ip.add(6) } != IPPROTO_UDP {
                return None;
            }
            let mut dst = [0u8; 16];
            for (i, b) in dst.iter_mut().enumerate() {
                // SAFETY: as above; 24 + 15 < 48.
                *b = unsafe { *ip.add(24 + i) };
            }
            if dst[..12] == V4_MAPPED {
                return None;
            }
            // SAFETY: as above; IPV6_LEN + 2 + 2 <= 48.
            let port = u16::from_be(unsafe { read_u16(ip.add(IPV6_LEN + 2)) });
            Some((dst, port))
        }
        _ => None,
    }
}

/// A pointer to `len` bytes at `offset`, if they lie inside the packet.
#[inline(always)]
fn at(ctx: &XdpContext, offset: usize, len: usize) -> Option<*mut u8> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *mut u8)
}

/// Two octets at `p`.
///
/// # Safety
///
/// `p` and the octet after it lie inside the packet (a region [`at`]
/// checked).
#[inline(always)]
unsafe fn read_u16(p: *const u8) -> u16 {
    // SAFETY: the caller's contract: two octets at `p`.
    unsafe { u16::from_ne_bytes([*p, *p.add(1)]) }
}

/// Four octets at `p`.
///
/// # Safety
///
/// `p` and the three octets after it lie inside the packet.
#[inline(always)]
unsafe fn read_u32(p: *const u8) -> u32 {
    // SAFETY: the caller's contract: four octets at `p`.
    unsafe { u32::from_ne_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]) }
}

/// Write two octets at `p`.
///
/// # Safety
///
/// As [`read_u16`].
#[inline(always)]
unsafe fn write_u16(p: *mut u8, v: u16) {
    let b = v.to_ne_bytes();
    // SAFETY: the caller's contract: two octets at `p`.
    unsafe {
        *p = b[0];
        *p.add(1) = b[1];
    }
}

/// Write four octets at `p`.
///
/// # Safety
///
/// As [`read_u32`].
#[inline(always)]
unsafe fn write_u32(p: *mut u8, v: u32) {
    let b = v.to_ne_bytes();
    // SAFETY: the caller's contract: four octets at `p`.
    unsafe {
        *p = b[0];
        *p.add(1) = b[1];
        *p.add(2) = b[2];
        *p.add(3) = b[3];
    }
}

fn try_relay(ctx: &XdpContext) -> Option<u32> {
    let eth = at(ctx, 0, ETH_LEN)?;
    // SAFETY: `at` checked ETH_LEN (14) octets at `eth`; 12 + 2 <= 14.
    let v6 = match u16::from_be(unsafe { read_u16(eth.add(12)) }) {
        ETH_P_IPV4 => false,
        ETH_P_IPV6 => true,
        _ => return None,
    };
    let (key, action, ip, udp) = if v6 { lookup6(ctx)? } else { lookup4(ctx)? };
    let payload = if v6 {
        ETH_LEN + IPV6_LEN + UDP_LEN
    } else {
        ETH_LEN + IPV4_LEN + UDP_LEN
    };
    // The RTP marker and payload type, when there are two payload octets.
    // SAFETY: `at` checked the one octet at `p`.
    let second = at(ctx, payload + 1, 1).map(|p| unsafe { *p });
    let decision = decide(&action, second);
    if decision == Decision::Up {
        return Some(xdp_action::XDP_PASS);
    }
    if action.flags & flags::RECORD != 0 {
        record(ctx, &key, payload);
    }
    count(&key, (ctx.data_end() - ctx.data()) as u64);
    if decision == Decision::Drop {
        return Some(xdp_action::XDP_DROP);
    }
    // SAFETY: `ip` is the header `lookup6`/`lookup4` checked with `at`
    // (IPV6_LEN or IPV4_LEN octets), as `rewrite6`/`rewrite4` require.
    unsafe {
        if v6 {
            rewrite6(ip, &action);
        } else {
            rewrite4(ip, &action);
        }
    }

    // UDP: ports, and the checksum, which covers the pseudo-header
    // addresses too. `udp` is the UDP_LEN (8) octets `lookup4`/`lookup6`
    // checked with `at`.
    // SAFETY: (all four) 0 + 2, 2 + 2 and 6 + 2 are inside those 8 octets.
    let udp_check_p = unsafe { udp.add(6) };
    // SAFETY: as above.
    let check = udp_check_update(u16::from_be(unsafe { read_u16(udp_check_p) }), &key, &action);
    // SAFETY: as above.
    unsafe { write_u16(udp_check_p, check.to_be()) };
    // SAFETY: as above.
    unsafe { write_u16(udp, action.new_src_port) };
    // SAFETY: as above.
    unsafe { write_u16(udp.add(2), action.new_dst_port) };

    // Ethernet.
    for i in 0..6 {
        // SAFETY: `at` checked ETH_LEN (14) octets at `eth`; i and 6 + i
        // are below 12.
        unsafe {
            *eth.add(i) = action.dst_mac[i];
            *eth.add(6 + i) = action.src_mac[i];
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "device indexes are u32; bpf_redirect returns an XDP action (0..=4)"
    )]
    match egress(action.ifindex, ctx.ingress_ifindex() as u32) {
        Egress::Tx => Some(xdp_action::XDP_TX),
        Egress::Redirect(ifindex) => {
            // SAFETY: a helper call with plain integer arguments; it returns
            // XDP_REDIRECT, or XDP_ABORTED for a bad device.
            Some(unsafe { aya_ebpf::helpers::bpf_redirect(ifindex, 0) } as u32)
        }
    }
}

/// Copy the datagram's payload (from `payload`, at most `RECORD_MAX`
/// octets) and its flow into the recording ring. A full ring drops the
/// copy, never the datagram.
#[inline(always)]
fn record(ctx: &XdpContext, key: &FlowKey, payload: usize) {
    let total = ctx.data_end() - ctx.data();
    if total <= payload {
        return;
    }
    let mut len = total - payload;
    // Up to the UDP length: a short frame's Ethernet padding is no payload.
    let Some(udp_len) = at(ctx, payload - UDP_LEN + 4, 2) else {
        return;
    };
    // SAFETY: `at` checked the two octets at `udp_len`.
    let udp_payload =
        usize::from(u16::from_be(unsafe { read_u16(udp_len) })).saturating_sub(UDP_LEN);
    if udp_payload < len {
        len = udp_payload;
    }
    if len == 0 {
        return;
    }
    if len > RECORD_MAX {
        len = RECORD_MAX;
    }
    let Some(mut entry) = RECORD.reserve(0) else {
        return;
    };
    let sample = entry.as_mut_ptr();
    #[allow(
        clippy::cast_possible_truncation,
        reason = "len <= RECORD_MAX (1504) and payload <= 62, a header offset"
    )]
    // SAFETY: `sample` points to reserved ring memory the size of a
    // `RecordSample`, writable until it is submitted or discarded; the
    // copy writes at most `RECORD_MAX` octets into its `data` array.
    let copied = unsafe {
        (*sample).key = *key;
        (*sample).len = len as u16;
        (*sample).reserved = 0;
        (*sample).time_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        aya_ebpf::helpers::bpf_xdp_load_bytes(
            ctx.ctx,
            payload as u32,
            core::ptr::addr_of_mut!((*sample).data).cast(),
            len as u32,
        )
    };
    if copied == 0 {
        entry.submit(0);
    } else {
        entry.discard(0);
    }
}

/// IPv4: check and look up. Returns the key, the action, and the IP and
/// UDP headers.
#[inline(always)]
fn lookup4(ctx: &XdpContext) -> Option<(FlowKey, FlowAction, *mut u8, *mut u8)> {
    let ip = at(ctx, ETH_LEN, IPV4_LEN)?;
    // `at` checked IPV4_LEN (20) octets at `ip`, UDP_LEN (8) at `udp` and
    // one at `first`; every offset read below is inside its region.
    // SAFETY: octet 0 of 20.
    if unsafe { *ip } != 0x45 {
        return None; // not IPv4 or carries options
    }
    // SAFETY: octet 9 of 20.
    if unsafe { *ip.add(9) } != IPPROTO_UDP {
        return None;
    }
    // Fragment offset and MF must be zero: only whole datagrams.
    // SAFETY: octets 6..8 of 20.
    if u16::from_be(unsafe { read_u16(ip.add(6)) }) & 0x3fff != 0 {
        return None;
    }
    let udp = at(ctx, ETH_LEN + IPV4_LEN, UDP_LEN)?;
    let first = at(ctx, ETH_LEN + IPV4_LEN + UDP_LEN, 1)?;
    // SAFETY: the one octet at `first`.
    if !is_rtp_v2(unsafe { *first }) {
        return None;
    }
    // SAFETY: octets 12..16 of 20.
    let old_src = unsafe { read_u32(ip.add(12)) };
    // SAFETY: octets 16..20 of 20.
    let old_dst = unsafe { read_u32(ip.add(16)) };
    let key = FlowKey {
        src_addr: mapped(old_src.to_ne_bytes()),
        dst_addr: mapped(old_dst.to_ne_bytes()),
        // SAFETY: octets 0..2 and 2..4 of `udp`'s 8.
        src_port: unsafe { read_u16(udp) },
        // SAFETY: as above.
        dst_port: unsafe { read_u16(udp.add(2)) },
    };
    // SAFETY: the map value is only read.
    let action = *unsafe { FLOWS.get(&key) }?;
    Some((key, action, ip, udp))
}

/// IPv4: rewrite TTL, addresses and header checksum.
///
/// # Safety
///
/// `ip` points to the `IPV4_LEN` (20) octets of the header, inside the
/// packet (as `lookup4` returns it).
#[inline(always)]
unsafe fn rewrite4(ip: *mut u8, action: &FlowAction) {
    // SAFETY: octets 12..16 of the header's 20.
    let old_src = unsafe { read_u32(ip.add(12)) };
    // SAFETY: octets 16..20 of the header's 20.
    let old_dst = unsafe { read_u32(ip.add(16)) };
    let new_src = u32::from_ne_bytes([
        action.new_src_addr[12],
        action.new_src_addr[13],
        action.new_src_addr[14],
        action.new_src_addr[15],
    ]);
    let new_dst = u32::from_ne_bytes([
        action.new_dst_addr[12],
        action.new_dst_addr[13],
        action.new_dst_addr[14],
        action.new_dst_addr[15],
    ]);

    // TTL, addresses, header checksum (on big-endian words). Every offset
    // below is inside the header's 20 octets.
    // SAFETY: octets 10..12.
    let ip_check_p = unsafe { ip.add(10) };
    // SAFETY: as above.
    let mut ip_check = u16::from_be(unsafe { read_u16(ip_check_p) });
    // SAFETY: octets 8..10.
    let ttl_proto_p = unsafe { ip.add(8) };
    // SAFETY: as above.
    let old_ttl_proto = u16::from_be(unsafe { read_u16(ttl_proto_p) });
    let new_ttl_proto = (u16::from(FRESH_TTL) << 8) | u16::from(IPPROTO_UDP);
    ip_check = csum_replace2(ip_check, old_ttl_proto, new_ttl_proto);
    // SAFETY: octets 8..10.
    unsafe { write_u16(ttl_proto_p, new_ttl_proto.to_be()) };
    ip_check = csum_replace4(ip_check, u32::from_be(old_src), u32::from_be(new_src));
    ip_check = csum_replace4(ip_check, u32::from_be(old_dst), u32::from_be(new_dst));
    // SAFETY: octets 12..16.
    unsafe { write_u32(ip.add(12), new_src) };
    // SAFETY: octets 16..20.
    unsafe { write_u32(ip.add(16), new_dst) };
    // SAFETY: octets 10..12.
    unsafe { write_u16(ip_check_p, ip_check.to_be()) };
}

/// Read 16 octets.
///
/// # Safety
///
/// `p` and the 15 octets after it lie inside the packet.
#[inline(always)]
unsafe fn read16(p: *const u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    for (i, b) in a.iter_mut().enumerate() {
        // SAFETY: the caller's contract: 16 octets at `p`, `i` < 16.
        *b = unsafe { *p.add(i) };
    }
    a
}

/// Write 16 octets.
///
/// # Safety
///
/// As [`read16`].
#[inline(always)]
unsafe fn write16(p: *mut u8, a: &[u8; 16]) {
    for (i, b) in a.iter().enumerate() {
        // SAFETY: the caller's contract: 16 octets at `p`, `i` < 16.
        unsafe { *p.add(i) = *b };
    }
}

/// IPv6: check and look up. Returns the key, the action, and the IP and
/// UDP headers.
#[inline(always)]
fn lookup6(ctx: &XdpContext) -> Option<(FlowKey, FlowAction, *mut u8, *mut u8)> {
    let ip = at(ctx, ETH_LEN, IPV6_LEN)?;
    // `at` checked IPV6_LEN (40) octets at `ip`, UDP_LEN (8) at `udp` and
    // one at `first`; every offset read below is inside its region.
    // SAFETY: octet 0 of 40.
    if unsafe { *ip } >> 4 != 6 {
        return None;
    }
    // UDP right after the fixed header; extension headers go to the stack.
    // SAFETY: octet 6 of 40.
    if unsafe { *ip.add(6) } != IPPROTO_UDP {
        return None;
    }
    let udp = at(ctx, ETH_LEN + IPV6_LEN, UDP_LEN)?;
    // A zero UDP checksum is not allowed over IPv6 (RFC 8200 §8.1).
    // SAFETY: octets 6..8 of `udp`'s 8.
    if unsafe { read_u16(udp.add(6)) } == 0 {
        return None;
    }
    let first = at(ctx, ETH_LEN + IPV6_LEN + UDP_LEN, 1)?;
    // SAFETY: the one octet at `first`.
    if !is_rtp_v2(unsafe { *first }) {
        return None;
    }
    // SAFETY: octets 8..24 of 40.
    let src = unsafe { read16(ip.add(8)) };
    // SAFETY: octets 24..40 of 40.
    let dst = unsafe { read16(ip.add(24)) };
    // IPv4-mapped addresses never appear on the wire; they would collide
    // with the IPv4 keys.
    if is_mapped(&src) || is_mapped(&dst) {
        return None;
    }
    let key = FlowKey {
        src_addr: src,
        dst_addr: dst,
        // SAFETY: octets 0..2 and 2..4 of `udp`'s 8.
        src_port: unsafe { read_u16(udp) },
        // SAFETY: as above.
        dst_port: unsafe { read_u16(udp.add(2)) },
    };
    // SAFETY: the map value is only read.
    let action = *unsafe { FLOWS.get(&key) }?;
    Some((key, action, ip, udp))
}

/// IPv6: rewrite hop limit and addresses (there is no header checksum).
///
/// # Safety
///
/// `ip` points to the `IPV6_LEN` (40) octets of the header, inside the
/// packet (as `lookup6` returns it).
#[inline(always)]
unsafe fn rewrite6(ip: *mut u8, action: &FlowAction) {
    // SAFETY: octet 7 of the header's 40.
    unsafe { *ip.add(7) = FRESH_TTL };
    // SAFETY: octets 8..24 of 40.
    unsafe { write16(ip.add(8), &action.new_src_addr) };
    // SAFETY: octets 24..40 of 40.
    unsafe { write16(ip.add(24), &action.new_dst_addr) };
}

#[inline(always)]
fn is_mapped(a: &[u8; 16]) -> bool {
    a[..10].iter().all(|&b| b == 0) && a[10] == 0xff && a[11] == 0xff
}

/// Account for a relayed (or dropped) frame of `len` octets.
#[inline(always)]
fn count(key: &FlowKey, len: u64) {
    let Some(stats) = STATS.get_ptr_mut(key) else {
        return;
    };
    // SAFETY: `stats` points to this CPU's copy of a live `FlowStats` map
    // value for the duration of the run; no other CPU writes this copy, and
    // the program is not preempted on its CPU, so plain updates are exclusive.
    unsafe {
        (*stats).packets += 1;
        (*stats).bytes += len;
        (*stats).last_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
