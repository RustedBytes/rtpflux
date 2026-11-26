//! Userspace side of the XDP fast path: turning a relayed media stream into
//! forwarding-map entries ([`entry`]), loading the
//! program and managing its map ([`loader`]), and test frames for the
//! `xdp-selftest` tool ([`testframe`]).

// The `unsafe` this crate has (`pod`, `xsk`) says why it is sound, one
// operation at a time (AGENTS.md §5).
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]

pub mod loader;
pub mod neigh;
mod pod;
pub mod testframe;
#[cfg(feature = "af-xdp")]
pub mod xsk;

use core::net::{IpAddr, SocketAddr};
use rtpflux_xdp_common::{FlowAction, FlowKey, mapped};

/// One direction of a relayed stream, as the userspace relay has latched it:
/// datagrams from `peer` arriving at the relay's `local` port are sent from
/// the relay's `out_local` port to `target`, out of device `ifindex`.
/// `peer` and `local` share a family, as do `out_local` and `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Direction {
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub out_local: SocketAddr,
    pub target: SocketAddr,
    /// MAC address of the relay's interface that sends.
    pub own_mac: [u8; 6],
    /// MAC address of the next hop towards `target` (from the neighbour table).
    pub next_hop_mac: [u8; 6],
    /// The sending device (0: the arrival device).
    pub ifindex: u32,
    /// `rtpflux_xdp_common::flags`, and the telephone-event payload type
    /// they refer to.
    pub flags: u8,
    pub event_pt: u8,
}

/// An address as the map holds it: IPv4 as IPv4-mapped.
#[must_use]
pub fn addr(a: IpAddr) -> [u8; 16] {
    match a {
        IpAddr::V4(v4) => mapped(v4.octets()),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn port(p: u16) -> u16 {
    u16::from_ne_bytes(p.to_be_bytes())
}

/// The map entry for one direction, or `None` when it would change the
/// family (the frame keeps its header layout, so that stays in userspace).
/// Fields are in network byte order, as the XDP program reads them
/// straight from the packet.
#[must_use]
pub fn entry(d: &Direction) -> Option<(FlowKey, FlowAction)> {
    // An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) never appears on the
    // wire, and would be stored as IPv4 in a key of an IPv6 flow.
    let mapped = |a: std::net::SocketAddr| match a.ip() {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
        std::net::IpAddr::V4(_) => false,
    };
    if d.peer.is_ipv4() != d.local.is_ipv4()
        || d.out_local.is_ipv4() != d.target.is_ipv4()
        || d.peer.is_ipv4() != d.target.is_ipv4()
        || [d.peer, d.local, d.out_local, d.target]
            .into_iter()
            .any(mapped)
    {
        return None;
    }
    Some((
        FlowKey {
            src_addr: addr(d.peer.ip()),
            dst_addr: addr(d.local.ip()),
            src_port: port(d.peer.port()),
            dst_port: port(d.local.port()),
        },
        FlowAction {
            new_src_addr: addr(d.out_local.ip()),
            new_dst_addr: addr(d.target.ip()),
            new_src_port: port(d.out_local.port()),
            new_dst_port: port(d.target.port()),
            src_mac: d.own_mac,
            dst_mac: d.next_hop_mac,
            ifindex: d.ifindex,
            flags: d.flags,
            event_pt: d.event_pt,
            reserved: [0; 2],
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn dir(peer: &str, local: &str, out_local: &str, target: &str) -> Direction {
        Direction {
            peer: sa(peer),
            local: sa(local),
            out_local: sa(out_local),
            target: sa(target),
            own_mac: [2, 0, 0, 0, 0, 1],
            next_hop_mac: [2, 0, 0, 0, 0, 2],
            ifindex: 5,
            flags: rtpflux_xdp_common::flags::EVENTS_UP,
            event_pt: 101,
        }
    }

    #[test]
    fn fields_are_network_order() {
        let (k, a) = entry(&dir(
            "192.0.2.10:4000",
            "198.51.100.1:30000",
            "198.51.100.1:30002",
            "203.0.113.5:5004",
        ))
        .unwrap();
        // The bytes in memory are the bytes on the wire.
        assert_eq!(k.src_addr, mapped([192, 0, 2, 10]));
        assert_eq!(k.src_port.to_ne_bytes(), 4000u16.to_be_bytes());
        assert_eq!(k.dst_port.to_ne_bytes(), 30000u16.to_be_bytes());
        assert_eq!((a.ifindex, a.flags, a.event_pt), (5, 2, 101));
        let (k6, _) = entry(&dir(
            "[2001:db8::10]:4000",
            "[2001:db8::1]:30000",
            "[2001:db8::1]:30002",
            "[2001:db8::5]:5004",
        ))
        .unwrap();
        assert_eq!(k6.src_addr[..4], [0x20, 0x01, 0x0d, 0xb8]);
    }

    #[test]
    fn the_family_never_changes() {
        assert!(
            entry(&dir(
                "192.0.2.10:4000",
                "198.51.100.1:30000",
                "[2001:db8::1]:30002",
                "[2001:db8::5]:5004",
            ))
            .is_none()
        );
        // IPv4-mapped IPv6 addresses are not offloaded, wherever they are.
        for (i, mapped) in ["[::ffff:192.0.2.10]:4000"; 4].iter().enumerate() {
            let mut a = [
                "[2001:db8::10]:4000",
                "[2001:db8::1]:30000",
                "[2001:db8::1]:30002",
                "[2001:db8::5]:5004",
            ];
            a[i] = mapped;
            assert!(entry(&dir(a[0], a[1], a[2], a[3])).is_none(), "{a:?}");
        }
    }
}
