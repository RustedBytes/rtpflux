//! MAC addresses for the XDP rewrite: the relay's own interface address and
//! the next hop's, from the kernel's tables.
//!
//! * own MAC: `/sys/class/net/<dev>/address`;
//! * next hop: `/proc/net/route` (longest prefix on the device; a zero
//!   gateway means the destination is on-link);
//! * its MAC: `/proc/net/arp` (complete entries only);
//! * which device owns an address: `getifaddrs`.
//!
//! IPv6: routes from `/proc/net/ipv6_route` (longest prefix on the device;
//! a zero next hop means on-link) and neighbours from a netlink
//! `RTM_GETNEIGH` dump (entries with a link-layer address in a usable
//! state). The parsers are pure and tested on sample text and messages;
//! the readers only fetch the files and the dump.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A route from `/proc/net/route` (addresses as host-order octets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub device: String,
    pub destination: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// Lower is preferred among equally specific routes.
    pub metric: u32,
}

/// A complete ARP entry from `/proc/net/arp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub device: String,
}

/// Parse `aa:bb:cc:dd:ee:ff`.
#[must_use]
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.trim().split(':');
    for b in &mut mac {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// `/proc/net/route` prints each address as the hex of its in-memory
/// (network-order) `u32` read on a little-endian host.
fn proc_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(v.to_le_bytes()))
}

/// Parse `/proc/net/route` (up routes only).
#[must_use]
pub fn parse_routes(text: &str) -> Vec<Route> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 {
                return None;
            }
            let flags = u32::from_str_radix(f[3], 16).ok()?;
            if flags & 0x1 == 0 {
                return None; // RTF_UP
            }
            Some(Route {
                device: f[0].to_owned(),
                destination: proc_ipv4(f[1])?,
                gateway: proc_ipv4(f[2])?,
                mask: proc_ipv4(f[7])?,
                metric: f[6].parse().ok()?,
            })
        })
        .collect()
}

/// Parse `/proc/net/arp` (complete entries only, flag `0x2`).
#[must_use]
pub fn parse_arp(text: &str) -> Vec<Neighbour> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).ok()?;
            if flags & 0x2 == 0 {
                return None; // ATF_COM
            }
            Some(Neighbour {
                ip: f[0].parse().ok()?,
                mac: parse_mac(f[3])?,
                device: f[5].to_owned(),
            })
        })
        .collect()
}

/// The next hop towards `dst` through `device`: the gateway of the longest
/// matching route on that device (the lowest metric among equals, as the
/// kernel chooses), or `dst` itself for an on-link route. Policy routing
/// (`ip rule`, tables other than main) is not followed.
#[must_use]
pub fn next_hop(routes: &[Route], device: &str, dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let d = u32::from(dst);
    routes
        .iter()
        .filter(|r| {
            r.device == device
                && d & u32::from(r.mask) == u32::from(r.destination) & u32::from(r.mask)
        })
        .max_by_key(|r| (u32::from(r.mask).count_ones(), core::cmp::Reverse(r.metric)))
        .map(|r| {
            if r.gateway.is_unspecified() {
                dst
            } else {
                r.gateway
            }
        })
}

/// The MAC of `ip` on `device`, from parsed ARP entries.
#[must_use]
pub fn mac_of(neighbours: &[Neighbour], device: &str, ip: Ipv4Addr) -> Option<[u8; 6]> {
    neighbours
        .iter()
        .find(|n| n.device == device && n.ip == ip)
        .map(|n| n.mac)
}

/// The MAC address of `device`.
#[must_use]
pub fn device_mac(device: &str) -> Option<[u8; 6]> {
    if device.contains('/') || device.contains("..") {
        return None;
    }
    parse_mac(&std::fs::read_to_string(format!("/sys/class/net/{device}/address")).ok()?)
}

/// The MAC address of the next hop from `device` towards `dst`, if the
/// kernel has resolved it.
#[must_use]
pub fn next_hop_mac(device: &str, dst: IpAddr) -> Option<[u8; 6]> {
    Tables::read().next_hop_mac(device, dst)
}

/// The kernel's routes and neighbours, read once: many next hops can then
/// be resolved without reading them again.
#[derive(Debug, Clone, Default)]
pub struct Tables {
    pub routes: Vec<Route>,
    pub arp: Vec<Neighbour>,
    pub routes6: Vec<Route6>,
    pub neighbours6: Vec<Neighbour6>,
}

impl Tables {
    /// Read them now (a table that cannot be read is empty).
    #[must_use]
    pub fn read() -> Self {
        let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        Tables {
            routes: parse_routes(&read("/proc/net/route")),
            arp: parse_arp(&read("/proc/net/arp")),
            routes6: parse_routes6(&read("/proc/net/ipv6_route")),
            neighbours6: neighbours6().unwrap_or_default(),
        }
    }

    /// The MAC of the next hop from `device` towards `dst`.
    #[must_use]
    pub fn next_hop_mac(&self, device: &str, dst: IpAddr) -> Option<[u8; 6]> {
        match dst {
            IpAddr::V4(dst) => {
                let hop = next_hop(&self.routes, device, dst)?;
                mac_of(&self.arp, device, hop)
            }
            IpAddr::V6(dst) => {
                let hop = next_hop6(&self.routes6, device, dst)?;
                let index = ifindex(device)?;
                self.neighbours6
                    .iter()
                    .find(|n| n.ifindex == index && n.ip == hop)
                    .map(|n| n.mac)
            }
        }
    }
}

/// The interface index of `device`.
#[must_use]
pub fn ifindex(device: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(device)
        .ok()
        .filter(|&i| i != 0)
}

/// A route from `/proc/net/ipv6_route`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route6 {
    pub device: String,
    pub destination: Ipv6Addr,
    pub prefix_len: u8,
    /// `::` when the destination is on-link.
    pub next_hop: Ipv6Addr,
    /// Lower is preferred among equally specific routes.
    pub metric: u32,
}

fn proc_ipv6(hex: &str) -> Option<Ipv6Addr> {
    (hex.len() == 32).then_some(())?;
    u128::from_str_radix(hex, 16).ok().map(Ipv6Addr::from)
}

/// Parse `/proc/net/ipv6_route`: destination, prefix length, source,
/// source prefix length, next hop, metric, reference count, use, flags,
/// device. Routes not up (`RTF_UP`) and reject routes are skipped.
#[must_use]
pub fn parse_routes6(text: &str) -> Vec<Route6> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let flags = u32::from_str_radix(f[8], 16).ok()?;
            if flags & 0x1 == 0 || flags & 0x200 != 0 {
                return None; // not RTF_UP, or RTF_REJECT
            }
            Some(Route6 {
                device: f[9].to_owned(),
                destination: proc_ipv6(f[0])?,
                prefix_len: u8::from_str_radix(f[1], 16).ok().filter(|&p| p <= 128)?,
                next_hop: proc_ipv6(f[4])?,
                metric: u32::from_str_radix(f[5], 16).ok()?,
            })
        })
        .collect()
}

/// The next hop from `device` towards `dst`: the longest matching prefix
/// on the device (the lowest metric among equals); its next hop, or `dst`
/// itself when on-link.
#[must_use]
pub fn next_hop6(routes: &[Route6], device: &str, dst: Ipv6Addr) -> Option<Ipv6Addr> {
    let mask = |len: u8| u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
    let d = u128::from(dst);
    routes
        .iter()
        .filter(|r| {
            r.device == device
                && d & mask(r.prefix_len) == u128::from(r.destination) & mask(r.prefix_len)
        })
        .max_by_key(|r| (r.prefix_len, core::cmp::Reverse(r.metric)))
        .map(|r| {
            if r.next_hop.is_unspecified() {
                dst
            } else {
                r.next_hop
            }
        })
}

/// An IPv6 neighbour with a link-layer address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour6 {
    pub ifindex: u32,
    pub ip: Ipv6Addr,
    pub mac: [u8; 6],
}

const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const AF_INET6: u8 = 10;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
/// `NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT`:
/// states whose link-layer address can be used.
const NUD_USABLE: u16 = 0x02 | 0x04 | 0x08 | 0x10 | 0x80;

/// The `RTM_GETNEIGH` dump request for IPv6 (`nlmsghdr` + `ndmsg`).
#[must_use]
pub fn neigh_request(seq: u32) -> [u8; 28] {
    let mut m = [0u8; 28];
    m[0..4].copy_from_slice(&28u32.to_ne_bytes());
    m[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    m[6..8].copy_from_slice(&(0x1u16 | 0x300).to_ne_bytes()); // NLM_F_REQUEST | NLM_F_DUMP
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    m[16] = AF_INET6;
    m
}

fn ne16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn ne32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

/// Parse one datagram of a neighbour dump: the usable IPv6 entries, and
/// whether the dump is complete (`NLMSG_DONE` or an error).
#[must_use]
pub fn parse_neigh_dump(buf: &[u8]) -> (Vec<Neighbour6>, bool) {
    let mut out = Vec::new();
    let mut at = 0;
    while let (Some(len), Some(kind)) = (ne32(buf, at), ne16(buf, at + 4)) {
        let len = len as usize;
        if len < 16 || at + len > buf.len() {
            return (out, true);
        }
        match kind {
            NLMSG_DONE | NLMSG_ERROR => return (out, true),
            RTM_NEWNEIGH => {
                if let Some(n) = neighbour(&buf[at + 16..at + len]) {
                    out.push(n);
                }
            }
            _ => {}
        }
        at += (len + 3) & !3;
    }
    (out, false)
}

/// An `ndmsg` and its attributes.
fn neighbour(m: &[u8]) -> Option<Neighbour6> {
    if *m.first()? != AF_INET6 || ne16(m, 8)? & NUD_USABLE == 0 {
        return None;
    }
    let ifindex = ne32(m, 4)?;
    let (mut ip, mut mac) = (None, None);
    let mut at = 12;
    while let (Some(len), Some(kind)) = (ne16(m, at), ne16(m, at + 2)) {
        let len = usize::from(len);
        let value = m.get(at + 4..at + len)?;
        match kind {
            NDA_DST => ip = <[u8; 16]>::try_from(value).ok().map(Ipv6Addr::from),
            NDA_LLADDR => mac = <[u8; 6]>::try_from(value).ok(),
            _ => {}
        }
        if len < 4 {
            return None;
        }
        at += (len + 3) & !3;
    }
    Some(Neighbour6 {
        ifindex,
        ip: ip?,
        mac: mac?,
    })
}

/// The kernel's IPv6 neighbours (a netlink dump).
#[must_use]
pub fn neighbours6() -> Option<Vec<Neighbour6>> {
    use nix::sys::socket::{
        AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, send,
        socket,
    };
    use std::os::fd::AsRawFd;
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )
    .ok()?;
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0)).ok()?;
    send(fd.as_raw_fd(), &neigh_request(1), MsgFlags::empty()).ok()?;
    let mut all = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    for _ in 0..1024 {
        let n = recv(fd.as_raw_fd(), &mut buf, MsgFlags::empty()).ok()?;
        let (found, done) = parse_neigh_dump(&buf[..n]);
        all.extend(found);
        if done || n == 0 {
            return Some(all);
        }
    }
    Some(all)
}

/// The network device that holds `ip`.
#[must_use]
pub fn device_of(ip: IpAddr) -> Option<String> {
    nix::ifaddrs::getifaddrs().ok()?.find_map(|ifa| {
        let a = ifa.address?;
        let owns = match ip {
            IpAddr::V4(v4) => a.as_sockaddr_in().is_some_and(|s| s.ip() == v4),
            IpAddr::V6(v6) => a.as_sockaddr_in6().is_some_and(|s| s.ip() == v6),
        };
        owns.then_some(ifa.interface_name)
    })
}

/// How many receive queues device `device` has (from sysfs; 1 when it
/// cannot be told).
#[must_use]
pub fn rx_queues(device: &str) -> u32 {
    let dir = std::path::Path::new("/sys/class/net")
        .join(device)
        .join("queues");
    let n = std::fs::read_dir(dir).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("rx-"))
            .count()
    });
    u32::try_from(n).unwrap_or(u32::MAX).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0102000A\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0002000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth1\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
eth1\t0001A8C0\t00000000\t0000\t0\t0\t0\t00FFFFFF\t0\t0\t0
";

    const ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
10.0.2.1         0x1         0x2         52:54:00:12:35:02     *        eth0
10.0.2.77        0x1         0x2         52:54:00:aa:bb:cc     *        eth0
192.168.0.9      0x1         0x0         00:00:00:00:00:00     *        eth1
";

    #[test]
    fn macs() {
        assert_eq!(
            parse_mac("52:54:00:12:35:02\n"),
            Some([0x52, 0x54, 0, 0x12, 0x35, 2])
        );
        assert_eq!(parse_mac("52:54:00:12:35"), None);
        assert_eq!(parse_mac("52:54:00:12:35:02:01"), None);
        assert_eq!(parse_mac("zz:54:00:12:35:02"), None);
    }

    #[test]
    fn routes() {
        let r = parse_routes(ROUTE);
        assert_eq!(r.len(), 3, "the down route is skipped");
        assert_eq!(r[0].gateway, Ipv4Addr::new(10, 0, 2, 1));
        assert_eq!(r[1].destination, Ipv4Addr::new(10, 0, 2, 0));
        assert_eq!(r[1].mask, Ipv4Addr::new(255, 255, 255, 0));
        // on-link destination: itself
        assert_eq!(
            next_hop(&r, "eth0", Ipv4Addr::new(10, 0, 2, 77)),
            Some(Ipv4Addr::new(10, 0, 2, 77))
        );
        // elsewhere: the default gateway
        assert_eq!(
            next_hop(&r, "eth0", Ipv4Addr::new(203, 0, 113, 5)),
            Some(Ipv4Addr::new(10, 0, 2, 1))
        );
        // no route on that device
        assert_eq!(next_hop(&r, "eth1", Ipv4Addr::new(203, 0, 113, 5)), None);
        // the down 192.168.1.0/24 route on eth1 is ignored
        assert_eq!(next_hop(&r, "eth1", Ipv4Addr::new(192, 168, 1, 3)), None);
    }

    #[test]
    fn arp() {
        let n = parse_arp(ARP);
        assert_eq!(n.len(), 2, "incomplete entries are skipped");
        assert_eq!(
            mac_of(&n, "eth0", Ipv4Addr::new(10, 0, 2, 1)),
            Some([0x52, 0x54, 0, 0x12, 0x35, 2])
        );
        assert_eq!(mac_of(&n, "eth1", Ipv4Addr::new(10, 0, 2, 1)), None);
        assert_eq!(mac_of(&n, "eth1", Ipv4Addr::new(192, 168, 0, 9)), None);
    }

    #[test]
    fn loopback_device() {
        assert_eq!(
            device_of(IpAddr::V4(Ipv4Addr::LOCALHOST)).as_deref(),
            Some("lo")
        );
        assert!(device_mac("../etc").is_none());
    }

    const ROUTE6: &str = "\
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0
20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000201 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
";

    #[test]
    fn routes6() {
        let r = parse_routes6(ROUTE6);
        assert_eq!(r.len(), 2, "{r:?}"); // the reject routes are skipped
        let on_link: Ipv6Addr = "2001:db8::77".parse().unwrap();
        assert_eq!(next_hop6(&r, "eth0", on_link), Some(on_link));
        let far: Ipv6Addr = "2001:db8:1::5".parse().unwrap();
        assert_eq!(next_hop6(&r, "eth0", far), Some("fe80::1".parse().unwrap()));
        assert_eq!(next_hop6(&r, "eth1", far), None);
    }

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&u16::try_from(4 + value.len()).unwrap().to_ne_bytes());
        a.extend_from_slice(&kind.to_ne_bytes());
        a.extend_from_slice(value);
        while a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    fn neigh_msg(ifindex: u32, state: u16, ip: Ipv6Addr, mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut body = vec![AF_INET6, 0, 0, 0];
        body.extend_from_slice(&ifindex.to_ne_bytes());
        body.extend_from_slice(&state.to_ne_bytes());
        body.extend_from_slice(&[0, 1]);
        body.extend(attr(NDA_DST, &ip.octets()));
        if let Some(m) = mac {
            body.extend(attr(NDA_LLADDR, &m));
        }
        body.extend(attr(9, &[1, 2, 3, 4])); // NDA_PROBES, ignored
        let mut m = Vec::new();
        m.extend_from_slice(&u32::try_from(16 + body.len()).unwrap().to_ne_bytes());
        m.extend_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
        m.extend_from_slice(&[0; 10]);
        m.extend(body);
        m
    }

    #[test]
    fn neighbour_dump() {
        let mac = [0x52, 0x54, 0, 0xaa, 0xbb, 0xcc];
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut dump = neigh_msg(3, 0x02, ip, Some(mac));
        dump.extend(neigh_msg(3, 0x01, "fe80::2".parse().unwrap(), Some(mac))); // incomplete
        dump.extend(neigh_msg(4, 0x04, "2001:db8::9".parse().unwrap(), None)); // no address
        let (found, done) = parse_neigh_dump(&dump);
        assert_eq!(
            found,
            vec![Neighbour6 {
                ifindex: 3,
                ip,
                mac
            }]
        );
        assert!(!done);
        let mut end = vec![0u8; 20];
        end[0..4].copy_from_slice(&20u32.to_ne_bytes());
        end[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        assert_eq!(parse_neigh_dump(&end), (vec![], true));
        let req = neigh_request(7);
        assert_eq!(u32::from_ne_bytes(req[0..4].try_into().unwrap()), 28);
        assert_eq!(req[16], AF_INET6);
    }

    /// The readers against this host's own tables, on the loopback device
    /// every Linux host has.
    #[test]
    fn this_hosts_loopback() {
        let lo = ifindex("lo").expect("lo has an index");
        assert!(lo > 0);
        assert_eq!(ifindex("no-such-dev0"), None);
        assert_eq!(device_mac("lo"), Some([0; 6]));
        assert_eq!(device_mac("no-such-dev0"), None);
        assert_eq!(device_mac("../lo"), None, "no paths");
        assert_eq!(
            device_of("127.0.0.1".parse().unwrap()).as_deref(),
            Some("lo")
        );
        assert_eq!(device_of("192.0.2.123".parse().unwrap()), None);
        // The netlink dump works unprivileged.
        assert!(neighbours6().is_some());
        // Loopback has no neighbours: nothing to resolve, either family.
        assert_eq!(next_hop_mac("lo", "192.0.2.1".parse().unwrap()), None);
        assert_eq!(next_hop_mac("lo", "::1".parse().unwrap()), None);
    }

    #[test]
    fn equal_routes_go_by_metric() {
        // Two default routes on eth0: the backup (metric 200) is listed
        // last; the kernel uses the primary (metric 100).
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t00000000\t0200000A\t0003\t0\t0\t200\t00000000\t0\t0\t0\n";
        let routes = parse_routes(text);
        assert_eq!(routes.len(), 2);
        assert_eq!(
            next_hop(&routes, "eth0", Ipv4Addr::new(192, 0, 2, 1)),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }
}
