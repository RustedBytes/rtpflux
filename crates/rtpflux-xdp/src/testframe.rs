//! Ethernet / IPv4 or IPv6 / UDP frames with correct checksums, for
//! exercising the fast path (`xdp-selftest`) and checking its output.

use std::net::IpAddr;

/// Sum of big-endian 16-bit words (an odd length is padded with zero).
fn sum16(b: &[u8]) -> u32 {
    b.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum()
}

fn fold(mut s: u32) -> u16 {
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    u16::try_from(s).unwrap_or(0xffff)
}

/// Parameters of a test frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec<'a> {
    /// Source and destination, of one family.
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    /// TTL or hop limit.
    pub ttl: u8,
    /// Compute the UDP checksum (`false` leaves it zero, "no checksum";
    /// over IPv6 that makes an invalid frame).
    pub udp_checksum: bool,
    pub payload: &'a [u8],
}

/// Where the UDP header starts.
fn udp_at(f: &[u8]) -> usize {
    if f.get(12..14) == Some(&[0x86, 0xdd]) {
        54
    } else {
        34
    }
}

/// The pseudo-header's addresses.
fn pseudo(f: &[u8]) -> &[u8] {
    if udp_at(f) == 54 {
        &f[22..54]
    } else {
        &f[26..34]
    }
}

/// Build the frame.
///
/// # Panics
///
/// If the payload is longer than a datagram allows, or the addresses are
/// of different families.
#[must_use]
pub fn build(s: &Spec<'_>) -> Vec<u8> {
    let udp_len = u16::try_from(8 + s.payload.len()).expect("payload too long");
    let mut f = Vec::with_capacity(62 + s.payload.len());
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xaa]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xbb]);
    match (s.src, s.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = udp_len.checked_add(20).expect("payload too long");
            f.extend_from_slice(&0x0800u16.to_be_bytes());
            f.extend_from_slice(&[0x45, 0xb8]);
            f.extend_from_slice(&total.to_be_bytes());
            f.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, s.ttl, 17, 0, 0]);
            f.extend_from_slice(&src.octets());
            f.extend_from_slice(&dst.octets());
            let ip_check = !fold(sum16(&f[14..34]));
            f[24..26].copy_from_slice(&ip_check.to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            f.extend_from_slice(&0x86ddu16.to_be_bytes());
            f.extend_from_slice(&[0x60, 0x0b, 0x80, 0x00]);
            f.extend_from_slice(&udp_len.to_be_bytes());
            f.extend_from_slice(&[17, s.ttl]);
            f.extend_from_slice(&src.octets());
            f.extend_from_slice(&dst.octets());
        }
        _ => panic!("source and destination of different families"),
    }
    f.extend_from_slice(&s.sport.to_be_bytes());
    f.extend_from_slice(&s.dport.to_be_bytes());
    f.extend_from_slice(&udp_len.to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(s.payload);
    if s.udp_checksum {
        let udp = udp_at(&f);
        let mut c = !fold(sum16(pseudo(&f)) + 17 + u32::from(udp_len) + sum16(&f[udp..]));
        if c == 0 {
            c = 0xffff;
        }
        f[udp + 6..udp + 8].copy_from_slice(&c.to_be_bytes());
    }
    f
}

/// Whether the IPv4 header checksum of a frame verifies (IPv6 has none).
#[must_use]
pub fn ip_checksum_ok(f: &[u8]) -> bool {
    if udp_at(f) == 54 {
        return f.len() >= 54;
    }
    f.len() >= 34 && fold(sum16(&f[14..34])) == 0xffff
}

/// Whether the UDP checksum verifies (over IPv4 a zero checksum means
/// "none"; over IPv6 it is invalid).
#[must_use]
pub fn udp_checksum_ok(f: &[u8]) -> bool {
    let udp = udp_at(f);
    if f.len() < udp + 8 {
        return false;
    }
    if f[udp + 6..udp + 8] == [0, 0] {
        return udp == 34;
    }
    let Ok(len) = u32::try_from(f.len() - udp) else {
        return false;
    };
    fold(sum16(pseudo(f)) + 17 + len + sum16(&f[udp..])) == 0xffff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_frames_verify() {
        for (i, payload) in [&[0x80u8, 0, 1][..], &[0x80, 0x60, 0, 1, 2, 3, 4, 5][..]]
            .iter()
            .enumerate()
        {
            let (src, dst): (IpAddr, IpAddr) = if i == 0 {
                (
                    "192.0.2.1".parse().unwrap(),
                    "198.51.100.7".parse().unwrap(),
                )
            } else {
                (
                    "2001:db8::1".parse().unwrap(),
                    "2001:db8::7".parse().unwrap(),
                )
            };
            let f = build(&Spec {
                src,
                dst,
                sport: 4000 + u16::try_from(i).unwrap(),
                dport: 30000,
                ttl: 60,
                udp_checksum: true,
                payload,
            });
            assert!(ip_checksum_ok(&f));
            assert!(udp_checksum_ok(&f));
        }
    }
}

#[cfg(test)]
mod steering_tests {
    use super::*;
    use rtpflux_xdp_common::{datagram, mapped, steer_key};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn frame(v6: bool, udp_checksum: bool, payload: &[u8]) -> Vec<u8> {
        let (src, dst) = if v6 {
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            )
        } else {
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            )
        };
        build(&Spec {
            src,
            dst,
            sport: 4000,
            dport: 30_002,
            ttl: 64,
            udp_checksum,
            payload,
        })
    }

    #[test]
    fn steered_datagrams_read_back_as_the_stack_would() {
        // STUN, DTLS and SRTP alike: any payload.
        let payload = [0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3];
        for v6 in [false, true] {
            let f = frame(v6, true, &payload);
            let (addr, port) = steer_key(&f).unwrap();
            assert_eq!(port, 30_002);
            assert_eq!(
                addr,
                if v6 {
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets()
                } else {
                    mapped([198, 51, 100, 1])
                }
            );
            let d = datagram(&f).unwrap();
            assert_eq!(&f[d.payload.clone()], &payload);
            assert_eq!((d.src_port, d.dst_port), (4000, 30_002));
            // Ethernet padding after the datagram is not payload.
            let mut padded = f.clone();
            padded.extend_from_slice(&[0; 6]);
            assert_eq!(datagram(&padded).unwrap().payload, d.payload);
            // A corrupted payload fails the UDP checksum.
            let mut bad = f.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(datagram(&bad).is_none(), "v6 {v6}");
            // Cut short: the UDP length no longer fits.
            assert!(datagram(&f[..f.len() - 1]).is_none());
        }
        // IPv4 without a UDP checksum is accepted; IPv6 is not.
        assert!(datagram(&frame(false, false, &payload)).is_some());
        assert!(datagram(&frame(true, false, &payload)).is_none());
        // A corrupted IPv4 header fails its checksum.
        let mut f = frame(false, true, &payload);
        f[14 + 8] ^= 0x10;
        assert!(steer_key(&f).is_some() && datagram(&f).is_none());
        // Fragments, IP options and other protocols are left alone.
        let mut frag = frame(false, true, &payload);
        frag[14 + 6] = 0x20;
        assert!(steer_key(&frag).is_none());
        let mut opts = frame(false, true, &payload);
        opts[14] = 0x46;
        assert!(steer_key(&opts).is_none());
        // An IPv4 header claiming more than the frame holds (the UDP
        // length still fits): the stack drops it, so does this.
        let mut long = frame(false, true, &payload);
        let total = u16::from_be_bytes([long[16], long[17]]) + 20;
        long[16..18].copy_from_slice(&total.to_be_bytes());
        let c = {
            long[24..26].copy_from_slice(&[0, 0]);
            let mut sum = 0u32;
            for w in long[14..34].chunks(2) {
                sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
            }
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !u16::try_from(sum).unwrap()
        };
        long[24..26].copy_from_slice(&c.to_be_bytes());
        assert!(datagram(&long).is_none());
        // An IPv4-mapped IPv6 source: dropped.
        let mut mapped_src = frame(true, true, &payload);
        mapped_src[22..34].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert!(datagram(&mapped_src).is_none());
        let mut tcp = frame(true, true, &payload);
        tcp[14 + 6] = 6;
        assert!(steer_key(&tcp).is_none());
        assert!(steer_key(&[0u8; 10]).is_none());
    }

    #[test]
    fn steering_needs_the_port_range_and_the_device() {
        use rtpflux_xdp_common::{SteerRange, steered};
        let r = SteerRange {
            min_port: 30_000,
            max_port: 30_099,
            ifindex: 2,
        };
        assert!(steered(&r, 30_000, 2) && steered(&r, 30_099, 2));
        assert!(!steered(&r, 29_999, 2) && !steered(&r, 30_100, 2));
        assert!(!steered(&r, 30_050, 3), "another device");
    }
}
