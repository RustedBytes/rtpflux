extern crate std;
use super::*;
use std::vec::Vec;

/// Reference: the full Internet checksum (RFC 1071) of 16-bit words.
fn full(words: &[u16]) -> u16 {
    !fold(words.iter().map(|&w| u32::from(w)).sum())
}

/// Deterministic pseudo-random words (no external crates).
fn words(seed: u32, n: usize) -> Vec<u16> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            #[allow(clippy::cast_possible_truncation)]
            {
                (x >> 8) as u16
            }
        })
        .collect()
}

#[test]
fn replace2_matches_full_recomputation() {
    for seed in 0..2000 {
        let mut w = words(seed, 10);
        let i = (seed as usize) % w.len();
        let before = full(&w);
        let new = words(seed ^ 0xabcd, 1)[0];
        let old = w[i];
        w[i] = new;
        assert_eq!(csum_replace2(before, old, new), full(&w), "seed {seed}");
    }
}

#[test]
fn replace4_matches_full_recomputation() {
    for seed in 0..2000 {
        let mut w = words(seed, 10);
        let before = full(&w);
        let r = words(seed.wrapping_add(7), 2);
        let old = (u32::from(w[2]) << 16) | u32::from(w[3]);
        let new = (u32::from(r[0]) << 16) | u32::from(r[1]);
        w[2] = r[0];
        w[3] = r[1];
        assert_eq!(csum_replace4(before, old, new), full(&w), "seed {seed}");
    }
}

#[test]
fn rfc1624_example() {
    // RFC 1624 §4: header checksum 0xDD2F, a field changes 0x5555 -> 0x3285;
    // eqn. 3 gives 0x0000.
    assert_eq!(csum_replace2(0xdd2f, 0x5555, 0x3285), 0x0000);
}

#[test]
fn rtp_version_check() {
    assert!(is_rtp_v2(0x80));
    assert!(is_rtp_v2(0xbf));
    assert!(!is_rtp_v2(0x00)); // STUN
    assert!(!is_rtp_v2(0x40));
}

/// Sum of big-endian 16-bit words (odd length padded with zero).
fn sum16(b: &[u8]) -> u32 {
    b.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum()
}

fn ip_ok(f: &[u8]) -> bool {
    fold(sum16(&f[14..34])) == 0xffff
}

/// The UDP checksum verifies over the pseudo-header of either family.
fn udp_ok(f: &[u8]) -> bool {
    let (pseudo_addrs, udp) = if f[12..14] == [0x08, 0x00] {
        (&f[26..34], 34)
    } else {
        (&f[22..54], 54)
    };
    let len = u32::try_from(f.len() - udp).unwrap();
    fold(sum16(pseudo_addrs) + 17 + len + sum16(&f[udp..])) == 0xffff
}

fn finish_udp(f: &mut [u8], udp: usize, pseudo: core::ops::Range<usize>) {
    let len = u32::try_from(f.len() - udp).unwrap();
    let mut uc = !fold(sum16(&f[pseudo]) + 17 + len + sum16(&f[udp..]));
    if uc == 0 {
        uc = 0xffff;
    }
    f[udp + 6..udp + 8].copy_from_slice(&uc.to_be_bytes());
}

/// A valid frame: Ethernet, IPv4 (no options), UDP with checksum, RTP.
fn frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0xaa; 6]);
    f.extend_from_slice(&[0xbb; 6]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    let total = u16::try_from(20 + 8 + payload.len()).unwrap();
    f.extend_from_slice(&[0x45, 0xb8]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, ttl, 17, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    let c = !fold(sum16(&f[14..34]));
    f[24..26].copy_from_slice(&c.to_be_bytes());
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    finish_udp(&mut f, 34, 26..34);
    assert!(ip_ok(&f) && udp_ok(&f));
    f
}

/// A valid IPv6 frame: Ethernet, IPv6 (next header UDP), UDP, RTP.
fn frame6(
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    hops: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0xaa; 6]);
    f.extend_from_slice(&[0xbb; 6]);
    f.extend_from_slice(&0x86ddu16.to_be_bytes());
    let len = u16::try_from(8 + payload.len()).unwrap();
    f.extend_from_slice(&[0x60, 0x0b, 0x80, 0x00]);
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(&[17, hops]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    finish_udp(&mut f, 54, 22..54);
    assert!(udp_ok(&f));
    f
}

fn rtp(seed: u32) -> Vec<u8> {
    [0x80, 0x00]
        .iter()
        .copied()
        .chain(words(seed ^ 0x55, 9).iter().flat_map(|x| x.to_be_bytes()))
        .take(17 + (seed as usize % 5))
        .collect()
}

fn addr6(w: &[u16]) -> [u8; 16] {
    let mut a = [0u8; 16];
    for (i, x) in w.iter().take(8).enumerate() {
        a[2 * i..2 * i + 2].copy_from_slice(&x.to_be_bytes());
    }
    a[0] = 0x20; // global unicast, never IPv4-mapped
    a
}

#[test]
fn rewrite_keeps_both_checksums_valid() {
    for seed in 0..500u32 {
        let w = words(seed, 12);
        let b = |i: usize| w[i].to_be_bytes();
        let payload = rtp(seed);
        let src = [b(0)[0], b(0)[1], b(1)[0], b(1)[1]];
        let dst = [b(2)[0], b(2)[1], b(3)[0], b(3)[1]];
        let mut f = frame(
            src,
            dst,
            w[4],
            w[5],
            3 + u8::try_from(seed % 60).unwrap(),
            &payload,
        );
        let Verdict::Lookup(key) = classify(&f) else {
            panic!("not classified")
        };
        assert_eq!(unmapped(&key.src_addr), Some(src));
        let new_src = [b(6)[0], b(6)[1], b(7)[0], b(7)[1]];
        let action = FlowAction {
            new_src_addr: mapped(new_src),
            new_dst_addr: mapped([b(8)[0], b(8)[1], b(9)[0], b(9)[1]]),
            new_src_port: w[10].to_be(),
            new_dst_port: w[11].to_be(),
            src_mac: [2, 0, 0, 0, 0, 1],
            dst_mac: [2, 0, 0, 0, 0, 2],
            ifindex: 0,
            flags: 0,
            event_pt: 0,
            reserved: [0; 2],
        };
        rewrite(&mut f, &key, &action);
        assert!(ip_ok(&f), "ip checksum, seed {seed}");
        assert!(udp_ok(&f), "udp checksum, seed {seed}");
        assert_eq!(f[22], FRESH_TTL);
        assert_eq!(&f[26..30], &new_src);
        assert_eq!(&f[34..36], &w[10].to_be_bytes());
        assert_eq!(&f[42..], &payload[..], "payload untouched");
    }
}

#[test]
fn rewrite6_keeps_the_udp_checksum_valid() {
    for seed in 0..500u32 {
        let w = words(seed, 36);
        let payload = rtp(seed);
        let mut f = frame6(
            addr6(&w[0..8]),
            addr6(&w[8..16]),
            w[16],
            w[17],
            1 + (seed % 200) as u8,
            &payload,
        );
        let Verdict::Lookup(key) = classify(&f) else {
            panic!("not classified")
        };
        let action = FlowAction {
            new_src_addr: addr6(&w[18..26]),
            new_dst_addr: addr6(&w[26..34]),
            new_src_port: w[34].to_be(),
            new_dst_port: w[35].to_be(),
            src_mac: [2, 0, 0, 0, 0, 1],
            dst_mac: [2, 0, 0, 0, 0, 2],
            ifindex: 7,
            flags: 0,
            event_pt: 0,
            reserved: [0; 2],
        };
        rewrite(&mut f, &key, &action);
        assert!(udp_ok(&f), "udp checksum, seed {seed}");
        assert_eq!(f[21], FRESH_TTL);
        assert_eq!(&f[22..38], &action.new_src_addr);
        assert_eq!(&f[38..54], &action.new_dst_addr);
        assert_eq!(&f[54..56], &w[34].to_be_bytes());
        assert_eq!(&f[62..], &payload[..], "payload untouched");
        assert_eq!(f.len(), headers_len(&key) + payload.len());
    }
}

#[test]
fn classify_passes_non_candidates() {
    let good = frame(
        [192, 0, 2, 1],
        [198, 51, 100, 1],
        4000,
        30000,
        60,
        &[0x80, 0, 1, 2],
    );
    assert!(matches!(classify(&good), Verdict::Lookup(_)));
    let mut stun = good.clone();
    stun[42] = 0x00;
    assert_eq!(classify(&stun), Verdict::Pass);
    let mut opts = good.clone();
    opts[14] = 0x46;
    assert_eq!(classify(&opts), Verdict::Pass);
    let mut frag = good.clone();
    frag[20] = 0x20; // MF
    assert_eq!(classify(&frag), Verdict::Pass);
    let mut tcp = good.clone();
    tcp[23] = 6;
    assert_eq!(classify(&tcp), Verdict::Pass);
    assert_eq!(classify(&good[..42]), Verdict::Pass);
    assert_eq!(classify(&good[..10]), Verdict::Pass);

    let w = words(9, 16);
    let good6 = frame6(
        addr6(&w[..8]),
        addr6(&w[8..]),
        4000,
        30000,
        60,
        &[0x80, 0, 1, 2],
    );
    assert!(matches!(classify(&good6), Verdict::Lookup(_)));
    let mut ext = good6.clone();
    ext[20] = 0; // hop-by-hop options header
    assert_eq!(classify(&ext), Verdict::Pass);
    let mut nocsum = good6.clone();
    nocsum[60..62].copy_from_slice(&[0, 0]);
    assert_eq!(classify(&nocsum), Verdict::Pass);
    let mut v4m = good6.clone();
    v4m[22..38].copy_from_slice(&mapped([192, 0, 2, 1]));
    assert_eq!(classify(&v4m), Verdict::Pass);
    let mut badver = good6.clone();
    badver[14] = 0x40;
    assert_eq!(classify(&badver), Verdict::Pass);
    assert_eq!(classify(&good6[..62]), Verdict::Pass);
}

#[test]
fn egress_device() {
    assert_eq!(egress(0, 3), Egress::Tx);
    assert_eq!(egress(3, 3), Egress::Tx);
    assert_eq!(egress(4, 3), Egress::Redirect(4));
}

#[test]
fn layout_is_stable() {
    assert_eq!(core::mem::size_of::<FlowKey>(), 36);
    assert_eq!(core::mem::size_of::<FlowAction>(), 56);
    assert_eq!(core::mem::size_of::<RecordSample>(), 48 + RECORD_MAX);
    assert_eq!(core::mem::size_of::<FlowStats>(), 24);
}

#[test]
fn decisions_follow_the_flags() {
    let mut a = FlowAction {
        new_src_addr: [0; 16],
        new_dst_addr: [0; 16],
        new_src_port: 0,
        new_dst_port: 0,
        src_mac: [0; 6],
        dst_mac: [0; 6],
        ifindex: 0,
        flags: 0,
        event_pt: 101,
        reserved: [0; 2],
    };
    // No flags: everything is relayed.
    assert_eq!(decide(&a, Some(101)), Decision::Forward);
    // Events up: the event type (with or without the marker) goes up,
    // the rest is relayed, and a payload too short to say stays here.
    a.flags = flags::EVENTS_UP;
    assert_eq!(decide(&a, Some(101)), Decision::Up);
    assert_eq!(decide(&a, Some(0x80 | 0x65)), Decision::Up);
    assert_eq!(decide(&a, Some(0)), Decision::Forward);
    assert_eq!(decide(&a, None), Decision::Forward);
    // Dropped, but the events of a blocked side still go up (detected).
    a.flags = flags::DROP | flags::EVENTS_UP;
    assert_eq!(decide(&a, Some(101)), Decision::Up);
    assert_eq!(decide(&a, Some(8)), Decision::Drop);
    a.flags = flags::DROP;
    assert_eq!(decide(&a, Some(101)), Decision::Drop);
    // Recording changes nothing of the decision.
    a.flags = flags::RECORD;
    assert_eq!(decide(&a, Some(0)), Decision::Forward);
}

#[test]
fn records_read_back() {
    extern crate std;
    let key = FlowKey {
        src_addr: mapped([192, 0, 2, 1]),
        dst_addr: mapped([198, 51, 100, 7]),
        src_port: 4000u16.to_be(),
        dst_port: 30000u16.to_be(),
    };
    let mut bytes = std::vec![0u8; record_layout::SIZE];
    bytes[..16].copy_from_slice(&key.src_addr);
    bytes[16..32].copy_from_slice(&key.dst_addr);
    bytes[32..34].copy_from_slice(&key.src_port.to_ne_bytes());
    bytes[34..36].copy_from_slice(&key.dst_port.to_ne_bytes());
    bytes[record_layout::LEN..record_layout::LEN + 2].copy_from_slice(&3u16.to_ne_bytes());
    bytes[record_layout::TIME..record_layout::TIME + 8].copy_from_slice(&77u64.to_ne_bytes());
    bytes[record_layout::DATA..record_layout::DATA + 3].copy_from_slice(&[0x80, 0, 1]);
    let (k, t, data) = parse_record(&bytes).unwrap();
    assert_eq!((k, t, data), (key, 77, &[0x80, 0, 1][..]));
    // A length beyond the payload space is cut; short bytes are no record.
    bytes[record_layout::LEN..record_layout::LEN + 2].copy_from_slice(&u16::MAX.to_ne_bytes());
    assert_eq!(parse_record(&bytes).unwrap().2.len(), RECORD_MAX);
    assert!(parse_record(&bytes[..100]).is_none());
}
