//! RTCP compound packets (RFC 3550 §6): framing, sender and receiver
//! reports, and the round-trip computation of §6.4.1. Zero-copy views over
//! the (decrypted) packet; nothing is allocated.

use crate::rtp::Ssrc;

/// RTCP packet types (RFC 3550 §12.1).
pub const PT_SR: u8 = 200;
pub const PT_RR: u8 = 201;

fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(*b.get(i..)?.first_chunk::<4>()?))
}

/// The length of the packet whose header is `h`: (length field + 1) words,
/// at most 4 × 65536 octets (no overflow).
fn packet_len(h: [u8; 4]) -> usize {
    usize::from(u16::from_be_bytes([h[2], h[3]]))
        .wrapping_add(1)
        .wrapping_mul(4)
}

/// One packet of a compound: the count field (RC / SC / subtype), the
/// packet type and the body after the 4-octet header (padding included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub padding: bool,
    pub count: u8,
    pub pt: u8,
    pub body: &'a [u8],
}

/// The packets of a compound, after its framing has been checked.
#[derive(Debug, Clone)]
pub struct Compound<'a> {
    rest: &'a [u8],
}

/// Check the framing of a compound packet: at least one packet (its first
/// MUST be an SR or RR, §6.1, so an empty one is malformed), every packet
/// version 2 with a length that fits, and padding only on the last one,
/// of a count that fits it (§6.4.1, Appendix A.2); `None` otherwise.
/// Nothing more is required (which packet comes first is the sender's
/// duty).
#[must_use]
pub fn compound(buf: &[u8]) -> Option<Compound<'_>> {
    if buf.is_empty() {
        return None;
    }
    let mut rest = buf;
    while !rest.is_empty() {
        let h = rest.first_chunk::<4>()?;
        if h[0] >> 6 != 2 {
            return None;
        }
        let len = packet_len(*h);
        let (packet, after) = rest.split_at_checked(len)?;
        if h[0] & 0x20 != 0 {
            let pad = usize::from(packet.last().copied().unwrap_or(0));
            // `len` >= 4.
            if !after.is_empty() || pad == 0 || pad > len.wrapping_sub(4) {
                return None;
            }
        }
        rest = after;
    }
    Some(Compound { rest: buf })
}

impl<'a> Iterator for Compound<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Packet<'a>> {
        let b = self.rest;
        let h = b.first_chunk::<4>()?;
        let (packet, after) = b.split_at_checked(packet_len(*h))?;
        let padding = h[0] & 0x20 != 0;
        // The body without its padding (checked by `compound`).
        let pad = if padding {
            usize::from(packet.last().copied()?)
        } else {
            0
        };
        let p = Packet {
            padding,
            count: h[0] & 0x1f,
            pt: h[1],
            body: packet.get(4..packet.len().checked_sub(pad)?)?,
        };
        self.rest = after;
        Some(p)
    }
}

/// A report block (§6.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Block {
    pub ssrc: Ssrc,
    /// Fraction lost, 8-bit fixed point.
    pub fraction: u8,
    /// Cumulative number of packets lost (24-bit signed).
    pub lost: i32,
    pub highest: u32,
    pub jitter: u32,
    pub lsr: u32,
    pub dlsr: u32,
}

impl Block {
    fn read(b: &[u8]) -> Option<Self> {
        let raw = be32(b, 4)?;
        let lost = raw & 0x00ff_ffff;
        #[allow(clippy::cast_possible_wrap)]
        let lost = if lost & 0x0080_0000 != 0 {
            (lost | 0xff00_0000) as i32
        } else {
            lost as i32
        };
        Some(Block {
            ssrc: Ssrc::new(be32(b, 0)?),
            fraction: *b.get(4)?,
            lost,
            highest: be32(b, 8)?,
            jitter: be32(b, 12)?,
            lsr: be32(b, 16)?,
            dlsr: be32(b, 20)?,
        })
    }
}

/// The sender information of an SR (§6.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenderInfo {
    pub ntp: u64,
    pub rtp_ts: u32,
    pub packets: u32,
    pub octets: u32,
}

/// An SR or RR: the sender's SSRC, its sender information (SR only) and
/// its report blocks.
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    pub ssrc: Ssrc,
    pub sender: Option<SenderInfo>,
    blocks: &'a [u8],
    count: u8,
}

impl<'a> Report<'a> {
    /// An SR or RR packet with room for all its blocks; `None` for other
    /// types or a body too short (what follows the blocks, profile
    /// extensions or padding, is ignored).
    #[must_use]
    pub fn of(p: &Packet<'a>) -> Option<Self> {
        let (sender, at) = match p.pt {
            PT_SR => (
                Some(SenderInfo {
                    ntp: (u64::from(be32(p.body, 4)?) << 32) | u64::from(be32(p.body, 8)?),
                    rtp_ts: be32(p.body, 12)?,
                    packets: be32(p.body, 16)?,
                    octets: be32(p.body, 20)?,
                }),
                24,
            ),
            PT_RR => (None, 4),
            _ => return None,
        };
        // At most 31 blocks of 24 octets: no overflow.
        let len = usize::from(p.count).wrapping_mul(24);
        let blocks = p.body.get(at..)?.get(..len)?;
        Some(Report {
            ssrc: Ssrc::new(be32(p.body, 0)?),
            sender,
            blocks,
            count: p.count,
        })
    }

    /// The report blocks.
    pub fn blocks(&self) -> impl Iterator<Item = Block> + 'a {
        self.blocks
            .as_chunks::<24>()
            .0
            .iter()
            .take(usize::from(self.count))
            .filter_map(|b| Block::read(b))
    }
}

/// The middle 32 bits of an NTP timestamp (what LSR echoes).
#[must_use]
pub const fn ntp_middle(ntp: u64) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        (ntp >> 16) as u32
    }
}

/// §6.4.1: the round-trip delay `A - LSR - DLSR` in units of 1/65536 s,
/// modulo 2^32 (`a`: the report's arrival time on the same clock as LSR).
#[must_use]
pub const fn rtt(a: u32, lsr: u32, dlsr: u32) -> u32 {
    a.wrapping_sub(lsr).wrapping_sub(dlsr)
}

/// Milliseconds as 1/65536 s units (modulo 2^32), for [`rtt`].
#[must_use]
pub const fn units_of_ms(ms: u64) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        (ms.wrapping_mul(65_536) / 1000) as u32
    }
}

/// 1/65536 s units as milliseconds.
#[must_use]
pub const fn ms_of_units(units: u32) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        (units as u64 * 1000 / 65_536) as u32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn sr_with_a_block_and_sdes() {
        let mut c = vec![0x81, 200, 0, 12];
        c.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        c.extend_from_slice(&0xe000_0001_8000_0000u64.to_be_bytes());
        c.extend_from_slice(&160u32.to_be_bytes());
        c.extend_from_slice(&50u32.to_be_bytes());
        c.extend_from_slice(&8000u32.to_be_bytes());
        c.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
        c.extend_from_slice(&[0x40, 0xff, 0xff, 0xfe]); // 25%, lost -2
        c.extend_from_slice(&0x0001_0010u32.to_be_bytes());
        c.extend_from_slice(&33u32.to_be_bytes());
        c.extend_from_slice(&0x0001_8000u32.to_be_bytes());
        c.extend_from_slice(&0x0000_8000u32.to_be_bytes());
        c.extend_from_slice(&[0x81, 202, 0, 1, 0, 0, 0, 1]);
        let mut it = compound(&c).unwrap();
        let sr = Report::of(&it.next().unwrap()).unwrap();
        assert_eq!(sr.ssrc, Ssrc::new(0x1234_5678));
        assert_eq!(sr.sender.unwrap().packets, 50);
        let b: Vec<Block> = sr.blocks().collect();
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].fraction, b[0].lost, b[0].jitter), (0x40, -2, 33));
        let sdes = it.next().unwrap();
        assert_eq!(sdes.pt, 202);
        assert!(Report::of(&sdes).is_none());
        assert!(it.next().is_none());
        assert_eq!(ntp_middle(0xe000_0001_8000_0000), 0x0001_8000);
        // §6.4.1's example: A = 0xb7108000 (46864.500 s), LSR = 0xb7052000
        // (46853.125 s), DLSR = 0x00054000 (5.250 s): 0x00062000, 6.125 s.
        assert_eq!(rtt(0xb710_8000, 0xb705_2000, 0x0005_4000), 0x0006_2000);
        assert_eq!(ms_of_units(0x0006_2000), 6125);
        assert!(compound(&c[..c.len() - 1]).is_none());
        let mut v1 = c.clone();
        v1[0] = 0x41;
        assert!(compound(&v1).is_none());
    }

    #[test]
    fn padding_is_only_on_the_last_packet_and_not_read_as_data() {
        // An RR with one report block, padded by 4 octets: its body is the
        // block, not the padding.
        let mut rr = std::vec![0xa1, PT_RR, 0, 8, 0, 0, 0, 1];
        rr.extend_from_slice(&[7; 24]);
        rr.extend_from_slice(&[0, 0, 0, 4]);
        let p = compound(&rr).unwrap().next().unwrap();
        assert_eq!(p.body.len(), 4 + 24);
        assert_eq!(Report::of(&p).unwrap().blocks().count(), 1);
        // The same packet first in a compound: padding not on the last.
        let mut two = rr.clone();
        two.extend_from_slice(&[0x80, PT_RR, 0, 1, 0, 0, 0, 2]);
        assert!(compound(&two).is_none());
        // A padding count beyond the packet, and nothing at all.
        let mut bad = rr.clone();
        *bad.last_mut().unwrap() = 200;
        assert!(compound(&bad).is_none());
        assert!(compound(&[]).is_none());
    }
}
