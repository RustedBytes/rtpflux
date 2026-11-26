//! RTP fixed header, CSRC list, header extension and padding
//! (RFC 3550 §5.1, §5.3.1).
//!
//! Zero-copy: [`Packet`] is a validated view over the datagram; every
//! accessor reads from it, nothing is copied or allocated. Building writes
//! into a caller-provided buffer, and the `set_*` functions rewrite header
//! fields in place.

/// RTP version carried in every packet.
pub const VERSION: u8 = 2;

/// Length of the fixed header in octets.
pub const FIXED_HEADER_LEN: usize = 12;

/// The header extension (RFC 3550 §5.3.1): a 16-bit profile-defined value
/// and data whose length is a multiple of four octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    pub profile: u16,
    pub data: &'a [u8],
}

pub use rtpflux_srtp::Ssrc;

/// An RTP payload type (RFC 3550 §5.1: seven bits, 0–127). Made from a
/// value below 128 or read from a header, so whatever has one can write
/// it into a header as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pt(u8);

impl Pt {
    /// PCMU (RFC 3551 Table 4).
    pub const PCMU: Pt = Pt(0);
    /// PCMA.
    pub const PCMA: Pt = Pt(8);
    /// G.722.
    pub const G722: Pt = Pt(9);
    /// Comfort noise (RFC 3389).
    pub const CN: Pt = Pt(13);
    /// G.729.
    pub const G729: Pt = Pt(18);

    /// The payload type `v`, if below 128.
    #[must_use]
    pub const fn new(v: u8) -> Option<Pt> {
        if v < 128 { Some(Pt(v)) } else { None }
    }

    /// A payload type written in decimal (as in SDP): digits only (no
    /// sign), below 128.
    #[must_use]
    pub fn from_decimal(text: &[u8]) -> Option<Pt> {
        if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut v = 0u8;
        for &c in text {
            v = v.checked_mul(10)?.checked_add(c.checked_sub(b'0')?)?;
        }
        Pt::new(v)
    }

    /// The payload type in an RTP header's second octet (below the
    /// marker bit).
    #[must_use]
    pub const fn of_header(octet: u8) -> Pt {
        Pt(octet & 0x7f)
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// An RTP header's second octet: the marker bit, then this.
    #[must_use]
    pub const fn header_octet(self, marker: bool) -> u8 {
        (marker as u8) << 7 | self.0
    }
}

impl TryFrom<u8> for Pt {
    type Error = u8;

    fn try_from(v: u8) -> Result<Pt, u8> {
        Pt::new(v).ok_or(v)
    }
}

impl core::str::FromStr for Pt {
    type Err = ();

    /// As [`Pt::from_decimal`].
    fn from_str(s: &str) -> Result<Pt, ()> {
        Pt::from_decimal(s.as_bytes()).ok_or(())
    }
}

impl From<Pt> for u8 {
    fn from(p: Pt) -> u8 {
        p.0
    }
}

impl From<Pt> for usize {
    fn from(p: Pt) -> usize {
        usize::from(p.0)
    }
}

impl core::fmt::Display for Pt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// A set of payload types: a bit for each of 0 to 127, so a [`Pt`] (always
/// below 128) is always in range.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PtSet(u128);

impl PtSet {
    pub const EMPTY: PtSet = PtSet(0);

    const fn bit(pt: Pt) -> u128 {
        // `pt` < 128: the shift stays inside the 128 bits.
        1u128.wrapping_shl(pt.0 as u32)
    }

    #[must_use]
    pub const fn contains(self, pt: Pt) -> bool {
        self.0 & Self::bit(pt) != 0
    }

    /// Add `pt`; `true` when it was not in the set yet.
    pub fn insert(&mut self, pt: Pt) -> bool {
        let new = !self.contains(pt);
        self.0 |= Self::bit(pt);
        new
    }
}

/// A validated RTP packet borrowed from its datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    buf: &'a [u8],
    /// The fixed header (`parse` checked it is there): its fields are
    /// read without a bounds check that could fail.
    header: &'a [u8; FIXED_HEADER_LEN],
    payload_start: usize,
    payload_end: usize,
}

/// Why a packet was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Shorter than the fixed header, CSRC list or extension it announces.
    Truncated,
    /// The version field is not 2.
    BadVersion(u8),
    /// The P bit is set but the padding count is zero or exceeds the room
    /// left after the header.
    BadPadding,
}

/// Why a header cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// More than 15 CSRCs.
    TooManyCsrcs,
    /// Extension data whose length is not a multiple of four octets, or
    /// longer than 65535 words.
    BadExtension,
    /// The output buffer is shorter than the packet.
    BufferTooSmall,
}

/// The `N` octets at `b[i..]` (`None` past the end).
fn chunk<const N: usize>(b: &[u8], i: usize) -> Option<[u8; N]> {
    b.get(i..)?.first_chunk::<N>().copied()
}

/// Where the CSRC list ends, for a first octet (or a CSRC count) with
/// `cc` in its low four bits: at most 12 + 15 × 4, so no overflow.
const fn csrc_end(cc: u8) -> usize {
    FIXED_HEADER_LEN.wrapping_add(((cc & 0x0f) as usize).wrapping_mul(4))
}

impl<'a> Packet<'a> {
    /// Validate `buf` as an RTP packet.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when the packet is truncated, has a version
    /// other than 2, or carries an impossible padding count.
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let header = buf
            .first_chunk::<FIXED_HEADER_LEN>()
            .ok_or(ParseError::Truncated)?;
        let version = header[0] >> 6;
        if version != VERSION {
            return Err(ParseError::BadVersion(version));
        }
        // At most 15 CSRCs: 12 + 60, no overflow.
        let mut pos = csrc_end(header[0]);
        if buf.len() < pos {
            return Err(ParseError::Truncated);
        }
        if header[0] & 0x10 != 0 {
            let words = chunk::<4>(buf, pos).ok_or(ParseError::Truncated)?;
            // At most 4 + 4 * 65535 octets more.
            let ext = usize::from(u16::from_be_bytes([words[2], words[3]]))
                .wrapping_mul(4)
                .wrapping_add(4);
            pos = pos.checked_add(ext).ok_or(ParseError::Truncated)?;
            if buf.len() < pos {
                return Err(ParseError::Truncated);
            }
        }
        // `pos` <= the length (checked above).
        let room = buf.len().wrapping_sub(pos);
        let padding = if header[0] & 0x20 != 0 {
            let count = usize::from(buf.last().copied().unwrap_or(0));
            if count == 0 || count > room {
                return Err(ParseError::BadPadding);
            }
            count
        } else {
            0
        };
        Ok(Packet {
            buf,
            header,
            payload_start: pos,
            // `padding` <= `room`.
            payload_end: buf.len().wrapping_sub(padding),
        })
    }

    /// The whole datagram.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    #[must_use]
    pub fn marker(&self) -> bool {
        self.header[1] & 0x80 != 0
    }

    #[must_use]
    pub fn payload_type(&self) -> Pt {
        Pt::of_header(self.header[1])
    }

    #[must_use]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes([self.header[2], self.header[3]])
    }

    #[must_use]
    pub fn timestamp(&self) -> u32 {
        let h = self.header;
        u32::from_be_bytes([h[4], h[5], h[6], h[7]])
    }

    #[must_use]
    pub fn ssrc(&self) -> Ssrc {
        let h = self.header;
        Ssrc::new(u32::from_be_bytes([h[8], h[9], h[10], h[11]]))
    }

    /// Number of CSRCs (the CC field).
    #[must_use]
    pub fn csrc_count(&self) -> usize {
        usize::from(self.header[0] & 0x0f)
    }

    /// The CSRC list, read from the packet on demand.
    pub fn csrcs(&self) -> impl ExactSizeIterator<Item = Ssrc> + 'a {
        // `parse` checked the list is there.
        let list = self.buf.get(FIXED_HEADER_LEN..).unwrap_or_default();
        list.as_chunks::<4>()
            .0
            .iter()
            .map(|c| Ssrc::new(u32::from_be_bytes(*c)))
            .take(self.csrc_count())
    }

    /// The header extension, if the X bit is set.
    #[must_use]
    pub fn extension(&self) -> Option<Extension<'a>> {
        if self.header[0] & 0x10 == 0 {
            return None;
        }
        let at = csrc_end(self.header[0]);
        let [p0, p1, _, _] = chunk::<4>(self.buf, at)?;
        Some(Extension {
            profile: u16::from_be_bytes([p0, p1]),
            data: self.buf.get(at.checked_add(4)?..self.payload_start)?,
        })
    }

    /// The payload (between the header and the padding).
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.buf
            .get(self.payload_start..self.payload_end)
            .unwrap_or_default()
    }

    /// Number of padding octets (0 when the P bit is clear).
    #[must_use]
    pub fn padding(&self) -> usize {
        self.buf.len().saturating_sub(self.payload_end)
    }
}

/// Header fields for [`write()`]. Borrowed, so building allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    pub marker: bool,
    pub payload_type: Pt,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: Ssrc,
    /// At most 15 entries (the CC field is four bits).
    pub csrcs: &'a [Ssrc],
    pub extension: Option<Extension<'a>>,
}

/// Write a packet (header, `payload`, then `padding` padding octets whose
/// last holds the count) into `out`; returns its length.
///
/// # Errors
///
/// Returns a [`BuildError`] when the header cannot be represented or `out`
/// is too short.
pub fn write(
    header: &Header<'_>,
    payload: &[u8],
    padding: u8,
    out: &mut [u8],
) -> Result<usize, BuildError> {
    let csrc_count = u8::try_from(header.csrcs.len())
        .ok()
        .filter(|&n| n <= 15)
        .ok_or(BuildError::TooManyCsrcs)?;
    let ext_words = match header.extension {
        Some(e) if e.data.len() % 4 == 0 => {
            Some(u16::try_from(e.data.len() / 4).map_err(|_| BuildError::BadExtension)?)
        }
        Some(_) => return Err(BuildError::BadExtension),
        None => None,
    };
    let too_small = BuildError::BufferTooSmall;
    let ext_len = match header.extension {
        Some(e) => e.data.len().checked_add(4).ok_or(too_small)?,
        None => 0,
    };
    // At most 15 CSRCs (checked above): 12 + 60.
    let total = csrc_end(csrc_count)
        .checked_add(ext_len)
        .and_then(|n| n.checked_add(payload.len()))
        .and_then(|n| n.checked_add(usize::from(padding)))
        .ok_or(too_small)?;
    let out = out.get_mut(..total).ok_or(too_small)?;
    let mut b0 = VERSION << 6 | csrc_count;
    if padding > 0 {
        b0 |= 0x20;
    }
    if header.extension.is_some() {
        b0 |= 0x10;
    }
    // Everything fits (`total` checked above): nothing is half-written.
    let mut w = Cursor { out, pos: 0 };
    w.put(&[b0, header.payload_type.header_octet(header.marker)])?;
    w.put(&header.sequence.to_be_bytes())?;
    w.put(&header.timestamp.to_be_bytes())?;
    w.put(&header.ssrc.to_be_bytes())?;
    for c in header.csrcs {
        w.put(&c.to_be_bytes())?;
    }
    if let (Some(e), Some(words)) = (header.extension, ext_words) {
        w.put(&e.profile.to_be_bytes())?;
        w.put(&words.to_be_bytes())?;
        w.put(e.data)?;
    }
    w.put(payload)?;
    if let Some(zeros) = padding.checked_sub(1) {
        w.zeros(usize::from(zeros))?;
        w.put(&[padding])?;
    }
    Ok(w.pos)
}

/// Writes one field after the other into a buffer.
struct Cursor<'b> {
    out: &'b mut [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn next(&mut self, n: usize) -> Result<&mut [u8], BuildError> {
        let end = self.pos.checked_add(n).ok_or(BuildError::BufferTooSmall)?;
        let dst = self
            .out
            .get_mut(self.pos..end)
            .ok_or(BuildError::BufferTooSmall)?;
        self.pos = end;
        Ok(dst)
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), BuildError> {
        self.next(bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }

    fn zeros(&mut self, n: usize) -> Result<(), BuildError> {
        self.next(n)?.fill(0);
        Ok(())
    }
}

/// Rewrite the SSRC of a packet in place; `false` (nothing changed) when
/// `buf` is shorter than the fixed header.
pub fn set_ssrc(buf: &mut [u8], ssrc: Ssrc) -> bool {
    put(buf, 8, &ssrc.to_be_bytes())
}

/// Rewrite the sequence number in place; `false` for a buffer shorter
/// than the fixed header.
pub fn set_sequence(buf: &mut [u8], sequence: u16) -> bool {
    put(buf, 2, &sequence.to_be_bytes())
}

/// Rewrite the timestamp in place; `false` for a buffer shorter than the
/// fixed header.
pub fn set_timestamp(buf: &mut [u8], timestamp: u32) -> bool {
    put(buf, 4, &timestamp.to_be_bytes())
}

/// Rewrite the payload type in place, keeping the marker bit; `false` for
/// a buffer shorter than the fixed header.
pub fn set_payload_type(buf: &mut [u8], payload_type: Pt) -> bool {
    match buf.first_chunk_mut::<FIXED_HEADER_LEN>() {
        Some(h) => {
            h[1] = (h[1] & 0x80) | payload_type.get();
            true
        }
        None => false,
    }
}

/// Write `bytes` at `at` of a buffer holding at least the fixed header.
fn put(buf: &mut [u8], at: usize, bytes: &[u8]) -> bool {
    match buf
        .get_mut(..FIXED_HEADER_LEN)
        .and_then(|h| h.get_mut(at..at.checked_add(bytes.len())?))
    {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSRCS: [Ssrc; 2] = [Ssrc::new(1), Ssrc::new(2)];
    const EXT: [u8; 4] = [0x10, 0xaa, 0, 0];

    fn sample() -> Header<'static> {
        Header {
            marker: true,
            payload_type: Pt::PCMU,
            sequence: 0xbeef,
            timestamp: 0x0102_0304,
            ssrc: Ssrc::new(0xdead_cafe),
            csrcs: &CSRCS,
            extension: Some(Extension {
                profile: 0xbede,
                data: &EXT,
            }),
        }
    }

    fn check_header(p: &Packet<'_>, h: &Header<'_>) {
        assert_eq!(p.marker(), h.marker);
        assert_eq!(p.payload_type(), h.payload_type);
        assert_eq!(p.sequence(), h.sequence);
        assert_eq!(p.timestamp(), h.timestamp);
        assert_eq!(p.ssrc(), h.ssrc);
        assert!(p.csrcs().eq(h.csrcs.iter().copied()));
        assert_eq!(p.extension(), h.extension);
    }

    #[test]
    fn round_trip_with_csrcs_extension_and_padding() {
        let payload = [9u8, 8, 7, 6, 5];
        let mut buf = [0u8; 64];
        let n = write(&sample(), &payload, 3, &mut buf).unwrap();
        let p = Packet::parse(&buf[..n]).unwrap();
        check_header(&p, &sample());
        assert_eq!(p.payload(), &payload);
        assert_eq!(p.padding(), 3);
    }

    #[test]
    fn minimal_packet() {
        let h = Header {
            csrcs: &[],
            extension: None,
            ..sample()
        };
        let mut buf = [0u8; 12];
        assert_eq!(write(&h, &[], 0, &mut buf), Ok(FIXED_HEADER_LEN));
        assert_eq!(buf[0], 0x80);
        let p = Packet::parse(&buf).unwrap();
        check_header(&p, &h);
        assert_eq!(p.payload(), &[] as &[u8]);
    }

    #[test]
    fn in_place_rewrites() {
        let mut buf = [0u8; 32];
        let n = write(&sample(), &[1, 2, 3], 0, &mut buf).unwrap();
        assert!(set_ssrc(&mut buf, Ssrc::new(7)));
        assert!(set_sequence(&mut buf, 9));
        assert!(set_timestamp(&mut buf, 11));
        assert!(set_payload_type(&mut buf, Pt::new(96).unwrap()));
        // Too short for a header: nothing changes, nothing panics.
        let mut short = [0x80u8; 11];
        assert!(
            !set_ssrc(&mut short, Ssrc::new(1))
                && !set_payload_type(&mut short, Pt::new(1).unwrap())
        );
        assert_eq!(short, [0x80; 11]);
        let p = Packet::parse(&buf[..n]).unwrap();
        assert_eq!(
            (
                p.ssrc(),
                p.sequence(),
                p.timestamp(),
                p.payload_type(),
                p.marker()
            ),
            (Ssrc::new(7), 9, 11, Pt::new(96).unwrap(), true)
        );
        assert_eq!(p.payload(), &[1, 2, 3]);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(Packet::parse(&[0x80; 11]), Err(ParseError::Truncated));
        let mut buf = [0u8; 64];
        let n = write(&sample(), &[], 0, &mut buf).unwrap();
        let mut v1 = buf;
        v1[0] = (v1[0] & 0x3f) | 0x40;
        assert_eq!(Packet::parse(&v1[..n]), Err(ParseError::BadVersion(1)));
        // CC = 2 but only one CSRC present
        assert_eq!(
            Packet::parse(&[0x82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Err(ParseError::Truncated)
        );
        // extension announcing more words than present
        assert_eq!(
            Packet::parse(&[
                0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xde, 0, 2, 0, 0, 0, 0
            ]),
            Err(ParseError::Truncated)
        );
        // padding count larger than the body, and zero
        let mut p = [0x80u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 9];
        p[0] |= 0x20;
        assert_eq!(Packet::parse(&p), Err(ParseError::BadPadding));
        p[13] = 0;
        assert_eq!(Packet::parse(&p), Err(ParseError::BadPadding));
    }

    #[test]
    fn write_rejects_unrepresentable_headers() {
        let mut buf = [0u8; 128];
        let many = [Ssrc::new(0); 16];
        assert_eq!(
            write(
                &Header {
                    csrcs: &many,
                    ..sample()
                },
                &[],
                0,
                &mut buf
            ),
            Err(BuildError::TooManyCsrcs)
        );
        // A payload type above 127 cannot be made at all.
        assert_eq!(Pt::new(128), None);
        assert_eq!(Pt::from_decimal(b"+5"), None, "digits only");
        assert_eq!(Pt::from_decimal(b"127"), Pt::new(127));
        let ext = Extension {
            profile: 1,
            data: &[1, 2, 3],
        };
        assert_eq!(
            write(
                &Header {
                    extension: Some(ext),
                    ..sample()
                },
                &[],
                0,
                &mut buf
            ),
            Err(BuildError::BadExtension)
        );
        assert_eq!(
            write(&sample(), &[0; 8], 0, &mut buf[..20]),
            Err(BuildError::BufferTooSmall)
        );
    }
}
