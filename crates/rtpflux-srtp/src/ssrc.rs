//! The synchronization source identifier of RTP and RTCP.

/// An RTP synchronization source (RFC 3550 §5.1): any 32-bit value, but
/// not a number to compute with, and not a timestamp, rollover counter or
/// packet index, which sit beside it as `u32`s too (in an SRTP IV among
/// others, where swapping two of them would encrypt wrongly).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ssrc(u32);

impl Ssrc {
    #[must_use]
    pub const fn new(v: u32) -> Ssrc {
        Ssrc(v)
    }

    /// As written in a header (network order).
    #[must_use]
    pub const fn from_be_bytes(b: [u8; 4]) -> Ssrc {
        Ssrc(u32::from_be_bytes(b))
    }

    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for Ssrc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}
