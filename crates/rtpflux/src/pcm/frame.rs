//! The frames of a PCM stream (`stream.start`): what the relay and an
//! external audio service (speech recognition, a voice bot) exchange on
//! the service's Unix socket.
//!
//! Each frame is a 32-octet header, then its payload. Integers are
//! little-endian (the samples are too):
//!
//! | Octets | Field |
//! |---|---|
//! | 0–3 | `RFPC` |
//! | 4 | version, 1 |
//! | 5 | kind: 1 hello, 2 audio, 3 mark, 4 flush, 5 gap |
//! | 6–7 | flags: bit 0 discontinuity (audio after a gap or a flush) |
//! | 8–11 | stream id (the relay's, from `stream.start`) |
//! | 12–15 | sequence number, per direction, from 0 |
//! | 16–23 | media timestamp: milliseconds of audio since the stream began, per direction |
//! | 24–27 | sample rate: 8000, 16000, 24000 or 48000 |
//! | 28 | channels: 1 |
//! | 29 | encoding: 1, signed 16-bit little-endian PCM |
//! | 30–31 | samples in the payload (audio), or 0 |
//!
//! An audio frame's payload is `samples × 2` octets, 10 or 20 ms of
//! audio. A mark's sequence field is the service's mark id: the relay
//! answers it (a `stream.mark` event) once the audio sent before it has
//! been played to the endpoint. A gap (relay to service) says how many
//! frames the relay dropped, in its sequence field, because the service
//! read too slowly.

/// The header's length.
pub const HEADER: usize = 32;
/// The most samples in a frame: 20 ms at 48 kHz.
pub const MAX_SAMPLES: usize = 960;
/// The largest frame.
pub const MAX_FRAME: usize = HEADER + 2 * MAX_SAMPLES;

/// What a frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Hello = 1,
    Audio = 2,
    Mark = 3,
    Flush = 4,
    Gap = 5,
}

/// A frame's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub discontinuity: bool,
    pub stream: u32,
    pub seq: u32,
    pub timestamp_ms: u64,
    pub rate: u32,
    pub samples: u16,
}

/// Why a header is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Short,
    Magic,
    Version,
    Kind,
    Format,
    /// Not 10 or 20 ms of audio at its rate.
    Samples,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FrameError::Short => "short header",
            FrameError::Magic => "not RFPC",
            FrameError::Version => "unknown version",
            FrameError::Kind => "unknown kind",
            FrameError::Format => "unsupported rate, channels or encoding",
            FrameError::Samples => "not 10 or 20 ms of audio",
        })
    }
}

/// Whether `rate` is one a stream may use.
#[must_use]
pub fn valid_rate(rate: u32) -> bool {
    matches!(rate, 8000 | 16000 | 24000 | 48000)
}

impl Header {
    /// The header in `b`.
    ///
    /// # Errors
    ///
    /// When it is not a valid header of version 1.
    pub fn parse(b: &[u8]) -> Result<Header, FrameError> {
        let b: &[u8; HEADER] = b
            .get(..HEADER)
            .and_then(|h| h.try_into().ok())
            .ok_or(FrameError::Short)?;
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        if &b[..4] != b"RFPC" {
            return Err(FrameError::Magic);
        }
        if b[4] != 1 {
            return Err(FrameError::Version);
        }
        let kind = match b[5] {
            1 => Kind::Hello,
            2 => Kind::Audio,
            3 => Kind::Mark,
            4 => Kind::Flush,
            5 => Kind::Gap,
            _ => return Err(FrameError::Kind),
        };
        let flags = u16::from_le_bytes([b[6], b[7]]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&b[16..24]);
        let h = Header {
            kind,
            discontinuity: flags & 1 != 0,
            stream: u32_at(8),
            seq: u32_at(12),
            timestamp_ms: u64::from_le_bytes(ts),
            rate: u32_at(24),
            samples: u16::from_le_bytes([b[30], b[31]]),
        };
        if kind == Kind::Audio {
            if !valid_rate(h.rate) || b[28] != 1 || b[29] != 1 {
                return Err(FrameError::Format);
            }
            let per_ms = h.rate / 1000;
            if !(u32::from(h.samples) == per_ms * 10 || u32::from(h.samples) == per_ms * 20) {
                return Err(FrameError::Samples);
            }
        }
        Ok(h)
    }

    /// The payload's length.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        if self.kind == Kind::Audio {
            usize::from(self.samples) * 2
        } else {
            0
        }
    }

    /// The header, encoded.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER] {
        let mut b = [0u8; HEADER];
        b[..4].copy_from_slice(b"RFPC");
        b[4] = 1;
        b[5] = self.kind as u8;
        b[6..8].copy_from_slice(&u16::from(self.discontinuity).to_le_bytes());
        b[8..12].copy_from_slice(&self.stream.to_le_bytes());
        b[12..16].copy_from_slice(&self.seq.to_le_bytes());
        b[16..24].copy_from_slice(&self.timestamp_ms.to_le_bytes());
        b[24..28].copy_from_slice(&self.rate.to_le_bytes());
        b[28] = 1;
        b[29] = 1;
        b[30..32].copy_from_slice(&self.samples.to_le_bytes());
        b
    }
}

/// An audio frame of `pcm` (its header, then the samples), into `out`.
pub fn audio(header: &Header, pcm: &[i16], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&header.encode());
    for s in pcm {
        out.extend_from_slice(&s.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(kind: Kind, rate: u32, samples: u16) -> Header {
        Header {
            kind,
            discontinuity: true,
            stream: 7,
            seq: 9,
            timestamp_ms: 1_000_000_000_123,
            rate,
            samples,
        }
    }

    #[test]
    fn a_header_round_trips() {
        for (rate, n) in [(8000, 160), (16000, 160), (24000, 480), (48000, 960)] {
            let x = h(Kind::Audio, rate, n);
            assert_eq!(Header::parse(&x.encode()), Ok(x));
        }
        let m = h(Kind::Mark, 0, 0);
        assert_eq!(Header::parse(&m.encode()), Ok(m));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // A test's pseudo-random octets.
    fn bad_headers_are_refused() {
        let good = h(Kind::Audio, 16000, 320).encode();
        assert_eq!(Header::parse(&good[..31]), Err(FrameError::Short));
        let mut b = good;
        b[0] = b'X';
        assert_eq!(Header::parse(&b), Err(FrameError::Magic));
        let mut b = good;
        b[4] = 2;
        assert_eq!(Header::parse(&b), Err(FrameError::Version));
        let mut b = good;
        b[5] = 9;
        assert_eq!(Header::parse(&b), Err(FrameError::Kind));
        assert_eq!(
            Header::parse(&h(Kind::Audio, 11025, 220).encode()),
            Err(FrameError::Format)
        );
        assert_eq!(
            Header::parse(&h(Kind::Audio, 8000, 161).encode()),
            Err(FrameError::Samples)
        );
        assert_eq!(
            Header::parse(&h(Kind::Audio, 48000, 1920).encode()),
            Err(FrameError::Samples)
        );
        // Any 32 octets: an answer, never a panic.
        for seed in 0..2000u32 {
            let mut b = [0u8; HEADER];
            for (i, x) in b.iter_mut().enumerate() {
                *x = (seed.wrapping_mul(2_654_435_761).rotate_left(i as u32 % 31)) as u8;
            }
            b[..4].copy_from_slice(b"RFPC");
            b[4] = 1;
            let _ = Header::parse(&b);
        }
    }
}
