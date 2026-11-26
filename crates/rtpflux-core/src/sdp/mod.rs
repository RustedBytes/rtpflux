//! The parts of SDP (RFC 8866) a media relay reads and rewrites.
//!
//! Reading: each media section's transport port and protocol, its effective
//! connection address (media-level `c=`, else session-level), its RTCP
//! port (the first well-formed `a=rtcp`, RFC 3605, else port + 1),
//! `a=rtcp-mux`, and the first
//! usable SDES key (`a=crypto`, RFC 4568).
//!
//! Rewriting: the session and media `c=` addresses, each `m=` port and
//! `a=rtcp` become the relay's; `o=` optionally; the transport protocol
//! and SDES keys are the relay's own (it terminates SRTP on each side);
//! ICE attributes are removed (they would steer media around the relay),
//! and so are BUNDLE groups (the relay does not bundle; see
//! [`keeps_group`]).
//! Every other line is copied unchanged. Lines end in CRLF in the output.
//!
//! No allocation: input is a borrowed slice, output goes into a caller
//! buffer.

mod bundle;
mod formats;
pub mod ice;
mod keys;
mod read;
mod rewrite;
#[cfg(test)]
mod tests;

use crate::dtls::{Fingerprint, Setup};
pub use crate::rtp::Pt;
pub use bundle::{answer_group, bundle_group, keeps_group};
use core::net::IpAddr;
pub use formats::{FormatFilter, format_matches, format_name, select as select_formats};
pub use keys::decode_key;
use keys::{b64_key, parse_crypto, parse_crypto_declared};
pub use read::{check_body, read_media};
use read::{decimal, lines, parse_c, text};
pub use rewrite::{
    AttrEdits, DtlsAttrs, FormatEdit, IceAttrs, Plan, RelayCandidate, Relayed, RtcpAttr,
    SessionEdits, g711_name, origin_session, origin_version, rewrite,
};
pub use rtpflux_srtp::{MASTER_LEN, MasterKey, Suite};

/// Usable `a=crypto` lines kept per media section.
pub const MAX_CRYPTOS: usize = 6;

/// Fingerprints kept per media section (the first ones with a hash the
/// relay checks).
pub const MAX_FINGERPRINTS: usize = 2;

/// Most media sections handled in one SDP.
pub const MAX_MEDIA: usize = 8;

/// The RTP profile of a media section (the `m=` protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// `RTP/AVP`
    Avp,
    /// `RTP/AVPF`
    Avpf,
    /// `RTP/SAVP`: SRTP
    Savp,
    /// `RTP/SAVPF`: SRTP
    Savpf,
    /// `UDP/TLS/RTP/SAVP`: SRTP keyed by DTLS (RFC 5764 §8)
    UdpTlsSavp,
    /// `UDP/TLS/RTP/SAVPF`: SRTP keyed by DTLS (RFC 5764 §8)
    UdpTlsSavpf,
    /// Anything else (copied unchanged, never terminated by the relay).
    Other,
}

impl Transport {
    /// The profile named by an `m=` protocol field.
    #[must_use]
    pub fn parse(proto: &[u8]) -> Self {
        match proto {
            b"RTP/AVP" => Transport::Avp,
            b"RTP/AVPF" => Transport::Avpf,
            b"RTP/SAVP" => Transport::Savp,
            b"RTP/SAVPF" => Transport::Savpf,
            b"UDP/TLS/RTP/SAVP" => Transport::UdpTlsSavp,
            b"UDP/TLS/RTP/SAVPF" => Transport::UdpTlsSavpf,
            _ => Transport::Other,
        }
    }

    /// The `m=` protocol field (`None` for [`Transport::Other`]).
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Transport::Avp => Some("RTP/AVP"),
            Transport::Avpf => Some("RTP/AVPF"),
            Transport::Savp => Some("RTP/SAVP"),
            Transport::Savpf => Some("RTP/SAVPF"),
            Transport::UdpTlsSavp => Some("UDP/TLS/RTP/SAVP"),
            Transport::UdpTlsSavpf => Some("UDP/TLS/RTP/SAVPF"),
            Transport::Other => None,
        }
    }

    /// Media is SRTP (keyed by SDES or DTLS).
    #[must_use]
    pub const fn is_secure(self) -> bool {
        self.is_sdes() || self.is_dtls()
    }

    /// SRTP keyed in the SDP (`a=crypto`).
    #[must_use]
    pub const fn is_sdes(self) -> bool {
        matches!(self, Transport::Savp | Transport::Savpf)
    }

    /// SRTP keyed by a DTLS handshake on the media port.
    #[must_use]
    pub const fn is_dtls(self) -> bool {
        matches!(self, Transport::UdpTlsSavp | Transport::UdpTlsSavpf)
    }
}

/// One SDES key offer or answer (`a=crypto:<tag> <suite> inline:<key>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crypto {
    pub tag: u32,
    pub key: MasterKey,
}

/// Longest `a=mid` value kept (RFC 5888 §4: a token; browsers use a few
/// characters).
pub const MAX_MID: usize = 16;

/// An identification tag (`a=mid`, RFC 5888 §4).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mid {
    bytes: [u8; MAX_MID],
    len: u8,
}

impl Mid {
    /// A tag of at most [`MAX_MID`] octets, without spaces.
    #[must_use]
    pub fn new(tag: &[u8]) -> Option<Self> {
        if tag.is_empty() || tag.len() > MAX_MID || tag.contains(&b' ') {
            return None;
        }
        let mut bytes = [0u8; MAX_MID];
        bytes.get_mut(..tag.len())?.copy_from_slice(tag);
        Some(Mid {
            bytes,
            len: u8::try_from(tag.len()).ok()?,
        })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // `len` <= MAX_MID (`new`).
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }
}

impl core::fmt::Debug for Mid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Mid({:?})",
            core::str::from_utf8(self.as_bytes()).unwrap_or("?")
        )
    }
}

/// Most payload types kept per media section.
pub const MAX_FORMATS: usize = 32;

/// The RTP payload types of an `m=` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadTypes {
    types: [Pt; MAX_FORMATS],
    len: u8,
}

impl PayloadTypes {
    pub const EMPTY: PayloadTypes = PayloadTypes {
        types: [Pt::PCMU; MAX_FORMATS],
        len: 0,
    };

    #[must_use]
    pub fn as_slice(&self) -> &[Pt] {
        // `len` <= MAX_FORMATS (`push`).
        self.types.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// Add a payload type (beyond [`MAX_FORMATS`] it is dropped).
    pub fn push(&mut self, pt: Pt) {
        if let Some(slot) = self.types.get_mut(usize::from(self.len)) {
            *slot = pt;
            // At most MAX_FORMATS (32).
            self.len = self.len.wrapping_add(1);
        }
    }
}

/// What the relay needs to know about one media section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Media {
    pub port: u16,
    /// Effective connection address (media `c=`, else session `c=`).
    pub address: Option<IpAddr>,
    /// `a=rtcp` port, or `port + 1`.
    pub rtcp_port: u16,
    pub rtcp_mux: bool,
    pub transport: Transport,
    /// The first `a=crypto` line the relay can use: a supported suite, one
    /// key, no MKI and no session parameters.
    pub crypto: Option<Crypto>,
    /// Every such line, in order (the first [`MAX_CRYPTOS`]): the relay
    /// may pick another than the first (the `SDES` options).
    pub cryptos: [Option<Crypto>; MAX_CRYPTOS],
    /// Every line, also those with session parameters that switch
    /// protection off (their keys carry that policy), in order: used only
    /// when the proxy asks for such SRTP (the `SDES` options).
    pub declared: [Option<Crypto>; MAX_CRYPTOS],
    /// The sender uses ICE (`a=ice-ufrag` at session or media level).
    pub ice: bool,
    /// `a=setup` (media level, else session level).
    pub setup: Option<Setup>,
    /// `a=fingerprint` (media level, else session level; RFC 4572 §5).
    pub fingerprints: [Option<Fingerprint>; MAX_FINGERPRINTS],
    /// `a=mid` (RFC 5888 §4).
    pub mid: Option<Mid>,
    /// `a=bundle-only` (RFC 8843 §6): port 0, but part of the BUNDLE group.
    pub bundle_only: bool,
    /// The `m=` line's RTP payload types.
    pub payload_types: PayloadTypes,
    /// `a=rtpmap:<pt> telephone-event/<rate>` (RFC 4733 §7): the payload
    /// type and clock rate of telephone events.
    pub telephone_event: Option<(Pt, u32)>,
    /// `a=rtpmap:<pt> opus/48000[/2]` (RFC 7587 §7): Opus's payload type.
    pub opus: Option<Pt>,
    /// `a=rtpmap:<pt> AMR/8000` and `AMR-WB/16000` (RFC 4867 §8.1).
    pub amr: Option<Pt>,
    pub amr_wb: Option<Pt>,
    /// The `a=fmtp` lines of AMR payload types (the first few).
    pub amr_fmtp: [Option<AmrFmtp>; 4],
    /// The direction attribute (media level, else session level; RFC 3264
    /// §5.1).
    pub direction: Direction,
    /// `a=ptime` (RFC 8866 §6.4), whole milliseconds.
    pub ptime: Option<u16>,
}

/// A media section's direction attribute (RFC 3264 §5.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Direction {
    /// `a=sendrecv`, or none.
    #[default]
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    /// The attribute's value, if it is one.
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"sendrecv" => Some(Direction::SendRecv),
            b"sendonly" => Some(Direction::SendOnly),
            b"recvonly" => Some(Direction::RecvOnly),
            b"inactive" => Some(Direction::Inactive),
            _ => None,
        }
    }

    /// Whether it holds the stream (RFC 3264 §8.4): anything but
    /// `sendrecv`.
    #[must_use]
    pub const fn held(self) -> bool {
        !matches!(self, Direction::SendRecv)
    }
}

impl Media {
    /// The codec the relay can transcode of payload type `pt` here. AMR
    /// counts only octet-aligned, with a `mode-set` that has the relay's
    /// mode.
    #[must_use]
    pub fn codec_of(&self, pt: Pt) -> Option<Codec> {
        if let Some(c) = Codec::of_static(pt) {
            return Some(c);
        }
        let amr = |codec: Codec| {
            let mode = codec.amr_mode()?;
            self.amr_fmtp
                .iter()
                .flatten()
                .find(|f| f.pt == pt)
                .is_some_and(|f| f.allows(mode))
                .then_some(codec)
        };
        match pt {
            _ if self.opus == Some(pt) => Some(Codec::Opus),
            _ if self.amr == Some(pt) => amr(Codec::Amr),
            _ if self.amr_wb == Some(pt) => amr(Codec::AmrWb),
            _ => None,
        }
    }

    /// The payload type of a dynamic codec here, if offered (whether or not
    /// the relay can transcode it).
    #[must_use]
    pub fn dynamic_pt(&self, codec: Codec) -> Option<Pt> {
        match codec {
            Codec::Opus => self.opus,
            Codec::Amr => self.amr,
            Codec::AmrWb => self.amr_wb,
            _ => None,
        }
    }

    /// A placeholder for output arrays.
    pub const EMPTY: Media = Media {
        port: 0,
        address: None,
        rtcp_port: 0,
        rtcp_mux: false,
        transport: Transport::Avp,
        crypto: None,
        cryptos: [None; MAX_CRYPTOS],
        declared: [None; MAX_CRYPTOS],
        ice: false,
        setup: None,
        fingerprints: [None; MAX_FINGERPRINTS],
        mid: None,
        bundle_only: false,
        payload_types: PayloadTypes::EMPTY,
        telephone_event: None,
        opus: None,
        amr: None,
        amr_wb: None,
        amr_fmtp: [None; 4],
        direction: Direction::SendRecv,
        ptime: None,
    };
}

/// Why an SDP cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpError {
    /// A malformed `m=`, `c=` or `a=rtcp` line.
    Malformed,
    /// More than [`MAX_MEDIA`] media sections.
    TooManyMedia,
    /// Not valid UTF-8 where text is required.
    Encoding,
    /// The output buffer is too small.
    Overflow,
    /// The body does not start with a `v=` line (RFC 8866 §5): not an SDP.
    NotSdp,
    /// A media section with a port but no `c=` line, neither its own nor
    /// the session's (RFC 8866 §5.7): no address to rewrite or relay to.
    NoConnection,
}

impl core::fmt::Display for SdpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            SdpError::Malformed => "a malformed m=, c= or a=rtcp line",
            SdpError::TooManyMedia => "too many media sections",
            SdpError::Encoding => "not valid UTF-8",
            SdpError::Overflow => "the result does not fit",
            SdpError::NotSdp => "no v= line first: not an SDP body",
            SdpError::NoConnection => {
                "a media section without a c= line (none at session level either)"
            }
        })
    }
}

/// A codec the relay transcodes between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// G.711 μ-law (RFC 3551 §4.5.14), static payload type 0.
    Pcmu,
    /// G.711 A-law, static payload type 8.
    Pcma,
    /// G.722 (RFC 3551 §4.5.2), static payload type 9: 16 kHz audio on an
    /// 8000 Hz RTP clock.
    G722,
    /// G.729 with or without Annex B (RFC 3551 §4.5.6), static payload type
    /// 18: 10 ms frames of 10 octets, a 2-octet SID frame last.
    G729,
    /// Opus (RFC 7587), a dynamic payload type, RTP clock 48000 Hz.
    Opus,
    /// AMR (RFC 4867), a dynamic payload type, octet-aligned.
    Amr,
    /// AMR-WB (RFC 4867), a dynamic payload type, octet-aligned, RTP clock
    /// 16000 Hz.
    AmrWb,
}

impl Codec {
    /// Every codec.
    pub const ALL: [Codec; 7] = [
        Codec::Pcmu,
        Codec::Pcma,
        Codec::G722,
        Codec::G729,
        Codec::Opus,
        Codec::Amr,
        Codec::AmrWb,
    ];

    /// The encoding name (as in `a=rtpmap` and the `codec` options).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Codec::Pcmu => "PCMU",
            Codec::Pcma => "PCMA",
            Codec::G722 => "G722",
            Codec::G729 => "G729",
            Codec::Opus => "opus",
            Codec::Amr => "AMR",
            Codec::AmrWb => "AMR-WB",
        }
    }

    /// The codec of an encoding name (case-insensitive).
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        Codec::ALL
            .into_iter()
            .find(|c| c.name().as_bytes().eq_ignore_ascii_case(name))
    }

    /// The static payload type (G.711, G.722, G.729), if any.
    #[must_use]
    pub const fn static_pt(self) -> Option<Pt> {
        match self {
            Codec::Pcmu => Some(Pt::PCMU),
            Codec::Pcma => Some(Pt::PCMA),
            Codec::G722 => Some(Pt::G722),
            Codec::G729 => Some(Pt::G729),
            Codec::Opus | Codec::Amr | Codec::AmrWb => None,
        }
    }

    /// The codec of a static payload type.
    #[must_use]
    pub const fn of_static(pt: Pt) -> Option<Self> {
        match pt.get() {
            0 => Some(Codec::Pcmu),
            8 => Some(Codec::Pcma),
            9 => Some(Codec::G722),
            18 => Some(Codec::G729),
            _ => None,
        }
    }

    /// The RTP clock rate.
    #[must_use]
    pub const fn clock(self) -> u32 {
        match self {
            Codec::Opus => 48_000,
            Codec::AmrWb => 16_000,
            // G.722's audio is 16 kHz, its clock 8000 Hz (RFC 3551 §4.5.2).
            Codec::Pcmu | Codec::Pcma | Codec::G722 | Codec::G729 | Codec::Amr => 8000,
        }
    }

    /// The `a=rtpmap` encoding (after the payload type).
    #[must_use]
    pub const fn rtpmap(self) -> &'static str {
        match self {
            Codec::Pcmu => "PCMU/8000",
            Codec::Pcma => "PCMA/8000",
            Codec::G722 => "G722/8000",
            Codec::G729 => "G729/8000",
            Codec::Opus => "opus/48000/2",
            Codec::Amr => "AMR/8000",
            Codec::AmrWb => "AMR-WB/16000",
        }
    }

    /// The `a=fmtp` parameters the relay writes when it adds this codec:
    /// AMR octet-aligned (RFC 4867 §8.1), the only packing it transcodes.
    #[must_use]
    pub const fn fmtp(self) -> Option<&'static str> {
        match self {
            Codec::Amr | Codec::AmrWb => Some("octet-align=1"),
            _ => None,
        }
    }

    /// The AMR mode of a bitrate (bit/s): AMR 4750 to 12200 (modes 0 to
    /// 7), AMR-WB 6600 to 23850 (modes 0 to 8), RFC 4867 §1; `None` for
    /// another bitrate or codec.
    #[must_use]
    pub fn amr_mode_of(self, bps: u32) -> Option<u8> {
        const NB: [u32; 8] = [4750, 5150, 5900, 6700, 7400, 7950, 10_200, 12_200];
        const WB: [u32; 9] = [
            6600, 8850, 12_650, 14_250, 15_850, 18_250, 19_850, 23_050, 23_850,
        ];
        let table: &[u32] = match self {
            Codec::Amr => &NB,
            Codec::AmrWb => &WB,
            _ => return None,
        };
        table
            .iter()
            .position(|&b| b == bps)
            .and_then(|i| u8::try_from(i).ok())
    }

    /// The AMR mode the relay encodes in: 7 (12.2 kbit/s) for AMR, 2
    /// (12.65 kbit/s, the highest every AMR-WB peer must take) for AMR-WB.
    #[must_use]
    pub const fn amr_mode(self) -> Option<u8> {
        match self {
            Codec::Amr => Some(7),
            Codec::AmrWb => Some(2),
            _ => None,
        }
    }
}

/// The `a=fmtp` parameters of an AMR payload type that decide whether the
/// relay can transcode it (RFC 4867 §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmrFmtp {
    pub pt: Pt,
    /// `octet-align=1`.
    pub octet_align: bool,
    /// `mode-set`, as a bit per mode (none: every mode).
    pub mode_set: Option<u16>,
}

impl AmrFmtp {
    /// Whether the relay can send in `mode` and read the payloads.
    #[must_use]
    pub fn allows(&self, mode: u8) -> bool {
        self.octet_align && self.mode_set.is_none_or(|m| m & (1 << mode) != 0)
    }
}
