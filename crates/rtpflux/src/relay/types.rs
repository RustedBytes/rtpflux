//! The types of the relay's interface: sides, SRTP and ICE settings,
//! ports, errors and statistics.

#[allow(clippy::wildcard_imports)]
use super::*;
use rtpflux_core::rtp::Pt;

/// What a side sends to the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Inbound {
    /// Plain RTP/RTCP.
    #[default]
    Plain,
    /// SRTP whose key is not known yet (an offer sent to an SRTP answerer):
    /// dropped until the answer brings it.
    Pending,
    /// SRTP with this key: authenticated and decrypted on arrival.
    Key(MasterKey),
}

/// SRTP on one side of a call (RFC 3711, keyed by SDES): the relay
/// terminates it, so each side has its own keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Srtp {
    pub inbound: Inbound,
    /// The relay's key for what it sends to this side (`None`: plain).
    pub outbound: Option<MasterKey>,
}

impl Srtp {
    /// Plain RTP both ways.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.inbound == Inbound::Plain && self.outbound.is_none()
    }
}

/// Length of the relay's ICE username fragment (RFC 8445 §5.3: at least 4
/// characters).
pub const ICE_UFRAG_LEN: usize = 8;

/// Length of the relay's ICE password (at least 22 characters).
pub const ICE_PWD_LEN: usize = 24;

/// The relay's ICE credentials towards one side, and whether it is a lite
/// agent there (it only answers checks) or a full one (it checks too).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IceCreds {
    pub ufrag: [u8; ICE_UFRAG_LEN],
    pub pwd: [u8; ICE_PWD_LEN],
    pub lite: bool,
}

/// A candidate of a peer's (RFC 8839 §5.1), UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidate {
    pub foundation: Vec<u8>,
    pub component: u8,
    pub priority: u32,
    pub addr: SocketAddr,
}

/// A peer's ICE, from its SDP: credentials, whether it is a lite agent,
/// whether it trickles, its candidates for one media section, and whether
/// it sent them all (`a=end-of-candidates`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IcePeer {
    pub ufrag: Vec<u8>,
    pub pwd: Vec<u8>,
    pub lite: bool,
    pub trickle: bool,
    pub candidates: Vec<IceCandidate>,
    pub end_of_candidates: bool,
}

impl IcePeer {
    /// The same ICE generation (RFC 8839 §4.4.1.1.1: a restart changes both
    /// the ufrag and the password).
    #[must_use]
    pub fn same_generation(&self, other: &IcePeer) -> bool {
        self.ufrag == other.ufrag || self.pwd == other.pwd
    }
}

/// Start (or restart) the relay's full ICE agent towards one side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceStart {
    /// The relay's credentials towards the side.
    pub local: IceCreds,
    pub peer: IcePeer,
    pub controlling: bool,
    /// Restart the agent already there with these credentials.
    pub restart: bool,
    /// Ta, ms.
    pub pacing_ms: u64,
}

impl fmt::Debug for IceCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the password.
        write!(f, "IceCreds({}, ..)", String::from_utf8_lossy(&self.ufrag))
    }
}

/// DTLS-SRTP towards one side (RFC 5763): the relay's role in the
/// handshake and the fingerprints the side signalled (none yet: the
/// handshake may complete, keys wait for them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtlsSide {
    pub role: DtlsRole,
    pub remote: [Option<Fingerprint>; MAX_FINGERPRINTS],
}

/// One side of a call, as the control protocol describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Independent per-side settings.
pub struct Side {
    /// Index into the configured interfaces.
    pub interface: InterfaceId,
    /// RTP address from this side's SDP, if known.
    pub rtp: Option<SocketAddr>,
    /// RTCP address (defaults to RTP port + 1 when the SDP gives none).
    pub rtcp: Option<SocketAddr>,
    pub learning: Learning,
    pub strict_source: bool,
    /// `unidirectional`: the call may enter the XDP fast path with media
    /// one way only (the silent side still settled).
    pub unidirectional: bool,
    /// A new source can take a learned address over (`media-handover`;
    /// see [`Latch::with_handover`](rtpflux_core::latch::Latch::with_handover)).
    pub handover: bool,
    pub srtp: Srtp,
    /// RTCP shares the RTP port (RFC 5761): what goes to this side's RTCP
    /// leg is sent from and to its RTP port.
    pub rtcp_mux: bool,
    /// The relay answers this side's ICE checks (ICE-lite).
    pub ice: Option<IceCreds>,
    /// SRTP is keyed by a DTLS handshake with this side.
    pub dtls: Option<DtlsSide>,
    /// The payload type and clock rate of the telephone events this side
    /// sends (RFC 4733): they are detected and reported.
    pub dtmf: Option<(Pt, u32)>,
    /// Transcode what this side sends.
    pub transcode: Option<Transcode>,
    /// Not RTP (T.38's UDPTL, or another datagram protocol the relay does
    /// not parse): every datagram is relayed as it is, after latching.
    pub opaque: bool,
    /// DTMF transcoding of what this side sends.
    pub dtmf_xcode: Option<DtmfXcode>,
    /// Repacketise this side's audio, after any transcoding, into packets
    /// of this many milliseconds (`ptime`; see [`super::repack`]).
    pub repack: Option<Repack>,
}

/// DTMF transcoding of what a side sends: between telephone events
/// (RFC 4733) and in-band tones in G.711, for the other side, which has only
/// one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfXcode {
    /// The side's telephone events become tones in the other side's audio:
    /// this payload type and codec.
    pub to_inband: Option<(Pt, Codec)>,
    /// The side's in-band tones become telephone events of this payload
    /// type and clock rate for the other side.
    pub to_events: Option<(Pt, u32)>,
    /// The side's own audio (payload type and codec): where its tones are
    /// looked for (with `to_events`).
    pub audio: Option<(Pt, Codec)>,
}

/// Repacketising what a side sends (`ptime`): the packet duration, and
/// the payload type of Opus there (decoded and encoded again).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repack {
    pub ms: u16,
    pub opus: Option<Pt>,
}

/// `media echo`: what becomes of one side's media.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Echo {
    /// Relayed to the other side.
    Normal,
    /// Sent back to the side itself.
    Echo,
    /// Dropped.
    Discard,
}

impl Echo {
    /// Its code in the state file: 0 relayed, 1 sent back, 2 dropped.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Echo::Normal => 0,
            Echo::Echo => 1,
            Echo::Discard => 2,
        }
    }

    /// The mode of `code` (an unknown one: relayed).
    #[must_use]
    pub const fn of_code(code: u8) -> Self {
        match code {
            1 => Echo::Echo,
            2 => Echo::Discard,
            _ => Echo::Normal,
        }
    }
}

/// Transcoding of what a side sends: RTP of payload type `from.0` (codec
/// `from.1`) is relayed as payload type `to.0` (codec `to.1`). G.711 to
/// G.711, or either law to and from Opus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transcode {
    pub from: (Pt, Codec),
    pub to: (Pt, Codec),
    /// The bitrate (bit/s) of the encoder making `to`, when it is Opus
    /// (`opus/48000/2/<bitrate>` in `codec: transcode` or `set`); the
    /// relay's default otherwise.
    pub bitrate: Option<u32>,
}

/// One of the relay's network interfaces, by its place in the
/// configuration (`[[interface]]` in order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct InterfaceId(usize);

impl InterfaceId {
    /// The interface configured `n`-th (from 0).
    #[must_use]
    pub const fn new(n: usize) -> InterfaceId {
        InterfaceId(n)
    }

    /// Its place in the configuration.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl core::fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// A relay call's identity: given by the relay when it creates the call,
/// never reused. Not a number to compute with, and not a time (which the
/// relay also keeps in `u64`s beside it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct CallId(u64);

impl CallId {
    /// The first id a relay gives.
    pub const FIRST: CallId = CallId(1);

    /// The id after this one.
    #[must_use]
    pub const fn next(self) -> CallId {
        CallId(self.0 + 1)
    }

    /// The number, for logs, metrics and replies.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// An id for unit tests (the relay gives the others).
    #[cfg(test)]
    pub(crate) const fn of(n: u64) -> CallId {
        CallId(n)
    }
}

impl core::fmt::Display for CallId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// A leg of a relay call: `A`, the side the call was created with first
/// (a dialog's original offerer), or `B`. A dialog's parties map to legs
/// through who offered last (`control::Party`); the relay knows only legs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CallLeg {
    A,
    B,
}

impl CallLeg {
    /// `B` when `b` (as legs are written in the state file).
    #[must_use]
    pub const fn of_b(b: bool) -> CallLeg {
        if b { CallLeg::B } else { CallLeg::A }
    }

    #[must_use]
    pub const fn is_b(self) -> bool {
        matches!(self, CallLeg::B)
    }

    #[must_use]
    pub const fn other(self) -> CallLeg {
        match self {
            CallLeg::A => CallLeg::B,
            CallLeg::B => CallLeg::A,
        }
    }

    /// 0 for `A`, 1 for `B` (per-leg arrays).
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            CallLeg::A => 0,
            CallLeg::B => 1,
        }
    }

    /// The index of the leg's RTP slot among a call's four slots (A's RTP
    /// and RTCP, then B's).
    #[must_use]
    pub const fn rtp_slot(self) -> usize {
        2 * self.index()
    }
}

/// Where each side must send its media: the relay's local RTP port facing
/// that side, with the interface's advertised address (for the SDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallPorts {
    pub id: CallId,
    pub a: SocketAddr,
    pub b: SocketAddr,
}

/// Why a call could not be created.
#[derive(Debug)]
pub enum RelayError {
    UnknownInterface(InterfaceId),
    /// No free port pair in the chosen shard.
    PortsExhausted,
    /// The worker's command queue is full.
    Busy,
    /// The worker has stopped (its thread ended): nothing it holds can
    /// be changed.
    WorkerGone,
    Io(std::io::Error),
    Sys(nix::Error),
    /// Loading or attaching the XDP program failed.
    Xdp(rtpflux_xdp::loader::Error),
    /// The DTLS certificate could not be made.
    Dtls(crate::dtls::DtlsError),
    /// Recording storage that cannot be used.
    Recording(crate::recording::store::StoreError),
    /// The port range cannot be split into the workers' ranges.
    PortRange,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::UnknownInterface(i) => write!(f, "no interface with index {i}"),
            RelayError::PortsExhausted => write!(f, "no free media ports"),
            RelayError::Busy => write!(f, "worker queue full"),
            RelayError::WorkerGone => write!(f, "media worker stopped"),
            RelayError::Io(e) => write!(f, "{e}"),
            RelayError::Sys(e) => write!(f, "{e}"),
            RelayError::Xdp(e) => write!(f, "XDP: {e}"),
            RelayError::Dtls(e) => write!(f, "DTLS: {e}"),
            RelayError::Recording(e) => write!(f, "recording: {e}"),
            RelayError::PortRange => write!(f, "the media port range does not fit the workers"),
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RelayError::Io(e) => Some(e),
            RelayError::Sys(e) => Some(e),
            RelayError::Xdp(e) => Some(e),
            RelayError::Dtls(e) => Some(e),
            RelayError::Recording(e) => Some(e),
            _ => None,
        }
    }
}

impl<T> From<std::sync::mpsc::TrySendError<T>> for RelayError {
    /// A command not taken by a worker: its queue full, or the worker gone.
    fn from(e: std::sync::mpsc::TrySendError<T>) -> Self {
        match e {
            std::sync::mpsc::TrySendError::Full(_) => RelayError::Busy,
            std::sync::mpsc::TrySendError::Disconnected(_) => RelayError::WorkerGone,
        }
    }
}

impl From<std::io::Error> for RelayError {
    fn from(e: std::io::Error) -> Self {
        RelayError::Io(e)
    }
}

impl From<nix::Error> for RelayError {
    fn from(e: nix::Error) -> Self {
        RelayError::Sys(e)
    }
}

/// Counters shared by a worker (relaxed atomics, read for statistics only).
#[derive(Debug, Default)]
pub struct Stats {
    pub forwarded: AtomicU64,
    /// Octets of the datagrams in `forwarded` (UDP payloads).
    pub forwarded_bytes: AtomicU64,
    /// Packets and octets (UDP payloads) the XDP fast path relayed, as of
    /// the relay's last poll of its counters.
    pub kernel_packets: AtomicU64,
    pub kernel_bytes: AtomicU64,
    pub dropped: AtomicU64,
    pub send_errors: AtomicU64,
    pub calls_ended: AtomicU64,
    /// SRTP/SRTCP packets that failed authentication or replay checks, or
    /// arrived before their key.
    pub srtp_rejected: AtomicU64,
    /// ZRTP packets relayed as they are (counted in `forwarded` too).
    pub zrtp: AtomicU64,
    /// Full ICE: checks and consent requests sent, pairs nominated, role
    /// conflicts, consent lost, restarts.
    pub ice_checks: AtomicU64,
    pub ice_nominations: AtomicU64,
    pub ice_role_conflicts: AtomicU64,
    pub ice_consent_lost: AtomicU64,
    pub ice_restarts: AtomicU64,
    /// DTLS-SRTP associations that keyed SRTP, and ones that failed.
    pub dtls_handshakes: AtomicU64,
    pub dtls_failures: AtomicU64,
    /// Calls the XDP fast path relays now (a gauge, refreshed by the
    /// worker's offload sweep).
    pub offloaded_calls: AtomicU64,
    /// Relay calls this worker owns (a gauge).
    pub calls: AtomicU64,
    /// How the worker receives: `io_uring`, `recvmmsg`, or `recvmmsg`
    /// with why `io_uring` could not be used. Set once, at start.
    pub receive: std::sync::Mutex<String>,
}

/// A telephone event (RFC 4733) a side sent, as detected when it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfEvent {
    pub code: u8,
    /// RTP timestamp of the event.
    pub ts: u32,
    pub duration_ms: u32,
}

/// One leg of a call as `query` reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegStats {
    /// The relay's port of this leg.
    pub local_port: u16,
    /// Where the relay sends this leg's peer media (SDP, learned, or
    /// confirmed by ICE).
    pub peer: Option<SocketAddr>,
    /// Packets and octets accepted from the peer, and packets dropped.
    pub packets: u64,
    pub octets: u64,
    pub dropped: u64,
    /// Telephone events received on this leg (RTP legs), in order.
    pub dtmf: Vec<DtmfEvent>,
    /// What the peer's RTCP reports said (RTCP legs, or RTP legs with
    /// `rtcp-mux`).
    pub rtcp: RtcpStats,
    /// Packets and octets sent to the peer as copies (a subscription's
    /// leg).
    pub copied: [u64; 2],
    /// The latch has settled: where this leg's media goes is fixed
    /// (learned from the peer, or confirmed by ICE).
    pub settled: bool,
    /// DTLS-SRTP on this leg: `keyed` once the handshake gave SRTP keys,
    /// `handshaking` before (none: no DTLS).
    pub dtls: Option<&'static str>,
    /// The relay's full ICE agent towards this leg's peer, if it runs one.
    pub ice: Option<IceLegState>,
    /// The call is relayed in the kernel (XDP) now.
    pub in_kernel: bool,
}

/// The relay's ICE agent for one leg, as `query` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IceLegState {
    /// The relay is the controlling agent.
    pub controlling: bool,
    /// `running`, `completed` or `failed` (RFC 8445 §6.1.2.1).
    pub state: &'static str,
    /// The pair's remote address, once one is selected.
    pub selected: Option<SocketAddr>,
    /// Consent freshness (RFC 7675) expired on the selected pair.
    pub consent_lost: bool,
}

/// The latest RTCP reports from a leg's peer (RFC 3550 §6.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtcpStats {
    /// SR and RR packets read.
    pub reports: u64,
    /// The reporter's SSRC.
    pub ssrc: rtpflux_core::rtp::Ssrc,
    /// Its latest sender information (from an SR).
    pub sender: Option<rtpflux_core::rtcp::SenderInfo>,
    /// The first block of its latest report: what it receives.
    pub block: Option<rtpflux_core::rtcp::Block>,
    /// Round trip between the relay and the peer (ms): from an SR the
    /// relay forwarded to it and the block echoing it (§6.4.1).
    pub rtt_ms: Option<u32>,
}

/// A snapshot of all workers' counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    pub forwarded: u64,
    pub forwarded_bytes: u64,
    pub kernel_packets: u64,
    pub kernel_bytes: u64,
    pub dropped: u64,
    pub send_errors: u64,
    pub calls_ended: u64,
    pub srtp_rejected: u64,
    pub zrtp: u64,
    pub active_calls: usize,
}
