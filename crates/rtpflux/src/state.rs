//! The dialogs as a file (and in Redis, [`crate::redis`]), so a restarted
//! relay keeps its calls.
//!
//! Written (atomically: a temporary file, then a rename) after every
//! change and when the daemon stops; read when it starts. With both a file
//! and Redis, the newer snapshot ([`Saved::saved_ms`]) is restored. A restored call
//! gets its old ports back, with both sides' addresses (including the ones
//! learned from media), SDES keys, ICE credentials, `rtcp-mux`, BUNDLE
//! layout and telephone-event types, so its endpoints, which keep sending
//! to the same ports, carry on. What was blocked stays blocked, a
//! recording goes on in the same file, and an announcement goes on from
//! where it was (or not at all if it would have ended meanwhile). DTLS-SRTP keys live in the DTLS association
//! and are not written: a DTLS side waits for a new handshake after a
//! restart.

use crate::relay::{
    Codec, DtlsRole, DtlsSide, DtmfXcode, IceCandidate, IceCreds, IcePeer, Inbound, MasterKey,
    Side, Srtp, Transcode,
};
use rtpflux_core::dtls::Fingerprint;
use rtpflux_core::latch::Learning;
use rtpflux_core::rtp::Pt;
use rtpflux_core::sdp::Suite;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::Path;

/// File format version.
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    pub version: u32,
    /// When it was taken, in Unix milliseconds (0 in files written before
    /// this field existed).
    #[serde(default)]
    pub saved_ms: u64,
    pub sessions: Vec<SavedSession>,
    /// Media subscriptions (after the sessions they copy from).
    #[serde(default)]
    pub subscriptions: Vec<SavedSubscription>,
    /// `connect`ed parties: (call-id, tag) of each, as hex.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<[(String, String); 2]>,
    /// `connect` with `directional`: (call-id, tag) of the source and of
    /// the destination, as hex, and whether back too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub copies: Vec<([(String, String); 2], bool)>,
    /// The parties' labels: call-id, tag and label, as hex.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<[String; 3]>,
    /// The native API's endpoints (their media is in `sessions`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<SavedEndpoint>,
}

/// An endpoint of the native API: its identity and negotiation state (its
/// media is the created party of the same session and id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedEndpoint {
    pub id: String,
    pub tenant: String,
    pub session: String,
    /// `local_offer` or `remote_offer`.
    pub kind: String,
    pub generation: u64,
    pub revision: u64,
    pub ready: bool,
    #[serde(default)]
    pub pending_revision: Option<u64>,
    /// A remote endpoint's offer before the pending renegotiation.
    #[serde(default)]
    pub previous_remote_sdp: Option<String>,
    #[serde(default)]
    pub bridged_to: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// Its lease (it starts again at the restart).
    #[serde(default)]
    pub lease_ms: Option<u64>,
    #[serde(default)]
    pub remote_sdp: Option<String>,
    pub created_unix_ms: u64,
}

/// A media subscription (`subscribe request`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSubscription {
    /// `call-id` and the subscription's tag, as hex.
    pub call_id: String,
    pub to_tag: String,
    pub created: u64,
    /// The profile offered (`RTP/AVP`, …).
    pub proto: String,
    pub answered: bool,
    pub inactive: bool,
    /// Its relay calls: ports, and each half (the subscriber's address, the
    /// relay's SRTP key).
    pub sinks: Vec<SavedSink>,
    pub streams: Vec<SavedSubStream>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSink {
    pub port_a: u16,
    pub port_b: u16,
    pub a: SavedSide,
    pub b: SavedSide,
}

/// One copied section: its source (the dialog by its offerer's tag, as
/// hex; the media section; the side) and the half of a sink sending it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSubStream {
    pub dialog: String,
    pub media: usize,
    pub logical_b: bool,
    pub sink: usize,
    pub half_b: bool,
    /// The source party's tag (hex), media type and formats.
    pub tag: String,
    pub kind: String,
    pub formats: Vec<u8>,
    pub interface: usize,
}

impl Saved {
    /// As written to the file and to Redis.
    ///
    /// # Errors
    ///
    /// Never in practice (serialising plain data).
    pub fn encode(&self) -> std::io::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(std::io::Error::other)
    }

    /// Parse what [`Saved::encode`] wrote.
    ///
    /// # Errors
    ///
    /// When `bytes` is not a state record.
    pub fn decode(bytes: &[u8]) -> std::io::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Of two snapshots, the one to restore: the newer, the file's on a tie.
#[must_use]
pub fn newer(file: Option<Saved>, redis: Option<Saved>) -> Option<Saved> {
    match (file, redis) {
        (Some(f), Some(r)) if r.saved_ms > f.saved_ms => Some(r),
        (Some(f), _) => Some(f),
        (None, r) => r,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSession {
    /// `call-id`, `from-tag` and `to-tag` as hex (they are octets).
    pub call_id: String,
    pub from_tag: String,
    pub to_tag: Option<String>,
    pub created: u64,
    pub dir: [usize; 2],
    pub media: Vec<Option<SavedMedia>>,
    /// Each party's latest SDP: tag (hex) and SDP.
    #[serde(default)]
    pub sdps: Vec<(String, String)>,
    /// The `o=` versions the relay set (`sdp-version`): per origin (its
    /// session id, hex), the version and session id written, and the
    /// input's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<(Option<String>, u64, u64, u64)>,
    /// Legacy OSRTP: the offerer's folded sections, the answerer's
    /// doubled ones.
    #[serde(default, skip_serializing_if = "<[Vec<bool>]>::is_empty")]
    pub legacy: Vec<Vec<bool>>,
    /// The `via-branch` of the latest offer that had one (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_branch: Option<String>,
    /// `track-state`: the dialog as last agreed while a re-offer waits for
    /// its answer (its relay calls are this one's on the same ports, or
    /// those the re-offer removed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Box<SavedSession>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedMedia {
    pub port_a: u16,
    pub port_b: u16,
    pub a: SavedSide,
    pub b: SavedSide,
    pub a_transport: String,
    pub b_transport: String,
    pub a_tag: u32,
    pub a_mux: bool,
    pub mux: bool,
    pub mid: Option<String>,
    pub group: Option<usize>,
    pub payload_types: Vec<u8>,
    /// Side A is the relay call's B leg (the answerer re-offered); the
    /// ports and sides above are in the dialog's order.
    #[serde(default)]
    pub flipped: bool,
    /// The G.711 law (payload type) side A and side B receive, once
    /// answered (what an announcement is played in).
    #[serde(default)]
    pub laws: (Option<u8>, Option<u8>),
    /// The audio (payload type, codec name) side A and side B receive, in
    /// a codec the relay converts (DTMF).
    #[serde(default)]
    pub audio: [Option<(u8, String)>; 2],
    /// The Opus payload types of side A's and side B's SDP.
    #[serde(default)]
    pub opus: [Option<u8>; 2],
    /// The AMR and AMR-WB payload types, likewise.
    #[serde(default)]
    pub amr: [Option<u8>; 2],
    #[serde(default)]
    pub amr_wb: [Option<u8>; 2],
    /// Blocking, recording and announcements set on the relay call.
    #[serde(default)]
    pub extras: SavedExtras,
    /// What the offer decided for its answer, until the answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<SavedPending>,
}

/// What a section's offer decided for its answer: the relay's keys
/// offered to the answerer, opportunistic SRTP, `rtcp-mux` and DTLS
/// choices, `ptime`, and the codec and DTMF plans. Key texts are
/// `<suite> <hex key> [<params>]`, as a side's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPending {
    /// Further keys offered to B: (crypto tag, key).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub b_alt: Vec<(u32, String)>,
    /// OSRTP: the offerer's crypto (tag, key) and the relay's key towards
    /// it; the relay's key offered to B.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub osrtp_a: Option<(u32, String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub osrtp_b: Option<String>,
    /// ICE passed through (`force-relay`: the endpoints' relay candidates
    /// dropped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough: Option<bool>,
    /// `rtcp-mux` policy (`offer`, `require`, …; empty: the default).
    #[serde(default)]
    pub mux_policy: String,
    /// The relay's `a=setup` offered to B, and whether A offered
    /// `actpass`.
    #[serde(default)]
    pub b_setup: String,
    #[serde(default)]
    pub a_actpass: bool,
    /// `ptime` towards A and B.
    #[serde(default)]
    pub ptime: [Option<u16>; 2],
    /// Transcoding: payload types and codec names of A and B, masked,
    /// Opus bitrate, AMR bitrates towards A and B.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<SavedCodecPlan>,
    /// Format edits of the answer to A: (`replace`, `remove`, `append`, a
    /// payload type, the replacement).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a_formats: Option<(String, u8, Option<u8>)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub te_toward_a: Option<(String, u8, Option<u8>)>,
    /// Telephone events: offered to B with this payload type, or the
    /// offerer's kept (payload type, rate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtmf_plan: Option<(u8, Option<u32>)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedCodecPlan {
    pub a_pt: u8,
    pub a: String,
    pub b_pt: u8,
    pub b: String,
    pub masked: bool,
    pub opus_bitrate: Option<u32>,
    pub amr_bitrate: [Option<u32>; 2],
}

/// What `block media`/`block DTMF`, `start recording` and `play media`
/// set on one relay call. Unlike the rest of [`SavedMedia`] it is in the
/// relay call's leg order (index 0: the leg of the dialog's original
/// offerer), which a re-offer by the answerer does not change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedExtras {
    /// What is blocked of each leg's RTP.
    pub blocked: [crate::relay::Blocks; 2],
    /// The pcap file being recorded into (continued after a restart).
    pub recording: Option<String>,
    /// What the recording becomes when it ends.
    #[serde(default)]
    pub recording_settings: Option<crate::recording::Settings>,
    /// The recording is paused (`pause recording`).
    #[serde(default)]
    pub recording_paused: bool,
    /// Recording files opened for the call so far (the next gets a new
    /// name).
    #[serde(default)]
    pub recordings_opened: u32,
    /// The recording's metadata (embedded when it is converted).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub recording_metadata: std::collections::BTreeMap<String, String>,
    /// The announcement played to each leg.
    pub playing: [Option<SavedPlay>; 2],
    /// DTMF security (and delay) of each leg's keys.
    #[serde(default, skip_serializing_if = "no_plans")]
    pub dtmf_security: [Option<crate::relay::dtmf_security::Plan>; 2],
    /// `media echo` of each leg: 0 relayed, 1 sent back, 2 dropped.
    #[serde(default, skip_serializing_if = "is_zero_pair")]
    pub echo: [u8; 2],
}

fn no_plans(p: &[Option<crate::relay::dtmf_security::Plan>; 2]) -> bool {
    p.iter().all(Option::is_none)
}

#[allow(clippy::trivially_copy_pass_by_ref)] // `skip_serializing_if` passes a reference.
fn is_zero_pair(p: &[u8; 2]) -> bool {
    *p == [0, 0]
}

impl SavedExtras {
    /// The recording's state (`lifecycle::Rec`).
    #[must_use]
    pub fn rec(&self) -> crate::lifecycle::Rec {
        // A file written before the count was kept: it was the first.
        let opened = self
            .recordings_opened
            .max(u32::from(self.recording.is_some()));
        crate::lifecycle::Rec::of(
            self.recording
                .as_ref()
                .map(|_| (opened - 1, self.recording_paused)),
            opened,
        )
    }

    /// Keep `rec`'s state (the file's path is kept by the caller).
    pub fn set_rec(&mut self, rec: crate::lifecycle::Rec) {
        self.recording_paused = rec.current().is_some_and(|(_, paused)| paused);
        self.recordings_opened = rec.opened();
    }

    /// Nothing set: not worth writing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == SavedExtras::default()
    }
}

/// An announcement: started at `started_ms` (Unix time, milliseconds) and
/// `total_ms` long with its repetitions, so a restarted relay goes on from
/// where it was, or not at all once it is over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPlay {
    pub file: String,
    pub repeat: u32,
    pub started_ms: u64,
    pub total_ms: u64,
    /// The part of the file played (`start-pos`, `duration`), in ms.
    #[serde(default)]
    pub start_ms: u64,
    #[serde(default)]
    pub length_ms: Option<u64>,
    /// `repeat-duration`, in ms.
    #[serde(default)]
    pub repeat_ms: Option<u64>,
}

impl SavedPlay {
    /// Milliseconds already played at `now_ms`; `None` once it is over.
    #[must_use]
    pub fn elapsed(&self, now_ms: u64) -> Option<u64> {
        let e = now_ms.saturating_sub(self.started_ms);
        (e < self.total_ms).then_some(e)
    }
}

/// The codecs of DTMF transcoding as saved: the tones' codec name, and
/// the side's own audio (payload type, codec name).
pub type SavedXcodeCodecs = (Option<String>, Option<(u8, String)>);

/// DTMF transcoding as saved: events to tones in this payload type, tones
/// to events of this payload type and rate.
pub type SavedXcode = (Option<u8>, Option<(u8, u32)>);

/// A peer's ICE (the full agent towards it is started again from it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedIcePeer {
    pub ufrag: String,
    pub pwd: String,
    pub lite: bool,
    pub trickle: bool,
    /// `<foundation> <component> <priority> <address>`.
    pub candidates: Vec<String>,
    pub end_of_candidates: bool,
}

impl SavedIcePeer {
    #[must_use]
    pub fn of(p: &IcePeer) -> Self {
        SavedIcePeer {
            ufrag: String::from_utf8_lossy(&p.ufrag).into_owned(),
            pwd: String::from_utf8_lossy(&p.pwd).into_owned(),
            lite: p.lite,
            trickle: p.trickle,
            candidates: p
                .candidates
                .iter()
                .map(|c| {
                    format!(
                        "{} {} {} {}",
                        String::from_utf8_lossy(&c.foundation),
                        c.component,
                        c.priority,
                        c.addr
                    )
                })
                .collect(),
            end_of_candidates: p.end_of_candidates,
        }
    }

    /// `None` when a candidate does not read back.
    #[must_use]
    pub fn peer(&self) -> Option<IcePeer> {
        let candidates = self
            .candidates
            .iter()
            .map(|c| {
                let mut w = c.split(' ');
                Some(IceCandidate {
                    foundation: w.next()?.as_bytes().to_vec(),
                    component: w.next()?.parse().ok()?,
                    priority: w.next()?.parse().ok()?,
                    addr: w.next()?.parse().ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(IcePeer {
            ufrag: self.ufrag.as_bytes().to_vec(),
            pwd: self.pwd.as_bytes().to_vec(),
            lite: self.lite,
            trickle: self.trickle,
            candidates,
            end_of_candidates: self.end_of_candidates,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SavedSide {
    pub interface: usize,
    pub rtp: Option<String>,
    pub rtcp: Option<String>,
    pub learning: String,
    pub strict_source: bool,
    /// `plain`, `pending`, or `<suite> <hex key>`.
    pub inbound: String,
    pub outbound: Option<String>,
    pub rtcp_mux: bool,
    pub ice: Option<(String, String)>,
    /// The relay is a full ICE agent towards the side (absent: lite).
    #[serde(default)]
    pub ice_full: bool,
    /// The side's own ICE (its credentials and candidates), for the full
    /// agent.
    #[serde(default)]
    pub ice_peer: Option<SavedIcePeer>,
    /// `client` or `server`, and the fingerprints in SDP form.
    pub dtls: Option<(String, Vec<String>)>,
    pub dtmf: Option<(u8, u32)>,
    /// Transcoding of what this side sends (payload types from, to).
    #[serde(default)]
    pub transcode: Option<(u8, u8)>,
    /// Their codecs by name (absent: G.711 by its static payload types).
    #[serde(default)]
    pub transcode_codecs: Option<(String, String)>,
    /// The Opus encoder's bitrate of that transcoding, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcode_bitrate: Option<u32>,
    /// Not RTP (T.38's UDPTL): datagrams relayed as they are.
    #[serde(default)]
    pub opaque: bool,
    /// DTMF transcoding: events to tones in this payload type, tones to
    /// events of this payload type and rate.
    #[serde(default)]
    pub dtmf_xcode: Option<SavedXcode>,
    /// The codecs of DTMF transcoding: that of the tones made for the other
    /// side, and this side's own audio (payload type, codec). Absent in
    /// files written before: G.711.
    #[serde(default)]
    pub dtmf_xcode_codecs: Option<SavedXcodeCodecs>,
    /// `media-handover`.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub handover: bool,
    /// `unidirectional`.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub unidirectional: bool,
    /// Repacketisation of what this side sends (`ptime`, milliseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repack: Option<u16>,
    /// The Opus payload type of that repacketisation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repack_opus: Option<u8>,
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    // Hex digits only: `from_str_radix` alone would also take a sign
    // (`+f`), so two texts would read as the same octets.
    if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

/// `SUITE HEX`, then its SDES session parameters, if any.
#[must_use]
pub fn key_text(k: &MasterKey) -> String {
    let mut t = format!("{} {}", k.suite.name(), hex(k.bytes()));
    for p in k.policy.params() {
        t.push(' ');
        t.push_str(p);
    }
    t
}

#[must_use]
pub fn key_of(text: &str) -> Option<MasterKey> {
    let mut f = text.split(' ');
    let key = MasterKey::new(Suite::from_name(f.next()?.as_bytes())?, &unhex(f.next()?)?)?;
    let mut policy = rtpflux_srtp::Policy::NONE;
    for p in f {
        policy = policy.with_param(p.as_bytes())?;
    }
    key.with_policy(policy)
}

fn fingerprint_text(f: &Fingerprint) -> String {
    let digest: Vec<String> = f.digest().iter().map(|b| format!("{b:02X}")).collect();
    format!("{} {}", f.hash.name(), digest.join(":"))
}

/// A saved field that does not read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Unreadable;

impl SavedSide {
    /// `side`, with `learned` (RTP, RTCP) peer addresses when known.
    #[must_use]
    pub fn of(
        side: &Side,
        learned: (Option<std::net::SocketAddr>, Option<std::net::SocketAddr>),
    ) -> Self {
        SavedSide {
            interface: side.interface.get(),
            rtp: learned.0.or(side.rtp).map(|a| a.to_string()),
            rtcp: learned.1.or(side.rtcp).map(|a| a.to_string()),
            learning: match side.learning {
                Learning::Off => "off",
                Learning::Immediate => "immediate",
                Learning::Heuristic => "heuristic",
            }
            .to_owned(),
            strict_source: side.strict_source,
            inbound: match side.srtp.inbound {
                Inbound::Plain => "plain".to_owned(),
                Inbound::Pending => "pending".to_owned(),
                Inbound::Key(k) => key_text(&k),
            },
            outbound: side.srtp.outbound.as_ref().map(key_text),
            rtcp_mux: side.rtcp_mux,
            ice: side.ice.map(|c| {
                (
                    String::from_utf8_lossy(&c.ufrag).into_owned(),
                    String::from_utf8_lossy(&c.pwd).into_owned(),
                )
            }),
            ice_full: side.ice.is_some_and(|c| !c.lite),
            ice_peer: None,
            dtls: side.dtls.map(|d| {
                (
                    match d.role {
                        DtlsRole::Client => "client",
                        DtlsRole::Server => "server",
                    }
                    .to_owned(),
                    d.remote.iter().flatten().map(fingerprint_text).collect(),
                )
            }),
            dtmf: side.dtmf.map(|(pt, rate)| (pt.get(), rate)),
            transcode: side.transcode.map(|t| (t.from.0.get(), t.to.0.get())),
            transcode_codecs: side
                .transcode
                .map(|t| (t.from.1.name().to_owned(), t.to.1.name().to_owned())),
            transcode_bitrate: side.transcode.and_then(|t| t.bitrate),
            opaque: side.opaque,
            dtmf_xcode: side.dtmf_xcode.map(|x| {
                (
                    x.to_inband.map(|(pt, _)| pt.get()),
                    x.to_events.map(|(pt, rate)| (pt.get(), rate)),
                )
            }),
            dtmf_xcode_codecs: side.dtmf_xcode.map(|x| {
                (
                    x.to_inband.map(|(_, c)| c.name().to_owned()),
                    x.audio.map(|(pt, c)| (pt.get(), c.name().to_owned())),
                )
            }),
            repack: side.repack.map(|r| r.ms),
            repack_opus: side.repack.and_then(|r| r.opus).map(Pt::get),
            handover: side.handover,
            unidirectional: side.unidirectional,
        }
    }

    /// DTMF transcoding as saved (none in the file: `Ok(None)`).
    fn dtmf_xcode_side(&self) -> Result<Option<DtmfXcode>, Unreadable> {
        let Some((to_inband, to_events)) = self.dtmf_xcode else {
            return Ok(None);
        };
        let named = |n: &String| Codec::from_name(n.as_bytes());
        let codecs = self.dtmf_xcode_codecs.as_ref();
        let inband_codec = |pt: Pt| match codecs.and_then(|c| c.0.as_ref()) {
            Some(n) => named(n),
            None => Codec::of_static(pt),
        };
        let read = || {
            Some(DtmfXcode {
                to_inband: match to_inband {
                    Some(pt) => {
                        let pt = Pt::new(pt)?;
                        Some((pt, inband_codec(pt)?))
                    }
                    None => None,
                },
                to_events: match to_events {
                    Some((pt, rate)) => Some((Pt::new(pt)?, rate)),
                    None => None,
                },
                audio: match codecs.and_then(|c| c.1.as_ref()) {
                    Some((pt, n)) => Some((Pt::new(*pt)?, named(n)?)),
                    None => None,
                },
            })
        };
        read().map(Some).ok_or(Unreadable)
    }

    /// The side again; `None` if anything does not parse.
    #[must_use]
    pub fn side(&self) -> Option<Side> {
        let addr = |a: &Option<String>| a.as_deref().map(str::parse).transpose().ok();
        let inbound = match self.inbound.as_str() {
            "plain" => Inbound::Plain,
            "pending" => Inbound::Pending,
            k => Inbound::Key(key_of(k)?),
        };
        let ice = match &self.ice {
            Some((u, p)) => Some(IceCreds {
                ufrag: u.as_bytes().try_into().ok()?,
                pwd: p.as_bytes().try_into().ok()?,
                lite: !self.ice_full,
            }),
            None => None,
        };
        let dtls = match &self.dtls {
            Some((role, fps)) => {
                let mut remote = [None; crate::relay::MAX_FINGERPRINTS];
                for (slot, f) in remote.iter_mut().zip(fps) {
                    *slot = Some(Fingerprint::parse(f.as_bytes())?);
                }
                Some(DtlsSide {
                    role: match role.as_str() {
                        "client" => DtlsRole::Client,
                        "server" => DtlsRole::Server,
                        _ => return None,
                    },
                    remote,
                })
            }
            None => None,
        };
        Some(Side {
            interface: crate::relay::InterfaceId::new(self.interface),
            rtp: addr(&self.rtp)?,
            rtcp: addr(&self.rtcp)?,
            learning: match self.learning.as_str() {
                "off" => Learning::Off,
                "immediate" => Learning::Immediate,
                "heuristic" => Learning::Heuristic,
                _ => return None,
            },
            strict_source: self.strict_source,
            srtp: Srtp {
                inbound,
                outbound: match &self.outbound {
                    Some(k) => Some(key_of(k)?),
                    None => None,
                },
            },
            rtcp_mux: self.rtcp_mux,
            ice,
            dtls,
            dtmf: match self.dtmf {
                Some((pt, rate)) => Some((Pt::new(pt)?, rate)),
                None => None,
            },
            transcode: match self.transcode {
                Some((from, to)) => {
                    let (from, to) = (Pt::new(from)?, Pt::new(to)?);
                    let codec = |name: Option<&String>, pt: Pt| match name {
                        Some(n) => Codec::from_name(n.as_bytes()),
                        None => [Codec::Pcmu, Codec::Pcma]
                            .into_iter()
                            .find(|c| c.static_pt() == Some(pt)),
                    };
                    let names = self.transcode_codecs.as_ref();
                    Some(Transcode {
                        from: (from, codec(names.map(|n| &n.0), from)?),
                        to: (to, codec(names.map(|n| &n.1), to)?),
                        bitrate: self.transcode_bitrate,
                    })
                }
                None => None,
            },
            opaque: self.opaque,
            dtmf_xcode: self.dtmf_xcode_side().ok()?,
            repack: self.repack.map(|ms| crate::relay::Repack {
                ms,
                opus: self.repack_opus.and_then(Pt::new),
            }),
            handover: self.handover,
            unidirectional: self.unidirectional,
        })
    }
}

/// Write `saved` to `path` atomically and durably: a new file readable by
/// its owner only (it holds SRTP master keys and ICE passwords), on disk
/// before it replaces the old one.
///
/// # Errors
///
/// I/O errors.
pub fn write(path: &Path, saved: &Saved) -> std::io::Result<()> {
    write_bytes(path, &saved.encode()?)
}

/// [`write()`], of a snapshot already encoded.
///
/// # Errors
///
/// I/O errors.
pub fn write_bytes(path: &Path, text: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(text)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    // The rename itself, on disk.
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Read `path`; `Ok(None)` when it does not exist.
///
/// # Errors
///
/// I/O errors, or a file that does not parse.
pub fn read(path: &Path) -> std::io::Result<Option<Saved>> {
    match std::fs::read(path) {
        Ok(bytes) => Saved::decode(&bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn keys_keep_their_sdes_session_parameters() {
        let key = MasterKey::new(Suite::AesCm128HmacSha1_80, &[5; 30]).unwrap();
        let policed = key
            .with_policy(rtpflux_srtp::Policy {
                unencrypted_srtp: true,
                unauthenticated_srtp: true,
                ..rtpflux_srtp::Policy::NONE
            })
            .unwrap();
        for k in [key, policed] {
            assert_eq!(key_of(&key_text(&k)), Some(k));
        }
        assert!(key_text(&policed).ends_with(" UNENCRYPTED_SRTP UNAUTHENTICATED_SRTP"));
        assert_eq!(
            key_of(&format!("{} FEC_ORDER=FEC_SRTP", key_text(&key))),
            None
        );
    }
    use super::*;

    fn pt(n: u8) -> Pt {
        Pt::new(n).unwrap()
    }
    use crate::relay::InterfaceId;

    #[test]
    fn a_side_round_trips() {
        let text = std::format!("sha-256 {}", std::vec!["AB"; 32].join(":"));
        let fp = Fingerprint::parse(text.as_bytes()).unwrap();
        let side = Side {
            interface: InterfaceId::new(1),
            rtp: Some("192.0.2.1:4000".parse().unwrap()),
            rtcp: None,
            learning: Learning::Heuristic,
            strict_source: true,
            handover: true,
            unidirectional: false,
            srtp: Srtp {
                inbound: Inbound::Key(MasterKey::new(Suite::AeadAes256Gcm, &[7; 44]).unwrap()),
                outbound: Some(MasterKey::new(Suite::AesCm256HmacSha1_80, &[9; 46]).unwrap()),
            },
            rtcp_mux: true,
            ice: Some(IceCreds {
                ufrag: *b"abcdEFGH",
                pwd: *b"0123456789abcdefghijklmn",
                lite: false,
            }),
            dtls: Some(DtlsSide {
                role: DtlsRole::Client,
                remote: [Some(fp), None],
            }),
            dtmf: Some((pt(101), 8000)),
            transcode: Some(Transcode {
                from: (pt(111), Codec::Opus),
                to: (pt(8), Codec::Pcma),
                bitrate: None,
            }),
            opaque: true,
            dtmf_xcode: Some(DtmfXcode {
                to_inband: Some((pt(111), Codec::Opus)),
                to_events: Some((pt(101), 8000)),
                audio: Some((pt(111), Codec::Opus)),
            }),
            repack: Some(crate::relay::Repack {
                ms: 40,
                opus: Some(pt(111)),
            }),
        };
        let learned = Some("203.0.113.9:5000".parse().unwrap());
        let saved = SavedSide::of(&side, (learned, None));
        let back = saved.side().unwrap();
        assert_eq!(
            back,
            Side {
                rtp: learned,
                ..side
            }
        );
        let json = serde_json::to_string(&saved).unwrap();
        assert_eq!(serde_json::from_str::<SavedSide>(&json).unwrap(), saved);
        assert_eq!(unhex(&hex(b"\x00call\xff")).unwrap(), b"\x00call\xff");
    }

    #[test]
    fn every_variant_round_trips_and_bad_text_is_refused() {
        let base = Side {
            interface: InterfaceId::new(0),
            rtp: None,
            rtcp: None,
            learning: Learning::Off,
            strict_source: false,
            handover: false,
            unidirectional: false,
            srtp: Srtp {
                inbound: Inbound::Pending,
                outbound: None,
            },
            rtcp_mux: false,
            ice: None,
            dtls: Some(DtlsSide {
                role: DtlsRole::Server,
                remote: [None, None],
            }),
            dtmf: None,
            transcode: None,
            opaque: false,
            dtmf_xcode: None,
            repack: Some(crate::relay::Repack { ms: 30, opus: None }),
        };
        for learning in [Learning::Off, Learning::Immediate, Learning::Heuristic] {
            for inbound in [Inbound::Plain, Inbound::Pending] {
                let side = Side {
                    learning,
                    srtp: Srtp {
                        inbound,
                        outbound: None,
                    },
                    ..base
                };
                assert_eq!(SavedSide::of(&side, (None, None)).side(), Some(side));
            }
        }
        let good = SavedSide::of(&base, (None, None));
        let bad = |f: fn(&mut SavedSide)| {
            let mut s = good.clone();
            f(&mut s);
            s.side()
        };
        assert_eq!(bad(|s| s.learning = "sometimes".to_owned()), None);
        assert_eq!(bad(|s| s.inbound = "rot13 00".to_owned()), None);
        assert_eq!(bad(|s| s.rtp = Some("not an address".to_owned())), None);
        assert_eq!(bad(|s| s.dtls = Some(("both".to_owned(), vec![]))), None);
        assert_eq!(
            bad(|s| s.transcode = Some((0, 96))),
            None,
            "96 is no static law"
        );
        let mut g711 = good.clone();
        g711.transcode = Some((0, 8));
        assert!(
            g711.side().unwrap().transcode.is_some(),
            "older files: by payload type"
        );
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("+f"), None, "a sign is no hex digit");
        // A directory where the file should be is an error, not "absent".
        assert!(read(&std::env::temp_dir()).is_err());
        assert_eq!(read(Path::new("/nonexistent/state.json")).unwrap(), None);
    }

    #[test]
    fn the_state_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("rtpflux-state-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let saved = Saved {
            version: VERSION,
            saved_ms: 1,
            sessions: Vec::new(),
            subscriptions: Vec::new(),
            connections: Vec::new(),
            labels: Vec::new(),
            copies: Vec::new(),
            endpoints: Vec::new(),
        };
        write(&path, &saved).unwrap();
        // Written again (replacing the file), still private.
        write(&path, &saved).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(read(&path).unwrap().is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_newer_snapshot_is_restored() {
        let at = |ms| Saved {
            version: VERSION,
            saved_ms: ms,
            sessions: Vec::new(),
            subscriptions: Vec::new(),
            connections: Vec::new(),
            labels: Vec::new(),
            copies: Vec::new(),
            endpoints: Vec::new(),
        };
        assert_eq!(newer(Some(at(5)), Some(at(9))), Some(at(9)));
        assert_eq!(newer(Some(at(9)), Some(at(5))), Some(at(9)));
        assert_eq!(newer(Some(at(5)), Some(at(5))), Some(at(5)));
        assert_eq!(newer(None, Some(at(1))), Some(at(1)));
        assert_eq!(newer(Some(at(1)), None), Some(at(1)));
        assert_eq!(newer(None, None), None);
        // A file from before `saved_ms`: read as 0, so Redis wins.
        let old = Saved::decode(br#"{"version":1,"sessions":[]}"#).unwrap();
        assert_eq!(old.saved_ms, 0);
        assert_eq!(Saved::decode(&at(7).encode().unwrap()).unwrap(), at(7));
    }

    /// The blocked kinds are kept as one octet each, as files written
    /// before the type have them.
    #[test]
    fn blocks_keep_their_bits() {
        use crate::relay::{Blocked, Blocks};
        let old: [Blocks; 2] = serde_json::from_str("[5,24]").unwrap();
        assert_eq!(
            old[0].kinds().collect::<Vec<_>>(),
            [Blocked::Media, Blocked::Silence]
        );
        assert_eq!(
            old[1].kinds().collect::<Vec<_>>(),
            [Blocked::Copies, Blocked::CopiesSilence]
        );
        let mut b = Blocks::default();
        b.set(Blocked::Dtmf, true);
        b.set(Blocked::Media, true);
        b.set(Blocked::Media, false);
        assert_eq!(serde_json::to_string(&b).unwrap(), "2");
        assert!(Blocks::default().is_empty() && !b.is_empty());
    }
}
