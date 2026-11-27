//! The `ng` control protocol server: rtpengine's commands, as a SIP
//! proxy's `rtpengine` module sends them (see `docs/control-protocol.md`
//! for each command and option).
//!
//! An `offer` creates one relay call per media section of the offerer's SDP
//! (side A) and returns that SDP rewritten to the relay's ports facing the
//! answerer (side B); the `answer` gives side B's addresses and returns the
//! answer rewritten to the ports facing A. A dialog is stored under its
//! offerer's tag (`SessionKey`); forked branches and dialogs between
//! parties already in other dialogs of the call get keys of their own
//! (`branch_key`, `parties::pair_key`). Replies are cached by sender
//! and cookie, so a retransmitted request is answered identically instead
//! of being run twice, and two proxies that send the same cookie are not
//! answered from each other's cache.
//!
//! Each side is terminated on its own: SRTP (SDES, with opportunistic and
//! legacy OSRTP), DTLS-SRTP, ICE (a full agent, or ICE-lite; passed
//! through with `ICE=force-relay`/`optional`), `rtcp-mux` and BUNDLE, so
//! the two sides can use different profiles, and two SRTP sides never
//! share keys. The modules:
//!
//! - `offer`, `answer`, `media`, `keys`, `ice`, `opts`,
//!   `sdp_edits`, `legacy`: the offer/answer exchange and its options;
//! - `parties`, `rollback`, `create`: calls with more than two
//!   parties, labels, re-offers taken back, parties made by the relay;
//! - `features`, `dtmf_security`: blocking, silencing, recording,
//!   announcements, `play DTMF`, DTMF security and delay;
//! - `subscribe`, `copies`: subscriptions, `publish`, `connect`,
//!   `mesh`, `inject`;
//! - `query`: `list`, `query`, `statistics`;
//! - `persist`, `pending`: the state file and Redis;
//! - `streams`, `web`: requests from TCP, HTTP and WebSocket, and the
//!   web UI's questions; `args`, `reply`, `error`: reading requests
//!   and writing replies.

mod answer;
mod args;
mod copies;
mod create;
mod dtmf_security;
mod error;
mod features;
mod ice;
mod inventory;
mod keys;
pub mod ledger;
mod legacy;
mod media;
pub mod native;
mod offer;
mod opts;
mod parties;
mod pending;
mod persist;
mod query;
mod reply;
mod rollback;
mod sdp_edits;
mod streams;
mod subscribe;
mod web;

pub use streams::NgLink;
pub use web::{Unanswered, WebLink, WebQuery};

pub use error::{Error, RequestError, SdpError, StateError};

use crate::config::{IceMode, Interface};
use crate::metrics::ControlStats;
use crate::relay::{
    Blocked, CallId, CallLeg, CallPorts, Codec, DtlsRole, DtlsSide, DtmfXcode, ICE_PWD_LEN,
    ICE_UFRAG_LEN, IceCandidate, IceCreds, IcePeer, IceStart, Inbound, InterfaceId,
    MAX_FINGERPRINTS, MasterKey, Relay, Side, Srtp,
};
use crate::state;
use rtpflux_core::dtls::Setup;
use rtpflux_core::g711::{PT_PCMA, PT_PCMU};
use rtpflux_core::latch::Learning;
use rtpflux_core::rtp::Pt;
use rtpflux_core::sdp::{
    self, Crypto, DtlsAttrs, FormatEdit, IceAttrs, MAX_MEDIA, Media, Mid, Plan, Relayed, Suite,
    Transport,
};
use rtpflux_ng::bencode::{Dict, Encoder, Value};
use rtpflux_ng::{parse_message, write_reply};
use std::collections::HashMap;
use std::io::Read as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use media::{CodecOpts, DTLS_PENDING, MediaState, Party};
use opts::{DtlsOpt, IceLite, IcePolicy, MuxPolicy, Opts, opts};
use reply::{B, Reply, stats, stream_dict};

/// Largest `ng` datagram (and reply).
pub const MAX_DATAGRAM: usize = 65_535;
/// The epoll token of the web UI's questions.
const WEB: u64 = u64::MAX;
/// The epoll token of messages from streams.
const STREAMS: u64 = u64::MAX - 1;
/// The epoll key of the native API's wake-up.
const NATIVE: u64 = u64::MAX - 2;
/// The epoll key of the media events' wake-up.
const MEDIA: u64 = u64::MAX - 3;
/// Replies kept for retransmissions, at most, and their total size.
const CACHE_ENTRIES: usize = 4_096;
const CACHE_BYTES: usize = 32 * 1024 * 1024;
/// Cookies longer than this are answered but not cached.
const MAX_COOKIE: usize = 256;
/// How long a reply is kept for retransmissions.
const CACHE_TTL: Duration = Duration::from_secs(30);

/// A dialog's key: (`call-id`, `from-tag` of its offerer).
type SessionKey = (Vec<u8>, Vec<u8>);
/// A party of a `connect`: its call and leg, and the audio it receives (a
/// codec the relay converts), per media section.
type PartyLeg = ((CallId, CallLeg), Option<(Pt, sdp::Codec)>);

/// What a `delete` selects: the call, and optionally a tag (either
/// party's), the answerer's tag and the offer's `via-branch`.
#[derive(Debug, Clone)]
struct Selector {
    call_id: Vec<u8>,
    from_tag: Option<Vec<u8>>,
    to_tag: Option<Vec<u8>>,
    via: Option<Vec<u8>>,
    /// Only the dialogs of these generations ([`Session::generation`]): a
    /// delayed delete's, chosen when it was asked for.
    generations: Option<Vec<u64>>,
}

impl Selector {
    /// Whether it selects the dialog stored under `key`.
    fn matches(&self, (c, f): &SessionKey, s: &Session) -> bool {
        let f = base_tag(f);
        *c == self.call_id
            && self
                .generations
                .as_ref()
                .is_none_or(|g| g.contains(&s.generation))
            && self
                .from_tag
                .as_deref()
                .is_none_or(|t| t == f || s.to_tag.as_deref() == Some(t))
            && self
                .to_tag
                .as_deref()
                .is_none_or(|t| s.to_tag.as_deref().is_none_or(|own| own == t) || f == t)
            && self
                .via
                .as_deref()
                .is_none_or(|v| s.via_branch.as_deref().is_none_or(|own| own == v))
    }
}

/// What separates a forked branch's own key from the offerer's tag (no
/// SIP tag holds a NUL).
const BRANCH: &[u8] = b"\0via:";

/// The key of the offer of dialog `key` on another branch `via` (a forked
/// INVITE's).
pub(super) fn branch_key((c, f): &SessionKey, via: &[u8]) -> SessionKey {
    (c.clone(), [base_tag(f), BRANCH, via].concat())
}

/// The offerer's tag of a key, without its branch ([`BRANCH`]) or the
/// other party of a pair key ([`parties::PAIR`]): both start with a NUL.
fn base_tag(f: &[u8]) -> &[u8] {
    f.iter().position(|&c| c == 0).map_or(f, |at| &f[..at])
}

/// A session with the key it is stored under.
type Stored = (SessionKey, Session);

/// One SIP dialog's media, as created by an `offer`.
#[derive(Clone)]
struct Session {
    /// When the offer created it (seconds since the Unix epoch).
    created: u64,
    /// Which dialog under its key this is: a dialog made again under the
    /// same key (after a `delete`) has another, its re-offers the same, so
    /// what was meant for the earlier one (a `delete-delay`) never reaches
    /// it.
    generation: u64,
    /// The answer's `to-tag`, once answered.
    to_tag: Option<Vec<u8>>,
    /// Interface indices: offerer's side, answerer's side.
    dir: [InterfaceId; 2],
    /// One relay call per media section (`None` for rejected sections).
    media: Vec<Option<MediaState>>,
    /// Each party's latest SDP, by tag (what subscriptions offer).
    sdps: Vec<(Vec<u8>, Vec<u8>)>,
    /// The `o=` versions the relay set (`sdp-version`).
    versions: sdp_edits::Versions,
    /// Legacy OSRTP: which of the offerer's sections were folded pairs
    /// (`accept-legacy`), which sections offered to the answerer were
    /// doubled (`offer-legacy`).
    legacy: [Vec<bool>; 2],
    /// The `via-branch` of the latest offer that had one: a `delete`
    /// naming another branch leaves the dialog alone.
    via_branch: Option<Vec<u8>>,
    /// `track-state`: the dialog as last agreed (with its key), while a
    /// re-offer waits for its answer; its relay calls are kept until then
    /// ([`Control::rollback`]).
    checkpoint: Option<Box<Stored>>,
}

impl Session {
    /// A session of only these sections (to end them).
    fn bare(dir: [InterfaceId; 2], media: Vec<Option<MediaState>>) -> Self {
        Session {
            created: 0,
            generation: 0,
            to_tag: None,
            dir,
            media,
            sdps: Vec::new(),
            versions: Vec::new(),
            legacy: [Vec::new(), Vec::new()],
            via_branch: None,
            checkpoint: None,
        }
    }

    /// Remember `sdp` as the latest of the party tagged `tag`.
    fn remember(&mut self, tag: &[u8], sdp: &[u8]) {
        match self.sdps.iter_mut().find(|(t, _)| t == tag) {
            Some(e) => e.1 = sdp.to_vec(),
            None => self.sdps.push((tag.to_vec(), sdp.to_vec())),
        }
    }
}

/// Encode the reply to a request into `out`: its result, SDP or fields,
/// and `warning` (on success); or the error. Returns the length.
fn write_outcome(
    cookie: &[u8],
    out: &mut [u8],
    outcome: &Result<Reply, Error>,
    sdp_buf: &[u8],
    warning: Option<&str>,
) -> Result<usize, rtpflux_ng::bencode::Overflow> {
    let warn = |e: &mut Encoder<'_>| -> Result<(), rtpflux_ng::bencode::Overflow> {
        if let Some(w) = warning {
            e.bytes(b"warning")?;
            e.bytes(w.as_bytes())?;
        }
        Ok(())
    };
    write_reply(cookie, out, |e: &mut Encoder<'_>| {
        e.dict()?;
        match outcome {
            Ok(Reply::Pong) => {
                e.bytes(b"result")?;
                e.bytes(b"pong")?;
            }
            Ok(Reply::Ok) => {
                e.bytes(b"result")?;
                e.bytes(b"ok")?;
                warn(e)?;
            }
            Ok(Reply::Sdp(n)) => {
                e.bytes(b"result")?;
                e.bytes(b"ok")?;
                e.bytes(b"sdp")?;
                e.bytes(&sdp_buf[..*n])?;
                warn(e)?;
            }
            Ok(Reply::Fields(fields)) => {
                let mut all = fields.clone();
                all.push((b"result".to_vec(), B::Bytes(b"ok".to_vec())));
                if let Some(w) = warning {
                    all.push((b"warning".to_vec(), B::Bytes(w.as_bytes().to_vec())));
                }
                all.sort_by(|a, b| a.0.cmp(&b.0));
                for (k, v) in &all {
                    e.bytes(k)?;
                    v.encode(e)?;
                }
            }
            Err(reason) => {
                e.bytes(b"error-reason")?;
                e.bytes(reason.to_string().as_bytes())?;
                e.bytes(b"result")?;
                e.bytes(b"error")?;
            }
        }
        e.end()
    })
}

/// A digest of an `ng` request body, to tell a retransmission from a new
/// request that reuses the cookie.
fn request_digest(body: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut h);
    h.finish()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A cached reply's key: who sent the request (none for requests handed
/// over without a sender) and its cookie.
type CacheKey = (Option<std::net::SocketAddr>, Vec<u8>);

/// The control-plane state: the relay and the dialogs it serves.
pub struct Control {
    relay: Relay,
    /// When it started (`statistics` reports the uptime).
    started: Instant,
    /// Traffic per second, for `statistics`.
    rates: query::Rates,
    interfaces: Vec<Interface>,
    sessions: HashMap<(Vec<u8>, Vec<u8>), Session>,
    /// Media subscriptions, by `call-id` and the subscription's tag.
    subscriptions: HashMap<(Vec<u8>, Vec<u8>), subscribe::Subscription>,
    subscription_seq: u64,
    /// Deletes waiting for their `delete-delay`: when, `call-id`, tag.
    delayed_deletes: crate::lifecycle::Delays<Instant, Selector>,
    /// Replies kept for retransmissions (`ngcache`).
    /// Each with a digest of the request it answers: a cookie reused for
    /// another request is not a retransmission.
    cache: crate::ngcache::ReplyCache<CacheKey, (u64, Vec<u8>)>,
    /// Datagrams longer than this are ignored (`control.max_message`).
    max_message: usize,
    sdp_buf: Vec<u8>,
    reply: Vec<u8>,
    /// Source of SRTP master keys (opened on first use).
    random: Option<std::fs::File>,
    stats: Arc<ControlStats>,
    /// Where the dialogs are written ([`crate::state`]).
    state_file: Option<std::path::PathBuf>,
    /// … and the Redis writer, if they also go there ([`crate::redis`]).
    state_redis: Option<crate::redis::Writer>,
    /// Where `start recording` writes ([`crate::recording`]).
    recording_dir: Option<std::path::PathBuf>,
    /// What recordings become when they end ([`crate::recording`]).
    recording_settings: crate::recording::Settings,
    /// Recording file names (`[recording] file_name`).
    recording_file_name: String,
    /// Metadata of every recording (`[recording.metadata]`).
    recording_meta: std::collections::BTreeMap<String, String>,
    /// Blocking, recording and announcements per relay call, to be saved.
    extras: HashMap<CallId, state::SavedExtras>,
    /// Questions from the web UI.
    web: Option<web::WebInbox>,
    /// Messages from TCP, HTTP and WebSocket connections.
    streams: Option<streams::NgInbox>,
    /// The native API: its endpoints, and requests from its connections.
    native: native::Native,
    native_inbox: Option<native::NativeInbox>,
    /// Media events from the workers (key presses, announcements, …).
    media_events: Option<crate::relay::media_events::MediaEventInbox>,
    /// The dialogs changed since the state file was written, and when it
    /// was.
    state_dirty: bool,
    state_written: Instant,
    /// An offer's relay calls end this long after it unless answered
    /// (`sessions.offer_timeout`).
    offer_timeout: Duration,
    /// The most dialogs at once (`sessions.max`); a new one beyond it is
    /// refused.
    max_sessions: usize,
    /// A dialog ends this many seconds after its first offer, whatever its
    /// media (`sessions.final_timeout`; 0: never).
    final_timeout: u64,
    /// `strict-source` for every call (`sessions.strict_source`).
    strict_source: bool,
    /// What the request being handled did not do as asked: the reply's
    /// `warning` (rtpengine's), when it succeeds.
    warnings: Vec<String>,
    /// `loop protect`: the attribute this relay marks the SDP it writes
    /// with (`rtpflux:<instance>`), and seeing it in an SDP means the SDP
    /// has been through this relay already.
    loop_attr: Vec<u8>,
    /// `connect`ed parties ((call-id, tag) of each), kept in the state.
    connections: Vec<(SessionKey, SessionKey)>,
    /// `connect` with `directional`: copies of a party's media to another
    /// ([`copies`]), kept in the state.
    copies: Vec<copies::Copy>,
    /// Parties made by `create`, so far (for their made-up tags).
    created_seq: u64,
    /// The last dialog generation given ([`Session::generation`]).
    generation_seq: u64,
    /// The relay calls a pending checkpoint has, while an offer is handled:
    /// not ended by it.
    keep_calls: Vec<CallId>,
    /// The parties' labels, per call ([`parties`]).
    labels: parties::Labels,
    /// The relay's ICE agent towards endpoints that use ICE, and its Ta.
    ice_mode: IceMode,
    ice_pacing_ms: u64,
    /// Per interface: the relay's server-reflexive address, if known.
    srflx: crate::srflx::Shared,
    /// Per relay call and leg (`true`: its B leg): the endpoint's ICE and
    /// the generation the relay's full agent towards it runs with.
    ice: HashMap<(CallId, CallLeg), IceLeg>,
}

/// One leg's endpoint ICE ([`Control::ice`]).
#[derive(Debug, Clone, Default)]
pub(super) struct IceLeg {
    pub(super) peer: IcePeer,
    /// The endpoint's ufrag and password and the relay's ufrag the full
    /// agent runs with (none: not started).
    pub(super) running: Option<(Vec<u8>, Vec<u8>, [u8; ICE_UFRAG_LEN])>,
}

/// The commands that change what [`state::SavedExtras`] records.
fn sets_extras(command: &[u8]) -> bool {
    matches!(
        command,
        b"play media"
            | b"stop media"
            | b"start recording"
            | b"stop recording"
            | b"block media"
            | b"unblock media"
            | b"block DTMF"
            | b"unblock DTMF"
    )
}

/// Milliseconds since the Unix epoch.
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn list_contains(d: &Dict<'_>, key: &[u8], item: &[u8]) -> bool {
    match d.get(key) {
        Some(Value::List(l)) => l.iter().any(|v| v == Value::Bytes(item)),
        Some(Value::Bytes(b)) => b.split(|&c| c == b' ').any(|w| w == item),
        _ => false,
    }
}

fn required<'a>(d: &Dict<'a>, key: &str) -> Result<&'a [u8], Error> {
    d.get_bytes(key.as_bytes())
        .ok_or_else(|| Error::Missing(key.to_string()))
}

impl Control {
    #[must_use]
    pub fn new(mut relay: Relay, interfaces: Vec<Interface>) -> Self {
        let media_events = relay.take_media_events();
        Control {
            relay,
            started: Instant::now(),
            rates: query::Rates::default(),
            interfaces,
            sessions: HashMap::new(),
            subscriptions: HashMap::new(),
            subscription_seq: 0,
            delayed_deletes: crate::lifecycle::Delays::default(),
            cache: crate::ngcache::ReplyCache::new(
                CACHE_ENTRIES,
                CACHE_BYTES,
                u64::try_from(CACHE_TTL.as_millis()).unwrap_or(u64::MAX),
            ),
            max_message: MAX_DATAGRAM,
            sdp_buf: vec![0; MAX_DATAGRAM],
            reply: vec![0; MAX_DATAGRAM],
            random: None,
            stats: Arc::default(),
            state_file: None,
            state_redis: None,
            recording_dir: None,
            recording_settings: crate::recording::Settings::default(),
            recording_file_name: crate::recording::naming::DEFAULT_FILE_NAME.to_owned(),
            recording_meta: std::collections::BTreeMap::new(),
            extras: HashMap::new(),
            web: None,
            streams: None,
            native: native::Native::fresh(),
            native_inbox: None,
            media_events,
            state_dirty: false,
            state_written: Instant::now(),
            offer_timeout: Duration::from_secs(3_600),
            max_sessions: usize::MAX,
            final_timeout: 0,
            warnings: Vec::new(),
            connections: Vec::new(),
            labels: HashMap::new(),
            keep_calls: Vec::new(),
            created_seq: 0,
            generation_seq: 0,
            copies: Vec::new(),
            loop_attr: {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                std::process::id().hash(&mut h);
                std::time::SystemTime::now().hash(&mut h);
                format!("rtpflux:{:016x}", h.finish()).into_bytes()
            },
            strict_source: false,
            ice_mode: IceMode::Full,
            ice_pacing_ms: 50,
            srflx: crate::srflx::Shared::default(),
            ice: HashMap::new(),
        }
    }

    /// The relay's ICE agent towards endpoints that use ICE (`[ice]`).
    pub fn set_ice(&mut self, mode: IceMode, pacing_ms: u64) {
        self.ice_mode = mode;
        self.ice_pacing_ms = pacing_ms;
    }

    /// Where the relay's server-reflexive address on each interface is
    /// kept, as a STUN server reports it ([`crate::srflx`]).
    /// The server-reflexive addresses, as they are learned (for the web
    /// UI).
    #[must_use]
    pub fn srflx(&self) -> crate::srflx::Shared {
        self.srflx.clone()
    }

    pub fn set_srflx(&mut self, srflx: crate::srflx::Shared) {
        self.srflx = srflx;
    }

    /// The relay's server-reflexive address on `interface`, if known.
    fn srflx_of(&self, interface: InterfaceId) -> Option<IpAddr> {
        self.srflx
            .read()
            .ok()
            .and_then(|v| v.get(interface.get()).copied().flatten())
    }

    /// Allow `start recording`, into `dir`.
    pub fn set_recording_dir(&mut self, dir: Option<std::path::PathBuf>) {
        self.recording_dir = dir;
    }

    /// What recordings are converted to by default (`start recording` can
    /// override it per call).
    pub fn set_recording_settings(&mut self, settings: crate::recording::Settings) {
        self.recording_settings = settings;
    }

    /// How recording files are named (`[recording] file_name`, checked) and
    /// the metadata every recording carries (`[recording.metadata]`).
    pub fn set_recording_naming(
        &mut self,
        file_name: &str,
        metadata: std::collections::BTreeMap<String, String>,
    ) {
        file_name.clone_into(&mut self.recording_file_name);
        self.recording_meta = metadata;
    }

    /// Write the dialogs to `path` after every change ([`Control::save`]).
    pub fn set_state_file(&mut self, path: Option<std::path::PathBuf>) {
        self.state_file = path;
    }

    /// Also keep the dialogs in Redis ([`Control::save`]); `restore` reads
    /// the newer of the file and Redis.
    pub fn set_state_redis(&mut self, writer: Option<crate::redis::Writer>) {
        self.state_redis = writer;
    }

    /// How long an offer waits for its answer (`sessions.offer_timeout`).
    pub fn set_offer_timeout(&mut self, t: Duration) {
        self.offer_timeout = t;
    }

    /// The most dialogs at once (`sessions.max`): an offer for a new one
    /// beyond it is refused. Re-offers of existing dialogs always pass.
    pub fn set_max_sessions(&mut self, n: usize) {
        self.max_sessions = n;
    }

    /// Treat every call as flagged `strict-source`
    /// (`sessions.strict_source`).
    pub fn set_strict_source(&mut self, on: bool) {
        self.strict_source = on;
    }

    /// End dialogs this many seconds after their first offer, whatever
    /// their media (`sessions.final_timeout`); 0: never.
    pub fn set_final_timeout(&mut self, secs: u64) {
        self.final_timeout = secs;
    }

    /// End the dialogs older than `final_timeout`.
    fn end_overdue(&mut self) {
        if self.final_timeout == 0 {
            return;
        }
        let now = unix_now();
        let overdue: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.created) >= self.final_timeout)
            .map(|(k, _)| k.clone())
            .collect();
        if overdue.is_empty() {
            return;
        }
        for key in overdue {
            if let Some(s) = self.sessions.remove(&key) {
                log::info!(
                    "call {}: ended after final_timeout ({} s)",
                    String::from_utf8_lossy(&key.0),
                    self.final_timeout
                );
                self.end_session(&s);
            }
        }
        self.gauges();
        self.mark_dirty();
    }

    /// Tell the relay which of dialog `key`'s calls are on hold, from both
    /// parties' latest SDPs: a section is held when either party's is
    /// `sendonly`, `recvonly` or `inactive`, or has the `0.0.0.0` address
    /// (RFC 3264 §8.4). A held call's media timeout is
    /// `sessions.silent_timeout`.
    fn update_holds(&mut self, key: &SessionKey) {
        let Some(s) = self.sessions.get(key) else {
            return;
        };
        let tags = [Some(base_tag(&key.1)), s.to_tag.as_deref()];
        let mut held = vec![false; s.media.len()];
        for tag in tags.into_iter().flatten() {
            let Some((_, sdp)) = s.sdps.iter().find(|(t, _)| t == tag) else {
                continue;
            };
            let mut media = [rtpflux_core::sdp::Media::EMPTY; MAX_MEDIA];
            let Ok(n) = rtpflux_core::sdp::read_media(sdp, &mut media) else {
                continue;
            };
            for (h, m) in held.iter_mut().zip(&media[..n]) {
                *h |= m.direction.held() || m.address.is_some_and(|a| a.is_unspecified());
            }
        }
        let ids: Vec<(CallId, bool)> = s
            .media
            .iter()
            .zip(held)
            .filter_map(|(st, h)| st.as_ref().map(|st| (st.ports.id, h)))
            .collect();
        for (id, h) in ids {
            Self::logged("setting its media timeout", id, self.relay.set_held(id, h));
        }
    }

    /// Drop the dialogs whose relay calls ended on their own (no media,
    /// or no answer, in time): their ports are free and may already serve
    /// another call. The dialog's other sections end with it.
    pub fn prune_ended(&mut self) {
        self.link_gauges();
        if !self.delayed_deletes.is_empty() {
            self.due_deletes();
        }
        self.end_overdue();
        // Leases that ran out, endpoints a delayed delete ended.
        self.native_reconcile("ended");
        self.native_media_events();
        let ended = self.relay.take_ended();
        if ended.is_empty() {
            return;
        }
        let gone: Vec<(Vec<u8>, Vec<u8>)> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.media
                    .iter()
                    .flatten()
                    .any(|m| ended.contains(&m.ports.id))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in gone {
            if let Some(s) = self.sessions.remove(&key) {
                log::info!(
                    "call {}: ended (no media, or no answer, in time)",
                    String::from_utf8_lossy(&key.0)
                );
                self.end_session(&s);
            }
        }
        self.end_subscriptions_of(&ended);
        for id in ended {
            self.extras.remove(&id);
            self.ice_forget(id);
        }
        self.native_reconcile("timeout");
        self.gauges();
        self.mark_dirty();
    }

    /// The `ng` server's counters (for metrics).
    #[must_use]
    pub fn stats(&self) -> Arc<ControlStats> {
        Arc::clone(&self.stats)
    }

    /// Refresh the gauges of what links parties, and copy the Redis
    /// writer's counts: cheap (counts only), after every request and on
    /// every periodic pass.
    fn link_gauges(&self) {
        let s = &self.stats;
        s.connections
            .store(self.connections.len() as u64, Ordering::Relaxed);
        s.copies.store(self.copies.len() as u64, Ordering::Relaxed);
        s.subscriptions
            .store(self.subscriptions.len() as u64, Ordering::Relaxed);
        self.native_gauges();
        s.delayed_deletes
            .store(self.delayed_deletes.len() as u64, Ordering::Relaxed);
        if let Some(w) = &self.state_redis {
            let c = w.counts();
            s.redis_writes
                .store(c.written.load(Ordering::Relaxed), Ordering::Relaxed);
            s.redis_failures
                .store(c.failures.load(Ordering::Relaxed), Ordering::Relaxed);
            s.redis_failing.store(
                u64::from(c.failing.load(Ordering::Relaxed)),
                Ordering::Relaxed,
            );
        }
    }

    /// Refresh the session and call gauges.
    fn gauges(&mut self) {
        self.stats
            .sessions
            .store(self.sessions.len() as u64, Ordering::Relaxed);
        let calls = self.relay.totals().active_calls;
        self.stats.calls.store(calls as u64, Ordering::Relaxed);
        self.prune_parties();
    }

    /// Statistics of the relay underneath.
    pub fn relay(&mut self) -> &mut Relay {
        &mut self.relay
    }

    /// Run one command.
    fn dispatch(&mut self, command: &[u8], body: &Dict<'_>) -> Result<Reply, Error> {
        match command {
            b"ping" => Ok(Reply::Pong),
            b"offer" if list_contains(body, b"flags", b"fragment") => {
                self.fragment(body).map(Reply::Sdp)
            }
            b"offer" => self.offer(body).map(|n| {
                self.record_call(body);
                self.label_sdp_sender(body, b"from-tag");
                self.dtmf_delay_sdp_sender(body, b"from-tag");
                Reply::Sdp(n)
            }),
            b"answer" => self.answer(body).map(|n| {
                self.record_call(body);
                self.label_sdp_sender(body, b"to-tag");
                self.dtmf_delay_sdp_sender(body, b"to-tag");
                Reply::Sdp(n)
            }),
            b"delete" => self.delete(body).map(|()| Reply::Ok),
            b"pause recording" => self.pause_recording(body).map(|()| Reply::Ok),
            b"list" => Ok(Reply::Fields(self.list(body))),
            b"query" => self.query(body).map(Reply::Fields),
            b"play media" => self.play(body, true).map(Reply::Fields),
            b"stop media" => self.play(body, false).map(|_| Reply::Ok),
            b"start recording" => self.record(body, true).map(|()| Reply::Ok),
            b"stop recording" => self.record(body, false).map(|()| Reply::Ok),
            b"block media" => self.block(body, Blocked::Media, true).map(|()| Reply::Ok),
            b"unblock media" => self.block(body, Blocked::Media, false).map(|()| Reply::Ok),
            b"block DTMF" => self.block(body, Blocked::Dtmf, true).map(|()| Reply::Ok),
            b"unblock DTMF" => self.block(body, Blocked::Dtmf, false).map(|()| Reply::Ok),
            b"silence media" => self.block(body, Blocked::Silence, true).map(|()| Reply::Ok),
            b"unsilence media" => self
                .block(body, Blocked::Silence, false)
                .map(|()| Reply::Ok),
            b"play DTMF" => self.play_dtmf(body).map(|()| Reply::Ok),
            b"statistics" => Ok(Reply::Fields(self.statistics())),
            b"publish" => self.publish(body).map(|n| {
                self.label_sdp_sender(body, b"from-tag");
                Reply::Sdp(n)
            }),
            b"subscribe request" => self.subscribe_request(body).map(Reply::Fields),
            b"subscribe answer" => self.subscribe_answer(body).map(|()| Reply::Ok),
            b"unsubscribe" => self.unsubscribe(body).map(|()| Reply::Ok),
            b"connect" => self.connect(body).map(|()| Reply::Ok),
            b"rollback" => self.rollback(body).map(Reply::Fields),
            b"create" => self.create(body).map(|(call_id, tag, n)| {
                Reply::Fields(vec![
                    (b"call-id".to_vec(), B::Bytes(call_id)),
                    (b"from-tag".to_vec(), B::Bytes(tag)),
                    (b"sdp".to_vec(), B::Bytes(self.sdp_buf[..n].to_vec())),
                ])
            }),
            b"create answer" => self.create_answer(body).map(|()| Reply::Ok),
            b"create from offer" => self.create_from_offer(body).map(|(call_id, tag, n)| {
                Reply::Fields(vec![
                    (b"call-id".to_vec(), B::Bytes(call_id)),
                    (b"from-tag".to_vec(), B::Bytes(tag)),
                    (b"sdp".to_vec(), B::Bytes(self.sdp_buf[..n].to_vec())),
                ])
            }),
            b"inject start" => self.inject(body, true).map(|()| Reply::Ok),
            b"mesh" => self.mesh(body).map(|()| Reply::Ok),
            b"inject stop" => self.inject(body, false).map(|()| Reply::Ok),
            other => Err(Error::Request(RequestError::UnknownCommand(
                String::from_utf8_lossy(other).into_owned(),
            ))),
        }
    }

    /// Handle one datagram; returns the reply to send, if any.
    pub fn handle(&mut self, datagram: &[u8]) -> Option<&[u8]> {
        self.handle_from(datagram, None)
    }

    /// [`Control::handle`] for a datagram from `from`: its reply is cached
    /// for retransmissions from that sender only.
    pub fn handle_from(
        &mut self,
        datagram: &[u8],
        from: Option<std::net::SocketAddr>,
    ) -> Option<&[u8]> {
        let msg = match parse_message(datagram) {
            Ok(m) => m,
            Err(e) => {
                log::debug!("ng: malformed request: {e:?}");
                return None;
            }
        };
        let now = self.cache_now();
        let key = (from, msg.cookie.to_vec());
        // The body as sent (after the cookie and its space): a
        // retransmission repeats it byte for byte.
        let digest = request_digest(datagram.get(msg.cookie.len() + 1..).unwrap_or_default());
        match self.cache.get(now, &key) {
            Some((d, _)) if *d == digest => {
                self.stats.retransmissions.fetch_add(1, Ordering::Relaxed);
                return self.cache.get(now, &key).map(|(_, r)| r.as_slice());
            }
            Some(_) => log::debug!(
                "ng: cookie {} reused for another request; running it",
                String::from_utf8_lossy(msg.cookie)
            ),
            None => {}
        }
        let command = msg.body.get_bytes(b"command").unwrap_or_default();
        self.stats.count(command);
        let call_id = String::from_utf8_lossy(msg.body.get_bytes(b"call-id").unwrap_or_default())
            .into_owned();
        self.warnings.clear();
        let outcome = self.dispatch(command, &msg.body);
        // Endpoints of the native API an `ng` command ended.
        self.native_reconcile("ended");
        self.link_gauges();
        let warning = (!self.warnings.is_empty()).then(|| self.warnings.join("; "));
        if let Some(w) = &warning {
            log::debug!(
                "ng {} {call_id}: warning: {w}",
                String::from_utf8_lossy(command)
            );
        }
        let written = write_outcome(
            msg.cookie,
            &mut self.reply,
            &outcome,
            &self.sdp_buf,
            warning.as_deref(),
        );
        let Ok(n) = written else {
            log::warn!("ng: reply too large");
            return None;
        };
        match &outcome {
            Err(reason) => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                log::info!(
                    "ng {} {call_id}: {reason}",
                    String::from_utf8_lossy(command)
                );
            }
            Ok(_) if sets_extras(command) => {
                self.mark_dirty();
            }
            Ok(_)
                if matches!(
                    command,
                    b"subscribe request" | b"subscribe answer" | b"unsubscribe"
                ) =>
            {
                self.mark_dirty();
            }
            Ok(_)
                if matches!(
                    command,
                    b"offer"
                        | b"answer"
                        | b"delete"
                        | b"publish"
                        | b"create"
                        | b"create answer"
                        | b"create from offer"
                ) =>
            {
                self.mark_dirty();
                let sections = self
                    .sessions
                    .iter()
                    .filter(|((c, _), _)| c.as_slice() == call_id.as_bytes())
                    .map(|(_, s)| s.media.iter().flatten().count())
                    .sum::<usize>();
                log::info!(
                    "call {call_id}: {}, {sections} relayed media section(s)",
                    String::from_utf8_lossy(command)
                );
            }
            Ok(_) => {}
        }
        self.gauges();
        self.remember(key, digest, n);
        Some(&self.reply[..n])
    }

    /// Cache the reply to `key` for retransmissions (`ngcache`); a cookie
    /// longer than [`MAX_COOKIE`] is not.
    fn remember(&mut self, key: CacheKey, digest: u64, n: usize) {
        if key.1.len() > MAX_COOKIE {
            return;
        }
        let size = key.1.len() + n;
        let now = self.cache_now();
        self.cache
            .insert(now, key, (digest, self.reply[..n].to_vec()), size);
    }

    /// The cache's clock: milliseconds since the start.
    fn cache_now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Ignore `ng` datagrams longer than `n` octets (`control.max_message`).
    pub fn set_max_message(&mut self, n: usize) {
        self.max_message = n;
    }

    fn interface(&self, name: &[u8]) -> Result<InterfaceId, Error> {
        self.interfaces
            .iter()
            .position(|i| i.name.as_bytes() == name)
            .map(InterfaceId::new)
            .ok_or_else(|| {
                Error::Request(RequestError::UnknownInterface(
                    String::from_utf8_lossy(name).into_owned(),
                ))
            })
    }

    /// The interfaces of the offerer's and the answerer's side: the first
    /// interface, unless `direction` names others. A single name is used
    /// for both sides, so that a call meant to stay on one network never
    /// falls back to the first interface (often the public one).
    fn directions(&self, d: &Dict<'_>) -> Result<[InterfaceId; 2], Error> {
        let [a, b] = self.named_directions(d)?;
        let a = a.unwrap_or(InterfaceId::new(0));
        Ok([a, b.unwrap_or(a)])
    }

    /// The interfaces `direction` names for the offerer's and the
    /// answerer's side; a single name is both.
    fn named_directions(&self, d: &Dict<'_>) -> Result<[Option<InterfaceId>; 2], Error> {
        let mut dir = [None; 2];
        if let Some(Value::List(l)) = d.get(b"direction") {
            for (k, v) in l.iter().take(2).enumerate() {
                if let Value::Bytes(name) = v {
                    dir[k] = Some(self.interface(name)?);
                }
            }
            if l.iter().count() == 1 {
                dir[1] = dir[0];
            }
        }
        Ok(dir)
    }

    fn end_session(&mut self, s: &Session) {
        self.end_media(&s.media);
        // And those only its checkpoint still had.
        if let Some(c) = &s.checkpoint {
            let only = Self::only_in(&c.1.media, &s.media);
            self.end_media(&only);
        }
    }

    /// The sections of `a` whose relay calls `b` does not have.
    fn only_in(a: &[Option<MediaState>], b: &[Option<MediaState>]) -> Vec<Option<MediaState>> {
        a.iter()
            .map(|st| st.filter(|st| !b.iter().flatten().any(|x| x.ports.id == st.ports.id)))
            .collect()
    }

    /// End these sections' relay calls.
    fn end_media(&mut self, media: &[Option<MediaState>]) {
        let ids: Vec<CallId> = media.iter().flatten().map(|m| m.ports.id).collect();
        self.end_subscriptions_of(&ids);
        for m in media.iter().flatten() {
            self.extras.remove(&m.ports.id);
            self.ice_forget(m.ports.id);
            if let Err(e) = self.relay.delete_call(m.ports.id) {
                log::warn!("deleting relay call {}: {e}", m.ports.id);
            }
        }
    }

    /// The `loop protect` flag.
    fn loop_protect(req: &Dict<'_>) -> bool {
        list_contains(req, b"flags", b"loop-protect")
            || list_contains(req, b"flags", b"loop protect")
    }

    /// `loop protect` and an SDP this relay already wrote: returned as it
    /// is (nothing is set up), its length; `None` to go on.
    fn looped(&mut self, req: &Dict<'_>, sdp: &[u8]) -> Option<usize> {
        if !Self::loop_protect(req) {
            return None;
        }
        let mine = sdp
            .split(|&c| c == b'\n')
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
            .any(|l| l.strip_prefix(b"a=") == Some(&self.loop_attr[..]));
        let n = sdp.len();
        (mine && n <= self.sdp_buf.len()).then(|| {
            self.sdp_buf[..n].copy_from_slice(sdp);
            n
        })
    }

    /// `media echo` on the sections `states` after an offer (`offer`: its
    /// receiver is B) or an answer (its receiver is A).
    fn apply_echo(
        &mut self,
        states: &[Option<MediaState>],
        modes: Option<[crate::relay::Echo; 2]>,
        offer: bool,
    ) {
        let Some([receiver, sender]) = modes else {
            return;
        };
        let (r, s) = if offer {
            (Party::B, Party::A)
        } else {
            (Party::A, Party::B)
        };
        for st in states.iter().flatten() {
            let mut legs = [crate::relay::Echo::Normal; 2];
            legs[usize::from(st.leg(r) == CallLeg::B)] = receiver;
            legs[usize::from(st.leg(s) == CallLeg::B)] = sender;
            Self::logged(
                "media echo",
                st.ports.id,
                self.relay.echo(st.ports.id, legs),
            );
            // Kept with the call's extras, for a restart.
            self.extras.entry(st.ports.id).or_default().echo = legs.map(crate::relay::Echo::code);
        }
    }

    /// The relay calls and legs of the party tagged `tag` in call
    /// `call_id`, one per media section (`None`: a refused section), with
    /// the audio it receives in a codec the relay converts, if known.
    fn party_legs(&self, call_id: &[u8], tag: &[u8]) -> Option<Vec<Option<PartyLeg>>> {
        // A party in several dialogs: its first.
        let mut keys: Vec<&SessionKey> = self.sessions.keys().filter(|k| k.0 == call_id).collect();
        keys.sort();
        keys.into_iter().find_map(|k| {
            let s = &self.sessions[k];
            let party = parties::side_of(k, s, tag)?;
            Some(
                s.media
                    .iter()
                    .map(|st| {
                        st.as_ref()
                            .map(|st| ((st.ports.id, st.leg(party)), st.audio[party.index()]))
                    })
                    .collect(),
            )
        })
    }

    /// `connect`: the party `from-tag` of `call-id` and the party
    /// `to-tag` of `to-call-id` (default: the same call) talk to each
    /// other, section by section; the parties they leave are detached.
    /// Their codecs are converted when they differ; the connection is kept
    /// in the state.
    fn connect(&mut self, d: &Dict<'_>) -> Result<(), Error> {
        if list_contains(d, b"flags", b"directional")
            || parties::all_parties(d)
            || d.get(b"from-tags").is_some()
        {
            return self.connect_directional(d);
        }
        // Each party by tag or label (`label`/`from-label`, `to-label`).
        let call_id = required(d, "call-id")?;
        let to_call = d.get_bytes(b"to-call-id").unwrap_or(call_id);
        let from = self
            .party(d, call_id, parties::Which::From)?
            .ok_or_else(|| Error::Missing("from-tag".to_owned()))?;
        let to = self
            .party(d, to_call, parties::Which::To)?
            .ok_or_else(|| Error::Missing("to-tag".to_owned()))?;
        let (from, to) = (from.as_slice(), to.as_slice());
        if call_id == to_call && from == to {
            return Err(Error::unsupported("connect: a party to itself".to_owned()));
        }
        self.connect_parties(
            &(call_id.to_vec(), from.to_vec()),
            &(to_call.to_vec(), to.to_vec()),
        )
    }

    /// Connect the parties `a` and `b` ((call-id, tag) each), section by
    /// section, and keep the connection.
    pub(super) fn connect_parties(&mut self, a: &SessionKey, b: &SessionKey) -> Result<(), Error> {
        let x = self.party_legs(&a.0, &a.1).ok_or(Error::UnknownCallOrTag)?;
        let y = self.party_legs(&b.0, &b.1).ok_or(Error::UnknownCallOrTag)?;
        if x.len() != y.len() {
            self.warnings.push(format!(
                "connect: {} and {} media sections; the first {} are connected",
                x.len(),
                y.len(),
                x.len().min(y.len())
            ));
        }
        for ((x, ax), (y, ay)) in x.into_iter().zip(y).filter_map(|(x, y)| Some((x?, y?))) {
            // Each one's audio converted to the other's codec, when they
            // differ and the relay converts both.
            let transcode = match (ax, ay) {
                (Some(ax), Some(ay)) if ax.1 != ay.1 => [
                    Some(crate::relay::Transcode {
                        from: ax,
                        to: ay,
                        bitrate: None,
                    }),
                    Some(crate::relay::Transcode {
                        from: ay,
                        to: ax,
                        bitrate: None,
                    }),
                ],
                _ => [None, None],
            };
            if !self.relay.connect(x, y, transcode).map_err(Error::from)? {
                return Err(Error::UnknownCallOrTag);
            }
        }
        // Kept, to be connected again after a restart.
        let pair = (a.clone(), b.clone());
        self.connections
            .retain(|(a, b)| ![a, b].iter().any(|p| **p == pair.0 || **p == pair.1));
        self.connections.push(pair);
        self.mark_dirty();
        Ok(())
    }

    /// A dialog generation not given before.
    fn new_generation(&mut self) -> u64 {
        self.generation_seq += 1;
        self.generation_seq
    }

    fn delete(&mut self, d: &Dict<'_>) -> Result<(), Error> {
        // What selects the dialog besides the call: a tag, its answerer (a
        // fork that lost must not end the call another fork answered) and
        // the offer's branch. Nothing selected: a warning, or with `fatal`
        // an error.
        let sel = Selector {
            call_id: required(d, "call-id")?.to_vec(),
            from_tag: d.get_bytes(b"from-tag").map(<[u8]>::to_vec),
            to_tag: d.get_bytes(b"to-tag").map(<[u8]>::to_vec),
            via: d.get_bytes(b"via-branch").map(<[u8]>::to_vec),
            generations: None,
        };
        let selected = self.sessions.iter().any(|(k, s)| sel.matches(k, s));
        if !selected {
            if list_contains(d, b"flags", b"fatal") {
                return Err(Error::UnknownCall);
            }
            // rtpengine's words, which proxies may look for.
            self.warnings
                .push("Call-ID not found or tags didn't match".to_owned());
            return Ok(());
        }
        // `delete-delay` (seconds): the call goes on that long, so that
        // media still in flight (or a late re-INVITE's) is relayed.
        let delay = args::number_or_none(d, b"delete-delay")
            .or_else(|| args::number_or_none(d, b"delete delay"))
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0);
        if delay > 0 {
            // The dialogs selected now, not those made again meanwhile.
            let generations = self
                .sessions
                .iter()
                .filter(|(k, s)| sel.matches(k, s))
                .map(|(_, s)| s.generation)
                .collect();
            let sel = Selector {
                generations: Some(generations),
                ..sel
            };
            self.delayed_deletes
                .schedule(Instant::now() + Duration::from_secs(delay.min(3600)), sel);
            return Ok(());
        }
        self.delete_now(&sel)
    }

    /// Run the deletes whose delay is over.
    /// A relay operation that is best effort here (undoing, or telling a
    /// call's state): its failure is logged with what was being done.
    fn logged<T>(what: &str, id: CallId, r: Result<T, crate::relay::RelayError>) {
        if let Err(e) = r {
            log::warn!("call {id}: {what}: {e}");
        }
    }

    fn due_deletes(&mut self) {
        let due = self.delayed_deletes.due(Instant::now());
        if due.is_empty() {
            return;
        }
        for sel in due {
            match self.delete_now(&sel) {
                // Gone meanwhile (timed out, deleted again): nothing to do.
                Ok(()) | Err(Error::UnknownCall) => {}
                Err(e) => log::warn!(
                    "call {}: delayed delete: {e}",
                    String::from_utf8_lossy(&sel.call_id)
                ),
            }
        }
        self.gauges();
        self.mark_dirty();
    }

    fn delete_now(&mut self, sel: &Selector) -> Result<(), Error> {
        let keys: Vec<_> = self
            .sessions
            .iter()
            .filter(|(k, s)| sel.matches(k, s))
            .map(|(k, _)| k.clone())
            .collect();
        if keys.is_empty() {
            return Err(Error::UnknownCall);
        }
        for k in keys {
            if let Some(s) = self.sessions.remove(&k) {
                self.end_session(&s);
            }
        }
        Ok(())
    }
}

/// Serve `ng` requests on `sockets` until `stop` is set.
///
/// # Errors
///
/// The epoll set cannot be created or a socket cannot be registered.
pub fn serve(
    control: &mut Control,
    sockets: &[std::net::UdpSocket],
    stop: &std::sync::atomic::AtomicBool,
) -> Result<(), nix::Error> {
    use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
    use std::os::fd::AsFd;
    use std::sync::atomic::Ordering;

    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
    for (i, s) in sockets.iter().enumerate() {
        epoll.add(s.as_fd(), EpollEvent::new(EpollFlags::EPOLLIN, i as u64))?;
    }
    // The web UI's questions wake the loop too.
    if let Some(inbox) = &control.web {
        epoll.add(
            inbox.wake.as_fd(),
            EpollEvent::new(EpollFlags::EPOLLIN, WEB),
        )?;
    }
    if let Some(inbox) = &control.streams {
        epoll.add(
            inbox.wake.as_fd(),
            EpollEvent::new(EpollFlags::EPOLLIN, STREAMS),
        )?;
    }
    if let Some(inbox) = &control.native_inbox {
        epoll.add(
            inbox.wake.as_fd(),
            EpollEvent::new(EpollFlags::EPOLLIN, NATIVE),
        )?;
    }
    if let Some(inbox) = &control.media_events {
        epoll.add(
            inbox.wake.as_fd(),
            EpollEvent::new(EpollFlags::EPOLLIN, MEDIA),
        )?;
    }
    let mut ready = [EpollEvent::empty(); 16];
    let mut buf = vec![0u8; MAX_DATAGRAM];
    while !stop.load(Ordering::Relaxed) {
        control.prune_ended();
        control.sample_rates();
        control.flush_state();
        let n = match epoll.wait(&mut ready, EpollTimeout::from(200u16)) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => 0,
            Err(e) => return Err(e),
        };
        for ev in &ready[..n] {
            if ev.data() == WEB {
                control.answer_web();
                continue;
            }
            if ev.data() == STREAMS {
                control.answer_streams();
                continue;
            }
            if ev.data() == NATIVE {
                control.answer_native();
                continue;
            }
            if ev.data() == MEDIA {
                control.native_media_events();
                continue;
            }
            let Some(sock) = usize::try_from(ev.data()).ok().and_then(|i| sockets.get(i)) else {
                continue;
            };
            // Drain the socket (it is non-blocking).
            while let Ok((len, from)) = sock.recv_from(&mut buf) {
                if len > control.max_message {
                    log::debug!(
                        "ng: a {len}-octet datagram from {from} ignored (control.max_message)"
                    );
                    continue;
                }
                if let Some(reply) = control.handle_from(&buf[..len], Some(from))
                    && let Err(e) = sock.send_to(reply, from)
                {
                    log::warn!("ng: reply to {from}: {e}");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    fn control(first_port: u16) -> Control {
        let config = crate::config::Config::from_toml(&format!(
            "[[interface]]\nname = \"lo\"\naddress = \"127.0.0.1\"\n\
             [ports]\nmin = {first_port}\nmax = {}\n[sessions]\nmax = 4\n[runtime]\nworkers = 1\n",
            first_port + 15
        ))
        .unwrap();
        let relay = Relay::start(&config).unwrap();
        Control::new(relay, config.interfaces)
    }

    #[test]
    fn replies_are_cached_within_bounds() {
        let mut c = control(43_100);
        let ping = |cookie: &str| format!("{cookie} d7:command4:pinge");
        assert!(c.handle(ping("a").as_bytes()).is_some());
        assert!(c.handle(ping("a").as_bytes()).is_some());
        assert_eq!(c.stats.retransmissions.load(Ordering::Relaxed), 1);
        // The oldest go first past the limit (the TTL and the byte bound:
        // `ngcache`, and the conformance vectors).
        for i in 0..CACHE_ENTRIES + 10 {
            c.handle(ping(&format!("k{i}")).as_bytes());
        }
        assert_eq!(c.cache.len(), CACHE_ENTRIES);
        let now = c.cache_now();
        assert!(c.cache.get(now, &(None, b"k0".to_vec())).is_none());
        // Long cookies are answered, not cached.
        let long = "x".repeat(MAX_COOKIE + 1);
        assert!(c.handle(ping(&long).as_bytes()).is_some());
        assert!(c.cache.get(now, &(None, long.into_bytes())).is_none());
    }

    /// A cookie reused for another request is that request, run; the
    /// same request again is a retransmission.
    #[test]
    fn a_reused_cookie_with_another_request_runs_it() {
        let mut c = control(43_700);
        let ping = c.handle(b"same d7:command4:pinge").unwrap().to_vec();
        let list = c.handle(b"same d7:command4:liste").unwrap().to_vec();
        assert_ne!(ping, list);
        assert!(String::from_utf8_lossy(&list).contains("5:calls"));
        assert_eq!(c.stats.retransmissions.load(Ordering::Relaxed), 0);
        // Its retransmission gets the new reply.
        assert_eq!(c.handle(b"same d7:command4:liste").unwrap(), &list[..]);
        assert_eq!(c.stats.retransmissions.load(Ordering::Relaxed), 1);
    }

    /// Two proxies sending the same cookie each get their own reply; a
    /// retransmission from one of them is answered from the cache.
    #[test]
    fn the_cache_is_per_sender() {
        let mut c = control(43_200);
        let (a, b) = (
            Some("192.0.2.1:5060".parse().unwrap()),
            Some("192.0.2.2:5060".parse().unwrap()),
        );
        let list = |cookie: &str| format!("{cookie} d7:command4:liste");
        let ping = |cookie: &str| format!("{cookie} d7:command4:pinge");
        let first = c.handle_from(list("1_7_0").as_bytes(), a).unwrap().to_vec();
        // Proxy B's different command under the same cookie is executed.
        let second = c.handle_from(ping("1_7_0").as_bytes(), b).unwrap().to_vec();
        assert_ne!(first, second);
        assert_eq!(c.stats.retransmissions.load(Ordering::Relaxed), 0);
        // A's retransmission gets A's reply.
        assert_eq!(
            c.handle_from(list("1_7_0").as_bytes(), a).unwrap(),
            &first[..]
        );
        assert_eq!(c.stats.retransmissions.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod limits_tests {
    use super::*;

    static COOKIE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn control(first_port: u16, max: usize) -> Control {
        let config = crate::config::Config::from_toml(&format!(
            "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"\n\
             [[interface]]\nname = \"core\"\naddress = \"127.0.0.2\"\n\
             [ports]\nmin = {first_port}\nmax = {}\n[sessions]\nmax = 4\n[runtime]\nworkers = 1\n",
            first_port + 31
        ))
        .unwrap();
        let relay = Relay::start(&config).unwrap();
        let mut c = Control::new(relay, config.interfaces);
        c.set_max_sessions(max);
        c
    }

    fn bstr(s: &str) -> String {
        format!("{}:{s}", s.len())
    }

    /// An `offer` (keys sorted, as bencode wants) and its reply as text.
    fn offer(c: &mut Control, call: &str, tag: &str, sdp: &str, direction: &[&str]) -> String {
        let dir = if direction.is_empty() {
            String::new()
        } else {
            let names: String = direction.iter().map(|d| bstr(d)).collect();
            format!("{}l{names}e", bstr("direction"))
        };
        // A new cookie each time, or the reply cache answers.
        let cookie = COOKIE.fetch_add(1, Ordering::Relaxed);
        let msg = format!(
            "k{cookie} d{}{}{}{}{dir}{}{}{}{}e",
            bstr("call-id"),
            bstr(call),
            bstr("command"),
            bstr("offer"),
            bstr("from-tag"),
            bstr(tag),
            bstr("sdp"),
            bstr(sdp),
        );
        let reply = c.handle(msg.as_bytes()).expect(&msg);
        String::from_utf8_lossy(reply).into_owned()
    }

    fn sdp(addr: &str) -> String {
        let fam = if addr.contains(':') { "IP6" } else { "IP4" };
        format!(
            "v=0\r\no=- 1 1 IN {fam} {addr}\r\ns=-\r\nc=IN {fam} {addr}\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"
        )
    }

    #[test]
    fn sessions_max_refuses_new_dialogs_only() {
        let mut c = control(43_300, 2);
        assert!(offer(&mut c, "a", "t", &sdp("127.0.0.1"), &[]).contains("6:result2:ok"));
        assert!(offer(&mut c, "b", "t", &sdp("127.0.0.1"), &[]).contains("6:result2:ok"));
        let third = offer(&mut c, "c", "t", &sdp("127.0.0.1"), &[]);
        assert!(
            third.contains("session limit reached (sessions.max = 2)"),
            "{third}"
        );
        // A re-offer of a dialog that exists still works at the limit.
        assert!(offer(&mut c, "a", "t", &sdp("127.0.0.1"), &[]).contains("6:result2:ok"));
    }

    #[test]
    fn one_direction_name_is_both_sides() {
        let mut c = control(43_400, 10);
        let r = offer(&mut c, "d", "t", &sdp("127.0.0.1"), &["core"]);
        assert!(r.contains("c=IN IP4 127.0.0.2"), "{r}");
        let key = (b"d".to_vec(), b"t".to_vec());
        let core = InterfaceId::new(1);
        assert_eq!(c.sessions[&key].dir, [core, core]);
        // Two names: one each.
        let r = offer(&mut c, "e", "t", &sdp("127.0.0.1"), &["core", "pub"]);
        assert!(r.contains("c=IN IP4 127.0.0.1"), "{r}");
    }

    #[test]
    fn a_call_across_interfaces_hides_the_origin() {
        let mut c = control(43_800, 10);
        let sdp = "v=0\r\no=- 1 1 IN IP4 10.9.8.7\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
        let across = offer(&mut c, "x", "t", sdp, &["pub", "core"]);
        assert!(across.contains("o=- 1 1 IN IP4 127.0.0.2"), "{across}");
        assert!(!across.contains("10.9.8.7"), "{across}");
        // Within one network, o= is the proxy's to replace (replace-origin).
        let within = offer(&mut c, "y", "t", sdp, &["core", "core"]);
        assert!(within.contains("o=- 1 1 IN IP4 10.9.8.7"), "{within}");
    }

    #[test]
    fn the_peer_must_be_of_the_interface_family() {
        let mut c = control(43_500, 10);
        let r = offer(&mut c, "f", "t", &sdp("2001:db8::1"), &[]);
        assert!(
            r.contains("an IPv6 address, but interface pub has no IPv6 address"),
            "{r}"
        );
        assert!(c.sessions.is_empty());
    }

    #[test]
    fn bodies_that_are_not_sdp_are_refused() {
        let mut c = control(43_600, 10);
        let r = offer(&mut c, "g", "t", "hello", &[]);
        assert!(r.contains("not an SDP body"), "{r}");
        let r = offer(&mut c, "h", "t", "v=0\r\nm=audio 4000 RTP/AVP 0\r\n", &[]);
        assert!(r.contains("without a c= line"), "{r}");
        assert!(c.sessions.is_empty());
    }
}
