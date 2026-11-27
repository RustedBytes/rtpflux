//! The native control API: what a B2BUA or softswitch uses to manage
//! media endpoints (see `docs/native-api.md` and ADR 0001).
//!
//! Requests are JSON objects; the connection threads ([`crate::native`])
//! hand each to the control thread and wait for its reply. Each operation
//! runs on the same handlers as the `ng` commands, given requests made
//! here (`create`, `create from offer`, `connect`, `play media`, …): one
//! command model, two adapters. What `ng` has no word for lives here:
//!
//! - **Endpoints.** An endpoint is a party of the relay's own making (a
//!   [`create`](super::create) party), named by an id the relay makes up
//!   (`ep-` and 32 hex digits), in a media session (an `ng` call, `ms-` and
//!   32 hex digits unless the client names it). Its *generation* is given
//!   once, when it is created, and never reused; its *revision* counts its
//!   committed negotiations. A request may name the generation and revision
//!   it expects: another is a `conflict`.
//! - **Tombstones.** A destroyed endpoint is remembered for
//!   [`RETENTION`]: a late command for it fails (`not_found`, saying it was
//!   destroyed) and never brings it back; a second `endpoint.destroy` is a
//!   success that says so.
//! - **Idempotency.** A request with an `idempotency_key` seen within
//!   [`RETENTION`] (per tenant) gets the reply it got then, and runs
//!   nothing.
//! - **Leases.** An endpoint created with `lease_ms` is destroyed when its
//!   lease is not renewed in time; with none, it lasts until destroyed (or
//!   its media times out), whatever happens to the client's connection.
//! - **Events** to subscribers, each with a sequence number per endpoint
//!   and one across all events, so a gap can be seen; a subscriber whose
//!   queue is full misses events and is told so (`gap`) when it has room
//!   again, and then asks for a snapshot (`endpoint.list`).

use super::reply::{B, Reply};
use super::{Control, Error, MAX_DATAGRAM, RequestError};
use crate::relay::media_events::{MediaEvent, MediaEventKind, Subject};
use crate::relay::{CallLeg, RelayError};
use rtpflux_core::sdp::Codec;
use rtpflux_ng::bencode::{Encoder, Value, decode};
use serde_json::{Map, Value as Json, json};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::{Duration, Instant};

/// The protocol versions this relay speaks.
pub const VERSIONS: [u64; 1] = [1];
/// How long a destroyed endpoint and a request's idempotency key are
/// remembered.
pub const RETENTION: Duration = Duration::from_secs(300);
/// Idempotency keys remembered at most (the oldest go first).
/// Tombstones kept at most (the oldest go first).
const MAX_TOMBSTONES: usize = 65_536;
/// Events a subscriber's queue holds.
pub const SUBSCRIBER_QUEUE: usize = 1024;
/// The shortest lease (milliseconds).
const MIN_LEASE_MS: u64 = 1000;

/// The operations of version 1.
pub const OPERATIONS: [&str; 40] = [
    "hello",
    "ownership.claim",
    "endpoint.create",
    "endpoint.apply_answer",
    "endpoint.prepare",
    "endpoint.commit",
    "endpoint.abort",
    "endpoint.destroy",
    "endpoint.query",
    "endpoint.list",
    "endpoint.lookup",
    "operation.query",
    "inventory.list",
    "recovery.report",
    "recording.query",
    "endpoint.renew",
    "bridge.attach",
    "bridge.detach",
    "playback.start",
    "playback.stop",
    "dtmf.send",
    "dtmf.policy",
    "tone.start",
    "tone.stop",
    "endpoint.sensitive",
    "recording.start",
    "recording.stop",
    "recording.pause",
    "recording.resume",
    "stream.start",
    "stream.flush",
    "stream.detect",
    "stream.stop",
    "mixer.create",
    "mixer.add",
    "mixer.remove",
    "mixer.set",
    "mixer.destroy",
    "events.subscribe",
    "events.unsubscribe",
];

/// The events of version 1.
pub const EVENTS: [&str; 20] = [
    "endpoint.ready",
    "endpoint.failed",
    "endpoint.timeout",
    "endpoint.destroyed",
    "endpoint.events_lost",
    "bridge.changed",
    "ice.connected",
    "dtls.ready",
    "dtmf.detected",
    "playback.completed",
    "playback.stopped",
    "recording.completed",
    "recording.failed",
    "gap",
    "speech.started",
    "speech.ended",
    "stream.mark",
    "stream.flushed",
    "stream.ended",
    "mixer.speaker",
];

/// An error's kind, on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    NotFound,
    Conflict,
    Unsupported,
    Exhausted,
    Timeout,
    Unauthorized,
    Invalid,
    Internal,
    /// Durable storage failed: nothing was done (or, for an outcome that
    /// could not be recorded, the message says it was applied).
    Unavailable,
    /// The operation key's first attempt is older than the ledger keeps:
    /// its outcome is no longer known, so it is not run again.
    Expired,
    /// The operation began before a restart and its outcome was never
    /// recorded: it may or may not have taken effect.
    UnknownOutcome,
    /// Under `[ha]`: the request does not prove the current ownership
    /// epoch of what it touches (or no lease is running). Nothing was done.
    Fenced,
}

impl Code {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Code::NotFound => "not_found",
            Code::Conflict => "conflict",
            Code::Unsupported => "unsupported",
            Code::Exhausted => "exhausted",
            Code::Timeout => "timeout",
            Code::Unauthorized => "unauthorized",
            Code::Invalid => "invalid",
            Code::Internal => "internal",
            Code::Unavailable => "unavailable",
            Code::Expired => "expired",
            Code::UnknownOutcome => "unknown_outcome",
            Code::Fenced => "fenced",
        }
    }
}

/// A failed operation.
#[derive(Debug, Clone)]
pub struct NativeError {
    pub code: Code,
    pub message: String,
    /// Typed details (the resource a conflict is about, say).
    pub detail: Option<Json>,
}

impl NativeError {
    pub(super) fn new(code: Code, message: impl Into<String>) -> Self {
        NativeError {
            code,
            message: message.into(),
            detail: None,
        }
    }

    pub(super) fn invalid(message: impl Into<String>) -> Self {
        Self::new(Code::Invalid, message)
    }

    pub(super) fn with_detail(mut self, detail: Json) -> Self {
        self.detail = Some(detail);
        self
    }
}

impl From<Error> for NativeError {
    fn from(e: Error) -> Self {
        let code = match &e {
            Error::UnknownCall | Error::UnknownCallOrTag | Error::NoOffer => Code::NotFound,
            Error::Request(r) => match r {
                RequestError::TooManySessions(_) => Code::Exhausted,
                RequestError::UnknownCommand(_)
                | RequestError::UnsupportedOption(_)
                | RequestError::UnsupportedTransport(_)
                | RequestError::UnsupportedIce(_)
                | RequestError::UnsupportedIceLite(_) => Code::Unsupported,
                RequestError::UnknownTag(_)
                | RequestError::UnknownLabel(_)
                | RequestError::UnknownDialogue => Code::NotFound,
                _ => Code::Invalid,
            },
            Error::NotConfigured(_) => Code::Unsupported,
            Error::Relay(RelayError::PortsExhausted | RelayError::Busy) => Code::Exhausted,
            Error::Relay(_) | Error::State(_) => Code::Internal,
            Error::Missing(_) | Error::Sdp(_) | Error::Io { .. } | Error::Media(_) => Code::Invalid,
        };
        NativeError::new(code, e.to_string())
    }
}

/// How an endpoint was negotiated first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// The relay offered (`create`); the remote side answers.
    LocalOffer,
    /// The remote side offered (`create from offer`); the relay answered.
    RemoteOffer,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::LocalOffer => "local_offer",
            Kind::RemoteOffer => "remote_offer",
        }
    }
}

/// A renegotiation prepared, not committed yet.
#[derive(Debug, Clone)]
pub(super) struct Pending {
    revision: u64,
    /// The remote offer the endpoint had before (back at an abort).
    previous_remote: Option<Vec<u8>>,
    /// The relay offered (the commit brings the answer); else the remote
    /// side did (answered at prepare).
    local: bool,
}

/// An endpoint of the native API.
#[derive(Debug, Clone)]
pub(super) struct Endpoint {
    pub(super) id: String,
    pub(super) tenant: String,
    pub(super) session: String,
    pub(super) kind: Kind,
    pub(super) generation: u64,
    /// Committed negotiations, from 1.
    pub(super) revision: u64,
    /// Answered: media can flow.
    pub(super) ready: bool,
    pub(super) pending: Option<Pending>,
    pub(super) bridged_to: Option<String>,
    pub(super) label: Option<String>,
    /// Lease: its length and when it ends.
    pub(super) lease: Option<(u64, Instant)>,
    /// The last event's sequence number.
    pub(super) seq: u64,
    /// The remote side's latest offer (a remote endpoint's).
    pub(super) remote_sdp: Option<Vec<u8>>,
    /// The announcement playing to it: (playback id, operation id).
    pub(super) playback: Option<(String, Option<String>)>,
    pub(super) created_unix_ms: u64,
    /// The client's stable key for it (unique per tenant).
    pub(super) external_id: Option<String>,
    /// Its current recording's id.
    pub(super) recording: Option<String>,
    /// Counts the changes of what it is bridged to.
    pub(super) topology_revision: u64,
    /// Some of its media events were lost (the relay's queue was full):
    /// what it collected (digits) or awaited (an announcement's end) is
    /// indeterminate.
    pub(super) events_indeterminate: bool,
    /// `unconfirmed` while a change of its media's routing was not
    /// confirmed by its workers.
    pub(super) topology_state: Option<&'static str>,
}

/// A recording of an endpoint: what became of it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Recording {
    pub id: String,
    pub tenant: String,
    pub endpoint_id: String,
    /// `active`, `paused` (the media workers confirmed they stopped
    /// writing), `pausing` (asked to pause, not confirmed: capture may
    /// go on), `stopped` (asked to stop, not finished yet), `completed`
    /// or `failed`.
    pub state: String,
    pub file: Option<String>,
    pub uploaded: Option<bool>,
    pub detail: Option<String>,
    pub started_unix_ms: u64,
    pub ended_unix_ms: Option<u64>,
    /// Its pauses: when each began and ended, as the media workers
    /// confirmed them (the recording holds nothing in between).
    #[serde(default)]
    pub pauses: Vec<(u64, Option<u64>)>,
}

/// An endpoint destroyed: by whom, its generation, and when.
#[derive(Debug, Clone)]
pub(super) struct Tomb {
    pub(super) tenant: String,
    pub(super) generation: u64,
    pub(super) reason: String,
    pub(super) at_ms: u64,
    pub(super) external_id: Option<String>,
}

/// What a subscriber wants.
#[derive(Debug, Clone, Default)]
struct Filter {
    endpoints: Vec<String>,
    sessions: Vec<String>,
    types: Vec<String>,
    /// Events of `ng` parties too (not only endpoints).
    all_parties: bool,
    /// Sensitive digits as they are (others get them redacted).
    sensitive: bool,
}

impl Filter {
    fn wants(&self, event: &Json) -> bool {
        let field = |k: &str| event.get(k).and_then(Json::as_str);
        let ty = field("event").unwrap_or("");
        if ty == "gap" {
            return true;
        }
        if !self.types.is_empty() && !self.types.iter().any(|t| t == ty) {
            return false;
        }
        match field("endpoint_id") {
            Some(ep) => {
                (self.endpoints.is_empty() || self.endpoints.iter().any(|e| e == ep))
                    && (self.sessions.is_empty()
                        || field("session_id")
                            .is_some_and(|s| self.sessions.iter().any(|x| x == s)))
            }
            None => self.all_parties && self.endpoints.is_empty(),
        }
    }
}

/// A subscription: where its events go.
#[derive(Debug)]
struct Subscriber {
    id: u64,
    tenant: String,
    filter: Filter,
    tx: SyncSender<Vec<u8>>,
    /// Events it missed (its queue was full), to tell it about.
    missed: u64,
    /// The `global_seq` of the last event it was given: a gap says to
    /// resume from there.
    last: u64,
}

/// Events kept for replay by default.
pub const DEFAULT_JOURNAL: usize = 65_536;

impl Subscriber {
    /// Tell it about the events it missed, if its queue has room now:
    /// `false` once its connection is gone.
    fn flush_gap(&mut self, boot: &str) -> bool {
        if self.missed == 0 {
            return true;
        }
        let gap = json!({"event": "gap", "reason": "overflow", "missed": self.missed,
            "subscription_id": self.id, "resume_cursor": format!("{boot}:{}", self.last)});
        match self.tx.try_send(frame_json(&gap)) {
            Ok(()) => {
                self.missed = 0;
                true
            }
            Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Give it `event` (number `seq`, framed as `bytes`): `false` once its
    /// connection is gone. A full queue counts the event missed; the next
    /// time there is room, a gap says how many, and the cursor to resume
    /// from (`resume_cursor`) to get them back.
    fn deliver(&mut self, boot: &str, seq: u64, bytes: Vec<u8>) -> bool {
        if self.missed > 0 {
            let gap = json!({"event": "gap", "reason": "overflow", "missed": self.missed,
                "subscription_id": self.id, "resume_cursor": format!("{boot}:{}", self.last)});
            match self.tx.try_send(frame_json(&gap)) {
                Ok(()) => self.missed = 0,
                Err(TrySendError::Full(_)) => {
                    self.missed += 1;
                    return true;
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        match self.tx.try_send(bytes) {
            Ok(()) => {
                self.last = seq;
                true
            }
            Err(TrySendError::Full(_)) => {
                self.missed += 1;
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

/// The connection a request came on: its tenant's subscriptions go to
/// `events`.
#[derive(Debug, Clone)]
pub struct Origin {
    /// The connection (its subscriptions end with it).
    pub connection: u64,
    pub events: Option<SyncSender<Vec<u8>>>,
    /// The tenant the connection authenticated as (over TCP): its requests
    /// are that tenant's, and name no other.
    pub tenant: Option<String>,
}

/// The native API's state, on the control thread.
#[derive(Debug, Default)]
pub struct Native {
    pub(super) endpoints: HashMap<String, Endpoint>,
    pub(super) tombs: HashMap<String, Tomb>,
    pub(super) tomb_order: VecDeque<String>,
    /// (tenant, external id) → the live endpoint's id.
    pub(super) externals: HashMap<(String, String), String>,
    /// (tenant, external id) → the destroyed endpoint's id: kept as long
    /// as its tombstone, never evicted early (a new endpoint under the id
    /// needs `replaces_generation`).
    pub(super) external_tombs: HashMap<(String, String), String>,
    /// What became of keyed operations (durable with `[sessions] ledger`).
    pub(super) ledger: super::ledger::Ledger,
    /// Ownership fencing (`[ha]`).
    pub(super) ha: Option<super::ownership::Ownership>,
    /// Endpoints' IVR state: DTMF policy, sensitive digits, playback
    /// queues.
    pub(super) ivr: HashMap<String, super::ivr::Ivr>,
    /// Under `[ha]`: resource id (an endpoint's, `mixer_id:N`,
    /// `stream_id:N`) → the (tenant, group) owning it.
    pub(super) owned: HashMap<String, (String, String)>,
    subscribers: Vec<(u64, Subscriber)>,
    next_subscription: u64,
    /// This run's id (`boot-` and 32 hex digits), and the previous run's.
    pub(super) boot_id: String,
    pub(super) previous_boot: Option<String>,
    /// Changes whenever a resource or a link between resources may have:
    /// a paged inventory taken across a change starts again.
    pub(super) topology_epoch: u64,
    /// The events kept for replay (`global_seq`, event), oldest first, and
    /// how many at most.
    pub(super) journal: VecDeque<(u64, Json)>,
    pub(super) journal_cap: usize,
    /// The highest `global_seq` evicted from the journal (a cursor at or
    /// before it cannot be resumed).
    pub(super) journal_evicted: u64,
    /// Recordings: id → what became of it.
    pub(super) recordings: HashMap<String, Recording>,
    /// What the last restart could not bring back.
    pub(super) lost: Vec<Json>,
    /// The endpoints the last restart brought back.
    pub(super) restored: Vec<String>,
    /// The last event's number across all events.
    pub(super) global_seq: u64,
    pub(super) generation_seq: u64,
    /// Endpoints per tenant at most (0: no limit of its own).
    pub(super) max_endpoints: usize,
    /// Media events the queue dropped (gaps reported).
    pub(super) events_dropped: u64,
    /// Where external audio services' sockets are (`[control] pcm_dir`).
    pub(super) pcm_dir: Option<std::path::PathBuf>,
    /// PCM streams: id → (endpoint, handle).
    pub(super) streams: HashMap<u32, (String, crate::pcm::stream::Handle)>,
    pub(super) next_stream: u32,
    /// Mixers: id → (tenant, handle).
    pub(super) mixers: HashMap<u32, (String, crate::pcm::mixer::MixerHandle)>,
    pub(super) next_mixer: u32,
}

/// A request's common fields.
pub(super) struct Request<'a> {
    pub(super) op: &'a str,
    pub(super) operation_id: Option<&'a str>,
    pub(super) tenant: &'a str,
    pub(super) body: &'a Map<String, Json>,
}

impl Request<'_> {
    pub(super) fn str(&self, key: &str) -> Option<&str> {
        self.body.get(key).and_then(Json::as_str)
    }

    pub(super) fn need(&self, key: &str) -> Result<&str, NativeError> {
        self.str(key)
            .ok_or_else(|| NativeError::invalid(format!("missing {key}")))
    }

    pub(super) fn u64(&self, key: &str) -> Result<Option<u64>, NativeError> {
        match self.body.get(key) {
            None | Some(Json::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .map(Some)
                .ok_or_else(|| NativeError::invalid(format!("{key}: not a non-negative integer"))),
        }
    }
}

/// 128 random bits, as 32 hex digits, after `prefix`.
pub(super) fn random_id(prefix: &str) -> String {
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    let mut s = String::with_capacity(prefix.len() + 32);
    s.push_str(prefix);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Whether `s` may name a session or label: printable ASCII, no spaces.
fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|c| c.is_ascii_graphic())
}

/// A JSON value as a bencode one: strings as byte strings, integers as
/// integers, `true`/`false` as `yes`/`no`, arrays and objects as lists
/// and dictionaries; `null` and fractions have none.
fn to_b(v: &Json) -> Option<B> {
    Some(match v {
        Json::String(s) => B::Bytes(s.as_bytes().to_vec()),
        Json::Number(n) => B::Int(n.as_i64()?),
        Json::Bool(b) => B::Bytes(if *b { b"yes".to_vec() } else { b"no".to_vec() }),
        Json::Array(a) => B::List(a.iter().filter_map(to_b).collect()),
        Json::Object(o) => B::Dict(
            o.iter()
                .filter_map(|(k, v)| Some((k.as_bytes().to_vec(), to_b(v)?)))
                .collect(),
        ),
        Json::Null => return None,
    })
}

/// A bencode value as JSON (byte strings as text, lossily).
fn to_json(v: &B) -> Json {
    match v {
        B::Int(n) => json!(n),
        B::Bytes(b) => Json::String(String::from_utf8_lossy(b).into_owned()),
        B::List(l) => Json::Array(l.iter().map(to_json).collect()),
        B::Dict(d) => Json::Object(
            d.iter()
                .map(|(k, v)| (String::from_utf8_lossy(k).into_owned(), to_json(v)))
                .collect(),
        ),
    }
}

/// Keys a request's `options` may not set: the operation sets them.
const RESERVED: [&str; 8] = [
    "command",
    "call-id",
    "from-tag",
    "to-tag",
    "to-call-id",
    "sdp",
    "label",
    "set-label",
];

/// The request's `options` (`ng` options of the operation), as entries.
fn options(req: &Request<'_>) -> Result<Vec<(Vec<u8>, B)>, NativeError> {
    let Some(o) = req.body.get("options") else {
        return Ok(Vec::new());
    };
    let Json::Object(o) = o else {
        return Err(NativeError::invalid("options: not an object"));
    };
    let mut out = Vec::new();
    for (k, v) in o {
        if RESERVED.contains(&k.as_str()) {
            return Err(NativeError::invalid(format!(
                "options: {k} is set by the operation"
            )));
        }
        if let Some(b) = to_b(v) {
            out.push((k.as_bytes().to_vec(), b));
        }
    }
    Ok(out)
}

/// The request's `codecs` (the formats a local offer makes) as the
/// entries' `codec: offer`.
fn offer_codecs(req: &Request<'_>, entries: &mut Vec<(Vec<u8>, B)>) {
    if let Some(Json::Array(codecs)) = req.body.get("codecs") {
        let names = codecs.iter().filter_map(to_b).collect();
        entries.retain(|(k, _)| k != b"codec");
        entries.push((
            b"codec".to_vec(),
            B::Dict(vec![(b"offer".to_vec(), B::List(names))]),
        ));
    }
}

/// Add `flag` to the entries' `flags` list.
fn with_flag(entries: &mut Vec<(Vec<u8>, B)>, flag: &[u8]) {
    if let Some((_, B::List(l))) = entries.iter_mut().find(|(k, _)| k == b"flags") {
        l.push(B::Bytes(flag.to_vec()));
    } else {
        entries.retain(|(k, _)| k != b"flags");
        entries.push((b"flags".to_vec(), B::List(vec![B::Bytes(flag.to_vec())])));
    }
}

fn bytes(s: &[u8]) -> B {
    B::Bytes(s.to_vec())
}

impl Native {
    /// A generation not given before.
    fn new_generation(&mut self) -> u64 {
        self.generation_seq += 1;
        self.generation_seq
    }

    /// Remember the destroyed endpoint `ep`.
    fn bury(&mut self, ep: &Endpoint, reason: &str) {
        // Tombstones of external ids are not evicted early.
        while self.tomb_order.len() >= MAX_TOMBSTONES {
            let Some(old) = self.tomb_order.front() else {
                break;
            };
            if self.tombs.get(old).is_some_and(|t| t.external_id.is_some()) {
                break;
            }
            if let Some(old) = self.tomb_order.pop_front() {
                self.tombs.remove(&old);
            }
        }
        if let Some(x) = &ep.external_id {
            let k = (ep.tenant.clone(), x.clone());
            self.externals.remove(&k);
            self.external_tombs.insert(k, ep.id.clone());
        }
        self.tombs.insert(
            ep.id.clone(),
            Tomb {
                tenant: ep.tenant.clone(),
                generation: ep.generation,
                reason: reason.to_owned(),
                at_ms: crate::relay::media_events::unix_ms(),
                external_id: ep.external_id.clone(),
            },
        );
        self.tomb_order.push_back(ep.id.clone());
    }

    /// How long tombstones are kept: as long as the ledger keeps outcomes
    /// (at least [`RETENTION`]).
    pub(super) fn tomb_retention_ms(&self) -> u64 {
        self.ledger
            .retention_ms
            .max(u64::try_from(RETENTION.as_millis()).unwrap_or(u64::MAX))
    }

    /// Forget tombstones older than their retention.
    fn expire(&mut self) {
        let now = crate::relay::media_events::unix_ms();
        let keep = self.tomb_retention_ms();
        while let Some(id) = self.tomb_order.front() {
            match self.tombs.get(id) {
                Some(t) if now.saturating_sub(t.at_ms) < keep => break,
                _ => {
                    if let Some(id) = self.tomb_order.pop_front()
                        && let Some(t) = self.tombs.remove(&id)
                        && let Some(x) = t.external_id
                    {
                        self.external_tombs.remove(&(t.tenant, x));
                    }
                }
            }
        }
    }

    /// The endpoint `id` for `tenant`, or why not.
    fn get(&self, id: &str, tenant: &str) -> Result<&Endpoint, NativeError> {
        match self.endpoints.get(id) {
            Some(ep) if ep.tenant == tenant => Ok(ep),
            Some(_) => Err(NativeError::new(
                Code::Unauthorized,
                format!("endpoint {id}: another tenant's"),
            )),
            None => Err(match self.tombs.get(id) {
                Some(t) if t.tenant == tenant => NativeError::new(
                    Code::NotFound,
                    format!(
                        "endpoint {id}: destroyed ({}, generation {})",
                        t.reason, t.generation
                    ),
                ),
                _ => NativeError::new(Code::NotFound, format!("endpoint {id}: unknown")),
            }),
        }
    }

    /// Hand `event` to the subscribers that want it.
    fn publish(&mut self, mut event: Json) {
        self.global_seq += 1;
        let seq = self.global_seq;
        let journaled = event.get("event").and_then(Json::as_str) != Some("gap");
        if let Some(o) = event.as_object_mut() {
            o.insert("global_seq".to_owned(), json!(seq));
            o.insert(
                "time_unix_ms".to_owned(),
                json!(crate::relay::media_events::unix_ms()),
            );
            o.insert("boot_id".to_owned(), json!(self.boot_id));
            if journaled {
                o.insert(
                    "event_id".to_owned(),
                    json!(format!("{}:{seq}", self.boot_id)),
                );
            }
        }
        // Kept for replay (a gap is the subscriber's own).
        if journaled && self.journal_cap > 0 {
            if self.journal.len() >= self.journal_cap
                && let Some((old, _)) = self.journal.pop_front()
            {
                self.journal_evicted = old;
            }
            self.journal.push_back((seq, event.clone()));
        }
        let tenant = event
            .get("tenant")
            .and_then(Json::as_str)
            .map(str::to_owned);
        let mut encoded: Option<Vec<u8>> = None;
        let mut redacted: Option<Vec<u8>> = None;
        let sensitive = super::ivr::is_sensitive(&event);
        let boot = self.boot_id.clone();
        self.subscribers.retain_mut(|(_, s)| {
            if tenant.as_deref().is_some_and(|t| t != s.tenant) || !s.filter.wants(&event) {
                return true;
            }
            let bytes = if sensitive && !s.filter.sensitive {
                redacted
                    .get_or_insert_with(|| frame_json(&super::ivr::redact(&event)))
                    .clone()
            } else {
                encoded.get_or_insert_with(|| frame_json(&event)).clone()
            };
            s.deliver(&boot, seq, bytes)
        });
    }
}

/// `v` as one message of the native protocol's framing: a 4-octet
/// big-endian length, then the JSON text.
#[must_use]
pub fn frame_json(v: &Json) -> Vec<u8> {
    let body = serde_json::to_vec(v).unwrap_or_default();
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// The reply to `operation_id`: `result`, or the error.
fn reply(operation_id: Option<&str>, outcome: Result<Json, NativeError>) -> Json {
    let mut r = Map::new();
    r.insert("v".to_owned(), json!(1));
    if let Some(id) = operation_id {
        r.insert("operation_id".to_owned(), json!(id));
    }
    match outcome {
        Ok(result) => {
            r.insert("ok".to_owned(), json!(true));
            r.insert("result".to_owned(), result);
        }
        Err(e) => {
            r.insert("ok".to_owned(), json!(false));
            let mut err = json!({"code": e.code.as_str(), "message": e.message});
            if let (Some(d), Some(o)) = (e.detail, err.as_object_mut()) {
                o.insert("detail".to_owned(), d);
            }
            r.insert("error".to_owned(), err);
        }
    }
    Json::Object(r)
}

impl Control {
    /// Run one native request (`message`: a JSON object) from `origin`;
    /// the reply, as JSON text.
    pub fn native_request(&mut self, message: &[u8], origin: &Origin) -> Vec<u8> {
        self.native.expire();
        let parsed: Result<Json, _> = serde_json::from_slice(message);
        let Ok(Json::Object(body)) = parsed else {
            return serde_json::to_vec(&reply(
                None,
                Err(NativeError::invalid("not a JSON object")),
            ))
            .unwrap_or_default();
        };
        let req = Request {
            op: body.get("op").and_then(Json::as_str).unwrap_or(""),
            operation_id: body.get("operation_id").and_then(Json::as_str),
            tenant: origin.tenant.as_deref().unwrap_or_else(|| {
                body.get("tenant")
                    .and_then(Json::as_str)
                    .unwrap_or("default")
            }),
            body: &body,
        };
        // An authenticated connection names no other tenant.
        if let (Some(own), Some(named)) = (
            origin.tenant.as_deref(),
            body.get("tenant").and_then(Json::as_str),
        ) && own != named
        {
            return serde_json::to_vec(&reply(
                req.operation_id,
                Err(NativeError::new(
                    Code::Unauthorized,
                    format!("this connection is tenant {own}'s"),
                )),
            ))
            .unwrap_or_default();
        }
        // Refused before anything runs (definitely not executed): never
        // recorded, so a retry runs normally.
        if let Err(e) = Self::precheck(&req) {
            return serde_json::to_vec(&reply(req.operation_id, Err(e))).unwrap_or_default();
        }
        // Under `[ha]`: refused unless it proves the current epoch of what
        // it touches (definitely not executed, never recorded).
        if let Err(e) = self.fence(&req) {
            log::debug!("native {}: {}", req.op, e.message);
            return serde_json::to_vec(&reply(req.operation_id, Err(e))).unwrap_or_default();
        }
        let key = body
            .get("idempotency_key")
            .and_then(Json::as_str)
            .filter(|_| mutates(req.op));
        let r = if let Some(key) = key {
            self.keyed(&req, origin, key)
        } else {
            let outcome = self.native_checked(&req, origin);
            if let Err(e) = &outcome {
                log::debug!("native {}: {}: {}", req.op, e.code.as_str(), e.message);
            }
            reply(req.operation_id, outcome)
        };
        self.record_owned(&req, &r);
        let out = serde_json::to_vec(&r).unwrap_or_default();
        if mutates(req.op) {
            self.native.topology_epoch += 1;
        }
        // Endpoints whose media ended meanwhile (an `ng` delete, say).
        self.native_reconcile("ended");
        if !matches!(req.op, "hello" | "endpoint.query" | "endpoint.list") {
            self.mark_dirty();
        }
        out
    }

    /// The checks of a request's envelope (version, tenant, deadline): a
    /// request they refuse is definitely not executed.
    fn precheck(req: &Request<'_>) -> Result<(), NativeError> {
        if let Some(v) = req.u64("v")?
            && !VERSIONS.contains(&v)
        {
            return Err(NativeError::new(
                Code::Unsupported,
                format!("protocol version {v}"),
            ));
        }
        if !valid_name(req.tenant) {
            return Err(NativeError::invalid("tenant: not a name"));
        }
        if let Some(deadline) = req.u64("deadline_unix_ms")?
            && crate::relay::media_events::unix_ms() > deadline
        {
            return Err(NativeError::new(Code::Timeout, "the deadline has passed"));
        }
        Ok(())
    }

    /// The reply a keyed request gets from the ledger, if its key is known:
    /// the first outcome (the same intent), a conflict (another), or an
    /// unknown outcome.
    fn earlier_outcome(&self, req: &Request<'_>, key: &str, fp: &str) -> Option<Json> {
        use super::ledger::Status;
        let fail = |e: NativeError| reply(req.operation_id, Err(e));
        let e = self.native.ledger.get(req.tenant, key)?;
        if e.fingerprint != fp || e.op != req.op {
            return Some(fail(NativeError::new(
                Code::Conflict,
                format!("operation key {key} was used for another request"),
            )));
        }
        Some(match (e.status, &e.reply) {
            (Status::Applied | Status::Failed, Some(r)) => {
                let mut r = r.clone();
                if let Some(o) = r.as_object_mut() {
                    match req.operation_id {
                        Some(id) => o.insert("operation_id".to_owned(), json!(id)),
                        None => o.remove("operation_id"),
                    };
                    o.insert("replayed".to_owned(), json!(true));
                }
                r
            }
            _ => fail(
                NativeError::new(
                    Code::UnknownOutcome,
                    format!(
                        "operation {key} began before a restart and its outcome was not recorded: \
                         query the resources before trying again with a new key"
                    ),
                )
                .with_detail(json!({"resources": e.resources})),
            ),
        })
    }

    /// A request with an operation key: its earlier outcome if the ledger
    /// has it (the same intent), else run and recorded.
    fn keyed(&mut self, req: &Request<'_>, origin: &Origin, key: &str) -> Json {
        use super::ledger::{Entry, LedgerError, Status};
        let now = crate::relay::media_events::unix_ms();
        self.native.ledger.expire(now);
        let fp = super::ledger::fingerprint(req.body);
        let fail = |e: NativeError| reply(req.operation_id, Err(e));
        if let Some(earlier) = self.earlier_outcome(req, key, &fp) {
            return earlier;
        }
        // Not known: too old to be a first attempt?
        if let Ok(Some(first)) = req.u64("first_attempt_unix_ms")
            && now.saturating_sub(first) >= self.native.ledger.retention_ms
        {
            return fail(NativeError::new(
                Code::Expired,
                format!(
                    "operation {key} was first attempted longer ago than the ledger keeps outcomes"
                ),
            ));
        }
        let pending = Entry {
            op: req.op.to_owned(),
            fingerprint: fp,
            status: Status::Pending,
            reply: None,
            resources: Vec::new(),
            at_ms: now,
        };
        match self.native.ledger.record(req.tenant, key, pending.clone()) {
            Ok(()) => {}
            Err(LedgerError::Quota) => {
                return fail(NativeError::new(
                    Code::Exhausted,
                    "the tenant holds its quota of operation keys",
                ));
            }
            Err(LedgerError::Storage(e)) => {
                log::error!("ledger: {e}");
                return fail(NativeError::new(
                    Code::Unavailable,
                    "durable storage failed: nothing was done",
                ));
            }
        }
        fault("after_pending");
        let outcome = self.native_checked(req, origin);
        fault("after_apply");
        let status = match &outcome {
            Ok(_) => Status::Applied,
            // A change queued and not confirmed by the workers in time.
            Err(e) if e.code == Code::Timeout => Status::Unknown,
            Err(_) => Status::Failed,
        };
        let resources = outcome.as_ref().map_or_else(|_| Vec::new(), resource_refs);
        let r = reply(req.operation_id, outcome);
        // The resources' state on disk before the outcome is (durable mode).
        if self.native.ledger.durable()
            && status != Status::Failed
            && let Err(e) = self.save_durable()
        {
            log::error!("state: {e}");
            return fail(
                NativeError::new(
                    Code::Unavailable,
                    format!("operation {key} was applied but its state could not be written: its outcome is unknown after a restart"),
                )
                .with_detail(json!({"resources": resources})),
            );
        }
        fault("after_state");
        let done = Entry {
            status,
            reply: Some(r.clone()),
            resources: resources.clone(),
            ..pending
        };
        if let Err(e) = self.native.ledger.record(req.tenant, key, done) {
            log::error!("ledger: {e:?}");
            return fail(
                NativeError::new(
                    Code::Unavailable,
                    format!("operation {key} ran but its outcome could not be recorded durably"),
                )
                .with_detail(json!({"resources": resources, "reply": r})),
            );
        }
        fault("after_outcome");
        r
    }

    /// The checks every request passes, then the operation.
    fn native_checked(&mut self, req: &Request<'_>, origin: &Origin) -> Result<Json, NativeError> {
        // The endpoint named, at the generation and revision expected.
        // (A destroyed endpoint's `endpoint.destroy` says it was.)
        if let Some(id) = req.str("endpoint_id")
            && !(req.op == "endpoint.destroy" && self.native.tombs.contains_key(id))
        {
            let ep = self.native.get(id, req.tenant)?;
            if let Some(g) = req.u64("expected_generation")?
                && g != ep.generation
            {
                return Err(NativeError::new(
                    Code::Conflict,
                    format!("endpoint {id}: generation {} (not {g})", ep.generation),
                ));
            }
            if let Some(t) = req.u64("expected_topology_revision")?
                && t != ep.topology_revision
            {
                return Err(NativeError::new(
                    Code::Conflict,
                    format!(
                        "endpoint {id}: topology revision {} (not {t})",
                        ep.topology_revision
                    ),
                ));
            }
            if let Some(r) = req.u64("expected_revision")?
                && r != ep.revision
            {
                return Err(NativeError::new(
                    Code::Conflict,
                    format!("endpoint {id}: revision {} (not {r})", ep.revision),
                ));
            }
        }
        match req.op {
            "hello" => Ok(self.native_hello()),
            "endpoint.create" => self.native_create(req),
            "endpoint.apply_answer" => self.native_apply_answer(req),
            "endpoint.prepare" => self.native_prepare(req),
            "ownership.claim" => self.native_claim(req),
            "dtmf.send" => self.native_dtmf_send(req),
            "dtmf.policy" => self.native_dtmf_policy(req),
            "tone.start" => self.native_tone(req, true),
            "tone.stop" => self.native_tone(req, false),
            "endpoint.sensitive" => self.native_sensitive(req),
            "endpoint.commit" => self.native_commit(req),
            "endpoint.abort" => self.native_abort(req),
            "endpoint.destroy" => self.native_destroy(req),
            "endpoint.query" => self.native_query(req),
            "endpoint.list" => Ok(self.native_list(req.tenant)),
            "endpoint.lookup" => self.native_lookup(req),
            "inventory.list" => self.native_inventory(req),
            "recovery.report" => Ok(self.native_recovery()),
            "recording.query" => self.native_recording(req),
            "recording.pause" => self.native_record_pause(req, true),
            "recording.resume" => self.native_record_pause(req, false),
            "operation.query" => self.native_operation(req),
            "endpoint.renew" => self.native_renew(req),
            "bridge.attach" => self.native_attach(req),
            "bridge.detach" => self.native_detach(req),
            "playback.start" => self.native_play(req, true),
            "playback.stop" => self.native_play(req, false),
            "recording.start" => self.native_record(req, true),
            "recording.stop" => self.native_record(req, false),
            "stream.start" => self.native_stream_start(req),
            "stream.flush" | "stream.detect" | "stream.stop" => self.native_stream(req),
            "mixer.create" => self.native_mixer_create(req),
            "mixer.add" | "mixer.remove" | "mixer.set" | "mixer.destroy" => self.native_mixer(req),
            "events.subscribe" => self.native_subscribe(req, origin),
            "events.unsubscribe" => self.native_unsubscribe(req),
            "" => Err(NativeError::invalid("missing op")),
            other => Err(NativeError::new(
                Code::Unsupported,
                format!("operation {other}"),
            )),
        }
    }

    /// Run the `ng` command `command` with `entries`: its reply, and the
    /// warnings it gave.
    fn ng_run(
        &mut self,
        command: &[u8],
        mut entries: Vec<(Vec<u8>, B)>,
    ) -> Result<(Reply, Vec<String>), NativeError> {
        entries.retain(|(k, _)| k != b"command");
        entries.push((b"command".to_vec(), bytes(command)));
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut e = Encoder::new(&mut buf);
        B::Dict(entries)
            .encode(&mut e)
            .map_err(|_| NativeError::from(Error::Request(RequestError::TooLarge)))?;
        let n = e.len();
        buf.truncate(n);
        let Ok(Value::Dict(d)) = decode(&buf) else {
            return Err(NativeError::from(Error::Request(RequestError::TooLarge)));
        };
        self.stats.count(command);
        self.warnings.clear();
        let out = self.dispatch(command, &d);
        let warnings = std::mem::take(&mut self.warnings);
        self.link_gauges();
        match out {
            Ok(r) => {
                self.mark_dirty();
                self.gauges();
                Ok((r, warnings))
            }
            Err(e) => {
                self.stats
                    .errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(e.into())
            }
        }
    }

    /// The SDP a reply carries.
    fn reply_sdp(&self, r: &Reply) -> Option<String> {
        match r {
            Reply::Sdp(n) => Some(String::from_utf8_lossy(self.sdp_buf.get(..*n)?).into_owned()),
            Reply::Fields(f) => f
                .iter()
                .find(|(k, _)| k == b"sdp")
                .and_then(|(_, v)| match v {
                    B::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
                    _ => None,
                }),
            _ => None,
        }
    }

    fn native_hello(&self) -> Json {
        json!({
            "versions": VERSIONS,
            "boot_id": self.native.boot_id,
            "server": format!("rtpflux {}", env!("CARGO_PKG_VERSION")),
            "operations": OPERATIONS.as_slice(),
            "events": EVENTS.as_slice(),
            "capabilities": {
                "codecs": ["PCMU", "PCMA", "G722", "G729", "CN", "opus", "AMR", "AMR-WB", "telephone-event"],
                "transports": ["RTP/AVP", "RTP/AVPF", "RTP/SAVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVP", "UDP/TLS/RTP/SAVPF"],
                "ice": true,
                "bundle": true,
                "transcoding": true,
                "dtmf": ["rfc4733", "inband"],
                "recording": true,
                "playback": true,
                "pcm_streaming": self.native.pcm_dir.is_some(),
                "pcm_rates": [8000, 16000, 24000, 48000],
                "mixer": true,
                "mixer_max_participants": crate::pcm::mixer::MAX_PARTICIPANTS,
            },
            "guarantees": {
                "idempotency": if self.native.ledger.durable() { "durable" } else { "memory" },
                "idempotency_retention_ms": self.native.ledger.retention_ms,
                "operation_key_quota": self.native.ledger.quota,
                "state_commit": if self.native.ledger.durable() { "synced_before_reply" } else { "periodic" },
                "events": "replayable_within_journal",
                "event_journal": self.native.journal_cap,
                "fencing": if self.native.ha.is_some() { "authority_epochs" } else { "none" },
            },
            "limits": {
                "retention_ms": RETENTION.as_millis(),
                "subscriber_queue": SUBSCRIBER_QUEUE,
                "max_endpoints": self.native.max_endpoints,
            },
        })
    }

    /// An endpoint's snapshot.
    pub(super) fn endpoint_snapshot(ep: &Endpoint) -> Json {
        json!({
            "endpoint_id": ep.id,
            "session_id": ep.session,
            "kind": ep.kind.as_str(),
            "generation": ep.generation,
            "revision": ep.revision,
            "state": if ep.ready { "ready" } else { "offered" },
            "pending_revision": ep.pending.as_ref().map(|p| p.revision),
            "bridged_to": ep.bridged_to,
            "label": ep.label,
            "lease_ms": ep.lease.map(|l| l.0),
            "lease_remaining_ms": ep.lease.map(|l| {
                u64::try_from(l.1.saturating_duration_since(Instant::now()).as_millis()).unwrap_or(u64::MAX)
            }),
            "playback_id": ep.playback.as_ref().map(|p| &p.0),
            "event_seq": ep.seq,
            "created_unix_ms": ep.created_unix_ms,
            "external_id": ep.external_id,
            "recording_id": ep.recording,
            "topology_revision": ep.topology_revision,
            "topology_state": ep.topology_state.unwrap_or("confirmed"),
            "events_indeterminate": ep.events_indeterminate,
        })
    }

    /// Publish `event` of type `ty` about endpoint `id`, with `data`.
    pub(super) fn endpoint_event(
        &mut self,
        id: &str,
        ty: &str,
        operation_id: Option<&str>,
        data: Json,
    ) {
        let Some(ep) = self.native.endpoints.get_mut(id) else {
            return;
        };
        ep.seq += 1;
        let mut ev = json!({
            "event": ty,
            "endpoint_id": ep.id,
            "session_id": ep.session,
            "tenant": ep.tenant,
            "generation": ep.generation,
            "revision": ep.revision,
            "seq": ep.seq,
        });
        if let Some(o) = ev.as_object_mut() {
            o.insert("data".to_owned(), data);
            if let Some(op) = operation_id {
                o.insert("operation_id".to_owned(), json!(op));
            }
        }
        self.native.publish(ev);
    }

    /// Refused when the tenant holds its quota of endpoints.
    fn check_endpoint_quota(&self, tenant: &str) -> Result<(), NativeError> {
        let max = self.native.max_endpoints;
        if max > 0
            && self
                .native
                .endpoints
                .values()
                .filter(|e| e.tenant == tenant)
                .count()
                >= max
        {
            return Err(NativeError::new(
                Code::Exhausted,
                format!("tenant {tenant}: {max} endpoints already"),
            ));
        }
        Ok(())
    }

    fn native_create(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        self.check_endpoint_quota(req.tenant)?;
        let external_id = self.check_external(req)?;
        let session = match req.str("session_id") {
            Some(s) if valid_name(s) => s.to_owned(),
            Some(_) => return Err(NativeError::invalid("session_id: not a name")),
            None => random_id("ms-"),
        };
        // A session belongs to one tenant.
        if let Some(other) = self
            .native
            .endpoints
            .values()
            .find(|e| e.session == session && e.tenant != req.tenant)
        {
            return Err(NativeError::new(
                Code::Unauthorized,
                format!("session {}: another tenant's", other.session),
            ));
        }
        let label = req.str("label").map(str::to_owned);
        if label.as_deref().is_some_and(|l| !valid_name(l)) {
            return Err(NativeError::invalid("label: not a name"));
        }
        let lease = match req.u64("lease_ms")? {
            Some(ms) if ms < MIN_LEASE_MS => {
                return Err(NativeError::invalid(format!(
                    "lease_ms: at least {MIN_LEASE_MS}"
                )));
            }
            l => l,
        };
        let id = random_id("ep-");
        let mut entries = options(req)?;
        entries.push((b"call-id".to_vec(), bytes(session.as_bytes())));
        entries.push((b"from-tag".to_vec(), bytes(id.as_bytes())));
        if let Some(l) = &label {
            entries.push((b"label".to_vec(), bytes(l.as_bytes())));
        }
        let remote = req.str("remote_sdp").map(|s| s.as_bytes().to_vec());
        let (kind, command) = if let Some(sdp) = &remote {
            entries.push((b"sdp".to_vec(), bytes(sdp)));
            (Kind::RemoteOffer, &b"create from offer"[..])
        } else {
            offer_codecs(req, &mut entries);
            (Kind::LocalOffer, &b"create"[..])
        };
        let (r, warnings) = self.ng_run(command, entries)?;
        let sdp = self.reply_sdp(&r).unwrap_or_default();
        let generation = self.native.new_generation();
        let ready = kind == Kind::RemoteOffer;
        let ep = Endpoint {
            id: id.clone(),
            tenant: req.tenant.to_owned(),
            session: session.clone(),
            kind,
            generation,
            revision: 1,
            ready,
            pending: None,
            bridged_to: None,
            label,
            lease: lease.map(|ms| (ms, Instant::now() + Duration::from_millis(ms))),
            seq: 0,
            remote_sdp: remote,
            playback: None,
            created_unix_ms: crate::relay::media_events::unix_ms(),
            external_id: external_id.clone(),
            recording: None,
            topology_revision: 0,
            topology_state: None,
            events_indeterminate: false,
        };
        self.native.endpoints.insert(id.clone(), ep);
        if let Some(x) = external_id {
            self.native
                .external_tombs
                .remove(&(req.tenant.to_owned(), x.clone()));
            self.native
                .externals
                .insert((req.tenant.to_owned(), x), id.clone());
        }
        log::info!(
            "native: endpoint {id} created in {session} ({})",
            kind.as_str()
        );
        if ready {
            self.endpoint_event(&id, "endpoint.ready", req.operation_id, json!({}));
        }
        Ok(json!({
            "endpoint_id": id,
            "session_id": session,
            "generation": generation,
            "revision": 1,
            "state": if ready { "ready" } else { "offered" },
            "sdp_type": if ready { "answer" } else { "offer" },
            "sdp": sdp,
            "warnings": warnings,
        }))
    }

    fn endpoint(&self, req: &Request<'_>) -> Result<Endpoint, NativeError> {
        let id = req.need("endpoint_id")?;
        self.native.get(id, req.tenant).cloned()
    }

    fn native_apply_answer(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        if ep.kind != Kind::LocalOffer {
            return Err(NativeError::new(
                Code::Conflict,
                "the endpoint's remote side offered: nothing to answer",
            ));
        }
        if ep.ready {
            return Err(NativeError::new(
                Code::Conflict,
                "answered already (renegotiate with endpoint.prepare)",
            ));
        }
        let sdp = req.need("sdp")?;
        let mut entries = options(req)?;
        entries.push((b"call-id".to_vec(), bytes(ep.session.as_bytes())));
        entries.push((b"from-tag".to_vec(), bytes(ep.id.as_bytes())));
        entries.push((b"sdp".to_vec(), bytes(sdp.as_bytes())));
        let (_, warnings) = self.ng_run(b"create answer", entries)?;
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.ready = true;
        }
        self.endpoint_event(&ep.id, "endpoint.ready", req.operation_id, json!({}));
        Ok(json!({"revision": ep.revision, "state": "ready", "warnings": warnings}))
    }

    /// `endpoint.prepare`: a renegotiation, not committed until
    /// `endpoint.commit` (or taken back with `endpoint.abort`), in either
    /// direction, whichever side made the endpoint's first offer:
    /// - `remote_sdp`: the remote side's new offer (its re-INVITE); the
    ///   reply's `sdp` is the answer;
    /// - else (`codecs`, `options`): the relay's new offer; the remote
    ///   side's answer comes with `endpoint.commit`.
    ///
    /// Either way the committed media stay as they were (ports, keys, ICE,
    /// bridge) until the commit, and `endpoint.abort` puts them back
    /// exactly (`rollback`).
    fn native_prepare(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        if ep.pending.is_some() {
            return Err(NativeError::new(
                Code::Conflict,
                "a renegotiation is pending already",
            ));
        }
        if !ep.ready {
            return Err(NativeError::new(
                Code::Conflict,
                "not answered yet: nothing to renegotiate",
            ));
        }
        let mut entries = options(req)?;
        entries.push((b"call-id".to_vec(), bytes(ep.session.as_bytes())));
        entries.push((b"from-tag".to_vec(), bytes(ep.id.as_bytes())));
        // Kept as last agreed until the commit: an abort rolls back to it.
        with_flag(&mut entries, b"track-state");
        let pending_revision = ep.revision + 1;
        let remote = req.str("remote_sdp").map(str::to_owned);
        let (r, warnings) = if let Some(sdp) = &remote {
            entries.push((b"sdp".to_vec(), bytes(sdp.as_bytes())));
            // The relay's answer must not commit it: the commit does.
            self.keep_checkpoint = true;
            let run = self.ng_run(b"create from offer", entries);
            self.keep_checkpoint = false;
            run?
        } else {
            offer_codecs(req, &mut entries);
            self.ng_run(b"create", entries)?
        };
        let sdp = self.reply_sdp(&r).unwrap_or_default();
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.pending = Some(Pending {
                revision: pending_revision,
                previous_remote: ep.remote_sdp.clone(),
                local: remote.is_none(),
            });
            if let Some(sdp) = &remote {
                e.remote_sdp = Some(sdp.as_bytes().to_vec());
            }
        }
        Ok(json!({
            "pending_revision": pending_revision,
            "sdp_type": if remote.is_some() { "answer" } else { "offer" },
            "sdp": sdp,
            "warnings": warnings,
        }))
    }

    /// The pending renegotiation `revision` names (it must).
    fn pending_of(ep: &Endpoint, req: &Request<'_>) -> Result<Pending, NativeError> {
        let Some(p) = ep.pending.clone() else {
            return Err(NativeError::new(Code::Conflict, "no renegotiation pending"));
        };
        if let Some(r) = req.u64("revision")?
            && r != p.revision
        {
            return Err(NativeError::new(
                Code::Conflict,
                format!("the pending revision is {} (not {r})", p.revision),
            ));
        }
        Ok(p)
    }

    fn native_commit(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        let p = Self::pending_of(&ep, req)?;
        let mut warnings = Vec::new();
        if p.local {
            // The relay's offer, answered (the answer commits it).
            let sdp = req.need("sdp")?;
            let mut entries = options(req)?;
            entries.push((b"call-id".to_vec(), bytes(ep.session.as_bytes())));
            entries.push((b"from-tag".to_vec(), bytes(ep.id.as_bytes())));
            entries.push((b"sdp".to_vec(), bytes(sdp.as_bytes())));
            // An answer that does not fit: still pending, abort takes it
            // back.
            warnings = self.ng_run(b"create answer", entries)?.1;
        } else if let Some(key) = self.created_dialog(ep.session.as_bytes(), ep.id.as_bytes()) {
            // The remote offer, answered at prepare: its checkpoint goes.
            self.commit_checkpoint(&key);
            self.mark_dirty();
        }
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.pending = None;
            e.revision = p.revision;
        }
        Ok(json!({"revision": p.revision, "warnings": warnings}))
    }

    fn native_abort(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        let p = Self::pending_of(&ep, req)?;
        // The committed media back, exactly: ports, keys, ICE, roles.
        let entries = vec![
            (b"call-id".to_vec(), bytes(ep.session.as_bytes())),
            (b"from-tag".to_vec(), bytes(ep.id.as_bytes())),
            (
                b"to-tag".to_vec(),
                bytes(&[super::create::CREATOR, ep.id.as_bytes()].concat()),
            ),
        ];
        let (r, warnings) = self.ng_run(b"rollback", entries)?;
        let rolled = matches!(&r, Reply::Fields(f) if f.iter().any(|(k, v)| k == b"rolled-back" && matches!(v, B::Int(1))));
        if !rolled {
            return Err(NativeError::new(
                Code::Internal,
                "the renegotiation could not be taken back: the endpoint has its prepared media",
            ));
        }
        // Back where it was: bridged again, if it was.
        if let Some(key) = self.created_dialog(ep.session.as_bytes(), ep.id.as_bytes()) {
            self.park_or_rejoin(
                &key,
                &(ep.session.as_bytes().to_vec(), ep.id.as_bytes().to_vec()),
            );
        }
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.pending = None;
            if !p.local {
                e.remote_sdp.clone_from(&p.previous_remote);
            }
        }
        Ok(json!({"revision": ep.revision, "warnings": warnings}))
    }

    /// End endpoint `id`'s media and forget it (a tombstone stays).
    fn destroy_endpoint(&mut self, id: &str, reason: &'static str, operation_id: Option<&str>) {
        let Some(ep) = self.native.endpoints.get(id).cloned() else {
            return;
        };
        if reason != "ended" {
            // Its dialog with the hidden side, by the key it is under (an
            // unanswered offer of the relay's has no to-tag yet: its own
            // tag would not find it).
            let from = self
                .created_dialog(ep.session.as_bytes(), ep.id.as_bytes())
                .map_or_else(|| ep.id.as_bytes().to_vec(), |k| k.1);
            let entries = vec![
                (b"call-id".to_vec(), bytes(ep.session.as_bytes())),
                (b"from-tag".to_vec(), bytes(&from)),
            ];
            if let Err(e) = self.ng_run(b"delete", entries) {
                log::debug!("native: endpoint {id}: delete: {}", e.message);
            }
        }
        if let Some(peer) = ep.bridged_to.clone() {
            self.set_bridge(&peer, None, "peer_destroyed", None);
        }
        // Its streams end; it leaves its mixer.
        self.native.streams.retain(|_, (e, h)| {
            if e == id {
                h.stop();
            }
            e != id
        });
        for (_, m) in self.native.mixers.values_mut() {
            m.remove(id);
        }
        self.endpoint_event(
            id,
            "endpoint.destroyed",
            operation_id,
            json!({"reason": reason}),
        );
        self.native.bury(&ep, reason);
        self.native.endpoints.remove(id);
        self.native.topology_epoch += 1;
        log::info!("native: endpoint {id} destroyed ({reason})");
    }

    fn native_destroy(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let id = req.need("endpoint_id")?;
        match self.native.get(id, req.tenant) {
            Ok(_) => {
                self.destroy_endpoint(id, "request", req.operation_id);
                Ok(json!({"destroyed": true}))
            }
            // Destroyed before: the same outcome (idempotent).
            Err(e)
                if e.code == Code::NotFound
                    && self
                        .native
                        .tombs
                        .get(id)
                        .is_some_and(|t| t.tenant == req.tenant) =>
            {
                Ok(json!({"destroyed": false, "already": true}))
            }
            Err(e) => Err(e),
        }
    }

    fn native_query(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        let mut snap = Self::endpoint_snapshot(&ep);
        let entries = vec![
            (b"call-id".to_vec(), bytes(ep.session.as_bytes())),
            (b"from-tag".to_vec(), bytes(ep.id.as_bytes())),
        ];
        if let Ok((Reply::Fields(f), _)) = self.ng_run(b"query", entries) {
            let media = f
                .iter()
                .find(|(k, _)| k == b"tags")
                .and_then(|(_, t)| match t {
                    B::Dict(d) => d.iter().find(|(k, _)| k == ep.id.as_bytes()),
                    _ => None,
                })
                .map(|(_, v)| to_json(v));
            if let (Some(o), Some(m)) = (snap.as_object_mut(), media) {
                o.insert("media".to_owned(), m);
            }
        }
        Ok(snap)
    }

    fn native_list(&self, tenant: &str) -> Json {
        let mut eps: Vec<&Endpoint> = self
            .native
            .endpoints
            .values()
            .filter(|e| e.tenant == tenant)
            .collect();
        eps.sort_by_key(|e| e.generation);
        let destroyed: Vec<Json> = self
            .native
            .tomb_order
            .iter()
            .filter_map(|id| {
                let t = self.native.tombs.get(id)?;
                (t.tenant == tenant).then(
                    || json!({"endpoint_id": id, "generation": t.generation, "reason": t.reason}),
                )
            })
            .collect();
        json!({
            "endpoints": eps.iter().map(|e| Self::endpoint_snapshot(e)).collect::<Vec<_>>(),
            "destroyed": destroyed,
            "global_seq": self.native.global_seq,
        })
    }

    fn native_renew(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        let ms = match req.u64("lease_ms")? {
            Some(ms) if ms < MIN_LEASE_MS => {
                return Err(NativeError::invalid(format!(
                    "lease_ms: at least {MIN_LEASE_MS}"
                )));
            }
            Some(ms) => Some(ms),
            None => ep.lease.map(|l| l.0),
        };
        let Some(ms) = ms else {
            return Err(NativeError::new(
                Code::Conflict,
                "the endpoint has no lease",
            ));
        };
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.lease = Some((ms, Instant::now() + Duration::from_millis(ms)));
        }
        Ok(json!({"lease_ms": ms}))
    }

    /// Record that `id` is bridged to `peer` (or to nobody), and tell
    /// subscribers.
    fn set_bridge(
        &mut self,
        id: &str,
        peer: Option<&str>,
        reason: &str,
        operation_id: Option<&str>,
    ) {
        let Some(ep) = self.native.endpoints.get_mut(id) else {
            return;
        };
        if ep.bridged_to.as_deref() == peer {
            return;
        }
        ep.bridged_to = peer.map(str::to_owned);
        ep.topology_revision += 1;
        self.endpoint_event(
            id,
            "bridge.changed",
            operation_id,
            json!({"bridged_to": peer, "reason": reason}),
        );
    }

    fn native_attach(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let a = self.endpoint(req)?;
        let peer_id = req.need("peer_endpoint_id")?;
        let b = self.native.get(peer_id, req.tenant)?.clone();
        if let Some(g) = req.u64("peer_expected_generation")?
            && g != b.generation
        {
            return Err(NativeError::new(
                Code::Conflict,
                format!("endpoint {peer_id}: generation {} (not {g})", b.generation),
            ));
        }
        if let Some(t) = req.u64("peer_expected_topology_revision")?
            && t != b.topology_revision
        {
            return Err(NativeError::new(
                Code::Conflict,
                format!(
                    "endpoint {peer_id}: topology revision {} (not {t})",
                    b.topology_revision
                ),
            ));
        }
        if let Some(r) = req.u64("peer_expected_revision")?
            && r != b.revision
        {
            return Err(NativeError::new(
                Code::Conflict,
                format!("endpoint {peer_id}: revision {} (not {r})", b.revision),
            ));
        }
        if a.id == b.id {
            return Err(NativeError::invalid("an endpoint bridged to itself"));
        }
        let entries = vec![
            (b"call-id".to_vec(), bytes(a.session.as_bytes())),
            (b"from-tag".to_vec(), bytes(a.id.as_bytes())),
            (b"to-call-id".to_vec(), bytes(b.session.as_bytes())),
            (b"to-tag".to_vec(), bytes(b.id.as_bytes())),
        ];
        let warnings = match self.ng_run(b"connect", entries) {
            Ok((_, w)) => w,
            Err(e) => {
                // Part of it may have taken effect (a worker took its end,
                // the other did not): every endpoint involved is detached,
                // so what is reported is what the media do.
                self.compensate_attach(&a, &b, req.operation_id);
                return Err(e.with_detail(json!({"compensated": true,
                    "detached": [a.id, b.id, a.bridged_to, b.bridged_to]})));
            }
        };
        // Whoever either was bridged to is left alone (the relay detached
        // them).
        for (old, keep) in [(&a.bridged_to, &b.id), (&b.bridged_to, &a.id)] {
            if let Some(o) = old.as_deref().filter(|o| *o != keep.as_str()) {
                self.set_bridge(o, None, "replaced", req.operation_id);
            }
        }
        self.set_bridge(&a.id, Some(&b.id), "attached", req.operation_id);
        self.set_bridge(&b.id, Some(&a.id), "attached", req.operation_id);
        self.confirm(&[&a, &b])?;
        Ok(json!({
            "endpoint_id": a.id,
            "bridged_to": b.id,
            "replaced": [a.bridged_to, b.bridged_to],
            "warnings": warnings,
        }))
    }

    fn native_detach(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        let Some(peer) = ep.bridged_to.clone() else {
            return Ok(json!({"detached": false}));
        };
        let (call, tag) = (ep.session.as_bytes().to_vec(), ep.id.as_bytes().to_vec());
        let legs = self.party_legs(&call, &tag).unwrap_or_default();
        for ((id, leg), _) in legs.into_iter().flatten() {
            self.relay.detach((id, leg)).map_err(Error::from)?;
        }
        let key = (call, tag);
        self.connections.retain(|(a, b)| *a != key && *b != key);
        self.mark_dirty();
        self.set_bridge(&ep.id, None, "detached", req.operation_id);
        self.set_bridge(&peer, None, "detached", req.operation_id);
        self.confirm(&[&ep])?;
        Ok(json!({"detached": true, "was_bridged_to": peer}))
    }

    fn native_play(&mut self, req: &Request<'_>, start: bool) -> Result<Json, NativeError> {
        if start {
            self.native_play_as(req, None)
        } else {
            let ep = self.endpoint(req)?;
            self.drop_queue(&ep.id, "request");
            self.play_inner(req, false, None)
        }
    }

    /// `playback.start`, with the playback's id when it was queued.
    /// `queue: true` waits behind the current playback ([`QUEUE_MAX`] at
    /// most); `stop_on` (`dtmf`, `speech`) stops it, and drops the queue,
    /// when the endpoint presses a key or starts speaking.
    ///
    /// [`QUEUE_MAX`]: super::ivr::QUEUE_MAX
    pub(super) fn native_play_as(
        &mut self,
        req: &Request<'_>,
        id: Option<String>,
    ) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        let mut stop_on = Vec::new();
        if let Some(v) = req.body.get("stop_on") {
            for k in v.as_array().into_iter().flatten() {
                match k.as_str() {
                    Some(k @ ("dtmf" | "speech")) => stop_on.push(k.to_owned()),
                    _ => return Err(NativeError::invalid("stop_on: [\"dtmf\", \"speech\"]")),
                }
            }
        }
        let queue = req.body.get("queue").and_then(Json::as_bool) == Some(true);
        if queue && ep.playback.is_some() {
            let ivr = self.native.ivr.entry(ep.id.clone()).or_default();
            if ivr.queue.len() >= super::ivr::QUEUE_MAX {
                return Err(NativeError::new(
                    Code::Exhausted,
                    "the playback queue is full",
                ));
            }
            let id = random_id("pb-");
            let mut body = req.body.clone();
            body.remove("queue");
            ivr.queue.push_back(super::ivr::Queued {
                id: id.clone(),
                body,
                operation_id: req.operation_id.map(str::to_owned),
            });
            return Ok(json!({"playback_id": id, "queued": true, "position": ivr.queue.len()}));
        }
        let from_queue = id.is_some();
        let r = self.play_inner(req, true, id)?;
        if !from_queue && !queue {
            self.drop_queue(&ep.id, "replaced");
        }
        self.native.ivr.entry(ep.id).or_default().stop_on = stop_on;
        Ok(r)
    }

    /// Stop the endpoint's playback, reporting `reason`.
    pub(super) fn stop_playback(&mut self, id: &str, reason: &str) {
        let Some(ep) = self.native.endpoints.get(id).cloned() else {
            return;
        };
        let Some((old, op)) = ep.playback.clone() else {
            return;
        };
        let entries = vec![
            (b"call-id".to_vec(), bytes(ep.session.as_bytes())),
            (b"from-tag".to_vec(), bytes(ep.id.as_bytes())),
        ];
        if let Err(e) = self.ng_run(b"stop media", entries) {
            log::debug!(
                "native: endpoint {id}: stopping its playback: {}",
                e.message
            );
        }
        if let Some(e) = self.native.endpoints.get_mut(id) {
            e.playback = None;
        }
        if let Some(i) = self.native.ivr.get_mut(id) {
            i.stop_on.clear();
        }
        self.endpoint_event(
            id,
            "playback.stopped",
            op.as_deref(),
            json!({"playback_id": old, "reason": reason}),
        );
    }

    fn play_inner(
        &mut self,
        req: &Request<'_>,
        start: bool,
        preset: Option<String>,
    ) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        let mut entries = if start { options(req)? } else { Vec::new() };
        entries.push((b"call-id".to_vec(), bytes(ep.session.as_bytes())));
        entries.push((b"from-tag".to_vec(), bytes(ep.id.as_bytes())));
        if !start {
            let Some((old, op)) = ep.playback.clone() else {
                return Ok(json!({"stopped": false}));
            };
            self.ng_run(b"stop media", entries)?;
            if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
                e.playback = None;
            }
            if let Some(i) = self.native.ivr.get_mut(&ep.id) {
                i.stop_on.clear();
            }
            self.endpoint_event(
                &ep.id,
                "playback.stopped",
                op.as_deref().or(req.operation_id),
                json!({"playback_id": old, "reason": "request"}),
            );
            return Ok(json!({"stopped": true, "playback_id": old}));
        }
        if let Some(f) = req.str("file") {
            entries.push((b"file".to_vec(), bytes(f.as_bytes())));
        }
        if let Some(b) = req.str("blob_base64") {
            let blob = base64_decode(b).ok_or_else(|| NativeError::invalid("blob_base64"))?;
            entries.push((b"blob".to_vec(), B::Bytes(blob)));
        }
        for k in ["repeat_times", "start_pos", "duration", "repeat_duration"] {
            if let Some(n) = req.u64(k)? {
                entries.push((k.replace('_', "-").into_bytes(), B::int(n)));
            }
        }
        let (r, warnings) = self.ng_run(b"play media", entries)?;
        let duration = match &r {
            Reply::Fields(f) => f
                .iter()
                .find(|(k, _)| k == b"duration")
                .map(|(_, v)| to_json(v)),
            _ => None,
        };
        let id = preset.unwrap_or_else(|| random_id("pb-"));
        // A playback it replaces stops.
        if let Some((old, op)) = ep.playback.clone() {
            self.endpoint_event(
                &ep.id,
                "playback.stopped",
                op.as_deref(),
                json!({"playback_id": old, "reason": "replaced"}),
            );
        }
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.playback = Some((id.clone(), req.operation_id.map(str::to_owned)));
        }
        Ok(json!({"playback_id": id, "duration_ms": duration, "warnings": warnings}))
    }

    fn native_record(&mut self, req: &Request<'_>, start: bool) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        let mut entries = if start { options(req)? } else { Vec::new() };
        entries.push((b"call-id".to_vec(), bytes(ep.session.as_bytes())));
        entries.push((b"from-tag".to_vec(), bytes(ep.id.as_bytes())));
        let command: &[u8] = if start {
            b"start recording"
        } else {
            b"stop recording"
        };
        let (_, warnings) = self.ng_run(command, entries)?;
        let now = crate::relay::media_events::unix_ms();
        let current = ep.recording.clone().filter(|id| {
            self.native
                .recordings
                .get(id)
                .is_some_and(|r| matches!(r.state.as_str(), "active" | "paused" | "pausing"))
        });
        let id = if start {
            // Started again while it records: the same recording.
            current.unwrap_or_else(|| {
                let id = random_id("rec-");
                self.native.recordings.insert(
                    id.clone(),
                    Recording {
                        id: id.clone(),
                        tenant: ep.tenant.clone(),
                        endpoint_id: ep.id.clone(),
                        state: "active".into(),
                        file: None,
                        uploaded: None,
                        detail: None,
                        started_unix_ms: now,
                        ended_unix_ms: None,
                        pauses: Vec::new(),
                    },
                );
                id
            })
        } else {
            let Some(id) = current else {
                return Ok(
                    json!({"recording": false, "recording_id": ep.recording, "warnings": warnings}),
                );
            };
            if let Some(r) = self.native.recordings.get_mut(&id) {
                r.state = "stopped".into();
                r.ended_unix_ms = Some(now);
            }
            id
        };
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.recording = Some(id.clone());
        }
        Ok(json!({"recording": start, "recording_id": id, "warnings": warnings}))
    }

    fn native_subscribe(
        &mut self,
        req: &Request<'_>,
        origin: &Origin,
    ) -> Result<Json, NativeError> {
        let Some(tx) = origin.events.clone() else {
            return Err(NativeError::new(
                Code::Unsupported,
                "this connection cannot receive events",
            ));
        };
        let list = |k: &str| -> Vec<String> {
            match req.body.get(k) {
                Some(Json::Array(a)) => a
                    .iter()
                    .filter_map(Json::as_str)
                    .map(str::to_owned)
                    .collect(),
                _ => Vec::new(),
            }
        };
        let types = list("types");
        if let Some(t) = types.iter().find(|t| !EVENTS.contains(&t.as_str())) {
            return Err(NativeError::new(Code::Unsupported, format!("event {t}")));
        }
        let filter = Filter {
            endpoints: list("endpoint_ids"),
            sessions: list("session_ids"),
            types,
            all_parties: req
                .body
                .get("all_parties")
                .and_then(Json::as_bool)
                .unwrap_or(false),
            sensitive: req
                .body
                .get("sensitive")
                .and_then(Json::as_bool)
                .unwrap_or(false),
        };
        self.native.next_subscription += 1;
        let id = self.native.next_subscription;
        let n = &mut self.native;
        let mut sub = Subscriber {
            id,
            tenant: req.tenant.to_owned(),
            filter,
            tx,
            missed: 0,
            last: n.global_seq,
        };
        // From a cursor: what came after it first, then live. A cursor of
        // another run, or older than the journal, gets a gap saying so
        // (reconcile with the inventory), never a silent loss.
        let mut resumed = json!(null);
        if let Some(c) = req.str("cursor") {
            let parsed = c
                .rsplit_once(':')
                .and_then(|(boot, seq)| Some((boot, seq.parse::<u64>().ok()?)));
            let Some((boot, after)) = parsed else {
                return Err(NativeError::invalid("cursor: <boot_id>:<global_seq>"));
            };
            let reason = if boot != n.boot_id {
                Some("boot_changed")
            } else if after < n.journal_evicted {
                Some("retention_expired")
            } else {
                None
            };
            if let Some(reason) = reason {
                let gap = json!({"event": "gap", "reason": reason, "subscription_id": id,
                    "boot_id": n.boot_id, "global_seq": n.global_seq});
                let _ = sub.tx.try_send(frame_json(&gap));
                resumed = json!(false);
            } else {
                let boot = n.boot_id.clone();
                sub.last = after;
                for (seq, e) in n.journal.iter().filter(|(seq, _)| *seq > after) {
                    let mine = e
                        .get("tenant")
                        .and_then(Json::as_str)
                        .is_none_or(|t| t == sub.tenant);
                    let bytes = if super::ivr::is_sensitive(e) && !sub.filter.sensitive {
                        frame_json(&super::ivr::redact(e))
                    } else {
                        frame_json(e)
                    };
                    if mine && sub.filter.wants(e) && !sub.deliver(&boot, *seq, bytes) {
                        break;
                    }
                }
                if sub.last < n.global_seq && sub.missed == 0 {
                    sub.last = n.global_seq;
                }
                resumed = json!(true);
            }
        }
        n.subscribers.push((origin.connection, sub));
        Ok(json!({"subscription_id": id, "global_seq": n.global_seq,
            "cursor": format!("{}:{}", n.boot_id, n.global_seq), "resumed": resumed}))
    }

    fn native_unsubscribe(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let id = req
            .u64("subscription_id")?
            .ok_or_else(|| NativeError::invalid("missing subscription_id"))?;
        let before = self.native.subscribers.len();
        self.native
            .subscribers
            .retain(|(_, s)| !(s.id == id && s.tenant == req.tenant));
        Ok(json!({"unsubscribed": before != self.native.subscribers.len()}))
    }

    /// A connection closed: its subscriptions end.
    pub fn native_closed(&mut self, connection: u64) {
        self.native.subscribers.retain(|(c, _)| *c != connection);
    }

    /// Endpoints whose media is gone (deleted with `ng`, timed out) are
    /// destroyed; leases that ran out destroy theirs.
    pub(super) fn native_reconcile(&mut self, reason: &'static str) {
        if self.native.endpoints.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut gone = Vec::new();
        let mut expired = Vec::new();
        for ep in self.native.endpoints.values() {
            let (call, tag) = (ep.session.as_bytes(), ep.id.as_bytes());
            let creator = [super::create::CREATOR, tag].concat();
            let alive = self.sessions.contains_key(&(call.to_vec(), tag.to_vec()))
                || self.sessions.contains_key(&(call.to_vec(), creator));
            if !alive {
                gone.push(ep.id.clone());
            } else if ep.lease.is_some_and(|l| l.1 <= now) {
                expired.push(ep.id.clone());
            }
        }
        for id in gone {
            if reason == "timeout" {
                self.endpoint_event(&id, "endpoint.timeout", None, json!({}));
            }
            self.destroy_endpoint(
                &id,
                if reason == "timeout" {
                    "timeout"
                } else {
                    "ended"
                },
                None,
            );
        }
        for id in expired {
            self.destroy_endpoint(&id, "lease", None);
        }
    }

    /// The party of relay call `call` on leg `leg`: (Call-ID, tag), unless
    /// it is a hidden side.
    fn party_on_leg(&self, call: crate::relay::CallId, leg: CallLeg) -> Option<(Vec<u8>, Vec<u8>)> {
        self.sessions.iter().find_map(|(k, s)| {
            let st = s.media.iter().flatten().find(|st| st.ports.id == call)?;
            let party = [super::Party::A, super::Party::B]
                .into_iter()
                .find(|&p| st.leg(p) == leg)?;
            let tag = super::parties::tag_of(k, s, party)?;
            (!super::create::is_creator(tag)).then(|| (k.0.clone(), tag.to_vec()))
        })
    }

    /// A party of relay call `call` that is not a hidden side.
    pub(super) fn party_on_leg_any(
        &self,
        call: crate::relay::CallId,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        self.party_on_leg(call, CallLeg::A)
            .or_else(|| self.party_on_leg(call, CallLeg::B))
    }

    /// Hand the media events waiting to the subscribers.
    pub(super) fn native_media_events(&mut self) {
        let Some(inbox) = self.media_events.as_mut() else {
            return;
        };
        let (events, dropped) = inbox.take();
        let lost = if dropped > 0 {
            inbox.take_lost()
        } else {
            Vec::new()
        };
        if dropped > 0 {
            self.native.events_dropped += dropped;
            // The endpoints known to have lost events: marked, and told.
            let mut marked = Vec::new();
            for subject in &lost {
                let party = match subject {
                    Subject::Leg(call, leg) => self.party_on_leg(*call, *leg),
                    Subject::Call(call) => self.party_on_leg_any(*call),
                    Subject::Dialog {
                        call_id, from_tag, ..
                    } => Some((
                        call_id.as_bytes().to_vec(),
                        from_tag
                            .strip_prefix(std::str::from_utf8(super::create::CREATOR).unwrap_or(""))
                            .unwrap_or(from_tag)
                            .as_bytes()
                            .to_vec(),
                    )),
                };
                if let Some((_, tag)) = party
                    && let Ok(id) = String::from_utf8(tag)
                    && let Some(ep) = self.native.endpoints.get_mut(&id)
                {
                    ep.events_indeterminate = true;
                    marked.push(id);
                }
            }
            marked.sort();
            marked.dedup();
            for id in &marked {
                self.endpoint_event(
                    id,
                    "endpoint.events_lost",
                    None,
                    json!({
                        "reason": "the relay's media event queue was full: key presses, \
                                   announcements' ends or recordings' outcomes may be missing",
                    }),
                );
            }
            // And for every subscriber: some events were lost, perhaps of
            // endpoints not known (`attributed` says how many were).
            self.native
                .publish(json!({"event": "gap", "reason": "media_overflow",
                "missed": dropped, "source": "media", "attributed_endpoints": marked}));
        }
        if self.native.subscribers.is_empty() {
            // Playbacks still end for the endpoints' snapshots.
            for e in events {
                self.note_playback_end(&e);
            }
            return;
        }
        for e in &events {
            self.media_event(e);
        }
    }

    /// An announcement that played out: the endpoint's playback is over.
    fn note_playback_end(&mut self, e: &MediaEvent) -> Option<(String, String, Option<String>)> {
        let (MediaEventKind::PlaybackEnded, Subject::Leg(call, leg)) = (&e.kind, &e.subject) else {
            return None;
        };
        let (_, tag) = self.party_on_leg(*call, *leg)?;
        let id = String::from_utf8(tag).ok()?;
        let ep = self.native.endpoints.get_mut(&id)?;
        let (pb, op) = ep.playback.take()?;
        Some((id, pb, op))
    }

    fn media_event(&mut self, e: &MediaEvent) {
        if let Some((id, pb, op)) = self.note_playback_end(e) {
            self.endpoint_event(
                &id,
                "playback.completed",
                op.as_deref(),
                json!({"playback_id": pb}),
            );
            if let Some(i) = self.native.ivr.get_mut(&id) {
                i.stop_on.clear();
            }
            self.play_next(&id);
            return;
        }
        let (ty, data) = match &e.kind {
            MediaEventKind::Dtmf {
                code,
                duration_ms,
                rtp_timestamp,
                inband,
            } => (
                "dtmf.detected",
                json!({
                    "digit": rtpflux_core::dtmf::digit(*code).map(String::from),
                    "code": code,
                    "duration_ms": duration_ms,
                    "rtp_timestamp": rtp_timestamp,
                    "source": if *inband { "inband" } else { "rfc4733" },
                    "end_unix_ms": e.at_unix_ms,
                    "start_unix_ms": e.at_unix_ms.saturating_sub(u64::from(*duration_ms)),
                }),
            ),
            MediaEventKind::PlaybackEnded => ("playback.completed", json!({})),
            MediaEventKind::DtlsReady => ("dtls.ready", json!({})),
            MediaEventKind::DtlsFailed => ("endpoint.failed", json!({"reason": "dtls"})),
            MediaEventKind::IceConnected => ("ice.connected", json!({})),
            MediaEventKind::Failed { what, reason } => (
                if *what == "recording" {
                    "recording.failed"
                } else {
                    "endpoint.failed"
                },
                json!({"reason": what, "detail": reason,
                       "recording_id": (*what == "recording")
                           .then(|| self.recording_ended(&e.subject, None, None, Some(reason)))
                           .flatten()}),
            ),
            MediaEventKind::ActiveSpeaker { mixer } => {
                ("mixer.speaker", json!({"mixer_id": mixer}))
            }
            MediaEventKind::SpeechStarted => ("speech.started", json!({})),
            MediaEventKind::SpeechEnded => ("speech.ended", json!({})),
            k @ (MediaEventKind::StreamMark { .. } | MediaEventKind::StreamFlushed { .. }) => {
                stream_event(k)
            }
            MediaEventKind::StreamEnded { stream } => {
                self.native.streams.remove(stream);
                ("stream.ended", json!({"stream_id": stream}))
            }
            MediaEventKind::RecordingDone { file, uploaded } => (
                if file.is_some() {
                    "recording.completed"
                } else {
                    "recording.failed"
                },
                json!({"file": file, "uploaded": uploaded,
                       "recording_id": self.recording_ended(&e.subject, file.as_ref(), *uploaded, None)}),
            ),
        };
        self.route_event(e, ty, data);
    }

    /// Deliver a media event to the endpoint, or the `ng` party, it is
    /// about.
    fn route_event(&mut self, e: &MediaEvent, ty: &str, data: Json) {
        // Who it is about: an endpoint, or an `ng` party.
        let party = match &e.subject {
            Subject::Leg(call, leg) => self.party_on_leg(*call, *leg),
            // A call's: its first party that is not a hidden side.
            Subject::Call(call) => self.party_on_leg_any(*call),
            Subject::Dialog {
                call_id, from_tag, ..
            } => {
                let tag = from_tag
                    .strip_prefix(std::str::from_utf8(super::create::CREATOR).unwrap_or(""))
                    .unwrap_or(from_tag);
                Some((call_id.as_bytes().to_vec(), tag.as_bytes().to_vec()))
            }
        };
        let Some((call, tag)) = party else {
            return;
        };
        let id = String::from_utf8_lossy(&tag).into_owned();
        let mut data = data;
        if let (Subject::Dialog { section, .. }, Some(o)) = (&e.subject, data.as_object_mut()) {
            o.insert("section".to_owned(), json!(section));
        }
        if self
            .native
            .endpoints
            .get(&id)
            .is_some_and(|ep| ep.session.as_bytes() == call.as_slice())
        {
            if !self.ivr_admit(&id, ty, &mut data, e.at_unix_ms) {
                return;
            }
            self.endpoint_event(&id, ty, None, data);
            self.ivr_interrupt(&id, ty);
        } else {
            self.native.publish(json!({
                "event": ty,
                "call_id": String::from_utf8_lossy(&call),
                "tag": id,
                "data": data,
            }));
        }
    }
}

/// What a connection thread hands the control thread.
#[derive(Debug)]
enum Message {
    /// A request, and where its reply goes.
    Request {
        body: Vec<u8>,
        origin: Origin,
        reply: SyncSender<Vec<u8>>,
    },
    /// The connection closed.
    Closed(u64),
}

/// Requests waiting for the control thread, at most.
const QUEUE: usize = 256;
/// How long a connection waits for a reply.
const WAIT: Duration = Duration::from_secs(5);

/// A connection thread's link to the control thread.
#[derive(Debug, Clone)]
pub struct NativeLink {
    tx: SyncSender<Message>,
    wake: std::sync::Arc<nix::sys::eventfd::EventFd>,
}

impl NativeLink {
    /// The reply to the request `body` from `origin`; `None` when the
    /// control thread is busy or gone.
    #[must_use]
    pub fn ask(&self, body: Vec<u8>, origin: Origin) -> Option<Vec<u8>> {
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        self.tx
            .try_send(Message::Request {
                body,
                origin,
                reply,
            })
            .ok()?;
        let _ = self.wake.write(1);
        answer.recv_timeout(WAIT).ok()
    }

    /// Connection `connection` closed: its subscriptions end.
    pub fn closed(&self, connection: u64) {
        // Its subscribers also go when their queue is found disconnected.
        if self.tx.try_send(Message::Closed(connection)).is_ok() {
            let _ = self.wake.write(1);
        }
    }
}

/// The control thread's end.
#[derive(Debug)]
pub(super) struct NativeInbox {
    rx: std::sync::mpsc::Receiver<Message>,
    pub(super) wake: std::sync::Arc<nix::sys::eventfd::EventFd>,
}

impl Control {
    /// The link of the native API's connections to this control thread
    /// (made once; later calls replace it).
    ///
    /// # Errors
    ///
    /// When the eventfd cannot be created.
    pub fn native_link(&mut self) -> Result<NativeLink, nix::Error> {
        use nix::sys::eventfd::{EfdFlags, EventFd};
        let (tx, rx) = std::sync::mpsc::sync_channel(QUEUE);
        let wake = std::sync::Arc::new(EventFd::from_flags(
            EfdFlags::EFD_NONBLOCK | EfdFlags::EFD_CLOEXEC,
        )?);
        self.native_inbox = Some(NativeInbox {
            rx,
            wake: std::sync::Arc::clone(&wake),
        });
        Ok(NativeLink { tx, wake })
    }

    /// Answer the native requests waiting.
    pub(super) fn answer_native(&mut self) {
        let Some(inbox) = &self.native_inbox else {
            return;
        };
        let _ = inbox.wake.read();
        let waiting: Vec<Message> = inbox.rx.try_iter().collect();
        for m in waiting {
            match m {
                Message::Request {
                    body,
                    origin,
                    reply,
                } => {
                    let r = self.native_request(&body, &origin);
                    let _ = reply.send(r);
                }
                Message::Closed(c) => self.native_closed(c),
            }
        }
    }

    /// Wait until the media workers of `eps` have applied what was sent to
    /// them (a reply then means the change is in effect).
    ///
    /// # Errors
    ///
    /// `timeout` when a worker does not confirm within a second (the change
    /// may still take effect: `endpoint.query` tells).
    fn confirm(&mut self, eps: &[&Endpoint]) -> Result<(), NativeError> {
        let calls: Vec<crate::relay::CallId> = eps
            .iter()
            .filter_map(|e| self.party_legs(e.session.as_bytes(), e.id.as_bytes()))
            .flatten()
            .flatten()
            .map(|((id, _), _)| id)
            .collect();
        let confirmed = self.relay.applied(&calls, Duration::from_secs(1));
        // What the snapshots say until a later confirmation.
        for e in eps {
            if let Some(ep) = self.native.endpoints.get_mut(&e.id) {
                ep.topology_state = (!confirmed).then_some("unconfirmed");
            }
        }
        if confirmed {
            Ok(())
        } else {
            Err(NativeError::new(
                Code::Timeout,
                "the media workers did not confirm the change in time",
            ))
        }
    }

    /// A failed `bridge.attach`: `a`, `b` and whoever either was bridged to
    /// are detached on the media workers and in the records, each told so.
    fn compensate_attach(&mut self, a: &Endpoint, b: &Endpoint, operation_id: Option<&str>) {
        let mut ids: Vec<String> = vec![a.id.clone(), b.id.clone()];
        ids.extend(a.bridged_to.iter().cloned());
        ids.extend(b.bridged_to.iter().cloned());
        ids.sort();
        ids.dedup();
        for id in &ids {
            let Some(ep) = self.native.endpoints.get(id).cloned() else {
                continue;
            };
            let (call, tag) = (ep.session.as_bytes().to_vec(), ep.id.as_bytes().to_vec());
            for ((call_id, leg), _) in self
                .party_legs(&call, &tag)
                .unwrap_or_default()
                .into_iter()
                .flatten()
            {
                if let Err(e) = self.relay.detach((call_id, leg)) {
                    log::warn!("native: endpoint {id}: detaching after a failed attach: {e}");
                }
            }
            let key = (call, tag);
            self.connections.retain(|(x, y)| *x != key && *y != key);
            self.set_bridge(id, None, "attach_failed", operation_id);
        }
        self.mark_dirty();
        let eps: Vec<Endpoint> = ids
            .iter()
            .filter_map(|id| self.native.endpoints.get(id).cloned())
            .collect();
        let _ = self.confirm(&eps.iter().collect::<Vec<_>>());
    }

    /// The native API's gauges and counters, for `/metrics`.
    pub(super) fn native_gauges(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let s = &self.stats;
        let n = &self.native;
        s.native_endpoints.store(n.endpoints.len() as u64, Relaxed);
        s.native_bridged.store(
            n.endpoints
                .values()
                .filter(|e| e.bridged_to.is_some())
                .count() as u64,
            Relaxed,
        );
        s.native_mixers.store(n.mixers.len() as u64, Relaxed);
        s.native_streams.store(n.streams.len() as u64, Relaxed);
        s.media_events_dropped.store(n.events_dropped, Relaxed);
    }

    /// Set where external audio services' sockets are (`[control]
    /// pcm_dir`).
    pub fn set_pcm_dir(&mut self, dir: Option<std::path::PathBuf>) {
        self.native.pcm_dir = dir;
    }

    /// Keep the operation ledger in `path` (durable mode).
    ///
    /// # Errors
    ///
    /// When the file cannot be opened, read or written.
    pub fn open_ledger(
        &mut self,
        path: &std::path::Path,
        retention_ms: u64,
        quota: usize,
    ) -> std::io::Result<()> {
        let l = super::ledger::Ledger::open(
            path,
            retention_ms,
            quota,
            crate::relay::media_events::unix_ms(),
        )?;
        self.native.ledger = l;
        Ok(())
    }

    /// Tell subscribers that missed events, as soon as they have room, even
    /// when no event follows (on the control thread's every pass).
    pub(super) fn native_flush_gaps(&mut self) {
        let boot = self.native.boot_id.clone();
        self.native
            .subscribers
            .retain_mut(|(_, s)| s.flush_gap(&boot));
    }

    /// Keep `cap` events for replay (`[control] native_event_journal`).
    pub fn set_native_journal(&mut self, cap: usize) {
        self.native.journal_cap = cap;
    }

    /// Set the most endpoints one tenant may hold (0: no limit of its own).
    pub fn set_native_max_endpoints(&mut self, max: usize) {
        self.native.max_endpoints = max;
    }
}

impl Control {
    /// The endpoints, to be saved with the dialogs.
    pub(super) fn saved_endpoints(&self) -> Vec<crate::state::SavedEndpoint> {
        let text =
            |b: &Option<Vec<u8>>| b.as_ref().map(|s| String::from_utf8_lossy(s).into_owned());
        let mut v: Vec<crate::state::SavedEndpoint> = self
            .native
            .endpoints
            .values()
            .map(|e| crate::state::SavedEndpoint {
                id: e.id.clone(),
                tenant: e.tenant.clone(),
                session: e.session.clone(),
                kind: e.kind.as_str().to_owned(),
                generation: e.generation,
                revision: e.revision,
                ready: e.ready,
                pending_revision: e.pending.as_ref().map(|p| p.revision),
                pending_local: e.pending.as_ref().is_some_and(|p| p.local),
                previous_remote_sdp: e.pending.as_ref().and_then(|p| text(&p.previous_remote)),
                bridged_to: e.bridged_to.clone(),
                label: e.label.clone(),
                lease_ms: e.lease.map(|l| l.0),
                remote_sdp: text(&e.remote_sdp),
                created_unix_ms: e.created_unix_ms,
                external_id: e.external_id.clone(),
                recording: e.recording.clone(),
                playback: e.playback.as_ref().map(|p| p.0.clone()),
                topology_revision: e.topology_revision,
            })
            .collect();
        v.sort_by_key(|e| e.generation);
        v
    }

    /// The saved endpoints back, those whose media came back; the others
    /// are gone (a tombstone each).
    /// The counters and tombstones, to be saved.
    pub(super) fn saved_native(&self) -> crate::state::SavedNative {
        let n = &self.native;
        crate::state::SavedNative {
            generation_seq: n.generation_seq,
            next_stream: n.next_stream,
            next_mixer: n.next_mixer,
            tombstones: n
                .tomb_order
                .iter()
                .filter_map(|id| {
                    let t = n.tombs.get(id)?;
                    Some(crate::state::SavedTomb {
                        id: id.clone(),
                        tenant: t.tenant.clone(),
                        generation: t.generation,
                        reason: t.reason.clone(),
                        at_unix_ms: t.at_ms,
                        external_id: t.external_id.clone(),
                    })
                })
                .collect(),
            ..crate::state::SavedNative::default()
        }
    }

    pub(super) fn restore_endpoints(
        &mut self,
        saved: &[crate::state::SavedEndpoint],
        native: &crate::state::SavedNative,
    ) {
        // Counters first: no id given again.
        self.native.generation_seq = self.native.generation_seq.max(native.generation_seq);
        self.native.next_stream = self.native.next_stream.max(native.next_stream);
        self.native.next_mixer = self.native.next_mixer.max(native.next_mixer);
        for t in &native.tombstones {
            if let Some(x) = &t.external_id {
                self.native
                    .external_tombs
                    .insert((t.tenant.clone(), x.clone()), t.id.clone());
            }
            self.native.tombs.insert(
                t.id.clone(),
                Tomb {
                    tenant: t.tenant.clone(),
                    generation: t.generation,
                    reason: t.reason.clone(),
                    at_ms: t.at_unix_ms,
                    external_id: t.external_id.clone(),
                },
            );
            self.native.tomb_order.push_back(t.id.clone());
        }
        for e in saved {
            let kind = if e.kind == "remote_offer" {
                Kind::RemoteOffer
            } else {
                Kind::LocalOffer
            };
            let ep = Endpoint {
                id: e.id.clone(),
                tenant: e.tenant.clone(),
                session: e.session.clone(),
                kind,
                generation: e.generation,
                revision: e.revision,
                ready: e.ready,
                pending: e.pending_revision.map(|revision| Pending {
                    revision,
                    previous_remote: e
                        .previous_remote_sdp
                        .as_ref()
                        .map(|s| s.as_bytes().to_vec()),
                    local: e.pending_local,
                }),
                bridged_to: e.bridged_to.clone(),
                label: e.label.clone(),
                lease: e
                    .lease_ms
                    .map(|ms| (ms, Instant::now() + Duration::from_millis(ms))),
                seq: 0,
                remote_sdp: e.remote_sdp.as_ref().map(|s| s.as_bytes().to_vec()),
                playback: e.playback.clone().map(|p| (p, None)),
                created_unix_ms: e.created_unix_ms,
                external_id: e.external_id.clone(),
                recording: e.recording.clone(),
                topology_revision: e.topology_revision,
                topology_state: None,
                events_indeterminate: false,
            };
            if let Some(x) = &e.external_id {
                self.native
                    .externals
                    .insert((e.tenant.clone(), x.clone()), e.id.clone());
            }
            self.native.generation_seq = self.native.generation_seq.max(e.generation);
            self.native.endpoints.insert(e.id.clone(), ep);
        }
        // Those whose media is gone: destroyed (`ended`).
        self.native_reconcile("ended");
        if !saved.is_empty() {
            log::info!(
                "native: {} endpoint(s) restored",
                self.native.endpoints.len()
            );
        }
    }
}

/// Standard base64 (with or without padding) decoded; `None` when it is not.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

impl Control {
    /// `stream.start`: a PCM stream between endpoint `endpoint_id` and the
    /// service listening on `socket` (a file name in `[control] pcm_dir`):
    /// at `rate` (8000, 16000, 24000 or 48000; 16000 by default), the
    /// endpoint's audio to the service, and (`inject`, the default) the
    /// service's audio to the endpoint (a G.711 endpoint's).
    fn native_stream_start(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.endpoint(req)?;
        // A service's socket in pcm_dir; none: detectors only.
        let name = req.str("socket");
        let socket = match name {
            Some(name) => {
                let Some(dir) = self.native.pcm_dir.clone() else {
                    return Err(NativeError::new(
                        Code::Unsupported,
                        "PCM streams are not configured ([control] pcm_dir)",
                    ));
                };
                if !valid_name(name) || name.contains('/') || name.starts_with('.') {
                    return Err(NativeError::invalid("socket: a file name in pcm_dir"));
                }
                Some(dir.join(name))
            }
            None => None,
        };
        let detect = detectors(req, crate::pcm::stream::VAD | crate::pcm::stream::DTMF)?;
        let rate = u32::try_from(req.u64("rate")?.unwrap_or(16_000)).unwrap_or(0);
        if !crate::pcm::frame::valid_rate(rate) {
            return Err(NativeError::invalid("rate: 8000, 16000, 24000 or 48000"));
        }
        if self.native.streams.values().any(|(e, _)| *e == ep.id) {
            return Err(NativeError::new(
                Code::Conflict,
                "the endpoint has a stream already",
            ));
        }
        let want_inject = socket.is_some()
            && req
                .body
                .get("inject")
                .and_then(Json::as_bool)
                .unwrap_or(true);
        let protocol = match req.u64("protocol")?.unwrap_or(1) {
            1 => 1,
            2 => 2,
            _ => return Err(NativeError::invalid("protocol: 1 or 2")),
        };
        let socket_given = socket.is_some();
        let (leg, pt, codec, clock) = self.endpoint_audio(&ep)?;
        let inject = match crate::pcm::stream::encoder_for(codec) {
            Some(_) if want_inject => Some((pt, codec)),
            None if want_inject => {
                return Err(NativeError::new(
                    Code::Unsupported,
                    "the relay does not encode the endpoint's codec; use inject: false",
                ));
            }
            _ => None,
        };
        if self.in_mixer(&ep.id) {
            return Err(NativeError::new(
                Code::Conflict,
                "the endpoint is in a mixer",
            ));
        }
        self.native.next_stream = self.native.next_stream.wrapping_add(1).max(1);
        let id = self.native.next_stream;
        let spec = crate::pcm::stream::Spec {
            id,
            socket,
            detect,
            rate,
            pt,
            codec,
            clock,
            inject,
            protocol,
            events: self.relay.media_event_sender(),
            subject: Subject::Leg(leg.0, leg.1),
        };
        let (end, handle) = crate::pcm::stream::start(&spec).map_err(|e| {
            NativeError::new(
                Code::Invalid,
                format!("socket {}: {e}", name.unwrap_or("(none)")),
            )
        })?;
        if !self.relay.pcm_stream(leg, Some(end)).map_err(Error::from)? {
            handle.stop();
            return Err(NativeError::new(
                Code::NotFound,
                "the endpoint's media is gone",
            ));
        }
        self.native.streams.insert(id, (ep.id.clone(), handle));
        log::info!("native: stream {id} on endpoint {} ({rate} Hz)", ep.id);
        self.confirm(&[&ep])?;
        Ok(
            json!({"stream_id": id, "rate": rate, "inject": inject.is_some(), "protocol": protocol,
            "service": socket_given, "detect": detect_json(detect)}),
        )
    }

    /// `stream.flush` (barge-in: the audio queued for the endpoint goes)
    /// and `stream.stop`, of `stream_id`.
    fn native_stream(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let id = req
            .u64("stream_id")?
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| NativeError::invalid("missing stream_id"))?;
        let Some((ep_id, handle)) = self.native.streams.get(&id).cloned() else {
            return Err(NativeError::new(Code::NotFound, format!("stream {id}")));
        };
        let ep = self.native.get(&ep_id, req.tenant)?.clone();
        if req.op == "stream.flush" {
            handle.flush();
            return Ok(json!({"flushed": true}));
        }
        if req.op == "stream.detect" {
            let d = detectors(req, handle.detectors())?;
            handle.detect(d);
            return Ok(json!({"detect": detect_json(d)}));
        }
        handle.stop();
        self.native.streams.remove(&id);
        if let Some((leg, _)) = self
            .party_legs(ep.session.as_bytes(), ep.id.as_bytes())
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .next()
        {
            self.relay.pcm_stream(leg, None).map_err(Error::from)?;
        }
        Ok(json!({"stopped": true}))
    }
}

/// The detectors a request asks for (`vad`, `dtmf`), from `current`.
fn detectors(req: &Request<'_>, current: u8) -> Result<u8, NativeError> {
    use crate::pcm::stream::{DTMF, VAD};
    let mut d = current;
    for (key, bit) in [("vad", VAD), ("dtmf", DTMF)] {
        match req.body.get(key) {
            None => {}
            Some(Json::Bool(true)) => d |= bit,
            Some(Json::Bool(false)) => d &= !bit,
            Some(_) => return Err(NativeError::invalid(format!("{key}: true or false"))),
        }
    }
    Ok(d)
}

fn detect_json(d: u8) -> Json {
    use crate::pcm::stream::{DTMF, VAD};
    json!({"vad": d & VAD != 0, "dtmf": d & DTMF != 0})
}

/// A PCM stream's mark or flush, on the wire.
fn stream_event(k: &MediaEventKind) -> (&'static str, Json) {
    match k {
        MediaEventKind::StreamMark {
            stream,
            mark,
            generation,
            played_ms,
            flushed,
        } => (
            "stream.mark",
            json!({"stream_id": stream, "mark": mark, "generation": generation,
                   "played_ms": played_ms, "flushed": flushed, "boundary": "rtp_sent"}),
        ),
        MediaEventKind::StreamFlushed {
            stream,
            generation,
            played_ms,
        } => (
            "stream.flushed",
            json!({"stream_id": stream, "generation": generation, "played_ms": played_ms}),
        ),
        // Called with the two kinds above only.
        _ => ("gap", json!({})),
    }
}

impl Control {
    /// The leg an endpoint's audio is on (its first audio section), the
    /// payload type and codec of its audio, and its RTP clock.
    fn endpoint_audio(&self, ep: &Endpoint) -> Result<EndpointAudio, NativeError> {
        let legs = self
            .party_legs(ep.session.as_bytes(), ep.id.as_bytes())
            .unwrap_or_default();
        let Some((leg, audio)) = legs.into_iter().flatten().next() else {
            return Err(NativeError::new(
                Code::Conflict,
                "the endpoint has no audio",
            ));
        };
        let Some((pt, codec)) = audio else {
            return Err(NativeError::new(
                Code::Unsupported,
                "the endpoint's codec is not one the relay decodes",
            ));
        };
        let clock = match codec {
            Codec::Opus => 48_000,
            Codec::AmrWb => 16_000,
            _ => 8000,
        };
        Ok((leg, pt, codec, clock))
    }

    /// Whether endpoint `id` is in a mixer.
    fn in_mixer(&self, id: &str) -> bool {
        self.native
            .mixers
            .values()
            .any(|(_, m)| m.participants.iter().any(|p| p == id))
    }

    fn native_mixer_create(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        self.native.next_mixer = self.native.next_mixer.wrapping_add(1).max(1);
        let id = self.native.next_mixer;
        let handle = crate::pcm::mixer::start(id, self.relay.media_event_sender())
            .map_err(|e| NativeError::new(Code::Internal, format!("mixer: {e}")))?;
        self.native
            .mixers
            .insert(id, (req.tenant.to_owned(), handle));
        log::info!("native: mixer {id} created");
        Ok(json!({"mixer_id": id, "max_participants": crate::pcm::mixer::MAX_PARTICIPANTS}))
    }

    /// `mixer.add`, `mixer.remove`, `mixer.set` (`muted`, `gain_db`) and
    /// `mixer.destroy`.
    fn native_mixer(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let id = req
            .u64("mixer_id")?
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| NativeError::invalid("missing mixer_id"))?;
        match self.native.mixers.get(&id) {
            Some((t, _)) if t == req.tenant => {}
            Some(_) => {
                return Err(NativeError::new(
                    Code::Unauthorized,
                    format!("mixer {id}: another tenant's"),
                ));
            }
            None => return Err(NativeError::new(Code::NotFound, format!("mixer {id}"))),
        }
        if req.op == "mixer.destroy" {
            let Some((_, m)) = self.native.mixers.remove(&id) else {
                return Ok(json!({"destroyed": false}));
            };
            m.stop();
            for key in &m.participants {
                if let Some(ep) = self.native.endpoints.get(key).cloned()
                    && let Ok((leg, ..)) = self.endpoint_audio(&ep)
                {
                    self.relay.pcm_stream(leg, None).map_err(Error::from)?;
                }
            }
            return Ok(json!({"destroyed": true}));
        }
        let ep = self.endpoint(req)?;
        match req.op {
            "mixer.add" => {
                let role = self.mixer_role(req, id)?;
                let r = self.mixer_add(id, &ep)?;
                if let (Some(role), Some((_, m))) = (role, self.native.mixers.get(&id)) {
                    m.role(&ep.id, role);
                }
                Ok(r)
            }
            "mixer.remove" => {
                let removed = self
                    .native
                    .mixers
                    .get_mut(&id)
                    .is_some_and(|(_, m)| m.remove(&ep.id));
                if removed && let Ok((leg, ..)) = self.endpoint_audio(&ep) {
                    self.relay.pcm_stream(leg, None).map_err(Error::from)?;
                }
                Ok(json!({"removed": removed}))
            }
            _ => {
                let Some((_, m)) = self.native.mixers.get(&id) else {
                    return Err(NativeError::new(Code::NotFound, format!("mixer {id}")));
                };
                if !m.participants.contains(&ep.id) {
                    return Err(NativeError::new(Code::NotFound, "not a participant"));
                }
                if let Some(muted) = req.body.get("muted").and_then(Json::as_bool) {
                    m.mute(&ep.id, muted);
                }
                if let Some(db) = req.body.get("gain_db").and_then(Json::as_i64) {
                    m.gain(&ep.id, i32::try_from(db.clamp(-60, 24)).unwrap_or(0));
                }
                let role = self.mixer_role(req, id)?;
                if let (Some(role), Some((_, m))) = (role, self.native.mixers.get(&id)) {
                    m.role(&ep.id, role);
                }
                Ok(json!({"set": true}))
            }
        }
    }

    /// The `role` a request gives (`participant`, `listen`, or `whisper`
    /// with `whisper_to`, a participant of mixer `id`), if any.
    fn mixer_role(
        &self,
        req: &Request<'_>,
        id: u32,
    ) -> Result<Option<crate::pcm::mixer::Role>, NativeError> {
        use crate::pcm::mixer::Role;
        let Some(role) = req.str("role") else {
            return Ok(None);
        };
        Ok(Some(match role {
            "participant" => Role::Participant,
            "listen" => Role::Listen,
            "whisper" => {
                let to = req.need("whisper_to")?;
                let known = self
                    .native
                    .mixers
                    .get(&id)
                    .is_some_and(|(_, m)| m.participants.iter().any(|p| p == to));
                if !known {
                    return Err(NativeError::new(
                        Code::NotFound,
                        format!("whisper_to: {to} is not in mixer {id}"),
                    ));
                }
                Role::Whisper(to.to_owned())
            }
            other => {
                return Err(NativeError::invalid(format!(
                    "role: {other} (participant, listen or whisper)"
                )));
            }
        }))
    }

    /// Endpoint `ep` joins mixer `id`.
    fn mixer_add(&mut self, id: u32, ep: &Endpoint) -> Result<Json, NativeError> {
        if ep.bridged_to.is_some() {
            return Err(NativeError::new(
                Code::Conflict,
                "the endpoint is bridged (bridge.detach first)",
            ));
        }
        if self.in_mixer(&ep.id) || self.native.streams.values().any(|(e, _)| *e == ep.id) {
            return Err(NativeError::new(
                Code::Conflict,
                "the endpoint is in a mixer or has a stream",
            ));
        }
        let (leg, pt, codec, clock) = self.endpoint_audio(ep)?;
        let Some((_, m)) = self.native.mixers.get_mut(&id) else {
            return Err(NativeError::new(Code::NotFound, format!("mixer {id}")));
        };
        let end = m
            .add(crate::pcm::mixer::Joining {
                key: ep.id.clone(),
                codec,
                clock,
                pt,
                subject: Subject::Leg(leg.0, leg.1),
            })
            .map_err(|why| NativeError::new(Code::Exhausted, why))?;
        let participants = m.participants.len();
        if !self.relay.pcm_stream(leg, Some(end)).map_err(Error::from)? {
            if let Some((_, m)) = self.native.mixers.get_mut(&id) {
                m.remove(&ep.id);
            }
            return Err(NativeError::new(
                Code::NotFound,
                "the endpoint's media is gone",
            ));
        }
        self.confirm(&[ep])?;
        Ok(json!({"mixer_id": id, "participants": participants}))
    }
}

/// An endpoint's audio: its leg, payload type, codec and RTP clock.
type EndpointAudio = (
    (crate::relay::CallId, CallLeg),
    rtpflux_core::rtp::Pt,
    rtpflux_core::sdp::Codec,
    u32,
);

/// Whether operation `op` changes anything (only such operations are
/// recorded in the ledger).
pub(super) fn mutates(op: &str) -> bool {
    !matches!(
        op,
        "hello"
            | "endpoint.query"
            | "endpoint.list"
            | "endpoint.lookup"
            | "operation.query"
            | "inventory.list"
            | "recovery.report"
            | "recording.query"
            | "events.subscribe"
            | "events.unsubscribe"
    )
}

/// The resources a result names (their ids).
pub(super) fn resource_refs(result: &Json) -> Vec<String> {
    [
        "endpoint_id",
        "bridged_to",
        "mixer_id",
        "stream_id",
        "playback_id",
        "recording_id",
    ]
    .iter()
    .filter_map(|k| match result.get(k)? {
        Json::String(s) => Some(s.clone()),
        Json::Number(n) => Some(format!("{k}:{n}")),
        _ => None,
    })
    .collect()
}

impl Control {
    /// `operation.query`: what became of the operation `idempotency_key`.
    fn native_operation(&self, req: &Request<'_>) -> Result<Json, NativeError> {
        use super::ledger::Status;
        let key = req.need("idempotency_key")?;
        let Some(e) = self.native.ledger.get(req.tenant, key) else {
            // Older than the ledger keeps: its outcome is gone.
            let now = crate::relay::media_events::unix_ms();
            let expired = req
                .u64("first_attempt_unix_ms")?
                .is_some_and(|first| now.saturating_sub(first) >= self.native.ledger.retention_ms);
            return Ok(json!({
                "status": if expired { "expired" } else { "not_found" },
                "durable": self.native.ledger.durable(),
                "retention_ms": self.native.ledger.retention_ms,
            }));
        };
        let status = match e.status {
            Status::Pending => "pending",
            Status::Applied => "applied",
            Status::Failed => "failed",
            Status::Unknown => "unknown",
        };
        Ok(json!({
            "status": status,
            "op": e.op,
            "resources": e.resources,
            "reply": e.reply,
            "at_unix_ms": e.at_ms,
            "durable": self.native.ledger.durable(),
        }))
    }
}

/// External ids a tenant may hold, live and destroyed, at most.
const MAX_EXTERNAL_IDS: usize = 262_144;

impl Control {
    /// The request's `external_id`, if any, once it may be used: not held
    /// by a live endpoint, and, if a destroyed endpoint held it, named as
    /// replaced (`replaces_generation`).
    fn check_external(&self, req: &Request<'_>) -> Result<Option<String>, NativeError> {
        let Some(x) = req.str("external_id") else {
            return Ok(None);
        };
        if !valid_name(x) {
            return Err(NativeError::invalid("external_id: not a name"));
        }
        let k = (req.tenant.to_owned(), x.to_owned());
        if let Some(id) = self.native.externals.get(&k) {
            let generation = self.native.endpoints.get(id).map(|e| e.generation);
            return Err(NativeError::new(
                Code::Conflict,
                format!("external_id {x} is endpoint {id}'s"),
            )
            .with_detail(json!({"endpoint_id": id, "generation": generation, "state": "live"})));
        }
        if let Some(id) = self.native.external_tombs.get(&k)
            && let Some(t) = self.native.tombs.get(id)
            && req.u64("replaces_generation")? != Some(t.generation)
        {
            return Err(NativeError::new(
                Code::Conflict,
                format!(
                    "external_id {x} was endpoint {id}'s, destroyed ({}): a new endpoint under it needs replaces_generation {}",
                    t.reason, t.generation
                ),
            )
            .with_detail(json!({"endpoint_id": id, "generation": t.generation,
                "state": "destroyed", "reason": t.reason})));
        }
        let held = self
            .native
            .externals
            .keys()
            .chain(self.native.external_tombs.keys())
            .filter(|(t, _)| t == req.tenant)
            .count();
        if held >= MAX_EXTERNAL_IDS {
            return Err(NativeError::new(
                Code::Exhausted,
                "the tenant holds its quota of external ids",
            ));
        }
        Ok(Some(x.to_owned()))
    }

    /// `endpoint.lookup`: the endpoint an `external_id` names, live or
    /// destroyed (while its tombstone is kept).
    fn native_lookup(&self, req: &Request<'_>) -> Result<Json, NativeError> {
        let x = req.need("external_id")?;
        let k = (req.tenant.to_owned(), x.to_owned());
        if let Some(ep) = self
            .native
            .externals
            .get(&k)
            .and_then(|id| self.native.endpoints.get(id))
        {
            let mut snap = Self::endpoint_snapshot(ep);
            if let Some(o) = snap.as_object_mut() {
                o.insert("state_of_id".to_owned(), json!("live"));
            }
            return Ok(snap);
        }
        if let Some((id, t)) = self
            .native
            .external_tombs
            .get(&k)
            .and_then(|id| Some((id, self.native.tombs.get(id)?)))
        {
            return Ok(json!({
                "endpoint_id": id,
                "external_id": x,
                "generation": t.generation,
                "state_of_id": "destroyed",
                "reason": t.reason,
                "destroyed_unix_ms": t.at_ms,
            }));
        }
        Err(NativeError::new(
            Code::NotFound,
            format!("external_id {x}: no endpoint (or its tombstone has expired)"),
        ))
    }
}

/// Tests only (feature `fault-injection`): die at `point` (SIGKILL: no
/// cleanup, no state saved) when `RTPFLUX_FAULT` names it.
#[cfg(feature = "fault-injection")]
fn fault(point: &str) {
    if std::env::var("RTPFLUX_FAULT").is_ok_and(|v| v == point) {
        log::warn!("fault injection: killed at {point}");
        let _ = nix::sys::signal::raise(nix::sys::signal::Signal::SIGKILL);
    }
}

#[cfg(not(feature = "fault-injection"))]
fn fault(_point: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_becomes_bencode_and_back() {
        let v = json!({"ICE": "remove", "flags": ["trust-address"], "n": 3, "on": true, "x": null});
        let b = to_b(&v).unwrap();
        let back = to_json(&b);
        assert_eq!(back["ICE"], "remove");
        assert_eq!(back["flags"][0], "trust-address");
        assert_eq!(back["n"], 3);
        assert_eq!(back["on"], "yes");
        assert!(back.get("x").is_none());
    }

    #[test]
    fn base64_is_decoded() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert!(base64_decode("a*b").is_none());
    }

    #[test]
    fn a_filter_selects_events() {
        let f = Filter {
            endpoints: vec!["ep-1".to_owned()],
            types: vec!["dtmf.detected".to_owned()],
            ..Filter::default()
        };
        assert!(f.wants(&json!({"event": "dtmf.detected", "endpoint_id": "ep-1"})));
        assert!(!f.wants(&json!({"event": "dtmf.detected", "endpoint_id": "ep-2"})));
        assert!(!f.wants(&json!({"event": "dtls.ready", "endpoint_id": "ep-1"})));
        assert!(f.wants(&json!({"event": "gap"})));
        assert!(!f.wants(&json!({"event": "dtmf.detected", "call_id": "c"})));
        let all = Filter {
            all_parties: true,
            ..Filter::default()
        };
        assert!(all.wants(&json!({"event": "dtmf.detected", "call_id": "c"})));
    }

    #[test]
    fn errors_have_codes() {
        assert_eq!(NativeError::from(Error::UnknownCall).code, Code::NotFound);
        assert_eq!(
            NativeError::from(Error::Relay(RelayError::PortsExhausted)).code,
            Code::Exhausted
        );
        assert_eq!(
            NativeError::from(Error::unsupported("x")).code,
            Code::Unsupported
        );
    }

    #[test]
    fn ids_are_random_and_named() {
        let (a, b) = (random_id("ep-"), random_id("ep-"));
        assert_ne!(a, b);
        assert_eq!(a.len(), 35);
        assert!(valid_name(&a) && !valid_name("a b") && !valid_name(""));
    }
}
