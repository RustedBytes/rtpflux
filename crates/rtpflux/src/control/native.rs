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
const MAX_REMEMBERED: usize = 16_384;
/// Tombstones kept at most (the oldest go first).
const MAX_TOMBSTONES: usize = 65_536;
/// Events a subscriber's queue holds.
pub const SUBSCRIBER_QUEUE: usize = 1024;
/// The shortest lease (milliseconds).
const MIN_LEASE_MS: u64 = 1000;

/// The operations of version 1.
pub const OPERATIONS: [&str; 26] = [
    "hello",
    "endpoint.create",
    "endpoint.apply_answer",
    "endpoint.prepare",
    "endpoint.commit",
    "endpoint.abort",
    "endpoint.destroy",
    "endpoint.query",
    "endpoint.list",
    "endpoint.renew",
    "bridge.attach",
    "bridge.detach",
    "playback.start",
    "playback.stop",
    "recording.start",
    "recording.stop",
    "stream.start",
    "stream.flush",
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
pub const EVENTS: [&str; 18] = [
    "endpoint.ready",
    "endpoint.failed",
    "endpoint.timeout",
    "endpoint.destroyed",
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
        }
    }
}

/// A failed operation.
#[derive(Debug, Clone)]
pub struct NativeError {
    pub code: Code,
    pub message: String,
}

impl NativeError {
    fn new(code: Code, message: impl Into<String>) -> Self {
        NativeError {
            code,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(Code::Invalid, message)
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
    /// The remote offer the endpoint had before (a remote endpoint's
    /// abort offers it again).
    previous_remote: Option<Vec<u8>>,
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
}

/// An endpoint destroyed: by whom, its generation, and when.
#[derive(Debug, Clone)]
struct Tomb {
    tenant: String,
    generation: u64,
    reason: &'static str,
    at: Instant,
}

/// What a subscriber wants.
#[derive(Debug, Clone, Default)]
struct Filter {
    endpoints: Vec<String>,
    sessions: Vec<String>,
    types: Vec<String>,
    /// Events of `ng` parties too (not only endpoints).
    all_parties: bool,
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
    tombs: HashMap<String, Tomb>,
    tomb_order: VecDeque<String>,
    /// (tenant, idempotency key) → (when, reply).
    remembered: HashMap<(String, String), (Instant, Json)>,
    remembered_order: VecDeque<(String, String)>,
    subscribers: Vec<(u64, Subscriber)>,
    next_subscription: u64,
    /// The last event's number across all events.
    global_seq: u64,
    generation_seq: u64,
    /// Endpoints per tenant at most (0: no limit of its own).
    pub(super) max_endpoints: usize,
    /// Media events the queue dropped (gaps reported).
    pub(super) events_dropped: u64,
    /// Where external audio services' sockets are (`[control] pcm_dir`).
    pub(super) pcm_dir: Option<std::path::PathBuf>,
    /// PCM streams: id → (endpoint, handle).
    streams: HashMap<u32, (String, crate::pcm::stream::Handle)>,
    next_stream: u32,
    /// Mixers: id → (tenant, handle).
    mixers: HashMap<u32, (String, crate::pcm::mixer::MixerHandle)>,
    next_mixer: u32,
}

/// A request's common fields.
struct Request<'a> {
    op: &'a str,
    operation_id: Option<&'a str>,
    tenant: &'a str,
    body: &'a Map<String, Json>,
}

impl Request<'_> {
    fn str(&self, key: &str) -> Option<&str> {
        self.body.get(key).and_then(Json::as_str)
    }

    fn need(&self, key: &str) -> Result<&str, NativeError> {
        self.str(key)
            .ok_or_else(|| NativeError::invalid(format!("missing {key}")))
    }

    fn u64(&self, key: &str) -> Result<Option<u64>, NativeError> {
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
fn random_id(prefix: &str) -> String {
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
    fn bury(&mut self, ep: &Endpoint, reason: &'static str) {
        if self.tomb_order.len() >= MAX_TOMBSTONES
            && let Some(old) = self.tomb_order.pop_front()
        {
            self.tombs.remove(&old);
        }
        self.tombs.insert(
            ep.id.clone(),
            Tomb {
                tenant: ep.tenant.clone(),
                generation: ep.generation,
                reason,
                at: Instant::now(),
            },
        );
        self.tomb_order.push_back(ep.id.clone());
    }

    /// Forget tombstones and idempotency keys older than [`RETENTION`].
    fn expire(&mut self, now: Instant) {
        while let Some(id) = self.tomb_order.front() {
            match self.tombs.get(id) {
                Some(t) if now.duration_since(t.at) < RETENTION => break,
                _ => {
                    if let Some(id) = self.tomb_order.pop_front() {
                        self.tombs.remove(&id);
                    }
                }
            }
        }
        while let Some(k) = self.remembered_order.front() {
            match self.remembered.get(k) {
                Some((at, _)) if now.duration_since(*at) < RETENTION => break,
                _ => {
                    if let Some(k) = self.remembered_order.pop_front() {
                        self.remembered.remove(&k);
                    }
                }
            }
        }
    }

    fn remember(&mut self, key: (String, String), reply: Json) {
        if self.remembered_order.len() >= MAX_REMEMBERED
            && let Some(old) = self.remembered_order.pop_front()
        {
            self.remembered.remove(&old);
        }
        self.remembered_order.push_back(key.clone());
        self.remembered.insert(key, (Instant::now(), reply));
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
        if let Some(o) = event.as_object_mut() {
            o.insert("global_seq".to_owned(), json!(self.global_seq));
            o.insert(
                "time_unix_ms".to_owned(),
                json!(crate::relay::media_events::unix_ms()),
            );
        }
        let tenant = event
            .get("tenant")
            .and_then(Json::as_str)
            .map(str::to_owned);
        let mut encoded: Option<Vec<u8>> = None;
        self.subscribers.retain_mut(|(_, s)| {
            if tenant.as_deref().is_some_and(|t| t != s.tenant) || !s.filter.wants(&event) {
                return true;
            }
            if s.missed > 0 {
                let gap = json!({"event": "gap", "missed": s.missed, "subscription_id": s.id});
                match s.tx.try_send(frame_json(&gap)) {
                    Ok(()) => s.missed = 0,
                    Err(TrySendError::Full(_)) => {
                        s.missed += 1;
                        return true;
                    }
                    Err(TrySendError::Disconnected(_)) => return false,
                }
            }
            let bytes = encoded.get_or_insert_with(|| frame_json(&event)).clone();
            match s.tx.try_send(bytes) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    s.missed += 1;
                    true
                }
                Err(TrySendError::Disconnected(_)) => false,
            }
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
            r.insert(
                "error".to_owned(),
                json!({"code": e.code.as_str(), "message": e.message}),
            );
        }
    }
    Json::Object(r)
}

impl Control {
    /// Run one native request (`message`: a JSON object) from `origin`;
    /// the reply, as JSON text.
    pub fn native_request(&mut self, message: &[u8], origin: &Origin) -> Vec<u8> {
        let now = Instant::now();
        self.native.expire(now);
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
        // Retried: the reply it had, nothing run again.
        let idem = body
            .get("idempotency_key")
            .and_then(Json::as_str)
            .map(|k| (req.tenant.to_owned(), k.to_owned()));
        // Its outcome then, as the reply to this request (`replayed`).
        if let Some(k) = &idem
            && let Some((_, r)) = self.native.remembered.get(k)
        {
            let mut r = r.clone();
            if let Some(o) = r.as_object_mut() {
                match req.operation_id {
                    Some(id) => o.insert("operation_id".to_owned(), json!(id)),
                    None => o.remove("operation_id"),
                };
                o.insert("replayed".to_owned(), json!(true));
            }
            return serde_json::to_vec(&r).unwrap_or_default();
        }
        let outcome = self.native_checked(&req, origin);
        if let Err(e) = &outcome {
            log::debug!("native {}: {}: {}", req.op, e.code.as_str(), e.message);
        }
        let r = reply(req.operation_id, outcome);
        let out = serde_json::to_vec(&r).unwrap_or_default();
        if let Some(k) = idem {
            self.native.remember(k, r);
        }
        // Endpoints whose media ended meanwhile (an `ng` delete, say).
        self.native_reconcile("ended");
        if !matches!(req.op, "hello" | "endpoint.query" | "endpoint.list") {
            self.mark_dirty();
        }
        out
    }

    /// The checks every request passes, then the operation.
    fn native_checked(&mut self, req: &Request<'_>, origin: &Origin) -> Result<Json, NativeError> {
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
            "endpoint.commit" => self.native_commit(req),
            "endpoint.abort" => self.native_abort(req),
            "endpoint.destroy" => self.native_destroy(req),
            "endpoint.query" => self.native_query(req),
            "endpoint.list" => Ok(self.native_list(req.tenant)),
            "endpoint.renew" => self.native_renew(req),
            "bridge.attach" => self.native_attach(req),
            "bridge.detach" => self.native_detach(req),
            "playback.start" => self.native_play(req, true),
            "playback.stop" => self.native_play(req, false),
            "recording.start" => self.native_record(req, true),
            "recording.stop" => self.native_record(req, false),
            "stream.start" => self.native_stream_start(req),
            "stream.flush" | "stream.stop" => self.native_stream(req),
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
            "server": format!("rtpflux {}", env!("CARGO_PKG_VERSION")),
            "operations": OPERATIONS,
            "events": EVENTS,
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
            "limits": {
                "retention_ms": RETENTION.as_millis(),
                "subscriber_queue": SUBSCRIBER_QUEUE,
                "max_endpoints": self.native.max_endpoints,
            },
        })
    }

    /// An endpoint's snapshot.
    fn endpoint_snapshot(ep: &Endpoint) -> Json {
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
        })
    }

    /// Publish `event` of type `ty` about endpoint `id`, with `data`.
    fn endpoint_event(&mut self, id: &str, ty: &str, operation_id: Option<&str>, data: Json) {
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

    fn native_create(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let max = self.native.max_endpoints;
        if max > 0
            && self
                .native
                .endpoints
                .values()
                .filter(|e| e.tenant == req.tenant)
                .count()
                >= max
        {
            return Err(NativeError::new(
                Code::Exhausted,
                format!("tenant {}: {max} endpoints already", req.tenant),
            ));
        }
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
        };
        self.native.endpoints.insert(id.clone(), ep);
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
    /// `endpoint.commit` (or taken back with `endpoint.abort`). A remote
    /// endpoint gives its remote side's new offer (`remote_sdp`) and gets
    /// the answer; a local one gets a new offer (`codecs`, `options`).
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
        let pending_revision = ep.revision + 1;
        let (r, warnings, previous_remote) = match ep.kind {
            Kind::RemoteOffer => {
                let sdp = req.need("remote_sdp")?;
                entries.push((b"sdp".to_vec(), bytes(sdp.as_bytes())));
                let (r, w) = self.ng_run(b"create from offer", entries)?;
                if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
                    e.remote_sdp = Some(sdp.as_bytes().to_vec());
                }
                (r, w, ep.remote_sdp.clone())
            }
            Kind::LocalOffer => {
                offer_codecs(req, &mut entries);
                // Kept as last agreed until the answer: an abort rolls
                // back to it.
                with_flag(&mut entries, b"track-state");
                let (r, w) = self.ng_run(b"create", entries)?;
                (r, w, None)
            }
        };
        let sdp = self.reply_sdp(&r).unwrap_or_default();
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.pending = Some(Pending {
                revision: pending_revision,
                previous_remote,
            });
        }
        Ok(json!({
            "pending_revision": pending_revision,
            "sdp_type": if ep.kind == Kind::RemoteOffer { "answer" } else { "offer" },
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
        if ep.kind == Kind::LocalOffer {
            let sdp = req.need("sdp")?;
            let mut entries = options(req)?;
            entries.push((b"call-id".to_vec(), bytes(ep.session.as_bytes())));
            entries.push((b"from-tag".to_vec(), bytes(ep.id.as_bytes())));
            entries.push((b"sdp".to_vec(), bytes(sdp.as_bytes())));
            // An answer that does not fit: still pending, abort takes it
            // back.
            warnings = self.ng_run(b"create answer", entries)?.1;
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
        let mut warnings = Vec::new();
        match ep.kind {
            Kind::LocalOffer => {
                let entries = vec![
                    (b"call-id".to_vec(), bytes(ep.session.as_bytes())),
                    (b"from-tag".to_vec(), bytes(ep.id.as_bytes())),
                    (
                        b"to-tag".to_vec(),
                        bytes(&[super::create::CREATOR, ep.id.as_bytes()].concat()),
                    ),
                ];
                warnings = self.ng_run(b"rollback", entries)?.1;
            }
            Kind::RemoteOffer => {
                // The offer agreed before, again: the same ports and keys.
                if let Some(sdp) = &p.previous_remote {
                    let entries = vec![
                        (b"call-id".to_vec(), bytes(ep.session.as_bytes())),
                        (b"from-tag".to_vec(), bytes(ep.id.as_bytes())),
                        (b"sdp".to_vec(), bytes(sdp)),
                    ];
                    warnings = self.ng_run(b"create from offer", entries)?.1;
                }
                if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
                    e.remote_sdp.clone_from(&p.previous_remote);
                }
            }
        }
        if let Some(e) = self.native.endpoints.get_mut(&ep.id) {
            e.pending = None;
        }
        Ok(json!({"revision": ep.revision, "warnings": warnings}))
    }

    /// End endpoint `id`'s media and forget it (a tombstone stays).
    fn destroy_endpoint(&mut self, id: &str, reason: &'static str, operation_id: Option<&str>) {
        let Some(ep) = self.native.endpoints.get(id).cloned() else {
            return;
        };
        if reason != "ended" {
            let entries = vec![
                (b"call-id".to_vec(), bytes(ep.session.as_bytes())),
                (b"from-tag".to_vec(), bytes(ep.id.as_bytes())),
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
        if a.id == b.id {
            return Err(NativeError::invalid("an endpoint bridged to itself"));
        }
        let entries = vec![
            (b"call-id".to_vec(), bytes(a.session.as_bytes())),
            (b"from-tag".to_vec(), bytes(a.id.as_bytes())),
            (b"to-call-id".to_vec(), bytes(b.session.as_bytes())),
            (b"to-tag".to_vec(), bytes(b.id.as_bytes())),
        ];
        let (_, warnings) = self.ng_run(b"connect", entries)?;
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
        let id = random_id("pb-");
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
        Ok(json!({"recording": start, "warnings": warnings}))
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
        };
        self.native.next_subscription += 1;
        let id = self.native.next_subscription;
        self.native.subscribers.push((
            origin.connection,
            Subscriber {
                id,
                tenant: req.tenant.to_owned(),
                filter,
                tx,
                missed: 0,
            },
        ));
        Ok(json!({"subscription_id": id, "global_seq": self.native.global_seq}))
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

    /// Hand the media events waiting to the subscribers.
    pub(super) fn native_media_events(&mut self) {
        let Some(inbox) = self.media_events.as_mut() else {
            return;
        };
        let (events, dropped) = inbox.take();
        if dropped > 0 {
            self.native.events_dropped += dropped;
            self.native
                .publish(json!({"event": "gap", "missed": dropped, "source": "media"}));
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
                json!({"reason": what, "detail": reason}),
            ),
            MediaEventKind::ActiveSpeaker { mixer } => {
                ("mixer.speaker", json!({"mixer_id": mixer}))
            }
            MediaEventKind::SpeechStarted => ("speech.started", json!({})),
            MediaEventKind::SpeechEnded => ("speech.ended", json!({})),
            MediaEventKind::StreamMark { stream, mark } => {
                ("stream.mark", json!({"stream_id": stream, "mark": mark}))
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
                json!({"file": file, "uploaded": uploaded}),
            ),
        };
        // Who it is about: an endpoint, or an `ng` party.
        let party = match &e.subject {
            Subject::Leg(call, leg) => self.party_on_leg(*call, *leg),
            // A call's: its first party that is not a hidden side.
            Subject::Call(call) => self
                .party_on_leg(*call, CallLeg::A)
                .or_else(|| self.party_on_leg(*call, CallLeg::B)),
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
            self.endpoint_event(&id, ty, None, data);
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
        if self.relay.applied(&calls, Duration::from_secs(1)) {
            Ok(())
        } else {
            Err(NativeError::new(
                Code::Timeout,
                "the media workers did not confirm the change in time",
            ))
        }
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
                previous_remote_sdp: e.pending.as_ref().and_then(|p| text(&p.previous_remote)),
                bridged_to: e.bridged_to.clone(),
                label: e.label.clone(),
                lease_ms: e.lease.map(|l| l.0),
                remote_sdp: text(&e.remote_sdp),
                created_unix_ms: e.created_unix_ms,
            })
            .collect();
        v.sort_by_key(|e| e.generation);
        v
    }

    /// The saved endpoints back, those whose media came back; the others
    /// are gone (a tombstone each).
    pub(super) fn restore_endpoints(&mut self, saved: &[crate::state::SavedEndpoint]) {
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
                }),
                bridged_to: e.bridged_to.clone(),
                label: e.label.clone(),
                lease: e
                    .lease_ms
                    .map(|ms| (ms, Instant::now() + Duration::from_millis(ms))),
                seq: 0,
                remote_sdp: e.remote_sdp.as_ref().map(|s| s.as_bytes().to_vec()),
                playback: None,
                created_unix_ms: e.created_unix_ms,
            };
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
        let Some(dir) = self.native.pcm_dir.clone() else {
            return Err(NativeError::new(
                Code::Unsupported,
                "PCM streams are not configured ([control] pcm_dir)",
            ));
        };
        let name = req.need("socket")?;
        if !valid_name(name) || name.contains('/') || name.starts_with('.') {
            return Err(NativeError::invalid("socket: a file name in pcm_dir"));
        }
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
        let want_inject = req
            .body
            .get("inject")
            .and_then(Json::as_bool)
            .unwrap_or(true);
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
            socket: dir.join(name),
            rate,
            pt,
            codec,
            clock,
            inject,
            events: self.relay.media_event_sender(),
            subject: Subject::Leg(leg.0, leg.1),
        };
        let (end, handle) = crate::pcm::stream::start(&spec)
            .map_err(|e| NativeError::new(Code::Invalid, format!("socket {name}: {e}")))?;
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
        Ok(json!({"stream_id": id, "rate": rate, "inject": inject.is_some()}))
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
