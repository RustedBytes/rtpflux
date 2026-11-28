//! An async (Tokio) client of rtpflux's native control API, for a
//! softswitch's call control (see `docs/native-api.md`).
//!
//! ```no_run
//! use rtpflux_client_async::{
//!     AttachBridgeRequest, Config, CreateEndpointRequest, DestroyEndpointRequest,
//!     EventFilter, MediaClient,
//! };
//!
//! # async fn call(offer: String, answer: String) -> Result<(), rtpflux_client_async::MediaError> {
//! let media = MediaClient::connect(Config::unix("/run/rtpflux/native.sock")).await?;
//! let mut events = media.subscribe_events(EventFilter::default()).await?;
//! let mut inbound = CreateEndpointRequest::answering(offer);
//! inbound.idempotency_key = Some("call-42/a".into());
//! let a = media.create_endpoint(inbound).await?;        // a.sdp: the 200 OK's answer
//! let b = media.create_endpoint(CreateEndpointRequest::offering(["PCMU", "opus"])).await?;
//! // … INVITE the callee with b.sdp, then:
//! media.apply_answer(rtpflux_client_async::ApplyAnswerRequest {
//!     endpoint_id: b.endpoint_id.clone(), sdp: answer,
//!     expected_generation: Some(b.generation), options: None, deadline: None,
//! }).await?;
//! media.attach_bridge(AttachBridgeRequest::new(&a.endpoint_id, &b.endpoint_id)).await?;
//! while let Some(e) = events.next().await {
//!     if let Some((digit, _, _)) = e.dtmf() { println!("pressed {digit}"); }
//! #   break;
//! }
//! media.destroy_endpoint(DestroyEndpointRequest::new(&a.endpoint_id)).await?;
//! # Ok(()) }
//! ```
//!
//! # Semantics
//!
//! - **Bounded.** Each request connection has a bounded queue
//!   ([`Config::queue_per_connection`]) and a bound on the requests written
//!   but not answered ([`Config::in_flight_per_connection`]). When every
//!   queue is full a request fails at once with [`MediaError::Overloaded`]:
//!   nothing waits without bound.
//! - **Deadlines.** Every request has one (its own, or
//!   [`Config::default_deadline`]). It is sent too (`deadline_unix_ms`), so
//!   the relay does not run a request that arrives late. Past it, the
//!   request fails with [`MediaError::Timeout`].
//! - **Cancellation.** Dropping a request's future cancels it: if it was not
//!   written yet it never is; if it was, the relay may still run it (its
//!   reply is ignored). [`MediaError::outcome_unknown`] says when a failed
//!   request may have taken effect; retry it with the same
//!   `idempotency_key` (the relay gives the first attempt's outcome) or
//!   reconcile with `endpoint.query`/`endpoint.list`.
//! - **Reconnect.** A connection that breaks is made again with exponential
//!   backoff ([`Config::backoff_min`], [`Config::backoff_max`]), and
//!   authenticated again over TCP; the requests it had written fail with
//!   [`MediaError::Disconnected`] (`sent: true`), those still queued wait
//!   for the new connection (within their deadlines).
//! - **Events** come on a connection of their own
//!   ([`MediaClient::subscribe_events`]), each once, in order, resumed from
//!   the stream's position after a reconnect or an overflow; see
//!   [`MediaEventStream`].
//! - **Ordering.** Requests are spread over the pool's connections, and
//!   requests on different connections may be run in any order. Each
//!   connection's requests run in order. A request that depends on another
//!   (an attach on a create) must wait for that one's reply; that is the
//!   only ordering the client guarantees.
//! - **Correlation.** Operation ids are a per-client random prefix and a
//!   counter: unique across reconnects, so a late reply is never taken for
//!   another request's. The client never retries on its own; retry with
//!   the same `idempotency_key` when [`MediaError::outcome_unknown`] says
//!   to.
//! - **Reconciliation.** [`MediaClient::hello`] (capabilities, guarantees,
//!   boot id), [`MediaClient::inventory_all`] (a consistent snapshot and
//!   its [`Watermark`]: subscribe from [`Watermark::cursor`] to miss
//!   nothing after it), [`MediaClient::operation`],
//!   [`MediaClient::lookup`] (by external id), [`MediaClient::renew`],
//!   [`MediaClient::recovery_report`]. Unknown fields and values are kept
//!   (`extra`, `Other`): a newer relay does not break the client.

#![forbid(unsafe_code)]

mod config;
mod conn;
mod error;
mod events;
mod types;

pub use config::{Config, Transport};
pub use error::{ErrorCode, MediaError};
pub use events::MediaEventStream;
pub use types::{
    ApplyAnswerRequest, AttachBridgeRequest, BridgeResult, Capabilities, CreateEndpointRequest,
    DestroyEndpointRequest, Endpoint, EventFilter, EventKind, Guarantees, InventoryPage,
    MediaEvent, Negotiation, OperationState, OperationStatus, PlaybackState, PlaybackStatus,
    PrepareRequest, Prepared, RecoveryReport, Watermark,
};

use conn::Job;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// A client: cheap to clone (the clones share the connections). The
/// connections end when the last clone is dropped.
#[derive(Debug, Clone)]
pub struct MediaClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: Arc<Config>,
    pool: Vec<mpsc::Sender<Job>>,
    next: AtomicUsize,
    ids: AtomicU64,
    /// Operation ids are this and a counter: unique per client.
    prefix: String,
}

/// Milliseconds since the Unix epoch.
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A prefix for operation ids, unlikely to repeat (process, time, address).
fn prefix() -> String {
    use std::hash::{BuildHasher, RandomState};
    let h = RandomState::new().hash_one((std::process::id(), unix_ms()));
    format!("op-{h:016x}-")
}

/// `request`'s fields as a JSON object.
fn fields<T: Serialize>(request: &T) -> Result<Map<String, Value>, MediaError> {
    match serde_json::to_value(request) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Ok(Map::new()),
        Err(e) => Err(MediaError::Protocol(e.to_string())),
    }
}

/// A result, typed.
fn typed<T: DeserializeOwned>(v: Value) -> Result<T, MediaError> {
    serde_json::from_value(v).map_err(|e| MediaError::Protocol(e.to_string()))
}

impl MediaClient {
    /// Start the client's connections, and check that the relay answers
    /// (`hello`) within [`Config::connect_timeout`].
    ///
    /// # Errors
    ///
    /// When the relay does not answer, or refuses (a bad token).
    pub async fn connect(config: Config) -> Result<Self, MediaError> {
        let config = Arc::new(config);
        let pool = (0..config.connections.max(1))
            .map(|_| {
                let (tx, rx) = mpsc::channel(config.queue_per_connection.max(1));
                conn::spawn(Arc::clone(&config), rx);
                tx
            })
            .collect();
        let client = MediaClient {
            inner: Arc::new(Inner {
                config: Arc::clone(&config),
                pool,
                next: AtomicUsize::new(0),
                ids: AtomicU64::new(0),
                prefix: prefix(),
            }),
        };
        // Fail early on a relay that is not there or refuses the token.
        conn::open(&config).await?;
        client
            .call("hello", Map::new(), Some(config.connect_timeout))
            .await?;
        Ok(client)
    }

    /// Run operation `op` with `fields`, within `deadline` (else the
    /// default): its `result`.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn call(
        &self,
        op: &str,
        mut fields: Map<String, Value>,
        deadline: Option<Duration>,
    ) -> Result<Value, MediaError> {
        let inner = &self.inner;
        let wait = deadline.unwrap_or(inner.config.default_deadline);
        let id = format!(
            "{}{}",
            inner.prefix,
            inner.ids.fetch_add(1, Ordering::Relaxed)
        );
        fields.insert("v".into(), json!(1));
        fields.insert("op".into(), json!(op));
        fields.insert("operation_id".into(), json!(id));
        let ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        fields.insert(
            "deadline_unix_ms".into(),
            json!(unix_ms().saturating_add(ms)),
        );
        if let (Some(t), Transport::Unix(_)) = (&inner.config.tenant, &inner.config.transport) {
            fields.entry("tenant").or_insert_with(|| json!(t));
        }
        let (reply, answer) = oneshot::channel();
        let sent = Arc::new(AtomicBool::new(false));
        let mut job = Job {
            operation_id: id,
            body: Value::Object(fields).to_string().into_bytes(),
            deadline: tokio::time::Instant::now() + wait,
            sent: Arc::clone(&sent),
            reply,
        };
        // A connection with room in its queue, from the next one round.
        let n = inner.pool.len();
        let start = inner.next.fetch_add(1, Ordering::Relaxed);
        let mut queued = false;
        for k in 0..n {
            let Some(tx) = inner.pool.get((start + k) % n) else {
                continue;
            };
            match tx.try_send(job) {
                Ok(()) => {
                    queued = true;
                    break;
                }
                Err(mpsc::error::TrySendError::Full(j)) => job = j,
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(MediaError::Closed),
            }
        }
        if !queued {
            return Err(MediaError::Overloaded);
        }
        match tokio::time::timeout(wait, answer).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(MediaError::Disconnected {
                sent: sent.load(Ordering::Acquire),
            }),
            Err(_) => Err(MediaError::Timeout {
                sent: sent.load(Ordering::Acquire),
            }),
        }
    }

    /// `endpoint.create`: an endpoint answering a remote offer, or making
    /// the relay's own.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn create_endpoint(
        &self,
        request: CreateEndpointRequest,
    ) -> Result<Endpoint, MediaError> {
        let mut f = fields(&request)?;
        match &request.negotiation {
            Negotiation::RemoteOffer { sdp } => {
                f.insert("remote_sdp".into(), json!(sdp));
            }
            Negotiation::LocalOffer { codecs } => {
                f.insert("codecs".into(), json!(codecs));
            }
        }
        typed(self.call("endpoint.create", f, request.deadline).await?)
    }

    /// `endpoint.apply_answer`: the remote side's answer to the relay's
    /// offer.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn apply_answer(&self, request: ApplyAnswerRequest) -> Result<(), MediaError> {
        self.call("endpoint.apply_answer", fields(&request)?, request.deadline)
            .await
            .map(drop)
    }

    /// `bridge.attach`: in effect on the media workers when it returns.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn attach_bridge(
        &self,
        request: AttachBridgeRequest,
    ) -> Result<BridgeResult, MediaError> {
        typed(
            self.call("bridge.attach", fields(&request)?, request.deadline)
                .await?,
        )
    }

    /// `bridge.detach` of `endpoint_id`: whether it was bridged.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn detach_bridge(
        &self,
        endpoint_id: &str,
        deadline: Option<Duration>,
    ) -> Result<bool, MediaError> {
        let mut f = Map::new();
        f.insert("endpoint_id".into(), json!(endpoint_id));
        let r = self.call("bridge.detach", f, deadline).await?;
        Ok(r.get("detached").and_then(Value::as_bool).unwrap_or(false))
    }

    /// `endpoint.destroy`. An endpoint destroyed already is a success.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn destroy_endpoint(
        &self,
        request: DestroyEndpointRequest,
    ) -> Result<(), MediaError> {
        self.call("endpoint.destroy", fields(&request)?, request.deadline)
            .await
            .map(drop)
    }

    /// `endpoint.prepare`: a renegotiation, until `commit` or `abort`.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn prepare(&self, request: PrepareRequest) -> Result<Prepared, MediaError> {
        typed(
            self.call("endpoint.prepare", fields(&request)?, request.deadline)
                .await?,
        )
    }

    /// `endpoint.commit` of the pending `revision` (with the remote side's
    /// answer, for a local endpoint): the new revision.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn commit(
        &self,
        endpoint_id: &str,
        revision: u64,
        answer_sdp: Option<&str>,
        deadline: Option<Duration>,
    ) -> Result<u64, MediaError> {
        let mut f = Map::new();
        f.insert("endpoint_id".into(), json!(endpoint_id));
        f.insert("revision".into(), json!(revision));
        if let Some(sdp) = answer_sdp {
            f.insert("sdp".into(), json!(sdp));
        }
        let r = self.call("endpoint.commit", f, deadline).await?;
        r.get("revision")
            .and_then(Value::as_u64)
            .ok_or_else(|| MediaError::Protocol(format!("{r}")))
    }

    /// `endpoint.abort` of the pending `revision`: the committed revision.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn abort(
        &self,
        endpoint_id: &str,
        revision: u64,
        deadline: Option<Duration>,
    ) -> Result<u64, MediaError> {
        let mut f = Map::new();
        f.insert("endpoint_id".into(), json!(endpoint_id));
        f.insert("revision".into(), json!(revision));
        let r = self.call("endpoint.abort", f, deadline).await?;
        r.get("revision")
            .and_then(Value::as_u64)
            .ok_or_else(|| MediaError::Protocol(format!("{r}")))
    }

    /// `endpoint.query`: the endpoint's snapshot (and its media), as JSON.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn query_endpoint(
        &self,
        endpoint_id: &str,
        deadline: Option<Duration>,
    ) -> Result<Value, MediaError> {
        let mut f = Map::new();
        f.insert("endpoint_id".into(), json!(endpoint_id));
        self.call("endpoint.query", f, deadline).await
    }

    /// `endpoint.list`: every endpoint's snapshot, the recent tombstones and
    /// the current `global_seq` (to reconcile after a gap).
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn list_endpoints(&self, deadline: Option<Duration>) -> Result<Value, MediaError> {
        self.call("endpoint.list", Map::new(), deadline).await
    }

    /// `hello`: what the relay has (operations, events, codecs, …) and
    /// guarantees, and its run's boot id.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn hello(&self) -> Result<Capabilities, MediaError> {
        typed(self.call("hello", Map::new(), None).await?)
    }

    /// One page of the inventory of `kind` (`endpoints`, `bridges`,
    /// `streams`, `mixers`, `playbacks`, `recordings`), from `cursor`.
    ///
    /// # Errors
    ///
    /// See [`MediaError`]; a `conflict` when the inventory changed since
    /// the cursor's page.
    pub async fn inventory(
        &self,
        kind: &str,
        cursor: Option<&str>,
        limit: Option<u64>,
    ) -> Result<InventoryPage, MediaError> {
        let mut f = Map::new();
        f.insert("kind".into(), json!(kind));
        if let Some(c) = cursor {
            f.insert("cursor".into(), json!(c));
        }
        if let Some(l) = limit {
            f.insert("limit".into(), json!(l));
        }
        typed(self.call("inventory.list", f, None).await?)
    }

    /// The whole inventory of `kind`, as one consistent state, and its
    /// watermark (subscribe from [`Watermark::cursor`] to miss nothing
    /// after it). A walk the inventory changed under is started again, at
    /// most `attempts` times.
    ///
    /// # Errors
    ///
    /// See [`MediaError`]; the last `conflict` when every attempt raced a
    /// change.
    pub async fn inventory_all(
        &self,
        kind: &str,
        attempts: usize,
    ) -> Result<(Vec<Value>, Watermark), MediaError> {
        let mut last = MediaError::Protocol("no attempt".into());
        'walk: for _ in 0..attempts.max(1) {
            let mut items = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                match self.inventory(kind, cursor.as_deref(), Some(500)).await {
                    Ok(page) => {
                        items.extend(page.items);
                        match page.next_cursor {
                            Some(c) => cursor = Some(c),
                            None => return Ok((items, page.watermark)),
                        }
                    }
                    Err(e) if e.code() == Some(&ErrorCode::Conflict) => {
                        last = e;
                        continue 'walk;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Err(last)
    }

    /// `operation.query`: what became of the operation keyed `key` (pass
    /// when it was first attempted to tell an expired key from an unknown
    /// one).
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn operation(
        &self,
        key: &str,
        first_attempt_unix_ms: Option<u64>,
    ) -> Result<OperationStatus, MediaError> {
        let mut f = Map::new();
        f.insert("idempotency_key".into(), json!(key));
        if let Some(t) = first_attempt_unix_ms {
            f.insert("first_attempt_unix_ms".into(), json!(t));
        }
        let v = self.call("operation.query", f, None).await?;
        Ok(OperationStatus::from_wire(&v))
    }

    /// `endpoint.lookup`: the endpoint an external id names, live or
    /// destroyed (`state_of_id`).
    ///
    /// # Errors
    ///
    /// See [`MediaError`]; `not_found` when nothing has it.
    pub async fn lookup(&self, external_id: &str) -> Result<Value, MediaError> {
        let mut f = Map::new();
        f.insert("external_id".into(), json!(external_id));
        self.call("endpoint.lookup", f, None).await
    }

    /// `endpoint.renew`: the endpoint's lease again, for `lease` (or its
    /// own length).
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn renew(
        &self,
        endpoint_id: &str,
        lease: Option<Duration>,
    ) -> Result<(), MediaError> {
        let mut f = Map::new();
        f.insert("endpoint_id".into(), json!(endpoint_id));
        if let Some(l) = lease {
            f.insert(
                "lease_ms".into(),
                json!(u64::try_from(l.as_millis()).unwrap_or(u64::MAX)),
            );
        }
        self.call("endpoint.renew", f, None).await.map(drop)
    }

    /// `playback.query`: where playback `playback_id` is, or how it
    /// ended (the relay keeps the latest 8192 ends, until it restarts).
    ///
    /// # Errors
    ///
    /// See [`MediaError`]; `not_found` when the relay no longer knows it.
    pub async fn playback(&self, playback_id: &str) -> Result<PlaybackStatus, MediaError> {
        let mut f = Map::new();
        f.insert("playback_id".into(), json!(playback_id));
        typed(self.call("playback.query", f, None).await?)
    }

    /// `recovery.report`: what the relay's last restart brought back and
    /// lost, and the operations whose outcome is unknown.
    ///
    /// # Errors
    ///
    /// See [`MediaError`].
    pub async fn recovery_report(&self) -> Result<RecoveryReport, MediaError> {
        typed(self.call("recovery.report", Map::new(), None).await?)
    }

    /// Subscribe to events matching `filter`, on a connection of its own.
    /// The subscription is live when this returns.
    ///
    /// # Errors
    ///
    /// When the subscription cannot be made.
    pub async fn subscribe_events(
        &self,
        filter: EventFilter,
    ) -> Result<MediaEventStream, MediaError> {
        events::start(Arc::clone(&self.inner.config), filter).await
    }
}
