//! Typed requests and replies of the native API (`docs/native-api.md`).
//! Requests serialize to the wire's fields; a request's `deadline` (and
//! the operation, set by the client) are not among them.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::time::Duration;

/// How an endpoint is first negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiation {
    /// The remote side offered: the relay answers this SDP.
    RemoteOffer { sdp: String },
    /// The relay offers these codecs (`PCMU`, `opus`, …); the remote side
    /// answers ([`MediaClient::apply_answer`](crate::MediaClient::apply_answer)).
    LocalOffer { codecs: Vec<String> },
}

/// `endpoint.create`.
#[derive(Debug, Clone, Serialize)]
pub struct CreateEndpointRequest {
    #[serde(skip)]
    pub negotiation: Negotiation,
    /// The media session (an `ng` call) to put it in; made up when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Destroyed unless renewed within this (milliseconds on the wire).
    #[serde(skip_serializing_if = "Option::is_none", rename = "lease_ms")]
    pub lease_ms: Option<u64>,
    /// `ng` options (`{"ICE": "remove", "flags": ["trust-address"]}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Map<String, Value>>,
    /// Set it (a call's UUID and leg, say) to retry safely: a retry gets
    /// the first attempt's outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip)]
    pub deadline: Option<Duration>,
}

impl CreateEndpointRequest {
    /// An endpoint answering the remote side's offer `sdp`.
    #[must_use]
    pub fn answering(sdp: impl Into<String>) -> Self {
        Self::with(Negotiation::RemoteOffer { sdp: sdp.into() })
    }

    /// An endpoint offering `codecs`.
    #[must_use]
    pub fn offering<S: Into<String>>(codecs: impl IntoIterator<Item = S>) -> Self {
        Self::with(Negotiation::LocalOffer {
            codecs: codecs.into_iter().map(Into::into).collect(),
        })
    }

    fn with(negotiation: Negotiation) -> Self {
        CreateEndpointRequest {
            negotiation,
            session_id: None,
            label: None,
            lease_ms: None,
            options: None,
            idempotency_key: None,
            deadline: None,
        }
    }
}

/// What an endpoint is (`endpoint.create`'s reply).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Endpoint {
    pub endpoint_id: String,
    pub session_id: String,
    pub generation: u64,
    pub revision: u64,
    /// `offered` or `ready`.
    pub state: String,
    /// `offer` or `answer`: what `sdp` is.
    pub sdp_type: String,
    pub sdp: String,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// `endpoint.apply_answer`.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyAnswerRequest {
    pub endpoint_id: String,
    pub sdp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Map<String, Value>>,
    #[serde(skip)]
    pub deadline: Option<Duration>,
}

/// `bridge.attach`.
#[derive(Debug, Clone, Serialize)]
pub struct AttachBridgeRequest {
    pub endpoint_id: String,
    pub peer_endpoint_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_expected_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip)]
    pub deadline: Option<Duration>,
}

impl AttachBridgeRequest {
    /// Bridge `a` and `b`.
    #[must_use]
    pub fn new(a: impl Into<String>, b: impl Into<String>) -> Self {
        AttachBridgeRequest {
            endpoint_id: a.into(),
            peer_endpoint_id: b.into(),
            expected_generation: None,
            peer_expected_generation: None,
            idempotency_key: None,
            deadline: None,
        }
    }
}

/// `bridge.attach`'s reply: in effect on the media workers when it comes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BridgeResult {
    pub endpoint_id: String,
    pub bridged_to: String,
    /// The former peers of the two, now alone.
    #[serde(default)]
    pub replaced: Vec<Option<String>>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// `endpoint.destroy`. Destroying an endpoint already destroyed succeeds.
#[derive(Debug, Clone, Serialize)]
pub struct DestroyEndpointRequest {
    pub endpoint_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
    #[serde(skip)]
    pub deadline: Option<Duration>,
}

impl DestroyEndpointRequest {
    /// Destroy `endpoint_id`.
    #[must_use]
    pub fn new(endpoint_id: impl Into<String>) -> Self {
        DestroyEndpointRequest {
            endpoint_id: endpoint_id.into(),
            expected_generation: None,
            deadline: None,
        }
    }
}

/// `endpoint.prepare`: a renegotiation, committed or aborted later.
#[derive(Debug, Clone, Serialize)]
pub struct PrepareRequest {
    pub endpoint_id: String,
    /// A remote endpoint's new offer (its re-INVITE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_sdp: Option<String>,
    /// A local endpoint's new codecs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codecs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Map<String, Value>>,
    #[serde(skip)]
    pub deadline: Option<Duration>,
}

/// `endpoint.prepare`'s reply.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Prepared {
    pub pending_revision: u64,
    pub sdp_type: String,
    pub sdp: String,
}

/// What to filter events by (all optional).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EventFilter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoint_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub session_ids: Vec<String>,
    /// Events of `ng` parties too.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub all_parties: bool,
    /// Digits the endpoint marked sensitive (`endpoint.sensitive`) as
    /// they are, not redacted: for the controller collecting them. Other
    /// subscribers, and the logs, never see them.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
    /// Begin after this cursor (an event's `event_id`, a subscription's
    /// `cursor`, an inventory page's watermark): what came after it is
    /// replayed first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// An event's type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    EndpointReady,
    EndpointFailed,
    EndpointTimeout,
    EndpointDestroyed,
    /// Some of the endpoint's media events were lost before the relay's
    /// journal: what it awaited (digits, an announcement's end) is
    /// indeterminate.
    EndpointEventsLost,
    BridgeChanged,
    IceConnected,
    DtlsReady,
    DtmfDetected,
    PlaybackCompleted,
    PlaybackStopped,
    RecordingCompleted,
    RecordingFailed,
    SpeechStarted,
    SpeechEnded,
    StreamMark,
    /// A PCM stream was flushed: a new generation begins.
    StreamFlushed,
    StreamEnded,
    MixerSpeaker,
    /// Events were missed (`missed` in the data, or `reason:
    /// "reconnected"` after the event connection was made again):
    /// reconcile with `endpoint.list`.
    Gap,
    Other(String),
}

impl EventKind {
    /// The kind named `s` on the wire.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "endpoint.ready" => EventKind::EndpointReady,
            "endpoint.failed" => EventKind::EndpointFailed,
            "endpoint.timeout" => EventKind::EndpointTimeout,
            "endpoint.destroyed" => EventKind::EndpointDestroyed,
            "endpoint.events_lost" => EventKind::EndpointEventsLost,
            "bridge.changed" => EventKind::BridgeChanged,
            "ice.connected" => EventKind::IceConnected,
            "dtls.ready" => EventKind::DtlsReady,
            "dtmf.detected" => EventKind::DtmfDetected,
            "playback.completed" => EventKind::PlaybackCompleted,
            "playback.stopped" => EventKind::PlaybackStopped,
            "recording.completed" => EventKind::RecordingCompleted,
            "recording.failed" => EventKind::RecordingFailed,
            "speech.started" => EventKind::SpeechStarted,
            "speech.ended" => EventKind::SpeechEnded,
            "stream.mark" => EventKind::StreamMark,
            "stream.flushed" => EventKind::StreamFlushed,
            "stream.ended" => EventKind::StreamEnded,
            "mixer.speaker" => EventKind::MixerSpeaker,
            "gap" => EventKind::Gap,
            other => EventKind::Other(other.to_owned()),
        }
    }
}

/// An event.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaEvent {
    pub kind: EventKind,
    /// `<boot_id>:<global_seq>`: unique, and a cursor to resume after it.
    pub event_id: Option<String>,
    /// The run of the relay that gave it.
    pub boot_id: Option<String>,
    /// The endpoint it is about (`None` for an `ng` party's, or a gap).
    pub endpoint_id: Option<String>,
    pub session_id: Option<String>,
    pub generation: Option<u64>,
    /// Per endpoint, and across all events: a jump is a gap.
    pub seq: Option<u64>,
    pub global_seq: Option<u64>,
    pub time_unix_ms: Option<u64>,
    /// The operation that caused it, if any.
    pub operation_id: Option<String>,
    /// The event's own fields (`digit`, `reason`, …).
    pub data: Value,
}

impl MediaEvent {
    /// The event in the message `v` (it has `event`).
    #[must_use]
    pub fn from_wire(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let n = |k: &str| v.get(k).and_then(Value::as_u64);
        let kind = EventKind::parse(v.get("event")?.as_str()?);
        // A gap's fields are its data.
        let data = if kind == EventKind::Gap {
            v.clone()
        } else {
            v.get("data").cloned().unwrap_or(Value::Null)
        };
        Some(MediaEvent {
            kind,
            event_id: s("event_id"),
            boot_id: s("boot_id"),
            endpoint_id: s("endpoint_id"),
            session_id: s("session_id"),
            generation: n("generation"),
            seq: n("seq"),
            global_seq: n("global_seq"),
            time_unix_ms: n("time_unix_ms"),
            operation_id: s("operation_id"),
            data,
        })
    }

    /// A key press, if this is one: its digit, how long it was held, and
    /// whether it was found in the audio (in-band).
    #[must_use]
    pub fn dtmf(&self) -> Option<(char, u64, bool)> {
        if self.kind != EventKind::DtmfDetected {
            return None;
        }
        let digit = self.data.get("digit")?.as_str()?.chars().next()?;
        let ms = self.data.get("duration_ms")?.as_u64()?;
        let inband = self.data.get("source").and_then(Value::as_str) == Some("inband");
        Some((digit, ms, inband))
    }
}

/// What the relay says of itself (`hello`). Unknown fields are kept in
/// `extra`, so a newer relay's are not lost.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub versions: Vec<u64>,
    #[serde(default)]
    pub boot_id: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub guarantees: Guarantees,
    #[serde(default)]
    pub capabilities: Value,
    #[serde(default)]
    pub limits: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Capabilities {
    /// Whether the relay has operation `op`.
    #[must_use]
    pub fn supports(&self, op: &str) -> bool {
        self.operations.iter().any(|o| o == op)
    }
}

/// What the relay guarantees (`hello`'s `guarantees`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Guarantees {
    /// `durable` (an operation ledger on disk) or `memory`.
    #[serde(default)]
    pub idempotency: Option<String>,
    #[serde(default)]
    pub idempotency_retention_ms: Option<u64>,
    /// `synced_before_reply` (keyed mutations, durable mode) or `periodic`.
    #[serde(default)]
    pub state_commit: Option<String>,
    /// `replayable_within_journal`.
    #[serde(default)]
    pub events: Option<String>,
    #[serde(default)]
    pub event_journal: Option<u64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Where an inventory page was taken: a cursor to subscribe from
/// ([`Watermark::cursor`]) without missing anything after it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Watermark {
    pub boot_id: String,
    pub global_seq: u64,
    pub topology_epoch: u64,
}

impl Watermark {
    /// The events cursor at this watermark.
    #[must_use]
    pub fn cursor(&self) -> String {
        format!("{}:{}", self.boot_id, self.global_seq)
    }
}

/// A page of the inventory.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct InventoryPage {
    pub kind: String,
    pub items: Vec<Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    pub total: u64,
    pub watermark: Watermark,
}

/// What became of an operation (`operation.query`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationState {
    Pending,
    Applied,
    Failed,
    /// Begun before a restart, its outcome never recorded.
    Unknown,
    /// Older than the relay's ledger keeps.
    Expired,
    /// Not known to the ledger.
    NotFound,
    Other(String),
}

/// Where a playback is, or how it ended.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlaybackState {
    Playing,
    Queued,
    Completed,
    Stopped,
    #[serde(other)]
    Other,
}

/// `playback.query`'s answer: for a playback whose end event was missed
/// (across a reconnect).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PlaybackStatus {
    pub playback_id: String,
    pub state: PlaybackState,
    pub endpoint_id: String,
    #[serde(default)]
    pub generation: Option<u64>,
    /// Why it stopped (`request`, `replaced`, `dtmf`, `speech`,
    /// `interrupted`, `failed`, `endpoint_destroyed`).
    #[serde(default)]
    pub reason: Option<String>,
    /// Its place in the queue (1 is next).
    #[serde(default)]
    pub position: Option<u64>,
    /// It ended while still queued (it never played).
    #[serde(default)]
    pub queued: bool,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub ended_unix_ms: Option<u64>,
}

/// `operation.query`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationStatus {
    pub state: OperationState,
    pub op: Option<String>,
    pub resources: Vec<String>,
    /// The reply the operation got (applied or failed).
    pub reply: Option<Value>,
    pub durable: bool,
}

impl OperationStatus {
    pub(crate) fn from_wire(v: &Value) -> Self {
        let state = match v.get("status").and_then(Value::as_str).unwrap_or("") {
            "pending" => OperationState::Pending,
            "applied" => OperationState::Applied,
            "failed" => OperationState::Failed,
            "unknown" => OperationState::Unknown,
            "expired" => OperationState::Expired,
            "not_found" => OperationState::NotFound,
            other => OperationState::Other(other.to_owned()),
        };
        OperationStatus {
            state,
            op: v.get("op").and_then(Value::as_str).map(str::to_owned),
            resources: v
                .get("resources")
                .and_then(Value::as_array)
                .map_or_else(Vec::new, |a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                }),
            reply: v.get("reply").cloned().filter(|r| !r.is_null()),
            durable: v.get("durable").and_then(Value::as_bool).unwrap_or(false),
        }
    }
}

/// `recovery.report`'s answer.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RecoveryReport {
    pub boot_id: String,
    #[serde(default)]
    pub previous_boot_id: Option<String>,
    #[serde(default)]
    pub restored_endpoints: Vec<String>,
    /// What the restart could not bring back (`kind`, ids, `reason`).
    #[serde(default)]
    pub lost: Vec<Value>,
    /// Operations whose outcome is unknown (`idempotency_key`, `op`,
    /// `resources`).
    #[serde(default)]
    pub unknown_operations: Vec<Value>,
    #[serde(default)]
    pub durable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_serialize_to_the_wire_fields() {
        let mut r = CreateEndpointRequest::answering("v=0");
        r.deadline = Some(Duration::from_secs(1));
        r.idempotency_key = Some("k".into());
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v, serde_json::json!({"idempotency_key": "k"}));
        let b = serde_json::to_value(AttachBridgeRequest::new("a", "b")).unwrap();
        assert_eq!(
            b,
            serde_json::json!({"endpoint_id": "a", "peer_endpoint_id": "b"})
        );
        let f = serde_json::to_value(EventFilter::default()).unwrap();
        assert_eq!(f, serde_json::json!({}));
    }

    #[test]
    fn events_parse() {
        let v = serde_json::json!({"event": "dtmf.detected", "endpoint_id": "ep-1", "seq": 3,
            "global_seq": 9, "data": {"digit": "5", "duration_ms": 150, "source": "inband"}});
        let e = MediaEvent::from_wire(&v).unwrap();
        assert_eq!(e.kind, EventKind::DtmfDetected);
        assert_eq!(e.dtmf(), Some(('5', 150, true)));
        assert_eq!((e.seq, e.global_seq), (Some(3), Some(9)));
        let g = MediaEvent::from_wire(&serde_json::json!({"event": "gap", "missed": 4})).unwrap();
        assert_eq!(g.kind, EventKind::Gap);
        assert_eq!(g.data["missed"], 4);
        assert!(MediaEvent::from_wire(&serde_json::json!({"ok": true})).is_none());
        assert_eq!(EventKind::parse("x.y"), EventKind::Other("x.y".into()));
    }

    #[test]
    fn sensitive_filter_and_playback_status() {
        let f = EventFilter {
            sensitive: true,
            ..EventFilter::default()
        };
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            serde_json::json!({"sensitive": true})
        );
        assert_eq!(
            serde_json::to_value(EventFilter::default()).unwrap(),
            serde_json::json!({}),
            "left out unless asked"
        );
        let p: PlaybackStatus = serde_json::from_value(serde_json::json!({
            "playback_id": "pb-1", "state": "stopped", "endpoint_id": "e",
            "generation": 3, "reason": "endpoint_destroyed", "queued": true,
            "operation_id": null, "ended_unix_ms": 5}))
        .unwrap();
        assert_eq!(
            (p.state, p.reason.as_deref(), p.queued),
            (PlaybackState::Stopped, Some("endpoint_destroyed"), true)
        );
        let q: PlaybackStatus = serde_json::from_value(serde_json::json!({
            "playback_id": "pb-2", "state": "paused", "endpoint_id": "e"}))
        .unwrap();
        assert_eq!(q.state, PlaybackState::Other, "a later state");
    }
}
