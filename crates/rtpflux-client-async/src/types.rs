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
}

/// An event's type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    EndpointReady,
    EndpointFailed,
    EndpointTimeout,
    EndpointDestroyed,
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

    /// A gap the client itself reports (`reason`), with `missed` events.
    pub(crate) fn gap(reason: &str, missed: u64) -> Self {
        MediaEvent {
            kind: EventKind::Gap,
            endpoint_id: None,
            session_id: None,
            generation: None,
            seq: None,
            global_seq: None,
            time_unix_ms: None,
            operation_id: None,
            data: serde_json::json!({"event": "gap", "reason": reason, "missed": missed}),
        }
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
}
