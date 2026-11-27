//! IVR primitives of the native API. The digit collection policies and
//! timeouts belong to the controller; this module gives it the pieces:
//! - `dtmf.send`: keys to the endpoint, as RFC 4733 events or in-band
//!   tones;
//! - `tone.start` and `tone.stop`: a tone with a cadence (ringback, a
//!   beep);
//! - playback queues and interruption (`playback.start` with `queue` and
//!   `stop_on`);
//! - `dtmf.policy`: which DTMF sources reach the events, and how
//!   duplicates are dropped;
//! - `endpoint.sensitive`: sensitive digits (a PIN, a card number) kept
//!   out of logs, of other subscribers' events, and of recordings.
//!
//! Detectors without a service are PCM streams without a socket
//! (`stream.start` with no `socket`; `stream.detect` switches them).

use super::native::{Code, Endpoint, NativeError, Request};
use super::parties::side_of;
use super::{CallId, CallLeg, Control, SessionKey};
use crate::relay::{SILENCE, SINE, ToneMode, Tones};
use rtpflux_core::g711::PT_PCMA;
use rtpflux_core::rtp::Pt;
use serde_json::{Map, Value as Json, json};
use std::collections::VecDeque;

/// Playbacks waiting behind the current one, at most.
pub(super) const QUEUE_MAX: usize = 16;
/// A key reported by two sources within this is one press (ms).
const DEDUP_MS: u64 = 1000;
/// The most keys one `dtmf.send` plays.
const MAX_DIGITS: usize = 64;

/// Which DTMF sources reach the events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum DtmfPolicy {
    /// Both sources. A key reported by one is dropped when the other
    /// already reported the same key within a second, so a press is
    /// reported once, by whichever source reported it first.
    #[default]
    Dedup,
    /// Both, every report.
    Both,
    /// RFC 4733 events only.
    Rfc4733,
    /// In-band tones only.
    Inband,
}

impl DtmfPolicy {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "dedup" => DtmfPolicy::Dedup,
            "both" => DtmfPolicy::Both,
            "rfc4733" => DtmfPolicy::Rfc4733,
            "inband" => DtmfPolicy::Inband,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            DtmfPolicy::Dedup => "dedup",
            DtmfPolicy::Both => "both",
            DtmfPolicy::Rfc4733 => "rfc4733",
            DtmfPolicy::Inband => "inband",
        }
    }
}

/// A playback waiting its turn.
#[derive(Debug, Clone)]
pub(super) struct Queued {
    pub(super) id: String,
    pub(super) body: Map<String, Json>,
    pub(super) operation_id: Option<String>,
}

/// An endpoint's IVR state.
#[derive(Debug, Default)]
pub(super) struct Ivr {
    pub(super) policy: DtmfPolicy,
    pub(super) sensitive: bool,
    pub(super) queue: VecDeque<Queued>,
    /// What stops the current playback (`dtmf`, `speech`).
    pub(super) stop_on: Vec<String>,
    /// The last key reported: code, when (ms), in-band.
    last_key: Option<(u8, u64, bool)>,
    /// Recordings paused because digits are sensitive.
    recording_paused: bool,
}

/// Where tones to an endpoint go: its call and leg, its telephone-event
/// payload type and clock (if it takes events), and its audio codec.
struct Target {
    call: CallId,
    leg: CallLeg,
    event: Option<(Pt, u32)>,
    audio: Option<(Pt, crate::relay::Codec)>,
}

/// The event code of a key: `0-9`, `*`, `#`, `A-D`.
fn code_of(c: char) -> Option<u8> {
    Some(match c {
        '0'..='9' => u8::try_from(u32::from(c) - u32::from('0')).ok()?,
        '*' => 10,
        '#' => 11,
        'A'..='D' => 12 + u8::try_from(u32::from(c) - u32::from('A')).ok()?,
        'a'..='d' => 12 + u8::try_from(u32::from(c) - u32::from('a')).ok()?,
        _ => return None,
    })
}

/// `key` of a request: a number in `range`, or `default`.
fn number(
    req: &Request<'_>,
    key: &str,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<u64, NativeError> {
    let v = req.u64(key)?.unwrap_or(default);
    if range.contains(&v) {
        Ok(v)
    } else {
        Err(NativeError::invalid(format!(
            "{key}: {}..={}",
            range.start(),
            range.end()
        )))
    }
}

/// A key of a value in `range`, as the type a field takes.
fn narrow<T: TryFrom<u64>>(v: u64) -> Result<T, NativeError> {
    T::try_from(v).map_err(|_| NativeError::invalid("out of range"))
}

impl Control {
    fn ivr_endpoint(&self, req: &Request<'_>) -> Result<Endpoint, NativeError> {
        let id = req.need("endpoint_id")?;
        match self.native.endpoints.get(id) {
            Some(ep) if ep.tenant == req.tenant => Ok(ep.clone()),
            _ => Err(NativeError::new(Code::NotFound, format!("endpoint {id}"))),
        }
    }

    /// Where tones to `ep` go (its first media section).
    fn tone_target(&self, ep: &Endpoint) -> Option<Target> {
        let call = ep.session.as_bytes();
        let mut keys: Vec<&SessionKey> = self.sessions.keys().filter(|k| k.0 == call).collect();
        keys.sort();
        keys.into_iter().find_map(|k| {
            let s = self.sessions.get(k)?;
            let party = side_of(k, s, ep.id.as_bytes())?;
            let st = s.media.iter().flatten().next()?;
            let (side, law) = if party.is_b() {
                (&st.b_side, st.b_law)
            } else {
                (&st.a_side, st.a_law)
            };
            let g711 = law.map(|pt| {
                let codec = if pt == PT_PCMA {
                    crate::relay::Codec::Pcma
                } else {
                    crate::relay::Codec::Pcmu
                };
                (pt, codec)
            });
            Some(Target {
                call: st.ports.id,
                leg: st.leg(party),
                event: side.dtmf,
                audio: st.audio[party.index()].or(g711),
            })
        })
    }

    /// The target of tones to the endpoint a request names, when nothing
    /// else plays to it.
    fn free_target(&self, ep: &Endpoint) -> Result<Target, NativeError> {
        let t = self
            .tone_target(ep)
            .ok_or_else(|| NativeError::new(Code::Conflict, "the endpoint has no media"))?;
        if ep.playback.is_some()
            || self
                .extras
                .get(&t.call)
                .is_some_and(|x| x.playing[t.leg.index()].is_some())
        {
            return Err(NativeError::new(
                Code::Conflict,
                "an announcement is playing to the endpoint",
            ));
        }
        Ok(t)
    }

    fn play_to(&mut self, t: &Target, tones: Tones) -> Result<(), NativeError> {
        let played = self
            .relay
            .play_tones(t.call, t.leg, tones)
            .map_err(|e| NativeError::new(Code::Internal, e.to_string()))?;
        if played {
            Ok(())
        } else {
            Err(NativeError::new(
                Code::NotFound,
                "the endpoint's media is gone",
            ))
        }
    }

    /// `dtmf.send`: keys to the endpoint (`digits`), as telephone events
    /// when it takes them (`mode: auto`, the default, or `rfc4733`), else
    /// as tones in its audio (`inband`). The keys are not echoed or
    /// logged.
    pub(super) fn native_dtmf_send(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.ivr_endpoint(req)?;
        let digits = req.need("digits")?;
        let codes: Vec<u8> = digits
            .chars()
            .map(code_of)
            .collect::<Option<_>>()
            .filter(|c: &Vec<u8>| !c.is_empty() && c.len() <= MAX_DIGITS)
            .ok_or_else(|| NativeError::invalid("digits: 1 to 64 of 0-9 * # A-D"))?;
        let duration: u32 = narrow(number(req, "duration_ms", 100, 40..=5000)?)?;
        let pause: u32 = narrow(number(req, "pause_ms", 50, 0..=5000)?)?;
        let volume: u8 = narrow(number(req, "volume", 8, 0..=63)?)?;
        let t = self.free_target(&ep)?;
        let mode = match (req.str("mode").unwrap_or("auto"), t.event, t.audio) {
            ("auto" | "rfc4733", Some((pt, rate)), _) => ToneMode::Event { pt, rate },
            ("auto" | "inband", _, Some((pt, codec))) => ToneMode::Inband { pt, codec },
            ("auto" | "rfc4733" | "inband", ..) => {
                return Err(NativeError::new(
                    Code::Unsupported,
                    "the endpoint takes neither telephone events nor an audio codec the relay encodes in the mode asked",
                ));
            }
            _ => return Err(NativeError::invalid("mode: auto, rfc4733 or inband")),
        };
        // An event's duration field is 16 bits of its clock.
        let duration = match mode {
            ToneMode::Event { rate, .. } => duration
                .min(u32::try_from(65_535 * 1000 / u64::from(rate.max(1))).unwrap_or(u32::MAX)),
            ToneMode::Inband { .. } => duration,
        };
        let sent = codes.len();
        let mode_name = if matches!(mode, ToneMode::Event { .. }) {
            "rfc4733"
        } else {
            "inband"
        };
        self.play_to(
            &t,
            Tones {
                sine_hz: 0,
                codes,
                duration_ms: duration,
                pause_ms: pause,
                volume,
                mode,
            },
        )?;
        let total = u64::try_from(sent).unwrap_or(0) * u64::from(duration + pause);
        Ok(json!({"keys": sent, "mode": mode_name, "duration_ms": total}))
    }

    /// `tone.start`: a tone at `frequency_hz`, `on_ms` on and `off_ms` off,
    /// `repeat` times, in the endpoint's audio; `tone.stop` ends it.
    pub(super) fn native_tone(
        &mut self,
        req: &Request<'_>,
        start: bool,
    ) -> Result<Json, NativeError> {
        let ep = self.ivr_endpoint(req)?;
        let t = self
            .tone_target(&ep)
            .ok_or_else(|| NativeError::new(Code::Conflict, "the endpoint has no media"))?;
        let Some((pt, codec)) = t.audio else {
            return Err(NativeError::new(
                Code::Unsupported,
                "the endpoint's codec is not one the relay encodes",
            ));
        };
        let mode = ToneMode::Inband { pt, codec };
        if !start {
            // Replaced by 20 ms of silence: whatever played stops.
            let silence = Tones {
                sine_hz: 0,
                codes: vec![SILENCE],
                duration_ms: 20,
                pause_ms: 0,
                volume: 0,
                mode,
            };
            self.play_to(&t, silence)?;
            return Ok(json!({"stopped": true}));
        }
        let t = self.free_target(&ep)?;
        let hz: u16 = narrow(number(req, "frequency_hz", 0, 50..=4000)?)?;
        let on: u32 = narrow(number(req, "on_ms", 1000, 20..=60_000)?)?;
        let off: u32 = narrow(number(req, "off_ms", 0, 0..=60_000)?)?;
        let repeat: usize = narrow(number(req, "repeat", 1, 1..=1000)?)?;
        let volume: u8 = narrow(number(req, "volume", 10, 0..=63)?)?;
        self.play_to(
            &t,
            Tones {
                sine_hz: hz,
                codes: vec![SINE; repeat],
                duration_ms: on,
                pause_ms: off,
                volume,
                mode,
            },
        )?;
        let total = u64::try_from(repeat).unwrap_or(0) * u64::from(on + off);
        Ok(json!({"duration_ms": total}))
    }

    /// `dtmf.policy`: which sources reach the endpoint's `dtmf.detected`
    /// (`dedup`, the default, `both`, `rfc4733`, `inband`).
    pub(super) fn native_dtmf_policy(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.ivr_endpoint(req)?;
        let policy = DtmfPolicy::parse(req.need("policy")?)
            .ok_or_else(|| NativeError::invalid("policy: dedup, both, rfc4733 or inband"))?;
        self.native.ivr.entry(ep.id).or_default().policy = policy;
        Ok(json!({"policy": policy.name()}))
    }

    /// `endpoint.sensitive`: while on, the endpoint's digits are sensitive:
    /// - its `dtmf.detected` events carry `sensitive: true`, and reach only
    ///   subscribers that asked for sensitive events, others get them
    ///   redacted (no digit, no code);
    /// - its recordings are paused, and resumed when it is turned off.
    ///
    /// Digits are never logged, sensitive or not.
    pub(super) fn native_sensitive(&mut self, req: &Request<'_>) -> Result<Json, NativeError> {
        let ep = self.ivr_endpoint(req)?;
        let on = req
            .body
            .get("sensitive")
            .and_then(Json::as_bool)
            .ok_or_else(|| NativeError::invalid("sensitive: true or false"))?;
        let we_paused = self
            .native
            .ivr
            .get(&ep.id)
            .is_some_and(|i| i.recording_paused);
        // Confirmed by the media workers, or refused: never reported
        // paused while capture may go on.
        let paused = if on {
            self.pause_capture(&ep, true)?
        } else {
            if we_paused {
                self.pause_capture(&ep, false)?;
            }
            false
        };
        let ivr = self.native.ivr.entry(ep.id).or_default();
        ivr.sensitive = on;
        ivr.recording_paused = on && (paused || ivr.recording_paused);
        Ok(json!({"sensitive": on, "recording_paused": ivr.recording_paused}))
    }

    /// Whether an endpoint's event `ty` is delivered, by its DTMF policy,
    /// with `data` marked when its digits are sensitive.
    pub(super) fn ivr_admit(&mut self, id: &str, ty: &str, data: &mut Json, at_ms: u64) -> bool {
        if ty != "dtmf.detected" {
            return true;
        }
        let ivr = self.native.ivr.entry(id.to_owned()).or_default();
        let code = data
            .get("code")
            .and_then(Json::as_u64)
            .and_then(|c| u8::try_from(c).ok());
        let inband = data.get("source").and_then(Json::as_str) == Some("inband");
        let keep = match ivr.policy {
            DtmfPolicy::Both => true,
            DtmfPolicy::Rfc4733 => !inband,
            DtmfPolicy::Inband => inband,
            DtmfPolicy::Dedup => !ivr.last_key.is_some_and(|(c, at, src)| {
                Some(c) == code && src != inband && at_ms.saturating_sub(at) < DEDUP_MS
            }),
        };
        if keep && let Some(c) = code {
            ivr.last_key = Some((c, at_ms, inband));
        }
        if keep
            && ivr.sensitive
            && let Some(o) = data.as_object_mut()
        {
            o.insert("sensitive".to_owned(), json!(true));
        }
        keep
    }

    /// After an endpoint's event `ty`: a playback that stops on it stops
    /// (barge-in), and what was queued behind it is dropped.
    pub(super) fn ivr_interrupt(&mut self, id: &str, ty: &str) {
        let kind = match ty {
            "dtmf.detected" => "dtmf",
            "speech.started" => "speech",
            _ => return,
        };
        let stops = self
            .native
            .ivr
            .get(id)
            .is_some_and(|i| i.stop_on.iter().any(|k| k == kind));
        if stops
            && self
                .native
                .endpoints
                .get(id)
                .is_some_and(|e| e.playback.is_some())
        {
            self.stop_playback(id, kind);
            self.drop_queue(id, "interrupted");
        }
    }

    /// The queued playbacks of `id` go, each reported stopped (`reason`).
    pub(super) fn drop_queue(&mut self, id: &str, reason: &str) {
        let gone: Vec<Queued> = self
            .native
            .ivr
            .get_mut(id)
            .map_or_else(Vec::new, |i| i.queue.drain(..).collect());
        for q in gone {
            self.endpoint_event(
                id,
                "playback.stopped",
                q.operation_id.as_deref(),
                json!({"playback_id": q.id, "reason": reason, "queued": true}),
            );
        }
    }

    /// The next queued playback of `id`, now that the last one finished.
    pub(super) fn play_next(&mut self, id: &str) {
        loop {
            let Some(q) = self
                .native
                .ivr
                .get_mut(id)
                .and_then(|i| i.queue.pop_front())
            else {
                return;
            };
            let Some(tenant) = self.native.endpoints.get(id).map(|e| e.tenant.clone()) else {
                return;
            };
            let req = Request {
                op: "playback.start",
                operation_id: q.operation_id.as_deref(),
                tenant: &tenant,
                body: &q.body,
            };
            match self.native_play_as(&req, Some(q.id.clone())) {
                Ok(_) => return,
                Err(e) => self.endpoint_event(
                    id,
                    "playback.stopped",
                    q.operation_id.as_deref(),
                    json!({"playback_id": q.id, "reason": "failed", "detail": e.message}),
                ),
            }
        }
    }

    /// Forget the IVR state of endpoints that are gone.
    pub(super) fn ivr_prune(&mut self) {
        let n = &mut self.native;
        if n.ivr.len() > n.endpoints.len() {
            let endpoints = &n.endpoints;
            n.ivr.retain(|id, _| endpoints.contains_key(id));
        }
    }
}

/// Whether `event` is about sensitive digits.
pub(super) fn is_sensitive(event: &Json) -> bool {
    event
        .get("data")
        .and_then(|d| d.get("sensitive"))
        .and_then(Json::as_bool)
        == Some(true)
}

/// `event` without its digit, for subscribers that did not ask for
/// sensitive events.
pub(super) fn redact(event: &Json) -> Json {
    let mut e = event.clone();
    if let Some(d) = e.get_mut("data").and_then(Json::as_object_mut) {
        d.insert("digit".to_owned(), Json::Null);
        d.insert("code".to_owned(), Json::Null);
        d.insert("redacted".to_owned(), json!(true));
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_policies() {
        let codes: Vec<Option<u8>> = "09*#AdX".chars().map(code_of).collect();
        assert_eq!(
            codes,
            [
                Some(0),
                Some(9),
                Some(10),
                Some(11),
                Some(12),
                Some(15),
                None
            ]
        );
        for p in ["dedup", "both", "rfc4733", "inband"] {
            assert_eq!(DtmfPolicy::parse(p).unwrap().name(), p);
        }
        assert!(DtmfPolicy::parse("x").is_none());
        let e =
            json!({"event": "dtmf.detected", "data": {"digit": "5", "code": 5, "sensitive": true}});
        assert!(is_sensitive(&e));
        let r = redact(&e);
        assert_eq!(r["data"]["digit"], Json::Null);
        assert_eq!(r["data"]["code"], Json::Null);
        assert_eq!(r["data"]["redacted"], true);
    }
}
