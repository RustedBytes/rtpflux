//! Recording pause and resume of the native API (`recording.pause`,
//! `recording.resume`), with a boundary the media workers confirm.
//!
//! A pause counts only once the workers have taken it: the relay waits
//! for them (a barrier over the endpoint's calls) before it says
//! `paused`, and records when. Until then the recording is `pausing`, and
//! the request fails saying capture may go on: the relay never reports a
//! pause that has not happened. Resuming is confirmed the same way. Each
//! pause's boundaries are kept with the recording (`pauses`), in the
//! state file too, and the paused state survives a restart (the call's
//! recording state is saved paused).

use super::native::{Code, Endpoint, NativeError, RecordingState, Request};
use super::parties::side_of;
use super::{CallId, Control};
use crate::lifecycle::RecStep;
use serde_json::{Value as Json, json};
use std::time::Duration;

/// How long the media workers have to confirm a pause or a resume.
const CONFIRM: Duration = Duration::from_secs(1);

impl Control {
    /// The media sections of the calls `ep` is in.
    fn endpoint_sections(&self, ep: &Endpoint) -> Vec<CallId> {
        let call = ep.session.as_bytes();
        self.sessions
            .iter()
            .filter(|(k, s)| k.0 == call && side_of(k, s, ep.id.as_bytes()).is_some())
            .flat_map(|(_, s)| s.media.iter().flatten().map(|st| st.ports.id))
            .collect()
    }

    /// Pause (or resume) the recording of `ep`'s media, confirmed by the
    /// media workers before it counts. `Ok(false)`: nothing to change.
    ///
    /// # Errors
    ///
    /// `timeout` when the workers did not confirm (the recording is
    /// `pausing`: capture may go on), `internal` when they could not be
    /// asked.
    pub(super) fn pause_capture(
        &mut self,
        ep: &Endpoint,
        pause: bool,
    ) -> Result<bool, NativeError> {
        let mut changed = Vec::new();
        for id in self.endpoint_sections(ep) {
            let Some(x) = self.extras.get_mut(&id) else {
                continue;
            };
            let mut rec = x.rec();
            let step = if pause && rec.writes().is_some() {
                rec.pause()
            } else if !pause && rec.current().is_some_and(|(_, paused)| paused) {
                rec.start()
            } else {
                RecStep::Nothing
            };
            if matches!(step, RecStep::Pause(_) | RecStep::Resume(_)) {
                x.set_rec(rec);
                self.relay
                    .pause_recording(id, pause)
                    .map_err(|e| NativeError::new(Code::Internal, e.to_string()))?;
                changed.push(id);
            }
        }
        if changed.is_empty() {
            return Ok(false);
        }
        self.mark_dirty();
        let confirmed = self.relay.applied(&changed, CONFIRM);
        let now = crate::relay::media_events::unix_ms();
        if let Some(r) = ep
            .recording
            .as_ref()
            .and_then(|id| self.native.recordings.get_mut(id))
        {
            match (pause, confirmed) {
                (true, true) => {
                    r.state = RecordingState::Paused;
                    r.pauses.push((now, None));
                }
                (true, false) => r.state = RecordingState::Pausing,
                (false, _) => {
                    r.state = RecordingState::Active;
                    if let Some(last) = r.pauses.last_mut()
                        && last.1.is_none()
                    {
                        last.1 = Some(now);
                    }
                }
            }
        }
        if confirmed {
            Ok(true)
        } else {
            Err(NativeError::new(
                Code::Timeout,
                if pause {
                    "the media workers did not confirm the pause: capture may go on"
                } else {
                    "the media workers did not confirm the resume"
                },
            )
            .with_detail(json!({"state": if pause { "pausing" } else { "resuming" }})))
        }
    }

    /// `recording.pause` and `recording.resume` of the endpoint's current
    /// recording.
    pub(super) fn native_record_pause(
        &mut self,
        req: &Request<'_>,
        pause: bool,
    ) -> Result<Json, NativeError> {
        if req.body.contains_key("mixer_id") {
            if req.body.contains_key("endpoint_id") {
                return Err(NativeError::invalid("endpoint_id or mixer_id, not both"));
            }
            return self.native_mixrec_pause(req, pause);
        }
        let id = req.need("endpoint_id")?;
        let ep = match self.native.endpoints.get(id) {
            Some(ep) if ep.tenant == req.tenant => ep.clone(),
            _ => return Err(NativeError::new(Code::NotFound, format!("endpoint {id}"))),
        };
        let Some(rid) = ep.recording.clone().filter(|r| {
            self.native
                .recordings
                .get(r)
                .is_some_and(|r| r.state.going_on())
        }) else {
            return Err(NativeError::new(
                Code::Conflict,
                "the endpoint is not recording",
            ));
        };
        let changed = self.pause_capture(&ep, pause)?;
        let r = self.native.recordings.get(&rid);
        Ok(json!({
            "recording_id": rid,
            "state": r.map(|r| r.state),
            "changed": changed,
            "pauses": r.map(|r| r.pauses.clone()),
        }))
    }
}

/// A recording as `recording.query` gives it: its record, and its
/// outcomes kept apart: the file written (`finalized`), its upload
/// (`upload`: `none` without uploads, `uploaded`, `failed`, or `pending`
/// before it ends).
pub(super) fn recording_json(r: &super::native::Recording) -> Json {
    let mut v = json!(r);
    if let Some(o) = v.as_object_mut() {
        let ended = r.state.ended();
        o.insert("finalized".to_owned(), json!(r.file.is_some()));
        o.insert(
            "upload".to_owned(),
            json!(match (ended, r.uploaded) {
                (false, _) => "pending",
                (true, None) => "none",
                (true, Some(true)) => "uploaded",
                (true, Some(false)) => "failed",
            }),
        );
    }
    v
}
