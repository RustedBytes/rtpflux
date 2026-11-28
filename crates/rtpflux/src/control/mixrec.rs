//! Recording a conference mixer: `recording.start`, `recording.stop`,
//! `recording.pause` and `recording.resume` with a `mixer_id`.
//!
//! The recording is what a `listen` participant hears: every participant
//! heard by everyone, after its input gain (muted, `listen` and `whisper`
//! participants left out, whisperers kept with `include_whispers`). The
//! mixer hands each 20 ms period to the recording's queue, never waiting
//! for it ([`crate::pcm::mixer`]); a writer spools it, and the conversion
//! thread makes the files when it ends ([`crate::recording::mixrec`]),
//! stored and reported as an endpoint recording's are.
//!
//! - One recording per mixer at a time; starting again while it records
//!   gives the same `recording_id`. At most `[recording]
//!   max_mixer_recordings` at once.
//! - Pauses are confirmed by the mixer before they count, as an endpoint
//!   recording's are by its media workers. While a participant's endpoint
//!   is sensitive (`endpoint.sensitive`), the recording is paused, and
//!   resumed when none is (unless the controller paused it).
//! - `participants`: who was in the mixer while it recorded, and when.
//! - `mixer.destroy` stops the recording first: its outcome comes after
//!   `mixer.destroyed`.
//! - After a restart, a recording whose mixer came back goes on in a new
//!   section (a new file; the downtime is between the files), paused if it
//!   was; one whose mixer did not is finished with what it holds.

use super::Control;
use super::native::{Code, NativeError, Recording, Request};
use crate::recording::mixrec::{self, Finish, MixJob, Written};
use crate::recording::{Channels, Conversion, Format, Job, Meta, Settings};
use crate::relay::media_events::MediaEventKind;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How long the mixer has to confirm a pause or a resume.
const CONFIRM: Duration = Duration::from_secs(1);
/// Periods (20 ms) queued for the writer, at most: 5 s.
const QUEUE: usize = 250;
/// Milliseconds per period.
const PERIOD_MS: u64 = 20;
/// The options a mixer recording takes.
const OPTIONS: [&str; 7] = [
    "format",
    "sample_rate",
    "channels",
    "bitrate",
    "tracks",
    "include_whispers",
    "metadata",
];

/// A participant's time in the mixer while it recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participation {
    pub endpoint_id: String,
    #[serde(default)]
    pub external_id: Option<String>,
    /// `[joined_at, left_at]`, ms since the epoch (`left_at` null while
    /// it is there).
    pub intervals: Vec<(u64, Option<u64>)>,
}

/// A mixer recording's own record (kept in the state file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixRec {
    pub settings: Settings,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub include_whispers: bool,
    /// The file-name template, and when it started (seconds).
    pub template: String,
    pub started_s: u64,
    /// Each section's spool, in order.
    pub spools: Vec<String>,
    #[serde(default)]
    pub participants: Vec<Participation>,
    /// Periods written and lost in the sections before this one.
    #[serde(default)]
    pub periods: u64,
    #[serde(default)]
    pub lost: u64,
    /// Paused because a participant is sensitive (not by the controller).
    #[serde(default)]
    pub sensitive_hold: bool,
    /// Every section's audio file, once converted.
    #[serde(default)]
    pub files: Vec<String>,
}

/// A mixer recording going on: its writer's counters and hand-over.
#[derive(Debug)]
pub struct Running {
    lost: Arc<AtomicU64>,
    written: Arc<Written>,
    finish: Finish,
}

/// Whether a saved recording is a mixer's that was not finished (to go on
/// after a restart, or be finished).
pub(super) fn resumable(r: &Recording) -> bool {
    r.mixer_id.is_some()
        && matches!(
            r.state.as_str(),
            "active" | "paused" | "pausing" | "stopped"
        )
}

fn going_on(r: &Recording) -> bool {
    matches!(r.state.as_str(), "active" | "paused" | "pausing")
}

/// A recording's settings from its `options`: `[recording]`'s format
/// (WAV when that is `pcap`) and rate, mono, unless the options say.
fn settings_of(
    options: Option<&serde_json::Map<String, Json>>,
    defaults: Settings,
) -> Result<(Settings, bool, BTreeMap<String, String>), NativeError> {
    let mut s = Settings {
        format: if defaults.format == Format::Pcap {
            Format::Wav
        } else {
            defaults.format
        },
        channels: Channels::Mono,
        keep_pcap: false,
        ..defaults
    };
    let mut whispers = false;
    let mut metadata = BTreeMap::new();
    let Some(o) = options else {
        return Ok((s, whispers, metadata));
    };
    if let Some(k) = o.keys().find(|k| !OPTIONS.contains(&k.as_str())) {
        return Err(NativeError::invalid(format!(
            "options.{k}: a mixer recording takes {}",
            OPTIONS.join(", ")
        )));
    }
    let text = |k: &str| o.get(k).and_then(Json::as_str);
    if let Some(f) = text("format") {
        s.format = Format::from_name(f.as_bytes())
            .ok_or_else(|| NativeError::invalid(format!("options.format: {f}")))?;
        if s.format == Format::Pcap {
            return Err(NativeError::invalid(
                "options.format: pcap (a mixer has no packets to record)",
            ));
        }
    }
    if let Some(c) = text("channels") {
        s.channels = Channels::from_name(c.as_bytes())
            .ok_or_else(|| NativeError::invalid(format!("options.channels: {c}")))?;
    }
    let number = |k: &str| -> Result<Option<u32>, NativeError> {
        o.get(k)
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| NativeError::invalid(format!("options.{k}: a number")))
            })
            .transpose()
    };
    if let Some(r) = number("sample_rate")? {
        s.sample_rate = r;
    }
    if let Some(b) = number("bitrate")? {
        s.bitrate = b;
    }
    if let Some(p) = s.problems().first() {
        return Err(NativeError::invalid(format!("options: {p}")));
    }
    if o.get("tracks").and_then(Json::as_bool) == Some(true) {
        return Err(NativeError::new(
            Code::Unsupported,
            "options.tracks: per-participant tracks are not supported yet",
        ));
    }
    whispers = o.get("include_whispers").and_then(Json::as_bool) == Some(true);
    match o.get("metadata") {
        None => {}
        Some(Json::Object(m)) => {
            for (k, v) in m {
                let Some(v) = v.as_str() else {
                    return Err(NativeError::invalid(format!(
                        "options.metadata.{k}: a string"
                    )));
                };
                metadata.insert(k.clone(), v.to_owned());
            }
        }
        Some(_) => return Err(NativeError::invalid("options.metadata: an object")),
    }
    Ok((s, whispers, metadata))
}

impl Control {
    /// The mixer a request names, the requester's.
    fn mixer_of_request(&self, req: &Request<'_>) -> Result<u32, NativeError> {
        let id = req
            .u64("mixer_id")?
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| NativeError::invalid("mixer_id: a mixer's id"))?;
        match self.native.mixers.get(&id) {
            Some((t, _)) if t == req.tenant => Ok(id),
            Some(_) => Err(NativeError::new(
                Code::Unauthorized,
                format!("mixer {id}: another tenant's"),
            )),
            None => Err(NativeError::new(Code::NotFound, format!("mixer {id}"))),
        }
    }

    /// The recording going on of mixer `mixer`, if any.
    pub(super) fn mixer_recording(&self, mixer: u32) -> Option<String> {
        self.native
            .recordings
            .values()
            .find(|r| r.mixer_id == Some(mixer) && going_on(r))
            .map(|r| r.id.clone())
    }

    /// `recording.start` / `recording.stop` with a `mixer_id`.
    pub(super) fn native_mixrec(
        &mut self,
        req: &Request<'_>,
        start: bool,
    ) -> Result<Json, NativeError> {
        let mixer = self.mixer_of_request(req)?;
        if !start {
            let Some(rid) = self.mixer_recording(mixer) else {
                return Ok(json!({"recording": false, "mixer_id": mixer}));
            };
            self.stop_mixrec(&rid);
            let state = self.native.recordings.get(&rid).map(|r| r.state.clone());
            return Ok(
                json!({"recording": false, "recording_id": rid, "mixer_id": mixer,
                "state": state}),
            );
        }
        if let Some(rid) = self.mixer_recording(mixer) {
            return Ok(json!({"recording": true, "recording_id": rid, "mixer_id": mixer}));
        }
        let Some(dir) = self.recording_dir.clone() else {
            return Err(NativeError::new(
                Code::Unsupported,
                "recording is not configured ([recording] dir)",
            ));
        };
        let options = match req.body.get("options") {
            None | Some(Json::Null) => None,
            Some(Json::Object(o)) => Some(o),
            Some(_) => return Err(NativeError::invalid("options: an object")),
        };
        let (settings, include_whispers, extra) = settings_of(options, self.recording_settings)?;
        let mut metadata = self.recording_meta.clone();
        metadata.extend(extra);
        if let Some(why) = crate::recording::naming::check_metadata(&metadata) {
            return Err(NativeError::invalid(format!("options.metadata: {why}")));
        }
        let max = self.native.max_mixer_recordings;
        let recording = self.native.mixrecs.len();
        if recording >= max {
            return Err(NativeError::new(
                Code::Exhausted,
                format!(
                    "{recording} mixers are recorded, the most at once ([recording] max_mixer_recordings)"
                ),
            ));
        }
        if self.relay.recording_jobs().is_none() {
            return Err(NativeError::new(
                Code::Unsupported,
                "recording is not configured (no converter)",
            ));
        }
        let rid = super::native::random_id("rec-");
        let tenant = self
            .native
            .mixers
            .get(&mixer)
            .map_or_else(String::new, |(t, _)| t.clone());
        let template = if self.recording_file_name == crate::recording::naming::DEFAULT_FILE_NAME {
            crate::recording::naming::DEFAULT_MIXER_FILE_NAME.to_owned()
        } else {
            self.recording_file_name.clone()
        };
        let now = crate::relay::media_events::unix_ms();
        self.native.recordings.insert(
            rid.clone(),
            Recording {
                id: rid.clone(),
                tenant,
                endpoint_id: String::new(),
                state: "active".into(),
                file: None,
                uploaded: None,
                detail: None,
                started_unix_ms: now,
                ended_unix_ms: None,
                pauses: Vec::new(),
                mixer_id: Some(mixer),
                mix: Some(MixRec {
                    settings,
                    metadata,
                    include_whispers,
                    template,
                    started_s: now / 1000,
                    spools: Vec::new(),
                    participants: Vec::new(),
                    periods: 0,
                    lost: 0,
                    sensitive_hold: false,
                    files: Vec::new(),
                }),
            },
        );
        if let Err(e) = self.open_section(&rid, &dir, false) {
            self.native.recordings.remove(&rid);
            return Err(e);
        }
        self.mixrec_sync(mixer);
        self.native.topology_epoch += 1;
        self.mark_dirty();
        log::info!("native: mixer {mixer}: recording {rid}");
        Ok(json!({"recording": true, "recording_id": rid, "mixer_id": mixer}))
    }

    /// A new section of recording `rid` (its first, or the next after a
    /// restart): a spool, its writer, and the mixer's tap into it.
    fn open_section(
        &mut self,
        rid: &str,
        dir: &std::path::Path,
        paused: bool,
    ) -> Result<(), NativeError> {
        let Some(r) = self.native.recordings.get_mut(rid) else {
            return Err(NativeError::new(Code::NotFound, format!("recording {rid}")));
        };
        let (Some(mixer), Some(mix)) = (r.mixer_id, r.mix.as_mut()) else {
            return Err(NativeError::new(Code::Internal, "not a mixer recording"));
        };
        let base = crate::recording::naming::render(
            &mix.template,
            &crate::recording::naming::Fields {
                call_id: format!("mixer-{mixer}").as_bytes(),
                from_tag: rid.as_bytes(),
                to_tag: None,
                section: mix.spools.len() + 1,
                unix_s: mix.started_s,
                mixer_id: Some(mixer),
                recording_id: Some(rid),
                track: "",
            },
        );
        let spool = mixrec::spool_path(dir, &base);
        let (tx, rx) = std::sync::mpsc::sync_channel(QUEUE);
        let running = Running {
            lost: Arc::default(),
            written: Arc::default(),
            finish: Arc::default(),
        };
        mixrec::spawn_writer(
            &spool,
            rx,
            Arc::clone(&running.written),
            Arc::clone(&running.finish),
        )
        .map_err(|e| NativeError::new(Code::Internal, format!("recording: {e}")))?;
        let include_whispers = mix.include_whispers;
        mix.spools.push(spool.display().to_string());
        let Some((_, m)) = self.native.mixers.get(&mixer) else {
            return Err(NativeError::new(Code::NotFound, format!("mixer {mixer}")));
        };
        m.record(Some(crate::pcm::mixer::MixTap {
            blocks: tx,
            include_whispers,
            lost: Arc::clone(&running.lost),
            paused,
        }));
        self.native.mixrecs.insert(rid.to_owned(), running);
        Ok(())
    }

    /// The conversion job of recording `r`, its sections all.
    fn mixrec_job(r: &Recording) -> Option<Job> {
        let (mixer, mix) = (r.mixer_id?, r.mix.as_ref()?);
        let mut metadata = mix.metadata.clone();
        let who: Vec<String> = mix
            .participants
            .iter()
            .map(|p| match &p.external_id {
                Some(x) => format!("{} ({x})", p.endpoint_id),
                None => p.endpoint_id.clone(),
            })
            .collect();
        if !who.is_empty() {
            metadata
                .entry("participants".to_owned())
                .or_insert_with(|| who.join(", "));
        }
        let spools: Vec<std::path::PathBuf> = mix.spools.iter().map(Into::into).collect();
        Some(Job {
            pcap: spools.first().cloned().unwrap_or_default(),
            conversion: Conversion {
                settings: mix.settings,
                meta: Meta {
                    call_id: format!("mixer-{mixer}"),
                    from_tag: r.id.clone(),
                    to_tag: None,
                    section: 1,
                    left_port: 0,
                    opus_pts: Vec::new(),
                    amr_pts: Vec::new(),
                    amr_wb_pts: Vec::new(),
                    metadata,
                    mixer_id: Some(mixer),
                },
            },
            last: true,
            mix: Some(MixJob {
                recording_id: r.id.clone(),
                spools,
            }),
        })
    }

    /// End recording `rid`: `stopped` until its files are made; the
    /// mixer lets go of it, its writer writes what is queued, then the
    /// sections are converted.
    pub(super) fn stop_mixrec(&mut self, rid: &str) {
        let now = crate::relay::media_events::unix_ms();
        let Some(r) = self.native.recordings.get_mut(rid) else {
            return;
        };
        r.state = "stopped".into();
        r.ended_unix_ms.get_or_insert(now);
        if let Some(last) = r.pauses.last_mut()
            && last.1.is_none()
        {
            last.1 = Some(now);
        }
        if let Some(mix) = r.mix.as_mut() {
            for p in &mut mix.participants {
                if let Some(last) = p.intervals.last_mut()
                    && last.1.is_none()
                {
                    last.1 = Some(now);
                }
            }
        }
        let mixer = r.mixer_id;
        let job = Self::mixrec_job(r);
        let jobs = self.relay.recording_jobs();
        match (job, jobs) {
            (Some(job), Some(jobs)) => match self.native.mixrecs.get(rid) {
                Some(run) => mixrec::hand_over(&run.finish, job, jobs),
                // No writer (its mixer did not come back after a restart).
                None => {
                    let _ = jobs.send(job);
                }
            },
            _ => {
                if let Some(r) = self.native.recordings.get_mut(rid) {
                    r.state = "failed".into();
                    r.detail = Some("no recording converter".into());
                }
            }
        }
        if let Some((_, m)) = mixer.and_then(|m| self.native.mixers.get(&m)) {
            m.record(None);
        }
        self.native.topology_epoch += 1;
        self.mark_dirty();
    }

    /// `recording.pause` / `recording.resume` with a `mixer_id`.
    pub(super) fn native_mixrec_pause(
        &mut self,
        req: &Request<'_>,
        pause: bool,
    ) -> Result<Json, NativeError> {
        let mixer = self.mixer_of_request(req)?;
        let Some(rid) = self.mixer_recording(mixer) else {
            return Err(NativeError::new(
                Code::Conflict,
                "the mixer is not recording",
            ));
        };
        let changed = self.pause_mixrec(&rid, pause)?;
        if let Some(mix) = self
            .native
            .recordings
            .get_mut(&rid)
            .and_then(|r| r.mix.as_mut())
        {
            // The controller's own pause or resume: no longer the
            // sensitivity's.
            mix.sensitive_hold = false;
        }
        let r = self.native.recordings.get(&rid);
        Ok(json!({
            "recording_id": rid,
            "mixer_id": mixer,
            "state": r.map(|r| r.state.clone()),
            "changed": changed,
            "pauses": r.map(|r| r.pauses.clone()),
        }))
    }

    /// Pause (or resume) recording `rid` once the mixer confirms it;
    /// `Ok(false)`: nothing to change.
    fn pause_mixrec(&mut self, rid: &str, pause: bool) -> Result<bool, NativeError> {
        let Some(r) = self.native.recordings.get(rid) else {
            return Ok(false);
        };
        let paused = matches!(r.state.as_str(), "paused" | "pausing");
        if paused == pause && r.state != "pausing" {
            return Ok(false);
        }
        let Some((_, m)) = r.mixer_id.and_then(|m| self.native.mixers.get(&m)) else {
            return Err(NativeError::new(Code::NotFound, "the mixer is gone"));
        };
        let confirmed = m.pause_recording(pause, CONFIRM);
        let now = crate::relay::media_events::unix_ms();
        let Some(r) = self.native.recordings.get_mut(rid) else {
            return Ok(false);
        };
        match (pause, confirmed) {
            (true, true) => {
                if r.state != "pausing" || r.pauses.last().is_none_or(|p| p.1.is_some()) {
                    r.pauses.push((now, None));
                }
                r.state = "paused".into();
            }
            (true, false) => r.state = "pausing".into(),
            (false, true) => {
                r.state = "active".into();
                if let Some(last) = r.pauses.last_mut()
                    && last.1.is_none()
                {
                    last.1 = Some(now);
                }
            }
            (false, false) => {}
        }
        self.mark_dirty();
        if confirmed {
            Ok(true)
        } else {
            Err(NativeError::new(
                Code::Timeout,
                if pause {
                    "the mixer did not confirm the pause: capture may go on"
                } else {
                    "the mixer did not confirm the resume"
                },
            )
            .with_detail(json!({"state": if pause { "pausing" } else { "resuming" }})))
        }
    }

    /// After mixer `mixer` changed (who is in it, or their sensitivity):
    /// its recording's participants follow, and it is paused while one of
    /// them is sensitive (resumed when none is, if it paused it).
    pub(super) fn mixrec_sync(&mut self, mixer: u32) {
        let Some(rid) = self.mixer_recording(mixer) else {
            return;
        };
        let now = crate::relay::media_events::unix_ms();
        let present: Vec<String> = self
            .native
            .mixers
            .get(&mixer)
            .map_or_else(Vec::new, |(_, m)| m.participants.clone());
        let sensitive = present
            .iter()
            .any(|p| self.native.ivr.get(p).is_some_and(|i| i.sensitive));
        let externals: Vec<(String, Option<String>)> = present
            .iter()
            .map(|p| {
                (
                    p.clone(),
                    self.native
                        .endpoints
                        .get(p)
                        .and_then(|e| e.external_id.clone()),
                )
            })
            .collect();
        let Some(r) = self.native.recordings.get_mut(&rid) else {
            return;
        };
        let state = r.state.clone();
        let Some(mix) = r.mix.as_mut() else {
            return;
        };
        for p in &mut mix.participants {
            let here = present.contains(&p.endpoint_id);
            let open = p.intervals.last().is_some_and(|i| i.1.is_none());
            if open && !here {
                if let Some(last) = p.intervals.last_mut() {
                    last.1 = Some(now);
                }
            } else if here && !open {
                p.intervals.push((now, None));
            }
        }
        for (id, external_id) in externals {
            if !mix.participants.iter().any(|p| p.endpoint_id == id) {
                mix.participants.push(Participation {
                    endpoint_id: id,
                    external_id,
                    intervals: vec![(now, None)],
                });
            }
        }
        let hold = mix.sensitive_hold;
        self.mark_dirty();
        if sensitive && state == "active" {
            match self.pause_mixrec(&rid, true) {
                Ok(_) => {
                    if let Some(mix) = self
                        .native
                        .recordings
                        .get_mut(&rid)
                        .and_then(|r| r.mix.as_mut())
                    {
                        mix.sensitive_hold = true;
                    }
                }
                Err(e) => log::warn!("native: mixer {mixer}: recording {rid}: {}", e.message),
            }
        } else if !sensitive && hold {
            if let Err(e) = self.pause_mixrec(&rid, false) {
                log::warn!("native: mixer {mixer}: recording {rid}: {}", e.message);
            }
            if let Some(mix) = self
                .native
                .recordings
                .get_mut(&rid)
                .and_then(|r| r.mix.as_mut())
            {
                mix.sensitive_hold = false;
            }
        }
    }

    /// The mixers endpoint `id` is in.
    pub(super) fn mixers_of(&self, id: &str) -> Vec<u32> {
        self.native
            .mixers
            .iter()
            .filter(|(_, (_, m))| m.participants.iter().any(|p| p == id))
            .map(|(k, _)| *k)
            .collect()
    }

    /// A mixer recording's outcome (from the conversion thread).
    pub(super) fn mixrec_outcome(&mut self, rid: &str, kind: &MediaEventKind) {
        let run = self.native.mixrecs.remove(rid);
        let Some(r) = self.native.recordings.get_mut(rid) else {
            return;
        };
        let (ty, file, uploaded, failure) = match kind {
            MediaEventKind::RecordingDone { file, uploaded } => {
                ("recording.completed", file.clone(), *uploaded, None)
            }
            MediaEventKind::Failed { reason, .. } => {
                ("recording.failed", None, None, Some(reason.clone()))
            }
            _ => return,
        };
        r.state = if file.is_some() {
            "completed"
        } else {
            "failed"
        }
        .into();
        r.file.clone_from(&file);
        r.uploaded = uploaded;
        r.detail.clone_from(&failure);
        r.ended_unix_ms
            .get_or_insert_with(crate::relay::media_events::unix_ms);
        let Some(mix) = r.mix.as_mut() else {
            return;
        };
        if let Some(run) = run {
            mix.periods += run.written.periods.load(Ordering::Relaxed);
            mix.lost += run.lost.load(Ordering::Relaxed);
        }
        if mix.lost > 0 {
            log::warn!(
                "native: recording {rid}: {} ms of the mix lost (the writer fell behind)",
                mix.lost * PERIOD_MS
            );
        }
        mix.files = mix
            .spools
            .iter()
            .map(|s| {
                std::path::Path::new(s)
                    .with_extension(mix.settings.format.extension())
                    .display()
                    .to_string()
            })
            .filter(|f| std::path::Path::new(f).exists() || uploaded == Some(true))
            .collect();
        let data = json!({
            "recording_id": rid,
            "mixer_id": r.mixer_id,
            "file": file,
            "files": mix.files,
            "uploaded": uploaded,
            "section": mix.spools.len(),
            "duration_ms": mix.periods * PERIOD_MS,
            "lost_ms": mix.lost * PERIOD_MS,
            "reason": failure.as_ref().map(|_| "recording"),
            "detail": failure,
        });
        let event = json!({"event": ty, "mixer_id": r.mixer_id, "tenant": r.tenant, "data": data});
        self.native.topology_epoch += 1;
        self.mark_dirty();
        self.native.publish(event);
    }

    /// After a restart: each mixer recording that was going on goes on in
    /// a new section if its mixer came back (paused if it was), or is
    /// finished with what it holds; one stopped but not converted is
    /// converted now.
    pub(super) fn mixrec_restore(&mut self) {
        let ids: Vec<String> = self
            .native
            .recordings
            .values()
            .filter(|r| resumable(r))
            .map(|r| r.id.clone())
            .collect();
        for rid in ids {
            let Some(r) = self.native.recordings.get_mut(&rid) else {
                continue;
            };
            let mixer = r.mixer_id;
            let (tenant, state) = (r.tenant.clone(), r.state.clone());
            // What the sections before hold.
            if let Some(mix) = r.mix.as_mut() {
                mix.periods = mix
                    .spools
                    .iter()
                    .filter_map(|s| std::fs::metadata(s).ok())
                    .map(|m| m.len() / (2 * crate::pcm::mixer::BLOCK_SAMPLES as u64))
                    .sum();
            }
            let back = mixer.is_some_and(|m| self.native.mixers.contains_key(&m));
            if state == "stopped" || !back {
                if state != "stopped" {
                    self.native.lost.push(json!({"kind": "mixer_recording",
                        "recording_id": rid, "mixer_id": mixer, "tenant": tenant,
                        "reason": "its mixer was not restored: finished with what it holds"}));
                }
                self.stop_mixrec(&rid);
                continue;
            }
            let paused = matches!(state.as_str(), "paused" | "pausing");
            if let Some(r) = self.native.recordings.get_mut(&rid)
                && paused
            {
                // Its new section starts paused: the pause holds.
                r.state = "paused".into();
            }
            let Some(dir) = self.recording_dir.clone() else {
                self.stop_mixrec(&rid);
                continue;
            };
            match self.open_section(&rid, &dir, paused) {
                Ok(()) => {
                    log::info!("native: recording {rid} goes on in a new section");
                    self.native.restored_mixer_recordings.push(rid.clone());
                    if let Some(m) = mixer {
                        self.mixrec_sync(m);
                    }
                }
                Err(e) => {
                    self.native.lost.push(json!({"kind": "mixer_recording",
                        "recording_id": rid, "mixer_id": mixer, "tenant": tenant,
                        "reason": e.message}));
                    self.stop_mixrec(&rid);
                }
            }
        }
    }

    /// A recording as `recording.query` and the inventory give it.
    pub(super) fn recording_view(&self, r: &Recording) -> Json {
        let mut v = super::rec::recording_json(r);
        let (Some(mix), Some(o)) = (r.mix.as_ref(), v.as_object_mut()) else {
            return v;
        };
        o.remove("endpoint_id");
        o.remove("mix");
        let (periods, lost) = self.native.mixrecs.get(&r.id).map_or((0, 0), |run| {
            (
                run.written.periods.load(Ordering::Relaxed),
                run.lost.load(Ordering::Relaxed),
            )
        });
        o.insert("participants".into(), json!(mix.participants));
        o.insert("lost_ms".into(), json!((mix.lost + lost) * PERIOD_MS));
        o.insert(
            "duration_ms".into(),
            json!((mix.periods + periods) * PERIOD_MS),
        );
        o.insert("section".into(), json!(mix.spools.len()));
        o.insert("files".into(), json!(mix.files));
        o.insert(
            "options".into(),
            json!({"format": mix.settings.format, "sample_rate": mix.settings.sample_rate,
                   "channels": mix.settings.channels, "include_whispers": mix.include_whispers}),
        );
        v
    }

    /// A recording as saved: a mixer recording with what its writer lost
    /// so far (what it wrote is read back from the spools).
    pub(super) fn recording_to_save(&self, r: &Recording) -> Recording {
        let mut out = r.clone();
        if let (Some(mix), Some(run)) = (out.mix.as_mut(), self.native.mixrecs.get(&r.id)) {
            mix.lost += run.lost.load(Ordering::Relaxed);
        }
        out
    }
}
