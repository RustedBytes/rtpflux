//! The native API's inventory and recovery report: what exists, paged and
//! typed, and what a restart brought back or lost.
//!
//! - **Inventory** (`inventory.list`): one kind of resource per request
//!   (`endpoints`, `bridges`, `streams`, `mixers`, `playbacks`,
//!   `recordings`), in id order, at most [`MAX_PAGE`] per page. Every page
//!   carries the watermark it was taken at (boot id, `global_seq`,
//!   `topology_epoch`). The cursor names the page's run and epoch: if
//!   anything may have changed since the first page, the next one is
//!   refused (`conflict`) and the client starts again, rather than getting
//!   pages of two different states.
//! - **Recovery** (`recovery.report`): this run's and the previous run's
//!   boot ids; the endpoints and mixers restored (a mixer with the same
//!   id and its participants' settings); what was lost (PCM streams are
//!   never restored, nor announcements from a blob, nor a mixer's
//!   participant whose endpoint did not come back); the
//!   operations whose outcome is unknown. Nothing is reported as restored
//!   that was not.

use super::native::{Code, NativeError, Recording, RecordingState};
use super::{Control, native};
use crate::relay::media_events::Subject;
use serde_json::{Value as Json, json};

/// Items per inventory page at most (each well under 1 KiB, so a page stays
/// far below the 1 MiB frame).
pub const MAX_PAGE: usize = 500;

/// The kinds the inventory lists.
const KINDS: [&str; 6] = [
    "endpoints",
    "bridges",
    "streams",
    "mixers",
    "playbacks",
    "recordings",
];

/// Finished recordings kept for `recording.query` and the inventory, at
/// most (the latest to end).
pub(super) const MAX_FINISHED_RECORDINGS: usize = 4096;

impl native::Native {
    /// A native API state for a new run (its own boot id).
    pub(super) fn fresh() -> Self {
        let mut n = Self::default();
        n.boot_id = native::random_id("boot-");
        n.journal_cap = native::DEFAULT_JOURNAL;
        n.max_mixer_recordings = 64;
        n
    }
}

impl Control {
    /// The page `(boot, epoch, last id)` a cursor names.
    fn parse_cursor(cursor: &str) -> Option<(&str, u64, &str)> {
        let mut parts = cursor.splitn(3, '|');
        let boot = parts.next()?;
        let epoch = parts.next()?.parse().ok()?;
        Some((boot, epoch, parts.next()?))
    }

    /// Every item of `kind` for `tenant`, as (sort key, item).
    fn inventory_items(&self, tenant: &str, kind: &str) -> Vec<(String, Json)> {
        let n = &self.native;
        let mut items: Vec<(String, Json)> = match kind {
            "endpoints" => n
                .endpoints
                .values()
                .filter(|e| e.tenant == tenant)
                .map(|e| {
                    let mut snap = Self::endpoint_snapshot(e);
                    if let Some(o) = snap.as_object_mut() {
                        o.insert("stream_id".into(), json!(self.stream_of(&e.id)));
                        o.insert("mixer_id".into(), json!(self.mixer_of(&e.id)));
                    }
                    (e.id.clone(), snap)
                })
                .collect(),
            "bridges" => n
                .endpoints
                .values()
                .filter(|e| e.tenant == tenant)
                .filter_map(|e| {
                    let peer = e.bridged_to.as_ref()?;
                    (e.id < *peer).then(|| {
                        (
                            format!("{}+{peer}", e.id),
                            json!({"endpoints": [e.id, peer]}),
                        )
                    })
                })
                .collect(),
            "streams" => n
                .streams
                .iter()
                .filter(|(_, (ep, _))| n.endpoints.get(ep).is_some_and(|e| e.tenant == tenant))
                .map(|(id, (ep, _))| {
                    (
                        format!("{id:010}"),
                        json!({"stream_id": id, "endpoint_id": ep}),
                    )
                })
                .collect(),
            "mixers" => n
                .mixers
                .iter()
                .filter(|(_, (t, _))| t == tenant)
                .map(|(id, (_, m))| {
                    (
                        format!("{id:010}"),
                        json!({"mixer_id": id, "participants": m.participants}),
                    )
                })
                .collect(),
            "playbacks" => n
                .endpoints
                .values()
                .filter(|e| e.tenant == tenant)
                .filter_map(|e| {
                    let (id, op) = e.playback.as_ref()?;
                    Some((
                        id.clone(),
                        json!({"playback_id": id, "endpoint_id": e.id, "operation_id": op}),
                    ))
                })
                .collect(),
            _ => n
                .recordings
                .values()
                .filter(|r| r.tenant == tenant)
                .map(|r| (r.id.clone(), self.recording_view(r)))
                .collect(),
        };
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items
    }

    /// The PCM stream on endpoint `id`, if any.
    fn stream_of(&self, id: &str) -> Option<u32> {
        self.native
            .streams
            .iter()
            .find(|(_, (e, _))| e == id)
            .map(|(s, _)| *s)
    }

    /// The mixer endpoint `id` is in, if any.
    fn mixer_of(&self, id: &str) -> Option<u32> {
        self.native
            .mixers
            .iter()
            .find(|(_, (_, m))| m.participants.iter().any(|p| p == id))
            .map(|(m, _)| *m)
    }

    /// `inventory.list`: a page of `kind` (`cursor`, `limit`).
    pub(super) fn native_inventory(&self, req: &native::Request<'_>) -> Result<Json, NativeError> {
        let kind = req.str("kind").unwrap_or("endpoints");
        if !KINDS.contains(&kind) {
            return Err(NativeError::invalid(format!(
                "kind: one of {}",
                KINDS.join(", ")
            )));
        }
        let limit = req
            .u64("limit")?
            .map_or(100, |l| usize::try_from(l).unwrap_or(MAX_PAGE))
            .clamp(1, MAX_PAGE);
        let n = &self.native;
        let after = match req.str("cursor") {
            None => None,
            Some(c) => {
                let Some((boot, epoch, last)) = Self::parse_cursor(c) else {
                    return Err(NativeError::invalid("cursor: not one this relay gave"));
                };
                if boot != n.boot_id || epoch != n.topology_epoch {
                    return Err(NativeError::new(
                        Code::Conflict,
                        "the inventory changed since the first page: start again without a cursor",
                    )
                    .with_detail(
                        json!({"boot_id": n.boot_id, "topology_epoch": n.topology_epoch}),
                    ));
                }
                Some(last.to_owned())
            }
        };
        let items = self.inventory_items(req.tenant, kind);
        let start = after.map_or(0, |a| items.partition_point(|(k, _)| *k <= a));
        let page: Vec<&(String, Json)> = items.iter().skip(start).take(limit).collect();
        let next = (start + page.len() < items.len())
            .then(|| {
                page.last()
                    .map(|(k, _)| format!("{}|{}|{k}", n.boot_id, n.topology_epoch))
            })
            .flatten();
        Ok(json!({
            "kind": kind,
            "items": page.iter().map(|(_, v)| v).collect::<Vec<_>>(),
            "next_cursor": next,
            "total": items.len(),
            "watermark": {
                "boot_id": n.boot_id,
                "global_seq": n.global_seq,
                "topology_epoch": n.topology_epoch,
            },
        }))
    }

    /// `recovery.report`.
    pub(super) fn native_recovery(&self) -> Json {
        let n = &self.native;
        let unknown: Vec<Json> = n
            .ledger
            .unknown()
            .map(|(tenant, key, e)| {
                json!({"tenant": tenant, "idempotency_key": key, "op": e.op, "resources": e.resources})
            })
            .collect();
        json!({
            "boot_id": n.boot_id,
            "previous_boot_id": n.previous_boot,
            "restored_endpoints": n.restored,
            "restored_mixers": n.restored_mixers,
            "restored_mixer_recordings": n.restored_mixer_recordings,
            "lost": n.lost,
            "unknown_operations": unknown,
            "durable": n.ledger.durable(),
        })
    }

    /// Keep at most [`MAX_FINISHED_RECORDINGS`] finished recordings (the
    /// latest to end); one going on, or stopped and not converted yet, is
    /// never dropped. Without it, every recording ever made would stay in
    /// memory and be rewritten in every save of the state.
    pub(super) fn recordings_prune(&mut self) {
        let n = &mut self.native;
        let finished = n.recordings.values().filter(|r| r.state.ended()).count();
        if finished <= MAX_FINISHED_RECORDINGS {
            return;
        }
        let mut ended: Vec<(u64, String)> = n
            .recordings
            .values()
            .filter(|r| r.state.ended())
            .map(|r| (r.ended_unix_ms.unwrap_or(0), r.id.clone()))
            .collect();
        ended.sort_unstable();
        for (_, id) in ended.iter().take(finished - MAX_FINISHED_RECORDINGS) {
            n.recordings.remove(id);
        }
        self.mark_dirty();
    }

    /// `recording.query`: what became of recording `recording_id`.
    pub(super) fn native_recording(&self, req: &native::Request<'_>) -> Result<Json, NativeError> {
        let id = req.need("recording_id")?;
        match self.native.recordings.get(id) {
            Some(r) if r.tenant == req.tenant => Ok(self.recording_view(r)),
            Some(_) => Err(NativeError::new(
                Code::Unauthorized,
                format!("recording {id}: another tenant's"),
            )),
            None => Err(NativeError::new(Code::NotFound, format!("recording {id}"))),
        }
    }

    /// A recording of `subject` ended: its record updated (completed with
    /// `file`, or failed with `failure`); its id.
    pub(super) fn recording_ended(
        &mut self,
        subject: &Subject,
        file: Option<&String>,
        uploaded: Option<bool>,
        failure: Option<&String>,
    ) -> Option<String> {
        let tag = match subject {
            Subject::Dialog { from_tag, .. } => from_tag
                .strip_prefix(std::str::from_utf8(super::create::CREATOR).unwrap_or(""))
                .unwrap_or(from_tag)
                .to_owned(),
            Subject::Call(call) => {
                let (_, t) = self.party_on_leg_any(*call)?;
                String::from_utf8(t).ok()?
            }
            Subject::Leg(..) | Subject::Recording(_) => return None,
        };
        // Its endpoint's, or (destroyed) its last one not finished.
        let id = match self.native.endpoints.get(&tag) {
            Some(ep) => ep.recording.clone()?,
            None => self
                .native
                .recordings
                .values()
                .filter(|r| r.endpoint_id == tag && !r.state.ended())
                .max_by_key(|r| r.started_unix_ms)?
                .id
                .clone(),
        };
        let r = self.native.recordings.get_mut(&id)?;
        r.state = if file.is_some() {
            RecordingState::Completed
        } else {
            RecordingState::Failed
        };
        r.file = file.cloned();
        r.uploaded = uploaded;
        r.detail = failure.cloned();
        r.ended_unix_ms = Some(crate::relay::media_events::unix_ms());
        self.native.topology_epoch += 1;
        Some(id)
    }

    /// What the native API keeps besides its endpoints, for the state.
    pub(super) fn saved_native_extra(&self, saved: &mut crate::state::SavedNative) {
        let n = &self.native;
        saved.boot_id = Some(n.boot_id.clone());
        saved.owned = n
            .owned
            .iter()
            .filter(|(id, _)| n.endpoints.contains_key(*id))
            .map(|(id, (t, g))| (id.clone(), t.clone(), g.clone()))
            .collect();
        saved.streams = n
            .streams
            .iter()
            .filter_map(|(id, (ep, _))| {
                Some((*id, n.endpoints.get(ep)?.tenant.clone(), ep.clone()))
            })
            .collect();
        saved.mixers = n
            .mixers
            .iter()
            .map(|(id, (t, m))| (*id, t.clone(), m.participants.clone()))
            .collect();
        saved.recordings = n
            .recordings
            .values()
            .map(|r| self.recording_to_save(r))
            .collect::<Vec<Recording>>();
        saved.mixer_plans = self.mixer_plans();
    }

    /// After a restart: what the previous run had and this one does not
    /// (reported as lost), and the recordings' records back.
    pub(super) fn restore_native_extra(&mut self, saved: &crate::state::SavedNative) {
        let n = &mut self.native;
        n.previous_boot.clone_from(&saved.boot_id);
        // Restored endpoints keep their group (streams and mixers are not
        // restored).
        for (id, t, g) in &saved.owned {
            n.owned.insert(id.clone(), (t.clone(), g.clone()));
        }
        for (id, tenant, ep) in &saved.streams {
            n.lost
                .push(json!({"kind": "stream", "stream_id": id, "tenant": tenant,
                "endpoint_id": ep, "reason": "PCM streams are not restored: start it again"}));
        }
        // Mixers with a plan are rebuilt (at the first pass); one without
        // (saved by an older version) is lost.
        n.pending_mixers.clone_from(&saved.mixer_plans);
        for (id, tenant, parts) in &saved.mixers {
            if !saved.mixer_plans.iter().any(|p| p.id == *id) {
                n.lost.push(json!({"kind": "mixer", "mixer_id": id, "tenant": tenant,
                    "participants": parts, "reason": "mixers are not restored: create it again and add its participants"}));
            }
        }
        for r in &saved.recordings {
            n.recordings.insert(r.id.clone(), r.clone());
        }
        n.mixrec_pending = saved.recordings.iter().any(super::mixrec::resumable);
        n.restored = n.endpoints.keys().cloned().collect();
        n.restored.sort();
        // Announcements: back if the relay restored them (from a file),
        // else lost.
        let playing: Vec<(String, String)> = n
            .endpoints
            .values()
            .filter_map(|e| Some((e.id.clone(), e.playback.as_ref()?.0.clone())))
            .collect();
        for (ep, pb) in playing {
            if !self.plays_to(&ep) {
                if let Some(e) = self.native.endpoints.get_mut(&ep) {
                    e.playback = None;
                }
                self.native
                    .lost
                    .push(json!({"kind": "playback", "playback_id": pb,
                    "endpoint_id": ep, "reason": "an announcement from a blob is not restored"}));
            }
        }
    }

    /// Whether an announcement plays to endpoint `id` (as restored).
    fn plays_to(&self, id: &str) -> bool {
        let Some(e) = self.native.endpoints.get(id) else {
            return false;
        };
        self.party_legs(e.session.as_bytes(), id.as_bytes())
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .any(|((call, _), _)| {
                self.extras
                    .get(&call)
                    .is_some_and(|x| x.playing.iter().any(Option::is_some))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::native::RecordingState;

    fn record(id: &str, state: RecordingState, ended: Option<u64>) -> Recording {
        Recording {
            id: id.to_owned(),
            tenant: "t".into(),
            endpoint_id: "e".into(),
            state,
            file: None,
            uploaded: None,
            detail: None,
            started_unix_ms: 0,
            ended_unix_ms: ended,
            pauses: Vec::new(),
            mixer_id: None,
            mix: None,
        }
    }

    /// The finished recordings beyond the most kept go, the oldest first;
    /// those going on or not converted yet stay, however old.
    #[test]
    fn finished_recordings_are_bounded() {
        let config = crate::config::Config::from_toml(
            "[[interface]]\nname = \"lo\"\naddress = \"127.0.0.1\"\n\
             [ports]\nmin = 24700\nmax = 24715\n[sessions]\nmax = 4\n[runtime]\nworkers = 1\n",
        )
        .unwrap();
        let relay = crate::relay::Relay::start(&config).unwrap();
        let mut c = Control::new(relay, config.interfaces);
        let extra = 10;
        for i in 0..MAX_FINISHED_RECORDINGS + extra {
            let r = record(
                &format!("rec-{i}"),
                RecordingState::Completed,
                Some(1_000 + u64::try_from(i).unwrap()),
            );
            c.native.recordings.insert(r.id.clone(), r);
        }
        for (id, state) in [
            ("going", RecordingState::Active),
            ("converting", RecordingState::Stopped),
        ] {
            c.native
                .recordings
                .insert(id.to_owned(), record(id, state, Some(1)));
        }
        c.recordings_prune();
        let n = &c.native.recordings;
        assert_eq!(n.len(), MAX_FINISHED_RECORDINGS + 2);
        assert!(n.contains_key("going") && n.contains_key("converting"));
        assert!(
            !n.contains_key("rec-0") && !n.contains_key("rec-9"),
            "the oldest"
        );
        assert!(n.contains_key("rec-10"));
    }
}
