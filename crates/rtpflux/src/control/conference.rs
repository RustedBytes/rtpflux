//! Conference recovery: each mixer's desired topology, kept with the
//! state and rebuilt after a restart.
//!
//! A mixer's **plan** is what its operations made of it: its id and
//! tenant, and its seats, one per participant, each with
//! - its role (`participant`, `listen`, `whisper` to another);
//! - `muted`, `deafened`;
//! - input and output gains.
//!
//! It is updated by every successful `mixer.*` operation and saved in the
//! state file. After a restart, at the control thread's first pass, every
//! planned mixer is created again with the **same id** and its seats
//! filled again, each endpoint restored. A seat whose endpoint did not
//! come back is reported lost (`recovery.report`), never silently
//! dropped. The mixing state (jitter buffers, the active speaker) starts
//! afresh: the conference resumes, it is not transparently continued.
//!
//! PCM taps on participants (`stream.start` on a participant) are not
//! restored: PCM streams never are.

use super::Control;
use super::native::{Code, NativeError, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};

/// A participant's place in a mixer's plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seat {
    pub endpoint_id: String,
    /// `participant`, `listen` or `whisper`.
    pub role: String,
    /// The participant a whisperer is heard by.
    #[serde(default)]
    pub whisper_to: Option<String>,
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub deafened: bool,
    #[serde(default)]
    pub input_gain_db: i32,
    #[serde(default)]
    pub output_gain_db: i32,
}

/// A mixer's desired topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixerPlan {
    pub id: u32,
    pub tenant: String,
    pub seats: Vec<Seat>,
}

/// A gain field of a request, clamped to −60..=+24 dB.
pub(super) fn gain(req: &Request<'_>, key: &str) -> Option<i32> {
    req.body
        .get(key)
        .and_then(Json::as_i64)
        .map(|db| i32::try_from(db.clamp(-60, 24)).unwrap_or(0))
}

impl Control {
    /// After a successful `mixer.*` operation (`result` its reply), the
    /// plan follows.
    pub(super) fn note_mixer(&mut self, req: &Request<'_>, result: &Json) {
        let plans = &mut self.native.mixer_plans;
        let mixer = result
            .get("mixer_id")
            .or_else(|| req.body.get("mixer_id"))
            .and_then(Json::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        let Some(id) = mixer else {
            return;
        };
        let endpoint = req.str("endpoint_id").map(str::to_owned);
        match (req.op, endpoint) {
            ("mixer.create", _) => {
                plans.insert(
                    id,
                    MixerPlan {
                        id,
                        tenant: req.tenant.to_owned(),
                        seats: Vec::new(),
                    },
                );
            }
            ("mixer.destroy", _) => {
                plans.remove(&id);
            }
            ("mixer.add", Some(ep)) => {
                if let Some(p) = plans.get_mut(&id) {
                    p.seats.retain(|s| s.endpoint_id != ep);
                    let mut seat = Seat {
                        endpoint_id: ep,
                        role: "participant".into(),
                        whisper_to: None,
                        muted: false,
                        deafened: false,
                        input_gain_db: 0,
                        output_gain_db: 0,
                    };
                    set_seat(&mut seat, req);
                    p.seats.push(seat);
                }
            }
            ("mixer.remove", Some(ep)) => {
                if let Some(p) = plans.get_mut(&id) {
                    p.seats.retain(|s| s.endpoint_id != ep);
                }
            }
            ("mixer.set", Some(ep)) => {
                if let Some(s) = plans
                    .get_mut(&id)
                    .and_then(|p| p.seats.iter_mut().find(|s| s.endpoint_id == ep))
                {
                    set_seat(s, req);
                }
            }
            _ => {}
        }
        self.mark_dirty();
    }

    /// The plans of the mixers that still exist, their seats' endpoints
    /// still there (the state saved).
    pub(super) fn mixer_plans(&self) -> Vec<MixerPlan> {
        let n = &self.native;
        n.mixer_plans
            .values()
            .filter(|p| n.mixers.contains_key(&p.id))
            .map(|p| MixerPlan {
                seats: p
                    .seats
                    .iter()
                    .filter(|s| n.endpoints.contains_key(&s.endpoint_id))
                    .cloned()
                    .collect(),
                ..p.clone()
            })
            .collect()
    }

    /// After a restart: the planned mixers again, with the same ids, their
    /// restored endpoints seated as they were. What cannot come back is
    /// reported lost.
    pub(super) fn rebuild_mixers(&mut self) {
        let plans = std::mem::take(&mut self.native.pending_mixers);
        for plan in plans {
            let handle = match crate::pcm::mixer::start(plan.id, self.relay.media_event_sender()) {
                Ok(h) => h,
                Err(e) => {
                    self.native.lost.push(json!({"kind": "mixer", "mixer_id": plan.id,
                        "tenant": plan.tenant, "reason": format!("the mixer could not start: {e}")}));
                    continue;
                }
            };
            self.native.next_mixer = self.native.next_mixer.max(plan.id);
            self.native
                .mixers
                .insert(plan.id, (plan.tenant.clone(), handle));
            let mut seated = Vec::new();
            // Participants first, so a whisperer's listener is there.
            let mut seats = plan.seats.clone();
            seats.sort_by_key(|s| s.role == "whisper");
            for seat in &seats {
                match self.reseat(plan.id, &plan.tenant, seat) {
                    Ok(()) => seated.push(seat.clone()),
                    Err(e) => self.native.lost.push(json!({"kind": "mixer_participant",
                        "mixer_id": plan.id, "tenant": plan.tenant,
                        "endpoint_id": seat.endpoint_id, "reason": e.message})),
                }
            }
            log::info!(
                "native: mixer {} restored with {} of {} participants",
                plan.id,
                seated.len(),
                plan.seats.len()
            );
            self.native.restored_mixers.push(plan.id);
            self.native.mixer_plans.insert(
                plan.id,
                MixerPlan {
                    seats: seated,
                    ..plan
                },
            );
        }
        self.mark_dirty();
    }

    /// Seat `seat` in mixer `id` again.
    fn reseat(&mut self, id: u32, tenant: &str, seat: &Seat) -> Result<(), NativeError> {
        use crate::pcm::mixer::Role;
        let ep = match self.native.endpoints.get(&seat.endpoint_id) {
            Some(ep) if ep.tenant == tenant => ep.clone(),
            _ => {
                return Err(NativeError::new(
                    Code::NotFound,
                    "its endpoint was not restored",
                ));
            }
        };
        self.mixer_add(id, &ep)?;
        let Some((_, m)) = self.native.mixers.get(&id) else {
            return Err(NativeError::new(Code::NotFound, "the mixer is gone"));
        };
        let role = match (seat.role.as_str(), &seat.whisper_to) {
            ("listen", _) => Role::Listen,
            ("whisper", Some(to)) => Role::Whisper(to.clone()),
            _ => Role::Participant,
        };
        m.role(&ep.id, role);
        m.mute(&ep.id, seat.muted);
        m.deafen(&ep.id, seat.deafened);
        m.gain(&ep.id, seat.input_gain_db);
        m.output_gain(&ep.id, seat.output_gain_db);
        Ok(())
    }
}

/// A seat as `mixer.add` or `mixer.set` asks.
fn set_seat(seat: &mut Seat, req: &Request<'_>) {
    if let Some(role) = req.str("role") {
        role.clone_into(&mut seat.role);
        seat.whisper_to = req.str("whisper_to").map(str::to_owned);
    }
    if let Some(m) = req.body.get("muted").and_then(Json::as_bool) {
        seat.muted = m;
    }
    if let Some(d) = req.body.get("deafened").and_then(Json::as_bool) {
        seat.deafened = d;
    }
    if let Some(g) = gain(req, "input_gain_db").or_else(|| gain(req, "gain_db")) {
        seat.input_gain_db = g;
    }
    if let Some(g) = gain(req, "output_gain_db") {
        seat.output_gain_db = g;
    }
}
