//! Writing the dialogs to the state file and restoring them
//! ([`crate::state`]).

#[allow(clippy::wildcard_imports)]
use super::*;

/// A snapshot read from `what`, if there is one of this version.
fn usable_state(what: &str, read: std::io::Result<Option<state::Saved>>) -> Option<state::Saved> {
    match read {
        Ok(Some(s)) if s.version == state::VERSION => Some(s),
        Ok(Some(s)) => {
            log::warn!(
                "state: {what} has version {}, not {}; ignored",
                s.version,
                state::VERSION
            );
            None
        }
        Ok(None) => None,
        Err(e) => {
            log::warn!("state: reading {what}: {e}");
            None
        }
    }
}

/// Rename an unusable state file to `<name>.bad` (replacing an older
/// one), so that the relay's next write does not destroy it.
fn set_aside(path: &std::path::Path) {
    let mut bad = path.as_os_str().to_owned();
    bad.push(".bad");
    let bad = std::path::PathBuf::from(bad);
    match std::fs::rename(path, &bad) {
        Ok(()) => log::warn!(
            "state: {} cannot be used; kept as {}",
            path.display(),
            bad.display()
        ),
        Err(e) => log::warn!("state: keeping {} aside: {e}", path.display()),
    }
}

/// A saved session's key and `to-tag`.
fn saved_tags(s: &state::SavedSession) -> Option<(SessionKey, Option<Vec<u8>>)> {
    let key = (state::unhex(&s.call_id)?, state::unhex(&s.from_tag)?);
    let to_tag = match &s.to_tag {
        Some(t) => Some(state::unhex(t)?),
        None => None,
    };
    Some((key, to_tag))
}

/// The parties' SDPs of a saved session.
fn restored_sdps(s: &state::SavedSession) -> Vec<(Vec<u8>, Vec<u8>)> {
    s.sdps
        .iter()
        .filter_map(|(t, d)| Some((state::unhex(t)?, d.clone().into_bytes())))
        .collect()
}

/// A session's `o=` versions, legacy OSRTP patterns and `via-branch`, as
/// saved.
type SavedMeta = (
    Vec<(Option<String>, u64, u64, u64)>,
    Vec<Vec<bool>>,
    Option<String>,
);

fn saved_meta(s: &Session) -> SavedMeta {
    let versions = s
        .versions
        .iter()
        .map(|(o, v, sess, input)| (o.as_deref().map(state::hex), *v, *sess, *input))
        .collect();
    let legacy = if s.legacy.iter().any(|l| !l.is_empty()) {
        s.legacy.to_vec()
    } else {
        Vec::new()
    };
    (versions, legacy, s.via_branch.as_deref().map(state::hex))
}

/// The `o=` versions of a saved session.
fn restored_versions(s: &state::SavedSession) -> sdp_edits::Versions {
    s.versions
        .iter()
        .filter_map(|(o, v, sess, input)| {
            let origin = match o {
                Some(o) => Some(state::unhex(o)?),
                None => None,
            };
            Some((origin, *v, *sess, *input))
        })
        .collect()
}

impl Control {
    /// Dialog `s` (stored under `key`) as saved, with its pending
    /// checkpoint (`track-state`).
    fn saved_session(&mut self, key: &SessionKey, s: &Session, live: bool) -> state::SavedSession {
        let (versions, legacy, via_branch) = saved_meta(s);
        let sdps: Vec<(String, String)> = s
            .sdps
            .iter()
            .map(|(t, d)| (state::hex(t), String::from_utf8_lossy(d).into_owned()))
            .collect();
        let media = s
            .media
            .iter()
            .map(|st| st.as_ref().map(|st| self.saved_media(st, live)))
            .collect();
        let checkpoint = s
            .checkpoint
            .as_ref()
            .map(|c| Box::new(self.saved_session(&c.0, &c.1, false)));
        state::SavedSession {
            call_id: state::hex(&key.0),
            from_tag: state::hex(&key.1),
            to_tag: s.to_tag.as_deref().map(state::hex),
            created: s.created,
            dir: s.dir.map(InterfaceId::get),
            media,
            sdps,
            versions,
            legacy,
            via_branch,
            checkpoint,
        }
    }

    /// A media section as saved, with the peers the worker learned.
    /// `live`: with the addresses the worker learned (a checkpoint's are
    /// as agreed: the relay call has the re-offer's).
    fn saved_media(&mut self, st: &MediaState, live: bool) -> state::SavedMedia {
        let legs = if live {
            self.relay.query(st.ports.id)
        } else {
            None
        };
        let peer = |i: usize| legs.as_ref().and_then(|l| l[i].peer);
        let (la, lb) = (st.leg(Party::A).rtp_slot(), st.leg(Party::B).rtp_slot());
        // Each endpoint's ICE, for the relay's agents.
        let ice_peer = |party: Party| {
            self.ice
                .get(&(st.ports.id, st.leg(party)))
                .map(|e| state::SavedIcePeer::of(&e.peer))
        };
        state::SavedMedia {
            port_a: st.ports.a.port(),
            port_b: st.ports.b.port(),
            a: state::SavedSide {
                ice_peer: ice_peer(Party::A),
                ..state::SavedSide::of(&st.a_side, (peer(la), peer(la + 1)))
            },
            b: state::SavedSide {
                ice_peer: ice_peer(Party::B),
                ..state::SavedSide::of(&st.b_side, (peer(lb), peer(lb + 1)))
            },
            flipped: st.flipped,
            a_transport: st.a_transport.name().unwrap_or("other").to_owned(),
            b_transport: st.b_transport.name().unwrap_or("other").to_owned(),
            a_tag: st.a_tag,
            a_mux: st.a_mux,
            mux: st.mux,
            mid: st
                .mid
                .as_ref()
                .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned()),
            group: st.group,
            payload_types: st
                .payload_types
                .as_slice()
                .iter()
                .map(|p| p.get())
                .collect(),
            laws: (st.a_law.map(Pt::get), st.b_law.map(Pt::get)),
            audio: st
                .audio
                .map(|a| a.map(|(pt, c)| (pt.get(), c.name().to_owned()))),
            opus: st.opus.map(|p| p.map(Pt::get)),
            amr: st.amr.map(|p| p.map(Pt::get)),
            amr_wb: st.amr_wb.map(|p| p.map(Pt::get)),
            extras: self.saved_extras(st.ports.id),
            pending: st.pending(),
        }
    }

    /// The dialogs as a file record, with the peers the workers learned.
    pub(super) fn snapshot(&mut self) -> state::Saved {
        let keys: Vec<(Vec<u8>, Vec<u8>)> = self.sessions.keys().cloned().collect();
        let mut sessions = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(s) = self.sessions.get(&key).cloned() else {
                continue;
            };
            sessions.push(self.saved_session(&key, &s, true));
        }
        state::Saved {
            version: state::VERSION,
            saved_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            sessions,
            subscriptions: self.saved_subscriptions(),
            // Those whose parties are both still there.
            connections: self
                .connections
                .iter()
                .filter(|(a, b)| {
                    self.party_legs(&a.0, &a.1).is_some() && self.party_legs(&b.0, &b.1).is_some()
                })
                .map(|(a, b)| [a, b].map(|p| (state::hex(&p.0), state::hex(&p.1))))
                .collect(),
            copies: self
                .copies
                .iter()
                .filter(|(a, b, _)| {
                    self.party_legs(&a.0, &a.1).is_some() && self.party_legs(&b.0, &b.1).is_some()
                })
                .map(|(a, b, both)| ([a, b].map(|p| (state::hex(&p.0), state::hex(&p.1))), *both))
                .collect(),
            labels: self
                .labels
                .iter()
                .flat_map(|(call, list)| {
                    list.iter()
                        .map(move |(tag, label)| [call, tag, label].map(|x| state::hex(x)))
                })
                .collect(),
            endpoints: self.saved_endpoints(),
        }
    }

    /// Write the dialogs to the state file and hand them to the Redis
    /// writer, whichever are set (Redis is written in the background).
    pub fn save(&mut self) {
        if self.state_file.is_none() && self.state_redis.is_none() {
            return;
        }
        let snapshot = self.snapshot();
        match snapshot.encode() {
            Ok(bytes) => {
                if let Some(path) = &self.state_file {
                    self.stats.state_writes.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = state::write_bytes(path, &bytes) {
                        self.stats
                            .state_write_failures
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!("state: writing {}: {e}", path.display());
                    }
                }
                if let Some(w) = &self.state_redis {
                    w.put(bytes);
                }
            }
            Err(e) => log::warn!("state: encoding: {e}"),
        }
        self.state_dirty = false;
        self.state_written = Instant::now();
    }

    /// The dialogs changed: the state is written soon
    /// ([`Control::flush_state`]).
    pub(super) fn mark_dirty(&mut self) {
        self.state_dirty = self.state_file.is_some() || self.state_redis.is_some();
    }

    /// Write the state file if the dialogs changed and it was last written
    /// at least a second ago: a busy relay writes it once a second, not
    /// after every command (each write asks every call's worker for its
    /// learned peers).
    pub fn flush_state(&mut self) {
        if self.state_dirty && self.state_written.elapsed() >= Duration::from_secs(1) {
            self.save();
        }
    }

    /// Recreate the saved dialogs on their old ports, from the newer of
    /// the state file and Redis; returns how many were restored. Dialogs
    /// that cannot be restored are logged and skipped.
    pub fn restore(&mut self) -> usize {
        let file = self.state_file.as_ref().and_then(|path| {
            let what = path.display().to_string();
            let read = state::read(path);
            // A file that is there but cannot be used is kept aside: the
            // next write would replace it, and with it any chance of
            // recovering the calls by hand.
            let unusable = match &read {
                Err(e) => e.kind() == std::io::ErrorKind::InvalidData,
                Ok(Some(s)) => s.version != state::VERSION,
                Ok(None) => false,
            };
            if unusable {
                set_aside(path);
            }
            usable_state(&what, read)
        });
        let redis = self.state_redis.as_ref().and_then(|w| {
            let t = w.target();
            usable_state(
                &t.describe(),
                t.get()
                    .and_then(|v| v.as_deref().map(state::Saved::decode).transpose()),
            )
        });
        let Some(saved) = state::newer(file, redis) else {
            return 0;
        };
        let mut restored = 0;
        for s in saved.sessions {
            match self.restore_session(&s) {
                Ok(()) => restored += 1,
                Err(e) => log::warn!(
                    "state: call {}: not restored: {e}",
                    String::from_utf8_lossy(&state::unhex(&s.call_id).unwrap_or_default())
                ),
            }
        }
        for [call, tag, label] in &saved.labels {
            if let (Some(c), Some(t), Some(l)) =
                (state::unhex(call), state::unhex(tag), state::unhex(label))
            {
                self.labels.entry(c).or_default().push((t, l));
            }
        }
        // Connections, once both their calls are back.
        for c in &saved.connections {
            let party =
                |(call, tag): &(String, String)| Some((state::unhex(call)?, state::unhex(tag)?));
            let (Some(a), Some(b)) = (party(&c[0]), party(&c[1])) else {
                continue;
            };
            if let Err(e) = self.connect_parties(&a, &b) {
                log::warn!(
                    "state: call {}: connection not restored: {e}",
                    String::from_utf8_lossy(&a.0)
                );
            }
        }
        for (c, both) in &saved.copies {
            let party =
                |(call, tag): &(String, String)| Some((state::unhex(call)?, state::unhex(tag)?));
            let (Some(a), Some(b)) = (party(&c[0]), party(&c[1])) else {
                continue;
            };
            if let Err(e) = self.copy_party(&a, &b, *both) {
                log::warn!(
                    "state: call {}: copies not restored: {e}",
                    String::from_utf8_lossy(&a.0)
                );
            }
        }
        self.restore_endpoints(&saved.endpoints);
        for s in &saved.subscriptions {
            if let Err(e) = self.restore_subscription(s) {
                log::warn!(
                    "state: call {}: subscription not restored: {e}",
                    String::from_utf8_lossy(&state::unhex(&s.call_id).unwrap_or_default())
                );
            }
        }
        self.gauges();
        restored
    }

    pub(super) fn restore_session(&mut self, s: &state::SavedSession) -> Result<(), Error> {
        let (key, mut session) = self.restored_session(s, &[])?;
        // A re-offer's checkpoint: on the dialog's relay calls (the same
        // ports), and those the re-offer removed.
        if let Some(cp) = &s.checkpoint {
            let shared: Vec<MediaState> = session.media.iter().flatten().copied().collect();
            match self.restored_session(cp, &shared) {
                Ok((k, c)) => session.checkpoint = Some(Box::new((k, c))),
                Err(e) => log::warn!(
                    "state: call {}: the re-offer's checkpoint not restored: {e}",
                    String::from_utf8_lossy(&key.0)
                ),
            }
        }
        self.sessions.insert(key.clone(), session);
        self.update_holds(&key);
        Ok(())
    }

    /// The media section saved as `m`: on its relay call in common with
    /// `shared` (the same ports, in this dialog's order), or on one made
    /// again (true).
    fn restored_section(
        &mut self,
        m: &state::SavedMedia,
        shared: &[MediaState],
    ) -> Result<(MediaState, bool), Error> {
        let bad = || Error::State(StateError::UnreadableEntry);
        let (a_side, b_side) = (m.a.side().ok_or_else(bad)?, m.b.side().ok_or_else(bad)?);
        let common = shared.iter().find_map(|sh| {
            let (pa, pb) = (sh.ports.a.port(), sh.ports.b.port());
            if (pa, pb) == (m.port_a, m.port_b) {
                Some(sh.ports)
            } else if (pb, pa) == (m.port_a, m.port_b) {
                Some(CallPorts {
                    a: sh.ports.b,
                    b: sh.ports.a,
                    ..sh.ports
                })
            } else {
                None
            }
        });
        let made_here = common.is_none();
        let ports = match common {
            Some(p) => p,
            // The relay call's legs in its own order.
            None if m.flipped => {
                let p = self
                    .relay
                    .restore_call(b_side, a_side, m.port_b, m.port_a)
                    .map_err(Error::Relay)?;
                CallPorts {
                    a: p.b,
                    b: p.a,
                    ..p
                }
            }
            None => self
                .relay
                .restore_call(a_side, b_side, m.port_a, m.port_b)
                .map_err(Error::Relay)?,
        };
        let mut st = MediaState::restored(ports, m, &a_side, &b_side);
        if let Some(p) = &m.pending {
            st.restore_pending(p);
        }
        Ok((st, made_here))
    }

    /// The dialog saved as `s`, on its relay calls made again, but for
    /// those it has in common with `shared` (a checkpoint's with its
    /// dialog's: the same ports), which are taken as they are.
    fn restored_session(
        &mut self,
        s: &state::SavedSession,
        shared: &[MediaState],
    ) -> Result<(SessionKey, Session), Error> {
        let bad = || Error::State(StateError::UnreadableEntry);
        let (key, to_tag) = saved_tags(s).ok_or_else(bad)?;
        if s.dir.iter().any(|&i| i >= self.interfaces.len()) {
            return Err(Error::State(StateError::GoneInterface));
        }
        if s.media
            .iter()
            .flatten()
            .any(|m| m.group.is_some_and(|g| g >= s.media.len()))
        {
            return Err(bad());
        }
        let mut states: Vec<Option<MediaState>> = Vec::with_capacity(s.media.len());
        // Which of `states` this made (the others are `shared`'s).
        let mut fresh: Vec<bool> = Vec::with_capacity(s.media.len());
        let made = |states: &[Option<MediaState>], fresh: &[bool]| -> Vec<Option<MediaState>> {
            states
                .iter()
                .zip(fresh)
                .map(|(st, &f)| st.filter(|_| f))
                .collect()
        };
        for m in &s.media {
            let Some(m) = m else {
                states.push(None);
                fresh.push(false);
                continue;
            };
            match self.restored_section(m, shared) {
                Ok((st, made_here)) => {
                    states.push(Some(st));
                    fresh.push(made_here);
                }
                Err(e) => {
                    let mine = made(&states, &fresh);
                    self.end_session(&Session::bare(s.dir.map(InterfaceId::new), mine));
                    return Err(e);
                }
            }
        }
        // (A checkpoint's group is its dialog's, already set.)
        if let Some(p) = states
            .iter()
            .flatten()
            .find_map(|st| st.group)
            .and_then(|g| states.get(g).copied().flatten())
            .filter(|_| shared.is_empty())
        {
            let group: Vec<(CallId, Vec<Pt>)> = states
                .iter()
                .flatten()
                .filter(|st| st.group.is_some())
                .map(|st| (st.ports.id, st.payload_types.as_slice().to_vec()))
                .collect();
            if let Err(e) = self.relay.bundle(p.ports.id, &group) {
                let mine = made(&states, &fresh);
                self.end_session(&Session::bare(s.dir.map(InterfaceId::new), mine));
                return Err(Error::Relay(e));
            }
        }
        // An offer never answered waits for its answer again.
        if to_tag.is_none() {
            for st in made(&states, &fresh).iter().flatten() {
                let id = st.ports.id;
                Self::logged(
                    "waiting for its answer",
                    id,
                    self.relay.awaiting_answer(id, Some(self.offer_timeout)),
                );
            }
        }
        for (i, (m, st)) in s.media.iter().zip(&made(&states, &fresh)).enumerate() {
            if let (Some(m), Some(st)) = (m, st) {
                self.restore_extras(&key, to_tag.as_deref(), i, st, &m.extras);
                self.ice_restored(st, m, to_tag.is_some());
            }
        }
        log::info!(
            "state: call {} restored ({} media section(s))",
            String::from_utf8_lossy(&key.0),
            states.iter().flatten().count()
        );
        let session = Session {
            created: s.created,
            generation: self.new_generation(),
            to_tag,
            dir: s.dir.map(InterfaceId::new),
            media: states,
            sdps: restored_sdps(s),
            versions: restored_versions(s),
            legacy: [0, 1].map(|i| s.legacy.get(i).cloned().unwrap_or_default()),
            via_branch: s.via_branch.as_deref().and_then(state::unhex),
            checkpoint: None,
        };
        Ok((key, session))
    }

    /// What to save of relay call `id`: its extras, without an
    /// announcement that is over.
    pub(super) fn saved_extras(&self, id: CallId) -> state::SavedExtras {
        let mut x = self.extras.get(&id).cloned().unwrap_or_default();
        let now = unix_ms();
        for p in &mut x.playing {
            if p.as_ref().is_some_and(|p| p.elapsed(now).is_none()) {
                *p = None;
            }
        }
        x
    }

    /// Block again on relay call `id` what each leg's `blocked` bits say.
    fn restore_blocked(&mut self, id: CallId, blocked: [crate::relay::Blocks; 2]) {
        for (leg, blocks) in blocked.into_iter().enumerate() {
            for what in blocks.kinds() {
                if let Err(e) = self.relay.block(id, CallLeg::of_b(leg == 1), what, true) {
                    log::warn!("state: call {id}: blocking: {e}");
                }
            }
        }
    }

    /// Set `x` again on the restored relay call of `st`.
    pub(super) fn restore_extras(
        &mut self,
        key: &(Vec<u8>, Vec<u8>),
        to_tag: Option<&[u8]>,
        index: usize,
        st: &MediaState,
        x: &state::SavedExtras,
    ) {
        let id = st.ports.id;
        if x.dtmf_security.iter().any(Option::is_some) {
            self.restore_security(st, x.dtmf_security);
        }
        if x.echo != [0, 0] {
            let legs = x.echo.map(crate::relay::Echo::of_code);
            if let Err(e) = self.relay.echo(id, legs) {
                log::warn!("state: call {id}: media echo: {e}");
            }
        }
        self.restore_blocked(id, x.blocked);
        let settings = x.recording_settings.unwrap_or(self.recording_settings);
        if let Some(path) = &x.recording
            && let Err(e) = self.relay.record(
                id,
                Some(super::features::recording_spec(
                    key,
                    to_tag,
                    index,
                    st,
                    path.into(),
                    (settings, x.recording_metadata.clone()),
                )),
            )
        {
            log::warn!("state: call {id}: recording: {e}");
        }
        if x.recording.is_some()
            && x.recording_paused
            && let Err(e) = self.relay.pause_recording(id, true)
        {
            log::warn!("state: call {id}: pausing the recording: {e}");
        }
        let now = unix_ms();
        let mut kept = state::SavedExtras {
            playing: [None, None],
            ..x.clone()
        };
        for (leg, p) in x.playing.iter().enumerate() {
            let Some(p) = p else { continue };
            let Some(elapsed) = p.elapsed(now) else {
                continue;
            };
            // The law the leg receives: logical side B is the relay's B leg
            // unless the dialog's roles were swapped.
            let law = if (leg == 1) == st.flipped {
                st.a_law
            } else {
                st.b_law
            };
            let Some(pt) = law else { continue };
            let media = std::fs::read(&p.file)
                .map_err(Box::<dyn std::error::Error>::from)
                .and_then(|b| crate::media_file::load_media(&b, pt).map_err(Into::into));
            let codes = match media {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("state: call {id}: announcement {}: {e}", p.file);
                    continue;
                }
            };
            // 8 codes a millisecond, in whole 20 ms packets.
            let skip = usize::try_from(elapsed / 20 * 160).unwrap_or(usize::MAX);
            let Some(plan) = crate::relay::play::plan(
                codes.len(),
                p.start_ms,
                p.length_ms,
                p.repeat,
                p.repeat_ms,
            ) else {
                continue;
            };
            let playing = crate::relay::Playing {
                codes: codes[plan.start..plan.start + plan.len].into(),
                pt,
                repeat: plan.repeat,
                skip,
                limit: plan.limit,
            };
            match self.relay.play(id, CallLeg::of_b(leg == 1), Some(playing)) {
                Ok(_) => kept.playing[leg] = Some(p.clone()),
                Err(e) => log::warn!("state: call {id}: announcement: {e}"),
            }
        }
        if !kept.is_empty() {
            self.extras.insert(id, kept);
        }
    }
}
