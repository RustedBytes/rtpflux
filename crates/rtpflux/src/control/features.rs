//! `play media`/`stop media`, `play DTMF`, `start recording`/`stop
//! recording`/`pause recording`, and `block`/`unblock` and
//! `silence`/`unsilence` of media and DTMF (DTMF security is in
//! [`super::dtmf_security`]).

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::lifecycle::RecStep;
use crate::relay::ToneMode;
use parties::{Which, all_parties, side_of, tag_of};

/// When and how long `play media` plays (milliseconds).
struct PlayTimes {
    start_ms: u64,
    length_ms: Option<u64>,
    repeat_ms: Option<u64>,
    repeat: u32,
}

impl PlayTimes {
    fn of(d: &Dict<'_>) -> Self {
        let ms = |key: &[u8]| -> Option<u64> {
            super::args::number_or_none(d, key).and_then(|n| u64::try_from(n).ok())
        };
        let repeat = super::args::number_or_none(d, b"repeat-times")
            .map_or(1, |n| u32::try_from(n.max(1)).unwrap_or(u32::MAX));
        PlayTimes {
            start_ms: ms(b"start-pos").unwrap_or(0),
            length_ms: ms(b"duration").filter(|&l| l > 0),
            repeat_ms: ms(b"repeat-duration").filter(|&l| l > 0),
            repeat,
        }
    }
}

/// The media of `play media`: a file on the relay host (its path kept, to
/// go on after a restart) or the file's bytes in the request (`blob`).
fn play_source(d: &Dict<'_>) -> Result<(Option<String>, Vec<u8>), Error> {
    if let Some(blob) = d.get_bytes(b"blob") {
        return Ok((None, blob.to_vec()));
    }
    let path = d
        .get_bytes(b"file")
        .ok_or_else(|| Error::Request(RequestError::PlayNeedsFile))?;
    let path = std::str::from_utf8(path).map_err(|_| Error::Request(RequestError::FileNotUtf8))?;
    Ok((
        Some(path.to_owned()),
        read_media_file(path).map_err(Error::io(path))?,
    ))
}

impl Control {
    /// `play media` (`file`: a WAV file; `repeat-times`) to the participant
    /// `from-tag` names, in the G.711 law it receives, or `stop media`
    /// (that participant, or all of the call). While it plays, the other
    /// side's media to it is held back.
    /// The listeners `tag` names in `call_id` (every party without one):
    /// (relay call, its leg, the G.711 law that side receives).
    fn listeners(&self, call_id: &[u8], tag: Option<&[u8]>) -> Vec<(CallId, CallLeg, Option<Pt>)> {
        let mut targets = Vec::new();
        for (key, s) in &self.sessions {
            if key.0 != call_id {
                continue;
            }
            for party in [Party::A, Party::B] {
                let named = tag.is_none_or(|t| side_of(key, s, t) == Some(party));
                if named {
                    targets.extend(s.media.iter().flatten().map(|st| {
                        let law = if party == Party::B {
                            st.b_law
                        } else {
                            st.a_law
                        };
                        (st.ports.id, st.leg(party), law)
                    }));
                }
            }
        }
        targets
    }

    pub(super) fn play(&mut self, d: &Dict<'_>, on: bool) -> Result<Vec<(Vec<u8>, B)>, Error> {
        let call_id = required(d, "call-id")?.to_vec();
        // The listener, by tag or label; `all`: every party.
        let tag = self.party(d, &call_id, Which::From)?;
        if on && tag.is_none() && !all_parties(d) {
            return Err(Error::Request(RequestError::PlayNeedsListener));
        }
        let targets = self.listeners(&call_id, tag.as_deref());
        if targets.is_empty() {
            return Err(Error::UnknownCallOrTag);
        }
        let file = if on { Some(play_source(d)?) } else { None };
        let PlayTimes {
            start_ms,
            length_ms,
            repeat_ms,
            repeat,
        } = PlayTimes::of(d);
        let mut duration_ms = 0u64;
        let mut played = false;
        let now = unix_ms();
        for (id, leg, law) in targets {
            let media = match (&file, law) {
                (None, _) => None,
                (Some(_), None) => continue,
                (Some((_, bytes)), Some(pt)) => {
                    let codes = crate::media_file::load_media(bytes, pt)?;
                    let plan = crate::relay::play::plan(
                        codes.len(),
                        start_ms,
                        length_ms,
                        repeat,
                        repeat_ms,
                    )
                    .ok_or_else(|| Error::Request(RequestError::StartPastEnd))?;
                    Some(crate::relay::Playing {
                        codes: codes[plan.start..plan.start + plan.len].into(),
                        pt,
                        repeat: plan.repeat,
                        skip: 0,
                        limit: plan.limit,
                    })
                }
            };
            played |= media.is_some();
            let saved = media
                .as_ref()
                .zip(file.as_ref())
                .and_then(|(m, (path, _))| {
                    let codes = u64::try_from(m.codes.len()).unwrap_or(u64::MAX);
                    duration_ms = codes / 8;
                    // Whole frames, the last of each repetition padded.
                    let frames = codes.div_ceil(160).saturating_mul(u64::from(m.repeat));
                    let frames = m
                        .limit
                        .map_or(frames, |l| frames.min((l as u64).div_ceil(160)));
                    let total = frames * 20;
                    Some(state::SavedPlay {
                        file: path.clone()?,
                        repeat: m.repeat,
                        started_ms: now,
                        total_ms: total,
                        start_ms,
                        length_ms,
                        repeat_ms,
                    })
                });
            if let Some(m) = &media {
                duration_ms = u64::try_from(m.codes.len()).unwrap_or(u64::MAX) / 8;
            }
            self.relay.play(id, leg, media).map_err(Error::from)?;
            self.extras.entry(id).or_default().playing[leg.index()] = saved;
        }
        if on && !played {
            return Err(Error::Request(RequestError::NoG711));
        }
        // As rtpengine: the media's length, in ms.
        Ok(if on {
            vec![(b"duration".to_vec(), B::int(duration_ms))]
        } else {
            Vec::new()
        })
    }

    /// `play DTMF`: the keys of `code` (a string of `0-9 * # A-D`, or one
    /// event number) sent as if the participant `from-tag` names had
    /// pressed them: to the other side, as telephone events (RFC 4733) when
    /// it negotiated them, else as in-band tones in the G.711 law it
    /// receives. `duration` (ms, 250), `pause` between keys (ms, 100) and
    /// `volume` (below 0 dBm0, 8) as rtpengine has them: numbers out of
    /// range are clamped into it, text that is not a number is refused.
    pub(super) fn play_dtmf(&mut self, d: &Dict<'_>) -> Result<(), Error> {
        let call_id = required(d, "call-id")?.to_vec();
        let tag = self.party(d, &call_id, Which::From)?;
        if tag.is_none() && !all_parties(d) {
            return Err(Error::Missing("from-tag".to_owned()));
        }
        let codes = dtmf_codes(d.get(b"code"))?;
        let int = |key: &str,
                   default: i64,
                   range: core::ops::RangeInclusive<i64>|
         -> Result<i64, Error> {
            let v = super::args::number(d, key.as_bytes())?.unwrap_or(default);
            Ok(v.clamp(*range.start(), *range.end()))
        };
        let duration = u32::try_from(int("duration", 250, 40..=5000)?).unwrap_or(250);
        let pause = u32::try_from(int("pause", 100, 0..=5000)?).unwrap_or(100);
        let volume = u8::try_from(int("volume", 8, 0..=63)?).unwrap_or(8);
        // (call, the listener's relay leg, how it hears the tones).
        let mut targets: Vec<(CallId, CallLeg, Option<ToneMode>)> = Vec::new();
        for (key, s) in &self.sessions {
            if key.0 != call_id {
                continue;
            }
            for sender in [Party::A, Party::B] {
                // The sender, by tag or label; `all`: every party.
                let named = match &tag {
                    Some(t) => side_of(key, s, t) == Some(sender),
                    None => all_parties(d),
                };
                if !named {
                    continue;
                }
                let listener = sender.other();
                targets.extend(s.media.iter().flatten().map(|st| {
                    let (side, law) = if listener == Party::B {
                        (&st.b_side, st.b_law)
                    } else {
                        (&st.a_side, st.a_law)
                    };
                    // Events if it takes them, else tones in its audio:
                    // any codec the relay encodes (G.711 known after a
                    // restart too).
                    let g711 = law.map(|pt| {
                        let codec = if pt == PT_PCMA {
                            Codec::Pcma
                        } else {
                            Codec::Pcmu
                        };
                        (pt, codec)
                    });
                    let mode = side
                        .dtmf
                        .map(|(pt, rate)| ToneMode::Event { pt, rate })
                        .or(st.audio[usize::from(listener.is_b())]
                            .or(g711)
                            .map(|(pt, codec)| ToneMode::Inband { pt, codec }));
                    (st.ports.id, st.leg(listener), mode)
                }));
            }
        }
        if targets.is_empty() {
            return Err(Error::UnknownCallOrTag);
        }
        let mut played = false;
        for (id, leg, mode) in targets {
            let Some(mode) = mode else { continue };
            if self
                .extras
                .get(&id)
                .is_some_and(|x| x.playing[leg.index()].is_some())
            {
                return Err(Error::Request(RequestError::AnnouncementPlaying));
            }
            // An event's duration field is 16 bits of its clock.
            let max = match mode {
                ToneMode::Event { rate, .. } => {
                    u32::try_from(65_535 * 1000 / u64::from(rate.max(1))).unwrap_or(u32::MAX)
                }
                ToneMode::Inband { .. } => u32::MAX,
            };
            let tones = crate::relay::Tones {
                sine_hz: 0,
                codes: codes.clone(),
                duration_ms: duration.min(max),
                pause_ms: pause,
                volume,
                mode,
            };
            played |= self.relay.play_tones(id, leg, tones).map_err(Error::from)?;
        }
        if !played {
            return Err(Error::Request(RequestError::NoKeyPath));
        }
        Ok(())
    }

    /// `start recording` / `stop recording`: every media section of the
    /// call's dialogs (or of the one `from-tag` names, either tag) into
    /// `<dir>/<call-id>-<from-tag>-<section>.pcap`.
    pub(super) fn record(&mut self, d: &Dict<'_>, on: bool) -> Result<(), Error> {
        let dir = self.recording_dir.clone().ok_or(Error::NotConfigured(
            "recording is not configured ([recording] dir)",
        ))?;
        let call_id = required(d, "call-id")?.to_vec();
        let tag = d.get_bytes(b"from-tag");
        let settings = recording_settings(d, self.recording_settings)?;
        let metadata = self.recording_metadata(d)?;
        // (relay call, dialog, its to-tag, section, section state)
        let mut targets = Vec::new();
        for (key, s) in &self.sessions {
            let c = &key.0;
            if *c != call_id || tag.is_some_and(|t| side_of(key, s, t).is_none()) {
                continue;
            }
            for (i, st) in s.media.iter().enumerate() {
                if let Some(st) = st {
                    targets.push((st.ports.id, key.clone(), s.to_tag.clone(), i, *st));
                }
            }
        }
        if targets.is_empty() {
            return Err(Error::UnknownCallOrTag);
        }
        let (dir, template) = if on {
            self.recording_target(d, &dir)?
        } else {
            (dir, String::new())
        };
        for (id, key, to_tag, i, st) in targets {
            let extras = self.extras.entry(id).or_default();
            // `lifecycle::Rec`: a recording going on goes on (resumed if
            // paused) in its file; one started again after a stop gets a new
            // file, never the finished one's.
            let mut rec = extras.rec();
            let step = if on { rec.start() } else { rec.stop() };
            extras.set_rec(rec);
            match step {
                RecStep::Resume(_) => self
                    .relay
                    .pause_recording(id, false)
                    .map(drop)
                    .map_err(Error::from)?,
                RecStep::Open(file) => {
                    let fields = crate::recording::naming::Fields {
                        call_id: &key.0,
                        from_tag: &key.1,
                        to_tag: to_tag.as_deref(),
                        section: i + 1,
                        unix_s: super::unix_now(),
                        mixer_id: None,
                        recording_id: None,
                        track: "",
                    };
                    let base = crate::recording::naming::render(&template, &fields);
                    let path = free_path(&dir, &base, file);
                    let spec = recording_spec(
                        &key,
                        to_tag.as_deref(),
                        i,
                        &st,
                        path,
                        (settings, metadata.clone()),
                    );
                    extras.recording = Some(spec.path.to_string_lossy().into_owned());
                    extras.recording_settings = Some(settings);
                    extras.recording_metadata.clone_from(&metadata);
                    self.relay.record(id, Some(spec)).map_err(Error::from)?;
                }
                RecStep::Close(_) | RecStep::Nothing | RecStep::Pause(_) => {
                    extras.recording = None;
                    extras.recording_settings = None;
                    extras.recording_metadata.clear();
                    self.relay.record(id, None).map_err(Error::from)?;
                }
            }
        }
        Ok(())
    }

    /// `pause recording`: the call's recordings stop taking packets but stay
    /// open; `start recording` resumes them into the same files.
    pub(super) fn pause_recording(&mut self, d: &Dict<'_>) -> Result<(), Error> {
        let call_id = required(d, "call-id")?.to_vec();
        let tag = d.get_bytes(b"from-tag");
        let ids: Vec<CallId> = self
            .sessions
            .iter()
            .filter(|(key, s)| key.0 == call_id && tag.is_none_or(|t| side_of(key, s, t).is_some()))
            .flat_map(|(_, s)| s.media.iter().flatten().map(|st| st.ports.id))
            .collect();
        if ids.is_empty() {
            return Err(Error::UnknownCallOrTag);
        }
        for id in ids {
            let Some(x) = self.extras.get_mut(&id) else {
                continue;
            };
            let mut rec = x.rec();
            if let RecStep::Pause(_) = rec.pause() {
                x.set_rec(rec);
                self.relay.pause_recording(id, true).map_err(Error::from)?;
            }
        }
        Ok(())
    }

    /// `record-call` (or `record call`) on an offer or answer: `yes` starts
    /// recording the dialog (if recording is configured), `no` stops it.
    pub(super) fn record_call(&mut self, d: &Dict<'_>) {
        let v = d
            .get_bytes(b"record-call")
            .or_else(|| d.get_bytes(b"record call"));
        let on = match v.map(<[u8]>::to_ascii_lowercase).as_deref() {
            Some(b"yes" | b"on" | b"true") => true,
            Some(b"no" | b"off" | b"false") => false,
            _ => return,
        };
        if on && self.recording_dir.is_none() {
            log::warn!("record-call: recording is not configured ([recording] dir)");
            return;
        }
        if let Err(e) = self.record(d, on) {
            log::warn!("record-call: {e}");
        }
    }

    /// `block media`, `unblock media`, `block DTMF`, `unblock DTMF`: what
    /// the participant of `from-tag` sends (either tag of a dialog), or
    /// with no tag every participant of the call. Media keeps being
    /// received, counted and (for events) detected; it is not relayed.
    pub(super) fn block(&mut self, d: &Dict<'_>, what: Blocked, on: bool) -> Result<(), Error> {
        // DTMF security (`DTMF-security`, triggers, `DTMF-delay`) instead.
        if what == Blocked::Dtmf && self.block_dtmf_secure(d, on)? {
            return Ok(());
        }
        let call_id = required(d, "call-id")?.to_vec();
        // `all`: which of a party's flows (rtpengine's): `all` the whole
        // call; `offer-answer` what it sends to its dialog's other party
        // (the default); `except-offer-answer` its copies (subscriptions,
        // directional `connect`, injections); `flows` both.
        let scope = flow_scope(d, what)?;
        let whats: &[Blocked] = match (scope, what) {
            (Scope::Copies, Blocked::Media) => &[Blocked::Copies],
            (Scope::Copies, Blocked::Silence) => &[Blocked::CopiesSilence],
            (Scope::Flows, Blocked::Media) => &[Blocked::Media, Blocked::Copies],
            (Scope::Flows, Blocked::Silence) => &[Blocked::Silence, Blocked::CopiesSilence],
            _ => core::slice::from_ref(&what),
        };
        let tag = if scope == Scope::Call {
            None
        } else {
            self.party(d, &call_id, Which::From)?
        };
        // Only what it sends to this party (`to-tag`, `to-label`): its side
        // of their dialog.
        let to = if scope == Scope::Call {
            None
        } else {
            self.party(d, &call_id, Which::To)?
        };
        // (call, relay leg) of every side the request names.
        let mut targets: Vec<(CallId, CallLeg)> = Vec::new();
        for (key, s) in &self.sessions {
            if key.0 != call_id {
                continue;
            }
            for party in [Party::A, Party::B] {
                let named = tag
                    .as_deref()
                    .is_none_or(|t| side_of(key, s, t) == Some(party))
                    && to
                        .as_deref()
                        .is_none_or(|t| tag_of(key, s, party.other()) == Some(t));
                if named {
                    targets.extend(
                        s.media
                            .iter()
                            .flatten()
                            .map(|st| (st.ports.id, st.leg(party))),
                    );
                }
            }
        }
        if targets.is_empty() {
            return Err(Error::UnknownCallOrTag);
        }
        for (id, leg) in targets {
            for &what in whats {
                self.relay.block(id, leg, what, on).map_err(Error::from)?;
                self.extras.entry(id).or_default().blocked[leg.index()].set(what, on);
            }
        }
        Ok(())
    }
}

/// Which flows `all` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// `none` (or no `all`): as the other keys say.
    Default,
    /// `all` (the value or the flag): every party of the call.
    Call,
    /// `except-offer-answer`: a party's copies only.
    Copies,
    /// `flows`: its media and its copies.
    Flows,
}

/// The `all` of a block request: telephone events have no copies of
/// their own (`all: all` and `none` only).
fn flow_scope(d: &Dict<'_>, what: Blocked) -> Result<Scope, Error> {
    if list_contains(d, b"flags", b"all") {
        return Ok(Scope::Call);
    }
    let scope = match d.get_bytes(b"all") {
        None | Some(b"none" | b"offer-answer") => Scope::Default,
        Some(b"all") => Scope::Call,
        Some(b"except-offer-answer" | b"non-offer-answer") => Scope::Copies,
        Some(b"flows") => Scope::Flows,
        Some(other) => {
            return Err(Error::unsupported(format!(
                "all: {} (none, all, offer-answer, except-offer-answer, flows)",
                String::from_utf8_lossy(other)
            )));
        }
    };
    if what == Blocked::Dtmf && matches!(scope, Scope::Copies | Scope::Flows) {
        return Err(Error::unsupported(
            "all: telephone events are blocked with none or all".to_owned(),
        ));
    }
    Ok(scope)
}

/// The recording settings of `start recording`: `base` with what `d`
/// overrides (`format`, `channels`, `sample-rate`, `bitrate`, `keep-pcap`).
fn recording_settings(
    d: &Dict<'_>,
    base: crate::recording::Settings,
) -> Result<crate::recording::Settings, Error> {
    use crate::recording::{Channels, Format};
    // A number of `u32`'s range, or refused.
    let number = |key: &[u8]| -> Result<Option<u32>, Error> {
        super::args::number(d, key)?
            .map(|n| {
                u32::try_from(n).map_err(|_| {
                    Error::Request(RequestError::NotANumber(
                        String::from_utf8_lossy(key).into_owned(),
                    ))
                })
            })
            .transpose()
    };
    let mut s = base;
    if let Some(f) = d.get_bytes(b"format") {
        s.format = Format::from_name(f).ok_or_else(|| {
            Error::Request(RequestError::UnknownRecordingFormat(
                String::from_utf8_lossy(f).into_owned(),
            ))
        })?;
    }
    if let Some(c) = d.get_bytes(b"channels") {
        s.channels = Channels::from_name(c).ok_or_else(|| {
            Error::Request(RequestError::BadChannels(
                String::from_utf8_lossy(c).into_owned(),
            ))
        })?;
    }
    if let Some(r) = number(b"sample-rate")? {
        s.sample_rate = r;
    }
    if let Some(b) = number(b"bitrate")? {
        s.bitrate = b;
    }
    if let Some(k) = d.get_bytes(b"keep-pcap") {
        s.keep_pcap = matches!(k, b"yes" | b"true" | b"1");
    }
    let problems = s.problems();
    if problems.is_empty() {
        Ok(s)
    } else {
        Err(Error::Request(RequestError::Recording(problems)))
    }
}

/// What section `index` of the dialog `key` is recorded into, and what it
/// becomes when the recording ends. The caller (the relay call's A leg,
/// the dialog's first offerer) is the left channel.
pub(super) fn recording_spec(
    key: &(Vec<u8>, Vec<u8>),
    to_tag: Option<&[u8]>,
    index: usize,
    st: &MediaState,
    path: std::path::PathBuf,
    (settings, metadata): (
        crate::recording::Settings,
        std::collections::BTreeMap<String, String>,
    ),
) -> crate::recording::Spec {
    use crate::recording::{Conversion, Meta};
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    // Always: a pcap recording is not converted, but may be uploaded.
    let conversion = Some(Conversion {
        settings,
        meta: Meta {
            call_id: text(&key.0),
            from_tag: text(&key.1),
            to_tag: to_tag.map(text),
            section: index + 1,
            left_port: if st.flipped {
                st.ports.b.port()
            } else {
                st.ports.a.port()
            },
            opus_pts: st.opus.iter().flatten().map(|p| p.get()).collect(),
            amr_pts: st.amr.iter().flatten().map(|p| p.get()).collect(),
            amr_wb_pts: st.amr_wb.iter().flatten().map(|p| p.get()).collect(),
            metadata,
            mixer_id: None,
        },
    });
    crate::recording::Spec { path, conversion }
}

/// The largest file `play media` reads: over an hour of G.711, about 35
/// minutes of 16-bit 16 kHz WAV.
const MAX_MEDIA_FILE: u64 = 64 * 1024 * 1024;

/// Read an announcement file named by an `ng` client: a regular file (not
/// a device such as `/dev/zero`, nor a FIFO that would block the control
/// thread) of at most [`MAX_MEDIA_FILE`] octets, checked while reading so
/// a file that grows meanwhile is still bounded.
fn read_media_file(path: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if meta.len() > MAX_MEDIA_FILE {
        return Err(std::io::Error::other(format!(
            "larger than {MAX_MEDIA_FILE} octets"
        )));
    }
    let mut data = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.take(MAX_MEDIA_FILE + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_MEDIA_FILE {
        return Err(std::io::Error::other(format!(
            "larger than {MAX_MEDIA_FILE} octets"
        )));
    }
    Ok(data)
}

/// The event codes of a `play DTMF` `code`: a string of keys (`0-9`, `*`,
/// `#`, `A-D`, any case) or one event number (0-15).
fn dtmf_codes(code: Option<Value<'_>>) -> Result<Vec<u8>, Error> {
    let bad = || Error::Request(RequestError::BadCode);
    match code {
        None => Err(Error::Missing("code".to_owned())),
        Some(Value::Int(n)) => u8::try_from(n)
            .ok()
            .filter(|&c| c <= 15)
            .map(|c| vec![c])
            .ok_or_else(bad),
        Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= 64 => {
            // A number written as text is one event, as rtpengine reads it.
            if let Some(n) = std::str::from_utf8(b)
                .ok()
                .filter(|t| t.len() > 1)
                .and_then(|t| t.parse::<u8>().ok())
            {
                return (n <= 15).then(|| vec![n]).ok_or_else(bad);
            }
            b.iter()
                .map(|&k| match k {
                    b'0'..=b'9' => Ok(k - b'0'),
                    b'*' => Ok(10),
                    b'#' => Ok(11),
                    b'A'..=b'D' => Ok(k - b'A' + 12),
                    b'a'..=b'd' => Ok(k - b'a' + 12),
                    _ => Err(bad()),
                })
                .collect()
        }
        Some(_) => Err(bad()),
    }
}

/// The pcap of recording `file` (from 0) of a section whose name is
/// `base` ([`crate::recording::naming::render`]): the first has the plain
/// name, later ones `-2`, `-3`, …; and a name some file already has (a
/// template without the call-id, say) is never reused: the next number is
/// taken, so no recording is ever appended to another's file.
fn free_path(dir: &std::path::Path, base: &str, file: u32) -> std::path::PathBuf {
    let name = |n: u32| {
        if n == 0 {
            format!("{base}.pcap")
        } else {
            format!("{base}-{}.pcap", n + 1)
        }
    };
    let taken = |n: u32| {
        let p = dir.join(name(n));
        ["pcap", "wav", "flac", "opus", "mp3", "json"]
            .iter()
            .any(|x| p.with_extension(x).exists())
    };
    let mut n = file;
    while taken(n) && n < 10_000 {
        n += 1;
    }
    dir.join(name(n))
}

impl Control {
    /// Where the recordings `d` starts go, under the recording directory
    /// `root`: `recording-path` (a subdirectory, made if missing), and
    /// their name: `recording-file` or `output-destination` (a fixed name,
    /// perhaps with a subdirectory; a recording extension is dropped), else
    /// `recording-pattern` (a template), else `[recording] file_name`.
    /// Nothing outside `root` can be named.
    fn recording_target(
        &self,
        d: &Dict<'_>,
        root: &std::path::Path,
    ) -> Result<(std::path::PathBuf, String), Error> {
        use crate::recording::naming;
        let text = |key: &'static str| -> Result<Option<&str>, Error> {
            d.get_bytes(key.as_bytes())
                .map(|b| {
                    std::str::from_utf8(b).map_err(|_| {
                        Error::Request(RequestError::BadRecordingName(key, "not UTF-8".into()))
                    })
                })
                .transpose()
        };
        let bad = |key, why| Error::Request(RequestError::BadRecordingName(key, why));
        let mut sub = String::new();
        if let Some(p) = text("recording-path")? {
            if let Some(why) = naming::check_subdir(p) {
                return Err(bad("recording-path", why));
            }
            p.trim_end_matches('/').clone_into(&mut sub);
        }
        let fixed = match (text("recording-file")?, text("output-destination")?) {
            (Some(f), _) => Some(("recording-file", f)),
            (None, Some(f)) => Some(("output-destination", f)),
            (None, None) => None,
        };
        let template = if let Some((key, f)) = fixed {
            let (dir_part, name) = f.rsplit_once('/').unwrap_or(("", f));
            if !dir_part.is_empty() {
                if let Some(why) = naming::check_subdir(dir_part) {
                    return Err(bad(key, why));
                }
                sub = if sub.is_empty() {
                    dir_part.to_owned()
                } else {
                    format!("{sub}/{dir_part}")
                };
                if let Some(why) = naming::check_subdir(&sub) {
                    return Err(bad(key, why));
                }
            }
            let name = naming::strip_extension(name);
            if let Some(why) = naming::check_fixed_name(name) {
                return Err(bad(key, why));
            }
            name.to_owned()
        } else if let Some(p) = text("recording-pattern")? {
            if let Some(why) = naming::check_file_name(p) {
                return Err(bad("recording-pattern", why));
            }
            p.to_owned()
        } else {
            self.recording_file_name.clone()
        };
        let dir = if sub.is_empty() {
            root.to_path_buf()
        } else {
            let dir = root.join(&sub);
            std::fs::create_dir_all(&dir)
                .map_err(|e| bad("recording-path", format!("cannot create {sub}: {e}")))?;
            // Each level a real directory, never a link out of `root`.
            let mut at = root.to_path_buf();
            for part in sub.split('/') {
                at.push(part);
                if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_dir()) {
                    return Err(bad("recording-path", format!("{sub}: not a directory")));
                }
            }
            dir
        };
        Ok((dir, template))
    }

    /// The metadata of a recording `d` starts: `[recording.metadata]`, with
    /// what `d`'s `metadata` (a dictionary of strings; a string is the
    /// `comment`) adds or overrides.
    fn recording_metadata(
        &self,
        d: &Dict<'_>,
    ) -> Result<std::collections::BTreeMap<String, String>, Error> {
        let mut m = self.recording_meta.clone();
        let bad = |why: String| Error::Request(RequestError::BadMetadata(why));
        let text = |b: &[u8]| {
            std::str::from_utf8(b)
                .map(str::to_owned)
                .map_err(|_| bad("not UTF-8".to_owned()))
        };
        match d.get(b"metadata") {
            None => {}
            Some(Value::Bytes(b)) => {
                m.insert("comment".to_owned(), text(b)?);
            }
            Some(Value::Dict(x)) => {
                for (k, v) in x {
                    let v = match v {
                        Value::Bytes(b) => text(b)?,
                        Value::Int(n) => n.to_string(),
                        _ => return Err(bad("values are strings".to_owned())),
                    };
                    m.insert(text(k)?, v);
                }
            }
            Some(_) => return Err(bad("a dictionary of strings".to_owned())),
        }
        if let Some(why) = crate::recording::naming::check_metadata(&m) {
            return Err(bad(why));
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_regular_files_are_read() {
        let dir = std::env::temp_dir().join(format!("rtpflux-media-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("ok.raw");
        std::fs::write(&ok, [0xff; 320]).unwrap();
        assert_eq!(read_media_file(ok.to_str().unwrap()).unwrap().len(), 320);
        for bad in ["/dev/zero", "/dev/null", dir.to_str().unwrap()] {
            assert!(read_media_file(bad).is_err(), "{bad}");
        }
        let big = dir.join("big.raw");
        let f = std::fs::File::create(&big).unwrap();
        f.set_len(MAX_MEDIA_FILE + 1).unwrap();
        let e = read_media_file(big.to_str().unwrap()).unwrap_err();
        assert!(e.to_string().contains("larger than"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
