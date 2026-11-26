//! DTMF security and delay on a leg ([`crate::relay::dtmf_security`]):
//! the keys a party presses, as telephone events or in-band tones, are
//! passed, dropped, or replaced towards the other party, and with
//! `DTMF-delay` reach it later.
//!
//! - **Events.** An event's code is rewritten in place (another key), the
//!   event dropped, or (silence, tone) dropped while the listener hears the
//!   replacement in its audio from the tone player for as long as the key
//!   is held. Delayed, the event is replayed from a small queue: as events
//!   when the listener takes them, else as tones in its audio.
//! - **In-band tones.** The party's audio is searched for keys (G.711 as
//!   it is, other codecs decoded). While a key is held, the tone player
//!   sends the replacement (silence, a tone, the other key's tones) in its
//!   place and holds the party's own audio back. Detection takes a frame
//!   or two, so the first tens of milliseconds of a key pass. Delayed, the
//!   key is replaced by silence and then played after the delay (or once
//!   it is over, if longer), for as long as it was held.
//!
//! The state is made when the proxy sets it (`block DTMF`, `DTMF-delay`),
//! never while relaying; the delay queue is a fixed array.

use super::dtmf_xcode::{AudioIn, MAX_PCM};
use super::tones::{SILENCE, SINE};
#[allow(clippy::wildcard_imports)]
use super::*;
use crate::relay::dtmf_security::{Action, DtmfSecurity, State};
use crate::relay::xcode::EventTones;
use rtpflux_core::dtmf_inband::{Change, Detector, FRAME};

/// Keys waiting for their delay, per leg.
const QUEUE: usize = 16;

/// A delayed key: an event's start and end (live keys), or an in-band key
/// of a known length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delayed {
    Start(u8),
    End,
    Key { code: u8, ms: u32 },
}

/// A leg's DTMF security.
#[derive(Debug)]
pub(super) struct SecureLeg {
    sec: DtmfSecurity,
    state: State,
    events: EventTones,
    /// What becomes of the event being received (a random key stays the
    /// same over its packets).
    event: Option<Action>,
    detector: Detector,
    audio_in: Option<Box<AudioIn>>,
    /// The in-band key being replaced: its replacement code, action and
    /// start (worker ms).
    inband: Option<(u8, Action, u64)>,
    queue: [Option<(u64, Delayed)>; QUEUE],
}

impl SecureLeg {
    pub(super) fn new(sec: DtmfSecurity, seed: u64) -> Box<Self> {
        Box::new(SecureLeg {
            sec,
            state: State::new(sec.plan, seed),
            events: EventTones::default(),
            event: None,
            detector: Detector::default(),
            audio_in: sec.own_audio.and_then(|(_, c)| AudioIn::new(c)),
            inband: None,
            queue: [None; QUEUE],
        })
    }

    /// When something is due next: a delayed key, or a trigger's end.
    fn next_ms(&self) -> Option<u64> {
        self.queue
            .iter()
            .flatten()
            .map(|(t, _)| *t)
            .chain(self.state.next_ms())
            .min()
    }

    /// Queue `what` for `at`; false when the queue is full.
    fn delay(&mut self, at: u64, what: Delayed) -> bool {
        match self.queue.iter_mut().find(|q| q.is_none()) {
            Some(q) => {
                *q = Some((at, what));
                true
            }
            None => false,
        }
    }
}

impl Worker {
    /// Set (or remove) the DTMF security of RTP slot `slot`.
    pub(super) fn secure_dtmf(&mut self, call: CallId, leg: CallLeg, sec: Option<DtmfSecurity>) {
        let Some(c) = self.calls.get(&call) else {
            return;
        };
        let slot = c.slots[leg.rtp_slot()];
        let seed = self.now_ms() ^ (u64::from(slot.get()) << 32) ^ u64::from(std::process::id());
        if let Some(s) = self.secure.get_mut(slot) {
            *s = sec.map(|sec| SecureLeg::new(sec, seed));
        }
        self.secure_slots.retain(|&s| s != slot);
        if sec.is_some() {
            self.secure_slots.push(slot);
        }
        // Keys are looked at here: the call stays in userspace.
        self.refresh_offload(call);
    }

    /// Whether `slot`'s keys are secured.
    pub(super) fn secured(&self, slot: Slot) -> bool {
        self.secure.get(slot).is_some_and(Option::is_some)
    }

    /// The RTP packet at `bufs[at..at + len]` from `leg`, whose keys are
    /// secured: true when it is consumed (not relayed).
    pub(super) fn dtmf_secure(&mut self, leg: Slot, (at, len): (usize, usize), now: u64) -> bool {
        let Some(partner) = self.legs.get(leg).copied().flatten().map(|l| l.partner) else {
            return false;
        };
        let Some(call) = self.call_of(leg) else {
            return false;
        };
        let Ok(p) = rtpflux_core::rtp::Packet::parse(&self.bufs[at..at + len]) else {
            return false;
        };
        let (pt, ts) = (p.payload_type(), p.timestamp());
        let payload_at = at + p.as_bytes().len() - p.payload().len() - p.padding();
        let event_pt = self.dtmf.get(leg).and_then(Option::as_ref).map(|d| d.pt);
        if event_pt == Some(pt) {
            let payload = p.payload();
            if payload.len() < 4 {
                return true;
            }
            let (code, end) = (payload[0], payload[1] & 0x80 != 0);
            return self.secure_event(leg, (call, partner), (ts, code, end), payload_at, now);
        }
        self.secure_inband(leg, (call, partner), (at, len), now);
        false
    }

    /// An event packet (`ts`, `code`, `end`) of `leg`, its payload at
    /// `bufs[payload_at..]`: true when consumed.
    fn secure_event(
        &mut self,
        leg: Slot,
        (call, partner): (CallId, Slot),
        (ts, code, end): (u32, u8, bool),
        payload_at: usize,
        now: u64,
    ) -> bool {
        let Some(Some(s)) = self.secure.get_mut(leg) else {
            return false;
        };
        let (start, ends) = s.events.packet(ts, code, end);
        if let Some(c) = start {
            s.event = Some(s.state.key(c, now));
        }
        let action = s.event.unwrap_or(Action::Pass);
        let delay = u64::from(s.sec.plan.delay_ms);
        let sound = s.sec.listener_audio;
        let (volume, hz) = (s.sec.plan.volume, s.sec.plan.tone_hz);
        match action {
            Action::Pass | Action::Replace(_) if delay > 0 => {
                let code = match action {
                    Action::Replace(k) => k,
                    _ => code,
                };
                let mut queued = true;
                if start.is_some() {
                    queued &= s.delay(now + delay, Delayed::Start(code));
                }
                if ends {
                    queued &= s.delay(now + delay, Delayed::End);
                }
                if !queued {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
                true
            }
            Action::Pass => false,
            Action::Replace(k) => {
                if let Some(b) = self.bufs.get_mut(payload_at) {
                    *b = k;
                }
                false
            }
            Action::Drop => true,
            Action::Silence | Action::Tone => {
                if let Some((pt, codec)) = sound {
                    let what = if action == Action::Tone {
                        (SINE, hz)
                    } else {
                        (SILENCE, 0)
                    };
                    if start.is_some() {
                        self.live_sound_start(
                            call,
                            (partner, leg),
                            what,
                            volume,
                            ToneMode::Inband { pt, codec },
                        );
                    }
                    if ends {
                        self.live_tone_end(partner);
                    }
                }
                true
            }
        }
    }

    /// The audio packet at `bufs[at..at + len]` from `leg`: its in-band
    /// keys found, and replaced or delayed.
    fn secure_inband(
        &mut self,
        leg: Slot,
        (call, partner): (CallId, Slot),
        (at, len): (usize, usize),
        now: u64,
    ) {
        let Ok(p) = rtpflux_core::rtp::Packet::parse(&self.bufs[at..at + len]) else {
            return;
        };
        let pt = p.payload_type();
        let Some(Some(s)) = self.secure.get_mut(leg) else {
            return;
        };
        let law = pt == rtpflux_core::g711::PT_PCMU || pt == rtpflux_core::g711::PT_PCMA;
        let coded = !law && s.sec.own_audio.is_some_and(|(apt, _)| apt == pt);
        if !law && !coded {
            return;
        }
        let payload = p.payload();
        let mut pcm = [0i16; MAX_PCM];
        let n = if law {
            let n = payload.len().min(MAX_PCM);
            for (o, &c) in pcm.iter_mut().zip(&payload[..n]) {
                *o = if pt == rtpflux_core::g711::PT_PCMA {
                    rtpflux_core::g711::alaw_to_linear(c)
                } else {
                    rtpflux_core::g711::ulaw_to_linear(c)
                };
            }
            n
        } else {
            s.audio_in
                .as_mut()
                .and_then(|a| a.decode(payload, &mut pcm))
                .unwrap_or(0)
        };
        let mut changes = [None; MAX_PCM / FRAME];
        for (k, chunk) in pcm[..n].chunks(FRAME).enumerate() {
            changes[k] = s.detector.frame(chunk);
        }
        for c in changes.into_iter().flatten() {
            self.inband_change(leg, (call, partner), c, now);
        }
    }

    /// A key of `leg`'s audio starts or ends.
    fn inband_change(&mut self, leg: Slot, (call, partner): (CallId, Slot), c: Change, now: u64) {
        let Some(Some(s)) = self.secure.get_mut(leg) else {
            return;
        };
        let delay = u64::from(s.sec.plan.delay_ms);
        let (volume, hz) = (s.sec.plan.volume, s.sec.plan.tone_hz);
        let Some((pt, codec)) = s.sec.listener_audio else {
            // Nothing to replace it with: the triggers still see it.
            if let Change::Start(code) = c {
                s.state.key(code, now);
            }
            return;
        };
        match c {
            Change::Start(code) => {
                let action = s.state.key(code, now);
                // What the listener hears meanwhile: with a delay, silence
                // (the key comes later).
                let (sound, replaced) = match action {
                    Action::Drop => return,
                    Action::Pass if delay == 0 => return,
                    Action::Pass | Action::Silence => ((SILENCE, 0), code),
                    Action::Replace(k) if delay > 0 => ((SILENCE, 0), k),
                    Action::Replace(k) => ((k, 0), k),
                    Action::Tone => ((SINE, hz), code),
                };
                s.inband = Some((replaced, action, now));
                self.live_sound_start(
                    call,
                    (partner, leg),
                    sound,
                    volume,
                    ToneMode::Inband { pt, codec },
                );
            }
            Change::End => {
                let Some((code, action, started)) = s.inband.take() else {
                    return;
                };
                if delay > 0 && matches!(action, Action::Pass | Action::Replace(_)) {
                    let ms = u32::try_from(now.saturating_sub(started)).unwrap_or(u32::MAX);
                    let at = (started + delay).max(now);
                    if !s.delay(at, Delayed::Key { code, ms }) {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                self.live_tone_end(partner);
            }
        }
    }

    /// When the secured legs have something due next.
    pub(super) fn next_secure_ms(&self) -> Option<u64> {
        self.secure_slots
            .iter()
            .filter_map(|&s| self.secure.get(s)?.as_ref()?.next_ms())
            .min()
    }

    /// Delayed keys that are due reach their listeners; triggers whose
    /// time is up end.
    pub(super) fn secure_due(&mut self, now: u64) {
        for k in 0..self.secure_slots.len() {
            let leg = self.secure_slots[k];
            // Nothing due: no lookups (this runs on every turn).
            if self
                .secure
                .get(leg)
                .and_then(Option::as_ref)
                .and_then(|s| s.next_ms())
                .is_none_or(|t| t > now)
            {
                continue;
            }
            let Some(partner) = self.legs.get(leg).copied().flatten().map(|l| l.partner) else {
                continue;
            };
            let Some(call) = self.call_of(leg) else {
                continue;
            };
            while let Some(Some(s)) = self.secure.get_mut(leg) {
                s.state.tick(now);
                // The earliest due entry, in order.
                let Some(i) = s
                    .queue
                    .iter()
                    .enumerate()
                    .filter_map(|(i, q)| q.filter(|(t, _)| *t <= now).map(|(t, _)| (t, i)))
                    .min()
                    .map(|(_, i)| i)
                else {
                    break;
                };
                let Some((_, what)) = s.queue[i].take() else {
                    break;
                };
                let sec = s.sec;
                let mode = match (sec.listener_events, sec.listener_audio) {
                    (Some((pt, rate)), _) => ToneMode::Event { pt, rate },
                    (None, Some((pt, codec))) => ToneMode::Inband { pt, codec },
                    (None, None) => continue,
                };
                let volume = sec.plan.volume;
                match what {
                    Delayed::Start(code) => {
                        self.live_tone_start(call, partner, leg, code, volume, mode);
                    }
                    Delayed::End => self.live_tone_end(partner),
                    Delayed::Key { code, ms } => {
                        let tones = Tones {
                            codes: vec![code],
                            duration_ms: ms.clamp(40, 5_000).div_ceil(20) * 20,
                            pause_ms: 0,
                            volume,
                            mode,
                            sine_hz: 0,
                        };
                        self.tones_to(call, (partner, leg), tones);
                    }
                }
            }
        }
    }
}
