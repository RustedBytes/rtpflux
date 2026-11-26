//! DTMF security and delay as the proxy asks for them: `block DTMF` with
//! `DTMF-security` (and its triggers, `digit`, `frequency`, `volume`,
//! `DTMF-delay`), `unblock DTMF`, and `DTMF-delay` on an offer or answer
//! (the keys of the party that sent the SDP). Each party's plan is set on
//! its relay legs ([`crate::relay::dtmf_security`]) and kept with the
//! call's extras, so it is set again after a restart.

use super::args::number;
use super::media::{MediaState, Party};
use super::parties::{Which, side_of};
use super::{CallId, CallLeg, Control, Error, required};
use crate::relay::dtmf_security::{DtmfSecurity, Keys, Mode, Plan, TONE_HZ, code_of};
use rtpflux_core::g711::PT_PCMA;
use rtpflux_ng::bencode::{Dict, Value};

/// The keys of a request that ask for DTMF security.
const KEYS: [&[u8]; 8] = [
    b"DTMF-security",
    b"DTMF-security-trigger",
    b"DTMF-security-trigger-end",
    b"trigger",
    b"trigger-end",
    b"trigger-end-time",
    b"trigger-end-digits",
    b"DTMF-delay",
];

/// The level of what replaces keys when the proxy names none (rtpengine's:
/// 10 dB below 0 dBm0).
const VOLUME: u8 = 10;

/// Longest `DTMF-delay` taken (ms).
const MAX_DELAY_MS: i64 = 10_000;

/// `digit` (or `code`): a key, as a string or an event number.
fn digit(d: &Dict<'_>) -> Result<Option<u8>, Error> {
    match d.get(b"digit").or_else(|| d.get(b"code")) {
        None => Ok(None),
        Some(Value::Int(n)) => u8::try_from(n)
            .ok()
            .filter(|&c| c < 16)
            .map(Some)
            .ok_or_else(|| Error::unsupported("digit: a key 0-9 * # A-D, or an event 0-15")),
        Some(Value::Bytes(&[c])) => code_of(c)
            .map(Some)
            .ok_or_else(|| Error::unsupported("digit: a key 0-9 * # A-D, or an event 0-15")),
        Some(_) => Err(Error::unsupported(
            "digit: a key 0-9 * # A-D, or an event 0-15",
        )),
    }
}

/// The plan a request asks for (`None`: no DTMF security key in it).
fn plan_of(d: &Dict<'_>) -> Result<Option<Plan>, Error> {
    if !KEYS.iter().any(|k| d.get(k).is_some()) {
        return Ok(None);
    }
    let digit = digit(d)?;
    let mode = |key: &[u8]| -> Result<Option<Mode>, Error> {
        d.get_bytes(key)
            .map(|v| {
                Mode::parse(v, digit).ok_or_else(|| {
                    Error::unsupported(format!(
                        "{}: {} (off, drop, silence, tone, random, zero, DTMF with digit)",
                        String::from_utf8_lossy(key),
                        String::from_utf8_lossy(v)
                    ))
                })
            })
            .transpose()
    };
    let keys = |key: &[u8]| -> Result<Option<Keys>, Error> {
        d.get_bytes(key)
            .map(|v| {
                Keys::parse(v).ok_or_else(|| {
                    Error::unsupported(format!(
                        "{}: 1 to 16 keys 0-9 * # A-D",
                        String::from_utf8_lossy(key)
                    ))
                })
            })
            .transpose()
    };
    let trigger = keys(b"trigger")?;
    let delay = number(d, b"DTMF-delay")?;
    let frequency = match d.get(b"frequencies") {
        Some(Value::List(l)) => l.iter().find_map(|v| match v {
            Value::Int(n) => Some(n),
            Value::Bytes(b) => std::str::from_utf8(b).ok()?.trim().parse().ok(),
            _ => None,
        }),
        _ => number(d, b"frequency")?,
    };
    Ok(Some(Plan {
        // With a trigger, nothing is done until it comes (rtpengine's).
        mode: mode(b"DTMF-security")?.unwrap_or(if trigger.is_some() {
            Mode::Off
        } else {
            Mode::Drop
        }),
        trigger,
        trigger_mode: mode(b"DTMF-security-trigger")?.unwrap_or(Mode::Drop),
        end: keys(b"trigger-end")?,
        end_mode: mode(b"DTMF-security-trigger-end")?.unwrap_or(Mode::Off),
        end_ms: number(d, b"trigger-end-time")?.and_then(|n| u64::try_from(n).ok()),
        end_keys: number(d, b"trigger-end-digits")?.and_then(|n| u32::try_from(n).ok()),
        delay_ms: delay.map_or(0, |n| u32::try_from(n.clamp(0, MAX_DELAY_MS)).unwrap_or(0)),
        tone_hz: frequency
            .and_then(|f| u16::try_from(f.clamp(50, 4_000)).ok())
            .unwrap_or(TONE_HZ),
        // rtpengine writes it as negative dB too.
        volume: number(d, b"volume")?.map_or(VOLUME, |v| {
            u8::try_from(v.unsigned_abs().min(63)).unwrap_or(VOLUME)
        }),
    }))
}

/// The security of `sender`'s keys in section `st`, under `plan`: found
/// in its audio, replaced in the listener's.
fn security(st: &MediaState, sender: Party, plan: Plan) -> DtmfSecurity {
    let listener = sender.other();
    let (law, side) = if listener.is_b() {
        (st.b_law, &st.b_side)
    } else {
        (st.a_law, &st.a_side)
    };
    let g711 = law.map(|pt| {
        let codec = if pt == PT_PCMA {
            crate::relay::Codec::Pcma
        } else {
            crate::relay::Codec::Pcmu
        };
        (pt, codec)
    });
    DtmfSecurity {
        plan,
        own_audio: st.audio[sender.index()],
        listener_audio: st.audio[listener.index()].or(g711),
        listener_events: side.dtmf,
    }
}

impl Control {
    /// `block DTMF` with DTMF security, or `unblock DTMF` (`on` false):
    /// whether the request was such (else the plain blocking applies).
    pub(super) fn block_dtmf_secure(&mut self, d: &Dict<'_>, on: bool) -> Result<bool, Error> {
        let plan = if on {
            match plan_of(d)? {
                Some(p) => Some(p),
                None => return Ok(false),
            }
        } else {
            None
        };
        let call_id = required(d, "call-id")?.to_vec();
        let tag = self.party(d, &call_id, Which::From)?;
        let targets = self.sender_legs(&call_id, tag.as_deref());
        if targets.is_empty() {
            return Err(Error::UnknownCallOrTag);
        }
        for (id, leg, st, party) in targets {
            // It takes the place of plain blocking.
            if plan.is_some() {
                let what = crate::relay::Blocked::Dtmf;
                Self::logged(
                    "unblocking DTMF",
                    id,
                    self.relay.block(id, leg, what, false),
                );
                self.extras.entry(id).or_default().blocked[leg.index()].set(what, false);
            }
            self.set_security(id, leg, &st, party, plan);
        }
        // `unblock DTMF` goes on to clear the plain blocking too.
        Ok(on)
    }

    /// `DTMF-delay` on an offer or answer: the keys of the party that sent
    /// the SDP (its tag under `tag_key`) reach the other that much later.
    pub(super) fn dtmf_delay_sdp_sender(&mut self, d: &Dict<'_>, tag_key: &[u8]) {
        let (Some(call_id), Some(tag)) = (d.get_bytes(b"call-id"), d.get_bytes(tag_key)) else {
            return;
        };
        let Ok(Some(delay)) = number(d, b"DTMF-delay") else {
            return;
        };
        let delay_ms = u32::try_from(delay.clamp(0, MAX_DELAY_MS)).unwrap_or(0);
        for (id, leg, st, party) in self.sender_legs(call_id, Some(tag)) {
            let now = self
                .extras
                .get(&id)
                .and_then(|x| x.dtmf_security[leg.index()]);
            let plan = match now {
                Some(p) => Plan { delay_ms, ..p },
                None if delay_ms > 0 => Plan {
                    mode: Mode::Off,
                    delay_ms,
                    tone_hz: TONE_HZ,
                    volume: VOLUME,
                    ..Plan::default()
                },
                None => continue,
            };
            let plan = (plan
                != Plan {
                    mode: Mode::Off,
                    tone_hz: TONE_HZ,
                    volume: VOLUME,
                    ..Plan::default()
                })
            .then_some(plan);
            self.set_security(id, leg, &st, party, plan);
        }
    }

    /// The relay legs whose keys party `tag` of `call_id` sends (every
    /// party's without a tag), with their sections.
    fn sender_legs(
        &self,
        call_id: &[u8],
        tag: Option<&[u8]>,
    ) -> Vec<(CallId, CallLeg, MediaState, Party)> {
        let mut out = Vec::new();
        for (key, s) in &self.sessions {
            if key.0 != call_id {
                continue;
            }
            for party in [Party::A, Party::B] {
                if tag.is_some_and(|t| side_of(key, s, t) != Some(party)) {
                    continue;
                }
                out.extend(
                    s.media
                        .iter()
                        .flatten()
                        .map(|st| (st.ports.id, st.leg(party), *st, party)),
                );
            }
        }
        out
    }

    /// Set `plan` (or none) on leg `leg` of relay call `id`, whose keys
    /// are `party`'s in section `st`, and keep it.
    fn set_security(
        &mut self,
        id: CallId,
        leg: CallLeg,
        st: &MediaState,
        party: Party,
        plan: Option<Plan>,
    ) {
        let sec = plan.map(|p| security(st, party, p));
        Self::logged("DTMF security", id, self.relay.secure_dtmf(id, leg, sec));
        self.extras.entry(id).or_default().dtmf_security[leg.index()] = plan;
        self.mark_dirty();
    }

    /// Set the kept plans of relay call `id` (section `st`) again, after a
    /// restart.
    pub(super) fn restore_security(&mut self, st: &MediaState, plans: [Option<Plan>; 2]) {
        for (k, plan) in plans.into_iter().enumerate() {
            let Some(plan) = plan else { continue };
            let leg = CallLeg::of_b(k == 1);
            let party = if st.leg(Party::A) == leg {
                Party::A
            } else {
                Party::B
            };
            let sec = security(st, party, plan);
            Self::logged(
                "DTMF security",
                st.ports.id,
                self.relay.secure_dtmf(st.ports.id, leg, Some(sec)),
            );
        }
    }
}
