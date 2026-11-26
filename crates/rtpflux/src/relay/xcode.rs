//! DTMF transcoding (rtpengine's): who converts what, and the conversion
//! of telephone events into tones.
//!
//! [`plan`]: from the offer, whether the relay offers the answerer
//! telephone events the offerer lacks (`codec: transcode:
//! [telephone-event]`) or keeps the offerer's for an answerer that may
//! refuse them (`always transcode`). [`settle`]: from the answer, what each
//! side's DTMF becomes for the other, and the change to the answer towards
//! the offerer (which only ever loses the events the relay added, or gains
//! the offerer's own back). [`EventTones`]: the events (RFC 4733) one side sends, as the
//! starts and ends of the tones played to the other.

use super::{Codec, DtmfXcode};
use rtpflux_core::rtp::Pt;

/// What the offer set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Telephone events offered to the answerer with this payload type.
    Offered(Pt),
    /// The offerer's telephone events (payload type, rate), kept.
    Kept(Pt, u32),
}

/// The plan for an offer with these `formats`, of which `audio` are in a
/// codec the relay makes tones in and finds tones in, and telephone events
/// `te`.
#[must_use]
pub fn plan(
    formats: &[Pt],
    audio: &[Pt],
    te: Option<(Pt, u32)>,
    transcode_te: bool,
    always: bool,
) -> Option<Plan> {
    let sound = !audio.is_empty();
    match te {
        None if transcode_te && sound => core::iter::once(101)
            .chain(96..=127)
            .filter_map(Pt::new)
            .find(|pt| !formats.contains(pt))
            .map(Plan::Offered),
        Some((pt, rate)) if always && sound => Some(Plan::Kept(pt, rate)),
        _ => None,
    }
}

/// A change to the answer's format list towards the offerer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edit {
    Remove(Pt),
    Append(Pt),
}

/// What the answer settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settled {
    pub toward_a: Option<Edit>,
    /// What the offerer's (A's) and the answerer's (B's) DTMF become.
    pub a: Option<DtmfXcode>,
    pub b: Option<DtmfXcode>,
}

/// Settle `plan` with the answer's telephone events `answer_te`; `a_audio`
/// and `b_audio` are the audio (payload type, codec) A and B receive (and
/// send): tones are made in it for the side, and found in what it sends.
#[must_use]
pub fn settle(
    plan: Option<Plan>,
    answer_te: Option<(Pt, u32)>,
    a_audio: Option<(Pt, Codec)>,
    b_audio: Option<(Pt, Codec)>,
) -> Settled {
    match (plan, answer_te) {
        // B took the events offered (under the payload type offered: one
        // of A's own formats is never removed): B's events become tones
        // for A, A's tones events for B; A never sees them.
        (Some(Plan::Offered(offered)), Some((pt, rate))) if pt == offered => match a_audio {
            Some(audio) => Settled {
                toward_a: Some(Edit::Remove(pt)),
                a: Some(DtmfXcode {
                    to_inband: None,
                    to_events: Some((pt, rate)),
                    audio: Some(audio),
                }),
                b: Some(DtmfXcode {
                    to_inband: Some(audio),
                    to_events: None,
                    audio: None,
                }),
            },
            None => Settled::default(),
        },
        // B refused A's events: A's events become tones for B, B's tones
        // events for A, whose answer keeps them.
        (Some(Plan::Kept(pt, rate)), None) => match b_audio {
            Some(audio) => Settled {
                toward_a: Some(Edit::Append(pt)),
                a: Some(DtmfXcode {
                    to_inband: Some(audio),
                    to_events: None,
                    audio: None,
                }),
                b: Some(DtmfXcode {
                    to_inband: None,
                    to_events: Some((pt, rate)),
                    audio: Some(audio),
                }),
            },
            None => Settled::default(),
        },
        _ => Settled::default(),
    }
}

/// One side's telephone events, as tones played to the other: the event
/// being played (its RTP timestamp) and whether it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventTones {
    event: Option<(u32, bool)>,
}

impl EventTones {
    /// An event packet (timestamp, event code, E bit): the key whose tone
    /// starts (a new event, of a DTMF key), and whether the tone ends.
    pub fn packet(&mut self, ts: u32, code: u8, end: bool) -> (Option<u8>, bool) {
        match self.event {
            Some((t, ended)) if t == ts => {
                if end && !ended {
                    self.event = Some((ts, true));
                    (None, true)
                } else {
                    (None, false)
                }
            }
            _ => {
                self.event = Some((ts, end));
                ((code < 16).then_some(code), end)
            }
        }
    }
}
