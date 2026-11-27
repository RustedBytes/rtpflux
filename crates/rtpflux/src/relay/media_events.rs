//! What happens to a call's media that the control side reports to its
//! subscribers (the native API's events): a key press, an announcement
//! that played out, DTLS keyed or failed, ICE connected, a recording
//! finished.
//!
//! Workers (and the recording thread) hand events to the control thread
//! through one bounded queue. Sending never blocks a media worker: when the
//! queue is full the event is dropped and counted, and the next event the
//! control thread takes says so (`gap`), so a subscriber knows to ask for
//! a snapshot. Events are rare (per key press, per announcement, per
//! handshake), never per packet.

use super::{CallId, CallLeg};
use nix::sys::eventfd::{EfdFlags, EventFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

/// Events the queue holds, at most.
pub const QUEUE: usize = 4096;

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaEventKind {
    /// A key press ended (RFC 4733 telephone event, its end reported
    /// once whatever the retransmissions): its event code (0–15 are
    /// `0-9*#A-D`), how long it was held, and the RTP timestamp it began
    /// at.
    Dtmf {
        code: u8,
        duration_ms: u32,
        rtp_timestamp: u32,
        /// Found in the audio (tones), not sent as an RFC 4733 event.
        inband: bool,
    },
    /// The announcement playing to the leg played out (not stopped).
    PlaybackEnded,
    /// DTLS-SRTP keyed the leg.
    DtlsReady,
    /// The leg's DTLS association failed.
    DtlsFailed,
    /// ICE nominated a pair towards the leg.
    IceConnected,
    /// Voice activity began, or ended, in what the leg sends (a PCM
    /// stream's detector).
    SpeechStarted,
    SpeechEnded,
    /// A PCM stream's mark: the audio before it has played.
    StreamMark {
        stream: u32,
        mark: u32,
    },
    /// Something a worker was asked to do failed: what (`recording`,
    /// `media`), and why.
    Failed {
        what: &'static str,
        reason: String,
    },
    /// The leg's endpoint is the active speaker of mixer `mixer`.
    ActiveSpeaker {
        mixer: u32,
    },
    /// A PCM stream ended (its service closed the socket, or it was
    /// stopped).
    StreamEnded {
        stream: u32,
    },
    /// A recording of a dialog's media section finished: its audio file
    /// (`None` when the conversion failed and only the pcap is kept), and
    /// whether it was uploaded (`None` when recordings stay local).
    RecordingDone {
        file: Option<String>,
        uploaded: Option<bool>,
    },
}

/// What an event is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// A leg of a relay call.
    Leg(CallId, CallLeg),
    /// A relay call as a whole (both its parties).
    Call(CallId),
    /// A dialog (a recording's): its Call-ID, offerer's tag and media
    /// section (from 1).
    Dialog {
        call_id: String,
        from_tag: String,
        section: usize,
    },
}

/// One event: what it concerns, and when (Unix milliseconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaEvent {
    pub subject: Subject,
    pub at_unix_ms: u64,
    pub kind: MediaEventKind,
}

/// The sending end, cloned into each worker.
#[derive(Debug, Clone)]
pub struct MediaEvents {
    tx: SyncSender<MediaEvent>,
    dropped: Arc<AtomicU64>,
    wake: Arc<EventFd>,
    /// What dropped events were about, as far as known (at most
    /// [`MAX_LOST`]; taken only if the lock is free: never waited for).
    lost: Arc<std::sync::Mutex<Vec<Subject>>>,
}

/// Subjects of dropped events remembered between two takes, at most.
pub const MAX_LOST: usize = 256;

impl MediaEvents {
    /// Hand `kind` about `subject` to the control thread; dropped and
    /// counted when the queue is full.
    pub fn emit(&self, subject: Subject, kind: MediaEventKind) {
        let event = MediaEvent {
            subject,
            at_unix_ms: unix_ms(),
            kind,
        };
        if let Err(e) = self.tx.try_send(event) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            let subject = match e {
                std::sync::mpsc::TrySendError::Full(ev)
                | std::sync::mpsc::TrySendError::Disconnected(ev) => ev.subject,
            };
            if let Ok(mut l) = self.lost.try_lock()
                && l.len() < MAX_LOST
                && !l.contains(&subject)
            {
                l.push(subject);
            }
        } else {
            let _ = self.wake.write(1);
        }
    }
}

/// The control thread's end.
#[derive(Debug)]
pub struct MediaEventInbox {
    rx: Receiver<MediaEvent>,
    dropped: Arc<AtomicU64>,
    lost: Arc<std::sync::Mutex<Vec<Subject>>>,
    /// Events dropped as of the last [`MediaEventInbox::take`].
    seen_dropped: u64,
    /// Written once per event: wakes the control thread.
    pub wake: Arc<EventFd>,
}

impl MediaEventInbox {
    /// The events waiting, and how many were dropped since the last call
    /// (a gap before them).
    pub fn take(&mut self) -> (Vec<MediaEvent>, u64) {
        let _ = self.wake.read();
        let events: Vec<MediaEvent> = self.rx.try_iter().collect();
        let dropped = self.dropped.load(Ordering::Relaxed);
        let gap = dropped.saturating_sub(self.seen_dropped);
        self.seen_dropped = dropped;
        (events, gap)
    }

    /// What the events dropped since the last call were about, as far as
    /// known (some may not be: count them with [`MediaEventInbox::take`]).
    #[must_use]
    pub fn take_lost(&self) -> Vec<Subject> {
        self.lost
            .lock()
            .map_or_else(|_| Vec::new(), |mut l| std::mem::take(&mut *l))
    }

    /// Events dropped since the start.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A queue: its sending end (for the workers) and the control thread's.
///
/// # Errors
///
/// When the eventfd cannot be created.
pub fn channel() -> Result<(MediaEvents, MediaEventInbox), nix::Error> {
    let (tx, rx) = sync_channel(QUEUE);
    let dropped = Arc::new(AtomicU64::new(0));
    let lost = Arc::new(std::sync::Mutex::new(Vec::new()));
    let wake = Arc::new(EventFd::from_flags(
        EfdFlags::EFD_NONBLOCK | EfdFlags::EFD_CLOEXEC,
    )?);
    Ok((
        MediaEvents {
            tx,
            dropped: Arc::clone(&dropped),
            wake: Arc::clone(&wake),
            lost: Arc::clone(&lost),
        },
        MediaEventInbox {
            rx,
            dropped,
            lost,
            seen_dropped: 0,
            wake,
        },
    ))
}

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_arrive_in_order_and_an_overflow_is_a_gap() {
        let (tx, mut rx) = channel().unwrap();
        for code in 0..3 {
            tx.emit(
                Subject::Leg(CallId::of(1), CallLeg::A),
                MediaEventKind::Dtmf {
                    code,
                    duration_ms: 100,
                    rtp_timestamp: 0,
                    inband: false,
                },
            );
        }
        let (events, gap) = rx.take();
        assert_eq!(gap, 0);
        let codes: Vec<u8> = events
            .iter()
            .map(|e| match e.kind {
                MediaEventKind::Dtmf { code, .. } => code,
                _ => 99,
            })
            .collect();
        assert_eq!(codes, [0, 1, 2]);
        for _ in 0..QUEUE + 5 {
            tx.emit(
                Subject::Leg(CallId::of(1), CallLeg::B),
                MediaEventKind::PlaybackEnded,
            );
        }
        let (events, gap) = rx.take();
        assert_eq!((events.len(), gap), (QUEUE, 5));
        assert_eq!(rx.take().1, 0, "a gap is reported once");
    }
}
