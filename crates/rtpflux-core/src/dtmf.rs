//! Telephone events (RFC 4733): the payload, and detecting each event once
//! as it ends, the way the playout receiver of §2.5.2.2 schedules it.
//!
//! An event is its (RTP timestamp, code). It starts on a report for an event
//! not yet finished and ends on the E bit, a report for a new timestamp
//! (the next event), non-event media, or when nothing has come for three
//! packet interarrival times past its reported end. Its duration is the
//! longest one reported; reports for an event that already ended are
//! ignored (no restarts). Nothing is allocated; the finished events are
//! remembered in a small ring for that check.

/// One named-event report (§2.3, the first four octets of the payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub code: u8,
    /// E: the end of the event.
    pub end: bool,
    pub volume: u8,
    /// Timestamp units.
    pub duration: u16,
}

/// The event report at the start of a telephone-event payload.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<Event> {
    let &[code, flags, d0, d1, ..] = payload else {
        return None;
    };
    Some(Event {
        code,
        end: flags & 0x80 != 0,
        volume: flags & 0x3f,
        duration: u16::from_be_bytes([d0, d1]),
    })
}

/// The digit of a DTMF event code (§3.2 Table 3).
#[must_use]
pub const fn digit(code: u8) -> Option<char> {
    match code {
        // Within the matched range: no overflow.
        0..=9 => Some(b'0'.wrapping_add(code) as char),
        10 => Some('*'),
        11 => Some('#'),
        12..=15 => Some(b'A'.wrapping_add(code.wrapping_sub(12)) as char),
        _ => None,
    }
}

/// A finished event: code, timestamp, longest reported duration, and how
/// far past it the event was held when it timed out (timestamp units).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finished {
    pub code: u8,
    pub ts: u32,
    pub duration: u32,
    pub extension: u32,
}

/// Finished events remembered for "already played".
const REMEMBERED: usize = 32;

/// The detector of one stream.
#[derive(Debug, Clone, Copy)]
pub struct Detector {
    interarrival: u32,
    /// The event in progress: code, timestamp, longest duration so far.
    current: Option<(u8, u32, u32)>,
    finished: [Option<(u32, u8)>; REMEMBERED],
    next: usize,
}

/// What one input finished: at most two events (the one in progress, and
/// a new one that starts and ends with the same report).
pub type Ended = [Option<Finished>; 2];

impl Detector {
    /// A detector for packets `interarrival` timestamp units apart (e.g.
    /// 20 ms at 8000 Hz: 160).
    #[must_use]
    pub const fn new(interarrival: u32) -> Self {
        Detector {
            interarrival,
            current: None,
            finished: [None; REMEMBERED],
            next: 0,
        }
    }

    /// The event in progress (code, timestamp, longest duration so far).
    #[must_use]
    pub fn current(&self) -> Option<(u8, u32, u32)> {
        self.current
    }

    fn played(&self, ts: u32, code: u8) -> bool {
        self.finished.contains(&Some((ts, code)))
    }

    fn stop(&mut self, extension: u32) -> Option<Finished> {
        let (code, ts, duration) = self.current.take()?;
        if let Some(slot) = self.finished.get_mut(self.next) {
            *slot = Some((ts, code));
        }
        self.next = self.next.wrapping_add(1) % REMEMBERED;
        Some(Finished {
            code,
            ts,
            duration,
            extension,
        })
    }

    /// Start an event (ending it at once on E).
    fn start(&mut self, ts: u32, ev: Event) -> Option<Finished> {
        self.current = Some((ev.code, ts, u32::from(ev.duration)));
        if ev.end { self.stop(0) } else { None }
    }

    /// A report `ev` in a packet with RTP timestamp `ts`.
    pub fn report(&mut self, ts: u32, ev: Event) -> Ended {
        match self.current {
            Some((code, t, d)) if t == ts && code == ev.code => {
                self.current = Some((code, t, d.max(u32::from(ev.duration))));
                [if ev.end { self.stop(0) } else { None }, None]
            }
            Some(_) => {
                // The next event: the current one ends.
                let first = self.stop(0);
                let second = if self.played(ts, ev.code) {
                    None
                } else {
                    self.start(ts, ev)
                };
                [first, second]
            }
            None => [
                if self.played(ts, ev.code) {
                    None
                } else {
                    self.start(ts, ev)
                },
                None,
            ],
        }
    }

    /// Non-event media arrived: the event in progress ends.
    pub fn media(&mut self) -> Option<Finished> {
        self.stop(0)
    }

    /// The stream's clock reached `now` (timestamp units) without a report:
    /// an event three interarrival times past its reported end ends.
    pub fn tick(&mut self, now: u64) -> Option<Finished> {
        let (_, t, d) = self.current?;
        let hold = 3 * u64::from(self.interarrival);
        if u64::from(t)
            .saturating_add(u64::from(d))
            .saturating_add(hold)
            <= now
        {
            self.stop(u32::try_from(hold).unwrap_or(u32::MAX))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(code: u8, end: bool, duration: u16) -> Event {
        Event {
            code,
            end,
            volume: 10,
            duration,
        }
    }

    #[test]
    fn payload_and_digits() {
        assert_eq!(decode(&[5, 0x8a, 0x06, 0x40]), Some(ev(5, true, 1600)));
        assert_eq!(decode(&[5, 0x8a, 0x06]), None);
        assert_eq!(
            (digit(0), digit(10), digit(11), digit(15), digit(16)),
            (Some('0'), Some('*'), Some('#'), Some('D'), None)
        );
    }

    #[test]
    fn one_event_once() {
        let mut d = Detector::new(160);
        assert_eq!(d.report(1000, ev(5, false, 400)), [None, None]);
        let [Some(f), None] = d.report(1000, ev(5, true, 800)) else {
            panic!()
        };
        assert_eq!((f.code, f.ts, f.duration), (5, 1000, 800));
        // the E retransmissions change nothing
        assert_eq!(d.report(1000, ev(5, true, 800)), [None, None]);
    }
}
