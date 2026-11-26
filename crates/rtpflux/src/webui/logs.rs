//! The last log lines, kept in memory for the web UI's Logs page: a
//! `tracing` layer copies each event that passes the log filter into a
//! bounded ring, and the UI polls for the lines after the last one it has.
//!
//! Off until [`enable`] is called (by `main`, with `[webui] log_buffer`).

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Mutex, OnceLock, PoisonError};
use tracing_core::field::{Field, Visit};
use tracing_core::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// The longest line kept, in octets (longer ones are cut).
const MAX_LINE: usize = 2048;

/// One kept line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Increasing from 1 (to ask for the lines after one).
    pub seq: u64,
    /// Unix time, milliseconds.
    pub ts_ms: u64,
    pub level: &'static str,
    /// `target: message key=value…`.
    pub text: String,
}

struct Ring {
    cap: usize,
    next: u64,
    lines: VecDeque<Line>,
}

static RING: OnceLock<Mutex<Ring>> = OnceLock::new();

/// Keep the last `cap` lines (from now on).
pub fn enable(cap: usize) {
    let _ = RING.set(Mutex::new(Ring {
        cap: cap.max(1),
        next: 1,
        lines: VecDeque::with_capacity(cap.clamp(1, 4096)),
    }));
}

/// Whether lines are kept.
#[must_use]
pub fn enabled() -> bool {
    RING.get().is_some()
}

fn push(level: &'static str, text: String) {
    let Some(r) = RING.get() else {
        return;
    };
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let mut g = r.lock().unwrap_or_else(PoisonError::into_inner);
    let seq = g.next;
    g.next += 1;
    if g.lines.len() >= g.cap {
        g.lines.pop_front();
    }
    g.lines.push_back(Line {
        seq,
        ts_ms,
        level,
        text,
    });
}

/// The lines after `since` (oldest first, at most `max`, the newest ones
/// when there are more) and the sequence number of the newest line; `None`
/// when lines are not kept.
#[must_use]
pub fn tail(since: u64, max: usize) -> Option<(Vec<Line>, u64)> {
    let g = RING.get()?.lock().unwrap_or_else(PoisonError::into_inner);
    let newest = g.next - 1;
    let start = g.lines.partition_point(|l| l.seq <= since);
    let skip = (g.lines.len() - start).saturating_sub(max);
    Some((g.lines.iter().skip(start + skip).cloned().collect(), newest))
}

/// The layer that feeds the ring.
#[derive(Debug, Default, Clone, Copy)]
pub struct RingLayer;

/// Collects an event's message and fields; records forwarded from the
/// `log` crate carry their target as `log.target`.
#[derive(Default)]
struct Text {
    target: Option<String>,
    message: String,
    fields: String,
}

impl Visit for Text {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "log.target" => self.target = Some(value.to_owned()),
            "message" => self.message.push_str(value),
            n if n.starts_with("log.") => {}
            n => {
                let _ = write!(self.fields, " {n}={value}");
            }
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => {
                let _ = write!(self.message, "{value:?}");
            }
            n if n.starts_with("log.") => {}
            n => {
                let _ = write!(self.fields, " {n}={value:?}");
            }
        }
    }
}

const fn level_name(l: Level) -> &'static str {
    match l {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

impl<S: Subscriber> Layer<S> for RingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if RING.get().is_none() {
            return;
        }
        let mut t = Text::default();
        event.record(&mut t);
        let meta = event.metadata();
        let target = t.target.as_deref().unwrap_or(meta.target());
        let mut text = format!("{target}: {}{}", t.message, t.fields);
        if text.len() > MAX_LINE {
            let mut end = MAX_LINE;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push('…');
        }
        push(level_name(*meta.level()), text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn events_reach_the_ring_in_order() {
        enable(3);
        let subscriber = tracing_subscriber::registry().with(RingLayer);
        tracing_core::dispatcher::with_default(&tracing_core::Dispatch::new(subscriber), || {
            for i in 0..5 {
                log_event(i);
            }
        });
        let (lines, newest) = tail(0, 100).unwrap();
        assert!(newest >= 5);
        // Only the last three are kept.
        let texts: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(lines.len(), 3, "{texts:?}");
        assert!(texts[2].ends_with("line 4 n=4"), "{texts:?}");
        assert_eq!(lines[2].level, "WARN");
        // After a sequence number: only what follows; at most `max`.
        assert_eq!(tail(lines[1].seq, 100).unwrap().0.len(), 1);
        assert_eq!(tail(0, 1).unwrap().0, vec![lines[2].clone()]);
    }

    /// An event as `tracing` macros make it (without depending on the
    /// `tracing` crate): a WARN event with a message and a field.
    fn log_event(i: u64) {
        use tracing_core::{Metadata, callsite::Callsite, field::FieldSet, identify_callsite};
        struct Site;
        static SITE: Site = Site;
        static META: Metadata<'static> = Metadata::new(
            "event",
            "rtpflux::test",
            Level::WARN,
            None,
            None,
            None,
            FieldSet::new(&["message", "n"], identify_callsite!(&SITE)),
            tracing_core::metadata::Kind::EVENT,
        );
        impl Callsite for Site {
            fn set_interest(&self, _: tracing_core::subscriber::Interest) {}
            fn metadata(&self) -> &Metadata<'_> {
                &META
            }
        }
        let fields = META.fields();
        let (message, n) = (fields.field("message").unwrap(), fields.field("n").unwrap());
        let text = format!("line {i}");
        let values: [(&Field, Option<&dyn tracing_core::field::Value>); 2] = [
            (
                &message,
                Some(&text.as_str() as &dyn tracing_core::field::Value),
            ),
            (&n, Some(&i as &dyn tracing_core::field::Value)),
        ];
        Event::dispatch(&META, &fields.value_set(&values));
    }
}
