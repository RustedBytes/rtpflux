//! A logger for tests: every record at every level is formatted (so the
//! code building log messages runs, and cannot panic unnoticed) and
//! discarded.

use std::io::Write as _;

struct Discard;

impl log::Log for Discard {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let _ = write!(std::io::sink(), "{} {}", record.target(), record.args());
    }

    fn flush(&self) {}
}

/// Install the logger (once per test binary).
pub fn init() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if log::set_logger(&Discard).is_ok() {
            log::set_max_level(log::LevelFilter::Trace);
        }
    });
}
