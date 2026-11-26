//! The rtpflux daemon: configuration, the `ng` control protocol, the
//! userspace media relay and its XDP fast path.

// No `unsafe` here, and no way to allow it (AGENTS.md §5).
#![forbid(unsafe_code)]
pub mod codec;
pub mod config;
pub mod control;
pub mod daemon;
pub mod dtls;
pub mod lifecycle;
pub mod media_file;
pub mod metrics;
pub mod ngcache;
pub mod ngstream;
pub mod publish;
pub mod recording;
pub mod redis;
pub mod relay;
pub mod reoffer;
pub mod srflx;
pub mod state;
pub mod subscription;
pub mod trickle;
pub mod webui;

/// Run `f`, the body of a thread the relay cannot do without (a media
/// worker, the control thread, the XDP controller); if it panics, abort the
/// process. A relay with a dead thread would keep answering `ng` while
/// its calls go silent; aborting lets the service manager restart it (and
/// a state file bring the calls back). The panic message is printed first.
pub fn essential<T>(name: &str, f: impl FnOnce() -> T) -> T {
    if let Ok(v) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        v
    } else {
        log::error!("{name} panicked: aborting so that the relay restarts");
        std::process::abort();
    }
}

#[cfg(test)]
#[path = "../tests/support/logging.rs"]
pub(crate) mod test_logging;
