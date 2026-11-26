//! Prometheus metrics (text exposition format 0.0.4) on `GET /metrics`.
//!
//! Counters come from the workers' shared atomics and the `ng` server's;
//! reading them takes no lock and touches no hot-path state. The HTTP side
//! is a minimal blocking server on its own thread: one request per
//! connection, `GET /metrics` only.

use crate::relay::Stats;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// `ng` commands counted by name.
pub const COMMANDS: [&str; 31] = [
    "ping",
    "offer",
    "answer",
    "delete",
    "list",
    "query",
    "play media",
    "stop media",
    "start recording",
    "stop recording",
    "block media",
    "unblock media",
    "block DTMF",
    "unblock DTMF",
    "play DTMF",
    "silence media",
    "unsilence media",
    "statistics",
    "pause recording",
    "publish",
    "subscribe request",
    "subscribe answer",
    "unsubscribe",
    "connect",
    "mesh",
    "inject start",
    "inject stop",
    "rollback",
    "create",
    "create answer",
    "other",
];

/// Counters of the `ng` server.
#[derive(Debug, Default)]
pub struct ControlStats {
    /// Requests per command (index into [`COMMANDS`]).
    pub requests: [AtomicU64; COMMANDS.len()],
    /// Requests answered with an error.
    pub errors: AtomicU64,
    /// Retransmissions answered from the reply cache.
    pub retransmissions: AtomicU64,
    /// Dialogs (`call-id`, `from-tag`) with media.
    pub sessions: AtomicU64,
    /// Relay calls (one per relayed media section).
    pub calls: AtomicU64,
    /// State file writes, and the ones that failed.
    pub state_writes: AtomicU64,
    pub state_write_failures: AtomicU64,
    /// Redis: snapshots written, failed attempts, failing now (0 or 1).
    pub redis_writes: AtomicU64,
    pub redis_failures: AtomicU64,
    pub redis_failing: AtomicU64,
    /// `connect`ed pairs, copies (directional `connect`, `inject`, `mesh`),
    /// subscriptions, and deletes waiting for their `delete-delay`.
    pub connections: AtomicU64,
    pub copies: AtomicU64,
    pub subscriptions: AtomicU64,
    pub delayed_deletes: AtomicU64,
}

impl ControlStats {
    pub fn count(&self, command: &[u8]) {
        let i = COMMANDS
            .iter()
            .position(|c| c.as_bytes() == command)
            .unwrap_or(COMMANDS.len() - 1);
        self.requests[i].fetch_add(1, Ordering::Relaxed);
    }
}

/// Everything `/metrics` reports.
#[derive(Debug, Clone)]
pub struct Sources {
    pub workers: Vec<Arc<Stats>>,
    pub control: Arc<ControlStats>,
    /// What became of finished recordings.
    pub recording: Arc<crate::recording::activity::Activity>,
    /// Each interface's server-reflexive address, once learned
    /// (`[ice] stun_server`; for the web UI).
    pub srflx: crate::srflx::Shared,
    /// The calls the XDP program relays (for the web UI).
    pub xdp_flows: crate::relay::XdpFlows,
}

/// The workers' counters (summed over the workers): metric, help, field.
type WorkerCounter = (&'static str, &'static str, fn(&Stats) -> &AtomicU64);

const WORKER_COUNTERS: [WorkerCounter; 16] = [
    (
        "rtpflux_packets_forwarded_total",
        "Packets relayed by the userspace workers.",
        |s| &s.forwarded,
    ),
    (
        "rtpflux_packets_dropped_total",
        "Packets dropped (no leg, wrong source, no destination, malformed).",
        |s| &s.dropped,
    ),
    (
        "rtpflux_send_errors_total",
        "Packets the kernel refused to send.",
        |s| &s.send_errors,
    ),
    (
        "rtpflux_srtp_rejected_total",
        "SRTP/SRTCP packets failing authentication or replay checks, or before their keys.",
        |s| &s.srtp_rejected,
    ),
    (
        "rtpflux_zrtp_forwarded_total",
        "ZRTP packets relayed untouched between endpoints (also in packets forwarded).",
        |s| &s.zrtp,
    ),
    (
        "rtpflux_calls_timed_out_total",
        "Relay calls ended by the media timeout.",
        |s| &s.calls_ended,
    ),
    (
        "rtpflux_ice_checks_total",
        "ICE connectivity checks and consent requests the relay's full agents sent.",
        |s| &s.ice_checks,
    ),
    (
        "rtpflux_ice_nominations_total",
        "Candidate pairs the relay's full agents nominated or accepted as nominated.",
        |s| &s.ice_nominations,
    ),
    (
        "rtpflux_ice_role_conflicts_total",
        "ICE role conflicts the relay's full agents resolved.",
        |s| &s.ice_role_conflicts,
    ),
    (
        "rtpflux_ice_consent_lost_total",
        "Pairs whose consent expired (RFC 7675): media to them stopped.",
        |s| &s.ice_consent_lost,
    ),
    (
        "rtpflux_ice_restarts_total",
        "ICE restarts of the relay's full agents.",
        |s| &s.ice_restarts,
    ),
    (
        "rtpflux_bytes_forwarded_total",
        "Octets (UDP payloads) relayed by the userspace workers.",
        |s| &s.forwarded_bytes,
    ),
    (
        "rtpflux_kernel_packets_total",
        "Packets the XDP fast path relayed in the kernel (as of the last poll).",
        |s| &s.kernel_packets,
    ),
    (
        "rtpflux_kernel_bytes_total",
        "Octets (UDP payloads) the XDP fast path relayed in the kernel.",
        |s| &s.kernel_bytes,
    ),
    (
        "rtpflux_dtls_handshakes_total",
        "DTLS-SRTP handshakes that keyed SRTP.",
        |s| &s.dtls_handshakes,
    ),
    (
        "rtpflux_dtls_failures_total",
        "DTLS-SRTP associations that failed.",
        |s| &s.dtls_failures,
    ),
];

/// The control thread's metrics: metric, group, counter (else gauge),
/// help, field.
type ControlMetric = (
    &'static str,
    &'static str,
    bool,
    &'static str,
    fn(&ControlStats) -> &AtomicU64,
);

const CONTROL_METRICS: [ControlMetric; 13] = [
    (
        "rtpflux_sessions",
        "relay",
        false,
        "Dialogs with relayed media.",
        |c| &c.sessions,
    ),
    (
        "rtpflux_calls",
        "relay",
        false,
        "Relay calls (relayed media sections).",
        |c| &c.calls,
    ),
    (
        "rtpflux_connections",
        "links",
        false,
        "Parties joined with connect (transfers).",
        |c| &c.connections,
    ),
    (
        "rtpflux_copies",
        "links",
        false,
        "Copies of a party's media to another (directional connect, inject, mesh).",
        |c| &c.copies,
    ),
    (
        "rtpflux_subscriptions",
        "links",
        false,
        "Media subscriptions (SIPREC and others).",
        |c| &c.subscriptions,
    ),
    (
        "rtpflux_delayed_deletes",
        "links",
        false,
        "Deletes waiting for their delete-delay.",
        |c| &c.delayed_deletes,
    ),
    (
        "rtpflux_state_writes_total",
        "state",
        true,
        "State file writes.",
        |c| &c.state_writes,
    ),
    (
        "rtpflux_state_write_failures_total",
        "state",
        true,
        "State file writes that failed.",
        |c| &c.state_write_failures,
    ),
    (
        "rtpflux_redis_writes_total",
        "state",
        true,
        "Snapshots written to Redis.",
        |c| &c.redis_writes,
    ),
    (
        "rtpflux_redis_failures_total",
        "state",
        true,
        "Failed attempts to write to Redis.",
        |c| &c.redis_failures,
    ),
    (
        "rtpflux_redis_failing",
        "state",
        false,
        "1 while writing to Redis fails.",
        |c| &c.redis_failing,
    ),
    (
        "rtpflux_ng_errors_total",
        "ng",
        true,
        "ng requests answered with an error.",
        |c| &c.errors,
    ),
    (
        "rtpflux_ng_retransmissions_total",
        "ng",
        true,
        "ng requests answered from the reply cache.",
        |c| &c.retransmissions,
    ),
];

/// What became of finished recordings: metric, help, field (counters).
type RecordingCounter = (
    &'static str,
    &'static str,
    fn(&crate::recording::activity::Activity) -> &AtomicU64,
);

const RECORDING_COUNTERS: [RecordingCounter; 7] = [
    (
        "rtpflux_recordings_converted_total",
        "Recordings converted when they ended (or kept as pcap).",
        |r| &r.converted,
    ),
    (
        "rtpflux_recording_conversions_failed_total",
        "Recording conversions that failed (the pcap is kept).",
        |r| &r.conversions_failed,
    ),
    (
        "rtpflux_recording_uploads_total",
        "Recording files uploaded to S3.",
        |r| &r.uploaded,
    ),
    (
        "rtpflux_recording_upload_failures_total",
        "Recording files not uploaded after every attempt (kept locally).",
        |r| &r.uploads_failed,
    ),
    (
        "rtpflux_recording_webhooks_delivered_total",
        "Upload notifications the webhook answered with 2xx.",
        |r| &r.webhooks_delivered,
    ),
    (
        "rtpflux_recording_webhooks_failed_total",
        "Upload notifications given up on, or refused with a final status.",
        |r| &r.webhooks_failed,
    ),
    (
        "rtpflux_recording_webhooks_dropped_total",
        "Upload notifications dropped unsent (queue full, or the relay stopping).",
        |r| &r.webhooks_dropped,
    ),
];

/// One reading of a metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// The family's Prometheus name.
    pub metric: &'static str,
    /// A grouping for the web UI (`relay`, `ng`, `ng_requests`).
    pub group: &'static str,
    /// The web UI's name: the family's without its prefix and `_total`, or
    /// the label value.
    pub name: String,
    /// `command="…"` label value, for labelled families.
    pub label: Option<&'static str>,
    pub counter: bool,
    pub help: &'static str,
    pub value: u64,
}

impl Sources {
    /// Every metric, in exposition order.
    #[must_use]
    pub fn samples(&self) -> Vec<Sample> {
        let sum = |f: fn(&Stats) -> &AtomicU64| -> u64 {
            self.workers
                .iter()
                .map(|w| f(w).load(Ordering::Relaxed))
                .sum()
        };
        let c = &self.control;
        let plain = |metric: &'static str, group, counter, help, value| Sample {
            metric,
            group,
            name: metric
                .trim_start_matches("rtpflux_")
                .trim_start_matches("ng_")
                .trim_end_matches("_total")
                .to_owned(),
            label: None,
            counter,
            help,
            value,
        };
        let mut out: Vec<Sample> = WORKER_COUNTERS
            .iter()
            .map(|&(metric, help, field)| plain(metric, "relay", true, help, sum(field)))
            .collect();
        out.push(plain(
            "rtpflux_workers",
            "relay",
            false,
            "Media worker threads.",
            self.workers.len() as u64,
        ));
        out.push(plain(
            "rtpflux_offloaded_calls",
            "relay",
            false,
            "Relay calls the XDP fast path relays now.",
            sum(|s| &s.offloaded_calls),
        ));
        out.extend(
            CONTROL_METRICS
                .iter()
                .map(|&(metric, group, counter, help, field)| {
                    plain(
                        metric,
                        group,
                        counter,
                        help,
                        field(c).load(Ordering::Relaxed),
                    )
                }),
        );
        out.extend(RECORDING_COUNTERS.iter().map(|&(metric, help, field)| {
            plain(
                metric,
                "recording",
                true,
                help,
                field(&self.recording).load(Ordering::Relaxed),
            )
        }));
        for (name, n) in COMMANDS.iter().zip(&c.requests) {
            out.push(Sample {
                metric: "rtpflux_ng_requests_total",
                group: "ng_requests",
                name: (*name).to_owned(),
                label: Some(name),
                counter: true,
                help: "ng requests by command.",
                value: n.load(Ordering::Relaxed),
            });
        }
        out
    }

    /// The exposition text.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut family = "";
        for s in self.samples() {
            if s.metric != family {
                family = s.metric;
                let kind = if s.counter { "counter" } else { "gauge" };
                let _ = writeln!(
                    out,
                    "# HELP {} {}\n# TYPE {} {kind}",
                    s.metric, s.help, s.metric
                );
            }
            match s.label {
                Some(l) => {
                    let _ = writeln!(out, "{}{{command=\"{l}\"}} {}", s.metric, s.value);
                }
                None => {
                    let _ = writeln!(out, "{} {}", s.metric, s.value);
                }
            }
        }
        out
    }
}

/// How long one scrape may take, reading and writing: connections are
/// served one at a time, so a slow client must not hold up the others.
const DEADLINE: Duration = Duration::from_secs(3);

fn answer(mut conn: TcpStream, sources: &Sources) {
    let deadline = std::time::Instant::now() + DEADLINE;
    let _ = conn.set_write_timeout(Some(DEADLINE));
    let mut buf = [0u8; 4096];
    let mut n = 0;
    while n < buf.len() {
        let Some(left) = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return;
        };
        let _ = conn.set_read_timeout(Some(left));
        match conn.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => {
                n += k;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    let request = &buf[..n];
    let (status, body, ctype) =
        if request.starts_with(b"GET /metrics ") || request.starts_with(b"GET /metrics?") {
            (
                "200 OK",
                sources.render(),
                "text/plain; version=0.0.4; charset=utf-8",
            )
        } else {
            (
                "404 Not Found",
                "not found\n".to_owned(),
                "text/plain; charset=utf-8",
            )
        };
    let _ = write!(
        conn,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// Serve `/metrics` on `listener` until `stop` is set.
pub fn serve(listener: &TcpListener, sources: &Sources, stop: &AtomicBool) {
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((conn, _)) => {
                let _ = conn.set_nonblocking(false);
                answer(conn, sources);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                log::warn!("metrics: accept: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Bind `/metrics` listeners.
///
/// # Errors
///
/// When an address cannot be bound.
pub fn bind(addrs: &[SocketAddr]) -> Result<Vec<TcpListener>, crate::daemon::StartError> {
    addrs
        .iter()
        .map(|&a| TcpListener::bind(a).map_err(crate::daemon::StartError::listen("metrics", a)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_the_exposition_format() {
        let stats = Arc::new(Stats::default());
        stats.forwarded.store(42, Ordering::Relaxed);
        stats.zrtp.store(3, Ordering::Relaxed);
        let control = Arc::new(ControlStats::default());
        control.count(b"offer");
        control.count(b"bogus");
        let sources = Sources {
            workers: vec![stats],
            control,
            recording: Arc::default(),
            srflx: crate::srflx::Shared::default(),
            xdp_flows: crate::relay::XdpFlows::default(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, stop2) = (sources.clone(), Arc::clone(&stop));
        let t = std::thread::spawn(move || serve(&listener, &s2, &stop2));
        let get = |path: &str| {
            let mut c = TcpStream::connect(addr).unwrap();
            write!(c, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut body = String::new();
            c.read_to_string(&mut body).unwrap();
            body
        };
        let page = get("/metrics");
        assert!(page.starts_with("HTTP/1.1 200 OK\r\n"), "{page}");
        assert!(
            page.contains("\nrtpflux_packets_forwarded_total 42\n"),
            "{page}"
        );
        assert!(
            page.contains("\nrtpflux_zrtp_forwarded_total 3\n"),
            "{page}"
        );
        assert!(
            page.contains("rtpflux_ng_requests_total{command=\"offer\"} 1\n"),
            "{page}"
        );
        assert!(
            page.contains("rtpflux_ng_requests_total{command=\"other\"} 1\n"),
            "{page}"
        );
        assert!(page.contains("# TYPE rtpflux_sessions gauge\n"), "{page}");
        assert!(get("/").starts_with("HTTP/1.1 404"));
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
    }
}
