//! The load generator end to end: a short run against an in-process relay,
//! with plain RTP, SRTP on one side and SRTP on both sides.

use clap::Parser;
use rtpflux::config::Config;
use rtpflux::control::{Control, serve};
use rtpflux::relay::Relay;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A relay with its ng server on a free loopback port; stops when dropped.
struct Server {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

fn server() -> Server {
    let config = Config::from_toml(
        r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 51000
        max = 51063
        [sessions]
        max = 8
        [runtime]
        workers = 1
        "#,
    )
    .unwrap();
    let relay = Relay::start(&config).unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_nonblocking(true).unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let interfaces = config.interfaces.clone();
    let thread = std::thread::spawn(move || {
        let mut control = Control::new(relay, interfaces);
        serve(&mut control, &[sock], &stop_t).unwrap();
    });
    Server {
        addr,
        stop,
        thread: Some(thread),
    }
}

/// The report of a one-second run with two calls in `srtp` mode.
fn report(srtp: &str) -> String {
    let srv = server();
    let pid = std::process::id().to_string();
    let ng = srv.addr.to_string();
    let args = rtpflux_bench::Args::parse_from([
        "rtpflux-bench",
        "--name",
        "test",
        "--ng",
        &ng,
        "--pid",
        &pid,
        "--calls",
        "2",
        "--warmup",
        "0",
        "--duration",
        "1",
        "--threads",
        "2",
        "--srtp",
        srtp,
    ]);
    let mut out = Vec::new();
    rtpflux_bench::run(&args, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// The numbers of the report's single step: calls, offered, delivered, loss%.
fn step(report: &str) -> (u64, f64, f64, f64) {
    let lines: Vec<&str> = report.lines().collect();
    assert_eq!(lines.len(), 3, "{report}");
    assert!(lines[0].starts_with("# test — G.711 20 ms"), "{report}");
    assert!(lines[1].contains("relayCPU%"), "{report}");
    let f: Vec<&str> = lines[2].split_whitespace().collect();
    (
        f[0].parse().unwrap(),
        f[1].parse().unwrap(),
        f[2].parse().unwrap(),
        f[3].parse().unwrap(),
    )
}

#[test]
fn every_srtp_mode_delivers_all_packets() {
    for mode in ["none", "a", "both"] {
        let report = report(mode);
        let (calls, offered, delivered, loss) = step(&report);
        assert_eq!(calls, 2, "{report}");
        // Two calls, both ways, 50 packets a second each way: about 200/s.
        assert!(offered > 150.0, "{mode}: {report}");
        assert!(delivered > 150.0, "{mode}: {report}");
        assert!(loss < 5.0, "{mode}: {report}");
        if mode != "none" {
            assert!(report.contains("SRTP on"), "{report}");
        }
    }
}
