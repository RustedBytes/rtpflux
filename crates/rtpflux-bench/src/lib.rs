//! Load generator for RTP relays controlled over `ng` (rtpflux, rtpengine).
//!
//! For each step it sets up N calls with `offer`/`answer`, then every call
//! sends 172-octet RTP packets (G.711, 20 ms) in both directions — 100
//! packets per second per call, start times staggered. Over a measurement
//! window after a warm-up it reports delivery, one-way latency through the
//! relay (send timestamp in the payload) and the relay's CPU time
//! (`/proc/<pid>/stat`). Calls are deleted between steps.
//!
//! `--srtp a`: side A uses SDES-SRTP (`RTP/SAVP`, `AES_CM_128_HMAC_SHA1_80`)
//! and side B plain RTP, so the relay decrypts or encrypts every packet;
//! `--srtp both`: both sides use SRTP with their own keys, so the relay
//! decrypts and re-encrypts every packet. The client's SRTP work is its
//! own CPU, not the relay's.

// No `unsafe` here, and no way to allow it (AGENTS.md §5).
#![forbid(unsafe_code)]
mod calls;
mod load;
mod ng;
mod report;
mod sdp;

use clap::Parser;
use nix::sched::{CloneFlags, setns};
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::unistd::{SysconfVar, sysconf};
use rtpflux_core::sdp::{MAX_MEDIA, MasterKey, Media, Suite, read_media};
use rtpflux_ng::bencode::{Encoder, Value, decode};
use rtpflux_srtp::{Protect, Unprotect};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use calls::{Call, Peers, setup, teardown};
use load::{HIST_US, Tally, load};
use ng::Ng;
use report::{Trial, median, trial, us};
use sdp::{bench_key, relay_key, relay_port, sdp_for};

#[derive(Debug, Parser)]
#[command(about)]
pub struct Args {
    /// Label for the report (e.g. the relay's name).
    #[arg(long, default_value = "relay")]
    pub name: String,
    /// The relay's ng control address.
    #[arg(long, default_value = "127.0.0.1:2223")]
    pub ng: SocketAddr,
    /// PID of the relay process (for CPU accounting).
    #[arg(long)]
    pub pid: u32,
    /// Numbers of concurrent calls to measure, comma-separated.
    #[arg(long, value_delimiter = ',', default_value = "250,500,1000,2000,4000")]
    pub calls: Vec<usize>,
    /// Client threads.
    #[arg(long, default_value_t = 4)]
    pub threads: usize,
    /// Warm-up before measuring, in seconds.
    #[arg(long, default_value_t = 2)]
    pub warmup: u64,
    /// Measurement window, in seconds.
    #[arg(long, default_value_t = 10)]
    pub duration: u64,
    /// Measurement windows per step; the median of each column is reported.
    #[arg(long, default_value_t = 1)]
    pub repeat: usize,
    /// Address of the callers' endpoints (side A).
    #[arg(long, default_value = "127.0.0.1")]
    pub a_addr: IpAddr,
    /// Address of the callees' endpoints (side B).
    #[arg(long, default_value = "127.0.0.1")]
    pub b_addr: IpAddr,
    /// Create the endpoints' sockets in this network namespace (a path such
    /// as /var/run/netns/peer); the ng socket stays in the current one.
    #[arg(long)]
    pub peer_netns: Option<std::path::PathBuf>,
    /// SRTP (SDES) on side A only, or on both sides.
    #[arg(long, value_enum, default_value_t = SrtpMode::None)]
    pub srtp: SrtpMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SrtpMode {
    None,
    A,
    Both,
}

/// Run every step of `args` against the relay and write the report to
/// `out`: a header line, the column names, and one row per step.
///
/// # Errors
///
/// Writing to `out`.
///
/// # Panics
///
/// When the relay does not answer `ng` or an endpoint socket cannot be made.
pub fn run(args: &Args, out: &mut dyn std::io::Write) -> std::io::Result<()> {
    let mut ng = Ng::new(args.ng);
    ng.request(&[(b"command", b"ping")], &[]);
    let relay = args.pid.to_string();
    let peers = Peers {
        a: args.a_addr,
        b: args.b_addr,
        netns: args
            .peer_netns
            .as_ref()
            .map(|p| std::fs::File::open(p).expect("peer netns path")),
    };
    writeln!(
        out,
        "# {} — G.711 20 ms, 172-octet RTP both ways{}, {} s window, median of {}, {} client threads",
        args.name,
        match args.srtp {
            SrtpMode::None => "",
            SrtpMode::A => ", SRTP on side A (SDES, AES_CM_128_HMAC_SHA1_80)",
            SrtpMode::Both => ", SRTP on both sides (SDES, AES_CM_128_HMAC_SHA1_80)",
        },
        args.duration,
        args.repeat.max(1),
        args.threads
    )?;
    writeln!(
        out,
        "{:>6} {:>9} {:>9} {:>7} {:>7} {:>7} {:>8} {:>9} {:>9} {:>10} {:>8} {:>8}",
        "calls",
        "offered",
        "deliv.",
        "loss%",
        "p50us",
        "p99us",
        "p99.9us",
        "relayCPU%",
        "us/packet",
        "clientCPU%",
        "sirqCPU%",
        "hostCPU%"
    )?;
    for (step, &n) in args.calls.iter().enumerate() {
        let calls = Arc::new(setup(&mut ng, &peers, n, step, args.srtp));
        std::thread::sleep(Duration::from_millis(200));
        let trials: Vec<Trial> = (0..args.repeat.max(1))
            .map(|_| trial(&calls, args, &relay))
            .collect();
        let col = |f: fn(&Trial) -> f64| median(trials.iter().map(f).collect());
        writeln!(
            out,
            "{:>6} {:>9.0} {:>9.0} {:>7.3} {:>7} {:>7} {:>8} {:>9.1} {:>9.2} {:>10.1} {:>8.1} {:>8.1}",
            n,
            col(|t| t.offered),
            col(|t| t.delivered),
            col(|t| t.loss),
            us(col(|t| t.p50)),
            us(col(|t| t.p99)),
            us(col(|t| t.p999)),
            col(|t| t.relay_cpu),
            col(|t| t.per_packet),
            col(|t| t.client_cpu),
            col(|t| t.softirq_cpu),
            col(|t| t.host_cpu),
        )?;
        teardown(&mut ng, &calls);
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}
