//! A load generator for rtpflux's native API: endpoint creations and
//! destructions over its Unix socket, timed one by one.
//!
//! - `--ops N`: N endpoints made (an offer of PCMU) and destroyed, in
//!   turn. It reports the rate of the pairs (creations per second), each
//!   operation's p50/p95/p99, and how fast a second connection received
//!   their `endpoint.destroyed` events (event throughput).
//! - `--keyed`: each operation carries an idempotency key (with
//!   `[sessions] ledger`, a durable operation: synced before its reply).
//! - `--keep N`: N endpoints made and left (for a restart's recovery time);
//!   `--expect N`: wait until the relay lists N endpoints, and say how
//!   long that took (the recovery time after a restart).
//! - `--pid`: the relay's RSS (resident memory) before and after.

#![allow(clippy::print_stdout, reason = "a command-line tool's report")]

use clap::Parser;
use rtpflux_client::Client;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
struct Args {
    /// The native API's socket.
    #[arg(long)]
    socket: PathBuf,
    /// The relay's pid (for its RSS).
    #[arg(long)]
    pid: Option<u32>,
    /// Endpoints to make and destroy.
    #[arg(long, default_value_t = 0)]
    ops: usize,
    /// With idempotency keys.
    #[arg(long)]
    keyed: bool,
    /// Endpoints to make and keep.
    #[arg(long, default_value_t = 0)]
    keep: usize,
    /// Wait until the relay lists this many endpoints.
    #[arg(long)]
    expect: Option<usize>,
    /// A label for the report.
    #[arg(long, default_value = "rtpflux")]
    name: String,
}

fn rss_kib(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// The `q` quantile of sorted `v`, in ms.
fn quantile(v: &[Duration], q: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index into a short list"
    )]
    let i = ((v.len() - 1) as f64 * q).round() as usize;
    v[i.min(v.len() - 1)].as_secs_f64() * 1000.0
}

fn summary(name: &str, mut v: Vec<Duration>) -> String {
    v.sort_unstable();
    format!(
        "{name} p50 {:.3} ms, p95 {:.3} ms, p99 {:.3} ms",
        quantile(&v, 0.50),
        quantile(&v, 0.95),
        quantile(&v, 0.99)
    )
}

fn connect(socket: &PathBuf) -> Client {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match Client::connect(socket) {
            Ok(c) => return c,
            Err(e) if Instant::now() > deadline => panic!("{}: {e}", socket.display()),
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn create(api: &mut Client, key: Option<String>) -> Result<String, String> {
    let mut req = json!({"codecs": ["PCMU"]});
    if let Some(k) = key {
        req["idempotency_key"] = json!(k);
    }
    let r = api
        .call("endpoint.create", req)
        .map_err(|e| e.to_string())?;
    r["endpoint_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{r}"))
}

fn main() {
    let args = Args::parse();
    let started = Instant::now();
    if let Some(n) = args.expect {
        // The relay just started: how long until it lists them all.
        let mut api = connect(&args.socket);
        loop {
            let listed = api
                .call("endpoint.list", Value::Null)
                .ok()
                .and_then(|v| v["endpoints"].as_array().map(Vec::len))
                .unwrap_or(0);
            if listed >= n {
                println!(
                    "{}: recovery: {listed} endpoints listed {:.1} ms after the first try",
                    args.name,
                    started.elapsed().as_secs_f64() * 1000.0
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        return;
    }
    let mut api = connect(&args.socket);
    let rss_before = args.pid.and_then(rss_kib);
    let run = std::process::id();
    if args.keep > 0 {
        for k in 0..args.keep {
            create(&mut api, args.keyed.then(|| format!("keep-{run}-{k}"))).unwrap();
        }
        println!("{}: {} endpoints made and kept", args.name, args.keep);
        return;
    }
    // Events of the destructions, counted on a connection of their own.
    let mut events = connect(&args.socket);
    events
        .call("events.subscribe", json!({"types": ["endpoint.destroyed"]}))
        .unwrap();
    let ops = args.ops;
    let counter = std::thread::spawn(move || {
        let mut n = 0;
        let mut first = None;
        let mut last = Instant::now();
        while n < ops {
            match events.next_event(Duration::from_secs(10)) {
                Ok(Some(_)) => {
                    first.get_or_insert_with(Instant::now);
                    last = Instant::now();
                    n += 1;
                }
                _ => break,
            }
        }
        (n, first.map(|f| last.duration_since(f)))
    });
    let (mut creates, mut destroys) = (Vec::with_capacity(ops), Vec::with_capacity(ops));
    let mut failures = 0;
    let t0 = Instant::now();
    for k in 0..ops {
        let t = Instant::now();
        let Ok(id) = create(&mut api, args.keyed.then(|| format!("c-{run}-{k}"))) else {
            failures += 1;
            continue;
        };
        creates.push(t.elapsed());
        let t = Instant::now();
        let mut req = json!({"endpoint_id": id});
        if args.keyed {
            req["idempotency_key"] = json!(format!("d-{run}-{k}"));
        }
        if api.call("endpoint.destroy", req).is_err() {
            failures += 1;
        }
        destroys.push(t.elapsed());
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let (received, span) = counter.join().unwrap();
    #[allow(clippy::cast_precision_loss, reason = "a rate")]
    let rate = creates.len() as f64 / elapsed;
    println!(
        "{}: {} create+destroy pairs ({}), {rate:.0} pairs/s, {failures} failed",
        args.name,
        creates.len(),
        if args.keyed { "keyed" } else { "unkeyed" }
    );
    println!("{}: {}", args.name, summary("create", creates));
    println!("{}: {}", args.name, summary("destroy", destroys));
    #[allow(clippy::cast_precision_loss, reason = "a rate")]
    let ev_rate = span.map_or(f64::NAN, |s| received as f64 / s.as_secs_f64().max(1e-6));
    println!(
        "{}: events: {received}/{ops} endpoint.destroyed received, {ev_rate:.0}/s",
        args.name
    );
    // Let the relay settle, then its memory.
    std::thread::sleep(Duration::from_millis(500));
    if let (Some(before), Some(after)) = (rss_before, args.pid.and_then(rss_kib)) {
        println!(
            "{}: RSS {before} KiB before, {after} KiB after ({:+} KiB)",
            args.name,
            i64::try_from(after).unwrap_or(0) - i64::try_from(before).unwrap_or(0)
        );
    }
}
