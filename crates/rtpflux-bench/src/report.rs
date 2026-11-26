//! One measurement window, CPU accounting and the report's numbers.

#[allow(clippy::wildcard_imports)]
use super::*;

/// utime + stime of a process, in seconds.
pub(super) fn cpu_seconds(pid: &str) -> f64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    // Fields after the parenthesised command name.
    let rest = stat.rsplit_once(')').map_or("", |(_, r)| r);
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ticks = f.get(11).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
        + f.get(12).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let hz = sysconf(SysconfVar::CLK_TCK).ok().flatten().unwrap_or(100);
    #[allow(clippy::cast_precision_loss)]
    {
        ticks as f64 / hz as f64
    }
}

/// One measurement window's results.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Trial {
    pub(super) offered: f64,
    pub(super) delivered: f64,
    pub(super) loss: f64,
    pub(super) p50: f64,
    pub(super) p99: f64,
    pub(super) p999: f64,
    pub(super) relay_cpu: f64,
    pub(super) per_packet: f64,
    pub(super) client_cpu: f64,
    pub(super) softirq_cpu: f64,
    pub(super) host_cpu: f64,
}

pub(super) fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v.get(v.len() / 2).copied().unwrap_or(f64::NAN)
}

pub(super) fn us(v: f64) -> String {
    if v.is_infinite() {
        format!(">{HIST_US}")
    } else if v.is_nan() {
        "-".to_owned()
    } else {
        format!("{v:.0}")
    }
}

/// Run one window of load on `calls` and measure it.
pub(super) fn trial(calls: &Arc<Vec<Call>>, args: &Args, relay: &str) -> Trial {
    let n = calls.len();
    let start = Instant::now();
    let (warmup_ns, window_ns) = (args.warmup * 1_000_000_000, args.duration * 1_000_000_000);
    let threads = args.threads.clamp(1, n.max(1));
    let per = n.div_ceil(threads);
    let handles: Vec<_> = (0..threads)
        .map(|k| {
            let calls = Arc::clone(calls);
            std::thread::spawn(move || {
                let lo = (k * per).min(calls.len());
                let hi = ((k + 1) * per).min(calls.len());
                load(&calls[lo..hi], start, warmup_ns, window_ns)
            })
        })
        .collect();
    std::thread::sleep(Duration::from_nanos(warmup_ns));
    let (r0, c0, h0) = (cpu_seconds(relay), cpu_seconds("self"), host_cpu());
    std::thread::sleep(Duration::from_nanos(window_ns));
    let (r1, c1, h1) = (cpu_seconds(relay), cpu_seconds("self"), host_cpu());
    let mut total = Tally::new();
    for h in handles {
        total.merge(&h.join().expect("load thread"));
    }
    #[allow(clippy::cast_precision_loss)]
    let (secs, sent, recv) = (
        args.duration as f64,
        total.sent as f64,
        total.received as f64,
    );
    let relay_cpu = r1 - r0;
    Trial {
        offered: sent / secs,
        delivered: recv / secs,
        loss: if total.sent > 0 {
            100.0 * (sent - recv) / sent
        } else {
            0.0
        },
        p50: total.percentile(0.50).unwrap_or(f64::NAN),
        p99: total.percentile(0.99).unwrap_or(f64::NAN),
        p999: total.percentile(0.999).unwrap_or(f64::NAN),
        relay_cpu: 100.0 * relay_cpu / secs,
        per_packet: if recv > 0.0 {
            relay_cpu / recv * 1e6
        } else {
            0.0
        },
        client_cpu: 100.0 * (c1 - c0) / secs,
        softirq_cpu: 100.0 * (h1.1 - h0.1) / secs,
        host_cpu: 100.0 * (h1.0 - h0.0) / secs,
    }
}

/// Host-wide CPU time from `/proc/stat` (all CPUs), in seconds: (busy,
/// softirq). Busy is everything but idle and iowait.
pub(super) fn host_cpu() -> (f64, f64) {
    let stat = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let line = stat.lines().next().unwrap_or_default();
    let f: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    let get = |i: usize| f.get(i).copied().unwrap_or(0);
    // user nice system idle iowait irq softirq steal
    let busy = get(0) + get(1) + get(2) + get(5) + get(6) + get(7);
    let hz = sysconf(SysconfVar::CLK_TCK).ok().flatten().unwrap_or(100);
    #[allow(clippy::cast_precision_loss)]
    {
        (busy as f64 / hz as f64, get(6) as f64 / hz as f64)
    }
}
