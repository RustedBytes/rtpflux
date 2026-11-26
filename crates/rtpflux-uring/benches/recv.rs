//! Receiving UDP on many sockets: epoll + `recvmmsg` (what the media
//! workers do) against `io_uring` multishot receive (`rtpflux-uring`).
//!
//! A sender spreads datagrams of an RTP packet's size (172 octets: 20 ms
//! of G.711) round-robin over N sockets, paced at a steady rate, as many
//! calls do (each stream 50 packets a second). Each receiver runs on its
//! own thread; what counts is that thread's CPU time (user + system) per
//! datagram received, and how many were received. A flood on one socket
//! (unpaced) is the case most favourable to `recvmmsg` (deep queues, full
//! batches).
//!
//! `cargo bench -p rtpflux-uring` (the numbers vary with the machine; run
//! it on an otherwise idle one).
#![allow(
    clippy::cast_precision_loss,
    reason = "rates and ratios of a report, not exact quantities"
)]

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::resource::{UsageWho, getrusage};
use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrIn, SockaddrStorage, recvmmsg, sendmmsg};
use rtpflux_uring::{OVERHEAD, Receiver};
use std::io::IoSliceMut;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PAYLOAD: usize = 172;
const BATCH: usize = 32;

/// This thread's CPU time so far.
fn cpu() -> Duration {
    let u = getrusage(UsageWho::RUSAGE_THREAD).expect("getrusage");
    let t = |tv: nix::sys::time::TimeVal| {
        Duration::new(
            u64::try_from(tv.tv_sec()).unwrap_or(0),
            u32::try_from(tv.tv_usec()).unwrap_or(0) * 1000,
        )
    };
    t(u.user_time()) + t(u.system_time())
}

/// Sockets on loopback, with large receive buffers left at the default.
fn sockets(n: usize) -> Vec<UdpSocket> {
    (0..n)
        .map(|_| {
            let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
            s.set_nonblocking(true).expect("nonblocking");
            s
        })
        .collect()
}

/// Send `total` datagrams round-robin to `to`, `rate` a second (0: as fast
/// as possible), in `sendmmsg` batches.
fn send(to: &[SocketAddr], total: u64, rate: u64) {
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addrs: Vec<SockaddrIn> = to
        .iter()
        .map(|a| match a {
            SocketAddr::V4(v4) => SockaddrIn::from(*v4),
            SocketAddr::V6(_) => unreachable!("loopback v4"),
        })
        .collect();
    let payload = [0x80u8; PAYLOAD];
    let mut data = MultiHeaders::<SockaddrIn>::preallocate(64, None);
    let start = Instant::now();
    let mut sent = 0u64;
    let mut next = 0usize;
    while sent < total {
        let n = usize::try_from((total - sent).min(64)).unwrap_or(64);
        let iovs: Vec<[std::io::IoSlice<'_>; 1]> =
            (0..n).map(|_| [std::io::IoSlice::new(&payload)]).collect();
        let dst: Vec<Option<SockaddrIn>> = (0..n)
            .map(|k| Some(addrs[(next + k) % addrs.len()]))
            .collect();
        let done = sendmmsg(
            tx.as_raw_fd(),
            &mut data,
            &iovs,
            &dst,
            [],
            MsgFlags::empty(),
        )
        .map_or(0, Iterator::count);
        next = (next + done.max(1)) % addrs.len();
        sent += u64::try_from(done.max(1)).unwrap_or(1);
        if rate > 0 {
            // Paced: wait until this many are due.
            let due = Duration::from_secs_f64(sent as f64 / rate as f64);
            while start.elapsed() < due {
                std::hint::spin_loop();
            }
        }
    }
}

/// The receivers.
#[derive(Clone, Copy, Debug)]
enum How {
    Recvmmsg,
    Uring,
}

/// Run `how` on `socks` until `stop` is set: (datagrams, CPU time).
fn receive(how: How, socks: &[UdpSocket], stop: &AtomicBool, got: &AtomicU64) -> Duration {
    let start = cpu();
    match how {
        How::Recvmmsg => {
            let epoll = Epoll::new(EpollCreateFlags::empty()).expect("epoll");
            for (i, s) in socks.iter().enumerate() {
                epoll
                    .add(s.as_fd(), EpollEvent::new(EpollFlags::EPOLLIN, i as u64))
                    .expect("epoll add");
            }
            let mut events = [EpollEvent::empty(); 256];
            let mut bufs = vec![[0u8; 2048]; BATCH];
            let mut hdr = MultiHeaders::<SockaddrStorage>::preallocate(BATCH, None);
            while !stop.load(Ordering::Relaxed) {
                let n = epoll
                    .wait(&mut events, EpollTimeout::from(50u16))
                    .unwrap_or(0);
                for ev in &events[..n] {
                    let fd = socks[usize::try_from(ev.data()).unwrap_or(0)].as_raw_fd();
                    loop {
                        let mut iovs: Vec<[IoSliceMut<'_>; 1]> =
                            bufs.iter_mut().map(|b| [IoSliceMut::new(b)]).collect();
                        let k =
                            recvmmsg(fd, &mut hdr, iovs.iter_mut(), MsgFlags::MSG_DONTWAIT, None)
                                .map_or(0, Iterator::count);
                        got.fetch_add(k as u64, Ordering::Relaxed);
                        if k < BATCH {
                            break;
                        }
                    }
                }
            }
        }
        How::Uring => {
            let mut r = Receiver::new(1024, 4096, OVERHEAD + 2048).expect("io_uring");
            for (i, s) in socks.iter().enumerate() {
                r.arm(s.as_fd(), i as u64).expect("arm");
            }
            while !stop.load(Ordering::Relaxed) {
                let _ = r.wait();
                let k = r.complete(|_, d| {
                    std::hint::black_box(d.payload);
                });
                got.fetch_add(k as u64, Ordering::Relaxed);
            }
        }
    }
    cpu().saturating_sub(start)
}

/// One run: (datagrams received, receiver CPU per datagram).
fn run(how: How, n_sockets: usize, total: u64, rate: u64) -> (u64, Duration) {
    let socks = Arc::new(sockets(n_sockets));
    let to: Vec<SocketAddr> = socks.iter().map(|s| s.local_addr().unwrap()).collect();
    let stop = Arc::new(AtomicBool::new(false));
    let got = Arc::new(AtomicU64::new(0));
    let rx = {
        let (socks, stop, got) = (Arc::clone(&socks), Arc::clone(&stop), Arc::clone(&got));
        std::thread::spawn(move || receive(how, &socks, &stop, &got))
    };
    std::thread::sleep(Duration::from_millis(50));
    send(&to, total, rate);
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    // Wake an io_uring receiver blocked in its wait.
    let waker = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..4 {
        let _ = waker.send_to(b"stop", to[0]);
    }
    let cpu = rx.join().expect("receiver");
    let got = got.load(Ordering::Relaxed);
    (got, cpu / u32::try_from(got.max(1)).unwrap_or(u32::MAX))
}

fn main() {
    // `cargo bench` passes `--bench`; a filter word is ignored.
    println!(
        "{:<34} {:>10} {:>12} {:>12} {:>8}",
        "case", "received", "recvmmsg", "io_uring", "ratio"
    );
    let cases: [(&str, usize, u64, u64); 5] = [
        ("1 socket, flood", 1, 1_000_000, 0),
        ("16 sockets, 100k pps", 16, 500_000, 100_000),
        ("256 sockets, 100k pps", 256, 500_000, 100_000),
        ("1024 sockets, 100k pps", 1024, 500_000, 100_000),
        ("4096 sockets, 200k pps", 4096, 1_000_000, 200_000),
    ];
    for (name, n, total, rate) in cases {
        let (got_m, per_m) = run(How::Recvmmsg, n, total, rate);
        let (got_u, per_u) = run(How::Uring, n, total, rate);
        println!(
            "{name:<34} {:>10} {:>9} ns {:>9} ns {:>7.2}x",
            format!("{got_m}/{got_u}"),
            per_m.as_nanos(),
            per_u.as_nanos(),
            per_m.as_nanos() as f64 / per_u.as_nanos().max(1) as f64,
        );
    }
}
