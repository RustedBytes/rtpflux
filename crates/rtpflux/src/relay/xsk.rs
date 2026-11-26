//! The `AF_XDP` receive path (`[xdp] af_xdp`): one thread per receive queue
//! of the device reads the frames the XDP program steered to its socket
//! (datagrams to the relay's ports that no kernel flow relays), checks
//! them as the stack would (`rtpflux_xdp_common::datagram`), and hands each
//! UDP payload to the worker owning the destination port, which relays it
//! as if its socket had received it. Replies and relayed packets leave
//! through the workers' sockets as usual.
//!
//! The port tells the worker and the slot: shards are contiguous port
//! ranges. Each worker has a bounded queue of fixed-size datagrams (no
//! allocation per packet); when it is full, datagrams are dropped and
//! counted.

use super::Stats;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::eventfd::EventFd;
use rtpflux_xdp_common::{datagram, unmapped};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::thread::JoinHandle;

/// The largest UDP payload carried (larger datagrams are dropped): a
/// 1,500-octet MTU's worth, so less is copied per datagram.
pub(super) const MAX_PAYLOAD: usize = 1500;
/// Datagrams waiting for a worker, at most.
pub(super) const INBOX: usize = 1024;

/// One received datagram for a worker.
pub(super) struct XskDatagram {
    /// The worker's slot of the destination port.
    pub slot: rtpflux_core::relay::Slot,
    pub src: SocketAddr,
    pub len: u16,
    pub data: [u8; MAX_PAYLOAD],
}

/// Where frames come from: an `AF_XDP` socket, or a test's.
pub(super) trait FrameSource: Send {
    /// Readable when frames are waiting.
    fn fd(&self) -> BorrowedFd<'_>;
    /// Hand each waiting frame (a batch) to `f`; returns how many.
    fn receive(&mut self, f: &mut dyn FnMut(&[u8])) -> usize;
}

#[cfg(feature = "af-xdp")]
impl FrameSource for rtpflux_xdp::xsk::XskReceiver {
    fn fd(&self) -> BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(self)
    }

    fn receive(&mut self, f: &mut dyn FnMut(&[u8])) -> usize {
        rtpflux_xdp::xsk::XskReceiver::receive(self, f)
    }
}

/// The address of 16 octets (IPv4-mapped for IPv4) and a port.
fn socket_addr(addr: &[u8; 16], port: u16) -> SocketAddr {
    match unmapped(addr) {
        Some(v4) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4)), port),
        None => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*addr)), port),
    }
}

/// Which worker and slot a relay port belongs to, and their queues.
#[derive(Clone)]
pub(super) struct Router {
    pub min_port: u16,
    /// Ports per shard (two per pair).
    pub shard_ports: u16,
    pub inboxes: Vec<(SyncSender<XskDatagram>, Arc<EventFd>, Arc<Stats>)>,
}

impl Router {
    /// (worker, slot) of relay port `port`.
    fn owner(&self, port: u16) -> Option<(usize, rtpflux_core::relay::Slot)> {
        let i = port.checked_sub(self.min_port)?;
        if self.shard_ports == 0 {
            return None;
        }
        let shard = usize::from(i / self.shard_ports);
        (shard < self.inboxes.len()).then_some((
            shard,
            rtpflux_core::relay::Slot::new(u32::from(i % self.shard_ports)),
        ))
    }

    /// Queue one frame's datagram for its worker; `touched[shard]` is set
    /// when one was queued. Frames the stack would drop, and datagrams for
    /// no worker or too large, are dropped (and counted when a worker is
    /// known).
    pub(super) fn route(&self, frame: &[u8], touched: &mut [bool]) {
        let Some(d) = datagram(frame) else {
            return;
        };
        let Some((shard, slot)) = self.owner(d.dst_port) else {
            return;
        };
        let Some((tx, _, stats)) = self.inboxes.get(shard) else {
            return;
        };
        let payload = &frame[d.payload.clone()];
        let Ok(len) = u16::try_from(payload.len()) else {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if payload.len() > MAX_PAYLOAD || payload.is_empty() {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut item = XskDatagram {
            slot,
            src: socket_addr(&d.src, d.src_port),
            len,
            data: [0; MAX_PAYLOAD],
        };
        item.data[..payload.len()].copy_from_slice(payload);
        match tx.try_send(item) {
            Ok(()) => {
                if let Some(t) = touched.get_mut(shard) {
                    *t = true;
                }
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Wake the workers that were given datagrams.
    fn wake(&self, touched: &mut [bool]) {
        for (k, t) in touched.iter_mut().enumerate() {
            if std::mem::take(t)
                && let Some((_, wake, _)) = self.inboxes.get(k)
            {
                let _ = wake.write(1);
            }
        }
    }
}

/// Read `source` until `stop` is set, routing its frames.
fn run(mut source: Box<dyn FrameSource>, router: &Router, stop: &AtomicBool) {
    let mut touched = vec![false; router.inboxes.len()];
    while !stop.load(Ordering::Relaxed) {
        let ready = {
            let mut fds = [PollFd::new(source.fd(), PollFlags::POLLIN)];
            poll(&mut fds, PollTimeout::from(100u16)).unwrap_or(0)
        };
        if ready == 0 {
            continue;
        }
        // Until the socket is empty, waking the workers after each batch.
        loop {
            let n = source.receive(&mut |frame| router.route(frame, &mut touched));
            router.wake(&mut touched);
            if n == 0 {
                break;
            }
        }
    }
}

/// The receive threads; stopped (and joined) when dropped.
pub(super) struct Receivers {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Receivers {
    /// The receive threads of `sources` (none: `None`), routing to the
    /// workers' `inboxes` by port.
    pub(super) fn start(
        sources: Vec<Box<dyn FrameSource>>,
        min_port: u16,
        shard_ports: u16,
        inboxes: Vec<(SyncSender<XskDatagram>, Arc<EventFd>, Arc<Stats>)>,
    ) -> std::io::Result<Option<Self>> {
        if sources.is_empty() {
            return Ok(None);
        }
        let router = Router {
            min_port,
            shard_ports,
            inboxes,
        };
        Self::spawn(sources, &router).map(Some)
    }

    /// One thread per source.
    pub(super) fn spawn(
        sources: Vec<Box<dyn FrameSource>>,
        router: &Router,
    ) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::with_capacity(sources.len());
        for (q, source) in sources.into_iter().enumerate() {
            let (router, stop) = (router.clone(), Arc::clone(&stop));
            threads.push(
                std::thread::Builder::new()
                    .name(format!("rtpflux-xsk-{q}"))
                    .spawn(move || run(source, &router, &stop))?,
            );
        }
        Ok(Receivers { stop, threads })
    }
}

impl Drop for Receivers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use nix::sys::eventfd::EfdFlags;
    use rtpflux_xdp::testframe::{Spec, build};
    use std::os::fd::AsFd;
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver, sync_channel};

    /// Frames waiting in a [`FakeSource`].
    pub(in crate::relay) type Frames = Arc<Mutex<Vec<Vec<u8>>>>;

    /// Frames handed in by a test; readable while some wait.
    pub(in crate::relay) struct FakeSource {
        pub ready: Arc<EventFd>,
        pub frames: Frames,
    }

    impl FakeSource {
        /// The source, its frame list, and its signal (write 1 after
        /// adding frames).
        pub(in crate::relay) fn new() -> (Self, Frames, Arc<EventFd>) {
            let ready = Arc::new(EventFd::from_flags(EfdFlags::EFD_NONBLOCK).unwrap());
            let frames = Arc::new(Mutex::new(Vec::new()));
            (
                FakeSource {
                    ready: Arc::clone(&ready),
                    frames: Arc::clone(&frames),
                },
                frames,
                ready,
            )
        }
    }

    impl FrameSource for FakeSource {
        fn fd(&self) -> BorrowedFd<'_> {
            self.ready.as_fd()
        }

        fn receive(&mut self, f: &mut dyn FnMut(&[u8])) -> usize {
            let frames = std::mem::take(&mut *self.frames.lock().unwrap());
            if frames.is_empty() {
                let _ = self.ready.read();
            }
            for fr in &frames {
                f(fr);
            }
            frames.len()
        }
    }

    fn frame(dport: u16, payload: &[u8]) -> Vec<u8> {
        build(&Spec {
            src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            sport: 4000,
            dport,
            ttl: 64,
            udp_checksum: true,
            payload,
        })
    }

    fn router(workers: usize) -> (Router, Vec<Receiver<XskDatagram>>, Vec<Arc<Stats>>) {
        let mut inboxes = Vec::new();
        let mut rxs = Vec::new();
        let mut stats = Vec::new();
        for _ in 0..workers {
            let (tx, rx) = sync_channel(2);
            let s = Arc::new(Stats::default());
            let wake = Arc::new(EventFd::from_flags(EfdFlags::EFD_NONBLOCK).unwrap());
            inboxes.push((tx, wake, Arc::clone(&s)));
            rxs.push(rx);
            stats.push(s);
        }
        (
            Router {
                min_port: 30_000,
                shard_ports: 100,
                inboxes,
            },
            rxs,
            stats,
        )
    }

    #[test]
    fn datagrams_go_to_the_worker_and_slot_of_their_port() {
        let (r, rxs, stats) = router(2);
        let mut touched = [false; 2];
        r.route(&frame(30_003, b"first"), &mut touched);
        r.route(&frame(30_105, b"second"), &mut touched);
        assert_eq!(touched, [true, true]);
        let d = rxs[0].try_recv().unwrap();
        assert_eq!(
            (d.slot.get(), &d.data[..usize::from(d.len)]),
            (3, &b"first"[..])
        );
        assert_eq!(d.src, "192.0.2.7:4000".parse().unwrap());
        let d = rxs[1].try_recv().unwrap();
        assert_eq!(
            (d.slot.get(), &d.data[..usize::from(d.len)]),
            (5, &b"second"[..])
        );
        r.wake(&mut touched);
        assert_eq!(touched, [false, false]);
        // Below the range, beyond the last worker, a bad frame: nothing.
        r.route(&frame(29_999, b"x"), &mut touched);
        r.route(&frame(30_200, b"x"), &mut touched);
        let mut bad = frame(30_001, b"x");
        *bad.last_mut().unwrap() ^= 1;
        r.route(&bad, &mut touched);
        assert_eq!(touched, [false, false]);
        assert!(rxs[0].try_recv().is_err() && rxs[1].try_recv().is_err());
        // A full queue drops, and counts.
        for _ in 0..3 {
            r.route(&frame(30_001, b"x"), &mut touched);
        }
        assert_eq!(stats[0].dropped.load(Ordering::Relaxed), 1);
        // Too large for a datagram slot: dropped and counted.
        let big = vec![0x80; MAX_PAYLOAD + 1];
        r.route(&frame(30_101, &big), &mut touched);
        assert_eq!(stats[1].dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn receive_threads_stop_when_dropped() {
        let (r, rxs, _) = router(1);
        let (source, frames, signal) = FakeSource::new();
        let threads = Receivers::start(vec![Box::new(source)], 30_000, 100, r.inboxes).unwrap();
        frames.lock().unwrap().push(frame(30_002, b"hello"));
        signal.write(1).unwrap();
        let d = rxs[0]
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(&d.data[..usize::from(d.len)], b"hello");
        drop(threads);
        assert!(
            Receivers::start(Vec::new(), 0, 1, Vec::new())
                .unwrap()
                .is_none()
        );
    }
}
