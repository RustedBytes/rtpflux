//! `io_uring` multishot UDP receive: one request per socket keeps receiving
//! (`IORING_OP_RECVMSG` with `IORING_RECV_MULTISHOT`), each datagram into
//! a buffer the kernel picks from a provided-buffer ring, and the
//! completions of every socket are read from one queue, without a system
//! call per socket or per datagram.
//!
//! A [`Receiver`] is armed on sockets ([`Receiver::arm`], each with a
//! token), waited on ([`Receiver::wait`], or its file in an epoll set), and
//! drained ([`Receiver::complete`]): each datagram is handed over with its
//! token, source and payload, and its buffer goes back to the ring. A
//! socket whose multishot request ends (the buffers ran out, say) is armed
//! again; [`Receiver::disarm`] stops one, and what it still completes is
//! dropped. All `unsafe` is in the `ring` module.

// Every `unsafe` says why it is sound, one operation at a time (AGENTS.md
// §5).
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block
)]

mod ring;

use io_uring::{IoUring, cqueue, types};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

/// The buffer group of a receiver's provided buffers.
const GROUP: u16 = 0;

/// The token of a cancellation request (no socket's).
const CANCEL: u64 = u64::MAX;

/// What each buffer holds besides the datagram: the kernel's header
/// (`io_uring_recvmsg_out`, 16 octets) and the source address field (a
/// `sockaddr_storage`, 128).
pub const OVERHEAD: u32 = 16 + 128;

/// A datagram received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    /// Where it came from (`None`: an address family other than IP).
    pub source: Option<SocketAddr>,
    pub payload: &'a [u8],
    /// It did not fit its buffer: `payload` is its start only.
    pub truncated: bool,
}

/// Multishot receive on a set of UDP sockets.
pub struct Receiver {
    ring: IoUring,
    buffers: ring::Buffers,
    msghdr: ring::MsgHdr,
    /// The armed sockets, by token.
    armed: HashMap<u64, RawFd>,
    /// Sockets to arm again (their multishot ended), and whether the
    /// buffers ran out.
    rearm: Vec<u64>,
    /// The completions being handled (kept: no allocation per call).
    cq: Vec<(u64, i32, u32)>,
}

impl Receiver {
    /// A receiver with `buffers` buffers (a power of two, at most 32768)
    /// of `size` octets (each holds a datagram of `size - OVERHEAD`
    /// octets), and a ring of `entries` submission entries.
    ///
    /// # Errors
    ///
    /// When the kernel has no `io_uring` or no buffer rings, or memory is
    /// short. Multishot receive needs Linux 6.0: on 5.19 (buffer rings, no
    /// multishot receive) each socket's request fails when armed, with a
    /// warning, and the socket receives nothing here.
    pub fn new(entries: u32, buffers: u16, size: u32) -> io::Result<Self> {
        if size <= OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("buffers of more than {OVERHEAD} octets"),
            ));
        }
        // Room for a completion per buffer and as many more (the ends of
        // sockets' receives, cancellations), so that the queue overflows
        // rarely (the kernel's limit is 65536).
        let cq = entries
            .saturating_mul(4)
            .max(u32::from(buffers).saturating_mul(2))
            .min(65_536);
        let ring = IoUring::builder().setup_cqsize(cq).build(entries)?;
        let buffers = ring::Buffers::new(buffers, size)?;
        ring::register(&ring, &buffers, GROUP)?;
        Ok(Receiver {
            ring,
            buffers,
            msghdr: ring::MsgHdr::new(),
            armed: HashMap::new(),
            rearm: Vec::new(),
            cq: Vec::with_capacity(cq as usize),
        })
    }

    /// The ring's file (also [`AsFd`]): readable when completions wait
    /// (for epoll).
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.ring.as_raw_fd()
    }

    /// Receive on `socket` (a UDP socket, which must stay open until it is
    /// disarmed), its datagrams handed over with `token` (unique among the
    /// armed sockets, and not `u64::MAX`).
    ///
    /// # Errors
    ///
    /// When the submission queue is full, or the token is taken. Once
    /// queued, the request is armed: should handing it to the kernel fail
    /// now, the next call (`wait`, `complete`, another `arm`) hands it on.
    pub fn arm(&mut self, socket: BorrowedFd<'_>, token: u64) -> io::Result<()> {
        if token == CANCEL || self.armed.contains_key(&token) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "token in use"));
        }
        let fd = socket.as_raw_fd();
        self.submit_recv(fd, token)?;
        self.armed.insert(token, fd);
        let _ = self.ring.submit();
        Ok(())
    }

    /// Stop receiving for `token`; its completions still queued are
    /// dropped.
    ///
    /// # Errors
    ///
    /// When the cancellation cannot be submitted.
    ///
    /// Every request carrying `token` is cancelled (a request that ended
    /// and was armed again included), and the token is forgotten only once
    /// the cancellation is queued: on an error it stays armed.
    pub fn disarm(&mut self, token: u64) -> io::Result<()> {
        if !self.armed.contains_key(&token) {
            return Ok(());
        }
        // The submission queue full: hand it to the kernel, then again.
        ring::push_cancel(&mut self.ring, token, CANCEL).or_else(|_| {
            self.ring.submit()?;
            ring::push_cancel(&mut self.ring, token, CANCEL)
        })?;
        self.armed.remove(&token);
        self.rearm.retain(|&t| t != token);
        let _ = self.ring.submit();
        Ok(())
    }

    /// Wait until at least one completion is queued.
    ///
    /// # Errors
    ///
    /// As `io_uring_enter`.
    pub fn wait(&self) -> io::Result<()> {
        self.ring.submit_and_wait(1).map(|_| ())
    }

    /// Hand the queued datagrams to `f` with their sockets' tokens, give
    /// their buffers back, and arm again the sockets whose multishot
    /// request ended. Returns the datagrams handed over.
    pub fn complete(&mut self, mut f: impl FnMut(u64, Datagram<'_>)) -> usize {
        let mut n = 0;
        // Taken out so that buffers can be read while the queue is.
        let mut cq = std::mem::take(&mut self.cq);
        loop {
            cq.clear();
            cq.extend(
                self.ring
                    .completion()
                    .map(|e| (e.user_data(), e.result(), e.flags())),
            );
            if cq.is_empty() {
                // Completions the queue had no room for wait in the
                // kernel's overflow list until an `io_uring_enter` (with
                // GETEVENTS, which `submit` adds) brings them in. Among
                // them may be the ends of sockets' receives (no buffers):
                // left there, those sockets would never be armed again.
                if self.ring.submission().cq_overflow() && self.ring.submit().is_ok() {
                    continue;
                }
                break;
            }
            for &(token, result, flags) in &cq {
                n += self.one(token, result, flags, &mut f);
            }
        }
        self.cq = cq;
        self.buffers.publish();
        self.rearm_ended();
        n
    }

    /// One completion: a datagram (1), or none.
    fn one(
        &mut self,
        token: u64,
        result: i32,
        flags: u32,
        f: &mut impl FnMut(u64, Datagram<'_>),
    ) -> usize {
        if token == CANCEL {
            return 0;
        }
        let live = self.armed.contains_key(&token);
        // The request goes on while the kernel says MORE. Otherwise it
        // ended: the buffers ran out, or the kernel ended it (its
        // completion queue overflowed): armed again. Cancelled (a disarm,
        // perhaps of an earlier request under the same token): nothing to
        // do. Any other error would end it again at once: the socket is
        // given up, with a warning, rather than armed in a loop.
        if live && !cqueue::more(flags) {
            if result >= 0 || result == -libc::ENOBUFS {
                if !self.rearm.contains(&token) {
                    self.rearm.push(token);
                }
            } else if result != -libc::ECANCELED {
                self.armed.remove(&token);
                log::warn!(
                    "io_uring: a socket's receive failed ({}); it receives no more",
                    io::Error::from_raw_os_error(result.saturating_neg())
                );
            }
        }
        let Some(bid) = cqueue::buffer_select(flags) else {
            return 0;
        };
        // The kernel handed the buffer over; out of range, it is ignored.
        if !self.buffers.take(bid) {
            return 0;
        }
        let mut delivered = 0;
        if live
            && let Ok(len) = usize::try_from(result)
            && let Some(buf) = self.buffers.received(bid, len)
            && let Ok(out) = types::RecvMsgOut::parse(buf, self.msghdr.get())
        {
            f(
                token,
                Datagram {
                    source: socket_addr(out.name_data()),
                    payload: out.payload_data(),
                    truncated: out.is_payload_truncated(),
                },
            );
            delivered = 1;
        }
        self.buffers.give(bid);
        delivered
    }

    /// Arm again the sockets whose request ended.
    fn rearm_ended(&mut self) {
        let mut submitted = false;
        for token in std::mem::take(&mut self.rearm) {
            let Some(&fd) = self.armed.get(&token) else {
                continue;
            };
            // The submission queue full: hand it to the kernel, then again.
            let armed = self.submit_recv(fd, token).is_ok()
                || (self.ring.submit().is_ok() && self.submit_recv(fd, token).is_ok());
            if armed {
                submitted = true;
            } else {
                self.rearm.push(token);
            }
        }
        if submitted {
            let _ = self.ring.submit();
        }
    }

    fn submit_recv(&mut self, fd: RawFd, token: u64) -> io::Result<()> {
        ring::push_recv(&mut self.ring, fd, self.msghdr, GROUP, token)
    }

    /// Sockets armed.
    #[must_use]
    pub fn armed(&self) -> usize {
        self.armed.len()
    }
}

impl AsFd for Receiver {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.ring.as_fd()
    }
}

/// A `sockaddr_in` or `sockaddr_in6`, as the kernel wrote it (native-endian
/// family, network-order port and address).
fn socket_addr(name: &[u8]) -> Option<SocketAddr> {
    let family = i32::from(u16::from_ne_bytes([*name.first()?, *name.get(1)?]));
    let port = u16::from_be_bytes([*name.get(2)?, *name.get(3)?]);
    if family == libc::AF_INET {
        let a: [u8; 4] = name.get(4..8)?.try_into().ok()?;
        Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(a), port)))
    } else if family == libc::AF_INET6 {
        let flow = u32::from_be_bytes(name.get(4..8)?.try_into().ok()?);
        let a: [u8; 16] = name.get(8..24)?.try_into().ok()?;
        let scope = u32::from_ne_bytes(name.get(24..28)?.try_into().ok()?);
        Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(a),
            port,
            flow,
            scope,
        )))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsFd;
    use std::time::{Duration, Instant};

    /// The buffers' bookkeeping, not the caller, keeps the ring sound: a
    /// buffer is read only once the kernel handed it over, and given back
    /// once (a second give would overwrite an entry the kernel has yet to
    /// read).
    #[test]
    fn buffers_go_back_once_and_are_read_only_when_handed_over() {
        let mut b = ring::Buffers::new(8, 64).unwrap();
        let tail = |b: &ring::Buffers| b.tail();
        assert_eq!(tail(&b), 8, "all in the ring");
        b.give(3);
        assert_eq!(tail(&b), 8, "a buffer in the ring is not given again");
        assert!(b.received(3, 10).is_none(), "in the ring: not readable");
        assert!(!b.take(8), "out of range");
        assert!(b.take(3));
        assert_eq!(b.received(3, 10).map(<[u8]>::len), Some(10));
        assert!(b.received(3, 65).is_none(), "longer than the buffer");
        b.give(3);
        b.give(3);
        assert_eq!(tail(&b), 9, "given back once");
        assert!(b.received(3, 10).is_none());
    }

    /// Disarmed, armed again under the same token, disarmed again: every
    /// request is gone (none left consuming buffers or holding the
    /// socket), so once the socket closes its port is free.
    #[test]
    fn rearming_a_token_leaves_no_request_behind() {
        let mut r = Receiver::new(8, 16, 512).unwrap();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap();
        r.arm(s.as_fd(), 7).unwrap();
        r.disarm(7).unwrap();
        r.arm(s.as_fd(), 7).unwrap();
        // The first request's cancellation arrives while 7 is armed again.
        std::thread::sleep(Duration::from_millis(20));
        r.complete(|_, _| {});
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"x", port).unwrap();
        assert_eq!(collect(&mut r, 1).len(), 1, "the second arm receives");
        r.disarm(7).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        r.complete(|_, _| {});
        drop(s);
        // A request left behind would keep the socket's file, and its port.
        let mut free = false;
        for _ in 0..50 {
            if UdpSocket::bind(port).is_ok() {
                free = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
            r.complete(|_, _| {});
        }
        assert!(free, "the port is free again");
    }

    /// A socket the kernel cannot receive on (a listening TCP socket) is
    /// given up, not armed again in a loop.
    #[test]
    fn a_failing_socket_is_given_up() {
        let mut r = Receiver::new(8, 16, 512).unwrap();
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        r.arm(tcp.as_fd(), 1).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while r.armed() > 0 && Instant::now() < until {
            r.complete(|_, _| {});
        }
        assert_eq!(r.armed(), 0, "given up");
        // And no completion keeps coming.
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(r.complete(|_, _| {}), 0);
    }

    /// Receive until `want` datagrams came or a second passed.
    fn collect(r: &mut Receiver, want: usize) -> Vec<(u64, SocketAddr, Vec<u8>)> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(1);
        while got.len() < want && Instant::now() < until {
            r.complete(|t, d| got.push((t, d.source.unwrap(), d.payload.to_vec())));
            if got.len() < want {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        got
    }

    #[test]
    fn datagrams_of_several_sockets_come_with_their_tokens() {
        let mut r = Receiver::new(64, 8, 2048).unwrap();
        let socks: Vec<UdpSocket> = (0..3)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        for (i, s) in socks.iter().enumerate() {
            r.arm(s.as_fd(), i as u64 + 10).unwrap();
        }
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        // More datagrams than buffers: they come back to the ring as they
        // are handed over, and the requests are armed again when they ran
        // out.
        let mut sent = 0;
        let mut got = Vec::new();
        for round in 0..20u8 {
            for (i, s) in socks.iter().enumerate() {
                tx.send_to(&[round, u8::try_from(i).unwrap()], s.local_addr().unwrap())
                    .unwrap();
                sent += 1;
            }
            got.extend(collect(&mut r, 3));
        }
        assert_eq!(got.len(), sent);
        for (token, from, payload) in &got {
            assert_eq!(*from, tx.local_addr().unwrap());
            assert_eq!(u64::from(payload[1]) + 10, *token);
        }
        // Disarmed: nothing more is handed over for it.
        r.disarm(10).unwrap();
        tx.send_to(b"x", socks[0].local_addr().unwrap()).unwrap();
        tx.send_to(b"y", socks[1].local_addr().unwrap()).unwrap();
        let got = collect(&mut r, 1);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].0, got[0].2.as_slice()), (11, &b"y"[..]));
        assert_eq!(r.armed(), 2);
    }

    #[test]
    fn long_datagrams_are_truncated_and_v6_sources_read() {
        // Room for 112 octets of payload.
        let mut r = Receiver::new(8, 4, OVERHEAD + 112).unwrap();
        let s = UdpSocket::bind("[::1]:0").unwrap();
        r.arm(s.as_fd(), 1).unwrap();
        let tx = UdpSocket::bind("[::1]:0").unwrap();
        tx.send_to(&[7; 200], s.local_addr().unwrap()).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        let mut seen = None;
        while seen.is_none() && Instant::now() < until {
            r.complete(|_, d| seen = Some((d.source, d.truncated, d.payload.len())));
        }
        let (source, truncated, len) = seen.expect("a datagram");
        assert_eq!(source, Some(tx.local_addr().unwrap()));
        assert!(truncated);
        assert_eq!(len, 112);
    }

    /// Overload: more datagrams than buffers, and more completions than
    /// the completion queue holds. With as many queue entries as buffers
    /// (32), the datagrams fill the queue, and the completions that end
    /// the other sockets' receives (no buffers left) all go to the
    /// kernel's overflow list. Once drained, the receiver must have those
    /// too, and armed those sockets again: they keep receiving.
    #[test]
    fn receiving_goes_on_after_an_overload() {
        let mut r = Receiver::new(8, 32, 512).unwrap();
        let socks: Vec<UdpSocket> = (0..200)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        for (i, s) in socks.iter().enumerate() {
            r.arm(s.as_fd(), i as u64).unwrap();
        }
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..3 {
            for s in &socks {
                tx.send_to(b"flood", s.local_addr().unwrap()).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
        // Drain what is there (some of it), for a while.
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until {
            r.complete(|_, _| {});
        }
        // Then each socket gets one more: most must come through.
        for s in &socks {
            tx.send_to(b"after", s.local_addr().unwrap()).unwrap();
        }
        let mut after = 0;
        let until = Instant::now() + Duration::from_secs(2);
        while after < socks.len() && Instant::now() < until {
            r.complete(|_, d| after += usize::from(d.payload == b"after"));
        }
        assert!(
            after >= socks.len() * 9 / 10,
            "{after} of {} after the overload",
            socks.len()
        );
    }

    /// The buffers' memory under stress: datagrams of random sizes (empty,
    /// a buffer's worth, larger) to sockets armed and disarmed as they
    /// come. Every datagram handed over is a whole one of the size sent, or
    /// truncated to exactly the room a buffer has; nothing comes for a
    /// disarmed token; and receiving goes on to the end (no buffer lost).
    #[test]
    fn random_sizes_and_churn_keep_the_buffers_sound() {
        const ROOM: u32 = 256;
        let mut r = Receiver::new(16, 64, OVERHEAD + ROOM).unwrap();
        let socks: Vec<UdpSocket> = (0..32)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Tokens carry a generation, as the workers' do.
        let mut generation = vec![0u64; socks.len()];
        let token = |i: usize, g: u64| (g << 32) | i as u64;
        for (i, s) in socks.iter().enumerate() {
            r.arm(s.as_fd(), token(i, 0)).unwrap();
        }
        let mut armed = vec![true; socks.len()];
        let mut rng = 0x9e37_79b9_u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut handed = 0usize;
        for round in 0..400 {
            for _ in 0..8 {
                let i = usize::try_from(next() % socks.len() as u64).unwrap();
                let len = usize::try_from(next() % 700).unwrap();
                // The first two octets say which socket and how long.
                let mut d = vec![u8::try_from(i).unwrap(); len.max(3)];
                let n = u16::try_from(d.len()).unwrap();
                d[1..3].copy_from_slice(&n.to_be_bytes());
                let _ = tx.send_to(&d, socks[i].local_addr().unwrap());
            }
            if round % 10 == 0 {
                // Churn: disarm one, arm another again (a new generation).
                let i = usize::try_from(next() % socks.len() as u64).unwrap();
                if armed[i] {
                    r.disarm(token(i, generation[i])).unwrap();
                } else {
                    generation[i] += 1;
                    r.arm(socks[i].as_fd(), token(i, generation[i])).unwrap();
                }
                armed[i] = !armed[i];
            }
            r.complete(|t, d| {
                let i = usize::try_from(t & 0xffff_ffff).unwrap();
                assert!(
                    armed[i] && t >> 32 == generation[i],
                    "a datagram for a disarmed token"
                );
                assert_eq!(
                    d.payload[0],
                    u8::try_from(i).unwrap(),
                    "the socket's own datagram"
                );
                let sent = usize::from(u16::from_be_bytes([d.payload[1], d.payload[2]]));
                if d.truncated {
                    assert!(
                        sent > ROOM as usize && d.payload.len() == ROOM as usize,
                        "{sent} cut to {}",
                        d.payload.len()
                    );
                } else {
                    assert_eq!(d.payload.len(), sent);
                }
                handed += 1;
            });
        }
        // Still receiving, on every armed socket.
        let live: Vec<usize> = (0..socks.len()).filter(|&i| armed[i]).collect();
        std::thread::sleep(Duration::from_millis(50));
        r.complete(|_, _| {});
        for &i in &live {
            tx.send_to(
                &[u8::try_from(i).unwrap(), 0, 3],
                socks[i].local_addr().unwrap(),
            )
            .unwrap();
        }
        let mut last = 0;
        let until = Instant::now() + Duration::from_secs(2);
        while last < live.len() && Instant::now() < until {
            r.complete(|_, d| last += usize::from(d.payload.len() == 3));
        }
        assert_eq!(last, live.len(), "every armed socket still receives");
        assert!(handed > 1000, "{handed} datagrams handed over");
    }

    #[test]
    fn bad_sizes_are_refused_and_tokens_unique() {
        assert!(Receiver::new(8, 3, 512).is_err(), "not a power of two");
        assert!(
            Receiver::new(8, 4, OVERHEAD).is_err(),
            "no room for a datagram"
        );
        let mut r = Receiver::new(8, 4, 512).unwrap();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        r.arm(s.as_fd(), 1).unwrap();
        assert!(r.arm(s.as_fd(), 1).is_err());
        assert!(r.arm(s.as_fd(), u64::MAX).is_err());
    }

    #[test]
    fn addresses_of_both_families() {
        let mut v4 = vec![0u8; 16];
        v4[..2].copy_from_slice(&u16::try_from(libc::AF_INET).unwrap().to_ne_bytes());
        v4[2..4].copy_from_slice(&5004u16.to_be_bytes());
        v4[4..8].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(socket_addr(&v4), Some("192.0.2.1:5004".parse().unwrap()));
        assert_eq!(socket_addr(&v4[..6]), None, "short");
        assert_eq!(socket_addr(&[0; 16]), None, "AF_UNSPEC");
    }
}
