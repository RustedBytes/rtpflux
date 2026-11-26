//! The load: paced RTP both ways on every call, and the latency tally.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) const PAYLOAD: usize = 160;

pub(super) const PACKET: usize = 12 + PAYLOAD;

pub(super) const INTERVAL_NS: u64 = 20_000_000;

pub(super) const HIST_US: usize = 100_000;

// ---------------------------------------------------------------- load

#[derive(Clone)]
pub(super) struct Tally {
    pub(super) sent: u64,
    pub(super) received: u64,
    pub(super) hist: Vec<u32>,
    pub(super) overflow: u64,
}

impl Tally {
    pub(super) fn new() -> Self {
        Tally {
            sent: 0,
            received: 0,
            hist: vec![0; HIST_US],
            overflow: 0,
        }
    }

    pub(super) fn merge(&mut self, o: &Tally) {
        self.sent += o.sent;
        self.received += o.received;
        self.overflow += o.overflow;
        for (a, b) in self.hist.iter_mut().zip(&o.hist) {
            *a += b;
        }
    }

    /// Latency percentile in µs; `None` without samples, infinity past the
    /// histogram's range.
    pub(super) fn percentile(&self, q: f64) -> Option<f64> {
        let total: u64 = self.hist.iter().map(|&c| u64::from(c)).sum::<u64>() + self.overflow;
        if total == 0 {
            return None;
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let rank = ((total as f64) * q).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (us, &c) in self.hist.iter().enumerate() {
            seen += u64::from(c);
            if seen >= rank {
                #[allow(clippy::cast_precision_loss)]
                return Some(us as f64);
            }
        }
        Some(f64::INFINITY)
    }
}

pub(super) fn nanos(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// One client thread: send for its calls on schedule, receive and time.
pub(super) fn load(calls: &[Call], start: Instant, warmup_ns: u64, window_ns: u64) -> Tally {
    let mut tally = Tally::new();
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    for (i, c) in calls.iter().enumerate() {
        epoll
            .add(
                c.a.as_fd(),
                EpollEvent::new(EpollFlags::EPOLLIN, 2 * i as u64),
            )
            .unwrap();
        epoll
            .add(
                c.b.as_fd(),
                EpollEvent::new(EpollFlags::EPOLLIN, 2 * i as u64 + 1),
            )
            .unwrap();
    }
    let per_call_slots = calls.len().max(1) as u64;
    let mut next: Vec<u64> = (0..calls.len() as u64)
        .map(|i| i * INTERVAL_NS / per_call_slots)
        .collect();
    // This thread owns its calls' endpoint state for the window.
    let mut state: Vec<_> = calls
        .iter()
        .map(|c| c.state.lock().expect("endpoint state"))
        .collect();
    let mut sbuf = [0u8; PACKET + 16];
    let stop_send = warmup_ns + window_ns;
    let stop_all = stop_send + 500_000_000; // late packets
    let mut pkt = [0u8; PACKET];
    pkt[0] = 0x80;
    let mut rbuf = [0u8; 2048];
    let mut ready = [EpollEvent::empty(); 256];
    loop {
        let now = nanos(start);
        if now >= stop_all {
            break;
        }
        if now < stop_send {
            for (i, c) in calls.iter().enumerate() {
                while next[i] <= now {
                    let send_ns = nanos(start);
                    state[i].seq = state[i].seq.wrapping_add(1);
                    pkt[2..4].copy_from_slice(&state[i].seq.to_be_bytes());
                    pkt[12..20].copy_from_slice(&send_ns.to_le_bytes());
                    let counted = (warmup_ns..stop_send).contains(&send_ns);
                    for (side, sock, to) in [(0, &c.a, c.a_to), (1, &c.b, c.b_to)] {
                        let st = &mut *state[i];
                        let tx = if side == 0 { &mut st.a } else { &mut st.b };
                        let wire: &[u8] = match tx {
                            Some((p, _)) => {
                                sbuf[..PACKET].copy_from_slice(&pkt);
                                let n = p.rtp(&mut sbuf, PACKET).expect("SRTP protect");
                                &sbuf[..n]
                            }
                            None => &pkt,
                        };
                        if sock.send_to(wire, to).is_ok() && counted {
                            tally.sent += 1;
                        }
                    }
                    next[i] += INTERVAL_NS;
                }
            }
        }
        let wait_ms: u16 = 1;
        let ready_count = epoll
            .wait(&mut ready, EpollTimeout::from(wait_ms))
            .unwrap_or(0);
        for ev in &ready[..ready_count] {
            let Ok(idx) = usize::try_from(ev.data()) else {
                continue;
            };
            let c = &calls[idx / 2];
            let (sock, rx) = if idx % 2 == 0 {
                (&c.a, &mut state[idx / 2].a)
            } else {
                (&c.b, &mut state[idx / 2].b)
            };
            let window = warmup_ns..stop_send;
            drain(sock, rx, &mut rbuf, &mut tally, start, &window);
        }
    }
    tally
}

/// Read everything waiting on `sock`; time what was sent in `window`.
pub(super) fn drain(
    sock: &UdpSocket,
    rx: &mut Option<(Protect, Unprotect)>,
    rbuf: &mut [u8],
    tally: &mut Tally,
    start: Instant,
    window: &std::ops::Range<u64>,
) {
    loop {
        match sock.recv_from(rbuf) {
            Ok((len, _)) if len >= 20 => {
                if let Some((_, u)) = rx
                    && u.rtp(rbuf, len).is_err()
                {
                    continue;
                }
                let now = nanos(start);
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&rbuf[12..20]);
                let send_ns = u64::from_le_bytes(ts);
                if window.contains(&send_ns) {
                    tally.received += 1;
                    let us =
                        usize::try_from(now.saturating_sub(send_ns) / 1_000).unwrap_or(usize::MAX);
                    match tally.hist.get_mut(us) {
                        Some(b) => *b += 1,
                        None => tally.overflow += 1,
                    }
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}
