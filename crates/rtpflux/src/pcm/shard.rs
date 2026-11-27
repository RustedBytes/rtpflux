//! The PCM shards: a few threads that serve every PCM stream (see
//! [`super::stream`]). There are no threads per stream.
//!
//! A stream stays on one shard (by its id), so its state is never shared
//! or moved. Every 20 ms a shard runs each of its streams once:
//! - the endpoint's audio is decoded, analysed and framed for the
//!   service, and written as far as the socket takes it (non-blocking);
//! - the service's frames are read, only while the worker has room for
//!   its audio, and at most a few per stream, so no service starves the
//!   others.
//!
//! Each stream costs one read and one write per tick: no readiness
//! events, no epoll interest changes. The worker plays the service's
//! audio once every 20 ms anyway, so reading at that pace adds nothing
//! the queue does not already hide. Measured with the `load` test in
//! `tests/pcm.rs`: an epoll loop that waited for readability used more CPU
//! than the threads per stream it replaced, because its interest changed
//! twice a tick per stream that a service wrote ahead.
//!
//! Media workers never wait for a shard: they only exchange bounded queues
//! with it.

use super::stream::Stream;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

/// Streams waiting to be taken by a shard, at most.
const SUBMIT_QUEUE: usize = 256;
/// The shards' tick.
const TICK: Duration = Duration::from_millis(20);

/// Shards to start (0: one per CPU, at most 4); set before the first
/// stream.
static WANTED: AtomicUsize = AtomicUsize::new(0);
static POOL: OnceLock<Vec<SyncSender<Box<Stream>>>> = OnceLock::new();

/// Use `n` shards (`[runtime] pcm_shards`; 0: one per CPU, at most 4).
/// Only before the first stream starts.
pub fn configure(n: usize) {
    WANTED.store(n, Ordering::Relaxed);
}

/// The number of shards serving streams (starting them if need be).
///
/// # Errors
///
/// When a shard's thread cannot be made.
pub fn shards() -> std::io::Result<usize> {
    pool().map(<[_]>::len)
}

fn pool() -> std::io::Result<&'static [SyncSender<Box<Stream>>]> {
    if let Some(p) = POOL.get() {
        return Ok(p);
    }
    let n = match WANTED.load(Ordering::Relaxed) {
        0 => std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
        n => n,
    };
    let mut senders = Vec::with_capacity(n);
    for k in 0..n {
        let (tx, rx) = sync_channel(SUBMIT_QUEUE);
        std::thread::Builder::new()
            .name(format!("rtpflux-pcm-{k}"))
            .spawn(move || run(&rx))?;
        senders.push(tx);
    }
    // Another thread may have won: its pool is the one.
    let _ = POOL.set(senders);
    POOL.get()
        .map(Vec::as_slice)
        .ok_or_else(|| std::io::Error::other("PCM shards"))
}

/// Hand a stream to its shard.
pub(super) fn submit(stream: Box<Stream>) -> std::io::Result<()> {
    let pool = pool()?;
    let k = stream.id() as usize % pool.len().max(1);
    let Some(tx) = pool.get(k) else {
        return Err(std::io::Error::other("PCM shards"));
    };
    match tx.try_send(stream) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "PCM shard busy",
        )),
        Err(TrySendError::Disconnected(_)) => Err(std::io::Error::other("PCM shard gone")),
    }
}

/// One shard's loop.
fn run(rx: &Receiver<Box<Stream>>) {
    let mut streams: Vec<Box<Stream>> = Vec::new();
    let mut next_tick = Instant::now() + TICK;
    loop {
        loop {
            match rx.try_recv() {
                Ok(s) => streams.push(s),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                // The pool is static: never gone.
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            }
        }
        std::thread::sleep(next_tick.saturating_duration_since(Instant::now()));
        let now = Instant::now();
        // Paced; after a stall, from now.
        next_tick = if now > next_tick + 5 * TICK {
            now + TICK
        } else {
            next_tick + TICK
        };
        streams.retain_mut(|s| {
            let alive = s.tick() && s.read();
            if !alive {
                s.end();
            }
            alive
        });
    }
}
